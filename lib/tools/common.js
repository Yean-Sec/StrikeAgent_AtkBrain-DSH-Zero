/**
 * Tool registration and shared guards.
 *
 * `ctx.tools.register` accepts a raw JSON-Schema subset, does not validate
 * arguments, and copies `output.presentationMeta` into the durable
 * `tool/result.meta` field. Every AtkBrain tool therefore:
 *   - validates its own arguments (InputError -> actionable model feedback),
 *   - reads a detached copy of the projection state,
 *   - returns `{summary, ops, details}`; the summary is what the model sees,
 *     the ops are what the projection folds. A resident teammate's ops are
 *     appended to the lead session and are not also stored on the child.
 */
import { PROJECTION_KEY, STATE_SCHEMA, TOOL_NAMES } from '../constants.js';
import { commitLeadLedger, graphOwner } from '../ledger-host.js';
import { selfTeamNode } from '../self-teams.js';
import { handoffOverdue, handoffText } from '../supervision-memory.js';
import { listUnreadWorkspaceFiles, unlinkedPluginEvidence } from '../workspace-residue.js';
import { canonicalIp, isLoopbackIp } from '../cidr.js';
import { applyOps, auditOp } from '../ops.js';
import { canonicalHost, evaluateScope } from '../scope.js';
import {
  InputError,
  clone,
  invalid,
  isPlainObject,
  nodeId,
  nowIso,
  shortHash,
  textBlock,
} from '../util.js';
import { evidenceNodeOp, link } from './build.js';

const TOOL_TIMEOUT_MS = 180000;

/** Read a detached copy of the attack graph this caller must use. */
export function readState(ctx, agent) {
  if (!agent?.session) throw new Error('AtkBrain requires an owning agent session');
  const owner = graphOwner(ctx, agent);
  let state;
  try {
    state = ctx.sessionProjections.stateOf(owner.session, PROJECTION_KEY);
  } catch (error) {
    throw new Error(`AtkBrain projection "${PROJECTION_KEY}" is unavailable: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (state === undefined) {
    throw new Error(`AtkBrain projection "${PROJECTION_KEY}" is not registered; the Host bundle is not active in this session`);
  }
  return clone(state);
}

/** Reject an op batch that would exceed the configured graph caps. */
export function assertCaps(state, config, ops) {
  if (!Array.isArray(ops)) return;
  const existingIds = new Set(Object.keys(state.nodes));
  const newNodeIds = new Set();
  let newEdges = 0;
  let audit = 0;
  for (const op of ops) {
    if (!isPlainObject(op)) continue;
    if (op.op === 'node.upsert') {
      const id = nodeId(op.kind ?? 'unknown', op.key ?? String(op.id ?? ''));
      if (!existingIds.has(id)) newNodeIds.add(id);
    } else if (op.op === 'edge.upsert') {
      newEdges += 1;
    } else if (op.op === 'audit') {
      audit += 1;
    }
  }
  if (existingIds.size + newNodeIds.size > (config.maxNodes ?? 20000)) {
    invalid(`graph node cap would be exceeded (${existingIds.size} + ${newNodeIds.size} > ${config.maxNodes}); export/report and start a new session or raise maxNodes`);
  }
  if (Object.keys(state.edges).length + newEdges > (config.maxEdges ?? 60000)) {
    invalid(`graph edge cap would be exceeded (${Object.keys(state.edges).length} + ${newEdges} > ${config.maxEdges})`);
  }
  if (ops.length > 50000) invalid(`too many ops in one result: ${ops.length}`);
  if (audit > 10) invalid('at most 10 audit ops are allowed per result');
}

/** Build the tool output schema (validated by the tool runtime on every call). */
function outputSchema() {
  return {
    type: 'object',
    additionalProperties: false,
    required: ['summary', 'ops'],
    properties: {
      summary: { type: 'string', description: 'Human-readable result; the model sees exactly this text.' },
      ops: {
        type: 'array',
        description: 'Graph ops folded by the atkGraph session projection.',
        items: { type: 'object', additionalProperties: true },
      },
      details: {
        type: 'object',
        additionalProperties: true,
        description: 'Structured result for the tool card/UI; not shown to the model as text.',
      },
    },
  };
}

/**
 * Register one AtkBrain tool.
 * @param {object} definition {name, description, parameters, validate, run, timeoutMs?, concurrencySafe?, callTitle?}
 */
function handoffBlocks(name, input) {
  return name === TOOL_NAMES.report || (name === TOOL_NAMES.selftteam && input?.action === 'report');
}

function residueBlocks(name, input) {
  return name === TOOL_NAMES.coverage || name === TOOL_NAMES.probe || name === TOOL_NAMES.report
    || (name === TOOL_NAMES.selftteam && input?.action === 'report');
}

export function registerAtkTool(ctx, config, deps, definition) {
  const { name } = definition;
  if (typeof definition.run !== 'function') throw new Error(`AtkBrain tool ${name} has no run handler`);
  ctx.tools.register({
    name,
    description: definition.description,
    parameters: definition.parameters,
    timeoutMs: definition.timeoutMs ?? TOOL_TIMEOUT_MS,
    isConcurrencySafe: () => definition.concurrencySafe === true,
    output: {
      schema: outputSchema(),
      render: (_args, value) => textBlock(value?.summary ?? 'AtkBrain completed with no summary'),
      presentationMeta: (_args, value) => {
        const ops = Array.isArray(value?.ops) ? value.ops : [];
        // The runtime snapshots this return value as lossless JSON, so it must
        // never be undefined. An empty op batch is a valid no-op meta.
        return { schema: STATE_SCHEMA, at: nowIso(), ops };
      },
    },
    presentCall: (args) => ({
      card: 'generic',
      title: definition.callTitle ?? name,
      kind: 'other',
      rawInput: isPlainObject(args) ? args : {},
    }),
    async execute(args, exec) {
      if (!exec.agent) throw new Error(`${name} requires an owning agent session`);
      if (config.enabled === false) throw new Error('AtkBrain is disabled in the plugin configuration (enabled: false)');
      // The Host hands tools a frozen args object; several tool validators
      // normalise args in place (e.g. atkbrain_arsenal recovers `name` from
      // `tool`/`binary`/`args[0]`). Work on a shallow mutable copy so those
      // normalisers do not throw "object is not extensible".
      const input = isPlainObject(args) ? { ...args } : {};
      try {
        definition.validate?.(input);
        const state = readState(ctx, exec.agent);
        const nodes = Object.values(state.nodes ?? {});
        if (handoffBlocks(name, input) || residueBlocks(name, input)) {
          const team = selfTeamNode(state, 'supervision');
          const overdue = team !== undefined && handoffOverdue(nodes, team.attrs?.lastBriefAt);
          const unread = await listUnreadWorkspaceFiles(exec.agent, nodes);
          const lines = [];
          if (overdue && handoffBlocks(name, input)) {
            const brief = handoffText(nodes);
            const clipped = brief.length > 700 ? `${brief.slice(0, 700)}…` : brief;
            lines.push(`御者要先交接。\n${clipped}\n先调用 atkbrain_selftteam action=brief。`);
          }
          if (unread.length > 0 && residueBlocks(name, input)) {
            lines.push(`这些文件已经写在本次测试目录里，图谱没有收：\n${unread.join('\n')}\n先调用 atkbrain_ingest，paths 带上这些路径。页面和脚本只记成证据，不要把里面的主机名收成目标。`);
          }
          if (lines.length > 0) invalid(lines.join('\n'));
        }
        const result = await definition.run({
          args: input,
          exec,
          state,
          ctx,
          config,
          deps,
        });
        if (!isPlainObject(result) || typeof result.summary !== 'string') {
          throw new Error(`${name} returned an invalid result (expected {summary, ops, details?})`);
        }
        const residue = await unlinkedPluginEvidence(exec.agent, nodes);
        if (residue.length > 0) {
          const recorded = residue.map((file) => evidenceNodeOp(state, {
            ...file,
            label: `evidence ${file.relative.split('/').pop()}`,
            origin: 'test-directory',
          }));
          result.ops = [...recorded, ...(Array.isArray(result.ops) ? result.ops : [])];
        }
        const ops = Array.isArray(result.ops) ? result.ops : [];
        assertCaps(state, config, ops);
        let safeOps;
        let safeDetails;
        try {
          // The tool runtime requires lossless JSON for both the value and the
          // presentation metadata. Dropping undefined properties here keeps a
          // builder that leaves an optional field unset from failing the call.
          safeOps = JSON.parse(JSON.stringify(ops));
          safeDetails = JSON.parse(JSON.stringify(isPlainObject(result.details) ? result.details : {}));
        } catch (error) {
          throw new Error(`${name} produced a non-JSON result: ${error instanceof Error ? error.message : String(error)}`);
        }
        const owner = graphOwner(ctx, exec.agent);
        const mirrored = owner.session !== exec.agent.session;
        if (mirrored && safeOps.length > 0) {
          const at = nowIso();
          applyOps(state, safeOps, at);
          await commitLeadLedger(ctx, owner.session, {
            schema: STATE_SCHEMA,
            at,
            ops: safeOps,
          });
        }
        return {
          summary: result.summary,
          ops: mirrored ? [] : safeOps,
          details: safeDetails,
        };
      } catch (error) {
        if (error instanceof InputError) throw error;
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`[${name}] ${message}`);
      }
    },
  });
}

/** Require an object argument set. */
export function assertArgs(value) {
  if (!isPlainObject(value)) invalid('arguments must be an object');
  return value;
}

/** Require a non-empty string property. */
export function requireString(args, key, { max = 4096 } = {}) {
  const value = args[key];
  if (typeof value !== 'string' || value.trim().length === 0) invalid(`${key} must be a non-empty string`);
  if (value.length > max) invalid(`${key} is too long (${value.length} > ${max})`);
  return value.trim();
}

/** Optional string property. */
export function optionalString(args, key, { max = 4096 } = {}) {
  const value = args[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') invalid(`${key} must be a string`);
  if (value.length > max) invalid(`${key} is too long (${value.length} > ${max})`);
  return value.trim().length > 0 ? value.trim() : undefined;
}

/** Optional integer property. */
export function optionalInteger(args, key, { min = -Infinity, max = Infinity } = {}) {
  const value = args[key];
  if (value === undefined || value === null) return undefined;
  if (!Number.isInteger(value) || value < min || value > max) invalid(`${key} must be an integer between ${min} and ${max}`);
  return value;
}

/** Require an array property within a length bound. */
export function requireArray(args, key, { min = 1, max = 500 } = {}) {
  const value = args[key];
  if (!Array.isArray(value)) invalid(`${key} must be an array`);
  if (value.length < min) invalid(`${key} must contain at least ${min} item(s)`);
  if (value.length > max) invalid(`${key} contains too many items (${value.length} > ${max})`);
  return value;
}

/** Require one value from an enum. */
export function requireEnum(args, key, allowed) {
  const value = args[key];
  if (typeof value !== 'string' || !allowed.includes(value)) invalid(`${key} must be one of ${allowed.join(', ')}`);
  return value;
}

/** Resolve a host through the shared resolver and return its addresses. */
export async function resolveHostIps(deps, host, { signal } = {}) {
  const result = await deps.resolver.resolveHost(host, { signal });
  if (result === undefined) return { status: 'error', ips: [], cname: [], raw: undefined };
  const ips = [...new Set([...(result.a ?? []), ...(result.aaaa ?? [])])];
  return { status: result.status, ips, cname: result.cname ?? [], raw: result };
}

/** Whether a hostname resolves to loopback (or is localhost). */
export function isLoopbackName(host) {
  const name = canonicalHost(host);
  return name === 'localhost' || name === 'localhost.localdomain' || isLoopbackIp(name);
}

/**
 * Enforce the engagement scope for one network target.
 * @returns {{target:object, ips:string[], evaluation:object}}
 */
export async function scopeGuard({ deps, state, config, target, signal, resolve = true }) {
  if (!target || typeof target !== 'object') invalid('network target is missing');
  let host = target.host;
  let url = target.url;
  let cidr = target.cidr;
  let ip = target.ip;
  let ips = Array.isArray(target.ips) ? target.ips.filter((entry) => canonicalIp(entry) !== undefined) : [];

  if (url !== undefined && host === undefined) {
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      invalid(`invalid target URL: ${url}`);
    }
  }
  if (host !== undefined) host = canonicalHost(host);

  if (config.offline) {
    if (ip !== undefined && !isLoopbackIp(ip)) invalid(`offline mode blocks non-loopback target ${ip}`);
    if (cidr !== undefined) invalid('offline mode blocks CIDR operations');
    if (host !== undefined && !isLoopbackName(host)) {
      if (ips.length === 0) invalid(`offline mode blocks non-loopback target ${host}`);
      if (!ips.every((entry) => isLoopbackIp(entry))) invalid(`offline mode blocks non-loopback target ${host}`);
    }
  }

  if (resolve && host !== undefined) {
    const resolved = await resolveHostIps(deps, host, { signal });
    if (resolved.status === 'error' || resolved.status === 'servfail' || resolved.status === 'timeout') {
      // A DNS error is not a scope decision; let the caller report it as an
      // observation. We still deny when the host has no allow rule.
      if (ips.length === 0) ips = resolved.ips;
    } else if (resolved.ips.length > 0) {
      ips = resolved.ips;
    }
  }

  const normalized = {
    ...(host !== undefined ? { type: target.type === 'url' || url !== undefined ? 'url' : 'host', host } : {}),
    ...(url !== undefined ? { url } : {}),
    ...(ip !== undefined ? { type: 'ip', ip } : {}),
    ...(cidr !== undefined ? { type: 'cidr', cidr } : {}),
    ...(host === undefined && ip === undefined && cidr === undefined ? { type: 'host', host: 'invalid' } : {}),
    ...(ips.length > 0 ? { ips } : {}),
    ...(Number.isInteger(target.port) ? { port: target.port } : {}),
  };

  if (!config.requireScope) {
    const denialCheck = evaluateScope({ allow: [], deny: state.scope?.deny ?? [] }, normalized);
    if (denialCheck.matchedDeny !== undefined) {
      invalid(`target is explicitly denied: ${denialCheck.reason}`);
    }
    return { target: normalized, ips, evaluation: { allowed: true, reason: 'requireScope=false (deny list still enforced)', allowedIps: ips } };
  }

  const allow = state.scope?.allow ?? [];
  if (allow.length === 0) {
    invalid('no authorized scope is set; call atkbrain_scope with the engagement authorization and allow list before any network action');
  }
  const evaluation = evaluateScope(state.scope, normalized);
  if (!evaluation.allowed) {
    invalid(`scope denied: ${evaluation.reason}. A more specific allow outranks a broader deny. To change denies, call atkbrain_scope action=set with the deny array to keep, or deny: [] to clear it. Do not bypass scope.`);
  }
  return { target: normalized, ips, evaluation };
}

/** Require a user-only approval for one high-impact operation. */
export async function requestApproval({ ctx, exec, config, enabled, reason, displayReason }) {
  if (!enabled) return { approved: true, outcome: 'not-required', approvalId: null };
  const approval = ctx.get('approval');
  if (approval === undefined || approval === null) {
    throw new Error('this operation requires user approval, but no approval service is available; ask the operator to approve it or disable the approval gate in the plugin configuration');
  }
  const outcome = await approval.request({
    agent: exec.agent,
    toolName: exec.name,
    callId: exec.callId,
    reason,
    ...(displayReason ? { displayReason } : {}),
    signal: exec.signal,
  });
  if (outcome !== 'allowed-once') {
    throw new Error(`approval ${outcome}: ${reason}`);
  }
  return { approved: true, outcome, approvalId: String(exec.callId) };
}

/** Create an evidence artifact, its node op, and a provenance edge op. */
export async function recordEvidence(deps, exec, state, subjectRef, name, payload, mediaType = 'application/json') {
  const artifact = await deps.writeEvidence(exec.agent, name, payload, mediaType);
  const op = evidenceNodeOp(state, {
    ...artifact,
    label: name,
    collectedBy: 'plugin',
  });
  const edges = subjectRef === undefined ? [] : [link(subjectRef, { kind: 'evidence', key: artifact.sha256 }, 'derived_from', { confidence: 1 })];
  return { artifact, nodeOp: op, edgeOps: edges, evidenceId: artifact.sha256 };
}

/** Append one audit op. */
export function audit(tool, action, target, result, evidenceIds = []) {
  return auditOp(tool, action, target, result, evidenceIds);
}

/** Hash one value for a stable action/task identity. */
export function hashParams(value) {
  return shortHash(JSON.stringify(value ?? {}), 12);
}

/** Build the standard "scope is required" error message for tools. */
export function scopeRequiredMessage() {
  return 'No engagement scope is set. Call atkbrain_scope with {action:"set", engagement:{name,authorization,...}, allow:[...]} first. Every network action is refused until then.';
}

/** Clamp a severity string to the known set. */
export function asSeverity(value, fallback = 'info') {
  return ['critical', 'high', 'medium', 'low', 'info'].includes(value) ? value : fallback;
}

/** Whether a node id is a valid stored node. */
export function existingNode(state, id) {
  return typeof id === 'string' ? state.nodes[id] : undefined;
}
