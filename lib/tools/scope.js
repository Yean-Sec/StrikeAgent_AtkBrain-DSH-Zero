/**
 * `atkbrain_scope` — record the authorized engagement and its allow/deny lists.
 *
 * This is the authority boundary for every network action. Setting a scope is
 * a user-owned decision: unless `requireScopeApproval` is false, the tool asks
 * the Host approval service and fails closed when no approval channel exists.
 */
import { randomUUID } from 'node:crypto';

import { TOOL_NAMES } from '../constants.js';
import { normalizeEngagementMode, normalizeScopeEntry, scopeSummary } from '../scope.js';
import { SELF_TEAM_ORDER, bootstrapSelfTeamOps } from '../self-teams.js';
import { nowIso, isPlainObject, invalid } from '../util.js';
import {
  assertArgs,
  audit,
  optionalString,
  registerAtkTool,
  requestApproval,
  requireEnum,
} from './common.js';

const ACTIONS = ['get', 'set'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'get the current scope, or set an authorized engagement scope. An allow or deny array you send replaces that side; deny: [] clears the deny list. Omitting a side leaves it unchanged.' },
    engagement: {
      type: 'object',
      additionalProperties: true,
      description: 'Engagement identity: {name, client?, authorization, window?, mode?, roe?}. `authorization` is a written-approval reference and is required for set. mode is view, collect, validate, or intrusive. A pentest label such as authorized-pentest is stored as intrusive.',
    },
    allow: {
      type: 'array',
      items: { type: 'object', additionalProperties: true },
      description: 'Allow entries: [{type:"domain"|"host"|"ip"|"cidr"|"url", value, ports?, note?}]. ports may be a number, "80,443", "80-82", or a service name such as https. Sending this array replaces the allow list. A more specific allow outranks a broader deny.',
    },
    deny: {
      type: 'array',
      items: { type: 'object', additionalProperties: true },
      description: 'Deny entries with the same shape. Sending this array replaces the deny list, including an empty array, which clears it. An exact deny outranks a broader allow. A parent-domain deny does not block a more specific allowed host, so do not deny a parent domain to represent "everything else".',
    },
    roe: {
      type: 'object',
      additionalProperties: true,
      description: 'Rules of engagement caps: {maxQps, maxHostsPerAction, maxPortsPerAction, techniques:[T0..T3]}.',
    },
    note: { type: 'string', description: 'Free-form operator note stored with the audit entry.' },
  },
};

function positiveNumber(value) {
  const number = typeof value === 'number' ? value : (typeof value === 'string' && value.trim().length > 0 ? Number(value) : NaN);
  return Number.isFinite(number) && number > 0 ? number : undefined;
}

function positiveInteger(value) {
  const number = positiveNumber(value);
  return number !== undefined && Number.isInteger(number) ? number : undefined;
}

function normalizeRoe(value) {
  if (!isPlainObject(value)) return undefined;
  const roe = {};
  const maxQps = positiveNumber(value.maxQps);
  const maxHosts = positiveInteger(value.maxHostsPerAction);
  const maxPorts = positiveInteger(value.maxPortsPerAction);
  if (maxQps !== undefined) roe.maxQps = maxQps;
  if (maxHosts !== undefined) roe.maxHostsPerAction = maxHosts;
  if (maxPorts !== undefined) roe.maxPortsPerAction = maxPorts;
  const techniqueSource = Array.isArray(value.techniques)
    ? value.techniques
    : (typeof value.techniques === 'string' ? value.techniques.split(/[,;\s]+/u) : []);
  const techniques = techniqueSource.map((entry) => String(entry).trim().toUpperCase()).filter((entry) => ['T0', 'T1', 'T2', 'T3'].includes(entry));
  if (techniques.length > 0) roe.techniques = [...new Set(techniques)].sort();
  return Object.keys(roe).length > 0 ? roe : undefined;
}

function normalizeEntries(value, label) {
  if (value === undefined) return [];
  if (isPlainObject(value)) value = [value];
  if (!Array.isArray(value)) invalid(`${label} must be an array`);
  if (value.length > 1000) invalid(`${label} contains too many entries (${value.length} > 1000)`);
  return value.map((entry, index) => {
    try {
      return normalizeScopeEntry(entry);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      invalid(`${label}[${index}]: ${message}`);
    }
    return undefined;
  }).filter(Boolean);
}

function describeScope(scope, engagement) {
  const summary = scopeSummary(scope);
  const name = engagement?.name ?? '(no engagement)';
  const auth = engagement?.authorization ? `auth=${engagement.authorization}` : 'auth=none';
  return `Scope ${name}: ${summary.allowCount} allow, ${summary.denyCount} deny, ${auth}`
    + `${summary.empty ? ' — empty allow list; all network actions are refused' : ''}`;
}

export function registerScopeTool(ctx, config, deps) {
  registerAtkTool(ctx, config, deps, {
    name: TOOL_NAMES.scope,
    callTitle: 'Set engagement scope',
    description: 'Read or set the authorized penetration-testing scope for this session. Every network tool refuses to run until an allow list exists. A more specific allow outranks a broader deny, and an exact deny outranks a broader allow. An allow or deny array in action=set replaces that side; pass deny: [] to clear denies. Hosts left off the allow list are already out of scope. When approval is enabled, setting a scope asks the operator first.',
    parameters: PARAMETERS,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (action === 'set') {
        if (!isPlainObject(args.engagement)) invalid('engagement must be an object for action=set');
        if (typeof args.engagement.name !== 'string' || args.engagement.name.trim().length === 0) invalid('engagement.name is required');
        if (typeof args.engagement.authorization !== 'string' || args.engagement.authorization.trim().length === 0) {
          invalid('engagement.authorization (the written approval reference) is required; do not run a network test without it');
        }
        if (args.engagement.mode !== undefined) normalizeEngagementMode(args.engagement.mode);
        normalizeEntries(args.allow, 'allow');
        normalizeEntries(args.deny, 'deny');
      }
      return true;
    },
    async run({ args, state, exec, ctx: toolCtx, config: cfg }) {
      if (args.action === 'get') {
        const summary = describeScope(state.scope, state.engagement);
        return {
          summary,
          ops: [],
          details: {
            engagement: state.engagement,
            scope: scopeSummary(state.scope),
            note: 'Use atkbrain_scope action=set with an authorization reference to enable network tools.',
          },
        };
      }

      const allowProvided = args.allow !== undefined;
      const denyProvided = args.deny !== undefined;
      const allow = allowProvided ? normalizeEntries(args.allow, 'allow') : [];
      const deny = denyProvided ? normalizeEntries(args.deny, 'deny') : [];
      const nextAllow = allowProvided ? allow : (state.scope?.allow ?? []);
      const nextDeny = denyProvided ? deny : (state.scope?.deny ?? []);
      const mode = normalizeEngagementMode(args.engagement.mode);
      const roe = normalizeRoe(args.roe ?? args.engagement.roe);
      const now = nowIso();
      const approval = await requestApproval({
        ctx: toolCtx,
        exec,
        config: cfg,
        enabled: cfg.requireScopeApproval === true,
        reason: `Authorize AtkBrain engagement "${args.engagement.name}" (${nextAllow.length} allow, ${nextDeny.length} deny entries).`,
        displayReason: `AtkBrain wants to record an authorized scope for “${args.engagement.name}”. Network tools stay blocked until the operator approves.`,
      });

      const projectId = (() => {
        const existing = typeof state.engagement?.id === 'string' ? state.engagement.id.trim() : '';
        if (/^PRJ-[A-Z0-9]{8}$/u.test(existing)) return existing;
        return `PRJ-${randomUUID().replace(/-/gu, '').slice(0, 8).toUpperCase()}`;
      })();
      const engagement = {
        id: projectId,
        name: String(args.engagement.name).trim(),
        ...(optionalString(args.engagement, 'client', { max: 200 }) ? { client: optionalString(args.engagement, 'client', { max: 200 }) } : {}),
        authorization: String(args.engagement.authorization).trim(),
        ...(mode ? { mode } : {}),
        ...(isPlainObject(args.engagement.window) ? { window: args.engagement.window } : {}),
        ...(roe ? { roe } : {}),
        createdAt: now,
      };
      const ops = [
        { op: 'engagement.set', engagement },
        {
          op: 'scope.set',
          ...(allowProvided ? { allow, replaceAllow: true } : {}),
          ...(denyProvided ? { deny, replaceDeny: true } : {}),
          ...(roe ? { roe } : {}),
          updatedAt: now,
          approvedAt: approval.approved ? now : null,
          ...(approval.approvalId ? { approvalId: approval.approvalId } : {}),
        },
        audit(TOOL_NAMES.scope, 'scope.set', engagement.name, `${nextAllow.length} allow / ${nextDeny.length} deny`, []),
      ];
      const teamOps = nextAllow.length > 0 && cfg.selfTeamMode !== 'off' ? bootstrapSelfTeamOps(state) : [];
      ops.push(...teamOps);
      const nativeTeams = {
        available: false,
        spawned: [],
        existing: [],
        errors: [],
        skipped: 'native teams are not started automatically in this edition',
      };
      const wildcardScope = nextAllow.some((entry) => entry.type === 'cidr' && ['0.0.0.0/0', '::/0'].includes(entry.canonical));
      const warnings = [];
      if (nextAllow.length === 0) warnings.push('allow list is empty: every network action will be refused');
      if (wildcardScope) warnings.push('allow list contains a global CIDR; confirm the written authorization really covers it');
      if (denyProvided) warnings.push(deny.length === 0 ? 'deny list cleared' : 'deny list replaced; a broader deny does not block a more specific allowed host');
      return {
        summary: `${describeScope({ ...state.scope, allow: nextAllow, deny: nextDeny }, engagement)}. Project ID: ${projectId}. Approval: ${approval.outcome}.`
          + `${teamOps.length > 0 ? `\n已记录从者、二次验证和报告撰写：${teamOps.length} 个团队节点。监督团队需要时再用 atkbrain_selftteam action=start team=supervision。` : '\n从者、二次验证和报告撰写已存在。监督团队需要时再单独启动。'}`
          + `${warnings.length > 0 ? `\nWarnings: ${warnings.join('; ')}` : ''}`,
        ops,
        details: {
          engagement,
          projectId,
          scope: scopeSummary({ allow: nextAllow, deny: nextDeny, roe, updatedAt: now }),
          warnings,
          approval,
          teamsStarted: teamOps.map((op) => op.attrs?.type).filter(Boolean),
          teamOrder: [...SELF_TEAM_ORDER],
          nativeTeams,
        },
      };
    },
  });
}
