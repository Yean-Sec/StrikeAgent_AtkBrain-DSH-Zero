/**
 * `atkbrain_ingest` — merge asset documents, observation JSONL and exported
 * graph JSON into the session graph, with dedupe and wildcard-DNS handling.
 *
 * The tool never pulls facts out of another tool's result text: files are
 * hashed and parsed here, or the agent writes an observations artifact.
 */
import path from 'node:path';
import { stat } from 'node:fs/promises';

import { TOOL_NAMES } from '../constants.js';
import { canonicalIp, isPrivateIp } from '../cidr.js';
import { extractDocumentText } from '../doc.js';
import { detectDocumentFormat, mergeNormalized, parseAssetRecords, parseObservationsJsonl } from '../ingest.js';
import { applyOps } from '../ops.js';
import { canonicalHost, domainInScope, evaluateScope, hostInScope } from '../scope.js';
import { probeWildcardZone, classifyHostAnswers } from '../wildcard.js';
import {
  InputError,
  fileSha256,
  invalid,
  isPlainObject,
  mapLimit,
  readTextFile,
  logicalArtifactRelative,
  resolveArtifact,
  sha256Hex,
  shortHash,
} from '../util.js';
import {
  accessNodeOp,
  cidrNodeOp,
  dataNodeOp,
  domainNodeOp,
  evidenceNodeOp,
  findingNodeOp,
  hostNodeOp,
  ipNodeOp,
  link,
  pivotNodeOp,
  registrableDomain,
  ref,
  taskNodeOp,
  webappNodeOp,
  credentialNodeOp,
} from './build.js';
import {
  assertArgs,
  audit,
  optionalString,
  registerAtkTool,
  requireEnum,
  scopeGuard,
} from './common.js';

const FORMATS = ['auto', 'lines', 'csv', 'json', 'jsonl', 'markdown', 'observations', 'graph-json'];
const CAPTURED_EXT = new Set(['.html', '.htm', '.js', '.mjs', '.xml', '.har', '.hdr']);
const SCOPED_ASSET_KINDS = new Set(['host', 'domain', 'ip', 'cidr', 'segment', 'webapp', 'service']);
const MAX_FILE_BYTES = 50 * 1024 * 1024;
const MAX_INLINE_CHARS = 2 * 1024 * 1024;
const MAX_FILES = 20;
const MAX_WILDCARD_ZONES = 20;
const MAX_WILDCARD_HOSTS = 100;

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  properties: {
    paths: {
      type: 'array',
      items: { type: 'string' },
      description: 'Workspace-relative or absolute asset documents (.txt/.csv/.json/.jsonl/.md/.docx/.xlsx/.pptx). At most 20.',
    },
    text: { type: 'string', description: 'Inline asset text, pasted from the operator or an extracted document.' },
    format: {
      type: 'string',
      enum: FORMATS,
      description: 'Force a parser. `observations` reads the agent-collected JSONL schema; `graph-json` merges another AtkBrain export.',
    },
    tags: { type: 'array', items: { type: 'string' }, description: 'Tags applied to every imported node.' },
    sourceName: { type: 'string', description: 'Human label for an inline source.' },
    probeWildcard: { type: 'boolean', description: 'Run wildcard-DNS classification for discovered zones (default true; skipped without scope).' },
  },
};

function mediaTypeFor(filePath, format) {
  const extension = path.extname(filePath).toLowerCase();
  if (extension === '.json') return 'application/json';
  if (extension === '.jsonl' || format === 'observations') return 'application/x-ndjson';
  if (extension === '.csv' || extension === '.tsv') return 'text/csv';
  if (extension === '.md') return 'text/markdown';
  if (extension === '.docx' || extension === '.xlsx' || extension === '.pptx' || extension === '.pdf') return 'application/octet-stream';
  return 'text/plain';
}

function formatWarning(warning) {
  if (typeof warning === 'string') return warning;
  if (isPlainObject(warning)) {
    const reason = typeof warning.reason === 'string' ? warning.reason : 'parser warning';
    const line = warning.line !== undefined ? `:${warning.line}` : '';
    const raw = typeof warning.raw === 'string' && warning.raw.length > 0 ? ` (${warning.raw.slice(0, 120)})` : '';
    return `${reason}${line}${raw}`;
  }
  return String(warning);
}

function recordValue(record) {
  return typeof record?.value === 'string' && record.value.length > 0
    ? record.value
    : typeof record?.key === 'string' ? record.key : '';
}

function withEvidence(op, sha) {
  if (op === undefined || sha === undefined) return op;
  return { ...op, evidenceIds: [...new Set([...(op.evidenceIds ?? []), sha])] };
}

function addSource(op, source) {
  if (op === undefined || source === undefined) return op;
  return { ...op, sources: [...new Set([...(op.sources ?? []), source])] };
}

function domainForHost(host) {
  const registrable = registrableDomain(host);
  if (registrable === undefined || registrable === canonicalHost(host)) return undefined;
  return registrable;
}

/**
 * Saved pages and previous-engagement tool output are observations. Auto
 * ingest records the file and does not mine it for hostnames.
 */
export function capturedObservationPath(relative) {
  const rel = String(relative ?? '').replace(/\\/gu, '/');
  const ext = path.posix.extname(rel).toLowerCase();
  if (CAPTURED_EXT.has(ext)) return true;
  return rel.startsWith('.atkbrain/evidence/')
    || rel.includes('/.atkbrain/evidence/')
    || rel.startsWith('.atkbrain/surface/')
    || rel.includes('/.atkbrain/surface/');
}

function webappHost(key, attrs) {
  if (typeof attrs?.host === 'string' && attrs.host.trim().length > 0) return attrs.host;
  try { return new URL(String(key)).hostname; } catch { return ''; }
}

function endpointAllowed(scope, endpoint) {
  const text = String(endpoint ?? '').trim();
  if (text.length === 0) return false;
  const literal = canonicalIp(text.split(':')[0]);
  if (literal !== undefined) return hostInScope(scope, literal);
  return hostInScope(scope, text);
}

/** Whether one graph node belongs to the approved scope. An empty allow list keeps everything. */
export function nodeInScope(scope, node) {
  if (!SCOPED_ASSET_KINDS.has(node?.kind)) return true;
  if (!Array.isArray(scope?.allow) || scope.allow.length === 0) return true;
  if (node.kind === 'host') return hostInScope(scope, node.key, node.attrs?.ips);
  if (node.kind === 'domain') return domainInScope(scope, node.key);
  if (node.kind === 'ip' || node.kind === 'cidr') {
    try { return evaluateScope(scope, node.kind === 'ip' ? { type: 'ip', ip: node.key } : { type: 'cidr', cidr: node.key }).allowed; }
    catch { return false; }
  }
  if (node.kind === 'webapp') return hostInScope(scope, webappHost(node.key, node.attrs));
  if (node.kind === 'service') return endpointAllowed(scope, node.attrs?.endpoint ?? node.key);
  return true;
}

function recordInScope(scope, record) {
  if (!Array.isArray(scope?.allow) || scope.allow.length === 0) return true;
  const kind = record?.kind;
  const value = recordValue(record);
  if (kind === 'host') return hostInScope(scope, value);
  if (kind === 'domain') return domainInScope(scope, value);
  if (kind === 'ip' || kind === 'cidr') {
    try { return evaluateScope(scope, kind === 'ip' ? { type: 'ip', ip: value } : { type: 'cidr', cidr: value }).allowed; }
    catch { return false; }
  }
  if (kind === 'url') {
    try { return hostInScope(scope, new URL(value).hostname); } catch { return false; }
  }
  return true;
}

/** Drop hosts, domains, addresses and URLs the approved scope does not cover. */
export function filterOpsToScope(scope, ops) {
  const list = Array.isArray(ops) ? ops : [];
  if (!Array.isArray(scope?.allow) || scope.allow.length === 0) return { ops: list, dropped: 0 };
  const dropped = new Set();
  for (const op of list) {
    if (op?.op !== 'node.upsert' || !SCOPED_ASSET_KINDS.has(op.kind)) continue;
    if (!nodeInScope(scope, op)) dropped.add(`${op.kind}|${op.key}`);
  }
  for (const op of list) {
    if (op?.op !== 'edge.upsert' || op.kind !== 'resolves_to') continue;
    const from = op.from;
    const to = op.to;
    if (from?.kind === 'host' && to?.kind === 'ip' && !dropped.has(`host|${from.key}`)) {
      dropped.delete(`ip|${to.key}`);
    }
  }
  if (dropped.size === 0) return { ops: list, dropped: 0 };
  const next = [];
  let count = 0;
  for (const op of list) {
    if (op?.op === 'node.upsert' && dropped.has(`${op.kind}|${op.key}`)) {
      count += 1;
      continue;
    }
    if (op?.op === 'edge.upsert') {
      const fromKey = `${op.from?.kind}|${op.from?.key}`;
      const toKey = `${op.to?.kind}|${op.to?.key}`;
      if (dropped.has(fromKey) || dropped.has(toKey)) {
        count += 1;
        continue;
      }
    }
    next.push(op);
  }
  return { ops: next, dropped: count };
}

/** Build graph ops for one normalized asset record. */
function assetOps(state, record, context) {
  const ops = [];
  const tags = context.tags;
  const source = context.source;
  const evidenceId = context.evidenceId;
  const push = (op) => {
    if (op === undefined) return;
    ops.push(withEvidence(addSource(op, source), evidenceId));
  };

  if (record.kind === 'domain') {
    push(domainNodeOp(recordValue(record), { tags, sources: [source] }));
    return ops;
  }
  if (record.kind === 'host') {
    const host = canonicalHost(recordValue(record));
    push(hostNodeOp(host, {
      declared: true,
      realm: record.attrs?.realm,
      wildcardStatus: 'unknown',
      tags,
      sources: [source],
      attrs: isPlainObject(record.attrs) ? record.attrs : {},
    }));
    const domain = domainForHost(host);
    if (domain !== undefined) {
      push(domainNodeOp(domain, { tags, sources: [source] }));
      push(link(ref('domain', domain), ref('host', host), 'contains', { confidence: 0.7 }));
    }
    return ops;
  }
  if (record.kind === 'ip') {
    push(ipNodeOp(recordValue(record), { tags, sources: [source], realm: record.attrs?.realm }));
    return ops;
  }
  if (record.kind === 'cidr') {
    push(cidrNodeOp(recordValue(record), { tags, sources: [source], realm: record.attrs?.realm }));
    return ops;
  }
  if (record.kind === 'url') {
    let url;
    try {
      url = new URL(recordValue(record));
    } catch {
      return ops;
    }
    const host = url.hostname.toLowerCase();
    const port = url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80);
    const webappKey = recordValue(record);
    push(hostNodeOp(host, { declared: true, tags, sources: [source] }));
    push(webappNodeOp(webappKey, {
      host,
      port,
      path: url.pathname,
      scheme: url.protocol.replace(':', ''),
      tags,
      sources: [source],
      attrs: {
        ...(url.search ? { query: url.search } : {}),
        ...(record.attrs ?? {}),
      },
    }));
    push(link(ref('host', host), ref('webapp', webappKey), 'exposes', { confidence: 0.8 }));
    const domain = domainForHost(host);
    if (domain !== undefined) {
      push(domainNodeOp(domain, { tags, sources: [source] }));
      push(link(ref('domain', domain), ref('host', host), 'contains', { confidence: 0.7 }));
    }
    return ops;
  }
  return ops;
}

/** Build ops for one agent-collected observation. */
function observationOps(state, observation, context) {
  const ops = [];
  const tags = context.tags;
  const source = context.source;
  const evidenceId = context.evidenceId;
  const push = (op) => {
    if (op === undefined) return;
    ops.push(withEvidence(addSource(op, source), evidenceId));
  };
  if (!isPlainObject(observation)) return ops;
  const sign = (op) => op;

  if (observation.kind === 'host' || observation.kind === 'domain') {
    const host = canonicalHost(observation.host ?? observation.value ?? '');
    if (host.length > 0) push(hostNodeOp(host, { declared: true, tags, sources: [source] }));
    return ops;
  }
  if (observation.kind === 'ip') {
    const ip = canonicalIp(observation.ip ?? observation.value ?? '');
    if (ip !== undefined) push(ipNodeOp(ip, { tags, sources: [source] }));
    return ops;
  }
  if (observation.kind === 'dns') {
    const host = canonicalHost(observation.host ?? '');
    if (host.length === 0) return ops;
    const a = Array.isArray(observation.a) ? observation.a.filter((ip) => canonicalIp(ip) !== undefined) : [];
    const aaaa = Array.isArray(observation.aaaa) ? observation.aaaa.filter((ip) => canonicalIp(ip) !== undefined) : [];
    const ips = [...a, ...aaaa];
    push(hostNodeOp(host, { declared: true, tags, sources: [source], ips }));
    for (const ip of ips) {
      push(ipNodeOp(ip, { tags, sources: [source] }));
      push(link(ref('host', host), ref('ip', ip), 'resolves_to', { confidence: 0.8 }));
    }
    if (Array.isArray(observation.cname)) {
      for (const target of observation.cname) {
        const cname = canonicalHost(target);
        if (cname.length === 0) continue;
        push(hostNodeOp(cname, { tags, sources: [source] }));
        push(link(ref('host', host), ref('host', cname), 'cname', { confidence: 0.7 }));
      }
    }
    return ops;
  }
  if (observation.kind === 'service') {
    const host = canonicalHost(observation.host ?? '');
    const ip = observation.ip !== undefined ? canonicalIp(observation.ip) : undefined;
    const endpoint = host.length > 0 ? host : ip;
    const port = Number(observation.port);
    if (endpoint === undefined || !Number.isInteger(port) || port < 1 || port > 65535) return ops;
    const transport = observation.transport === 'udp' ? 'udp' : 'tcp';
    const endpointRef = host.length > 0 ? ref('host', host) : ref('ip', ip);
    if (host.length > 0) push(hostNodeOp(host, { tags, sources: [source] }));
    if (ip !== undefined) push(ipNodeOp(ip, { tags, sources: [source] }));
    const serviceKey = `${transport}:${endpoint}:${port}`;
    push({
      op: 'node.upsert',
      kind: 'service',
      key: serviceKey,
      label: `${endpoint}:${port}`,
      attrs: {
        endpoint,
        port,
        transport,
        state: observation.state ?? 'open',
        ...(observation.protocol ? { protocol: observation.protocol } : {}),
        ...(observation.banner ? { banner: String(observation.banner).slice(0, 2000) } : {}),
      },
      status: observation.state === 'open' ? 'open' : 'closed',
      confidence: 0.7,
      tags,
      sources: [source],
      evidenceIds: evidenceId ? [evidenceId] : [],
    });
    push(link(endpointRef, ref('service', `${transport}:${endpoint}:${port}`), 'exposes', { confidence: 0.8 }));
    return ops;
  }
  if (observation.kind === 'http') {
    const rawUrl = observation.url;
    let url;
    try {
      url = new URL(rawUrl);
    } catch {
      return ops;
    }
    const host = url.hostname.toLowerCase();
    const port = url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80);
    const webappKey = url.origin + url.pathname;
    push(hostNodeOp(host, { declared: true, tags, sources: [source] }));
    push(webappNodeOp(webappKey, {
      host,
      port,
      path: url.pathname,
      scheme: url.protocol.replace(':', ''),
      status: Number(observation.status),
      title: observation.title,
      server: observation.server,
      tags,
      sources: [source],
      attrs: {
        ...(Array.isArray(observation.techs) ? { techs: observation.techs.slice(0, 30) } : {}),
        ...(isPlainObject(observation.headers) ? { headers: observation.headers } : {}),
      },
    }));
    push(link(ref('host', host), ref('webapp', webappKey), 'exposes', { confidence: 0.8 }));
    return ops;
  }
  if (observation.kind === 'finding') {
    const template = String(observation.template ?? 'agent-observation');
    const subject = String(observation.subject ?? observation.host ?? observation.url ?? 'unknown');
    push(findingNodeOp(state, {
      template,
      title: observation.title ?? template,
      severity: observation.severity,
      status: observation.status ?? 'candidate',
      subjectKey: subject,
      evidence: observation.evidence,
      cve: observation.cve,
      cwe: observation.cwe,
      repro: observation.repro,
      remediation: observation.remediation,
      evidenceIds: evidenceId ? [evidenceId] : [],
      attrs: {
        collectedBy: 'agent',
        ...(isPlainObject(observation.attrs) ? observation.attrs : {}),
      },
    }));
    return ops;
  }
  return ops;
}

/** Convert an exported graph JSON into upsert ops. */
// Child graph exports carry a copy of their own five self-teams. Those local
// timestamps, native member ids and report paths must never overwrite the
// parent's team/report state when the child graph is merged.
const CHILD_SELF_TEAM_LOCAL_KEYS = new Set([
  'lastBriefAt', 'lastBriefPath', 'lastDistillAt', 'lastVerifyAt',
  'lastReportAt', 'lastReportPath', 'lastReportTheme', 'lastReportKind',
  'lastFindingReportAt', 'lastFindingReportPath', 'lastFindingReportId',
  'nativeId', 'nativeStatus', 'verifiedCount', 'ratedCount', 'skillCount', 'skillDir',
]);

function scrubbedChildAttrs(kind, attrs) {
  if (kind !== 'self_team' || !isPlainObject(attrs)) return attrs;
  const out = {};
  for (const [key, value] of Object.entries(attrs)) {
    if (CHILD_SELF_TEAM_LOCAL_KEYS.has(key)) continue;
    if (value === null || value === undefined) continue;
    if (Array.isArray(value) && value.length === 0) continue;
    out[key] = value;
  }
  return out;
}

export function graphJsonOps(document, context) {
  if (!isPlainObject(document) || document.schema !== 'atkbrain/1') {
    invalid('graph-json must be an AtkBrain export with schema "atkbrain/1"');
  }
  const nodes = Array.isArray(document.nodes) ? document.nodes : [];
  const edges = Array.isArray(document.edges) ? document.edges : [];
  if (nodes.length > 20000) invalid('graph-json contains too many nodes (max 20000)');
  const byId = new Map();
  const ops = [];
  const skipped = [];
  const plausibleDomain = (key) => {
    const labels = String(key).split('.');
    return labels.length >= 2
      && labels.every((label) => label.length > 0)
      && labels.some((label) => /[a-z]/iu.test(label))
      && /[a-z]/iu.test(labels[labels.length - 1]);
  };
  for (const node of nodes) {
    if (!isPlainObject(node) || typeof node.kind !== 'string' || typeof node.key !== 'string') continue;
    if (isPlainObject(node.attrs) && node.attrs.stub === true) {
      skipped.push({ id: node.id, kind: node.kind, key: node.key, reason: 'stub endpoint placeholder' });
      continue;
    }
    if (node.kind === 'domain' && (canonicalIp(node.key) !== undefined || !plausibleDomain(node.key))) {
      skipped.push({ id: node.id, kind: node.kind, key: node.key, reason: 'invalid domain artifact' });
      continue;
    }
    if (node.kind === 'host' && canonicalIp(node.key) !== undefined) {
      skipped.push({ id: node.id, kind: node.kind, key: node.key, reason: 'IP literal imported as host' });
      continue;
    }
    byId.set(node.id, { kind: node.kind, key: node.key });
    ops.push({
      op: 'node.upsert',
      kind: node.kind,
      key: node.key,
      label: node.label,
      attrs: scrubbedChildAttrs(node.kind, isPlainObject(node.attrs) ? node.attrs : {}),
      status: node.status,
      confidence: node.confidence,
      verification: node.verification,
      tags: Array.isArray(node.tags) ? node.tags : [],
      sources: [...new Set([...(Array.isArray(node.sources) ? node.sources : []), context.source])],
      evidenceIds: Array.isArray(node.evidenceIds) ? node.evidenceIds : [],
      ...(node.firstSeen ? { firstSeen: node.firstSeen } : {}),
      ...(node.lastSeen ? { lastSeen: node.lastSeen } : {}),
    });
  }
  let importedEdges = 0;
  for (const edge of edges) {
    if (!isPlainObject(edge) || typeof edge.kind !== 'string') continue;
    const from = byId.get(edge.from);
    const to = byId.get(edge.to);
    if (from === undefined || to === undefined) continue;
    importedEdges += 1;
    ops.push({
      op: 'edge.upsert',
      from,
      to,
      kind: edge.kind,
      confidence: edge.confidence,
      attrs: isPlainObject(edge.attrs) ? edge.attrs : {},
      evidenceIds: Array.isArray(edge.evidenceIds) ? edge.evidenceIds : [],
    });
  }
  return {
    ops,
    importedNodes: ops.filter((op) => op.op === 'node.upsert').length,
    importedEdges,
    skippedNodes: skipped,
  };
}

/** Whether a zone may be probed under the current scope. */
async function zoneScopeAllowed({ deps, state, config, zone, signal }) {
  if (!config.requireScope) {
    const denial = evaluateScope({ allow: [], deny: state.scope?.deny ?? [] }, { type: 'domain', host: zone });
    return denial.matchedDeny === undefined ? { allowed: true } : { allowed: false, reason: denial.reason };
  }
  if ((state.scope?.allow?.length ?? 0) === 0) return { allowed: false, reason: 'scope.allow is empty' };
  const direct = evaluateScope(state.scope, { type: 'domain', host: zone });
  if (direct.allowed) return { allowed: true };
  try {
    const resolved = await deps.resolver.resolveHost(zone, { signal });
    const ips = [...new Set([...(resolved?.a ?? []), ...(resolved?.aaaa ?? [])])];
    if (ips.length > 0) {
      const byIp = evaluateScope(state.scope, { type: 'host', host: zone, ips });
      if (byIp.allowed) return { allowed: true };
    }
  } catch {
    // Fall through to the direct denial reason.
  }
  return { allowed: false, reason: direct.reason };
}

export function registerIngestTool(ctx, config, deps) {
  registerAtkTool(ctx, config, deps, {
    name: TOOL_NAMES.ingest,
    callTitle: 'Import and merge assets',
    description: 'Import asset documents, agent-collected observation JSONL, or another AtkBrain graph export into the attack graph. Normalizes, canonicalizes, de-duplicates and optionally classifies wildcard DNS. Use this once per asset document; repeated imports are idempotent and report merges.',
    parameters: PARAMETERS,
    validate(args) {
      assertArgs(args);
      const paths = args.paths;
      const text = args.text;
      if (!Array.isArray(paths) && (typeof text !== 'string' || text.trim().length === 0)) {
        invalid('provide paths (array) and/or text');
      }
      if (Array.isArray(paths)) {
        if (paths.length > MAX_FILES) invalid(`too many paths (${paths.length} > ${MAX_FILES})`);
        if (paths.length === 0 && (typeof text !== 'string' || text.trim().length === 0)) {
          invalid('paths is empty and no inline text was provided');
        }
        if (paths.some((entry) => typeof entry !== 'string' || entry.trim().length === 0)) invalid('every paths entry must be a non-empty string');
      }
      if (typeof text === 'string' && text.length > MAX_INLINE_CHARS) invalid(`text is too large (${text.length} > ${MAX_INLINE_CHARS})`);
      if (args.format !== undefined) requireEnum(args, 'format', FORMATS);
      if (args.tags !== undefined && !Array.isArray(args.tags)) invalid('tags must be an array of strings');
      if (args.probeWildcard !== undefined && typeof args.probeWildcard !== 'boolean') invalid('probeWildcard must be a boolean');
      return true;
    },
    async run({ args, state, exec, config: cfg, deps: runtime }) {
      const formatArg = args.format ?? 'auto';
      const tags = Array.isArray(args.tags) ? args.tags.filter((tag) => typeof tag === 'string').slice(0, 30) : [];
      const probeWildcard = args.probeWildcard !== false;
      const warnings = [];
      const artifacts = [];
      const normalized = [];
      const observationRecords = [];
      const graphOps = [];
      const quarantineSamples = [];
      let quarantineCount = 0;
      let graphImported = null;
      let droppedScope = 0;
      let capturedFiles = 0;

      const readOne = async (filePath) => {
        const workspace = runtime.workspace(exec.agent);
        const absolute = resolveArtifact(exec.agent, workspace, filePath);
        const info = await stat(absolute);
        if (info.size > MAX_FILE_BYTES) invalid(`file ${filePath} is ${info.size} bytes; the limit is ${MAX_FILE_BYTES}`);
        const extension = path.extname(absolute).toLowerCase();
        let text;
        let parsedFormat = formatArg;
        let via = 'text';
        if (['.docx', '.xlsx', '.pptx', '.pdf'].includes(extension) && formatArg === 'auto') {
          const extracted = await extractDocumentText(absolute, { pythonPath: cfg.pythonPath, maxBytes: MAX_FILE_BYTES });
          if (extracted?.unsupported === true) {
            warnings.push(`${filePath}: ${extracted.guidance ?? 'unsupported document format'}`);
            return {
              artifact: undefined,
              warnings: [`${filePath}: unsupported`],
              parsed: { records: [], warnings: [], quarantined: [] },
              unsupported: extracted,
            };
          }
          text = extracted.text;
          parsedFormat = 'lines';
          via = extracted.via ?? 'python';
        } else {
          text = await readTextFile(absolute, MAX_FILE_BYTES);
          if (parsedFormat === 'auto') parsedFormat = detectDocumentFormat(absolute, text);
        }
        const sha256 = await fileSha256(absolute);
        const logical = logicalArtifactRelative(exec.agent, absolute);
        const artifact = {
          path: absolute,
          relative: logical ?? path.relative(workspace, absolute),
          sha256,
          bytes: info.size,
          mediaType: mediaTypeFor(absolute, parsedFormat),
          via,
        };
        return { text, parsedFormat, artifact, filePath };
      };

      const inputs = [];
      for (const filePath of Array.isArray(args.paths) ? args.paths : []) {
        try {
          const input = await readOne(filePath);
          if (input.unsupported !== undefined) {
            const artifact = {
              path: input.filePath,
              relative: logicalArtifactRelative(exec.agent, resolveArtifact(exec.agent, runtime.workspace(exec.agent), input.filePath))
                ?? input.filePath,
              sha256: undefined,
              bytes: undefined,
              mediaType: 'application/pdf',
            };
            inputs.push({ ...input, artifact });
            const guidance = input.unsupported.guidance ?? 'Convert the PDF to text and import the text file.';
            graphOps.push(taskNodeOp(state, {
              actionType: 'extract_document',
              targetId: artifact.relative,
              label: `Extract text from ${artifact.relative}`,
              priority: 70,
              why: [guidance],
              toolClass: 'manual',
              risk: 'none',
            }));
            continue;
          }
          inputs.push(input);
        } catch (error) {
          if (error instanceof InputError) throw error;
          warnings.push(`${filePath}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

      if (typeof args.text === 'string' && args.text.trim().length > 0) {
        const sha256 = sha256Hex(args.text);
        inputs.push({
          text: args.text,
          parsedFormat: formatArg === 'auto' ? 'lines' : formatArg,
          artifact: {
            path: null,
            relative: args.sourceName ?? `inline-${sha256.slice(0, 8)}`,
            sha256,
            bytes: Buffer.byteLength(args.text, 'utf8'),
            mediaType: 'text/plain',
            via: 'inline',
          },
          filePath: args.sourceName ?? 'inline',
        });
      }

      for (const input of inputs) {
        const artifact = input.artifact;
        if (artifact === undefined) continue;
        const source = artifact.relative ?? artifact.path ?? 'unknown';
        artifacts.push(artifact);
        const evidenceOp = evidenceNodeOp(state, {
          path: artifact.path,
          relative: artifact.relative,
          mediaType: artifact.mediaType,
          bytes: artifact.bytes,
          sha256: artifact.sha256,
          label: `import ${source}`,
        });
        if (artifact.sha256 !== undefined) graphOps.push(evidenceOp);

        const effectiveFormat = formatArg === 'auto' ? input.parsedFormat : formatArg;
        if (formatArg === 'auto' && capturedObservationPath(source)) {
          capturedFiles += 1;
          continue;
        }
        if (effectiveFormat === 'graph-json') {
          let document;
          try {
            document = JSON.parse(input.text);
          } catch (error) {
            warnings.push(`${source}: graph-json parse failed: ${error instanceof Error ? error.message : String(error)}`);
            continue;
          }
          if (state.engagement !== null && document.engagement?.name && state.engagement.name !== document.engagement.name) {
            invalid(`graph-json belongs to engagement "${document.engagement.name}", but this session is "${state.engagement.name}"; start a separate session instead of mixing engagements`);
          }
          const converted = graphJsonOps(document, { source, evidenceId: artifact.sha256 });
          const scopedGraph = filterOpsToScope(state.scope, converted.ops);
          droppedScope += scopedGraph.dropped;
          graphOps.push(...scopedGraph.ops);
          graphImported = {
            nodes: (graphImported?.nodes ?? 0) + scopedGraph.ops.filter((op) => op.op === 'node.upsert').length,
            edges: (graphImported?.edges ?? 0) + scopedGraph.ops.filter((op) => op.op === 'edge.upsert').length,
          };
          continue;
        }
        if (effectiveFormat === 'observations') {
          const parsed = parseObservationsJsonl(input.text);
          warnings.push(...(parsed.warnings ?? []).map((warning) => `${source}: ${formatWarning(warning)}`));
          for (const observation of parsed.records ?? []) observationRecords.push({ observation, source, evidenceId: artifact.sha256 });
          continue;
        }
        try {
          const parsed = parseAssetRecords(input.text, { format: effectiveFormat, filename: source });
          warnings.push(...(parsed.warnings ?? []).map((warning) => `${source}: ${formatWarning(warning)}`));
          quarantineCount += Array.isArray(parsed.quarantined) ? parsed.quarantined.length : 0;
          for (const entry of Array.isArray(parsed.quarantined) ? parsed.quarantined.slice(0, 20) : []) {
            quarantineSamples.push({ source, ...entry });
          }
          for (const record of parsed.records ?? []) normalized.push({ record, source, evidenceId: artifact.sha256 });
        } catch (error) {
          warnings.push(`${source}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

      const merged = mergeNormalized(normalized.map((entry) => entry.record));
      for (const conflict of merged.conflicts ?? []) {
        warnings.push(`conflict ${conflict.kind ?? ''}:${conflict.key ?? ''} ${conflict.field ?? ''}: ${conflict.first ?? '?'} vs ${conflict.next ?? '?'}`);
      }
      const sourceByKey = new Map();
      for (const entry of normalized) {
        const key = `${entry.record.kind}|${entry.record.key ?? entry.record.value}`;
        if (!sourceByKey.has(key)) sourceByKey.set(key, { source: entry.source, evidenceId: entry.evidenceId });
      }

      for (const record of merged.unique ?? []) {
        if (!recordInScope(state.scope, record)) {
          droppedScope += 1;
          continue;
        }
        const key = `${record.kind}|${record.key ?? record.value}`;
        const meta = sourceByKey.get(key) ?? { source: 'asset-import', evidenceId: undefined };
        const ops = assetOps(state, record, {
          tags: [...new Set([...tags, 'imported'])],
          source: meta.source,
          evidenceId: meta.evidenceId,
        });
        graphOps.push(...ops);
      }

      for (const entry of observationRecords) {
        const ops = observationOps(state, entry.observation, {
          tags: [...new Set([...tags, 'observed'])],
          source: entry.source,
          evidenceId: entry.evidenceId,
        });
        if (ops.length === 0) warnings.push(`${entry.source}: observation kind ${String(entry.observation?.kind)} was not recognized`);
        const scopedObservation = filterOpsToScope(state.scope, ops);
        droppedScope += scopedObservation.dropped;
        graphOps.push(...scopedObservation.ops);
      }

      // Wildcard classification for discovered domains.
      const hostCandidates = new Map();
      for (const node of Object.values(state.nodes)) {
        if (node.kind !== 'host' || !hostInScope(state.scope, node.key, node.attrs?.ips)) continue;
        hostCandidates.set(node.key, {
          key: node.key,
          attrs: node.attrs ?? {},
          tags: node.tags ?? [],
          sources: node.sources ?? [],
        });
      }
      for (const op of graphOps) {
        if (op.op !== 'node.upsert' || op.kind !== 'host' || !hostInScope(state.scope, op.key, op.attrs?.ips)) continue;
        const previous = hostCandidates.get(op.key);
        hostCandidates.set(op.key, {
          key: op.key,
          attrs: { ...(previous?.attrs ?? {}), ...(op.attrs ?? {}) },
          tags: [...new Set([...(previous?.tags ?? []), ...(op.tags ?? [])])],
          sources: [...new Set([...(previous?.sources ?? []), ...(op.sources ?? [])])],
        });
      }
      const zones = new Set();
      for (const host of hostCandidates.values()) {
        const domain = domainForHost(host.key);
        if (domain !== undefined) zones.add(domain);
      }
      for (const record of merged.unique ?? []) {
        if (record.kind === 'domain' && recordInScope(state.scope, record)) zones.add(canonicalHost(recordValue(record)));
      }
      const zoneList = [...zones].sort().slice(0, MAX_WILDCARD_ZONES);
      const wildcardSummary = { zones: 0, confirmed: 0, suspect: 0, cleared: 0, inconclusive: 0, hostsSuspect: 0, skipped: 0 };
      if (probeWildcard && zoneList.length > 0) {
        if ((state.scope?.allow?.length ?? 0) === 0 && cfg.requireScope) {
          warnings.push('wildcard probing skipped: no authorized scope is set (call atkbrain_scope first)');
          graphOps.push(taskNodeOp(state, {
            actionType: 'set_scope',
            targetId: 'engagement',
            label: 'Set engagement scope before wildcard DNS probing',
            priority: 100,
            why: ['wildcard probing is a network action and requires an allow list'],
            toolClass: 'setup',
            risk: 'none',
          }));
        } else {
          for (const zone of zoneList) {
            const allowed = await zoneScopeAllowed({ deps: runtime, state, config: cfg, zone, signal: exec.signal });
            if (!allowed.allowed) {
              wildcardSummary.skipped += 1;
              warnings.push(`wildcard probe skipped for ${zone}: ${allowed.reason}`);
              continue;
            }
            let result;
            try {
              result = await probeWildcardZone(runtime.resolver, zone, {
                probes: cfg.wildcardProbes,
                rounds: cfg.wildcardRounds,
                timeoutMs: cfg.dnsTimeoutMs,
                signal: exec.signal,
              });
            } catch (error) {
              warnings.push(`wildcard probe failed for ${zone}: ${error instanceof Error ? error.message : String(error)}`);
              continue;
            }
            wildcardSummary.zones += 1;
            if (result.status in wildcardSummary) wildcardSummary[result.status] += 1;
            graphOps.push(nodeOpForWildcard(zone, result));
            // Classify hosts under this zone (bounded).
            const hosts = [...hostCandidates.values()]
              .filter((host) => hostUnderZone(host.key, zone))
              .slice(0, MAX_WILDCARD_HOSTS);
            const classifications = await mapLimit(hosts, Math.max(1, Math.min(6, cfg.dnsConcurrency)), async (host) => {
              let resolved;
              try {
                resolved = await runtime.resolver.resolveHost(host.key, { signal: exec.signal });
              } catch {
                return undefined;
              }
              const answers = {
                a: resolved?.a ?? [],
                aaaa: resolved?.aaaa ?? [],
                cname: resolved?.cname ?? [],
              };
              const classification = classifyHostAnswers(host.key, answers, { zone, ...result });
              return { host, answers, classification };
            }, exec.signal);
            for (const entry of classifications) {
              if (entry === undefined) continue;
              const { host, answers, classification } = entry;
              const ips = [...new Set([...(answers.a ?? []), ...(answers.aaaa ?? [])])];
              const wildcardStatus = classification.status === 'unknown'
                ? (result.status === 'confirmed' ? 'suspect' : 'unknown')
                : classification.status;
              if (wildcardStatus === 'suspect') wildcardSummary.hostsSuspect += 1;
              graphOps.push(hostNodeOp(host.key, {
                declared: host.attrs?.declared === true,
                wildcardStatus,
                ips,
                tags: host.tags,
                sources: host.sources,
                criticality: host.attrs?.criticality,
                crownJewel: host.attrs?.crownJewel === true,
                attrs: {
                  ...(host.attrs ?? {}),
                  wildcardZone: zone,
                  wildcardConfidence: classification.confidence ?? result.confidence,
                },
              }));
              for (const ip of ips) {
                graphOps.push(ipNodeOp(ip, { sources: host.sources }));
                graphOps.push(link(ref('host', host.key), ref('ip', ip), 'resolves_to', { confidence: 0.75 }));
              }
            }
          }
        }
      }

      const addedNodes = merged.unique?.length ?? 0;
      const addedObservations = observationRecords.length;
      const stats = state.stats ?? {};
      const rawCount = merged.stats?.input ?? normalized.length;
      const duplicateCount = merged.stats?.duplicates ?? 0;
      const conflictCount = merged.stats?.conflicts ?? (Array.isArray(merged.conflicts) ? merged.conflicts.length : 0);
      graphOps.push({
        op: 'stats.patch',
        patch: {
          importedArtifacts: (stats.importedArtifacts ?? 0) + artifacts.length,
          rawEntries: (stats.rawEntries ?? 0) + rawCount + observationRecords.length,
          unique: (stats.unique ?? 0) + addedNodes + observationRecords.length,
          collapsed: (stats.collapsed ?? 0) + duplicateCount,
          quarantined: (stats.quarantined ?? 0) + quarantineCount,
          conflicts: (stats.conflicts ?? 0) + conflictCount,
          wildcardZones: (stats.wildcardZones ?? 0) + wildcardSummary.zones,
          suspects: (stats.suspects ?? 0) + wildcardSummary.hostsSuspect,
        },
      });
      graphOps.push(audit(
        TOOL_NAMES.ingest,
        'ingest',
        artifacts.map((artifact) => artifact.relative ?? artifact.path).filter(Boolean).slice(0, 5).join(', ') || 'inline',
        `${addedNodes} unique assets, ${addedObservations} observations, ${wildcardSummary.zones} wildcard zones`,
        artifacts.map((artifact) => artifact.sha256).filter(Boolean).slice(0, 20),
      ));

      const wildcardText = wildcardSummary.zones > 0
        ? ` Wildcard DNS: ${wildcardSummary.zones} zone(s), ${wildcardSummary.confirmed} confirmed, ${wildcardSummary.suspect} suspect, ${wildcardSummary.cleared} cleared, ${wildcardSummary.inconclusive} inconclusive; ${wildcardSummary.hostsSuspect} host(s) marked suspect.`
        : (zoneList.length > 0 && probeWildcard ? ' Wildcard DNS: not classified (see warnings).' : '');
      let projectedState = state;
      try {
        projectedState = applyOps(state, graphOps, new Date().toISOString());
      } catch {
        // The real projection will report a cap/malformation; keep the summary
        // usable instead of failing after the work was already done.
      }
      const summary = (artifacts.length === 0
        ? 'No artifact was imported; see warnings.'
        : `Imported ${artifacts.length} artifact(s): ${rawCount} raw candidate(s) -> ${merged.unique?.length ?? 0} unique, ${duplicateCount} duplicate(s), ${quarantineCount} quarantined; ${addedObservations} observation(s).`)
        + (capturedFiles > 0 ? ` ${capturedFiles} captured file(s) stored as evidence and not expanded into hosts.` : '')
        + (droppedScope > 0 ? ` Left ${droppedScope} out-of-scope name(s) out of the graph.` : '')
        + (graphImported !== null ? ` Merged graph-json: ${graphImported.nodes} node(s), ${graphImported.edges} edge(s).` : '')
        + wildcardText
        + ` Graph after this call: ${Object.keys(projectedState.nodes).length} node(s), ${Object.keys(projectedState.edges).length} edge(s).`
        + (warnings.length > 0 ? `\nWarnings (${warnings.length}): ${warnings.slice(0, 8).join('; ')}` : '')
        + `\nNext: review the attack graph, then call atkbrain_query action=frontier.`;

      return {
        summary,
        ops: graphOps,
        details: {
          artifacts,
          dedupe: {
            raw: rawCount,
            unique: merged.unique?.length ?? 0,
            duplicates: duplicateCount,
            quarantined: quarantineCount,
            conflicts: merged.conflicts ?? [],
          },
          observations: addedObservations,
          wildcard: wildcardSummary,
          graphImported,
          warnings,
          quarantinedSamples: quarantineSamples.slice(0, 20),
        },
      };
    },
  });
}

function hostUnderZone(host, zone) {
  return host === zone || host.endsWith(`.${zone}`);
}

function nodeOpForWildcard(zone, result) {
  return {
    op: 'node.upsert',
    kind: 'wildcard_zone',
    key: `*.${zone}`,
    label: `*.${zone}`,
    attrs: {
      zone,
      signature: result.signature ?? {},
      probes: Array.isArray(result.probes) ? result.probes.slice(0, 12) : [],
      cdn: result.cdn === true,
      apex: result.apex === true,
      confidence: result.confidence ?? 0,
      reason: result.reason ?? null,
    },
    status: result.status ?? 'inconclusive',
    confidence: result.confidence ?? 0,
  };
}
