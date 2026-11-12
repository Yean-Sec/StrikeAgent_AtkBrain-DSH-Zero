/**
 * Pure state fold for the attack-graph projection.
 *
 * Every tool returns `{summary, ops}` and `presentationMeta` copies `ops` into
 * the durable `tool/result.meta`. The projection calls `applyOps` for each such
 * result, in log order. `applyOps` must be synchronous, deterministic and free
 * of I/O: resume, fork and replay all depend on that.
 */
import {
  ACCESS_STATUS_RANK,
  CREDENTIAL_VALIDITY_RANK,
  DATA_STATUS_RANK,
  EDGE_KINDS,
  FINDING_STATUS_RANK,
  INTENT_STATUS_RANK,
  LESSON_STATUS_RANK,
  LOOP_STATUS_RANK,
  SELF_TEAM_STATUS_RANK,
  MCP_STATUS_RANK,
  COVERAGE_STATUS_RANK,
  HYPOTHESIS_STATUS_RANK,
  SKILL_STATUS_RANK,
  NODE_KINDS,
  STATE_SCHEMA,
  VERIFICATION_RANK,
} from './constants.js';
import {
  clone,
  edgeId,
  isPlainObject,
  nodeId,
  nowIso,
  shortHash,
  stableStringify,
  unionStrings,
  uniqueStrings,
} from './util.js';

const HARD_MAX_NODES = 100000;
const HARD_MAX_EDGES = 300000;
const HARD_MAX_OPS = 50000;
const DEFAULT_KEY = 'unknown';

/** Build a brand-new empty graph state. */
export function emptyState() {
  return {
    schema: STATE_SCHEMA,
    seq: 0,
    engagement: null,
    scope: {
      allow: [],
      deny: [],
      roe: {
        maxQps: null,
        maxHostsPerAction: null,
        maxPortsPerAction: null,
        techniques: ['T0', 'T1'],
      },
      updatedAt: null,
      approvedAt: null,
      approvalId: null,
    },
    nodes: {},
    edges: {},
    aliases: {},
    audit: [],
    stats: {
      importedArtifacts: 0,
      rawEntries: 0,
      unique: 0,
      collapsed: 0,
      quarantined: 0,
      conflicts: 0,
      wildcardZones: 0,
      suspects: 0,
      stubNodes: 0,
      refused: 0,
    },
    lastAction: null,
  };
}

/** Status used when a tool does not supply one. */
function defaultStatus(kind) {
  if (kind === 'finding') return 'candidate';
  if (kind === 'access') return 'attempted';
  if (kind === 'credential') return 'untested';
  if (kind === 'data') return 'claimed';
  if (kind === 'task') return 'pending';
  if (kind === 'wildcard_zone') return 'inconclusive';
  if (kind === 'loop') return 'running';
  if (kind === 'intent') return 'open';
  if (kind === 'supervision') return 'recorded';
  if (kind === 'lesson') return 'active';
  if (kind === 'self_team') return 'active';
  if (kind === 'skill') return 'active';
  if (kind === 'mcp') return 'checking';
  if (kind === 'coverage') return 'open';
  if (kind === 'hypothesis') return 'open';
  if (kind === 'honeypot') return 'active';
  return 'unknown';
}

/** One fresh node with all public fields populated. */
export function makeNode(kind, key, at = nowIso()) {
  const canonicalKind = NODE_KINDS.includes(kind) ? kind : 'unknown';
  const canonicalKey = typeof key === 'string' && key.length > 0 ? key : DEFAULT_KEY;
  return {
    id: nodeId(canonicalKind, canonicalKey),
    kind: canonicalKind,
    key: canonicalKey,
    label: canonicalKey,
    status: defaultStatus(canonicalKind),
    confidence: 0.5,
    attrs: {},
    tags: [],
    sources: [],
    evidenceIds: [],
    verification: 'unverified',
    firstSeen: at,
    lastSeen: at,
  };
}

/** Resolve a `{kind,key}` reference or an existing id, following aliases. */
export function resolveNodeId(state, ref) {
  if (ref === undefined || ref === null) return undefined;
  let id;
  if (typeof ref === 'string') {
    id = ref;
  } else if (isPlainObject(ref)) {
    if (typeof ref.id === 'string' && state.nodes[ref.id] !== undefined) id = ref.id;
    else if (typeof ref.kind === 'string' && typeof ref.key === 'string') {
      const byKey = nodeId(ref.kind, ref.key);
      const named = state.nodes[ref.key];
      if (state.nodes[byKey] !== undefined) id = byKey;
      else if (named !== undefined && named.kind === ref.kind) id = ref.key;
      else id = byKey;
    }
  }
  if (id === undefined) return undefined;
  let resolved = id;
  for (let hop = 0; hop < 8; hop += 1) {
    const next = state.aliases[resolved];
    if (next === undefined) return resolved;
    resolved = next;
  }
  return resolved;
}

/** Choose the stronger node status for a merge. */
function mergeStatus(kind, existing, incoming) {
  if (incoming === undefined || incoming === null) return existing;
  if (existing === undefined || existing === null) return incoming;
  if (kind === 'loop' || kind === 'intent' || kind === 'lesson' || kind === 'self_team' || kind === 'skill' || kind === 'mcp' || kind === 'coverage' || kind === 'hypothesis' || kind === 'honeypot') return incoming;
  const terminal = new Set(['fixed', 'lost', 'invalid', 'expired', 'cleared', 'refuted', 'merged']);
  if (terminal.has(incoming)) return incoming;
  const rankOf = (status) => {
    if (kind === 'finding') return FINDING_STATUS_RANK[status] ?? 0;
    if (kind === 'access') return ACCESS_STATUS_RANK[status] ?? 0;
    if (kind === 'credential') return CREDENTIAL_VALIDITY_RANK[status] ?? 0;
    if (kind === 'data') return DATA_STATUS_RANK[status] ?? 0;
    if (kind === 'wildcard_zone') return { cleared: 0, inconclusive: 1, suspect: 2, confirmed: 3 }[status] ?? 0;
    if (kind === 'loop') return LOOP_STATUS_RANK[status] ?? 0;
    if (kind === 'intent') return INTENT_STATUS_RANK[status] ?? 0;
    if (kind === 'lesson') return LESSON_STATUS_RANK[status] ?? 0;
    if (kind === 'self_team') return SELF_TEAM_STATUS_RANK[status] ?? 0;
    if (kind === 'skill') return SKILL_STATUS_RANK[status] ?? 0;
    if (kind === 'mcp') return MCP_STATUS_RANK[status] ?? 0;
    if (kind === 'coverage') return COVERAGE_STATUS_RANK[status] ?? 0;
    if (kind === 'hypothesis') return HYPOTHESIS_STATUS_RANK[status] ?? 0;
    return 0;
  };
  return rankOf(incoming) >= rankOf(existing) ? incoming : existing;
}

/** Choose a display label, keeping an existing one unless it is just the key. */
function mergeLabel(existing, incoming) {
  const label = typeof incoming === 'string' ? incoming.trim() : '';
  if (label.length === 0) return existing;
  if (existing === undefined || existing.length === 0) return label;
  return existing;
}

const ARRAY_ATTR_KEYS = new Set(['tags', 'sources', 'evidenceIds', 'ips', 'cnames', 'names', 'paths', 'cves', 'cwe', 'aliases', 'segments', 'probes', 'samples', 'hashes', 'parameters', 'contexts']);

/** Merge attrs defensively: arrays union, objects shallow-merge, scalars incoming-wins. */
function mergeAttrs(existing, incoming, depth = 0) {
  if (!isPlainObject(incoming)) return existing ?? {};
  const base = isPlainObject(existing) ? { ...existing } : {};
  for (const [key, value] of Object.entries(incoming)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      if (ARRAY_ATTR_KEYS.has(key) && Array.isArray(base[key])) {
        base[key] = key === 'probes' || key === 'samples'
          ? value.slice(0, 200)
          : unionStrings(base[key].filter((entry) => typeof entry === 'string'), value.filter((entry) => typeof entry === 'string'));
        if (base[key].length === 0 && value.length === 0) base[key] = [];
      } else {
        base[key] = clone(value);
      }
      continue;
    }
    if (isPlainObject(value) && depth < 3) {
      base[key] = mergeAttrs(base[key], value, depth + 1);
      continue;
    }
    if (isPlainObject(value)) {
      base[key] = clone(value);
      continue;
    }
    base[key] = value;
  }
  return base;
}

/** Merge a node op into an existing node without ever mutating either input. */
export function mergeNode(existing, incoming, kind, key, at) {
  const next = {
    ...existing,
    kind,
    key,
    label: mergeLabel(existing.label, incoming.label),
    status: mergeStatus(kind, existing.status, incoming.status),
    confidence: Math.max(Number(existing.confidence) || 0, Number(incoming.confidence) || 0),
    verification: (VERIFICATION_RANK[incoming.verification] ?? 0) > (VERIFICATION_RANK[existing.verification] ?? 0)
      ? incoming.verification
      : existing.verification,
    attrs: mergeAttrs(existing.attrs, incoming.attrs),
    tags: unionStrings(existing.tags, incoming.tags),
    sources: unionStrings(existing.sources, incoming.sources),
    evidenceIds: unionStrings(existing.evidenceIds, incoming.evidenceIds),
    firstSeen: earlierIso(existing.firstSeen, incoming.firstSeen ?? at),
    lastSeen: laterIso(existing.lastSeen, incoming.lastSeen ?? at),
  };
  return next;
}

function earlierIso(a, b) {
  if (typeof a !== 'string' || a.length === 0) return b;
  if (typeof b !== 'string' || b.length === 0) return a;
  return a <= b ? a : b;
}

function laterIso(a, b) {
  if (typeof a !== 'string' || a.length === 0) return b;
  if (typeof b !== 'string' || b.length === 0) return a;
  return a >= b ? a : b;
}

/** Turn a raw node op into a normalized node record (without merging). */
function nodeFromOp(op, at) {
  const kind = NODE_KINDS.includes(op.kind) ? op.kind : 'unknown';
  const key = typeof op.key === 'string' && op.key.length > 0
    ? op.key
    : typeof op.id === 'string' ? op.id : DEFAULT_KEY;
  const node = makeNode(kind, key, at);
  node.label = typeof op.label === 'string' && op.label.trim().length > 0 ? op.label.trim() : node.label;
  if (typeof op.status === 'string' && op.status.length > 0) node.status = op.status;
  if (Number.isFinite(op.confidence)) node.confidence = Math.max(0, Math.min(1, Number(op.confidence)));
  if (isPlainObject(op.attrs)) node.attrs = clone(op.attrs);
  if (Array.isArray(op.tags)) node.tags = uniqueStrings(op.tags.filter((tag) => typeof tag === 'string'));
  if (Array.isArray(op.sources)) node.sources = uniqueStrings(op.sources);
  if (Array.isArray(op.evidenceIds)) node.evidenceIds = uniqueStrings(op.evidenceIds);
  if (typeof op.verification === 'string') node.verification = op.verification;
  if (typeof op.firstSeen === 'string') node.firstSeen = op.firstSeen;
  if (typeof op.lastSeen === 'string') node.lastSeen = op.lastSeen;
  return node;
}

/** Add or merge one node op into `nodes`/`aliases`. */
function upsertNodeOp(state, op, at) {
  const incoming = nodeFromOp(op, at);
  let id = incoming.id;
  let existing = state.nodes[id];
  if (existing === undefined) {
    // A previous merge may have retired this identity.
    const alias = state.aliases[id];
    if (alias !== undefined && state.nodes[alias] !== undefined) {
      id = alias;
      existing = state.nodes[id];
      incoming.id = id;
    }
  }
  if (existing === undefined) {
    state.nodes[id] = incoming;
    return id;
  }
  state.nodes[id] = mergeNode(existing, incoming, existing.kind, existing.key, at);
  return id;
}

/** Create a stub node so an edge never dangles because of op ordering. */
function ensureStubNode(state, id, ref, at) {
  if (state.nodes[id] !== undefined) return;
  const kind = isPlainObject(ref) && typeof ref.kind === 'string' ? ref.kind : 'unknown';
  const key = isPlainObject(ref) && typeof ref.key === 'string' ? ref.key : (typeof ref === 'string' ? ref : id);
  const node = makeNode(kind, key, at);
  node.attrs = { stub: true };
  state.nodes[id] = node;
  state.stats.stubNodes = (state.stats.stubNodes ?? 0) + 1;
}

/** Merge edge attributes and provenance. */
function mergeEdge(existing, incoming, at) {
  return {
    ...existing,
    confidence: Math.max(Number(existing.confidence) || 0, Number(incoming.confidence) || 0),
    attrs: mergeAttrs(existing.attrs, incoming.attrs),
    evidenceIds: unionStrings(existing.evidenceIds, incoming.evidenceIds),
    firstSeen: earlierIso(existing.firstSeen, incoming.firstSeen ?? at),
    lastSeen: laterIso(existing.lastSeen, incoming.lastSeen ?? at),
  };
}

/** Upsert one edge op, creating endpoint stubs when needed. */
function upsertEdgeOp(state, op, at) {
  const kind = EDGE_KINDS.includes(op.kind) ? op.kind : undefined;
  if (kind === undefined) return false;
  if (!isPlainObject(op.from) || !isPlainObject(op.to) && typeof op.to !== 'string') {
    // Accept {from:{kind,key}, to:{kind,key}} and also raw ids for internal use.
  }
  const fromId = resolveNodeId(state, op.from);
  const toId = resolveNodeId(state, op.to);
  if (fromId === undefined || toId === undefined || fromId === toId) return false;
  ensureStubNode(state, fromId, op.from, at);
  ensureStubNode(state, toId, op.to, at);
  const id = edgeId(fromId, kind, toId);
  const incoming = {
    id,
    from: fromId,
    to: toId,
    kind,
    confidence: Number.isFinite(op.confidence) ? Math.max(0, Math.min(1, Number(op.confidence))) : 0.6,
    attrs: isPlainObject(op.attrs) ? clone(op.attrs) : {},
    evidenceIds: Array.isArray(op.evidenceIds) ? uniqueStrings(op.evidenceIds.filter((entry) => typeof entry === 'string')) : [],
    firstSeen: typeof op.firstSeen === 'string' ? op.firstSeen : at,
    lastSeen: typeof op.lastSeen === 'string' ? op.lastSeen : at,
  };
  const existing = state.edges[id];
  if (existing === undefined) state.edges[id] = incoming;
  else state.edges[id] = mergeEdge(existing, incoming, at);
  return true;
}

/** Re-point edges and record the alias for a merge. */
function mergeNodeOp(state, op, at) {
  const fromId = resolveNodeId(state, op.from);
  const intoId = resolveNodeId(state, op.into);
  if (fromId === undefined || intoId === undefined || fromId === intoId) return false;
  const from = state.nodes[fromId];
  const into = state.nodes[intoId] ?? makeNode(isPlainObject(op.into) ? op.into.kind : 'unknown', isPlainObject(op.into) ? op.into.key : intoId, at);
  if (state.nodes[intoId] === undefined) state.nodes[intoId] = into;
  if (from !== undefined) {
    state.nodes[intoId] = mergeNode(into, from, into.kind, into.key, at);
    state.nodes[fromId] = {
      ...from,
      status: 'merged',
      attrs: { ...from.attrs, mergedInto: intoId, mergeReason: op.reason ?? 'duplicate identity' },
      lastSeen: at,
    };
  }
  state.aliases[fromId] = intoId;
  // Re-point existing edges and drop self/duplicate edges.
  for (const [id, edge] of Object.entries(state.edges)) {
    if (edge.from !== fromId && edge.to !== fromId) continue;
    const nextFrom = edge.from === fromId ? intoId : edge.from;
    const nextTo = edge.to === fromId ? intoId : edge.to;
    if (nextFrom === nextTo) {
      delete state.edges[id];
      continue;
    }
    const nextId = edgeId(nextFrom, edge.kind, nextTo);
    if (nextId !== id && state.edges[nextId] !== undefined) {
      state.edges[nextId] = mergeEdge(state.edges[nextId], { ...edge, id: nextId, from: nextFrom, to: nextTo }, at);
      delete state.edges[id];
      continue;
    }
    delete state.edges[id];
    state.edges[nextId] = { ...edge, id: nextId, from: nextFrom, to: nextTo, lastSeen: at };
  }
  return true;
}

/** Add one audit entry with a hash chain. */
function appendAudit(state, entry, at, limit = 500) {
  const prev = state.audit[state.audit.length - 1];
  const prevHash = prev?.hash ?? '';
  const body = {
    id: `aud_${shortHash(`${prevHash}\u001f${at}\u001f${entry.tool}\u001f${entry.action}\u001f${entry.target ?? ''}`, 18)}`,
    at: entry.at ?? at,
    tool: entry.tool ?? 'unknown',
    action: entry.action ?? 'unknown',
    target: entry.target ?? null,
    result: entry.result ?? null,
    evidenceIds: Array.isArray(entry.evidenceIds) ? uniqueStrings(entry.evidenceIds) : [],
    prevHash,
  };
  body.hash = shortHash(stableStringify(body), 32);
  state.audit.push(body);
  const max = Number.isInteger(limit) && limit > 0 ? limit : 500;
  if (state.audit.length > max) state.audit.splice(0, state.audit.length - max);
  state.lastAction = body;
}

/** Merge scope entries by `type|canonical`, deny wins on duplicate input. */
function mergeScopeEntries(existing, incoming) {
  const byKey = new Map();
  for (const entry of [...(Array.isArray(existing) ? existing : []), ...(Array.isArray(incoming) ? incoming : [])]) {
    if (!isPlainObject(entry) || typeof entry.type !== 'string') continue;
    const value = typeof entry.value === 'string' ? entry.value : entry.canonical;
    if (typeof value !== 'string' || value.length === 0) continue;
    const canonical = typeof entry.canonical === 'string' ? entry.canonical : value;
    byKey.set(`${entry.type}\u001f${canonical}`, {
      type: entry.type,
      value: canonical,
      canonical,
      ...(Array.isArray(entry.ports) && entry.ports.length > 0 ? { ports: entry.ports.filter((port) => Number.isInteger(port)) } : {}),
      ...(typeof entry.note === 'string' ? { note: entry.note } : {}),
    });
  }
  return [...byKey.values()].sort((a, b) => `${a.type}\u001f${a.canonical}`.localeCompare(`${b.type}\u001f${b.canonical}`));
}

/**
 * Fold one batch of ops into a new state.
 *
 * @param {object} state current projection state (never mutated)
 * @param {object[]} ops ordered op list from a tool result
 * @param {string} at ISO timestamp carried by the result meta
 * @returns {object} the next state, or the same reference when nothing changed
 */
export function applyOps(state, ops, at = nowIso()) {
  if (!Array.isArray(ops) || ops.length === 0) return state;
  if (ops.length > HARD_MAX_OPS) throw new Error(`too many ops in one result: ${ops.length} > ${HARD_MAX_OPS}`);
  const next = {
    ...state,
    engagement: state.engagement === null ? null : clone(state.engagement),
    scope: {
      ...state.scope,
      allow: clone(state.scope?.allow ?? []),
      deny: clone(state.scope?.deny ?? []),
      roe: clone(state.scope?.roe ?? {}),
    },
    nodes: { ...state.nodes },
    edges: { ...state.edges },
    aliases: { ...state.aliases },
    audit: state.audit.slice(),
    stats: { ...state.stats },
  };
  let changed = false;
  let sawMutation = false;
  let lastAudit = null;

  for (const op of ops) {
    if (!isPlainObject(op) || typeof op.op !== 'string') continue;
    switch (op.op) {
      case 'engagement.set': {
        if (!isPlainObject(op.engagement)) break;
        next.engagement = mergeEngagement(next.engagement, op.engagement);
        changed = true;
        sawMutation = true;
        break;
      }
      case 'scope.set': {
        if (op.replaceAllow === true) next.scope.allow = clone(Array.isArray(op.allow) ? op.allow : []);
        else if (op.allow !== undefined) next.scope.allow = mergeScopeEntries(next.scope.allow, op.allow);
        if (op.replaceDeny === true) next.scope.deny = clone(Array.isArray(op.deny) ? op.deny : []);
        else if (op.deny !== undefined) next.scope.deny = mergeScopeEntries(next.scope.deny, op.deny);
        if (isPlainObject(op.roe)) next.scope.roe = { ...next.scope.roe, ...clone(op.roe) };
        next.scope.updatedAt = op.updatedAt ?? at;
        if (typeof op.approvedAt === 'string') next.scope.approvedAt = op.approvedAt;
        if (typeof op.approvalId === 'string') next.scope.approvalId = op.approvalId;
        changed = true;
        sawMutation = true;
        break;
      }
      case 'stats.patch': {
        if (!isPlainObject(op.patch)) break;
        for (const [key, value] of Object.entries(op.patch)) {
          if (typeof value === 'number' && Number.isFinite(value)) next.stats[key] = value;
        }
        changed = true;
        break;
      }
      case 'node.upsert': {
        upsertNodeOp(next, op, at);
        changed = true;
        sawMutation = true;
        break;
      }
      case 'edge.upsert': {
        if (upsertEdgeOp(next, op, at)) {
          changed = true;
          sawMutation = true;
        }
        break;
      }
      case 'node.merge': {
        if (mergeNodeOp(next, op, at)) {
          changed = true;
          sawMutation = true;
        }
        break;
      }
      case 'audit': {
        if (!isPlainObject(op.entry)) break;
        appendAudit(next, op.entry, at);
        lastAudit = next.lastAction;
        changed = true;
        break;
      }
      default:
        break;
    }
  }

  if (!changed) return state;
  if (Object.keys(next.nodes).length > HARD_MAX_NODES) {
    throw new Error(`graph node cap exceeded: ${Object.keys(next.nodes).length} > ${HARD_MAX_NODES}`);
  }
  if (Object.keys(next.edges).length > HARD_MAX_EDGES) {
    throw new Error(`graph edge cap exceeded: ${Object.keys(next.edges).length} > ${HARD_MAX_EDGES}`);
  }
  next.seq = (Number(state.seq) || 0) + 1;
  if (sawMutation || lastAudit === null) {
    // Tools that mutate graph state normally also append an audit op. Keep a
    // synthetic marker when they did not, so the UI always has a last action.
    if (lastAudit === null && next.audit.length === (state.audit?.length ?? 0)) {
      appendAudit(next, { tool: 'atkbrain', action: 'graph.update', target: null }, at, next.audit.length + 1);
    }
  }
  next.lastAction = next.audit[next.audit.length - 1] ?? state.lastAction ?? null;
  return next;
}

/** Merge a tool-supplied engagement descriptor into the current one. */
function mergeEngagement(existing, incoming) {
  const base = isPlainObject(existing) ? existing : {};
  const next = { ...base, ...clone(incoming) };
  if (isPlainObject(base.roe) || isPlainObject(incoming.roe)) {
    next.roe = { ...(isPlainObject(base.roe) ? base.roe : {}), ...(isPlainObject(incoming.roe) ? clone(incoming.roe) : {}) };
  }
  return next;
}

/** Create a minimal `audit` op; tools use this to keep the trail consistent. */
export function auditOp(tool, action, target = null, result = null, evidenceIds = []) {
  return { op: 'audit', entry: { tool, action, target, result, evidenceIds } };
}

/** Convenience wrapper for one node op. */
export function nodeOp(kind, key, label, attrs = {}, extra = {}) {
  return {
    op: 'node.upsert',
    kind,
    key,
    label,
    attrs,
    ...extra,
  };
}

/** Convenience wrapper for one edge op. */
export function edgeOp(from, to, kind, attrs = {}, extra = {}) {
  return {
    op: 'edge.upsert',
    from,
    to,
    kind,
    attrs,
    ...extra,
  };
}
