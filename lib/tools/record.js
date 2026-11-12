/**
 * `atkbrain_record` — record findings, credentials, access, data evidence,
 * pivots, tasks and chain steps discovered by the agent or operator.
 *
 * Raw secrets and raw PII are rejected by construction: credentials accept a
 * mask/fingerprint only, and data samples are redacted here before they can
 * enter the projection state.
 */
import { autoVerifyFindings } from '../auto-verify.js';
import { wakeEngagementTeams, notifyResidentTeams } from '../native-teams.js';
import { pendingEscalations } from '../escalation-queue.js';
import { applyOps } from '../ops.js';
import { pendingFindings } from '../verify-queue.js';
import path from 'node:path';
import { stat } from 'node:fs/promises';

import { EDGE_KINDS, NODE_KINDS, SEVERITIES, TOOL_NAMES } from '../constants.js';
import { findingAttrs, fromInput as resolveCvss } from '../cvss31.js';
import { canonicalIp, parseCidr } from '../cidr.js';
import { publicAttrs, redactRow } from '../redact.js';
import { headerProductVersions, isHardeningFinding, hardeningScoreRefusal } from '../finding-classification.js';
import { recordedHeaderFindings } from '../exposure.js';
import { validateFindingProof } from '../proof.js';
import { canonicalHost } from '../scope.js';
import {
  fileSha256,
  invalid,
  isPlainObject,
  nodeId,
  nowIso,
  resolvePath,
} from '../util.js';
import { mergeLedgerAttrs } from '../endpoint-vocab.js';
import {
  accessNodeOp,
  chainStepNodeOp,
  cidrNodeOp,
  credentialNodeOp,
  dataNodeOp,
  domainNodeOp,
  evidenceNodeOp,
  findingNodeOp,
  hostNodeOp,
  ipNodeOp,
  link,
  pivotNodeOp,
  ref,
  serviceNodeOp,
  taskNodeOp,
  techNodeOp,
  webappNodeOp,
} from './build.js';
import {
  assertArgs,
  audit,
  optionalString,
  registerAtkTool,
  requireArray,
  requireEnum,
  requireString,
} from './common.js';

const MAX_NODES = 500;
const MAX_EDGES = 1000;
const MAX_STATUS = 100;
const MAX_EVIDENCE = 50;

const NODE_KINDS_SET = new Set(NODE_KINDS);
const EDGE_KINDS_SET = new Set(EDGE_KINDS);

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  properties: {
    nodes: {
      type: 'array',
      description: 'Nodes to upsert. Each: {kind, key?, label?, attrs?, status?, confidence?, tags?, verification?, evidenceIds?}.',
      items: { type: 'object', additionalProperties: true },
    },
    edges: {
      type: 'array',
      description: 'Edges to upsert. Each: {from:{kind,key}, to:{kind,key}, kind, confidence?, attrs?, evidenceIds?}.',
      items: { type: 'object', additionalProperties: true },
    },
    statusChanges: {
      type: 'array',
      description: 'Lifecycle changes for existing nodes: {id, status, verification?, note?}.',
      items: { type: 'object', additionalProperties: true },
    },
    evidence: {
      type: 'array',
      description: 'Evidence artifacts: {path, sha256?, mediaType?, label?, subject?:{kind,key}}. The file is hashed; raw content is never stored.',
      items: { type: 'object', additionalProperties: true },
    },
    note: { type: 'string', description: 'Operator/analyst note recorded in the audit trail.' },
    cvssVector: { type: 'string', description: 'NVD CVSS v3.1 Base vector for a finding, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.' },
    cvss: { type: 'object', additionalProperties: true, description: 'CVSS v3.1 Base metrics {AV,AC,PR,UI,S,C,I,A}; the score/rating are computed, never supplied.' },
  },
};

const SECRET_ALLOWED = new Set(['secretMask', 'secretFp', 'secretRef']);

function sanitizeAttrs(kind, attrs) {
  if (!isPlainObject(attrs)) return {};
  const out = {};
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'rows' && kind === 'data') continue;
    if (/secret|password|passwd|pwd|token|apikey|api_key|private_key|cookie|authorization/i.test(key) && !SECRET_ALLOWED.has(key)) {
      continue;
    }
    if (value === undefined) continue;
    out[key] = value;
  }
  return out;
}

function requireKey(kind, key, derived) {
  const value = typeof key === 'string' && key.trim().length > 0 ? key.trim() : derived;
  if (typeof value !== 'string' || value.length === 0) {
    invalid(`node kind "${kind}" requires a key or the fields needed to derive one`);
  }
  return value;
}

function canonicalKeyFor(kind, input) {
  const attrs = isPlainObject(input.attrs) ? input.attrs : {};
  if (kind === 'host') return canonicalHost(input.key ?? attrs.fqdn ?? attrs.host ?? '');
  if (kind === 'domain') return canonicalHost(input.key ?? attrs.name ?? attrs.domain ?? '');
  if (kind === 'ip') return canonicalIp(input.key ?? attrs.addr ?? attrs.ip ?? '') ?? '';
  if (kind === 'cidr') return parseCidr(input.key ?? attrs.cidr ?? attrs.network ?? '')?.canonical ?? '';
  if (kind === 'tech') return input.key ?? [attrs.vendor, attrs.product, attrs.version].filter(Boolean).join('/');
  if (kind === 'webapp') return input.key ?? attrs.url;
  if (kind === 'service') {
    if (typeof input.key === 'string' && input.key.length > 0) return input.key;
    const endpoint = attrs.endpoint ?? attrs.host ?? attrs.ip;
    const port = Number(attrs.port);
    if (typeof endpoint === 'string' && Number.isInteger(port)) return `${attrs.transport ?? 'tcp'}:${endpoint}:${port}`;
    return undefined;
  }
  return input.key;
}

function redactSamples(attrs, state) {
  const out = { ...attrs };
  const raw = Array.isArray(attrs.rows) ? attrs.rows : undefined;
  if (raw !== undefined) {
    out.samples = raw.slice(0, 10).map((row) => {
      const redacted = redactRow(row, { salt: state.engagement?.name ?? 'atkbrain', classHint: attrs.dataClass });
      return { fields: Object.keys(redacted.masked), masked: redacted.masked, hashes: redacted.hashes };
    });
    delete out.rows;
  } else if (Array.isArray(attrs.samples)) {
    out.samples = attrs.samples.slice(0, 10).map((sample) => {
      if (!isPlainObject(sample)) return { masked: { value: '[sample]' }, hashes: {} };
      if (isPlainObject(sample.masked) || isPlainObject(sample.hashes)) {
        return {
          ...(Array.isArray(sample.fields) ? { fields: sample.fields.slice(0, 50) } : {}),
          ...(isPlainObject(sample.masked) ? { masked: sample.masked } : {}),
          ...(isPlainObject(sample.hashes) ? { hashes: sample.hashes } : {}),
          ...(typeof sample.rowHash === 'string' ? { rowHash: sample.rowHash } : {}),
        };
      }
      const redacted = redactRow(sample, { salt: state.engagement?.name ?? 'atkbrain', classHint: attrs.dataClass });
      return { fields: Object.keys(redacted.masked), masked: redacted.masked, hashes: redacted.hashes };
    });
  }
  if (Array.isArray(attrs.hashes)) out.hashes = attrs.hashes.slice(0, 50);
  return out;
}

const PAGE_ATTRS = ['html', 'body', 'text', 'source', 'script', 'content', 'js'];

function headerObservationOps(state, op) {
  const headers = op.attrs?.headers;
  if (!isPlainObject(headers)) return [];
  const https = String(op.attrs?.scheme ?? op.attrs?.url ?? op.key ?? '').startsWith('https');
  const status = Number(op.attrs?.status) || 200;
  const ops = [];
  for (const item of headerProductVersions(headers)) {
    const name = `observed/${item.product}/${item.version}`;
    ops.push(techNodeOp(name, { evidence: 'response-header', label: item.label }));
    ops.push(link(ref('webapp', op.key), ref('tech', name), 'exposes', { confidence: 0.6 }));
  }
  for (const finding of recordedHeaderFindings(headers, { https, status, path: op.attrs?.path || '/' })) {
    const node = findingNodeOp(state, {
      template: finding.template,
      title: finding.title,
      severity: finding.severity,
      status: 'candidate',
      subjectKey: op.key,
      evidence: finding.evidence,
      remediation: finding.recommendation,
    });
    ops.push({ ...node, tags: ['exposure'], sources: ['record'] });
    ops.push(link(ref('webapp', op.key), ref('finding', node.key), 'affects', { confidence: 0.6 }));
  }
  return ops;
}

function webappRecordOp(state, key, attrs, input) {
  const pageText = PAGE_ATTRS
    .map((name) => attrs[name])
    .filter((value) => typeof value === 'string' && value.trim().length > 0)
    .join('\n');
  const blob = [attrs.url, key, input.label, pageText].filter((part) => typeof part === 'string' && part.length > 0).join('\n');
  const existing = Object.values(state.nodes).find((node) => node.kind === 'webapp' && node.key === key);
  const prior = existing?.attrs ?? {};
  const entryPath = prior.entryPath || attrs.entryPath || attrs.path || attrs.url || key;
  const ledger = mergeLedgerAttrs({ ...prior, entryPath }, blob, { inventoried: pageText.length > 0 });
  return webappNodeOp(key, { ...attrs, label: input.label, tags: input.tags, entryPath, attrs: { ...attrs, ...ledger, entryPath: ledger.entryPath || entryPath } });
}

function nodeOpFor(state, input, config) {
  const kind = input.kind;
  if (!NODE_KINDS_SET.has(kind)) invalid(`unknown node kind "${kind}" (known: ${NODE_KINDS.join(', ')})`);
  const rawAttrs = isPlainObject(input.attrs) ? input.attrs : {};
  if (kind === 'credential' && (rawAttrs.secret !== undefined || rawAttrs.password !== undefined || rawAttrs.token !== undefined)) {
    invalid('do not send raw secrets; pass secretMask and optional secretFp instead');
  }
  const attrs = sanitizeAttrs(kind, rawAttrs);
  const key = canonicalKeyFor(kind, { ...input, attrs });
  const keyOptional = new Set(['finding', 'credential', 'access', 'pivot', 'data', 'task', 'chain_step']);
  if (typeof key !== 'string' || key.length === 0) {
    if (!keyOptional.has(kind)) invalid(`cannot derive a canonical key for node kind "${kind}"; pass key or the kind-specific fields`);
  }

  if (kind === 'host') return hostNodeOp(key, { ...attrs, attrs, tags: input.tags });
  if (kind === 'domain') return domainNodeOp(key, { ...attrs, attrs, tags: input.tags });
  if (kind === 'ip') return ipNodeOp(key, { ...attrs, attrs, tags: input.tags });
  if (kind === 'cidr') return cidrNodeOp(key, { ...attrs, attrs, tags: input.tags });
  if (kind === 'tech') return techNodeOp(key, { evidence: attrs.evidence, label: input.label });
  if (kind === 'webapp') return webappRecordOp(state, key, attrs, input);
  if (kind === 'service') {
    const endpoint = attrs.endpoint ?? attrs.host ?? attrs.ip;
    const port = Number(attrs.port);
    return {
      op: 'node.upsert',
      kind,
      key,
      label: input.label ?? `${endpoint}:${port}`,
      attrs: { ...attrs, endpoint, port, transport: attrs.transport ?? 'tcp', state: attrs.state ?? 'open' },
      ...(input.status !== undefined ? { status: input.status } : {}),
      ...(input.confidence !== undefined ? { confidence: input.confidence } : {}),
      ...(Array.isArray(input.tags) ? { tags: input.tags } : {}),
      ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds } : {}),
      ...(input.verification !== undefined ? { verification: input.verification } : {}),
    };
  }
  if (kind === 'finding') {
    const template = String(attrs.template ?? input.key ?? 'manual-finding');
    const cvss = resolveCvss({
      cvssVector: attrs.cvssVector ?? input.cvssVector,
      cvss: attrs.cvss ?? input.cvss,
    });
    if (cvss.present === true) {
      if (cvss.ok !== true) invalid(`invalid CVSS v3.1 input: ${cvss.reason}`);
      if (cvss.rejected === true) invalid(cvss.reason);
      const hardening = hardeningScoreRefusal({ ...attrs, template, title: attrs.title ?? input.label }, cvss);
      if (hardening !== null) invalid(hardening);
      Object.assign(attrs, findingAttrs(cvss));
    } else if (attrs.cvssScore !== undefined || attrs.cvssRating !== undefined || attrs.cvssSeverity !== undefined) {
      invalid('cvssScore/cvssRating/cvssSeverity must be derived from cvssVector or the eight cvss metrics; do not supply a score without a vector');
    }
    const severity = String(attrs.severity ?? cvss?.rating ?? 'info');
    if (!SEVERITIES.includes(severity)) invalid(`finding.severity must be one of ${SEVERITIES.join(', ')}`);
    if (String(input.status ?? 'candidate') === 'verified' && config?.requireProofForVerified !== false) {
      const verdict = validateFindingProof({ ...attrs, severity }, { requireSecondaryForHigh: false });
      if (!verdict.ok) invalid(`finding cannot be recorded as verified without proof (${verdict.reason}); attach proofType/proofDetail/proofUrl/proofCanary/evidenceIds or leave it candidate`);
    }
    const subjectKey = String(attrs.subjectKey ?? attrs.subjectId ?? attrs.subject ?? 'unknown');
    const built = findingNodeOp(state, {
      ...attrs,
      template,
      title: attrs.title ?? input.label ?? template,
      severity,
      subjectKey,
      subjectId: attrs.subjectId,
      attrs,
      status: input.status ?? attrs.status ?? 'candidate',
      verification: input.verification ?? attrs.verification,
      evidenceIds: input.evidenceIds,
    });
    return input.label !== undefined ? { ...built, label: input.label } : built;
  }
  if (kind === 'credential') {
    if (attrs.secret !== undefined || attrs.password !== undefined) invalid('do not send raw secrets; pass secretMask and optional secretFp instead');
    const username = String(attrs.username ?? input.key ?? 'unknown');
    const realm = String(attrs.realm ?? 'external');
    const fingerprint = String(attrs.secretFp ?? attrs.secretMask ?? username);
    return credentialNodeOp(state, {
      username,
      realm,
      kind: attrs.kind ?? 'password',
      secretMask: attrs.secretMask,
      secretFp: attrs.secretFp,
      validity: attrs.validity ?? input.status ?? 'untested',
      privilege: attrs.privilege,
      targetId: attrs.targetId,
      sourceAccessId: attrs.sourceAccessId,
      label: input.label,
      confidence: input.confidence,
      attrs,
    });
  }
  if (kind === 'access') {
    return accessNodeOp(state, {
      assetKey: attrs.assetKey ?? attrs.assetId ?? input.key,
      assetId: attrs.assetId,
      kind: attrs.kind ?? 'shell',
      privilege: attrs.privilege ?? 'user',
      status: input.status ?? attrs.status ?? 'obtained',
      osUser: attrs.osUser,
      transport: attrs.transport,
      persistence: attrs.persistence,
      proof: attrs.proof,
      reachableSegments: attrs.reachableSegments,
      evidenceIds: input.evidenceIds,
      label: input.label,
      confidence: input.confidence,
      verification: input.verification,
      attrs,
    });
  }
  if (kind === 'pivot') {
    return pivotNodeOp(state, {
      accessId: attrs.accessId,
      targetId: attrs.targetId,
      targetKey: attrs.targetKey,
      transport: attrs.transport,
      localEndpoint: attrs.localEndpoint,
      remoteEndpoint: attrs.remoteEndpoint,
      verified: attrs.verified === true,
      tunnelId: attrs.tunnelId,
      label: input.label,
      attrs,
    });
  }
  if (kind === 'data') {
    const dataClass = String(attrs.dataClass ?? 'internal');
    const thresholds = {
      ...(config?.bulkThresholds ?? {}),
      ...(state.engagement?.roe?.bulkThresholds ?? {}),
    };
    const bucket = dataClass === 'customer_records' ? 'pii' : dataClass === 'keys_tokens' ? 'keys' : dataClass;
    const required = thresholds[bucket] ?? 500;
    const count = Number(attrs.count);
    if (!Number.isFinite(count) || count < 0) invalid('data node requires a non-negative count');
    const redacted = sanitizeAttrs('data', redactSamples(rawAttrs, state));
    return dataNodeOp(state, {
      ...redacted,
      subjectId: attrs.subjectId ?? attrs.subject ?? input.key,
      dataClass,
      count,
      countMethod: attrs.countMethod ?? 'unknown',
      thresholdMet: count >= required,
      samples: redacted.samples,
      hashes: redacted.hashes,
      status: input.status ?? attrs.status ?? 'claimed',
      verification: input.verification ?? attrs.verification,
      evidenceIds: input.evidenceIds,
      label: input.label,
      confidence: input.confidence,
    });
  }
  if (kind === 'coverage') {
    invalid('coverage cells are written only by atkbrain_coverage; atkbrain_record cannot seed, close, or refute them');
  }
  if (kind === 'evidence' && (attrs.toolName !== undefined || attrs.origin === 'arsenal')) {
    invalid('external scanner evidence is not accepted; skills, dictionaries and pentest tools are not available');
  }
  if (kind === 'task') {
    if (attrs.actionType === 'capability' || attrs.capability !== undefined || attrs.capabilityAction !== undefined) {
      invalid('skill, dictionary and scanner capability tasks are not available');
    }
    if (typeof attrs.actionType !== 'string' || attrs.actionType.length === 0) invalid('task node requires attrs.actionType');
    return taskNodeOp(state, {
      actionType: attrs.actionType,
      targetId: attrs.targetId,
      label: input.label ?? attrs.actionType,
      priority: attrs.priority,
      why: attrs.why,
      toolClass: attrs.toolClass,
      expectedEvidence: attrs.expectedEvidence,
      risk: attrs.risk,
      scopeVerdict: attrs.scopeVerdict,
      status: input.status ?? attrs.status ?? 'pending',
      attrs,
    });
  }
  if (kind === 'chain_step') {
    if (attrs.chainId === undefined || attrs.ordinal === undefined || attrs.stage === undefined) {
      invalid('chain_step requires attrs.chainId, attrs.ordinal and attrs.stage');
    }
    return chainStepNodeOp(state, {
      chainId: String(attrs.chainId),
      ordinal: Number(attrs.ordinal),
      stage: attrs.stage,
      nodeRef: attrs.nodeRef,
      edgeRef: attrs.edgeRef,
      result: attrs.result,
      evidenceIds: input.evidenceIds,
      label: input.label,
      status: input.status,
      confidence: input.confidence,
    });
  }
  if (kind === 'evidence') {
    if (typeof attrs.sha256 !== 'string') invalid('evidence node requires attrs.sha256');
    return evidenceNodeOp(state, attrs);
  }
  if (kind === 'segment') {
    return {
      op: 'node.upsert',
      kind,
      key,
      label: input.label ?? key,
      attrs,
      ...(input.status !== undefined ? { status: input.status } : {}),
      ...(Array.isArray(input.tags) ? { tags: input.tags } : {}),
    };
  }
  return {
    op: 'node.upsert',
    kind,
    key,
    label: input.label ?? key,
    attrs,
    ...(input.status !== undefined ? { status: input.status } : {}),
    ...(input.confidence !== undefined ? { confidence: input.confidence } : {}),
    ...(Array.isArray(input.tags) ? { tags: input.tags } : {}),
    ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds } : {}),
    ...(input.verification !== undefined ? { verification: input.verification } : {}),
  };
}

function absorbKindlessNodes(args) {
  if (!Array.isArray(args.nodes)) return;
  const evidence = Array.isArray(args.evidence) ? [...args.evidence] : [];
  const nodes = [];
  for (const node of args.nodes) {
    if (!isPlainObject(node)) {
      nodes.push(node);
      continue;
    }
    if (typeof node.kind === 'string' && node.kind.length > 0) {
      nodes.push(node);
      continue;
    }
    if (typeof node.path === 'string' || typeof node.sha256 === 'string') {
      evidence.push(node);
      continue;
    }
    if (Array.isArray(node.evidence)) {
      for (const item of node.evidence) {
        if (isPlainObject(item)) evidence.push(item);
      }
    }
    const attrs = isPlainObject(node.attrs) ? { ...node.attrs } : {};
    if (typeof node.title === 'string' && attrs.title === undefined) attrs.title = node.title;
    if (typeof node.template === 'string' && attrs.template === undefined) attrs.template = node.template;
    if (typeof node.label === 'string' && attrs.title === undefined) attrs.title = node.label;
    const vector = node.cvssVector ?? attrs.cvssVector ?? args.cvssVector;
    const metrics = node.cvss ?? attrs.cvss ?? args.cvss;
    if (vector !== undefined && attrs.cvssVector === undefined) attrs.cvssVector = vector;
    if (metrics !== undefined && attrs.cvss === undefined) attrs.cvss = metrics;
    if (attrs.title !== undefined || attrs.template !== undefined || attrs.cvssVector !== undefined || attrs.cvss !== undefined || node.severity !== undefined || attrs.severity !== undefined) {
      nodes.push({ ...node, kind: 'finding', attrs, evidence: undefined });
      continue;
    }
    nodes.push(node);
  }
  args.nodes = nodes;
  if (args.nodes.length === 0) delete args.nodes;
  if (evidence.length > 0) args.evidence = evidence;
}

function looseNode(state, token) {
  const wanted = String(token ?? '').trim().toLowerCase();
  if (wanted.length === 0) return undefined;
  const matches = Object.values(state.nodes ?? {}).filter((node) => node.status !== 'merged' && [
    node.key, node.id, node.label, node.attrs?.title, node.attrs?.template,
  ].some((value) => String(value ?? '').trim().toLowerCase() === wanted));
  matches.sort((left, right) => (right.attrs?.stub === true ? 0 : 2) - (left.attrs?.stub === true ? 0 : 2));
  return matches[0];
}

function evidenceSubject(state, subject) {
  if (typeof subject === 'string') {
    const node = looseNode(state, subject);
    return node === undefined ? null : { kind: node.kind, key: node.key };
  }
  if (!isPlainObject(subject)) return null;
  if (typeof subject.kind === 'string' && typeof subject.key === 'string') return { kind: subject.kind, key: subject.key };
  const token = subject.key ?? subject.id ?? subject.template ?? subject.title ?? subject.label;
  const node = looseNode(state, token);
  if (node !== undefined) return { kind: node.kind, key: node.key };
  return null;
}

function resolveEdgeRef(state, value, label, recordedById = new Map()) {
  if (typeof value === 'string') {
    const node = state.nodes[value];
    if (node !== undefined) return { kind: node.kind, key: node.key };
    const recorded = recordedById.get(value);
    if (recorded !== undefined) return recorded;
    invalid(`${label} is an unknown node id "${value}"; use {kind,key} or a node id returned by a tool`);
  }
  if (isPlainObject(value) && typeof value.kind === 'string' && typeof value.key === 'string') {
    return { kind: value.kind, key: value.key };
  }
  invalid(`${label} must be {kind,key} or an existing node id`);
  return undefined;
}

export function registerRecordTool(ctx, config, deps) {
  registerAtkTool(ctx, config, deps, {
    name: TOOL_NAMES.record,
    callTitle: 'Record discovery',
    description: 'Record findings, credentials (masked only), access/footholds, data evidence (redacted samples), pivots, tasks, chain steps and asset nodes into the attack graph. Raw secrets and raw PII are rejected. Use this after verifying a vulnerability or obtaining access.',
    parameters: PARAMETERS,
    validate(args) {
      assertArgs(args);
      absorbKindlessNodes(args);
      const hasNodes = Array.isArray(args.nodes) && args.nodes.length > 0;
      const hasEdges = Array.isArray(args.edges) && args.edges.length > 0;
      const hasStatus = Array.isArray(args.statusChanges) && args.statusChanges.length > 0;
      const hasEvidence = Array.isArray(args.evidence) && args.evidence.length > 0;
      const hasNote = typeof args.note === 'string' && args.note.trim().length > 0;
      if (!hasNodes && !hasEdges && !hasStatus && !hasEvidence && !hasNote) {
        invalid('provide at least one of nodes, edges, statusChanges, evidence, note');
      }
      if (args.nodes !== undefined) requireArray(args, 'nodes', { max: MAX_NODES });
      if (args.edges !== undefined) requireArray(args, 'edges', { max: MAX_EDGES });
      if (args.statusChanges !== undefined) requireArray(args, 'statusChanges', { max: MAX_STATUS });
      if (args.evidence !== undefined) requireArray(args, 'evidence', { max: MAX_EVIDENCE });
      for (const node of args.nodes ?? []) {
        if (!isPlainObject(node)) invalid('every nodes entry must be an object');
        if (typeof node.kind !== 'string') invalid('every nodes entry needs a kind');
      }
      for (const edge of args.edges ?? []) {
        if (!isPlainObject(edge)) invalid('every edges entry must be an object');
        if (!EDGE_KINDS_SET.has(edge.kind)) invalid(`edge kind must be one of ${EDGE_KINDS.join(', ')}`);
      }
      return true;
    },
    async run({ args, state, exec, ctx: toolCtx, config: cfg, deps: runtime }) {
      const ops = [];
      const recorded = [];
      const warnings = [];
      const evidenceIds = [];

      for (const evidenceInput of Array.isArray(args.evidence) ? args.evidence : []) {
        try {
          let sha256 = typeof evidenceInput.sha256 === 'string' ? evidenceInput.sha256 : undefined;
          let bytes = Number.isFinite(evidenceInput.size) ? evidenceInput.size : undefined;
          let absolute;
          let relative;
          if (typeof evidenceInput.path === 'string' && evidenceInput.path.trim().length > 0) {
            const workspace = runtime.workspace(exec.agent);
            absolute = resolvePath(workspace, evidenceInput.path);
            const info = await stat(absolute);
            bytes = info.size;
            relative = path.relative(workspace, absolute);
            if (sha256 === undefined) sha256 = await fileSha256(absolute);
          }
          if (sha256 === undefined) invalid('evidence entries need a path or sha256');
          const op = evidenceNodeOp(state, {
            path: absolute ?? null,
            relative: relative ?? evidenceInput.path,
            sha256,
            bytes,
            mediaType: evidenceInput.mediaType,
            label: evidenceInput.label ?? `evidence ${sha256.slice(0, 10)}`,
            collectedBy: 'agent',
          });
          ops.push(op);
          evidenceIds.push(sha256);
          const subject = evidenceSubject(state, evidenceInput.subject);
          if (subject !== null) {
            ops.push(link(ref(subject.kind, subject.key), ref('evidence', sha256), 'derived_from', { confidence: 0.9, evidenceIds: [sha256] }));
            if (subject.kind === 'finding' && typeof args.cvssVector === 'string' && args.cvssVector.length > 0) {
              const existing = looseNode(state, subject.key);
              const cvss = resolveCvss({ cvssVector: args.cvssVector, cvss: args.cvss });
              if (cvss.present === true && cvss.ok === true && cvss.rejected !== true && existing !== undefined && existing.attrs?.cvssVector === undefined) {
                ops.push({
                  op: 'node.upsert',
                  kind: 'finding',
                  key: existing.key,
                  label: existing.label,
                  attrs: { ...existing.attrs, ...findingAttrs(cvss) },
                });
              }
            }
          }
        } catch (error) {
          if (error instanceof Error && error.name === 'ATK_INVALID_ARGS') throw error;
          warnings.push(`evidence: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

      for (const input of Array.isArray(args.nodes) ? args.nodes : []) {
        const op = nodeOpFor(state, input, config);
        if (input.evidenceIds !== undefined && !Array.isArray(input.evidenceIds)) invalid('nodes[].evidenceIds must be an array');
        ops.push(op);
        if (op.kind === 'webapp') ops.push(...headerObservationOps(state, op));
        recorded.push({ id: nodeId(op.kind, op.key), kind: op.kind, key: op.key, label: op.label, attrs: op.attrs });
      }

      const recordedById = new Map(recorded.map((entry) => [entry.id, { kind: entry.kind, key: entry.key }]));
      for (const input of Array.isArray(args.edges) ? args.edges : []) {
        const from = resolveEdgeRef(state, input.from, 'from', recordedById);
        const to = resolveEdgeRef(state, input.to, 'to', recordedById);
        const edge = link(from, to, input.kind, {
          confidence: input.confidence,
          attrs: isPlainObject(input.attrs) ? input.attrs : {},
          evidenceIds: Array.isArray(input.evidenceIds) ? input.evidenceIds : [],
        });
        ops.push(edge);
      }

      for (const change of Array.isArray(args.statusChanges) ? args.statusChanges : []) {
        if (typeof change.id !== 'string') invalid('statusChanges[].id must be a node id');
        const existing = state.nodes[change.id];
        const pending = recordedById.get(change.id);
        if (existing === undefined && pending === undefined) {
          warnings.push(`status change ignored: node ${change.id} is not in the graph`);
          continue;
        }
        if (typeof change.status !== 'string' || change.status.length === 0) invalid('statusChanges[].status is required');
        const changeKind = existing?.kind ?? pending.kind;
        if (changeKind === 'coverage') invalid('coverage status is changed only by atkbrain_coverage action=note');
        if (changeKind === 'task' && (existing?.attrs?.actionType === 'capability' || existing?.attrs?.capability !== undefined)) {
          invalid('skill, dictionary and scanner capability tasks are not available');
        }
        if (changeKind === 'finding' && String(change.status) === 'verified' && config?.requireProofForVerified !== false) {
          const candidate = { ...(existing?.attrs ?? {}), ...(isPlainObject(change.proof) ? change.proof : {}) };
          const verdict = validateFindingProof(candidate, { requireSecondaryForHigh: false });
          if (!verdict.ok) invalid(`finding status verified rejected (${verdict.reason}); record proof fields/evidence first or leave it candidate`);
        }
        const op = {
          op: 'node.upsert',
          kind: existing?.kind ?? pending.kind,
          key: existing?.key ?? pending.key,
          label: existing?.label ?? pending.label ?? pending.key,
          attrs: {
            ...(existing?.attrs ?? {}),
            ...(isPlainObject(change.proof) ? change.proof : {}),
            ...(change.note ? { statusNote: String(change.note).slice(0, 1000) } : {}),
          },
          status: change.status,
          ...(existing?.confidence !== undefined ? { confidence: existing.confidence } : {}),
          ...(existing?.tags !== undefined ? { tags: existing.tags } : {}),
          ...(existing?.sources !== undefined ? { sources: existing.sources } : {}),
          ...(existing?.evidenceIds !== undefined ? { evidenceIds: existing.evidenceIds } : {}),
          ...(change.verification !== undefined ? { verification: change.verification } : {}),
        };
        ops.push(op);
        recorded.push({ id: nodeId(op.kind, op.key), kind: op.kind, key: op.key, label: op.label, status: change.status, attrs: op.attrs });
      }

      const impactRecord = recorded.some((entry) => entry.kind === 'access' || entry.kind === 'credential' || entry.kind === 'data'
        || (entry.kind === 'finding' && !isHardeningFinding(entry.attrs ?? {})));
      if (typeof args.note === 'string' && args.note.trim().length > 0) {
        ops.push(audit(TOOL_NAMES.record, 'note', null, args.note.trim().slice(0, 2000), evidenceIds));
      } else {
        ops.push(audit(TOOL_NAMES.record, impactRecord ? 'record.impact' : 'record', recorded.map((entry) => entry.label).slice(0, 5).join(', ') || 'record', `${recorded.length} node/status change(s)`, evidenceIds));
      }

      const candidates = (Array.isArray(args.nodes) ? args.nodes : [])
        .filter((input) => input?.kind === 'finding')
        .map((input) => ({ key: input.key ?? input.attrs?.title ?? 'finding', label: input.label ?? input.attrs?.title ?? input.key, attrs: input.attrs ?? {}, tags: Array.isArray(input.tags) ? input.tags : [] }));
      const preview = applyOps(state, ops);
      const pending = pendingFindings(Object.values(preview.nodes ?? {}));
      let autoVerification = { ops: [], verified: [], errors: [], skipped: null, queued: pending.map((node) => node.key) };
      const wake = (state.scope?.allow?.length ?? 0) > 0 && cfg.selfTeamMode !== 'off'
        ? (async () => {
          try {
            const agentTeams = toolCtx.get('agentTeams');
            return await wakeEngagementTeams({
              agentTeams,
              agent: exec.agent,
              signal: exec.signal,
              state: preview,
              config: cfg,
              pending,
              forceVerifier: candidates.length > 0,
            });
          } catch {
            return null;
          }
        })()
        : Promise.resolve(null);
      if (cfg.autoVerifyFindings !== false && candidates.length > 0) {
        const budgetMs = Math.min(Number(cfg.verifierTimeoutMs) || 20000, 20000);
        const budget = AbortSignal.timeout(budgetMs);
        const signal = exec.signal ? AbortSignal.any([exec.signal, budget]) : budget;
        try {
          autoVerification = await Promise.race([
            autoVerifyFindings({
              ctx: toolCtx,
              agent: exec.agent,
              state,
              ops,
              candidates,
              config: cfg,
              writeEvidence: runtime.writeEvidence,
              signal,
              timeoutMs: budgetMs,
            }),
            new Promise((resolve) => {
              setTimeout(() => resolve({
                ops: [],
                verified: [],
                errors: ['verification continues with the resident team'],
                skipped: 'budget',
                queued: pending.map((node) => node.key),
              }), budgetMs + 500);
            }),
          ]);
          ops.push(...autoVerification.ops);
        } catch (error) {
          autoVerification.errors.push(error instanceof Error ? error.message : String(error));
        }
      }
      await wake;
      if ((autoVerification.verified ?? []).some((entry) => entry.verdict === 'verified') && cfg.selfTeamMode !== 'off') {
        try {
          const agentTeams = toolCtx.get('agentTeams');
          const after = applyOps(preview, autoVerification.ops ?? []);
          await notifyResidentTeams({
            agentTeams,
            agent: exec.agent,
            signal: exec.signal,
            state: after,
            config: cfg,
            pending: pendingFindings(Object.values(after.nodes ?? {})),
            escalationPending: pendingEscalations(after),
            forceEscalation: true,
            justVerified: autoVerification.verified,
          });
        } catch {
          /* the next verified finding notifies evolution again */
        }
      }

      const added = recorded.filter((entry) => entry.id !== undefined);
      const summary = [
        `Recorded ${added.length} graph change(s) and ${evidenceIds.length} evidence artifact(s).`,
        added.length > 0 ? `Kinds: ${Object.entries(added.reduce((counts, entry) => ({ ...counts, [entry.kind]: (counts[entry.kind] ?? 0) + 1 }), {})).map(([kind, count]) => `${kind}=${count}`).join(', ')}.` : '',
        evidenceIds.length > 0 ? `Evidence ids: ${evidenceIds.slice(0, 5).join(', ')}.` : '',
        warnings.length > 0 ? `Warnings: ${warnings.slice(0, 5).join('; ')}` : '',
        autoVerification.verified.length > 0 ? `Auto verification & rating team: ${autoVerification.verified.map((entry) => `${entry.finding} (${entry.verdict}/${entry.rating})`).join('; ')}.` : '',
        autoVerification.errors.length > 0 ? `Auto verification unavailable: ${autoVerification.errors.slice(0, 2).join('; ')}` : '',
        'Use atkbrain_query action=frontier to see the next verified step.',
      ].filter(Boolean).join(' ');
      return {
        summary,
        ops,
        details: {
          recorded,
          evidenceIds,
          warnings,
          publicSample: added.slice(0, 20).map((entry) => ({ id: entry.id, kind: entry.kind, label: entry.label, status: entry.status })),
        },
      };
    },
  });
}
