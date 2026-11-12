/**
 * Redaction helpers.
 *
 * Two rules are load-bearing:
 *  - credentials never enter graph state as raw values (only a mask + HMAC);
 *  - sensitive-data evidence keeps counts, field schemas and row hashes, never
 *    raw rows.
 *
 * The graph projection also calls `publicAttrs` before sending anything to the
 * browser, so a tool that accidentally stores a secret key cannot leak it to
 * the Client page.
 */
import { SECRET_KEY_PATTERN } from './constants.js';
import { hmac16, isPlainObject, stableStringify, truncate } from './util.js';

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/u;
const PHONE_RE = /(?:\+?\d[\d\s-]{6,}\d)/u;
const PAN_RE = /\b(?:\d[ -]?){12,18}\d\b/u;
const IBAN_RE = /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/u;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u;
const PEM_RE = /-----BEGIN [A-Z ]+PRIVATE KEY-----/u;

/** Mask an email address. */
export function maskEmail(value) {
  const text = String(value);
  const at = text.lastIndexOf('@');
  if (at <= 0) return '***';
  const local = text.slice(0, at);
  const domain = text.slice(at);
  return `${local.slice(0, 1)}***${local.length > 1 ? local.slice(-1) : ''}${domain}`;
}

/** Mask a phone number, keeping the last four digits. */
export function maskPhone(value) {
  const digits = String(value).replace(/\D/gu, '');
  if (digits.length <= 4) return '***';
  return `***${digits.slice(-4)}`;
}

/** Mask a card-like number, keeping the last four digits. */
export function maskPan(value) {
  const digits = String(value).replace(/\D/gu, '');
  if (digits.length <= 4) return '***';
  return `****${digits.slice(-4)}`;
}

/** Mask an IBAN-like value. */
export function maskIban(value) {
  const text = String(value).replace(/\s/gu, '');
  if (text.length <= 6) return '***';
  return `${text.slice(0, 4)}${'*'.repeat(Math.max(0, text.length - 8))}${text.slice(-4)}`;
}

/** Mask an arbitrary string, preserving a small prefix only. */
export function maskText(value) {
  const text = String(value);
  if (text.length <= 2) return '**';
  if (text.length <= 8) return `${text.slice(0, 1)}***`;
  return `${text.slice(0, 2)}***${text.slice(-2)}`;
}

/** Classify and mask one value. Returns `{masked, class}`. */
export function classifyAndMask(value, hint) {
  if (value === null || value === undefined) return { masked: null, class: 'empty' };
  if (typeof value === 'number') return { masked: '***', class: hint ?? 'numeric' };
  if (typeof value === 'boolean') return { masked: value, class: 'boolean' };
  const text = String(value);
  if (PEM_RE.test(text)) return { masked: `[private-key len=${text.length}]`, class: 'keys_tokens' };
  if (JWT_RE.test(text)) return { masked: `[jwt len=${text.length}]`, class: 'keys_tokens' };
  if (EMAIL_RE.test(text)) return { masked: maskEmail(text), class: 'pii' };
  if (IBAN_RE.test(text)) return { masked: maskIban(text), class: 'financial' };
  if (PAN_RE.test(text) && text.replace(/\D/gu, '').length >= 13) return { masked: maskPan(text), class: 'financial' };
  if (PHONE_RE.test(text) && text.replace(/\D/gu, '').length >= 7) return { masked: maskPhone(text), class: 'pii' };
  if (hint === 'keys_tokens' || hint === 'credentials') return { masked: `[redacted len=${text.length}]`, class: 'keys_tokens' };
  return { masked: maskText(text), class: hint ?? 'internal' };
}

/**
 * Redact one row into a graph-safe sample.
 * @returns {{masked:object, hashes:object, classes:object}}
 */
export function redactRow(row, { salt = 'atkbrain', classHint } = {}) {
  if (!isPlainObject(row)) {
    const classified = classifyAndMask(row, classHint);
    return {
      masked: { value: classified.masked },
      hashes: { value: hmac16(salt, stableStringify(row)) },
      classes: { value: classified.class },
    };
  }
  const masked = {};
  const hashes = {};
  const classes = {};
  let index = 0;
  for (const [key, value] of Object.entries(row)) {
    index += 1;
    if (index > 50) break;
    if (SECRET_KEY_PATTERN.test(key)) {
      masked[key] = '[redacted]';
      hashes[key] = hmac16(salt, stableStringify(value));
      classes[key] = 'credentials';
      continue;
    }
    const classified = classifyAndMask(value, classHint);
    masked[key] = classified.masked;
    hashes[key] = hmac16(salt, stableStringify(value));
    classes[key] = classified.class;
  }
  return { masked, hashes, classes };
}

/** Strip secret-like keys and bound an arbitrary JSON value for the wire. */
export function boundValue(value, depth = 0) {
  if (depth > 4) return '[depth-limit]';
  if (typeof value === 'string') return truncate(value, 1200);
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 80).map((entry) => boundValue(entry, depth + 1));
  if (!isPlainObject(value)) return undefined;
  const out = {};
  let count = 0;
  for (const [key, entry] of Object.entries(value)) {
    count += 1;
    if (count > 80) {
      out._truncated = true;
      break;
    }
    if (SECRET_KEY_PATTERN.test(key)) continue;
    const bounded = boundValue(entry, depth + 1);
    if (bounded !== undefined) out[key] = bounded;
  }
  return out;
}

/**
 * Mask credentials in an HTTP request/response packet while keeping the
 * method/path/status and non-secret headers readable for the finding detail.
 */
export function redactPacket(value, max = 16000) {
  const text = String(value ?? '').slice(0, max);
  return text
    .replace(/^(\s*(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key|api-key)\s*:\s*).*$/gimu, '$1[redacted]')
    .replace(/((?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|session)\s*[=:]\s*)([^&\s;,'"]+)/giu, '$1[redacted]')
    .replace(/([?&](?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|session)=)[^&\s]+/giu, '$1[redacted]')
    .replace(/\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b/gu, '[jwt]')
    .replace(/-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/gu, '[private-key]');
}

/** Finding attrs with request/response packets masked for the browser. */
function publicFindingAttrs(source) {
  const out = {};
  for (const [key, value] of Object.entries(source ?? {})) {
    if (SECRET_KEY_PATTERN.test(key)) continue;
    if (['request', 'response', 'httpRequest', 'httpResponse', 'pocCurl', 'pocPython', 'repro', 'proofDetail', 'escalationProof'].includes(key)) {
      out[key] = redactPacket(value);
      continue;
    }
    const bounded = boundValue(value);
    if (bounded !== undefined) out[key] = bounded;
  }
  return out;
}

/** Redact one data-evidence node's attributes for the wire view. */
function publicDataAttrs(attrs) {  const out = {};
  for (const [key, value] of Object.entries(attrs ?? {})) {
    if (SECRET_KEY_PATTERN.test(key)) continue;
    if (key === 'samples' && Array.isArray(value)) {
      out.samples = value.slice(0, 10).map((sample) => {
        if (!isPlainObject(sample)) return '[sample]';
        return {
          ...(Array.isArray(sample.fields) ? { fields: sample.fields.slice(0, 50) } : {}),
          ...(isPlainObject(sample.masked) ? { masked: boundValue(sample.masked) } : {}),
          ...(isPlainObject(sample.hashes) ? { hashes: boundValue(sample.hashes) } : {}),
          ...(typeof sample.rowHash === 'string' ? { rowHash: sample.rowHash } : {}),
        };
      });
      continue;
    }
    const bounded = boundValue(value);
    if (bounded !== undefined) out[key] = bounded;
  }
  return out;
}

const LOOP_ATTR_KEYS = Object.freeze([
  'objective', 'objectiveType', 'phase', 'round', 'maxRounds', 'goalId', 'goalRevision',
  'goalPhase', 'activation', 'ring', 'allowedRing', 'noProgressRounds', 'emptyRounds',
  'maxActionsPerRound', 'baseline', 'latestSnapshot', 'stopReason', 'autoContinue',
  'usedLessonKeys', 'appliedLessonKeys', 'startedAt', 'lastStepAt', 'latestSupervisionKey',
]);
const INTENT_ATTR_KEYS = Object.freeze([
  'actionType', 'actionId', 'targetId', 'targetKind', 'targetLabel', 'priority', 'why',
  'hypothesis', 'strategyKey', 'expectedEvidence', 'scopeVerdict', 'round', 'attempts',
  'observations', 'channelCount', 'claimedAt', 'resolvedAt', 'result', 'supervisorKey',
]);
const SUPERVISION_ATTR_KEYS = Object.freeze([
  'type', 'round', 'verdict', 'diagnosis', 'nextPlan', 'mustIntents', 'preferTactics',
  'banRepeats', 'stopRecommended', 'stopReason', 'confidence', 'source', 'childId',
  'promptHash', 'planHash', 'findingKey', 'secondaryVerdict', 'secondaryMode', 'ratingSource', 'teamType', 'progressSummary', 'gained', 'missed', 'advice', 'antiDeadlock', 'recommendedNext', 'deadlockRisk', 'artifactPath', 'rationale',
  'createdAt', 'basis', 'auditCursor',
]);
const LESSON_ATTR_KEYS = Object.freeze([
  'lessonKey', 'idea', 'method', 'route', 'chain', 'when', 'do', 'avoid', 'confidence',
  'wins', 'fails', 'uses', 'status', 'sourceEngagementHash', 'sourceOutcome',
  'sourceFindingClasses', 'createdAt', 'updatedAt', 'lastUsedAt',
]);
const LESSON_FORBIDDEN_RE = /(?:\b\d{1,3}(?:\.\d{1,3}){3}\b|https?:\/\/|(?:^|\s)\/[A-Za-z0-9_./-]{2,}|-----BEGIN )/u;

function pickAttrs(source, keys) {
  const out = {};
  for (const key of keys) {
    if (source[key] === undefined) continue;
    const bounded = boundValue(source[key]);
    if (bounded !== undefined) out[key] = bounded;
  }
  return out;
}

function publicLessonAttrs(source) {
  const out = pickAttrs(source, LESSON_ATTR_KEYS);
  for (const key of ['idea', 'method', 'route', 'chain']) {
    if (typeof out[key] === 'string' && LESSON_FORBIDDEN_RE.test(out[key])) out[key] = '[redacted-lesson]';
  }
  return out;
}

const SELF_TEAM_ATTR_KEYS = Object.freeze([
  'type', 'mode', 'members', 'lastBriefAt', 'lastBriefPath', 'lastDistillAt',
  'lastVerifyAt', 'lastReportAt', 'lastReportPath', 'lastReportTheme', 'themeSource',
  'verifiedCount', 'ratedCount', 'skillCount', 'skillDir', 'createdAt', 'updatedAt',
]);
const COVERAGE_ATTR_KEYS = Object.freeze([
  'path', 'bugClass', 'status', 'role', 'reason', 'findingId', 'channels', 'evidenceIds',
  'hits', 'checkedAt',
]);
const HYPOTHESIS_ATTR_KEYS = Object.freeze([
  'hypothesisId', 'strategy', 'bugClass', 'targetKey', 'expectedProof', 'status', 'reason',
  'coverageKey', 'channels', 'evidenceIds', 'updatedAt',
]);
const HONEYPOT_ATTR_KEYS = Object.freeze(['targetKey', 'reason', 'severity', 'status']);
const MCP_ATTR_KEYS = Object.freeze([
  'serverId', 'label', 'transport', 'endpoint', 'status', 'toolCount', 'tools',
  'error', 'latencyMs', 'serverName', 'serverVersion', 'protocolVersion', 'checkedAt',
]);
const SKILL_ATTR_KEYS = Object.freeze([
  'skillKey', 'name', 'summary', 'when', 'do', 'avoid', 'route', 'preconditions',
  'verification', 'steps', 'pitfalls', 'confidence', 'status', 'slug', 'path',
  'sourceEngagementHash', 'sourceOutcome', 'sourceFindingClasses', 'createdAt', 'updatedAt',
]);
const SKILL_TEXT_KEYS = Object.freeze(['name', 'summary', 'route']);
const SKILL_TEXT_LIST_KEYS = Object.freeze(['preconditions', 'verification', 'steps', 'pitfalls']);

function scrubSkillValue(value) {
  if (typeof value === 'string') return LESSON_FORBIDDEN_RE.test(value) ? '[redacted-skill]' : value;
  if (Array.isArray(value)) return value.map((entry) => scrubSkillValue(entry));
  return value;
}

function publicSkillAttrs(source) {
  const out = pickAttrs(source, SKILL_ATTR_KEYS);
  for (const key of SKILL_TEXT_KEYS) if (out[key] !== undefined) out[key] = scrubSkillValue(out[key]);
  for (const key of SKILL_TEXT_LIST_KEYS) if (out[key] !== undefined) out[key] = scrubSkillValue(out[key]);
  return out;
}

/** Redact one credential node's attributes for the wire view. */
function publicCredentialAttrs(attrs) {
  const out = {};
  for (const [key, value] of Object.entries(attrs ?? {})) {
    if (key === 'secret' || key === 'password' || key === 'value' || key === 'token') continue;
    if (SECRET_KEY_PATTERN.test(key)) continue;
    if (key === 'secretMask' || key === 'secretFp' || key === 'username' || key === 'kind' || key === 'validity' || key === 'privilege' || key === 'realm' || key === 'targetId' || key === 'sourceAccessId') {
      const bounded = boundValue(value);
      if (bounded !== undefined) out[key] = bounded;
      continue;
    }
    const bounded = boundValue(value);
    if (bounded !== undefined) out[key] = bounded;
  }
  return out;
}

/**
 * Return the browser-safe attributes of one node.
 * This is the last line of defense: even a buggy tool that stored a secret
 * attribute cannot leak it through the projection wire.
 */
export function publicAttrs(kind, attrs) {
  const source = isPlainObject(attrs) ? attrs : {};
  if (kind === 'credential') return publicCredentialAttrs(source);
  if (kind === 'data') return publicDataAttrs(source);
  if (kind === 'loop') return pickAttrs(source, LOOP_ATTR_KEYS);
  if (kind === 'intent') return pickAttrs(source, INTENT_ATTR_KEYS);
  if (kind === 'supervision') return pickAttrs(source, SUPERVISION_ATTR_KEYS);
  if (kind === 'lesson') return publicLessonAttrs(source);
  if (kind === 'self_team') return pickAttrs(source, SELF_TEAM_ATTR_KEYS);
  if (kind === 'skill') return publicSkillAttrs(source);
  if (kind === 'mcp') return pickAttrs(source, MCP_ATTR_KEYS);
  if (kind === 'coverage') return pickAttrs(source, COVERAGE_ATTR_KEYS);
  if (kind === 'hypothesis') return pickAttrs(source, HYPOTHESIS_ATTR_KEYS);
  if (kind === 'honeypot') return pickAttrs(source, HONEYPOT_ATTR_KEYS);
  if (kind === 'finding') return publicFindingAttrs(source);
  if (kind === 'evidence') {
    const out = {};
    for (const key of ['path', 'mediaType', 'size', 'sha256', 'commandHash', 'collectedBy', 'collectedAt', 'prevHash', 'label']) {
      if (source[key] !== undefined) out[key] = boundValue(source[key]);
    }
    return out;
  }
  return boundValue(source) ?? {};
}

/** Redact a whole report-safe node (defense in depth for JSON export). */
export function publicNodeForReport(node) {
  return {
    ...node,
    attrs: publicAttrs(node.kind, node.attrs),
  };
}
