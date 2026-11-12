/**
 * Pure report renderer for the AtkBrain workbench.
 *
 * `renderReport` is a deterministic projection of graph state: it performs no
 * file I/O and never reads the wall clock. The caller supplies `generatedAt`
 * and the effective plugin config; the returned Markdown/JSON/CSV strings are
 * then written by the report tool (or an operator) under `reportDir`.
 *
 * Redaction is load-bearing here because reports leave the session:
 *  - every printed node passes through `publicNodeForReport`;
 *  - credential secrets are never present (only `secretMask` + `secretFp`);
 *  - data samples are reduced to field names, masked values and hashes;
 *  - secret-keyed attributes are dropped and secret-looking values are masked
 *    again as a defense-in-depth pass, even if a tool stored them by accident;
 *  - target-controlled strings are escaped before entering Markdown tables.
 *
 * The JSON export is a re-importable `atkbrain/1` graph document:
 * `{schema, generatedAt, engagement, scope, summary, nodes, edges, frontier,
 * chains}`.
 */

import { bigIntToIpv4, bigIntToIpv6, isPrivateIp, parseCidr } from './cidr.js';
import {
  DEFAULT_CONFIG,
  EDGE_KIND_RANK,
  NODE_KIND_RANK,
  SECRET_KEY_PATTERN,
  SEVERITY_RANK,
  STATE_SCHEMA,
} from './constants.js';
import { computeFrontier } from './frontier.js';
import { graphSummary } from './graph.js';
import { computeCrownPaths, isCrownJewel } from './path.js';
import { localizedFindingTitle } from './finding-i18n.js';
import { maskEmail, publicAttrs, publicNodeForReport } from './redact.js';
import { scopeSummary } from './scope.js';
import {
  formatCount,
  isPlainObject,
  nodeId,
  safeFileName,
  shortHash,
  stableStringify,
  truncate,
  uniqueStrings,
} from './util.js';

/** Markdown/CSV presentation caps. JSON always carries the complete live graph. */
const LIMITS = Object.freeze({
  assets: 100,
  findings: 200,
  credentials: 100,
  access: 100,
  data: 100,
  samplesPerDataNode: 5,
  evidence: 200,
  auditTail: 30,
  scopeEntries: 100,
  wildcardZones: 100,
  pivots: 100,
  lateralEdges: 100,
  internalAssets: 100,
  crownPaths: 5,
  crownPathCompute: 20,
  explicitChains: 20,
  chainSteps: 50,
  remediation: 25,
  excluded: 100,
  auditGroups: 30,
  loopSupervisions: 30,
  loopIntents: 30,
  verificationRows: 30,
  lessons: 30,
  appliedLessons: 30,
  skills: 30,
});

const SEVERITY_ORDER = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

const LIFECYCLE_RANK = Object.freeze({ impacted: 4, exploited: 3, verified: 2, candidate: 1, fixed: 0 });
const ACCESS_RANK = Object.freeze({ escalated: 4, validated: 3, obtained: 2, attempted: 1, lost: 0 });
const DATA_STATUS_RANK = Object.freeze({ verified: 3, partial: 2, claimed: 1 });
const CREDENTIAL_VALIDITY_RANK = Object.freeze({ valid: 3, untested: 2, expired: 1, invalid: 0 });

const PUBLIC_ENGAGEMENT_KEYS = Object.freeze(['name', 'client', 'authorization', 'window', 'mode', 'roe', 'createdAt', 'notes']);

/** Attribute value that looks like a live secret, even under an innocent key. */
const SECRET_VALUE_RE = /(?:-----BEGIN [A-Z ]{2,}PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|cookie|authorization)\b\s*[:=]\s*["']?[^\s"',;]{3,})/iu;
/** Replacement twin of the scan regex; keeping the scan regex non-global makes `.test` side-effect free. */
const SECRET_VALUE_GLOBAL_RE = new RegExp(SECRET_VALUE_RE.source, 'giu');

/**
 * Cross-engagement lessons are global: they must not carry target IPv4s,
 * URLs, filesystem paths, secrets or PII. This is the report-level defense on
 * top of `publicAttrs('lesson', ...)`; either layer alone must redact.
 */
const LESSON_UNSAFE_PATTERNS = Object.freeze([
  /\b\d{1,3}(?:\.\d{1,3}){3}\b/u,
  /\b[a-z][a-z0-9+.-]*:\/\//iu,
  /(?:^|[\s("'`=])\/[A-Za-z0-9_.~%-]{2,}/u,
  /\b[A-Za-z]:\\[^\s"']+/u,
  /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/u,
  /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b/iu,
  /\b\d{9,}\b/u,
  SECRET_VALUE_RE,
]);

const LATERAL_EDGE_KINDS = Object.freeze(new Set(['pivots_to', 'reached_via', 'authenticates_to', 'controls']));
const INTERNAL_CHAIN_STAGES = Object.freeze(new Set(['cross_tenant', 'lateral_movement', 'credential_access', 'privilege_escalation']));

const DATA_CLASS_THRESHOLD_KEY = Object.freeze({
  pii: 'pii',
  customer_records: 'pii',
  financial: 'financial',
  regulated: 'regulated',
  credentials: 'credentials',
  keys_tokens: 'keys',
});

/** Deterministic string comparison (never locale-dependent). */
function compareText(a, b) {
  const left = String(a ?? '');
  const right = String(b ?? '');
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Deterministic numeric compare for descending sort. */
function compareNumberDesc(a, b) {
  return a === b ? 0 : a > b ? -1 : 1;
}

/** First non-empty trimmed string in a candidate list. */
function firstString(values) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim().length > 0) return value.trim();
  }
  return undefined;
}

/** Accept only a printable timestamp string; never call the wall clock. */
function normalizeGeneratedAt(value) {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  if (typeof value === 'string' && value.trim().length > 0) return value.trim();
  return 'unspecified';
}

/** Threshold map merged from DEFAULT_CONFIG plus the supplied config. */
function bulkThresholdsOf(config) {
  const base = DEFAULT_CONFIG.bulkThresholds;
  const result = { ...base };
  if (isPlainObject(config?.bulkThresholds)) {
    for (const [key, value] of Object.entries(config.bulkThresholds)) {
      if (Number.isInteger(value) && value >= 0) result[key] = value;
    }
  }
  return result;
}

/** Percentage with one decimal, locale independent. */
function pct(part, total) {
  const numerator = Number(part);
  const denominator = Number(total);
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0) return '0.0%';
  return `${((numerator / denominator) * 100).toFixed(1)}%`;
}

/** Integer display without locale grouping. */
function integerText(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? String(Math.floor(number)) : '0';
}

/** `1 finding` / `3 findings`, locale independent. */
function plural(count, singular, pluralForm = `${singular}s`) {
  const value = Number(count) || 0;
  return `${formatCount(value)} ${value === 1 ? singular : pluralForm}`;
}

/** Escape a value for a Markdown table cell or paragraph. */
function mdCell(value, max = 120) {
  let text;
  if (value === null || value === undefined) text = '';
  else if (typeof value === 'string') text = value;
  else text = String(value);
  text = truncate(text.replace(/\r?\n/gu, ' ').trim(), max);
  return text
    .replace(/\\/gu, '\\\\')
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/\[/gu, '\\[')
    .replace(/\]/gu, '\\]')
    .replace(/\|/gu, '\\|')
    .replace(/`/gu, '\\`');
}

/** Inline code span with target-controlled backticks neutralized. */
function codeSpan(value, max = 160) {
  let text = truncate(String(value ?? '').replace(/\r?\n/gu, ' ').trim(), max);
  text = text.replace(/`/gu, '\u02cb');
  return `\`${text}\``;
}

/** Bold inline label without breaking out of a bullet line. */
function inlineLabel(value, max = 100) {
  return `**${mdCell(value, max)}**`;
}

/** Render one Markdown table. */
function markdownTable(headers, rows, cellMax = 100) {
  const lines = [];
  lines.push(`| ${headers.map((header) => mdCell(header, 40)).join(' | ')} |`);
  lines.push(`| ${headers.map(() => '---').join(' | ')} |`);
  for (const row of rows) lines.push(`| ${row.map((cell) => mdCell(cell, cellMax)).join(' | ')} |`);
  return lines.join('\n');
}

/** Bullet list from already-safe lines. */
function bulletList(items) {
  return items.map((item) => `- ${item}`).join('\n');
}

/** Numbered list from already-safe lines. */
function numberedList(items) {
  return items.map((item, index) => `${index + 1}. ${item}`).join('\n');
}

/** `_Showing X of Y ..._` helper, or an empty string when everything fits. */
function truncationNote(shown, total, label) {
  if (shown >= total) return '';
  return `_Showing ${integerText(shown)} of ${integerText(total)} ${label}; the remainder is omitted here. The JSON export carries the complete live node/edge set, and the CSV exports are unbounded._`;
}

/** Mask one secret-looking value while preserving the rest of the string. */
function scrubString(value) {
  if (typeof value !== 'string') return value;
  const text = truncate(value, 1200);
  if (!SECRET_VALUE_RE.test(text)) return text;
  return text.replace(SECRET_VALUE_GLOBAL_RE, '[redacted]');
}

/**
 * Report-level lesson defense: redact any lesson text that carries target
 * identifiers (IPv4/URL/path/domain), secrets or PII before it is printed.
 */
function lessonText(value) {
  if (value === null || value === undefined) return '—';
  if (typeof value !== 'string') return scrubString(String(value));
  const text = truncate(value.replace(/\r?\n/gu, ' ').trim(), 500);
  if (text.length === 0) return '—';
  for (const pattern of LESSON_UNSAFE_PATTERNS) {
    if (pattern.test(text)) return '[redacted-lesson]';
  }
  return scrubString(text);
}

/** Recursively bound and re-redact an arbitrary public attribute value. */
function deepScrub(value, depth = 0) {
  if (depth > 6) return '[depth-limit]';
  if (typeof value === 'string') return scrubString(value);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 200).map((entry) => deepScrub(entry, depth + 1));
  if (!isPlainObject(value)) return null;
  const result = {};
  let count = 0;
  for (const [key, entry] of Object.entries(value)) {
    count += 1;
    if (count > 80) {
      result._truncated = true;
      break;
    }
    if (SECRET_KEY_PATTERN.test(key)) continue;
    const bounded = deepScrub(entry, depth + 1);
    if (bounded !== undefined) result[key] = bounded;
  }
  return result;
}

/**
 * Reduce any `samples` attribute to the only report-safe shape:
 * `{fields, masked, hashes, rowHash}`. Raw rows never survive this pass.
 */
function sanitizeSamples(attrs) {
  if (!isPlainObject(attrs)) return {};
  const result = { ...attrs };
  if (!Array.isArray(attrs.samples)) return result;
  result.samples = attrs.samples.slice(0, 200).map((sample) => {
    if (!isPlainObject(sample)) return { fields: [], masked: {}, hashes: {} };
    return {
      fields: Array.isArray(sample.fields) ? sample.fields.slice(0, 100).map((field) => String(field)) : [],
      masked: isPlainObject(sample.masked) ? deepScrub(sample.masked) : {},
      hashes: isPlainObject(sample.hashes) ? deepScrub(sample.hashes) : {},
      ...(typeof sample.rowHash === 'string' ? { rowHash: truncate(sample.rowHash, 128) } : {}),
    };
  });
  return result;
}

/** One report-safe node; starts from `publicNodeForReport` and re-bounds strings. */
function buildReportNode(node) {
  const pub = publicNodeForReport(node);
  const sanitized = sanitizeSamples(isPlainObject(pub.attrs) ? pub.attrs : {});
  const findingTitle = pub.kind === 'finding'
    ? localizedFindingTitle(sanitized.template ?? sanitized.category, pub.attrs?.title ?? pub.label)
    : null;
  if (findingTitle !== null) {
    sanitized.title = findingTitle;
  }
  return {
    id: String(pub.id ?? ''),
    kind: String(pub.kind ?? 'unknown'),
    key: scrubString(String(pub.key ?? '')),
    label: scrubString(String(findingTitle ?? pub.label ?? pub.key ?? '')),
    status: String(pub.status ?? 'unknown'),
    confidence: Number.isFinite(pub.confidence) ? Number(pub.confidence) : 0.5,
    verification: String(pub.verification ?? 'unverified'),
    attrs: deepScrub(sanitized),
    tags: (Array.isArray(pub.tags) ? pub.tags : []).slice(0, 30).map((tag) => scrubString(String(tag))),
    sources: (Array.isArray(pub.sources) ? pub.sources : []).slice(0, 20).map((source) => scrubString(String(source))),
    evidenceIds: (Array.isArray(pub.evidenceIds) ? pub.evidenceIds : []).slice(0, 100).map((id) => String(id)),
    firstSeen: typeof pub.firstSeen === 'string' ? pub.firstSeen : null,
    lastSeen: typeof pub.lastSeen === 'string' ? pub.lastSeen : null,
  };
}

/** Stable node order: kind rank, then key, then id (works for raw and report nodes). */
function compareReportNodes(a, b) {
  return (NODE_KIND_RANK[a.kind] ?? 99) - (NODE_KIND_RANK[b.kind] ?? 99)
    || compareText(a.key, b.key)
    || compareText(a.id, b.id);
}

/** Stable public edge order: kind rank, then id. */
function compareReportEdges(a, b) {
  return (EDGE_KIND_RANK[a.kind] ?? 99) - (EDGE_KIND_RANK[b.kind] ?? 99)
    || compareText(a.id, b.id);
}

/** Node ids referenced as `{kind,key}` or a raw id string. */
function resolveRefId(ref) {
  if (typeof ref === 'string') return ref;
  if (isPlainObject(ref)) {
    if (typeof ref.id === 'string') return ref.id;
    if (typeof ref.kind === 'string' && typeof ref.key === 'string') return nodeId(ref.kind, ref.key);
  }
  return undefined;
}

/** Public label for a `{kind,key}`/id reference attribute, or an em dash. */
function referenceLabel(ctx, attrs) {
  const explicit = firstString([attrs?.nodeRefLabel]);
  if (explicit !== undefined) return scrubString(explicit);
  if (attrs?.nodeRef === undefined || attrs?.nodeRef === null) return '—';
  const id = resolveRefId(attrs.nodeRef);
  return id === undefined ? '—' : ctx.labelOf(id);
}

/** Severity label canonicalized to the known vocabulary. */
function severityOf(node) {
  const text = String(node.attrs?.severity ?? 'info').toLowerCase();
  return Object.prototype.hasOwnProperty.call(SEVERITY_RANK, text) ? text : 'info';
}

/** CVSS v3.1 Base score/vector stored on a finding, if present. */
function cvssOf(node) {
  const attrs = node.attrs ?? {};
  const nested = isPlainObject(attrs.cvss) ? attrs.cvss : {};
  const rawScore = attrs.cvssScore ?? nested.baseScore;
  const score = Number(rawScore);
  const vector = firstString([attrs.cvssVector, nested.vector]);
  const severity = firstString([attrs.cvssSeverity, nested.baseSeverity]);
  if ((!Number.isFinite(score) || score < 0 || score > 10) && vector === undefined) {
    return { score: null, vector: null, severity: null };
  }
  return {
    score: Number.isFinite(score) && score >= 0 && score <= 10 ? score : null,
    vector: vector ?? null,
    severity: severity ?? null,
  };
}

/** Compact CVSS cell for the finding register. */
function cvssCell(node) {
  const cvss = cvssOf(node);
  if (cvss.score === null && cvss.vector === null) return '—';
  const score = cvss.score === null ? '—' : cvss.score.toFixed(1);
  return `${score}${cvss.severity ? ` ${cvss.severity}` : ''}`;
}

/** Severity after the loop's red-team rating override (used by §11/§12). */
function ratedSeverity(node) {
  const rated = String(node.attrs?.redteamRating ?? '').toLowerCase();
  if (Object.prototype.hasOwnProperty.call(SEVERITY_RANK, rated)) return rated;
  return severityOf(node);
}

/** Impact-epsilon score used for report ordering. */
function impactEp(node) {
  const impact = node.attrs?.impact;
  const candidates = [
    isPlainObject(impact) ? impact.ep : undefined,
    node.attrs?.ep,
    node.attrs?.impactEp,
    node.attrs?.impactScore,
    node.attrs?.epScore,
  ];
  for (const raw of candidates) {
    if (raw === undefined || raw === null || raw === '') continue;
    const value = Number(raw);
    if (Number.isFinite(value)) return value;
  }
  return 0;
}

/** Human-readable impact sentence for tables. */
function findingImpactText(node) {
  const impact = node.attrs?.impact;
  if (typeof impact === 'string' && impact.trim().length > 0) return scrubString(impact.trim());
  if (isPlainObject(impact)) {
    for (const key of ['summary', 'description', 'desc', 'statement', 'label']) {
      if (typeof impact[key] === 'string' && impact[key].trim().length > 0) return scrubString(impact[key].trim());
    }
  }
  for (const key of ['impactSummary', 'impactDescription', 'impactStatement', 'businessImpact']) {
    if (typeof node.attrs?.[key] === 'string' && node.attrs[key].trim().length > 0) return scrubString(node.attrs[key].trim());
  }
  const ep = impactEp(node);
  return ep > 0 ? `EP ${ep}` : '—';
}

/** Verification level for a finding. */
function verificationOf(node) {
  return scrubString(firstString([node.verification, node.attrs?.verification, node.attrs?.verificationLevel]) ?? 'unverified');
}

/** Gather CVEs from attributes and tags. */
function findingCves(node) {
  const values = [];
  for (const key of ['cve', 'cves', 'cveIds']) {
    const value = node.attrs?.[key];
    if (typeof value === 'string') values.push(value);
    else if (Array.isArray(value)) {
      for (const entry of value) if (typeof entry === 'string') values.push(entry);
    }
  }
  for (const tag of Array.isArray(node.tags) ? node.tags : []) {
    if (/^CVE-\d{4}-\d{4,}$/iu.test(tag)) values.push(tag.toUpperCase());
  }
  return uniqueStrings(values.map((entry) => scrubString(entry.trim())).filter((entry) => entry.length > 0));
}

/** Gather CWEs from attributes and tags. */
function findingCwes(node) {
  const values = [];
  for (const key of ['cwe', 'cwes', 'cweIds']) {
    const value = node.attrs?.[key];
    if (typeof value === 'string') values.push(value);
    else if (Array.isArray(value)) {
      for (const entry of value) if (typeof entry === 'string') values.push(entry);
    }
  }
  for (const tag of Array.isArray(node.tags) ? node.tags : []) {
    if (/^CWE-\d+$/iu.test(tag)) values.push(tag.toUpperCase());
  }
  return uniqueStrings(values.map((entry) => scrubString(entry.trim())).filter((entry) => entry.length > 0));
}

/** Finding register order: lifecycle, severity, impact.ep, id. */
function compareFindings(a, b) {
  const lifecycle = (LIFECYCLE_RANK[b.status] ?? 0) - (LIFECYCLE_RANK[a.status] ?? 0);
  if (lifecycle !== 0) return lifecycle;
  const severity = (SEVERITY_RANK[severityOf(b)] ?? 0) - (SEVERITY_RANK[severityOf(a)] ?? 0);
  if (severity !== 0) return severity;
  const impact = compareNumberDesc(impactEp(a), impactEp(b));
  if (impact !== 0) return impact;
  return compareText(a.id, b.id);
}

/** Count one field across nodes into a plain object. */
function countByField(nodes, pick) {
  const counts = {};
  for (const node of nodes) {
    const key = pick(node);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

/** Banded count for sensitive-data evidence. Never prints an exact row count. */
function bandCount(count) {
  if (!Number.isFinite(count) || count < 0) return 'unknown';
  const value = Math.floor(count);
  const bands = [
    [0, 0, '0'],
    [1, 9, '1–9'],
    [10, 99, '10–99'],
    [100, 499, '100–499'],
    [500, 999, '500–999'],
    [1000, 4999, '1k–4.9k'],
    [5000, 9999, '5k–9.9k'],
    [10000, 49999, '10k–49.9k'],
    [50000, 99999, '50k–99.9k'],
    [100000, Number.POSITIVE_INFINITY, '100k+'],
  ];
  for (let index = 0; index < bands.length; index += 1) {
    const [low, high, label] = bands[index];
    if (value >= low && value <= high) return `${label} (band ${index + 1})`;
  }
  return '100k+';
}

/** Data class for one sensitive-data node. */
function dataClassOf(node) {
  const attrs = node.attrs ?? {};
  const direct = firstString([attrs.dataClass, attrs.class, attrs.category, attrs.dataCategory]);
  if (direct !== undefined) return direct.toLowerCase();
  if (Array.isArray(attrs.categories) && attrs.categories.length > 0) {
    return attrs.categories.map((entry) => String(entry)).join('+').toLowerCase();
  }
  return 'unknown';
}

/** Reported count for one sensitive-data node (or undefined). */
function dataCountOf(node) {
  const attrs = node.attrs ?? {};
  for (const key of ['count', 'rowCount', 'rows', 'recordCount', 'totalCount', 'records']) {
    const raw = attrs[key];
    if (raw === undefined || raw === null || raw === '') continue;
    const value = Number(raw);
    if (Number.isFinite(value) && value >= 0) return Math.floor(value);
  }
  return undefined;
}

/** Bulk threshold applying to one data node. */
function dataThresholdOf(node, thresholds) {
  const attrs = node.attrs ?? {};
  const explicit = Number(attrs.threshold);
  if (Number.isInteger(explicit) && explicit >= 0) return explicit;
  const classKey = DATA_CLASS_THRESHOLD_KEY[dataClassOf(node)];
  if (classKey === undefined) return null;
  const configured = thresholds[classKey];
  return Number.isInteger(configured) && configured >= 0 ? configured : null;
}

/** Whether a data node's threshold was met (explicit flag wins). */
function thresholdMetOf(node, thresholds) {
  const attrs = node.attrs ?? {};
  if (typeof attrs.thresholdMet === 'boolean') return attrs.thresholdMet;
  const count = dataCountOf(node);
  const threshold = dataThresholdOf(node, thresholds);
  if (count === undefined || threshold === null) return undefined;
  return count >= threshold;
}

/** Hash summary for a sensitive-data node (never raw values). */
function dataHashesSummary(attrs) {
  const hashes = Array.isArray(attrs.hashes) ? attrs.hashes.filter((entry) => typeof entry === 'string') : [];
  if (hashes.length > 0) return hashes.slice(0, 3).map((hash) => truncate(hash, 24)).join('; ');
  const samples = Array.isArray(attrs.samples) ? attrs.samples : [];
  if (samples.length > 0) return `${samples.length} row hash(es)`;
  if (typeof attrs.rowHash === 'string' && attrs.rowHash.length > 0) return truncate(attrs.rowHash, 24);
  return '—';
}

/** Whether a node is an internal / lateral-movement asset. */
function isInternalAsset(node) {
  const attrs = node.attrs ?? {};
  if (node.kind === 'host') {
    if (attrs.realm === 'internal') return true;
    return isPrivateIp(String(attrs.addr ?? attrs.ip ?? ''));
  }
  if (node.kind === 'ip') return isPrivateIp(String(attrs.addr ?? node.key));
  if (node.kind === 'cidr') {
    const parsed = parseCidr(String(node.key));
    if (parsed !== undefined) {
      const address = parsed.version === 4 ? bigIntToIpv4(parsed.network) : bigIntToIpv6(parsed.network);
      return isPrivateIp(address);
    }
    return attrs.realm === 'internal';
  }
  if (node.kind === 'segment') return attrs.realm !== 'external';
  return false;
}

/** Address or realm column for an internal asset. */
function addressOf(node) {
  const attrs = node.attrs ?? {};
  if (node.kind === 'host') {
    const ips = Array.isArray(attrs.ips) ? attrs.ips.filter((entry) => typeof entry === 'string') : [];
    return firstString([attrs.addr, attrs.ip, ips.join(', '), attrs.realm, node.key]) ?? node.key;
  }
  if (node.kind === 'ip') return String(attrs.addr ?? node.key);
  if (node.kind === 'cidr') return node.key;
  return firstString([attrs.realm, attrs.segment, node.key]) ?? node.key;
}

/** Compact JSON for audit/result cells. */
function compactJson(value, max = 120) {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return truncate(scrubString(value), max);
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return truncate(JSON.stringify(deepScrub(value)), max);
  } catch {
    return '—';
  }
}

/** Inline JSON suitable for a code span. */
function inlineJson(value, max = 200) {
  try {
    return truncate(JSON.stringify(deepScrub(value)), max);
  } catch {
    return '{}';
  }
}

/** Verify the retained audit hash chain without mutating it. */
function verifyAuditChain(audit) {
  const entries = Array.isArray(audit) ? audit.filter((entry) => isPlainObject(entry)) : [];
  if (entries.length === 0) {
    return {
      entries: 0,
      hashValid: 0,
      hashInvalid: 0,
      linkValid: 0,
      linkInvalid: 0,
      tailHash: null,
      firstPrevHash: null,
      intact: true,
    };
  }
  let hashValid = 0;
  let hashInvalid = 0;
  let linkValid = 0;
  let linkInvalid = 0;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const expected = shortHash(stableStringify({
      id: entry.id,
      at: entry.at,
      tool: entry.tool,
      action: entry.action,
      target: entry.target ?? null,
      result: entry.result ?? null,
      evidenceIds: uniqueStrings(Array.isArray(entry.evidenceIds) ? entry.evidenceIds.filter((id) => typeof id === 'string') : []),
      prevHash: entry.prevHash ?? '',
    }), 32);
    if (expected === entry.hash) hashValid += 1;
    else hashInvalid += 1;
    if (index > 0) {
      if ((entries[index - 1].hash ?? '') === (entry.prevHash ?? '')) linkValid += 1;
      else linkInvalid += 1;
    }
  }
  return {
    entries: entries.length,
    hashValid,
    hashInvalid,
    linkValid,
    linkInvalid,
    tailHash: entries[entries.length - 1].hash ?? null,
    firstPrevHash: entries[0].prevHash ?? null,
    intact: hashInvalid === 0 && linkInvalid === 0,
  };
}

/** Group explicit `chain_step` nodes by `attrs.chainId`, in ordinal order. */
function groupExplicitChains(nodes) {
  const groups = new Map();
  for (const node of nodes) {
    if (node.kind !== 'chain_step') continue;
    const chainId = firstString([node.attrs?.chainId]) ?? 'chain';
    let list = groups.get(chainId);
    if (list === undefined) {
      list = [];
      groups.set(chainId, list);
    }
    list.push(node);
  }
  return [...groups.entries()]
    .map(([chainId, steps]) => ({
      chainId,
      steps: steps
        .slice()
        .sort((a, b) => (Number(a.attrs?.ordinal) || 0) - (Number(b.attrs?.ordinal) || 0) || compareText(a.id, b.id)),
    }))
    .sort((a, b) => compareText(a.chainId, b.chainId));
}

/** Build the derived, report-safe model once for all renderers. */
function buildContext(state, options = {}) {
  const generatedAt = normalizeGeneratedAt(options?.generatedAt);
  const suppliedConfig = isPlainObject(options?.config) ? options.config : {};
  const config = { ...DEFAULT_CONFIG, ...suppliedConfig };
  const thresholds = bulkThresholdsOf(suppliedConfig);

  const graph = {
    schema: typeof state?.schema === 'string' ? state.schema : STATE_SCHEMA,
    seq: Number(state?.seq) || 0,
    engagement: isPlainObject(state?.engagement) ? state.engagement : null,
    scope: isPlainObject(state?.scope) ? state.scope : { allow: [], deny: [], roe: {} },
    nodes: isPlainObject(state?.nodes) ? state.nodes : {},
    edges: isPlainObject(state?.edges) ? state.edges : {},
    aliases: isPlainObject(state?.aliases) ? state.aliases : {},
    audit: Array.isArray(state?.audit) ? state.audit : [],
    stats: isPlainObject(state?.stats) ? state.stats : {},
    lastAction: state?.lastAction ?? null,
  };

  const aliases = graph.aliases;
  const allNodes = Object.values(graph.nodes).filter((node) => isPlainObject(node));
  const liveNodes = allNodes.filter((node) => aliases[node.id] === undefined && node.status !== 'merged');
  const liveIdSet = new Set(liveNodes.map((node) => node.id));
  const liveEdges = Object.values(graph.edges)
    .filter((edge) => isPlainObject(edge))
    .filter((edge) => liveIdSet.has(edge.from) && liveIdSet.has(edge.to))
    .sort(compareReportEdges);

  const reportNodes = liveNodes.map((node) => buildReportNode(node)).sort(compareReportNodes);
  const reportById = new Map(reportNodes.map((node) => [node.id, node]));

  const outgoing = new Map();
  const incoming = new Map();
  const edgeById = new Map();
  for (const edge of liveEdges) {
    edgeById.set(edge.id, edge);
    if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
    outgoing.get(edge.from).push(edge);
    if (!incoming.has(edge.to)) incoming.set(edge.to, []);
    incoming.get(edge.to).push(edge);
  }

  /** Public label for a node id, resolving retired identities through aliases. */
  function labelOf(id) {
    const reportNode = reportById.get(id);
    if (reportNode !== undefined) return reportNode.label;
    const raw = graph.nodes[id] ?? graph.nodes[aliases[id]];
    if (raw !== undefined) return scrubString(String(raw.label ?? raw.key ?? id));
    return String(id);
  }

  /** Public kind for a node id. */
  function kindOf(id) {
    const reportNode = reportById.get(id);
    if (reportNode !== undefined) return reportNode.kind;
    const raw = graph.nodes[id] ?? graph.nodes[aliases[id]];
    return raw?.kind ?? 'unknown';
  }

  /** Resolve a `{kind,key}`/id reference and return its public label. */
  function labelFromRef(ref) {
    const id = resolveRefId(ref);
    if (id === undefined) return undefined;
    if (graph.nodes[id] === undefined && aliases[id] === undefined) return undefined;
    return labelOf(id);
  }

  /** Public label/kind for any node id in the report JSON. */
  const ctx = {
    state,
    graph,
    config,
    thresholds,
    generatedAt,
    liveNodes,
    liveEdges,
    reportNodes,
    reportById,
    outgoing,
    incoming,
    edgeById,
    labelOf,
    kindOf,
  };

  const findings = liveNodes.filter((node) => node.kind === 'finding').sort(compareFindings);
  const verifiedFindings = findings.filter((node) => ['verified', 'exploited', 'impacted'].includes(node.status));
  const candidates = findings.filter((node) => node.status === 'candidate');
  const fixedFindings = findings.filter((node) => node.status === 'fixed');

  const assets = liveNodes
    .filter((node) => node.kind === 'host' || node.kind === 'ip')
    .slice()
    .sort(compareReportNodes);
  const credentials = liveNodes
    .filter((node) => node.kind === 'credential')
    .slice()
    .sort((a, b) => (CREDENTIAL_VALIDITY_RANK[b.status] ?? 0) - (CREDENTIAL_VALIDITY_RANK[a.status] ?? 0)
      || compareText(String(a.attrs?.kind ?? ''), String(b.attrs?.kind ?? ''))
      || compareText(a.id, b.id));
  const accessNodes = liveNodes
    .filter((node) => node.kind === 'access')
    .slice()
    .sort((a, b) => (ACCESS_RANK[b.status] ?? 0) - (ACCESS_RANK[a.status] ?? 0)
      || compareText(String(a.attrs?.accessType ?? ''), String(b.attrs?.accessType ?? ''))
      || compareText(a.id, b.id));
  const validatedAccess = accessNodes.filter((node) => ['validated', 'escalated'].includes(node.status));
  const dataNodes = liveNodes
    .filter((node) => node.kind === 'data')
    .slice()
    .sort((a, b) => (DATA_STATUS_RANK[b.status] ?? 0) - (DATA_STATUS_RANK[a.status] ?? 0)
      || compareText(dataClassOf(a), dataClassOf(b))
      || compareText(a.id, b.id));
  const verifiedData = dataNodes.filter((node) => node.status === 'verified');
  const evidenceNodes = liveNodes
    .filter((node) => node.kind === 'evidence')
    .slice()
    .sort((a, b) => compareText(String(a.attrs?.collectedAt ?? ''), String(b.attrs?.collectedAt ?? ''))
      || compareText(a.id, b.id));
  const pivotNodes = liveNodes
    .filter((node) => node.kind === 'pivot')
    .slice()
    .sort((a, b) => compareText(a.id, b.id));
  const verifiedPivots = pivotNodes.filter((node) => node.status === 'verified' || node.attrs?.verified === true);
  const wildcardZoneNodes = liveNodes
    .filter((node) => node.kind === 'wildcard_zone')
    .slice()
    .sort((a, b) => compareText(a.key, b.key) || compareText(a.id, b.id));
  const internalAssets = liveNodes
    .filter((node) => isInternalAsset(node))
    .slice()
    .sort(compareReportNodes);

  const wildcard = {
    zones: wildcardZoneNodes.length,
    confirmed: 0,
    suspect: 0,
    inconclusive: 0,
    cleared: 0,
    hosts: { explicit: 0, suspect: 0, unknown: 0, cleared: 0 },
  };
  for (const zone of wildcardZoneNodes) {
    if (Object.prototype.hasOwnProperty.call(wildcard, zone.status) && typeof wildcard[zone.status] === 'number') {
      wildcard[zone.status] += 1;
    }
  }
  for (const node of liveNodes) {
    if (node.kind !== 'host') continue;
    const status = node.attrs?.wildcardStatus;
    if (status === 'suspect' || status === 'explicit' || status === 'cleared') wildcard.hosts[status] += 1;
    else wildcard.hosts.unknown += 1;
  }

  const servicesOf = (id) => (outgoing.get(id) ?? []).filter((edge) => edge.kind === 'exposes').length;
  const findingsByAsset = new Map();
  for (const finding of findings) {
    const subjectIds = new Set();
    for (const ref of [finding.attrs?.subjectId, finding.attrs?.assetId, finding.attrs?.targetId]) {
      const id = resolveRefId(ref);
      if (typeof id === 'string') subjectIds.add(id);
    }
    for (const edge of incoming.get(finding.id) ?? []) if (edge.kind === 'affects') subjectIds.add(edge.from);
    for (const edge of outgoing.get(finding.id) ?? []) if (edge.kind === 'affects') subjectIds.add(edge.to);
    for (const id of subjectIds) findingsByAsset.set(id, (findingsByAsset.get(id) ?? 0) + 1);
  }

  const coverage = {
    assets: assets.length,
    assetsWithServices: assets.filter((node) => servicesOf(node.id) > 0).length,
    assetsWithoutServices: 0,
    services: liveNodes.filter((node) => node.kind === 'service').length,
    webapps: liveNodes.filter((node) => node.kind === 'webapp').length,
    findings: findings.length,
    verifiedFindings: verifiedFindings.length,
    candidates: candidates.length,
    fixedFindings: fixedFindings.length,
    credentials: credentials.length,
    validatedCredentials: credentials.filter((node) => node.status === 'valid').length,
    access: accessNodes.length,
    validatedAccess: validatedAccess.length,
    data: dataNodes.length,
    verifiedData: verifiedData.length,
    pivots: pivotNodes.length,
    verifiedPivots: verifiedPivots.length,
    crownJewels: liveNodes.filter((node) => isCrownJewel(node)).length,
    evidence: evidenceNodes.length,
  };
  coverage.assetsWithoutServices = Math.max(0, coverage.assets - coverage.assetsWithServices);

  const baseSummary = graphSummary(graph);

  const allCrownPaths = computeCrownPaths(graph, { limit: LIMITS.crownPathCompute })
    .filter((path) => Array.isArray(path.nodes) && path.nodes.every((id) => liveIdSet.has(id)));
  const crownPaths = allCrownPaths.slice(0, LIMITS.crownPaths);
  const explicitChains = groupExplicitChains(liveNodes);
  const shownExplicitChains = explicitChains.slice(0, LIMITS.explicitChains);

  const severityCountsAll = countByField(findings, severityOf);
  const severityCountsVerified = countByField(verifiedFindings, severityOf);
  const dataThresholdMet = dataNodes.some((node) => thresholdMetOf(node, thresholds) === true);
  const lateralEdges = liveEdges.filter((edge) => LATERAL_EDGE_KINDS.has(edge.kind));

  const engagementName = truncate(
    scrubString(firstString([graph.engagement?.name, graph.engagement?.client]) ?? 'Unnamed engagement'),
    120,
  );

  ctx.findings = findings;
  ctx.verifiedFindings = verifiedFindings;
  ctx.candidates = candidates;
  ctx.fixedFindings = fixedFindings;
  ctx.assets = assets;
  ctx.credentials = credentials;
  ctx.accessNodes = accessNodes;
  ctx.validatedAccess = validatedAccess;
  ctx.dataNodes = dataNodes;
  ctx.verifiedData = verifiedData;
  ctx.evidenceNodes = evidenceNodes;
  ctx.pivotNodes = pivotNodes;
  ctx.verifiedPivots = verifiedPivots;
  ctx.wildcardZoneNodes = wildcardZoneNodes;
  ctx.internalAssets = internalAssets;
  ctx.wildcard = wildcard;
  ctx.servicesOf = servicesOf;
  ctx.findingsByAsset = findingsByAsset;
  ctx.coverage = coverage;
  ctx.dedupe = isPlainObject(baseSummary?.dedupe) ? baseSummary.dedupe : {};
  ctx.allCrownPaths = allCrownPaths;
  ctx.crownPaths = crownPaths;
  ctx.explicitChains = explicitChains;
  ctx.shownExplicitChains = shownExplicitChains;
  ctx.severityCountsAll = severityCountsAll;
  ctx.severityCountsVerified = severityCountsVerified;
  ctx.dataThresholdMet = dataThresholdMet;
  ctx.lateralEdges = lateralEdges;
  ctx.engagementName = engagementName;
  ctx.engagement = reportEngagement(graph.engagement);
  ctx.scopeReport = reportScope(graph.scope);
  ctx.auditChain = verifyAuditChain(graph.audit);

  const validated = validatedAccess.length;
  const verifiedDataCount = verifiedData.length;
  const crownPathTotal = allCrownPaths.length;

  ctx.summary = {
    engagementName,
    nodes: liveNodes.length,
    edges: liveEdges.length,
    verifiedFindings: verifiedFindings.length,
    validatedAccess: validated,
    verifiedData: verifiedDataCount,
    crownPaths: crownPathTotal,
    wildcard: wildcard.zones,
  };

  /** Resolve the subject label of a finding or data node. */
  ctx.subjectOf = (node) => {
    const attrs = node.attrs ?? {};
    for (const ref of [attrs.subjectId, attrs.subject, attrs.assetId, attrs.targetId]) {
      const label = labelFromRef(ref);
      if (label !== undefined) return label;
    }
    for (const key of ['subjectLabel', 'targetLabel', 'assetLabel', 'host', 'url', 'path']) {
      if (typeof attrs[key] === 'string' && attrs[key].trim().length > 0) return scrubString(attrs[key].trim());
    }
    return '—';
  };

  ctx.findingTitle = (node) => {
    const reportNode = reportById.get(node.id);
    const raw = firstString([node.attrs?.title, reportNode?.label, node.label, node.key, node.id]) ?? node.id;
    return scrubString(node.kind === 'finding' ? localizedFindingTitle(node.attrs?.template ?? node.attrs?.category, raw) : raw);
  };

  // §11/§12: supervised-loop state, supervisor reviews, intents and lessons.
  const loopNodes = liveNodes
    .filter((node) => node.kind === 'loop')
    .slice()
    .sort((a, b) => compareText(String(b.lastSeen ?? ''), String(a.lastSeen ?? '')) || compareText(a.id, b.id));
  const loopNode = loopNodes[0];
  const loopAttrs = loopNode === undefined ? {} : (reportById.get(loopNode.id)?.attrs ?? {});
  ctx.loop = loopNode === undefined
    ? null
    : { id: loopNode.id, phase: String(loopNode.status ?? loopAttrs.phase ?? 'unknown'), attrs: loopAttrs };

  const allSupervisions = liveNodes.filter((node) => node.kind === 'supervision');
  const supervisions = allSupervisions
    .slice()
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0)
      || compareText(String(b.attrs?.createdAt ?? ''), String(a.attrs?.createdAt ?? ''))
      || compareText(a.id, b.id))
    .slice(0, LIMITS.loopSupervisions);

  const allIntents = liveNodes.filter((node) => node.kind === 'intent');
  const intents = allIntents
    .slice()
    .sort((a, b) => {
      const active = (node) => (['open', 'claimed'].includes(node.status) ? 1 : 0);
      return active(b) - active(a)
        || (Number(b.attrs?.priority) || 0) - (Number(a.attrs?.priority) || 0)
        || (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0)
        || compareText(a.id, b.id);
    })
    .slice(0, LIMITS.loopIntents);

  const allLessons = liveNodes.filter((node) => node.kind === 'lesson');
  const lessonOrder = (a, b) => (Number(b.attrs?.confidence) || 0) - (Number(a.attrs?.confidence) || 0)
    || (Number(b.attrs?.uses) || 0) - (Number(a.attrs?.uses) || 0)
    || (Number(b.attrs?.wins) || 0) - (Number(a.attrs?.wins) || 0)
    || compareText(String(a.attrs?.lessonKey ?? a.key), String(b.attrs?.lessonKey ?? b.key));
  const lessons = allLessons.slice().sort(lessonOrder).slice(0, LIMITS.lessons);
  const lessonByKey = new Map();
  for (const lesson of allLessons.slice().sort(lessonOrder)) {
    const key = firstString([lesson.attrs?.lessonKey]) ?? lesson.key;
    if (!lessonByKey.has(key)) lessonByKey.set(key, lesson);
  }
  const appliedLessonKeys = Array.isArray(loopAttrs.appliedLessonKeys)
    ? loopAttrs.appliedLessonKeys.filter((key) => typeof key === 'string').slice(0, LIMITS.appliedLessons)
    : [];
  const usedLessonKeys = Array.isArray(loopAttrs.usedLessonKeys)
    ? loopAttrs.usedLessonKeys.filter((key) => typeof key === 'string').slice(0, LIMITS.appliedLessons)
    : [];
  ctx.supervisions = supervisions;
  ctx.supervisionTotal = allSupervisions.length;
  ctx.intents = intents;
  ctx.intentTotal = allIntents.length;
  ctx.lessons = lessons;
  ctx.lessonTotal = allLessons.length;
  ctx.lessonByKey = lessonByKey;
  ctx.appliedLessonKeys = appliedLessonKeys;
  ctx.usedLessonKeys = usedLessonKeys;

  const allSkills = liveNodes
    .filter((node) => node.kind === 'skill')
    .slice()
    .sort((a, b) => (Number(b.attrs?.confidence) || 0) - (Number(a.attrs?.confidence) || 0)
      || compareText(String(a.attrs?.name ?? a.label), String(b.attrs?.name ?? b.label)));
  ctx.skills = allSkills.slice(0, LIMITS.skills);
  ctx.skillTotal = allSkills.length;
  const allSelfTeams = liveNodes
    .filter((node) => node.kind === 'self_team')
    .slice()
    .sort((a, b) => compareText(String(a.attrs?.type ?? ''), String(b.attrs?.type ?? '')));
  ctx.selfTeams = allSelfTeams;
  ctx.selfTeamBrief = allSupervisions
    .filter((node) => node.attrs?.type === 'self_team_brief')
    .slice()
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0))[0] ?? null;

  ctx.frontierActions = computeFrontier(graph, { limit: 30 }).map(publicFrontierAction);
  return ctx;
}

/** Public engagement descriptor, scrubbed and key-filtered. */
function reportEngagement(engagement) {
  if (!isPlainObject(engagement)) return null;
  const result = {};
  for (const key of PUBLIC_ENGAGEMENT_KEYS) {
    if (engagement[key] === undefined) continue;
    result[key] = deepScrub(engagement[key]);
  }
  return result;
}

/** One scope entry with its note scrubbed. */
function reportScopeEntry(entry) {
  if (!isPlainObject(entry)) return null;
  const value = firstString([entry.canonical, entry.value]);
  if (value === undefined || typeof entry.type !== 'string') return null;
  const result = { type: entry.type, value: scrubString(value) };
  if (Array.isArray(entry.ports) && entry.ports.length > 0) result.ports = entry.ports.filter((port) => Number.isInteger(port));
  if (typeof entry.note === 'string' && entry.note.trim().length > 0) result.note = scrubString(entry.note.trim());
  return result;
}

/** Report-safe scope snapshot (allow/deny capped, RoE scrubbed). */
function reportScope(scope) {
  const summary = scopeSummary(scope);
  const allow = (summary.allow ?? []).slice(0, LIMITS.scopeEntries).map(reportScopeEntry).filter(Boolean);
  const deny = (summary.deny ?? []).slice(0, LIMITS.scopeEntries).map(reportScopeEntry).filter(Boolean);
  return {
    allow,
    deny,
    allowCount: summary.allowCount ?? 0,
    denyCount: summary.denyCount ?? 0,
    roe: deepScrub(isPlainObject(summary.roe) ? summary.roe : {}),
    updatedAt: summary.updatedAt ?? null,
    approvedAt: summary.approvedAt ?? null,
    approvalId: summary.approvalId ?? null,
    empty: (summary.allowCount ?? 0) === 0,
  };
}

/** Public edge record for the JSON export. */
function reportEdge(edge) {
  const evidenceIds = Array.isArray(edge.evidenceIds) ? edge.evidenceIds.slice(0, 100).map((id) => String(id)) : [];
  const base = {
    id: edge.id,
    from: edge.from,
    to: edge.to,
    kind: edge.kind,
    confidence: Number.isFinite(edge.confidence) ? edge.confidence : 0.5,
    ...(evidenceIds.length > 0 ? { evidenceIds } : {}),
    evidenceCount: evidenceIds.length,
  };
  const attrs = isPlainObject(edge.attrs) ? publicAttrs('edge', edge.attrs) : {};
  if (isPlainObject(attrs) && Object.keys(attrs).length > 0) {
    const bounded = deepScrub(attrs);
    if (isPlainObject(bounded) && Object.keys(bounded).length > 0) base.attrs = bounded;
  }
  return base;
}

/** Public frontier action for the JSON export. */
function publicFrontierAction(action) {
  const scope = isPlainObject(action.scope)
    ? {
      verdict: String(action.scope.verdict ?? 'unknown'),
      reason: scrubString(String(action.scope.reason ?? '')),
      allowedIps: Array.isArray(action.scope.allowedIps) ? action.scope.allowedIps.slice(0, 40).map(String) : [],
    }
    : null;
  return {
    actionId: String(action.actionId ?? ''),
    actionType: String(action.actionType ?? ''),
    targetId: action.targetId ?? null,
    targetKind: action.targetKind ?? null,
    targetLabel: scrubString(String(action.targetLabel ?? '')),
    priority: Number.isFinite(action.priority) ? action.priority : 0,
    why: (Array.isArray(action.why) ? action.why : []).slice(0, 12).map((entry) => scrubString(String(entry))),
    toolClass: action.toolClass ?? null,
    risk: action.risk ?? null,
    approvalRequired: action.approvalRequired === true,
    status: action.status ?? 'pending',
    params: deepScrub(isPlainObject(action.params) ? action.params : {}),
    scope,
    expectedEvidence: isPlainObject(action.expectedEvidence) ? deepScrub(action.expectedEvidence) : null,
  };
}

/** Build the full Markdown report. */
function renderMarkdown(ctx) {
  const parts = [
    renderHeader(ctx),
    renderExecutiveSummary(ctx),
    renderAuthorization(ctx),
    renderAssets(ctx),
    renderFindings(ctx),
    renderChains(ctx),
    renderCredentials(ctx),
    renderData(ctx),
    renderLateral(ctx),
    renderRemediation(ctx),
    renderEvidence(ctx),
    renderLoop(ctx),
    renderEvolution(ctx),
    renderAppendix(ctx),
    `---\n_Generated by AtkBrain at ${mdCell(ctx.generatedAt, 80)} (schema ${STATE_SCHEMA}). Sensitive values are masked; raw secrets and row data are never included; target-controlled strings are escaped._`,
  ];
  return `${parts.join('\n\n')}\n`;
}

/** Front matter table. */
function renderHeader(ctx) {
  const engagement = ctx.engagement;
  const rows = [
    ['Engagement', ctx.engagementName],
    ...(engagement?.client !== undefined ? [['Client', compactJson(engagement.client, 120)]] : []),
    ['Authorization reference', compactJson(engagement?.authorization, 120)],
    ['Authorized window', compactJson(engagement?.window, 120)],
    ['Engagement mode', compactJson(engagement?.mode, 80)],
    ['Report generated (UTC)', ctx.generatedAt],
    ['Report schema', STATE_SCHEMA],
  ];
  return [
    `# AtkBrain Engagement Report — ${mdCell(ctx.engagementName, 120)}`,
    markdownTable(['Field', 'Value'], rows),
  ].join('\n\n');
}

/** 1. Executive summary (kept to roughly one page). */
function renderExecutiveSummary(ctx) {
  const summary = ctx.summary;
  const verifiedCounts = ctx.severityCountsVerified;
  const criticalCount = verifiedCounts.critical ?? 0;
  const highCount = verifiedCounts.high ?? 0;
  const totalVerified = ctx.verifiedFindings.length;

  const statement = totalVerified === 0
    ? (ctx.findings.length === 0
      ? 'No findings are recorded, so there is no verified vulnerability to report and no confirmed exposure.'
      : 'No finding has been verified yet: the recorded evidence is still at the candidate stage, so this report should not be treated as a confirmed vulnerability assessment.')
    : `${plural(totalVerified, 'verified finding')}: ${formatCount(criticalCount)} critical and ${formatCount(highCount)} high.`;

  const accessStatement = ctx.validatedAccess.length > 0
    ? `${plural(ctx.validatedAccess.length, 'access path')} validated, up to privilege "${mdCell(firstString(ctx.validatedAccess.map((node) => node.attrs?.privilege)) ?? 'unknown', 40)}".`
    : 'No access path has been validated to a shell, database, admin panel or cloud role yet.';

  const pathStatement = ctx.allCrownPaths.length > 0
    ? `Milestone paths computed: ${formatCount(ctx.allCrownPaths.length)} (see §5).`
    : 'No realized foothold currently reaches a milestone target.';

  const dataStatement = ctx.verifiedData.length > 0
    ? `Verified sensitive-data evidence sets: ${formatCount(ctx.verifiedData.length)}${ctx.dataThresholdMet ? ', and at least one bulk-impact threshold was met' : ', without a bulk-impact threshold being met'}.`
    : 'No sensitive-data evidence has been verified.';

  const wildcardStatement = `Wildcard DNS analysis classified ${formatCount(ctx.wildcard.zones)} zone(s): ${integerText(ctx.wildcard.confirmed)} confirmed, ${integerText(ctx.wildcard.suspect)} suspect, ${integerText(ctx.wildcard.inconclusive)} inconclusive, ${integerText(ctx.wildcard.cleared)} cleared.`;

  const metrics = [
    ['Authorized assets (host/IP)', integerText(ctx.assets.length)],
    ['Services with observed exposure', integerText(ctx.coverage.services)],
    ['Verified findings', integerText(summary.verifiedFindings)],
    ['CVSS vulnerabilities (High/Critical)', integerText(ctx.coverage.vulnerabilities ?? 0)],
    ['Unscored findings', integerText(ctx.coverage.unscoredFindings ?? 0)],
    ['Validated access paths', integerText(summary.validatedAccess)],
    ['Verified sensitive-data evidence', integerText(summary.verifiedData)],
    ['Milestone paths', integerText(summary.crownPaths)],
    ['Wildcard DNS zones', integerText(summary.wildcard)],
    ['Evidence artifacts', integerText(ctx.evidenceNodes.length)],
    ['Audit entries retained', integerText(ctx.auditChain.entries)],
  ];

  const topFindings = ctx.verifiedFindings.slice(0, 5);
  const topBlock = topFindings.length === 0
    ? '_No verified findings are available for the executive summary._'
    : bulletList(topFindings.map((node) => {
      const severity = severityOf(node).toUpperCase();
      const ep = impactEp(node);
      return `${inlineLabel(severity, 20)} — ${inlineLabel(ctx.findingTitle(node), 100)} (${mdCell(ctx.subjectOf(node), 70)}); lifecycle ${mdCell(node.status, 20)}, impact EP ${ep > 0 ? ep : '—'}.`;
    }));

  const authLine = ctx.scopeReport.empty
    ? '**WARNING:** no authorized scope is recorded in this graph. Any active testing is out of policy until an approved allow list exists.'
    : `All graph actions are constrained by an allow list of ${integerText(ctx.scopeReport.allowCount)} entry(ies) with ${integerText(ctx.scopeReport.denyCount)} explicit exclusion(s); deny entries take precedence.`;

  const approvalLine = ctx.scopeReport.approvedAt !== null
    ? `Scope approved${ctx.scopeReport.approvalId !== null ? ` under reference ${codeSpan(String(ctx.scopeReport.approvalId), 80)}` : ''} at ${mdCell(ctx.scopeReport.approvedAt, 40)}.`
    : 'Scope is recorded but has no approval timestamp; treat the engagement as draft until approval is captured.';

  const evidenceLine = ctx.auditChain.entries === 0
    ? 'No audit entries are retained, so chain-of-custody cannot be verified from this export.'
    : `Audit hash chain: ${ctx.auditChain.intact ? 'intact' : '**failed integrity check**'} across ${integerText(ctx.auditChain.entries)} retained entrie(s); tail hash ${codeSpan(ctx.auditChain.tailHash ?? '—', 64)}.`;

  return [
    '## 1. Executive Summary',
    `${statement} ${accessStatement}`,
    pathStatement,
    dataStatement,
    wildcardStatement,
    '### Headline metrics',
    markdownTable(['Metric', 'Value'], metrics),
    '### Most significant verified findings',
    topBlock,
    '### Authorization and evidence posture',
    bulletList([authLine, approvalLine, evidenceLine, 'This report contains no raw secrets, credentials or PII: credential values are represented by a mask plus an HMAC fingerprint, and sensitive-data evidence is banded and hash-only.']),
  ].join('\n\n');
}

/** 2. Authorization, scope and methodology. */
function renderAuthorization(ctx) {
  const scope = ctx.scopeReport;
  const roe = isPlainObject(scope.roe) ? scope.roe : {};
  const engagement = ctx.engagement;

  const authorizationRows = [
    ['Engagement name', ctx.engagementName],
    ['Client', compactJson(engagement?.client, 120)],
    ['Authorization reference', compactJson(engagement?.authorization, 120)],
    ['Authorized window', compactJson(engagement?.window, 120)],
    ['Mode', compactJson(engagement?.mode, 80)],
    ['Engagement notes', compactJson(engagement?.notes, 200)],
  ];

  const allowRows = scope.allow.map((entry) => [
    entry.type,
    entry.value,
    Array.isArray(entry.ports) && entry.ports.length > 0 ? entry.ports.join(', ') : 'any',
    entry.note ?? '',
  ]);
  const denyRows = scope.deny.map((entry) => [
    entry.type,
    entry.value,
    Array.isArray(entry.ports) && entry.ports.length > 0 ? entry.ports.join(', ') : 'any',
    entry.note ?? '',
  ]);

  const roeRows = [
    ['Max queries per second', roe.maxQps !== null && roe.maxQps !== undefined ? String(roe.maxQps) : 'not capped'],
    ['Max hosts per action', roe.maxHostsPerAction !== null && roe.maxHostsPerAction !== undefined ? String(roe.maxHostsPerAction) : 'not capped'],
    ['Max ports per action', roe.maxPortsPerAction !== null && roe.maxPortsPerAction !== undefined ? String(roe.maxPortsPerAction) : 'not capped'],
    ['Permitted techniques', Array.isArray(roe.techniques) && roe.techniques.length > 0 ? roe.techniques.map((entry) => scrubString(String(entry))).join(', ') : 'not specified'],
    ['Scope updated at', scope.updatedAt ?? '—'],
    ['Scope approved at', scope.approvedAt ?? '—'],
    ['Approval reference', scope.approvalId ?? '—'],
  ];

  const methodology = [
    `**Scope normalization.** Hostnames are lowercased and IDNA-normalized; deny entries always win; allow entries may restrict ports. The frontier refuses any target outside the allow list.`,
    `**Asset discovery and dedupe.** Imported artifacts are merged by canonical identity; wildcard DNS is classified with at least ${integerText(ctx.config.wildcardProbes)} randomized probes plus a guard probe before a host is accepted.`,
    '**Service exposure.** TCP probing and safe, read-only HTTP checks only; no destructive payload is sent during discovery.',
    '**Vulnerability verification.** A finding is `verified` only after a repeatable reproduction is stored with hashes; `exploited` and `impacted` require demonstrated security and business impact respectively.',
    '**Access validation.** Footholds are proven with an engagement nonce and privilege mapping; escalation and persistence are executed only when the rules of engagement allow them.',
    '**Sensitive-data evidence.** Only metadata, field names, banded counts, per-field HMACs and row hashes are retained; raw rows are never stored in graph state or reports.',
    '**Lateral movement.** Tunnels require explicit approval; a pivot is verified only by a far-side nonce round-trip through the tunnel.',
    '**Chain of custody.** Every evidence artifact carries a path plus SHA-256; audit entries form a hash chain whose tail is reported in §10.',
  ];

  const parts = [
    '## 2. Authorization, Scope & Methodology',
    markdownTable(['Authorization field', 'Value'], authorizationRows),
    '### Authorized scope (allow)',
  ];
  if (allowRows.length === 0) parts.push('_No allow entries are recorded — no network action should have been executed._');
  else {
    parts.push(markdownTable(['Type', 'Value', 'Ports', 'Note'], allowRows));
    const note = truncationNote(allowRows.length, scope.allowCount, 'allow entries');
    if (note.length > 0) parts.push(note);
  }
  parts.push('### Explicit exclusions (deny)');
  if (denyRows.length === 0) parts.push('_No explicit deny entries recorded._');
  else {
    parts.push(markdownTable(['Type', 'Value', 'Ports', 'Note'], denyRows));
    const note = truncationNote(denyRows.length, scope.denyCount, 'deny entries');
    if (note.length > 0) parts.push(note);
  }
  parts.push('### Rules of engagement');
  parts.push(markdownTable(['Rule', 'Value'], roeRows));
  parts.push('### Methodology');
  parts.push(numberedList(methodology.map((entry) => entry)));
  parts.push('### Evidence and redaction policy');
  parts.push(bulletList([
    'Credential nodes keep only `secretMask` (a display mask) and `secretFp` (an HMAC fingerprint); raw secrets are never written to graph state.',
    'Sensitive-data nodes keep field names, banded counts and hashes only; raw rows and raw PII are never exported.',
    'Every node printed in this report passes through the public report projection; secret-keyed attributes are dropped even if a tool stored them by mistake.',
    'Target-controlled strings (titles, banners, paths) are escaped before they reach Markdown tables.',
    'Evidence artifacts are stored outside the session log; this report references them by path and SHA-256.',
  ]));
  return parts.join('\n\n');
}

/** 3. Asset inventory, dedupe statistics and wildcard classification. */
function renderAssets(ctx) {
  const coverageRows = [
    ['Authorized assets (host/IP)', integerText(ctx.coverage.assets)],
    ['Assets with observed services', integerText(ctx.coverage.assetsWithServices)],
    ['Assets without services', integerText(ctx.coverage.assetsWithoutServices)],
    ['Services', integerText(ctx.coverage.services)],
    ['Web applications', integerText(ctx.coverage.webapps)],
    ['Findings (all statuses)', integerText(ctx.coverage.findings)],
    ['Vulnerabilities (not refuted)', integerText(ctx.coverage.vulnerabilities ?? 0)],
    ['Unscored findings', integerText(ctx.coverage.unscoredFindings ?? 0)],
    ['Milestone nodes', integerText(ctx.coverage.crownJewels)],
    ['Credentials', integerText(ctx.coverage.credentials)],
    ['Access paths', integerText(ctx.coverage.access)],
    ['Sensitive-data evidence', integerText(ctx.coverage.data)],
    ['Pivots', integerText(ctx.coverage.pivots)],
    ['Evidence artifacts', integerText(ctx.coverage.evidence)],
  ];

  const dedupe = ctx.dedupe;
  const dedupeRows = [
    ['Imported artifacts', integerText(dedupe.importedArtifacts)],
    ['Raw entries', integerText(dedupe.rawEntries)],
    ['Unique identities', integerText(dedupe.unique)],
    ['Collapsed duplicates', integerText(dedupe.collapsed)],
    ['Collision conflicts', integerText(dedupe.conflicts)],
    ['Quarantined entries', integerText(dedupe.quarantined)],
    ['Wildcard zones identified', integerText(dedupe.wildcardZones)],
    ['Suspected wildcard assets', integerText(dedupe.suspects)],
    ['Stub nodes created by edge ordering', integerText(dedupe.stubNodes)],
    ['Refused / out-of-scope actions', integerText(dedupe.refused)],
  ];

  const assetRows = ctx.assets.slice(0, LIMITS.assets).map((node) => {
    const reportNode = ctx.reportById.get(node.id);
    const label = reportNode?.label ?? ctx.labelOf(node.id);
    return [
      node.kind,
      label,
      node.status,
      String(node.attrs?.wildcardStatus ?? 'unknown'),
      integerText(ctx.servicesOf(node.id)),
      integerText(ctx.findingsByAsset.get(node.id) ?? 0),
      integerText(Array.isArray(node.sources) ? node.sources.length : 0),
    ];
  });

  const zoneRows = ctx.wildcardZoneNodes.slice(0, LIMITS.wildcardZones).map((node) => {
    const reportNode = ctx.reportById.get(node.id);
    const attrs = reportNode?.attrs ?? {};
    const probes = Array.isArray(attrs.probes) ? attrs.probes.length : 0;
    return [
      reportNode?.label ?? ctx.labelOf(node.id),
      node.status,
      attrs.cdn === true ? 'yes' : 'no',
      integerText(probes),
      Number.isFinite(reportNode?.confidence) ? reportNode.confidence.toFixed(2) : '0.50',
      node.lastSeen ?? '—',
    ];
  });

  const wildcardRows = [
    ['Wildcard zones', integerText(ctx.wildcard.zones)],
    ['— confirmed', integerText(ctx.wildcard.confirmed)],
    ['— suspect', integerText(ctx.wildcard.suspect)],
    ['— inconclusive', integerText(ctx.wildcard.inconclusive)],
    ['— cleared', integerText(ctx.wildcard.cleared)],
    ['Hosts: explicit resolution', integerText(ctx.wildcard.hosts.explicit)],
    ['Hosts: wildcard suspect', integerText(ctx.wildcard.hosts.suspect)],
    ['Hosts: wildcard status unknown', integerText(ctx.wildcard.hosts.unknown)],
    ['Hosts: wildcard cleared', integerText(ctx.wildcard.hosts.cleared)],
  ];

  const rawEntries = Number(dedupe.rawEntries) || 0;
  const collapsed = Number(dedupe.collapsed) || 0;
  const dedupeSentence = rawEntries > 0
    ? `Dedupe reduced ${integerText(rawEntries)} raw entries to ${integerText(dedupe.unique)} unique identities (${pct(collapsed, rawEntries)} collapsed; ${integerText(dedupe.quarantined)} quarantined).`
    : 'No ingestion statistics are recorded for this state, so dedupe effectiveness cannot be quantified.';

  const excludedCount = ctx.graph.aliases !== undefined ? Object.keys(ctx.graph.aliases).length : 0;
  const suspectCount = ctx.wildcard.suspect + ctx.wildcard.hosts.suspect;

  const parts = [
    '## 3. Asset Inventory & Dedupe',
    '### Coverage',
    markdownTable(['Metric', 'Value'], coverageRows),
    '### Dedupe statistics',
    markdownTable(['Dedupe metric', 'Value'], dedupeRows),
    dedupeSentence,
    `### Assets (top ${LIMITS.assets})`,
  ];
  if (assetRows.length === 0) parts.push('_No host or IP assets are recorded._');
  else {
    parts.push(markdownTable(['Kind', 'Label', 'Status', 'Wildcard', 'Services', 'Findings', 'Sources'], assetRows));
    const note = truncationNote(assetRows.length, ctx.assets.length, 'assets');
    if (note.length > 0) parts.push(note);
  }
  parts.push('### Wildcard DNS classification');
  parts.push(markdownTable(['Classification', 'Count'], wildcardRows));
  if (zoneRows.length === 0) parts.push('_No wildcard zones were recorded; every host resolution is explicit._');
  else {
    parts.push(markdownTable(['Zone', 'Status', 'CDN', 'Probes', 'Confidence', 'Last seen'], zoneRows));
    const note = truncationNote(zoneRows.length, ctx.wildcardZoneNodes.length, 'wildcard zones');
    if (note.length > 0) parts.push(note);
  }
  parts.push(`_Excluded identities: ${integerText(excludedCount)}. Suspect assets: ${integerText(suspectCount)}. Details are listed in the Appendix and are not counted as confirmed assets._`);
  return parts.join('\n\n');
}

/** 4. Verified findings register. */
function renderFindings(ctx) {
  const counts = ctx.severityCountsVerified;
  const severityRows = SEVERITY_ORDER.map((severity) => [severity, integerText(counts[severity] ?? 0)]);

  const verifiedRows = ctx.verifiedFindings.slice(0, LIMITS.findings).map((node) => {
    const cve = findingCves(node);
    const cwe = findingCwes(node);
    const refs = [...cve, ...cwe];
    return [
      severityOf(node).toUpperCase(),
      cvssCell(node),
      node.status,
      ctx.findingTitle(node),
      ctx.subjectOf(node),
      verificationOf(node),
      impactEp(node) > 0 ? String(impactEp(node)) : '—',
      refs.length > 0 ? refs.join(', ') : '—',
      integerText(Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0),
    ];
  });

  const parts = [
    '## 4. Verified Findings',
    `Verified findings are those the engagement reproduced (\`verified\`), demonstrated a security impact for (\`exploited\`), or demonstrated a business impact for (\`impacted\`). Rows are ordered by lifecycle (impacted, exploited, verified), then severity, then impact EP, then finding id. Candidate (${integerText(ctx.candidates.length)}) and fixed (${integerText(ctx.fixedFindings.length)}) findings are excluded from this section but remain in \`findingsCsv\` and the JSON graph.`,
    '### Severity distribution (verified only)',
    markdownTable(['Severity', 'Verified findings'], severityRows),
  ];
  if (verifiedRows.length === 0) {
    parts.push('_No verified findings are recorded. Candidates still require reproduction before they can be reported as vulnerabilities._');
  } else {
    parts.push(`### Finding register (top ${LIMITS.findings})`);
    parts.push(markdownTable(['Severity', 'CVSS', 'Status', 'Title', 'Subject', 'Verification', 'EP', 'CVE / CWE', 'Evidence'], verifiedRows));
    const cvssRows = ctx.verifiedFindings
      .map((node) => {
        const cvss = cvssOf(node);
        return cvss.vector === null ? null : [inlineLabel(ctx.findingTitle(node), 100), cvss.score === null ? '—' : cvss.score.toFixed(1), cvss.severity ?? '—', codeSpan(cvss.vector, 160)];
      })
      .filter((row) => row !== null)
      .slice(0, LIMITS.findings);
    if (cvssRows.length > 0) {
      parts.push('### CVSS v3.1 Base vectors');
      parts.push(markdownTable(['Finding', 'Base score', 'NVD severity', 'Vector'], cvssRows));
      parts.push('_CVSS is a severity score, not proof of exploitability or risk. The evidence and verification state above remain authoritative; Temporal and Environmental metrics are not filled by the plugin._');
    }
    const note = truncationNote(verifiedRows.length, ctx.verifiedFindings.length, 'verified findings');
    if (note.length > 0) parts.push(note);
  }
  return parts.join('\n\n');
}

/** 5. Attack chains: milestone paths and explicit chain steps. */
function crownPathMarkdown(ctx, path, index) {
  const target = ctx.labelOf(path.targetId);
  const cost = Number.isFinite(path.cost) ? path.cost.toFixed(3) : '0.000';
  const lines = [
    `${inlineLabel(`Path ${index + 1} — ${target}`, 120)} (${mdCell(path.targetKind, 30)}; cost ${cost}; ${integerText(path.steps.length)} step(s))`,
  ];
  const steps = path.steps.map((step) => {
    const from = inlineLabel(ctx.labelOf(step.from), 90);
    const to = inlineLabel(ctx.labelOf(step.to), 90);
    return `${from} \u2014[${mdCell(step.kind, 30)}]\u2192 ${to}`;
  });
  if (steps.length === 0) lines.push('- _The foothold is itself the milestone target._');
  else lines.push(bulletList(steps));
  lines.push(`_Path id ${codeSpan(path.chainId, 80)}._`);
  return lines.join('\n');
}

function renderChains(ctx) {
  const parts = [
    '## 5. Attack Chains',
    `Milestone paths are weighted shortest paths from a realized foothold (validated/escalated access or verified pivot) to a milestone target. ${integerText(ctx.allCrownPaths.length)} path(s) were computed and ${integerText(ctx.crownPaths.length)} are shown below. Edge weights favor structural links and penalize uncertain or exploit-heavy hops.`,
    '### Milestone paths',
  ];
  if (ctx.crownPaths.length === 0) {
    parts.push('_No milestone path could be computed: either no foothold is realized yet or no milestone target is reachable from one._');
  } else {
    parts.push(ctx.crownPaths.map((path, index) => crownPathMarkdown(ctx, path, index)).join('\n\n'));
    const note = truncationNote(ctx.crownPaths.length, ctx.allCrownPaths.length, 'milestone paths');
    if (note.length > 0) parts.push(note);
  }
  parts.push('### Explicit attack chains');
  if (ctx.shownExplicitChains.length === 0) {
    parts.push('_No explicit `chain_step` nodes are recorded. Chains are optional narrative evidence; the milestone paths above are derived from the graph._');
  } else {
    for (const group of ctx.shownExplicitChains) {
      const rows = group.steps.slice(0, LIMITS.chainSteps).map((step) => {
        const reportNode = ctx.reportById.get(step.id);
        const attrs = reportNode?.attrs ?? step.attrs ?? {};
        const nodeRef = referenceLabel(ctx, attrs);
        return [
          String(Number(attrs.ordinal) || 0),
          String(attrs.stage ?? 'recon'),
          String(step.status ?? 'unknown'),
          reportNode?.label ?? ctx.labelOf(step.id),
          nodeRef,
          integerText(Array.isArray(step.evidenceIds) ? step.evidenceIds.length : 0),
        ];
      });
      const block = [
        `#### Chain ${mdCell(group.chainId, 80)} (${integerText(group.steps.length)} step(s))`,
        markdownTable(['Ordinal', 'Stage', 'Status', 'Step', 'Referenced node', 'Evidence'], rows),
      ];
      const note = truncationNote(rows.length, group.steps.length, 'chain steps');
      if (note.length > 0) block.push(note);
      parts.push(block.join('\n\n'));
    }
    const chainNote = truncationNote(ctx.shownExplicitChains.length, ctx.explicitChains.length, 'explicit chains');
    if (chainNote.length > 0) parts.push(chainNote);
  }
  return parts.join('\n\n');
}

/** Masked username display for credential tables. */
function maskUsername(value) {
  const text = String(value ?? '').trim();
  if (text.length === 0) return '—';
  if (text.includes('@')) return maskEmail(text);
  return truncate(text, 80);
}

/** 6. Credentials and access paths (masked). */
function renderCredentials(ctx) {
  const credentialRows = ctx.credentials.slice(0, LIMITS.credentials).map((node) => {
    const reportNode = ctx.reportById.get(node.id);
    const attrs = reportNode?.attrs ?? {};
    const secretMask = firstString([attrs.secretMask, attrs.mask]) ?? (firstString([attrs.secretFp]) !== undefined ? '[redacted]' : '—');
    return [
      firstString([attrs.kind, attrs.type]) ?? 'unknown',
      maskUsername(attrs.username ?? attrs.user ?? node.key),
      secretMask,
      firstString([attrs.secretFp, attrs.fingerprint]) ?? '—',
      node.status,
      firstString([attrs.privilege, attrs.role]) ?? 'unknown',
      attrs.targetId !== undefined ? ctx.labelOf(resolveRefId(attrs.targetId) ?? node.key) : '—',
      integerText(Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0),
    ];
  });

  const accessRows = ctx.accessNodes.slice(0, LIMITS.access).map((node) => {
    const reportNode = ctx.reportById.get(node.id);
    const attrs = reportNode?.attrs ?? {};
    return [
      firstString([attrs.accessType, attrs.type]) ?? 'unknown',
      firstString([attrs.privilege, attrs.role]) ?? 'unknown',
      node.status,
      attrs.assetId !== undefined || attrs.targetId !== undefined
        ? ctx.labelOf(resolveRefId(attrs.assetId ?? attrs.targetId) ?? '')
        : '—',
      verificationOf(node),
      firstString([attrs.blastRadius, attrs.scope]) ?? 'unknown',
      integerText(Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0),
    ];
  });

  const validCredentials = ctx.credentials.filter((node) => node.status === 'valid').length;
  const parts = [
    '## 6. Credentials & Access',
    `The graph holds ${integerText(ctx.credentials.length)} credential record(s), of which ${integerText(validCredentials)} are validated, and ${integerText(ctx.accessNodes.length)} access path(s), of which ${integerText(ctx.validatedAccess.length)} are validated or escalated. Raw secrets are never stored: only a display mask and an HMAC fingerprint are reported.`,
    `### Credentials (top ${LIMITS.credentials})`,
  ];
  if (credentialRows.length === 0) parts.push('_No credential records are recorded._');
  else {
    parts.push(markdownTable(['Kind', 'Username', 'Secret (masked)', 'Fingerprint', 'Validity', 'Privilege', 'Target', 'Evidence'], credentialRows));
    const note = truncationNote(credentialRows.length, ctx.credentials.length, 'credentials');
    if (note.length > 0) parts.push(note);
  }
  parts.push(`### Access paths (top ${LIMITS.access})`);
  if (accessRows.length === 0) parts.push('_No access paths are recorded._');
  else {
    parts.push(markdownTable(['Access type', 'Privilege', 'Status', 'Asset', 'Verification', 'Blast radius', 'Evidence'], accessRows));
    const note = truncationNote(accessRows.length, ctx.accessNodes.length, 'access paths');
    if (note.length > 0) parts.push(note);
  }
  return parts.join('\n\n');
}

/** 7. Sensitive-data evidence (banded counts, thresholds, hashes). */
function renderData(ctx) {
  const dataRows = ctx.dataNodes.slice(0, LIMITS.data).map((node) => {
    const reportNode = ctx.reportById.get(node.id);
    const attrs = reportNode?.attrs ?? {};
    const count = dataCountOf(node);
    const threshold = dataThresholdOf(node, ctx.thresholds);
    const met = thresholdMetOf(node, ctx.thresholds);
    const samples = Array.isArray(attrs.samples) ? attrs.samples.length : 0;
    return [
      dataClassOf(node),
      count === undefined ? 'unknown' : bandCount(count),
      threshold === null ? '—' : String(threshold),
      met === undefined ? 'unknown' : met ? 'yes' : 'no',
      ctx.subjectOf(node),
      node.status,
      integerText(samples),
      dataHashesSummary(attrs),
    ];
  });

  const thresholdRows = Object.entries(ctx.thresholds)
    .sort((a, b) => compareText(a[0], b[0]))
    .map(([key, value]) => [key, integerText(value)]);

  const sampleBlocks = [];
  for (const node of ctx.dataNodes.slice(0, 5)) {
    const reportNode = ctx.reportById.get(node.id);
    const attrs = reportNode?.attrs ?? {};
    const samples = Array.isArray(attrs.samples) ? attrs.samples.slice(0, LIMITS.samplesPerDataNode) : [];
    const lines = [];
    for (let index = 0; index < samples.length; index += 1) {
      const sample = isPlainObject(samples[index]) ? samples[index] : {};
      const fields = Array.isArray(sample.fields) ? sample.fields.map(String).join(', ') : '—';
      const masked = isPlainObject(sample.masked) ? inlineJson(sample.masked) : '{}';
      const rowHash = typeof sample.rowHash === 'string' ? sample.rowHash : '—';
      lines.push(`- Sample ${index + 1}: fields ${codeSpan(fields, 120)}; masked values ${codeSpan(masked, 200)}; row hash ${codeSpan(rowHash, 80)}.`);
    }
    if (lines.length === 0) lines.push('- _No masked samples recorded._');
    sampleBlocks.push([`**${mdCell(ctx.subjectOf(node), 100)}** (${mdCell(dataClassOf(node), 40)}, ${mdCell(node.status, 20)})`, ...lines].join('\n'));
  }

  const parts = [
    '## 7. Sensitive Data Evidence',
    'Only evidence metadata is stored: data class, a banded count, the applicable bulk threshold, field names, and HMAC/SHA hashes. Raw rows and raw PII are never retained, so the counts below are deliberately presented as bands rather than exact record counts.',
    `### Data evidence register (top ${LIMITS.data})`,
  ];
  if (dataRows.length === 0) parts.push('_No sensitive-data evidence is recorded._');
  else {
    parts.push(markdownTable(['Class', 'Count (band)', 'Threshold', 'Threshold met', 'Subject', 'Status', 'Samples', 'Hashes'], dataRows));
    const note = truncationNote(dataRows.length, ctx.dataNodes.length, 'data evidence sets');
    if (note.length > 0) parts.push(note);
  }
  parts.push('### Bulk thresholds in effect');
  parts.push(markdownTable(['Class key', 'Threshold (rows)'], thresholdRows));
  parts.push('### Masked samples');
  if (sampleBlocks.length === 0) parts.push('_No masked samples are available._');
  else parts.push(sampleBlocks.join('\n\n'));
  return parts.join('\n\n');
}

/** 8. Internal assets, pivots and lateral movement. */
function renderLateral(ctx) {
  const internalRows = ctx.internalAssets.slice(0, LIMITS.internalAssets).map((node) => {
    const reportNode = ctx.reportById.get(node.id);
    return [
      node.kind,
      reportNode?.label ?? ctx.labelOf(node.id),
      addressOf(node),
      integerText(ctx.servicesOf(node.id)),
      node.status,
    ];
  });

  const pivotRows = ctx.pivotNodes.slice(0, LIMITS.pivots).map((node) => {
    const reportNode = ctx.reportById.get(node.id);
    const attrs = reportNode?.attrs ?? {};
    const target = attrs.targetId !== undefined || attrs.assetId !== undefined
      ? ctx.labelOf(resolveRefId(attrs.targetId ?? attrs.assetId) ?? '')
      : '—';
    return [
      reportNode?.label ?? ctx.labelOf(node.id),
      node.status,
      firstString([attrs.tunnelType, attrs.type, attrs.kind]) ?? 'tunnel',
      target,
      attrs.localPort !== undefined ? String(attrs.localPort) : '—',
      node.status === 'verified' || attrs.verified === true ? 'yes' : 'no',
      integerText(Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0),
    ];
  });

  const lateralRows = ctx.lateralEdges.slice(0, LIMITS.lateralEdges).map((edge) => [
    ctx.labelOf(edge.from),
    edge.kind,
    ctx.labelOf(edge.to),
    Number.isFinite(edge.confidence) ? edge.confidence.toFixed(2) : '0.60',
    integerText(Array.isArray(edge.evidenceIds) ? edge.evidenceIds.length : 0),
  ]);

  const chainSteps = [];
  for (const group of ctx.explicitChains) {
    for (const step of group.steps) {
      const stage = String(step.attrs?.stage ?? 'recon');
      if (!INTERNAL_CHAIN_STAGES.has(stage)) continue;
      const reportNode = ctx.reportById.get(step.id);
      chainSteps.push([
        group.chainId,
        stage,
        reportNode?.label ?? ctx.labelOf(step.id),
        referenceLabel(ctx, step.attrs ?? {}),
        integerText(Array.isArray(step.evidenceIds) ? step.evidenceIds.length : 0),
      ]);
    }
  }

  const parts = [
    '## 8. Internal & Lateral Movement',
    `Internal scope contains ${integerText(ctx.internalAssets.length)} asset(s); ${integerText(ctx.pivotNodes.length)} pivot(s) are recorded (${integerText(ctx.verifiedPivots.length)} verified) and ${integerText(ctx.lateralEdges.length)} lateral/link edge(s) connect internal identities.`,
    `### Internal assets (top ${LIMITS.internalAssets})`,
  ];
  if (internalRows.length === 0) parts.push('_No internal-range assets were discovered._');
  else {
    parts.push(markdownTable(['Kind', 'Asset', 'Address / realm', 'Services', 'Status'], internalRows));
    const note = truncationNote(internalRows.length, ctx.internalAssets.length, 'internal assets');
    if (note.length > 0) parts.push(note);
  }
  parts.push(`### Pivots and tunnels (top ${LIMITS.pivots})`);
  if (pivotRows.length === 0) parts.push('_No pivots are recorded._');
  else {
    parts.push(markdownTable(['Pivot', 'Status', 'Type', 'Far-side target', 'Local port', 'Verified', 'Evidence'], pivotRows));
    const note = truncationNote(pivotRows.length, ctx.pivotNodes.length, 'pivots');
    if (note.length > 0) parts.push(note);
  }
  parts.push(`### Lateral movement edges (top ${LIMITS.lateralEdges})`);
  if (lateralRows.length === 0) parts.push('_No pivot, reachability, authentication or control edges are recorded._');
  else {
    parts.push(markdownTable(['From', 'Relationship', 'To', 'Confidence', 'Evidence'], lateralRows));
    const note = truncationNote(lateralRows.length, ctx.lateralEdges.length, 'lateral edges');
    if (note.length > 0) parts.push(note);
  }
  parts.push('### Lateral / credential chain steps');
  if (chainSteps.length === 0) parts.push('_No explicit lateral-movement or credential-access chain steps are recorded._');
  else parts.push(markdownTable(['Chain', 'Stage', 'Step', 'Referenced node', 'Evidence'], chainSteps));
  return parts.join('\n\n');
}

/** Default remediation guidance by severity. */
function defaultRemediation(severity) {
  if (severity === 'critical') return 'Patch or disable the affected component immediately, add a detection rule, and re-test with the recorded reproduction before closing.';
  if (severity === 'high') return 'Schedule an urgent fix in the current change window, restrict exposure where possible, and verify the fix with a repeatable test.';
  if (severity === 'medium') return 'Fix within the normal hardening cycle and add compensating controls (WAF rule, configuration baseline) until patched.';
  if (severity === 'low') return 'Address during routine maintenance; document the residual risk if accepted.';
  return 'Review and harden as part of configuration hygiene; no immediate exploitation impact was demonstrated.';
}

/** 9. Remediation plan. */
function renderRemediation(ctx) {
  const rollupRows = SEVERITY_ORDER.map((severity) => [
    severity,
    integerText(ctx.severityCountsAll[severity] ?? 0),
    integerText(ctx.severityCountsVerified[severity] ?? 0),
  ]);

  const criticalVerified = ctx.severityCountsVerified.critical ?? 0;
  const highVerified = ctx.severityCountsVerified.high ?? 0;
  const mediumVerified = ctx.severityCountsVerified.medium ?? 0;
  const lowVerified = ctx.severityCountsVerified.low ?? 0;
  const recommendations = [];
  if (criticalVerified > 0) {
    recommendations.push({ priority: 1, text: 'Treat critical findings as an emergency change: remediate, add monitoring for the exploited path, and re-test within the agreed window.', trigger: `${integerText(criticalVerified)} verified critical finding(s)` });
  }
  if (ctx.dataThresholdMet) {
    recommendations.push({ priority: 2, text: 'Escalate the exposed sensitive data to the data owner: start the incident/notification assessment, preserve the evidence hashes, and avoid collecting further raw rows.', trigger: 'a bulk sensitive-data threshold was met' });
  }
  if (ctx.validatedAccess.length > 0) {
    recommendations.push({ priority: 3, text: 'Revoke every engagement foothold, rotate the validated credentials, invalidate sessions, and verify no persistence was left behind.', trigger: `${integerText(ctx.validatedAccess.length)} validated access path(s)` });
  }
  if (ctx.allCrownPaths.length > 0) {
    recommendations.push({ priority: 4, text: 'Break the milestone paths at their choke points: enforce least privilege on the shared identity/segment and monitor the path legs that carry exploit or credential hops.', trigger: `${integerText(ctx.allCrownPaths.length)} milestone path(s)` });
  }
  if (ctx.wildcard.confirmed + ctx.wildcard.suspect > 0) {
    recommendations.push({ priority: 5, text: 'Harden wildcard DNS: remove wildcard records that are not required, exclude staging from production zones, and alert on wildcard-resolved hosts appearing in scope.', trigger: `${integerText(ctx.wildcard.confirmed + ctx.wildcard.suspect)} wildcard zone(s) confirmed or suspect` });
  }
  if (ctx.verifiedPivots.length > 0) {
    recommendations.push({ priority: 6, text: 'Re-segment the internal network around the far side of the verified pivot, restrict egress from the foothold subnet, and require MFA/jump-host access for administration.', trigger: `${integerText(ctx.verifiedPivots.length)} verified pivot(s)` });
  }
  if (highVerified > 0) {
    recommendations.push({ priority: 7, text: 'Fix high-severity findings in the current change window and add regression tests for the reproduced conditions.', trigger: `${integerText(highVerified)} verified high finding(s)` });
  }
  if (mediumVerified + lowVerified > 0) {
    recommendations.push({ priority: 8, text: 'Bundle medium/low findings into the next hardening sprint and record any accepted risk with an owner and review date.', trigger: `${integerText(mediumVerified + lowVerified)} verified medium/low finding(s)` });
  }
  recommendations.push({ priority: 9, text: 'Re-test every fixed item, attach fresh evidence hashes, and close findings only when the reproduction no longer succeeds.', trigger: 'always' });
  recommendations.sort((a, b) => a.priority - b.priority || compareText(a.text, b.text));

  const remediationRows = ctx.findings.slice(0, LIMITS.remediation).map((node) => {
    const explicit = firstString([node.attrs?.remediation, node.attrs?.fix, node.attrs?.recommendation, node.attrs?.solution]);
    const severity = severityOf(node);
    return [
      severity.toUpperCase(),
      ctx.findingTitle(node),
      explicit !== undefined ? scrubString(explicit) : defaultRemediation(severity),
    ];
  });

  const parts = [
    '## 9. Remediation',
    'Recommendations are derived from the verified evidence in this graph, ordered by urgency. Finding-level guidance uses an explicit remediation field when a tool recorded one and otherwise applies severity-based guidance.',
    '### Severity rollup',
    markdownTable(['Severity', 'All findings', 'Verified findings'], rollupRows),
    '### Prioritized recommendations',
    numberedList(recommendations.map((entry) => `${mdCell(entry.text, 400)} _(${mdCell(entry.trigger, 120)})_`)),
    `### Finding-level remediation (top ${LIMITS.remediation})`,
  ];
  if (remediationRows.length === 0) parts.push('_No findings are recorded, so there is no finding-level remediation to list._');
  else {
    parts.push(markdownTable(['Severity', 'Finding', 'Remediation'], remediationRows));
    const note = truncationNote(remediationRows.length, ctx.findings.length, 'findings');
    if (note.length > 0) parts.push(note);
  }
  return parts.join('\n\n');
}

/** 10. Evidence index and audit hash chain. */
function renderEvidence(ctx) {
  const evidenceRows = ctx.evidenceNodes.slice(0, LIMITS.evidence).map((node, index) => {
    const reportNode = ctx.reportById.get(node.id);
    const attrs = reportNode?.attrs ?? {};
    const sha = typeof attrs.sha256 === 'string' && attrs.sha256.length > 0 ? attrs.sha256 : 'MISSING';
    const size = attrs.size !== undefined ? `${integerText(attrs.size)} B` : '—';
    const media = firstString([attrs.mediaType]) ?? '—';
    return [
      String(index + 1),
      reportNode?.label ?? ctx.labelOf(node.id),
      firstString([attrs.path]) ?? '—',
      sha,
      `${size} / ${media}`,
      firstString([attrs.collectedAt]) ?? '—',
      firstString([attrs.commandHash]) ?? '—',
      firstString([attrs.prevHash]) ?? '—',
    ];
  });

  const chain = ctx.auditChain;
  const chainRows = [
    ['Retained audit entries', integerText(chain.entries)],
    ['Hash checks passed', integerText(chain.hashValid)],
    ['Hash checks failed', integerText(chain.hashInvalid)],
    ['Prev-hash links verified', integerText(chain.linkValid)],
    ['Prev-hash links failed', integerText(chain.linkInvalid)],
    ['Chain status', chain.entries === 0 ? 'not available (no audit entries retained)' : chain.intact ? 'intact' : '**FAILED — treat evidence as potentially tampered**'],
    ['Tail hash', chain.tailHash ?? '—'],
    ['First retained prev-hash', chain.firstPrevHash === null ? '—' : chain.firstPrevHash === '' ? '(chain start)' : chain.firstPrevHash],
  ];

  const tailRows = ctx.graph.audit.slice(-LIMITS.auditTail).map((entry) => [
    entry.at ?? '—',
    entry.tool ?? '—',
    entry.action ?? '—',
    entry.target !== null && entry.target !== undefined ? compactJson(entry.target, 60) : '—',
    compactJson(entry.result, 80),
    truncate(String(entry.hash ?? '—'), 20),
  ]);

  const parts = [
    '## 10. Evidence Index & Hash Chain',
    `The graph references ${integerText(ctx.evidenceNodes.length)} evidence artifact(s). Artifact contents are stored outside the session log; this report carries the path, media type, size and SHA-256 for each one so a reviewer can re-hash the file and compare. Audit entries are chained with SHA-256 over stable JSON: each entry commits to the previous entry's hash.`,
    `### Evidence index (top ${LIMITS.evidence})`,
  ];
  if (evidenceRows.length === 0) parts.push('_No evidence artifacts are recorded._');
  else {
    parts.push(markdownTable(['#', 'Evidence', 'Path', 'SHA-256', 'Size / media', 'Collected at', 'Command hash', 'Prev hash'], evidenceRows, 120));
    const note = truncationNote(evidenceRows.length, ctx.evidenceNodes.length, 'evidence artifacts');
    if (note.length > 0) parts.push(note);
  }
  parts.push('### Audit hash chain');
  parts.push(markdownTable(['Chain metric', 'Value'], chainRows));
  parts.push('### Recent audit entries (tail)');
  if (tailRows.length === 0) parts.push('_No audit entries are retained._');
  else parts.push(markdownTable(['At', 'Tool', 'Action', 'Target', 'Result', 'Hash'], tailRows));
  parts.push('### How to verify');
  parts.push(bulletList([
    'Re-hash each evidence file with `sha256sum <path>` and compare it with the SHA-256 column above.',
    'Recompute each audit entry hash as the first 32 hex characters of SHA-256 over the stable JSON of `{id, at, tool, action, target, result, evidenceIds, prevHash}`, then check each entry\'s `prevHash` against its predecessor\'s hash.',
    `The retained tail hash is ${codeSpan(chain.tailHash ?? '—', 64)}; retain it out-of-band to detect retroactive edits.`,
  ]));
  return parts.join('\n\n');
}

/** Markdown table that preserves the exact `[redacted-lesson]` literal in raw output. */
function lessonMarkdownTable(headers, rows, cellMax = 80) {
  return markdownTable(headers, rows, cellMax).replace(/\\\[redacted-lesson\\\]/gu, '[redacted-lesson]');
}

/** Display attributes for one node from the report-safe projection. */
function reportAttrsOf(ctx, node) {
  return ctx.reportById.get(node.id)?.attrs ?? node.attrs ?? {};
}

/** `yes` / `no` / `—` renderer. */
function yesNo(value) {
  return value === true ? 'yes' : value === false ? 'no' : '—';
}

/** Resolve an id/`{kind,key}` reference to a report label. */
function subjectLabelOf(ctx, ref) {
  const id = resolveRefId(ref);
  return id === undefined ? '—' : ctx.labelOf(id);
}

/** 11. Autonomous loop state and supervisor reviews. */
function renderLoop(ctx) {
  const parts = [
    '## 11. Autonomous Loop & Supervision',
    'The autonomous loop is a supervised, goal-bound execution cycle: each round a supervisor reviews progress, policy clamps the plan to allowed frontier actions, intents carry an explicit evidence contract, and independent verification/rating rows gate any impact claim. This section is a point-in-time projection of the durable loop state.',
    '### Loop state',
  ];
  if (ctx.loop === null) {
    parts.push('_No `loop` node is recorded for this engagement; the graph was built manually or the loop has not started, so there is no round/supervision history to report._');
  } else {
    const attrs = ctx.loop.attrs;
    const round = Number(attrs.round) || 0;
    const maxRounds = Number(attrs.maxRounds) || 0;
    const ring = Number(attrs.ring) || 1;
    const allowedRing = Number(attrs.allowedRing) || 1;
    const rows = [
      ['phase', ctx.loop.phase],
      ['objective', scrubString(String(attrs.objective ?? '—'))],
      ['objectiveType', String(attrs.objectiveType ?? 'impact')],
      ['round / maxRounds', maxRounds > 0 ? `${round} / ${maxRounds}` : `${round}`],
      ['goalPhase', scrubString(String(attrs.goalPhase ?? '—'))],
      ['activation', String(attrs.activation ?? 'disarmed')],
      ['ring', allowedRing !== ring ? `${ring} (allowed ${allowedRing})` : String(ring)],
      ['noProgressRounds', integerText(attrs.noProgressRounds)],
      ['emptyRounds', integerText(attrs.emptyRounds)],
      ['stopReason', scrubString(String(attrs.stopReason ?? '—'))],
      ['autoContinue', yesNo(attrs.autoContinue)],
    ];
    parts.push(markdownTable(['Field', 'Value'], rows, 200));
  }

  parts.push(`### Supervisor reviews (top ${LIMITS.loopSupervisions})`);
  if (ctx.supervisions.length === 0) parts.push('_No supervision rows are recorded._');
  else {
    const rows = ctx.supervisions.map((node) => {
      const attrs = reportAttrsOf(ctx, node);
      const finding = attrs.findingKey !== null && attrs.findingKey !== undefined
        ? subjectLabelOf(ctx, attrs.findingKey)
        : '—';
      return [
        String(Number(attrs.round) || 0),
        scrubString(String(attrs.type ?? 'round_plan')),
        scrubString(String(attrs.verdict ?? 'hold')),
        scrubString(String(attrs.source ?? 'deterministic')),
        scrubString(String(attrs.diagnosis ?? '—')),
        scrubString(String(attrs.nextPlan ?? '—')),
        Array.isArray(attrs.mustIntents) ? attrs.mustIntents.map((id) => String(id)).join(', ') : '—',
        Number.isFinite(Number(attrs.confidence)) ? Number(attrs.confidence).toFixed(2) : '0.00',
        finding,
        scrubString(String(attrs.secondaryVerdict ?? '—')),
      ];
    });
    parts.push(markdownTable(['round', 'type', 'verdict', 'source', 'diagnosis', 'nextPlan', 'mustIntents', 'confidence', 'findingKey', 'secondaryVerdict'], rows));
    const note = truncationNote(rows.length, ctx.supervisionTotal, 'supervision reviews');
    if (note.length > 0) parts.push(note);
  }

  parts.push('### Intents');
  if (ctx.intents.length === 0) parts.push('_No loop intents are recorded._');
  else {
    const rows = ctx.intents.map((node) => {
      const attrs = reportAttrsOf(ctx, node);
      return [
        String(Number(attrs.round) || 0),
        scrubString(String(attrs.actionType ?? 'manual')),
        scrubString(String(attrs.targetLabel ?? node.label ?? '—')),
        String(node.status ?? 'unknown'),
        String(Number(attrs.priority) || 0),
        compactJson(attrs.expectedEvidence, 90),
        `${integerText(attrs.attempts)} / ${integerText(attrs.channelCount)}`,
      ];
    });
    parts.push(markdownTable(['round', 'actionType', 'targetLabel', 'status', 'priority', 'expectedEvidence', 'attempts / channelCount'], rows));
    const note = truncationNote(rows.length, ctx.intentTotal, 'loop intents');
    if (note.length > 0) parts.push(note);
  }

  parts.push('### Verification and rating');
  const verificationRows = [];
  for (const node of ctx.supervisions) {
    const attrs = reportAttrsOf(ctx, node);
    const type = String(attrs.type ?? 'round_plan');
    if (!/verification|rating/iu.test(type)) continue;
    verificationRows.push([
      'supervision',
      String(Number(attrs.round) || 0),
      scrubString(type),
      scrubString(String(attrs.verdict ?? 'hold')),
      '—',
      attrs.findingKey !== null && attrs.findingKey !== undefined ? subjectLabelOf(ctx, attrs.findingKey) : '—',
      scrubString(firstString([attrs.secondaryVerdict, attrs.secondaryMode]) ?? '—'),
      '—',
      Number.isFinite(Number(attrs.confidence)) ? Number(attrs.confidence).toFixed(2) : '0.00',
    ]);
  }
  for (const node of ctx.findings) {
    const attrs = reportAttrsOf(ctx, node);
    if (attrs.secondaryVerified === undefined && attrs.redteamRating === undefined && attrs.claimGuard === undefined) continue;
    verificationRows.push([
      'finding',
      '—',
      'finding_attrs',
      ratedSeverity(node),
      scrubString(String(attrs.redteamRating ?? '—')),
      ctx.findingTitle(node),
      `secondaryVerified=${yesNo(attrs.secondaryVerified)}`,
      scrubString(String(attrs.claimGuard ?? 'none')),
      '—',
    ]);
  }
  if (verificationRows.length === 0) parts.push('_No independent verification or rating rows are available._');
  else {
    const shownRows = verificationRows.slice(0, LIMITS.verificationRows);
    parts.push(markdownTable(['source', 'round', 'type', 'verdict', 'redteamRating', 'subject', 'secondaryVerified / secondaryVerdict', 'claimGuard', 'confidence'], shownRows));
    const note = truncationNote(shownRows.length, verificationRows.length, 'verification/rating rows');
    if (note.length > 0) parts.push(note);
  }

  parts.push('### Self-team brief');
  if (ctx.selfTeamBrief === null) {
    parts.push('_No self-supervision team brief is recorded; run `atkbrain_selftteam action=brief`._');
  } else {
    const attrs = reportAttrsOf(ctx, ctx.selfTeamBrief);
    parts.push(markdownTable(['Field', 'Value'], [
      ['progress', scrubString(String(attrs.progressSummary ?? '—'))],
      ['gained', Array.isArray(attrs.gained) ? attrs.gained.map((entry) => scrubString(String(entry))).join('; ') || '—' : '—'],
      ['missed', Array.isArray(attrs.missed) ? attrs.missed.map((entry) => scrubString(String(entry))).join('; ') || '—' : '—'],
      ['advice', scrubString(String(attrs.advice ?? '—'))],
      ['anti-deadlock', Array.isArray(attrs.antiDeadlock) ? attrs.antiDeadlock.map((entry) => scrubString(String(entry))).join('; ') || '—' : '—'],
      ['recommended next', Array.isArray(attrs.recommendedNext) ? attrs.recommendedNext.map((entry) => scrubString(String(entry))).join('; ') || '—' : '—'],
      ['deadlock risk', scrubString(String(attrs.deadlockRisk ?? 'unknown'))],
      ['source', scrubString(String(attrs.source ?? 'unknown'))],
      ['artifact', scrubString(String(attrs.artifactPath ?? '—'))],
    ]));
  }
  if (ctx.selfTeams.length > 0) {
    const rows = ctx.selfTeams.map((node) => {
      const attrs = reportAttrsOf(ctx, node);
      return [
        scrubString(String(attrs.type ?? 'unknown')),
        String(node.status ?? 'unknown'),
        Array.isArray(attrs.members) ? attrs.members.map((member) => String(member?.name ?? member?.role ?? '')).filter(Boolean).join(', ') || '—' : '—',
        scrubString(String(attrs.lastBriefAt ?? '—')),
        scrubString(String(attrs.lastDistillAt ?? '—')),
        integerText(attrs.skillCount),
      ];
    });
    parts.push('### Self-teams');
    parts.push(markdownTable(['team', 'status', 'members', 'lastBriefAt', 'lastDistillAt', 'skills'], rows));
  }
  return parts.join('\n\n');
}

/** 12. Evolution playbook: cross-engagement distilled lessons. */
function renderEvolution(ctx) {
  const parts = [
    '## 12. Evolution Playbook',
    'Cross-engagement lessons are distilled only from qualifying outcomes: a verified high/critical finding with independent secondary confirmation, a validated access path, or verified bulk-data evidence. Candidate findings and medium/low findings are deliberately not distilled, and lesson text is stripped of target identifiers before it is printed.',
    '### Distillation gate',
  ];
  const qualifiesHigh = ctx.verifiedFindings.filter((node) => {
    const attrs = node.attrs ?? {};
    return ['critical', 'high'].includes(ratedSeverity(node))
      && (attrs.secondaryVerified === true || node.status === 'exploited' || node.status === 'impacted');
  });
  const ratedHigh = ctx.verifiedFindings.filter((node) => ['critical', 'high'].includes(ratedSeverity(node)));
  const bulkData = ctx.verifiedData.filter((node) => thresholdMetOf(node, ctx.thresholds) === true).length;
  const candidateHigh = ctx.candidates.filter((node) => ['critical', 'high'].includes(ratedSeverity(node))).length;
  parts.push(markdownTable(['Gate', 'Count'], [
    ['Verified high/critical findings', integerText(ratedHigh.length)],
    ['— with independent secondary confirmation', integerText(qualifiesHigh.length)],
    ['Validated access paths', integerText(ctx.validatedAccess.length)],
    ['Verified bulk-data evidence sets', integerText(bulkData)],
    ['Candidate high/critical findings (excluded)', integerText(candidateHigh)],
    ['Distilled lessons recorded', integerText(ctx.lessonTotal)],
  ]));

  parts.push(`### Lessons (top ${LIMITS.lessons})`);
  if (ctx.lessons.length === 0) {
    parts.push('_No qualifying high/critical/validated impact outcome was available for distillation; candidate, medium and low findings are not distilled into the playbook._');
  } else {
    const rows = ctx.lessons.map((node) => {
      const attrs = node.attrs ?? {};
      return [
        scrubString(String(attrs.lessonKey ?? node.key)),
        lessonText(attrs.route),
        lessonText(attrs.idea),
        lessonText(attrs.method),
        Number.isFinite(Number(attrs.confidence)) ? Number(attrs.confidence).toFixed(2) : '0.00',
        integerText(attrs.wins),
        integerText(attrs.fails),
        integerText(attrs.uses),
        String(node.status ?? attrs.status ?? 'unknown'),
        scrubString(String(attrs.sourceOutcome ?? '—')),
      ];
    });
    parts.push(lessonMarkdownTable(['lessonKey', 'route', 'idea', 'method', 'confidence', 'wins', 'fails', 'uses', 'status', 'sourceOutcome'], rows, 80));
    const note = truncationNote(rows.length, ctx.lessonTotal, 'lessons');
    if (note.length > 0) parts.push(note);
  }

  parts.push('### Distilled path skills');
  if (ctx.skills.length === 0) {
    parts.push('_No path skill is recorded._');
  } else {
    const rows = ctx.skills.map((node) => {
      const attrs = node.attrs ?? {};
      return [
        scrubString(String(attrs.name ?? node.label ?? '—')),
        scrubString(String(attrs.route ?? '—')),
        Array.isArray(attrs.when) ? attrs.when.join(', ') : '—',
        Array.isArray(attrs.do) ? attrs.do.join(', ') : '—',
        Array.isArray(attrs.verification) ? attrs.verification.map((entry) => scrubString(String(entry))).join('; ') || '—' : '—',
        Number.isFinite(Number(attrs.confidence)) ? Number(attrs.confidence).toFixed(2) : '0.00',
        String(node.status ?? attrs.status ?? 'unknown'),
        scrubString(String(attrs.path ?? '—')),
      ];
    });
    parts.push(markdownTable(['name', 'route', 'when', 'do', 'verification', 'confidence', 'status', 'SKILL.md'], rows, 100));
    const note = truncationNote(rows.length, ctx.skillTotal, 'distilled skills');
    if (note.length > 0) parts.push(note);
  }

  parts.push('### Applied lessons');
  const appliedKeys = ctx.appliedLessonKeys.length > 0 ? ctx.appliedLessonKeys : ctx.usedLessonKeys;
  const appliedLabel = ctx.appliedLessonKeys.length > 0 ? 'applied' : 'used';
  if (ctx.loop === null) {
    parts.push('_No loop state is recorded, so no applied-lesson history is available._');
  } else if (appliedKeys.length === 0) {
    parts.push('_No lessons have been applied in the current loop._');
  } else {
    const rows = appliedKeys.map((key) => {
      const lesson = ctx.lessonByKey.get(key);
      if (lesson === undefined) return [scrubString(String(key)), '—', '—', '—', 'unknown'];
      const attrs = lesson.attrs ?? {};
      return [
        scrubString(String(attrs.lessonKey ?? lesson.key)),
        lessonText(attrs.idea),
        Number.isFinite(Number(attrs.confidence)) ? Number(attrs.confidence).toFixed(2) : '0.00',
        `${integerText(attrs.wins)} / ${integerText(attrs.fails)} / ${integerText(attrs.uses)}`,
        String(lesson.status ?? attrs.status ?? 'unknown'),
      ];
    });
    parts.push(`_The loop reports ${integerText(appliedKeys.length)} ${appliedLabel} lesson(s); keys without a matching lesson node are retained for audit._`);
    parts.push(lessonMarkdownTable(['lessonKey', 'idea', 'confidence', 'wins / fails / uses', 'status'], rows, 120));
  }
  return parts.join('\n\n');
}

/** Appendix: excluded/suspect assets, audit summary and limitations. */
function renderAppendix(ctx) {
  const aliasIds = new Set(Object.keys(ctx.graph.aliases));
  const excluded = [];
  const suspects = [];
  for (const node of Object.values(ctx.graph.nodes)) {
    if (!isPlainObject(node)) continue;
    if (aliasIds.has(node.id)) {
      excluded.push({
        category: 'merged duplicate',
        kind: node.kind,
        label: ctx.labelOf(node.id),
        reason: `merged into ${ctx.labelOf(ctx.graph.aliases[node.id])}`,
      });
      continue;
    }
    if (node.status === 'merged') {
      const into = node.attrs?.mergedInto !== undefined ? ctx.labelOf(resolveRefId(node.attrs.mergedInto) ?? '') : 'another identity';
      excluded.push({
        category: 'merged duplicate',
        kind: node.kind,
        label: ctx.labelOf(node.id),
        reason: `retired duplicate; merged into ${into}`,
      });
      continue;
    }
    if (node.attrs?.excluded === true || node.attrs?.quarantined === true || node.status === 'quarantined' || node.status === 'refused') {
      excluded.push({
        category: 'excluded by policy',
        kind: node.kind,
        label: ctx.labelOf(node.id),
        reason: firstString([node.attrs?.excludeReason, node.attrs?.reason, node.status === 'refused' ? 'refused by scope guard' : undefined]) ?? 'flagged during ingestion',
      });
      continue;
    }
    if (node.kind === 'wildcard_zone' && node.status === 'cleared') {
      excluded.push({
        category: 'wildcard excluded',
        kind: node.kind,
        label: ctx.labelOf(node.id),
        reason: 'wildcard signature cleared; not treated as a real asset',
      });
      continue;
    }
    if (node.kind === 'wildcard_zone' && (node.status === 'suspect' || node.status === 'inconclusive')) {
      suspects.push({
        category: 'wildcard zone',
        kind: node.kind,
        label: ctx.labelOf(node.id),
        reason: `wildcard status ${node.status}; not counted as a confirmed asset`,
      });
      continue;
    }
    if (node.kind === 'host' && node.attrs?.wildcardStatus === 'suspect') {
      suspects.push({
        category: 'wildcard host',
        kind: node.kind,
        label: ctx.labelOf(node.id),
        reason: 'host resolves through a suspected wildcard; excluded from confirmed asset totals',
      });
      continue;
    }
    if (node.attrs?.suspect === true) {
      suspects.push({
        category: 'flagged suspect',
        kind: node.kind,
        label: ctx.labelOf(node.id),
        reason: 'flagged as suspect during ingestion',
      });
    }
  }

  const excludedRows = excluded.slice(0, LIMITS.excluded).map((entry) => [entry.category, entry.kind, entry.label, entry.reason]);
  const suspectRows = suspects.slice(0, LIMITS.excluded).map((entry) => [entry.category, entry.kind, entry.label, entry.reason]);

  const auditByTool = countByField(ctx.graph.audit.filter((entry) => isPlainObject(entry)), (entry) => String(entry.tool ?? 'unknown'));
  const auditByAction = countByField(ctx.graph.audit.filter((entry) => isPlainObject(entry)), (entry) => String(entry.action ?? 'unknown'));
  const toolRows = Object.entries(auditByTool).sort((a, b) => compareText(a[0], b[0])).slice(0, LIMITS.auditGroups).map(([tool, count]) => [tool, integerText(count)]);
  const actionRows = Object.entries(auditByAction).sort((a, b) => compareText(a[0], b[0])).slice(0, LIMITS.auditGroups).map(([action, count]) => [action, integerText(count)]);

  const parts = [
    '## Appendix',
    '### A.1 Excluded assets',
    'Excluded identities are not confirmed assets and must not be retested without a scope change. They are listed here for auditability of the dedupe and quarantine decisions.',
  ];
  if (excludedRows.length === 0) parts.push('_No excluded identities are recorded._');
  else {
    parts.push(markdownTable(['Category', 'Kind', 'Label', 'Reason'], excludedRows));
    const note = truncationNote(excludedRows.length, excluded.length, 'excluded identities');
    if (note.length > 0) parts.push(note);
  }
  parts.push('### A.2 Suspect assets');
  if (suspectRows.length === 0) parts.push('_No suspect assets are recorded._');
  else {
    parts.push(markdownTable(['Category', 'Kind', 'Label', 'Reason'], suspectRows));
    const note = truncationNote(suspectRows.length, suspects.length, 'suspect assets');
    if (note.length > 0) parts.push(note);
  }
  parts.push('### A.3 Audit summary');
  if (toolRows.length === 0) parts.push('_No audit entries are retained._');
  else {
    parts.push(markdownTable(['Tool', 'Audit entries'], toolRows));
    parts.push(markdownTable(['Action', 'Audit entries'], actionRows));
    parts.push(`Last action: ${ctx.graph.lastAction !== null && ctx.graph.lastAction !== undefined ? codeSpan(compactJson(ctx.graph.lastAction, 160), 200) : 'none recorded'}.`);
    parts.push(`Refused / out-of-scope actions: ${integerText(ctx.dedupe.refused)}. Quarantined ingestion entries: ${integerText(ctx.dedupe.quarantined)}.`);
  }
  parts.push('### A.4 Scope, completeness and limitations');
  parts.push(bulletList([
    `This report is a point-in-time snapshot generated at ${mdCell(ctx.generatedAt, 60)}; the graph may have advanced since then.`,
    `Markdown tables are bounded (assets ${LIMITS.assets}, verified findings ${LIMITS.findings}, credentials ${LIMITS.credentials}, access ${LIMITS.access}, data ${LIMITS.data}, evidence ${LIMITS.evidence}, audit tail ${LIMITS.auditTail}). Truncation is called out inline; the JSON export contains every live node and edge.`,
    'Sensitive-data counts are banded by design; the threshold check is advisory and does not replace a data-owner assessment.',
    'The JSON export follows the `atkbrain/1` graph document shape and excludes merged/aliased identities; evidence files referenced by path are not embedded.',
    'Scope allow/deny lists are capped in this report; the approved scope in graph state remains the source of truth for any follow-up testing.',
    'Redaction strips secret-keyed attributes and masks secret-looking values, but operators should still review the report before external distribution.',
  ]));
  return parts.join('\n\n');
}

/** Build the re-importable JSON graph document. */
function buildJsonPayload(ctx) {
  const crownJson = ctx.allCrownPaths.map((path) => ({
    chainId: path.chainId,
    targetId: path.targetId,
    targetKind: path.targetKind,
    targetLabel: ctx.labelOf(path.targetId),
    cost: Number.isFinite(path.cost) ? path.cost : 0,
    nodes: path.nodes.map((id) => ({ id, label: ctx.labelOf(id), kind: ctx.kindOf(id) })),
    steps: path.steps.map((step) => ({
      from: step.from,
      to: step.to,
      kind: step.kind,
      edgeId: step.edgeId,
      cost: Number.isFinite(step.cost) ? step.cost : 0,
    })),
  }));
  const explicitJson = ctx.explicitChains.map((group) => ({
    chainId: group.chainId,
    steps: group.steps.slice(0, LIMITS.chainSteps).map((step) => {
      const reportNode = ctx.reportById.get(step.id);
      const attrs = reportNode?.attrs ?? step.attrs ?? {};
      return {
        id: step.id,
        ordinal: Number(attrs.ordinal) || 0,
        stage: String(attrs.stage ?? 'recon'),
        status: String(step.status ?? 'unknown'),
        label: reportNode?.label ?? ctx.labelOf(step.id),
        nodeRef: attrs.nodeRef ?? null,
        evidenceCount: Array.isArray(step.evidenceIds) ? step.evidenceIds.length : 0,
      };
    }),
  }));
  return {
    schema: STATE_SCHEMA,
    generatedAt: ctx.generatedAt,
    engagement: ctx.engagement,
    scope: ctx.scopeReport,
    summary: ctx.summary,
    nodes: ctx.reportNodes,
    edges: ctx.liveEdges.map(reportEdge),
    frontier: ctx.frontierActions,
    chains: { crown: crownJson, explicit: explicitJson },
  };
}

/** RFC 4180 field escaping. */
export function csvEscape(value) {
  if (value === null || value === undefined) return '';
  let text;
  if (typeof value === 'string') text = value;
  else if (typeof value === 'number' || typeof value === 'boolean') text = String(value);
  else text = compactJson(value, 500);
  if (/[",\r\n]/u.test(text)) return `"${text.replace(/"/gu, '""')}"`;
  return text;
}

/** Build one CSV row with CRLF termination. */
function csvRow(values) {
  return `${values.map((value) => csvEscape(value)).join(',')}\r\n`;
}

/** Asset CSV: id,kind,label,status,wildcardStatus,services,findings,sourceCount. */
function buildAssetsCsv(ctx) {
  let out = csvRow(['id', 'kind', 'label', 'status', 'wildcardStatus', 'services', 'findings', 'sourceCount']);
  for (const node of ctx.assets) {
    const reportNode = ctx.reportById.get(node.id);
    out += csvRow([
      node.id,
      node.kind,
      reportNode?.label ?? ctx.labelOf(node.id),
      node.status,
      String(node.attrs?.wildcardStatus ?? 'unknown'),
      ctx.servicesOf(node.id),
      ctx.findingsByAsset.get(node.id) ?? 0,
      Array.isArray(node.sources) ? node.sources.length : 0,
    ]);
  }
  return out;
}

/** Findings CSV: severity,status,title,subject,verification,impact,cve,cwe,evidenceCount. */
function buildFindingsCsv(ctx) {
  let out = csvRow(['severity', 'status', 'title', 'subject', 'verification', 'impact', 'cve', 'cwe', 'evidenceCount', 'cvss_score', 'cvss_rating', 'cvss_vector']);
  for (const node of ctx.findings) {
    out += csvRow([
      severityOf(node),
      node.status,
      ctx.findingTitle(node),
      ctx.subjectOf(node),
      verificationOf(node),
      findingImpactText(node),
      findingCves(node).join('; '),
      findingCwes(node).join('; '),
      Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0,
      cvssOf(node).score === null ? '' : String(cvssOf(node).score),
      cvssOf(node).severity ?? '',
      cvssOf(node).vector ?? '',
    ]);
  }
  return out;
}

/**
 * Render the engagement report.
 *
 * @param {object} state graph state produced by `ops.applyOps`
 * @param {{generatedAt?: string, config?: object}} [options]
 * @returns {{markdown: string, json: string, assetsCsv: string, findingsCsv: string, summary: object}}
 */
export function renderReport(state, options = {}) {
  const ctx = buildContext(state, options);
  return {
    markdown: renderMarkdown(ctx),
    json: `${JSON.stringify(buildJsonPayload(ctx), null, 2)}\n`,
    assetsCsv: buildAssetsCsv(ctx),
    findingsCsv: buildFindingsCsv(ctx),
    summary: ctx.summary,
  };
}

/** Extract a `YYYY-MM-DD` stamp from a supplied date string/Date, else `undated`. */
function dateStampOf(date) {
  if (date instanceof Date) {
    if (!Number.isFinite(date.getTime())) return 'undated';
    return date.toISOString().slice(0, 10);
  }
  if (typeof date !== 'string') return 'undated';
  const match = /^(\d{4}-\d{2}-\d{2})/u.exec(date.trim());
  return match !== null ? match[1] : 'undated';
}

/**
 * Safe, deterministic report file name, e.g.
 * `atkbrain-acme-external-2026-10-31.md`.
 *
 * @param {object|string|null} engagement engagement descriptor or name
 * @param {string|Date} date supplied generation date (never read from the clock)
 * @returns {string}
 */
export function suggestedReportName(engagement, date) {
  const rawName = typeof engagement === 'string'
    ? engagement
    : firstString([engagement?.name, engagement?.client]) ?? 'engagement';
  const base = safeFileName(rawName, 'engagement');
  return `atkbrain-${base}-${dateStampOf(date)}.md`;
}
