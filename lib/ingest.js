/**
 * Asset ingestion helpers: format dispatch plus duplicate/conflict merging.
 *
 * The heavy lifting lives in `normalize.js`; this module is the small, stable
 * surface that Host tools call:
 *
 *   const parsed = parseAssetRecords(text, { filename });
 *   const merged = mergeNormalized(parsed.records);
 *
 * `mergeNormalized` keeps the first occurrence of a `kind|key` pair, unions
 * list attributes, collects differing ports into `attrs.ports`, and reports
 * critical scalar disagreements (label, url, addr, fqdn, ip, cidr, scheme,
 * severity, status, title, protocol, record type) as conflicts.
 */
import { detectDocumentFormat, parseAssetDocument } from './normalize.js';
import { clone, isPlainObject, stableStringify, truncate, unionStrings } from './util.js';

/** Attribute keys whose disagreement is a real conflict rather than extra context. */
const CRITICAL_ATTRS = new Set([
  'url', 'addr', 'fqdn', 'ip', 'cidr', 'host', 'domain', 'scheme', 'severity', 'status',
  'title', 'protocol', 'kind', 'name', 'zone', 'recordType',
]);

const MAX_CONFLICTS = 500;

/**
 * Documented schema for observation JSONL accepted by `parseObservationsJsonl`
 * (normalize.js) and by the `atkbrain_ingest` / `atkbrain_record` tools.
 *
 * It is a plain frozen constant instead of a runtime validator because the
 * validator already exists as `parseObservationsJsonl`; this object exists so a
 * model-facing tool description can show the accepted shape without importing
 * the whole parser.
 */
export const observationSchema = Object.freeze({
  version: 1,
  lineFormat: 'one JSON object per line; blank lines and lines starting with # or // are ignored',
  kinds: Object.freeze(['service', 'http', 'finding', 'dns', 'host']),
  common: Object.freeze({
    kind: 'required: service|http|finding|dns|host; `type` is accepted only when it names one of these kinds',
    ts: 'optional ISO-8601 string or epoch milliseconds; normalized to ISO-8601',
    source: 'optional provenance string or object; stored under attrs.source',
    attrs: 'optional object; secret-like keys are stripped and values bounded',
    recordShape: 'each parsed record is {kind, key, label, attrs, ts?} plus top-level mirrors of the canonical fields (service host/port/transport, http url/status/title, dns host/a/aaaa/cname, finding title/severity/subject, host host/ips) so graph builders can consume them directly',
  }),
  service: Object.freeze({
    required: Object.freeze(['host', 'port']),
    optional: Object.freeze(['protocol', 'service', 'product', 'version', 'banner', 'state', 'tls']),
    key: 'host:port',
  }),
  http: Object.freeze({
    required: Object.freeze(['url']),
    optional: Object.freeze(['status', 'title', 'server', 'techs', 'headers', 'contentLength', 'redirects']),
    key: 'canonical URL (fragment removed, default port elided)',
    note: 'url may be omitted when host+port are given; scheme defaults to https unless tls=false or port=80',
  }),
  finding: Object.freeze({
    required: Object.freeze(['title']),
    optional: Object.freeze(['severity', 'status', 'url', 'host', 'cve', 'cwe', 'cvss', 'impact', 'description', 'evidence', 'remediation', 'verification']),
    key: 'finding_<hash of title + subject>',
    defaults: Object.freeze({ severity: 'info', status: 'candidate' }),
  }),
  dns: Object.freeze({
    required: Object.freeze(['host']),
    optional: Object.freeze(['addresses', 'ips', 'cname', 'recordType', 'ttl']),
    key: 'host',
  }),
  host: Object.freeze({
    required: Object.freeze(['host']),
    optional: Object.freeze(['ips', 'addresses', 'os', 'state', 'tags']),
    key: 'canonical host',
  }),
  secretHandling: 'keys matching SECRET_KEY_PATTERN (password/passwd/pwd/secret/token/apikey/access_key/private_key/cookie/authorization/bearer/ntlm/hash) and HTTP cookie/authorization/token headers are stripped before storage',
  limits: Object.freeze({
    maxBytes: 16 * 1024 * 1024,
    maxLines: 20000,
    maxWarnings: 100,
  }),
});

/**
 * Parse asset records from a document, dispatching on an explicit format or on
 * filename/content detection.
 *
 * @param {string} text
 * @param {{format?:string, filename?:string, maxBytes?:number}} [opts]
 * @returns {{records:object[], warnings:object[], quarantined:object[], stats:object}}
 *          the same shape as `parseAssetDocument`.
 */
export function parseAssetRecords(text, opts = {}) {
  const options = isPlainObject(opts) ? opts : {};
  const format = options.format ?? detectDocumentFormat(options.filename, text ?? '');
  return parseAssetDocument(text, { ...options, format });
}

/** Deep-clone a record field while tolerating non-cloneable values. */
function cloneField(value) {
  try {
    return clone(value);
  } catch {
    return value;
  }
}

/** Whether two attribute values are equal for conflict purposes. */
function equalValue(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a === 'object' && a !== null && b !== null) {
    try {
      return stableStringify(a) === stableStringify(b);
    } catch {
      return false;
    }
  }
  return false;
}

/** Union two attribute arrays deterministically. */
function unionAttributeArray(a, b) {
  if (a.every((entry) => typeof entry === 'string') && b.every((entry) => typeof entry === 'string')) {
    return unionStrings([...a, ...b]);
  }
  if (a.every((entry) => Number.isInteger(entry)) && b.every((entry) => Number.isInteger(entry))) {
    return [...new Set([...a, ...b])].sort((left, right) => left - right);
  }
  const seen = new Set();
  const merged = [];
  for (const entry of [...a, ...b]) {
    let marker;
    try {
      marker = stableStringify(entry);
    } catch {
      marker = String(entry);
    }
    if (seen.has(marker)) continue;
    seen.add(marker);
    merged.push(cloneField(entry));
  }
  return merged;
}

/** Merge duplicate ports into `attrs.ports` while keeping the first scalar port. */
function mergePorts(existing, incomingPort) {
  const port = Number.isInteger(incomingPort) && incomingPort >= 1 && incomingPort <= 65535
    ? incomingPort
    : undefined;
  if (port === undefined) return;
  if (existing.port === undefined) {
    existing.port = port;
    return;
  }
  if (existing.port === port) return;
  const ports = new Set([
    existing.port,
    port,
    ...(Array.isArray(existing.ports) ? existing.ports.filter((entry) => Number.isInteger(entry)) : []),
  ]);
  existing.ports = [...ports].sort((left, right) => left - right);
}

/** Merge duplicate attribute objects, reporting critical disagreements. */
function mergeAttributes(existing, incoming, context) {
  if (!isPlainObject(incoming)) return existing;
  for (const [key, value] of Object.entries(incoming)) {
    if (value === undefined) continue;
    if (key === 'port') {
      mergePorts(existing, value);
      continue;
    }
    const current = existing[key];
    if (current === undefined) {
      existing[key] = cloneField(value);
      continue;
    }
    if (Array.isArray(current) && Array.isArray(value)) {
      existing[key] = unionAttributeArray(current, value);
      continue;
    }
    if (isPlainObject(current) && isPlainObject(value)) {
      mergeAttributes(current, value, context);
      continue;
    }
    if (equalValue(current, value)) continue;
    if (CRITICAL_ATTRS.has(key)) context.conflict(key, current, value);
    // Non-critical scalars keep the first value.
  }
  return existing;
}

/** Normalize one input record into the mergeable shape, or undefined. */
function coerceRecord(record) {
  if (!isPlainObject(record)) return undefined;
  const rawKind = typeof record.kind === 'string'
    ? record.kind.trim().toLowerCase()
    : typeof record.type === 'string' ? record.type.trim().toLowerCase() : '';
  if (rawKind.length === 0 || rawKind.length > 40) return undefined;
  const rawKey = typeof record.key === 'string'
    ? record.key
    : typeof record.canonical === 'string' ? record.canonical : '';
  const key = rawKey.trim();
  if (key.length === 0 || key.length > 2048) return undefined;
  const label = typeof record.label === 'string' && record.label.trim().length > 0
    ? truncate(record.label.trim(), 300)
    : undefined;
  const attrs = isPlainObject(record.attrs) ? cloneField(record.attrs) : {};
  return {
    kind: rawKind,
    key,
    label,
    attrs: isPlainObject(attrs) ? attrs : {},
    extra: record,
  };
}

/**
 * Deduplicate normalized records by `kind|key`.
 *
 * Contract:
 *  - the first occurrence of a `kind|key` pair wins for scalar attributes;
 *  - string/number arrays are unioned deterministically (sorted);
 *  - differing ports become `attrs.ports` while `attrs.port` keeps the first;
 *  - differing critical scalars (label, url, addr, fqdn, ip, cidr, host, domain,
 *    scheme, severity, status, title, protocol, kind, name, zone, recordType)
 *    are recorded in `conflicts` and the first value is kept;
 *  - `duplicates` counts *extra* occurrences keyed by `kind|key`, mirroring the
 *    duplicate vocabulary used by the graph projection.
 *
 * @param {object[]} records
 * @returns {{unique:object[], duplicates:Record<string,number>, conflicts:object[], stats:object}}
 */
export function mergeNormalized(records) {
  const input = Array.isArray(records) ? records : [];
  const unique = [];
  const byId = new Map();
  const counts = new Map();
  const conflicts = [];
  let conflictCount = 0;
  let invalid = 0;
  const reportConflict = (kind, key, field, first, next) => {
    conflictCount += 1;
    if (conflicts.length >= MAX_CONFLICTS) return;
    const entry = { kind, key, field };
    try {
      entry.first = truncate(typeof first === 'string' ? first : stableStringify(first), 300);
      entry.next = truncate(typeof next === 'string' ? next : stableStringify(next), 300);
    } catch {
      entry.first = String(first).slice(0, 300);
      entry.next = String(next).slice(0, 300);
    }
    conflicts.push(entry);
  };

  for (const record of input) {
    const coerced = coerceRecord(record);
    if (coerced === undefined) {
      invalid += 1;
      continue;
    }
    const id = `${coerced.kind}|${coerced.key}`;
    counts.set(id, (counts.get(id) ?? 0) + 1);
    const existing = byId.get(id);
    if (existing === undefined) {
      byId.set(id, {
        kind: coerced.kind,
        key: coerced.key,
        ...(coerced.label !== undefined ? { label: coerced.label } : {}),
        attrs: coerced.attrs,
      });
      unique.push(byId.get(id));
      continue;
    }
    const source = coerced.extra;
    if (coerced.label !== undefined) {
      if (existing.label === undefined) existing.label = coerced.label;
      else if (existing.label !== coerced.label) {
        reportConflict(coerced.kind, coerced.key, 'label', existing.label, coerced.label);
      }
    }
    mergeAttributes(existing.attrs, coerced.attrs, {
      conflict: (field, first, next) => reportConflict(coerced.kind, coerced.key, field, first, next),
    });
    // Preserve non-identity top-level fields (ts, status, ...) with first-wins.
    for (const [field, value] of Object.entries(source)) {
      if (field === 'kind' || field === 'type' || field === 'key' || field === 'canonical'
        || field === 'label' || field === 'attrs' || value === undefined) continue;
      if (existing[field] === undefined) {
        existing[field] = cloneField(value);
        continue;
      }
      if (Array.isArray(existing[field]) && Array.isArray(value)) {
        existing[field] = unionAttributeArray(existing[field], value);
        continue;
      }
      if (!equalValue(existing[field], value) && CRITICAL_ATTRS.has(field)) {
        reportConflict(coerced.kind, coerced.key, field, existing[field], value);
      }
    }
  }

  const duplicates = {};
  let duplicateRecords = 0;
  for (const [id, count] of counts) {
    if (count <= 1) continue;
    duplicates[id] = count;
    duplicateRecords += count - 1;
  }
  return {
    unique,
    duplicates,
    conflicts,
    stats: {
      input: input.length,
      unique: unique.length,
      duplicates: duplicateRecords,
      conflicts: conflictCount,
      invalid,
    },
  };
}

/** Re-export the small set of helpers tools commonly want next to ingestion. */
export { detectDocumentFormat, normalizeAsset, parseObservationsJsonl } from './normalize.js';
