/**
 * CVSS v3.1 Base Score calculator.
 *
 * Implements the FIRST CVSS v3.1 specification equations and the Appendix A
 * Roundup algorithm. NVD publishes the Base metric group in `cvssMetricV31`;
 * Temporal and Environmental metrics are intentionally not synthesized here.
 *
 * References:
 *  - https://www.first.org/cvss/v3.1/specification-document
 *  - https://www.first.org/cvss/v3.1/user-guide
 *  - https://nvd.nist.gov/vuln-metrics/cvss
 */

export const CVSS_VERSION = '3.1';
export const BASE_KEYS = Object.freeze(['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']);
export const OPTIONAL_KEYS = Object.freeze([
  'E', 'RL', 'RC',
  'CR', 'IR', 'AR',
  'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA',
]);

const AV = Object.freeze({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 });
const AC = Object.freeze({ L: 0.77, H: 0.44 });
const UI = Object.freeze({ N: 0.85, R: 0.62 });
const CIA = Object.freeze({ H: 0.56, L: 0.22, N: 0 });
const PR = Object.freeze({
  U: Object.freeze({ N: 0.85, L: 0.62, H: 0.27 }),
  C: Object.freeze({ N: 0.85, L: 0.68, H: 0.5 }),
});

const WORD_ALIASES = Object.freeze({
  AV: Object.freeze({
    NETWORK: 'N', N: 'N', 网络: 'N',
    ADJACENT: 'A', A: 'A', 相邻: 'A',
    LOCAL: 'L', L: 'L', 本地: 'L',
    PHYSICAL: 'P', P: 'P', 物理: 'P',
  }),
  AC: Object.freeze({
    LOW: 'L', L: 'L', 低: 'L',
    HIGH: 'H', H: 'H', 高: 'H',
  }),
  PR: Object.freeze({
    NONE: 'N', N: 'N', 无: 'N',
    LOW: 'L', L: 'L', 低: 'L',
    HIGH: 'H', H: 'H', 高: 'H',
  }),
  UI: Object.freeze({
    NONE: 'N', N: 'N', 无: 'N',
    REQUIRED: 'R', R: 'R', 需要: 'R',
  }),
  S: Object.freeze({
    UNCHANGED: 'U', U: 'U', 不变: 'U',
    CHANGED: 'C', C: 'C', 改变: 'C',
  }),
  C: Object.freeze({ HIGH: 'H', H: 'H', 高: 'H', LOW: 'L', L: 'L', 低: 'L', NONE: 'N', N: 'N', 无: 'N' }),
  I: Object.freeze({ HIGH: 'H', H: 'H', 高: 'H', LOW: 'L', L: 'L', 低: 'L', NONE: 'N', N: 'N', 无: 'N' }),
  A: Object.freeze({ HIGH: 'H', H: 'H', 高: 'H', LOW: 'L', L: 'L', 低: 'L', NONE: 'N', N: 'N', 无: 'N' }),
});

const ALLOWED = Object.freeze({
  AV: new Set(['N', 'A', 'L', 'P']),
  AC: new Set(['L', 'H']),
  PR: new Set(['N', 'L', 'H']),
  UI: new Set(['N', 'R']),
  S: new Set(['U', 'C']),
  C: new Set(['H', 'L', 'N']),
  I: new Set(['H', 'L', 'N']),
  A: new Set(['H', 'L', 'N']),
});

function codeFor(key, value) {
  const raw = String(value ?? '').trim();
  if (raw.length === 0) return undefined;
  const upper = raw.toUpperCase();
  if (ALLOWED[key]?.has(upper)) return upper;
  return WORD_ALIASES[key]?.[upper] ?? WORD_ALIASES[key]?.[raw];
}

/** Normalize the eight Base metric codes. */
export function normalizeMetrics(raw) {
  if (raw === null || typeof raw !== 'object') {
    return { ok: false, reason: 'CVSS metrics must be an object' };
  }
  const metrics = {};
  for (const key of BASE_KEYS) {
    const value = raw[key] ?? raw[key.toLowerCase()];
    const code = codeFor(key, value);
    if (code === undefined) {
      return { ok: false, reason: `invalid or missing CVSS ${key} value ${JSON.stringify(value)}` };
    }
    metrics[key] = code;
  }
  return { ok: true, metrics };
}

/** Parse a CVSS:3.1 vector. Optional Temporal/Environmental metrics are ignored for Base scoring. */
export function parseVector(text) {
  const raw = String(text ?? '').trim();
  if (raw.length === 0) return { ok: false, reason: 'CVSS vector is empty' };
  const parts = raw.split('/').filter((part) => part.length > 0);
  if (parts.length === 0) return { ok: false, reason: 'CVSS vector is empty' };
  const head = parts[0].toUpperCase();
  if (head !== 'CVSS:3.1') {
    return { ok: false, reason: `expected CVSS:3.1 vector, got ${parts[0]}` };
  }
  const metrics = {};
  const ignored = [];
  const seen = new Set();
  for (const part of parts.slice(1)) {
    const index = part.indexOf(':');
    if (index <= 0) return { ok: false, reason: `malformed vector segment "${part}"` };
    const key = part.slice(0, index).trim().toUpperCase();
    const value = part.slice(index + 1).trim();
    if (seen.has(key)) return { ok: false, reason: `duplicate CVSS metric ${key}` };
    seen.add(key);
    if (BASE_KEYS.includes(key)) {
      const code = codeFor(key, value);
      if (code === undefined) return { ok: false, reason: `invalid CVSS ${key} value ${JSON.stringify(value)}` };
      metrics[key] = code;
    } else if (OPTIONAL_KEYS.includes(key)) {
      ignored.push(key);
    } else {
      return { ok: false, reason: `unknown CVSS metric ${key}` };
    }
  }
  for (const key of BASE_KEYS) {
    if (metrics[key] === undefined) return { ok: false, reason: `CVSS vector is missing base metric ${key}` };
  }
  return { ok: true, metrics, ignored, vector: formatVector(metrics) };
}

/** Render the canonical Base vector. */
export function formatVector(metrics) {
  return `CVSS:${CVSS_VERSION}/${BASE_KEYS.map((key) => `${key}:${metrics[key]}`).join('/')}`;
}

/**
 * CVSS v3.1 Appendix A Roundup: one decimal place, avoiding binary float drift.
 * @param {number} value non-negative raw score
 * @returns {number}
 */
export function roundup(value) {
  const intInput = Math.round(Number(value) * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** NVD qualitative severity from a numeric Base score. */
export function qualitative(score) {
  const numeric = Number(score);
  if (!Number.isFinite(numeric) || numeric <= 0) return 'NONE';
  if (numeric <= 3.9) return 'LOW';
  if (numeric <= 6.9) return 'MEDIUM';
  if (numeric <= 8.9) return 'HIGH';
  return 'CRITICAL';
}

/** Plugin severity label used by the graph/report (NONE -> info). */
export function ratingLabel(score) {
  const nvd = qualitative(score);
  if (nvd === 'NONE') return 'info';
  return nvd.toLowerCase();
}

/** Whether NVD refuses to score a vector with no C/I/A impact. */
export function nvdRejectReason(metrics) {
  if (metrics?.C === 'N' && metrics?.I === 'N' && metrics?.A === 'N') {
    return 'NVD does not assign a vulnerability score when Confidentiality, Integrity and Availability are all None';
  }
  return null;
}

/**
 * Compute the CVSS v3.1 Base Score.
 * @param {string|object} input vector string or eight metric codes
 */
export function score(input) {
  let metrics;
  let vector;
  if (typeof input === 'string') {
    const parsed = parseVector(input);
    if (!parsed.ok) return parsed;
    metrics = parsed.metrics;
    vector = parsed.vector;
  } else {
    const normalized = normalizeMetrics(input);
    if (!normalized.ok) return normalized;
    metrics = normalized.metrics;
    vector = formatVector(metrics);
  }
  const rejected = nvdRejectReason(metrics);
  if (rejected !== null) {
    return {
      ok: true,
      rejected: true,
      reason: rejected,
      metrics,
      vector,
      score: 0,
      scoreText: '0.0',
      rating: 'info',
      nvdSeverity: 'NONE',
    };
  }
  const scopeChanged = metrics.S === 'C';
  const c = CIA[metrics.C];
  const i = CIA[metrics.I];
  const a = CIA[metrics.A];
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    : 6.42 * iss;
  const exploitability = 8.22
    * AV[metrics.AV]
    * AC[metrics.AC]
    * PR[scopeChanged ? 'C' : 'U'][metrics.PR]
    * UI[metrics.UI];
  let base = 0;
  if (impact > 0) {
    base = scopeChanged
      ? roundup(Math.min(1.08 * (impact + exploitability), 10))
      : roundup(Math.min(impact + exploitability, 10));
  }
  const normalizedScore = Number(base.toFixed(1));
  const nvdSeverity = qualitative(normalizedScore);
  return {
    ok: true,
    rejected: false,
    metrics,
    vector,
    score: normalizedScore,
    scoreText: normalizedScore.toFixed(1),
    rating: ratingLabel(normalizedScore),
    nvdSeverity,
    iss: Number(iss.toFixed(6)),
    impact: Number(impact.toFixed(6)),
    exploitability: Number(exploitability.toFixed(6)),
  };
}

/**
 * Resolve a CVSS score from tool arguments.
 * Accepts either `{cvssVector}` or `{cvss: {AV,AC,PR,UI,S,C,I,A}}`; rejects conflicts.
 */
export function fromInput({ cvssVector, cvss } = {}) {
  const hasVector = typeof cvssVector === 'string' && cvssVector.trim().length > 0;
  const hasMetrics = cvss !== undefined && cvss !== null;
  if (!hasVector && !hasMetrics) return { ok: true, present: false };
  let fromVector;
  if (hasVector) {
    fromVector = score(cvssVector);
    if (!fromVector.ok) return { ...fromVector, present: true };
  }
  let fromMetrics;
  if (hasMetrics) {
    fromMetrics = score(cvss);
    if (!fromMetrics.ok) return { ...fromMetrics, present: true };
  }
  if (fromVector && fromMetrics) {
    if (fromVector.vector !== fromMetrics.vector) {
      return { ok: false, present: true, reason: 'cvssVector and cvss metrics describe different vectors' };
    }
    return { ...fromVector, present: true };
  }
  return { ...(fromVector ?? fromMetrics), present: true };
}

/** Compact attrs stored on a finding. */
export function findingAttrs(result) {
  if (!result?.ok || result.present === false) return {};
  return {
    cvss: {
      version: CVSS_VERSION,
      vector: result.vector,
      baseScore: result.score,
      baseSeverity: result.nvdSeverity,
      source: 'nvd-cvss31',
    },
    cvssVector: result.vector,
    cvssScore: result.score,
    cvssRating: result.rating,
    cvssSeverity: result.nvdSeverity,
    cvssSource: 'nvd-cvss31',
  };
}
