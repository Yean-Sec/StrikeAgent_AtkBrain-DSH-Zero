/**
 * Persistent hypotheses for the discovery loop.
 *
 * A hypothesis is a strategy plus a target plus an expected proof. It is not a
 * finding: opening one costs nothing, and it only closes on evidence (two
 * independent observation channels or an evidence artifact). A negative
 * resolution must name what was actually observed; "everything is closed" is
 * not a result.
 *
 * These helpers are pure state: they validate, copy and return plain objects.
 * No clock, filesystem or network access.
 */
import { clone, invalid, isPlainObject } from './util.js';
import { BUG_CLASSES, coverageKey } from './coverage.js';
import { PROOF_TYPES, interfacePathFrom } from './proof.js';

/** Hypothesis lifecycle values (A-U intent statuses). */
export const HYPOTHESIS_STATUSES = Object.freeze([
  'open',
  'active',
  'verified',
  'disproved',
  'deferred',
  'blocked',
]);

/** Expected proof values, shared with proof.js. */
export const EXPECTED_PROOFS = PROOF_TYPES;

/** Conventional observation channels; free-form strings are also accepted. */
export const HYPOTHESIS_CHANNELS = Object.freeze([
  'status',
  'body',
  'header',
  'timing',
  'side_effect',
  'callback',
]);

/** Coverage classes plus the non-web classes the engagement planner uses. */
const EXTRA_BUG_CLASSES = Object.freeze([]);

const STATUS_RANK = Object.freeze({
  open: 0,
  active: 1,
  deferred: 2,
  verified: 3,
  disproved: 4,
  blocked: 5,
});

const DEFAULT_PROOF = 'poc_replay';
const MAX_STRATEGY = 1500;
const MAX_TARGET = 500;
const MAX_NOTE = 2000;
const MAX_ID = 300;

/** Generic closing phrases that need the exact target plus evidence. */
const GENERIC_CLOSE_RE = /(?:全部\s*404|全站\s*404|所有\s*404|all\s+404|everything\s*404|面\s*(?:关闭|已关|已死)|穷尽|无差异|全部关闭|全部失败|all\s+payloads?\s+failed|所有\s*payload\s*(?:失败|无效)|\buniform\b|\bexhausted\b|no\s+difference|everything\s+(?:closed|failed))/iu;

/** Concrete observations that make a negative note specific. */
const SPECIFIC_NOTE_RE = /(?:\b[1-5]\d{2}\b|\b\d+\s*(?:ms|毫秒|秒|s|bytes?|字节|行)\b|payload|canary|回显|反射|响应|正文|响应头|长度|耗时|时延|差异|参数|scope|allow|deny|permission|out\s+of\s+scope|forbidden|refus|unreachable|reset|timeout|lockout|waf|rate\s*limit|credential|password|口令|账号|token|blocked\s+by|拒绝|阻断|不可达|超时|锁定|超出范围|限流|未打中|没有反射|no\s+reflection|reflect|timing|length|header|body|status|difference|connection|\/[A-Za-z0-9_./-]{2,})/iu;

/** Concrete channel/parameter detail that lifts a generic close out of the reject set. */
const CONTRAST_NOTE_RE = /(?:响应|正文|响应头|长度|耗时|时延|回显|反射|payload|参数|header|body|timing|length|difference|状态码|status\s*code)/iu;

function normalizeBugClass(value) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim().toLowerCase();
  if (text.length === 0) return null;
  if (!BUG_CLASSES.includes(text) && !EXTRA_BUG_CLASSES.includes(text)) {
    invalid(`hypothesis bugClass must be one of ${[...BUG_CLASSES, ...EXTRA_BUG_CLASSES].join(', ')}`);
  }
  return text;
}

function normalizeStatus(value, { allowUndefined = false } = {}) {
  if (value === undefined && allowUndefined) return undefined;
  const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!HYPOTHESIS_STATUSES.includes(text)) {
    invalid(`hypothesis status must be one of ${HYPOTHESIS_STATUSES.join(', ')}, got ${JSON.stringify(value)}`);
  }
  return text;
}

function normalizeText(value, field, max) {
  if (typeof value !== 'string') invalid(`${field} must be a string`);
  const text = value.trim();
  if (text.length === 0) invalid(`${field} is empty`);
  if (text.length > max) invalid(`${field} is longer than ${max} characters`);
  if (/[\r\n]/u.test(text)) invalid(`${field} must not contain newlines`);
  return text;
}

function optionalText(value, field, max) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') invalid(`${field} must be a string`);
  const text = value.trim();
  return text.length > 0 ? text.slice(0, max) : null;
}

function stringList(value, field, cap = 50) {
  if (value === undefined || value === null) return [];
  const list = Array.isArray(value) ? value : [value];
  const out = [];
  const seen = new Set();
  for (const entry of list) {
    if (typeof entry !== 'string') invalid(`${field} must contain strings`);
    const text = entry.trim();
    if (text.length === 0) continue;
    if (text.length > MAX_ID) invalid(`${field} entry is too long`);
    if (seen.has(text)) continue;
    seen.add(text);
    out.push(text);
    if (out.length >= cap) break;
  }
  return out;
}

function channelList(value) {
  const list = stringList(value, 'channels', 20);
  const out = [];
  const seen = new Set();
  for (const channel of list) {
    const text = channel.toLowerCase();
    if (seen.has(text)) continue;
    seen.add(text);
    out.push(text);
  }
  return out;
}

/** A negative note must name this target and cite something observable. */
function specificNegativeNote(note, hypothesis, channels, evidenceIds) {
  const text = note.trim();
  if (text.length < 8) return false;
  const lower = text.toLowerCase();
  const target = String(hypothesis.targetKey ?? '').trim().toLowerCase();
  const targetPath = interfacePathFrom(target);
  const namesTarget = (target.length > 0 && lower.includes(target))
    || (targetPath.length > 0 && lower.includes(targetPath));
  if (GENERIC_CLOSE_RE.test(text)) {
    if (!namesTarget) return false;
    if (channels.length < 2 && evidenceIds.length === 0 && !CONTRAST_NOTE_RE.test(text)) return false;
  }
  if (SPECIFIC_NOTE_RE.test(text)) return true;
  return namesTarget && text.length >= 24;
}

/**
 * Propose a hypothesis.
 *
 * `bugClass` is optional (null when absent). `expectedProof` must be one of
 * `PROOF_TYPES` when supplied and defaults to `poc_replay`. A `coverageKey` is
 * accepted directly, or derived from `path` + a web bug class.
 */
export function proposeHypothesis(input) {
  if (!isPlainObject(input)) invalid('hypothesis must be an object with {strategy, targetKey}');
  const strategy = normalizeText(input.strategy, 'strategy', MAX_STRATEGY);
  if (strategy.length < 3) invalid('hypothesis strategy is too short');
  const targetKey = normalizeText(input.targetKey, 'targetKey', MAX_TARGET);
  const bugClass = normalizeBugClass(input.bugClass);

  let expectedProof = DEFAULT_PROOF;
  if (input.expectedProof !== undefined && input.expectedProof !== null && input.expectedProof !== '') {
    if (typeof input.expectedProof !== 'string') invalid('expectedProof must be a string');
    const text = input.expectedProof.trim().toLowerCase();
    if (!PROOF_TYPES.includes(text)) invalid(`expectedProof must be one of ${PROOF_TYPES.join(', ')}`);
    expectedProof = text;
  }

  let linkedCoverage = null;
  if (typeof input.coverageKey === 'string' && input.coverageKey.trim().length > 0) {
    linkedCoverage = input.coverageKey.trim().slice(0, 400);
  } else if (typeof input.path === 'string' && bugClass !== null && BUG_CLASSES.includes(bugClass)) {
    const key = coverageKey(input.path, bugClass);
    if (key.length > 0) linkedCoverage = key;
  }

  const note = optionalText(input.note, 'note', MAX_NOTE);
  return {
    strategy,
    targetKey,
    bugClass,
    expectedProof,
    status: 'open',
    coverageKey: linkedCoverage,
    channels: [],
    evidenceIds: [],
    note,
    reason: note,
  };
}

/**
 * Resolve an open hypothesis.
 *
 * `verified` needs two distinct channels or one evidence id. `disproved` and
 * `blocked` need a note that names the target and cites a concrete
 * observation (or carries channels/evidence). Reopening with `open` clears
 * the resolution payload so stale evidence cannot masquerade as current.
 */
export function resolveHypothesis(hypothesis, resolution) {
  if (!isPlainObject(hypothesis)) invalid('hypothesis must be an object');
  if (!isPlainObject(resolution)) invalid('hypothesis resolution must be an object');
  const status = normalizeStatus(resolution.status);
  let channels = channelList(resolution.channels);
  let evidenceIds = stringList(resolution.evidenceIds, 'evidenceIds', 50);
  let note = optionalText(resolution.note ?? resolution.reason, 'note', MAX_NOTE);

  if (status === 'verified' && channels.length < 2 && evidenceIds.length === 0) {
    invalid('verified hypothesis requires >=2 distinct channels or at least one evidenceId');
  }
  if (status === 'disproved' || status === 'blocked') {
    if (note === null) invalid(`${status} hypothesis requires a specific note`);
    if (!specificNegativeNote(note, hypothesis, channels, evidenceIds)) {
      invalid(`${status} hypothesis requires a specific note that names this target and cites a concrete observation; a generic all-closed note is not enough`);
    }
  }
  if (status === 'open') {
    channels = [];
    evidenceIds = [];
    note = null;
  }

  return {
    ...hypothesis,
    status,
    channels,
    evidenceIds,
    note,
    reason: note,
  };
}

function hypothesisKey(hypothesis) {
  if (typeof hypothesis.id === 'string' && hypothesis.id.trim().length > 0) return hypothesis.id.trim();
  return `${hypothesis.strategy ?? ''}\u001f${hypothesis.targetKey ?? ''}\u001f${hypothesis.bugClass ?? ''}`;
}

/** Accept a plain hypothesis or a graph node whose details live in `attrs`. */
function hypothesisData(row) {
  if (!isPlainObject(row)) return null;
  if (!isPlainObject(row.attrs)) return row;
  return {
    ...row.attrs,
    ...row,
    id: row.attrs.hypothesisId ?? row.id ?? row.key,
    status: row.status ?? row.attrs.status,
  };
}

function foldHypotheses(rows) {
  const folded = new Map();
  if (!Array.isArray(rows)) return folded;
  for (const row of rows) {
    const data = hypothesisData(row);
    if (data === null) continue;
    if (typeof data.strategy !== 'string' && typeof data.targetKey !== 'string') continue;
    folded.set(hypothesisKey(data), data);
  }
  return folded;
}

function statusRank(status) {
  return STATUS_RANK[status] ?? 99;
}

/**
 * Copy, dedupe (last wins) and sort hypotheses for display. Open/active work
 * comes before terminal hypotheses; optional `{status, limit}` filters.
 */
export function listHypotheses(rows, options = {}) {
  if (options === null || options === undefined) options = {};
  if (typeof options === 'number') options = { limit: options };
  if (!isPlainObject(options)) invalid('listHypotheses options must be an object');

  const wanted = options.status === undefined
    ? null
    : new Set((Array.isArray(options.status) ? options.status : [options.status]).map((value) => String(value).toLowerCase()));

  let list = [...foldHypotheses(rows).values()];
  if (wanted !== null) list = list.filter((row) => wanted.has(String(row.status ?? '').toLowerCase()));
  list.sort((left, right) => (
    statusRank(String(left.status ?? '').toLowerCase()) - statusRank(String(right.status ?? '').toLowerCase())
    || String(left.strategy ?? '').localeCompare(String(right.strategy ?? ''))
    || String(left.targetKey ?? '').localeCompare(String(right.targetKey ?? ''))
  ));

  if (options.limit !== undefined) {
    const limit = Number(options.limit);
    if (!Number.isInteger(limit) || limit < 0) invalid('listHypotheses limit must be a non-negative integer');
    list = list.slice(0, limit);
  }

  return list.map((row) => clone(row));
}

/**
 * Aggregate hypotheses by status, bug class and strategy. Duplicate rows are
 * folded (last wins) before counting.
 */
export function hypothesisSummary(rows) {
  const values = [...foldHypotheses(rows).values()];
  const byStatus = Object.fromEntries(HYPOTHESIS_STATUSES.map((status) => [status, 0]));
  const byBugClass = {};
  for (const bugClass of [...BUG_CLASSES, ...EXTRA_BUG_CLASSES, 'unclassified']) byBugClass[bugClass] = 0;
  const byStrategy = {};
  let channelBacked = 0;
  let evidenceBacked = 0;
  let coverageLinked = 0;

  for (const row of values) {
    const status = String(row.status ?? 'open').toLowerCase();
    if (byStatus[status] !== undefined) byStatus[status] += 1;
    const bugClass = typeof row.bugClass === 'string' && row.bugClass.length > 0 ? row.bugClass : 'unclassified';
    byBugClass[bugClass] = (byBugClass[bugClass] ?? 0) + 1;
    const strategy = typeof row.strategy === 'string' && row.strategy.length > 0 ? row.strategy : 'unknown';
    byStrategy[strategy] = (byStrategy[strategy] ?? 0) + 1;
    if (Array.isArray(row.evidenceIds) && row.evidenceIds.length > 0) evidenceBacked += 1;
    if (Array.isArray(row.channels) && new Set(row.channels.map(String)).size >= 2) channelBacked += 1;
    if (typeof row.coverageKey === 'string' && row.coverageKey.length > 0) coverageLinked += 1;
  }

  return {
    total: values.length,
    open: byStatus.open,
    active: byStatus.active,
    verified: byStatus.verified,
    disproved: byStatus.disproved,
    deferred: byStatus.deferred,
    blocked: byStatus.blocked,
    unresolved: byStatus.open + byStatus.active + byStatus.deferred,
    evidenceBacked,
    channelBacked,
    coverageLinked,
    byStatus,
    byBugClass,
    byStrategy,
  };
}
