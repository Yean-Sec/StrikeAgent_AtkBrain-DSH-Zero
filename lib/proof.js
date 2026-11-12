/**
 * Finding authenticity and proof rules, ported from A-U's `graph/verify.py`,
 * `graph/finding_claim.py` and `graph/shell_bound.py`.
 *
 * A finding is not verified because its title says so. It needs material that
 * can be replayed, read back, or counted; a high/critical claim additionally
 * needs independent secondary review when the caller asks for it. An RCE claim
 * without an execution echo must not be rated high or critical, and command
 * output from a container/sandbox is a foothold, not a host shell.
 *
 * CVSS remains a severity score; it is never proof of exploitability. All
 * helpers are pure and return new values.
 */
import { isPlainObject } from './util.js';
import { normalizeInterfacePath } from './coverage.js';

/** Proof types recorded on a finding. */
export const PROOF_TYPES = Object.freeze(['poc_replay', 'write_txt', 'impact_extract']);

/** Categories that are visible but cannot be an exploited asset. */
export const NON_EXPLOIT_CATEGORIES = Object.freeze([
  'availability',
  'dos',
  'crash',
  'error_handling',
  'misconfig',
]);

/** Compatibility alias for callers that use the shorter name. */
export const NON_EXPLOIT = NON_EXPLOIT_CATEGORIES;

const SEVERITY_ORDER = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
const MAX_TEXT = 8000;
const MAX_TEXTS = 40;

const STATIC_ASSET_RE = /\.(?:css|js|mjs|map|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|webp|avif)$/iu;

/** Container / sandbox markers. */
const CONTAINER_RE = /\.dockerenv|kubepods|containerd|cri-?o|libpod|s6-svscan|s6-supervise|\btini\b|dumb-init|docker-init|overlayfs|沙箱|sandbox|容器内|cubebox-|gvisor|\brunsc\b/iu;

/** A negation only applies to the line that carries it. */
const UNPROVEN_RE = /未证明|尚未|未能|没有逃|未逃|未重放|不成立|不算逃/iu;

/** Evidence that PID 1 is the outer host init, not a container init. */
const OUTER_PID1_RE = /PID1(?:\s*(?:=|comm=|\/comm)\s*|\s+is\s*)(?:systemd|\/sbin\/init|\/lib\/systemd|init\b|cube-agent)/iu;

/** Category/title aliases that mean the same issue family. */
const CATEGORY_FAMILY = Object.freeze({
  xss: 'xss',
  rate_limit: 'rate_limit',
  ratelimit: 'rate_limit',
  vhost_bypass: 'vhost_bypass',
  cors: 'cors_policy',
  cors_policy: 'cors_policy',
  sqli: 'sqli',
  sql: 'sqli',
  sql_injection: 'sqli',
  db_access: 'sqli',
  file: 'file_read',
  file_read: 'file_read',
  file_download: 'file_read',
  lfi: 'file_read',
  rfi: 'file_read',
  arbitrary_file_read: 'file_read',
  path_traversal: 'file_read',
  directory_traversal: 'file_read',
  file_upload: 'file_upload',
  file_write: 'file_upload',
  upload: 'file_upload',
  info_disclosure: 'info_disclosure',
  information_disclosure: 'info_disclosure',
  info_leak: 'info_disclosure',
  leak: 'info_disclosure',
  source_leak: 'info_disclosure',
  backup_leak: 'info_disclosure',
  hardcoded_secret: 'info_disclosure',
  key_leak: 'info_disclosure',
  mass_pii: 'info_disclosure',
  cloud_credential: 'info_disclosure',
  sensitive_data_exposure: 'info_disclosure',
  credential_dump: 'info_disclosure',
  secrets_leak: 'info_disclosure',
  authz: 'authz',
  auth_bypass: 'authz',
  unauthorized: 'authz',
  unauth: 'authz',
  idor: 'authz',
  access_control: 'authz',
  admin_access: 'authz',
  privilege_escalation: 'authz',
  account_takeover: 'authz',
  rce: 'rce',
  command_injection: 'rce',
  cmd: 'rce',
  code: 'rce',
  code_execution: 'rce',
  code_injection: 'rce',
  arbitrary_code_execution: 'rce',
  ssti: 'rce',
  template_injection: 'rce',
  expression_injection: 'rce',
  deserialization: 'rce',
  deserialize: 'rce',
  getshell: 'rce',
  logic: 'business_logic',
  business_logic: 'business_logic',
  race_condition: 'business_logic',
  nday: 'nday',
  n_day: 'nday',
  cve: 'nday',
  public_vuln: 'nday',
  ssrf: 'ssrf',
  ssrf_internal: 'ssrf',
  credential: 'credential',
  credentials: 'credential',
  default_credentials: 'credential',
  weak_password: 'credential',
});

/** Issue-family patterns. Title and category are checked before evidence. */
const FAMILY_RULES = Object.freeze([
  [/xss|跨站脚本|反射型|存储型/iu, 'xss'],
  [/频率限制|速率限制|暴力破解|无锁定|撞库|credential\s*stuffing|rate[-_ ]?limit/iu, 'rate_limit'],
  [/尾点|vhost|虚拟主机|tomcat.{0,24}(?:默认|manager|examples|snoop)/iu, 'vhost_bypass'],
  [/crossdomain|allow-access-from|跨域策略|cors/iu, 'cors_policy'],
  [/\bsql\b|sql\s*注入|sqli|注入点|盲注|报错注入/iu, 'sqli'],
  [/任意文件读|文件读取|文件下载|文件包含|路径穿越|目录遍历|path[_\s-]?traversal|directory[_\s-]?traversal|file[_\s-]?inclusion|\blfi\b|\brfi\b|file[_\s-]?read|arbitrary[_\s-]?file/iu, 'file_read'],
  [/文件上传|任意文件上传|file[_\s-]?upload/iu, 'file_upload'],
  [/堆栈|异常|详细错误|stack\s*trace|内部类|\bbean\b|信息泄露|信息泄漏|敏感信息|源码|备份|泄露|泄漏|leak|disclosure/iu, 'info_disclosure'],
  [/未授权|越权|鉴权|权限绕过|权限|auth[_\s-]?bypass|idor|unauth|access[_\s-]?control/iu, 'authz'],
  [/命令注入|命令执行|(?:^|[^a-z0-9])rce(?:$|[^a-z0-9])|remote\s*code|代码执行|getshell|code[_\s-]?execution|command[_\s-]?injection|shell_exec|反序列化|deserial|ssti|模板注入|表达式注入/iu, 'rce'],
  [/n-?\s*day|公开漏洞|\bcve-\d{4}-\d{4,}\b/iu, 'nday'],
  [/业务逻辑|逻辑|越权领取|重放|并发|race\s*condition|business[_\s-]?logic/iu, 'business_logic'],
  [/ssrf|服务端请求伪造|url\s*跳转|url.*fetch/iu, 'ssrf'],
  [/弱口令|默认口令|口令|密码|credential|password/iu, 'credential'],
]);

/** Category -> default minimum severity (A-U's correction for underestimation). */
const CATEGORY_FLOORS = Object.freeze({
  rce: 'critical',
  command_injection: 'critical',
  cmd: 'critical',
  code: 'critical',
  code_execution: 'critical',
  code_injection: 'critical',
  arbitrary_code_execution: 'critical',
  ssti: 'critical',
  template_injection: 'critical',
  expression_injection: 'critical',
  deserialization: 'critical',
  deserialize: 'critical',
  getshell: 'critical',
  file_write: 'high',
  file_upload: 'high',
  file: 'high',
  arbitrary_file_read: 'high',
  file_read: 'high',
  file_download: 'high',
  lfi: 'high',
  rfi: 'high',
  path_traversal: 'high',
  directory_traversal: 'high',
  sqli: 'high',
  sql: 'high',
  sql_injection: 'high',
  db_access: 'high',
  auth_bypass: 'high',
  authz: 'high',
  admin_access: 'high',
  privilege_escalation: 'high',
  unauth: 'high',
  unauthorized: 'high',
  access_control: 'high',
  account_takeover: 'high',
  idor: 'medium',
  ssrf: 'medium',
  ssrf_internal: 'medium',
  xss: 'medium',
  info: 'info',
  business_logic: 'high',
  logic: 'high',
  source_leak: 'high',
  backup_leak: 'high',
  hardcoded_secret: 'high',
  key_leak: 'high',
  mass_pii: 'high',
  cloud_credential: 'high',
  sensitive_data_exposure: 'high',
  credential_dump: 'high',
  secrets_leak: 'high',
  leak: 'medium',
  info_disclosure: 'medium',
  information_disclosure: 'medium',
  info_leak: 'medium',
  nday: 'high',
  n_day: 'high',
  cve: 'high',
  public_vuln: 'high',
  credential: 'medium',
  credentials: 'medium',
  default_credentials: 'medium',
  weak_password: 'medium',
});

const FAMILY_FLOORS = Object.freeze({
  xss: 'medium',
  sqli: 'high',
  rce: 'critical',
  file_read: 'high',
  file_upload: 'high',
  authz: 'high',
  rate_limit: 'medium',
  business_logic: 'high',
  info_disclosure: 'medium',
  cors_policy: 'medium',
  vhost_bypass: 'medium',
  nday: 'high',
  ssrf: 'medium',
  credential: 'medium',
});

const RCE_CATEGORIES = new Set([
  'rce',
  'command_injection',
  'cmd',
  'code',
  'code_execution',
  'code_injection',
  'arbitrary_code_execution',
  'ssti',
  'template_injection',
  'expression_injection',
  'deserialization',
  'deserialize',
  'getshell',
]);

const RATING_ALIASES = Object.freeze({
  critical: 'critical',
  crit: 'critical',
  c: 'critical',
  严重: 'critical',
  high: 'high',
  h: 'high',
  高危: 'high',
  medium: 'medium',
  med: 'medium',
  m: 'medium',
  中危: 'medium',
  low: 'low',
  l: 'low',
  低危: 'low',
  info: 'info',
  informational: 'info',
  i: 'info',
  信息: 'info',
});

const EXEC_RE = /\bwhoami\b|uid=\d+(?:\([^)]+\))?|phpinfo\s*\(|\bshell_exec\b|command executed|命令执行成功|canary_ok|uname\s+-a/iu;
const NO_EXEC_RE = /未打成执行|未证明\s*rce|尚未证明|未获得代码执行|rce\s*未证明|upload_failed|未打通|没有解释器|未复现|版本命中|不给\s*rce|不标\s*rce|不能评.{0,8}rce|未打成.{0,6}执行|not\s+proven|unproven|no\s+command\s+execution/iu;
const PASSWD_LINE_RE = /(?:^|\n)[a-z0-9_.-]+:[x*!]:\d+:\d+:/imu;
const REPLAY_TEXT_RE = /\b(?:curl|wget)\b|\b(?:GET|POST|PUT|PATCH|DELETE)\s+\/|https?:\/\/\S+/iu;
const REPLAY_DETAIL_RE = /(?:replay|replayed|nonce|request|response|curl|wget|\b(?:GET|POST|PUT|PATCH|DELETE)\s+\/|https?:\/\/)/iu;
const ARTIFACT_DETAIL_RE = /https?:\/\/|\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.[A-Za-z0-9]{2,8}/u;
const COUNT_DETAIL_RE = /(\d+)\s*(?:rows?|records?|条|行|users?|accounts?|items?|entries)/iu;

const HOST_TLDS = new Set([
  'com', 'net', 'org', 'cn', 'io', 'edu', 'gov', 'uk', 'jp', 'de', 'info', 'cc', 'co',
  'app', 'dev', 'xyz', 'top', 'site', 'online', 'local', 'internal', 'lan', 'corp',
  'intranet', 'arpa', 'me', 'tv', 'ai', 'cloud', 'tech', 'biz', 'us', 'eu', 'fr', 'ru',
  'in', 'kr', 'au', 'ca', 'ch', 'it', 'nl', 'se', 'no', 'es', 'pl', 'be', 'at', 'dk',
  'fi', 'cz', 'gr', 'pt', 'tr', 'za', 'mx', 'ar', 'cl', 'hk', 'tw', 'sg', 'my', 'th',
  'vn', 'id', 'ph', 'nz', 'ie', 'il', 'ae', 'sa', 'pk', 'bd', 'lk', 'np', 'example',
  'test', 'invalid',
]);

/** Merge a graph node's `attrs` with its top-level fields (top level wins). */
function mergeFinding(finding) {
  if (!isPlainObject(finding)) return {};
  const merged = isPlainObject(finding.attrs) ? { ...finding.attrs } : {};
  for (const [key, value] of Object.entries(finding)) {
    if (value !== undefined) merged[key] = value;
  }
  return merged;
}

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

const META_FIELDS = new Set(['type', 'kind', 'label', 'name', 'format', 'title', 'note', 'status', 'verified']);

/** A nested artifact is real only when it carries content, not just a type label. */
function hasArtifact(value) {
  if (hasText(value)) return true;
  if (typeof value === 'number') return Number.isFinite(value) && value > 0;
  if (Array.isArray(value)) return value.some((entry) => hasArtifact(entry));
  if (!isPlainObject(value)) return false;
  for (const [key, entry] of Object.entries(value)) {
    if (META_FIELDS.has(key)) continue;
    if (hasArtifact(entry)) return true;
  }
  return false;
}

function normalizeKey(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/gu, '_')
    .replace(/[^a-z0-9_]+/gu, '')
    .replace(/_+/gu, '_')
    .replace(/^_|_$/gu, '');
}

function bandFromScore(score) {
  if (!Number.isFinite(score) || score < 0) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

function normalizeBand(value) {
  if (typeof value === 'number') return bandFromScore(value);
  const raw = String(value ?? '').trim().toLowerCase();
  if (raw.length === 0) return null;
  const alias = RATING_ALIASES[raw] ?? RATING_ALIASES[raw.replace(/[\s-]+/gu, '_')];
  if (alias !== undefined) return alias;
  if (/^\d+(?:\.\d+)?$/u.test(raw)) return bandFromScore(Number(raw));
  return null;
}

function normalizeSeverity(value) {
  return normalizeBand(value);
}

const GENERIC_CATEGORIES = new Set(['vuln', 'unknown', 'finding', 'issue', 'other']);

/** Prefer a specific bugClass over a generic display category. */
function findingCategory(data) {
  const primary = String(data.category ?? '').trim().toLowerCase();
  const secondary = String(data.bugClass ?? data.type ?? '').trim().toLowerCase();
  if (primary.length > 0 && !GENERIC_CATEGORIES.has(primary)) return primary;
  return secondary.length > 0 ? secondary : primary;
}

function effectiveSeverity(data) {
  const explicit = normalizeSeverity(data.severity);
  const floor = categoryMinSeverity(findingCategory(data));
  if (floor === null) return explicit ?? 'info';
  if (explicit === null) return floor;
  return SEVERITY_ORDER[explicit] >= SEVERITY_ORDER[floor] ? explicit : floor;
}

/**
 * Lowest severity a category should carry. Returns null when the category has
 * no known floor. Accepts `{category}` as well as a category string.
 */
export function categoryMinSeverity(category) {
  const raw = isPlainObject(category)
    ? (category.category ?? category.bugClass ?? category.type)
    : category;
  const key = normalizeKey(raw);
  if (key.length === 0) return null;
  if (CATEGORY_FLOORS[key] !== undefined) return CATEGORY_FLOORS[key];
  const family = issueFamily(key, '', '');
  if (family !== key && FAMILY_FLOORS[family] !== undefined) return FAMILY_FLOORS[family];
  return null;
}

/** True when the category is availability/crash/hardening, not exploitability. */
export function isNonExploitCategory(category) {
  const key = normalizeKey(category);
  return NON_EXPLOIT_CATEGORIES.includes(key);
}

/**
 * Authenticity material: a replayable request, an evidence artifact, or a
 * proof field. A `proofType` label alone is not proof.
 */
export function hasAuthenticityProof(finding) {
  if (!isPlainObject(finding)) return false;
  const data = mergeFinding(finding);
  for (const key of [
    'evidence', 'evidenceText', 'poc', 'pocCurl', 'pocPython', 'pocReplay', 'replay',
    'proof', 'proofDetail', 'proofCanary', 'proofUrl', 'repro', 'artifactPath',
    'evidencePath', 'command', 'httpRequest', 'request', 'impact', 'impactExtract',
    'execution',
  ]) {
    if (hasArtifact(data[key])) return true;
  }
  if (Array.isArray(data.evidenceIds) && data.evidenceIds.length > 0) return true;
  if (Array.isArray(data.artifacts) && data.artifacts.length > 0) return true;
  return false;
}

/**
 * Count distinct observation channels on a finding. Accepts a channel array,
 * a channel string, or an object with `channels`, `observations`, an
 * `observation` map, or a nested `verification`.
 */
export function channelCount(finding) {
  if (Array.isArray(finding) || typeof finding === 'string') {
    return channelCount({ channels: finding });
  }
  if (!isPlainObject(finding)) return 0;
  const data = mergeFinding(finding);
  const seen = new Set();

  const add = (value) => {
    if (typeof value === 'string' && value.trim().length > 0) {
      seen.add(value.trim().toLowerCase());
      return;
    }
    if (Array.isArray(value)) {
      for (const entry of value) add(entry);
      return;
    }
    if (!isPlainObject(value)) return;
    for (const key of ['channel', 'kind', 'type']) {
      if (typeof value[key] === 'string' && value[key].trim().length > 0) {
        seen.add(value[key].trim().toLowerCase());
      }
    }
    if (Array.isArray(value.channels)) add(value.channels);
  };

  for (const key of ['channels', 'observationChannels', 'evidenceChannels', 'observedChannels', 'callbackChannels']) {
    add(data[key]);
  }
  add(data.observations);
  if (isPlainObject(data.observation)) {
    for (const [key, value] of Object.entries(data.observation)) {
      if (value !== undefined && value !== null && value !== false && value !== '') add(key);
    }
  } else {
    add(data.observation);
  }
  const verification = data.verification;
  if (isPlainObject(verification)) {
    for (const key of ['channels', 'observationChannels', 'observedChannels']) add(verification[key]);
  }
  return seen.size;
}

/**
 * True when command output still belongs to a container/sandbox and no line
 * proves an outer PID 1. Negated escape sentences do not count as proof.
 */
export function shellIsContainerBound(...texts) {
  const parts = [];
  const push = (value) => {
    if (typeof value === 'string') {
      if (value.length > 0) parts.push(value);
      return;
    }
    if (Array.isArray(value)) {
      for (const entry of value) push(entry);
    }
  };
  for (const value of texts) push(value);
  const blob = parts.join('\n');
  if (blob.trim().length === 0 || !CONTAINER_RE.test(blob)) return false;
  const proven = blob
    .split(/[。\n\r]+/u)
    .filter((line) => !UNPROVEN_RE.test(line))
    .join('\n');
  return OUTER_PID1_RE.test(proven) === false;
}

/**
 * Collapse issue aliases into one family. The title (and a class name in it)
 * wins over the category, and both win over generic evidence prose, matching
 * the A-U rule that evidence may mention a different class without changing
 * the finding's identity.
 */
export function issueFamily(category, title = '', evidence = '') {
  const titleText = typeof title === 'string' ? title : '';
  const categoryText = typeof category === 'string' ? category : '';
  const evidenceText = typeof evidence === 'string' ? evidence : '';

  for (const [pattern, family] of FAMILY_RULES) {
    if (titleText.length > 0 && pattern.test(titleText)) return family;
  }

  const key = normalizeKey(categoryText);
  if (key.length > 0 && CATEGORY_FAMILY[key] !== undefined) return CATEGORY_FAMILY[key];

  for (const [pattern, family] of FAMILY_RULES) {
    if (categoryText.length > 0 && pattern.test(categoryText)) return family;
  }

  for (const [pattern, family] of FAMILY_RULES) {
    if (evidenceText.length > 0 && pattern.test(evidenceText)) return family;
  }

  return key.length > 0 ? key : 'vuln';
}

/** First interface path in a finding text/URL/node key; '' for root/static. */
export function interfacePathFrom(text) {
  let input = text;
  if (isPlainObject(input)) {
    const source = isPlainObject(input.attrs) ? mergeFinding(input) : input;
    input = [
      source.interfacePath, source.proofUrl, source.proof_url, source.url, source.targetUrl,
      source.endpoint, source.targetKey, source.title, source.description, source.evidence,
    ].filter((value) => typeof value === 'string' && value.trim().length > 0).join('\n');
  } else if (Array.isArray(input)) {
    input = input.filter((value) => typeof value === 'string' && value.trim().length > 0).join('\n');
  }
  if (typeof input !== 'string') return '';
  const raw = input.trim();
  if (raw.length === 0) return '';

  const clean = (candidate) => {
    let value = String(candidate ?? '').split('?')[0].split('#')[0];
    value = value.replace(/[.,;)\]}]+$/u, '');
    const path = normalizeInterfacePath(value);
    if (path.length === 0 || path === '/') return '';
    if (path.includes('..') || path.includes('$') || /[{}]/u.test(path)) return '';
    if (STATIC_ASSET_RE.test(path)) return '';
    if (path.split('/').length - 1 > 8) return '';
    return path;
  };

  for (const match of raw.matchAll(/(?:https?:)?\/\/([^/\s'"<>?#]+)([^\s'"<>?#]*)/giu)) {
    const path = clean(match[2] || '/');
    if (path.length > 0) return path;
  }
  for (const match of raw.matchAll(/(?:^|[\s"'(])([a-z][a-z0-9+.-]*:[^\s/]*)(\/[^\s'"<>?#]+)/giu)) {
    const path = clean(match[2]);
    if (path.length > 0) return path;
  }
  for (const match of raw.matchAll(/\b(?:[a-z0-9][-a-z0-9.]*|\[[0-9a-f:]+\]):\d{2,5}(\/[^\s'"<>?#]+)/giu)) {
    const path = clean(match[1]);
    if (path.length > 0) return path;
  }
  for (const match of raw.matchAll(/(?<![\w./-])(\/[A-Za-z0-9_./~!$%{}@+-]{2,180})/gu)) {
    const path = clean(match[1]);
    if (path.length > 0) return path;
  }
  return '';
}

/**
 * Operational harm band: a valid red-team rating wins, then severity, then a
 * numeric score. Unknown input is `unset` (not silently `info`).
 */
export function harmBand(severity, rating) {
  const rated = normalizeBand(rating);
  if (rated !== null) return rated;
  const scored = normalizeBand(severity);
  if (scored !== null) return scored;
  return 'unset';
}

function hostFromText(text) {
  const raw = String(text ?? '');
  const url = /(?:https?:)?\/\/([^/\s'"<>?#]+)/iu.exec(raw);
  if (url !== null) {
    const host = url[1].replace(/^[^@]*@/u, '').replace(/:\d+$/u, '').replace(/\.$/u, '').toLowerCase();
    if (host.length > 0) return host;
  }
  const ip = /\b(?:\d{1,3}\.){3}\d{1,3}\b/u.exec(raw);
  if (ip !== null) return ip[0];
  for (const match of raw.matchAll(/\b([a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*)+)(?::\d{2,5})?\b/giu)) {
    const host = match[1].toLowerCase().replace(/\.$/u, '');
    const labels = host.split('.');
    if (labels.length < 2) continue;
    if (!HOST_TLDS.has(labels[labels.length - 1])) continue;
    return host;
  }
  if (/\blocalhost\b/iu.test(raw)) return 'localhost';
  return '';
}

function dedupFacts(input) {
  const data = typeof input === 'string' ? { title: input } : mergeFinding(input);
  const category = data.bugClass || data.category || data.type || data.issueType || '';
  const title = data.title ?? data.name ?? data.summary ?? data.label ?? '';
  const evidence = [data.evidence, data.proofDetail, data.description, data.impact]
    .filter((value) => typeof value === 'string' && value.trim().length > 0)
    .join('\n');
  const family = issueFamily(category, title, evidence);
  const band = (data.harm !== undefined && data.harm !== null)
    ? harmBand(data.harm)
    : harmBand(data.severity, data.redteamRating ?? data.rating);
  const locatorText = [
    data.proofUrl, data.proof_url, data.url, data.targetUrl, data.endpoint,
    data.interfacePath, data.targetKey, title, data.description,
  ].filter((value) => typeof value === 'string' && value.trim().length > 0).join('\n');
  const explicit = typeof data.interfacePath === 'string' ? normalizeInterfacePath(data.interfacePath) : '';
  const path = explicit.length > 0 ? explicit : interfacePathFrom(locatorText);
  const host = hostFromText(locatorText);
  const locator = path.length > 0
    ? (host.length > 0 ? `${host}${path}` : path)
    : (host.length > 0 ? host : 'nopath');
  return { data, category, title, family, band, path, host, locator };
}

/**
 * Primary dedup key: same interface + same issue family + same harm band.
 * A title-only change therefore collapses, while a different impact does not.
 * An array input returns the mapped keys.
 */
export function findingDedupKey(finding) {
  if (Array.isArray(finding)) return finding.map((entry) => findingDedupKey(entry));
  if (finding === undefined || finding === null || finding === '') return '';
  const facts = dedupFacts(finding);
  return `pc:${facts.locator}|${facts.family}|${facts.band}`;
}

/**
 * All A-U-style dedup keys for one finding (primary, plus page and vhost
 * refinements). The first key is always `findingDedupKey(finding)`.
 */
export function findingDedupKeys(finding) {
  const primary = findingDedupKey(finding);
  if (primary.length === 0) return [];
  const facts = dedupFacts(finding);
  const keys = [primary];
  if (facts.family === 'xss') {
    const named = /([a-z0-9_]+)(?:![a-z0-9_]+)?\.action/iu.exec(facts.title)
      ?? /([a-z0-9_]+)(?:![a-z0-9_]+)?\.action/iu.exec(facts.path);
    const page = named !== null
      ? named[1].toLowerCase()
      : (/登录/u.test(facts.title) ? 'login' : '');
    if (page.length > 0) keys.push(`pg:${page}|xss|${facts.band}`);
  }
  if (facts.family === 'vhost_bypass' && facts.host.length > 0) {
    keys.push(`vh:${facts.host}|vhost_bypass|${facts.band}`);
  }
  return [...new Set(keys)];
}

function asText(value) {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.filter((entry) => typeof entry === 'string').join(' ');
  return '';
}

/** True when a finding's category/title/body claims command execution. */
export function isRceClaim(finding) {
  if (isPlainObject(finding)) {
    const data = mergeFinding(finding);
    const category = normalizeKey(findingCategory(data));
    if (RCE_CATEGORIES.has(category)) return true;
    const text = [
      data.category, data.bugClass, data.type, data.title, data.name, data.description,
      data.evidence, data.proofDetail, data.impact,
    ].map(asText).filter(Boolean).join('\n');
    return /(?:^|[^a-z0-9])rce(?:$|[^a-z0-9])|远程代码执行|命令执行|命令注入|代码执行|getshell|webshell|shell_exec|command\s+injection|code\s+execution|反序列化|deserial|ssti|模板注入|表达式注入/iu.test(text);
  }
  if (typeof finding === 'string') {
    return /(?:^|[^a-z0-9])rce(?:$|[^a-z0-9])|远程代码执行|命令执行|命令注入|代码执行|getshell|webshell|shell_exec|command\s+injection|code\s+execution|反序列化|deserial|ssti|模板注入|表达式注入/iu.test(finding);
  }
  return false;
}

function pushTexts(out, value, depth = 0) {
  if (out.length >= MAX_TEXTS || depth > 4) return;
  if (typeof value === 'string') {
    const text = value.trim();
    if (text.length > 0) out.push(text.slice(0, MAX_TEXT));
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value.slice(0, 20)) pushTexts(out, entry, depth + 1);
    return;
  }
  if (!isPlainObject(value)) return;
  for (const entry of Object.values(value).slice(0, 20)) pushTexts(out, entry, depth + 1);
}

function proofTexts(finding) {
  const data = mergeFinding(finding);
  const out = [];
  for (const key of [
    'title', 'description', 'evidence', 'evidenceText', 'proofDetail', 'proofCanary',
    'pocCurl', 'pocPython', 'pocReplay', 'replay', 'command', 'output', 'stdout',
    'result', 'request', 'httpRequest', 'repro', 'impact', 'impactExtract',
  ]) {
    if (data[key] !== undefined) pushTexts(out, data[key]);
  }
  for (const key of ['proof', 'execution', 'verification', 'secondaryReview']) {
    if (isPlainObject(data[key])) pushTexts(out, data[key]);
  }
  return out;
}

function executionImpactProven(finding) {
  const data = mergeFinding(finding);
  if (isPlainObject(data.execution)) {
    for (const key of ['stdout', 'output', 'echo', 'result', 'commandOutput']) {
      if (hasText(data.execution[key])) return true;
    }
  }
  const text = proofTexts(data).join('\n');
  if (text.trim().length === 0) return false;
  const executed = EXEC_RE.test(text);
  if (PASSWD_LINE_RE.test(text) && !executed) return false;
  if (NO_EXEC_RE.test(text) && !executed) return false;
  return executed;
}

function claimsShell(finding) {
  const data = mergeFinding(finding);
  const access = String(data.accessType ?? data.access ?? data.shellType ?? '').toLowerCase();
  if (['user_shell', 'root_shell', 'shell', 'foothold', 'webshell'].includes(access)) return true;
  if (data.shell === true) return true;
  const execution = isPlainObject(data.execution)
    ? Object.values(data.execution).filter((value) => typeof value === 'string').join('\n')
    : '';
  const text = [
    data.category, data.bugClass, data.title, data.evidence, data.proofDetail,
    data.proofCanary, data.proofUrl, execution,
  ].filter((value) => typeof value === 'string').join('\n');
  return /\b(?:uid=\d+|whoami|getshell|webshell|reverse\s+shell|bind\s+shell)\b|命令执行成功|立足点/iu.test(text);
}

function hasSecondaryVerification(finding) {
  const data = mergeFinding(finding);
  if (data.secondaryVerified === true || data.secondary === true) return true;
  for (const key of ['secondaryStatus', 'secondaryVerdict', 'verificationMode']) {
    if (String(data[key] ?? '').toLowerCase() === 'verified' || String(data[key] ?? '').toLowerCase() === 'secondary') return true;
  }
  if (String(data.verifiedBy ?? '').toLowerCase() === 'secondary' || String(data.verifiedBy ?? '').toLowerCase() === 'verifier') return true;
  if (Array.isArray(data.secondaryEvidenceIds) && data.secondaryEvidenceIds.length > 0) return true;
  if (Array.isArray(data.secondaryEvidence) && data.secondaryEvidence.length > 0) return true;
  if (isPlainObject(data.secondary) && (data.secondary.verified === true || String(data.secondary.status ?? '').toLowerCase() === 'verified')) return true;
  if (isPlainObject(data.secondaryReview)) {
    if (data.secondaryReview.verified === true) return true;
    if (String(data.secondaryReview.status ?? '').toLowerCase() === 'verified') return true;
    if (Array.isArray(data.secondaryReview.evidenceIds) && data.secondaryReview.evidenceIds.length > 0) return true;
  }
  const verification = data.verification;
  if (isPlainObject(verification)) {
    if (verification.secondary === true) return true;
    if (String(verification.secondaryStatus ?? '').toLowerCase() === 'verified') return true;
    if (String(verification.secondaryVerdict ?? '').toLowerCase() === 'verified') return true;
    if (String(verification.mode ?? '').toLowerCase() === 'secondary') return true;
  }
  return false;
}

function proofMaterialMissing(data, proofType) {
  const missing = [];
  const nested = isPlainObject(data.proof) ? data.proof : {};
  if (proofType === 'poc_replay') {
    const replay = ['pocCurl', 'pocPython', 'pocReplay', 'replay', 'command', 'httpRequest', 'request', 'repro', 'poc', 'proofUrl'];
    const nestedReplay = ['curl', 'python', 'request', 'replay', 'command', 'httpRequest', 'poc', 'body']
      .some((key) => hasText(nested[key]));
    const detail = [data.evidence, data.proofDetail, data.repro, nested.detail]
      .filter((value) => typeof value === 'string')
      .join('\n');
    const present = replay.some((key) => hasArtifact(data[key]))
      || nestedReplay
      || REPLAY_TEXT_RE.test(detail)
      || REPLAY_DETAIL_RE.test(detail);
    if (!present) missing.push('replay');
  } else if (proofType === 'write_txt') {
    const canary = hasText(data.proofCanary) || hasText(data.canary) || hasText(nested.canary);
    const detail = [data.proofDetail, data.evidence, nested.detail].filter((value) => typeof value === 'string').join('\n');
    const artifact = hasText(data.proofUrl) || hasText(data.artifactPath)
      || hasText(data.evidencePath) || hasText(data.writeTxt) || hasText(data.url)
      || hasText(nested.url) || hasText(nested.path)
      || ARTIFACT_DETAIL_RE.test(detail);
    if (!canary) missing.push('canary');
    if (!artifact) missing.push('artifact');
  } else if (proofType === 'impact_extract') {
    const impact = data.impact ?? data.impactExtract ?? data.extract ?? data.dataEvidence;
    const count = data.dataCount ?? data.affectedCount ?? data.records ?? data.rowCount ?? data.count;
    const detail = [data.proofDetail, data.evidence, nested.detail].filter((value) => typeof value === 'string').join('\n');
    const present = hasArtifact(impact) || (typeof count === 'number' && count > 0)
      || hasArtifact(nested.impact) || (typeof nested.count === 'number' && nested.count > 0)
      || COUNT_DETAIL_RE.test(detail);
    if (!present) missing.push('impact_extract');
  }
  return missing;
}

function proofResult(status, reason, missing) {
  return { ok: status === 'verified', status, reason, missing };
}

/**
 * Validate a finding's proof material.
 *
 * Returns exactly `{ok, status, reason, missing}`:
 *   verified  proof material is sufficient
 *   pending   more evidence is needed (no proof, missing proof-type material,
 *             missing secondary review, container-bound shell)
 *   rejected  the claim is invalid (non-object, refuted, unknown proofType,
 *             unproven high/critical RCE)
 *
 * `requireSecondaryForHigh` (default false) asks for independent verification
 * of high/critical findings. Severity is normalized against the category floor
 * before that check, so a mislabeled `rce` cannot dodge it.
 */
export function validateFindingProof(finding, options = {}) {
  if (!isPlainObject(finding)) {
    return proofResult('rejected', 'finding must be an object', ['finding']);
  }
  const data = mergeFinding(finding);
  const category = findingCategory(data);

  if (isNonExploitCategory(category)) {
    return proofResult('pending', 'non-exploit category (availability/crash/misconfig) is not an exploited asset', ['exploit_impact']);
  }
  if (String(data.verification ?? '').trim().toLowerCase() === 'refuted' || String(data.status ?? '').trim().toLowerCase() === 'refuted') {
    return proofResult('rejected', 'finding is marked refuted', []);
  }
  if (!hasAuthenticityProof(data)) {
    return proofResult('pending', 'no authenticity proof: attach evidence, a PoC, or a proof artifact', ['proof']);
  }

  const rawProofType = data.proofType ?? (isPlainObject(data.proof) ? data.proof.type : undefined);
  const proofType = rawProofType === undefined || rawProofType === null || String(rawProofType).trim() === ''
    ? null
    : String(rawProofType).trim().toLowerCase();
  if (proofType !== null && !PROOF_TYPES.includes(proofType)) {
    return proofResult('rejected', `proofType must be one of ${PROOF_TYPES.join(', ')}`, ['proofType']);
  }
  if (proofType !== null) {
    const missing = proofMaterialMissing(data, proofType);
    if (missing.length > 0) {
      return proofResult('pending', `proofType ${proofType} is missing required material`, missing);
    }
  }

  const severity = effectiveSeverity(data);
  if (options?.requireSecondaryForHigh === true
    && SEVERITY_ORDER[severity] >= SEVERITY_ORDER.high
    && !hasSecondaryVerification(data)) {
    return proofResult('pending', 'high/critical finding requires independent secondary verification', ['secondary_verification']);
  }

  if (isRceClaim(data)
    && SEVERITY_ORDER[severity] >= SEVERITY_ORDER.high
    && !executionImpactProven(data)) {
    return proofResult('rejected', 'unproven RCE/command execution cannot be rated high or critical; attach an execution echo', ['execution_echo']);
  }

  if (claimsShell(data) && shellIsContainerBound(proofTexts(data))) {
    return proofResult('pending', 'shell evidence is container/sandbox-bound; prove an outer PID 1 or record a foothold', ['outer_pid1']);
  }

  return proofResult('verified', 'proof accepted', []);
}
