/**
 * Interface x bug-class coverage board.
 *
 * A web interface is tested once per bug class. The board is deliberately
 * small and JSON-friendly: nine classes times every observed path, with a
 * lifecycle that prevents a worker from silently closing a cell on one
 * observation channel.
 *
 * Statuses:
 *   open      nobody has worked this cell yet
 *   claimed   a worker took it (a worker starting is not coverage)
 *   seen      the cell was actually exercised; needs two channels or evidence
 *   refuted   a negative result that names this path and this class
 *   reported  a finding exists for this cell; needs findingId
 *
 * The module is pure: every function returns new plain objects, never mutates
 * its input, and never reads the clock, the filesystem or the network.
 */
import { classesForParameter } from './surface.js';
import { invalid, isPlainObject } from './util.js';

/** Coverage classes kept on the board, in dispatch order. */
export const BUG_CLASSES = Object.freeze([
  'xss',
  'sqli',
  'authz',
  'leak',
]);

/**
 * What must be true before a cell of that class can be closed.
 * These are acceptance rules for the coverage board, not scanner recipes.
 */
export const COVERAGE_DUTIES = Object.freeze({
  xss: Object.freeze({
    role: 'cov-xss',
    duty: '跨站脚本。先看输入落在正文、属性、事件还是脚本里，再按那个位置闭合。这个接口已经记下的参数，闭合时必须点名。和别的接口共用页面，也算这一口。输入已经进入这些位置时不能否证。JSON 里回显不算这格测完。',
  }),
  sqli: Object.freeze({
    role: 'cov-sqli',
    duty: 'SQL 注入。对每个新的字符串参数做一次引号差分。一次 400、402 或 500 不能否证，要换过方法、空正文或另一个身份。',
  }),
  cmd: Object.freeze({
    role: 'cov-cmd',
    duty: '命令执行。对每个新的字符串参数做一次命令元字符差分。',
  }),
  code: Object.freeze({
    role: 'cov-code',
    duty: '代码执行。对每个新的字符串参数做一次模板或表达式探测，也包括反序列化。',
  }),
  file: Object.freeze({
    role: 'cov-file',
    duty: '文件读取。路径、文件名、模板、图像、导出、包含和备份都做路径差分。没有上传不能把这格写成测完。跳到对象存储或带签名的地址是观察，不是否证。一次 400、402 或 500 不能否证，要换过方法、空正文或另一个身份。',
  }),
  authz: Object.freeze({
    role: 'cov-authz',
    duty: '越权。无会话访问一次，再更换对象标识访问一次。对象标识和批量赋值都要看。同一接口已经出现方法名分发时，不能只写成公开读取。一次 400、402 或 500 不能否证，要换过方法、空正文或另一个身份。',
  }),
  logic: Object.freeze({
    role: 'cov-logic',
    duty: '业务逻辑。看会员、钱包、优惠券、数量和价格，以及状态和步骤。登录、改密、找回密码要写明失败次数有没有被限制。写成没有限制或没有锁定时，不能否证。一次 400、402 或 500 不能否证，要换过方法、空正文或另一个身份。',
  }),
  leak: Object.freeze({
    role: 'cov-leak',
    duty: '信息泄露。看日志、密钥、指标、目录、JSONP，以及 swagger、.git、配置和带调用栈的报错。响应里已经有调用栈、异常页或版本时，不能否证。',
  }),
  nday: Object.freeze({
    role: 'cov-nday',
    duty: '已知漏洞。先确认产品或版本，再查公开漏洞。没有版本就停。',
  }),
});

const JSON_ONLY_XSS_RE = /json/iu;
const HTML_CONTEXT_RE = /正文|属性|事件|脚本|body|attribute|onclick|href|script|html/iu;
const UPLOAD_ONLY_RE = /没有上传|无上传|no upload/iu;
const FILE_SINK_RE = /路径|文件名|模板|图像|导出|包含|\bpath\b|filename|template|include/iu;
const VERSION_RE = /版本|version|banner|tomcat|struts|产品/iu;
const NDAY_HUNT_RE = /cve-|nuclei|公开漏洞|已知漏洞/iu;

const OBJECT_FETCH_RE = /(?:302|301|redirect|跳转|location).{0,80}(?:bucket|s3|oss|blob|presign|signed|签名|对象)|(?:bucket|presign|signed url|对象存储|签名地址)|(?:读到|读取到|\bread\b|returned|downloaded|fetched).{0,40}(?:对象|文件内容|object contents|object body)|对象内容/iu;
const AUTH_PATH_RE = /login|signin|sign-in|password|passwd|forgot|reset|改密|找回/iu;
const RATE_OBSERVATION_RE = /429|captcha|lock|throttle|rate|limit|频率|锁定|验证码|次数/iu;
const CONTROL_ABSENT_RE = /(?:\bnot\b|\bno\b|\bwithout\b|没有|未见|未发现|未|无|缺乏).{0,24}(?:rate[- ]?limit|lock(?:out)?|captcha|throttle|频率限制|频率|锁定|验证码)|(?:\bno\b|\bwithout\b|没有|未见|未返回|未).{0,8}429|not limited|没有限制|未限制|无限制|未被限制|没有被限制|protection is absent/iu;
const CONTROL_PRESENT_RE = /(?:\b(?:is|are|was|were)\b\s+limited|已限制|有锁定|锁定生效|lockout after|account locked|returned\s+429|返回\s*429|http\s*429|验证码拦截|captcha (?:blocked|required|shown|enforced))/iu;
const SHARED_PAGE_RE = /同一(?:张|个)?(?:页面|表单)|same (?:form|page|document|template)|returns? the login|回到登录|login form|同一页/iu;
const ACTIVE_REFUTE = new Set(['xss', 'sqli', 'cmd', 'code', 'file']);
const DISPATCH_RE = /!method|dynamic method|nosuchmethod|方法名|动态方法/iu;
const DISPATCH_AUTH_RE = /未登录.{0,12}方法|拦截器|interceptor|unauthenticated method/iu;
const FILE_HANDLER_RE = /(?:download|export|upload|include|attach|readfile|getfile|\/file\b|file\.)/iu;
const FILE_CONTAINED_RE = /指定目录|留在目录|目录内|未越出|没有越出|越出.{0,12}拒绝|outside.{0,24}(?:rejected|denied)|traversal (?:failed|denied|rejected)|stayed in the intended/iu;
const LOGIN_WALL_RE = /login|signin|sign-in|auth|account|password/iu;
const GAVE_UP_RE = /没进去|进不去|无法访问|could not (?:access|enter)|not accessible|未进入/iu;
const ANON_REJECT_RE = /未登录.{0,24}(?:拒绝|401|403)|anonymous.{0,24}(?:denied|rejected|401|403)|未授权.{0,12}拒绝/iu;
const ENCODED_RE = /编码|encoded|escaped|转义/iu;

function missingNames(names, text) {
  const body = String(text ?? '').toLowerCase();
  return names.filter((name) => {
    const token = String(name ?? '').trim();
    return token.length > 0 && !body.includes(token.toLowerCase());
  });
}

/** Note and reason are the same observation. Older cells stored only one of them. */
export function coverageNoteText(attrs = {}) {
  const note = typeof attrs.note === 'string' ? attrs.note.trim() : '';
  const reason = typeof attrs.reason === 'string' ? attrs.reason.trim() : '';
  if (note.length === 0) return reason;
  if (reason.length === 0 || reason === note) return note;
  return `${note}\n${reason}`;
}

function postureViolation(bugClass, status, surface) {
  if (status !== 'refuted' || !ACTIVE_REFUTE.has(bugClass)) return null;
  const mode = String(surface.mode ?? '').trim().toLowerCase();
  const lowMode = mode === 'view' || mode === 'collect' || mode === 'validate';
  const techniques = Array.isArray(surface.techniques) ? surface.techniques.map(String) : null;
  const missingT3 = techniques !== null && !techniques.includes('T3');
  if (!lowMode && !missingT3) return null;
  return `${bugClass} cannot be refuted while engagement mode is ${lowMode ? mode : 'not intrusive'} or techniques omit T3; set mode intrusive and techniques T0-T3 before a negative result`;
}

function negatedBefore(text, index) {
  const before = text.slice(Math.max(0, index - 24), index);
  return /(?:\bnot\b|\bno\b|\bwithout\b|\bnever\b|没有|未见|未发现|未|无)\s*$/iu.test(before);
}

function xssLanded(text) {
  const landing = /reflect(?:ed|s)?|rendered|进入了|写进了|写入了|落地/giu;
  let match;
  while ((match = landing.exec(text)) !== null) {
    if (negatedBefore(text, match.index)) continue;
    const after = text.slice(match.index, match.index + 80);
    if (/(?:正文|属性|事件|脚本|body|attribute|event|script|hidden|value|href)/iu.test(after)) return true;
  }
  return false;
}

function leakDisclosed(text) {
  const signal = /stack\s*trace|调用栈|异常页|exception\s*(?:page|report)|whitelabel|status\s*report|版本号|服务器版本|tomcat\/\d|version\s*(?:string|disclosure|banner|\d)|server version/giu;
  let match;
  while ((match = signal.exec(text)) !== null) {
    if (!negatedBefore(text, match.index)) return true;
  }
  return false;
}

function sharedParameterViolation(bugClass, text, surface) {
  if (!SHARED_PAGE_RE.test(text) || !isPlainObject(surface.parameterMap)) return null;
  const lower = text.toLowerCase();
  const keys = Object.keys(surface.parameterMap).filter((key) => {
    const path = String(key).toLowerCase();
    if (path.length > 1 && lower.includes(path)) return true;
    if (/login|signin|sign-in|form/iu.test(lower) && /login|signin|sign-in|form/iu.test(path)) return true;
    return false;
  });
  const names = [...new Set(keys.flatMap((key) => (Array.isArray(surface.parameterMap[key]) ? surface.parameterMap[key] : [])))];
  const missing = missingNames(names, text);
  if (missing.length === 0) return null;
  return `cov-${bugClass} stays open: the note says this response is a page that already has parameters; name them: ${missing.slice(0, 8).join(', ')}`;
}

const EARLY_FAILURE_RE = /\b(?:400|402|500)\b/gu;
const VARIANT_ATTEMPT_RE = /空正文|empty body|换方法|另一(?:个)?(?:方法|身份|角色)|无会话|另一个用户|\b(?:POST|PUT|PATCH|DELETE)\b|second attempt|again with/iu;

/** One 400/402/500, with no second method, body, or role, does not refute the cell. */
function singleFailureRefute(bugClass, status, text) {
  if (status !== 'refuted' || !['logic', 'authz', 'sqli', 'file'].includes(bugClass)) return null;
  const codes = [...new Set(text.match(EARLY_FAILURE_RE) ?? [])];
  if (codes.length !== 1 || VARIANT_ATTEMPT_RE.test(text)) return null;
  return `cov-${bugClass} stays open: one ${codes[0]} is not a refutation; record a second attempt with another method, an empty body, or another role`;
}

/**
 * Why a close note does not satisfy that class. Null when the note may stand.
 * `surface` is the ledger already stored for this path: parameters, output
 * contexts, and notes from the other classes on the same path.
 */
export function coverageDutyViolation(bugClass, note, status, surface = {}) {
  if (status !== 'seen' && status !== 'refuted' && status !== 'reported') return null;
  const text = String(note ?? '');
  if (text.length === 0) return null;
  const parameters = Array.isArray(surface.parameters) ? surface.parameters : [];
  const contexts = Array.isArray(surface.contexts) ? surface.contexts : [];
  const sibling = String(surface.siblingNote ?? '');
  const path = String(surface.path ?? '');
  const posture = postureViolation(bugClass, status, surface);
  if (posture !== null) return posture;
  const early = singleFailureRefute(bugClass, status, text);
  if (early !== null) return early;
  if (status === 'refuted' && bugClass === 'logic' && AUTH_PATH_RE.test(path) && CONTROL_ABSENT_RE.test(text) && !CONTROL_PRESENT_RE.test(text)) {
    return 'cov-logic stays open: the note says this authentication path has no rate limit or no lockout; record that as a finding or seen, do not refute it';
  }
  if (status === 'refuted' && bugClass === 'leak' && leakDisclosed(text)) {
    return 'cov-leak stays open: the note says the response already exposes a stack, exception page, or version; record that as a finding or seen, do not refute it';
  }
  if (status === 'refuted' && bugClass === 'xss' && xssLanded(text)) {
    return 'cov-xss stays open: the note says input already landed in the body, an attribute, an event, or a script; record that as a finding or seen, do not refute it';
  }
  const shared = status === 'refuted' ? sharedParameterViolation(bugClass, text, surface) : null;
  if (shared !== null) return shared;
  if (bugClass === 'xss' && JSON_ONLY_XSS_RE.test(text) && !HTML_CONTEXT_RE.test(text)) {
    return 'JSON reflection does not close cov-xss; name whether the input lands in body, attribute, event, or script';
  }
  if (bugClass === 'xss' && status === 'refuted' && surface.ledgerThin === true) {
    return 'cov-xss stays open: this application has many paths and this path has no stored parameter or output context; call endpoint_vocab before a negative result';
  }
  if (bugClass === 'xss' && (status === 'refuted' || status === 'seen')) {
    const missing = missingNames(parameters, text);
    if (missing.length > 0) {
      return `cov-xss stays open until the note names the parameter(s) already stored for this path: ${missing.slice(0, 8).join(', ')}`;
    }
    if (contexts.includes('hidden-input-value') && !/属性|attribute|hidden/iu.test(text)) {
      return 'cov-xss stays open: a hidden input value was observed on this path and the note does not say whether that attribute reflects';
    }
    if (contexts.includes('inline-event-handler') && !/事件|onclick|onload|onerror|event handler|inline event/iu.test(text)) {
      return 'cov-xss stays open: an inline event handler was observed on this path and the note does not say whether it reflects';
    }
    if (contexts.includes('href-attribute') && !/href|链接/iu.test(text)) {
      return 'cov-xss stays open: an href was observed on this path and the note does not say whether it reflects';
    }
    const dangerousContext = contexts.some((name) => /hidden|href|event|attribute|script/iu.test(String(name)));
    if (status === 'refuted' && dangerousContext && !ENCODED_RE.test(text)) {
      return 'cov-xss stays open: an attribute, event, link, or script context is already stored; name the parameter and say that location was encoded';
    }
  }
  if (bugClass === 'file' && status === 'refuted' && (OBJECT_FETCH_RE.test(text) || OBJECT_FETCH_RE.test(sibling))) {
    return 'cov-file stays open: this path already showed a redirect or signed object URL; record that observation, do not refute the cell from a traversal miss';
  }
  if (bugClass === 'file' && UPLOAD_ONLY_RE.test(text) && !FILE_SINK_RE.test(text)) {
    return 'the absence of an upload does not close cov-file; record a path differential for path, filename, template, image, export, or include';
  }
  if (bugClass === 'file' && status === 'refuted' && FILE_HANDLER_RE.test(path) && !FILE_CONTAINED_RE.test(text)) {
    return 'cov-file stays open: a file or download handler stays open until the note says the read stayed in the intended directory or an escape was rejected';
  }
  if (bugClass === 'file' && (status === 'refuted' || status === 'seen')) {
    const named = parameters.filter((name) => classesForParameter(name).includes('file'));
    const missing = missingNames(named, text);
    if (missing.length > 0) {
      return `cov-file stays open until the note names the file parameter(s) already stored for this path: ${missing.slice(0, 8).join(', ')}`;
    }
  }
  if (bugClass === 'authz' && status === 'refuted' && DISPATCH_RE.test(`${text}\n${sibling}`) && !DISPATCH_AUTH_RE.test(text)) {
    return 'cov-authz stays open: this path already showed method dispatch; a public-read note does not close it';
  }
  if (bugClass === 'authz' && status === 'refuted' && !LOGIN_WALL_RE.test(path) && GAVE_UP_RE.test(text) && !ANON_REJECT_RE.test(text)) {
    return 'cov-authz stays open: this path is outside the login wall; a note that access failed does not close it unless it says an anonymous request was rejected';
  }
  if (bugClass === 'logic' && status === 'refuted' && AUTH_PATH_RE.test(path) && !RATE_OBSERVATION_RE.test(text)) {
    return 'cov-logic stays open on an authentication path until the note says whether repeated failures are limited';
  }
  if ((bugClass === 'leak' || bugClass === 'xss' || bugClass === 'authz') && status === 'refuted' && /\.xml$/iu.test(path) && /text\/html|homepage|首页/iu.test(text) && !/application\/xml|xml policy|策略文件/iu.test(text)) {
    return 'this path is its own document; a homepage HTML body does not close it';
  }
  if (bugClass === 'nday' && NDAY_HUNT_RE.test(text) && !VERSION_RE.test(text)) {
    return 'cov-nday stops until a product or version is recorded; do not close it from a public-vuln check that had no version';
  }
  if (bugClass === 'nday' && (status === 'refuted' || status === 'seen') && Array.isArray(surface.unrecordedVersions) && surface.unrecordedVersions.length > 0) {
    return `cov-nday stays open: an error page already names ${surface.unrecordedVersions.slice(0, 3).join(', ')} and that version is not a tech node`;
  }
  return null;
}

export function coverageDuty(bugClass) {
  return COVERAGE_DUTIES[bugClass] ?? null;
}

/** Coverage lifecycle values. */
export const COVERAGE_STATUSES = Object.freeze([
  'open',
  'claimed',
  'seen',
  'refuted',
  'reported',
]);

const DEFAULT_ROLE = 'web-exploit';
const DEFAULT_PATH_LIMIT = 200;
const MAX_PATH_LIMIT = 2000;
const MAX_NOTE = 2000;
const MAX_PATH = 300;
const MAX_ID = 300;

/** Immutable-file and decoration paths are not interfaces. */
const STATIC_ASSET_RE = /\.(?:css|js|mjs|map|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|webp|avif)$/iu;

/** Closing words that are not evidence on their own. */
const GENERIC_CLOSE_RE = /(?:全部\s*404|全站\s*404|一律\s*404|面\s*(?:关闭|已关|死了|已死)|穷尽|无差异|全部关闭|全部失败|\buniform\b|\bexhausted\b|no\s+difference)/iu;

/** A real refutation names something observable. */
const SPECIFIC_OBSERVATION_RE = /(?:\b[1-5]\d{2}\b|\b\d+\s*(?:ms|毫秒|秒|bytes?|字节|行)\b|payload|canary|回显|反射|响应|正文|响应头|长度|耗时|时延|差异|参数|未打中|没有反射|no\s+reflection|reflect|timing|length|header|body|status|difference)/iu;

/** Concrete channel/parameter detail that lifts a generic close out of the reject set. */
const SPECIFIC_CONTRAST_RE = /(?:响应|正文|响应头|长度|耗时|时延|回显|反射|payload|参数|header|body|timing|length|difference|状态码|status\s*code)/iu;

/** Normalize one bug class; returns '' when it is not in BUG_CLASSES. */
function normalizeBugClass(value) {
  const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return BUG_CLASSES.includes(text) ? text : '';
}

/**
 * Extract and canonicalize the path component of a URL or path.
 *
 * Only the path is returned (never the host, query or fragment) and it is
 * lower-cased. Root stays `/`; empty, malformed, traversal, placeholder and
 * non-path inputs return ''. Static-asset filtering is a board policy and
 * lives in `seedCoverage`/`noteCoverage`, not here.
 */
export function normalizeInterfacePath(value) {
  if (typeof value !== 'string') return '';
  const raw = value.trim();
  if (raw.length === 0 || raw.startsWith('#')) return '';
  if (/[\u0000-\u001f\u007f]/u.test(raw)) return '';

  let pathname = '';
  if (/^[a-z][a-z0-9+.-]*:\/{3,}/iu.test(raw)) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(raw) || raw.startsWith('//')) {
    try {
      const url = new URL(raw.startsWith('//') ? `http:${raw}` : raw);
      pathname = url.pathname;
    } catch {
      return '';
    }
  } else if (raw.startsWith('/')) {
    pathname = raw;
  } else if (raw.startsWith('?')) {
    pathname = '/';
  } else {
    const scheme = /^([a-z][a-z0-9+.-]*):([^/]*)(\/.*)$/iu.exec(raw);
    if (scheme !== null) {
      // Single-letter schemes are Windows drive letters, not URLs.
      if (scheme[1].length < 2) return '';
      pathname = scheme[3];
    } else if (/^[a-z][a-z0-9+.-]*:/iu.test(raw)) {
      // mailto:, data:, javascript: etc. have no path component.
      return '';
    } else {
      const slash = raw.indexOf('/');
      if (slash > 0) {
        const prefix = raw.slice(0, slash);
        const looksLikeHost = /^[a-z0-9.[\]:_-]+$/iu.test(prefix)
          && (/[.:]/u.test(prefix) || prefix.toLowerCase() === 'localhost');
        pathname = looksLikeHost ? raw.slice(slash) : `/${raw}`;
      } else {
        pathname = `/${raw}`;
      }
    }
  }

  pathname = pathname.split('?')[0].split('#')[0];
  pathname = pathname.replace(/;jsessionid=[^/]*/iu, '');
  pathname = pathname.replace(/\/\.\//gu, '/').replace(/\/\.$/u, '/');
  if (pathname.length === 0) return '';
  if (!pathname.startsWith('/')) pathname = `/${pathname}`;
  if (pathname.includes('..') || pathname.includes('$') || /[{}]/u.test(pathname)) return '';
  if (/[\s"'<>\\]/u.test(pathname)) return '';

  while (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1);
  if (pathname.length > MAX_PATH) return '';
  return pathname.toLowerCase();
}

/**
 * Stable key for one coverage cell.
 *
 * Throws for an unknown bug class (a programming error); returns '' when the
 * path is empty or cannot be normalized (data noise that the caller filters).
 */
export function coverageKey(path, bugClass) {
  const cleanClass = normalizeBugClass(bugClass);
  if (cleanClass.length === 0) invalid(`coverage bugClass must be one of ${BUG_CLASSES.join(', ')}`);
  const cleanPath = normalizeInterfacePath(path);
  if (cleanPath.length === 0) return '';
  return `${cleanPath}#${cleanClass}`;
}

/** Browser/static noise that must not become an interface cell. */
function isBoardPath(path) {
  if (path.length === 0) return false;
  if (path !== '/' && path.split('/').length - 1 > 8) return false;
  return !STATIC_ASSET_RE.test(path);
}

function normalizeRole(value) {
  if (value === undefined || value === null) return DEFAULT_ROLE;
  if (typeof value !== 'string') invalid('role must be a string');
  const text = value.trim().slice(0, 80);
  return text.length > 0 ? text : DEFAULT_ROLE;
}

function normalizeLimit(value, fallback, max) {
  if (value === undefined || value === null) return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0) invalid(`limit must be a non-negative integer, got ${JSON.stringify(value)}`);
  return Math.min(number, max);
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

function normalizeNote(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') invalid('note must be a string');
  const text = value.trim();
  return text.length > 0 ? text.slice(0, MAX_NOTE) : null;
}

function normalizeFindingId(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') invalid('findingId must be a string');
  const text = value.trim();
  if (text.length === 0) return null;
  if (text.length > MAX_ID) invalid('findingId is too long');
  return text;
}

/**
 * Seed the open board from one path or a list of paths.
 *
 * `limit` caps the number of unique interface paths (not cells), so a request
 * always yields complete path rows. The result is sorted by path; static
 * assets are ignored and duplicates are removed case-insensitively.
 *
 * @param {string|string[]} paths
 * @param {{role?: string, limit?: number}} [options]
 * @returns {Array<{path:string,bugClass:string,status:string,role:string}>}
 */
export function seedCoverage(paths, options = {}) {
  if (options === null || options === undefined) options = {};
  if (!isPlainObject(options)) invalid('seedCoverage options must be an object');
  const role = normalizeRole(options.role);
  const limit = normalizeLimit(options.limit, DEFAULT_PATH_LIMIT, MAX_PATH_LIMIT);

  const list = Array.isArray(paths) ? paths : [paths];
  const unique = new Set();
  for (const entry of list) {
    const clean = normalizeInterfacePath(entry);
    if (clean.length === 0 || !isBoardPath(clean)) continue;
    unique.add(clean);
  }

  const selected = [...unique].sort().slice(0, limit);
  const cells = [];
  for (const path of selected) {
    for (const bugClass of BUG_CLASSES) {
      const duty = COVERAGE_DUTIES[bugClass];
      cells.push({
        key: coverageKey(path, bugClass),
        path,
        bugClass,
        status: 'open',
        role,
        dutyRole: duty?.role ?? '',
        duty: duty?.duty ?? '',
      });
    }
  }
  return cells;
}

/**
 * Validate one lifecycle note and return a fresh cell.
 *
 * The caller folds the returned cell into its own ledger; later cells with the
 * same key replace earlier ones. `seen` needs two distinct channels or one
 * evidence id. `refuted` needs a note that names the exact path and cites a
 * concrete observation (or carries evidence), because "全部404 / 面关闭 / 穷尽
 * / 无差异" alone is not a result. `reported` needs the finding id.
 *
 * @param {{path:string,bugClass?:string,kind?:string,status:string,role?:string,
 *          channels?:string[],evidenceIds?:string[],note?:string,findingId?:string}} input
 */
function namesOtherPath(note, path) {
  const wanted = String(path ?? '').toLowerCase();
  const found = String(note ?? '').toLowerCase().match(/\/[a-z0-9._~-]+(?:\/[a-z0-9._~-]+)*/gu) ?? [];
  if (found.length === 0) return false;
  return !found.some((item) => item === wanted || wanted.endsWith(item) || item.endsWith(wanted));
}

/**
 * A reported cell can name the finding in findingId or, when that field was
 * left in the note, by the recorded finding id or key.
 */
export function resolveReportedFinding(input, findings) {
  const given = normalizeFindingId(input?.findingId);
  if (given !== null) return given;
  if (String(input?.status ?? '').trim().toLowerCase() !== 'reported') return null;
  const note = String(input?.note ?? '');
  const list = Array.isArray(findings) ? findings : [];
  const hinted = list.find((node) => {
    const id = String(node?.id ?? '');
    const key = String(node?.key ?? '');
    return (id.length > 0 && note.includes(id)) || (key.length > 0 && note.includes(key));
  });
  if (hinted) return hinted.id ?? hinted.key;
  const path = normalizeInterfacePath(input?.path);
  const same = list.filter((node) => normalizeInterfacePath(node?.attrs?.path ?? '') === path);
  if (same.length === 1) return same[0].id ?? same[0].key;
  return null;
}

export function noteCoverage(input) {
  if (!isPlainObject(input)) invalid('coverage note must be an object with {path, bugClass, status}');
  const path = normalizeInterfacePath(input.path);
  if (path.length === 0) invalid('coverage note path is empty or cannot be normalized');
  if (!isBoardPath(path)) invalid(`coverage note path ${path} is a static asset or too deep to be an interface`);

  const bugClass = normalizeBugClass(input.bugClass ?? input.kind);
  if (bugClass.length === 0) invalid(`coverage bugClass must be one of ${BUG_CLASSES.join(', ')}`);

  const status = typeof input.status === 'string' ? input.status.trim().toLowerCase() : '';
  if (!COVERAGE_STATUSES.includes(status)) {
    invalid(`coverage status must be one of ${COVERAGE_STATUSES.join(', ')}, got ${JSON.stringify(input.status)}`);
  }

  let channels = channelList(input.channels);
  let evidenceIds = stringList(input.evidenceIds, 'evidenceIds', 50);
  let note = normalizeNote(input.note);
  let findingId = normalizeFindingId(input.findingId);
  const role = normalizeRole(input.role);

  if (status === 'seen' && channels.length < 2 && evidenceIds.length === 0) {
    invalid('seen coverage requires >=2 distinct channels or at least one evidenceId');
  }
  const dutyViolation = coverageDutyViolation(bugClass, note, status, {
    path,
    parameters: Array.isArray(input.parameters) ? input.parameters : [],
    contexts: Array.isArray(input.contexts) ? input.contexts : [],
    siblingNote: typeof input.siblingNote === 'string' ? input.siblingNote : '',
    parameterMap: isPlainObject(input.parameterMap) ? input.parameterMap : {},
    mode: input.mode,
    techniques: Array.isArray(input.techniques) ? input.techniques : undefined,
    ledgerThin: input.ledgerThin === true,
    unrecordedVersions: Array.isArray(input.unrecordedVersions) ? input.unrecordedVersions : [],
  });
  if (dutyViolation !== null) invalid(dutyViolation);

  if (status === 'refuted') {
    if (note === null) invalid('refuted coverage requires a specific note');
    if (namesOtherPath(note, path)) {
      invalid(`refuted coverage note must name the exact path ${path}`);
    }
    if (GENERIC_CLOSE_RE.test(note) && channels.length < 2 && evidenceIds.length === 0
      && !SPECIFIC_CONTRAST_RE.test(note)) {
      invalid('refuted coverage note is a generic close (全部404 / 面关闭 / 穷尽 / 无差异); attach >=2 channels or an evidenceId');
    }
    if (!SPECIFIC_OBSERVATION_RE.test(note) && channels.length < 2 && evidenceIds.length === 0) {
      invalid('refuted coverage note must cite a concrete observation (status code, timing/length delta, header/body marker, or payload result)');
    }
  }

  if (status === 'reported' && findingId === null) {
    invalid('reported coverage requires findingId');
  }

  if (status === 'open') {
    channels = [];
    evidenceIds = [];
    note = null;
    findingId = null;
  }

  return {
    key: coverageKey(path, bugClass),
    path,
    bugClass,
    status,
    role,
    channels,
    evidenceIds,
    note,
    findingId,
  };
}

function normalizedCell(value) {
  if (!isPlainObject(value)) return undefined;
  const source = isPlainObject(value.attrs) ? { ...value.attrs, ...value } : value;
  const path = normalizeInterfacePath(source.path);
  const bugClass = normalizeBugClass(source.bugClass ?? source.kind);
  const status = typeof source.status === 'string' ? source.status.trim().toLowerCase() : '';
  if (path.length === 0 || bugClass.length === 0 || !COVERAGE_STATUSES.includes(status)) return undefined;
  return { path, bugClass, status };
}

/** Fold cells by key; the last occurrence wins, so events replay cleanly. */
function foldCells(cells) {
  const folded = new Map();
  let invalidCells = 0;
  if (!Array.isArray(cells)) return { folded, invalidCells };
  for (const cell of cells) {
    const normalized = normalizedCell(cell);
    if (normalized === undefined) {
      invalidCells += 1;
      continue;
    }
    folded.set(coverageKey(normalized.path, normalized.bugClass), normalized);
  }
  return { folded, invalidCells };
}

/**
 * Aggregate a coverage ledger. Duplicate cells are folded (last wins) so an
 * `open` cell followed by a `seen` cell counts once, as seen.
 */
export function coverageSummary(cells) {
  const { folded, invalidCells } = foldCells(cells);
  const byStatus = Object.fromEntries(COVERAGE_STATUSES.map((status) => [status, 0]));
  const byBugClass = {};
  for (const bugClass of BUG_CLASSES) {
    byBugClass[bugClass] = { total: 0, open: 0, claimed: 0, seen: 0, refuted: 0, reported: 0 };
  }

  const paths = new Set();
  let open = 0;
  for (const cell of folded.values()) {
    paths.add(cell.path);
    byStatus[cell.status] += 1;
    byBugClass[cell.bugClass].total += 1;
    byBugClass[cell.bugClass][cell.status] += 1;
    if (cell.status === 'open') open += 1;
  }

  return {
    total: folded.size,
    paths: paths.size,
    open,
    claimed: byStatus.claimed,
    seen: byStatus.seen,
    refuted: byStatus.refuted,
    reported: byStatus.reported,
    unresolved: open + byStatus.claimed,
    complete: folded.size > 0 && open === 0 && byStatus.claimed === 0,
    invalid: invalidCells,
    byStatus,
    byBugClass,
  };
}

/**
 * Inspect the matrix for one path or for the whole ledger.
 *
 * With `{path}` the result is `{path, found, matrix:{class:status}, open:[class],
 * openKeys:[key]}`. Without a path it returns `{paths, matrix:{path:{class:status}},
 * open:[{path,bugClass}], openKeys:[key]}`. A class with no cell is `open`.
 */
export function checkCoverage(cells, options = {}) {
  if (options !== null && options !== undefined && !isPlainObject(options)) {
    invalid('checkCoverage options must be an object');
  }
  const wanted = normalizeInterfacePath(options?.path);
  const summary = coverageSummary(cells);
  const { folded, invalidCells } = foldCells(cells);

  if (wanted.length > 0) {
    const matrix = {};
    const open = [];
    const openClasses = [];
    const openKeys = [];
    let found = false;
    for (const bugClass of BUG_CLASSES) {
      const key = coverageKey(wanted, bugClass);
      const cell = folded.get(key);
      const status = cell?.status ?? 'open';
      if (cell !== undefined) found = true;
      matrix[bugClass] = status;
      if (status === 'open') {
        open.push({ path: wanted, bugClass });
        openClasses.push(bugClass);
        openKeys.push(key);
      }
    }
    return { path: wanted, found, matrix, open, openClasses, openKeys, invalid: invalidCells, summary };
  }

  const paths = [...new Set([...folded.values()].map((cell) => cell.path))].sort();
  const matrix = {};
  const open = [];
  const openKeys = [];
  for (const path of paths) {
    matrix[path] = {};
    for (const bugClass of BUG_CLASSES) {
      const key = coverageKey(path, bugClass);
      const cell = folded.get(key);
      const status = cell?.status ?? 'open';
      matrix[path][bugClass] = status;
      if (status === 'open') {
        open.push({ path, bugClass });
        openKeys.push(key);
      }
    }
  }
  return { path: null, paths, found: paths.length > 0, matrix, open, openKeys, invalid: invalidCells, summary };
}
