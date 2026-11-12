/**
 * Finding classification.
 *
 * CVSS is a severity score. Secondary verification success puts a real
 * vulnerability on the vulnerability page at any score, including
 * error-disclosure. Missing headers, certificates and fingerprints stay on
 * the findings page even after a secondary check. Reflected XSS is capped
 * at medium; stored XSS may stay high. Same interface and type share one key.
 */
import { fromInput } from './cvss31.js';

const VULNERABILITY_CLASS_RE = /xss|cross[- ]site\s*scripting|sqli|sql\s*injection|sql\s*注入|注入|rce|remote\s*code|command\s*injection|命令执行|代码执行|code\s*execution|deseriali[sz]ation|反序列化|xxe|ssti|template\s*injection|模板注入|path\s*traversal|directory\s*traversal|lfi|rfi|file\s*inclusion|文件包含|file\s*read|任意文件读取|ssrf|server[- ]side\s*request|csrf|cross[- ]site\s*request\s*forgery|open[-\s]*redirect|url[-\s]*redirect|auth(?:entication|orization)?\s*bypass|认证绕过|权限绕过|idor|越权|privilege\s*escalation|提权|cve-\d{4}-\d+|密码重置|race\s*condition|逻辑漏洞/iu;
const EXPOSURE_CLASS_RE = /missing\s*(?:security\s*)?header|security\s*header|header\s*缺失|technology\s*disclosure|version\s*disclosure|server\s*version|指纹|robots\.txt|directory\s*listing|目录遍历|directory\s*index|admin.*exposed|manager.*exposed|examples|docs|snoop|certificate|证书|tls|self[- ]signed|weak\s*cipher|弱加密|信息泄露|stack\s*trace|exception|错误堆栈|公开.*管理|exposed.*admin/iu;
/** Hardening and fingerprint signals are never vulnerabilities, even after a secondary check. */
const HARDENING_RE = /missing\s*(?:security\s*)?header|security[- ]headers?|header\s*缺失|缺少安全响应头|安全响应头|certificate|证书|robots\.txt|technology\s*disclosure|version\s*disclosure|server\s*version|技术栈指纹|指纹|fingerprint|directory\s*listing|目录列表|crossdomain|allow-access-from|permissive-crossdomain/iu;

const REFLECTED_XSS_CAP = 6.1;

/** "非存储型" names a reflected finding. Do not treat that negation as stored XSS. */
const STORED_XSS_RE = /(?<!非)(?<!不是)(?<!并非)(?<!not\s)(?<!non[- ]?)(?:stored\s*xss|persistent\s*xss|存储型|存储式)/iu;

const FAMILY_RULES = Object.freeze([
  ['xss-stored', STORED_XSS_RE],
  ['xss-reflected', /xss|cross[- ]site\s*scripting|跨站脚本|反射型|反射式/iu],
  ['sqli', /sqli|sql\s*injection|sql\s*注入/iu],
  ['cmd', /command\s*injection|命令执行|os\s*command/iu],
  ['code', /远程代码|代码执行|remote\s*code|rce|模板注入|ssti|deseriali/iu],
  ['file', /path\s*traversal|directory\s*traversal|文件包含|任意文件|file\s*read|lfi|rfi/iu],
  ['authz', /idor|越权|权限绕过|认证绕过|authorization|authz/iu],
  ['logic', /逻辑漏洞|race\s*condition|业务逻辑/iu],
  ['leak', /信息泄露|stack\s*trace|错误堆栈|报错/iu],
  ['nday', /cve-\d{4}-\d+|nday|已知漏洞/iu],
]);

const METRIC_ZH = Object.freeze({
  AV: { N: '攻击向量是网络（AV:N），不需要本地访问', A: '攻击向量是相邻网络（AV:A）', L: '攻击向量是本地（AV:L）', P: '攻击向量是物理接触（AV:P）' },
  AC: { L: '攻击复杂度低（AC:L）', H: '攻击复杂度高（AC:H）' },
  PR: { N: '不需要账号权限（PR:N）', L: '需要低权限（PR:L）', H: '需要高权限（PR:H）' },
  UI: { N: '不需要受害者配合（UI:N）', R: '需要受害者进行一次操作（UI:R）' },
  S: { U: '影响停在当前组件（S:U）', C: '影响超出当前组件（S:C）' },
  C: { H: '机密性影响高（C:H）', L: '机密性影响低（C:L）', N: '不影响机密性（C:N）' },
  I: { H: '完整性影响高（I:H）', L: '完整性影响低（I:L）', N: '不影响完整性（I:N）' },
  A: { H: '可用性影响高（A:H）', L: '可用性影响低（A:L）', N: '不影响可用性（A:N）' },
});

function severityFromScore(score) {
  if (!Number.isFinite(score)) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

function classText(attrs = {}) {
  return `${attrs?.template ?? ''} ${attrs?.category ?? ''} ${attrs?.title ?? ''} ${attrs?.label ?? ''} ${attrs?.cwe ?? ''}`;
}

/** Header, certificate and fingerprint rows are not vulnerabilities. */
export function isHardeningFinding(attrs = {}) {
  return HARDENING_RE.test(classText(attrs));
}

/**
 * Configuration exposure stays off the vulnerability score.
 * CVSS v3.1 itself is unchanged: Changed scope plus Low confidentiality is
 * what produces a Medium score from an unproven policy file.
 */
export function hardeningScoreRefusal(attrs, cvss) {
  if (!isHardeningFinding(attrs)) return null;
  if (cvss?.present !== true || cvss.ok !== true || cvss.rejected === true) return null;
  return '这是配置暴露，不按漏洞记 CVSS。计算器是 NVD CVSS 3.1；范围填成 Changed、机密性填成 Low 就会得到中危。没有证明读到数据时，不要填这组指标。';
}

const RED_ANCHOR = Object.freeze({ info: 0, low: 2.5, medium: 5.5, high: 7.5, critical: 9.5 });
const RED_EXECUTION_RE = /uid=\d+|whoami|命令执行成功|command executed|已证明以应用权限执行命令|validated foothold/iu;
const RED_RCE_CLAIM_RE = /\brce\b|remote\s*code|命令执行|代码执行|getshell/iu;
const RED_UNPROVEN_RE = /未打成|未证明|not proven|未复现|no command execution|version match only/iu;

/** Red-team exploitability, separate from the NVD score. */
export function redTeamJudgement(attrs = {}) {
  const text = `${classText(attrs)} ${attrs.evidence ?? ''} ${attrs.impact ?? ''} ${attrs.proof ?? ''} ${attrs.description ?? ''}`;
  if (isHardeningFinding(attrs)) {
    return { rating: 'info', score: RED_ANCHOR.info, rationale: '配置暴露或过时客户端策略，红队不能直接利用。' };
  }
  if (RED_EXECUTION_RE.test(text) && !RED_UNPROVEN_RE.test(text)) {
    return { rating: 'critical', score: RED_ANCHOR.critical, rationale: '已经打出命令执行或立足点。' };
  }
  if (RED_RCE_CLAIM_RE.test(text)) {
    return { rating: 'medium', score: RED_ANCHOR.medium, rationale: '声称能执行命令，但没有打成的证据。' };
  }
  if (STORED_XSS_RE.test(text)) {
    return { rating: 'high', score: RED_ANCHOR.high, rationale: '存储型脚本会在其他人正常访问时触发。' };
  }
  if (/xss|跨站脚本|反射型|反射式/iu.test(text)) {
    return { rating: 'medium', score: RED_ANCHOR.medium, rationale: '需要受害者打开链接。' };
  }
  if (/sqli|sql\s*注入|任意文件|file\s*read|文件读取/iu.test(text)) {
    return { rating: 'high', score: RED_ANCHOR.high, rationale: '能读到数据或文件。' };
  }
  if (/越权|认证绕过|权限绕过|auth(?:entication|orization)?\s*bypass/iu.test(text)) {
    return { rating: 'high', score: RED_ANCHOR.high, rationale: '能绕过认证或越权。' };
  }
  if (/stack|堆栈|报错|信息泄露|\bleak\b/iu.test(text)) {
    return { rating: 'low', score: RED_ANCHOR.low, rationale: '只看到报错或信息，还不能直接控制目标。' };
  }
  return { rating: 'low', score: RED_ANCHOR.low, rationale: '没有打出可利用的影响。' };
}

function bandForScore(score) {
  if (!(score > 0)) return 'info';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Displayed result: red team 70%, CVSS base score 30%.
 * CVSS stays stored unchanged. Without a CVSS score the result is the red-team judgement.
 */
export function blendOperational(attrs = {}) {
  const red = redTeamJudgement(attrs);
  const cvssScore = readScore(attrs).score;
  const score = cvssScore === null
    ? red.score
    : Math.round((red.score * 0.7 + cvssScore * 0.3) * 10) / 10;
  return {
    red,
    score,
    severity: bandForScore(score),
    cvssScore,
    weights: { red: 0.7, cvss: 0.3 },
  };
}

/** Stored XSS is explicit. Every other XSS is treated as reflected. */
export function xssPlacement(attrs = {}) {
  const text = classText(attrs);
  if (!/xss|cross[- ]site\s*scripting|跨站脚本|反射型|反射式|存储型|存储式/iu.test(text)) return null;
  if (STORED_XSS_RE.test(text)) return 'stored';
  return 'reflected';
}

function readScore(attrs = {}) {
  const nested = attrs?.cvss && typeof attrs.cvss === 'object' ? attrs.cvss : {};
  const vector = typeof attrs?.cvssVector === 'string'
    ? attrs.cvssVector
    : (typeof nested.vector === 'string' ? nested.vector : '');
  const rawScore = attrs?.cvssScore ?? nested.baseScore ?? attrs?.cvss31?.baseScore;
  let score = Number(rawScore);
  if (!Number.isFinite(score) || score < 0 || score > 10) {
    if (vector.length > 0) {
      const computed = fromInput({ cvssVector: vector });
      if (computed?.ok === true && Number.isFinite(computed.score)) score = computed.score;
    }
  }
  return {
    score: Number.isFinite(score) && score >= 0 && score <= 10 ? score : null,
    vector,
    nested,
  };
}

/** A finished rating is a real CVSS base score, not a missing value displayed as 0. */
export function hasCvssScore(attrs = {}) {
  const read = readScore(attrs);
  if (read.score === null) return false;
  if (typeof read.vector === 'string' && read.vector.startsWith('CVSS:')) return true;
  if (attrs?.ratingSource === 'nvd-cvss31') return true;
  const severity = String(attrs?.cvssSeverity ?? read.nested?.baseSeverity ?? '').toLowerCase();
  return ['none', 'low', 'medium', 'high', 'critical', 'info'].includes(severity);
}

/**
 * Reflected XSS needs the victim to open a crafted link, so it stays at most
 * medium. Stored XSS may remain high.
 */
export function reflectedXssAdjustment(attrs = {}) {
  const placement = xssPlacement(attrs);
  const current = readScore(attrs);
  if (placement !== 'reflected' || current.score === null || current.score < 7) {
    return { attrs, capped: false, placement, originalScore: current.score };
  }
  const next = {
    ...attrs,
    cvssScore: REFLECTED_XSS_CAP,
    cvssSeverity: 'MEDIUM',
    cvssRating: 'medium',
    severity: attrs.severity === 'critical' || attrs.severity === 'high' ? 'medium' : (attrs.severity ?? 'medium'),
    cvssCap: 'reflected-xss',
    cvssCapFrom: current.score,
  };
  if (current.nested && typeof current.nested === 'object' && Object.keys(current.nested).length > 0) {
    next.cvss = { ...current.nested, baseScore: REFLECTED_XSS_CAP, baseSeverity: 'MEDIUM' };
  }
  return { attrs: next, capped: true, placement, originalScore: current.score };
}

/** One row per host + interface + vulnerability type. */
export function findingInterfacePath(attrs = {}) {
  const blobs = [attrs.interfacePath, attrs.endpoint, attrs.path, attrs.url, attrs.proofUrl, attrs.title, attrs.label];
  for (const blob of blobs) {
    const text = String(blob ?? '').trim();
    if (text.length === 0) continue;
    let path = text;
    try {
      if (/^https?:\/\//iu.test(text)) path = new URL(text).pathname;
    } catch {
      path = text;
    }
    const match = /(\/[a-z0-9._~!$&'()*+,;=:@%-]+(?:\/[a-z0-9._~!$&'()*+,;=:@%-]+)*)/iu.exec(path);
    if (match !== null) {
      const normalized = match[1].replace(/\/+$/u, '');
      return normalized.length > 0 ? normalized : '/';
    }
  }
  return '/';
}

export function findingFamily(attrs = {}) {
  if (isHardeningFinding(attrs)) {
    const text = classText(attrs);
    if (/header|响应头/iu.test(text)) return 'hardening-headers';
    if (/cert|证书|tls/iu.test(text)) return 'hardening-tls';
    return 'hardening';
  }
  const text = classText(attrs);
  for (const [family, pattern] of FAMILY_RULES) {
    if (pattern.test(text)) return family;
  }
  const template = String(attrs.template ?? 'finding').toLowerCase().replace(/[^a-z0-9]+/gu, '-').replace(/^-|-$/gu, '');
  return template.length > 0 ? template.slice(0, 48) : 'finding';
}

/**
 * Harm band for identity. The same interface and type merge only inside one band.
 * Command execution and a validated foothold stay on their own row so a later,
 * higher-impact result is not folded into the original finding.
 */
export function harmRank(attrs = {}) {
  const text = classText(attrs);
  if (/getshell|remote\s*code|代码执行|命令执行|command\s*execution|反序列化|webshell|\brce\b|validated foothold|foothold/iu.test(text)) return 4;
  const classified = classifyFindingCvss(attrs);
  if (classified.severity === 'critical') return 4;
  if (classified.severity === 'high') return 3;
  if (classified.severity === 'medium') return 2;
  if (classified.severity === 'low') return 1;
  return 0;
}

export function harmBand(attrs = {}) {
  return ['info', 'low', 'medium', 'high', 'exec'][harmRank(attrs)] ?? 'info';
}

export function findingMergeKey(engagement, attrs = {}) {
  const subject = String(attrs.subjectKey ?? attrs.subjectId ?? attrs.host ?? 'unknown')
    .replace(/^https?:\/\//iu, '')
    .split('/')[0]
    .toLowerCase();
  return `${engagement}/${subject}${findingInterfacePath(attrs)}/${findingFamily(attrs)}/${harmBand(attrs)}`;
}

/** Paths that already have this bug class, so the frontier does not schedule them again. */
export function pathsWithFinding(nodes, bugClass) {
  const wanted = bugClass === 'xss' ? ['xss-reflected', 'xss-stored'] : [bugClass];
  const paths = new Set();
  for (const node of Array.isArray(nodes) ? nodes : []) {
    if (node?.kind !== 'finding') continue;
    if (String(node.attrs?.secondaryVerdict ?? '').toLowerCase() === 'refuted') continue;
    const family = findingFamily(node.attrs ?? {});
    if (!wanted.includes(family) && family !== bugClass) continue;
    paths.add(findingInterfacePath(node.attrs ?? {}));
  }
  return paths;
}

function metricSentence(vector) {
  const parsed = fromInput({ cvssVector: vector });
  if (parsed?.ok !== true || parsed.metrics === undefined) return [];
  return ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
    .map((key) => METRIC_ZH[key]?.[parsed.metrics[key]])
    .filter((line) => typeof line === 'string');
}

/** Plain-language reason for the displayed score. */
export function explainCvss(attrs = {}, classified = {}) {
  const placement = classified.placement ?? xssPlacement(attrs);
  const lines = [];
  const sentences = metricSentence(classified.vector || attrs.cvssVector || attrs.cvss?.vector || '');
  if (sentences.length > 0) {
    lines.push(`分数来自 CVSS v3.1 的八个基础指标：${sentences.join('；')}。`);
  } else {
    lines.push('这条记录没有 CVSS v3.1 向量，不能按八个指标解释分数。');
  }
  if (placement === 'reflected') {
    lines.push('这是反射型 XSS：受害者必须自己打开构造后的链接，按用户交互（UI:R）最高到中危。存储型 XSS 可以在其他用户正常访问时触发，才可以评为高危。');
    if (classified.capped === true && Number.isFinite(classified.originalScore)) {
      lines.push(`记录里的分数是 ${Number(classified.originalScore).toFixed(1)}，已按反射型上限调整为 ${Number(classified.score).toFixed(1)}（中危）。`);
    }
  } else if (placement === 'stored') {
    lines.push('这是存储型 XSS：内容留在服务端，其他用户访问时即可触发，因此可以评为高危。');
  }
  if (Number.isFinite(classified.score)) {
    lines.push(`显示分数 ${Number(classified.score).toFixed(1)}（${classified.severity ?? 'unscored'}）。`);
  }
  return lines.join('');
}

/** A real vulnerability class survives even at CVSS Medium. */
export function isVulnerabilityClass(attrs = {}) {
  const text = classText(attrs);
  if (EXPOSURE_CLASS_RE.test(text) && !VULNERABILITY_CLASS_RE.test(text)) return false;
  return VULNERABILITY_CLASS_RE.test(text);
}

/** Extract CVSS fields without trusting the agent-assigned severity label. */
export function classifyFindingCvss(attrs = {}) {
  const adjusted = reflectedXssAdjustment(attrs);
  const source = adjusted.attrs;
  const nested = source?.cvss && typeof source.cvss === 'object' ? source.cvss : {};
  const read = readScore(source);
  const score = read.score;
  const rawSeverity = String(source?.cvssSeverity ?? nested.baseSeverity ?? source?.cvss31?.baseSeverity ?? '').toLowerCase();
  const severity = Number.isFinite(score) && score >= 0 && score <= 10
    ? severityFromScore(score)
    : (['critical', 'high', 'medium', 'low', 'info'].includes(rawSeverity) ? rawSeverity : 'unscored');
  const exposureClass = EXPOSURE_CLASS_RE.test(classText(attrs)) && !VULNERABILITY_CLASS_RE.test(classText(attrs));
  const vulnerability = isHardeningFinding(attrs) === false && exposureClass === false && (isVulnerabilityClass(attrs)
    || (Number.isFinite(score) && score >= 7));
  return {
    score,
    severity,
    vulnerability,
    highCritical: severity === 'critical' || severity === 'high',
    capped: adjusted.capped,
    originalScore: adjusted.originalScore,
    placement: adjusted.placement,
    vector: read.vector,
  };
}

/** Convenience predicate for graph/report summaries. */
export function isVulnerabilityNode(node) {
  return node?.kind === 'finding' && classifyFindingCvss(node.attrs ?? {}).vulnerability;
}

const VERSION_SKIP = new Set(['http', 'https', 'html', 'utf', 'iso', 'rfc', 'cve', 'jquery', 'bootstrap', 'cloudflare', 'javascript', 'css', 'json', 'xml', 'mozilla', 'chrome', 'safari', 'applewebkit', 'gecko', 'windows', 'linux']);

const HEADER_VERSION_RE = /\b([A-Za-z][A-Za-z0-9._-]{2,24})\/(\d+\.\d+(?:\.\d+){0,2})\b/gu;

/** Product versions already written on Server or X-Powered-By. */
export function headerProductVersions(headers = {}) {
  const found = [];
  const seen = new Set();
  for (const name of ['server', 'x-powered-by']) {
    const value = headers?.[name];
    const text = Array.isArray(value) ? value.join(' ') : String(value ?? '');
    HEADER_VERSION_RE.lastIndex = 0;
    let match;
    while ((match = HEADER_VERSION_RE.exec(text)) !== null) {
      const product = match[1];
      const version = match[2];
      if (VERSION_SKIP.has(product.toLowerCase())) continue;
      const label = `${product} ${version}`;
      if (seen.has(label.toLowerCase())) continue;
      seen.add(label.toLowerCase());
      found.push({ product, version, label });
      if (found.length >= 6) return found;
    }
  }
  return found;
}

/**
 * Product versions named on an error page that are not stored as tech nodes.
 * Header-only findings are skipped. The returned labels are safe to show.
 */
export function unrecordedProductVersions(nodes) {
  const list = Array.isArray(nodes) ? nodes : [];
  const known = new Set();
  for (const node of list) {
    if (node?.kind !== 'tech' || node.status === 'merged') continue;
    const version = String(node.attrs?.version ?? '').trim();
    if (version.length > 0) known.add(version);
    const blob = `${node.attrs?.product ?? ''} ${node.label ?? ''}`;
    for (const match of blob.matchAll(/(\d+\.\d+(?:\.\d+){0,2})/gu)) known.add(match[1]);
  }
  const missing = [];
  const seen = new Set();
  for (const node of list) {
    if (node?.kind === 'webapp' && node.status !== 'merged') {
      for (const item of headerProductVersions(node.attrs?.headers ?? {})) {
        if (known.has(item.version)) continue;
        if (seen.has(item.label)) continue;
        seen.add(item.label);
        missing.push(item.label);
        if (missing.length >= 6) return missing;
      }
    }
    if (node?.kind !== 'finding' || node.status === 'merged') continue;
    const text = `${node.attrs?.title ?? ''} ${node.attrs?.description ?? ''} ${node.label ?? ''}`.slice(0, 500);
    if (!/stack|trace|exception|错误|堆栈|status report|whitelabel|版本|version/iu.test(text)) continue;
    if (/missing\s*(?:security\s*)?header|security header|证书|certificate/iu.test(text) && !/stack|trace|exception|堆栈/iu.test(text)) continue;
    const re = /\b([A-Za-z][A-Za-z0-9._-]{2,24})[ /](\d+\.\d+(?:\.\d+){0,2})\b/gu;
    let match;
    while ((match = re.exec(text)) !== null) {
      const product = match[1];
      const version = match[2];
      if (VERSION_SKIP.has(product.toLowerCase())) continue;
      if (known.has(version)) continue;
      const label = `${product} ${version}`;
      if (seen.has(label)) continue;
      seen.add(label);
      missing.push(label);
      if (missing.length >= 6) return missing;
    }
  }
  return missing;
}

/** Independent verification accepted this finding and the rating is recorded. */
export function secondaryVerificationPassed(attrs = {}) {
  if (String(attrs?.secondaryVerdict ?? '').toLowerCase() === 'refuted') return false;
  if (attrs?.secondaryVerified === false) return false;
  const passed = attrs?.secondaryVerified === true || String(attrs?.secondaryVerdict ?? '').toLowerCase() === 'verified';
  return passed && hasCvssScore(attrs);
}

/**
 * Shown on the vulnerability page.
 * Secondary verification success is enough at any score, including configuration
 * and error-disclosure findings. A refuted verdict stays off the page.
 * Vulnerability-class findings that are not yet verified still appear.
 */
export function isIncludedVulnerabilityNode(node) {
  if (node?.kind !== 'finding') return false;
  const attrs = node.attrs ?? {};
  if (isHardeningFinding(attrs)) return false;
  if (String(attrs.secondaryVerdict ?? '').toLowerCase() === 'refuted' || attrs.secondaryVerified === false) return false;
  if (secondaryVerificationPassed(attrs)) return true;
  return classifyFindingCvss(attrs).vulnerability;
}

/** Backwards-compatible alias: included means not refuted by secondary verification. */
export const isVerifiedVulnerabilityNode = isIncludedVulnerabilityNode;
