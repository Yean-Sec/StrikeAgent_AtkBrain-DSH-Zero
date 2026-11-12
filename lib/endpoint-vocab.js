/**
 * Endpoint vocabulary builder, ported from A-U `tools/endpoint_vocab.py`.
 *
 * Only words the target already emitted are reused: path segments, parameter
 * names, class names and file types from saved pages/scripts/errors. No
 * interface name is pre-seeded. Output is a candidate wordlist for coverage
 * seeding or a small dirsearch run, never authorization to probe.
 *
 * Pure and deterministic: same text in, same arrays out. No clock, filesystem,
 * network or imports.
 */

const PATH_RE = /(?<![A-Za-z0-9./])(\/[A-Za-z][A-Za-z0-9_-]*(?:\/[A-Za-z0-9_-]+){0,6}\.[A-Za-z]{2,8})/gu;
const PARAM_RE = /[?&]([A-Za-z][A-Za-z0-9_]{1,24})=/gu;
const NAME_ATTR_RE = /\b(?:name|id)\s*=\s*["']([A-Za-z][A-Za-z0-9_]{1,24})["']/giu;
const CLASS_RE = /\b([A-Z][A-Za-z0-9]{2,40}(?:Action|Controller|Servlet|Download|Resource))\b/gu;
const CAMEL_RE = /[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])/gu;
const WORD_RE = /\b([A-Za-z]{3,12})\b/gu;

const QUERY_NAME_RE = /[?&]([A-Za-z][A-Za-z0-9_]{1,32})=/gu;
const EL_NAME_RE = /\$\{([A-Za-z][A-Za-z0-9_]{1,32})\}/gu;
const FORM_NAME_RE = /\bname\s*=\s*["']([A-Za-z][A-Za-z0-9_]{1,32})["']/giu;
const PLACEHOLDER_RE = /\{([A-Za-z][A-Za-z0-9_]{1,32})\}/gu;
const EQ_LIST_RE = /=\s*([A-Za-z][A-Za-z0-9_]{1,40}(?:\s*[,，]\s*[A-Za-z][A-Za-z0-9_]{1,40}){1,24})/gu;

const ROUTE_EXT = new Set(['action', 'jsp', 'do', 'php', 'aspx', 'html', 'json', 'xml']);
const TYPE_EXT = new Set(['gif', 'png', 'jpg', 'jpeg', 'pdf', 'zip', 'bak', 'sql', 'txt', 'csv']);
const ROLE_WORDS = new Set(['file', 'download', 'export', 'upload', 'attach', 'resource']);

const STOP_WORDS = new Set([
  'html', 'http', 'https', 'www', 'com', 'src', 'href', 'type', 'text', 'true', 'false',
  'null', 'this', 'var', 'let', 'const', 'function', 'return', 'document', 'window',
  'style', 'class', 'data', 'content', 'charset', 'ajax', 'jquery', 'bootstrap',
  'css', 'min', 'ver', 'img', 'div', 'span', 'head', 'body', 'meta', 'link', 'script',
  'title', 'width', 'height', 'left', 'right', 'index', 'default', 'static', 'assets',
  'images', 'image', 'public', 'common', 'main', 'home', 'page', 'item',
  'name', 'value', 'string', 'object', 'error', 'exception', 'java', 'lang', 'org',
  'springframework', 'apache', 'struts', 'action', 'controller', 'servlet', 'download',
]);

/** Parameter names that are framework/HTML noise, not target input names. */
const PARAM_NOISE = new Set([
  'html', 'http', 'https', 'www', 'com', 'src', 'href', 'true', 'false',
  'null', 'this', 'var', 'let', 'const', 'function', 'return', 'document',
  'window', 'style', 'class', 'charset', 'jquery', 'bootstrap', 'css',
  'min', 'ver', 'img', 'div', 'span', 'head', 'body', 'meta', 'link',
  'script', 'title', 'width', 'height', 'left', 'right', 'static',
  'assets', 'images', 'image', 'timeout', 'max', 'time', 'code', 'desc',
  'shift', 'echo', 'curl', 'header', 'content', 'length', 'status',
  'output', 'input', 'none', 'text', 'data',
]);

const INPUT_LIMIT = 24;

function bump(object, key) {
  if (typeof key !== 'string' || key.length === 0) return;
  const current = Object.hasOwn(object, key) ? object[key] : 0;
  object[key] = current + 1;
}

/** Split a token into the lowercase stems that already appear in it. */
function stemsOf(token) {
  const raw = String(token ?? '').replace(/[^A-Za-z0-9_]/gu, '');
  if (raw.length === 0) return [];
  const parts = raw.split('_').filter((part) => part.length > 0);
  const source = parts.length > 0 ? parts : [raw];
  const out = [];
  for (const part of source) {
    const bits = part.match(CAMEL_RE) ?? [part];
    for (const bit of bits) {
      const word = bit.toLowerCase();
      if (word.length >= 3 && word.length <= 12 && /^[a-z]+$/u.test(word) && !STOP_WORDS.has(word)) {
        out.push(word);
      }
    }
    const whole = part.toLowerCase();
    if (whole.length >= 3 && whole.length <= 16 && /^[a-z]+$/u.test(whole)
      && !STOP_WORDS.has(whole) && !out.includes(whole)) {
      out.push(whole);
    }
  }
  return out;
}

/**
 * Harvest the target's own vocabulary.
 *
 * @param {string} text
 * @returns {{stems:Record<string,number>,exts:Record<string,number>,known:string[]}}
 *   `stems`/`exts` are insertion-ordered counts; `known` is the sorted list of
 *   relative paths already emitted by the target.
 */
export function harvest(text) {
  const input = typeof text === 'string' ? text : '';
  const stems = {};
  const exts = {};
  const known = new Set();
  if (input.length === 0) return { stems, exts, known: [] };

  for (const match of input.matchAll(PATH_RE)) {
    const raw = match[1] ?? '';
    const path = raw.split('?')[0].split('#')[0].replace(/^\/+/u, '');
    if (path.length === 0 || path.includes('..')) continue;
    known.add(path);
    const ext = path.includes('.') ? path.split('.').pop().toLowerCase() : '';
    if (ROUTE_EXT.has(ext)) bump(exts, ext);
    else if (TYPE_EXT.has(ext)) bump(stems, ext);
    for (const segment of path.split('/')) {
      const stem = segment.includes('.') ? segment.slice(0, segment.lastIndexOf('.')) : segment;
      for (const word of stemsOf(stem)) bump(stems, word);
    }
  }

  for (const pattern of [PARAM_RE, NAME_ATTR_RE]) {
    for (const match of input.matchAll(pattern)) {
      for (const word of stemsOf(match[1])) bump(stems, word);
    }
  }
  for (const match of input.matchAll(CLASS_RE)) {
    for (const word of stemsOf(match[1])) bump(stems, word);
  }
  for (const match of input.matchAll(WORD_RE)) {
    const word = match[1].toLowerCase();
    if (ROLE_WORDS.has(word)) bump(stems, word);
  }

  return { stems, exts, known: [...known].sort() };
}

function normalizeOptions(options, fallback, max) {
  let raw = options;
  if (typeof raw === 'number') raw = { limit: raw };
  if (raw === null || raw === undefined || typeof raw !== 'object') return fallback;
  const number = Number(raw.limit);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(1, Math.min(Math.floor(number), max));
}

function rankedWords(counts, limit) {
  // Stable sort preserves insertion order for equal counts, matching Python's
  // Counter.most_common tie behavior.
  return Object.entries(counts)
    .sort((left, right) => right[1] - left[1])
    .slice(0, limit)
    .map(([word]) => word);
}

/**
 * Synthesize candidate relative paths from the target's own vocabulary.
 *
 * With no observed route extension, only already-seen paths are returned;
 * nothing is invented from a bare type. Type stems and role words (file,
 * download, ...) combine into routes such as `giffile.action`, but only when
 * both the type and the role word actually appeared in the text.
 *
 * @param {string} text
 * @param {{limit?: number}|number} [options]
 * @returns {string[]}
 */
export function synthesize(text, options = {}) {
  const limit = normalizeOptions(options, 400, 5000);
  const { stems, exts, known } = harvest(text);
  const routeExts = rankedWords(exts, 4);
  const words = rankedWords(stems, 40);
  const out = [];
  const seen = new Set();

  const add = (value) => {
    const path = String(value ?? '').trim().replace(/^\/+/u, '');
    if (path.length === 0 || path.length > 80 || path.includes('..') || seen.has(path)) return;
    seen.add(path);
    out.push(path);
  };

  for (const path of known) {
    add(path);
    if (out.length >= Math.min(120, limit)) break;
  }

  for (const word of words) {
    for (const ext of routeExts) {
      add(`${word}.${ext}`);
      if (out.length >= limit) return out;
    }
  }

  const typeStems = Object.keys(stems).filter((stem) => TYPE_EXT.has(stem));
  const roles = [...ROLE_WORDS].filter((word) => Object.hasOwn(stems, word)).sort();
  for (const typeStem of typeStems) {
    for (const role of roles) {
      if (typeStem === role) continue;
      for (const combo of [typeStem + role, role + typeStem]) {
        for (const ext of routeExts.slice(0, 2)) {
          add(`${combo}.${ext}`);
          if (out.length >= limit) return out;
        }
      }
    }
  }

  const pairStems = [...new Set([...typeStems, ...words.slice(0, 24)])].slice(0, 28);
  for (let leftIndex = 0; leftIndex < pairStems.length; leftIndex += 1) {
    const left = pairStems[leftIndex];
    if (left.length < 3 || left.length > 8) continue;
    for (let rightIndex = leftIndex + 1; rightIndex < pairStems.length; rightIndex += 1) {
      const right = pairStems[rightIndex];
      if (right.length < 3 || right.length > 8) continue;
      if (left.length + right.length > 16) continue;
      for (const combo of [left + right, right + left]) {
        for (const ext of routeExts.slice(0, 2)) {
          add(`${combo}.${ext}`);
          if (out.length >= limit) return out;
        }
      }
    }
  }

  return out;
}

function keepParam(name) {
  const token = String(name ?? '').trim();
  if (token.length === 0 || PARAM_NOISE.has(token.toLowerCase())) return false;
  return /^[A-Za-z][A-Za-z0-9_]{1,40}$/u.test(token);
}

/**
 * Parameter names already sent as input by the target's pages/scripts/errors.
 * Original spelling is preserved; no name list is pre-seeded.
 *
 * @param {string} text
 * @param {{limit?: number}|number} [options]
 * @returns {string[]}
 */
export function parameterNames(text, options = {}) {
  const limit = normalizeOptions(options, INPUT_LIMIT, 200);
  const input = typeof text === 'string' ? text : '';
  const counts = new Map();
  const order = [];

  const add = (value) => {
    const name = String(value ?? '').trim();
    if (!keepParam(name)) return;
    if (!counts.has(name)) {
      order.push(name);
      counts.set(name, 0);
    }
    counts.set(name, counts.get(name) + 1);
  };

  if (input.length === 0) return [];
  for (const pattern of [QUERY_NAME_RE, FORM_NAME_RE, PLACEHOLDER_RE, EL_NAME_RE]) {
    for (const match of input.matchAll(pattern)) add(match[1]);
  }
  for (const match of input.matchAll(EQ_LIST_RE)) {
    for (const part of String(match[1] ?? '').split(/\s*[,，]\s*/u)) add(part);
  }

  const indexOf = new Map(order.map((name, index) => [name, index]));
  return [...counts.entries()]
    .sort((left, right) => (
      right[1] - left[1]
      || indexOf.get(left[0]) - indexOf.get(right[0])
    ))
    .slice(0, limit)
    .map(([name]) => name);
}

/**
 * Inventory concrete endpoints and output contexts already emitted by the
 * target's HTML/JS. Handles bare `.action` names, form actions, JS URL strings
 * and extensionless API routes; it does not assume a particular framework.
 *
 * @param {string} text
 * @param {{limit?: number}|number} [options]
 * @returns {{endpoints:string[], jsRoutes:string[], parameters:string[], contexts:string[], queryParams:Record<string,string[]>, contextMap:Record<string,string[]>}}
 */
export function endpointInventory(text, options = {}) {
  const limit = normalizeOptions(options, 200, 2000);
  const input = typeof text === 'string' ? text : '';
  const endpointRe = /(?:^|[^A-Za-z0-9_/.-])((?:\.\.?\/)?[A-Za-z][A-Za-z0-9_.!-]*(?:\/[A-Za-z0-9_.!-]+)*\.(?:action|do|jsp|php|aspx|xml))(?:\?([^"'\s<>]*))?/giu;
  const jsUrlRe = /(?:\b(?:url|action|href|src|endpoint|path|api)\s*[:=]\s*["'`]([^"'`\s<>]+)["'`]|\b(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["'`]([^"'`\s<>]+)["'`])/giu;
  const formActionRe = /<form\b[^>]*\baction\s*=\s*["']([^"']+)["']/giu;
  const endpoints = [];
  const jsRoutes = [];
  const seen = new Set();
  const queryParams = {};
  const staticAsset = /\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|mp4|webp)(?:\?|$)/iu;
  const add = (value, bucket = endpoints) => {
    let raw = String(value ?? '').trim();
    if (raw.length === 0 || raw.length > 160 || raw.includes('..')) return '';
    raw = raw.split('#')[0];
    if (raw.startsWith('//') || /^[a-z][a-z0-9+.-]*:/iu.test(raw)) return '';
    if (staticAsset.test(raw)) return '';
    const path = raw.split('?')[0].replace(/^\.?\//u, '');
    if (path.length === 0) return '';
    if (!seen.has(path)) {
      seen.add(path);
      bucket.push(path);
    }
    return path;
  };
  const addQuery = (path, rawQuery) => {
    if (path.length === 0 || rawQuery.length === 0) return;
    const names = [];
    for (const parameter of rawQuery.matchAll(/(?:^|&)([A-Za-z][A-Za-z0-9_]{1,40})=/gu)) names.push(parameter[1]);
    if (names.length > 0) queryParams[path] = [...new Set([...(queryParams[path] ?? []), ...names])];
  };
  if (input.length > 0) {
    for (const match of input.matchAll(endpointRe)) addQuery(add(match[1]), String(match[2] ?? ''));
    for (const match of input.matchAll(formActionRe)) add(match[1]);
    for (const match of input.matchAll(jsUrlRe)) {
      const value = String(match[1] ?? match[2] ?? '').trim();
      if (value.length === 0) continue;
      const path = add(value, jsRoutes);
      const queryIndex = value.indexOf('?');
      if (queryIndex >= 0) addQuery(path, value.slice(queryIndex + 1));
    }
  }
  const jsParameters = [];
  for (const match of input.matchAll(/\b(?:data|params|payload)\s*:\s*\{([\s\S]{0,1200}?)\}/giu)) {
    for (const parameter of String(match[1] ?? '').matchAll(/([A-Za-z][A-Za-z0-9_]{1,40})\s*:/gu)) {
      const name = parameter[1];
      if (!PARAM_NOISE.has(name.toLowerCase()) && !jsParameters.includes(name)) jsParameters.push(name);
    }
  }
  const contextMap = {};
  const rememberContext = (path, value) => {
    if (path.length === 0 || value.length === 0) return;
    const list = contextMap[path] ?? [];
    if (!list.includes(value)) list.push(value);
    contextMap[path] = list;
  };
  const contextsNear = (index) => {
    const window = input.slice(Math.max(0, index - 240), Math.min(input.length, index + 700));
    const found = [];
    if (/<input\b[^>]*\bvalue\s*=/iu.test(window)) found.push('hidden-input-value');
    if (/\bon(?:click|mouseover|mouseout|focus|load|error)\s*=/iu.test(window)) found.push('inline-event-handler');
    if (/\bhref\s*=/iu.test(window)) found.push('href-attribute');
    if (/<script\b/iu.test(window)) found.push('inline-script-or-dom-sink');
    return found;
  };
  if (input.length > 0) {
    for (const match of input.matchAll(/<form\b[^>]*\baction\s*=\s*["']([^"']+)["'][^>]*>([\s\S]{0,5000}?)<\/form>/giu)) {
      const path = add(match[1]);
      const names = [];
      for (const field of String(match[2] ?? '').matchAll(/\bname\s*=\s*["']([A-Za-z][A-Za-z0-9_]{1,40})["']/giu)) names.push(field[1]);
      if (names.length > 0) queryParams[path] = [...new Set([...(queryParams[path] ?? []), ...names])];
      for (const context of contextsNear(match.index ?? 0)) rememberContext(path, context);
    }
    for (const match of input.matchAll(/\burl\s*:\s*["']([^"']+)["'][\s\S]{0,500}?\bdata\s*:\s*\{([\s\S]{0,800}?)\}/giu)) {
      const path = add(match[1]);
      const names = [];
      for (const field of String(match[2] ?? '').matchAll(/([A-Za-z][A-Za-z0-9_]{1,40})\s*:/gu)) {
        if (!PARAM_NOISE.has(field[1].toLowerCase())) names.push(field[1]);
      }
      if (names.length > 0) queryParams[path] = [...new Set([...(queryParams[path] ?? []), ...names])];
    }
    for (const match of input.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/giu)) {
      const href = String(match[1] ?? '').trim();
      if (href.length === 0 || href.startsWith('#') || href.startsWith('?')) continue;
      if (href.startsWith('//') || /^[a-z][a-z0-9+.-]*:/iu.test(href)) continue;
      const pathOnly = href.split('#')[0].split('?')[0].replace(/\/+$/u, '');
      const depth = pathOnly.split('/').filter((part) => part.length > 0 && part !== '.').length;
      if (depth === 0 || depth > 6) continue;
      const path = add(pathOnly);
      const queryIndex = href.indexOf('?');
      if (queryIndex >= 0) addQuery(path, href.slice(queryIndex + 1).split('#')[0]);
      if (path.length > 0) rememberContext(path, 'href-attribute');
    }
  }
  const contexts = [];
  const addContext = (value) => { if (!contexts.includes(value)) contexts.push(value); };
  if (/<input\b[^>]*\bvalue\s*=/iu.test(input)) addContext('hidden-input-value');
  if (/\bon(?:click|mouseover|mouseout|focus|load|error)\s*=/iu.test(input)) addContext('inline-event-handler');
  if (/<a\b[^>]*\bhref\s*=|\bhref\s*=\s*["'][^"']*\$?\{|\bhref\s*=\s*["'][^"']*</iu.test(input)) addContext('href-attribute');
  if (/<script\b[^>]*>[\s\S]*?(?:\$\{|<%)/iu.test(input) || /\.(?:html|append|prepend|innerHTML)\s*\(/iu.test(input)) addContext('inline-script-or-dom-sink');
  if (/<form\b[^>]*\baction\s*=/iu.test(input)) addContext('form-action');
  if (/application\/json|JSON\.parse|responseType\s*[:=]\s*["']json/iu.test(input)) addContext('json-response');
  return {
    endpoints: [...new Set([...endpoints, ...jsRoutes])].slice(0, limit),
    jsRoutes: jsRoutes.slice(0, limit),
    parameters: [...new Set([...parameterNames(input, { limit: 120 }), ...jsParameters])].slice(0, 120),
    contexts,
    queryParams,
    contextMap,
  };
}

const LEDGER_STATIC_RE = /\.(?:css|js|mjs|map|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|webp|avif|mp4)$/iu;

/** Lower-case interface path used as the ledger key. Empty when it is not an interface. */
export function ledgerPath(value) {
  let raw = String(value ?? '').trim();
  if (raw.length === 0) return '';
  if (/^https?:\/\//iu.test(raw)) {
    try { raw = new URL(raw).pathname; } catch { return ''; }
  }
  raw = raw.split('?')[0].split('#')[0];
  if (raw.length === 0) return '';
  if (!raw.startsWith('/')) raw = `/${raw.replace(/^\.?\//u, '')}`;
  if (raw.includes('..')) return '';
  while (raw.length > 1 && raw.endsWith('/')) raw = raw.slice(0, -1);
  raw = raw.toLowerCase();
  if (LEDGER_STATIC_RE.test(raw)) return '';
  return raw;
}

/** One suffix set applied to every discovered file. Not a list of target paths. */
export const ARTIFACT_SUFFIXES = Object.freeze(['.bak', '.old', '.swp', '~']);

function lastSegment(path) {
  const key = ledgerPath(path);
  if (key.length <= 1) return '';
  return key.split('/').pop() ?? '';
}

/** A ledger path whose last segment names a file. */
export function isFilePath(path) {
  const segment = lastSegment(path);
  return segment.includes('.');
}

/** A ledger path whose last segment names a directory. The site root is not one. */
export function isDirectoryPath(path) {
  const key = ledgerPath(path);
  if (key.length <= 1) return false;
  return !lastSegment(path).includes('.');
}

/** Sibling artifact paths for files already on the ledger. */
export function artifactSiblingPaths(paths) {
  const out = [];
  const seen = new Set();
  for (const path of Array.isArray(paths) ? paths : []) {
    if (!isFilePath(path)) continue;
    const key = ledgerPath(path);
    for (const suffix of ARTIFACT_SUFFIXES) {
      const next = `${key}${suffix}`;
      if (seen.has(next)) continue;
      seen.add(next);
      out.push(next);
    }
  }
  return out;
}

/** Directory paths already on the ledger. */
export function directoryPaths(paths) {
  const out = [];
  const seen = new Set();
  for (const path of Array.isArray(paths) ? paths : []) {
    if (!isDirectoryPath(path)) continue;
    const key = ledgerPath(path);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(key);
  }
  return out;
}

/** Path of the operator's URL. Later modules are not this path. */
export function entryPathOf(attrs = {}) {
  return ledgerPath(attrs.entryPath || attrs.path || attrs.url || '');
}

/**
 * True when the ledger names a module besides the entry page.
 * The site root alone is not a second module.
 */
export function applicationExpanded(attrs = {}) {
  const entry = entryPathOf(attrs);
  const endpoints = Array.isArray(attrs.endpoints) ? attrs.endpoints : [];
  return endpoints.some((path) => {
    const key = ledgerPath(path);
    return key.length > 0 && key !== '/' && key !== entry;
  });
}

function mergeNames(map, path, names) {
  const key = ledgerPath(path);
  if (key.length === 0) return;
  const list = map[key] ?? [];
  for (const name of names) {
    const text = String(name ?? '').trim();
    if (text.length === 0 || list.some((entry) => entry.toLowerCase() === text.toLowerCase())) continue;
    list.push(text);
  }
  if (list.length > 0) map[key] = list.slice(0, 24);
}

/**
 * Paths, per-path parameters and per-path output contexts already emitted by
 * the target. The visible graph keeps one webapp per host; this ledger is the
 * full surface those nodes point at.
 *
 * @param {string} text
 */
export function surfaceLedger(text) {
  const inventory = endpointInventory(text, { limit: 800 });
  const parameterMap = {};
  const contextMap = {};
  const endpoints = [];
  const addEndpoint = (path) => {
    const key = ledgerPath(path);
    if (key.length === 0 || endpoints.includes(key)) return;
    endpoints.push(key);
  };
  for (const path of inventory.endpoints) addEndpoint(path);
  for (const [path, names] of Object.entries(inventory.queryParams)) mergeNames(parameterMap, path, names);
  for (const [path, names] of Object.entries(inventory.contextMap)) mergeNames(contextMap, path, names);
  const input = typeof text === 'string' ? text : '';
  for (const match of input.matchAll(/https?:\/\/[^\s'"`<>]+/giu)) {
    try {
      const url = new URL(match[0]);
      addEndpoint(url.pathname);
      mergeNames(parameterMap, url.pathname, [...url.searchParams.keys()]);
    } catch { /* ignore malformed URL */ }
  }
  const ranked = endpoints.slice().sort((left, right) => {
    const score = (path) => (/\.(?:action|do|jsp|php|aspx|xml)$/iu.test(path) ? 2 : path.endsWith('.html') ? 1 : 0);
    return score(right) - score(left);
  });
  return {
    endpoints: ranked.slice(0, 400),
    parameterMap,
    contextMap,
    parameters: inventory.parameters,
    contexts: inventory.contexts,
  };
}

const PAGE_TEXT_RE = /<(?:html|form|script|input|textarea|a|body|div)\b|<\/script>|function\s*\(|\$\.(?:ajax|get|post)|document\.|fetch\s*\(/iu;

/** True when the text is a page or script, not a bare URL or a path list. */
export function pageTextSupplied(text) {
  return PAGE_TEXT_RE.test(String(text ?? ''));
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function unionCapped(left, right, cap) {
  const out = [];
  const seen = new Set();
  for (const name of [...(Array.isArray(left) ? left : []), ...(Array.isArray(right) ? right : [])]) {
    const text = String(name ?? '').trim();
    const key = text.toLowerCase();
    if (text.length === 0 || seen.has(key)) continue;
    seen.add(key);
    out.push(text);
    if (out.length >= cap) break;
  }
  return out;
}

/**
 * A repeated path shape is a parameter even when the varying piece is a path
 * segment rather than a query string. Four or more paths that differ in one
 * position produce a `segment` parameter on each of those paths.
 */
export function familyParameters(endpoints) {
  const paths = [...new Set((Array.isArray(endpoints) ? endpoints : [])
    .map((item) => String(item ?? '').split('?')[0])
    .filter((path) => path.startsWith('/')))];
  const byLength = new Map();
  for (const path of paths) {
    const parts = path.split('/').filter(Boolean);
    if (parts.length < 2) continue;
    const bag = byLength.get(parts.length) ?? [];
    bag.push(parts);
    byLength.set(parts.length, bag);
  }
  const map = {};
  for (const groups of byLength.values()) {
    if (groups.length < 4) continue;
    const width = groups[0].length;
    for (let slot = 0; slot < width; slot += 1) {
      const buckets = new Map();
      for (const parts of groups) {
        const key = parts.map((part, index) => (index === slot ? '{}' : part)).join('/');
        const bag = buckets.get(key) ?? [];
        bag.push(parts);
        buckets.set(key, bag);
      }
      for (const bag of buckets.values()) {
        if (bag.length < 4) continue;
        const values = new Set(bag.map((parts) => parts[slot]));
        if (values.size < 3) continue;
        for (const parts of bag) map[`/${parts.join('/')}`] = ['segment'];
      }
    }
  }
  return map;
}

/** Many paths and almost no parameters or output contexts means the ledger is unfinished. */
export function ledgerIsThin(attrs = {}) {
  const endpoints = Array.isArray(attrs.endpoints) ? attrs.endpoints : [];
  if (endpoints.length < 12) return false;
  const families = familyParameters(endpoints);
  const map = attrs.parameterMap && typeof attrs.parameterMap === 'object' && !Array.isArray(attrs.parameterMap) ? attrs.parameterMap : {};
  const contextMap = attrs.contextMap && typeof attrs.contextMap === 'object' && !Array.isArray(attrs.contextMap) ? attrs.contextMap : {};
  let named = 0;
  for (const key of new Set([...Object.keys(map), ...Object.keys(families)])) {
    const names = [...(Array.isArray(map[key]) ? map[key] : []), ...(families[key] ?? [])];
    if (names.length > 0) named += 1;
  }
  return named < 3 && Object.keys(contextMap).length < 3 && (!Array.isArray(attrs.contexts) || attrs.contexts.length === 0);
}

/**
 * Merge a fresh ledger into the attrs already stored on a webapp.
 * One entry page does not inventory the application. A second module path does.
 */
export function mergeLedgerAttrs(existing = {}, text, { inventoried = false } = {}) {
  const ledger = surfaceLedger(typeof text === 'string' ? text : '');
  const parameterMap = plainObject(existing.parameterMap) ? { ...existing.parameterMap } : {};
  for (const [path, names] of Object.entries(ledger.parameterMap)) {
    parameterMap[path] = unionCapped(parameterMap[path], names, 24);
  }
  const contextMap = plainObject(existing.contextMap) ? { ...existing.contextMap } : {};
  for (const [path, names] of Object.entries(ledger.contextMap)) {
    contextMap[path] = unionCapped(contextMap[path], names, 12);
  }
  const endpoints = unionCapped(existing.endpoints, ledger.endpoints, 400);
  const families = familyParameters(endpoints);
  for (const [path, listed] of Object.entries(families)) {
    parameterMap[path] = unionCapped(parameterMap[path], listed, 24);
  }
  const entryPath = entryPathOf(existing) || ledgerPath(existing.path || existing.url || '');
  const expanded = applicationExpanded({ ...existing, endpoints, entryPath });
  const page = inventoried === true || pageTextSupplied(text);
  const already = existing.surfaceInventoried === true;
  return {
    ...(entryPath.length > 0 ? { entryPath } : {}),
    endpoints,
    parameterMap,
    contextMap,
    parameters: unionCapped(existing.parameters, [...ledger.parameters, ...(Object.keys(families).length > 0 ? ['segment'] : [])], 80),
    contexts: unionCapped(existing.contexts, ledger.contexts, 20),
    surfaceInventoried: already || (page && expanded),
  };
}
