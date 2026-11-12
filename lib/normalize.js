/**
 * Asset normalization and document parsing for AtkBrain ingestion.
 *
 * Everything here is pure and deterministic: no DNS, no network, no filesystem
 * access. The module turns messy recon text (TXT/CSV/TSV/JSON/JSONL/Markdown,
 * or text extracted from Office documents) into canonical asset records:
 *
 *   domain  -> `example.com` (registrable apex) or `*.example.com` (wildcard)
 *   host    -> `www.example.com`, `web01`, ...
 *   ip      -> canonical IPv4/IPv6 literal
 *   cidr    -> canonical network/prefix (host bits cleared)
 *   url     -> canonical absolute URL, fragment dropped, default port elided
 *
 * Quarantine rules are intentionally conservative: an input that looks like an
 * address but is malformed (for example an IPv4 address with leading zeros) is
 * reported through `quarantined` plus `{ ok:false, reason, raw, quarantine:true }`
 * instead of being silently reinterpreted as a hostname.
 *
 * Secrets never enter output attributes. URL userinfo is reduced to a
 * `credentialHint` that records only presence, username length and whether a
 * password existed. Secret-like object keys (password/token/cookie/...) are
 * stripped recursively before attributes are returned.
 */
import { domainToASCII } from 'node:url';

import { parseCidr, parseIp } from './cidr.js';
import { FINDING_STATUSES, SECRET_KEY_PATTERN, SEVERITIES, VERIFICATION_LEVELS } from './constants.js';
import {
  InputError,
  byteLength,
  invalid,
  isPlainObject,
  sha256Hex,
  stripSecrets,
  truncate,
  uniqueStrings,
} from './util.js';

/** Asset kinds emitted by `normalizeAsset`. */
export const ASSET_KINDS = Object.freeze(['domain', 'host', 'ip', 'cidr', 'url']);

/** Document formats understood by `parseAssetDocument`. */
export const DOCUMENT_FORMATS = Object.freeze(['txt', 'csv', 'tsv', 'json', 'jsonl', 'markdown']);

/** Observation kinds accepted by `parseObservationsJsonl`. */
export const OBSERVATION_KINDS = Object.freeze(['service', 'http', 'finding', 'dns', 'host']);

const MAX_TOKEN_LENGTH = 2048;
const MAX_DOCUMENT_BYTES = 32 * 1024 * 1024;
const MAX_OBSERVATION_BYTES = 16 * 1024 * 1024;
const MAX_CANDIDATES = 50000;
const MAX_QUARANTINED = 200;
const MAX_WARNINGS = 100;
const MAX_ATTRIBUTE_KEYS = 80;
const MAX_ARRAY_ITEMS = 100;

const INVISIBLE_RE = /[\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/gu;
const UNICODE_SPACE_RE = /[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/gu;
const DOT_VARIANT_RE = /[\u2024\u3002\uFE52\uFF0E\uFF61]/gu;

const URL_SCHEMES = new Set(['http', 'https', 'ws', 'wss']);

/**
 * Common multi-label public suffixes used for apex detection. This is a
 * pragmatic built-in list, not a Public Suffix List replacement: when the last
 * two labels are not a known suffix the registrable domain is assumed to be the
 * last two labels.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk', 'sch.uk',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn', 'cn.com',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au', 'asn.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'ad.jp', 'ed.jp', 'gr.jp', 'lg.jp',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'geek.nz', 'school.nz',
  'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr', 're.kr', 'pe.kr',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'firm.in', 'gen.in', 'ind.in', 'res.in',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'art.br', 'blog.br',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx', 'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
  'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk', 'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw',
  'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za', 'co.il', 'net.il', 'org.il', 'gov.il', 'ac.il',
  'com.co', 'net.co', 'org.co', 'gov.co', 'edu.co', 'com.pe', 'net.pe', 'org.pe', 'gob.pe', 'edu.pe',
  'com.ve', 'com.ec', 'com.uy', 'com.bo', 'com.py', 'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph', 'com.pk', 'net.pk', 'org.pk', 'gov.pk', 'edu.pk',
  'com.eg', 'com.sa', 'com.ae', 'com.qa', 'com.kw', 'com.om', 'com.bh',
  'co.id', 'or.id', 'ac.id', 'go.id', 'web.id', 'co.th', 'or.th', 'ac.th', 'go.th', 'in.th',
  'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn', 'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua',
  'com.pl', 'net.pl', 'org.pl', 'gov.pl', 'edu.pl', 'com.ru', 'net.ru', 'org.ru', 'msk.ru', 'spb.ru',
  'co.at', 'or.at', 'ac.at', 'gv.at', 'com.es', 'nom.es', 'org.es', 'gob.es', 'edu.es',
  'github.io', 'gitlab.io', 'herokuapp.com', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev',
  'cloudfront.net', 'azurewebsites.net', 'appspot.com', 'firebaseapp.com', 'web.app', 'blogspot.com',
  's3.amazonaws.com', 'elasticbeanstalk.com', 'herokudns.com',
]);

/**
 * File-extension labels. In strict mode (generic JSON strings, CSV cells
 * without a header) a hostname whose TLD is a common file extension is treated
 * as a filename, not an asset.
 */
const FILE_EXTENSION_LABELS = new Set([
  'txt', 'text', 'csv', 'tsv', 'json', 'jsonl', 'ndjson', 'md', 'markdown', 'doc', 'docx', 'xls',
  'xlsx', 'ppt', 'pptx', 'pdf', 'csv', 'js', 'mjs', 'ts', 'html', 'htm', 'xml', 'yml', 'yaml',
  'log', 'zip', 'gz', 'tar', '7z', 'rar', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'exe', 'dll',
  'so', 'bin', 'cfg', 'conf', 'ini', 'bak', 'tmp', 'sql', 'sh', 'py', 'go', 'rs', 'java', 'class',
  'jar', 'war', 'apk', 'iso', 'img', 'mp3', 'mp4', 'mov', 'bmp', 'webp', 'db', 'sqlite', 'lock',
]);

/** Header/JSON field names that identify a column of assets. */
const ASSET_FIELD_ROLES = new Map([
  ['host', { role: 'asset', kindHint: 'host' }],
  ['hosts', { role: 'asset', kindHint: 'host' }],
  ['hostname', { role: 'asset', kindHint: 'host' }],
  ['hostnames', { role: 'asset', kindHint: 'host' }],
  ['fqdn', { role: 'asset', kindHint: 'host' }],
  ['domain', { role: 'asset', kindHint: 'domain' }],
  ['domains', { role: 'asset', kindHint: 'domain' }],
  ['subdomain', { role: 'asset', kindHint: 'domain' }],
  ['subdomains', { role: 'asset', kindHint: 'domain' }],
  ['ip', { role: 'asset', kindHint: 'ip' }],
  ['ips', { role: 'asset', kindHint: 'ip' }],
  ['ipv4', { role: 'asset', kindHint: 'ip' }],
  ['ipv6', { role: 'asset', kindHint: 'ip' }],
  ['addr', { role: 'asset', kindHint: 'ip' }],
  ['address', { role: 'asset', kindHint: 'ip' }],
  ['addresses', { role: 'asset', kindHint: 'ip' }],
  ['cidr', { role: 'asset', kindHint: 'cidr' }],
  ['subnet', { role: 'asset', kindHint: 'cidr' }],
  ['subnets', { role: 'asset', kindHint: 'cidr' }],
  ['network', { role: 'asset', kindHint: 'cidr' }],
  ['url', { role: 'asset', kindHint: 'url' }],
  ['urls', { role: 'asset', kindHint: 'url' }],
  ['uri', { role: 'asset', kindHint: 'url' }],
  ['endpoint', { role: 'asset', kindHint: 'url' }],
  ['endpoints', { role: 'asset', kindHint: 'url' }],
  ['website', { role: 'asset', kindHint: 'url' }],
  ['link', { role: 'asset', kindHint: 'url' }],
  ['port', { role: 'port' }],
  ['ports', { role: 'port' }],
  ['portnumber', { role: 'port' }],
  ['portnum', { role: 'port' }],
  ['label', { role: 'label' }],
  ['alias', { role: 'label' }],
]);

/** Keys whose string values are prose/filenames rather than assets. */
const GENERIC_STRING_SKIP_RE = /(filename|filepath|file|path|doc|docx|note|comment|description|desc|title|version|build|sha256|hash|fingerprint|cve|cwe|id|uuid)s?$/iu;

/** Plural keys that clearly hold an asset list, so single-label names are kept. */
const ASSET_COLLECTION_KEY_RE = /^(hosts?|domains?|subdomains?|fqdns?|ips?|ipv4s?|ipv6s?|urls?|uris?|targets?|assets?|endpoints?|nodes?|servers?|cidrs?|subnets?|networks?|addresses?|addrs?|records?|names?)$/iu;

/** Header-ish token used for the observation `kind` field. */
function observationKindOf(input) {
  const direct = typeof input.kind === 'string' ? input.kind.trim().toLowerCase() : '';
  if (OBSERVATION_KINDS.includes(direct)) return direct;
  const fallback = typeof input.type === 'string' ? input.type.trim().toLowerCase() : '';
  if (OBSERVATION_KINDS.includes(fallback)) return fallback;
  return undefined;
}

/** Remove invisible / bidi / zero-width characters and normalize exotic spaces. */
export function cleanText(value) {
  return String(value ?? '')
    .replace(INVISIBLE_RE, '')
    .replace(UNICODE_SPACE_RE, ' ')
    .replace(DOT_VARIANT_RE, '.');
}

/** Clean one token: invisible characters removed, exotic dots/spaces normalized, trimmed. */
export function cleanToken(value) {
  return cleanText(value).trim();
}

/** Canonical hostname: lowercase, IDNA/UTS-46 ASCII, trailing dots stripped. */
export function canonicalHost(host) {
  let text = cleanText(host).trim().toLowerCase();
  if (text.length === 0) return '';
  if (text.startsWith('*.')) text = text.slice(2);
  text = text.replace(/\.+$/u, '');
  if (text.length === 0) return '';
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  const ip = parseIp(text);
  if (ip !== undefined) return ip.canonical;
  if (/[:/\\?#@*\s]/u.test(text)) return '';
  try {
    const ascii = domainToASCII(text);
    if (typeof ascii !== 'string' || ascii.length === 0) return '';
    text = ascii.toLowerCase().replace(/\.+$/u, '');
  } catch {
    return '';
  }
  if (text.length === 0 || text.length > 253) return '';
  const labels = text.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return '';
    if (!/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/u.test(label)) return '';
  }
  if (labels.length >= 2 && /^\d+$/u.test(labels[labels.length - 1])) return '';
  return text;
}

/** Whether the hostname is the registrable apex (e.g. `example.com`). */
function isRegistrableApex(hostname) {
  const labels = hostname.split('.');
  if (labels.length <= 1) return false;
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return labels.length === 3;
  return labels.length === 2;
}

/** Build a domain/host/wildcard record, or null when the token is not a hostname. */
function classifyHostnameToken(text, opts = {}) {
  const wildcard = text.startsWith('*.');
  const bareText = wildcard ? text.slice(2) : text;
  const canonical = canonicalHost(bareText);
  if (canonical.length === 0) return null;
  if (wildcard) {
    return {
      kind: 'domain',
      value: `*.${canonical}`,
      canonical: `*.${canonical}`,
      attrs: { wildcard: true, zone: canonical },
    };
  }
  if (opts.strict === true) {
    const labels = canonical.split('.');
    if (labels.length < 2) return null;
    if (FILE_EXTENSION_LABELS.has(labels[labels.length - 1])) return null;
  }
  if (isRegistrableApex(canonical)) {
    return { kind: 'domain', value: canonical, canonical, attrs: { domain: canonical } };
  }
  return { kind: 'host', value: canonical, canonical, attrs: { fqdn: canonical } };
}

/** Parse a canonical port string/number; undefined when out of range. */
function normalizePortNumber(value) {
  if (typeof value === 'number') {
    return Number.isInteger(value) && value >= 1 && value <= 65535 ? value : undefined;
  }
  if (typeof value !== 'string' || !/^\d{1,5}$/u.test(value.trim())) return undefined;
  const port = Number(value.trim());
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : undefined;
}

/** Split `host:port` / `[v6]:port`; returns `{ host, port }` (port may be undefined). */
function splitHostPort(text) {
  const bracket = /^\[([^\]]+)\](?::(\d{1,5}))?$/u.exec(text);
  if (bracket !== null) {
    const port = bracket[2] === undefined ? undefined : normalizePortNumber(bracket[2]);
    if (bracket[2] !== undefined && port === undefined) return undefined;
    return { host: bracket[1], port, bracketed: true };
  }
  const colon = text.lastIndexOf(':');
  if (colon <= 0) return { host: text, port: undefined };
  const portText = text.slice(colon + 1);
  if (!/^\d{1,5}$/u.test(portText)) return { host: text, port: undefined };
  const port = normalizePortNumber(portText);
  if (port === undefined) return undefined;
  return { host: text.slice(0, colon), port };
}

/** Strip decorative punctuation around a token (quotes, angle brackets, list bullets). */
function stripPunctuation(text) {
  let out = text;
  for (let round = 0; round < 3; round += 1) {
    const before = out;
    out = out.replace(/^[<("'`\s]+/u, '').replace(/[>)"'`\s]+$/u, '');
    if (!out.includes('://') && !out.includes('/')) out = out.replace(/[.,;]+$/u, '');
    if (out === before) break;
  }
  return out;
}

/** Build canonical ip record. */
function ipRecord(parsedIp, port) {
  const canonical = parsedIp.canonical;
  const attrs = { addr: canonical, version: parsedIp.version };
  if (port !== undefined) attrs.port = port;
  const display = port === undefined
    ? canonical
    : parsedIp.version === 6 ? `[${canonical}]:${port}` : `${canonical}:${port}`;
  return {
    kind: 'ip',
    value: display,
    canonical,
    attrs,
  };
}

/** Build canonical cidr record. */
function cidrRecord(parsedCidr) {
  return {
    kind: 'cidr',
    value: parsedCidr.canonical,
    canonical: parsedCidr.canonical,
    attrs: { version: parsedCidr.version, prefix: parsedCidr.prefix },
  };
}

/**
 * Canonicalize an absolute URL.
 * Fragment is dropped from the key; default ports are elided by WHATWG URL.
 * Path/query survive in the key and are duplicated into `attrs.path`/`attrs.query`.
 * Userinfo is never copied: only a `credentialHint` with presence metadata.
 */
export function canonicalizeUrl(input) {
  let text = cleanText(input).trim();
  if (text.length === 0 || text.length > MAX_TOKEN_LENGTH || /\s/u.test(text)) return undefined;
  if (!/^[a-z][a-z0-9+.-]*:\/\//iu.test(text)) {
    // Schemeless input must start with a plausible host. A bare path
    // (`/just/a/path`), a query or a fragment is not an asset.
    const authority = text.split(/[/?#]/u)[0];
    const split = splitHostPort(authority);
    if (split === undefined || split.host.length === 0) return undefined;
    const hostCandidate = canonicalHost(split.host);
    if (hostCandidate.length === 0) return undefined;
    if (isLeadingZeroIpv4Like(split.host)) return undefined;
    const hostIsIp = parseIp(split.host) !== undefined;
    if (!hostIsIp && !hostCandidate.includes('.') && hostCandidate !== 'localhost') return undefined;
    let scheme = 'https';
    if (split.port !== undefined) {
      scheme = split.port === 443 || split.port === 8443 ? 'https' : 'http';
    }
    text = `${scheme}://${text}`;
  } else {
    // The WHATWG parser silently reads `010.0.0.0` as octal 8.0.0.0. Refuse
    // leading-zero IPv4 hosts before that reinterpretation can happen.
    const afterScheme = text.replace(/^[a-z][a-z0-9+.-]*:\/\//iu, '');
    const authority = afterScheme.split(/[/?#]/u)[0];
    const hostPart = authority.slice(authority.lastIndexOf('@') + 1).replace(/:\d{1,5}$/u, '');
    if (isLeadingZeroIpv4Like(hostPart)) return undefined;
  }
  let url;
  try {
    url = new URL(text);
  } catch {
    return undefined;
  }
  const scheme = url.protocol.replace(/:$/u, '').toLowerCase();
  if (!URL_SCHEMES.has(scheme)) return undefined;
  const host = canonicalHost(url.hostname);
  if (host.length === 0) return undefined;
  const port = url.port.length === 0 ? undefined : Number(url.port);
  if (port !== undefined && normalizePortNumber(port) === undefined) return undefined;
  const ipv6Literal = url.hostname.startsWith('[');
  const hostPart = ipv6Literal ? `[${host}]` : host;
  const authority = port === undefined ? hostPart : `${hostPart}:${port}`;
  const pathname = url.pathname.length === 0 ? '/' : url.pathname;
  const search = url.search;
  const originOnly = pathname === '/' && search.length === 0;
  const key = originOnly ? `${scheme}://${authority}` : `${scheme}://${authority}${pathname}${search}`;
  const hasUserinfo = url.username.length > 0 || url.password.length > 0;
  const attrs = {
    url: key,
    scheme,
    host,
    path: pathname,
  };
  if (port !== undefined) attrs.port = port;
  if (search.length > 1) attrs.query = search.slice(1);
  if (hasUserinfo) {
    attrs.hasUserinfo = true;
    attrs.credentialHint = {
      present: true,
      usernameLength: safeDecodedLength(url.username),
      hasPassword: url.password.length > 0,
    };
  }
  if (url.hash.length > 1) attrs.hasFragment = true;
  return { kind: 'url', value: key, canonical: key, attrs };
}

/** Decode a percent-encoded userinfo component only enough to report its length. */
function safeDecodedLength(value) {
  if (typeof value !== 'string' || value.length === 0) return 0;
  try {
    return decodeURIComponent(value).length;
  } catch {
    return value.length;
  }
}

/** Classify one token into an asset record; null when it is not an asset. */
export function classifyToken(token, opts = {}) {
  const rawText = String(token ?? '');
  if (rawText.length > MAX_TOKEN_LENGTH * 2) return null;
  const cleaned = cleanToken(rawText);
  if (cleaned.length === 0 || cleaned.length > MAX_TOKEN_LENGTH) return null;
  const options = isPlainObject(opts) ? opts : {};
  const variants = [cleaned];
  const punctuation = stripPunctuation(cleaned);
  if (punctuation !== cleaned) variants.push(punctuation);
  if (cleaned.includes('[') && cleaned.includes(']')) {
    const bracketed = cleaned.replace(/^\[+/u, '').replace(/\]+$/u, '');
    if (bracketed !== cleaned) variants.push(bracketed);
  }
  if (cleaned.endsWith('.') && !cleaned.includes('://')) variants.push(cleaned.replace(/\.+$/u, ''));
  for (const variant of variants) {
    if (variant.length === 0 || variant.length > MAX_TOKEN_LENGTH || /\s/u.test(variant)) continue;
    const record = classifyVariant(variant, options);
    if (record !== null && record !== undefined) return record;
  }
  return null;
}

/** Classify a single cleaned token variant. */
function classifyVariant(text, opts) {
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(text)) return canonicalizeUrl(text);
  const bracketed = /^\[([^\]]+)\](?::(\d{1,5}))?$/u.exec(text);
  if (bracketed !== null) {
    const ip = parseIp(bracketed[1]);
    if (ip === undefined) return null;
    const port = bracketed[2] === undefined ? undefined : normalizePortNumber(bracketed[2]);
    if (bracketed[2] !== undefined && port === undefined) return null;
    return ipRecord(ip, port);
  }
  const ip = parseIp(text);
  if (ip !== undefined) return ipRecord(ip, undefined);
  if (text.includes('/')) {
    const cidr = parseCidr(text);
    if (cidr !== undefined) return cidrRecord(cidr);
    // `<ip>/<prefix>` with an invalid prefix is a broken CIDR, never a URL.
    const slash = text.indexOf('/');
    const addressPart = text.slice(0, slash);
    const prefixPart = text.slice(slash + 1);
    if (parseIp(addressPart) !== undefined && /^\d{1,3}$/u.test(prefixPart)) return null;
  }
  const split = splitHostPort(text);
  if (split !== undefined && split.port !== undefined) {
    const splitIp = parseIp(split.host);
    if (splitIp !== undefined) return ipRecord(splitIp, split.port);
    const hostname = classifyHostnameToken(split.host, opts);
    if (hostname === null) return null;
    return {
      ...hostname,
      value: `${hostname.canonical}:${split.port}`,
      attrs: { ...hostname.attrs, port: split.port },
    };
  }
  if (/[/?#]/u.test(text)) return canonicalizeUrl(text);
  return classifyHostnameToken(text, opts);
}

/** Whether a raw token looks like an address attempt worth quarantining. */
function isLeadingZeroIpv4Like(text) {
  const core = text.includes('/') ? text.slice(0, text.indexOf('/')) : text.replace(/:\d{1,5}$/u, '');
  const parts = core.split('.');
  if (parts.length !== 4) return false;
  if (!parts.every((part) => /^\d+$/u.test(part))) return false;
  return parts.some((part) => part.length > 1 && part.startsWith('0'));
}

/** Whether a cleaned token plausibly intended to be an asset. */
function looksLikeAssetAttempt(text) {
  if (/:\/\//u.test(text)) return true;
  if (isLeadingZeroIpv4Like(text)) return true;
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:\/\d{1,3})?$/u.test(text)) return true;
  if (/^[0-9a-f:]{2,}$/u.test(text) && text.includes(':')) return true;
  if (/^[^:@/\s]+:[^@/\s]+@/u.test(text)) return true;
  if (/^[^\s/]+:\d{1,5}(?:[/?#]|$)/u.test(text)) return true;
  if (/^[^\s/]+\/\d{1,3}$/u.test(text)) return true;
  return false;
}

/** Reason code for a token that failed normalization. */
function quarantineReason(token) {
  const text = cleanToken(token);
  if (text.length === 0) return 'empty';
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(text)) return 'invalid-url';
  if (/^[^:@/\s]+:[^@/\s]+@/u.test(text)) return 'credential-like';
  if (isLeadingZeroIpv4Like(text)) return 'ipv4-leading-zero';
  if (text.includes('/')) return 'invalid-cidr';
  const hostCandidate = text.replace(/:\d{1,5}$/u, '');
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(hostCandidate)) return 'invalid-ipv4';
  if (text.includes(':')) return 'invalid-ip';
  if (text.includes('.')) return 'invalid-host';
  return 'not-asset';
}

/** Mask userinfo before a raw token can be echoed in a quarantine/warning record. */
function safeRaw(value) {
  let text;
  if (typeof value === 'string') text = value;
  else {
    try {
      text = JSON.stringify(value);
    } catch {
      text = String(value);
    }
  }
  text = String(text ?? '');
  text = text.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/giu, '$1***@');
  text = text.replace(/^([^:@/\s]+):([^@/\s]+)@/u, '***@');
  return truncate(text, 300);
}

/** Bound one attribute value (strings truncated, arrays/objects capped). */
function boundAttrValue(value, depth = 0) {
  if (depth > 4) return undefined;
  if (typeof value === 'string') return truncate(value, 2000);
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY_ITEMS)
      .map((entry) => boundAttrValue(entry, depth + 1))
      .filter((entry) => entry !== undefined);
  }
  if (isPlainObject(value)) {
    const out = {};
    for (const [key, entry] of Object.entries(value)) {
      if (SECRET_KEY_PATTERN.test(key)) continue;
      const bounded = boundAttrValue(entry, depth + 1);
      if (bounded === undefined) continue;
      out[truncate(String(key), 100)] = bounded;
      if (Object.keys(out).length >= MAX_ATTRIBUTE_KEYS) break;
    }
    return out;
  }
  return undefined;
}

/** Strip secrets and bound an attribute object. */
function sanitizeAttributes(value) {
  if (!isPlainObject(value)) return {};
  const stripped = stripSecrets(value);
  if (!isPlainObject(stripped)) return {};
  const out = {};
  for (const [key, entry] of Object.entries(stripped)) {
    if (entry === undefined) continue;
    if (Object.keys(out).length >= MAX_ATTRIBUTE_KEYS) break;
    const name = truncate(String(key), 100);
    if (SECRET_KEY_PATTERN.test(name)) continue;
    const bounded = boundAttrValue(entry);
    if (bounded !== undefined) out[name] = bounded;
  }
  return out;
}

/** Merge two attribute objects, unioning arrays and collecting port differences. */
function mergeAttributeObjects(base, incoming) {
  const out = { ...base };
  if (!isPlainObject(incoming)) return out;
  for (const [key, value] of Object.entries(incoming)) {
    if (value === undefined) continue;
    if (key === 'port') {
      const incomingPort = normalizePortNumber(value);
      if (incomingPort === undefined) continue;
      if (out.port === undefined) {
        out.port = incomingPort;
      } else if (out.port !== incomingPort) {
        const ports = new Set([out.port, incomingPort, ...(Array.isArray(out.ports) ? out.ports : [])]);
        out.ports = [...ports].filter(Number.isInteger).sort((a, b) => a - b);
      }
      continue;
    }
    const existing = out[key];
    if (existing === undefined) {
      out[key] = value;
      continue;
    }
    if (Array.isArray(existing) && Array.isArray(value)) {
      if (existing.every(Number.isInteger) && value.every(Number.isInteger)) {
        out[key] = [...new Set([...existing, ...value])].sort((a, b) => a - b);
      } else if (existing.every((entry) => typeof entry === 'string') && value.every((entry) => typeof entry === 'string')) {
        out[key] = uniqueStrings([...existing, ...value]);
      } else {
        const seen = new Set();
        const merged = [];
        for (const entry of [...existing, ...value]) {
          const marker = typeof entry === 'object' ? JSON.stringify(entry) : String(entry);
          if (seen.has(marker)) continue;
          seen.add(marker);
          merged.push(entry);
        }
        out[key] = merged;
      }
    }
    // Scalars keep the first value; conflicting critical keys are reported by
    // mergeNormalized, and duplicates within one document are rare.
  }
  return out;
}

/** Advisory coercion between the two name kinds when a field hint asks for it. */
function coerceKind(record, kindHint) {
  if (typeof kindHint !== 'string' || record.kind === kindHint) return record;
  if (record.attrs?.wildcard === true) return record;
  if (kindHint === 'domain' && record.kind === 'host') {
    const attrs = { ...record.attrs };
    delete attrs.fqdn;
    attrs.domain = record.canonical;
    return { ...record, kind: 'domain', attrs };
  }
  if (kindHint === 'host' && record.kind === 'domain') {
    const attrs = { ...record.attrs };
    delete attrs.domain;
    attrs.fqdn = record.canonical;
    return { ...record, kind: 'host', attrs };
  }
  return undefined;
}

/** Normalize the kind hint accepted by `normalizeAsset` options / records. */
function normalizeKindHint(value) {
  if (typeof value !== 'string') return undefined;
  const kind = value.trim().toLowerCase();
  return ASSET_KINDS.includes(kind) ? kind : undefined;
}

/** First non-empty string among the given object keys. */
function firstStringFrom(input, keys) {
  if (!isPlainObject(input)) return undefined;
  for (const key of keys) {
    const value = input[key];
    if (typeof value === 'string' && value.trim().length > 0) return value.trim();
  }
  return undefined;
}

/** String form of a value for diagnostics, never containing userinfo secrets. */
function rawForDiagnostics(input) {
  if (typeof input === 'string') return input;
  if (isPlainObject(input)) {
    try {
      return JSON.stringify(input);
    } catch {
      return '[object]';
    }
  }
  return String(input ?? '');
}

const ASSET_VALUE_KEYS = Object.freeze([
  'value', 'key', 'raw', 'asset', 'host', 'hostname', 'fqdn', 'domain', 'ip', 'addr', 'address',
  'cidr', 'subnet', 'network', 'url', 'uri', 'endpoint', 'target',
]);

/**
 * Normalize one asset candidate.
 *
 * @param {string|object} input raw token, or `{kind?, value?, attrs?, port?, label?, source?}`.
 * @param {object} [opts] `{kindHint?, port?, attrs?, source?, strict?}`.
 * @returns {{ok:true, kind:string, key:string, value:string, attrs:object}
 *          |{ok:false, reason:string, raw:string, quarantine:true}}
 */
export function normalizeAsset(input, opts = {}) {
  const options = isPlainObject(opts) ? opts : {};
  const raw = rawForDiagnostics(input);
  try {
    const kindHint = normalizeKindHint(options.kindHint ?? options.kind
      ?? (isPlainObject(input) ? input.kind ?? input.type : undefined));
    let token;
    let extraAttrs = {};
    if (isPlainObject(input)) {
      token = firstStringFrom(input, ASSET_VALUE_KEYS);
      if (token === undefined) {
        return { ok: false, reason: 'missing-value', raw: safeRaw(raw), quarantine: true };
      }
      if (isPlainObject(input.attrs)) extraAttrs = { ...extraAttrs, ...input.attrs };
      const inputPort = normalizePortNumber(input.port);
      if (inputPort !== undefined) extraAttrs.port = inputPort;
      if (typeof input.label === 'string' && input.label.trim().length > 0) {
        extraAttrs.label = truncate(input.label.trim(), 300);
      }
      if (typeof input.source === 'string' && input.source.trim().length > 0) {
        extraAttrs.source = truncate(input.source.trim(), 300);
      }
    } else if (typeof input === 'string') {
      token = input;
    } else {
      return { ok: false, reason: 'invalid-input', raw: safeRaw(raw), quarantine: true };
    }
    if (isPlainObject(options.attrs)) extraAttrs = { ...extraAttrs, ...options.attrs };
    const optionPort = normalizePortNumber(options.port);
    if (optionPort !== undefined && extraAttrs.port === undefined) extraAttrs.port = optionPort;
    if (typeof options.source === 'string' && options.source.length > 0) {
      extraAttrs.source = truncate(options.source, 300);
    }

    let record = classifyToken(token, { strict: options.strict === true });
    if (record === null) {
      return { ok: false, reason: quarantineReason(token), raw: safeRaw(token ?? raw), quarantine: true };
    }
    if (kindHint !== undefined) record = coerceKind(record, kindHint) ?? record;
    const attrs = mergeAttributeObjects(sanitizeAttributes(extraAttrs), record.attrs);
    return {
      ok: true,
      kind: record.kind,
      key: record.canonical,
      // `value` is always the canonical identity (port lives in attrs.port) so
      // downstream graph tools can feed it straight into node builders.
      value: record.canonical,
      attrs,
    };
  } catch {
    return { ok: false, reason: 'internal-error', raw: safeRaw(raw), quarantine: true };
  }
}

// ---------------------------------------------------------------------------
// Delimited text (CSV / TSV)
// ---------------------------------------------------------------------------

const DELIMITER_PRIORITY = [',', '\t', ';', '|'];

/** Guess the delimiter of a small delimited text sample. */
export function sniffDelimiter(text) {
  const source = String(text ?? '');
  const counts = new Map(DELIMITER_PRIORITY.map((delimiter) => [delimiter, 0]));
  let inQuotes = false;
  let lines = 0;
  for (let index = 0; index < source.length && lines < 20; index += 1) {
    const char = source[index];
    if (char === '"') {
      if (inQuotes && source[index + 1] === '"') {
        index += 1;
        continue;
      }
      inQuotes = !inQuotes;
      continue;
    }
    if (char === '\n') {
      lines += 1;
      continue;
    }
    if (!inQuotes && counts.has(char)) counts.set(char, counts.get(char) + 1);
  }
  let best = ',';
  let bestCount = -1;
  for (const delimiter of DELIMITER_PRIORITY) {
    const count = counts.get(delimiter);
    if (count > bestCount) {
      bestCount = count;
      best = delimiter;
    }
  }
  return best;
}

/**
 * Parse RFC4180-ish delimited text.
 *
 * Supports quoted fields containing delimiters, CR/LF or CRLF breaks, doubled
 * quote escapes (`""`), comment rows starting with `#` or `//`, and delimiter
 * sniffing when `delimiter` is omitted.
 *
 * @returns {{rows:string[][], warnings:{reason:string, line?:number}[], delimiter:string}}
 */
export function parseDelimited(text, options = {}) {
  const source = String(text ?? '');
  const opts = isPlainObject(options) ? options : {};
  const delimiter = typeof opts.delimiter === 'string' && opts.delimiter.length === 1
    ? opts.delimiter
    : sniffDelimiter(source);
  const maxRows = Number.isFinite(opts.maxRows) && opts.maxRows > 0 ? opts.maxRows : 20000;
  const ignoreComments = opts.ignoreComments !== false;
  const rows = [];
  const warnings = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  let overflow = false;
  let index = 0;
  if (source.charCodeAt(0) === 0xfeff) index = 1;
  const pushField = () => {
    row.push(field);
    field = '';
  };
  const pushRow = () => {
    pushField();
    if (row.some((cell) => cell.trim().length > 0)) {
      if (rows.length >= maxRows) {
        if (!overflow) {
          overflow = true;
          warnings.push({ reason: 'too-many-rows', line: rows.length + 1 });
        }
      } else {
        rows.push(row);
      }
    }
    row = [];
  };
  while (index < source.length) {
    const char = source[index];
    if (inQuotes) {
      if (char === '"') {
        if (source[index + 1] === '"') {
          field += '"';
          index += 2;
          continue;
        }
        inQuotes = false;
        index += 1;
        continue;
      }
      field += char;
      index += 1;
      continue;
    }
    if (ignoreComments && row.length === 0 && field.length === 0) {
      const rest = source.slice(index, index + 2);
      if (char === '#' || rest === '//') {
        while (index < source.length && source[index] !== '\n' && source[index] !== '\r') index += 1;
        continue;
      }
    }
    if (char === '"' && field.length === 0) {
      inQuotes = true;
      index += 1;
      continue;
    }
    if (char === delimiter) {
      pushField();
      index += 1;
      continue;
    }
    if (char === '\r') {
      if (source[index + 1] === '\n') index += 1;
      pushRow();
      index += 1;
      continue;
    }
    if (char === '\n') {
      pushRow();
      index += 1;
      continue;
    }
    field += char;
    index += 1;
  }
  if (inQuotes) warnings.push({ reason: 'unclosed-quote', line: rows.length + 1 });
  if (field.length > 0 || row.length > 0) pushRow();
  return { rows, warnings, delimiter };
}

// ---------------------------------------------------------------------------
// Document parsing
// ---------------------------------------------------------------------------

/** Split text into lines while stripping a leading BOM. */
function splitLines(text) {
  return String(text ?? '').replace(/^\uFEFF/u, '').split(/\r\n|\n|\r/u);
}

/** Normalize a header cell / JSON key to a lookup token. */
function normalizeFieldName(value) {
  return cleanToken(value).toLowerCase().replace(/[\s_.-]+/gu, '');
}

/** Map the first table row to column roles, or null when it is data. */
function detectHeaderRow(cells) {
  if (!Array.isArray(cells) || cells.length === 0) return null;
  let recognized = 0;
  const columns = cells.map((cell) => {
    const role = ASSET_FIELD_ROLES.get(normalizeFieldName(cell));
    if (role !== undefined) recognized += 1;
    return role ?? null;
  });
  if (recognized === 0) return null;
  const needed = Math.max(1, Math.ceil(cells.length * 0.5));
  if (recognized < needed) return null;
  return columns;
}

/** Harvest one row of cells using header roles when available. */
function harvestRow(cells, context) {
  const { header, line, source, add } = context;
  const safeCells = Array.isArray(cells) ? cells : [];
  if (header !== null) {
    let port;
    const labels = [];
    for (let index = 0; index < header.length && index < safeCells.length; index += 1) {
      const role = header[index];
      if (role === null) continue;
      if (role.role === 'port') {
        port = normalizePortNumber(safeCells[index].trim());
      } else if (role.role === 'label') {
        const label = safeCells[index].trim();
        if (label.length > 0) labels.push(label);
      }
    }
    let added = 0;
    for (let index = 0; index < header.length && index < safeCells.length; index += 1) {
      const role = header[index];
      if (role === null || role.role !== 'asset') continue;
      const cell = safeCells[index].trim();
      if (cell.length === 0) continue;
      add(cell, {
        kindHint: role.kindHint,
        port,
        label: labels[0],
        explicit: true,
        line,
        source,
      });
      added += 1;
    }
    if (added === 0) harvestStrictCells(safeCells, context);
    return;
  }
  if (safeCells.length === 1) {
    const cell = safeCells[0].trim();
    if (cell.length > 0) add(cell, { line, source });
    return;
  }
  harvestStrictCells(safeCells, context);
}

/** Harvest headerless cells: only clearly asset-shaped values are kept. */
function harvestStrictCells(cells, context) {
  const { line, source, add } = context;
  const trimmed = cells.map((cell) => cell.trim());
  let port;
  for (const cell of trimmed) {
    const candidate = normalizePortNumber(cell);
    if (candidate !== undefined && /^\d{1,5}$/u.test(cell)) {
      port = candidate;
      break;
    }
  }
  for (const cell of trimmed) {
    if (cell.length === 0) continue;
    if (/^\d{1,5}$/u.test(cell) && normalizePortNumber(cell) !== undefined) continue;
    add(cell, { strict: true, port, line, source });
  }
}

/** Whether a Markdown line is a table separator (`| --- | :---: |`). */
function isTableSeparator(line) {
  const text = String(line ?? '').trim();
  if (!text.includes('|') && !text.includes(':')) return false;
  let cells = text;
  if (cells.startsWith('|')) cells = cells.slice(1);
  if (cells.endsWith('|')) cells = cells.slice(0, -1);
  const parts = cells.split('|');
  if (parts.length === 0) return false;
  return parts.every((part) => /^\s*:?-{2,}:?\s*$/u.test(part));
}

/** Split one Markdown table row into trimmed cells. */
function splitTableRow(line) {
  let text = String(line ?? '').trim();
  if (text.startsWith('|')) text = text.slice(1);
  if (text.endsWith('|')) text = text.slice(0, -1);
  return text.split('|').map((cell) => cell.trim().replace(/\\\|/gu, '|'));
}

/** Build the provenance string used for `attrs.source`. */
function sourceFor(filename, pathText, line) {
  if (typeof pathText === 'string' && pathText.length > 0) return truncate(pathText, 300);
  const base = typeof filename === 'string' && filename.length > 0 ? filename : 'document';
  return line !== undefined ? `${base}:${line}` : base;
}

/** Validate and resolve a document format name. */
function normalizeFormatName(value) {
  if (typeof value !== 'string') return undefined;
  const format = value.trim().toLowerCase();
  if (format === 'auto') return undefined;
  if (format === 'md') return 'markdown';
  if (format === 'ndjson') return 'jsonl';
  if (format === 'tab') return 'tsv';
  if (format === 'text') return 'txt';
  return DOCUMENT_FORMATS.includes(format) ? format : undefined;
}

/**
 * Detect the document format from the filename and, when the extension is
 * unknown or absent, from the content shape.
 */
export function detectDocumentFormat(filename, text) {
  const name = typeof filename === 'string' ? filename : '';
  const base = name.split(/[\\/]/u).pop().toLowerCase();
  const dot = base.lastIndexOf('.');
  const extension = dot >= 0 ? base.slice(dot + 1) : '';
  const byExtension = {
    txt: 'txt', text: 'txt', list: 'txt', lst: 'txt', log: 'txt',
    csv: 'csv', tsv: 'tsv', tab: 'tsv',
    json: 'json', jsonl: 'jsonl', ndjson: 'jsonl',
    md: 'markdown', markdown: 'markdown', mdx: 'markdown',
  };
  if (byExtension[extension] !== undefined) return byExtension[extension];
  const body = String(text ?? '').replace(/^\uFEFF/u, '').trim();
  if (body.length === 0) return 'txt';
  const lines = body.split(/\r\n|\n|\r/u).filter((line) => line.trim().length > 0);
  if (lines.some((line) => isTableSeparator(line))) return 'markdown';
  const first = lines[0];
  if (first.startsWith('{') || first.startsWith('[')) {
    if (lines.length === 1) return 'json';
    if (lines.every((line) => safeJsonParseLine(line) !== undefined)) return 'jsonl';
    if (safeJsonParseLine(body) !== undefined) return 'json';
    return 'jsonl';
  }
  const sample = lines.slice(0, 10);
  if (sample.some((line) => line.includes('\t'))) return 'tsv';
  if (sample.some((line) => (line.match(/,/gu) ?? []).length >= 2)) return 'csv';
  if (sample.some((line) => (line.match(/;/gu) ?? []).length >= 2)) return 'csv';
  if (sample.some((line) => (line.match(/\|/gu) ?? []).length >= 2)) return 'markdown';
  return 'txt';
}

/** JSON.parse that returns undefined instead of throwing. */
function safeJsonParseLine(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * Whether a text block is predominantly tab-delimited in its first lines.
 * Office extraction (`doc.js`) emits xlsx rows as TSV but docx paragraphs as
 * plain lines, so the ratio matters rather than a single tab row.
 */
function hasTabDelimitedContent(text) {
  let inspected = 0;
  let tabRows = 0;
  for (const line of splitLines(text)) {
    if (line.trim().length === 0) continue;
    inspected += 1;
    if (line.includes('\t')) tabRows += 1;
    if (inspected >= 20) break;
  }
  return tabRows >= 2 && tabRows / inspected >= 0.5;
}

/**
 * Parse a document into canonical asset records.
 *
 * @param {string} text document text (already extracted for Office files).
 * @param {{format?:string, filename?:string, maxBytes?:number}} [opts]
 * @returns {{
 *   records: {ok:true, kind:string, key:string, value:string, attrs:object}[],
 *   warnings: {reason:string, line?:number, raw?:string, source?:string}[],
 *   quarantined: {raw:string, reason:string, line?:number, source?:string}[],
 *   stats: {format:string, lines:number, candidates:number, records:number,
 *           duplicates:number, quarantined:number, skipped:number, warnings:number}
 * }}
 */
export function parseAssetDocument(text, opts = {}) {
  const options = isPlainObject(opts) ? opts : {};
  const sourceText = String(text ?? '');
  const bytes = byteLength(sourceText);
  const maxBytes = Number.isFinite(options.maxBytes) && options.maxBytes > 0
    ? options.maxBytes
    : MAX_DOCUMENT_BYTES;
  if (bytes > maxBytes) invalid(`asset document is ${bytes} bytes; the limit is ${maxBytes} bytes`);
  const filename = typeof options.filename === 'string' ? options.filename : '';
  const requestedFormat = typeof options.format === 'string' ? options.format.trim().toLowerCase() : '';
  let format;
  const namedFormat = normalizeFormatName(options.format);
  if (namedFormat !== undefined) {
    format = namedFormat;
  } else if (requestedFormat === 'lines') {
    // Host tools pass "lines" for extracted document text; tab-delimited
    // extraction (xlsx) is still parsed as a table so ports respect columns.
    format = hasTabDelimitedContent(sourceText) ? 'tsv' : 'txt';
  } else {
    format = detectDocumentFormat(filename, sourceText);
  }

  const records = [];
  const warnings = [];
  const quarantined = [];
  const seenIds = new Set();
  const quarantineSeen = new Set();
  let warningCount = 0;
  let candidateOverflow = false;
  let quarantineOverflow = false;
  const stats = {
    format,
    lines: 0,
    candidates: 0,
    records: 0,
    duplicates: 0,
    quarantined: 0,
    skipped: 0,
    warnings: 0,
  };

  const warn = (reason, detail = {}) => {
    warningCount += 1;
    if (warnings.length >= MAX_WARNINGS) return;
    const entry = { reason };
    if (detail.line !== undefined) entry.line = detail.line;
    if (detail.raw !== undefined) entry.raw = safeRaw(detail.raw);
    if (detail.source !== undefined) entry.source = String(detail.source).slice(0, 300);
    if (detail.limit !== undefined) entry.limit = detail.limit;
    if (typeof detail.cause === 'string') entry.cause = detail.cause;
    if (typeof detail.field === 'string') entry.field = detail.field;
    warnings.push(entry);
  };

  const quarantine = (entry) => {
    const marker = `${entry.reason}\u001f${entry.raw}`;
    if (quarantineSeen.has(marker)) return;
    if (quarantined.length >= MAX_QUARANTINED) {
      if (!quarantineOverflow) {
        quarantineOverflow = true;
        warn('quarantine-truncated', { limit: MAX_QUARANTINED });
      }
      return;
    }
    quarantineSeen.add(marker);
    quarantined.push(entry);
    stats.quarantined += 1;
  };

  const add = (token, hint = {}) => {
    if (typeof token !== 'string') return;
    const cleaned = cleanToken(token);
    if (cleaned.length === 0) return;
    if (stats.candidates >= MAX_CANDIDATES) {
      if (!candidateOverflow) {
        candidateOverflow = true;
        warn('candidate-limit', { limit: MAX_CANDIDATES });
      }
      return;
    }
    stats.candidates += 1;
    const normalized = normalizeAsset(cleaned, {
      kindHint: hint.kindHint,
      port: hint.port,
      attrs: hint.attrs,
      source: hint.source,
      strict: hint.strict === true,
    });
    const line = hint.line;
    if (normalized.ok) {
      stats.records += 1;
      const id = `${normalized.kind}|${normalized.key}`;
      if (seenIds.has(id)) stats.duplicates += 1;
      else seenIds.add(id);
      records.push(normalized);
      return;
    }
    if (hint.strict === true && !looksLikeAssetAttempt(cleaned)) {
      stats.skipped += 1;
      return;
    }
    if (hint.explicit === true) warn('invalid-asset', { cause: normalized.reason, raw: normalized.raw, line });
    quarantine({
      raw: normalized.raw,
      reason: normalized.reason,
      ...(line !== undefined ? { line } : {}),
      ...(hint.source !== undefined ? { source: hint.source } : {}),
    });
  };

  const context = { add, warn, filename };

  try {
    if (format === 'csv' || format === 'tsv') collectDelimited(sourceText, format, context, stats);
    else if (format === 'json') collectJson(sourceText, context, stats);
    else if (format === 'jsonl') collectJsonl(sourceText, context, stats);
    else if (format === 'markdown') collectMarkdown(sourceText, context, stats);
    else collectTxt(sourceText, context, stats);
  } catch (error) {
    if (error instanceof InputError) throw error;
    warn('internal-parse-error');
  }

  stats.warnings = warningCount;
  return { records, warnings, quarantined, stats };
}

/** Parse free-form TXT lines (comments and blank lines skipped). */
function collectTxt(text, context, stats) {
  const { add, filename } = context;
  const lines = splitLines(text);
  stats.lines = lines.length;
  for (let index = 0; index < lines.length; index += 1) {
    const trimmed = lines[index].trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
    const lineNumber = index + 1;
    const source = sourceFor(filename, undefined, lineNumber);
    if (/[\s,]+/u.test(trimmed)) {
      const parts = trimmed.split(/[\s,]+/u).filter((part) => part.length > 0);
      const portHint = parts.length === 2 ? normalizePortNumber(parts[1]) : undefined;
      for (const part of parts) {
        add(part, {
          strict: true,
          ...(portHint !== undefined && part === parts[0] ? { port: portHint } : {}),
          line: lineNumber,
          source,
        });
      }
      continue;
    }
    add(trimmed, { line: lineNumber, source });
  }
}

/** Parse CSV/TSV with optional header mapping. */
function collectDelimited(text, format, context, stats) {
  const { add, warn, filename } = context;
  const parsed = parseDelimited(text, {
    delimiter: format === 'tsv' ? '\t' : undefined,
    maxRows: 20000,
    ignoreComments: true,
  });
  stats.lines = parsed.rows.length;
  for (const warning of parsed.warnings) warn(warning.reason, { line: warning.line });
  if (parsed.rows.length === 0) {
    warn('empty-table');
    return;
  }
  const header = detectHeaderRow(parsed.rows[0]);
  const start = header === null ? 0 : 1;
  for (let index = start; index < parsed.rows.length; index += 1) {
    const lineNumber = index + 1;
    harvestRow(parsed.rows[index], {
      header,
      line: lineNumber,
      source: sourceFor(filename, undefined, lineNumber),
      add,
    });
  }
}

/** Recursively collect asset candidates from a parsed JSON value. */
function collectJson(text, context, stats) {
  const { add, warn } = context;
  const body = String(text ?? '').replace(/^\uFEFF/u, '');
  const parsed = safeJsonParseLine(body);
  if (parsed === undefined) {
    warn('invalid-json', { raw: truncate(body, 200) });
    stats.lines = 0;
    return;
  }
  stats.lines = 1;
  walkJson(parsed, { path: '$', depth: 0, strict: false }, add, warn);
}

/** Parse one-object-per-line JSONL. */
function collectJsonl(text, context, stats) {
  const { add, warn } = context;
  const lines = splitLines(text);
  stats.lines = lines.length;
  for (let index = 0; index < lines.length; index += 1) {
    const trimmed = lines[index].trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
    const lineNumber = index + 1;
    const parsed = safeJsonParseLine(trimmed);
    if (parsed === undefined) {
      warn('invalid-json-line', { line: lineNumber, raw: trimmed });
      continue;
    }
    walkJson(parsed, { path: `$[line ${lineNumber}]`, depth: 0, strict: true }, add, warn);
  }
}

/** Recursively walk a JSON value and feed asset-shaped strings to `add`. */
function walkJson(value, context, add, warn) {
  if (context.depth > 12) {
    warn('json-depth-limit', { source: context.path });
    return;
  }
  if (typeof value === 'string') {
    add(value, { strict: context.strict === true, source: context.path });
    return;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      walkJson(value[index], {
        path: `${context.path}[${index}]`,
        depth: context.depth + 1,
        strict: context.strict === true,
      }, add, warn);
    }
    return;
  }
  if (!isPlainObject(value)) return;
  const siblings = jsonSiblingHint(value);
  for (const [rawKey, entry] of Object.entries(value)) {
    const key = String(rawKey);
    const fieldName = normalizeFieldName(key);
    const role = ASSET_FIELD_ROLES.get(fieldName);
    const path = `${context.path}.${key}`;
    if (role !== undefined && role.role === 'asset' && typeof entry === 'string') {
      add(entry, {
        kindHint: role.kindHint,
        port: siblings.port,
        attrs: siblings.attrs,
        label: siblings.label,
        explicit: true,
        source: path,
      });
      continue;
    }
    if (typeof entry === 'string') {
      if (GENERIC_STRING_SKIP_RE.test(fieldName)) continue;
      // Non-field strings must be unmistakably asset-shaped: sibling metadata
      // such as service names or banners would otherwise become fake hosts.
      add(entry, { strict: true, source: path });
      continue;
    }
    if (Array.isArray(entry)) {
      walkJson(entry, {
        path,
        depth: context.depth + 1,
        strict: !ASSET_COLLECTION_KEY_RE.test(fieldName),
      }, add, warn);
      continue;
    }
    if (isPlainObject(entry)) {
      walkJson(entry, { path, depth: context.depth + 1, strict: true }, add, warn);
      if (classifyToken(key, { strict: true }) !== null) {
        const nested = jsonSiblingHint(entry);
        add(key, {
          strict: true,
          port: nested.port,
          attrs: nested.attrs,
          label: nested.label,
          source: `${path} (key)`,
        });
      }
    }
  }
}

/** Pull label/port and small scalar attributes from a JSON object. */
function jsonSiblingHint(value) {
  const attrs = {};
  let label;
  let port;
  for (const [rawKey, entry] of Object.entries(value)) {
    const fieldName = normalizeFieldName(rawKey);
    if (fieldName === 'port' || fieldName === 'ports') {
      port = normalizePortNumber(entry);
      continue;
    }
    if (fieldName === 'label' || fieldName === 'alias') {
      if (typeof entry === 'string' && entry.trim().length > 0) label = truncate(entry.trim(), 300);
      continue;
    }
    if (ASSET_FIELD_ROLES.has(fieldName)) continue;
    if (typeof entry === 'string') {
      attrs[rawKey] = truncate(entry, 500);
    } else if (typeof entry === 'number' || typeof entry === 'boolean') {
      attrs[rawKey] = entry;
    } else if (Array.isArray(entry) && entry.length <= 20 && entry.every((item) => typeof item === 'string')) {
      attrs[rawKey] = entry.map((item) => truncate(item, 200));
    }
  }
  return { attrs, label, port };
}

/** Parse Markdown tables plus list/plain lines. */
function collectMarkdown(text, context, stats) {
  const { add, warn, filename } = context;
  const lines = splitLines(text);
  stats.lines = lines.length;
  const consumed = new Set();
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (index + 1 < lines.length && line.includes('|') && !isTableSeparator(line)
      && isTableSeparator(lines[index + 1])) {
      const headerCells = splitTableRow(line);
      const header = detectHeaderRow(headerCells);
      if (header === null) warn('markdown-table-header-unrecognized', { line: index + 1 });
      consumed.add(index);
      consumed.add(index + 1);
      index += 2;
      while (index < lines.length && lines[index].includes('|') && !isTableSeparator(lines[index])) {
        const lineNumber = index + 1;
        harvestRow(splitTableRow(lines[index]), {
          header,
          line: lineNumber,
          source: sourceFor(filename, undefined, lineNumber),
          add,
        });
        consumed.add(index);
        index += 1;
      }
      continue;
    }
    index += 1;
  }
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    if (consumed.has(lineIndex)) continue;
    const trimmed = lines[lineIndex].trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
    const deBulleted = trimmed.replace(/^(?:[-*+]|\d+[.)])\s+/u, '');
    if (deBulleted.length === 0) continue;
    const lineNumber = lineIndex + 1;
    add(deBulleted, {
      strict: true,
      line: lineNumber,
      source: sourceFor(filename, undefined, lineNumber),
    });
  }
}

// ---------------------------------------------------------------------------
// Observation JSONL
// ---------------------------------------------------------------------------

const SEVERITY_ALIASES = new Map([
  ['critical', 'critical'], ['crit', 'critical'],
  ['high', 'high'], ['medium', 'medium'], ['moderate', 'medium'], ['med', 'medium'],
  ['low', 'low'], ['info', 'info'], ['informational', 'info'], ['none', 'info'],
]);

const RECORD_TYPES = new Set(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'PTR', 'SOA']);

/** Explicit header names that must never be copied into stored attributes. */
const SENSITIVE_HEADER_RE = /(^|[-_])(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|token|secret|password|session|csrf|xsrf)([-_]|$)/iu;

/** Bound a string for observation attributes. */
function obsString(value, max = 1000) {
  return typeof value === 'string' ? truncate(value, max) : undefined;
}

/** Sanitize arbitrary observation attributes: strip secrets, bound values. */
function sanitizeObservationAttrs(value) {
  if (!isPlainObject(value)) return {};
  const stripped = stripSecrets(value);
  if (!isPlainObject(stripped)) return {};
  const out = {};
  for (const [key, entry] of Object.entries(stripped)) {
    if (entry === undefined) continue;
    if (Object.keys(out).length >= MAX_ATTRIBUTE_KEYS) break;
    const name = truncate(String(key), 100);
    if (SECRET_KEY_PATTERN.test(name)) continue;
    const bounded = boundAttrValue(entry);
    if (bounded !== undefined) out[name] = bounded;
  }
  return out;
}

/** Validate timestamp input deterministically (never falls back to clock time). */
function observationTimestamp(input) {
  const value = input.ts ?? input.timestamp ?? input.time;
  if (typeof value === 'number' && Number.isFinite(value)) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Date.parse(value.trim());
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : undefined;
  }
  return undefined;
}

/** Resolve a host-ish observation field to `{kind, key, attrs}`. */
function resolveObservationHost(value) {
  if (typeof value !== 'string' || value.trim().length === 0) return undefined;
  const record = classifyToken(value, { strict: false });
  if (record === null) return undefined;
  if (record.kind === 'ip') return { kind: 'ip', key: record.canonical, attrs: record.attrs };
  if (record.kind === 'host' || record.kind === 'domain') {
    return { kind: record.kind, key: record.canonical, attrs: record.attrs };
  }
  if (record.kind === 'url') {
    return { kind: 'host', key: record.attrs.host, attrs: { fqdn: record.attrs.host } };
  }
  return undefined;
}

/** Pick `http`/`https` for an observation without a scheme. */
function inferHttpScheme(input) {
  const explicit = typeof input.scheme === 'string'
    ? input.scheme.trim().toLowerCase().replace(/:$/u, '')
    : undefined;
  if (explicit === 'http' || explicit === 'https') return explicit;
  if (input.tls === true) return 'https';
  if (input.tls === false) return 'http';
  const port = normalizePortNumber(input.port ?? input.portNumber);
  if (port === 80) return 'http';
  return 'https';
}

/** Validate a status code field. */
function observationStatus(value, warn, lineNumber) {
  if (value === undefined || value === null) return undefined;
  const numeric = typeof value === 'number' ? value : Number(value);
  if (Number.isInteger(numeric) && numeric >= 100 && numeric <= 599) return numeric;
  warn(lineNumber, 'http-invalid-status', { raw: truncate(String(value), 80) });
  return undefined;
}

/** Sanitize HTTP headers: cookie/authorization/token headers never survive. */
function sanitizeHeaders(headers) {
  if (!isPlainObject(headers)) return undefined;
  const out = {};
  let count = 0;
  for (const [key, value] of Object.entries(headers)) {
    if (count >= 40) break;
    if (SENSITIVE_HEADER_RE.test(key) || SECRET_KEY_PATTERN.test(key)) continue;
    const name = key.toLowerCase().slice(0, 100);
    if (typeof value === 'string') out[name] = truncate(value, 500);
    else if (Array.isArray(value) && value.every((entry) => typeof entry === 'string')) {
      out[name] = value.slice(0, 10).map((entry) => truncate(entry, 300));
    } else continue;
    count += 1;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** Normalize a severity string with aliases. */
function observationSeverity(value, warn, lineNumber) {
  if (typeof value !== 'string' || value.trim().length === 0) return 'info';
  const key = value.trim().toLowerCase().replace(/[\s-]+/gu, '_');
  const mapped = SEVERITY_ALIASES.get(key);
  if (mapped !== undefined && SEVERITIES.includes(mapped)) return mapped;
  warn(lineNumber, 'unknown-severity', { raw: truncate(value, 40) });
  return 'info';
}

/** Normalize a finding status string. */
function observationFindingStatus(value, warn, lineNumber) {
  if (typeof value !== 'string' || value.trim().length === 0) return 'candidate';
  const status = value.trim().toLowerCase();
  if (FINDING_STATUSES.includes(status)) return status;
  warn(lineNumber, 'unknown-finding-status', { raw: truncate(value, 40) });
  return 'candidate';
}

/** Validate and canonicalize an array of IP strings. */
function observationAddresses(value, warn, lineNumber, field = 'addresses') {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const entry of value.slice(0, 200)) {
    if (typeof entry !== 'string') continue;
    const parsed = parseIp(entry.trim());
    if (parsed === undefined) {
      warn(lineNumber, 'invalid-ip-address', { raw: entry, field });
      continue;
    }
    out.push(parsed.canonical);
  }
  return uniqueStrings(out);
}

/** Build the `service` observation record. */
function observationService(input, warn, lineNumber) {
  const target = isPlainObject(input.target) ? input.target : {};
  const hostRecord = resolveObservationHost(
    (typeof input.host === 'string' ? input.host : undefined)
      ?? (typeof input.hostname === 'string' ? input.hostname : undefined)
      ?? (typeof target.host === 'string' ? target.host : undefined)
      ?? (typeof input.target === 'string' ? input.target : undefined),
  );
  if (hostRecord === undefined) {
    warn(lineNumber, 'service-missing-host');
    return undefined;
  }
  const port = normalizePortNumber(input.port ?? target.port ?? hostRecord.attrs?.port);
  if (port === undefined) {
    warn(lineNumber, 'service-missing-port');
    return undefined;
  }
  const portNumber = port;
  const attrs = {
    host: hostRecord.key,
    port: portNumber,
    ...(typeof input.protocol === 'string' ? { protocol: truncate(input.protocol.trim().toLowerCase(), 20) } : {}),
    ...(typeof input.service === 'string' ? { service: truncate(input.service.trim(), 80) } : {}),
    ...(typeof input.product === 'string' ? { product: truncate(input.product.trim(), 120) } : {}),
    ...(typeof input.version === 'string' ? { version: truncate(input.version.trim(), 60) } : {}),
    ...(typeof input.banner === 'string' ? { banner: truncate(input.banner, 500) } : {}),
    ...(typeof input.state === 'string' ? { state: truncate(input.state.trim().toLowerCase(), 20) } : {}),
    ...(typeof input.tls === 'boolean' ? { tls: input.tls } : {}),
  };
  const mirror = {
    ...(hostRecord.kind === 'ip' ? { ip: hostRecord.key } : { host: hostRecord.key }),
    port: portNumber,
    transport: typeof input.transport === 'string' && input.transport.trim().toLowerCase() === 'udp' ? 'udp' : 'tcp',
    ...(attrs.protocol !== undefined ? { protocol: attrs.protocol } : {}),
    ...(attrs.banner !== undefined ? { banner: attrs.banner } : {}),
    ...(attrs.state !== undefined ? { state: attrs.state } : {}),
    ...(attrs.tls !== undefined ? { tls: attrs.tls } : {}),
  };
  return finishObservation('service', `${hostRecord.key}:${portNumber}`, `${hostRecord.key}:${portNumber}`, attrs, input, mirror);
}

/** Build the `http` observation record. */
function observationHttp(input, warn, lineNumber) {
  const rawUrl = typeof input.url === 'string' && input.url.trim().length > 0
    ? input.url.trim()
    : typeof input.uri === 'string' && input.uri.trim().length > 0 ? input.uri.trim() : undefined;
  let candidate = rawUrl;
  if (candidate === undefined) {
    const hostRecord = resolveObservationHost(
      (typeof input.host === 'string' ? input.host : undefined)
        ?? (isPlainObject(input.target) && typeof input.target.host === 'string' ? input.target.host : undefined),
    );
    if (hostRecord === undefined) {
      warn(lineNumber, 'http-missing-url');
      return undefined;
    }
    const port = normalizePortNumber(input.port ?? (isPlainObject(input.target) ? input.target.port : undefined));
    candidate = `${inferHttpScheme(input)}://${hostRecord.key}${port === undefined ? '' : `:${port}`}`;
  }
  const urlRecord = canonicalizeUrl(candidate);
  if (urlRecord === undefined) {
    warn(lineNumber, 'http-invalid-url', { raw: candidate });
    return undefined;
  }
  const status = observationStatus(input.status ?? input.statusCode ?? input.code, warn, lineNumber);
  const title = obsString(input.title, 300);
  const server = obsString(input.server ?? input.serverHeader, 200);
  const techs = Array.isArray(input.techs)
    ? uniqueStrings(input.techs.slice(0, 50).filter((entry) => typeof entry === 'string')).map((entry) => truncate(entry, 80))
    : Array.isArray(input.technologies)
      ? uniqueStrings(input.technologies.slice(0, 50).filter((entry) => typeof entry === 'string')).map((entry) => truncate(entry, 80))
      : [];
  const headers = sanitizeHeaders(input.headers);
  let redirects;
  if (Array.isArray(input.redirects)) {
    redirects = input.redirects.slice(0, 10)
      .map((entry) => (typeof entry === 'string' ? canonicalizeUrl(entry) : undefined))
      .filter((record) => record !== undefined)
      .map((record) => record.canonical);
  }
  const lengthValue = input.contentLength ?? input.length;
  const contentLength = Number.isInteger(lengthValue) && lengthValue >= 0 ? lengthValue : undefined;
  const attrs = {
    url: urlRecord.canonical,
    host: urlRecord.attrs.host,
    scheme: urlRecord.attrs.scheme,
    ...(urlRecord.attrs.port !== undefined ? { port: urlRecord.attrs.port } : {}),
    ...(urlRecord.attrs.path !== undefined ? { path: urlRecord.attrs.path } : {}),
    ...(urlRecord.attrs.query !== undefined ? { query: urlRecord.attrs.query } : {}),
    ...(urlRecord.attrs.hasUserinfo === true ? {
      hasUserinfo: true,
      credentialHint: urlRecord.attrs.credentialHint,
    } : {}),
    ...(status !== undefined ? { status } : {}),
    ...(title !== undefined ? { title } : {}),
    ...(server !== undefined ? { server } : {}),
    ...(techs.length > 0 ? { techs } : {}),
    ...(headers !== undefined ? { headers } : {}),
    ...(contentLength !== undefined ? { contentLength } : {}),
    ...(redirects !== undefined && redirects.length > 0 ? { redirects } : {}),
  };
  const mirror = {
    url: attrs.url,
    ...(attrs.status !== undefined ? { status: attrs.status } : {}),
    ...(attrs.title !== undefined ? { title: attrs.title } : {}),
    ...(attrs.server !== undefined ? { server: attrs.server } : {}),
    ...(attrs.techs !== undefined ? { techs: attrs.techs } : {}),
    ...(attrs.headers !== undefined ? { headers: attrs.headers } : {}),
  };
  return finishObservation('http', urlRecord.canonical, urlRecord.canonical, attrs, input, mirror);
}

/** Build the `finding` observation record. */
function observationFinding(input, warn, lineNumber) {
  const title = obsString(input.title, 300);
  if (title === undefined || title.trim().length === 0) {
    warn(lineNumber, 'finding-missing-title');
    return undefined;
  }
  const cleanTitle = title.trim();
  const severity = observationSeverity(input.severity ?? input.risk, warn, lineNumber);
  const status = observationFindingStatus(input.status, warn, lineNumber);
  const subjectUrl = typeof input.url === 'string' && input.url.trim().length > 0
    ? canonicalizeUrl(input.url.trim())
    : undefined;
  const subjectHost = resolveObservationHost(
    typeof input.host === 'string' ? input.host : undefined,
  );
  let subjectKey = 'unknown';
  const attrs = { title: cleanTitle, severity, status };
  if (subjectUrl !== undefined) {
    subjectKey = subjectUrl.canonical;
    attrs.url = subjectUrl.canonical;
    attrs.host = subjectUrl.attrs.host;
  } else if (subjectHost !== undefined) {
    subjectKey = subjectHost.key;
    attrs.host = subjectHost.key;
  }
  const cve = typeof input.cve === 'string' && /^CVE-\d{4}-\d{4,7}$/iu.test(input.cve.trim())
    ? input.cve.trim().toUpperCase()
    : undefined;
  const cwe = typeof input.cwe === 'string' && /^CWE-\d{1,4}$/iu.test(input.cwe.trim())
    ? input.cwe.trim().toUpperCase()
    : undefined;
  const cvss = typeof input.cvss === 'number' && Number.isFinite(input.cvss) && input.cvss >= 0 && input.cvss <= 10
    ? input.cvss
    : undefined;
  const impact = obsString(input.impact, 1000);
  const description = obsString(input.description ?? input.detail, 2000);
  const evidence = obsString(input.evidence, 1000);
  const remediation = obsString(input.remediation ?? input.fix, 2000);
  const verification = typeof input.verification === 'string'
    && VERIFICATION_LEVELS.includes(input.verification.trim().toLowerCase())
    ? input.verification.trim().toLowerCase()
    : undefined;
  Object.assign(attrs, {
    ...(cve !== undefined ? { cve } : {}),
    ...(cwe !== undefined ? { cwe } : {}),
    ...(cvss !== undefined ? { cvss } : {}),
    ...(impact !== undefined ? { impact } : {}),
    ...(description !== undefined ? { description } : {}),
    ...(evidence !== undefined ? { evidence } : {}),
    ...(remediation !== undefined ? { remediation } : {}),
    ...(verification !== undefined ? { verification } : {}),
  });
  const key = `finding_${sha256Hex(`${cleanTitle.toLowerCase()}\u001f${subjectKey}`).slice(0, 16)}`;
  const mirror = {
    title: cleanTitle,
    severity,
    status,
    subject: subjectKey,
    ...(subjectUrl !== undefined ? { url: subjectUrl.canonical } : {}),
    ...(attrs.host !== undefined ? { host: attrs.host } : {}),
    ...(cve !== undefined ? { cve } : {}),
    ...(cwe !== undefined ? { cwe } : {}),
    ...(cvss !== undefined ? { cvss } : {}),
    ...(evidence !== undefined ? { evidence } : {}),
    ...(remediation !== undefined ? { remediation } : {}),
  };
  return finishObservation('finding', key, cleanTitle, attrs, input, mirror);
}

/** Build the `dns` observation record. */
function observationDns(input, warn, lineNumber) {
  const hostValue = typeof input.host === 'string'
    ? input.host
    : typeof input.name === 'string' ? input.name : undefined;
  const hostRecord = resolveObservationHost(hostValue);
  if (hostRecord === undefined) {
    warn(lineNumber, 'dns-missing-host');
    return undefined;
  }
  const addresses = observationAddresses(input.addresses ?? input.ips ?? input.a ?? input.aaaa, warn, lineNumber);
  const cnameRaw = typeof input.cname === 'string' ? input.cname : undefined;
  const cname = cnameRaw === undefined ? undefined : canonicalHost(cnameRaw) || undefined;
  if (cnameRaw !== undefined && cname === undefined) warn(lineNumber, 'dns-invalid-cname', { raw: cnameRaw });
  const kindProvided = typeof input.kind === 'string' && input.kind.trim().length > 0;
  let recordType = typeof input.recordType === 'string'
    ? input.recordType.trim().toUpperCase()
    : kindProvided && typeof input.type === 'string' ? input.type.trim().toUpperCase() : undefined;
  if (recordType !== undefined && !RECORD_TYPES.has(recordType)) {
    warn(lineNumber, 'dns-unknown-record-type', { raw: recordType });
    recordType = undefined;
  }
  if (recordType === undefined) {
    if (cname !== undefined) recordType = 'CNAME';
    else if (addresses.some((address) => address.includes(':'))) recordType = 'AAAA';
    else recordType = 'A';
  }
  const ttlValue = input.ttl;
  const ttl = Number.isInteger(ttlValue) && ttlValue >= 0 ? ttlValue : undefined;
  const attrs = {
    host: hostRecord.key,
    recordType,
    ...(addresses.length > 0 ? { addresses } : {}),
    ...(cname !== undefined ? { cname } : {}),
    ...(ttl !== undefined ? { ttl } : {}),
  };
  const ipv4 = addresses.filter((address) => !address.includes(':'));
  const ipv6 = addresses.filter((address) => address.includes(':'));
  const mirror = {
    host: hostRecord.key,
    a: ipv4,
    aaaa: ipv6,
    cname: cname !== undefined ? [cname] : [],
  };
  return finishObservation('dns', hostRecord.key, hostRecord.key, attrs, input, mirror);
}

/** Build the `host` observation record. */
function observationHost(input, warn, lineNumber) {
  const hostValue = typeof input.host === 'string'
    ? input.host
    : typeof input.hostname === 'string' ? input.hostname
      : typeof input.fqdn === 'string' ? input.fqdn : undefined;
  const hostRecord = resolveObservationHost(hostValue);
  if (hostRecord === undefined) {
    warn(lineNumber, 'host-missing-host');
    return undefined;
  }
  const addresses = observationAddresses(input.ips ?? input.addresses ?? input.addrs, warn, lineNumber);
  const osValue = obsString(input.os ?? input.platform, 120);
  const tags = Array.isArray(input.tags)
    ? uniqueStrings(input.tags.slice(0, 30).filter((entry) => typeof entry === 'string')).map((entry) => truncate(entry, 80))
    : [];
  let state;
  if (typeof input.state === 'string') {
    const normalized = input.state.trim().toLowerCase();
    if (['up', 'down', 'unknown'].includes(normalized)) state = normalized;
    else warn(lineNumber, 'host-unknown-state', { raw: input.state });
  }
  const attrs = {
    ...(hostRecord.kind === 'ip' ? { ip: hostRecord.key } : { fqdn: hostRecord.key }),
    ...(addresses.length > 0 ? { ips: addresses } : {}),
    ...(osValue !== undefined ? { os: osValue } : {}),
    ...(state !== undefined ? { state } : {}),
    ...(tags.length > 0 ? { tags } : {}),
  };
  const mirror = {
    host: hostRecord.key,
    ...(attrs.ips !== undefined ? { ips: attrs.ips } : {}),
    ...(attrs.os !== undefined ? { os: attrs.os } : {}),
    ...(attrs.state !== undefined ? { state: attrs.state } : {}),
    ...(attrs.tags !== undefined ? { tags: attrs.tags } : {}),
  };
  return finishObservation('host', hostRecord.key, hostRecord.key, attrs, input, mirror);
}

/** Assemble an observation record with merged user attributes and optional ts. */
function finishObservation(kind, key, label, attrs, input, mirror = {}) {
  const merged = { ...sanitizeObservationAttrs(input.attrs), ...attrs };
  const record = {
    kind,
    key,
    label: truncate(label, 300),
    attrs: merged,
    ...mirror,
  };
  const ts = observationTimestamp(input);
  if (ts !== undefined) record.ts = ts;
  const source = input.source;
  if (typeof source === 'string' && source.trim().length > 0) {
    record.attrs.source = truncate(source.trim(), 300);
  } else if (isPlainObject(source)) {
    record.attrs.source = sanitizeObservationAttrs(source);
  }
  return record;
}

/**
 * Parse observation JSONL (one JSON object per line).
 *
 * Allowed kinds: service, http, finding, dns, host. Unknown kinds produce a
 * warning instead of an error; malformed lines are skipped with a warning.
 * Secret-like keys (`password`, `token`, `cookie`, ...) are stripped from every
 * record, and HTTP cookie/authorization headers are dropped explicitly.
 *
 * @param {string} text
 * @param {{maxBytes?:number, maxLines?:number}} [opts]
 * @returns {{records:object[], warnings:{line:number, reason:string, raw?:string}[]}}
 */
export function parseObservationsJsonl(text, opts = {}) {
  const options = isPlainObject(opts) ? opts : {};
  const source = String(text ?? '');
  const bytes = byteLength(source);
  const maxBytes = Number.isFinite(options.maxBytes) && options.maxBytes > 0
    ? options.maxBytes
    : MAX_OBSERVATION_BYTES;
  if (bytes > maxBytes) invalid(`observation JSONL is ${bytes} bytes; the limit is ${maxBytes} bytes`);
  const maxLines = Number.isFinite(options.maxLines) && options.maxLines > 0 ? options.maxLines : 20000;
  const records = [];
  const warnings = [];
  const warn = (lineNumber, reason, detail = {}) => {
    if (warnings.length >= MAX_WARNINGS) return;
    const entry = { line: lineNumber, reason };
    if (detail.raw !== undefined) entry.raw = safeRaw(detail.raw);
    if (typeof detail.field === 'string') entry.field = detail.field;
    warnings.push(entry);
  };
  const lines = splitLines(source);
  const limit = Math.min(lines.length, maxLines);
  for (let index = 0; index < limit; index += 1) {
    const trimmed = lines[index].trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
    const lineNumber = index + 1;
    const parsed = safeJsonParseLine(trimmed);
    if (parsed === undefined) {
      warn(lineNumber, 'invalid-json', { raw: trimmed });
      continue;
    }
    if (!isPlainObject(parsed)) {
      warn(lineNumber, 'not-an-object', { raw: trimmed });
      continue;
    }
    const kind = observationKindOf(parsed);
    if (kind === undefined) {
      warn(lineNumber, 'unknown-kind', { raw: parsed.kind ?? parsed.type ?? 'missing' });
      continue;
    }
    let record;
    if (kind === 'service') record = observationService(parsed, warn, lineNumber);
    else if (kind === 'http') record = observationHttp(parsed, warn, lineNumber);
    else if (kind === 'finding') record = observationFinding(parsed, warn, lineNumber);
    else if (kind === 'dns') record = observationDns(parsed, warn, lineNumber);
    else record = observationHost(parsed, warn, lineNumber);
    if (record !== undefined) records.push(record);
  }
  if (lines.length > limit) warn(limit + 1, 'line-limit', { raw: `truncated at ${limit} lines` });
  return { records, warnings };
}
