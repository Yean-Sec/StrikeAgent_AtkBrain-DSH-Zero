/**
 * Authorization-scope normalization and matching.
 *
 * A scope is a pair of allow/deny lists. Deny always wins, a port restriction
 * on the matching allow entry is enforced, and a target is only actionable
 * when an allow entry matches the hostname/URL or one of its resolved IPs.
 */
import { domainToASCII } from 'node:url';

import { canonicalIp, cidrContainsCidr, cidrContainsIp, isCidr, parseCidr } from './cidr.js';
import { invalid, isPlainObject, uniqueStrings } from './util.js';

const TYPES = new Set(['domain', 'host', 'ip', 'cidr', 'url']);
const TYPE_ALIASES = {
  host: 'host',
  hostname: 'host',
  fqdn: 'host',
  domain: 'domain',
  dns: 'domain',
  ip: 'ip',
  ipv4: 'ip',
  ipv6: 'ip',
  cidr: 'cidr',
  network: 'cidr',
  subnet: 'cidr',
  url: 'url',
  uri: 'url',
  origin: 'url',
  website: 'url',
};
const NAMED_PORTS = {
  http: 80,
  www: 80,
  https: 443,
  ssl: 443,
  ssh: 22,
  dns: 53,
  ftp: 21,
  smtp: 25,
  rdp: 3389,
  mysql: 3306,
  redis: 6379,
};
const ENGAGEMENT_MODES = ['view', 'collect', 'validate', 'intrusive'];

/**
 * Map an operator or model mode label onto the four engagement postures.
 * A pentest authorization is intrusive. Unknown labels still fail closed.
 */
export function normalizeEngagementMode(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim().toLowerCase().replace(/[\s_]+/gu, '-');
  if (text.length === 0) return undefined;
  if (ENGAGEMENT_MODES.includes(text)) return text;
  if (['read', 'readonly', 'read-only', 'passive'].includes(text)) return 'view';
  if (['recon', 'reconnaissance', 'enumerate', 'enumeration', 'discovery'].includes(text)) return 'collect';
  if (['verify', 'verification', 'check'].includes(text)) return 'validate';
  if (/(?:^|-)(?:pentest|pen-test|penetration|intrusive|exploit|attack)(?:-|$)/u.test(text)) return 'intrusive';
  invalid(`mode must be one of ${ENGAGEMENT_MODES.join(', ')}; "${String(value).slice(0, 80)}" is not a recognized mode`);
  return undefined;
}

/** Lowercase + IDNA + trailing-dot canonical hostname. */
export function canonicalHost(host) {
  let text = String(host ?? '').trim().toLowerCase();
  if (text.startsWith('*.')) text = text.slice(2);
  text = text.replace(/\.+$/u, '');
  if (text.length === 0) return '';
  try {
    const ascii = domainToASCII(text);
    if (typeof ascii === 'string' && ascii.length > 0) text = ascii.toLowerCase();
  } catch {
    // domainToASCII throws on some malformed input; the original text is kept
    // so the matcher can still reject it rather than silently widening scope.
  }
  return text;
}

/** Canonical URL origin (`scheme://host[:port]`) or undefined. */
export function canonicalOrigin(input) {
  if (typeof input !== 'string' || input.trim().length === 0) return undefined;
  try {
    const url = new URL(input.includes('://') ? input : `https://${input}`);
    const port = url.port.length > 0 ? `:${url.port}` : '';
    return `${url.protocol}//${url.hostname.toLowerCase()}${port}`;
  } catch {
    return undefined;
  }
}

function scopeType(value) {
  const text = String(value ?? '').trim().toLowerCase();
  return TYPE_ALIASES[text];
}

function finishPorts(nums) {
  const ports = [...new Set(nums)].filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535).sort((a, b) => a - b);
  if (ports.length === 0) invalid('scope entry ports is empty or invalid');
  return ports;
}

function parsePortText(text) {
  const raw = String(text).trim().toLowerCase();
  if (raw.length === 0 || ['any', 'all', '*', 'none', 'unrestricted'].includes(raw)) return null;
  const nums = [];
  let unrestricted = false;
  for (const piece of raw.split(/[,;\s]+/u).map((part) => part.trim()).filter(Boolean)) {
    if (['any', 'all', '*'].includes(piece)) {
      unrestricted = true;
      continue;
    }
    if (NAMED_PORTS[piece] !== undefined) {
      nums.push(NAMED_PORTS[piece]);
      continue;
    }
    const range = /^(\d{1,5})-(\d{1,5})$/u.exec(piece);
    if (range) {
      let start = Number(range[1]);
      let end = Number(range[2]);
      if (end < start) [start, end] = [end, start];
      if (end - start > 64) {
        unrestricted = true;
        continue;
      }
      for (let port = start; port <= end; port += 1) nums.push(port);
      continue;
    }
    if (/^\d{1,5}$/u.test(piece)) {
      nums.push(Number(piece));
      continue;
    }
    invalid(`invalid scope port "${piece.slice(0, 40)}"`);
  }
  if (nums.length === 0 && unrestricted) return null;
  return nums;
}

/**
 * Accept a port number, a numeric string, "80,443", "80-82", or a service name.
 * A blank list or an all-ports range means no port restriction.
 */
export function coerceScopePorts(value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value === 'number') return finishPorts([value]);
  if (typeof value === 'string') {
    const parsed = parsePortText(value);
    return parsed === null ? undefined : finishPorts(parsed);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return undefined;
    const nums = [];
    let unrestricted = false;
    for (const item of value) {
      if (typeof item === 'number') nums.push(item);
      else if (typeof item === 'string') {
        const parsed = parsePortText(item);
        if (parsed === null) unrestricted = true;
        else nums.push(...parsed);
      } else invalid('scope entry ports must be port numbers, a list, or a range');
    }
    if (nums.length === 0 && unrestricted) return undefined;
    return finishPorts(nums);
  }
  invalid('scope entry ports must be port numbers, a list, or a range');
  return undefined;
}

function splitHostPort(value) {
  const match = /^(.*):(\d{1,5})$/u.exec(String(value).trim());
  if (!match || match[1].includes(':')) return { host: String(value).trim(), port: undefined };
  return { host: match[1], port: Number(match[2]) };
}

/** Normalize one scope entry; throws an actionable input error when invalid. */
export function normalizeScopeEntry(entry) {
  if (!isPlainObject(entry)) invalid('scope entry must be an object with {type,value}');
  const typeName = scopeType(entry.type);
  if (typeName === undefined) invalid(`scope entry type must be one of ${[...TYPES].join(', ')}`);
  if (typeof entry.value !== 'string' || entry.value.trim().length === 0) invalid('scope entry value is empty');
  let value = entry.value.trim();
  let canonical;
  let type = typeName;
  let portFromValue;
  if (type === 'domain' || type === 'host') {
    const split = splitHostPort(value);
    value = split.host;
    portFromValue = split.port;
    canonical = canonicalHost(value);
    if (canonical.length === 0 || canonical.includes('/')) invalid(`invalid ${type} scope entry: ${entry.value}`);
    if (type === 'host' && value.startsWith('*.')) type = 'domain';
  } else if (type === 'ip') {
    canonical = canonicalIp(value);
    if (canonical === undefined) invalid(`invalid IP scope entry: ${value}`);
  } else if (type === 'cidr') {
    canonical = isCidr(value) ? parseCidr(value).canonical : undefined;
    if (canonical === undefined) invalid(`invalid CIDR scope entry: ${value}`);
  } else {
    canonical = canonicalOrigin(value);
    if (canonical === undefined) invalid(`invalid URL scope entry: ${value}`);
  }
  let ports = coerceScopePorts(entry.ports);
  if (portFromValue !== undefined && ports !== undefined) ports = finishPorts([...ports, portFromValue]);
  return {
    type,
    value: canonical,
    canonical,
    ...(ports !== undefined ? { ports } : {}),
    ...(typeof entry.note === 'string' && entry.note.trim().length > 0 ? { note: entry.note.trim() } : {}),
  };
}

/** Normalize a target descriptor used by tools and the frontier. */
export function normalizeTarget(target) {
  if (!isPlainObject(target)) invalid('target must be an object');
  const type = target.type ?? (target.ip !== undefined ? 'ip' : target.cidr !== undefined ? 'cidr' : target.host !== undefined ? 'host' : undefined);
  if (!TYPES.has(type)) invalid(`target type must be one of ${[...TYPES].join(', ')}`);
  if (type === 'ip') {
    const canonical = canonicalIp(target.ip ?? target.value);
    if (canonical === undefined) invalid(`invalid target IP: ${target.ip ?? target.value}`);
    return { type: 'ip', host: undefined, ip: canonical, cidr: undefined, port: normalizePort(target.port), ips: [canonical] };
  }
  if (type === 'cidr') {
    const cidr = parseCidr(target.cidr ?? target.value);
    if (cidr === undefined) invalid(`invalid target CIDR: ${target.cidr ?? target.value}`);
    return { type: 'cidr', host: undefined, ip: undefined, cidr: cidr.canonical, port: normalizePort(target.port), ips: [] };
  }
  if (type === 'url') {
    const origin = canonicalOrigin(target.url ?? target.value);
    if (origin === undefined) invalid(`invalid target URL: ${target.url ?? target.value}`);
    const parsed = new URL(origin);
    return {
      type: 'url',
      host: parsed.hostname.toLowerCase(),
      ip: undefined,
      cidr: undefined,
      port: normalizePort(target.port ?? (parsed.port.length > 0 ? Number(parsed.port) : undefined)),
      ips: Array.isArray(target.ips) ? uniqueStrings(target.ips.map((ip) => canonicalIp(ip)).filter(Boolean)) : [],
    };
  }
  const host = canonicalHost(target.host ?? target.value);
  if (host.length === 0) invalid(`invalid target host: ${target.host ?? target.value}`);
  return {
    type,
    host,
    ip: undefined,
    cidr: undefined,
    port: normalizePort(target.port),
    ips: Array.isArray(target.ips) ? uniqueStrings(target.ips.map((ip) => canonicalIp(ip)).filter(Boolean)) : [],
  };
}

function normalizePort(port) {
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : undefined;
}

function entryMatchesHost(entry, target) {
  if (entry.ports !== undefined && target.port !== undefined && !entry.ports.includes(target.port)) return false;
  const targetIpLiteral = typeof target.host === 'string' ? canonicalIp(target.host) : undefined;
  if (entry.type === 'ip' && targetIpLiteral !== undefined) return targetIpLiteral === entry.canonical;
  if (entry.type === 'cidr' && targetIpLiteral !== undefined) return cidrContainsIp(entry.canonical, targetIpLiteral);
  if (entry.type === 'domain') {
    const host = target.host;
    if (typeof host !== 'string') return false;
    return host === entry.canonical || host.endsWith(`.${entry.canonical}`);
  }
  if (entry.type === 'host') return target.host === entry.canonical;
  if (entry.type === 'url') {
    if (typeof target.host !== 'string') return false;
    try {
      const expected = new URL(entry.canonical);
      if (target.host !== expected.hostname.toLowerCase()) return false;
      if (entry.ports !== undefined && target.port !== undefined && !entry.ports.includes(target.port)) return false;
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

function entryMatchesIp(entry, ip) {
  if (entry.type === 'ip') return ip === entry.canonical;
  if (entry.type === 'cidr') return cidrContainsIp(entry.canonical, ip);
  // A host entry written as an IP literal is also an exact IP allow/deny.
  if (entry.type === 'host' && canonicalIp(entry.canonical) !== undefined) return canonicalIp(entry.canonical) === ip;
  return false;
}

function entryMatchesCidr(entry, cidr) {
  return entry.type === 'cidr' && (entry.canonical === cidr || cidrContainsCidr(entry.canonical, cidr));
}

function prefixLength(canonical) {
  const match = /\/(\d+)$/u.exec(String(canonical ?? ''));
  return match ? Number(match[1]) : 0;
}

/**
 * Higher rank is more specific. An exact host/IP outranks a parent domain,
 * and a longer domain suffix outranks a shorter one. Equal rank keeps deny.
 */
function matchRank(entry, target) {
  if (entryMatchesHost(entry, target) || (target.cidr !== undefined && entryMatchesCidr(entry, target.cidr))) {
    const length = String(entry.canonical ?? '').length;
    if (entry.type === 'host' || entry.type === 'url' || entry.type === 'ip') return 3000 + length;
    if (entry.type === 'domain') return (target.host === entry.canonical ? 2000 : 1000) + length;
    if (entry.type === 'cidr') return 100 + prefixLength(entry.canonical);
  }
  return null;
}

function ipRank(entry, ip) {
  if (!entryMatchesIp(entry, ip)) return null;
  if (entry.type === 'ip' || entry.type === 'host') return 3000 + String(entry.canonical).length;
  if (entry.type === 'cidr') return 100 + prefixLength(entry.canonical);
  return null;
}

function bestRank(entries, rankOf) {
  let best = null;
  let rank = -1;
  for (const entry of entries) {
    const next = rankOf(entry);
    if (next === null || next < rank) continue;
    rank = next;
    best = entry;
  }
  return best === null ? null : { entry: best, rank };
}

/**
 * Evaluate one target against a scope.
 * @returns {{allowed:boolean, reason:string, matchedAllow?:object, matchedDeny?:object, allowedIps:string[]}}
 */
export function evaluateScope(scope, targetInput) {
  const target = normalizeTarget(targetInput);
  const allow = Array.isArray(scope?.allow) ? scope.allow : [];
  const deny = Array.isArray(scope?.deny) ? scope.deny : [];
  const resolvedIps = [...new Set([...(target.ips ?? []), ...(target.ip !== undefined ? [target.ip] : [])])];

  const hostDeny = bestRank(deny, (entry) => matchRank(entry, target));
  const hostAllow = bestRank(allow, (entry) => matchRank(entry, target));
  if (hostDeny !== null && (hostAllow === null || hostDeny.rank >= hostAllow.rank)) {
    return { allowed: false, reason: `target is denied by ${hostDeny.entry.type}:${hostDeny.entry.canonical}`, matchedDeny: hostDeny.entry, allowedIps: [] };
  }

  for (const ip of resolvedIps) {
    const ipDeny = bestRank(deny, (entry) => ipRank(entry, ip));
    const ipAllow = bestRank(allow, (entry) => ipRank(entry, ip));
    if (ipDeny !== null && (ipAllow === null || ipDeny.rank >= ipAllow.rank)) {
      return { allowed: false, reason: `resolved IP ${ip} is denied by ${ipDeny.entry.type}:${ipDeny.entry.canonical}`, matchedDeny: ipDeny.entry, allowedIps: [] };
    }
  }

  if (allow.length === 0) return { allowed: false, reason: 'scope.allow is empty; set an authorized engagement scope first', allowedIps: [] };

  if (hostAllow !== null) return { allowed: true, reason: 'host/domain/url allow match', matchedAllow: hostAllow.entry, allowedIps: resolvedIps };

  const allowedIps = resolvedIps.filter((ip) => allow.some((entry) => entryMatchesIp(entry, ip)));
  if (allowedIps.length > 0) {
    return { allowed: true, reason: 'resolved IP allow match', matchedAllow: allow.find((entry) => entryMatchesIp(entry, allowedIps[0])), allowedIps };
  }

  if (target.cidr !== undefined && allow.some((entry) => entryMatchesCidr(entry, target.cidr))) {
    return { allowed: true, reason: 'cidr allow match', matchedAllow: allow.find((entry) => entryMatchesCidr(entry, target.cidr)), allowedIps: [] };
  }

  return {
    allowed: false,
    reason: resolvedIps.length > 0
      ? `no allow entry covers ${target.host ?? target.ip ?? target.cidr ?? target.type} or its ${resolvedIps.length} resolved IP(s)`
      : `no allow entry covers ${target.host ?? target.ip ?? target.cidr ?? target.type}`,
    allowedIps: [],
  };
}

/** Compact scope copy for the wire view (entries capped). */
export function scopeSummary(scope, limit = 200) {
  const allow = Array.isArray(scope?.allow) ? scope.allow.slice(0, limit) : [];
  const deny = Array.isArray(scope?.deny) ? scope.deny.slice(0, limit) : [];
  return {
    allow,
    deny,
    allowCount: Array.isArray(scope?.allow) ? scope.allow.length : 0,
    denyCount: Array.isArray(scope?.deny) ? scope.deny.length : 0,
    roe: isPlainObject(scope?.roe) ? scope.roe : {},
    updatedAt: scope?.updatedAt ?? null,
    approvedAt: scope?.approvedAt ?? null,
    approvalId: scope?.approvalId ?? null,
    empty: allow.length === 0,
  };
}

/** Whether this hostname or IP literal is inside the approved allow list. */
export function hostInScope(scope, host, ips) {
  if (!Array.isArray(scope?.allow) || scope.allow.length === 0) return true;
  const name = canonicalHost(host);
  if (name.length === 0) return false;
  const literal = canonicalIp(name);
  try {
    if (literal !== undefined) return evaluateScope(scope, { type: 'ip', ip: literal }).allowed;
    const resolved = Array.isArray(ips) ? ips.map((ip) => canonicalIp(ip)).filter(Boolean) : [];
    return evaluateScope(scope, { type: 'host', host: name, ...(resolved.length > 0 ? { ips: resolved } : {}) }).allowed;
  } catch {
    return false;
  }
}

/**
 * A domain stays with the engagement when it is an allow entry, a child of an
 * allowed domain, or the parent zone of an allowed host. A one-label suffix
 * such as `com` is not a zone.
 */
export function domainInScope(scope, domain) {
  if (!Array.isArray(scope?.allow) || scope.allow.length === 0) return true;
  const name = canonicalHost(domain);
  if (name.length === 0 || !name.includes('.')) return false;
  for (const entry of scope.allow) {
    if (!isPlainObject(entry)) continue;
    if (entry.type === 'domain') {
      const zone = canonicalHost(entry.canonical ?? entry.value);
      if (zone.length > 0 && (name === zone || name.endsWith(`.${zone}`))) return true;
    }
    let host = '';
    if (entry.type === 'host') host = canonicalHost(entry.canonical ?? entry.value);
    else if (entry.type === 'url') {
      try { host = canonicalHost(new URL(entry.canonical ?? entry.value).hostname); } catch { host = ''; }
    }
    if (host.length > 0 && (host === name || host.endsWith(`.${name}`))) return true;
  }
  return false;
}
