/**
 * Strict IP / CIDR canonicalization, containment and minimal-prefix merging.
 *
 * Pure functions only (no DNS, no network), so the unit tests can cover the
 * scope guard and the asset dedupe path without a live Host.
 */
import { invalid } from './util.js';

const V4_BITS = 32;
const V6_BITS = 128;
const V4_MAX = (1n << 32n) - 1n;
const V6_MAX = (1n << 128n) - 1n;

/** Parse a strict dotted-quad IPv4 address; leading zeros are rejected. */
export function parseIpv4(text) {
  if (typeof text !== 'string') return undefined;
  const parts = text.trim().split('.');
  if (parts.length !== 4) return undefined;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/u.test(part)) return undefined;
    if (part.length > 1 && part.startsWith('0')) return undefined;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return undefined;
    value = (value << 8n) | BigInt(octet);
  }
  return {
    version: 4,
    value,
    canonical: bigIntToIpv4(value),
    mapped: undefined,
  };
}

/** Format an IPv4 BigInt. */
export function bigIntToIpv4(value) {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 0xffn)).join('.');
}

/** Expand an embedded IPv4 tail into two IPv6 groups, or return undefined. */
function ipv4TailToGroups(part) {
  const parsed = parseIpv4(part);
  if (parsed === undefined) return undefined;
  return [Number((parsed.value >> 16n) & 0xffffn), Number(parsed.value & 0xffffn)];
}

/**
 * Parse an IPv6 address. Accepts a zone suffix (`fe80::1%en0`) but drops it
 * from the canonical form, brackets, and an IPv4 tail. Rejects `::` more than
 * once and group counts that contradict the compression.
 */
export function parseIpv6(text) {
  if (typeof text !== 'string') return undefined;
  let input = text.trim().toLowerCase();
  if (input.startsWith('[') && input.endsWith(']')) input = input.slice(1, -1);
  const zone = input.indexOf('%');
  if (zone >= 0) input = input.slice(0, zone);
  if (input.length === 0) return undefined;
  if (input.includes(':::')) return undefined;

  const compression = input.indexOf('::');
  const hasCompression = compression >= 0;
  if (hasCompression && input.indexOf('::', compression + 2) >= 0) return undefined;

  const leftText = hasCompression ? input.slice(0, compression) : input;
  const rightText = hasCompression ? input.slice(compression + 2) : '';
  const leftParts = leftText.length === 0 ? [] : leftText.split(':');
  const rightParts = rightText.length === 0 ? [] : rightText.split(':');

  const expand = (parts) => {
    const groups = [];
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index];
      if (part.length === 0) return undefined;
      if (part.includes('.')) {
        if (index !== parts.length - 1) return undefined;
        const pair = ipv4TailToGroups(part);
        if (pair === undefined) return undefined;
        groups.push(...pair);
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/u.test(part)) return undefined;
      groups.push(Number.parseInt(part, 16));
    }
    return groups;
  };

  const left = expand(leftParts);
  const right = expand(rightParts);
  if (left === undefined || right === undefined) return undefined;

  const explicit = left.length + right.length;
  if (hasCompression) {
    if (explicit > 7) return undefined;
  } else if (explicit !== 8) {
    return undefined;
  }

  const groups = hasCompression
    ? [...left, ...Array.from({ length: 8 - explicit }, () => 0), ...right]
    : [...left, ...right];
  if (groups.length !== 8) return undefined;

  let value = 0n;
  for (const group of groups) value = (value << 16n) | BigInt(group);

  const mapped = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0
    && groups[4] === 0 && groups[5] === 0xffff
    ? bigIntToIpv4(value & V4_MAX)
    : undefined;

  return {
    version: 6,
    value,
    canonical: bigIntToIpv6(value),
    mapped,
    groups,
  };
}

/** Format an IPv6 BigInt in RFC 5952 canonical form (longest zero run compressed). */
export function bigIntToIpv6(value) {
  const groups = [];
  for (let shift = 112n; shift >= 0n; shift -= 16n) groups.push(Number((value >> shift) & 0xffffn));
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  for (let index = 0; index <= groups.length; index += 1) {
    const isZero = index < groups.length && groups[index] === 0;
    if (isZero) {
      if (runStart < 0) runStart = index;
    } else if (runStart >= 0) {
      const length = index - runStart;
      if (length > bestLength && length >= 2) {
        bestStart = runStart;
        bestLength = length;
      }
      runStart = -1;
    }
  }
  const hex = groups.map((group) => group.toString(16));
  if (bestStart < 0) return hex.join(':');
  const before = hex.slice(0, bestStart).join(':');
  const after = hex.slice(bestStart + bestLength).join(':');
  if (before.length === 0 && after.length === 0) return '::';
  if (before.length === 0) return `::${after}`;
  if (after.length === 0) return `${before}::`;
  return `${before}::${after}`;
}

/** Parse either family. */
export function parseIp(text) {
  const ipv4 = parseIpv4(text);
  if (ipv4 !== undefined) return ipv4;
  return parseIpv6(text);
}

/** Canonical IP string, or undefined when invalid. */
export function canonicalIp(text) {
  const parsed = parseIp(text);
  return parsed?.canonical;
}

/** Whether a string is a valid IP literal. */
export function isIp(text) {
  return parseIp(text) !== undefined;
}

/**
 * Parse a CIDR block. Host bits are forced to zero.
 * A bare IP is not accepted here; callers decide whether /32 or /128 applies.
 */
export function parseCidr(text) {
  if (typeof text !== 'string') return undefined;
  const trimmed = text.trim();
  const slash = trimmed.lastIndexOf('/');
  if (slash < 0) return undefined;
  const addressText = trimmed.slice(0, slash);
  const prefixText = trimmed.slice(slash + 1);
  if (!/^\d{1,3}$/u.test(prefixText)) return undefined;
  const prefix = Number(prefixText);
  const parsed = parseIp(addressText);
  if (parsed === undefined) return undefined;
  const bits = parsed.version === 4 ? V4_BITS : V6_BITS;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return undefined;
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
  const network = parsed.value & mask;
  return {
    version: parsed.version,
    network,
    prefix,
    canonical: `${parsed.version === 4 ? bigIntToIpv4(network) : bigIntToIpv6(network)}/${prefix}`,
    bits,
  };
}

/** Whether a parsed/typed IP falls inside a parsed CIDR. */
export function cidrContainsIp(cidr, ip) {
  const parsedCidr = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  const parsedIp = typeof ip === 'string' ? parseIp(ip) : ip;
  if (parsedCidr === undefined || parsedIp === undefined) return false;
  if (parsedCidr.version !== parsedIp.version) {
    // An IPv4-mapped IPv6 address still belongs to the mapped IPv4 block.
    if (parsedIp.version === 6 && parsedIp.mapped !== undefined) {
      const mapped = parseIpv4(parsedIp.mapped);
      return mapped !== undefined && cidrContainsIp(parsedCidr, mapped);
    }
    return false;
  }
  const bits = parsedCidr.bits;
  const mask = parsedCidr.prefix === 0 ? 0n : ((1n << BigInt(parsedCidr.prefix)) - 1n) << BigInt(bits - parsedCidr.prefix);
  return (parsedIp.value & mask) === parsedCidr.network;
}

/** Whether CIDR `outer` fully contains CIDR `inner`. */
export function cidrContainsCidr(outer, inner) {
  const a = typeof outer === 'string' ? parseCidr(outer) : outer;
  const b = typeof inner === 'string' ? parseCidr(inner) : inner;
  if (a === undefined || b === undefined || a.version !== b.version) return false;
  if (b.prefix < a.prefix) return false;
  const mask = a.prefix === 0 ? 0n : ((1n << BigInt(a.prefix)) - 1n) << BigInt(a.bits - a.prefix);
  return (b.network & mask) === a.network;
}

/** Inclusive BigInt range of a parsed CIDR. */
export function cidrRange(cidr) {
  const size = 1n << BigInt(cidr.bits - cidr.prefix);
  return { start: cidr.network, end: cidr.network + size - 1n };
}

/** Number of trailing zero bits in a positive BigInt (0 => 128). */
function trailingZeros(value, bits) {
  if (value === 0n) return bits;
  let count = 0;
  let current = value;
  while ((current & 1n) === 0n && count < bits) {
    current >>= 1n;
    count += 1;
  }
  return count;
}

/** Number of bits required to represent `value` (0 => 0). */
function bitLength(value) {
  if (value <= 0n) return 0;
  return value.toString(2).length;
}

/**
 * Split one inclusive IP range into the minimal set of aligned CIDR blocks.
 * @returns {{version:number, network:bigint, prefix:number, canonical:string, bits:number}[]}
 */
export function rangeToCidrs(startInput, endInput, version) {
  let start = BigInt(startInput);
  let end = BigInt(endInput);
  const bits = version === 4 ? V4_BITS : V6_BITS;
  const maxValue = version === 4 ? V4_MAX : V6_MAX;
  if (start < 0n || end > maxValue || start > end) return [];
  const blocks = [];
  while (start <= end) {
    const align = trailingZeros(start, bits);
    const remaining = end - start + 1n;
    const availableBits = Math.max(0, bitLength(remaining) - 1);
    const sizeBits = Math.min(align, availableBits);
    const blockSize = 1n << BigInt(sizeBits);
    const prefix = bits - sizeBits;
    blocks.push({
      version,
      network: start,
      prefix,
      bits,
      canonical: `${version === 4 ? bigIntToIpv4(start) : bigIntToIpv6(start)}/${prefix}`,
    });
    start += blockSize;
  }
  return blocks;
}

/**
 * Merge overlapping and adjacent CIDRs into the minimal covering prefix set.
 * IPv4 and IPv6 never mix. Input order does not affect the result.
 */
export function mergeCidrs(values, { maxInput = 100000, maxOutput = 10000 } = {}) {
  const list = Array.from(values ?? []);
  if (list.length > maxInput) invalid(`too many CIDRs: ${list.length} > ${maxInput}`);
  const parsed = new Map();
  for (const value of list) {
    const cidr = typeof value === 'string' ? parseCidr(value) : parseCidr(value?.canonical ?? '');
    if (cidr === undefined) invalid(`invalid CIDR: ${String(value)}`);
    parsed.set(`${cidr.version}:${cidr.canonical}`, cidr);
  }
  const byVersion = { 4: [], 6: [] };
  for (const cidr of parsed.values()) {
    const range = cidrRange(cidr);
    byVersion[cidr.version].push({ start: range.start, end: range.end });
  }
  const merged = [];
  for (const version of [4, 6]) {
    const ranges = byVersion[version].sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
    let current;
    for (const range of ranges) {
      if (current === undefined) {
        current = { start: range.start, end: range.end };
        continue;
      }
      if (range.start <= current.end + 1n) {
        if (range.end > current.end) current.end = range.end;
      } else {
        merged.push(...rangeToCidrs(current.start, current.end, version));
        current = { start: range.start, end: range.end };
      }
    }
    if (current !== undefined) merged.push(...rangeToCidrs(current.start, current.end, version));
  }
  if (merged.length > maxOutput) invalid(`CIDR merge produced ${merged.length} blocks > ${maxOutput}`);
  return merged
    .map((block) => ({ ...block, canonical: `${block.version === 4 ? bigIntToIpv4(block.network) : bigIntToIpv6(block.network)}/${block.prefix}` }))
    .sort((a, b) => (a.version - b.version) || (a.network < b.network ? -1 : a.network > b.network ? 1 : 0) || (a.prefix - b.prefix));
}

/** IPv4-mapped IPv6 (or a plain IP) as an IPv4 parsed value when possible. */
export function asIpv4(ip) {
  const parsed = typeof ip === 'string' ? parseIp(ip) : ip;
  if (parsed === undefined) return undefined;
  if (parsed.version === 4) return parsed;
  if (parsed.mapped !== undefined) return parseIpv4(parsed.mapped);
  return undefined;
}

/** Whether an IP is loopback. */
export function isLoopbackIp(ip) {
  const parsed = typeof ip === 'string' ? parseIp(ip) : ip;
  if (parsed === undefined) return false;
  if (parsed.version === 4) return cidrContainsIp(parseCidr('127.0.0.0/8'), parsed);
  if (parsed.mapped !== undefined) return isLoopbackIp(parseIpv4(parsed.mapped));
  return parsed.value === 1n || parsed.value === 0n;
}

/** Whether an IP is in a private, link-local, CGNAT or ULA range. */
export function isPrivateIp(ip) {
  const parsed = typeof ip === 'string' ? parseIp(ip) : ip;
  if (parsed === undefined) return false;
  if (parsed.version === 4) {
    return ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10', '0.0.0.0/8']
      .some((block) => cidrContainsIp(parseCidr(block), parsed));
  }
  if (parsed.mapped !== undefined) return isPrivateIp(parseIpv4(parsed.mapped));
  return ['fc00::/7', 'fe80::/10', '::1/128', '::/128'].some((block) => cidrContainsIp(parseCidr(block), parsed));
}

/** Whether a parsed/typed IP is IPv4-mapped. */
export function isMappedIpv6(ip) {
  const parsed = typeof ip === 'string' ? parseIp(ip) : ip;
  return parsed?.version === 6 && parsed.mapped !== undefined;
}

/** Canonicalize an IP or CIDR or return undefined. */
export function canonicalIpOrCidr(text) {
  if (typeof text !== 'string') return undefined;
  if (text.includes('/')) return parseCidr(text)?.canonical;
  return canonicalIp(text);
}

/** Whether a string is a CIDR. */
export function isCidr(text) {
  return parseCidr(text) !== undefined;
}

/** Human-readable range of a CIDR. */
export function cidrSize(cidr) {
  const parsed = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  if (parsed === undefined) return 0n;
  return 1n << BigInt(parsed.bits - parsed.prefix);
}
