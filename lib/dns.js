/**
 * DNS resolution with an injectable implementation.
 *
 * `createResolver({servers, timeoutMs, impl})` returns a resolver whose
 * `query`/`resolveHost`/`apexExists` methods never throw for protocol-level
 * failures: they map NXDOMAIN, SERVFAIL, timeouts and transport errors onto a
 * small status vocabulary so callers (wildcard probing, the dns tool) can make
 * decisions without parsing platform error codes.
 *
 * Tests inject a fake `impl` with resolve4/resolve6/resolveCname/resolveNs/
 * resolveSoa methods; production uses `node:dns/promises`. Every query is
 * bounded by a per-attempt timeout and retried at least once for transient
 * failures.
 */
import { Resolver as DnsResolver } from 'node:dns/promises';

import { canonicalHost } from './scope.js';
import { assertNetworkAllowed } from './socks.js';
import { InputError, sleep, withTimeout } from './util.js';

/** Supported record types and the resolver method used for each. */
export const DNS_QUERY_TYPES = Object.freeze({
  A: 'resolve4',
  AAAA: 'resolve6',
  CNAME: 'resolveCname',
  NS: 'resolveNs',
  SOA: 'resolveSoa',
});

const TRANSIENT_STATUSES = new Set(['timeout', 'servfail', 'error']);

/** First 200 chars of an error message, never the raw error object. */
function describeError(error) {
  const message = String(error?.message ?? error ?? 'unknown error').replace(/\s+/gu, ' ').trim();
  return message.length > 200 ? `${message.slice(0, 199)}\u2026` : message;
}

/**
 * Map a Node DNS rejection onto the resolver status vocabulary.
 * @returns {{status:'ok'|'nxdomain'|'servfail'|'timeout'|'error', empty?:boolean}}
 */
export function classifyDnsError(error) {
  const code = String(error?.code ?? '').toUpperCase();
  const errno = Number(error?.errno);
  if (code === 'ENOTFOUND' || code === 'NXDOMAIN' || code === 'EAI_NONAME') return { status: 'nxdomain' };
  if (code === 'ENODATA' || code === 'EAI_NODATA' || errno === -3001) return { status: 'ok', empty: true };
  if (code === 'ETIMEOUT' || code === 'ETIMEDOUT' || code === 'EAI_AGAIN' || errno === -3007) return { status: 'timeout' };
  if (code === 'SERVFAIL' || code === 'ESERVFAIL' || errno === -3005) return { status: 'servfail' };
  if (/timed out|timeout/iu.test(String(error?.message ?? ''))) return { status: 'timeout' };
  if (code === 'ECONNREFUSED' || code === 'ECONNRESET' || errno === -3002) return { status: 'error' };
  if (code === 'EBADNAME' || code === 'EFORMERR' || code === 'EBADRESP' || code === 'EREFUSED') return { status: 'error' };
  return { status: 'error' };
}

/** Normalize whatever an implementation returns into an array of strings. */
export function normaliseAnswers(type, value) {
  const list = Array.isArray(value) ? value : value === undefined || value === null ? [] : [value];
  const answers = [];
  for (const entry of list) {
    if (typeof entry === 'string') {
      const text = entry.trim().replace(/\.+$/u, '');
      if (text.length > 0) answers.push(text);
      continue;
    }
    if (typeof entry === 'number') {
      answers.push(String(entry));
      continue;
    }
    if (entry !== null && typeof entry === 'object') {
      if (typeof entry.nsname === 'string') answers.push(entry.nsname.trim().replace(/\.+$/u, ''));
      else if (typeof entry.address === 'string') answers.push(entry.address.trim());
      else if (typeof entry.value === 'string') answers.push(entry.value.trim());
    }
  }
  return [...new Set(answers)];
}

/** Build the production DNS implementation around `node:dns/promises`. */
function createRealImpl(servers, timeoutMs) {
  const resolver = new DnsResolver({ timeout: Math.max(1, Math.floor(timeoutMs)), tries: 1 });
  if (servers.length > 0) {
    try {
      resolver.setServers(servers);
    } catch (error) {
      throw new InputError(`invalid DNS server list ${JSON.stringify(servers)}: ${describeError(error)}`, 'ATK_DNS_SERVERS');
    }
  }
  return {
    resolve4: (name) => resolver.resolve4(name),
    resolve6: (name) => resolver.resolve6(name),
    resolveCname: (name) => resolver.resolveCname(name),
    resolveNs: (name) => resolver.resolveNs(name),
    resolveSoa: (name) => resolver.resolveSoa(name),
  };
}

/**
 * Create a resolver.
 *
 * @param {object} [options]
 * @param {string[]} [options.servers] DNS servers (`ip` or `ip:port`); empty = system resolvers
 * @param {number} [options.timeoutMs] per-attempt timeout (default 3000)
 * @param {number} [options.retries] extra attempts after the first (default 1)
 * @param {object|null} [options.impl] fake implementation for tests
 * @param {boolean} [options.offline] offline guard (also honoured via PENTEST_OFFLINE)
 */
export function createResolver(options = {}) {
  const timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0 ? Math.floor(options.timeoutMs) : 3000;
  const retries = Number.isInteger(options.retries) && options.retries >= 0 ? Math.min(options.retries, 5) : 1;
  const servers = Array.isArray(options.servers)
    ? options.servers.map((server) => (typeof server === 'string' ? server.trim() : '')).filter((server) => server.length > 0)
    : [];
  const offline = options.offline === true;
  const impl = options.impl ?? createRealImpl(servers, timeoutMs);

  /**
   * Run one DNS query with per-attempt timeout and retries.
   * @returns {Promise<{status:'ok'|'nxdomain'|'servfail'|'timeout'|'error', answers:string[], error?:string}>}
   */
  async function query(input, type, queryOptions = {}) {
    const name = canonicalHost(input);
    if (name.length === 0) return { status: 'error', answers: [], error: 'DNS name is empty' };
    const recordType = String(type ?? '').trim().toUpperCase();
    const method = DNS_QUERY_TYPES[recordType];
    if (method === undefined) {
      return { status: 'error', answers: [], error: `unsupported DNS record type "${String(type)}"` };
    }
    // Security guard: offline mode must stop non-loopback resolution before any
    // socket/DNS packet leaves the process.
    assertNetworkAllowed(name, { offline }, 'resolve');

    const attemptTimeout = Number.isFinite(queryOptions.timeoutMs) && queryOptions.timeoutMs > 0
      ? Math.floor(queryOptions.timeoutMs)
      : timeoutMs;
    const attempts = Number.isInteger(queryOptions.retries) && queryOptions.retries >= 0
      ? Math.min(queryOptions.retries, 5) + 1
      : retries + 1;

    let last = { status: 'error', answers: [], error: 'DNS query was not attempted' };
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (queryOptions.signal?.aborted) {
        return { status: 'error', answers: [], error: 'DNS query aborted' };
      }
      try {
        const implFunction = impl?.[method];
        if (typeof implFunction !== 'function') {
          return { status: 'error', answers: [], error: `resolver implementation is missing ${method}()` };
        }
        const raw = await withTimeout(
          Promise.resolve(implFunction.call(impl, name)),
          attemptTimeout,
          `DNS ${recordType} query for ${name}`,
        );
        return { status: 'ok', answers: normaliseAnswers(recordType, raw) };
      } catch (error) {
        const mapped = classifyDnsError(error);
        if (mapped.status === 'nxdomain') {
          return { status: 'nxdomain', answers: [], error: describeError(error) };
        }
        if (mapped.status === 'ok' && mapped.empty === true) {
          // The name exists but has no record of this type; that is not an error.
          return { status: 'ok', answers: [] };
        }
        last = { status: mapped.status === 'ok' ? 'error' : mapped.status, answers: [], error: describeError(error) };
        if (!TRANSIENT_STATUSES.has(last.status) || attempt === attempts - 1) break;
        await sleep(25 * (attempt + 1));
      }
    }
    return last;
  }

  /** Resolve A/AAAA/CNAME/NS/SOA in parallel and fold the statuses. */
  async function resolveHost(input, hostOptions = {}) {
    const host = canonicalHost(input);
    if (host.length === 0) {
      return { status: 'error', a: [], aaaa: [], cname: [], ns: [], soa: false };
    }
    const queryOptions = { signal: hostOptions.signal, timeoutMs: hostOptions.timeoutMs };
    const [a, aaaa, cname, ns, soa] = await Promise.all([
      query(host, 'A', queryOptions),
      query(host, 'AAAA', queryOptions),
      query(host, 'CNAME', queryOptions),
      query(host, 'NS', queryOptions),
      query(host, 'SOA', queryOptions),
    ]);
    const primary = [a, aaaa, cname];
    const okCount = primary.filter((entry) => entry.status === 'ok').length;
    let status;
    if (okCount > 0) {
      status = 'ok';
    } else {
      const statuses = new Set(primary.map((entry) => entry.status));
      if (statuses.size === 1) {
        status = [...statuses][0];
      } else if (statuses.has('servfail')) {
        status = 'servfail';
      } else if (statuses.has('timeout')) {
        status = 'timeout';
      } else if (statuses.has('error')) {
        status = 'error';
      } else {
        status = 'nxdomain';
      }
    }
    return {
      status,
      a: a.status === 'ok' ? a.answers : [],
      aaaa: aaaa.status === 'ok' ? aaaa.answers : [],
      cname: cname.status === 'ok' ? cname.answers : [],
      ns: ns.status === 'ok' ? ns.answers : [],
      soa: soa.status === 'ok' && soa.answers.length > 0,
    };
  }

  /** Whether the zone apex exists (has NS or SOA records). */
  async function apexExists(input, apexOptions = {}) {
    const zone = canonicalHost(input);
    if (zone.length === 0) return false;
    try {
      const queryOptions = { signal: apexOptions.signal, timeoutMs: apexOptions.timeoutMs };
      const [ns, soa] = await Promise.all([query(zone, 'NS', queryOptions), query(zone, 'SOA', queryOptions)]);
      return (ns.status === 'ok' && ns.answers.length > 0) || (soa.status === 'ok' && soa.answers.length > 0);
    } catch {
      return false;
    }
  }

  return { query, resolveHost, apexExists, servers, timeoutMs, retries, impl, offline };
}
