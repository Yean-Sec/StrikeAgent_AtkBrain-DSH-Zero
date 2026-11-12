/**
 * TCP / HTTP / TLS probing over direct sockets or a SOCKS5 pivot.
 *
 * The HTTP client is a deliberately small HTTP/1.1 implementation on top of
 * `node:net`/`node:tls`: it never uses fetch, so it can run over a SOCKS5 socket
 * and can enforce per-request byte caps and a manual redirect policy (the scope
 * guard re-checks every redirect target before it is followed).
 *
 * Offline mode (`PENTEST_OFFLINE=1` or `options.offline`) makes every non
 * loopback connect/resolve throw before a socket is opened.
 */
import net from 'node:net';
import tls from 'node:tls';

import { parsePortsSpec } from './util.js';
import {
  abortError,
  assertNetworkAllowed,
  connectViaSocks5,
  isAbortError,
  isOfflineMode,
  isLoopbackHost,
  isTimeoutError,
  timeoutError,
} from './socks.js';
import { InputError, clamp, mapLimit } from './util.js';
import { connectViaHttpProxy, normaliseHttpProxy } from './proxy/connect.js';

export { assertNetworkAllowed, isLoopbackHost, isOfflineMode };

const DEFAULT_TCP_TIMEOUT_MS = 4000;
const DEFAULT_HTTP_TIMEOUT_MS = 5000;
const DEFAULT_TLS_TIMEOUT_MS = 5000;
const DEFAULT_MAX_BODY_BYTES = 1048576;
const DEFAULT_MAX_HEADER_BYTES = 65536;
const DEFAULT_MAX_PORTS = 1024;
const MAX_CONCURRENCY = 128;
const HEADER_END = Buffer.from('\r\n\r\n', 'latin1');
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function positiveInteger(value, fallback, cap = Number.MAX_SAFE_INTEGER) {
  if (!Number.isInteger(value) || value <= 0) return fallback;
  return Math.min(value, cap);
}

function requireHost(value) {
  const host = String(value ?? '').trim();
  if (host.length === 0) throw new InputError('host is required', 'ATK_INVALID_ARGS');
  return host;
}

function requirePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new InputError(`invalid port ${JSON.stringify(value)} (expected 1-65535)`, 'ATK_INVALID_ARGS');
  }
  return port;
}

/**
 * Parse a port specification or an explicit array of ports.
 * @param {string|number|Array<string|number>} spec
 * @param {{max?:number}} [options]
 */
export function parsePorts(spec, options = {}) {
  const max = positiveInteger(options.max, DEFAULT_MAX_PORTS);
  if (Array.isArray(spec)) {
    const ports = new Set();
    for (const entry of spec) {
      const port = Number(entry);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new InputError(`invalid port ${JSON.stringify(entry)} (expected 1-65535)`, 'ATK_INVALID_ARGS');
      }
      ports.add(port);
      if (ports.size > max) throw new InputError(`too many ports: more than ${max}`, 'ATK_INVALID_ARGS');
    }
    if (ports.size === 0) throw new InputError('ports resolved to an empty set', 'ATK_INVALID_ARGS');
    return [...ports].sort((a, b) => a - b);
  }
  return parsePortsSpec(spec, max);
}

/** Normalize a SOCKS5 proxy descriptor (object or `socks5://user:pass@host:port`). */
export function normaliseVia(via) {
  if (via === undefined || via === null || via === '') return null;
  if (typeof via === 'string' && /^https?:\/\//iu.test(via)) {
    return normaliseHttpProxy(via);
  }
  if (typeof via === 'string') {
    let parsed;
    try {
      parsed = new URL(via.includes('://') ? via : `socks5://${via}`);
    } catch {
      throw new InputError(`invalid SOCKS5 proxy "${via}"`, 'ATK_INVALID_ARGS');
    }
    if (!/^socks5h?:$/u.test(parsed.protocol)) {
      throw new InputError(`unsupported proxy scheme "${parsed.protocol}"; use socks5://`, 'ATK_INVALID_ARGS');
    }
    const port = parsed.port.length > 0 ? Number(parsed.port) : 1080;
    return {
      host: parsed.hostname,
      port,
      ...(parsed.username.length > 0 ? { username: decodeURIComponent(parsed.username) } : {}),
      ...(parsed.password.length > 0 ? { password: decodeURIComponent(parsed.password) } : {}),
    };
  }
  if (typeof via !== 'object') throw new InputError('via must be a SOCKS5/HTTP proxy object or URL string', 'ATK_INVALID_ARGS');
  if (via.type === 'http' || via.type === 'https') return normaliseHttpProxy(via);
  const host = String(via.host ?? via.proxyHost ?? '').trim();
  if (host.length === 0) throw new InputError('SOCKS5 proxy host is required', 'ATK_INVALID_ARGS');
  const port = requirePort(via.port ?? via.proxyPort ?? 1080);
  return {
    host,
    port,
    ...(typeof via.username === 'string' && via.username.length > 0 ? { username: via.username } : {}),
    ...(typeof via.password === 'string' ? { password: via.password } : {}),
  };
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortError(signal);
}

/** React to an abort/scope denial instead of treating it as a network state. */
function rethrowControlErrors(error, options) {
  if (isAbortError(error, options?.signal)) throw error;
  if (error instanceof InputError) throw error;
}

/** Open a plain TCP connection (connected socket, no protocol traffic yet). */
function openTcp(host, port, options = {}) {
  assertNetworkAllowed(host, options, 'connect');
  throwIfAborted(options.signal);
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TCP_TIMEOUT_MS);
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = net.connect({ host, port });
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('error', onError);
      socket.removeListener('connect', onConnect);
      options.signal?.removeEventListener?.('abort', onAbort);
    };
    function onError(error) {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      reject(error);
    }
    function onConnect() {
      if (settled) return;
      settled = true;
      cleanup();
      // Post-connect errors are handled by the protocol layer (banner/HTTP/TLS);
      // keep a no-op listener so a late reset cannot become an unhandled event.
      socket.on('error', () => {});
      resolve(socket);
    }
    function onAbort() {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      reject(abortError(options.signal));
    }
    timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      reject(timeoutError(`connection to ${host}:${port} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    socket.once('error', onError);
    socket.once('connect', onConnect);
    options.signal?.addEventListener?.('abort', onAbort, { once: true });
  });
}

/** Read up to `maxBytes` of a service banner, bounded by `timeoutMs`. */
function readBanner(socket, maxBytes, timeoutMs, signal) {
  return new Promise((resolve) => {
    let buffer = Buffer.alloc(0);
    let done = false;
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('end', onEnd);
      socket.removeListener('close', onEnd);
      signal?.removeEventListener?.('abort', onAbort);
    };
    const finish = () => {
      if (done) return;
      done = true;
      cleanup();
      resolve(buffer);
    };
    function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= maxBytes) {
        buffer = buffer.subarray(0, maxBytes);
        finish();
      }
    }
    function onError() {
      finish();
    }
    function onEnd() {
      finish();
    }
    function onAbort() {
      finish();
    }
    const timer = setTimeout(finish, Math.max(1, Math.min(timeoutMs, 2000)));
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('end', onEnd);
    socket.once('close', onEnd);
    signal?.addEventListener?.('abort', onAbort, { once: true });
    socket.resume();
  });
}

function sanitiseBanner(buffer) {
  let text = '';
  for (const byte of buffer) {
    text += byte === 9 || (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : byte === 10 || byte === 13 ? ' ' : '.';
  }
  return text.replace(/\s+/gu, ' ').trim().slice(0, 256);
}

/**
 * Map a target-level SOCKS5 failure (refused/unreachable target) onto a
 * port-scan state. Returns undefined for proxy/auth/protocol failures, which
 * must abort the scan instead of being reported as a closed port.
 */
function socksTargetState(error) {
  if (error?.name !== 'SocksConnectError' || error?.code !== 'ATK_SOCKS_CONNECT') return undefined;
  const reply = Number(error.socksReply);
  if (reply === 0x05) return 'closed';
  if (reply === 0x03 || reply === 0x04 || reply === 0x06) return 'filtered';
  return undefined;
}

/** Map a connect error onto the port-scan state vocabulary. */
export function connectErrorState(error) {
  if (isTimeoutError(error)) return 'filtered';
  const code = String(error?.code ?? '').toUpperCase();
  if (['EHOSTUNREACH', 'ENETUNREACH', 'EHOSTDOWN', 'ENETDOWN', 'EACCES', 'EPERM', 'EAI_AGAIN', 'EAI_FAIL', 'ENETRESET', 'EADDRNOTAVAIL'].includes(code)) {
    return 'filtered';
  }
  return 'closed';
}

/** Open a connection to `host:port`, optionally through a SOCKS5 proxy. */
async function openConnection(host, port, options = {}) {
  if (options.via !== undefined && options.via !== null) {
    const via = normaliseVia(options.via);
    const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TCP_TIMEOUT_MS);
    if (via.type === 'http') return await connectViaHttpProxy(via, { host, port }, { timeoutMs, signal: options.signal });
    return await connectViaSocks5(via, { host, port }, { timeoutMs, signal: options.signal, offline: options.offline });
  }
  return await openTcp(host, port, options);
}

async function connectVia(via, host, port, options = {}) {
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TCP_TIMEOUT_MS);
  if (via.type === 'http') return await connectViaHttpProxy(via, { host, port }, { timeoutMs, signal: options.signal });
  return await connectViaSocks5(via, { host, port }, { timeoutMs, signal: options.signal, offline: options.offline });
}

/**
 * Probe one TCP port.
 * @returns {Promise<{host:string,port:number,state:'open'|'closed'|'filtered',banner?:string,ms:number}>}
 */
export async function tcpProbe(hostInput, portInput, options = {}) {
  const host = requireHost(hostInput);
  const port = requirePort(portInput);
  assertNetworkAllowed(host, options, 'connect');
  const started = Date.now();
  let socket;
  try {
    socket = await openConnection(host, port, options);
  } catch (error) {
    const socksState = socksTargetState(error);
    if (socksState !== undefined) return { host, port, state: socksState, ms: Date.now() - started };
    rethrowControlErrors(error, options);
    return { host, port, state: connectErrorState(error), ms: Date.now() - started };
  }
  const result = { host, port, state: 'open', ms: 0 };
  try {
    if (options.banner !== false) {
      const bannerTimeout = Math.min(500, positiveInteger(options.timeoutMs, DEFAULT_TCP_TIMEOUT_MS));
      const banner = await readBanner(socket, 256, bannerTimeout, options.signal);
      if (banner.length > 0) result.banner = sanitiseBanner(banner);
    }
  } finally {
    socket.destroy();
  }
  result.ms = Date.now() - started;
  return result;
}

/**
 * Scan a port range with bounded concurrency. Returns every probe result
 * (open, closed and filtered) in input-port order.
 */
export async function scanPorts(hostInput, portsInput, options = {}) {
  const host = requireHost(hostInput);
  const ports = parsePorts(portsInput, { max: positiveInteger(options.maxPorts, DEFAULT_MAX_PORTS) });
  assertNetworkAllowed(host, options, 'connect');
  const concurrency = clamp(positiveInteger(options.concurrency, 32), 1, MAX_CONCURRENCY);
  const via = options.via === undefined || options.via === null ? null : normaliseVia(options.via);
  const shared = {
    timeoutMs: positiveInteger(options.timeoutMs, DEFAULT_TCP_TIMEOUT_MS),
    signal: options.signal,
    offline: isOfflineMode(options),
    banner: options.banner === true,
    ...(via !== null ? { via } : {}),
  };
  return await mapLimit(ports, concurrency, async (port) => {
    try {
      return await tcpProbe(host, port, shared);
    } catch (error) {
      const socksState = socksTargetState(error);
      if (socksState !== undefined) return { host, port, state: socksState, ms: 0 };
      rethrowControlErrors(error, options);
      return { host, port, state: connectErrorState(error), ms: 0 };
    }
  }, options.signal);
}

/* ------------------------------------------------------------------ */
/* HTTP/1.1 client                                                     */
/* ------------------------------------------------------------------ */

function parseHttpUrl(input) {
  const text = String(input ?? '').trim();
  if (text.length === 0) throw new InputError('url is empty', 'ATK_INVALID_ARGS');
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new InputError(`invalid URL "${text}"`, 'ATK_INVALID_ARGS');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new InputError(`unsupported URL scheme "${url.protocol}"; use http:// or https://`, 'ATK_INVALID_ARGS');
  }
  return url;
}

function hostOfUrl(url) {
  return url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname;
}

function portOfUrl(url) {
  if (url.port.length > 0) return Number(url.port);
  return url.protocol === 'https:' ? 443 : 80;
}

/** TLS SNI name: hostnames only, never IP literals. */
function sniFor(host, explicit) {
  if (typeof explicit === 'string' && explicit.trim().length > 0) return explicit.trim();
  return net.isIP(host) === 0 ? host : undefined;
}

/** Open a TLS socket (optionally over an existing raw socket). */
function openTls({ host, port, socket: existingSocket, servername, timeoutMs = DEFAULT_TLS_TIMEOUT_MS, signal }) {
  throwIfAborted(signal);
  const effectiveTimeout = positiveInteger(timeoutMs, DEFAULT_TLS_TIMEOUT_MS);
  return new Promise((resolve, reject) => {
    let settled = false;
    const connectOptions = {
      rejectUnauthorized: false,
      ALPNProtocols: ['http/1.1'],
    };
    if (existingSocket !== undefined) connectOptions.socket = existingSocket;
    else {
      connectOptions.host = host;
      connectOptions.port = port;
    }
    if (typeof servername === 'string' && servername.length > 0) connectOptions.servername = servername;
    const tlsSocket = tls.connect(connectOptions);
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      tlsSocket.removeListener('error', onError);
      tlsSocket.removeListener('secureConnect', onSecure);
      signal?.removeEventListener?.('abort', onAbort);
    };
    function onError(error) {
      if (settled) return;
      settled = true;
      cleanup();
      tlsSocket.destroy();
      reject(error);
    }
    function onSecure() {
      if (settled) return;
      settled = true;
      cleanup();
      // Peer certificates are inspected by the caller; do not let late socket
      // errors turn into unhandled 'error' events.
      tlsSocket.on('error', () => {});
      resolve(tlsSocket);
    }
    function onAbort() {
      if (settled) return;
      settled = true;
      cleanup();
      tlsSocket.destroy();
      reject(abortError(signal));
    }
    timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      tlsSocket.destroy();
      reject(timeoutError(`TLS handshake with ${host ?? 'socket'}:${port ?? ''} timed out after ${effectiveTimeout}ms`));
    }, effectiveTimeout);
    tlsSocket.once('error', onError);
    tlsSocket.once('secureConnect', onSecure);
    signal?.addEventListener?.('abort', onAbort, { once: true });
    if (existingSocket !== undefined) existingSocket.resume();
  });
}

function formatDistinguishedName(value) {
  if (value === null || typeof value !== 'object') return undefined;
  const parts = [];
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'string' && entry.length > 0) parts.push(`${key}=${entry}`);
  }
  return parts.length > 0 ? parts.join(', ') : undefined;
}

function sameDistinguishedName(a, b) {
  const left = a ?? {};
  const right = b ?? {};
  const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
  for (const key of keys) {
    if (String(left[key] ?? '') !== String(right[key] ?? '')) return false;
  }
  return true;
}

function isoOrRaw(value) {
  if (typeof value !== 'string' || value.length === 0) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : value;
}

/** Extract the interesting pieces of a TLS connection and its peer cert. */
export function collectTlsInfo(tlsSocket) {
  let certificate = {};
  try {
    certificate = tlsSocket.getPeerCertificate(true) ?? {};
  } catch {
    certificate = {};
  }
  const cipher = typeof tlsSocket.getCipher === 'function' ? tlsSocket.getCipher() : undefined;
  const alternativeNames = typeof certificate.subjectaltname === 'string'
    ? certificate.subjectaltname.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0)
    : [];
  const selfSigned = certificate.issuerCertificate !== undefined
    ? certificate.issuerCertificate?.fingerprint256 === certificate.fingerprint256
    : sameDistinguishedName(certificate.issuer, certificate.subject);
  return {
    protocol: typeof tlsSocket.getProtocol === 'function' ? (tlsSocket.getProtocol() ?? undefined) : undefined,
    cipher: typeof cipher?.name === 'string' ? cipher.name : undefined,
    issuer: formatDistinguishedName(certificate.issuer),
    subject: formatDistinguishedName(certificate.subject),
    subjectAltName: alternativeNames,
    validFrom: isoOrRaw(certificate.valid_from),
    validTo: isoOrRaw(certificate.valid_to),
    selfSigned,
    fingerprint256: typeof certificate.fingerprint256 === 'string' ? certificate.fingerprint256 : undefined,
  };
}

/** Extract a page title from HTML, entity-decoded and length-capped. */
export function extractTitle(body) {
  const text = String(body ?? '');
  const match = /<title[^>]*>([\s\S]{0,300}?)<\/title>/iu.exec(text);
  if (match === null) return undefined;
  const decoded = match[1]
    .replace(/&amp;/gu, '&')
    .replace(/&lt;/gu, '<')
    .replace(/&gt;/gu, '>')
    .replace(/&quot;/gu, '"')
    .replace(/&#0*39;|&apos;/gu, "'")
    .replace(/&nbsp;/gu, ' ')
    .replace(/&#x([0-9a-f]+);/giu, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/gu, (_, dec) => String.fromCodePoint(Number(dec)))
    .replace(/\s+/gu, ' ')
    .trim();
  return decoded.length > 0 ? decoded.slice(0, 200) : undefined;
}

/** Best-effort technology fingerprints from headers and body. */
export function fingerprintTechs(headers = {}, body = '') {
  const techs = new Set();
  const server = String(headers.server ?? '').toLowerCase();
  const powered = String(headers['x-powered-by'] ?? '').toLowerCase();
  const generator = String(headers['x-generator'] ?? '').toLowerCase();
  const cookies = JSON.stringify(headers['set-cookie'] ?? '').toLowerCase();
  const html = String(body ?? '').toLowerCase();

  const serverSignatures = [
    ['nginx', 'nginx'],
    ['openresty', 'OpenResty'],
    ['apache', 'Apache'],
    ['microsoft-iis', 'IIS'],
    ['cloudflare', 'Cloudflare'],
    ['envoy', 'Envoy'],
    ['caddy', 'Caddy'],
    ['gunicorn', 'Gunicorn'],
    ['jetty', 'Jetty'],
    ['tomcat', 'Tomcat'],
    ['kestrel', 'Kestrel'],
    ['lighttpd', 'lighttpd'],
  ];
  for (const [needle, label] of serverSignatures) {
    if (server.includes(needle)) techs.add(label);
  }
  if (powered.includes('php')) techs.add('PHP');
  if (powered.includes('asp.net')) techs.add('ASP.NET');
  if (powered.includes('express')) techs.add('Express');
  if (powered.includes('servlet')) techs.add('Java');
  if (powered.includes('node')) techs.add('Node.js');
  if (powered.includes('django')) techs.add('Django');
  if (generator.includes('wordpress')) techs.add('WordPress');
  if (generator.includes('drupal')) techs.add('Drupal');
  if (generator.includes('joomla')) techs.add('Joomla');

  if (headers['x-drupal-cache'] !== undefined || headers['x-drupal-dynamic-cache'] !== undefined) techs.add('Drupal');
  if (headers['x-aspnet-version'] !== undefined) techs.add('ASP.NET');
  if (headers['x-nextjs-cache'] !== undefined) techs.add('Next.js');

  if (cookies.includes('jsessionid')) techs.add('Java');
  if (cookies.includes('phpsessid')) techs.add('PHP');
  if (cookies.includes('asp.net_sessionid')) techs.add('ASP.NET');
  if (cookies.includes('laravel_session')) techs.add('Laravel');
  if (cookies.includes('django')) techs.add('Django');

  if (html.includes('wp-content') || html.includes('wp-includes')) techs.add('WordPress');
  if (html.includes('__next_data__')) techs.add('Next.js');
  if (html.includes('ng-version=')) techs.add('Angular');
  if (html.includes('data-reactroot') || html.includes('_reactrootcontainer')) techs.add('React');
  if (html.includes('swagger-ui')) techs.add('Swagger UI');
  if (html.includes('graphiql')) techs.add('GraphiQL');
  if (html.includes('jquery')) techs.add('jQuery');
  if (html.includes('bootstrap')) techs.add('Bootstrap');
  return [...techs].sort();
}

function buildRequest(method, url, headers) {
  const path = `${url.pathname.length > 0 ? url.pathname : '/'}${url.search}`;
  const lines = [`${method} ${path} HTTP/1.1`, `Host: ${url.host}`];
  const merged = new Map([
    ['user-agent', 'AtkBrain/0.1 (authorized-engagement-scanner)'],
    ['accept', '*/*'],
    ['accept-encoding', 'identity'],
    ['connection', 'close'],
  ].map(([name, value]) => [name, `${name}: ${value}`]));
  if (headers !== null && typeof headers === 'object') {
    for (const [rawName, rawValue] of Object.entries(headers)) {
      if (rawValue === undefined || rawValue === null) continue;
      const name = String(rawName).replace(/[\r\n:]/gu, '').trim();
      const value = String(rawValue).replace(/[\r\n]/gu, ' ').trim();
      if (name.length === 0) continue;
      merged.set(name.toLowerCase(), `${name}: ${value}`);
    }
  }
  lines.push(...merged.values());
  return `${lines.join('\r\n')}\r\n\r\n`;
}

function parseResponseHead(text) {
  const lines = text.split('\r\n');
  const statusLine = (lines.shift() ?? '').trim();
  const match = /^HTTP\/(\d+(?:\.\d+)?)\s+(\d{3})(?:\s+(.*))?$/u.exec(statusLine);
  if (match === null) {
    throw new InputError(`malformed HTTP status line: ${statusLine.slice(0, 120)}`, 'ATK_HTTP_MALFORMED');
  }
  const headers = {};
  for (const line of lines) {
    if (line.length === 0) continue;
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name.length === 0) continue;
    if (name === 'set-cookie') {
      if (Array.isArray(headers[name])) headers[name].push(value);
      else headers[name] = [value];
      continue;
    }
    headers[name] = headers[name] === undefined ? value : `${headers[name]}, ${value}`;
  }
  const contentLengthText = headers['content-length'];
  const transferEncoding = String(headers['transfer-encoding'] ?? '').toLowerCase();
  let framing = 'until-close';
  let contentLength = 0;
  if (transferEncoding.includes('chunked')) {
    framing = 'chunked';
  } else if (contentLengthText !== undefined) {
    const parsed = Number(String(contentLengthText).split(',')[0].trim());
    if (Number.isInteger(parsed) && parsed >= 0) {
      framing = parsed === 0 ? 'none' : 'length';
      contentLength = parsed;
    } else {
      framing = 'until-close';
    }
  }
  return {
    httpVersion: `HTTP/${match[1]}`,
    status: Number(match[2]),
    statusText: match[3] ?? '',
    headers,
    framing,
    contentLength,
  };
}

/** Incremental `Transfer-Encoding: chunked` decoder with a decoded-byte cap. */
class ChunkedDecoder {
  constructor(maxBytes) {
    this.maxBytes = maxBytes;
    this.buffer = Buffer.alloc(0);
    this.chunks = [];
    this.length = 0;
    this.truncated = false;
    this.state = 'size';
    this.size = 0;
    this.done = false;
  }

  push(chunk) {
    if (this.done) return { done: true, truncated: this.truncated };
    this.buffer = this.buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffer, chunk]);
    for (;;) {
      if (this.state === 'size') {
        const lineEnd = this.buffer.indexOf('\r\n');
        if (lineEnd < 0) return { done: false, truncated: this.truncated };
        const line = this.buffer.subarray(0, lineEnd).toString('latin1').split(';')[0].trim();
        this.buffer = this.buffer.subarray(lineEnd + 2);
        if (!/^[0-9a-fA-F]{1,16}$/u.test(line)) {
          return { done: false, truncated: this.truncated, error: new InputError('malformed chunked encoding', 'ATK_HTTP_MALFORMED') };
        }
        this.size = Number.parseInt(line, 16);
        if (this.size === 0) {
          this.done = true;
          return { done: true, truncated: this.truncated };
        }
        this.state = 'data';
      }
      if (this.state === 'data') {
        if (this.buffer.length < this.size + 2) return { done: false, truncated: this.truncated };
        this.append(this.buffer.subarray(0, this.size));
        this.buffer = this.buffer.subarray(this.size + 2);
        if (this.truncated) {
          this.done = true;
          return { done: true, truncated: true };
        }
        this.state = 'size';
      }
    }
  }

  append(data) {
    const remaining = this.maxBytes - this.length;
    if (remaining <= 0) {
      this.truncated = true;
      return;
    }
    const slice = data.length > remaining ? data.subarray(0, remaining) : data;
    if (slice.length > 0) {
      this.chunks.push(Buffer.from(slice));
      this.length += slice.length;
    }
    if (data.length > remaining) this.truncated = true;
  }

  result() {
    return { body: Buffer.concat(this.chunks), truncated: this.truncated };
  }
}

/** Read one HTTP response from an already-connected socket. */
function readHttpResponse(socket, options) {
  return new Promise((resolve, reject) => {
    const method = options.method ?? 'GET';
    const maxHeaderBytes = positiveInteger(options.maxHeaderBytes, DEFAULT_MAX_HEADER_BYTES);
    const maxBodyBytes = positiveInteger(options.maxBodyBytes, DEFAULT_MAX_BODY_BYTES);
    const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_HTTP_TIMEOUT_MS);
    let buffer = Buffer.alloc(0);
    let head;
    let chunked;
    const bodyChunks = [];
    let bodyLength = 0;
    let truncated = false;
    let finished = false;
    let timer;

    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('end', onEnd);
      socket.removeListener('close', onClose);
      options.signal?.removeEventListener?.('abort', onAbort);
    };
    const finish = (error, value) => {
      if (finished) return;
      finished = true;
      cleanup();
      try {
        socket.destroy();
      } catch {
        // ignore: socket already gone
      }
      if (error !== undefined && error !== null) reject(error);
      else resolve(value);
    };
    const build = () => {
      if (chunked !== undefined) {
        const decoded = chunked.result();
        return {
          httpVersion: head?.httpVersion,
          status: head?.status ?? 0,
          statusText: head?.statusText,
          headers: head?.headers ?? {},
          body: decoded.body,
          truncated: truncated || decoded.truncated,
        };
      }
      return {
        httpVersion: head?.httpVersion,
        status: head?.status ?? 0,
        statusText: head?.statusText,
        headers: head?.headers ?? {},
        body: Buffer.concat(bodyChunks),
        truncated,
      };
    };
    const appendBody = (data) => {
      if (data.length === 0) return;
      const remaining = maxBodyBytes - bodyLength;
      if (remaining <= 0) {
        truncated = true;
        return;
      }
      const slice = data.length > remaining ? data.subarray(0, remaining) : data;
      bodyChunks.push(Buffer.from(slice));
      bodyLength += slice.length;
      if (data.length > remaining) truncated = true;
    };
    const consumeBody = (chunk) => {
      if (chunk.length === 0) return;
      if (chunked !== undefined) {
        const step = chunked.push(chunk);
        if (step.error !== undefined) {
          finish(step.error);
          return;
        }
        if (step.done) finish(null, build());
        return;
      }
      if (head.framing === 'none') {
        finish(null, build());
        return;
      }
      if (head.framing === 'length') {
        const needed = head.contentLength - bodyLength;
        appendBody(chunk.subarray(0, Math.max(0, needed)));
        if (bodyLength >= head.contentLength || truncated) finish(null, build());
        return;
      }
      appendBody(chunk);
      if (truncated) finish(null, build());
    };
    function onData(chunk) {
      if (finished) return;
      try {
        buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
        if (head === undefined) {
          const index = buffer.indexOf(HEADER_END);
          if (index < 0) {
            if (buffer.length > maxHeaderBytes) {
              finish(new InputError(`HTTP response headers exceeded ${maxHeaderBytes} bytes`, 'ATK_HTTP_HEADERS'));
            }
            return;
          }
          head = parseResponseHead(buffer.subarray(0, index).toString('latin1'));
          buffer = buffer.subarray(index + 4);
          if (head.framing === 'chunked') chunked = new ChunkedDecoder(maxBodyBytes);
          if (method === 'HEAD' || head.status === 204 || head.status === 304 || head.status === 101 || head.framing === 'none') {
            finish(null, build());
            return;
          }
        }
        const pending = buffer;
        buffer = Buffer.alloc(0);
        consumeBody(pending);
      } catch (error) {
        finish(error);
      }
    }
    function onEnd() {
      if (finished) return;
      if (head === undefined) {
        finish(new InputError('connection closed before HTTP response headers completed', 'ATK_HTTP_TRUNCATED'));
        return;
      }
      if (chunked !== undefined) {
        if (buffer.length > 0) {
          const step = chunked.push(buffer);
          buffer = Buffer.alloc(0);
          if (step.error !== undefined) {
            finish(step.error);
            return;
          }
          if (step.done) {
            finish(null, build());
            return;
          }
        }
        finish(null, build());
        return;
      }
      finish(null, build());
    }
    function onClose() {
      onEnd();
    }
    function onError(error) {
      finish(error);
    }
    function onAbort() {
      finish(abortError(options.signal));
    }
    timer = setTimeout(() => {
      finish(timeoutError(`HTTP response timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('end', onEnd);
    socket.once('close', onClose);
    options.signal?.addEventListener?.('abort', onAbort, { once: true });
    socket.resume();
  });
}

/** Perform one HTTP request/response exchange. */
async function requestOnce(url, options) {
  const host = hostOfUrl(url);
  const port = portOfUrl(url);
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_HTTP_TIMEOUT_MS);
  assertNetworkAllowed(host, options, 'connect');
  throwIfAborted(options.signal);
  let socket;
  let tlsInfo;
  const sni = sniFor(host, options.servername);
  if (options.via !== undefined && options.via !== null) {
    const via = normaliseVia(options.via);
    const raw = await connectVia(via, host, port, { timeoutMs, signal: options.signal, offline: options.offline });
    if (url.protocol === 'https:') {
      socket = await openTls({ socket: raw, servername: sni, timeoutMs, signal: options.signal });
      tlsInfo = collectTlsInfo(socket);
    } else {
      socket = raw;
    }
  } else if (url.protocol === 'https:') {
    socket = await openTls({ host, port, servername: sni, timeoutMs, signal: options.signal });
    tlsInfo = collectTlsInfo(socket);
  } else {
    socket = await openTcp(host, port, { timeoutMs, signal: options.signal, offline: options.offline });
  }
  const responsePromise = readHttpResponse(socket, {
    method: options.method,
    maxHeaderBytes: options.maxHeaderBytes,
    maxBodyBytes: options.maxBodyBytes,
    timeoutMs,
    signal: options.signal,
  });
  try {
    socket.write(buildRequest(options.method, url, options.headers));
  } catch (error) {
    try {
      socket.destroy();
    } catch {
      // ignore
    }
    throw error;
  }
  const response = await responsePromise;
  return {
    url: url.href,
    status: response.status,
    statusText: response.statusText,
    httpVersion: response.httpVersion,
    headers: response.headers,
    body: response.body.toString('utf8'),
    truncated: response.truncated === true,
    ...(tlsInfo !== undefined ? { tls: tlsInfo } : {}),
  };
}

/**
 * Fetch a URL with the minimal HTTP/1.1 client.
 *
 * @param {string} input URL
 * @param {object} [options] {timeoutMs,maxBodyBytes,method,headers,followRedirects,onRedirect,via,signal,offline}
 * @returns {Promise<{url:string,status:number,headers:object,body:string,title:string|undefined,server:string|undefined,techs:string[],redirects:{status:number,from:string,to:string}[]}>}
 */
export async function httpProbe(input, options = {}) {
  const url = parseHttpUrl(input);
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_HTTP_TIMEOUT_MS);
  const maxBodyBytes = positiveInteger(options.maxBodyBytes, DEFAULT_MAX_BODY_BYTES);
  const maxHeaderBytes = positiveInteger(options.maxHeaderBytes, DEFAULT_MAX_HEADER_BYTES);
  const method = String(options.method ?? 'GET').toUpperCase() === 'HEAD' ? 'HEAD' : 'GET';
  const followRedirects = Number.isInteger(options.followRedirects) && options.followRedirects >= 0
    ? Math.min(options.followRedirects, 10)
    : 3;
  const via = options.via === undefined || options.via === null ? null : normaliseVia(options.via);
  const redirects = [];
  let current = url;

  for (let hop = 0; ; hop += 1) {
    throwIfAborted(options.signal);
    assertNetworkAllowed(hostOfUrl(current), options, 'connect');
    const response = await requestOnce(current, {
      method,
      headers: options.headers,
      maxBodyBytes,
      maxHeaderBytes,
      timeoutMs,
      signal: options.signal,
      offline: options.offline,
      servername: options.servername,
      ...(via !== null ? { via } : {}),
    });
    const location = response.headers.location;
    if (REDIRECT_STATUSES.has(response.status) && typeof location === 'string' && location.length > 0 && hop < followRedirects) {
      let next;
      try {
        next = new URL(location, current);
      } catch {
        // A malformed Location header is reported as the final response.
        return finishHttpResult(current, response, redirects);
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        throw new InputError(`redirect to unsupported scheme "${next.protocol}" (from ${current.href})`, 'ATK_REDIRECT_BLOCKED');
      }
      redirects.push({ status: response.status, from: current.href, to: next.href });
      if (typeof options.onRedirect === 'function') {
        const verdict = await options.onRedirect(next.href, {
          status: response.status,
          from: current.href,
          to: next.href,
          index: redirects.length,
        });
        if (verdict === false) {
          throw new InputError(`redirect to ${next.href} was blocked by the scope guard`, 'ATK_REDIRECT_BLOCKED');
        }
      }
      assertNetworkAllowed(hostOfUrl(next), options, 'connect');
      current = next;
      continue;
    }
    return finishHttpResult(current, response, redirects);
  }
}

function finishHttpResult(url, response, redirects) {
  return {
    url: url.href,
    status: response.status,
    headers: response.headers,
    body: response.body,
    title: extractTitle(response.body),
    server: typeof response.headers.server === 'string' ? response.headers.server : undefined,
    techs: fingerprintTechs(response.headers, response.body),
    redirects,
    ...(response.tls !== undefined ? { tls: response.tls } : {}),
  };
}

/**
 * Probe a TLS service and describe its certificate and negotiated parameters.
 * Certificate verification is intentionally disabled: scanning engagements need
 * visibility into self-signed/expired endpoints, and the result reports the
 * findings instead of failing the handshake.
 */
export async function tlsProbe(hostInput, portInput, options = {}) {
  const host = requireHost(hostInput);
  const port = requirePort(portInput ?? 443);
  assertNetworkAllowed(host, options, 'connect');
  throwIfAborted(options.signal);
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TLS_TIMEOUT_MS);
  const sni = sniFor(host, options.servername);
  let socket;
  if (options.via !== undefined && options.via !== null) {
    const via = normaliseVia(options.via);
    const raw = await connectViaSocks5(via, { host, port }, { timeoutMs, signal: options.signal, offline: options.offline });
    socket = await openTls({ socket: raw, servername: sni, timeoutMs, signal: options.signal });
  } else {
    socket = await openTls({ host, port, servername: sni, timeoutMs, signal: options.signal });
  }
  const info = collectTlsInfo(socket);
  socket.destroy();
  return info;
}
