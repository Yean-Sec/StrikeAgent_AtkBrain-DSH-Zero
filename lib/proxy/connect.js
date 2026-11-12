/**
 * HTTP CONNECT proxy helpers.
 *
 * This is the raw-socket path used by the AtkBrain probe layer: it opens a TCP
 * (or TLS) connection to an HTTP proxy, performs `CONNECT host:port`, validates
 * the proxy status line and hands the caller a paused socket positioned at the
 * start of the tunnel. It deliberately does not use fetch/undici, so it can
 * carry TLS, banner grabs and any other protocol the probe layer speaks.
 *
 * Proxy credentials are only ever placed in `Proxy-Authorization`; public
 * helpers (`redactProxyUrl`, `redactProxyText`) mask them in logs and status.
 */
import net from 'node:net';
import tls from 'node:tls';

import { InputError } from '../util.js';
import { abortError, assertNetworkAllowed, timeoutError } from '../socks.js';

const MAX_HEADER_BYTES = 32768;
const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_OBJECT_PORT = 8080;
const SENSITIVE_QUERY_RE = /^(?:access[-_]?token|api[-_]?key|auth|authorization|credential|credentials|key|passwd|password|secret|token)$/iu;

function bareHost(value) {
  const text = String(value ?? '').trim();
  if (text.startsWith('[') && text.endsWith(']')) return text.slice(1, -1);
  return text;
}

function decodeUserinfo(value) {
  const text = String(value ?? '');
  if (text.length === 0) return undefined;
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

function requirePort(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new InputError(`invalid HTTP proxy port ${JSON.stringify(value)} (expected 1-65535)`, 'ATK_INVALID_ARGS');
  }
  return port;
}

/** Mask credentials in one proxy URL for public output. */
export function redactProxyUrl(value) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  if (text.length === 0) return null;
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//iu.test(text) ? text : `http://${text}`);
  } catch {
    return '[invalid-proxy-url]';
  }
  if (url.username.length > 0) url.username = '***';
  if (url.password.length > 0) url.password = '***';
  for (const key of [...url.searchParams.keys()]) {
    if (SENSITIVE_QUERY_RE.test(key)) url.searchParams.set(key, '***');
  }
  const rendered = url.toString();
  return url.pathname === '/' && url.search.length === 0 && url.hash.length === 0
    ? rendered.replace(/\/$/u, '')
    : rendered;
}

/** Mask any `scheme://user:pass@host` userinfo that leaked into an error string. */
export function redactProxyText(value) {
  return String(value ?? '').replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/giu, '$1***@');
}

function fromUrl(url) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new InputError(
      `unsupported HTTP proxy scheme "${url.protocol}"; use http:// or https:// (SOCKS5 proxies use atkbrain_tunnel)`,
      'ATK_INVALID_ARGS',
    );
  }
  const host = bareHost(url.hostname);
  if (host.length === 0) throw new InputError('HTTP proxy URL has no host', 'ATK_INVALID_ARGS');
  const secure = url.protocol === 'https:';
  const port = requirePort(url.port, secure ? 443 : 80);
  const username = decodeUserinfo(url.username);
  const password = decodeUserinfo(url.password);
  if (username === undefined && password !== undefined) {
    throw new InputError('HTTP proxy password requires a username', 'ATK_INVALID_ARGS');
  }
  return {
    type: 'http',
    host,
    port,
    protocol: secure ? 'https' : 'http',
    secure,
    tls: secure,
    ...(username === undefined ? {} : { username }),
    ...(password === undefined ? {} : { password }),
    // Internal only: carries credentials for ProxyAgent/CONNECT. Redact before
    // returning this object from any public surface.
    url: url.toString(),
  };
}

/**
 * Normalise an HTTP proxy descriptor.
 *
 * Accepts `http(s)://[user:pass@]host[:port]`, a WHATWG URL, or an object with
 * `{host, port?, username?, password?, secure?, protocol?, url?}`.
 * Object descriptors default to port 8080 (Burp/local-proxy convention).
 *
 * @param {string|URL|object} input
 * @returns {{host:string,port:number,protocol:'http'|'https',secure:boolean,username?:string,password?:string,url:string}}
 */
export function normaliseHttpProxy(input) {
  if (input === undefined || input === null) {
    throw new InputError('HTTP proxy is required', 'ATK_INVALID_ARGS');
  }
  if (input instanceof URL) return fromUrl(input);
  if (typeof input === 'string') {
    const text = input.trim();
    if (text.length === 0) throw new InputError('HTTP proxy is empty', 'ATK_INVALID_ARGS');
    let url;
    try {
      url = new URL(/^[a-z][a-z0-9+.-]*:\/\//iu.test(text) ? text : `http://${text}`);
    } catch {
      throw new InputError(`invalid HTTP proxy URL "${redactProxyUrl(text) ?? '[empty]'}"`, 'ATK_INVALID_ARGS');
    }
    return fromUrl(url);
  }
  if (typeof input !== 'object') {
    throw new InputError('HTTP proxy must be a URL string or an object', 'ATK_INVALID_ARGS');
  }
  const nested = input.url ?? input.uri ?? input.href;
  if (typeof nested === 'string' && nested.trim().length > 0) return normaliseHttpProxy(nested);

  const host = bareHost(input.host ?? input.proxyHost);
  if (host.length === 0) throw new InputError('HTTP proxy host is required', 'ATK_INVALID_ARGS');
  const protocolText = String(input.protocol ?? input.scheme ?? '').replace(/:$/u, '').toLowerCase();
  if (protocolText.length > 0 && protocolText !== 'http' && protocolText !== 'https') {
    throw new InputError(`unsupported HTTP proxy scheme "${protocolText}"; use http:// or https://`, 'ATK_INVALID_ARGS');
  }
  const secure = input.secure === true || protocolText === 'https';
  const port = requirePort(input.port ?? input.proxyPort, secure ? 443 : DEFAULT_OBJECT_PORT);
  const username = typeof input.username === 'string' && input.username.length > 0
    ? input.username
    : (typeof input.user === 'string' && input.user.length > 0 ? input.user : undefined);
  const password = typeof input.password === 'string' ? input.password : undefined;
  if (username === undefined && password !== undefined) {
    throw new InputError('HTTP proxy password requires a username', 'ATK_INVALID_ARGS');
  }
  const authority = net.isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`;
  const userinfo = username === undefined
    ? ''
    : `${encodeURIComponent(username)}${password === undefined ? '' : `:${encodeURIComponent(password)}`}@`;
  return {
    type: 'http',
    host,
    port,
    protocol: secure ? 'https' : 'http',
    secure,
    tls: secure,
    ...(username === undefined ? {} : { username }),
    ...(password === undefined ? {} : { password }),
    url: `${secure ? 'https' : 'http'}://${userinfo}${authority}`,
  };
}

function basicAuthHeader(proxy) {
  if (proxy.username === undefined) return undefined;
  const token = Buffer.from(`${proxy.username}:${proxy.password ?? ''}`, 'utf8').toString('base64');
  return `Basic ${token}`;
}

function formatAuthority(host, port) {
  const bare = bareHost(host);
  return net.isIP(bare) === 6 ? `[${bare}]:${port}` : `${bare}:${port}`;
}

function buildConnectRequest(proxy, host, port) {
  const authority = formatAuthority(host, port);
  const lines = [
    `CONNECT ${authority} HTTP/1.1`,
    `Host: ${authority}`,
    'Proxy-Connection: keep-alive',
    'User-Agent: AtkBrain/0.1 (authorized-engagement-connector)',
  ];
  const authorization = basicAuthHeader(proxy);
  if (authorization !== undefined) lines.push(`Proxy-Authorization: ${authorization}`);
  return `${lines.join('\r\n')}\r\n\r\n`;
}

function openProxySocket(proxy, timeoutMs, signal, rejectUnauthorized) {
  if (signal?.aborted) throw abortError(signal);
  return new Promise((resolve, reject) => {
    let settled = false;
    let socket;
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      socket?.removeListener('error', onError);
      socket?.removeListener('connect', onConnect);
      socket?.removeListener('secureConnect', onConnect);
      signal?.removeEventListener?.('abort', onAbort);
    };
    const finish = (handler, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      handler(value);
    };
    const onError = (error) => {
      finish(reject, error);
      socket?.destroy();
    };
    const onConnect = () => {
      try { socket.setNoDelay?.(true); } catch { /* unsupported */ }
      finish(resolve, socket);
    };
    const onAbort = () => {
      finish(reject, abortError(signal));
      socket?.destroy();
    };
    const options = { host: proxy.host, port: proxy.port };
    try {
      socket = proxy.secure
        ? tls.connect({
          ...options,
          ...(net.isIP(proxy.host) === 0 ? { servername: proxy.host } : {}),
          rejectUnauthorized: rejectUnauthorized === true,
        })
        : net.connect(options);
    } catch (error) {
      finish(reject, error);
      return;
    }
    timer = setTimeout(() => {
      finish(reject, timeoutError(`HTTP proxy connection to ${proxy.host}:${proxy.port} timed out after ${timeoutMs}ms`));
      socket?.destroy();
    }, timeoutMs);
    socket.once('error', onError);
    socket.once(proxy.secure ? 'secureConnect' : 'connect', onConnect);
    signal?.addEventListener?.('abort', onAbort, { once: true });
  });
}

function parseResponseHead(text) {
  const lines = text.split(/\r?\n/u);
  const statusLine = (lines.shift() ?? '').trim();
  const match = /^HTTP\/(\d+(?:\.\d+)?)\s+(\d{3})(?:\s+(.*))?$/u.exec(statusLine);
  if (match === null) {
    throw new InputError(`malformed HTTP proxy response: ${statusLine.slice(0, 120)}`, 'ATK_HTTP_PROXY');
  }
  const headers = {};
  for (const line of lines) {
    if (line.length === 0) continue;
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name.length === 0) continue;
    headers[name] = headers[name] === undefined ? value : `${headers[name]}, ${value}`;
  }
  return {
    httpVersion: `HTTP/${match[1]}`,
    status: Number(match[2]),
    statusText: match[3] ?? '',
    headers,
  };
}

function performConnect(socket, proxy, host, port, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let buffer = Buffer.alloc(0);
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('end', onEnd);
      socket.removeListener('close', onEnd);
      signal?.removeEventListener?.('abort', onAbort);
    };
    const finish = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error !== undefined && error !== null) {
        socket.destroy();
        reject(error);
        return;
      }
      // Keep a no-op listener so a late reset cannot become an unhandled event.
      socket.on('error', () => {});
      socket.pause();
      resolve(socket);
    };
    const headerEnd = () => {
      const crlf = buffer.indexOf('\r\n\r\n');
      if (crlf >= 0) return { index: crlf, length: 4 };
      const lf = buffer.indexOf('\n\n');
      if (lf >= 0) return { index: lf, length: 2 };
      return null;
    };
    function onData(chunk) {
      if (settled) return;
      buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
      const end = headerEnd();
      if (end === null) {
        if (buffer.length > MAX_HEADER_BYTES) {
          finish(new InputError(`HTTP proxy response headers exceeded ${MAX_HEADER_BYTES} bytes`, 'ATK_HTTP_PROXY_HEADERS'));
        }
        return;
      }
      const total = end.index + end.length;
      if (total > MAX_HEADER_BYTES) {
        finish(new InputError(`HTTP proxy response headers exceeded ${MAX_HEADER_BYTES} bytes`, 'ATK_HTTP_PROXY_HEADERS'));
        return;
      }
      let parsed;
      try {
        parsed = parseResponseHead(buffer.subarray(0, end.index).toString('latin1'));
      } catch (error) {
        finish(error);
        return;
      }
      if (parsed.status === 407) {
        finish(new InputError('HTTP proxy authentication required (407)', 'ATK_HTTP_PROXY_AUTH'));
        return;
      }
      if (parsed.status < 200 || parsed.status >= 300) {
        const reason = parsed.statusText.length > 0 ? ` ${parsed.statusText}` : '';
        finish(new InputError(`HTTP proxy CONNECT failed with status ${parsed.status}${reason}`, 'ATK_HTTP_PROXY'));
        return;
      }
      const leftover = buffer.subarray(total);
      if (leftover.length > 0) socket.unshift(leftover);
      finish(null);
    }
    function onError(error) {
      finish(error);
    }
    function onEnd() {
      finish(new InputError('HTTP proxy closed the connection before the CONNECT response completed', 'ATK_HTTP_PROXY'));
    }
    function onAbort() {
      finish(abortError(signal));
    }
    timer = setTimeout(() => {
      finish(timeoutError(`HTTP proxy CONNECT to ${host}:${port} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('end', onEnd);
    socket.once('close', onEnd);
    signal?.addEventListener?.('abort', onAbort, { once: true });
    try {
      socket.write(buildConnectRequest(proxy, host, port));
    } catch (error) {
      finish(error);
    }
  });
}

/**
 * Open a tunnel to `target` through an HTTP CONNECT proxy.
 *
 * @param {string|object} proxyInput normaliseHttpProxy-compatible descriptor
 * @param {{host:string,port:number}} target
 * @param {{timeoutMs?:number,signal?:AbortSignal,offline?:boolean,rejectUnauthorized?:boolean}} [options]
 * @returns {Promise<import('node:net').Socket>} connected, paused socket with
 *   any tunnel bytes that arrived with the proxy response already unshifted
 */
export async function connectViaHttpProxy(proxyInput, target, options = {}) {
  const proxy = normaliseHttpProxy(proxyInput);
  const host = bareHost(target?.host);
  const port = Number(target?.port);
  if (host.length === 0) throw new InputError('CONNECT target host is required', 'ATK_INVALID_ARGS');
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new InputError('CONNECT target port must be an integer between 1 and 65535', 'ATK_INVALID_ARGS');
  }
  assertNetworkAllowed(proxy.host, options, 'connect to HTTP proxy');
  assertNetworkAllowed(host, options, 'reach CONNECT target');
  if (options.signal?.aborted) throw abortError(options.signal);
  const timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
    ? Math.floor(options.timeoutMs)
    : DEFAULT_TIMEOUT_MS;

  const socket = await openProxySocket(proxy, timeoutMs, options.signal, options.rejectUnauthorized);
  try {
    await performConnect(socket, proxy, host, port, timeoutMs, options.signal);
    return socket;
  } catch (error) {
    socket.destroy();
    throw error;
  }
}
