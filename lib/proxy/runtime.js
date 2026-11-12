/**
 * Process-wide HTTP(S) proxy runtime for the DSH Host plane.
 *
 * `installGlobalProxy` swaps undici's global dispatcher for a factory Agent:
 * proxied origins go through a ProxyAgent, loopback and NO_PROXY origins go
 * through a direct Pool. Built-in `fetch` consults that global dispatcher, so
 * one install covers the plugin, subagents and any other fetch
 * caller in this process. The returned disposer restores the previous
 * dispatcher and destroys the installed Agent.
 *
 * `undici` is imported dynamically so the rest of AtkBrain keeps working (and
 * its tests keep running) when the dependency has not been installed yet.
 * `directRequest`/`proxiedRequest` are one-shot helpers for health checks: they
 * never touch the global dispatcher.
 */
import { createRequire } from 'node:module';
import net from 'node:net';

import { InputError } from '../util.js';
import { abortError, isLoopbackHost, isTimeoutError, timeoutError } from '../socks.js';
import { normaliseHttpProxy, redactProxyText, redactProxyUrl } from './connect.js';

export { redactProxyText, redactProxyUrl };

/** Backwards-compatible alias for the redaction helper. */
export const maskProxyUrl = redactProxyUrl;

/** Symbol used by both bundled and npm undici for their global dispatcher. */
export const GLOBAL_DISPATCHER_KEY = Symbol.for('undici.globalDispatcher.1');
/** Dead local proxy used by fail-closed mode. */
export const BLACKHOLE_PROXY_URL = 'http://127.0.0.1:9';

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_MAX_BODY_BYTES = 65536;

let cachedUndici = null;
let undiciMajor = 0;

function majorOf(version) {
  const match = /^(\d+)/u.exec(String(version ?? ''));
  return match === null ? 0 : Number(match[1]);
}

const NODE_UNDICI_MAJOR = majorOf(process.versions.undici) || 7;

function detectUndiciMajor() {
  if (undiciMajor !== 0) return undiciMajor;
  try {
    const require = createRequire(import.meta.url);
    undiciMajor = majorOf(require('undici/package.json').version);
  } catch {
    undiciMajor = 0;
  }
  return undiciMajor;
}

function toRawHeaders(value) {
  if (Array.isArray(value)) return value;
  if (value === null || typeof value !== 'object') return [];
  const raw = [];
  for (const [name, entry] of Object.entries(value)) {
    if (Array.isArray(entry)) {
      for (const item of entry) raw.push(name, item);
    } else {
      raw.push(name, entry);
    }
  }
  return raw;
}

/**
 * Translate the pre-undici-8 handler protocol used by Node's bundled fetch
 * into the handler protocol used by undici >= 8. Node 24 ships undici 7 while
 * the npm package may be 8.x; without this bridge the built-in fetch throws
 * `UND_ERR_INVALID_ARG` ("invalid onRequestStart method").
 */
function adaptLegacyHandler(handler) {
  return {
    onRequestStart(controller, context) {
      return handler.onConnect?.((reason) => controller.abort(reason), context);
    },
    onResponseStarted() {
      return handler.onResponseStarted?.();
    },
    onResponseStart(controller, statusCode, headers, statusText) {
      const result = handler.onHeaders?.(statusCode, toRawHeaders(headers), () => controller.resume(), statusText);
      if (result === false) controller.pause();
      return result;
    },
    onResponseData(controller, chunk) {
      const result = handler.onData?.(chunk);
      if (result === false) controller.pause();
      return result;
    },
    onResponseEnd(controller, trailers) {
      return handler.onComplete?.(toRawHeaders(trailers));
    },
    onResponseError(controller, error) {
      return handler.onError?.(error);
    },
    onBodySent(chunk) {
      return handler.onBodySent?.(chunk);
    },
    onRequestSent() {
      return handler.onRequestSent?.();
    },
  };
}

class LegacyHandlerDispatcher {
  constructor(inner) {
    this.inner = inner;
  }

  dispatch(options, handler) {
    const adapted = handler !== null && typeof handler === 'object' && typeof handler.onRequestStart === 'function'
      ? handler
      : adaptLegacyHandler(handler);
    return this.inner.dispatch(options, adapted);
  }

  close() {
    return this.inner.close();
  }

  destroy() {
    return this.inner.destroy();
  }
}



/**
 * Import undici on demand and verify the API this module needs.
 * @returns {Promise<object>}
 */
export async function loadUndici() {
  if (cachedUndici !== null) return cachedUndici;
  let module;
  try {
    module = await import('undici');
  } catch (error) {
    throw new InputError(
      `undici is not available (${redactProxyText(error instanceof Error ? error.message : String(error))}); install the "undici" package to use proxy support`,
      'ATK_UNDICI_MISSING',
    );
  }
  for (const name of ['Agent', 'Pool', 'ProxyAgent', 'request']) {
    if (typeof module?.[name] !== 'function') {
      throw new InputError(`undici does not expose ${name}(); proxy support is unavailable`, 'ATK_UNDICI_MISSING');
    }
  }
  cachedUndici = module;
  return module;
}

/** Whether the optional undici dependency can be loaded. */
export async function isUndiciAvailable() {
  try {
    await loadUndici();
    return true;
  } catch {
    return false;
  }
}

function parseNoProxyEntries(value) {
  if (value === undefined || value === null) return [];
  const list = Array.isArray(value) ? value : String(value).split(/[\s,;]+/u);
  return list
    .map((entry) => String(entry ?? '').trim())
    .filter((entry) => entry.length > 0);
}

function originUrl(origin) {
  if (origin instanceof URL) return origin;
  try {
    return new URL(String(origin));
  } catch {
    return null;
  }
}

/**
 * Whether one origin must bypass the proxy.
 * Loopback is always direct; NO_PROXY entries may be host names, domain
 * suffixes (`.example.com` or `example.com`) or `host:port`; `*` bypasses all.
 */
export function isProxyBypassed(origin, noProxy) {
  const url = originUrl(origin);
  if (url === null) return false;
  const host = String(url.hostname ?? '').replace(/^\[|\]$/gu, '').toLowerCase();
  if (isLoopbackHost(host)) return true;
  const port = url.port.length > 0 ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80);
  for (const entry of parseNoProxyEntries(noProxy)) {
    if (entry === '*') return true;
    let value = entry;
    const scheme = /^[a-z][a-z0-9+.-]*:\/\//iu.exec(value);
    if (scheme !== null) value = value.slice(scheme[0].length);
    value = value.split('/')[0].trim();
    if (value.length === 0) continue;
    let entryHost = value;
    let entryPort = null;
    if (value.startsWith('[')) {
      const close = value.indexOf(']');
      if (close > 0) {
        entryHost = value.slice(1, close);
        const rest = value.slice(close + 1);
        if (rest.startsWith(':') && /^\d+$/u.test(rest.slice(1))) entryPort = Number(rest.slice(1));
      }
    } else {
      const colon = value.lastIndexOf(':');
      if (colon > 0 && /^\d+$/u.test(value.slice(colon + 1))) {
        entryHost = value.slice(0, colon);
        entryPort = Number(value.slice(colon + 1));
      }
    }
    entryHost = entryHost.replace(/^\[|\]$/gu, '').replace(/^\*?\./u, '').toLowerCase();
    if (entryHost.length === 0) continue;
    if (entryPort !== null && entryPort !== port) continue;
    if (net.isIP(entryHost) !== 0) {
      if (host === entryHost) return true;
      continue;
    }
    if (host === entryHost || host.endsWith(`.${entryHost}`)) return true;
  }
  return false;
}

function mergedNoProxy(noProxy) {
  return [
    ...parseNoProxyEntries(noProxy),
    ...parseNoProxyEntries(process.env.NO_PROXY),
    ...parseNoProxyEntries(process.env.no_proxy),
  ];
}

/**
 * Install the global proxy dispatcher.
 *
 * @param {{proxyUrl?:string|null,noProxy?:string|string[],logger?:object}} [options]
 *   `proxyUrl` null/empty installs a direct Agent (useful to cancel an earlier
 *   proxy); otherwise an HTTP(S) proxy URL.
 * @returns {Promise<() => Promise<void>>} idempotent disposer that restores the
 *   previous global dispatcher and destroys the installed Agent
 */
export async function installGlobalProxy({ proxyUrl, noProxy, logger } = {}) {
  const undici = await loadUndici();
  let uri = null;
  if (proxyUrl !== undefined && proxyUrl !== null) {
    if (typeof proxyUrl === 'object') {
      uri = normaliseHttpProxy(proxyUrl).url;
    } else {
      const text = String(proxyUrl).trim();
      if (text.length > 0) uri = normaliseHttpProxy(text).url;
    }
  }
  const bypassList = mergedNoProxy(noProxy);

  const agent = new undici.Agent({
    factory: (origin, options) => {
      const originValue = originUrl(origin);
      const bypass = originValue !== null && isProxyBypassed(originValue, bypassList);
      if (uri === null || bypass) return new undici.Pool(origin, options ?? {});
      return new undici.ProxyAgent({ ...(options ?? {}), uri, proxyTunnel: false });
    },
  });

  const needsLegacyBridge = detectUndiciMajor() >= 8 && NODE_UNDICI_MAJOR < 8;
  const dispatcher = needsLegacyBridge ? new LegacyHandlerDispatcher(agent) : agent;
  const previous = globalThis[GLOBAL_DISPATCHER_KEY];
  globalThis[GLOBAL_DISPATCHER_KEY] = dispatcher;
  let disposed = false;

  return async function dispose() {
    if (disposed) return;
    disposed = true;
    if (globalThis[GLOBAL_DISPATCHER_KEY] === dispatcher) {
      if (previous === undefined) {
        try {
          delete globalThis[GLOBAL_DISPATCHER_KEY];
        } catch {
          try { globalThis[GLOBAL_DISPATCHER_KEY] = undefined; } catch { /* leave installed */ }
        }
      } else {
        globalThis[GLOBAL_DISPATCHER_KEY] = previous;
      }
    }
    try {
      if (typeof agent.destroy === 'function') await agent.destroy();
      else await agent.close();
    } catch (error) {
      logger?.debug?.(`proxy dispatcher close failed: ${redactProxyText(error instanceof Error ? error.message : String(error))}`);
    }
  };
}

function positiveInteger(value, fallback) {
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.floor(value);
}

async function requestText(undici, dispatcher, input, options = {}) {
  const url = String(input ?? '').trim();
  if (url.length === 0) throw new InputError('request URL is empty', 'ATK_INVALID_ARGS');
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS);
  const maxBodyBytes = positiveInteger(options.maxBodyBytes, DEFAULT_MAX_BODY_BYTES);
  if (options.signal?.aborted) throw abortError(options.signal);

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const onAbort = () => controller.abort(options.signal.reason);
  options.signal?.addEventListener?.('abort', onAbort, { once: true });
  const started = Date.now();

  try {
    const response = await undici.request(url, {
      dispatcher,
      method: options.method ?? 'GET',
      headers: {
        accept: 'application/json, text/plain;q=0.9, */*;q=0.5',
        ...(options.headers ?? {}),
      },
      signal: controller.signal,
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
      maxRedirections: options.maxRedirections ?? 0,
    });
    const chunks = [];
    let size = 0;
    let truncated = false;
    if (response.body !== null && response.body !== undefined) {
      for await (const chunk of response.body) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (size + buffer.length > maxBodyBytes) {
          const remaining = maxBodyBytes - size;
          if (remaining > 0) chunks.push(buffer.subarray(0, remaining));
          size = maxBodyBytes;
          truncated = true;
          break;
        }
        chunks.push(buffer);
        size += buffer.length;
      }
      if (truncated) {
        try { response.body.destroy?.(); } catch { /* best effort */ }
      }
    }
    return {
      url: redactProxyUrl(url),
      statusCode: response.statusCode,
      headers: response.headers,
      body: Buffer.concat(chunks).toString('utf8'),
      truncated,
      latencyMs: Date.now() - started,
    };
  } catch (error) {
    if (timedOut || isTimeoutError(error)) {
      throw timeoutError(`HTTP request to ${redactProxyUrl(url)} timed out after ${timeoutMs}ms`);
    }
    if (options.signal?.aborted) throw abortError(options.signal);
    throw error;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener?.('abort', onAbort);
  }
}

/**
 * One direct request that bypasses the global dispatcher.
 * @returns {Promise<{url:string,statusCode:number,headers:object,body:string,truncated:boolean,latencyMs:number}>}
 */
export async function directRequest(input, options = {}) {
  const undici = await loadUndici();
  const agent = new undici.Agent({ factory: (origin, opts) => new undici.Pool(origin, opts ?? {}) });
  try {
    return await requestText(undici, agent, input, options);
  } finally {
    try {
      if (typeof agent.destroy === 'function') await agent.destroy();
      else await agent.close();
    } catch { /* best effort */ }
  }
}

/**
 * One request through a candidate proxy without touching the global dispatcher.
 * @returns {Promise<{url:string,statusCode:number,headers:object,body:string,truncated:boolean,latencyMs:number}>}
 */
export async function proxiedRequest(proxyInput, input, options = {}) {
  const proxy = normaliseHttpProxy(proxyInput);
  const undici = await loadUndici();
  const agent = new undici.ProxyAgent({ uri: proxy.url, proxyTunnel: false });
  try {
    return await requestText(undici, agent, input, options);
  } finally {
    try {
      if (typeof agent.destroy === 'function') await agent.destroy();
      else await agent.close();
    } catch { /* best effort */ }
  }
}
