/**
 * Global egress proxy manager plus an opt-in candidate pool.
 *
 * - `direct`: no proxy is installed (an earlier install is restored).
 * - `custom`: `proxyUrl` or the env var named by `proxyUrlEnv`.
 * - `local`: `proxyLocalUrl` (defaults to a local mixed proxy).
 * - `provider`: fetch a proxy list from `proxyProviderUrl` (text, JSON array or
 *   `{proxies: [...]}`); no remote endpoint is contacted unless configured.
 *
 * The manager owns exactly one global dispatcher. Every public result is
 * credential-masked, health failures never throw, and fail-closed mode installs
 * `http://127.0.0.1:9` (which still leaves loopback direct) when no candidate
 * is available or a health check fails.
 */
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

import { InputError, nowIso } from '../util.js';
import { abortError, timeoutError } from '../socks.js';
import { normaliseHttpProxy, redactProxyText, redactProxyUrl } from './connect.js';
import {
  BLACKHOLE_PROXY_URL,
  directRequest,
  installGlobalProxy,
  proxiedRequest,
} from './runtime.js';

const MODES = ['direct', 'custom', 'local', 'provider'];
const MAX_POOL = 200;
const MAX_HEALTH_CANDIDATES = 5;
const MAX_PROVIDER_BYTES = 1048576;
const MAX_PROVIDER_REDIRECTS = 3;
const PROVIDER_CACHE_MS = 30000;

const DEFAULTS = Object.freeze({
  proxyEnabled: false,
  proxyMode: 'direct',
  proxyUrl: '',
  proxyUrlEnv: '',
  proxyLocalUrl: 'http://127.0.0.1:7890',
  proxyPool: Object.freeze([]),
  proxyProviderUrl: '',
  proxyNoProxy: Object.freeze(['localhost', '127.0.0.1', '::1']),
  proxyFailClosed: false,
  proxyEchoUrl: '',
  proxyCheckIntervalMs: 60000,
  proxyTimeoutMs: 8000,
});

const SENSITIVE_QUERY_RE = /([?&](?:access[-_]?token|api[-_]?key|auth|authorization|credential|credentials|key|passwd|password|secret|token)=)[^&\s]+/giu;

function sanitizeMessage(value) {
  return redactProxyText(String(value ?? ''))
    .replace(SENSITIVE_QUERY_RE, '$1***');
}

function splitList(value) {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) {
    return value.map((entry) => String(entry ?? '').trim()).filter((entry) => entry.length > 0);
  }
  return String(value).split(/[\s,;]+/u).map((entry) => entry.trim()).filter((entry) => entry.length > 0);
}

function poolInputs(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') return splitList(value);
  return [];
}

function boundedInteger(value, fallback, min, max, allowZero = false) {
  if (value === undefined || value === null) return fallback;
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  if (allowZero && number === 0) return 0;
  if (number <= 0) return fallback;
  return Math.min(max, Math.max(min, Math.floor(number)));
}

function normalizeConfig(raw) {
  const source = raw !== null && typeof raw === 'object' ? raw : {};
  const warnings = [];
  const config = {
    ...DEFAULTS,
    proxyPool: [],
    proxyNoProxy: [...DEFAULTS.proxyNoProxy],
  };

  if (source.proxyEnabled !== undefined) {
    if (typeof source.proxyEnabled === 'boolean') config.proxyEnabled = source.proxyEnabled;
    else warnings.push('proxyEnabled must be a boolean; ignored');
  }
  if (source.proxyMode !== undefined) {
    if (MODES.includes(source.proxyMode)) config.proxyMode = source.proxyMode;
    else warnings.push(`proxyMode must be one of ${MODES.join(', ')}; using ${DEFAULTS.proxyMode}`);
  }
  for (const key of ['proxyUrl', 'proxyUrlEnv', 'proxyLocalUrl', 'proxyProviderUrl', 'proxyEchoUrl']) {
    if (source[key] === undefined) continue;
    if (typeof source[key] === 'string') config[key] = source[key].trim();
    else warnings.push(`${key} must be a string; ignored`);
  }
  config.proxyUrlEnv = config.proxyUrlEnv.replace(/^\$/u, '');
  if (source.proxyPool !== undefined) {
    if (Array.isArray(source.proxyPool) || typeof source.proxyPool === 'string') config.proxyPool = [...poolInputs(source.proxyPool)];
    else warnings.push('proxyPool must be an array or a string; ignored');
  }
  if (source.proxyNoProxy !== undefined) {
    if (Array.isArray(source.proxyNoProxy) || typeof source.proxyNoProxy === 'string') config.proxyNoProxy = splitList(source.proxyNoProxy);
    else warnings.push('proxyNoProxy must be an array or a string; ignored');
  }
  if (source.proxyFailClosed !== undefined) {
    if (typeof source.proxyFailClosed === 'boolean') config.proxyFailClosed = source.proxyFailClosed;
    else warnings.push('proxyFailClosed must be a boolean; ignored');
  }
  config.proxyCheckIntervalMs = boundedInteger(source.proxyCheckIntervalMs, DEFAULTS.proxyCheckIntervalMs, 5000, 3600000, true);
  config.proxyTimeoutMs = boundedInteger(source.proxyTimeoutMs, DEFAULTS.proxyTimeoutMs, 500, 120000);
  return { config, warnings };
}

function normalizePatch(patch) {
  const out = { ...patch };
  const aliases = {
    url: 'proxyUrl',
    mode: 'proxyMode',
    noProxy: 'proxyNoProxy',
    failClosed: 'proxyFailClosed',
    providerUrl: 'proxyProviderUrl',
    localUrl: 'proxyLocalUrl',
    echoUrl: 'proxyEchoUrl',
    pool: 'proxyPool',
  };
  for (const [alias, key] of Object.entries(aliases)) {
    if (out[alias] !== undefined && out[key] === undefined) out[key] = out[alias];
  }
  return out;
}

function addCandidate(list, seen, warnings, value, source) {
  try {
    const proxy = normaliseHttpProxy(value);
    if (seen.has(proxy.url)) return;
    seen.add(proxy.url);
    list.push({ ...proxy, source });
  } catch (error) {
    warnings.push(`${source}: ${sanitizeMessage(error instanceof Error ? error.message : String(error))}`);
  }
}

function extractExitIp(body, headers) {
  const headerIp = headers?.['x-exit-ip'] ?? headers?.['x-forwarded-for'];
  if (typeof headerIp === 'string') {
    const first = headerIp.split(',')[0].trim();
    if (net.isIP(first) !== 0) return first;
  }
  const text = String(body ?? '').trim();
  if (text.length === 0) return null;
  try {
    const data = JSON.parse(text);
    if (data !== null && typeof data === 'object') {
      for (const key of ['ip', 'query', 'origin', 'address', 'IPv4']) {
        const value = data[key];
        if (typeof value === 'string' && net.isIP(value.trim()) !== 0) return value.trim();
      }
    }
  } catch { /* plain-text echo */ }
  const v4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/u.exec(text);
  if (v4 !== null && net.isIP(v4[0]) === 4) return v4[0];
  const v6 = /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b/iu.exec(text);
  if (v6 !== null && net.isIP(v6[0]) === 6) return v6[0];
  return null;
}

/**
 * Parse provider bodies: a JSON array, `{proxies:[...]}`, or one URL per text
 * line (blank lines and `#` comments ignored).
 */
export function parseProviderPayload(text) {
  const raw = String(text ?? '').trim();
  if (raw.length === 0) return [];
  try {
    return extractProxyEntries(JSON.parse(raw));
  } catch { /* newline-separated text */ }
  return raw.split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'))
    .map((line) => (line.startsWith('//') ? line.slice(2).trim() : line))
    .filter((line) => line.length > 0);
}

function extractProxyEntries(data) {
  if (Array.isArray(data)) {
    const out = [];
    for (const entry of data) {
      if (typeof entry === 'string') {
        if (entry.trim().length > 0) out.push(entry.trim());
        continue;
      }
      if (entry === null || typeof entry !== 'object') continue;
      const value = entry.url ?? entry.uri ?? entry.proxy ?? entry.address;
      if (typeof value === 'string' && value.trim().length > 0) {
        out.push(value.trim());
        continue;
      }
      if (typeof entry.host === 'string' && entry.host.trim().length > 0) {
        out.push(entry.port === undefined ? entry.host.trim() : `${entry.host.trim()}:${entry.port}`);
      }
    }
    return out;
  }
  if (data !== null && typeof data === 'object') {
    for (const key of ['proxies', 'proxy', 'items', 'data']) {
      if (Array.isArray(data[key])) return extractProxyEntries(data[key]);
    }
  }
  return [];
}

function requestProviderOnce(url, { timeoutMs, maxBytes, signal }) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError(signal));
      return;
    }
    const lib = url.protocol === 'https:' ? https : http;
    let request;
    let timer;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener?.('abort', onAbort);
      if (error !== undefined && error !== null) {
        try { request?.destroy(); } catch { /* already gone */ }
        reject(error);
        return;
      }
      resolve(value);
    };
    const onAbort = () => finish(abortError(signal));
    try {
      request = lib.request(url, {
        method: 'GET',
        headers: {
          accept: 'application/json, text/plain;q=0.9, */*;q=0.5',
          'user-agent': 'AtkBrain/0.1 (authorized-engagement-proxy)',
        },
      }, (response) => {
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          if (settled) return;
          size += chunk.length;
          if (size > maxBytes) {
            finish(new InputError(`proxy provider response exceeded ${maxBytes} bytes`, 'ATK_PROVIDER_RESPONSE'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          finish(null, {
            statusCode: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
        response.on('aborted', () => finish(new InputError('proxy provider response was aborted', 'ATK_PROVIDER_RESPONSE')));
        response.on('error', (error) => finish(error));
      });
    } catch (error) {
      finish(error);
      return;
    }
    timer = setTimeout(() => finish(timeoutError(`proxy provider request timed out after ${timeoutMs}ms`)), timeoutMs);
    request.on('timeout', () => finish(timeoutError(`proxy provider request timed out after ${timeoutMs}ms`)));
    request.on('error', (error) => finish(error));
    signal?.addEventListener?.('abort', onAbort, { once: true });
    request.end();
  });
}

async function fetchProviderText(input, { timeoutMs = 8000, maxBytes = MAX_PROVIDER_BYTES, signal } = {}) {
  let current;
  try {
    current = new URL(String(input ?? '').trim());
  } catch {
    throw new InputError(`invalid proxy provider URL "${redactProxyUrl(input) ?? '[empty]'}"`, 'ATK_INVALID_ARGS');
  }
  for (let hop = 0; hop <= MAX_PROVIDER_REDIRECTS; hop += 1) {
    if (current.protocol !== 'http:' && current.protocol !== 'https:') {
      throw new InputError('proxy provider URL must use http:// or https://', 'ATK_INVALID_ARGS');
    }
    const response = await requestProviderOnce(current, { timeoutMs, maxBytes, signal });
    const location = response.headers.location;
    if ([301, 302, 303, 307, 308].includes(response.statusCode) && typeof location === 'string' && location.length > 0) {
      try {
        current = new URL(location, current);
      } catch {
        throw new InputError('proxy provider returned an invalid redirect location', 'ATK_PROVIDER_RESPONSE');
      }
      continue;
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new InputError(`proxy provider responded HTTP ${response.statusCode}`, 'ATK_PROVIDER_RESPONSE');
    }
    return response.body;
  }
  throw new InputError('proxy provider redirected too many times', 'ATK_PROVIDER_RESPONSE');
}

function mergedNoProxy(config) {
  const list = [
    ...splitList(config.proxyNoProxy),
    ...splitList(process.env.NO_PROXY),
    ...splitList(process.env.no_proxy),
  ];
  return [...new Set(list.map((entry) => entry.trim()).filter((entry) => entry.length > 0))];
}

export class ProxyManager {
  constructor({ config = {}, logger } = {}) {
    const normalized = normalizeConfig(config);
    this.config = normalized.config;
    this.configWarnings = normalized.warnings.slice(-20);
    this.logger = logger;
    this.candidates = [];
    this.activeIndex = 0;
    this.health = [];
    this.installedUrl = null;
    this.dispose = null;
    this.blackholed = false;
    this.dispatcherAvailable = null;
    this.lastError = null;
    this.providerError = null;
    this.providerCache = null;
    this.providerFetchedAt = null;
    this.lastAppliedAt = null;
    this.lastHealthAt = null;
    this.resolveWarnings = [];
    this.timer = null;
    this.started = false;
    this.checking = false;
    this.applying = false;
    this.queue = Promise.resolve();
    this.refreshStaticCandidates();
  }

  /* ------------------------------------------------------------------ */
  /* Candidate resolution                                                */
  /* ------------------------------------------------------------------ */

  proxyUrlFromConfig(warnings) {
    if (this.config.proxyUrl.length > 0) return this.config.proxyUrl;
    const envName = this.config.proxyUrlEnv;
    if (envName.length === 0) return '';
    const envValue = process.env[envName];
    if (typeof envValue === 'string' && envValue.trim().length > 0) return envValue.trim();
    warnings.push(`proxyUrlEnv "${envName}" is not set`);
    return '';
  }

  baseCandidates(warnings) {
    const list = [];
    const seen = new Set();
    if (this.config.proxyMode === 'custom') {
      const url = this.proxyUrlFromConfig(warnings);
      if (url.length > 0) addCandidate(list, seen, warnings, url, 'proxyUrl');
    } else if (this.config.proxyMode === 'local') {
      if (this.config.proxyLocalUrl.length > 0) addCandidate(list, seen, warnings, this.config.proxyLocalUrl, 'proxyLocalUrl');
    }
    return { list, seen };
  }

  appendPoolCandidates(list, seen, warnings) {
    if (this.config.proxyMode === 'direct') return;
    for (const entry of this.config.proxyPool) addCandidate(list, seen, warnings, entry, 'pool');
  }

  setCandidates(list, warnings) {
    this.candidates = list;
    this.resolveWarnings = warnings.slice(-20);
    if (!Number.isInteger(this.activeIndex) || this.activeIndex < 0 || this.activeIndex >= list.length) this.activeIndex = 0;
  }

  refreshStaticCandidates() {
    const warnings = [];
    const { list, seen } = this.baseCandidates(warnings);
    if (this.config.proxyMode === 'provider') {
      for (const entry of this.providerCache ?? []) addCandidate(list, seen, warnings, entry, 'provider');
    }
    this.appendPoolCandidates(list, seen, warnings);
    this.setCandidates(list, warnings);
    return this.candidates;
  }

  async resolveCandidates({ refreshProvider = false, allowProviderFetch = false } = {}) {
    const warnings = [];
    const { list, seen } = this.baseCandidates(warnings);
    if (this.config.proxyMode === 'provider') {
      let entries = [];
      if (allowProviderFetch) {
        entries = await this.providerProxies(refreshProvider);
      } else {
        entries = this.providerCache ?? [];
        if (this.providerCache === null) warnings.push('proxy provider has not been fetched yet');
      }
      for (const entry of entries) addCandidate(list, seen, warnings, entry, 'provider');
    }
    this.appendPoolCandidates(list, seen, warnings);
    this.setCandidates(list, warnings);
    return this.candidates;
  }

  async providerProxies(refresh) {
    if (this.config.proxyMode !== 'provider') return [];
    const providerUrl = this.config.proxyProviderUrl;
    if (providerUrl.length === 0) {
      this.providerError = 'proxyProviderUrl is not configured';
      return [];
    }
    const now = Date.now();
    if (!refresh && this.providerCache !== null && this.providerFetchedAt !== null
      && now - this.providerFetchedAt < PROVIDER_CACHE_MS) {
      return this.providerCache;
    }
    try {
      const text = await fetchProviderText(providerUrl, { timeoutMs: this.config.proxyTimeoutMs });
      const entries = parseProviderPayload(text).slice(0, MAX_POOL);
      this.providerCache = entries;
      this.providerFetchedAt = now;
      this.providerError = entries.length === 0 ? 'proxy provider returned no proxies' : null;
      return entries;
    } catch (error) {
      this.providerCache = [];
      this.providerFetchedAt = now;
      this.providerError = sanitizeMessage(error instanceof Error ? error.message : String(error));
      return [];
    }
  }

  currentCandidate() {
    if (this.candidates.length === 0) return null;
    const index = Math.min(Math.max(this.activeIndex, 0), this.candidates.length - 1);
    return this.candidates[index] ?? null;
  }

  /* ------------------------------------------------------------------ */
  /* Dispatcher lifecycle                                                */
  /* ------------------------------------------------------------------ */

  enqueue(task) {
    const run = this.queue.then(task, task);
    this.queue = run.then(() => undefined, () => undefined);
    return run;
  }

  async install(url) {
    await this.uninstall();
    this.dispose = await installGlobalProxy({
      proxyUrl: url,
      noProxy: this.config.proxyNoProxy,
      logger: this.logger,
    });
    this.installedUrl = url;
    this.dispatcherAvailable = true;
  }

  async uninstall() {
    const dispose = this.dispose;
    this.dispose = null;
    this.installedUrl = null;
    this.blackholed = false;
    if (dispose !== null) {
      try {
        await dispose();
      } catch (error) {
        this.lastError = sanitizeMessage(error instanceof Error ? error.message : String(error));
      }
    }
  }

  async installBlackhole(reason) {
    try {
      await this.install(BLACKHOLE_PROXY_URL);
      this.blackholed = true;
      if (reason !== undefined && reason !== null && String(reason).length > 0) this.lastError = sanitizeMessage(reason);
    } catch (error) {
      this.blackholed = false;
      this.lastError = sanitizeMessage(error instanceof Error ? error.message : String(error));
      if (error?.code === 'ATK_UNDICI_MISSING') this.dispatcherAvailable = false;
    }
  }

  async doApply() {
    if (!this.config.proxyEnabled || this.config.proxyMode === 'direct') {
      await this.uninstall();
      if (this.config.proxyMode === 'direct') this.lastError = null;
      this.lastAppliedAt = nowIso();
      return;
    }
    const candidates = await this.resolveCandidates({ refreshProvider: true, allowProviderFetch: true });
    if (candidates.length === 0) {
      if (this.config.proxyFailClosed) {
        await this.installBlackhole('no proxy candidate is available; fail-closed to http://127.0.0.1:9');
      } else {
        await this.uninstall();
      }
      this.lastAppliedAt = nowIso();
      return;
    }
    const candidate = candidates[this.activeIndex] ?? candidates[0];
    this.activeIndex = Math.max(0, candidates.indexOf(candidate));
    try {
      await this.install(candidate.url);
      this.blackholed = false;
      this.lastError = null;
      this.logger?.debug?.(`atkbrain proxy installed: ${redactProxyUrl(candidate.url)}`);
    } catch (error) {
      this.lastError = sanitizeMessage(error instanceof Error ? error.message : String(error));
      if (error?.code === 'ATK_UNDICI_MISSING') this.dispatcherAvailable = false;
      this.logger?.warn?.(`atkbrain proxy install failed: ${this.lastError}`);
      if (this.config.proxyFailClosed) await this.installBlackhole(this.lastError);
      else await this.uninstall();
    } finally {
      this.lastAppliedAt = nowIso();
    }
  }

  apply() {
    return this.enqueue(async () => {
      this.applying = true;
      try {
        await this.doApply();
      } catch (error) {
        this.lastError = sanitizeMessage(error instanceof Error ? error.message : String(error));
      } finally {
        this.applying = false;
      }
      return this.status();
    });
  }

  async enable(patch) {
    if (patch !== null && typeof patch === 'object' && Object.keys(patch).length > 0) {
      const normalized = { ...normalizePatch(patch), proxyEnabled: true };
      if (normalized.proxyMode === undefined
        && typeof normalized.proxyUrl === 'string'
        && normalized.proxyUrl.trim().length > 0
        && this.config.proxyMode === 'direct') {
        normalized.proxyMode = 'custom';
      }
      return this.configure(normalized);
    }
    this.config.proxyEnabled = true;
    return this.apply();
  }

  async disable() {
    this.config.proxyEnabled = false;
    return this.enqueue(async () => {
      await this.uninstall();
      this.lastError = null;
      this.blackholed = false;
      return this.status();
    });
  }

  async configure(patch) {
    if (patch === null || typeof patch !== 'object') return this.status();
    const patchValue = normalizePatch(patch);
    if (typeof patchValue.url === 'string' && patchValue.url.trim().length > 0) {
      const mode = patchValue.proxyMode ?? this.config.proxyMode;
      if (mode === 'local' && patchValue.proxyLocalUrl === undefined) patchValue.proxyLocalUrl = patchValue.url;
      if (mode === 'provider' && patchValue.proxyProviderUrl === undefined) patchValue.proxyProviderUrl = patchValue.url;
    }
    const normalized = normalizeConfig({ ...this.config, ...patchValue });
    this.config = normalized.config;
    this.configWarnings = normalized.warnings.slice(-20);
    if (this.config.proxyEnabled) return this.apply();
    if (this.dispose !== null) {
      await this.enqueue(async () => {
        await this.uninstall();
        this.lastError = null;
      });
    }
    this.refreshStaticCandidates();
    return this.status();
  }

  set(patch) {
    return this.configure(patch);
  }

  async rotate() {
    if (this.candidates.length === 0) this.refreshStaticCandidates();
    if (this.candidates.length === 0) {
      if (this.config.proxyEnabled) return this.apply();
      return this.status();
    }
    this.activeIndex = (this.activeIndex + 1) % this.candidates.length;
    if (this.config.proxyEnabled) return this.apply();
    return this.status();
  }

  async addPool(entry) {
    const values = poolInputs(entry);
    const seen = new Set();
    for (const value of this.config.proxyPool) {
      try { seen.add(normaliseHttpProxy(value).url); } catch { /* invalid existing entry */ }
    }
    for (const value of values) {
      try {
        const proxy = normaliseHttpProxy(value);
        if (seen.has(proxy.url)) continue;
        seen.add(proxy.url);
        this.config.proxyPool.push(proxy.url);
      } catch (error) {
        this.configWarnings.push(sanitizeMessage(`addPool: ${error instanceof Error ? error.message : String(error)}`));
      }
    }
    if (this.config.proxyPool.length > MAX_POOL) this.config.proxyPool.length = MAX_POOL;
    this.configWarnings = this.configWarnings.slice(-20);
    if (this.config.proxyEnabled) return this.apply();
    this.refreshStaticCandidates();
    return this.status();
  }

  /* ------------------------------------------------------------------ */
  /* Health and exit-IP checks                                           */
  /* ------------------------------------------------------------------ */

  async test(candidateUrl) {
    const checkedAt = nowIso();
    try {
      const echoUrl = this.config.proxyEchoUrl;
      if (echoUrl.length === 0) {
        return {
          ok: false,
          proxy: null,
          mode: 'unknown',
          exitIp: null,
          proxyIp: null,
          directIp: null,
          directStatus: null,
          sameExitIp: false,
          masked: null,
          statusCode: null,
          latencyMs: 0,
          echoUrl: null,
          checkedAt,
          error: 'proxyEchoUrl is not configured',
        };
      }
      let candidate = null;
      if (candidateUrl !== undefined && candidateUrl !== null && String(candidateUrl).trim().length > 0) {
        candidate = normaliseHttpProxy(candidateUrl);
      } else {
        candidate = this.currentCandidate();
      }

      let directResult = null;
      let directError = null;
      try {
        directResult = await directRequest(echoUrl, { timeoutMs: this.config.proxyTimeoutMs });
      } catch (error) {
        directError = sanitizeMessage(error instanceof Error ? error.message : String(error));
      }
      const directIp = directResult === null ? null : extractExitIp(directResult.body, directResult.headers);

      if (candidate === null) {
        let ok = directResult !== null && directResult.statusCode >= 200 && directResult.statusCode < 400 && directIp !== null;
        let error = directError;
        if (ok === false && error === null) error = 'direct echo response did not contain an exit IP';
        return {
          ok,
          proxy: null,
          mode: 'direct',
          exitIp: directIp,
          proxyIp: directIp,
          directIp,
          directStatus: directResult?.statusCode ?? null,
          sameExitIp: directIp !== null,
          masked: null,
          statusCode: directResult?.statusCode ?? null,
          latencyMs: directResult?.latencyMs ?? 0,
          echoUrl: redactProxyUrl(echoUrl),
          checkedAt,
          error,
        };
      }

      let proxyResult = null;
      let proxyError = null;
      try {
        proxyResult = await proxiedRequest(candidate.url, echoUrl, { timeoutMs: this.config.proxyTimeoutMs });
      } catch (error) {
        proxyError = sanitizeMessage(error instanceof Error ? error.message : String(error));
      }
      const exitIp = proxyResult === null ? null : extractExitIp(proxyResult.body, proxyResult.headers);
      let ok = proxyResult !== null && proxyResult.statusCode >= 200 && proxyResult.statusCode < 400 && exitIp !== null;
      let error = proxyError;
      if (ok === false && error === null) error = 'proxy echo response did not contain an exit IP';
      return {
        ok,
        proxy: redactProxyUrl(candidate.url),
        mode: candidate.url === BLACKHOLE_PROXY_URL ? 'fail-closed' : 'proxy',
        exitIp,
        proxyIp: exitIp,
        directIp,
        directStatus: directResult?.statusCode ?? null,
        sameExitIp: exitIp !== null && directIp !== null && exitIp === directIp,
        masked: exitIp !== null && directIp !== null ? exitIp !== directIp : null,
        statusCode: proxyResult?.statusCode ?? null,
        latencyMs: proxyResult?.latencyMs ?? 0,
        echoUrl: redactProxyUrl(echoUrl),
        checkedAt,
        error,
      };
    } catch (error) {
      return {
        ok: false,
        proxy: null,
        mode: 'unknown',
        exitIp: null,
        proxyIp: null,
        directIp: null,
        directStatus: null,
        sameExitIp: false,
        masked: null,
        statusCode: null,
        latencyMs: 0,
        echoUrl: this.config.proxyEchoUrl.length > 0 ? redactProxyUrl(this.config.proxyEchoUrl) : null,
        checkedAt,
        error: sanitizeMessage(error instanceof Error ? error.message : String(error)),
      };
    }
  }

  async enforceFailClosed(results) {
    if (!this.config.proxyEnabled || !this.config.proxyFailClosed) return;
    if (this.blackholed) {
      const candidate = this.currentCandidate();
      if (candidate === null) return;
      const health = results.find((entry) => entry.proxy === candidate.url);
      if (health?.ok === true) {
        await this.enqueue(async () => {
          try {
            await this.install(candidate.url);
            this.blackholed = false;
            this.lastError = null;
          } catch (error) {
            this.lastError = sanitizeMessage(error instanceof Error ? error.message : String(error));
          }
        });
      }
      return;
    }
    if (this.installedUrl === null) return;
    const health = results.find((entry) => entry.proxy === this.installedUrl);
    if (health !== undefined && health.ok === false) {
      await this.enqueue(async () => {
        await this.installBlackhole(`proxy health check failed: ${health.error ?? 'unknown error'}`);
      });
    }
  }

  async refreshHealth() {
    if (this.checking) return this.status();
    this.checking = true;
    try {
      let candidates = this.candidates;
      if (candidates.length === 0) candidates = await this.resolveCandidates({ allowProviderFetch: false });
      const checkedAt = nowIso();
      if (candidates.length === 0) {
        this.health = [];
        this.lastHealthAt = checkedAt;
        if (this.config.proxyEnabled && this.config.proxyFailClosed && this.config.proxyMode !== 'direct') {
          await this.enqueue(async () => {
            await this.installBlackhole('no proxy candidate is available; fail-closed to http://127.0.0.1:9');
          });
        }
        return this.status();
      }
      if (this.config.proxyEchoUrl.length === 0) {
        this.health = candidates.slice(0, MAX_HEALTH_CANDIDATES).map((candidate) => ({
          proxy: candidate.url,
          ok: null,
          skipped: true,
          reason: 'proxyEchoUrl is not configured',
          exitIp: null,
          directIp: null,
          statusCode: null,
          latencyMs: 0,
          error: null,
          checkedAt,
        }));
        this.lastHealthAt = checkedAt;
        return this.status();
      }
      const results = [];
      for (const candidate of candidates.slice(0, MAX_HEALTH_CANDIDATES)) {
        const result = await this.test(candidate.url);
        results.push({
          proxy: candidate.url,
          ok: result.ok,
          skipped: false,
          exitIp: result.exitIp,
          directIp: result.directIp,
          statusCode: result.statusCode,
          latencyMs: result.latencyMs,
          error: result.error,
          checkedAt: result.checkedAt,
        });
      }
      this.health = results;
      this.lastHealthAt = checkedAt;
      await this.enforceFailClosed(results);
    } catch (error) {
      this.lastError = sanitizeMessage(error instanceof Error ? error.message : String(error));
    } finally {
      this.checking = false;
    }
    return this.status();
  }

  /* ------------------------------------------------------------------ */
  /* Lifecycle and public status                                         */
  /* ------------------------------------------------------------------ */

  async start() {
    if (this.started) return this.status();
    this.started = true;
    if (this.config.proxyEnabled) await this.apply();
    else this.refreshStaticCandidates();
    const interval = this.config.proxyCheckIntervalMs;
    if (interval > 0) {
      this.timer = setInterval(() => {
        if (this.config.proxyEnabled) void this.refreshHealth();
      }, interval);
      if (typeof this.timer.unref === 'function') this.timer.unref();
    }
    if (this.config.proxyEnabled && this.config.proxyEchoUrl.length > 0) void this.refreshHealth();
    return this.status();
  }

  async stop() {
    this.started = false;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    await this.enqueue(async () => {
      await this.uninstall();
    });
    return this.status();
  }

  status() {
    const selected = this.currentCandidate();
    const active = this.installedUrl;
    const health = this.health.map((entry) => ({
      proxy: redactProxyUrl(entry.proxy),
      ok: entry.ok,
      skipped: entry.skipped === true,
      exitIp: entry.exitIp ?? null,
      directIp: entry.directIp ?? null,
      statusCode: entry.statusCode ?? null,
      latencyMs: entry.latencyMs ?? null,
      error: entry.error === undefined || entry.error === null ? null : sanitizeMessage(entry.error),
      ...(entry.reason === undefined ? {} : { reason: sanitizeMessage(entry.reason) }),
      checkedAt: entry.checkedAt ?? null,
    }));
    const warnings = [...this.configWarnings, ...this.resolveWarnings];
    if (this.providerError !== null) warnings.push(`provider: ${this.providerError}`);
    return {
      enabled: this.config.proxyEnabled === true,
      mode: this.config.proxyMode,
      installed: this.dispose !== null,
      activeProxy: active === null ? null : redactProxyUrl(active),
      selectedProxy: selected === null ? null : redactProxyUrl(selected.url),
      current: active === null ? null : {
        proxy: redactProxyUrl(active),
        ip: this.health.find((entry) => entry.proxy === active)?.exitIp ?? null,
        latencyMs: this.health.find((entry) => entry.proxy === active)?.latencyMs ?? null,
      },
      blackholed: this.blackholed,
      blocked: this.blackholed,
      failClosed: this.config.proxyFailClosed === true,
      pool: this.candidates.map((candidate) => redactProxyUrl(candidate.url)),
      poolSize: this.candidates.length,
      activeIndex: this.activeIndex,
      noProxy: mergedNoProxy(this.config),
      provider: this.config.proxyProviderUrl.length > 0 ? redactProxyUrl(this.config.proxyProviderUrl) : null,
      providerFetchedAt: this.providerFetchedAt === null ? null : new Date(this.providerFetchedAt).toISOString(),
      providerError: this.providerError,
      echoUrl: this.config.proxyEchoUrl.length > 0 ? redactProxyUrl(this.config.proxyEchoUrl) : null,
      timeoutMs: this.config.proxyTimeoutMs,
      checkIntervalMs: this.config.proxyCheckIntervalMs,
      started: this.started,
      checking: this.checking,
      applying: this.applying,
      dispatcherAvailable: this.dispatcherAvailable,
      lastAppliedAt: this.lastAppliedAt,
      lastHealthAt: this.lastHealthAt,
      lastError: this.lastError,
      warnings: warnings.slice(-20).map((warning) => sanitizeMessage(warning)),
      health,
      config: {
        proxyUrl: this.config.proxyUrl.length > 0 ? redactProxyUrl(this.config.proxyUrl) : null,
        proxyLocalUrl: this.config.proxyLocalUrl.length > 0 ? redactProxyUrl(this.config.proxyLocalUrl) : null,
        proxyProviderUrl: this.config.proxyProviderUrl.length > 0 ? redactProxyUrl(this.config.proxyProviderUrl) : null,
        proxyEchoUrl: this.config.proxyEchoUrl.length > 0 ? redactProxyUrl(this.config.proxyEchoUrl) : null,
        proxyUrlEnv: this.config.proxyUrlEnv.length > 0 ? this.config.proxyUrlEnv : null,
      },
    };
  }
}

export function createProxyManager({ config, logger } = {}) {
  return new ProxyManager({ config, logger });
}
