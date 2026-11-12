/**
 * Compatibility adapter around the proxy builder's ProxyManager.
 *
 * It keeps the rest of AtkBrain on a narrow API while also publishing the
 * resolved proxy to child processes (the manager itself owns the dispatcher).
 */
import { normaliseHttpProxy, redactProxyUrl } from './connect.js';
import { saveProxySettings } from './settings.js';

const ENV_NAMES = ['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'no_proxy', 'NO_PROXY', 'NODE_USE_ENV_PROXY'];

function publish(activeUrl, noProxy) {
  if (!activeUrl) return;
  const proxy = normaliseHttpProxy(activeUrl);
  const extra = Array.isArray(noProxy) ? noProxy.join(',') : String(noProxy ?? '');
  const merged = [...new Set(['localhost', '127.0.0.1', '::1', '[::1]', ...extra.split(/[,\s]+/u).filter(Boolean)])].join(',');
  process.env.http_proxy = proxy.url;
  process.env.HTTP_PROXY = proxy.url;
  process.env.https_proxy = proxy.url;
  process.env.HTTPS_PROXY = proxy.url;
  process.env.no_proxy = merged;
  process.env.NO_PROXY = merged;
  process.env.NODE_USE_ENV_PROXY = '1';
}

function clearEnv() {
  for (const name of ENV_NAMES) delete process.env[name];
}

export function createProxyCompat(raw) {
  const manager = raw;
  let started = false;
  async function save() {
    if (manager.config) await saveProxySettings(manager.config);
  }

  function activeUrl() {
    try {
      const status = manager.status();
      if (!status?.installed || status.blackholed) return null;
      const candidate = manager.currentCandidate?.();
      return candidate?.url ?? null;
    } catch {
      return null;
    }
  }

  function publishCurrent() {
    const url = activeUrl();
    if (url) publish(url, manager.status?.().noProxy ?? '');
    else clearEnv();
  }

  const compat = {
    raw: manager,
    get config() { return manager.config; },
    async start() {
      if (started) return compat.status();
      started = true;
      await manager.start();
      publishCurrent();
      return compat.status();
    },
    async stop() {
      await manager.stop();
      clearEnv();
      started = false;
    },
    async enable(patch) {
      const result = await manager.enable(patch);
      try { await manager.refreshHealth?.(); } catch { /* health is advisory */ }
      publishCurrent();
      await save();
      return compat.status();
    },
    async disable() {
      const result = await manager.disable();
      clearEnv();
      await save();
      return compat.status(result);
    },
    async set(patch) {
      const result = await manager.configure ? await manager.configure(patch) : await manager.set?.(patch);
      publishCurrent();
      await save();
      return compat.status(result);
    },
    async test(url) {
      const result = await manager.test(url);
      return normalizeTest(result);
    },
    async rotate() {
      const result = await manager.rotate();
      try { await manager.refreshHealth?.(); } catch { /* health is advisory */ }
      publishCurrent();
      await save();
      return compat.status(result);
    },
    async addPool(entries) {
      const result = await manager.addPool(entries);
      await save();
      return compat.status(result);
    },
    currentProxy() {
      const url = activeUrl();
      return url ? normaliseHttpProxy(url) : null;
    },
    currentCandidate() { return manager.currentCandidate?.() ?? null; },
    mask(url) { return url ? redactProxyUrl(String(url)) : null; },
    async handle(action, args = {}) {
      if (action === 'enable') return compat.enable(args);
      if (action === 'disable') return compat.disable();
      if (action === 'set') return compat.set(args);
      if (action === 'test') return compat.test(args.url);
      if (action === 'rotate') return compat.rotate();
      if (action === 'pool') return compat.addPool(args.pool ?? args.url ?? '');
      if (action === 'mode') return compat.set({ mode: args.mode });
      return compat.status();
    },
    status(input) {
      const raw = input ?? manager.status();
      const selected = raw?.current ?? null;
      const health = Array.isArray(raw?.health) ? raw.health : [];
      const current = selected ? {
        proxy: selected.proxy,
        ip: selected.ip ?? null,
        latencyMs: selected.latencyMs ?? null,
      } : null;
      const active = raw?.installed === true && raw?.blackholed !== true;
      const poolLive = raw?.poolSize ?? (Array.isArray(raw?.pool) ? raw.pool.length : 0);
      const exitIp = current?.ip ?? health.find((entry) => entry.ok)?.exitIp ?? null;
      const directIp = health.find((entry) => entry.directIp)?.directIp ?? null;
      return {
        enabled: raw?.enabled === true,
        mode: raw?.mode ?? 'direct',
        active,
        blocked: raw?.blackholed === true || raw?.blocked === true,
        current,
        exitIp,
        directIp,
        masked: exitIp !== null && directIp !== null ? exitIp !== directIp : null,
        pool: { total: poolLive, configured: poolLive, live: active ? 1 : 0 },
        failClosed: raw?.failClosed === true,
        noProxy: raw?.noProxy ?? '',
        transport: 'http(s)',
        error: raw?.lastError ?? null,
        checkedAt: raw?.lastHealthAt ?? null,
        raw,
      };
    },
    get enabled() { return manager.config?.proxyEnabled === true; },
  };
  return compat;
}

function normalizeTest(result) {
  if (!result || typeof result !== 'object') return { ok: false, error: 'proxy test returned no result' };
  return {
    ok: result.ok === true,
    proxy: result.proxy ?? null,
    proxyIp: result.proxyIp ?? result.exitIp ?? null,
    directIp: result.directIp ?? null,
    masked: result.masked ?? result.sameExitIp === false ? true : false,
    latencyMs: result.latencyMs ?? null,
    checkedAt: result.checkedAt ?? null,
    error: result.error ?? null,
  };
}
