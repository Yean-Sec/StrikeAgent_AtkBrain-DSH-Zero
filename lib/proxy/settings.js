/** Persist global proxy settings (0600) outside the graph/session log. */
import { promises as fs, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function proxySettingsPath() {
  return path.join(process.env.HOME || os.homedir(), '.dsh', 'atkbrain', 'proxy.json');
}

export function loadProxySettingsSync(file = proxySettingsPath()) {
  try {
    const data = JSON.parse(readFileSync(file, 'utf8'));
    return data !== null && typeof data === 'object' ? data : {};
  } catch {
    return {};
  }
}

export async function loadProxySettings(file = proxySettingsPath()) {
  try {
    const text = await fs.readFile(file, 'utf8');
    const data = JSON.parse(text);
    return data !== null && typeof data === 'object' ? data : {};
  } catch {
    return {};
  }
}

export async function saveProxySettings(config, file = proxySettingsPath()) {
  const data = {
    version: 1,
    proxyEnabled: config?.proxyEnabled === true,
    proxyMode: config?.proxyMode ?? 'direct',
    proxyUrl: typeof config?.proxyUrl === 'string' ? config.proxyUrl : '',
    proxyPool: Array.isArray(config?.proxyPool) ? config.proxyPool.slice(0, 200) : [],
    proxyNoProxy: Array.isArray(config?.proxyNoProxy) ? config.proxyNoProxy : [String(config?.proxyNoProxy ?? '')].filter(Boolean),
    proxyFailClosed: config?.proxyFailClosed !== false,
    updatedAt: new Date().toISOString(),
  };
  try {
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
    await fs.chmod(file, 0o600).catch(() => {});
  } catch { /* status still works; next apply can retry */ }
  return data;
}
