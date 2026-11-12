/**
 * AtkBrain settings directory.
 *
 * Text configuration is stored outside the graph/session log with mode 0600.
 * API keys are never returned by the public status or written to graph/report;
 * only a masked fingerprint and "configured" flag are exposed.
 */
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { invalid, isPlainObject } from './util.js';

export const SURVEY_PROVIDERS = Object.freeze(['fofa', 'hunter', 'quake']);
export const PROVIDER_LABELS = Object.freeze({ fofa: 'FOFA', hunter: '鹰图 Hunter', quake: '360 Quake' });

const DEFAULT_PROVIDER = Object.freeze({
  enabled: false,
  baseUrl: '',
  email: '',
  apiKey: '',
  keyEnv: '',
  timeoutMs: 10000,
});

export const DEFAULT_SETTINGS = Object.freeze({
  version: 1,
  survey: Object.freeze({
    fofa: Object.freeze({ ...DEFAULT_PROVIDER, baseUrl: 'https://fofa.info', keyEnv: 'FOFA_KEY' }),
    hunter: Object.freeze({ ...DEFAULT_PROVIDER, baseUrl: 'https://hunter.qianxin.com', keyEnv: 'HUNTER_API_KEY' }),
    quake: Object.freeze({ ...DEFAULT_PROVIDER, baseUrl: 'https://quake.360.net', keyEnv: 'QUAKE_API_KEY' }),
  }),
});

export function settingsPath() {
  return path.join(process.env.HOME || os.homedir(), '.dsh', 'atkbrain', 'settings.json');
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function mergeSettings(raw) {
  const settings = clone(DEFAULT_SETTINGS);
  if (!isPlainObject(raw)) return settings;
  if (isPlainObject(raw.survey)) {
    for (const provider of SURVEY_PROVIDERS) {
      if (isPlainObject(raw.survey[provider])) {
        settings.survey[provider] = { ...settings.survey[provider], ...raw.survey[provider] };
      }
    }
  }
  return settings;
}

export async function loadSettings(file = settingsPath()) {
  try {
    const text = await fs.readFile(file, 'utf8');
    return mergeSettings(JSON.parse(text));
  } catch {
    return clone(DEFAULT_SETTINGS);
  }
}

export async function saveSettings(settings, file = settingsPath()) {
  const merged = mergeSettings(settings);
  try {
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, `${JSON.stringify(merged, null, 2)}\n`, { mode: 0o600 });
    await fs.chmod(file, 0o600).catch(() => {});
  } catch (error) {
    invalid(`settings could not be saved: ${error instanceof Error ? error.message : String(error)}`);
  }
  return merged;
}

function maskSecret(value) {
  const text = String(value ?? '').trim();
  if (text.length === 0) return '';
  if (text.length <= 6) return '******';
  return `****${text.slice(-4)}`;
}

function envValue(provider) {
  const envName = String(provider?.keyEnv ?? '').trim();
  if (envName.length === 0) return '';
  return String(process.env[envName] ?? '').trim();
}

/** Public, credential-free status for the page and tools. */
export function publicSettings(settings) {
  const source = mergeSettings(settings);
  const survey = {};
  for (const id of SURVEY_PROVIDERS) {
    const provider = source.survey[id] ?? DEFAULT_PROVIDER;
    const envKey = envValue(provider);
    const key = String(provider.apiKey ?? '').trim() || envKey;
    survey[id] = {
      id,
      label: PROVIDER_LABELS[id],
      enabled: provider.enabled === true,
      baseUrl: provider.baseUrl,
      email: provider.email ?? '',
      keyEnv: provider.keyEnv ?? '',
      configured: key.length > 0,
      keySource: String(provider.apiKey ?? '').trim().length > 0 ? 'settings' : (envKey.length > 0 ? `env:${provider.keyEnv}` : 'none'),
      keyMask: maskSecret(key),
      timeoutMs: Number(provider.timeoutMs) || 10000,
    };
  }
  return { version: 1, survey };
}

/** Raw provider config for a request; never send this to the browser. */
export function effectiveSurvey(settings, id) {
  if (!SURVEY_PROVIDERS.includes(id)) invalid(`unknown survey provider: ${id}`);
  const source = mergeSettings(settings);
  const provider = source.survey[id];
  const envKey = envValue(provider);
  return {
    id,
    enabled: provider.enabled === true,
    baseUrl: String(provider.baseUrl ?? '').replace(/\/+$/u, ''),
    email: String(provider.email ?? '').trim(),
    apiKey: String(provider.apiKey ?? '').trim() || envKey,
    keyEnv: String(provider.keyEnv ?? '').trim(),
    timeoutMs: Math.max(1000, Math.min(Number(provider.timeoutMs) || 10000, 60000)),
    keySource: String(provider.apiKey ?? '').trim().length > 0 ? 'settings' : (envKey.length > 0 ? `env:${provider.keyEnv}` : 'none'),
  };
}

function validUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

/** Update one provider's non-secret and secret fields. */
export async function updateSurveySettings(id, patch, file = settingsPath()) {
  if (!SURVEY_PROVIDERS.includes(id)) invalid(`survey provider must be one of ${SURVEY_PROVIDERS.join(', ')}`);
  if (!isPlainObject(patch)) invalid('survey settings patch must be an object');
  const settings = await loadSettings(file);
  const provider = settings.survey[id];
  if (patch.enabled !== undefined) provider.enabled = patch.enabled === true;
  if (patch.baseUrl !== undefined) {
    if (!validUrl(patch.baseUrl)) invalid('baseUrl must be an http:// or https:// URL');
    provider.baseUrl = String(patch.baseUrl).replace(/\/+$/u, '');
  }
  if (patch.email !== undefined) {
    const email = String(patch.email).trim();
    if (email.length > 0 && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(email)) invalid('email is not a valid address');
    provider.email = email;
  }
  if (patch.keyEnv !== undefined) {
    const name = String(patch.keyEnv).trim();
    if (name.length > 0 && !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) invalid('keyEnv must be an environment variable name');
    provider.keyEnv = name;
  }
  if (patch.timeoutMs !== undefined) {
    const timeout = Number(patch.timeoutMs);
    if (!Number.isFinite(timeout) || timeout < 1000 || timeout > 60000) invalid('timeoutMs must be between 1000 and 60000');
    provider.timeoutMs = Math.floor(timeout);
  }
  if (patch.clearKey === true) provider.apiKey = '';
  else if (typeof patch.apiKey === 'string' && patch.apiKey.trim().length > 0 && !/^\*+$/u.test(patch.apiKey.trim())) {
    provider.apiKey = patch.apiKey.trim();
  }
  return await saveSettings(settings, file);
}

export function surveyConfigured(settings, id) {
  return effectiveSurvey(settings, id).apiKey.length > 0;
}

export function surveyStatus(settings) {
  const pub = publicSettings(settings);
  return {
    providers: SURVEY_PROVIDERS.map((id) => pub.survey[id]),
    configured: SURVEY_PROVIDERS.filter((id) => pub.survey[id].configured).length,
    total: SURVEY_PROVIDERS.length,
  };
}
