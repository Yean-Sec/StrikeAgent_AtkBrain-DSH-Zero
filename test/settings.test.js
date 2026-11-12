/** Settings store, survey credential masking and the four-resource inventory. */
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm, stat } from 'node:fs/promises';

import { loadSettings, publicSettings, updateSurveySettings, surveyStatus } from '../lib/settings.js';
import { searchSurvey, testSurveyProvider } from '../lib/survey.js';
import { checkResourceHealth } from '../lib/resource-health.js';

async function tempSettings() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-settings-'));
  return { dir, file: path.join(dir, 'settings.json') };
}

test('survey settings mask credentials and stay 0600', async () => {
  const { dir, file } = await tempSettings();
  try {
    await updateSurveySettings('fofa', {
      enabled: true,
      baseUrl: 'https://fofa.info',
      email: 'user@example.com',
      apiKey: 'SUPERSECRETKEY',
      keyEnv: 'FOFA_KEY',
    }, file);
    const settings = await loadSettings(file);
    const pub = publicSettings(settings);
    assert.equal(pub.survey.fofa.configured, true);
    assert.equal(pub.survey.fofa.keySource, 'settings');
    assert.equal(pub.survey.fofa.keyMask, '****TKEY');
    assert.equal(JSON.stringify(pub).includes('SUPERSECRETKEY'), false);
    assert.equal((await stat(file)).mode & 0o077, 0);
    assert.equal(surveyStatus(settings).configured, 1);

    // Blank/masked keys keep the stored secret; clearKey removes it.
    await updateSurveySettings('fofa', { apiKey: '' }, file);
    assert.equal(publicSettings(await loadSettings(file)).survey.fofa.configured, true);
    await updateSurveySettings('fofa', { clearKey: true }, file);
    assert.equal(publicSettings(await loadSettings(file)).survey.fofa.configured, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('survey provider tests use account endpoints and redact failures', async () => {
  const { dir, file } = await tempSettings();
  try {
    await updateSurveySettings('fofa', { apiKey: 'TOP-SECRET', email: 'a@b.com' }, file);
    const settings = await loadSettings(file);
    const calls = [];
    const fetchImpl = async (url) => {
      calls.push(String(url));
      return { status: 200, text: async () => JSON.stringify({ error: false, username: 'analyst' }) };
    };
    const ok = await testSurveyProvider(settings, 'fofa', { fetchImpl });
    assert.equal(ok.ok, true);
    assert.match(ok.message, /analyst/u);
    assert.equal(calls[0].includes('/api/v1/info/my'), true);
    assert.equal(JSON.stringify(ok).includes('TOP-SECRET'), false);

    const denied = await testSurveyProvider(settings, 'fofa', {
      fetchImpl: async () => ({ status: 200, text: async () => JSON.stringify({ error: true, errmsg: 'bad TOP-SECRET key' }) }),
    });
    assert.equal(denied.ok, false);
    assert.equal(JSON.stringify(denied).includes('TOP-SECRET'), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('all three survey providers use the documented endpoints and normalize results', async () => {
  const { dir, file } = await tempSettings();
  try {
    await updateSurveySettings('fofa', { apiKey: 'FOFA-KEY', email: 'a@b.com' }, file);
    await updateSurveySettings('hunter', { apiKey: 'HUNTER-KEY' }, file);
    await updateSurveySettings('quake', { apiKey: 'QUAKE-KEY' }, file);
    const settings = await loadSettings(file);
    const calls = [];
    const fetchImpl = async (url, options = {}) => {
      calls.push({ url: String(url), headers: options.headers || {} });
      const u = String(url);
      if (u.includes('/api/v1/info/my')) return { status: 200, text: async () => JSON.stringify({ error: false, username: 'f' }) };
      if (u.includes('/openApi/userInfo')) return { status: 200, text: async () => JSON.stringify({ code: 200 }) };
      if (u.includes('/api/v3/user/info')) return { status: 200, text: async () => JSON.stringify({ code: 0 }) };
      if (u.includes('/api/v1/search/all')) return { status: 200, text: async () => JSON.stringify({ error: false, size: 1, results: [['app.example:443', '203.0.113.9', '443', 'https', 'App']] }) };
      if (u.includes('/openApi/search')) return { status: 200, text: async () => JSON.stringify({ code: 200, data: { arr: [{ ip: '203.0.113.10', domain: 'hunter.example', port: 443, url: 'https://hunter.example', web_title: 'Hunter App' }] } }) };
      if (u.includes('/api/v3/search/quake_service')) return { status: 200, text: async () => JSON.stringify({ code: 0, data: [{ ip: '203.0.113.11', port: 8443, service: { http: { title: 'Quake App', protocol: 'https' } } }] }) };
      return { status: 404, text: async () => '{}' };
    };
    assert.equal((await testSurveyProvider(settings, 'fofa', { fetchImpl })).ok, true);
    assert.equal((await testSurveyProvider(settings, 'hunter', { fetchImpl })).ok, true);
    const quakeTest = await testSurveyProvider(settings, 'quake', { fetchImpl });
    assert.equal(quakeTest.ok, true);
    assert.equal(calls.some((call) => call.url.includes('/openApi/userInfo') && call.url.includes('api-key=HUNTER-KEY')), true);
    assert.equal(calls.some((call) => call.url.includes('/api/v3/user/info') && call.headers['X-QuakeToken'] === 'QUAKE-KEY'), true);

    const fofa = await searchSurvey(settings, 'fofa', 'domain="example.com"', { limit: 5, fetchImpl });
    assert.equal(fofa.ok, true);
    assert.equal(fofa.results[0].host, 'app.example:443');
    assert.equal(fofa.results[0].ip, '203.0.113.9');
    assert.equal(JSON.stringify(fofa).includes('FOFA-KEY'), false);
    const hunter = await searchSurvey(settings, 'hunter', 'domain="hunter.example"', { limit: 5, fetchImpl });
    assert.equal(hunter.results[0].title, 'Hunter App');
    const quake = await searchSurvey(settings, 'quake', 'domain:"quake.example"', { limit: 5, fetchImpl });
    assert.equal(quake.results[0].title, 'Quake App');
    assert.equal(JSON.stringify(quake).includes('QUAKE-KEY'), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('resource health no longer inventories skills, dictionaries or scanners', async () => {
  const health = await checkResourceHealth({ checkTools: false, settings: {} });
  assert.deepEqual(health.resources, {});
  assert.equal(health.survey.total, 3);
});
