/**
 * FOFA / 鹰图 Hunter / 360 Quake survey adapters.
 *
 * Credentials come from the 0600 settings file or a named env var. API calls
 * use the process-wide fetch (and therefore the DSH egress proxy when enabled).
 * Results are normalized to host/ip/port/url/title and never include the key.
 */
import { effectiveSurvey } from './settings.js';

const DEFAULT_BASE = Object.freeze({
  fofa: 'https://fofa.info',
  hunter: 'https://hunter.qianxin.com',
  quake: 'https://quake.360.net',
});

function scrub(text, config) {
  let value = String(text ?? '');
  for (const secret of [config.apiKey, config.email]) {
    if (typeof secret === 'string' && secret.length > 2) value = value.split(secret).join('***');
  }
  return value.replace(/([?&](?:api[-_]?key|key|token|auth)=)[^&\s]+/giu, '$1***').slice(0, 500);
}

async function requestJson(config, url, options = {}, fetchImpl = fetch) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  try {
    const response = await fetchImpl(url, { ...options, signal: controller.signal });
    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { throw new Error(`survey API returned non-JSON (HTTP ${response.status}): ${text.slice(0, 200)}`); }
    return { status: response.status, data };
  } finally {
    clearTimeout(timer);
  }
}

function baseUrl(config, id) {
  return String(config.baseUrl || DEFAULT_BASE[id] || '').replace(/\/+$/u, '');
}

function requireKey(config) {
  if (!config.apiKey) throw new Error(`${config.id} API key is not configured (settings page or ${config.keyEnv || 'env'})`);
  return config.apiKey;
}

function makeUrl(base, pathname, params) {
  const url = new URL(pathname, `${base}/`);
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

function fofaRow(row) {
  if (!Array.isArray(row)) return null;
  const [host = '', ip = '', port = '', protocol = '', title = ''] = row;
  const portNumber = Number.parseInt(String(port), 10) || 0;
  const scheme = String(protocol || 'http') || 'http';
  const hostText = String(host || '');
  let url = '';
  if (hostText.startsWith('http://') || hostText.startsWith('https://')) url = hostText;
  else if (hostText) url = `${scheme}://${hostText}${hostText.includes(':') ? '' : `:${portNumber || 80}`}`;
  return { host: hostText, ip: String(ip || ''), port: portNumber, url, title: String(title || ''), source: 'fofa' };
}

function hunterRow(row) {
  if (row === null || typeof row !== 'object') return null;
  const url = String(row.url ?? row.web_url ?? '').trim();
  const host = String(row.domain ?? row.host ?? '').trim() || (url ? new URL(url).hostname : '');
  return {
    host,
    ip: String(row.ip ?? row.ip_str ?? '').trim(),
    port: Number(row.port ?? 0) || 0,
    url,
    title: String(row.web_title ?? row.title ?? '').trim(),
    source: 'hunter',
  };
}

function quakeRow(row) {
  if (row === null || typeof row !== 'object') return null;
  const service = row.service && typeof row.service === 'object' ? row.service : {};
  const http = service.http && typeof service.http === 'object' ? service.http : {};
  const host = String(row.ip ?? row.host ?? '').trim();
  const port = Number(row.port ?? 0) || 0;
  const title = String(http.title ?? service.title ?? row.title ?? '').trim();
  const protocol = String(http.protocol ?? service.protocol ?? 'http');
  return {
    host,
    ip: String(row.ip ?? ''),
    port,
    url: host && port ? `${protocol}://${host}:${port}` : '',
    title,
    source: 'quake',
  };
}

/** Test only the account/key endpoint; no survey query is charged. */
export async function testSurveyProvider(settings, id, { fetchImpl = fetch } = {}) {
  const config = effectiveSurvey(settings, id);
  try {
    const key = requireKey(config);
    const base = baseUrl(config, id);
    let data;
    if (id === 'fofa') {
      const url = makeUrl(base, '/api/v1/info/my', { key, email: config.email });
      data = (await requestJson(config, url, {}, fetchImpl)).data;
      if (data?.error) throw new Error(String(data.errmsg || 'FOFA rejected the key'));
      return { ok: true, engine: id, message: `FOFA key usable${data?.username ? ` (${String(data.username).slice(0, 60)})` : ''}` };
    }
    if (id === 'hunter') {
      const url = makeUrl(base, '/openApi/userInfo', { 'api-key': key });
      data = (await requestJson(config, url, {}, fetchImpl)).data;
      if (String(data?.code) !== '200') throw new Error(String(data?.message || data?.msg || 'Hunter rejected the key'));
      return { ok: true, engine: id, message: '鹰图 Hunter key usable' };
    }
    const url = makeUrl(base, '/api/v3/user/info', {});
    data = (await requestJson(config, url, { headers: { 'X-QuakeToken': key } }, fetchImpl)).data;
    if (String(data?.code) !== '0') throw new Error(String(data?.message || '360 Quake rejected the key'));
    return { ok: true, engine: id, message: '360 Quake key usable' };
  } catch (error) {
    return { ok: false, engine: id, message: scrub(error instanceof Error ? error.message : String(error), config) };
  }
}

/** Run one bounded survey query. The caller remains responsible for scope. */
export async function searchSurvey(settings, id, query, { limit = 10, fetchImpl = fetch } = {}) {
  const config = effectiveSurvey(settings, id);
  const size = Math.max(1, Math.min(Number(limit) || 10, 100));
  const q = String(query ?? '').trim();
  if (q.length === 0) throw new Error('survey query is required');
  try {
    const key = requireKey(config);
    const base = baseUrl(config, id);
    let rows = [];
    if (id === 'fofa') {
      const url = makeUrl(base, '/api/v1/search/all', {
        key,
        email: config.email,
        qbase64: Buffer.from(q, 'utf8').toString('base64'),
        size,
        page: 1,
        fields: 'host,ip,port,protocol,title',
      });
      const data = (await requestJson(config, url, {}, fetchImpl)).data;
      if (data?.error) throw new Error(String(data.errmsg || 'FOFA query failed'));
      rows = (Array.isArray(data?.results) ? data.results : []).map(fofaRow);
    } else if (id === 'hunter') {
      const url = makeUrl(base, '/openApi/search', {
        'api-key': key,
        search: Buffer.from(q, 'utf8').toString('base64'),
        page: 1,
        page_size: size,
        is_web: 3,
      });
      const data = (await requestJson(config, url, {}, fetchImpl)).data;
      if (String(data?.code) !== '200') throw new Error(String(data?.message || data?.msg || 'Hunter query failed'));
      const list = data?.data?.arr ?? data?.data?.list ?? [];
      rows = (Array.isArray(list) ? list : []).map(hunterRow);
    } else {
      const url = makeUrl(base, '/api/v3/search/quake_service', {});
      const data = (await requestJson(config, url, {
        method: 'POST',
        headers: { 'X-QuakeToken': key, 'content-type': 'application/json' },
        body: JSON.stringify({ query: q, start: 0, size }),
      }, fetchImpl)).data;
      if (String(data?.code) !== '0') throw new Error(String(data?.message || '360 Quake query failed'));
      rows = (Array.isArray(data?.data) ? data.data : []).map(quakeRow);
    }
    const results = rows.filter(Boolean).slice(0, size);
    return { ok: true, engine: id, query: q, count: results.length, results };
  } catch (error) {
    return {
      ok: false,
      engine: id,
      query: q,
      count: 0,
      results: [],
      error: scrub(error instanceof Error ? error.message : String(error), config),
    };
  }
}
