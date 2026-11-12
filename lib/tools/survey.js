/**
 * `atkbrain_survey` — FOFA / Hunter / 360 Quake survey queries.
 *
 * The settings page stores credentials. This tool exposes the same configured
 * providers to the agent with credential-free results.
 */
import { TOOL_NAMES } from '../constants.js';
import { loadSettings, publicSettings } from '../settings.js';
import { searchSurvey, testSurveyProvider } from '../survey.js';
import { invalid } from '../util.js';
import { evaluateScope } from '../scope.js';
import { evidenceNodeOp, hostNodeOp, ipNodeOp, serviceNodeOp, webappNodeOp } from './build.js';
import { assertArgs, audit, optionalInteger, registerAtkTool, requireEnum, requireString } from './common.js';

const PROVIDERS = ['fofa', 'hunter', 'quake'];
const ACTIONS = ['status', 'test', 'search', 'pipeline'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'status shows configured providers; test checks one API key; search runs one bounded query; pipeline merges one survey provider for explicit all-assets enumeration.' },
    provider: { type: 'string', enum: PROVIDERS, description: 'Survey provider.' },
    query: { type: 'string', description: 'Provider query syntax, e.g. domain="example.com".' },
    limit: { type: 'integer', description: 'Maximum results (1-100).' },
    ingest: { type: 'boolean', description: 'Auto-ingest scope-filtered results into the attack graph (default true).' },
    note: { type: 'string', description: 'Operator note.' },
    domain: { type: 'string', description: 'Domain for action=pipeline.' },
    allAssets: { type: 'boolean', description: 'Required true for action=pipeline: explicit all-assets/subdomain enumeration.' },
    maxHosts: { type: 'integer', description: 'Pipeline host cap (1-500).' },
  },
};

export function registerSurveyTool(ctx, config, runtime) {
  registerAtkTool(ctx, config, runtime, {
    name: TOOL_NAMES.survey,
    callTitle: 'Survey providers (FOFA / Hunter / Quake)',
    description: 'Query the configured FOFA, 鹰图 Hunter or 360 Quake survey source. Use status first. Results are host/ip/port/url/title only and never include the API key. Scope-filtered results are auto-ingested into the attack graph by default; pass ingest=false to only preview. Use action=pipeline only for explicit all-assets enumeration: it queries one survey provider, scope-filters, and ingests hosts. External scanners are not available.',
    parameters: PARAMETERS,
    timeoutMs: 600000,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (action === 'test' || action === 'search') requireEnum(args, 'provider', PROVIDERS);
      if (action === 'search') requireString(args, 'query', { max: 2000 });
      if (args.limit !== undefined) optionalInteger(args, 'limit', { min: 1, max: 100 });
      if (action === 'pipeline') {
        requireString(args, 'domain', { max: 300 });
        if (args.allAssets !== true) invalid('pipeline is only for explicit all-assets/subdomain enumeration; pass allAssets=true (not for a single-domain/app test)');
        if (args.maxHosts !== undefined) optionalInteger(args, 'maxHosts', { min: 1, max: 500 });
      }
      return action;
    },
    async run({ args, state, exec, config: cfg, deps: runtime }) {
      const settings = await loadSettings();
      if (args.action === 'status') {
        const pub = publicSettings(settings);
        const describe = (id, label) => {
          const provider = pub.survey[id];
          if (!provider.configured) return `${label} not configured`;
          return `${label} configured${provider.enabled === true ? '' : ' (provider toggle off; search may still work with the stored key)'}`;
        };
        return {
          summary: `Survey providers: ${describe('fofa', 'FOFA')}; ${describe('hunter', 'Hunter')}; ${describe('quake', 'Quake')}. Keys are masked on the Settings page. Use action=test to verify the account; action=search auto-ingests scope-filtered results by default.`,
          ops: [],
          details: pub,
        };
      }
      if (args.action === 'test') {
        const result = await testSurveyProvider(settings, args.provider);
        return {
          summary: result.ok ? (result.message || `${args.provider} key usable`) : `${args.provider} key test failed: ${result.message}`,
          ops: [audit(TOOL_NAMES.survey, 'survey.test', args.provider, result.ok ? 'usable' : 'failed', [])],
          details: result,
        };
      }
      if (args.action === 'pipeline') {
        if (!Array.isArray(state.scope?.allow) || state.scope.allow.length === 0) invalid('pipeline requires an authorized engagement allow list; set atkbrain_scope first');
        const domain = String(args.domain ?? '').trim().toLowerCase().replace(/^https?:\/\//u, '').split('/')[0];
        const domainVerdict = evaluateScope(state.scope, { type: 'domain', domain });
        if (!domainVerdict.allowed) invalid(`pipeline domain is outside the recorded scope: ${domain} (${domainVerdict.reason})`);
        const provider = args.provider ?? 'fofa';
        const limit = Math.max(1, Math.min(Number(args.limit) || 100, 100));
        const maxHosts = Math.max(1, Math.min(Number(args.maxHosts) || 200, 500));
        const collected = new Map();
        const addHost = (host) => {
          const value = String(host ?? '').toLowerCase().replace(/\.$/u, '').replace(/^https?:\/\//u, '').split('/')[0].split(':')[0];
          if (value.length === 0 || !value.includes('.')) return;
          const verdict = evaluateScope(state.scope, { type: 'host', host: value });
          if (verdict.allowed) collected.set(value, true);
        };
        addHost(domain);
        let surveyResult;
        try {
          surveyResult = await searchSurvey(await loadSettings(), provider, `domain=\"${domain}\"`, { limit });
        } catch (error) {
          surveyResult = { ok: false, count: 0, results: [], error: error instanceof Error ? error.message : String(error) };
        }
        if (!surveyResult.ok) invalid(`${provider} survey failed: ${surveyResult.error || 'unknown error'}`);
        let skipped = 0;
        for (const row of surveyResult.results ?? []) {
          const host = String(row.host ?? '').trim().replace(/^https?:\/\//u, '').split('/')[0].split(':')[0];
          if (host.length === 0) continue;
          const before = collected.size;
          addHost(host);
          if (collected.size === before) skipped += 1;
        }
        const surveyOps = [];
        for (const host of collected.keys()) {
          if (surveyOps.length >= maxHosts) break;
          surveyOps.push(hostNodeOp(host, { sources: ['survey'], tags: ['survey', 'recon-pipeline'] }));
        }
        const hostList = [...collected.keys()].slice(0, maxHosts);
        const listEvidence = await runtime.writeEvidence(exec.agent, `recon-hosts-${domain}`, hostList.join('\n'), 'text/plain');
        const ops = [
          ...surveyOps,
          evidenceNodeOp(state, { ...listEvidence, label: `recon survey ${domain}` }),
          audit(TOOL_NAMES.survey, 'survey.pipeline', domain, `${hostList.length} host(s) from ${provider}`, [listEvidence.sha256]),
        ];
        return {
          summary: `全资产流水线 ${domain}: ${provider} survey, scope filter, ingest. Merged ${hostList.length} host(s); ${provider} returned ${surveyResult.count}.${collected.size >= maxHosts ? ` Host cap ${maxHosts} reached; narrow scope.` : ''}`,
          ops,
          details: {
            domain,
            allAssets: true,
            provider,
            survey: { count: surveyResult.count, provider },
            mergedHosts: hostList,
            hostListEvidence: listEvidence.relative,
            skippedOutOfScope: skipped,
          },
        };
      }

      if (!Array.isArray(state.scope?.allow) || state.scope.allow.length === 0) {
        invalid('survey search requires an authorized engagement allow list; set atkbrain_scope first');
      }
      const result = await searchSurvey(settings, args.provider, args.query, { limit: args.limit ?? 10 });
      if (!result.ok) invalid(`${args.provider} survey failed: ${result.error || 'unknown error'}`);
      const rows = result.results.slice(0, 100);
      const ops = [];
      let ingested = 0;
      let skipped = 0;
      if (args.ingest !== false && Array.isArray(state.scope?.allow) && state.scope.allow.length > 0) {
        for (const row of rows) {
          const host = String(row.host ?? '').trim().replace(/^https?:\/\//u, '').split('/')[0].split(':')[0];
          const ip = String(row.ip ?? '').trim();
          const url = String(row.url ?? '').trim();
          const candidates = [];
          if (host.length > 0) candidates.push({ type: 'host', host });
          if (ip.length > 0) candidates.push({ type: 'ip', ip });
          for (const candidate of candidates.slice(0, 2)) {
            const verdict = evaluateScope(state.scope, candidate);
            if (!verdict.allowed) { skipped += 1; continue; }
            if (candidate.type === 'ip') ops.push(ipNodeOp(candidate.ip, { sources: [args.provider], tags: ['survey'] }));
            else ops.push(hostNodeOp(candidate.host, { sources: [args.provider], tags: ['survey'] }));
            if (url.length > 0 && candidate.type === 'host') {
              ops.push(serviceNodeOp(candidate.host, Number(row.port) || (/^https:/u.test(url) ? 443 : 80), { protocol: /^https:/u.test(url) ? 'https' : 'http', sources: [args.provider] }));
              ops.push(webappNodeOp(url, { host: candidate.host, port: Number(row.port) || (/^https:/u.test(url) ? 443 : 80), sources: [args.provider] }));
            }
            ingested += 1;
          }
        }
      }
      ops.push(audit(TOOL_NAMES.survey, 'survey.search', args.provider, `${result.count} rows, ${ingested} ingested`, []));
      return {
        summary: `${args.provider} survey returned ${result.count} result(s) for "${args.query}".${rows.length > 0 ? ` ${rows.slice(0, 8).map((row) => row.host || row.ip || row.url).join('; ')}` : ''}${ingested > 0 ? ` Auto-ingested ${ingested} scope-filtered host(s).` : ' Scope filtering is still required before ingest.'}${skipped > 0 ? ` Skipped ${skipped} out-of-scope candidate(s).` : ''}`,
        ops,
        details: { provider: args.provider, query: args.query, count: result.count, results: rows, ingested, skippedOutOfScope: skipped },
      };
    },
  });
}
