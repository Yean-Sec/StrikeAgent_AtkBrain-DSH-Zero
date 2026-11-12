/**
 * AtkBrain Host half.
 *
 * The plugin is one bundle with two halves:
 *  - this Host half registers the `atkGraph` session projection, the workbench
 *    tools and the pentest methodology prompt section;
 *  - `client.js` registers the session-bound Attack Graph view.
 *
 * Graph state is derived from durable `tool/result.meta` ops on the lead
 * session. A resident teammate runs in its own session, so its tool result
 * never reaches that log. Those ops are appended to the lead session as an
 * ignorable plugin record and folded here by the same path. There is no
 * second database and no client RPC.
 */
import { PROJECTION_KEY, PROJECTION_STATE_VERSION } from './lib/constants.js';
import { describeConfig, resolveConfig } from './lib/config.js';
import { applyOps, emptyState } from './lib/ops.js';
import { ledgerMeta } from './lib/ledger-host.js';
import { buildView } from './lib/graph.js';
import { buildMethodology } from './lib/prompt.js';
import { createRuntime } from './lib/runtime.js';
import { registerScopeTool } from './lib/tools/scope.js';
import { registerIngestTool } from './lib/tools/ingest.js';
import { registerProbeTool } from './lib/tools/probe.js';
import { registerRecordTool } from './lib/tools/record.js';
import { registerQueryTool } from './lib/tools/query.js';
import { registerReportTool } from './lib/tools/report.js';
import { registerTunnelTool } from './lib/tools/tunnel.js';
import { registerSuperviseTool } from './lib/tools/supervise.js';
import { registerSelfTeamTool } from './lib/tools/selftteam.js';
import { createProxyManager } from './lib/proxy/manager.js';
import { createProxyCompat } from './lib/proxy/compat.js';
import { loadProxySettingsSync } from './lib/proxy/settings.js';
import { loadSettings, publicSettings, updateSurveySettings } from './lib/settings.js';
import { testSurveyProvider } from './lib/survey.js';
import { checkResourceHealth } from './lib/resource-health.js';
import { renderReportExport, reportStateFromWire } from './lib/report-export.js';
import { renderHtmlReport, suggestedHtmlReportName } from './lib/report-html.js';
import { mergeReportNarrative, runReportAi } from './lib/report-ai.js';
import { detectReportTheme } from './lib/theme.js';
import { registerProxyTool } from './lib/tools/proxy.js';
import { registerSurveyTool } from './lib/tools/survey.js';
import { registerArsenalTool } from './lib/tools/arsenal.js';
import { registerCoverageTool } from './lib/tools/coverage.js';
import { registerHypothesisTool } from './lib/tools/hypothesis.js';

export const name = 'atk-brain';
export const inject = ['tools', 'sessionProjections', 'systemPrompt'];

/**
 * Activate the workbench.
 * @param {object} ctx Cordis context of the plugin row.
 * @param {object} rawConfig raw `config` mapping from `cordis.patch.yml`.
 */
export function apply(ctx, rawConfig) {
  const { config, warnings } = resolveConfig(rawConfig);
  const logger = ctx.logger;
  for (const warning of warnings) logger?.warn?.(`atk-brain: ${warning}`);

  const savedProxy = loadProxySettingsSync();
  if (savedProxy.proxyEnabled === true) {
    config.proxyEnabled = true;
    if (typeof savedProxy.proxyMode === 'string') config.proxyMode = savedProxy.proxyMode;
    if (typeof savedProxy.proxyUrl === 'string') config.proxyUrl = savedProxy.proxyUrl;
    if (Array.isArray(savedProxy.proxyPool)) config.proxyPool = savedProxy.proxyPool;
    if (Array.isArray(savedProxy.proxyNoProxy)) config.proxyNoProxy = savedProxy.proxyNoProxy.join(',');
    else if (typeof savedProxy.proxyNoProxy === 'string') config.proxyNoProxy = savedProxy.proxyNoProxy;
    if (typeof savedProxy.proxyFailClosed === 'boolean') config.proxyFailClosed = savedProxy.proxyFailClosed;
  }
  const runtime = createRuntime({ ctx, config, logger });
  const proxyManager = createProxyCompat(createProxyManager({ config, logger }));
  runtime.proxy = proxyManager;
  ctx.effect(() => () => proxyManager.stop(), 'atk-brain: proxy manager cleanup');

  /**
   * Register the loopback status/settings/report routes and start the
   * background checks they expose.
   * @param {object} ownerCtx context owning the route effects
   * @param {object} webServer the `webServer` service
   */
  const mountWebRoutes = (ownerCtx, webServer) => {
    void proxyManager.start().catch((error) => logger?.warn?.(`atkbrain proxy startup failed: ${error instanceof Error ? error.message : String(error)}`));
    ownerCtx.effect(() => webServer.register({
      kind: 'exact',
      path: '/atkbrain/proxy/status',
      handler: (req, res) => {
        if (req?.method !== 'GET') {
          res.writeHead(405, { allow: 'GET' }).end();
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify(proxyManager.status()));
      },
    }), 'atk-brain: proxy status route');
    ownerCtx.effect(() => webServer.register({
      kind: 'exact',
      path: '/atkbrain/proxy',
      handler: (req, res) => {
        if (req?.method !== 'POST') {
          res.writeHead(405, { allow: 'POST' }).end();
          return;
        }
        const chunks = [];
        let bytes = 0;
        req.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > 65536) { req.destroy(); return; }
          chunks.push(chunk);
        });
        req.on('end', async () => {
          try {
            const raw = Buffer.concat(chunks).toString('utf8');
            const body = raw.trim().length > 0 ? JSON.parse(raw) : {};
            const action = String(body.action ?? 'status');
            if (!['status', 'enable', 'disable', 'test', 'rotate'].includes(action)) throw new Error(`unsupported proxy action: ${action}`);
            const result = action === 'status' ? proxyManager.status()
              : action === 'enable' ? await proxyManager.enable({ url: body.url, mode: body.mode, noProxy: body.noProxy, failClosed: body.failClosed })
                : action === 'disable' ? await proxyManager.disable()
                  : action === 'test' ? await proxyManager.test(body.url)
                    : await proxyManager.rotate();
            res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
            res.end(JSON.stringify(result));
          } catch (error) {
            res.writeHead(400, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
            res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
          }
        });
      },
    }), 'atk-brain: proxy control route');
    const readSettingsBody = (req) => new Promise((resolve, reject) => {
      const chunks = [];
      let bytes = 0;
      req.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > 65536) { reject(new Error('settings request is too large')); req.destroy(); return; }
        chunks.push(chunk);
      });
      req.on('end', () => {
        try {
          const raw = Buffer.concat(chunks).toString('utf8');
          resolve(raw.trim().length > 0 ? JSON.parse(raw) : {});
        } catch (error) { reject(error); }
      });
      req.on('error', reject);
    });
    const settingsPayload = async ({ checkTools = true } = {}) => {
      const settings = await loadSettings();
      const health = await checkResourceHealth({ checkTools, settings });
      return {
        checkedAt: new Date().toISOString(),
        settings: publicSettings(settings),
        survey: health.survey,
        proxy: proxyManager.status(),
        resources: health.resources,
      };
    };
    ownerCtx.effect(() => webServer.register({
      kind: 'exact',
      path: '/atkbrain/settings/status',
      handler: (req, res) => {
        if (req?.method !== 'GET') { res.writeHead(405, { allow: 'GET' }).end(); return; }
        void settingsPayload().then((payload) => {
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
          res.end(JSON.stringify(payload));
        }).catch((error) => {
          res.writeHead(500, { 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
        });
      },
    }), 'atk-brain: settings status route');
    ownerCtx.effect(() => webServer.register({
      kind: 'exact',
      path: '/atkbrain/settings',
      handler: (req, res) => {
        if (req?.method !== 'POST') { res.writeHead(405, { allow: 'POST' }).end(); return; }
        void (async () => {
          try {
            const body = await readSettingsBody(req);
            const action = String(body.action ?? 'status');
            if (action === 'check') {
              const payload = await settingsPayload({ checkTools: true });
              res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
              res.end(JSON.stringify(payload));
              return;
            }
            if (action === 'saveSurvey') {
              const provider = String(body.provider ?? '');
              const settings = await updateSurveySettings(provider, body.config ?? {});
              res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
              res.end(JSON.stringify({ ok: true, settings: publicSettings(settings), survey: (await checkResourceHealth({ checkTools: false, settings })).survey }));
              return;
            }
            if (action === 'testSurvey') {
              const provider = String(body.provider ?? '');
              const settings = await loadSettings();
              const result = await testSurveyProvider(settings, provider);
              res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
              res.end(JSON.stringify(result));
              return;
            }
            throw new Error(`unsupported settings action: ${action}`);
          } catch (error) {
            res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
          }
        })();
      },
    }), 'atk-brain: settings control route');
    ownerCtx.effect(() => webServer.register({
      kind: 'exact',
      path: '/atkbrain/report/export',
      handler: (req, res) => {
        if (req?.method !== 'POST') { res.writeHead(405, { allow: 'POST' }).end(); return; }
        const chunks = [];
        let bytes = 0;
        req.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > 8 * 1024 * 1024) { req.destroy(); return; }
          chunks.push(chunk);
        });
        req.on('end', () => {
          void (async () => {
            try {
              const raw = Buffer.concat(chunks).toString('utf8');
              const body = raw.trim().length > 0 ? JSON.parse(raw) : {};
              const format = String(body.format ?? 'markdown');
              if (!['markdown', 'html', 'json', 'csv'].includes(format)) throw new Error(`unsupported report format: ${format}`);
              if (body.model === undefined || body.model === null) throw new Error('report model is required');
              let result;
              let aiWritten = false;
              let aiError = null;
              if (format === 'html' && config.reportAi !== false && typeof body.sessionId === 'string' && body.sessionId.length > 0) {
                const agents = (() => { try { return ownerCtx.get('agents'); } catch { return undefined; } })();
                const agent = agents !== undefined && agents !== null && typeof agents.get === 'function' ? agents.get(body.sessionId) : undefined;
                if (agent?.session !== undefined) {
                  let state = reportStateFromWire(body.model);
                  try {
                    const projected = ownerCtx.sessionProjections.stateOf(agent.session, PROJECTION_KEY);
                    if (projected !== undefined && projected !== null) state = projected;
                  } catch { /* use wire snapshot */ }
                  try {
                    const ai = await runReportAi({
                      ctx,
                      agent,
                      state,
                      timeoutMs: Number(config.reportAiTimeoutMs) || 120000,
                    });
                    if (ai.narrative !== null) {
                      const theme = await detectReportTheme({ ctx, config });
                      const generatedAt = new Date();
                      const renderState = mergeReportNarrative(state, ai.narrative);
                      const content = await renderHtmlReport(renderState, {
                        generatedAt: generatedAt.toISOString(),
                        theme: theme.theme,
                        themeSource: theme.source,
                        reportTeam: 'atkbrain-reporter',
                        narrative: ai.narrative,
                      });
                      result = {
                        filename: `${suggestedHtmlReportName(state.engagement, generatedAt).replace(/\.html$/u, '')}.html`,
                        mime: 'text/html; charset=utf-8',
                        content,
                      };
                      aiWritten = true;
                    } else {
                      aiError = ai.error ?? 'report team returned no narrative';
                    }
                  } catch (error) {
                    aiError = error instanceof Error ? error.message : String(error);
                  }
                } else {
                  aiError = 'current session agent is not available for the report team';
                }
              }
              if (result === undefined) result = await renderReportExport({ wire: body.model, format, ctx, config });
              res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
              res.end(JSON.stringify({ ...result, aiWritten, aiError }));
            } catch (error) {
              res.writeHead(400, { 'content-type': 'application/json; charset=utf-8' });
              res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
            }
          })();
        });
        req.on('error', () => { try { res.writeHead(400).end(); } catch { /* already closed */ } });
      },
    }), 'atk-brain: report export route');
  };

  // Wait for the web surface instead of sampling it once. Cordis activates a
  // plugin as soon as this plugin's own `inject` services exist, which can be
  // before `webServer` is provided (the browser surface is a separate bundle
  // row). Sampling here meant the status/settings/report routes silently never
  // registered and the page reported "状态接口不可用"; a re-provided surface
  // now also re-registers instead of leaving dead routes behind.
  if (typeof ctx.inject === 'function') {
    ctx.inject(['webServer'], (webCtx) => {
      const webServer = webCtx.webServer ?? (() => { try { return webCtx.get('webServer'); } catch { return undefined; } })();
      if (webServer !== undefined && webServer !== null && typeof webServer.register === 'function') mountWebRoutes(webCtx, webServer);
    });
  } else {
    // Minimal hosts without lazy injection: one-shot sample, as before.
    const webServer = (() => { try { return ctx.get('webServer'); } catch { return undefined; } })();
    if (webServer !== undefined && webServer !== null && typeof webServer.register === 'function') mountWebRoutes(ctx, webServer);
  }

  if (config.proxyEnabled === true) {
    void proxyManager.start().catch((error) => logger?.warn?.(`atkbrain proxy startup failed: ${error instanceof Error ? error.message : String(error)}`));
  }

  const stateSchema = { parse: (value) => value };
  const disposeProjection = ctx.sessionProjections.register({
    key: PROJECTION_KEY,
    stateVersion: PROJECTION_STATE_VERSION,
    stateSchema,
    init: () => emptyState(),
    apply: (state, event) => {
      const meta = ledgerMeta(event);
      if (meta === undefined) return state;
      try {
        return applyOps(state, meta.ops, typeof meta.at === 'string' ? meta.at : undefined);
      } catch (error) {
        // A malformed or over-cap op batch must not take down the projection
        // or the live session. The tool already reported its failure to the
        // model; keep the last good state.
        logger?.warn?.(`atk-brain: dropped malformed projection ops: ${error instanceof Error ? error.message : String(error)}`);
        return state;
      }
    },
    wire: {
      viewSchema: stateSchema,
      view: (state) => buildView(state, config),
    },
  });
  ctx.effect(() => () => {
    try {
      disposeProjection();
    } catch {
      /* already disposed with the service */
    }
  }, 'atk-brain: projection');

  registerScopeTool(ctx, config, runtime);
  registerIngestTool(ctx, config, runtime);
  registerProbeTool(ctx, config, runtime);
  registerRecordTool(ctx, config, runtime);
  registerQueryTool(ctx, config, runtime);
  registerReportTool(ctx, config, runtime);
  registerTunnelTool(ctx, config, runtime);
  registerSuperviseTool(ctx, config, runtime);
  registerSelfTeamTool(ctx, config, runtime);
  registerArsenalTool(ctx, config, runtime);
  registerProxyTool(ctx, config, runtime, proxyManager);
  registerSurveyTool(ctx, config, runtime);
  registerCoverageTool(ctx, config, runtime);
  registerHypothesisTool(ctx, config, runtime);

  ctx.systemPrompt.section({
    name: 'atkbrain:methodology',
    order: 2500,
    text: buildMethodology(config),
  });

  ctx.effect(() => () => runtime.dispose(), 'atk-brain: runtime cleanup');
  logger?.info?.(`atk-brain: activated (${describeConfig(config)})`);
}
