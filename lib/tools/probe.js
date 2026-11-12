/**
 * `atkbrain_probe` — scoped DNS/TCP/HTTP/TLS collection plus the sandbox
 * boundary check. Probes run from the DSH Host process, not the model's bash,
 * so they are the supported path to a real intranet.
 */
import { TOOL_NAMES, HIGH_VALUE_PORTS, PORT_PROTOCOLS } from '../constants.js';
import { canonicalIp } from '../cidr.js';
import { classifyHostAnswers, probeWildcardZone } from '../wildcard.js';
import { autoVerifyFindings } from '../auto-verify.js';
import { notifyResidentTeams, wakeEngagementTeams } from '../native-teams.js';
import { pendingEscalations } from '../escalation-queue.js';
import { applyOps } from '../ops.js';
import { pendingFindings } from '../verify-queue.js';
import { headerProductVersions } from '../finding-classification.js';
import { canonicalHost, evaluateScope } from '../scope.js';
import { invalid, isPlainObject, parsePortsSpec } from '../util.js';
import {
  evidenceNodeOp,
  findingNodeOp,
  hostNodeOp,
  ipNodeOp,
  link,
  ref,
  registrableDomain,
  serviceNodeOp,
  techNodeOp,
  webappNodeOp,
} from './build.js';
import {
  assertArgs,
  audit,
  optionalInteger,
  optionalString,
  recordEvidence,
  registerAtkTool,
  requireEnum,
  requireString,
  scopeGuard,
} from './common.js';

const ACTIONS = ['dns', 'tcp', 'http', 'tls', 'sandbox'];
const CHECKS = ['fingerprint', 'exposure', 'tls', 'headers', 'cors'];
const DEFAULT_CHECKS = ['fingerprint', 'exposure'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'dns resolves/classifies wildcard DNS; tcp scans ports; http fingerprints and runs safe exposure checks; tls reads a certificate; sandbox compares the agent bash sandbox with the Host plane.' },
    target: { type: 'string', description: 'Host, IP, domain or zone (dns/tcp/tls).' },
    url: { type: 'string', description: 'Absolute http(s) URL for action=http.' },
    ports: { type: 'string', description: 'Port list/ranges, e.g. "80,443,8000-8010". Defaults to a common port set.' },
    port: { type: 'integer', description: 'Single port for action=tls (default 443).' },
    via: { type: 'string', description: 'Active tunnel id from atkbrain_tunnel; routes the probe through that SOCKS5 endpoint.' },
    checks: { type: 'array', items: { type: 'string', enum: CHECKS }, description: 'HTTP checks to run (default fingerprint+exposure).' },
    classifyWildcard: { type: 'boolean', description: 'For dns, also probe the registrable zone for wildcard answers (default true).' },
  },
};

function endpointOf(value) {
  const ip = canonicalIp(value);
  if (ip !== undefined) return { kind: 'ip', key: ip, ip };
  const host = canonicalHost(value);
  if (host.length === 0) invalid(`invalid target: ${value}`);
  return { kind: 'host', key: host, host };
}

function endpointRef(endpoint) {
  return ref(endpoint.kind, endpoint.key);
}

function serviceKey(endpoint, port, transport = 'tcp') {
  return `${transport}:${endpoint.key}:${port}`;
}

function highValueSeverity(port) {
  if (HIGH_VALUE_PORTS.has(port)) return 'high';
  if (port === 6379 || port === 27017 || port === 9200 || port === 2375 || port === 6443 || port === 10250) return 'high';
  return 'medium';
}

function derivedFindingFields(finding, { subjectKey, url, observations }) {
  const template = String(finding.template ?? 'http-exposure');
  const title = String(finding.title ?? template);
  const evidence = String(finding.evidence ?? finding.evidenceText ?? '').trim();
  const severity = String(finding.severity ?? 'info').toLowerCase();
  const status = finding.statusCode ?? observations?.status ?? null;
  const tls = observations?.tls ?? observations?.cert;
  const subject = String(subjectKey ?? '');
  const tlsLike = /tls|certificate|expired|self-signed|weak-tls/iu.test(template + title);
  let description;
  let impact;
  let repro;
  let request;
  let response;
  if (tlsLike) {
    const cert = isPlainObject(tls) ? tls : {};
    const when = cert.validTo ?? (/(?:expired at|notAfter[=:]\s*)([^\s;]+)/iu.exec(evidence)?.[1]);
    description = `目标 ${subject} 的 TLS 证书存在配置问题，证书有效期截止 ${when ?? '未知'}。`;
    impact = '客户端证书校验可能失败或被迫忽略警告，影响传输信任和依赖证书校验的服务可用性。';
    repro = `atkbrain_probe action=tls target=${subject.split(':')[0] || subject} port=${subject.split(':')[1] || 443}`;
    request = `TLS ClientHello\nSNI=${subject.split(':')[0] || subject}`;
    response = [
      'TLS ServerHello / Certificate',
      `subject=${cert.subject ?? 'unknown'}`,
      `issuer=${cert.issuer ?? 'unknown'}`,
      `validFrom=${cert.validFrom ?? 'unknown'}`,
      `validTo=${when ?? 'unknown'}`,
      `protocol=${cert.protocol ?? 'unknown'}`,
    ].join('\n');
  } else if (status !== null) {
    const host = String(url ?? subject).replace(/^https?:\/\//iu, '').split('/')[0];
    const path = String(finding.path ?? '/');
    const headers = isPlainObject(observations?.headers) ? observations.headers : {};
    const headerLines = ['content-type', 'server', 'x-powered-by', 'location']
      .filter((name) => typeof headers[name] === 'string')
      .map((name) => `${name}: ${String(headers[name]).slice(0, 400)}`);
    description = `${title} 在 ${url ?? subject} 被观测到，HTTP 响应包含对应暴露特征；证据已保存到证据文件。`;
    impact = ['info', 'low'].includes(severity)
      ? '该问题属于暴露面/加固项，当前未证明直接入侵影响，需要结合其他证据评估。'
      : '该问题可能扩大攻击面；实际影响以验证结果和 access/data 节点为准。';
    repro = `atkbrain_probe action=http url=${url ?? subject} checks=["fingerprint","exposure","headers"]`;
    request = `GET ${path} HTTP/1.1\nHost: ${host}\nUser-Agent: AtkBrain-Probe\nAccept: */*`;
    response = [`HTTP/1.1 ${status}`, ...headerLines, '', '[response body omitted; see evidence artifact]'].join('\n');
  } else {
    description = `${title} 在 ${subject || '目标'} 被记录，证据已保存到证据文件。`;
    impact = ['info', 'low'].includes(severity) ? '暴露面/加固项，需要进一步验证。' : '可能扩大攻击面，需要二次验证。';
    repro = '用 atkbrain_query action=node 查看证据，并用 atkbrain_probe 或等价只读请求复现两次。';
  }
  return { description, impact, repro, request, response };
}

function findingOps(state, findings, { subjectKey, subjectRef, evidenceId, source, tags, observations, url }) {
  const ops = [];
  if (!Array.isArray(findings)) return ops;
  for (const finding of findings.slice(0, 100)) {
    if (!isPlainObject(finding)) continue;
    const template = String(finding.template ?? 'http-exposure');
    const op = findingNodeOp(state, {
      template,
      title: finding.title ?? template,
      severity: finding.severity,
      status: 'candidate',
      subjectKey,
      evidence: finding.evidence ?? finding.evidenceText,
      remediation: finding.recommendation,
      evidenceIds: evidenceId ? [evidenceId] : [],
      attrs: {
        path: finding.path,
        statusCode: finding.statusCode,
        source: 'plugin',
        ...derivedFindingFields(finding, { subjectKey, url, observations }),
        ...(isPlainObject(finding.attrs) ? finding.attrs : {}),
      },
    });
    ops.push({ ...op, tags: [...new Set([...(op.tags ?? []), 'exposure'])], sources: [source] });
    ops.push(link(subjectRef, ref('finding', op.key), 'affects', { confidence: 0.7 }));
    if (evidenceId !== undefined) {
      ops.push(link(ref('evidence', evidenceId), ref('finding', op.key), 'proves', { confidence: 0.7 }));
    }
  }
  return ops;
}

function hostIdentityOps(state, endpoint, ips, extras = {}) {
  const ops = [];
  const tags = extras.tags ?? [];
  const sources = extras.sources ?? [];
  if (endpoint.kind === 'host') {
    ops.push(hostNodeOp(endpoint.key, {
      declared: extras.declared === true,
      ips,
      tags,
      sources,
      criticality: extras.criticality,
      crownJewel: extras.crownJewel === true,
    }));
    for (const ip of ips) {
      ops.push(ipNodeOp(ip, { tags, sources }));
      ops.push(link(ref('host', endpoint.key), ref('ip', ip), 'resolves_to', { confidence: 0.75 }));
    }
  } else {
    ops.push(ipNodeOp(endpoint.key, { tags, sources }));
  }
  return ops;
}

export function registerProbeTool(ctx, config, deps) {
  registerAtkTool(ctx, config, deps, {
    name: TOOL_NAMES.probe,
    callTitle: 'Probe attack surface',
    description: 'Run a scoped, read-only probe from the DSH Host process: DNS resolution + wildcard classification, TCP port/banner scan, HTTP fingerprint + safe exposure checks, TLS certificate inspection, or the sandbox-boundary check. It records services, web apps, technologies and candidate findings in the attack graph. Never sends exploit payloads.',
    parameters: PARAMETERS,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (action === 'dns' || action === 'tcp' || action === 'tls') {
        if (typeof args.target !== 'string' || args.target.trim().length === 0) invalid(`target is required for action=${action}`);
      }
      if (action === 'http') {
        const url = args.url ?? args.target;
        if (typeof url !== 'string' || !/^https?:\/\//u.test(url)) invalid('url must be an absolute http(s) URL for action=http');
      }
      if (args.ports !== undefined) {
        if (typeof args.ports !== 'string' || args.ports.trim().length === 0) invalid('ports must be a non-empty string');
        parsePortsSpec(args.ports, config.maxPortsPerCall);
      }
      if (args.port !== undefined) optionalInteger(args, 'port', { min: 1, max: 65535 });
      if (args.checks !== undefined) {
        if (!Array.isArray(args.checks)) invalid('checks must be an array');
        for (const check of args.checks) if (!CHECKS.includes(check)) invalid(`unknown check "${check}"`);
      }
      if (args.via !== undefined) requireString(args, 'via', { max: 100 });
      if (args.classifyWildcard !== undefined && typeof args.classifyWildcard !== 'boolean') invalid('classifyWildcard must be a boolean');
      return true;
    },
    async run({ args, state, exec, ctx: toolCtx, config: cfg, deps: runtime }) {
      const action = args.action;
      if (action === 'sandbox') {
        const observations = await deps.runProbe({ action: 'sandbox' }, { config: cfg, resolver: runtime.resolver, signal: exec.signal });
        const evidence = await recordEvidence(runtime, exec, state, undefined, 'probe-sandbox', observations, 'application/json');
        const ops = [evidence.nodeOp, ...evidence.edgeOps];
        const matrix = observations?.matrix ?? {};
        const divergence = matrix.agentSandboxLikely === true && matrix.hostNetworkAllowed !== false;
        if (divergence) {
          ops.push(findingNodeOp(state, {
            template: 'sandbox-boundary-divergence',
            title: 'Agent sandbox and Host-plane network capability differ',
            severity: 'info',
            status: 'verified',
            subjectKey: 'sandbox',
            evidence: JSON.stringify(matrix),
            evidenceIds: [evidence.evidenceId],
            remediation: 'Treat Host-plane tools as the authorized intranet path; document the boundary in the engagement report.',
          }));
        }
        ops.push({
          op: 'node.upsert',
          kind: 'task',
          key: `eng/verify_sandbox/${evidence.evidenceId}`,
          label: 'Review sandbox boundary results',
          attrs: {
            actionType: 'verify_sandbox',
            targetId: 'sandbox',
            priority: 55,
            why: ['host-plane vs agent-bash capability matrix recorded'],
            toolClass: 'manual',
            risk: 'none',
            scopeVerdict: 'allow',
            matrix,
          },
          status: 'pending',
          confidence: 0.5,
        });
        ops.push(audit(TOOL_NAMES.probe, 'sandbox', 'host', matrix, [evidence.evidenceId]));
        return {
          summary: `Sandbox boundary recorded: host network ${matrix.hostNetworkAllowed === true ? 'allowed' : matrix.hostNetworkAllowed === false ? 'blocked' : 'unknown'}, loopback ${matrix.loopbackReachable === true ? 'reachable' : 'unknown'}, DNS ${matrix.dnsReachable === true ? 'reachable' : 'unknown'}${divergence ? '; agent-bash and Host-plane capabilities diverge (routing network work through Host tools is the supported path).' : '.'} Evidence: ${evidence.artifact.relative}.`,
          ops,
          details: { observations, evidence: evidence.artifact },
        };
      }

      let viaSpec;
      if (args.via !== undefined) {
        viaSpec = runtime.tunnels.get(args.via);
        if (viaSpec === undefined) invalid(`tunnel "${args.via}" is not active; call atkbrain_tunnel action=list or open a new tunnel`);
      }

      const source = `atkbrain_probe:${action}`;
      const tags = ['probed'];
      const ops = [];
      const findings = [];
      let observations;

      if (action === 'dns') {
        const raw = String(args.target).trim();
        const maybeIp = canonicalIp(raw);
        if (maybeIp !== undefined) invalid('action=dns requires a host or zone, not an IP');
        const host = canonicalHost(raw);
        const guarded = await scopeGuard({
          deps: runtime,
          state,
          config: cfg,
          target: { type: 'host', host },
          signal: exec.signal,
          resolve: true,
        });
        const resolved = await runtime.resolver.resolveHost(host, { signal: exec.signal });
        const ips = [...new Set([...(resolved?.a ?? []), ...(resolved?.aaaa ?? [])])];
        const answers = {
          a: resolved?.a ?? [],
          aaaa: resolved?.aaaa ?? [],
          cname: resolved?.cname ?? [],
          ns: resolved?.ns ?? [],
          soa: resolved?.soa ?? false,
        };
        const zone = domainOf(host);
        let wildcard;
        if (args.classifyWildcard !== false && zone !== undefined) {
          const allowed = await dnsZoneAllowed({ runtime, state, config: cfg, zone, signal: exec.signal });
          if (allowed.allowed) {
            wildcard = await probeWildcardZone(runtime.resolver, zone, {
              probes: cfg.wildcardProbes,
              rounds: cfg.wildcardRounds,
              timeoutMs: cfg.dnsTimeoutMs,
              signal: exec.signal,
            });
            const classification = classifyHostAnswers(host, answers, { zone, ...wildcard });
            ops.push({
              op: 'node.upsert',
              kind: 'wildcard_zone',
              key: `*.${zone}`,
              label: `*.${zone}`,
              attrs: {
                zone,
                signature: wildcard.signature ?? {},
                probes: Array.isArray(wildcard.probes) ? wildcard.probes.slice(0, 12) : [],
                cdn: wildcard.cdn === true,
                apex: wildcard.apex === true,
                confidence: wildcard.confidence ?? 0,
                reason: wildcard.reason ?? null,
              },
              status: wildcard.status ?? 'inconclusive',
              confidence: wildcard.confidence ?? 0,
            });
            if (classification.status !== 'unknown') {
              ops.push(hostNodeOp(host, {
                declared: false,
                ips,
                tags,
                sources: [source],
                wildcardStatus: classification.status,
                attrs: { wildcardZone: zone, wildcardConfidence: classification.confidence },
              }));
            }
          } else {
            wildcard = { status: 'inconclusive', reason: allowed.reason, probes: [] };
          }
        }
        observations = { action: 'dns', target: host, answers, wildcard, guarded: guarded.evaluation, ips };
        // Host and IP nodes.
        if (!ops.some((op) => op.op === 'node.upsert' && op.kind === 'host')) {
          ops.push(hostNodeOp(host, { declared: false, ips, tags, sources: [source] }));
        }
        for (const ip of ips) {
          ops.push(ipNodeOp(ip, { tags, sources: [source] }));
          ops.push(link(ref('host', host), ref('ip', ip), 'resolves_to', { confidence: 0.8 }));
        }
        for (const cname of answers.cname) {
          const target = canonicalHost(cname);
          if (target.length === 0) continue;
          ops.push(hostNodeOp(target, { tags, sources: [source] }));
          ops.push(link(ref('host', host), ref('host', target), 'cname', { confidence: 0.7 }));
        }
        const domain = zone;
        if (domain !== undefined) {
          ops.push({ op: 'node.upsert', kind: 'domain', key: domain, label: domain, attrs: { name: domain }, status: 'unknown', confidence: 0.7, tags, sources: [source] });
          ops.push(link(ref('domain', domain), ref('host', host), 'contains', { confidence: 0.7 }));
        }
      } else if (action === 'tcp') {
        const endpoint = endpointOf(args.target);
        const guarded = await scopeGuard({
          deps: runtime,
          state,
          config: cfg,
          target: endpoint.kind === 'ip' ? { type: 'ip', ip: endpoint.key } : { type: 'host', host: endpoint.key },
          signal: exec.signal,
          resolve: true,
        });
        const ips = endpoint.kind === 'ip' ? [endpoint.key] : guarded.ips;
        const ports = args.ports !== undefined
          ? parsePortsSpec(args.ports, cfg.maxPortsPerCall)
          : parsePortsSpec('22,80,443,8080,8443', cfg.maxPortsPerCall);
        observations = await deps.runProbe({ action: 'tcp', target: endpoint.key, ports, via: viaSpec }, {
          config: cfg,
          resolver: runtime.resolver,
          signal: exec.signal,
        });
        const evidence = await recordEvidence(runtime, exec, state, endpointRef(endpoint), `probe-tcp-${endpoint.key}`, observations, 'application/json');
        ops.push(evidence.nodeOp, ...evidence.edgeOps);
        ops.push(...hostIdentityOps(state, endpoint, ips, { tags, sources: [source] }));
        for (const result of observations?.results ?? []) {
          if (result?.state !== 'open') continue;
          const protocol = result.protocol ?? PORT_PROTOCOLS[result.port] ?? 'tcp';
          const key = serviceKey(endpoint, result.port, result.transport ?? 'tcp');
          ops.push({
            op: 'node.upsert',
            kind: 'service',
            key,
            label: `${endpoint.key}:${result.port}`,
            attrs: {
              endpoint: endpoint.key,
              port: result.port,
              transport: result.transport ?? 'tcp',
              state: 'open',
              protocol,
              ...(result.banner ? { banner: String(result.banner).slice(0, 2000) } : {}),
              ...(result.ms !== undefined ? { latencyMs: result.ms } : {}),
            },
            status: 'open',
            confidence: 0.8,
            tags,
            sources: [source],
            evidenceIds: [evidence.evidenceId],
          });
          ops.push(link(endpointRef(endpoint), ref('service', key), 'exposes', { confidence: 0.85 }));
          if (HIGH_VALUE_PORTS.has(result.port)) {
            const finding = findingNodeOp(state, {
              template: `exposed-service-${protocol}`,
              title: `Exposed ${protocol} service on ${endpoint.key}:${result.port}`,
              severity: highValueSeverity(result.port),
              status: 'candidate',
              subjectKey: `${endpoint.key}:${result.port}`,
              evidence: `TCP port ${result.port} accepted a connection (${protocol}); banner: ${String(result.banner ?? '').slice(0, 200)}`,
              remediation: `Restrict ${protocol} to trusted networks, require authentication, and patch the service.`,
              evidenceIds: [evidence.evidenceId],
              attrs: { port: result.port, protocol, source: 'plugin' },
            });
            findings.push(finding);
            ops.push(finding);
            ops.push(link(endpointRef(endpoint), ref('finding', finding.key), 'affects', { confidence: 0.7 }));
          }
        }
      } else if (action === 'http') {
        const rawUrl = String(args.url ?? args.target);
        let parsed;
        try {
          parsed = new URL(rawUrl);
        } catch {
          invalid(`invalid URL: ${rawUrl}`);
        }
        if (!['http:', 'https:'].includes(parsed.protocol)) invalid('only http(s) URLs are supported');
        const host = parsed.hostname.toLowerCase();
        const port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
        const guarded = await scopeGuard({
          deps: runtime,
          state,
          config: cfg,
          target: { type: 'url', url: parsed.origin, port },
          signal: exec.signal,
          resolve: true,
        });
        const checks = args.checks !== undefined ? args.checks : DEFAULT_CHECKS;
        observations = await deps.runProbe({ action: 'http', url: rawUrl, checks, via: viaSpec }, {
          config: cfg,
          resolver: runtime.resolver,
          signal: exec.signal,
          scopeGuard: async (nextTarget) => {
            const nextUrl = typeof nextTarget === 'string'
              ? nextTarget
              : (nextTarget?.url ?? nextTarget?.href);
            if (typeof nextUrl !== 'string') invalid('HTTP scope guard received an invalid redirect target');
            const next = new URL(nextUrl);
            await scopeGuard({
              deps: runtime,
              state,
              config: cfg,
              target: { type: 'url', url: next.origin, port: next.port ? Number(next.port) : (next.protocol === 'https:' ? 443 : 80) },
              signal: exec.signal,
              resolve: true,
            });
          },
        });
        const evidence = await recordEvidence(runtime, exec, state, ref('host', host), `probe-http-${host}-${port}`, observations, 'application/json');
        ops.push(evidence.nodeOp, ...evidence.edgeOps);
        ops.push(...hostIdentityOps(state, { kind: 'host', key: host, host }, guarded.ips, { tags, sources: [source], declared: false }));
        const webappUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
        ops.push(webappNodeOp(webappUrl, {
          host,
          port,
          path: parsed.pathname,
          scheme: parsed.protocol.replace(':', ''),
          status: observations?.status,
          title: observations?.title,
          server: observations?.server,
          tags,
          sources: [source],
          attrs: {
            ...(isPlainObject(observations?.headers) ? { headers: observations.headers } : {}),
            ...(observations?.tls ? { tls: observations.tls } : {}),
          },
        }));
        ops.push(link(ref('host', host), ref('webapp', webappUrl), 'exposes', { confidence: 0.85 }));
        const techIds = [];
        for (const techName of Array.isArray(observations?.techs) ? observations.techs.slice(0, 20) : []) {
          if (typeof techName !== 'string' || techName.length === 0) continue;
          ops.push(techNodeOp(techName, { evidence: 'http-fingerprint' }));
          ops.push(link(ref('webapp', webappUrl), ref('tech', techName), 'exposes', { confidence: 0.5 }));
          techIds.push(techName);
        }
        for (const item of headerProductVersions(isPlainObject(observations?.headers) ? observations.headers : {})) {
          const name = `observed/${item.product}/${item.version}`;
          ops.push(techNodeOp(name, { evidence: 'response-header', label: item.label }));
          ops.push(link(ref('webapp', webappUrl), ref('tech', name), 'exposes', { confidence: 0.6 }));
          techIds.push(name);
        }
        const serviceKeyValue = serviceKey({ kind: 'host', key: host }, port, 'tcp');
        ops.push(serviceNodeOp(host, port, {
          transport: 'tcp',
          protocol: port === 443 || parsed.protocol === 'https:' ? 'https' : 'http',
          state: 'open',
          tls: observations?.tls,
          sources: [source],
          confidence: 0.8,
        }));
        ops.push(link(ref('host', host), ref('service', serviceKeyValue), 'exposes', { confidence: 0.8 }));
        const httpFindings = findingOps(state, observations?.findings, {
          subjectKey: webappUrl,
          subjectRef: ref('webapp', webappUrl),
          evidenceId: evidence.evidenceId,
          source,
          tags,
          observations,
          url: webappUrl,
        });
        findings.push(...httpFindings.filter((op) => op.op === 'node.upsert' && op.kind === 'finding'));
        ops.push(...httpFindings);
      } else if (action === 'tls') {
        const endpoint = endpointOf(args.target);
        const port = args.port ?? 443;
        const guarded = await scopeGuard({
          deps: runtime,
          state,
          config: cfg,
          target: endpoint.kind === 'ip' ? { type: 'ip', ip: endpoint.key, port } : { type: 'host', host: endpoint.key, port },
          signal: exec.signal,
          resolve: true,
        });
        observations = await deps.runProbe({ action: 'tls', host: endpoint.key, port, via: viaSpec }, {
          config: cfg,
          resolver: runtime.resolver,
          signal: exec.signal,
        });
        const evidence = await recordEvidence(runtime, exec, state, endpointRef(endpoint), `probe-tls-${endpoint.key}-${port}`, observations, 'application/json');
        ops.push(evidence.nodeOp, ...evidence.edgeOps);
        const ips = endpoint.kind === 'ip' ? [endpoint.key] : guarded.ips;
        ops.push(...hostIdentityOps(state, endpoint, ips, { tags, sources: [source] }));
        const key = serviceKey(endpoint, port, 'tcp');
        ops.push(serviceNodeOp(endpoint.key, port, {
          transport: 'tcp',
          protocol: 'tls',
          state: 'open',
          tls: observations?.cert ?? observations?.tls,
          sources: [source],
          confidence: 0.8,
        }));
        ops.push(link(endpointRef(endpoint), ref('service', key), 'exposes', { confidence: 0.8 }));
        const cert = observations?.cert ?? observations?.tls;
        const tlsDetails = isPlainObject(cert) ? derivedFindingFields({ template: 'expired-tls-certificate', title: `TLS certificate on ${endpoint.key}:${port}`, severity: 'high', evidence: `notAfter=${cert.validTo ?? 'unknown'}` }, { subjectKey: `${endpoint.key}:${port}`, observations: { tls: cert } }) : {};
        if (isPlainObject(cert)) {
          const expires = Date.parse(cert.validTo);
          if (Number.isFinite(expires) && expires < Date.now()) {
            const finding = findingNodeOp(state, {
              template: 'expired-tls-certificate',
              title: `Expired TLS certificate on ${endpoint.key}:${port}`,
              severity: 'medium',
              status: 'candidate',
              subjectKey: `${endpoint.key}:${port}`,
              evidence: `notAfter=${cert.validTo}`,
              evidenceIds: [evidence.evidenceId],
              remediation: 'Renew the certificate and confirm clients validate it.',
              attrs: tlsDetails,
            });
            findings.push(finding);
            ops.push(finding);
            ops.push(link(endpointRef(endpoint), ref('finding', finding.key), 'affects', { confidence: 0.7 }));
          }
          if (cert.selfSigned === true) {
            const finding = findingNodeOp(state, {
              template: 'self-signed-tls-certificate',
              title: `Self-signed TLS certificate on ${endpoint.key}:${port}`,
              severity: 'low',
              status: 'candidate',
              subjectKey: `${endpoint.key}:${port}`,
              evidence: `issuer=${cert.issuer ?? 'unknown'}`,
              evidenceIds: [evidence.evidenceId],
              remediation: 'Use a certificate issued by a trusted CA where the service is meant to be public.',
            });
            findings.push(finding);
            ops.push(finding);
            ops.push(link(endpointRef(endpoint), ref('finding', finding.key), 'affects', { confidence: 0.6 }));
          }
          if (typeof cert.protocol === 'string' && ['TLSv1', 'TLSv1.1'].includes(cert.protocol)) {
            const finding = findingNodeOp(state, {
              template: 'weak-tls-protocol',
              title: `Weak TLS protocol (${cert.protocol}) on ${endpoint.key}:${port}`,
              severity: 'medium',
              status: 'candidate',
              subjectKey: `${endpoint.key}:${port}`,
              evidence: `protocol=${cert.protocol} cipher=${cert.cipher ?? 'unknown'}`,
              evidenceIds: [evidence.evidenceId],
              remediation: 'Require TLS 1.2+ and disable legacy protocols/ciphers.',
            });
            findings.push(finding);
            ops.push(finding);
            ops.push(link(endpointRef(endpoint), ref('finding', finding.key), 'affects', { confidence: 0.7 }));
          }
        }
      }

      const preview = applyOps(state, ops);
      const pending = pendingFindings(Object.values(preview.nodes ?? {}));
      let autoVerification = { ops: [], verified: [], errors: [], skipped: null, queued: [] };
      const wake = cfg.selfTeamMode === 'off'
        ? Promise.resolve(null)
        : (async () => {
          try {
            const agentTeams = toolCtx.get('agentTeams');
            return await wakeEngagementTeams({
              agentTeams,
              agent: exec.agent,
              signal: exec.signal,
              state: preview,
              config: cfg,
              pending,
              forceVerifier: findings.length > 0,
            });
          } catch {
            return null;
          }
        })();
      if (findings.length > 0 && cfg.autoVerifyFindings !== false) {
        try {
          autoVerification = await autoVerifyFindings({
            ctx: toolCtx,
            agent: exec.agent,
            state,
            ops,
            candidates: findings,
            config: cfg,
            writeEvidence: runtime.writeEvidence,
            signal: exec.signal,
            timeoutMs: cfg.verifierTimeoutMs,
          });
          ops.push(...autoVerification.ops);
        } catch (error) {
          autoVerification.errors.push(error instanceof Error ? error.message : String(error));
        }
      }
      await wake;
      if ((autoVerification.verified ?? []).some((entry) => entry.verdict === 'verified') && cfg.selfTeamMode !== 'off') {
        try {
          const agentTeams = toolCtx.get('agentTeams');
          const after = applyOps(preview, autoVerification.ops ?? []);
          await notifyResidentTeams({
            agentTeams,
            agent: exec.agent,
            signal: exec.signal,
            state: after,
            config: cfg,
            pending: pendingFindings(Object.values(after.nodes ?? {})),
            escalationPending: pendingEscalations(after),
            forceEscalation: true,
            justVerified: autoVerification.verified,
          });
        } catch {
          /* the next verified finding notifies evolution again */
        }
      }
      ops.push(audit(TOOL_NAMES.probe, action, args.url ?? args.target ?? 'sandbox', `${findings.length} candidate finding(s)`, []));
      const evidenceLine = ops.find((op) => op.op === 'node.upsert' && op.kind === 'evidence');
      const summary = [
        `atkbrain_probe ${action} completed for ${args.url ?? args.target ?? 'host'}.`,
        action === 'dns' ? `Answers: ${(observations?.answers?.a?.length ?? 0)} A, ${(observations?.answers?.aaaa?.length ?? 0)} AAAA, ${(observations?.answers?.cname?.length ?? 0)} CNAME; wildcard ${observations?.wildcard?.status ?? 'not classified'}.` : '',
        action === 'tcp' ? `Ports: ${(observations?.results ?? []).filter((entry) => entry.state === 'open').length} open of ${(observations?.results ?? []).length} scanned.` : '',
        action === 'http' ? `HTTP ${observations?.status ?? '?'} ${observations?.title ? `“${String(observations.title).slice(0, 80)}”` : ''}; ${findings.length} candidate finding(s).` : '',
        action === 'tls' ? `TLS ${observations?.cert?.protocol ?? observations?.tls?.protocol ?? 'unknown'}; ${findings.length} candidate finding(s).` : '',
        evidenceLine === undefined ? 'No evidence artifact was written.' : `Evidence: ${evidenceLine.attrs?.relative ?? evidenceLine.attrs?.path ?? evidenceLine.key}.`,
        findings.length > 0
          ? `${findings.length} finding(s) entered the verification queue; ${autoVerification.verified.length} reached a secondary verdict in this call. A timeout stays queued for the next Lead turn. Do not keep a subagent running after the Lead has finished.`
          : 'Review the graph. Findings that are not verified or refuted stay queued for the next Lead turn.',
        autoVerification.verified.length > 0
          ? `Verification team: ${autoVerification.verified.map((entry) => `${entry.finding} (${entry.verdict}/${entry.rating})`).join('; ')}.`
          : (autoVerification.errors.length > 0 ? `Verification still queued: ${autoVerification.errors.slice(0, 2).join('; ')}` : ''),
      ].filter(Boolean).join(' ');
      return {
        summary,
        ops,
        details: {
          observations,
          findings: findings.map((finding) => ({ key: finding.key, label: finding.label, severity: finding.attrs?.severity })),
          autoVerification: { verified: autoVerification.verified, errors: autoVerification.errors, skipped: autoVerification.skipped },
          evidence: evidenceLine?.attrs ?? null,
          scope: observations?.guarded ?? null,
        },
      };
    },
  });
}

function domainOf(host) {
  return registrableDomain(host);
}

async function dnsZoneAllowed({ runtime, state, config, zone, signal }) {
  if (!config.requireScope) return { allowed: true };
  if ((state.scope?.allow?.length ?? 0) === 0) return { allowed: false, reason: 'scope.allow is empty' };
  const direct = evaluateScope(state.scope, { type: 'domain', host: zone });
  if (direct.allowed) return { allowed: true };
  try {
    const resolved = await runtime.resolver.resolveHost(zone, { signal });
    const ips = [...new Set([...(resolved?.a ?? []), ...(resolved?.aaaa ?? [])])];
    if (ips.length > 0) {
      const byIp = evaluateScope(state.scope, { type: 'host', host: zone, ips });
      if (byIp.allowed) return { allowed: true };
    }
  } catch {
    // Keep the direct denial reason.
  }
  return { allowed: false, reason: direct.reason };
}
