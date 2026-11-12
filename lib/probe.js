/**
 * Probe orchestration: one `runProbe(request)` entry point used by the
 * `atkbrain_probe` host tool.
 *
 * Every action returns a structured observation object. Scope is enforced
 * defensively: when a `scopeGuard` is supplied it is called before each target
 * (including every redirect target) and a denied verdict throws with the scope
 * reason. Sandbox detection only touches loopback/self state and never scans an
 * external host.
 */
import { access } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { lookup } from 'node:dns/promises';

import { isIp, isPrivateIp } from './cidr.js';
import { COMMON_PORTS, DEFAULT_CONFIG } from './constants.js';
import { createResolver } from './dns.js';
import { cookieFlagFindings, runExposureChecks } from './exposure.js';
import { httpProbe, normaliseVia, parsePorts, scanPorts, tlsProbe } from './net.js';
import { canonicalHost } from './scope.js';
import { abortError, isAbortError, isOfflineMode } from './socks.js';
import { classifyHostAnswers, probeWildcardZone } from './wildcard.js';
import { localizedFindingDetails, localizedFindingTitle } from './finding-i18n.js';
import { InputError, invalid, isPlainObject, truncate } from './util.js';

/** Supported probe actions. */
export const PROBE_ACTIONS = Object.freeze(['dns', 'tcp', 'http', 'tls', 'sandbox']);

const MAX_WARNINGS = 20;
const MAX_PORTS_DEFAULT = 1024;

function describeError(error) {
  return truncate(String(error?.message ?? error ?? 'unknown error').replace(/\s+/gu, ' ').trim(), 200);
}

function resolveConfig(config) {
  const resolved = { ...DEFAULT_CONFIG };
  if (isPlainObject(config)) {
    for (const [key, value] of Object.entries(config)) {
      if (value !== undefined) resolved[key] = value;
    }
  }
  return resolved;
}

/** Choose the explicit tunnel/HTTP proxy or the global proxy for one probe. */
function effectiveVia(request, ctx, targetHost) {
  if (request.via !== undefined && request.via !== null && request.via !== '') return normaliseVia(request.via);
  if (ctx.proxy === null || ctx.config.proxyApplyToProbe !== true) return null;
  const proxy = ctx.proxy.currentProxy?.();
  if (proxy === null || proxy === undefined) return null;
  if (ctx.config.proxyBypassPrivate === true && targetHost && isPrivateIp(targetHost)) return null;
  return proxy;
}

function denyControlError(reason) {
  const error = new InputError(reason, 'ATK_SCOPE_DENIED');
  return error;
}

function normaliseChecks(checks) {
  if (checks === undefined || checks === null) return new Set(['exposure', 'tls', 'headers']);
  const entries = Array.isArray(checks) ? checks : String(checks).split(/[,\s]+/u);
  const normalised = new Set();
  for (const entry of entries) {
    const value = String(entry).trim().toLowerCase();
    if (value === 'full' || value === 'all') {
      for (const name of ['exposure', 'tls', 'headers', 'wildcard']) normalised.add(name);
      continue;
    }
    if (value.length > 0) normalised.add(value);
  }
  return normalised;
}

/** Findings for certificate problems, sharing the exposure finding shape. */
export function certificateFindings(cert) {
  const findings = [];
  if (cert === null || typeof cert !== 'object') return findings;
  const add = (template, title, severity, evidence, recommendation) => {
    const details = localizedFindingDetails(template);
    findings.push({
      template,
      title: localizedFindingTitle(template, title),
      severity,
      statusCode: null,
      path: '/',
      evidence: truncate(evidence, 300),
      description: `${localizedFindingTitle(template, title)}：证书检查发现配置问题，证据已保存到证据文件。`,
      impact: details.impact,
      recommendation: details.remediation || recommendation,
    });
  };
  if (cert.selfSigned === true) {
    add('self-signed-certificate', 'Self-signed TLS certificate', 'medium', `subject: ${cert.subject ?? 'unknown'}; issuer: ${cert.issuer ?? 'unknown'}`, 'Replace the self-signed certificate with one issued by a trusted CA.');
  }
  const notAfter = Date.parse(String(cert.validTo ?? ''));
  if (Number.isFinite(notAfter)) {
    const now = Date.now();
    if (notAfter < now) {
      add('expired-certificate', 'Expired TLS certificate', 'high', `certificate expired at ${cert.validTo}`, 'Renew the certificate and automate expiry monitoring.');
    } else if (notAfter - now < 30 * 86_400_000) {
      add('certificate-expiring-soon', 'TLS certificate expires soon', 'low', `certificate expires at ${cert.validTo}`, 'Renew the certificate before it expires.');
    }
  }
  const protocol = String(cert.protocol ?? '');
  if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
    add('weak-tls-version', 'Weak TLS protocol negotiated', 'medium', `negotiated ${protocol}`, 'Disable TLS 1.0/1.1 and require TLS 1.2 or newer.');
  }
  const cipher = String(cert.cipher ?? '');
  if (/RC4|3DES|DES-CBC|EXPORT|MD5|NULL/iu.test(cipher)) {
    add('weak-tls-cipher', 'Weak TLS cipher negotiated', 'medium', `negotiated ${cipher}`, 'Disable legacy ciphers and prefer AEAD cipher suites.');
  }
  return findings;
}

function addWarnings(target, messages) {
  for (const message of messages) {
    if (typeof message === 'string' && message.length > 0 && !target.includes(message) && target.length < MAX_WARNINGS) {
      target.push(message);
    }
  }
}

function guardDescriptorForUrl(url) {
  const text = String(url ?? '').trim();
  if (/^https?:\/\//iu.test(text)) {
    try {
      const parsed = new URL(text);
      return { type: 'url', url: parsed.href, host: parsed.hostname.toLowerCase() };
    } catch {
      return { type: 'url', url: text };
    }
  }
  const host = canonicalHost(text);
  return isIp(host) ? { type: 'ip', ip: host } : { type: 'host', host };
}

/**
 * Run one probe request.
 *
 * @param {object} request {action:'dns'|'tcp'|'http'|'tls'|'sandbox', target?, ports?, url?, zone?, via?, checks?}
 * @param {object} [context] {config, resolver, signal, scopeGuard}
 */
export async function runProbe(request, context = {}) {
  if (!isPlainObject(request)) invalid('probe request must be an object with an action');
  const action = String(request.action ?? '').trim().toLowerCase();
  if (!PROBE_ACTIONS.includes(action)) {
    invalid(`unknown probe action "${String(request.action)}"; expected one of ${PROBE_ACTIONS.join(', ')}`);
  }
  const config = resolveConfig(context.config);
  const signal = context.signal;
  if (signal?.aborted) throw abortError(signal);
  const offline = isOfflineMode({ offline: config.offline === true });
  const scopeGuard = context.scopeGuard;

  /** Call the external scope guard (if any) and throw on a denied verdict. */
  const guard = async (target) => {
    if (typeof scopeGuard !== 'function') return;
    const verdict = await scopeGuard(target);
    if (verdict === undefined || verdict === null || verdict === true) return;
    if (verdict === false) throw denyControlError(`target denied by the scope guard: ${target.host ?? target.url ?? 'target'}`);
    if (typeof verdict === 'string') throw denyControlError(verdict);
    if (typeof verdict === 'object' && verdict.allowed === false) {
      throw denyControlError(typeof verdict.reason === 'string' && verdict.reason.length > 0
        ? verdict.reason
        : `target denied by the scope guard: ${target.host ?? target.url ?? 'target'}`);
    }
  };
  const ctx = { config, signal, offline, guard, resolver: context.resolver ?? null, proxy: context.proxy ?? null };

  if (action === 'dns') return await probeDns(request, ctx);
  if (action === 'tcp') return await probeTcp(request, ctx);
  if (action === 'http') return await probeHttp(request, ctx);
  if (action === 'tls') return await probeTls(request, ctx);
  return await probeSandbox(ctx);
}

/* ------------------------------------------------------------------ */
/* DNS                                                                 */
/* ------------------------------------------------------------------ */

async function probeDns(request, ctx) {
  const target = canonicalHost(request.target ?? request.zone ?? request.name ?? '');
  if (target.length === 0) invalid('dns action requires a target hostname (request.target)');
  const ipLiteral = isIp(target);
  await ctx.guard(ipLiteral ? { type: 'ip', ip: target } : { type: 'host', host: target });

  const warnings = [];
  if (ctx.proxy !== null && ctx.config.proxyApplyToProbe === true) warnings.push('DNS resolution stays local; the HTTP(S) proxy does not route DNS queries');
  const resolver = ctx.resolver ?? createResolver({
    servers: ctx.config.dnsResolvers,
    timeoutMs: ctx.config.dnsTimeoutMs,
    offline: ctx.offline,
  });

  if (ipLiteral) {
    const ipv6 = target.includes(':');
    return {
      action: 'dns',
      target,
      status: 'ok',
      answers: { a: ipv6 ? [] : [target], aaaa: ipv6 ? [target] : [], cname: [], ns: [], soa: false },
      wildcard: null,
      warnings,
    };
  }

  let resolved;
  try {
    resolved = await resolver.resolveHost(target);
  } catch (error) {
    if (error instanceof InputError || isAbortError(error, ctx.signal)) throw error;
    warnings.push(`DNS resolution failed: ${describeError(error)}`);
    resolved = { status: 'error', a: [], aaaa: [], cname: [], ns: [], soa: false };
  }

  const checks = normaliseChecks(request.checks ?? ['wildcard']);
  const wantWildcard = checks.has('wildcard');
  const zone = canonicalHost(request.zone ?? target);
  let wildcard = null;
  if (wantWildcard && zone.length > 0) {
    try {
      const result = await probeWildcardZone(resolver, zone, {
        probes: ctx.config.wildcardProbes,
        rounds: ctx.config.wildcardRounds,
        timeoutMs: ctx.config.dnsTimeoutMs,
        signal: ctx.signal,
      });
      wildcard = {
        status: result.status,
        confidence: result.confidence,
        signature: result.signature,
        probes: result.probes,
      };
      addWarnings(warnings, result.warnings);
      const classification = classifyHostAnswers(target, resolved, result);
      addWarnings(warnings, [`host classification: ${classification.status} (${classification.reason})`]);
    } catch (error) {
      if (error instanceof InputError || isAbortError(error, ctx.signal)) throw error;
      warnings.push(`wildcard probe failed: ${describeError(error)}`);
    }
  }

  return {
    action: 'dns',
    target,
    status: resolved.status,
    answers: {
      a: resolved.a,
      aaaa: resolved.aaaa,
      cname: resolved.cname,
      ns: resolved.ns,
      soa: resolved.soa === true,
    },
    wildcard,
    warnings,
  };
}

/* ------------------------------------------------------------------ */
/* TCP                                                                 */
/* ------------------------------------------------------------------ */

async function probeTcp(request, ctx) {
  const target = String(request.target ?? request.host ?? '').trim();
  if (target.length === 0) invalid('tcp action requires a target host or IP (request.target)');
  const maxPorts = Number.isInteger(ctx.config.maxPortsPerCall) ? ctx.config.maxPortsPerCall : MAX_PORTS_DEFAULT;
  const ports = request.ports === undefined || request.ports === null
    ? [...COMMON_PORTS]
    : parsePorts(request.ports, { max: maxPorts });
  await ctx.guard(isIp(target) ? { type: 'ip', ip: target } : { type: 'host', host: target });
  const via = effectiveVia(request, ctx, target);
  const results = await scanPorts(target, ports, {
    concurrency: ctx.config.probeConcurrency,
    timeoutMs: ctx.config.probeTimeoutMs,
    signal: ctx.signal,
    offline: ctx.offline,
    banner: request.banner === true,
    ...(via !== null ? { via } : {}),
  });
  const counts = { open: 0, closed: 0, filtered: 0 };
  for (const result of results) {
    if (result.state in counts) counts[result.state] += 1;
  }
  const open = results.filter((result) => result.state === 'open');
  const warnings = [];
  if (open.length !== results.length) {
    warnings.push(`port scan ${target}: ${results.length} probed, ${counts.open} open, ${counts.closed} closed, ${counts.filtered} filtered`);
  }
  return { action: 'tcp', target, results: open, warnings };
}

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */

async function probeHttp(request, ctx) {
  const url = String(request.url ?? request.target ?? '').trim();
  if (url.length === 0) invalid('http action requires a url (request.url)');
  await ctx.guard(guardDescriptorForUrl(url));
  const checks = normaliseChecks(request.checks);
  let via = null;
  try { via = effectiveVia(request, ctx, new URL(url).hostname); } catch { via = null; }
  const warnings = [];
  /** Redirects are re-checked against the scope before they are followed. */
  const onRedirect = async (nextUrl) => {
    await ctx.guard(guardDescriptorForUrl(nextUrl));
  };

  let result;
  try {
    result = await httpProbe(url, {
      timeoutMs: ctx.config.probeTimeoutMs,
      maxBodyBytes: ctx.config.maxHttpBodyBytes,
      followRedirects: ctx.config.followRedirects,
      headers: isPlainObject(request.headers) ? request.headers : undefined,
      onRedirect,
      signal: ctx.signal,
      offline: ctx.offline,
      ...(via !== null ? { via } : {}),
    });
  } catch (error) {
    if (error instanceof InputError || isAbortError(error, ctx.signal)) throw error;
    warnings.push(`HTTP request failed: ${describeError(error)}`);
    return {
      action: 'http',
      url,
      status: 0,
      headers: {},
      title: undefined,
      server: undefined,
      techs: [],
      findings: [],
      warnings,
    };
  }

  const findings = [];
  if (checks.has('exposure') || checks.has('headers')) {
    try {
      const probed = new URL(result.url);
      const exposure = await runExposureChecks(probed.origin, {
        paths: checks.has('exposure') ? undefined : [],
        extraPaths: probed.pathname && probed.pathname !== '/' ? [probed.pathname] : [],
        timeoutMs: ctx.config.probeTimeoutMs,
        maxBodyBytes: ctx.config.maxHttpBodyBytes,
        signal: ctx.signal,
        offline: ctx.offline,
        ...(via !== null ? { via } : {}),
      });
      findings.push(...exposure);
    } catch (error) {
      if (error instanceof InputError || isAbortError(error, ctx.signal)) throw error;
      warnings.push(`exposure checks failed: ${describeError(error)}`);
    }
  }
  if (result.headers && Number(result.status) >= 200 && Number(result.status) < 300) {
    let https = false;
    let path = '/';
    try {
      const probed = new URL(result.url);
      https = probed.protocol === 'https:';
      path = probed.pathname || '/';
    } catch { /* the status line still carries the cookie flags */ }
    findings.push(...cookieFlagFindings(result.headers, { https, path, status: result.status }));
  }
  if (result.tls !== undefined && checks.has('tls')) findings.push(...certificateFindings(result.tls));

  return {
    action: 'http',
    url: result.url,
    status: result.status,
    headers: result.headers,
    title: result.title,
    server: result.server,
    techs: result.techs,
    findings,
    ...(result.tls !== undefined ? { tls: result.tls } : {}),
    warnings,
  };
}

/* ------------------------------------------------------------------ */
/* TLS                                                                 */
/* ------------------------------------------------------------------ */

async function probeTls(request, ctx) {
  const host = String(request.target ?? request.host ?? '').trim();
  if (host.length === 0) invalid('tls action requires a target host (request.target)');
  const port = Number(request.port ?? 443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) invalid(`invalid TLS port ${request.port} (expected 1-65535)`);
  await ctx.guard(isIp(host) ? { type: 'ip', ip: host, port } : { type: 'host', host, port });
  const via = effectiveVia(request, ctx, host);
  const warnings = [];
  let cert;
  try {
    cert = await tlsProbe(host, port, {
      timeoutMs: ctx.config.probeTimeoutMs,
      servername: typeof request.servername === 'string' ? request.servername : undefined,
      signal: ctx.signal,
      offline: ctx.offline,
      ...(via !== null ? { via } : {}),
    });
  } catch (error) {
    if (error instanceof InputError || isAbortError(error, ctx.signal)) throw error;
    warnings.push(`TLS handshake failed: ${describeError(error)}`);
    return { action: 'tls', host, port, cert: null, findings: [], warnings };
  }
  return { action: 'tls', host, port, cert, findings: certificateFindings(cert), warnings };
}

/* ------------------------------------------------------------------ */
/* Sandbox detection (loopback / self only)                            */
/* ------------------------------------------------------------------ */

function checkLoopbackReachable() {
  return new Promise((resolve) => {
    let settled = false;
    const server = net.createServer();
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        server.close();
      } catch {
        // ignore: server already closed
      }
      resolve(value);
    };
    const timer = setTimeout(() => finish(false), 1500);
    server.once('error', () => finish(false));
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = address !== null && typeof address === 'object' ? address.port : 0;
      if (port <= 0) {
        finish(false);
        return;
      }
      const socket = net.connect({ host: '127.0.0.1', port });
      socket.once('connect', () => {
        socket.destroy();
        finish(true);
      });
      socket.once('error', () => finish(false));
    });
  });
}

async function checkLocalDns() {
  try {
    const result = await lookup('localhost');
    return Array.isArray(result) ? result.length > 0 : Boolean(result?.address);
  } catch {
    return false;
  }
}

async function checkFilesystemOutsideWorkspace() {
  const candidates = process.platform === 'win32'
    ? [path.join(process.env.WINDIR ?? 'C:\\Windows', 'win.ini')]
    : ['/etc/hosts', '/etc/resolv.conf', '/etc/passwd'];
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return true;
    } catch {
      // try the next candidate
    }
  }
  return false;
}

function checkHostNetworkAllowed() {
  return new Promise((resolve) => {
    let settled = false;
    const server = net.createServer();
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        server.close();
      } catch {
        // ignore: server already closed
      }
      resolve(value);
    };
    const timer = setTimeout(() => finish(false), 1500);
    server.once('error', () => finish(false));
    server.listen(0, '0.0.0.0', () => finish(true));
  });
}

async function probeSandbox(ctx) {
  const warnings = [];
  const loopbackReachable = await checkLoopbackReachable();
  const dnsReachable = await checkLocalDns();
  const filesystemOutsideWorkspaceReadable = await checkFilesystemOutsideWorkspace();
  const hostNetworkAllowed = ctx.offline ? false : await checkHostNetworkAllowed();
  const agentSandboxLikely = !loopbackReachable || !filesystemOutsideWorkspaceReadable || !hostNetworkAllowed;
  if (ctx.offline) warnings.push('offline mode is active: external network access is disabled by policy');
  if (!loopbackReachable) warnings.push('loopback sockets are unavailable; probe actions relying on localhost will fail');
  if (!dnsReachable) warnings.push('local name resolution for "localhost" failed');
  if (!filesystemOutsideWorkspaceReadable) warnings.push('reads outside the workspace are restricted by the agent sandbox');
  if (!hostNetworkAllowed) warnings.push('binding a non-loopback (0.0.0.0) listener was denied; host network may be restricted');
  if (agentSandboxLikely) warnings.push('agent sandbox indicators suggest network/filesystem restrictions; expect limited probe fidelity');
  return {
    action: 'sandbox',
    matrix: {
      agentSandboxLikely,
      hostNetworkAllowed,
      loopbackReachable,
      dnsReachable,
      filesystemOutsideWorkspaceReadable,
    },
    warnings,
  };
}
