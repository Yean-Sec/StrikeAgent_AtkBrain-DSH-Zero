/**
 * TCP / HTTP / TLS / SOCKS / exposure / probe-orchestration tests.
 *
 * All fixtures bind loopback only (HTTP 127.0.0.1:18080, SOCKS5 127.0.0.1:11080,
 * TLS 127.0.0.1:18443; the authentication SOCKS fixture uses an ephemeral
 * loopback port). Offline-mode assertions verify that non-loopback egress is
 * rejected before a socket is opened.
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import { after, before, test } from 'node:test';

import { createResolver } from '../lib/dns.js';
import { DEFAULT_PATHS, classifyExposure, runExposureChecks } from '../lib/exposure.js';
import {
  connectErrorState,
  httpProbe,
  normaliseVia,
  parsePorts,
  scanPorts,
  tcpProbe,
  tlsProbe,
} from '../lib/net.js';
import { runProbe } from '../lib/probe.js';
import { connectViaSocks5 } from '../lib/socks.js';
import { startHttpFixture, startTlsFixture } from './fixtures/http-fixture.mjs';
import { startSocksFixture } from './fixtures/socks-fixture.mjs';

let httpFixture;
let socksFixture;
let authSocksFixture;
let tlsFixture;
let tlsSkipReason = '';

/** A 127.0.0.1 port that was just released, so connect() is refused. */
function closedLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

/** Read everything from an already-connected socket after writing a request. */
function exchange(socket, requestText) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let finished = false;
    const timer = setTimeout(() => {
      if (finished) return;
      finished = true;
      socket.destroy();
      reject(new Error('raw socket exchange timed out'));
    }, 2000);
    const finish = (error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('end', onEnd);
      socket.removeListener('close', onEnd);
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      if (error !== undefined) reject(error);
      else resolve(Buffer.concat(chunks).toString('utf8'));
    };
    const onData = (chunk) => chunks.push(chunk);
    const onError = (error) => finish(error);
    const onEnd = () => finish(undefined);
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('end', onEnd);
    socket.once('close', onEnd);
    socket.resume();
    socket.write(requestText);
  });
}

before(async () => {
  httpFixture = await startHttpFixture({ port: 18080 });
  socksFixture = await startSocksFixture({ port: 11080 });
  authSocksFixture = await startSocksFixture({
    port: 0,
    requireAuth: true,
    users: [{ username: 'atkuser', password: 'atkpass' }],
  });
  try {
    tlsFixture = await startTlsFixture({ port: 18443 });
  } catch (error) {
    tlsFixture = null;
    tlsSkipReason = String(error?.message ?? error);
  }
});

after(async () => {
  await tlsFixture?.close();
  await authSocksFixture?.close();
  await socksFixture?.close();
  await httpFixture?.close();
});

/* ------------------------------------------------------------------ */
/* Ports and error mapping                                             */
/* ------------------------------------------------------------------ */

test('parsePorts accepts lists/ranges/arrays and rejects invalid input', () => {
  assert.deepEqual(parsePorts('80,443,8000-8002'), [80, 443, 8000, 8001, 8002]);
  assert.deepEqual(parsePorts('8080 8443'), [8080, 8443]);
  assert.deepEqual(parsePorts([443, 80, 443]), [80, 443]);
  assert.throws(() => parsePorts('not-a-port'), /invalid port/u);
  assert.throws(() => parsePorts('70000'), /invalid port/u);
  assert.throws(() => parsePorts('0'), /invalid port/u);
  assert.throws(() => parsePorts('1-100', { max: 10 }), /too many ports/u);
  assert.throws(() => parsePorts([]), /empty/u);
});

test('connectErrorState maps socket errors onto the port-scan vocabulary', () => {
  const withCode = (code) => Object.assign(new Error(code), { code });
  assert.equal(connectErrorState(withCode('ECONNREFUSED')), 'closed');
  assert.equal(connectErrorState(withCode('ECONNRESET')), 'closed');
  assert.equal(connectErrorState(withCode('ETIMEDOUT')), 'filtered');
  assert.equal(connectErrorState(withCode('EHOSTUNREACH')), 'filtered');
  assert.equal(connectErrorState(withCode('ENETUNREACH')), 'filtered');
  assert.equal(connectErrorState(withCode('EUNKNOWN')), 'closed');
  const timeout = new Error('connection timed out after 1ms');
  timeout.code = 'ETIMEDOUT';
  assert.equal(connectErrorState(timeout), 'filtered');
});

test('normaliseVia accepts objects and socks5:// URLs', () => {
  assert.deepEqual(normaliseVia({ host: '127.0.0.1', port: 1080 }), { host: '127.0.0.1', port: 1080 });
  assert.deepEqual(normaliseVia('socks5://127.0.0.1:11080'), { host: '127.0.0.1', port: 11080 });
  assert.deepEqual(normaliseVia('socks5://user:pass@127.0.0.1:11080'), {
    host: '127.0.0.1',
    port: 11080,
    username: 'user',
    password: 'pass',
  });
  assert.equal(normaliseVia(null), null);
  const http = normaliseVia('http://127.0.0.1:8080');
  assert.equal(http.type, 'http');
  assert.equal(http.host, '127.0.0.1');
  assert.equal(http.port, 8080);
  assert.equal(http.tls, false);
});

/* ------------------------------------------------------------------ */
/* TCP                                                                 */
/* ------------------------------------------------------------------ */

test('tcpProbe reports open/closed states and reads a banner', async () => {
  const open = await tcpProbe('127.0.0.1', httpFixture.port, { banner: false });
  assert.equal(open.state, 'open');
  assert.equal(open.host, '127.0.0.1');
  assert.equal(open.port, httpFixture.port);
  assert.ok(open.ms >= 0);
  assert.equal(open.banner, undefined);

  const closedPort = await closedLoopbackPort();
  const closed = await tcpProbe('127.0.0.1', closedPort, { banner: false, timeoutMs: 1000 });
  assert.equal(closed.state, 'closed');

  const bannerServer = net.createServer((socket) => {
    socket.write('ATK-BANNER ready\r\n');
  });
  await new Promise((resolve, reject) => {
    bannerServer.once('error', reject);
    bannerServer.listen(0, '127.0.0.1', resolve);
  });
  try {
    const address = bannerServer.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;
    const banner = await tcpProbe('127.0.0.1', port, { banner: true, timeoutMs: 2000 });
    assert.equal(banner.state, 'open');
    assert.match(banner.banner ?? '', /ATK-BANNER/u);
  } finally {
    bannerServer.close();
  }
});

test('tcpProbe over SOCKS5 works and reports filtered on proxy stall', async () => {
  const via = { host: '127.0.0.1', port: socksFixture.port };
  const open = await tcpProbe('127.0.0.1', httpFixture.port, { via, banner: false, timeoutMs: 2000 });
  assert.equal(open.state, 'open');

  const stalled = await tcpProbe('127.0.0.1', 9, { via, banner: false, timeoutMs: 250 });
  assert.equal(stalled.state, 'filtered');
});

test('tcpProbe rejects invalid ports before opening a socket', async () => {
  await assert.rejects(tcpProbe('127.0.0.1', 0, { banner: false }), /invalid port/u);
  await assert.rejects(tcpProbe('', 80, { banner: false }), /host is required/u);
});

test('scanPorts scans with bounded concurrency and preserves per-port state', async () => {
  const closedPort = await closedLoopbackPort();
  const results = await scanPorts('127.0.0.1', [httpFixture.port, closedPort], { concurrency: 2, timeoutMs: 1000 });
  assert.equal(results.length, 2);
  assert.deepEqual(results.map((result) => result.port), [httpFixture.port, closedPort].sort((a, b) => a - b));
  const byPort = new Map(results.map((result) => [result.port, result.state]));
  assert.equal(byPort.get(httpFixture.port), 'open');
  assert.equal(byPort.get(closedPort), 'closed');
});

/* ------------------------------------------------------------------ */
/* SOCKS5                                                              */
/* ------------------------------------------------------------------ */

test('connectViaSocks5 no-auth tunnel reaches the HTTP fixture (domain target)', async () => {
  const socket = await connectViaSocks5(
    { host: '127.0.0.1', port: socksFixture.port },
    { host: 'localhost', port: httpFixture.port },
    { timeoutMs: 2000 },
  );
  const response = await exchange(socket, 'GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n');
  assert.match(response, /^HTTP\/1\.1 200/u);
  assert.match(response, /AtkBrain HTTP Fixture/u);
  const lastConnection = socksFixture.connections.at(-1);
  assert.equal(lastConnection.target.host, 'localhost');
  assert.equal(lastConnection.target.port, httpFixture.port);
});

test('connectViaSocks5 supports username/password auth and rejects bad credentials', async () => {
  const proxy = { host: '127.0.0.1', port: authSocksFixture.port, username: 'atkuser', password: 'atkpass' };
  const socket = await connectViaSocks5(proxy, { host: '127.0.0.1', port: httpFixture.port }, { timeoutMs: 2000 });
  const response = await exchange(socket, 'GET /missing HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n');
  assert.match(response, /^HTTP\/1\.1 404/u);
  assert.equal(authSocksFixture.connections.at(-1).authenticated, true);

  await assert.rejects(
    connectViaSocks5(
      { ...proxy, password: 'wrong-password' },
      { host: '127.0.0.1', port: httpFixture.port },
      { timeoutMs: 2000 },
    ),
    /authentication failed/u,
  );
});

test('per-port SOCKS5 target failures become port states instead of aborting the scan', async () => {
  const via = { host: '127.0.0.1', port: socksFixture.port };
  const closedPort = await closedLoopbackPort();
  const individual = await tcpProbe('127.0.0.1', closedPort, { via, banner: false, timeoutMs: 2000 });
  assert.equal(individual.state, 'closed');

  const results = await scanPorts('127.0.0.1', [httpFixture.port, closedPort], { via, concurrency: 2, timeoutMs: 2000 });
  const byPort = new Map(results.map((result) => [result.port, result.state]));
  assert.equal(byPort.get(httpFixture.port), 'open');
  assert.equal(byPort.get(closedPort), 'closed');
});

test('connectViaSocks5 times out when the proxy stalls', async () => {
  await assert.rejects(
    connectViaSocks5(
      { host: '127.0.0.1', port: socksFixture.port },
      { host: '127.0.0.1', port: 9 },
      { timeoutMs: 200 },
    ),
    /timed out/u,
  );
});

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */

test('httpProbe fetches the fixture root with headers, title and techs', async () => {
  const result = await httpProbe(httpFixture.url);
  assert.equal(result.status, 200);
  assert.equal(result.url, `${httpFixture.url}/`);
  assert.equal(result.title, 'AtkBrain HTTP Fixture');
  assert.equal(result.server, 'fixture-http/1.0');
  assert.match(String(result.headers['content-type']), /text\/html/u);
  assert.match(result.body, /<h1>Home<\/h1>/u);
  assert.ok(result.techs.includes('Node.js'), `techs: ${result.techs.join(', ')}`);
  assert.deepEqual(result.redirects, []);
});

test('httpProbe HEAD returns no body', async () => {
  const result = await httpProbe(httpFixture.url, { method: 'HEAD' });
  assert.equal(result.status, 200);
  assert.equal(result.body, '');
});

test('httpProbe follows redirects manually and records each hop', async () => {
  const result = await httpProbe(`${httpFixture.url}/redirect`);
  assert.equal(result.status, 200);
  assert.equal(result.title, 'Admin Login');
  assert.equal(result.redirects.length, 1);
  assert.equal(result.redirects[0].status, 302);
  assert.match(result.redirects[0].from, /\/redirect$/u);
  assert.match(result.redirects[0].to, /\/admin$/u);
});

test('httpProbe reports redirects when followRedirects is 0', async () => {
  const result = await httpProbe(`${httpFixture.url}/redirect`, { followRedirects: 0 });
  assert.equal(result.status, 302);
  assert.equal(result.headers.location, '/admin');
  assert.deepEqual(result.redirects, []);
});

test('httpProbe calls onRedirect for scope re-checks and honours a denial', async () => {
  const seen = [];
  await assert.rejects(httpProbe(`${httpFixture.url}/redirect`, {
    onRedirect: async (nextUrl) => {
      seen.push(nextUrl);
      return false;
    },
  }), /blocked by the scope guard/u);
  assert.deepEqual(seen, [`${httpFixture.url}/admin`]);

  const chained = await httpProbe(`${httpFixture.url}/redirect-chain`, {
    onRedirect: async () => true,
  });
  assert.equal(chained.status, 200);
  assert.equal(chained.redirects.length, 2);
});

test('httpProbe stops following after max redirects for redirect loops', async () => {
  const result = await httpProbe(`${httpFixture.url}/loop`, { followRedirects: 2 });
  assert.equal(result.status, 302);
  assert.equal(result.redirects.length, 2);
});

test('httpProbe enforces maxBodyBytes and decodes chunked transfer encoding', async () => {
  const capped = await httpProbe(`${httpFixture.url}/large`, { maxBodyBytes: 100 });
  assert.equal(capped.status, 200);
  assert.equal(capped.body.length, 100);

  const chunked = await httpProbe(`${httpFixture.url}/chunked`);
  assert.equal(chunked.status, 200);
  assert.equal(chunked.body, 'first-chunk;second-chunk;last-chunk');
  assert.equal(chunked.headers['x-fixture'], 'chunked');
});

test('httpProbe sends custom headers', async () => {
  const result = await httpProbe(`${httpFixture.url}/echo-header`, {
    headers: { 'X-Fixture-Header': 'atkbrain-test' },
  });
  assert.equal(result.status, 200);
  assert.match(result.body, /atkbrain-test/u);
});

test('httpProbe times out slow responses and reports connection failures', async () => {
  await assert.rejects(httpProbe(`${httpFixture.url}/slow`, { timeoutMs: 100 }), /timed out/u);
  const closedPort = await closedLoopbackPort();
  await assert.rejects(httpProbe(`http://127.0.0.1:${closedPort}/`, { timeoutMs: 1000 }), /ECONNREFUSED|connect/u);
});

test('httpProbe works through a SOCKS5 proxy', async () => {
  const result = await httpProbe(httpFixture.url, {
    via: { host: '127.0.0.1', port: socksFixture.port },
    timeoutMs: 3000,
  });
  assert.equal(result.status, 200);
  assert.equal(result.title, 'AtkBrain HTTP Fixture');
});

/* ------------------------------------------------------------------ */
/* TLS                                                                 */
/* ------------------------------------------------------------------ */

test('tlsProbe describes a self-signed certificate (TLS fixture)', async (t) => {
  if (tlsFixture === null) {
    t.skip(`TLS fixture unavailable: ${tlsSkipReason}`);
    return;
  }
  const info = await tlsProbe('127.0.0.1', tlsFixture.port, { timeoutMs: 4000 });
  assert.match(String(info.protocol), /^TLS/u);
  assert.ok(typeof info.cipher === 'string' && info.cipher.length > 0);
  assert.equal(info.selfSigned, true);
  assert.match(String(info.subject), /CN=localhost/u);
  assert.match(String(info.issuer), /CN=localhost/u);
  assert.match(String(info.fingerprint256), /^[0-9A-F:]{16,}$/iu);
  assert.ok(Number.isFinite(Date.parse(String(info.validTo))), `validTo: ${info.validTo}`);
  assert.ok(Array.isArray(info.subjectAltName));
});

test('tlsProbe works through a SOCKS5 proxy (TLS fixture)', async (t) => {
  if (tlsFixture === null) {
    t.skip(`TLS fixture unavailable: ${tlsSkipReason}`);
    return;
  }
  const info = await tlsProbe('127.0.0.1', tlsFixture.port, {
    via: { host: '127.0.0.1', port: socksFixture.port },
    timeoutMs: 4000,
  });
  assert.match(String(info.protocol), /^TLS/u);
  assert.equal(info.selfSigned, true);
});

test('httpProbe over HTTPS exposes negotiated TLS metadata', async (t) => {
  if (tlsFixture === null) {
    t.skip(`TLS fixture unavailable: ${tlsSkipReason}`);
    return;
  }
  const result = await httpProbe(tlsFixture.url);
  assert.equal(result.status, 200);
  assert.equal(result.title, 'AtkBrain HTTP Fixture');
  assert.ok(result.tls !== undefined);
  assert.equal(result.tls.selfSigned, true);
  assert.match(String(result.tls.protocol), /^TLS/u);
});

test('tlsProbe rejects a non-TLS endpoint', async () => {
  await assert.rejects(tlsProbe('127.0.0.1', httpFixture.port, { timeoutMs: 1000 }), /wrong version number|SSL|TLS|ECONNRESET|socket hang up/iu);
});

/* ------------------------------------------------------------------ */
/* Exposure checks                                                     */
/* ------------------------------------------------------------------ */

test('DEFAULT_PATHS is the homepage only', () => {
  assert.deepEqual([...DEFAULT_PATHS], ['/']);
  assert.ok(Object.isFrozen(DEFAULT_PATHS));
});

test('runExposureChecks finds exposed git/env/actuator/listing/CORS/admin and masks values', async () => {
  const paths = [
    '/',
    '/.git/HEAD',
    '/.git/config',
    '/.env',
    '/actuator',
    '/actuator/env',
    '/actuator/health',
    '/files/',
    '/cors',
    '/admin',
    '/manager/html',
    '/server-status',
    '/swagger-ui.html',
    '/phpinfo.php',
    '/.well-known/security.txt',
  ];
  const findings = await runExposureChecks(httpFixture.url, { paths, timeoutMs: 2000 });
  const templates = new Set(findings.map((finding) => finding.template));
  for (const expected of [
    'exposed-git-repository',
    'exposed-git-config',
    'exposed-env-file',
    'actuator-env-exposed',
    'actuator-health-public',
    'directory-listing',
    'cors-wildcard',
    'admin-interface-reachable',
    'tomcat-manager-protected',
    'apache-server-status',
    'api-docs-exposed',
    'phpinfo-exposed',
    'missing-security-headers',
    'security-txt-present',
  ]) {
    assert.ok(templates.has(expected), `missing template ${expected}; got ${[...templates].join(', ')}`);
  }
  const serialized = JSON.stringify(findings);
  assert.ok(!serialized.includes('fixture-db-secret'), 'env values must never appear in evidence');
  assert.ok(!serialized.includes('fixture-api-token'), 'env values must never appear in evidence');
  for (const finding of findings) {
    assert.equal(typeof finding.template, 'string');
    assert.equal(typeof finding.title, 'string');
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity));
    assert.ok(finding.statusCode === null || Number.isInteger(finding.statusCode));
    assert.equal(typeof finding.path, 'string');
    assert.equal(typeof finding.evidence, 'string');
    assert.equal(typeof finding.recommendation, 'string');
    assert.ok(finding.evidence.length <= 300);
  }
  const git = findings.find((finding) => finding.template === 'exposed-git-repository');
  assert.equal(git.severity, 'critical');
  assert.equal(git.path, '/.git/HEAD');
  assert.match(git.evidence, /ref: refs\/heads\/main/u);
});

test('classifyExposure handles directory listings and dotenv masking directly', () => {
  const listing = classifyExposure('/files/', {
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '<html><head><title>Index of /files</title></head><body></body></html>',
  });
  assert.ok(listing.some((finding) => finding.template === 'directory-listing'));

  const env = classifyExposure('/.env', {
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: 'APP_ENV=production\nDB_PASSWORD=super-secret\n',
  });
  const envFinding = env.find((finding) => finding.template === 'exposed-env-file');
  assert.equal(envFinding.severity, 'critical');
  assert.match(envFinding.evidence, /APP_ENV/u);
  assert.match(envFinding.evidence, /DB_PASSWORD/u);
  assert.ok(!envFinding.evidence.includes('super-secret'));

  assert.deepEqual(classifyExposure('/missing', { status: 404, headers: {}, body: 'not found' }), []);
});

/* ------------------------------------------------------------------ */
/* Probe orchestration                                                 */
/* ------------------------------------------------------------------ */

test('runProbe http returns structured observations and exposure findings', async () => {
  const result = await runProbe({ action: 'http', url: httpFixture.url }, {
    config: { probeTimeoutMs: 2000, maxHttpBodyBytes: 262144 },
    scopeGuard: async () => ({ allowed: true, reason: 'in scope' }),
  });
  assert.equal(result.action, 'http');
  assert.equal(result.status, 200);
  assert.equal(result.title, 'AtkBrain HTTP Fixture');
  assert.equal(result.server, 'fixture-http/1.0');
  assert.ok(Array.isArray(result.techs));
  assert.ok(Array.isArray(result.findings));
  assert.ok(result.findings.some((finding) => finding.template === 'missing-security-headers'));
  assert.ok(Array.isArray(result.warnings));
});

test('runProbe dns resolves the target and folds in the wildcard verdict', async () => {
  const resolver = {
    async resolveHost(host) {
      return { status: 'ok', a: ['192.0.2.5'], aaaa: [], cname: [], ns: [], soa: false };
    },
    async query(name, type) {
      if (name.endsWith('.invalid')) return { status: 'nxdomain', answers: [] };
      if (type === 'A') return { status: 'ok', answers: ['192.0.2.66'] };
      return { status: 'ok', answers: [] };
    },
    async apexExists() {
      return true;
    },
  };
  const result = await runProbe({ action: 'dns', target: 'www.wildcard.test', zone: 'wildcard.test' }, {
    resolver,
    config: { wildcardProbes: 3, wildcardRounds: 2, dnsTimeoutMs: 500 },
  });
  assert.equal(result.action, 'dns');
  assert.equal(result.target, 'www.wildcard.test');
  assert.equal(result.status, 'ok');
  assert.deepEqual(result.answers.a, ['192.0.2.5']);
  assert.equal(result.answers.soa, false);
  assert.equal(result.wildcard.status, 'confirmed');
  assert.deepEqual(result.wildcard.signature.a, ['192.0.2.66']);
  assert.ok(Array.isArray(result.wildcard.probes));
  assert.ok(Array.isArray(result.warnings));
});

test('runProbe tcp scans ports and returns only open results plus a summary warning', async () => {
  const closedPort = await closedLoopbackPort();
  const result = await runProbe({ action: 'tcp', target: '127.0.0.1', ports: `${httpFixture.port},${closedPort}` }, {
    config: { probeConcurrency: 4, probeTimeoutMs: 1000 },
  });
  assert.equal(result.action, 'tcp');
  assert.equal(result.target, '127.0.0.1');
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].port, httpFixture.port);
  assert.equal(result.results[0].state, 'open');
  assert.ok(result.warnings.some((warning) => /closed/u.test(warning)));
});

test('runProbe tls reports certificate findings', async (t) => {
  if (tlsFixture === null) {
    t.skip(`TLS fixture unavailable: ${tlsSkipReason}`);
    return;
  }
  const result = await runProbe({ action: 'tls', target: '127.0.0.1', port: tlsFixture.port }, {
    config: { probeTimeoutMs: 3000 },
  });
  assert.equal(result.action, 'tls');
  assert.equal(result.host, '127.0.0.1');
  assert.equal(result.cert.selfSigned, true);
  assert.ok(result.findings.some((finding) => finding.template === 'self-signed-certificate'));
});

test('runProbe sandbox reports the loopback-only self matrix', async () => {
  const result = await runProbe({ action: 'sandbox' }, { config: {} });
  assert.equal(result.action, 'sandbox');
  assert.equal(typeof result.matrix, 'object');
  for (const key of ['agentSandboxLikely', 'hostNetworkAllowed', 'loopbackReachable', 'dnsReachable', 'filesystemOutsideWorkspaceReadable']) {
    assert.equal(typeof result.matrix[key], 'boolean', `${key} must be boolean`);
  }
  assert.equal(result.matrix.loopbackReachable, true);
  assert.ok(Array.isArray(result.warnings));
});

test('runProbe enforces scopeGuard before any network action', async () => {
  let calls = 0;
  await assert.rejects(
    runProbe({ action: 'http', url: httpFixture.url }, {
      scopeGuard: async () => {
        calls += 1;
        return { allowed: false, reason: 'target is outside the engagement scope' };
      },
    }),
    /outside the engagement scope/u,
  );
  assert.equal(calls, 1);

  await assert.rejects(
    runProbe({ action: 'tcp', target: '192.0.2.10', ports: '80' }, { scopeGuard: async () => false }),
    /denied by the scope guard/u,
  );
});

test('runProbe rejects unknown actions and missing targets', async () => {
  await assert.rejects(runProbe({ action: 'explode' }), /unknown probe action/u);
  await assert.rejects(runProbe({ action: 'dns' }), /requires a target/u);
  await assert.rejects(runProbe({ action: 'tcp' }), /requires a target/u);
  await assert.rejects(runProbe({ action: 'http' }), /requires a url/u);
});

/* ------------------------------------------------------------------ */
/* Offline safety                                                      */
/* ------------------------------------------------------------------ */

test('options.offline rejects non-loopback connects before opening a socket', async () => {
  await assert.rejects(tcpProbe('192.0.2.1', 80, { offline: true, banner: false }), /offline mode/u);
  await assert.rejects(tcpProbe('example.com', 80, { offline: true, banner: false }), /offline mode/u);
  await assert.rejects(scanPorts('192.0.2.1', [80, 443], { offline: true }), /offline mode/u);
  await assert.rejects(tlsProbe('192.0.2.1', 443, { offline: true }), /offline mode/u);
  await assert.rejects(httpProbe('http://example.com/', { offline: true }), /offline mode/u);
  await assert.rejects(
    connectViaSocks5({ host: '192.0.2.1', port: 1080 }, { host: '192.0.2.1', port: 80 }, { offline: true }),
    /offline mode/u,
  );
  // Loopback stays usable while offline.
  const loopback = await tcpProbe('127.0.0.1', httpFixture.port, { offline: true, banner: false, timeoutMs: 1000 });
  assert.equal(loopback.state, 'open');
});

test('PENTEST_OFFLINE=1 makes the probe layer and resolver refuse non-loopback egress', async () => {
  const previous = process.env.PENTEST_OFFLINE;
  process.env.PENTEST_OFFLINE = '1';
  try {
    await assert.rejects(tcpProbe('192.0.2.1', 80, { banner: false }), /offline mode/u);
    await assert.rejects(httpProbe('http://192.0.2.1/'), /offline mode/u);
    await assert.rejects(tlsProbe('192.0.2.1', 443), /offline mode/u);
    await assert.rejects(
      runProbe({ action: 'tcp', target: '192.0.2.1', ports: '80' }, { config: { offline: true } }),
      /offline mode/u,
    );
    const resolver = createResolver({
      impl: {
        resolve4: async () => ['192.0.2.1'],
        resolve6: async () => [],
        resolveCname: async () => [],
        resolveNs: async () => [],
        resolveSoa: async () => ({ nsname: 'ns.example' }),
      },
      offline: true,
    });
    await assert.rejects(resolver.query('example.com', 'A'), /offline mode: refusing to resolve/u);
  } finally {
    if (previous === undefined) delete process.env.PENTEST_OFFLINE;
    else process.env.PENTEST_OFFLINE = previous;
  }
});
