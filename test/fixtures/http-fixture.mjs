/**
 * Local HTTP/HTTPS fixtures for the probe tests.
 *
 * Binds 127.0.0.1:18080 (plain HTTP) and 127.0.0.1:18443 (TLS) by default and
 * serves the minimal set of responses the TCP/HTTP/TLS/exposure tests need.
 * The TLS certificate is generated locally with the platform `openssl` binary;
 * when that is unavailable `startTlsFixture` throws and the test skips with an
 * explicit reason.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';

const HOME_HTML = '<!doctype html><html><head><title>AtkBrain HTTP Fixture</title></head><body><h1>Home</h1></body></html>';
const ADMIN_HTML = '<!doctype html><html><head><title>Admin Login</title></head><body><form action="/login"><input name="user"><input name="pass" type="password"></form></body></html>';
const FILES_HTML = '<!doctype html><html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href="../">Parent Directory</a><a href="notes.txt">notes.txt</a></body></html>';
const UPLOADS_HTML = '<!doctype html><html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><a href="../">Parent Directory</a></body></html>';
const ACTUATOR_ENV_JSON = JSON.stringify({
  activeProfiles: [],
  propertySources: [{
    name: 'systemProperties',
    properties: {
      'db.password': { value: 'fixture-db-secret' },
      'spring.datasource.url': { value: 'jdbc:h2:mem:test' },
      'api.token': { value: 'fixture-api-token' },
    },
  }],
});

function send(response, request, status, body, headers = {}) {
  try {
    const buffer = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
    response.writeHead(status, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Length': buffer.length,
      ...headers,
    });
    if (request.method === 'HEAD') {
      response.end();
      return;
    }
    response.end(buffer);
  } catch {
    try {
      response.destroy();
    } catch {
      // client already gone
    }
  }
}

/** Build the request handler shared by the HTTP and HTTPS fixtures. */
export function createFixtureHandler(state) {
  return (request, response) => {
    request.on('error', () => {});
    response.on('error', () => {});
    const url = new URL(request.url ?? '/', 'http://fixture.invalid');
    const pathname = url.pathname;
    if (state.requests.length < 2000) {
      state.requests.push({ method: request.method ?? 'GET', path: pathname, headers: { ...request.headers } });
    }
    if (pathname === '/') {
      send(response, request, 200, HOME_HTML, { Server: 'fixture-http/1.0', 'X-Powered-By': 'Node.js' });
      return;
    }
    if (pathname === '/admin') {
      send(response, request, 200, ADMIN_HTML, { Server: 'fixture-http/1.0', 'X-Powered-By': 'Node.js' });
      return;
    }
    if (pathname === '/.git/HEAD') {
      send(response, request, 200, 'ref: refs/heads/main\n', { 'Content-Type': 'text/plain' });
      return;
    }
    if (pathname === '/.git/config') {
      send(response, request, 200, '[core]\n\trepositoryformatversion = 0\n', { 'Content-Type': 'text/plain' });
      return;
    }
    if (pathname === '/.env') {
      send(response, request, 200, 'APP_ENV=production\nDB_PASSWORD=fixture-db-secret\nAPI_TOKEN=fixture-api-token\n', { 'Content-Type': 'text/plain' });
      return;
    }
    if (pathname === '/actuator') {
      send(response, request, 200, JSON.stringify({ _links: { self: { href: 'http://fixture.invalid/actuator' }, health: { href: 'http://fixture.invalid/actuator/health' } } }), { 'Content-Type': 'application/json' });
      return;
    }
    if (pathname === '/actuator/env') {
      send(response, request, 200, ACTUATOR_ENV_JSON, { 'Content-Type': 'application/json' });
      return;
    }
    if (pathname === '/actuator/health') {
      send(response, request, 200, '{"status":"UP"}', { 'Content-Type': 'application/json' });
      return;
    }
    if (pathname === '/files/') {
      send(response, request, 200, FILES_HTML, { Server: 'fixture-http/1.0' });
      return;
    }
    if (pathname === '/uploads/') {
      send(response, request, 200, UPLOADS_HTML, { Server: 'fixture-http/1.0' });
      return;
    }
    if (pathname === '/cors') {
      send(response, request, 200, '{"cors":true}', { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      return;
    }
    if (pathname === '/swagger-ui.html') {
      send(response, request, 200, '<!doctype html><html><head><title>Swagger UI</title></head><body>swagger-ui</body></html>');
      return;
    }
    if (pathname === '/server-status') {
      send(response, request, 200, '<html><head><title>Apache Server Status</title></head><body>Apache Server Status for fixture</body></html>');
      return;
    }
    if (pathname === '/phpinfo.php') {
      send(response, request, 200, '<html><body>PHP Version 8.1.0 phpinfo()</body></html>');
      return;
    }
    if (pathname === '/.well-known/security.txt') {
      send(response, request, 200, 'Contact: security@example.invalid\nExpires: 2099-01-01T00:00:00Z\n', { 'Content-Type': 'text/plain' });
      return;
    }
    if (pathname === '/manager/html') {
      send(response, request, 401, 'Authentication required', { 'WWW-Authenticate': 'Basic realm="Tomcat Manager Application"', 'Content-Type': 'text/plain' });
      return;
    }
    if (pathname === '/redirect') {
      send(response, request, 302, 'redirecting', { Location: '/admin' });
      return;
    }
    if (pathname === '/redirect-chain') {
      send(response, request, 302, 'redirecting', { Location: '/redirect' });
      return;
    }
    if (pathname === '/redirect-external') {
      send(response, request, 302, 'redirecting', { Location: 'http://203.0.113.5/landing' });
      return;
    }
    if (pathname === '/loop') {
      send(response, request, 302, 'redirecting', { Location: '/loop' });
      return;
    }
    if (pathname === '/large') {
      send(response, request, 200, 'A'.repeat(20000), { 'Content-Type': 'text/plain' });
      return;
    }
    if (pathname === '/chunked') {
      response.writeHead(200, { 'Content-Type': 'text/plain', 'X-Fixture': 'chunked' });
      if (request.method === 'HEAD') {
        response.end();
        return;
      }
      response.write('first-chunk;');
      response.write('second-chunk;');
      response.end('last-chunk');
      return;
    }
    if (pathname === '/slow') {
      setTimeout(() => {
        send(response, request, 200, 'slow-response', { 'Content-Type': 'text/plain' });
      }, 400);
      return;
    }
    if (pathname === '/echo-header') {
      send(response, request, 200, JSON.stringify({ header: request.headers['x-fixture-header'] ?? null }), { 'Content-Type': 'application/json' });
      return;
    }
    send(response, request, 404, 'not found', { 'Content-Type': 'text/plain' });
  };
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.removeListener('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.removeListener('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
}

/** Close a server and all sockets it still owns (Node 18.2+). */
export function closeServer(server) {
  return new Promise((resolve) => {
    if (server === null || server === undefined) {
      resolve();
      return;
    }
    try {
      server.closeAllConnections?.();
    } catch {
      // ignore: server may not expose this helper
    }
    if (!server.listening) {
      resolve();
      return;
    }
    try {
      server.close(() => resolve());
    } catch {
      resolve();
    }
  });
}

/**
 * Start the plain HTTP fixture.
 * @param {{host?:string,port?:number}} [options]
 */
export async function startHttpFixture(options = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 18080;
  const state = { requests: [] };
  const server = http.createServer(createFixtureHandler(state));
  server.keepAliveTimeout = 1000;
  await listen(server, port, host);
  server.on('error', () => {});
  const boundPort = server.address()?.port ?? port;
  return {
    server,
    state,
    requests: state.requests,
    host,
    port: boundPort,
    url: `http://${host}:${boundPort}`,
    close: () => closeServer(server),
  };
}

/**
 * Generate a local self-signed certificate with `openssl` (no npm dependency).
 * @returns {{key:string,cert:string,dir:string,cleanup:()=>void}}
 */
export function createSelfSignedCertificate() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'atkbrain-tls-'));
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  const result = spawnSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-subj', '/CN=localhost',
  ], { stdio: 'pipe', timeout: 30_000 });
  if (result.error !== undefined || result.status !== 0) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore cleanup failure
    }
    const reason = result.error?.message ?? String(result.stderr ?? '').trim() ?? 'unknown error';
    throw new Error(`openssl self-signed certificate generation failed: ${reason}`);
  }
  return {
    key: readFileSync(keyPath, 'utf8'),
    cert: readFileSync(certPath, 'utf8'),
    dir,
    cleanup: () => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // ignore cleanup failure
      }
    },
  };
}

/**
 * Start the HTTPS fixture on 127.0.0.1:18443. Throws when no local certificate
 * can be generated (the test skips with an explicit reason).
 */
export async function startTlsFixture(options = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 18443;
  const material = createSelfSignedCertificate();
  const state = { requests: [] };
  const server = https.createServer({ key: material.key, cert: material.cert }, createFixtureHandler(state));
  try {
    await listen(server, port, host);
  } catch (error) {
    material.cleanup();
    throw error;
  }
  server.on('error', () => {});
  const boundPort = server.address()?.port ?? port;
  return {
    server,
    state,
    requests: state.requests,
    host,
    port: boundPort,
    url: `https://${host}:${boundPort}`,
    certificate: material.cert,
    close: async () => {
      await closeServer(server);
      material.cleanup();
    },
  };
}
