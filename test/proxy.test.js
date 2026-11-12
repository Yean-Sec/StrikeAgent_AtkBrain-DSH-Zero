/**
 * HTTP proxy runtime/manager/CONNECT tests.
 *
 * Everything runs against loopback fixtures. The undici-dependent tests are
 * skipped when the optional `undici` dependency is not installed, so the rest
 * of the AtkBrain suite stays green without network access.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { test } from 'node:test';

import { connectViaHttpProxy, normaliseHttpProxy } from '../lib/proxy/connect.js';
import { ProxyManager, parseProviderPayload } from '../lib/proxy/manager.js';
import {
  GLOBAL_DISPATCHER_KEY,
  installGlobalProxy,
  isProxyBypassed,
  isUndiciAvailable,
} from '../lib/proxy/runtime.js';

const UNDICI_AVAILABLE = await isUndiciAvailable();
const SKIP_UNDICI = UNDICI_AVAILABLE ? false : 'undici is not installed; proxy integration tests skipped';

function listen(server) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.removeListener('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.removeListener('error', onError);
      resolve(server.address().port);
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(0, '127.0.0.1');
  });
}

function trackSockets(server) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  return () => {
    for (const socket of sockets) socket.destroy();
    sockets.clear();
  };
}

async function closeServer(server, destroy) {
  destroy?.();
  if (!server.listening) return;
  await new Promise((resolve) => server.close(() => resolve()));
}

function splitAuthority(authority) {
  const text = String(authority ?? '');
  const colon = text.lastIndexOf(':');
  if (colon <= 0) return { host: text, port: 80 };
  return { host: text.slice(0, colon).replace(/^\[|\]$/gu, ''), port: Number(text.slice(colon + 1)) };
}

/**
 * One HTTP proxy fixture handling absolute-form GET and CONNECT.
 * `tunnelPort` maps every CONNECT authority to one local upstream.
 */
async function startProxy(options = {}) {
  const state = { requests: [], connects: [] };
  const requiredAuth = options.requireAuth ?? null;
  const server = http.createServer((request, response) => {
    state.requests.push({ url: request.url, headers: request.headers });
    if (requiredAuth !== null && request.headers['proxy-authorization'] !== requiredAuth) {
      response.writeHead(407, { 'proxy-authenticate': 'Basic realm="atkbrain-test"', 'content-length': 0 });
      response.end();
      return;
    }
    if (typeof options.absoluteBody === 'function') {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end(options.absoluteBody(request));
      return;
    }
    response.writeHead(200, { 'content-type': 'text/plain', 'x-proxy-fixture': '1' });
    response.end(`PROXY-ABSOLUTE ${request.url}`);
  });
  server.on('connect', (request, client, head) => {
    state.connects.push({ authority: request.url, headers: request.headers });
    client.on('error', () => {});
    if (requiredAuth !== null && request.headers['proxy-authorization'] !== requiredAuth) {
      client.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="atkbrain-test"\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    if (options.stall === true) return;
    if (options.oversizedHeaders === true) {
      client.write('HTTP/1.1 200 Connection Established\r\n');
      client.write(`X-Padding: ${'a'.repeat(40000)}\r\n`);
      return;
    }
    if (Number.isInteger(options.failStatus)) {
      client.end(`HTTP/1.1 ${options.failStatus} Fixture Failure\r\nContent-Length: 0\r\n\r\n`);
      return;
    }
    const target = options.tunnelPort === undefined
      ? splitAuthority(request.url)
      : { host: '127.0.0.1', port: options.tunnelPort };
    const upstream = net.connect({ host: target.host, port: target.port }, () => {
      client.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: atkbrain-test\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on('error', () => {
      client.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');
    });
    client.on('error', () => upstream.destroy());
    client.on('close', () => upstream.destroy());
  });
  const destroy = trackSockets(server);
  const port = await listen(server);
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    state,
    close: () => closeServer(server, destroy),
  };
}

async function startHttpTarget(handler) {
  const server = http.createServer(handler);
  const destroy = trackSockets(server);
  const port = await listen(server);
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    close: () => closeServer(server, destroy),
  };
}

async function startTcpEcho() {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    socket.pipe(socket);
  });
  const port = await listen(server);
  return {
    port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      if (server.listening) await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

function readUntil(socket, marker, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out waiting for ${JSON.stringify(marker)}`));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
    };
    function onData(chunk) {
      data += chunk.toString('utf8');
      if (data.includes(marker)) {
        cleanup();
        resolve(data);
      }
    }
    function onError(error) {
      cleanup();
      reject(error);
    }
    socket.on('data', onData);
    socket.on('error', onError);
    socket.resume();
  });
}

test('normaliseHttpProxy accepts URL/object descriptors and rejects SOCKS', () => {
  const fromUrl = normaliseHttpProxy('http://user:pa%40ss@127.0.0.1:8080');
  assert.equal(fromUrl.host, '127.0.0.1');
  assert.equal(fromUrl.port, 8080);
  assert.equal(fromUrl.protocol, 'http');
  assert.equal(fromUrl.secure, false);
  assert.equal(fromUrl.username, 'user');
  assert.equal(fromUrl.password, 'pa@ss');

  const httpsProxy = normaliseHttpProxy('https://proxy.example:8443');
  assert.equal(httpsProxy.secure, true);
  assert.equal(httpsProxy.port, 8443);

  const objectProxy = normaliseHttpProxy({ host: '127.0.0.1', port: '3128', username: 'u', password: 'p' });
  assert.equal(objectProxy.port, 3128);
  assert.equal(objectProxy.username, 'u');

  const defaulted = normaliseHttpProxy({ host: '127.0.0.1' });
  assert.equal(defaulted.port, 8080);

  const nested = normaliseHttpProxy({ url: 'http://127.0.0.1:9000' });
  assert.equal(nested.port, 9000);

  assert.throws(() => normaliseHttpProxy('socks5://127.0.0.1:1080'), /unsupported HTTP proxy scheme/u);
  assert.throws(() => normaliseHttpProxy(''), /empty/u);
  assert.throws(() => normaliseHttpProxy({ host: '127.0.0.1', port: 70000 }), /port/u);
  assert.throws(() => normaliseHttpProxy({ password: 'x', host: '127.0.0.1' }), /requires a username/u);
});

test('connectViaHttpProxy tunnels to a local echo server with Basic auth', async () => {
  const echo = await startTcpEcho();
  const authorization = `Basic ${Buffer.from('proxyuser:proxypass').toString('base64')}`;
  const proxy = await startProxy({ requireAuth: authorization, tunnelPort: echo.port });
  let socket;
  try {
    socket = await connectViaHttpProxy(
      `http://proxyuser:proxypass@127.0.0.1:${proxy.port}`,
      { host: 'echo.atkbrain.test', port: 80 },
      { timeoutMs: 2000 },
    );
    assert.equal(socket.destroyed, false);
    socket.write('ping-42\n');
    const received = await readUntil(socket, 'ping-42\n');
    assert.match(received, /ping-42/u);
    assert.equal(proxy.state.connects.length, 1);
    assert.equal(proxy.state.connects[0].authority, 'echo.atkbrain.test:80');
    assert.equal(proxy.state.connects[0].headers['proxy-authorization'], authorization);
  } finally {
    socket?.destroy();
    await proxy.close();
    await echo.close();
  }
});

test('connectViaHttpProxy maps 407 and non-200 CONNECT replies to proxy errors', async () => {
  const authProxy = await startProxy({ requireAuth: 'Basic expected' });
  const failingProxy = await startProxy({ failStatus: 502 });
  try {
    await assert.rejects(
      connectViaHttpProxy(authProxy.url, { host: 'example.test', port: 80 }, { timeoutMs: 1000 }),
      (error) => {
        assert.equal(error.code, 'ATK_HTTP_PROXY_AUTH');
        assert.match(error.message, /407/u);
        return true;
      },
    );
    await assert.rejects(
      connectViaHttpProxy(failingProxy.url, { host: 'example.test', port: 80 }, { timeoutMs: 1000 }),
      (error) => {
        assert.equal(error.code, 'ATK_HTTP_PROXY');
        assert.match(error.message, /502/u);
        return true;
      },
    );
  } finally {
    await authProxy.close();
    await failingProxy.close();
  }
});

test('connectViaHttpProxy caps headers and times out a stalled proxy', async () => {
  const oversized = await startProxy({ oversizedHeaders: true });
  const stalled = await startProxy({ stall: true });
  try {
    await assert.rejects(
      connectViaHttpProxy(oversized.url, { host: 'example.test', port: 80 }, { timeoutMs: 1500 }),
      (error) => {
        assert.equal(error.code, 'ATK_HTTP_PROXY_HEADERS');
        return true;
      },
    );
    await assert.rejects(
      connectViaHttpProxy(stalled.url, { host: 'example.test', port: 80 }, { timeoutMs: 150 }),
      (error) => {
        assert.equal(error.code, 'ETIMEDOUT');
        assert.match(error.message, /timed out/u);
        return true;
      },
    );
  } finally {
    await oversized.close();
    await stalled.close();
  }
});

test('isProxyBypassed honours loopback, NO_PROXY suffixes, ports and *', () => {
  assert.equal(isProxyBypassed('http://127.0.0.1:8080/x', ''), true);
  assert.equal(isProxyBypassed('http://localhost/x', ''), true);
  assert.equal(isProxyBypassed('http://[::1]/x', ''), true);
  assert.equal(isProxyBypassed('http://example.com/x', ''), false);
  assert.equal(isProxyBypassed('http://api.example.com/x', 'example.com'), true);
  assert.equal(isProxyBypassed('http://api.example.com/x', '.internal,example.com'), true);
  assert.equal(isProxyBypassed('https://example.com/x', 'example.com:8080'), false);
  assert.equal(isProxyBypassed('http://example.com/x', 'example.com:80'), true);
  assert.equal(isProxyBypassed('http://anything.test/x', '*'), true);
});

test('ProxyManager status redacts proxy credentials and provider/echo tokens', async () => {
  const manager = new ProxyManager({
    config: {
      proxyEnabled: false,
      proxyMode: 'custom',
      proxyUrl: 'http://user:supersecret@127.0.0.1:8080',
      proxyPool: ['http://pooluser:poolsecret@127.0.0.1:8081'],
      proxyProviderUrl: 'http://provider.test/list?token=providersecret',
      proxyEchoUrl: 'http://echo.test/ip?api_key=echosecret',
    },
  });
  const status = manager.status();
  const serialized = JSON.stringify(status);
  for (const secret of ['supersecret', 'poolsecret', 'providersecret', 'echosecret']) {
    assert.equal(serialized.includes(secret), false, `status leaked ${secret}`);
  }
  assert.equal(status.enabled, false);
  assert.equal(status.mode, 'custom');
  assert.equal(status.installed, false);
  assert.equal(status.activeProxy, null);
  assert.match(status.selectedProxy, /127\.0\.0\.1:8080/u);
  assert.match(status.selectedProxy, /\*\*\*/u);
  assert.equal(status.pool.length, 2);
  assert.match(status.pool[0], /127\.0\.0\.1:8080/u);
  assert.match(status.pool[1], /127\.0\.0\.1:8081/u);
  assert.match(status.provider, /\*\*\*/u);

  const changed = await manager.configure({ proxyUrl: 'http://other:pw2@127.0.0.1:8082' });
  assert.equal(JSON.stringify(changed).includes('pw2'), false);
  assert.match(changed.selectedProxy, /127\.0\.0\.1:8082/u);
});

test('addPool and rotate update the selection without exposing credentials', async () => {
  const manager = new ProxyManager({
    config: { proxyEnabled: false, proxyMode: 'custom', proxyUrl: 'http://127.0.0.1:8001' },
  });
  let status = await manager.addPool([
    'http://u:rotatesecret@127.0.0.1:8002',
    { host: '127.0.0.1', port: 8003 },
  ]);
  assert.equal(status.pool.length, 3);
  assert.match(status.selectedProxy, /8001/u);
  assert.equal(JSON.stringify(status).includes('rotatesecret'), false);

  status = await manager.rotate();
  assert.match(status.selectedProxy, /8002/u);
  status = await manager.rotate();
  assert.match(status.selectedProxy, /8003/u);
  status = await manager.rotate();
  assert.match(status.selectedProxy, /8001/u);
  assert.equal(status.pool.length, 3);
});

test('provider payload parser handles JSON arrays, {proxies} and text', () => {
  assert.deepEqual(parseProviderPayload('["http://127.0.0.1:7001"]'), ['http://127.0.0.1:7001']);
  assert.deepEqual(
    parseProviderPayload('{"proxies":["http://127.0.0.1:7002",{"url":"http://127.0.0.1:7003"}]}'),
    ['http://127.0.0.1:7002', 'http://127.0.0.1:7003'],
  );
  assert.deepEqual(
    parseProviderPayload('http://127.0.0.1:7004\n# comment\n\nhttp://127.0.0.1:7005\n'),
    ['http://127.0.0.1:7004', 'http://127.0.0.1:7005'],
  );
});

test('provider mode fetches a local list and redacts credentials', async () => {
  let requests = 0;
  const provider = await startHttpTarget((request, response) => {
    requests += 1;
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({
      proxies: ['http://127.0.0.1:7001', 'http://puser:psecret@127.0.0.1:7002'],
    }));
  });
  const manager = new ProxyManager({
    config: {
      proxyEnabled: true,
      proxyMode: 'provider',
      proxyProviderUrl: `${provider.url}/list`,
      proxyFailClosed: false,
      proxyEchoUrl: '',
      proxyCheckIntervalMs: 0,
    },
  });
  try {
    const status = await manager.enable();
    assert.equal(status.poolSize, 2);
    assert.match(status.pool[0], /127\.0\.0\.1:7001/u);
    assert.match(status.pool[1], /127\.0\.0\.1:7002/u);
    assert.equal(JSON.stringify(status).includes('psecret'), false);
    assert.equal(requests, 1);
  } finally {
    await manager.disable();
    await manager.stop();
    await provider.close();
  }
});

test('refreshHealth never throws and redacts failed proxies', async () => {
  const manager = new ProxyManager({
    config: {
      proxyEnabled: false,
      proxyMode: 'custom',
      proxyUrl: 'http://user:healthsecret@127.0.0.1:1',
      proxyEchoUrl: 'http://127.0.0.1:1/ip',
      proxyTimeoutMs: 500,
      proxyCheckIntervalMs: 0,
    },
  });
  try {
    const status = await manager.refreshHealth();
    assert.equal(status.health.length, 1);
    assert.equal(status.health[0].ok, false);
    assert.equal(typeof status.health[0].error, 'string');
    assert.equal(JSON.stringify(status).includes('healthsecret'), false);
    assert.equal(status.health[0].proxy.includes('healthsecret'), false);
  } finally {
    await manager.stop();
  }
});

test('installGlobalProxy routes built-in fetch, bypasses loopback and restores', { skip: SKIP_UNDICI }, async () => {
  const target = await startHttpTarget((request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end(`LOCAL-ECHO ${request.url}`);
  });
  const proxy = await startProxy({ absoluteBody: (request) => `LOCAL-ECHO ${new URL(request.url).pathname}` });
  const before = globalThis[GLOBAL_DISPATCHER_KEY];
  let dispose = null;
  try {
    dispose = await installGlobalProxy({ proxyUrl: proxy.url, noProxy: 'atkbrain.internal' });
    const proxied = await fetch('http://atkbrain.test/hello');
    assert.equal(proxied.status, 200);
    assert.match(await proxied.text(), /LOCAL-ECHO \/hello/u);
    assert.equal(proxy.state.requests.length, 1);
    assert.equal(proxy.state.requests[0].url, 'http://atkbrain.test/hello');

    const direct = await fetch(`http://127.0.0.1:${target.port}/direct`);
    assert.equal(direct.status, 200);
    assert.match(await direct.text(), /LOCAL-ECHO \/direct/u);
    assert.equal(proxy.state.requests.length, 1, 'loopback must bypass the proxy');
  } finally {
    if (dispose !== null) await dispose();
    await proxy.close();
    await target.close();
  }
});

test('ProxyManager enable routes fetch and disable restores the dispatcher', { skip: SKIP_UNDICI }, async () => {
  const target = await startHttpTarget((request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end(`MANAGER-LOCAL ${request.url}`);
  });
  const proxy = await startProxy({ absoluteBody: (request) => `MANAGER-LOCAL ${new URL(request.url).pathname}` });
  const before = globalThis[GLOBAL_DISPATCHER_KEY];
  const manager = new ProxyManager({
    config: {
      proxyEnabled: false,
      proxyMode: 'custom',
      proxyUrl: proxy.url,
      proxyEchoUrl: '',
      proxyCheckIntervalMs: 0,
    },
  });
  try {
    let status = await manager.enable();
    assert.equal(status.enabled, true);
    assert.equal(status.installed, true);
    assert.match(status.activeProxy, /127\.0\.0\.1/u);

    const response = await fetch('http://manager.test/x');
    assert.equal(response.status, 200);
    assert.match(await response.text(), /MANAGER-LOCAL \/x/u);
    assert.equal(proxy.state.requests.length, 1);
    assert.equal(proxy.state.requests[0].url, 'http://manager.test/x');

    status = await manager.disable();
    assert.equal(status.enabled, false);
    assert.equal(status.installed, false);
  
    const direct = await fetch(`http://127.0.0.1:${target.port}/after`);
    assert.equal(direct.status, 200);
    assert.match(await direct.text(), /MANAGER-LOCAL \/after/u);
  } finally {
    await manager.stop();
    await proxy.close();
    await target.close();
  }
});

test('fail-closed blocks external fetches while loopback stays direct', { skip: SKIP_UNDICI }, async () => {
  const target = await startHttpTarget((request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end(`LOOPBACK-OK ${request.url}`);
  });
  const before = globalThis[GLOBAL_DISPATCHER_KEY];
  const manager = new ProxyManager({
    config: {
      proxyEnabled: true,
      proxyMode: 'custom',
      proxyUrl: '',
      proxyFailClosed: true,
      proxyEchoUrl: '',
      proxyCheckIntervalMs: 0,
    },
  });
  try {
    const status = await manager.enable();
    assert.equal(status.installed, true);
    assert.equal(status.blackholed, true);
    assert.equal(status.activeProxy, 'http://127.0.0.1:9');

    await assert.rejects(
      fetch('http://atkbrain-external.invalid/blocked', { signal: AbortSignal.timeout(5000) }),
      (error) => {
        assert.match(String(error?.message ?? error), /fetch failed|ECONNREFUSED|connect/u);
        return true;
      },
    );

    const local = await fetch(`http://127.0.0.1:${target.port}/ok`);
    assert.equal(local.status, 200);
    assert.match(await local.text(), /LOOPBACK-OK \/ok/u);
  } finally {
    await manager.disable();
    await manager.stop();
    await target.close();
  }
});

test('ProxyManager.test reports the exit IP through a candidate proxy', { skip: SKIP_UNDICI }, async () => {
  const echo = await startHttpTarget((request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ ip: '203.0.113.7', path: request.url }));
  });
  const proxy = await startProxy({ absoluteBody: () => JSON.stringify({ ip: '203.0.113.7' }) });
  const manager = new ProxyManager({
    config: {
      proxyEnabled: false,
      proxyMode: 'custom',
      proxyUrl: `http://u:testsecret@127.0.0.1:${proxy.port}`,
      proxyEchoUrl: `${echo.url}/ip`,
      proxyTimeoutMs: 3000,
      proxyCheckIntervalMs: 0,
    },
  });
  try {
    const result = await manager.test();
    assert.equal(result.ok, true);
    assert.equal(result.exitIp, '203.0.113.7');
    assert.equal(result.directIp, '203.0.113.7');
    assert.equal(result.sameExitIp, true);
    assert.match(result.proxy, /\*\*\*/u);
    assert.equal(JSON.stringify(result).includes('testsecret'), false);

    const invalid = await manager.test('socks5://127.0.0.1:1080');
    assert.equal(invalid.ok, false);
    assert.match(invalid.error, /unsupported HTTP proxy scheme/u);
  } finally {
    await manager.stop();
    await proxy.close();
    await echo.close();
  }
});
