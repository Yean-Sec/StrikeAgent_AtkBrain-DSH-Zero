/** AtkBrain raw probe through the global HTTP proxy adapter. */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';

import { runProbe } from '../lib/probe.js';

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return server.address().port;
}

test('runProbe uses the global HTTP proxy for an HTTP target', async () => {
  const target = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', server: 'probe-fixture' });
    res.end('<html><head><title>proxied probe</title></head><body>ok</body></html>');
  });
  const targetPort = await listen(target);
  const connects = [];
  const proxy = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('proxy');
  });
  proxy.on('connect', (req, client, head) => {
    connects.push(req.url);
    const [host, port] = req.url.split(':');
    const upstream = net.connect(Number(port), host, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on('error', () => client.destroy());
  });
  const proxyPort = await listen(proxy);
  try {
    const result = await runProbe({ action: 'http', url: `http://127.0.0.1:${targetPort}/`, checks: [] }, {
      config: { probeTimeoutMs: 3000, proxyApplyToProbe: true },
      proxy: { currentProxy: () => ({ type: 'http', host: '127.0.0.1', port: proxyPort }) },
    });
    assert.equal(result.status, 200);
    assert.equal(result.title, 'proxied probe');
    assert.deepEqual(connects, [`127.0.0.1:${targetPort}`]);
  } finally {
    await new Promise((resolve) => proxy.close(resolve));
    await new Promise((resolve) => target.close(resolve));
  }
});
