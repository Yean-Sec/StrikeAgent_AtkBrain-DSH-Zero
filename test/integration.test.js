/**
 * Host-tool integration test.
 *
 * Runs the real plugin `apply` against a fake Cordis context, a loopback HTTP
 * fixture and an in-memory projection state. It exercises the full path:
 * tool call -> summary + ops -> projection fold -> query/report.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';

import { apply } from '../index.js';
import { applyOps, emptyState } from '../lib/ops.js';

function startFixture() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html', server: 'atkbrain-fixture' });
      res.end('<html><head><title>AtkBrain Fixture</title></head><body>hello</body></html>');
      return;
    }
    if (url.pathname === '/admin') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html><head><title>Admin Console</title></head><body>admin</body></html>');
      return;
    }
    if (url.pathname === '/.git/HEAD') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ref: refs/heads/main\n');
      return;
    }
    if (url.pathname === '/actuator/env') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ activeProfiles: ['prod'], spring: { datasource: { password: 'not-a-real-secret' } } }));
      return;
    }
    if (url.pathname === '/files/') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html><head><title>Index of /files</title></head><body><a href="../">../</a></body></html>');
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ server, port: address.port });
    });
  });
}

function createHarness() {
  let state = emptyState();
  const tools = new Map();
  const ctx = {
    logger: { warn() {}, info() {} },
    sessionProjections: {
      stateOf: () => state,
      register: () => () => {},
    },
    tools: {
      register(definition) {
        tools.set(definition.name, definition);
        return () => {};
      },
    },
    systemPrompt: { section: () => () => {} },
    effect(fn) {
      const dispose = fn();
      return () => { if (typeof dispose === 'function') dispose(); };
    },
    get(name) {
      if (name === 'approval') {
        return {
          async request() { return 'allowed-once'; },
        };
      }
      return undefined;
    },
  };
  apply(ctx, { requireScopeApproval: true });
  function getTool(name) {
    const tool = tools.get(name);
    assert.ok(tool, `tool ${name} was not registered`);
    return tool;
  }
  let callCounter = 0;
  async function run(name, args, agent) {
    callCounter += 1;
    const tool = getTool(name);
    const controller = new AbortController();
    const exec = {
      agent,
      callId: `call-${callCounter}`,
      name,
      signal: controller.signal,
      arguments: args,
    };
    const value = await tool.execute(args, exec);
    assert.equal(typeof value.summary, 'string');
    assert.ok(Array.isArray(value.ops));
    const meta = tool.output.presentationMeta(args, value);
    if (meta !== undefined) {
      assert.equal(meta.schema, 'atkbrain/1');
      state = applyOps(state, meta.ops, meta.at);
    }
    return value;
  }
  return { ctx, tools, getTool, run, state: () => state };
}

test('Host tools integrate: scope -> ingest -> probe -> record -> query -> report', async () => {
  const { server, port } = await startFixture();
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-it-'));
  const agent = {
    id: 'session-it',
    session: {
      id: 'session-it',
      header: { cwd: workspace },
    },
  };
  const harness = createHarness();
  try {
    // 1. Scope (approval service returns allowed-once).
    const scopeResult = await harness.run('atkbrain_scope', {
      action: 'set',
      engagement: {
        name: 'it-engagement',
        client: 'fixture',
        authorization: 'AUTH-TEST',
        roe: { techniques: ['T0', 'T1'] },
      },
      allow: [{ type: 'host', value: '127.0.0.1' }],
      deny: [],
    }, agent);
    assert.match(scopeResult.summary, /1 allow/);
    assert.match(scopeResult.details.projectId, /^PRJ-[A-Z0-9]{8}$/);
    assert.equal(scopeResult.details.engagement.id, scopeResult.details.projectId);
    assert.match(scopeResult.summary, /二次验证和报告撰写/);
    const bootTeams = Object.values(harness.state().nodes).filter((node) => node.kind === 'self_team');
    assert.equal(bootTeams.length, 3, 'scope set records lead, verification and report');
    assert.deepEqual(bootTeams.map((node) => node.attrs.type).sort(), ['lead', 'report', 'verification']);
    assert.ok(bootTeams.every((node) => /[\u3400-\u9fff]/u.test(node.label)), 'team labels must be Chinese');
    const leadTeam = bootTeams.find((node) => node.attrs.type === 'lead');
    assert.equal(leadTeam.attrs.mode, 'main');
    const reportTeam = bootTeams.find((node) => node.attrs.type === 'report');
    assert.deepEqual(reportTeam.attrs.reportModes, ['project', 'finding']);

    // 2. Asset ingestion with intentional duplicates.
    const ingestResult = await harness.run('atkbrain_ingest', {
      text: [
        '127.0.0.1',
        '127.0.0.1',
        'http://127.0.0.1:' + port + '/admin',
        '10.20.0.0/24',
        'app.internal.test',
      ].join('\n'),
      format: 'lines',
      probeWildcard: false,
      tags: ['fixture'],
      sourceName: 'fixture.txt',
    }, agent);
    assert.match(ingestResult.summary, /raw candidate/);
    assert.ok(ingestResult.ops.length > 0);

    // 3. TCP probe on the loopback fixture (port is open).
    const tcp = await harness.run('atkbrain_probe', {
      action: 'tcp',
      target: '127.0.0.1',
      ports: String(port),
    }, agent);
    assert.match(tcp.summary, /completed/);
    assert.ok(tcp.ops.some((op) => op.op === 'node.upsert' && op.kind === 'service'));

    // 4. HTTP probe with safe exposure checks.
    const httpResult = await harness.run('atkbrain_probe', {
      action: 'http',
      url: `http://127.0.0.1:${port}/`,
      checks: ['fingerprint', 'exposure'],
    }, agent);
    assert.match(httpResult.summary, /HTTP 200/);
    assert.ok(httpResult.ops.some((op) => op.op === 'node.upsert' && op.kind === 'webapp'));
    const candidateFinding = httpResult.ops.find((op) => op.op === 'node.upsert' && op.kind === 'finding');
    assert.ok(candidateFinding, 'exposure checks should produce a candidate finding');

    // 5. Record verified finding, credential, access and redacted data evidence.
    const stateAfterHttp = harness.state();
    const webapp = Object.values(stateAfterHttp.nodes).find((node) => node.kind === 'webapp');
    assert.ok(webapp);
    const record = await harness.run('atkbrain_record', {
      nodes: [
        {
          kind: 'finding',
          attrs: {
            template: 'manual-auth-bypass',
            title: 'Admin panel reachable without authentication',
            severity: 'high',
            subjectKey: webapp.key,
            subjectId: webapp.id,
            verification: 'verified',
            proofType: 'poc_replay',
            proofUrl: `http://127.0.0.1:${port}/admin`,
            proofDetail: 'GET /admin returned 200 with title "Admin Console" and no session cookie.',
            channels: ['status', 'body'],
            repro: 'GET /admin returned 200 with title "Admin Console" and no session cookie.',
          },
          status: 'verified',
          verification: 'verified',
        },
        {
          kind: 'credential',
          attrs: {
            username: 'admin',
            kind: 'password',
            realm: 'external',
            secretMask: '******',
            secretFp: 'hmac-fixture',
            validity: 'valid',
            privilege: 'admin',
          },
        },
        {
          kind: 'access',
          attrs: {
            assetKey: webapp.key,
            kind: 'admin_panel',
            privilege: 'admin',
            status: 'validated',
            proof: 'authenticated /admin role marker',
          },
          status: 'validated',
          verification: 'verified',
        },
      ],
    }, agent);
    assert.match(record.summary, /Recorded/);
    const stateAfterRecord = harness.state();
    const access = Object.values(stateAfterRecord.nodes).find((node) => node.kind === 'access');
    assert.ok(access);

    const data = await harness.run('atkbrain_record', {
      nodes: [{
        kind: 'data',
        attrs: {
          subjectId: access.id,
          dataClass: 'pii',
          count: 640,
          countMethod: 'SELECT COUNT(*) FROM customers',
          rows: [{ email: 'alice@example.com', phone: '13812345678', note: 'fixture' }],
          verification: 'verified',
        },
        status: 'verified',
        verification: 'verified',
      }],
    }, agent);
    assert.match(data.summary, /Recorded/);

    // 6. Query graph, frontier, path and scope.
    const stats = await harness.run('atkbrain_query', { action: 'stats' }, agent);
    assert.match(stats.summary, /node\(s\)/);
    const frontier = await harness.run('atkbrain_query', { action: 'frontier', limit: 10 }, agent);
    assert.ok(Array.isArray(frontier.details.actions));
    const scope = await harness.run('atkbrain_query', { action: 'scope', target: '127.0.0.1' }, agent);
    assert.match(scope.summary, /allowed/);
    const search = await harness.run('atkbrain_query', { action: 'search', query: 'admin' }, agent);
    assert.ok(Array.isArray(search.details.nodes));

    // 7. The handoff is due once findings exist. Brief, then write the report.
    const brief = await harness.run('atkbrain_selftteam', { action: 'brief' }, agent);
    assert.match(brief.summary, /目标：/);
    const report = await harness.run('atkbrain_report', { format: 'all' }, agent);
    assert.match(report.summary, /Report written/);
    assert.ok(report.details.files.length >= 4);
    for (const file of report.details.files) {
      const text = await readFile(file.path, 'utf8');
      assert.ok(text.length > 0, `${file.relative} should not be empty`);
      assert.ok(!text.includes('alice@example.com'), 'raw email must not leak');
      assert.ok(!text.includes('13812345678'), 'raw phone must not leak');
    }
    const markdownFile = report.details.files.find((entry) => entry.relative.endsWith('.md'));
    assert.ok(markdownFile, 'expected a markdown report file');
    const markdown = await readFile(markdownFile.path, 'utf8');
    assert.match(markdown, /# .*Assessment|# .*Report|# .*安全/iu);
    assert.match(markdown, /Evidence|证据/iu);

    // 8. The projection state contains redacted samples only.
    const finalState = harness.state();
    const dataNode = Object.values(finalState.nodes).find((node) => node.kind === 'data');
    assert.ok(dataNode);
    assert.equal(JSON.stringify(dataNode.attrs).includes('alice@example.com'), false);
    assert.equal(JSON.stringify(dataNode.attrs).includes('13812345678'), false);
    assert.equal(finalState.audit.length > 0, true);

    // 9. Tunnel list is available and empty.
    const tunnels = await harness.run('atkbrain_tunnel', { action: 'list' }, agent);
    assert.match(tunnels.summary, /active tunnel/);

    // 10. Out-of-scope probe is refused by the scope guard.
    await assert.rejects(
      () => harness.run('atkbrain_probe', { action: 'tcp', target: '198.51.100.7', ports: '80' }, agent),
      /scope denied|no allow entry|requires a scope|scope/i,
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
    await new Promise((resolve) => server.close(resolve));
  }
});

test('scope set reads a frozen engagement mode instead of writing it back', async () => {
  const harness = createHarness();
  const engagement = Object.freeze({
    name: 'frozen-mode',
    authorization: 'AUTH-TEST',
    mode: 'authorized-pentest',
  });
  const agent = { id: 'session-frozen', session: { id: 'session-frozen', header: { cwd: os.tmpdir() } } };
  const result = await harness.run('atkbrain_scope', {
    action: 'set',
    engagement,
    allow: [{ type: 'host', value: 'app.example.test' }],
    deny: [],
  }, agent);
  assert.equal(engagement.mode, 'authorized-pentest');
  assert.equal(result.details.engagement.mode, 'intrusive');
});
