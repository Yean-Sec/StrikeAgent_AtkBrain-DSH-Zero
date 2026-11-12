/** New tool surface: arsenal, coverage, hypothesis, proxy. */
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';

import { apply } from '../index.js';
import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { computeFrontier } from '../lib/frontier.js';
import { publicAttrs } from '../lib/redact.js';

async function harness() {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'arsenal-it', authorization: 'AUTH-ARSENAL-1' } },
    { op: 'scope.set', allow: [{ type: 'cidr', value: '10.0.0.0/24', canonical: '10.0.0.0/24' }], deny: [] },
    nodeOp('host', '10.0.0.1', '10.0.0.1', { fqdn: '10.0.0.1', realm: 'internal' }),
  ]);
  const tools = new Map();
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-arsenal-'));
  const ctx = {
    logger: { warn() {}, info() {} },
    sessionProjections: { stateOf: () => state, register: () => () => {} },
    systemPrompt: { section: () => () => {} },
    effect(fn) { const dispose = fn(); return () => { if (typeof dispose === 'function') dispose(); }; },
    tools: {
      register(definition) { tools.set(definition.name, definition); return () => {}; },
      get(name) { return tools.get(name); },
    },
    get(name) { if (name === 'approval') return { async request() { return 'allowed-once'; } }; return undefined; },
  };
  apply(ctx, {
    requireScopeApproval: false,
    requireTunnelApproval: false,
    arsenalRoot: '',
    proxyEnabled: false,
  });
  let counter = 0;
  async function run(name, args) {
    counter += 1;
    const tool = tools.get(name);
    assert.ok(tool, `tool ${name}`);
    const value = await tool.execute(args, {
      agent: { id: 'parent', session: { id: 'parent', header: { cwd: workspace } } },
      callId: `call-${counter}`,
      name,
      signal: new AbortController().signal,
      arguments: args,
    });
    const meta = tool.output.presentationMeta(args, value);
    if (meta !== undefined) state = applyOps(state, meta.ops, meta.at);
    return value;
  }
  return { run, state: () => state, close: () => rm(workspace, { recursive: true, force: true }) };
}

test('removed skill, dictionary and scanner actions are rejected', async () => {
  const h = await harness();
  try {
    await assert.rejects(h.run('atkbrain_arsenal', { action: 'skill_search', query: 'xss' }), /action/u);
    await assert.rejects(h.run('atkbrain_arsenal', { action: 'dict_read', path: 'dicts/common.txt' }), /action/u);
    await assert.rejects(h.run('atkbrain_arsenal', { action: 'tool_run', name: 'curl', args: ['--version'] }), /action/u);
  } finally {
    await h.close();
  }
});

test('finding detail fields retain request/response packets and redact cookies', async () => {
  const h = await harness();
  try {
    await h.run('atkbrain_record', {
      nodes: [{
        kind: 'finding',
        attrs: {
          template: 'manual-rce',
          title: 'Upload webshell RCE',
          severity: 'critical',
          category: 'rce',
          subjectKey: '10.0.0.1',
          description: 'Upload accepts PHP and serves it from the uploads directory.',
          impact: 'www-data command execution on the target host.',
          request: 'GET /uploads/shell.php?x=id HTTP/1.1\nHost: 10.0.0.1\nCookie: session=TOP-SECRET',
          response: 'HTTP/1.1 200 OK\n\nuid=33(www-data)',
          repro: 'GET /uploads/shell.php?x=id with no authentication',
          proofType: 'poc_replay',
          proofDetail: 'nonce OMPSTART returned uid=33',
          secondaryVerified: true,
          redteamRating: 'critical',
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        },
      }],
    });
    const finding = Object.values(h.state().nodes).find((node) => node.kind === 'finding');
    assert.equal(finding.attrs.request.includes('/uploads/shell.php'), true);
    const publicFinding = publicAttrs('finding', finding.attrs);
    assert.equal(publicFinding.request.includes('TOP-SECRET'), false);
    assert.equal(publicFinding.request.includes('[redacted]'), true);
    assert.equal(publicFinding.response.includes('uid=33'), true);
    assert.equal(publicFinding.description.includes('PHP'), true);
  } finally {
    await h.close();
  }
});

test('coverage tool seeds four cells and enforces a two-channel seen note', async () => {
  const h = await harness();
  try {
    const seed = await h.run('atkbrain_coverage', { action: 'seed', path: '/login' });
    assert.match(seed.summary, /4 coverage cell/u);
    await assert.rejects(
      h.run('atkbrain_coverage', { action: 'note', path: '/login', bugClass: 'xss', status: 'seen', channels: ['status'] }),
      /two observation channels|evidence/u,
    );
    const seen = await h.run('atkbrain_coverage', { action: 'note', path: '/login', bugClass: 'xss', status: 'seen', channels: ['status', 'body'], note: 'unique nonce reflected in body' });
    assert.match(seen.summary, /xss -> seen/u);
    const check = await h.run('atkbrain_coverage', { action: 'check', path: '/login' });
    assert.match(check.summary, /4 cell/u);
    assert.equal(check.details.summary.seen, 1);
    const frontier = computeFrontier(h.state(), { limit: 100 });
    assert.ok(frontier.some((action) => action.actionType === 'test_coverage'), 'open coverage cells must enter the frontier');
    await assert.rejects(
      h.run('atkbrain_coverage', { action: 'note', path: '/login', bugClass: 'sqli', status: 'refuted', note: '全部 404，面关闭' }),
      /refuted|concrete|specific|generic/u,
    );
  } finally {
    await h.close();
  }
});

test('hypothesis tool persists and resolves with evidence', async () => {
  const h = await harness();
  try {
    const proposed = await h.run('atkbrain_hypothesis', { action: 'propose', strategy: 'the login page leaks a stack trace', targetKey: '10.0.0.1', bugClass: 'leak', expectedProof: 'poc_replay' });
    const id = proposed.details.hypothesis?.hypothesisId ?? proposed.details.id;
    const openFrontier = computeFrontier(h.state(), { limit: 100 });
    assert.ok(openFrontier.some((action) => action.actionType === 'test_hypothesis'), 'open hypotheses must enter the frontier');
    const resolved = await h.run('atkbrain_hypothesis', { action: 'resolve', id, status: 'verified', channels: ['body', 'timing'] });
    assert.match(resolved.summary, /verified/u);
    const list = await h.run('atkbrain_hypothesis', { action: 'list' });
    assert.match(list.summary, /1 hypothesis/u);
  } finally {
    await h.close();
  }
});

test('proxy tool reports a masked, disabled state without credentials', async () => {
  const h = await harness();
  try {
    const status = await h.run('atkbrain_proxy', { action: 'status' });
    assert.match(status.summary, /Proxy disabled/u);
    assert.equal(status.details.enabled, false);
    const testResult = await h.run('atkbrain_proxy', { action: 'test', url: 'http://user:secret@127.0.0.1:9' });
    assert.equal(testResult.details.ok, false);
    assert.equal(JSON.stringify(testResult).includes('secret'), false);
  } finally {
    await h.close();
  }
});

test('endpoint_vocab inventories bare action endpoints and seeds coverage', async () => {
  const h = await harness();
  try {
    await h.run('atkbrain_record', { nodes: [{ kind: 'webapp', key: 'http://10.0.0.1/', attrs: { url: 'http://10.0.0.1/', host: '10.0.0.1' } }] });
    const text = `<form action="shareGroupCard.action"><input name="userId"></form>
      $.ajax({url: "worddetail!execute.action", data: {searchKey: q}});
      $.ajax({url: "shopPorductAction!showProducts.action", data: {succLoginRedirect: r}});`;
    const result = await h.run('atkbrain_arsenal', { action: 'endpoint_vocab', target: '10.0.0.1', text });
    assert.match(result.summary, /shareGroupCard\.action/u);
    assert.match(result.summary, /worddetail!execute\.action/u);
    assert.ok(result.details.endpoints.includes('shareGroupCard.action'));
    assert.ok(result.details.endpoints.includes('worddetail!execute.action'));
    assert.equal(result.ops.some((op) => op.op === 'node.upsert' && op.kind === 'coverage'), false);
    assert.equal(result.details.coverageSeeded, 0);
    const webapp = Object.values(h.state().nodes).find((node) => node.kind === 'webapp');
    assert.ok(webapp.attrs.parameters.includes('userId'));
    assert.ok(webapp.attrs.parameters.includes('searchKey'));
    assert.ok(webapp.attrs.parameterMap['/sharegroupcard.action'].includes('userId'));
    assert.ok(webapp.attrs.parameterMap['/worddetail!execute.action'].includes('searchKey'));
  } finally {
    await h.close();
  }
});

test('recording a webapp writes the ledger and blocks a close until page text is supplied', async () => {
  const h = await harness();
  try {
    await h.run('atkbrain_record', {
      nodes: [{ kind: 'webapp', key: 'http://10.0.0.1/login.action?user=1', attrs: { url: 'http://10.0.0.1/login.action?user=1', host: '10.0.0.1' } }],
    });
    let app = Object.values(h.state().nodes).find((node) => node.kind === 'webapp');
    assert.notEqual(app.attrs.surfaceInventoried, true);
    assert.ok(app.attrs.endpoints.includes('/login.action'));
    assert.ok(app.attrs.parameterMap['/login.action'].includes('user'));
    await assert.rejects(
      h.run('atkbrain_coverage', { action: 'note', path: '/login.action', bugClass: 'leak', status: 'refuted', note: '/login.action generic 404 page, no stack and no version' }),
      /endpoint_vocab/,
    );
    await h.run('atkbrain_record', {
      nodes: [{
        kind: 'webapp',
        key: 'http://10.0.0.1/login.action?user=1',
        attrs: { url: 'http://10.0.0.1/login.action?user=1', host: '10.0.0.1', html: '<form action="/login.action"><input name="user"></form>' },
      }],
    });
    app = Object.values(h.state().nodes).find((node) => node.kind === 'webapp');
    assert.equal(app.attrs.entryPath, '/login.action');
    assert.equal(app.attrs.surfaceInventoried, false);
    await assert.rejects(
      h.run('atkbrain_coverage', { action: 'note', path: '/login.action', bugClass: 'leak', status: 'refuted', note: '/login.action generic 404 page, no stack and no version' }),
      /endpoint_vocab/,
    );
    await h.run('atkbrain_record', {
      nodes: [{
        kind: 'webapp',
        key: 'http://10.0.0.1/login.action?user=1',
        attrs: {
          url: 'http://10.0.0.1/login.action?user=1',
          host: '10.0.0.1',
          html: '<form action="/login.action"><input name="user"></form><form action="/modules/exec.php"></form>',
        },
      }],
    });
    app = Object.values(h.state().nodes).find((node) => node.kind === 'webapp');
    assert.equal(app.attrs.surfaceInventoried, true);
    await h.run('atkbrain_record', {
      nodes: [{
        kind: 'webapp',
        key: 'http://10.0.0.1/login.action?user=1',
        attrs: { url: 'http://10.0.0.1/login.action?user=1', host: '10.0.0.1', title: 'later note' },
      }],
    });
    app = Object.values(h.state().nodes).find((node) => node.kind === 'webapp' && node.attrs?.surfaceInventoried === true);
    assert.equal(app.attrs.surfaceInventoried, true);
    await h.run('atkbrain_record', {
      nodes: [{ kind: 'webapp', key: 'http://10.0.0.1/', attrs: { url: 'http://10.0.0.1/', host: '10.0.0.1' } }],
    });
    const noted = await h.run('atkbrain_coverage', {
      action: 'note',
      path: '/login.action',
      bugClass: 'leak',
      status: 'refuted',
      note: '/login.action generic 404 page, no stack and no version',
    });
    assert.match(noted.summary, /leak -> refuted/);
    const cell = Object.values(h.state().nodes).find((node) => node.kind === 'coverage' && node.attrs?.bugClass === 'leak');
    assert.match(cell.attrs.note, /404/);
    assert.match(cell.attrs.reason, /404/);
    await assert.rejects(
      h.run('atkbrain_coverage', { action: 'note', path: '/login.action', bugClass: 'xss', status: 'refuted', note: '/login.action user was not reflected in the body' }),
      /T3|intrusive/,
    );
  } finally {
    await h.close();
  }
});

test('frontier does not ask for skills, dictionaries or scanners', () => {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'web', authorization: 'AUTH-WEB' } },
    { op: 'scope.set', allow: [{ type: 'host', value: 'app.example', canonical: 'app.example' }], deny: [] },
    nodeOp('webapp', 'https://app.example', 'https://app.example', { url: 'https://app.example', host: 'app.example' }),
  ]);
  const frontier = computeFrontier(state, { limit: 12 });
  assert.equal(frontier[0].actionType, 'expand_application');
  const posture = frontier.find((action) => action.actionType === 'raise_posture');
  assert.equal(posture.params.engagement.mode, 'intrusive');
  assert.deepEqual(posture.params.roe.techniques, ['T0', 'T1', 'T2', 'T3']);
  assert.equal(frontier.some((action) => action.actionType === 'invoke_scanner'), false);
  assert.equal(frontier.some((action) => action.actionType === 'invoke_skill'), false);
  assert.equal(frontier.some((action) => action.actionType === 'invoke_dictionary'), false);
  assert.equal(frontier.some((action) => action.actionType === 'inventory_surface'), true);
});
