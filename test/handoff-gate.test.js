/** Handoff overdue rule, seven sections, and the discovery gaps around them. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { bootstrapSelfTeamOps, selfTeamOp } from '../lib/self-teams.js';
import { computeFrontier } from '../lib/frontier.js';
import { familyParameters } from '../lib/endpoint-vocab.js';
import { handoffOverdue, handoffText } from '../lib/supervision-memory.js';
import { listUnreadWorkspaceFiles, observationRelative, unreadWorkspaceFiles, unlinkedPluginEvidence } from '../lib/workspace-residue.js';
import { createRuntime } from '../lib/runtime.js';

function base() {
  let state = emptyState();
  state.engagement = { name: 'synthetic', authorization: 'lab' };
  state.scope.allow = [{ type: 'domain', value: 'app.example' }];
  state = applyOps(state, bootstrapSelfTeamOps(state), '2026-11-01T00:00:00.000Z');
  return state;
}

test('a saved file stays unread until some graph node points at it', () => {
  assert.equal(observationRelative('wc/page.html'), true);
  assert.equal(observationRelative('reports/out.html'), false);
  assert.equal(observationRelative('.atkbrain/reports/out.html'), false);
  assert.equal(observationRelative('.atkbrain/evidence/page.txt'), false);
  assert.equal(observationRelative('.atkbrain/evidence/verify-8f25f5052e-5c09c5313c.json'), false);
  assert.equal(observationRelative('.atkbrain/surface/home.html'), false);
  const nodes = [{ kind: 'evidence', attrs: { relative: '.atkbrain/evidence/page.txt' } }];
  assert.deepEqual(unreadWorkspaceFiles(nodes, [
    { relative: '.atkbrain/evidence/page.txt' },
    { relative: '.atkbrain/evidence/old-run.txt' },
    { relative: 'wc/page.html' },
    { relative: 'reports/out.md' },
  ]), ['wc/page.html']);
});

test('seven sections stay visible when credentials and footholds are absent', () => {
  const state = applyOps(base(), [
    nodeOp('host', 'app.example', 'app.example', { fqdn: 'app.example' }),
    nodeOp('webapp', 'https://app.example/', 'app', {
      host: 'app.example',
      url: 'https://app.example/',
      endpoints: ['/login', '/download'],
      surfaceInventoried: true,
    }),
    nodeOp('service', 'app.example:80', 'app.example:80', { endpoint: 'app.example', protocol: 'http', port: 80 }),
    nodeOp('service', 'app.example:443', 'app.example:443', { endpoint: 'app.example', protocol: 'https', port: 443 }),
  ], '2026-11-01T00:05:00.000Z');
  const text = handoffText(Object.values(state.nodes));
  assert.match(text, /目标：/);
  assert.match(text, /\/login/);
  assert.doesNotMatch(text, /ledger/u);
  assert.match(text, /服务：/);
  assert.match(text, /明文未核对/);
  assert.match(text, /凭证：无/);
  assert.match(text, /立足点：无/);
});

test('eight new coverage rows make the handoff overdue and one finding is enough', () => {
  let state = applyOps(base(), [
    nodeOp('webapp', 'https://app.example/', 'app', {
      host: 'app.example',
      url: 'https://app.example/',
      endpoints: ['/one', '/two'],
    }),
  ], '2026-11-01T00:05:00.000Z');
  state = applyOps(state, [
    selfTeamOp(state, 'supervision', { lastBriefAt: '2026-11-01T00:05:00.000Z' }),
  ], '2026-11-01T00:05:00.000Z');
  const coverage = Array.from({ length: 7 }, (_, index) => nodeOp(
    'coverage',
    `cov/${index}`,
    `/${index}`,
    { path: `/${index}`, bugClass: 'xss', note: 'looked' },
    { status: 'seen' },
  ));
  state = applyOps(state, coverage, '2026-11-01T00:06:00.000Z');
  assert.equal(handoffOverdue(Object.values(state.nodes), '2026-11-01T00:05:00.000Z'), false);
  state = applyOps(state, [
    nodeOp('coverage', 'cov/7', '/7', { path: '/7', bugClass: 'xss', note: 'looked' }, { status: 'seen' }),
  ], '2026-11-01T00:07:00.000Z');
  assert.equal(handoffOverdue(Object.values(state.nodes), '2026-11-01T00:05:00.000Z'), true);

  const quiet = applyOps(base(), [
    selfTeamOp(base(), 'supervision', { lastBriefAt: '2026-11-01T00:05:00.000Z' }),
    nodeOp('finding', 'finding/stack', 'error page', { title: 'error page', severity: 'medium' }),
  ], '2026-11-01T00:06:00.000Z');
  assert.equal(handoffOverdue(Object.values(quiet.nodes), '2026-11-01T00:05:00.000Z'), true);
  assert.equal(handoffOverdue([], null), false);
});

test('cleartext and a thin ledger stay ahead of more coverage', () => {
  const endpoints = Array.from({ length: 12 }, (_, index) => `/p${index}`);
  const state = applyOps(base(), [
    nodeOp('webapp', 'https://app.example/', 'app', {
      host: 'app.example',
      url: 'https://app.example/',
      endpoints,
      surfaceInventoried: true,
    }),
    nodeOp('service', 'app.example:80', 'app.example:80', { endpoint: 'app.example', protocol: 'http', port: 80 }),
    nodeOp('service', 'app.example:443', 'app.example:443', { endpoint: 'app.example', protocol: 'https', port: 443 }),
    nodeOp('host', 'app.example', 'app.example', {}),
    nodeOp('tech', 'edge/proxy', 'edge proxy', { product: 'proxy' }),
    nodeOp('tech', 'java', 'Java', { product: 'Java' }),
    nodeOp('task', 'dict-1', 'dict', {
      capability: 'dictionary',
      capabilityAction: 'dict_read',
      capabilityName: 'lists/common.txt',
      success: true,
    }, { status: 'completed' }),
  ], '2026-11-01T00:05:00.000Z');
  const frontier = computeFrontier(state, { limit: 100 });
  const transport = frontier.find((action) => action.actionType === 'check_transport');
  const seed = frontier.find((action) => action.actionType === 'seed_coverage');
  const inventory = frontier.find((action) => action.actionType === 'inventory_surface');
  assert.ok(transport);
  assert.ok(seed);
  assert.ok(transport.priority > seed.priority);
  assert.ok(inventory);
  assert.match(inventory.why.join(' '), /parameter/);
  assert.equal(frontier.some((action) => action.actionType === 'check_vhost'), true);
  assert.equal(frontier.some((action) => action.actionType === 'invoke_backup_dictionary'), false);
  assert.deepEqual(familyParameters(['/item/a', '/item/b', '/item/c', '/item/d'])['/item/a'], ['segment']);
});

test('an error-page version, a read config and a timed-out review stay on the frontier', () => {
  const state = applyOps(base(), [
    selfTeamOp(base(), 'supervision', {}),
    nodeOp('tech', 'java', 'Java', { product: 'Java' }),
    nodeOp('finding', 'finding/stack', 'error page Tomcat 9.0.45', {
      title: 'error page Tomcat 9.0.45 stack trace',
      severity: 'medium',
      secondaryVerdict: 'inconclusive',
      secondaryRationale: 'supervisor timeout',
      secondaryVerified: false,
    }, { status: 'verified' }),
    nodeOp('finding', 'finding/object', '读取到配置文件', {
      title: '读取到配置文件',
      severity: 'medium',
    }, { status: 'verified' }),
  ], '2026-11-01T00:05:00.000Z');
  const frontier = computeFrontier(state, { limit: 100 });
  assert.equal(frontier.some((action) => action.actionType === 'record_stack_tech'), true);
  assert.equal(frontier.some((action) => action.actionType === 'record_credential_gap'), true);
  assert.equal(frontier.some((action) => action.actionType === 'verify_finding'), true);
  const brief = frontier.find((action) => action.actionType === 'self_brief');
  assert.equal(brief.priority, 97);
});

test('evidence files stay in the test directory and out of the source tree', async () => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'atk-project-'));
  try {
    const runtime = createRuntime({ config: {}, logger: { info() {}, warn() {}, error() {} } });
    const agent = { id: 'session-a', session: { id: 'session-a', header: { cwd: workspace } } };
    const saved = await runtime.writeEvidence(agent, 'note', 'hello', 'text/plain');
    assert.equal(saved.relative.startsWith('.atkbrain/evidence/'), true);
    assert.equal(saved.path.startsWith(`${path.resolve(workspace)}${path.sep}`), true);
    assert.equal(saved.path.includes(`${path.sep}.atkbrain${path.sep}evidence${path.sep}`), true);
    const report = await runtime.writeReportAt(agent, '.atkbrain/reports/out.md', '# report');
    assert.equal(report.relative, '.atkbrain/reports/out.md');
    assert.equal(report.path.startsWith(`${path.resolve(workspace)}${path.sep}`), true);
    const names = await readdir(workspace);
    assert.deepEqual(names, ['.atkbrain']);
    const source = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
    const sourceAgent = { id: 'session-src', session: { id: 'session-src', header: { cwd: source } } };
    await assert.rejects(() => runtime.writeEvidence(sourceAgent, 'note', 'no', 'text/plain'), /源代码/);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('evidence files in the test directory do not block and can be recorded', async () => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'atk-evidence-'));
  const agent = { id: 'session-b', session: { id: 'session-b', header: { cwd: workspace } } };
  try {
    await mkdir(path.join(workspace, '.atkbrain', 'evidence'), { recursive: true });
    await writeFile(path.join(workspace, '.atkbrain', 'evidence', 'tool-curl-abc.txt'), 'output');
    await writeFile(path.join(workspace, 'page.html'), '<html></html>');
    const pending = await unlinkedPluginEvidence(agent, []);
    assert.equal(pending.length, 1);
    assert.equal(pending[0].relative, '.atkbrain/evidence/tool-curl-abc.txt');
    const unread = await listUnreadWorkspaceFiles(agent, []);
    assert.deepEqual(unread, ['page.html']);
    const again = await unlinkedPluginEvidence(agent, [{ kind: 'evidence', attrs: { relative: pending[0].relative } }]);
    assert.deepEqual(again, []);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
