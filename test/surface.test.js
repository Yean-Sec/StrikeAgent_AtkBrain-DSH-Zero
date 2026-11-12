/** Surface roles come from names already on the graph. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { computeFrontier } from '../lib/frontier.js';
import { classesForParameter, classSurface, observedProducts } from '../lib/surface.js';

test('parameter roles follow the name, not a project list', () => {
  assert.deepEqual(classesForParameter('searchKey').includes('xss'), true);
  assert.deepEqual(classesForParameter('searchKey').includes('sqli'), true);
  assert.deepEqual(classesForParameter('ownerId').includes('authz'), true);
  assert.deepEqual(classesForParameter('exportPath').includes('file'), false);
  assert.deepEqual(classesForParameter('unitPrice').includes('logic'), false);
  assert.deepEqual(classesForParameter('returnUrl').includes('xss'), true);
  assert.deepEqual(classesForParameter('color'), []);
});

test('one closed interface leaves the rest of that class on the frontier', () => {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'surface', authorization: 'AUTH-SURFACE' } },
    { op: 'scope.set', allow: [{ type: 'domain', value: 'app.example' }], deny: [] },
    nodeOp('webapp', 'https://app.example/', 'https://app.example/', { url: 'https://app.example/', host: 'app.example', parameters: ['searchKey', 'ownerId', 'exportPath'] }),
    nodeOp('tech', 'apache/tomcat/9.0.1', 'Apache Tomcat/9.0.1', { product: 'Tomcat', version: '9.0.1' }),
    nodeOp('coverage', 'cov/a/xss', '/login × xss', { path: '/login', bugClass: 'xss' }, { status: 'refuted' }),
    nodeOp('coverage', 'cov/b/xss', '/share × xss', { path: '/share', bugClass: 'xss' }, { status: 'open' }),
    nodeOp('coverage', 'cov/c/xss', '/detail × xss', { path: '/detail', bugClass: 'xss' }, { status: 'open' }),
    nodeOp('coverage', 'cov/a/file', '/login × file', { path: '/login', bugClass: 'file' }, { status: 'open' }),
    nodeOp('coverage', 'cov/a/nday', '/login × nday', { path: '/login', bugClass: 'nday' }, { status: 'open' }),
  ], '2026-10-31T00:00:00.000Z');
  const xss = classSurface(Object.values(state.nodes), 'xss');
  assert.deepEqual(xss.open, ['/share', '/detail']);
  assert.equal(xss.closed, 1);
  assert.ok(xss.implied.includes('searchKey'));
  assert.deepEqual(observedProducts(Object.values(state.nodes)).includes('Tomcat'), true);
  const frontier = computeFrontier(state, { limit: 100 });
  const action = frontier.find((entry) => entry.actionType === 'test_coverage' && entry.params?.bugClass === 'xss' && Array.isArray(entry.params.paths));
  assert.ok(action);
  assert.deepEqual(action.params.paths, ['/share', '/detail']);
  assert.match(action.why.join(' '), /does not close the others/u);
  assert.match(action.why.join(' '), /searchKey/u);
  const follow = frontier.find((entry) => entry.actionType === 'follow_stack');
  assert.equal(follow.params.query, 'Tomcat 9.0.1');
  assert.equal(frontier.some((entry) => entry.actionType === 'invoke_skill'), false);
  assert.equal(frontier.some((entry) => entry.actionType === 'inventory_surface'), true);
});

test('ledger paths, cleartext and a proxy host stay on the frontier', () => {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'surface', authorization: 'AUTH-SURFACE' } },
    { op: 'scope.set', allow: [{ type: 'domain', value: 'app.example' }], deny: [] },
    nodeOp('webapp', 'https://app.example/', 'https://app.example/', {
      url: 'https://app.example/', host: 'app.example', endpoints: ['/share.action', '/login.action'],
    }),
    nodeOp('service', 'app.example:80', 'app.example:80', { endpoint: 'app.example', port: 80, protocol: 'http' }),
    nodeOp('service', 'app.example:443', 'app.example:443', { endpoint: 'app.example', port: 443, protocol: 'https' }),
    nodeOp('host', 'app.example', 'app.example', {}),
    nodeOp('tech', 'cdn/proxy', 'edge proxy', { product: 'proxy' }),
    nodeOp('task', 'dict-1', 'dict', { capability: 'dictionary', capabilityAction: 'dict_read', capabilityName: 'lists/common.txt', success: true }, { status: 'completed' }),
    nodeOp('coverage', 'cov/login/xss', '/login.action × xss', { path: '/login.action', bugClass: 'xss' }, { status: 'seen' }),
  ], '2026-10-31T00:00:00.000Z');
  const frontier = computeFrontier(state, { limit: 100 });
  const seed = frontier.find((entry) => entry.actionType === 'seed_coverage');
  assert.deepEqual(seed.params.paths, ['/share.action']);
  assert.equal(frontier.some((entry) => entry.actionType === 'invoke_content_discovery'), false);
  assert.equal(frontier.some((entry) => entry.actionType === 'check_transport'), true);
  assert.equal(frontier.some((entry) => entry.actionType === 'check_vhost'), true);
  assert.equal(frontier.some((entry) => entry.actionType === 'record_observation'), true);
});
