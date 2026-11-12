/**
 * Core unit tests: CIDR, scope, ops fold, wire view, frontier, path, redaction.
 * These are dependency-free and run with `node --test`.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalIp,
  cidrContainsIp,
  isPrivateIp,
  mergeCidrs,
  parseCidr,
  parseIpv4,
  parseIpv6,
} from '../lib/cidr.js';
import { evaluateScope, normalizeEngagementMode, normalizeScopeEntry, scopeSummary } from '../lib/scope.js';
import { applyOps, emptyState, nodeOp, edgeOp, auditOp } from '../lib/ops.js';
import { buildView, graphSummary } from '../lib/graph.js';
import { computeFrontier } from '../lib/frontier.js';
import { computeCrownPaths } from '../lib/path.js';
import { publicAttrs, redactRow, maskEmail, maskPhone, maskPan } from '../lib/redact.js';
import { resolveConfig } from '../lib/config.js';
import { nodeId } from '../lib/util.js';

const AT = '2026-10-31T00:00:00.000Z';

function seededState() {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'acme', authorization: 'AUTH-1', roe: { techniques: ['T0', 'T1'] } } },
    { op: 'scope.set', allow: [{ type: 'cidr', value: '10.0.0.0/8', canonical: '10.0.0.0/8' }], deny: [], updatedAt: AT, approvedAt: AT },
    nodeOp('host', 'www.acme.test', 'www.acme.test', { fqdn: 'www.acme.test', realm: 'external', wildcardStatus: 'explicit' }),
    nodeOp('ip', '10.1.2.3', '10.1.2.3', { addr: '10.1.2.3', version: 4, realm: 'internal' }),
    edgeOp({ kind: 'host', key: 'www.acme.test' }, { kind: 'ip', key: '10.1.2.3' }, 'resolves_to'),
    nodeOp('service', 'tcp:10.1.2.3:6379', '10.1.2.3:6379', { endpoint: '10.1.2.3', port: 6379, transport: 'tcp', state: 'open', protocol: 'redis' }),
    edgeOp({ kind: 'ip', key: '10.1.2.3' }, { kind: 'service', key: 'tcp:10.1.2.3:6379' }, 'exposes'),
    nodeOp('finding', 'acme/finding/sqli', 'SQL injection', { template: 'sqli', title: 'SQL injection', severity: 'high', subjectKey: 'www.acme.test' }, { status: 'candidate' }),
    nodeOp('access', 'acme/www.acme.test/shell/user', 'www.acme.test shell', { assetKey: 'www.acme.test', kind: 'shell', privilege: 'user' }, { status: 'validated' }),
    nodeOp('data', 'acme/access/customer_records/001', 'customer records', { dataClass: 'customer_records', count: 640, countMethod: 'COUNT(*)', thresholdMet: true, subjectId: 'acme/www.acme.test/shell/user' }, { status: 'verified' }),
    auditOp('test', 'seed', 'www.acme.test', 'ok'),
  ], AT);
  return state;
}

test('IPv4 leading zeros are rejected', () => {
  assert.equal(parseIpv4('010.0.0.1'), undefined);
  assert.equal(parseIpv4('10.0.0.1')?.canonical, '10.0.0.1');
});

test('IPv6 canonicalization compresses the longest zero run', () => {
  assert.equal(parseIpv6('2001:0DB8::0001')?.canonical, '2001:db8::1');
  assert.equal(parseIpv6('::ffff:192.168.0.1')?.mapped, '192.168.0.1');
  assert.equal(parseIpv6('fe80::1%en0')?.canonical, 'fe80::1');
});

test('CIDR containment and merge', () => {
  assert.equal(cidrContainsIp('10.0.0.0/8', '10.9.9.9'), true);
  assert.equal(cidrContainsIp('10.0.0.0/8', '11.0.0.1'), false);
  const merged = mergeCidrs(['10.0.0.0/24', '10.0.1.0/24']).map((entry) => entry.canonical);
  assert.deepEqual(merged, ['10.0.0.0/23']);
  assert.equal(isPrivateIp('192.168.1.1'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
});

test('scope normalization and deny precedence', () => {
  const domain = normalizeScopeEntry({ type: 'domain', value: '*.ACME.test.' });
  assert.equal(domain.canonical, 'acme.test');
  const scope = {
    allow: [normalizeScopeEntry({ type: 'domain', value: 'acme.test' })],
    deny: [normalizeScopeEntry({ type: 'host', value: 'secret.acme.test' })],
  };
  assert.equal(evaluateScope(scope, { type: 'host', host: 'www.acme.test' }).allowed, true);
  const denied = evaluateScope(scope, { type: 'host', host: 'secret.acme.test' });
  assert.equal(denied.allowed, false);
  assert.match(denied.reason, /denied/);
  const out = evaluateScope(scope, { type: 'host', host: 'other.test', ips: ['203.0.113.5'] });
  assert.equal(out.allowed, false);
  assert.equal(scopeSummary(scope).allowCount, 1);
});

test('pentest mode labels are stored as intrusive', () => {
  assert.equal(normalizeEngagementMode('authorized-pentest'), 'intrusive');
  assert.equal(normalizeEngagementMode('Validate'), 'validate');
  assert.equal(normalizeEngagementMode('read-only'), 'view');
  assert.equal(normalizeEngagementMode('recon'), 'collect');
  assert.throws(() => normalizeEngagementMode('somewhere-else'), /mode must be one of/);
});

test('a more specific allow outranks a parent-domain deny', () => {
  const scope = {
    allow: [normalizeScopeEntry({ type: 'host', value: 'app.example.test' })],
    deny: [normalizeScopeEntry({ type: 'domain', value: '*.example.test' })],
  };
  assert.equal(evaluateScope(scope, { type: 'host', host: 'app.example.test' }).allowed, true);
  assert.equal(evaluateScope(scope, { type: 'host', host: 'other.example.test' }).allowed, false);
});

test('an explicit deny replacement clears a previous deny entry', () => {
  let state = emptyState();
  state = applyOps(state, [{
    op: 'scope.set',
    allow: [normalizeScopeEntry({ type: 'host', value: 'app.example.test' })],
    deny: [normalizeScopeEntry({ type: 'domain', value: 'example.test' })],
  }], AT);
  assert.equal(state.scope.deny.length, 1);
  state = applyOps(state, [{ op: 'scope.set', deny: [], replaceDeny: true }], AT);
  assert.deepEqual(state.scope.deny, []);
  assert.equal(state.scope.allow.length, 1);
});

test('scope ports accept numbers, lists, names and ranges', () => {
  assert.deepEqual(normalizeScopeEntry({ type: 'host', value: 'app.example.test', ports: '80, 443' }).ports, [80, 443]);
  assert.deepEqual(normalizeScopeEntry({ type: 'host', value: 'app.example.test', ports: 443 }).ports, [443]);
  assert.deepEqual(normalizeScopeEntry({ type: 'host', value: 'app.example.test', ports: ['80', 'https'] }).ports, [80, 443]);
  assert.deepEqual(normalizeScopeEntry({ type: 'host', value: 'app.example.test', ports: '80-82' }).ports, [80, 81, 82]);
  assert.equal(normalizeScopeEntry({ type: 'host', value: 'app.example.test', ports: 'any' }).ports, undefined);
  assert.equal(normalizeScopeEntry({ type: 'host', value: 'app.example.test', ports: [] }).ports, undefined);
  assert.equal(normalizeScopeEntry({ type: 'hostname', value: 'app.example.test:443' }).canonical, 'app.example.test');
  assert.equal(normalizeScopeEntry({ type: 'hostname', value: 'app.example.test:443' }).ports, undefined);
  assert.throws(() => normalizeScopeEntry({ type: 'host', value: 'app.example.test', ports: 'nope' }), /invalid scope port/);
});

test('scope port restriction is enforced', () => {
  const scope = { allow: [normalizeScopeEntry({ type: 'host', value: 'a.test', ports: [443] })], deny: [] };
  assert.equal(evaluateScope(scope, { type: 'host', host: 'a.test', port: 443 }).allowed, true);
  assert.equal(evaluateScope(scope, { type: 'host', host: 'a.test', port: 80 }).allowed, false);
});

test('applyOps merges nodes and keeps first/last seen', () => {
  let state = emptyState();
  state = applyOps(state, [nodeOp('host', 'a.test', 'a.test', { fqdn: 'a.test', ips: ['1.2.3.4'] }, { tags: ['x'] })], AT);
  state = applyOps(state, [nodeOp('host', 'a.test', 'A test', { fqdn: 'a.test', ips: ['1.2.3.5'] }, { tags: ['y'], confidence: 0.9 })], '2026-10-31T01:00:00.000Z');
  assert.equal(state.seq, 2);
  const node = state.nodes[nodeId('host', 'a.test')];
  assert.equal(node.label, 'a.test');
  assert.deepEqual(node.tags, ['x', 'y']);
  assert.deepEqual(node.attrs.ips, ['1.2.3.4', '1.2.3.5']);
  assert.equal(node.firstSeen, AT);
  assert.equal(node.lastSeen, '2026-10-31T01:00:00.000Z');
});

test('edge endpoint ordering creates stubs instead of dangling edges', () => {
  let state = emptyState();
  state = applyOps(state, [edgeOp({ kind: 'host', key: 'missing.test' }, { kind: 'ip', key: '10.0.0.9' }, 'resolves_to')], AT);
  assert.equal(Object.keys(state.edges).length, 1);
  assert.equal(Object.keys(state.nodes).length, 2);
  assert.equal(state.stats.stubNodes, 2);
});

test('an edge that names an existing finding id does not create a second finding', () => {
  let state = emptyState();
  state = applyOps(state, [
    nodeOp('host', 'app.example', 'app.example', { fqdn: 'app.example' }),
    nodeOp('finding', 'engagement/app.example/login.action/xss-reflected/medium', '反射型 XSS', { title: '反射型 XSS', template: 'xss' }),
  ], AT);
  const finding = Object.values(state.nodes).find((node) => node.kind === 'finding');
  state = applyOps(state, [
    edgeOp({ kind: 'finding', key: finding.id }, { kind: 'host', key: 'app.example' }, 'affects'),
  ], AT);
  const findings = Object.values(state.nodes).filter((node) => node.kind === 'finding');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].label, '反射型 XSS');
  assert.equal(state.stats.stubNodes ?? 0, 0);
});

test('node.merge aliases the old id and repoints edges', () => {
  let state = seededState();
  const oldId = nodeId('host', 'www.acme.test');
  const newId = nodeId('host', 'www.acme.test.canonical');
  state = applyOps(state, [
    nodeOp('host', 'www.acme.test.canonical', 'www.acme.test', { fqdn: 'www.acme.test' }),
    { op: 'node.merge', from: { kind: 'host', key: 'www.acme.test' }, into: { kind: 'host', key: 'www.acme.test.canonical' }, reason: 'test' },
  ], AT);
  assert.equal(state.aliases[oldId], newId);
  assert.ok(Object.values(state.edges).every((edge) => edge.from !== oldId && edge.to !== oldId));
});

test('no-op ops return the same state reference', () => {
  const state = emptyState();
  assert.equal(applyOps(state, [], AT), state);
  assert.equal(applyOps(state, [{ op: 'unknown' }], AT), state);
});

test('wire view counts, trims and redacts secrets', () => {
  let state = seededState();
  for (let index = 0; index < 60; index += 1) {
    state = applyOps(state, [
      nodeOp('host', `asset-${index}.acme.test`, `asset-${index}.acme.test`, { fqdn: `asset-${index}.acme.test`, ips: ['10.1.2.3'] }),
      edgeOp({ kind: 'host', key: `asset-${index}.acme.test` }, { kind: 'ip', key: '10.1.2.3' }, 'resolves_to'),
    ], AT);
  }
  state = applyOps(state, [
    nodeOp('credential', 'acme/external/admin/abc', 'admin credential', {
      username: 'admin', kind: 'password', realm: 'external', secret: 'SuperSecret!', secretMask: '******', secretFp: 'abc', validity: 'valid',
    }, { status: 'valid' }),
  ], AT);
  const view = buildView(state, { viewNodeLimit: 50, viewEdgeLimit: 10 });
  assert.equal(view.seq, state.seq);
  assert.ok(view.nodes.length <= 50);
  assert.equal(view.truncated.nodes, true);
  const credential = view.nodes.find((node) => node.kind === 'credential');
  if (credential !== undefined) {
    assert.equal(credential.attrs.secret, undefined);
    assert.equal(credential.attrs.secretMask, '******');
  }
  assert.equal(view.counts.byKind.finding >= 1, true);
  assert.ok(Array.isArray(view.frontier));
  assert.equal(graphSummary(state).counts.nodes, Object.keys(state.nodes).length);
});

test('frontier starts with scope and then proposes enumeration', () => {
  let state = emptyState();
  let actions = computeFrontier(state, { limit: 5 });
  assert.equal(actions[0].actionType, 'set_scope');
  state = seededState();
  actions = computeFrontier(state, { limit: 50 });
  assert.ok(actions.some((action) => action.actionType === 'enumerate_services' || action.actionType === 'collect_data_evidence'));
  assert.ok(actions.every((action) => typeof action.priority === 'number'));
});

test('crown path reaches a privileged target from a foothold', () => {
  let state = seededState();
  state = applyOps(state, [
    nodeOp('host', 'dc.acme.test', 'dc.acme.test', { fqdn: 'dc.acme.test', realm: 'internal', crownJewel: true, criticality: 4 }),
    edgeOp({ kind: 'access', key: 'acme/www.acme.test/shell/user' }, { kind: 'host', key: 'dc.acme.test' }, 'pivots_to', { confidence: 0.8 }),
  ], AT);
  const paths = computeCrownPaths(state, { limit: 3 });
  assert.ok(paths.length >= 1);
  assert.ok(paths[0].nodes.length >= 1);
});

test('redaction masks email, phone, PAN and secret keys', () => {
  assert.match(maskEmail('alice@example.com'), /^a\*\*\*e@example\.com$/u);
  assert.equal(maskPhone('13812345678'), '***5678');
  assert.equal(maskPan('4111 1111 1111 1234'), '****1234');
  const redacted = redactRow({ email: 'alice@example.com', card: '4111 1111 1111 1234', password: 'hunter2' }, { salt: 'acme' });
  assert.ok(!JSON.stringify(redacted.masked).includes('hunter2'));
  assert.equal(redacted.classes.password, 'credentials');
  const attrs = publicAttrs('credential', { username: 'admin', secret: 'x', secretMask: '***', secretFp: 'f' });
  assert.equal(attrs.secret, undefined);
  assert.equal(attrs.secretMask, '***');
});

test('config defaults and unknown key warnings', () => {
  const { config, warnings } = resolveConfig({ maxNodes: 10, unknownKey: true });
  assert.equal(config.maxNodes, 10);
  assert.equal(config.viewNodeLimit, 2500);
  assert.ok(warnings.some((warning) => warning.includes('unknownKey')));
  assert.equal(config.requireScope, true);
});

test('the graph picture keeps the approved host and folds the rest', () => {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'scope.set', allow: [{ type: 'host', value: 'app.example.test', canonical: 'app.example.test' }], deny: [] },
    nodeOp('host', 'app.example.test', 'app.example.test', { fqdn: 'app.example.test' }),
    nodeOp('host', 'prototype.copy', 'prototype.copy', { fqdn: 'prototype.copy' }),
    nodeOp('host', 'cdn.example.net', 'cdn.example.net', { fqdn: 'cdn.example.net' }),
    nodeOp('domain', 'example.test', 'example.test', { domain: 'example.test' }),
    nodeOp('domain', 'example.net', 'example.net', { domain: 'example.net' }),
    nodeOp('webapp', 'https://app.example.test/', 'https://app.example.test/', { url: 'https://app.example.test/', host: 'app.example.test', path: '/' }),
    nodeOp('webapp', 'https://app.example.test/word/1', 'word 1', { url: 'https://app.example.test/word/1', host: 'app.example.test', path: '/word/1' }),
    nodeOp('webapp', 'https://cdn.example.net/lib.js', 'lib', { url: 'https://cdn.example.net/lib.js', host: 'cdn.example.net', path: '/lib.js' }),
    nodeOp('ip', '203.0.113.5', '203.0.113.5', { addr: '203.0.113.5' }),
    edgeOp({ kind: 'host', key: 'app.example.test' }, { kind: 'ip', key: '203.0.113.5' }, 'resolves_to'),
  ], '2026-11-01T00:00:00.000Z');
  const view = buildView(state, {});
  const hosts = view.nodes.filter((node) => node.kind === 'host').map((node) => node.key);
  assert.deepEqual(hosts, ['app.example.test']);
  assert.equal(view.coverage.assets, 2);
  assert.equal(view.nodes.filter((node) => node.kind === 'webapp').length, 1);
  assert.equal(view.nodes.some((node) => node.kind === 'domain' && node.key === 'example.net'), false);
  assert.equal(view.nodes.some((node) => node.kind === 'domain' && node.key === 'example.test'), true);
  assert.equal(graphSummary(state).counts.nodes > view.counts.nodes, true);
});

test('canonicalIp accepts mapped IPv6 and canonical IPv4', () => {
  assert.equal(canonicalIp('10.0.0.1'), '10.0.0.1');
  assert.equal(canonicalIp('::ffff:10.0.0.1'), '::ffff:a00:1');
});

test('CIDR parser forces host bits to zero', () => {
  assert.equal(parseCidr('10.0.0.7/24')?.canonical, '10.0.0.0/24');
});
