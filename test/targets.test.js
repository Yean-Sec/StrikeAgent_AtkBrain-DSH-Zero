/** Cluster / target coverage tree. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { buildTargetTree, concreteAllowTargets, targetIdentity } from '../lib/targets.js';

function fixture() {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'Cluster Lab', authorization: 'SOW-CLUSTER-1', mode: 'external' } },
    { op: 'scope.set', allow: [{ type: 'domain', value: 'example.test' }], deny: [] },
    nodeOp('host', 'www.example.test', 'www.example.test', { fqdn: 'www.example.test' }, { status: 'unknown' }),
    nodeOp('host', 'api.example.test', 'api.example.test', { fqdn: 'api.example.test' }, { status: 'unknown' }),
    nodeOp('service', 'www.example.test:443', 'https/443', { port: 443, endpoint: 'www.example.test:443' }, { status: 'open' }),
    nodeOp('service', 'api.example.test:443', 'https/443', { port: 443, endpoint: 'api.example.test:443' }, { status: 'open' }),
    nodeOp('finding', 'cluster/xss', '反射型 XSS', { title: '反射型 XSS', severity: 'medium', cvssScore: 6.1, cvssSeverity: 'MEDIUM' }, { status: 'verified', verification: 'verified' }),
    nodeOp('coverage', 'cluster/coverage', '/search × xss', { path: '/search', bugClass: 'xss', targetKey: 'www.example.test' }, { status: 'seen' }),
    { op: 'edge.upsert', from: { kind: 'host', key: 'www.example.test' }, to: { kind: 'service', key: 'www.example.test:443' }, kind: 'exposes' },
    { op: 'edge.upsert', from: { kind: 'service', key: 'www.example.test:443' }, to: { kind: 'finding', key: 'cluster/xss' }, kind: 'affects' },
  ], '2026-10-31T00:00:00.000Z');
  return state;
}

test('target tree nests hosts under clusters and classifies recon/tested', () => {
  const tree = buildTargetTree(fixture());
  assert.equal(tree.totals.clusters, 1);
  assert.equal(tree.totals.targets, 2);
  assert.equal(tree.totals.recon, 1);
  assert.equal(tree.totals.tested, 1);
  assert.equal(tree.totals.coverageSeen, 1);
  const cluster = tree.clusters[0];
  assert.equal(cluster.label, 'example.test');
  const www = cluster.targets.find((target) => target.label === 'www.example.test');
  const api = cluster.targets.find((target) => target.label === 'api.example.test');
  assert.equal(www.status, 'tested');
  assert.equal(www.findings, 1);
  assert.equal(www.vulnerabilities, 1);
  assert.equal(www.coverageSeen, 1);
  assert.equal(api.status, 'recon');
});

test('resolved IPs are infrastructure unless explicitly authorized', () => {
  let state = fixture();
  state = applyOps(state, [
    nodeOp('ip', '203.0.113.9', '203.0.113.9', { addr: '203.0.113.9' }, { status: 'unknown' }),
    { op: 'edge.upsert', from: { kind: 'host', key: 'www.example.test' }, to: { kind: 'ip', key: '203.0.113.9' }, kind: 'resolves_to' },
  ], '2026-10-31T00:00:01.000Z');
  const tree = buildTargetTree(state);
  assert.equal(tree.totals.targets, 2);
  const scoped = applyOps(state, [
    { op: 'scope.set', allow: [{ type: 'domain', value: 'example.test' }, { type: 'ip', value: '203.0.113.9' }], deny: [] },
  ], '2026-10-31T00:00:02.000Z');
  assert.equal(buildTargetTree(scoped).totals.targets, 3);
});

test('same IP or same first-level subdomain is one target across ports', () => {
  assert.equal(targetIdentity('https://a.bac.com:8003/app').key, targetIdentity('a.bac.com').key);
  assert.equal(targetIdentity('api.a.bac.com').host, 'a.bac.com');
  assert.equal(targetIdentity('b.bac.com').host, 'b.bac.com');
  assert.notEqual(targetIdentity('a.bac.com').key, targetIdentity('b.bac.com').key);
  assert.notEqual(targetIdentity('bac.com').key, targetIdentity('a.bac.com').key);
  assert.equal(targetIdentity('192.0.2.1:8443').key, targetIdentity('192.0.2.1').key);
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'group', authorization: 'AUTH' } },
    {
      op: 'scope.set',
      allow: [
        { type: 'url', value: 'https://a.bac.com' },
        { type: 'url', value: 'https://a.bac.com:8003' },
        { type: 'host', value: 'b.bac.com' },
        { type: 'ip', value: '192.0.2.1', ports: [80] },
        { type: 'url', value: 'https://192.0.2.1:8443' },
      ],
      deny: [],
    },
  ], '2026-10-31T00:00:00.000Z');
  const tracks = concreteAllowTargets(state);
  assert.deepEqual(tracks.map((track) => track.canonical).sort(), ['192.0.2.1', 'a.bac.com', 'b.bac.com']);
  const grouped = Object.fromEntries(tracks.map((track) => [track.canonical, track]));
  assert.equal(grouped['a.bac.com'].type, 'domain');
  assert.deepEqual(grouped['a.bac.com'].ports, [8003]);
  assert.deepEqual(grouped['192.0.2.1'].ports, [80, 8443]);
});
