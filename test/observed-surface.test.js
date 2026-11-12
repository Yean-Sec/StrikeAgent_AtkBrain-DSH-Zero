/** Observed links, sibling paths, headers and foothold follow-ups. Synthetic fixtures only. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { endpointInventory, artifactSiblingPaths, directoryPaths, surfaceLedger } from '../lib/endpoint-vocab.js';
import { seedCoverage } from '../lib/coverage.js';
import { classifyExposure } from '../lib/exposure.js';
import { headerProductVersions, isHardeningFinding, isIncludedVulnerabilityNode } from '../lib/finding-classification.js';
import { recordedHeaderFindings } from '../lib/exposure.js';
import { computeFrontier } from '../lib/frontier.js';

test('a same-origin link without a fixed extension becomes an interface and four coverage cells', () => {
  const page = `
    <a href="/area/gate/">gate</a>
    <a href="area/other/?q=1">other</a>
    <a href="/assets/app.css">style</a>
    <a href="javascript:void(0)">skip</a>
  `;
  const inventory = endpointInventory(page);
  assert.ok(inventory.endpoints.includes('area/gate'));
  assert.ok(inventory.endpoints.includes('area/other'));
  assert.equal(inventory.endpoints.includes('assets/app.css'), false);
  const ledger = surfaceLedger(page);
  assert.ok(ledger.endpoints.includes('/area/gate'));
  const cells = seedCoverage(['/area/gate']);
  assert.equal(cells.length, 4);
});

test('every recorded file grows the same suffixes and every directory is revisited', () => {
  assert.ok(artifactSiblingPaths(['/app/view.php']).includes('/app/view.php.bak'));
  assert.ok(artifactSiblingPaths(['/app/view.php']).includes('/app/view.php~'));
  assert.deepEqual(directoryPaths(['/area/gate', '/app/view.php', '/']), ['/area/gate']);
  const source = classifyExposure('/app/view.php.bak', {
    status: 200,
    headers: { 'content-type': 'text/plain' },
    body: '<?php\n$keep = 1;\n',
  });
  assert.ok(source.some((finding) => finding.template === 'exposed-source-sibling'));
  const page = classifyExposure('/app/view.php.bak', {
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '<html><title>home</title></html>',
  });
  assert.equal(page.some((finding) => finding.template === 'exposed-source-sibling'), false);
  const listed = classifyExposure('/area/gate', {
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '<html><title>Index of /area/gate</title><a href="run.php">run.php</a></html>',
  });
  assert.ok(listed.some((finding) => finding.template === 'directory-listing'));
  assert.ok(listed.some((finding) => finding.template === 'served-executable'));
  assert.equal(isHardeningFinding({ template: 'directory-listing', title: '目录列表启用' }), true);
  assert.equal(isHardeningFinding({ template: 'served-executable', title: '列出的文件会被当作代码执行' }), false);
});

test('response headers become a versioned tech fact and a low cookie finding, not a header vulnerability', () => {
  const versions = headerProductVersions({ server: 'Example/1.2.3', 'x-powered-by': 'Widget/4.5' });
  assert.deepEqual(versions.map((item) => item.label), ['Example 1.2.3', 'Widget 4.5']);
  const findings = recordedHeaderFindings({
    server: 'Example/1.2.3',
    'set-cookie': 'sid=abc; Path=/',
  }, { https: true, status: 200 });
  const headers = findings.find((finding) => finding.template === 'missing-security-headers');
  const cookie = findings.find((finding) => finding.template === 'session-cookie-flags');
  assert.ok(headers);
  assert.ok(cookie);
  assert.equal(isHardeningFinding(headers), true);
  assert.equal(isIncludedVulnerabilityNode({ kind: 'finding', attrs: headers }), false);
  assert.equal(isHardeningFinding(cookie), false);
  assert.match(cookie.evidence, /HttpOnly/u);
  assert.match(cookie.evidence, /Secure/u);
  assert.equal(cookie.evidence.includes('abc'), false);
});

test('validated access and recorded materials schedule owner, data and unauthenticated revisits', () => {
  const state = applyOps(emptyState(), [
    { op: 'engagement.set', engagement: { name: 'surface', authorization: 'AUTH' } },
    { op: 'scope.set', allow: [{ type: 'domain', value: 'app.example', canonical: 'app.example' }], deny: [] },
    nodeOp('webapp', 'http://app.example/', 'http://app.example/', {
      url: 'http://app.example/',
      host: 'app.example',
      endpoints: ['/app/view.php', '/area/gate'],
      parameterMap: { '/enter': ['username', 'password'] },
      headers: { 'set-cookie': 'sid=abc; Path=/' },
    }),
    nodeOp('tech', 'observed/Example/1.2.3', 'Example 1.2.3', { product: 'Example', version: '1.2.3' }),
    nodeOp('access', 'access/app', 'process', { privilege: 'user' }, { status: 'validated' }),
    nodeOp('credential', 'cred/app', 'store', { username: 'app' }, { status: 'validated' }),
    nodeOp('coverage', 'cov/nday', '/app/view.php × nday', { path: '/app/view.php', bugClass: 'nday' }, { status: 'open' }),
  ]);
  const frontier = computeFrontier(state, { limit: 80 });
  const types = frontier.map((action) => action.actionType);
  assert.ok(types.includes('probe_sibling'));
  assert.ok(types.includes('revisit_directory'));
  assert.ok(types.includes('check_session_rotation'));
  assert.ok(types.includes('compare_process_owner'));
  assert.ok(types.includes('record_data_sample'));
  const sibling = frontier.find((action) => action.actionType === 'probe_sibling');
  assert.match(sibling.params.url, /\/app\/view\.php\.bak$/u);
  const directory = frontier.find((action) => action.actionType === 'revisit_directory');
  assert.match(directory.params.url, /\/area\/gate$/u);
  const follow = frontier.find((action) => action.actionType === 'follow_stack');
  assert.equal(follow.params.query, 'Example 1.2.3');
});
