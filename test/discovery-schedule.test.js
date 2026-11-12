/** Probe catch-all pages stay off the graph, and open interfaces outrank exposure checks. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { classifyExposure, documentBaseline } from '../lib/exposure.js';
import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { computeFrontier } from '../lib/frontier.js';

const HOME = '<html><head><title>Shop</title></head><body>home</body></html>';

test('a homepage catch-all does not become a heap dump, backup, or admin finding', () => {
  const baseline = documentBaseline({ status: 200, title: 'Shop', body: HOME });
  const page = { status: 200, headers: { 'content-type': 'text/html' }, title: 'Shop', body: HOME };
  for (const path of ['/heapdump', '/backup.zip', '/config.php.bak', '/health', '/debug', '/admin', '/actuator']) {
    assert.deepEqual(classifyExposure(path, page, { baseline }), [], path);
  }
  const dump = classifyExposure('/heapdump', {
    status: 200,
    headers: { 'content-type': 'application/octet-stream' },
    body: 'JAVA PROFILE 1.0.2',
  }, { baseline });
  assert.ok(dump.some((finding) => finding.template === 'heapdump-exposed'));
  const htmlDump = classifyExposure('/heapdump', {
    status: 200,
    headers: { 'content-type': 'text/html' },
    body: '<html>not a dump</html>',
  });
  assert.equal(htmlDump.some((finding) => finding.template === 'heapdump-exposed'), false);
});

test('open interfaces stay ahead of exposure verification', () => {
  const exposure = [];
  for (let index = 0; index < 12; index += 1) {
    exposure.push(nodeOp('finding', `exposure/${index}`, `backup ${index}`, {
      template: 'backup-archive-exposed',
      title: `backup ${index}`,
      severity: 'high',
      source: 'plugin',
    }, { status: 'candidate', tags: ['exposure'] }));
  }
  const state = applyOps(emptyState(), [
    { op: 'engagement.set', engagement: { name: 'schedule', authorization: 'AUTH-1' } },
    { op: 'scope.set', allow: [{ type: 'host', value: 'app.example', canonical: 'app.example' }], deny: [] },
    nodeOp('webapp', 'https://app.example/', 'app', { url: 'https://app.example/', host: 'app.example' }),
    nodeOp('finding', 'sqli', 'SQL injection', {
      template: 'sqli',
      title: 'SQL injection',
      severity: 'high',
      secondaryVerified: true,
      cvssScore: 9.1,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      cvssSeverity: 'CRITICAL',
    }, { status: 'verified' }),
    nodeOp('coverage', 'cov/feedbacks/xss', '/api/feedbacks × xss', { path: '/api/feedbacks', bugClass: 'xss' }, { status: 'open' }),
    nodeOp('coverage', 'cov/products/sqli', '/api/products × sqli', { path: '/api/products', bugClass: 'sqli' }, { status: 'open' }),
    nodeOp('coverage', 'cov/feedbacks/sqli', '/api/feedbacks × sqli', { path: '/api/feedbacks', bugClass: 'sqli' }, { status: 'open' }),
    ...exposure,
  ]);
  const frontier = computeFrontier(state, { limit: 40 });
  const scheduled = frontier.filter((action) => String(action.why?.[0] ?? '').includes('this interface is next'));
  const paths = scheduled.map((action) => action.params.path);
  assert.ok(paths.includes('/api/feedbacks'));
  assert.ok(paths.includes('/api/products'));
  const exposureAt = frontier.findIndex((action) => action.exposure === true);
  const coverageAt = frontier.findIndex((action) => action.actionType === 'test_coverage' && String(action.why?.[0] ?? '').includes('this interface is next'));
  assert.ok(coverageAt >= 0);
  assert.ok(exposureAt < 0 || coverageAt < exposureAt);
  assert.equal(frontier.filter((action) => action.exposure === true).length <= 2, true);
});
