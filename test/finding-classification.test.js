/** Finding classification: vulnerability class + CVSS severity are separate. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { blendOperational, classifyFindingCvss, explainCvss, findingMergeKey, harmBand, isIncludedVulnerabilityNode, isVulnerabilityNode, pathsWithFinding } from '../lib/finding-classification.js';

test('agent severity labels do not make an unscored finding a vulnerability', () => {
  const finding = { kind: 'finding', attrs: { severity: 'critical', redteamRating: 'critical' } };
  const result = classifyFindingCvss(finding.attrs);
  assert.equal(result.score, null);
  assert.equal(result.severity, 'unscored');
  assert.equal(result.vulnerability, false);
  assert.equal(isVulnerabilityNode(finding), false);
});

test('medium/low exposure signals are findings, not vulnerabilities', () => {
  assert.equal(classifyFindingCvss({ cvssScore: 5.3, cvssSeverity: 'MEDIUM', title: 'Missing security headers' }).vulnerability, false);
  assert.equal(classifyFindingCvss({ cvssScore: 6.1, cvssSeverity: 'MEDIUM', title: 'Expired TLS certificate' }).vulnerability, false);
  assert.equal(classifyFindingCvss({ cvssScore: 3.1, cvssSeverity: 'LOW' }).vulnerability, false);
});

test('medium XSS remains a vulnerability because CVSS is only severity', () => {
  const xss = classifyFindingCvss({ cvssScore: 6.1, cvssSeverity: 'MEDIUM', template: 'xss', title: 'Reflected XSS on login' });
  assert.equal(xss.severity, 'medium');
  assert.equal(xss.vulnerability, true);
  assert.equal(isVulnerabilityNode({ kind: 'finding', attrs: { cvssScore: 6.1, cvssSeverity: 'MEDIUM', title: '反射型 XSS' } }), true);
});

test('secondary verification shows a below-7 configuration or error finding', () => {
  const stack = { kind: 'finding', attrs: { cvssScore: 5.3, cvssSeverity: 'MEDIUM', title: 'production stack trace', secondaryVerified: true, secondaryVerdict: 'verified' } };
  const policy = { kind: 'finding', attrs: { cvssScore: 3.7, cvssSeverity: 'LOW', title: 'dynamic method invocation left open', secondaryVerdict: 'verified' } };
  assert.equal(classifyFindingCvss(stack.attrs).vulnerability, false);
  assert.equal(isIncludedVulnerabilityNode(stack), true);
  assert.equal(isIncludedVulnerabilityNode(policy), true);
  assert.equal(isIncludedVulnerabilityNode({ kind: 'finding', attrs: { ...stack.attrs, secondaryVerified: false, secondaryVerdict: 'refuted' } }), false);
  assert.equal(isIncludedVulnerabilityNode({ kind: 'finding', attrs: { cvssScore: 5.3, title: 'Missing security headers' } }), false);
  assert.equal(isIncludedVulnerabilityNode({
    kind: 'finding',
    attrs: { title: '缺少安全响应头', secondaryVerified: true, secondaryVerdict: 'verified' },
  }), false);
  assert.equal(isIncludedVulnerabilityNode({
    kind: 'finding',
    attrs: {
      template: 'permissive-crossdomain-policy',
      title: '宽松的 crossdomain.xml',
      secondaryVerified: true,
      secondaryVerdict: 'verified',
      cvssScore: 4.7,
      cvssSeverity: 'MEDIUM',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N',
    },
  }), false);
  const blended = blendOperational({
    template: 'permissive-crossdomain-policy',
    title: '宽松的 crossdomain.xml',
    cvssScore: 4.7,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N',
  });
  assert.equal(blended.red.rating, 'info');
  assert.equal(blended.severity, 'low');
  assert.ok(blended.score < 4);
});

test('reflected XSS is capped at medium and stored XSS may stay high', () => {
  const reflected = classifyFindingCvss({
    cvssScore: 8.2,
    cvssSeverity: 'HIGH',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N',
    title: '反射型 XSS',
  });
  assert.equal(reflected.score, 6.1);
  assert.equal(reflected.severity, 'medium');
  assert.equal(reflected.vulnerability, true);
  const negated = blendOperational({
    title: '反射型 XSS',
    impact: '属反射型（非存储型）XSS，需受害者点击构造好的链接',
    cvssScore: 6.1,
    cvssSeverity: 'MEDIUM',
  });
  assert.equal(negated.red.rating, 'medium');
  assert.equal(negated.severity, 'medium');
  assert.equal(reflected.capped, true);
  assert.match(explainCvss({ title: '反射型 XSS', cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N' }, reflected), /反射型 XSS/);
  assert.match(explainCvss({ title: '反射型 XSS', cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N' }, reflected), /AV:N/);
  const stored = classifyFindingCvss({ cvssScore: 8.2, cvssSeverity: 'HIGH', title: '存储型 XSS' });
  assert.equal(stored.score, 8.2);
  assert.equal(stored.severity, 'high');
});

test('the same interface and vulnerability type share one finding key', () => {
  const first = findingMergeKey('eng', { subjectKey: 'app.example', title: '反射型 XSS on /login.action', endpoint: '/login.action' });
  const second = findingMergeKey('eng', { subjectKey: 'app.example', title: 'reflected XSS attribute on /login.action', path: '/login.action' });
  assert.equal(first, second);
  const otherPath = findingMergeKey('eng', { subjectKey: 'app.example', title: '反射型 XSS', endpoint: '/share.action' });
  assert.notEqual(first, otherPath);
  const escalated = findingMergeKey('eng', { subjectKey: 'app.example', title: '反射型 XSS 命令执行', endpoint: '/login.action' });
  assert.notEqual(first, escalated);
  assert.equal(harmBand({ title: '反射型 XSS', cvssScore: 6.1 }), 'medium');
  assert.equal(harmBand({ title: '反射型 XSS 命令执行', endpoint: '/login.action' }), 'exec');
  const nodes = [
    { kind: 'finding', attrs: { title: '反射型 XSS', endpoint: '/login.action' } },
    { kind: 'finding', attrs: { title: '反射型 XSS', endpoint: '/share.action' } },
  ];
  assert.deepEqual([...pathsWithFinding(nodes, 'xss')], ['/login.action', '/share.action']);
});

test('CVSS high/critical count as vulnerabilities, including vector-only findings', () => {
  assert.equal(classifyFindingCvss({ cvssScore: 7.0, cvssSeverity: 'HIGH' }).vulnerability, true);
  assert.equal(classifyFindingCvss({ cvssScore: 9.8, cvssSeverity: 'CRITICAL' }).vulnerability, true);
  const vectorOnly = classifyFindingCvss({ cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' });
  assert.equal(vectorOnly.score, 9.8);
  assert.equal(vectorOnly.vulnerability, true);
});
