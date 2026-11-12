/**
 * HTML report renderer and report-theme selection tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { detectReportTheme } from '../lib/theme.js';
import { renderHtmlReport, suggestedHtmlReportName } from '../lib/report-html.js';

function fixture() {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'Acme Lab', authorization: 'SOW-REPORT-1', window: '2026-10-01..2026-10-31', mode: 'internal' } },
    { op: 'scope.set', allow: [{ type: 'cidr', value: '10.0.0.0/24' }], deny: [] },
    nodeOp('host', '10.0.0.5', 'portal.acme.test', { fqdn: 'portal.acme.test', addr: '10.0.0.5' }, { status: 'up' }),
    nodeOp('service', '10.0.0.5:443', 'https/443', { port: 443, service: 'https' }, { status: 'open' }),
    nodeOp('finding', 'acme/xss', 'Reflected XSS in search', {
      title: 'Reflected XSS in search', severity: 'high', template: 'xss', subjectLabel: 'portal.acme.test',
      impact: 'A reflected script can execute in the victim browser context.',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', secondaryVerified: true,
    }, { status: 'verified', verification: 'verified' }),
    nodeOp('access', 'acme/shell', 'user shell on portal', {
      kind: 'user_shell', privilege: 'user', assetKey: '10.0.0.5', proof: 'nonce canary',
    }, { status: 'validated', verification: 'verified' }),
    nodeOp('data', 'acme/pii', 'customer records', {
      dataClass: 'pii', count: 640, thresholdMet: true, samples: [{ fields: ['email'], masked: { email: 'u***@x' } }],
    }, { status: 'verified', verification: 'verified' }),
    nodeOp('credential', 'acme/cred', 'stored credential', { username: 'operator', secretMask: 'p***s', secretFp: 'fp1234', validity: 'valid' }, { status: 'valid' }),
  ], '2026-10-31T00:00:00.000Z');
  return state;
}

test('dark HTML report uses the template style and fills pentest content', async () => {
  const html = await renderHtmlReport(fixture(), { generatedAt: '2026-10-31T10:00:00.000Z', theme: 'dark' });
  assert.match(html, /^<!doctype html>/i);
  assert.ok(html.includes('atk-report--dark'));
  assert.ok(html.includes('反射型 XSS（search）'));
  assert.ok(html.includes('Acme Lab'));
  assert.ok(html.includes('执行摘要'));
  assert.ok(html.includes('发现清单总表'));
  assert.ok(html.includes('关键攻击路径'));
  assert.ok(!html.includes('atk-report-light-override'));
  assert.ok(!html.includes('P@ssw0rd'));
});

test('light HTML report keeps layout and adds only a palette override', async () => {
  const html = await renderHtmlReport(fixture(), { generatedAt: '2026-10-31T10:00:00.000Z', theme: 'light' });
  assert.ok(html.includes('atk-report--light'));
  assert.ok(html.includes('atk-report-light-override'));
  assert.ok(html.includes('#faf6f1'));
  assert.ok(html.includes('#ef4444'));
  assert.ok(!html.includes('atk-report-banner'));
  assert.ok(html.includes('执行摘要'));
  assert.ok(html.includes('反射型 XSS（search）'));
  const dark = await renderHtmlReport(fixture(), { generatedAt: '2026-10-31T10:00:00.000Z', theme: 'dark' });
  const sectionHeadings = (value) => [...value.matchAll(/<section class="sec" id="([^"]+)"/g)].map((match) => match[1]).join(',');
  assert.equal(sectionHeadings(html), sectionHeadings(dark), 'light must preserve template section layout');
});

test('report theme auto reads the DSH ui-theme preference', async () => {
  const ctx = { get: () => ({ describe: async () => [{ ns: 'ui-theme', value: { preference: 'dark' } }] }) };
  const resolved = await detectReportTheme({ ctx, config: { reportTheme: 'auto' }, explicit: 'auto' });
  assert.equal(resolved.theme, 'dark');
  assert.equal(resolved.source, 'ui-theme');
  const forced = await detectReportTheme({ ctx, config: { reportTheme: 'auto' }, explicit: 'light' });
  assert.equal(forced.theme, 'light');
  assert.equal(forced.source, 'argument');
});

test('suggested HTML report name is safe and deterministic', () => {
  assert.equal(suggestedHtmlReportName({ name: 'Acme Lab / 2026' }, '2026-10-31T10:00:00.000Z'), 'atkbrain-report-Acme-Lab-2026-2026-10-31.html');
});
