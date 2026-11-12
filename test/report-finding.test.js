/** Single-finding report must not call a Medium finding a vulnerability. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { renderFindingHtmlReport } from '../lib/report-finding.js';

function finding(attrs) {
  return {
    id: 'finding:medium-xss',
    kind: 'finding',
    key: 'finding/medium-xss',
    label: 'Reflected XSS on login',
    status: 'verified',
    verification: 'verified',
    confidence: 1,
    evidenceIds: [],
    attrs: {
      title: 'Reflected XSS on login',
      severity: 'medium',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
      cvssScore: 6.1,
      cvssSeverity: 'MEDIUM',
      redteamRating: 'medium',
      secondaryVerified: true,
      secondaryVerdict: 'verified',
      description: '登录回调参数 succLoginRedirect 未做输出编码，响应中原样反射攻击者可控脚本。',
      impact: '可诱导已登录用户在页面上下文执行脚本；当前证据未证明账户接管。',
      remediation: '对 succLoginRedirect 做服务端白名单校验并输出编码，同时启用 CSP。',
      request: 'GET /login.action?succLoginRedirect=marker HTTP/1.1',
      response: '<svg/onload=marker>',
      ...attrs,
    },
  };
}

test('Medium XSS report still uses vulnerability wording (CVSS is severity only)', async () => {
  const state = { nodes: { 'finding:medium-xss': finding() }, engagement: { name: 'report-it' } };
  const html = await renderFindingHtmlReport(state, 'finding:medium-xss', { theme: 'light' });
  assert.match(html, /单漏洞报告/u);
  assert.match(html, /① 漏洞简介与影响/u);
  assert.match(html, /6\.1 MEDIUM/u);
  assert.match(html, /登录回调参数 succLoginRedirect/u);
  assert.doesNotMatch(html, /单发现报告/u);
  assert.doesNotMatch(html, /非漏洞/u);
});

test('High finding report keeps vulnerability wording', async () => {
  const high = finding({
    severity: 'high',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvssScore: 9.8,
    cvssSeverity: 'CRITICAL',
    redteamRating: 'critical',
  });
  high.id = 'finding:high-rce';
  high.key = 'finding/high-rce';
  high.label = 'Remote command execution';
  high.attrs.title = 'Remote command execution';
  const html = await renderFindingHtmlReport({ nodes: { 'finding:high-rce': high }, engagement: { name: 'report-it' } }, 'finding:high-rce', { theme: 'light' });
  assert.match(html, /单漏洞报告/u);
  assert.match(html, /① 漏洞简介与影响/u);
  assert.match(html, /漏洞/u);
});

test('Exposure finding report uses security finding wording', async () => {
  const exposure = {
    id: 'finding:tls',
    kind: 'finding',
    key: 'finding/tls',
    label: 'Expired TLS certificate',
    status: 'verified',
    verification: 'verified',
    confidence: 1,
    evidenceIds: [],
    attrs: {
      title: 'Expired TLS certificate',
      template: 'expired-certificate',
      severity: 'medium',
      cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
      cvssScore: 4.2,
      cvssSeverity: 'MEDIUM',
      redteamRating: 'medium',
      secondaryVerified: true,
      secondaryVerdict: 'verified',
      description: '证书已于指定时间过期，客户端会拒绝或需要用户忽略警告。',
      impact: '可被中间人利用，但当前证据未证明实际接管。',
      remediation: '续期证书并监控到期时间。',
    },
  };
  const html = await renderFindingHtmlReport({ nodes: { 'finding:tls': exposure }, engagement: { name: 'report-it' } }, 'finding:tls', { theme: 'light' });
  assert.match(html, /单发现报告/u);
  assert.match(html, /安全发现/u);
  assert.doesNotMatch(html, /单漏洞报告/u);
});
