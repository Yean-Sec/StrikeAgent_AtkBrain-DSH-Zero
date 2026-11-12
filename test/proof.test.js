/** Proof/authenticity tests: proof gates, shell boundary, families and dedup. */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  NON_EXPLOIT,
  NON_EXPLOIT_CATEGORIES,
  PROOF_TYPES,
  categoryMinSeverity,
  channelCount,
  findingDedupKey,
  findingDedupKeys,
  harmBand,
  hasAuthenticityProof,
  interfacePathFrom,
  isNonExploitCategory,
  isRceClaim,
  issueFamily,
  shellIsContainerBound,
  validateFindingProof,
} from '../lib/proof.js';

test('proof and non-exploit vocabularies are exact', () => {
  assert.deepEqual([...PROOF_TYPES], ['poc_replay', 'write_txt', 'impact_extract']);
  assert.deepEqual([...NON_EXPLOIT_CATEGORIES], ['availability', 'dos', 'crash', 'error_handling', 'misconfig']);
  assert.equal(NON_EXPLOIT, NON_EXPLOIT_CATEGORIES);
  assert.equal(Object.isFrozen(PROOF_TYPES), true);
  assert.equal(isNonExploitCategory('DoS'), true);
  assert.equal(isNonExploitCategory('error-handling'), true);
  assert.equal(isNonExploitCategory('availability'), true);
  assert.equal(isNonExploitCategory('sqli'), false);
});

test('hasAuthenticityProof accepts evidence, PoC, artifacts and evidence ids', () => {
  assert.equal(hasAuthenticityProof(null), false);
  assert.equal(hasAuthenticityProof({}), false);
  assert.equal(hasAuthenticityProof({ proofType: 'poc_replay' }), false);
  assert.equal(hasAuthenticityProof({ evidence: '   ' }), false);
  assert.equal(hasAuthenticityProof({ evidence: 'GET /login -> 200' }), true);
  assert.equal(hasAuthenticityProof({ pocCurl: 'curl -s https://host/login' }), true);
  assert.equal(hasAuthenticityProof({ poc: { curl: 'curl -s https://host/login' } }), true);
  assert.equal(hasAuthenticityProof({ evidenceIds: ['ev_1'] }), true);
  assert.equal(hasAuthenticityProof({ artifacts: ['loot/proof.txt'] }), true);
  assert.equal(hasAuthenticityProof({ attrs: { evidence: 'from attrs' } }), true);
  assert.equal(hasAuthenticityProof({ poc: { type: 'poc_replay' } }), false);
  assert.equal(hasAuthenticityProof({ poc: { curl: 'curl -s https://host/login' } }), true);
  assert.equal(hasAuthenticityProof({ execution: { stdout: 'uid=0(root)' } }), true);
  assert.equal(hasAuthenticityProof({ execution: { type: 'shell' } }), false);
});

test('channelCount handles explicit, nested and observation-list channels', () => {
  assert.equal(channelCount({}), 0);
  assert.equal(channelCount({ channels: ['status', 'body', 'status'] }), 2);
  assert.equal(channelCount(['status', 'body']), 2);
  assert.equal(channelCount('timing'), 1);
  assert.equal(channelCount({ observations: [{ channel: 'status' }, { type: 'body' }, { channel: 'status' }] }), 2);
  assert.equal(channelCount({ observation: { status: 200, body: 'x', header: null } }), 2);
  assert.equal(channelCount({ verification: { channels: ['timing', 'side_effect'] } }), 2);
  assert.equal(channelCount({ channels: ['status'], observations: [{ channel: 'body' }] }), 2);
  assert.equal(channelCount(null), 0);
});

test('shellIsContainerBound respects container markers and negated escapes', () => {
  assert.equal(shellIsContainerBound('uid=0(root)\nPID1=systemd'), false);
  assert.equal(shellIsContainerBound('uid=0(root)\nPID1=s6-svscan\n沙箱内'), true);
  assert.equal(shellIsContainerBound('uid=0(root)\nPID1=s6-svscan\n沙箱\n尚未证明逃逸到宿主 PID1=cube-agent'), true);
  assert.equal(shellIsContainerBound('沙箱内 PID1=s6-svscan。逃出后 uid=0(root) PID1=cube-agent'), false);
  assert.equal(shellIsContainerBound(['沙箱', 'PID1=s6-svscan']), true);
  assert.equal(shellIsContainerBound('容器内\nPID1=systemd'), false);
  assert.equal(shellIsContainerBound('sandbox', 'PID1=init'), false);
  assert.equal(shellIsContainerBound('plain host, no markers'), false);
  assert.equal(shellIsContainerBound(''), false);
});

test('issueFamily collapses aliases and prefers title over category and evidence', () => {
  const cases = [
    ['xss', '', 'xss'],
    ['sqli', '登录 SQL 注入', 'sqli'],
    ['file_read', '接口异常堆栈泄露', 'info_disclosure'],
    ['unauth', '未授权调用', 'authz'],
    ['vuln', 'Host 尾点暴露管理台', 'vhost_bypass'],
    ['vuln', '登录无频率限制', 'rate_limit'],
    ['vuln', 'crossdomain.xml 策略', 'cors_policy'],
    ['vuln', '任意文件读取', 'file_read'],
    ['vuln', '文件包含', 'file_read'],
    ['vuln', '目录遍历', 'file_read'],
    ['vuln', '任意文件上传', 'file_upload'],
    ['vuln', '详细错误', 'info_disclosure'],
    ['vuln', '信息泄漏', 'info_disclosure'],
    ['vuln', '未授权访问', 'authz'],
    ['vuln', '命令执行', 'rce'],
    ['vuln', '远程代码执行', 'rce'],
    ['vuln', '反序列化', 'rce'],
    ['vuln', 'SSTI 模板注入', 'rce'],
    ['vuln', 'N-day 漏洞', 'nday'],
    ['vuln', 'CVE-2021-44228', 'nday'],
    ['vuln', '业务逻辑缺陷', 'business_logic'],
    ['vuln', 'SSRF', 'ssrf'],
    ['vuln', '弱口令', 'credential'],
  ];
  for (const [category, title, expected] of cases) {
    assert.equal(issueFamily(category, title), expected, `${category}/${title}`);
  }

  assert.equal(issueFamily('sqli', '', 'xss evidence'), 'sqli');
  assert.equal(issueFamily('', '', 'stack trace'), 'info_disclosure');
  assert.equal(issueFamily('custom'), 'custom');
  assert.equal(issueFamily(), 'vuln');
  assert.equal(issueFamily('deserialization'), 'rce');
  assert.equal(issueFamily('sql_injection'), 'sqli');
  assert.equal(issueFamily('n_day'), 'nday');
  assert.equal(issueFamily('information_disclosure'), 'info_disclosure');
  assert.equal(issueFamily('cmd'), 'rce');
  assert.equal(issueFamily('code'), 'rce');
  assert.equal(issueFamily('file'), 'file_read');
  assert.equal(issueFamily('leak'), 'info_disclosure');
  assert.equal(issueFamily('logic'), 'business_logic');
  assert.equal(issueFamily('nday'), 'nday');
  assert.equal(issueFamily('custom_rce'), 'rce');
  assert.equal(issueFamily('vuln', 'source code review'), 'vuln');
});

test('interfacePathFrom extracts the first real interface path', () => {
  assert.equal(interfacePathFrom('GET /App/Login?x=1 HTTP/1.1'), '/app/login');
  assert.equal(interfacePathFrom('https://Host/API/Users'), '/api/users');
  assert.equal(interfacePathFrom('//Host/API/Users'), '/api/users');
  assert.equal(interfacePathFrom('http:app.example:443/app/detail.action'), '/app/detail.action');
  assert.equal(interfacePathFrom('app.example:8443/API/Users'), '/api/users');
  assert.equal(interfacePathFrom('see /api/users and /api/admin'), '/api/users');
  assert.equal(interfacePathFrom('/api/v1/users.json'), '/api/v1/users.json');
  assert.equal(interfacePathFrom('https://host/'), '');
  assert.equal(interfacePathFrom('https://host'), '');
  assert.equal(interfacePathFrom('/static/app.css'), '');
  assert.equal(interfacePathFrom('/a/../b'), '');
  assert.equal(interfacePathFrom('/foo{id}'), '');
  assert.equal(interfacePathFrom('C:\\Windows\\System32'), '');
  assert.equal(interfacePathFrom(''), '');
  assert.equal(interfacePathFrom(null), '');
  assert.equal(interfacePathFrom({ proofUrl: 'https://host/API/Users' }), '/api/users');
  assert.equal(interfacePathFrom({ attrs: { proofUrl: 'https://host/API/Users' } }), '/api/users');
  assert.equal(interfacePathFrom({ title: 'SQLi at /login' }), '/login');
});

test('harmBand prefers a valid rating, then severity, then a numeric score', () => {
  assert.equal(harmBand('high'), 'high');
  assert.equal(harmBand('medium', 'low'), 'low');
  assert.equal(harmBand('critical', 'info'), 'info');
  assert.equal(harmBand('high', 'none'), 'high');
  assert.equal(harmBand('critical', 4.5), 'medium');
  assert.equal(harmBand('高危'), 'high');
  assert.equal(harmBand('严重'), 'critical');
  assert.equal(harmBand('中危'), 'medium');
  assert.equal(harmBand('低危'), 'low');
  assert.equal(harmBand('信息'), 'info');
  assert.equal(harmBand('c'), 'critical');
  assert.equal(harmBand('h'), 'high');
  assert.equal(harmBand('m'), 'medium');
  assert.equal(harmBand('l'), 'low');
  assert.equal(harmBand(9.8), 'critical');
  assert.equal(harmBand(7.5), 'high');
  assert.equal(harmBand(5), 'medium');
  assert.equal(harmBand(2), 'low');
  assert.equal(harmBand(0), 'info');
  assert.equal(harmBand('9.8'), 'critical');
  assert.equal(harmBand('unknown'), 'unset');
  assert.equal(harmBand(undefined, undefined), 'unset');
});

test('categoryMinSeverity returns floors and null for unknown categories', () => {
  const cases = {
    xss: 'medium',
    sqli: 'high',
    cmd: 'critical',
    code: 'critical',
    file: 'high',
    authz: 'high',
    logic: 'high',
    leak: 'medium',
    nday: 'high',
    info: 'info',
    rce: 'critical',
    command_injection: 'critical',
    file_read: 'high',
    idor: 'medium',
    ssrf: 'medium',
    business_logic: 'high',
    information_disclosure: 'medium',
  };
  for (const [category, expected] of Object.entries(cases)) {
    assert.equal(categoryMinSeverity(category), expected, category);
  }
  assert.equal(categoryMinSeverity('nope'), null);
  assert.equal(categoryMinSeverity(''), null);
  assert.equal(categoryMinSeverity('dos'), null);
  assert.equal(categoryMinSeverity({ category: 'sqli' }), 'high');
  assert.equal(categoryMinSeverity({ bugClass: 'cmd' }), 'critical');
  assert.equal(categoryMinSeverity('custom_rce'), 'critical');
  assert.equal(categoryMinSeverity('custom_file_inclusion'), 'high');
});

test('findingDedupKey collapses title-only changes on the same interface', () => {
  const login = { category: 'sqli', title: '登录 SQL 注入', proofUrl: 'https://App.Example/Login?id=1', severity: 'high' };
  const renamed = { category: 'sqli', title: '认证处注入', proofUrl: 'https://app.example/login', severity: 'high' };
  assert.equal(findingDedupKey(login), 'pc:app.example/login|sqli|high');
  assert.equal(findingDedupKey(login), findingDedupKey(renamed));

  const higher = { ...login, redteamRating: 'critical' };
  const otherHost = { ...login, proofUrl: 'https://other.example/login' };
  const otherFamily = { ...login, category: 'xss', title: '反射型 XSS' };
  assert.notEqual(findingDedupKey(login), findingDedupKey(higher));
  assert.notEqual(findingDedupKey(login), findingDedupKey(otherHost));
  assert.notEqual(findingDedupKey(login), findingDedupKey(otherFamily));
});

test('findingDedupKey handles host-only, pathless, harm and bugClass inputs', () => {
  assert.equal(findingDedupKey('/login'), 'pc:/login|vuln|unset');
  assert.equal(findingDedupKey({ category: 'xss', title: '反射型 XSS', severity: 'medium' }), 'pc:nopath|xss|medium');
  assert.equal(findingDedupKey({ category: 'xss', title: 'XSS', proofUrl: 'https://app.example', severity: 'medium' }), 'pc:app.example|xss|medium');
  assert.equal(
    findingDedupKey({ category: 'sqli', proofUrl: 'https://a.example/login', severity: 'critical', harm: 'low' }),
    'pc:a.example/login|sqli|low',
  );
  assert.equal(
    findingDedupKey({ category: 'vuln', bugClass: 'sqli', proofUrl: 'https://a.example/login', severity: 'high' }),
    'pc:a.example/login|sqli|high',
  );
  assert.equal(findingDedupKey(''), '');
  const mapped = findingDedupKey([
    { category: 'sqli', proofUrl: 'https://a.example/login', severity: 'high' },
    { category: 'xss', proofUrl: 'https://a.example/login', severity: 'medium' },
  ]);
  assert.deepEqual(mapped, ['pc:a.example/login|sqli|high', 'pc:a.example/login|xss|medium']);
});

test('findingDedupKeys adds page and vhost refinements', () => {
  const xss = findingDedupKeys({ category: 'xss', title: '登录页反射型 XSS', proofUrl: 'https://app.example/login.action', severity: 'medium' });
  assert.ok(xss.includes('pc:app.example/login.action|xss|medium'));
  assert.ok(xss.includes('pg:login|xss|medium'));

  const vhost = findingDedupKeys({ category: 'vhost_bypass', title: 'Host 尾点暴露管理台', proofUrl: 'https://app.example/manager/html', severity: 'medium' });
  assert.ok(vhost.includes('pc:app.example/manager/html|vhost_bypass|medium'));
  assert.ok(vhost.includes('vh:app.example|vhost_bypass|medium'));

  const shop = findingDedupKeys({ category: 'xss', title: 'showProducts XSS', proofUrl: 'https://app.example/shop!showProducts.action', severity: 'medium' });
  assert.ok(shop.includes('pg:shop|xss|medium'));
});

test('isRceClaim sees RCE categories and titles but not SQLi alone', () => {
  const yes = [
    { category: 'rce' },
    { category: 'command_injection' },
    { category: 'cmd' },
    { category: 'code' },
    { category: 'ssti' },
    { category: 'deserialization' },
    { category: 'sqli', title: '命令执行' },
    { category: 'file_upload', title: 'webshell upload' },
    'RCE',
    '远程代码执行',
    '命令注入',
    'custom_rce',
  ];
  for (const value of yes) {
    assert.equal(isRceClaim(value), true, JSON.stringify(value));
  }
  const no = [{ category: 'sqli' }, { category: 'xss' }, { category: 'sqli', title: 'source code review' }, 'SQL 注入', null, undefined, {}];
  for (const value of no) {
    assert.equal(isRceClaim(value), false, JSON.stringify(value));
  }
});

test('validateFindingProof rejects a non-object and a refuted finding', () => {
  assert.deepEqual(validateFindingProof(null), {
    ok: false,
    status: 'rejected',
    reason: 'finding must be an object',
    missing: ['finding'],
  });
  const refuted = validateFindingProof({ category: 'sqli', evidence: 'x', verification: 'refuted' });
  assert.equal(refuted.status, 'rejected');
  assert.match(refuted.reason, /refuted/);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', status: 'refuted' }).status, 'rejected');
});

test('validateFindingProof treats non-exploit categories as pending', () => {
  for (const category of NON_EXPLOIT_CATEGORIES) {
    assert.deepEqual(validateFindingProof({ category, evidence: 'crash observed' }), {
      ok: false,
      status: 'pending',
      reason: 'non-exploit category (availability/crash/misconfig) is not an exploited asset',
      missing: ['exploit_impact'],
    });
  }
});

test('validateFindingProof requires authenticity material', () => {
  assert.deepEqual(validateFindingProof({ category: 'sqli', severity: 'high' }), {
    ok: false,
    status: 'pending',
    reason: 'no authenticity proof: attach evidence, a PoC, or a proof artifact',
    missing: ['proof'],
  });
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'boolean diff' }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidenceIds: ['ev_1'] }).ok, true);
});

test('validateFindingProof checks proofType and its required material', () => {
  const invalid = validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'nope' });
  assert.equal(invalid.status, 'rejected');
  assert.deepEqual(invalid.missing, ['proofType']);

  const replay = validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'poc_replay' });
  assert.equal(replay.status, 'pending');
  assert.deepEqual(replay.missing, ['replay']);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'poc_replay', pocCurl: 'curl -s https://host/login' }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'GET /login -> 200', proofType: 'poc_replay' }).ok, true);

  const write = validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'write_txt' });
  assert.deepEqual(write.missing, ['canary', 'artifact']);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'write_txt', proofCanary: 'ATK123', proofUrl: 'https://host/atk.txt' }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'write_txt', proofCanary: 'ATK123', artifactPath: 'loot/atk.txt' }).ok, true);

  const impact = validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'impact_extract' });
  assert.deepEqual(impact.missing, ['impact_extract']);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'impact_extract', count: 100, samples: ['redacted'] }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'impact_extract', impact: { count: 10 } }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'impact_extract', count: 0 }).status, 'pending');

  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'POC_REPLAY', pocCurl: 'curl' }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'poc_replay', proofUrl: 'https://host/login' }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proof: { type: 'poc_replay', curl: 'curl' } }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'poc_replay', proofDetail: 'GET /login -> 200 with marker' }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'poc_replay', proofDetail: 'replayed twice with nonce ATK-7' }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'write_txt', proofCanary: 'ATK123', proofDetail: 'https://host/atk.txt' }).ok, true);
  assert.equal(validateFindingProof({ category: 'sqli', evidence: 'x', proofType: 'impact_extract', proofDetail: 'count 120 rows in users' }).ok, true);
});

test('validateFindingProof rejects unproven high/critical RCE claims', () => {
  const noEcho = validateFindingProof({ category: 'rce', severity: 'high', evidence: '/etc/passwd root:x:0:0' });
  assert.deepEqual(noEcho, {
    ok: false,
    status: 'rejected',
    reason: 'unproven RCE/command execution cannot be rated high or critical; attach an execution echo',
    missing: ['execution_echo'],
  });
  assert.equal(validateFindingProof({ category: 'rce', severity: 'high', evidence: 'version match only' }).status, 'rejected');
  assert.equal(validateFindingProof({ category: 'rce', severity: 'high', evidence: '未证明 RCE: version match only' }).status, 'rejected');
  assert.equal(validateFindingProof({ category: 'rce', severity: 'medium', evidence: '/etc/passwd root:x:0:0' }).status, 'rejected');
  assert.equal(validateFindingProof({ category: 'rce', severity: 'high', evidence: 'uid=0(root) gid=0(root)' }).ok, true);
  assert.equal(validateFindingProof({ category: 'rce', severity: 'high', evidence: 'whoami -> root' }).ok, true);
  assert.equal(validateFindingProof({ category: 'rce', severity: 'high', execution: { stdout: 'uid=0(root)' } }).ok, true);
});

test('validateFindingProof requires secondary review for high/critical when requested', () => {
  const pending = validateFindingProof(
    { category: 'sqli', severity: 'high', evidence: 'boolean diff 200/500' },
    { requireSecondaryForHigh: true },
  );
  assert.deepEqual(pending, {
    ok: false,
    status: 'pending',
    reason: 'high/critical finding requires independent secondary verification',
    missing: ['secondary_verification'],
  });

  const accepted = [
    { secondaryVerified: true },
    { secondaryStatus: 'verified' },
    { secondaryVerdict: 'verified' },
    { verifiedBy: 'verifier' },
    { secondaryEvidenceIds: ['ev_2'] },
    { secondary: { verified: true } },
    { secondaryReview: { status: 'verified' } },
    { verification: { secondary: true } },
    { verification: { mode: 'secondary' } },
  ];
  for (const extra of accepted) {
    const result = validateFindingProof(
      { category: 'sqli', severity: 'high', evidence: 'boolean diff 200/500', ...extra },
      { requireSecondaryForHigh: true },
    );
    assert.equal(result.ok, true, JSON.stringify(extra));
  }

  const low = validateFindingProof(
    { category: 'xss', severity: 'low', evidence: 'reflected marker' },
    { requireSecondaryForHigh: true },
  );
  assert.equal(low.ok, true);
});

test('validateFindingProof applies category floors before the secondary gate', () => {
  const rce = validateFindingProof(
    { category: 'cmd', severity: 'low', evidence: 'uid=0(root)' },
    { requireSecondaryForHigh: true },
  );
  assert.equal(rce.status, 'pending');
  assert.deepEqual(rce.missing, ['secondary_verification']);

  const accepted = validateFindingProof(
    { category: 'cmd', severity: 'low', evidence: 'uid=0(root)', secondaryVerified: true },
    { requireSecondaryForHigh: true },
  );
  assert.equal(accepted.ok, true);
});

test('validateFindingProof treats container-bound command output as a foothold', () => {
  const bound = validateFindingProof({
    category: 'rce',
    severity: 'high',
    evidence: 'uid=0(root)\nPID1=s6-svscan\n容器内',
  });
  assert.deepEqual(bound, {
    ok: false,
    status: 'pending',
    reason: 'shell evidence is container/sandbox-bound; prove an outer PID 1 or record a foothold',
    missing: ['outer_pid1'],
  });

  assert.equal(validateFindingProof({
    category: 'rce',
    severity: 'high',
    evidence: 'uid=0(root)\nPID1=systemd',
  }).ok, true);

  const access = validateFindingProof({
    category: 'authz',
    severity: 'high',
    evidence: '沙箱\nuid=0(root)',
    accessType: 'user_shell',
  });
  assert.equal(access.status, 'pending');
  assert.deepEqual(access.missing, ['outer_pid1']);

  const structured = validateFindingProof({
    category: 'rce',
    severity: 'high',
    execution: { stdout: 'uid=0(root)\nPID1=s6-svscan' },
  });
  assert.equal(structured.status, 'pending');
  assert.deepEqual(structured.missing, ['outer_pid1']);
});

test('validateFindingProof merges attrs and accepts nested verification', () => {
  assert.equal(validateFindingProof({ attrs: { category: 'sqli', severity: 'high', evidence: 'boolean diff' } }).ok, true);
  assert.equal(validateFindingProof({
    category: 'sqli',
    severity: 'high',
    evidence: 'boolean diff',
    verification: { secondary: true },
  }, { requireSecondaryForHigh: true }).ok, true);
});

test('validateFindingProof returns exactly the documented result shape', () => {
  const result = validateFindingProof({ category: 'sqli', evidence: 'x' });
  assert.deepEqual(Object.keys(result).sort(), ['missing', 'ok', 'reason', 'status']);
  assert.equal(typeof result.ok, 'boolean');
  assert.equal(typeof result.reason, 'string');
  assert.ok(Array.isArray(result.missing));
  assert.equal(result.ok, true);
});

test('proof helpers do not mutate their finding', () => {
  const finding = {
    category: 'rce',
    severity: 'high',
    evidence: 'uid=0(root)',
    channels: ['status'],
  };
  const snapshot = JSON.stringify(finding);
  validateFindingProof(finding, { requireSecondaryForHigh: false });
  channelCount(finding);
  hasAuthenticityProof(finding);
  isRceClaim(finding);
  assert.equal(JSON.stringify(finding), snapshot);
});

test('dedup and proof agree on the same interface and finding', () => {
  const first = {
    category: 'sqli',
    title: '登录 SQL 注入',
    proofUrl: 'https://app.example/login',
    severity: 'high',
    evidence: 'boolean diff 200/500',
  };
  const renamed = {
    ...first,
    title: '认证处注入',
  };
  assert.equal(findingDedupKey(first), findingDedupKey(renamed));
  assert.equal(validateFindingProof(first).ok, true);
});
