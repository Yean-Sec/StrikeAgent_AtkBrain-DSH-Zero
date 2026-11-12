/** Coverage board tests: path normalization, lifecycle gates and matrix views. */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  BUG_CLASSES,
  COVERAGE_STATUSES,
  checkCoverage,
  coverageKey,
  coverageDutyViolation,
  coverageNoteText,
  coverageSummary,
  noteCoverage,
  normalizeInterfacePath,
  resolveReportedFinding,
  seedCoverage,
} from '../lib/coverage.js';

test('BUG_CLASSES and statuses are the four board classes and five statuses', () => {
  assert.deepEqual([...BUG_CLASSES], ['xss', 'sqli', 'authz', 'leak']);
  assert.deepEqual([...COVERAGE_STATUSES], ['open', 'claimed', 'seen', 'refuted', 'reported']);
  assert.equal(Object.isFrozen(BUG_CLASSES), true);
  assert.equal(Object.isFrozen(COVERAGE_STATUSES), true);
});

test('normalizeInterfacePath extracts and lowercases only the path', () => {
  assert.equal(normalizeInterfacePath('https://Example.COM/App/Login.Action?User=1#frag'), '/app/login.action');
  assert.equal(normalizeInterfacePath('//HOST/API/V1/Users/'), '/api/v1/users');
  assert.equal(normalizeInterfacePath('/App/Login'), '/app/login');
  assert.equal(normalizeInterfacePath('/App/Login?x=1'), '/app/login');
  assert.equal(normalizeInterfacePath('/App/Login#x'), '/app/login');
  assert.equal(normalizeInterfacePath('App/Login'), '/app/login');
  assert.equal(normalizeInterfacePath('app.example/Login'), '/login');
  assert.equal(normalizeInterfacePath('http:app.example:443/app/detail.action?x=1'), '/app/detail.action');
  assert.equal(normalizeInterfacePath('https://host'), '/');
  assert.equal(normalizeInterfacePath('/'), '/');
  assert.equal(normalizeInterfacePath('?x=1'), '/');
});

test('normalizeInterfacePath rejects non-paths and unsafe shapes', () => {
  const bad = ['', '   ', null, 42, {}, '#frag', 'mailto:user@example.com', 'javascript:alert(1)', '/a/../b', '/foo bar', '/foo"bar', '/$secret', '/{id}', 'C:/Windows/System32', 'http://'];
  for (const input of bad) {
    assert.equal(normalizeInterfacePath(input), '', JSON.stringify(input));
  }
});

test('normalizeInterfacePath strips query, fragment, jsessionid and trailing slash', () => {
  assert.equal(normalizeInterfacePath('/app/x;jsessionid=ABC123?q=1'), '/app/x');
  assert.equal(normalizeInterfacePath('/app/x/'), '/app/x');
  assert.equal(normalizeInterfacePath('/APP/X?q=1#frag'), '/app/x');
  assert.equal(normalizeInterfacePath('/app/./x'), '/app/x');
  assert.equal(normalizeInterfacePath('http:///path'), '');
});

test('normalizeInterfacePath is idempotent', () => {
  const once = normalizeInterfacePath('HTTPS://Host/A/B/?x=1');
  assert.equal(normalizeInterfacePath(once), once);
});

test('coverageKey canonicalizes path and class and rejects bad classes', () => {
  assert.equal(coverageKey('/App/Login?x=1', 'XSS'), '/app/login#xss');
  assert.equal(coverageKey('https://host/api/users', 'sqli'), '/api/users#sqli');
  assert.equal(coverageKey('', 'xss'), '');
  assert.throws(() => coverageKey('/login', 'nope'), /bugClass/);
});

test('seedCoverage creates a complete open row per path', () => {
  const cells = seedCoverage('/App/Login?x=1');
  assert.equal(cells.length, BUG_CLASSES.length);
  assert.deepEqual(cells.map((cell) => cell.bugClass), [...BUG_CLASSES]);
  for (const cell of cells) {
    assert.deepEqual(Object.keys(cell).sort(), ['bugClass', 'duty', 'dutyRole', 'key', 'path', 'role', 'status']);
    assert.equal(cell.key, `${cell.path}#${cell.bugClass}`);
    assert.equal(cell.path, '/app/login');
    assert.equal(cell.status, 'open');
    assert.equal(cell.role, 'web-exploit');
  }
});

test('seedCoverage dedupes, sorts, honors role and caps paths', () => {
  const cells = seedCoverage(['/b', '/A', '/a', 'https://host/b'], { role: 'web-exploit-2', limit: 1 });
  assert.equal(cells.length, BUG_CLASSES.length);
  assert.ok(cells.every((cell) => cell.path === '/a'));
  assert.ok(cells.every((cell) => cell.role === 'web-exploit-2'));

  const two = seedCoverage(['/b', '/a'], { limit: 2 });
  assert.equal(two.length, BUG_CLASSES.length * 2);
  assert.deepEqual([...new Set(two.map((cell) => cell.path))], ['/a', '/b']);

  assert.deepEqual(seedCoverage('/static/app.css'), []);
  assert.deepEqual(seedCoverage('/a/../b'), []);
  assert.deepEqual(seedCoverage(''), []);
  assert.equal(seedCoverage('/').length, BUG_CLASSES.length);
  assert.deepEqual(seedCoverage(['/a', '/b'], { limit: 0 }), []);
  assert.throws(() => seedCoverage('/a', { limit: -1 }), /limit/);
});

test('seedCoverage does not mutate its input array', () => {
  const input = ['/b', '/a', '/a'];
  const before = [...input];
  seedCoverage(input, { limit: 1 });
  assert.deepEqual(input, before);
});

test('noteCoverage validates claimed/open and copies input', () => {
  const input = { path: '/App/Login', bugClass: 'xss', status: 'claimed', channels: ['status'] };
  const cell = noteCoverage(input);
  assert.equal(cell.path, '/app/login');
  assert.equal(cell.bugClass, 'xss');
  assert.equal(cell.status, 'claimed');
  assert.equal(cell.role, 'web-exploit');
  assert.deepEqual(cell.channels, ['status']);
  assert.equal(input.path, '/App/Login');
  assert.notEqual(cell.channels, input.channels);

  const reset = noteCoverage({
    path: '/login',
    bugClass: 'xss',
    status: 'open',
    channels: ['status', 'body'],
    evidenceIds: ['ev_1'],
    note: 'x',
    findingId: 'fnd_1',
  });
  assert.deepEqual(reset.channels, []);
  assert.deepEqual(reset.evidenceIds, []);
  assert.equal(reset.note, null);
  assert.equal(reset.findingId, null);
});

test('noteCoverage seen requires two distinct channels or evidence', () => {
  assert.equal(noteCoverage({ path: '/login', bugClass: 'xss', status: 'seen', channels: ['status', 'body'] }).status, 'seen');
  assert.equal(noteCoverage({ path: '/login', bugClass: 'xss', status: 'seen', channels: ['status', 'status', 'body'] }).channels.length, 2);
  assert.equal(noteCoverage({ path: '/login', bugClass: 'xss', status: 'seen', channels: ['status'], evidenceIds: ['ev_1'] }).evidenceIds[0], 'ev_1');
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'seen', channels: ['status'] }), />=2 distinct channels/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'seen' }), />=2 distinct channels/);
});

test('noteCoverage refuted requires the exact path and a concrete note', () => {
  const specific = noteCoverage({
    path: '/login',
    bugClass: 'xss',
    status: 'refuted',
    note: '/login 参数 q 在 3 个 payload 下均返回 200 且无反射',
  });
  assert.equal(specific.status, 'refuted');
  assert.match(specific.note, /payload/);

  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'refuted', note: '全部404' }), /generic close/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'refuted', note: '/login 全部404' }), /generic close/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'refuted', note: '/login 面关闭' }), /generic close/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'refuted', note: '/login 无差异' }), /generic close/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'refuted', note: '/other 返回 200' }), /must name the exact path/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'refuted', note: '/login 测试过' }), /concrete observation/);

  const withoutRepeatingPath = noteCoverage({
    path: '/login',
    bugClass: 'xss',
    status: 'refuted',
    note: '参数 q 在 3 个 payload 下均返回 200 且无反射',
  });
  assert.equal(withoutRepeatingPath.status, 'refuted');

  const withEvidence = noteCoverage({ path: '/login', bugClass: 'xss', status: 'refuted', note: '/login 全部404', evidenceIds: ['ev_404'] });
  assert.equal(withEvidence.status, 'refuted');

  const concreteChannel = noteCoverage({ path: '/login', bugClass: 'xss', status: 'refuted', note: '/login 参数 q 返回 403 且无差异' });
  assert.equal(concreteChannel.status, 'refuted');
});

test('a reported cell accepts the finding id written in the note', () => {
  const findings = [{ id: 'finding_1', key: 'finding-sqli-app', attrs: { path: '/vulnerabilities/sqli' } }];
  assert.equal(resolveReportedFinding({
    status: 'reported',
    path: '/vulnerabilities/sqli',
    note: 'UNION returns a row. Finding finding-sqli-app.',
  }, findings), 'finding_1');
  assert.equal(resolveReportedFinding({
    status: 'reported',
    path: '/vulnerabilities/sqli',
    note: 'UNION returns a row',
  }, findings), 'finding_1');
  assert.equal(noteCoverage({
    path: '/vulnerabilities/sqli',
    bugClass: 'sqli',
    status: 'reported',
    findingId: 'finding_1',
  }).findingId, 'finding_1');
});

test('class duties reject JSON-only XSS, upload-absent file reads, and version-less known-vuln closes', () => {
  const seeded = seedCoverage('/login');
  assert.equal(seeded.find((cell) => cell.bugClass === 'xss').dutyRole, 'cov-xss');
  assert.match(seeded.find((cell) => cell.bugClass === 'leak').duty, /信息泄露/);
  assert.throws(
    () => noteCoverage({ path: '/ajaxsearch/simsearch.action', bugClass: 'xss', status: 'refuted', note: '/ajaxsearch/simsearch.action JSON 回显不可执行' }),
    /JSON reflection does not close cov-xss/,
  );
  assert.equal(noteCoverage({
    path: '/worddetail/jia',
    bugClass: 'xss',
    status: 'refuted',
    note: '/worddetail/jia 输入落在事件属性，响应体无脚本闭合，状态码 200',
  }).status, 'refuted');
  assert.throws(
    () => noteCoverage({ path: '/export', bugClass: 'file', status: 'refuted', note: '/export 没有上传' }),
    /bugClass/,
  );
  assert.throws(
    () => noteCoverage({ path: '/login', bugClass: 'nday', status: 'refuted', note: '/login nuclei 公开漏洞无命中，状态码 404' }),
    /bugClass/,
  );
});

test('noteCoverage reported requires findingId', () => {
  const cell = noteCoverage({ path: '/login', bugClass: 'sqli', status: 'reported', findingId: 'fnd_1' });
  assert.equal(cell.findingId, 'fnd_1');
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'sqli', status: 'reported' }), /findingId/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'sqli', status: 'reported', findingId: '' }), /findingId/);
});

test('noteCoverage rejects malformed input', () => {
  assert.throws(() => noteCoverage(null), /object/);
  assert.throws(() => noteCoverage({ path: '', bugClass: 'xss', status: 'open' }), /path/);
  assert.throws(() => noteCoverage({ path: '/static/app.css', bugClass: 'xss', status: 'open' }), /static asset/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'nope', status: 'open' }), /bugClass/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'nope' }), /status/);
  assert.throws(() => noteCoverage({ path: '/login', bugClass: 'xss', status: 'seen', channels: [1, 2] }), /strings/);
  assert.equal(noteCoverage({ path: '/login', kind: 'sqli', status: 'claimed' }).bugClass, 'sqli');
});

test('coverageSummary folds duplicates and counts final states', () => {
  const cells = [
    ...seedCoverage(['/a', '/b'], { limit: 2 }),
    noteCoverage({ path: '/a', bugClass: 'xss', status: 'seen', channels: ['status', 'body'] }),
    noteCoverage({ path: '/a', bugClass: 'sqli', status: 'refuted', note: '/a 参数 id 返回 403 且无布尔差异' }),
    noteCoverage({ path: '/a', bugClass: 'leak', status: 'reported', findingId: 'fnd_1' }),
    noteCoverage({ path: '/b', bugClass: 'xss', status: 'claimed' }),
  ];
  const summary = coverageSummary(cells);

  assert.equal(summary.total, 8);
  assert.equal(summary.paths, 2);
  assert.equal(summary.open, 4);
  assert.equal(summary.claimed, 1);
  assert.equal(summary.seen, 1);
  assert.equal(summary.refuted, 1);
  assert.equal(summary.reported, 1);
  assert.equal(summary.unresolved, 5);
  assert.equal(summary.complete, false);
  assert.equal(summary.byBugClass.xss.total, 2);
  assert.equal(summary.byBugClass.xss.seen, 1);
  assert.equal(summary.byBugClass.xss.claimed, 1);
  assert.deepEqual(Object.keys(summary.byBugClass), [...BUG_CLASSES]);
  assert.deepEqual(summary.byStatus, { open: 4, claimed: 1, seen: 1, refuted: 1, reported: 1 });
});

test('coverageSummary last-write-wins and handles invalid cells', () => {
  const open = noteCoverage({ path: '/a', bugClass: 'xss', status: 'open' });
  const seen = noteCoverage({ path: '/a', bugClass: 'xss', status: 'seen', channels: ['status', 'body'] });
  const summary = coverageSummary([open, seen]);
  assert.equal(summary.total, 1);
  assert.equal(summary.seen, 1);
  assert.equal(summary.open, 0);

  const dirty = coverageSummary([
    null,
    { path: '/a', bugClass: 'nope', status: 'open' },
    { path: '/a', bugClass: 'xss', status: 'open' },
  ]);
  assert.equal(dirty.total, 1);
  assert.equal(dirty.invalid, 2);

  const empty = coverageSummary([]);
  assert.equal(empty.total, 0);
  assert.equal(empty.open, 0);
  assert.equal(empty.complete, false);
});

test('coverageSummary complete requires no open and no claimed cells', () => {
  const cells = seedCoverage('/a');
  const seen = cells.map((cell) => (
    cell.bugClass === 'xss'
      ? noteCoverage({ ...cell, status: 'seen', channels: ['status', 'body'] })
      : noteCoverage({ ...cell, status: 'refuted', note: `/a ${cell.bugClass} 参数返回 403 且响应体无反射` })
  ));
  const summary = coverageSummary(seen);
  assert.equal(summary.open, 0);
  assert.equal(summary.complete, true);

  const claimed = [...cells.slice(1), noteCoverage({ ...cells[0], status: 'claimed' })];
  assert.equal(coverageSummary(claimed).complete, false);
});

test('checkCoverage returns a four-class matrix for one path', () => {
  const cells = seedCoverage('/app/login');
  const empty = checkCoverage(cells, { path: '/APP/Login' });
  assert.equal(empty.found, true);
  assert.equal(empty.path, '/app/login');
  assert.deepEqual(empty.openClasses, [...BUG_CLASSES]);
  assert.ok(empty.open.every((entry) => entry.path === '/app/login'));
  assert.deepEqual(empty.matrix, Object.fromEntries(BUG_CLASSES.map((bugClass) => [bugClass, 'open'])));

  const seen = noteCoverage({ path: '/app/login', bugClass: 'xss', status: 'seen', channels: ['status', 'body'] });
  const refuted = noteCoverage({ path: '/app/login', bugClass: 'sqli', status: 'refuted', note: '/app/login id 参数返回 403 且响应体无反射' });
  const reported = noteCoverage({ path: '/app/login', bugClass: 'leak', status: 'reported', findingId: 'fnd_1' });
  const check = checkCoverage([...cells, seen, refuted, reported], { path: '/app/login' });

  assert.equal(check.found, true);
  assert.equal(check.matrix.xss, 'seen');
  assert.equal(check.matrix.sqli, 'refuted');
  assert.equal(check.matrix.leak, 'reported');
  assert.equal(check.matrix.authz, 'open');
  assert.deepEqual(check.openClasses, [...BUG_CLASSES].filter((bugClass) => !['xss', 'sqli', 'leak'].includes(bugClass)));
  assert.ok(check.openKeys.includes('/app/login#authz'));
  assert.equal(check.summary.total, BUG_CLASSES.length);
});

test('checkCoverage reports an unseeded path as entirely open', () => {
  const check = checkCoverage([], { path: '/missing' });
  assert.equal(check.found, false);
  assert.deepEqual(check.openClasses, [...BUG_CLASSES]);
  assert.deepEqual(check.matrix, Object.fromEntries(BUG_CLASSES.map((bugClass) => [bugClass, 'open'])));
});

test('checkCoverage builds the whole matrix when no path is given', () => {
  const cells = [
    ...seedCoverage(['/b', '/a'], { limit: 2 }),
    noteCoverage({ path: '/a', bugClass: 'xss', status: 'seen', channels: ['status', 'body'] }),
  ];
  const check = checkCoverage(cells);
  assert.deepEqual(check.paths, ['/a', '/b']);
  assert.equal(check.matrix['/a'].xss, 'seen');
  assert.equal(check.matrix['/b'].xss, 'open');
  assert.ok(check.open.some((entry) => entry.path === '/b' && entry.bugClass === 'xss'));
  assert.ok(!check.open.some((entry) => entry.path === '/a' && entry.bugClass === 'xss'));
  assert.ok(check.openKeys.includes('/b#xss'));
});

test('checkCoverage last-write-wins and is JSON serializable', () => {
  const seen = noteCoverage({ path: '/a', bugClass: 'xss', status: 'seen', channels: ['status', 'body'] });
  const claimed = noteCoverage({ path: '/a', bugClass: 'xss', status: 'claimed' });
  assert.equal(checkCoverage([seen, claimed], { path: '/a' }).matrix.xss, 'claimed');
  assert.doesNotThrow(() => JSON.stringify(checkCoverage([seen, claimed])));
  assert.throws(() => checkCoverage([], 'x'), /options/);
});

test('a stored parameter keeps xss open until the note names it', () => {
  const surface = { path: '/detail.action', parameters: ['searchKey'], contexts: ['inline-event-handler'] };
  assert.match(coverageDutyViolation('xss', '/detail.action marker was not reflected in the body', 'refuted', surface), /searchKey/);
  assert.match(coverageDutyViolation('xss', '/detail.action searchKey was not reflected in the inline event handler', 'refuted', surface), /encoded/);
  assert.equal(coverageDutyViolation('xss', '/detail.action searchKey was encoded in the inline event handler', 'refuted', surface), null);
});

test('a signed object URL does not refute file, and login logic needs a limit observation', () => {
  assert.match(coverageDutyViolation('file', '/download.action traversal returned 404', 'refuted', {
    path: '/download.action',
    siblingNote: '302 Location leaks a signed object URL',
  }), /cov-file stays open/);
  assert.match(coverageDutyViolation('logic', '/login.action has no state change', 'refuted', { path: '/login.action' }), /repeated failures/);
  assert.match(coverageDutyViolation('logic', '/login.action 20 failures, no lock and no captcha', 'refuted', { path: '/login.action' }), /do not refute/);
  assert.equal(coverageDutyViolation('logic', '/login.action 8 failures then HTTP 429 and a lockout; repeated failures are limited', 'refuted', { path: '/login.action' }), null);
});

test('a positive observation cannot be stored as a refutation', () => {
  assert.match(coverageDutyViolation('leak', '/err.action response includes a Java stack trace and the server version', 'refuted', { path: '/err.action' }), /do not refute/);
  assert.equal(coverageDutyViolation('leak', '/err.action generic 404 page, no stack and no version', 'refuted', { path: '/err.action' }), null);
  assert.match(coverageDutyViolation('xss', '/login.action redirectField reflected into the hidden attribute', 'refuted', {
    path: '/login.action',
    parameters: ['redirectField'],
  }), /do not refute/);
  assert.match(coverageDutyViolation('file', '/download.action the handler read the object body', 'refuted', { path: '/download.action' }), /cov-file stays open/);
  assert.match(coverageDutyViolation('xss', '/show.action without a token the response is the login form', 'refuted', {
    path: '/show.action',
    parameterMap: { '/login.action': ['userName', 'redirectField'] },
  }), /redirectField/);
  assert.equal(coverageDutyViolation('xss', '/show.action response is the login form; userName and redirectField were not reflected in the body', 'refuted', {
    path: '/show.action',
    parameterMap: { '/login.action': ['userName', 'redirectField'] },
  }), null);
});

test('a low engagement mode cannot refute an active class', () => {
  assert.match(coverageDutyViolation('xss', '/login.action q was not reflected in the body', 'refuted', {
    path: '/login.action',
    mode: 'validate',
    techniques: ['T0', 'T1', 'T2', 'T3'],
  }), /intrusive|T3/);
  assert.match(coverageDutyViolation('file', '/download.action path parameter returned 404 and was not reflected in the body', 'refuted', {
    path: '/download.action',
    techniques: ['T0', 'T1', 'T2'],
  }), /T3/);
  assert.equal(coverageDutyViolation('xss', '/login.action q was not reflected in the body', 'refuted', {
    path: '/login.action',
    mode: 'intrusive',
    techniques: ['T0', 'T1', 'T2', 'T3'],
  }), null);
  assert.equal(coverageDutyViolation('logic', '/login.action 8 failures then HTTP 429 and a lockout; repeated failures are limited', 'refuted', {
    path: '/login.action',
    mode: 'validate',
    techniques: ['T0', 'T1'],
  }), null);
});

test('coverage notes accept either note or reason', () => {
  assert.equal(coverageNoteText({ reason: 'method dispatch on this path' }), 'method dispatch on this path');
  assert.equal(coverageNoteText({ note: 'same', reason: 'same' }), 'same');
  assert.match(coverageNoteText({ note: 'public read', reason: 'method dispatch' }), /method dispatch/);
});

test('method dispatch keeps authz open and a homepage body does not close an xml path', () => {
  assert.match(coverageDutyViolation('authz', '/search.action is a public read', 'refuted', {
    path: '/search.action',
    siblingNote: 'NoSuchMethodException on dynamic method',
  }), /method dispatch/);
  assert.match(coverageDutyViolation('leak', '/crossdomain.xml body was the homepage', 'refuted', { path: '/crossdomain.xml' }), /homepage/);
});

test('file handlers, thin ledgers, authz and unnamed versions stay open', () => {
  assert.match(coverageDutyViolation('file', '/download returned 404', 'refuted', { path: '/download' }), /intended directory|escape was rejected/);
  assert.equal(coverageDutyViolation('file', '/download the read stayed in the intended directory', 'refuted', { path: '/download' }), null);
  assert.match(coverageDutyViolation('xss', '/item/1 q was not reflected', 'refuted', { path: '/item/1', ledgerThin: true }), /endpoint_vocab/);
  assert.match(coverageDutyViolation('xss', '/page q href was not reflected', 'refuted', {
    path: '/page',
    parameters: ['q'],
    contexts: ['href-attribute'],
  }), /encoded/);
  assert.equal(coverageDutyViolation('xss', '/page q href was encoded', 'refuted', {
    path: '/page',
    parameters: ['q'],
    contexts: ['href-attribute'],
  }), null);
  assert.match(coverageDutyViolation('authz', '/orders 没进去', 'refuted', { path: '/orders' }), /login wall/);
  assert.equal(coverageDutyViolation('authz', '/orders 未登录请求被拒绝 401', 'refuted', { path: '/orders' }), null);
  assert.match(coverageDutyViolation('nday', '/err no public issue', 'refuted', {
    path: '/err',
    unrecordedVersions: ['Tomcat 9.0.45'],
  }), /not a tech node/);
});

test('one 402 does not refute logic, authz, sqli, or file', () => {
  for (const bugClass of ['logic', 'authz', 'sqli', 'file']) {
    assert.match(coverageDutyViolation(bugClass, '/wallet returned 402', 'refuted', { path: '/wallet' }), /not a refutation/);
    assert.equal(coverageDutyViolation(bugClass, '/wallet returned 402, then an empty body with POST returned 200', 'refuted', { path: '/wallet' }), null);
  }
});

test('coverage helpers do not mutate cells', () => {
  const cells = seedCoverage(['/a', '/b'], { limit: 2 });
  const snapshot = JSON.stringify(cells);
  coverageSummary(cells);
  checkCoverage(cells);
  checkCoverage(cells, { path: '/a' });
  assert.equal(JSON.stringify(cells), snapshot);
});
