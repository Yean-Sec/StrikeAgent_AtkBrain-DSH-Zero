/**
 * Cross-engagement evolution-memory tests.
 *
 * Covers lesson sanitisation (host/secret scrubbing, alias canonicalisation,
 * chain generalisation, stable keys), tactic/cue mapping, chain generalisation,
 * evolution qualification, episode/lesson distillation, the append-only JSONL
 * store and cross-engagement retrieval.
 *
 * Everything is offline: graphs are plain objects and stores live in mkdtemp
 * directories that are removed after each test.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { appendFile, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';

import {
  CUE_TOKENS,
  STACK_TOKENS,
  TACTIC_ALIASES,
  TACTICS,
  appendEpisode,
  appendLessonRecords,
  buildEpisode,
  confidenceFor,
  cueForFinding,
  deterministicLessons,
  episodeStorePath,
  foldLessonRecords,
  formatLessonBlock,
  generalizeChainFromIds,
  graphSignals,
  graphStackTokens,
  lessonConsumesEvidence,
  lessonKeyFor,
  markLessonUsed,
  mergeLesson,
  parseEvolveLessons,
  qualifiesForEvolution,
  readLessonRecords,
  readLessons,
  reinforceLesson,
  resolveLessonStore,
  retrieveLessons,
  sanitizeLesson,
  scoreLesson,
  stackTokensOf,
  tacticForFinding,
  winningChain,
  writeLessonSnapshot,
} from '../lib/loop/memory.js';

const AT = '2026-01-01T00:00:00.000Z';
const CHAIN = 'entry → service(http) → vuln(weaponize)';

/* ------------------------------------------------------------------ helpers */

function graphNode(id, kind, key, status = 'observed', attrs = {}, extra = {}) {
  if (kind === 'finding' && attrs.cvssScore === undefined && ['high', 'critical'].includes(String(attrs.severity ?? '').toLowerCase())) {
    attrs = { ...attrs, cvssScore: attrs.severity === 'critical' ? 9.8 : 8.1, cvssSeverity: attrs.severity === 'critical' ? 'CRITICAL' : 'HIGH' };
  }
  return {
    id,
    kind,
    key,
    label: attrs.label ?? key,
    status,
    attrs,
    evidenceIds: [],
    firstSeen: AT,
    lastSeen: AT,
    ...extra,
  };
}

function graphEdge(from, to, kind = 'contains') {
  return { id: `e_${from}_${to}`, from, to, kind, confidence: 0.9 };
}

/** Plain graph-state object: {nodes:{id:node}, edges:{}, scope, engagement}. */
function graphState({
  nodes = [],
  edges = [],
  engagement = { name: 'acme-prod', authorization: 'AUTH-EVOLVE-1' },
} = {}) {
  return {
    nodes: Object.fromEntries(nodes.map((entry) => [entry.id, entry])),
    edges: Object.fromEntries(edges.map((entry) => [entry.id, entry])),
    scope: {
      allow: [{ type: 'host', value: '203.0.113.9', canonical: '203.0.113.9', note: 'authorized test host' }],
      deny: [],
    },
    engagement,
  };
}

/** Sanitised lesson draft used by the scoring/retrieval/store tests. */
function lessonDraft(overrides = {}) {
  return sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, ...overrides });
}

function approx(actual, expected, epsilon = 1e-9, label = 'value') {
  const value = Number(actual);
  assert.ok(
    Math.abs(value - expected) <= epsilon,
    `${label}: expected ~${expected}, got ${value}`,
  );
}

/** Isolated JSONL store inside a throw-away directory. */
async function tempStore(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-evolve-'));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  return { dir, store: path.join(dir, 'lessons.jsonl') };
}

/** Graph with a verified high finding, a webapp stack and a refuted intent. */
function sampleFindingState() {
  const state = graphState({
    nodes: [
      graphNode('h1', 'host', '203.0.113.9', 'alive', { fqdn: 'portal.example.test', realm: 'external' }),
      graphNode(
        'w1',
        'webapp',
        'https://203.0.113.9:8443/',
        'fingerprinted',
        { server: 'nginx/1.24.0' },
        { tags: ['php', 'mysql'] },
      ),
      graphNode('f1', 'finding', 'upload-exec', 'verified', {
        template: 'rce',
        category: 'rce',
        severity: 'critical',
        secondaryVerified: true,
        title: 'Upload endpoint writes executable content',
        label: 'Unrestricted upload reaches the web root',
      }),
      graphNode('i1', 'intent', 'intent-1', 'refuted', { actionType: 'verify_sqli' }),
    ],
  });
  state.nodes.f1.evidenceIds = ['ev_1'];
  return state;
}

/* ===================================================== sanitizeLesson ===== */

test('sanitizeLesson strips hosts, URLs, paths, ports, emails and secrets from tokens and chains', () => {
  const lesson = sanitizeLesson({
    when: [
      '10.0.0.5',
      '2001:db8::1',
      'https://10.0.0.5/.env',
      '/etc/passwd',
      'admin@example.com',
      'password=hunter2',
      '8080',
      'php',
      'debug_endpoint',
    ],
    do: ['rce', 'https://10.0.0.5/.env'],
    chain: 'entry:8080 → 10.0.0.5 → /etc/passwd → service(http) → vuln(weaponize)',
  });
  assert.notEqual(lesson, null);
  assert.deepEqual(lesson.when, ['php', 'debug_endpoint']);
  assert.deepEqual(lesson.do, ['weaponize']);
  assert.equal(lesson.chain, 'service(http) → vuln(weaponize)');
  const encoded = JSON.stringify(lesson);
  for (const banned of ['10.0.0.5', '2001:db8', '/etc/passwd', 'admin@example.com', 'hunter2', ':8080', 'https://']) {
    assert.equal(encoded.includes(banned), false, `${banned} leaked into the lesson`);
  }
});

test('sanitizeLesson rejects drafts that only carry engagement or host identifiers', () => {
  assert.equal(
    sanitizeLesson({
      when: ['acme-prod-engagement'],
      do: ['acme-prod'],
      avoid: ['ACME-PROD'],
      chain: 'acme-prod',
    }),
    null,
  );
  assert.equal(sanitizeLesson({ when: ['acme-prod'], do: ['acme-prod'] }), null);
});

test('sanitizeLesson keeps only stack/cue tokens in when and canonical tactics in do/avoid', () => {
  const lesson = sanitizeLesson({
    when: ['PHP', 'web', 'weaponize', 'auth_surface', 'debug_endpoint'],
    do: ['php', 'rce', 'unauth', 'lfi', 'command_injection', 'idor', 'ssrf', 'xxe', 'sqli'],
    avoid: ['idor', 'path_traversal'],
    chain: CHAIN,
  });
  assert.deepEqual(lesson.when, ['php', 'web', 'auth_surface', 'debug_endpoint']);
  assert.deepEqual(lesson.do, [
    'weaponize',
    'access_control',
    'file_read_chain',
    'ssrf_as_gateway',
    'xml_parse',
    'sql_chain',
  ]);
  assert.deepEqual(lesson.avoid, ['access_control', 'file_read_chain']);
});

test('sanitizeLesson generalizes a raw chain and drops private segments', () => {
  const arrows = sanitizeLesson({ when: ['php'], do: ['rce'], chain: 'entry -> service(http) -> vuln(weaponize)' });
  assert.equal(arrows.chain, CHAIN);

  const scrubbed = sanitizeLesson({
    when: ['php'],
    do: ['rce'],
    chain: 'entry:8080 → 10.0.0.5 → /etc/passwd → service(http) → entry → vuln(weaponize)',
  });
  assert.equal(scrubbed.chain, 'service(http) → entry → vuln(weaponize)');

  const deduped = sanitizeLesson({ when: ['php'], do: ['rce'], chain: 'entry → entry → service(http)' });
  assert.equal(deduped.chain, 'entry → service(http)');
});

test('sanitizeLesson clamps counters, confidence, status and provenance fields', () => {
  const lesson = sanitizeLesson({
    when: ['php'],
    do: ['rce'],
    chain: CHAIN,
    confidence: 9,
    wins: -3,
    fails: -1,
    uses: '2',
    status: 'archived',
    sourceOutcome: 'pwn',
    sourceEngagementHash: 'z'.repeat(50),
    sourceFindingClasses: ['rce:critical', 'bad class!@#', 42],
  });
  assert.equal(lesson.confidence, 0.95);
  assert.equal(lesson.wins, 0);
  assert.equal(lesson.fails, 0);
  assert.equal(lesson.uses, 2);
  assert.equal(lesson.status, 'active');
  assert.equal(lesson.sourceOutcome, null);
  assert.equal(lesson.sourceEngagementHash.length, 32);
  assert.deepEqual(lesson.sourceFindingClasses, ['rce:critical', 'badclass', '42']);
  assert.equal(sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, confidence: -1 }).confidence, 0.18);
  assert.equal(sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, confidence: 'abc' }).confidence, 0.4);
  assert.equal(sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, status: 'retired' }).status, 'retired');
  assert.equal(
    sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, sourceOutcome: 'shell' }).sourceOutcome,
    'shell',
  );
});

test('sanitizeLesson is idempotent and lessonKey is stable and order independent', () => {
  const first = sanitizeLesson({ when: ['php', 'web'], do: ['rce'], chain: CHAIN });
  const second = sanitizeLesson({ when: ['web', 'php'], do: ['command_injection'], chain: CHAIN });
  assert.match(first.lessonKey, /^[0-9a-f]{16}$/u);
  assert.equal(first.lessonKey, second.lessonKey);
  assert.equal(first.lessonKey, sanitizeLesson(first).lessonKey);
  assert.notEqual(
    sanitizeLesson({ when: ['php'], do: ['rce'], chain: 'entry → vuln(sql_chain)' }).lessonKey,
    first.lessonKey,
  );
  assert.equal(
    lessonKeyFor({ when: ['php', 'web'], do: ['weaponize'], avoid: [], chain: CHAIN }),
    first.lessonKey,
  );
  assert.equal(lessonKeyFor({}), lessonKeyFor({ when: [], do: [], avoid: [], chain: '' }));
});

test('sanitizeLesson rejects host, URL, path, email and secret text in idea, method and route', () => {
  const scrubbed = sanitizeLesson({
    when: ['php'],
    do: ['rce'],
    chain: CHAIN,
    idea: 'Reach 10.0.0.5 then read the config',
    method: 'Fetch http://10.0.0.5/.env and diff it',
    route: 'Open /etc/passwd first',
  });
  assert.equal(scrubbed.idea, '');
  assert.equal(scrubbed.method, '');
  assert.equal(scrubbed.route, CHAIN);
  assert.equal(
    sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, idea: 'Mail admin@example.com the result' }).idea,
    '',
  );
  assert.equal(
    sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, method: 'Use api_key=abc123 in the header' }).method,
    '',
  );
  assert.equal(sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, idea: 'short' }).idea, '');

  const kept = sanitizeLesson({
    when: ['php'],
    do: ['rce'],
    chain: CHAIN,
    idea: 'Prefer the upload surface before deeper enumeration',
    method: 'Confirm with a non-destructive probe and record evidence',
  });
  assert.equal(kept.idea, 'Prefer the upload surface before deeper enumeration');
  assert.equal(kept.method, 'Confirm with a non-destructive probe and record evidence');
});

test('sanitizeLesson requires a tactical chain segment when no tactic is drafted', () => {
  const chainOnly = sanitizeLesson({ chain: 'entry → vuln(weaponize)' });
  assert.notEqual(chainOnly, null);
  assert.deepEqual(chainOnly.do, []);
  assert.equal(chainOnly.chain, 'entry → vuln(weaponize)');
  assert.notEqual(sanitizeLesson({ chain: 'entry → service(http)' }), null);
  assert.equal(sanitizeLesson({ chain: 'entry' }), null);
  assert.equal(sanitizeLesson({ when: ['php'] }), null);
  assert.equal(sanitizeLesson({ idea: 'short', method: 'tiny' }), null);
});

test('sanitizeLesson rejects non-object drafts', () => {
  for (const value of [null, undefined, 'php', 42, [], true]) {
    assert.equal(sanitizeLesson(value), null);
  }
});

test('sanitizeLesson scrubs host, port, URL, path and secret text from free-text fields', () => {
  const scrub = (patch) => sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, ...patch });
  assert.equal(scrub({ idea: 'Reach 10.0.0.5 before probing deeper' }).idea, '');
  assert.equal(scrub({ idea: 'Reach 2001:0db8:85a3:0000:0000:8a2e:0370:7334 now' }).idea, '');
  assert.equal(scrub({ idea: 'The service listens on port 8080 today' }).idea, '');
  assert.equal(scrub({ idea: 'The service listens at :8080 today' }).idea, '');
  assert.equal(scrub({ method: 'Fetch https://203.0.113.9/.env and diff it' }).method, '');
  assert.equal(scrub({ method: 'Open /etc/passwd right now' }).method, '');
  assert.equal(scrub({ idea: 'Mail admin@example.com the result' }).idea, '');
  assert.equal(scrub({ method: 'Send api_key=abc123 in the header' }).method, '');
  assert.equal(scrub({ route: 'Open /etc/passwd first' }).route, CHAIN);

  const kept = scrub({ idea: 'Prefer the upload surface before deeper enumeration' });
  assert.equal(kept.idea, 'Prefer the upload surface before deeper enumeration');
});

test(
  'sanitizeLesson scrubs compressed IPv6 literals from free-text fields',
  {
  },
  () => {
    const scrub = (text) => sanitizeLesson({
      when: ['php'],
      do: ['rce'],
      chain: CHAIN,
      idea: text,
      method: 'Confirm the surface with a second read',
    }).idea;
    assert.equal(scrub('Reach 2001:db8::1 quickly'), '');
    assert.equal(scrub('Reach fe80::1 quickly'), '');
  },
);

/* ================================================== tactic/cue mapping ==== */

test('tacticForFinding maps exposure templates to canonical tactics', () => {
  const cases = [
    ['exposed-env-file', 'credential'],
    ['exposed-git-repository', 'source_leak'],
    ['exposed-git-config', 'source_leak'],
    ['exposed-git-head', 'source_leak'],
    ['actuator-env-exposed', 'debug'],
    ['actuator-health-public', 'debug'],
    ['actuator-root-exposed', 'debug'],
    ['admin-interface-reachable', 'auth_surface'],
    ['directory-listing', 'info_disclosure'],
    ['directory-listing-stale-entry', 'info_disclosure'],
    ['apache-server-status', 'info_disclosure'],
    ['phpinfo-exposed', 'info_disclosure'],
    ['graphql-introspection', 'info_disclosure'],
    ['server-version-disclosure', 'info_disclosure'],
    ['missing-security-headers', 'misconfig'],
    ['default-credentials', 'credential'],
    ['weak-password', 'credential'],
    ['tomcat-manager-protected', 'auth_surface'],
  ];
  for (const [template, expected] of cases) {
    assert.equal(tacticForFinding({ attrs: { template } }), expected, template);
  }
});

test('tacticForFinding maps vulnerability templates and raw categories', () => {
  const templates = [
    ['rce', 'weaponize'],
    ['command-injection', 'weaponize'],
    ['sqli', 'sql_chain'],
    ['sql-injection', 'sql_chain'],
    ['lfi', 'file_read_chain'],
    ['path-traversal', 'file_read_chain'],
    ['xss', 'web_inject'],
    ['ssrf', 'ssrf_as_gateway'],
    ['xxe', 'xml_parse'],
    ['deserialization', 'restricted_deserialize'],
    ['auth-bypass', 'access_control'],
    ['file-upload', 'upload_bypass'],
  ];
  for (const [template, expected] of templates) {
    assert.equal(tacticForFinding({ attrs: { template } }), expected, template);
  }
  // Category-only findings resolve through the alias table when the category name
  // itself is a tactic or an alias.
  assert.equal(tacticForFinding({ attrs: { category: 'sqli' } }), 'sql_chain');
  assert.equal(tacticForFinding({ attrs: { category: 'auth_bypass' } }), 'access_control');
  assert.equal(tacticForFinding({ attrs: { category: 'privilege_escalation' } }), 'privesc_lateral');
  assert.equal(tacticForFinding({ attrs: { category: 'file_read' } }), 'file_read_chain');
  assert.equal(tacticForFinding({ attrs: { category: 'credential' } }), 'credential');
});

test('tacticForFinding maps category-only findings to canonical tactics', () => {
  assert.equal(tacticForFinding({ attrs: { category: 'xss' } }), 'web_inject');
  assert.equal(tacticForFinding({ attrs: { category: 'sql_injection' } }), 'sql_chain');
  assert.equal(tacticForFinding({ attrs: { category: 'file_write' } }), 'file_read_chain');
  assert.equal(tacticForFinding({ attrs: { category: 'data_leak' } }), 'data_access');
  assert.equal(tacticForFinding({ attrs: { category: 'mass_disclosure' } }), 'data_access');
  assert.equal(tacticForFinding({ attrs: { category: 'default_credentials' } }), 'credential');
  assert.equal(tacticForFinding({ attrs: { category: 'data_access' } }), 'data_access');
});

test('tacticForFinding prefers the template, then the category, then falls back', () => {
  assert.equal(tacticForFinding({ attrs: { template: 'actuator-env-exposed', category: 'sqli' } }), 'debug');
  assert.equal(tacticForFinding({ attrs: { template: 'no-such-template', category: 'sqli' } }), 'sql_chain');
  assert.equal(tacticForFinding({ attrs: { template: 'no-such-template' } }), 'finding_read_loot');
  assert.equal(tacticForFinding({}), 'finding_read_loot');
  assert.equal(tacticForFinding({ attrs: {} }), 'finding_read_loot');
  // TEMPLATE_TACTICS maps 'open-redirect' to the token 'redirect', which is not in
  // TACTICS, so the lookup falls through to the generic read/loot tactic.
  assert.equal(tacticForFinding({ attrs: { template: 'open-redirect' } }), 'finding_read_loot');
});

test('cueForFinding maps template families to cue tokens', () => {
  const cases = [
    ['exposed-env-file', 'file_read_surface'],
    ['exposed-git-repository', 'file_read_surface'],
    ['admin-interface-reachable', 'auth_surface'],
    ['sqli', 'inject_surface'],
    ['xss', 'inject_surface'],
    ['arbitrary-upload', 'upload_surface'],
    ['deserialization', 'deserialize_surface'],
    ['actuator-health-public', 'debug_endpoint'],
    ['phpinfo-exposed', 'debug_endpoint'],
    ['graphql-introspection', 'graphql_surface'],
    ['soap-api', 'xml_surface'],
    ['directory-listing', 'web'],
    ['unknown-thing', 'web'],
  ];
  for (const [template, expected] of cases) {
    assert.equal(cueForFinding({ attrs: { template } }), expected, template);
  }
});

test('cueForFinding resolves overlapping template families deterministically', () => {
  // 'env' hits the file-read family before the actuator/debug branch, so the
  // env actuator endpoint reports the file-read cue rather than the debug cue.
  assert.equal(cueForFinding({ attrs: { template: 'actuator-env-exposed' } }), 'file_read_surface');
  assert.equal(cueForFinding({ attrs: { template: 'actuator-root-exposed' } }), 'debug_endpoint');
  // Upload families are checked before the generic file-read family so
  // 'file-upload' correctly reports the upload cue.
  assert.equal(cueForFinding({ attrs: { template: 'file-upload' } }), 'upload_surface');
  assert.equal(cueForFinding({ attrs: { template: 'arbitrary-upload' } }), 'upload_surface');
  assert.equal(cueForFinding({ attrs: { template: 'Admin-Interface-Reachable' } }), 'auth_surface');
  assert.equal(cueForFinding({}), 'web');
  assert.equal(cueForFinding({ attrs: {} }), 'web');
});

test('alias table only points at canonical tactics', () => {
  for (const [alias, canonical] of Object.entries(TACTIC_ALIASES)) {
    assert.equal(TACTICS.has(canonical), true, `${alias} -> ${canonical}`);
  }
  // Characterization of two dead tokens found while testing (reported, not fixed
  // here): 'redirect' is targeted by the open-redirect template but is not a
  // tactic, and graphSignals emits 'recon' although no lesson token can carry it.
  assert.equal(TACTICS.has('redirect'), false);
  assert.equal(CUE_TOKENS.has('recon'), false);
});

/* ================================== stack tokens and graph signals ======== */

test('stackTokensOf finds known stack tokens inside noisy fingerprints', () => {
  assert.deepEqual(
    stackTokensOf(['PHP/8.2', 'nginx', 'MySQL', 'nodejs', 'Tomcat 9']),
    ['php', 'nginx', 'mysql', 'node', 'nodejs', 'tomcat'],
  );
  assert.deepEqual(stackTokensOf(['php', 'php', 'PHP']), ['php']);
  assert.deepEqual(stackTokensOf(['unknown-stack']), []);
  assert.deepEqual(stackTokensOf([]), []);
  assert.deepEqual(stackTokensOf('php'), []);
  const many = ['php', 'java', 'python', 'ruby', 'go', 'nginx', 'apache', 'tomcat', 'mysql', 'redis'];
  assert.equal(stackTokensOf(many).length, 8);
});

test('graphStackTokens reads only tech, webapp and service nodes', () => {
  const state = graphState({
    nodes: [
      graphNode('h', 'host', 'php', 'alive', { fqdn: 'php.internal' }),
      graphNode('t', 'tech', 'php', 'detected', { label: 'PHP 8.2' }, { tags: ['fpm'] }),
      graphNode('w', 'webapp', 'https://203.0.113.9/', 'fingerprinted', { server: 'nginx/1.24' }, { tags: ['mysql'] }),
      graphNode('s', 'service', 's', 'open', { protocol: 'redis' }),
    ],
  });
  assert.deepEqual(graphStackTokens(state), ['php', 'nginx', 'mysql', 'redis']);
  assert.deepEqual(graphStackTokens({ nodes: {} }), []);
  assert.deepEqual(graphStackTokens({}), []);
});

test('graphSignals merges stack tokens with tactic, cue and impact signals', () => {
  const state = graphState({
    nodes: [
      graphNode('h', 'host', '203.0.113.9', 'alive', { realm: 'internal' }),
      graphNode('t', 'tech', 'php', 'detected', { label: 'PHP' }),
      graphNode('f', 'finding', 'f', 'verified', { template: 'sqli' }),
      graphNode('c', 'credential', 'c', 'valid'),
      graphNode('a', 'access', 'a', 'validated', { kind: 'user_shell' }),
      graphNode('d', 'data', 'd', 'verified', { thresholdMet: true }),
      graphNode('i1', 'intent', 'i1', 'open', { actionType: 'verify_sqli' }),
      graphNode('i2', 'intent', 'i2', 'open', { actionType: 'escalate_privilege' }),
    ],
  });
  const signals = graphSignals(state);
  assert.ok(signals instanceof Set);
  for (const expected of ['php', 'sql_chain', 'inject_surface', 'credential', 'foothold', 'data_access', 'internal', 'recon']) {
    assert.equal(signals.has(expected), true, expected);
  }
  assert.equal(signals.has('nginx'), false);
});

/* ================================================== chain generalisation == */

test('generalizeChainFromIds maps node kinds to transferable type tokens', () => {
  const state = graphState({
    nodes: [
      graphNode('h', 'host', '203.0.113.9', 'alive'),
      graphNode('ip', 'ip', '203.0.113.9', 'alive'),
      graphNode('dom', 'domain', 'portal.example.test', 'alive'),
      graphNode('w', 'webapp', 'https://203.0.113.9/', 'up'),
      graphNode('svc', 'service', 's1', 'open', { protocol: 'smb' }),
      graphNode('svc2', 'service', 's2', 'open', { protocol: 'custom' }),
      graphNode('f', 'finding', 'f', 'verified', { template: 'sqli' }),
      graphNode('a', 'access', 'a', 'validated', { kind: 'user_shell' }),
      graphNode('a2', 'access', 'a2', 'validated'),
      graphNode('d', 'data', 'd', 'verified'),
      graphNode('c', 'credential', 'c', 'valid'),
      graphNode('p', 'pivot', 'p', 'verified'),
      graphNode('t', 'task', 't', 'open'),
    ],
  });
  assert.deepEqual(
    generalizeChainFromIds(state, ['h', 'ip', 'dom', 'w', 'svc', 'svc2', 'f', 'a', 'a2', 'd', 'c', 'p', 't', 'missing', undefined]),
    [
      'entry',
      'service(http)',
      'service(smb)',
      'service',
      'vuln(sql_chain)',
      'foothold(user_shell)',
      'foothold(access)',
      'goal(data)',
      'cred(credential)',
      'pivot',
    ],
  );
});

test('generalizeChainFromIds dedupes only adjacent tokens', () => {
  const state = graphState({
    nodes: [graphNode('h', 'host', '203.0.113.9', 'alive'), graphNode('w', 'webapp', 'w', 'up')],
  });
  assert.deepEqual(generalizeChainFromIds(state, ['h', 'w', 'h']), ['entry', 'service(http)', 'entry']);
  assert.deepEqual(generalizeChainFromIds(state, ['h', 'missing']), ['entry']);
  assert.deepEqual(generalizeChainFromIds(state, []), []);
  assert.deepEqual(generalizeChainFromIds(state, null), []);
  assert.deepEqual(generalizeChainFromIds(state, 'h'), []);
});

test('winningChain follows a crown path from a foothold to verified data', () => {
  const state = graphState({
    nodes: [
      graphNode('a', 'access', 'a', 'validated', { kind: 'user_shell' }),
      graphNode('d', 'data', 'd', 'verified', { dataClass: 'users', thresholdMet: true }),
    ],
    edges: [graphEdge('a', 'd', 'proves')],
  });
  assert.deepEqual(winningChain(state), ['foothold(user_shell)', 'goal(data)']);
});

test('winningChain falls back to a tactic chain when no foothold is realized', () => {
  const state = graphState({
    nodes: [
      graphNode('h', 'host', '203.0.113.9', 'alive'),
      graphNode('w', 'webapp', 'w', 'up', { server: 'nginx' }),
      graphNode('f', 'finding', 'f', 'verified', { template: 'rce', severity: 'critical' }),
    ],
  });
  assert.deepEqual(winningChain(state), ['entry', 'service(http)', 'vuln(weaponize)']);
  assert.deepEqual(winningChain({ nodes: {} }), ['entry']);
});

/* ============================================== evolution qualification === */

test('qualifiesForEvolution ignores high candidates that are not verified', () => {
  const state = graphState({
    nodes: [graphNode('f', 'finding', 'f', 'candidate', { severity: 'high', template: 'sqli' })],
  });
  const result = qualifiesForEvolution(state, {});
  assert.equal(result.qualified, false);
  assert.equal(result.candidateHigh.length, 1);
  assert.deepEqual(result.verifiedHigh, []);
  assert.deepEqual(result.reasons, []);
});

test('qualifiesForEvolution requires secondary verification plus evidence for high findings', () => {
  const withoutSecondary = graphState({
    nodes: [graphNode('f', 'finding', 'f', 'verified', { severity: 'critical', template: 'rce' })],
  });
  withoutSecondary.nodes.f.evidenceIds = ['ev_1'];
  assert.equal(qualifiesForEvolution(withoutSecondary, {}).qualified, false);

  const withoutEvidence = graphState({
    nodes: [graphNode('f', 'finding', 'f', 'verified', { severity: 'critical', template: 'rce', secondaryVerified: true })],
  });
  assert.equal(qualifiesForEvolution(withoutEvidence, {}).qualified, false);

  const verified = graphState({
    nodes: [graphNode('f', 'finding', 'f', 'verified', { severity: 'critical', template: 'rce', secondaryVerified: true })],
  });
  verified.nodes.f.evidenceIds = ['ev_1'];
  const result = qualifiesForEvolution(verified, {});
  assert.equal(result.qualified, true);
  assert.equal(result.verifiedHigh.length, 1);
  assert.deepEqual(result.reasons, ['1 verified high/critical finding(s)']);
});

test('qualifiesForEvolution accepts exploited status as verification', () => {
  const state = graphState({
    nodes: [graphNode('f', 'finding', 'f', 'exploited', { severity: 'high', template: 'sqli' })],
  });
  state.nodes.f.evidenceIds = ['ev_1'];
  assert.equal(qualifiesForEvolution(state, {}).qualified, true);
});

test('qualifiesForEvolution counts validated access, not merely obtained access', () => {
  const validated = graphState({ nodes: [graphNode('a', 'access', 'a', 'validated', { kind: 'user_shell' })] });
  const result = qualifiesForEvolution(validated, {});
  assert.equal(result.qualified, true);
  assert.equal(result.access.length, 1);
  assert.deepEqual(result.reasons, ['1 validated access path(s)']);

  const obtained = graphState({ nodes: [graphNode('a', 'access', 'a', 'obtained', { kind: 'user_shell' })] });
  assert.equal(qualifiesForEvolution(obtained, {}).qualified, false);

  const escalated = graphState({ nodes: [graphNode('a', 'access', 'a', 'escalated', { kind: 'root_shell' })] });
  assert.equal(qualifiesForEvolution(escalated, {}).access.length, 1);
});

test('qualifiesForEvolution counts verified data only above the bulk threshold', () => {
  const below = graphState({ nodes: [graphNode('d', 'data', 'd', 'verified', { dataClass: 'users', count: 50 })] });
  assert.equal(qualifiesForEvolution(below, { bulkThresholds: { users: 100 } }).qualified, false);
  assert.equal(qualifiesForEvolution(below, { bulkThresholds: { users: 10 } }).qualified, true);

  const flagged = graphState({ nodes: [graphNode('d', 'data', 'd', 'verified', { dataClass: 'users', thresholdMet: true })] });
  assert.equal(qualifiesForEvolution(flagged, {}).qualified, true);
  assert.deepEqual(qualifiesForEvolution(flagged, {}).reasons, ['1 verified bulk-data evidence set(s)']);

  const candidate = graphState({ nodes: [graphNode('d', 'data', 'd', 'candidate', { thresholdMet: true })] });
  assert.equal(qualifiesForEvolution(candidate, {}).qualified, false);
});

test('qualifiesForEvolution rejects an unproven RCE claim and accepts execution proof', () => {
  const unproven = graphState({
    nodes: [
      graphNode('f', 'finding', 'f', 'verified', {
        severity: 'critical',
        template: 'rce',
        secondaryVerified: true,
        title: 'RCE in the upload endpoint',
        label: 'RCE in upload',
      }),
    ],
  });
  unproven.nodes.f.evidenceIds = ['ev_1'];
  assert.equal(qualifiesForEvolution(unproven, {}).qualified, false);

  const proven = graphState({
    nodes: [
      graphNode('f', 'finding', 'f', 'verified', {
        severity: 'critical',
        template: 'rce',
        secondaryVerified: true,
        title: 'RCE confirmed uid=0(root) whoami',
        label: 'RCE in upload',
      }),
    ],
  });
  proven.nodes.f.evidenceIds = ['ev_1'];
  assert.equal(qualifiesForEvolution(proven, {}).qualified, true);
});

/* =========================================== episode + lesson building ==== */

test('buildEpisode distils a host-free episode with stack, tactic and cue fields', () => {
  const episode = buildEpisode(sampleFindingState(), { sourceEngagementHash: 'eng-abc' });
  assert.equal(episode.objective, 'acme-prod');
  assert.equal(episode.outcomeClass, 'finding');
  assert.equal(episode.targetFp, 'nginx|php|mysql');
  assert.equal(episode.chain, CHAIN);
  assert.deepEqual(episode.tactics, ['weaponize']);
  assert.deepEqual(episode.cues, ['web']);
  assert.deepEqual(episode.failedTechniques, ['sqli']);
  assert.deepEqual(episode.findingClasses, ['rce:critical']);
  assert.deepEqual(episode.accessKinds, []);
  assert.deepEqual(episode.dataClasses, []);
  assert.equal(episode.sourceEngagementHash, 'eng-abc');
  assert.equal(episode.qualifying, true);
  assert.match(episode.occurredAt, /^\d{4}-\d{2}-\d{2}T/u);

  const encoded = JSON.stringify(episode);
  for (const banned of ['203.0.113.9', 'http://', 'https://', 'portal.example', '/etc/', '8080', '8443']) {
    assert.equal(encoded.includes(banned), false, `${banned} leaked into the episode`);
  }
});

test('buildEpisode prefers the loop objective, honours outcome override and flags unqualified graphs', () => {
  const state = sampleFindingState();
  assert.equal(
    buildEpisode(state, { loop: { attrs: { objective: 'collect database proof' } } }).objective,
    'collect database proof',
  );
  assert.equal(buildEpisode(state, { outcome: 'shell' }).outcomeClass, 'shell');

  const empty = graphState({ nodes: [graphNode('h', 'host', '203.0.113.9', 'alive')] });
  const episode = buildEpisode(empty, {});
  assert.equal(episode.qualifying, false);
  assert.equal(episode.targetFp, 'web');
  assert.equal(episode.chain, 'entry');
  assert.deepEqual(episode.tactics, []);
  assert.deepEqual(episode.cues, []);
  assert.equal(buildEpisode(empty, { loop: { attrs: { objective: 'x'.repeat(400) } } }).objective.length, 300);
});

test('buildEpisode classifies shell, data and admin outcomes', () => {
  const shell = graphState({ nodes: [graphNode('a', 'access', 'a', 'validated', { kind: 'user_shell' })] });
  assert.equal(buildEpisode(shell, {}).outcomeClass, 'shell');
  assert.deepEqual(buildEpisode(shell, {}).tactics, ['privesc_lateral']);
  assert.deepEqual(buildEpisode(shell, {}).cues, ['foothold']);

  const data = graphState({
    nodes: [
      graphNode('a', 'access', 'a', 'validated', { kind: 'user_shell' }),
      graphNode('d', 'data', 'd', 'verified', { dataClass: 'users', thresholdMet: true }),
    ],
    edges: [graphEdge('a', 'd', 'proves')],
  });
  const dataEpisode = buildEpisode(data, {});
  assert.equal(dataEpisode.outcomeClass, 'data');
  assert.deepEqual(dataEpisode.tactics, ['privesc_lateral', 'data_access']);
  assert.deepEqual(dataEpisode.dataClasses, ['users']);

  const admin = graphState({
    nodes: [
      graphNode('a', 'access', 'a', 'validated', { kind: 'db_admin' }),
      graphNode('d', 'data', 'd', 'verified', { dataClass: 'users', thresholdMet: true }),
    ],
    edges: [graphEdge('a', 'd', 'proves')],
  });
  const adminEpisode = buildEpisode(admin, {});
  assert.equal(adminEpisode.outcomeClass, 'admin');
  assert.deepEqual(adminEpisode.tactics, ['access_control', 'data_access']);
  assert.deepEqual(adminEpisode.accessKinds, ['db_admin']);
});

test('deterministicLessons refuses unqualified or chain-less episodes', () => {
  const empty = graphState({ nodes: [graphNode('h', 'host', '203.0.113.9', 'alive')] });
  assert.deepEqual(deterministicLessons(empty, buildEpisode(empty, {})), []);
  const handcrafted = {
    qualifying: true,
    targetFp: 'php',
    chain: 'entry',
    tactics: ['weaponize'],
    cues: ['web'],
    failedTechniques: [],
  };
  assert.deepEqual(deterministicLessons(empty, handcrafted), []);
});

test('deterministicLessons distils one host-free lesson from a qualifying episode', () => {
  const state = sampleFindingState();
  const episode = buildEpisode(state, { sourceEngagementHash: 'eng-abc' });
  const lessons = deterministicLessons(state, episode);
  assert.equal(lessons.length, 1);
  const [lesson] = lessons;
  assert.deepEqual(lesson.when, ['nginx', 'php', 'mysql', 'web']);
  assert.deepEqual(lesson.do, ['weaponize']);
  assert.deepEqual(lesson.avoid, ['sql_chain']);
  assert.equal(lesson.chain, CHAIN);
  assert.equal(lesson.route, CHAIN);
  assert.match(lesson.idea, /nginx\/php\/mysql/u);
  assert.match(lesson.method, /weaponize/u);
  assert.equal(lesson.sourceOutcome, 'finding');
  assert.equal(lesson.sourceEngagementHash, 'eng-abc');
  assert.equal(lesson.wins, 0);
  approx(lesson.confidence, 0.45, 1e-9, 'lesson confidence');
  assert.equal(lesson.lessonKey, sanitizeLesson(lesson).lessonKey);
  assert.equal(/203\.0\.113\.9|\/etc\/|https?:\/\//u.test(JSON.stringify(lesson)), false);
});

test('deterministicLessons credits access/data outcomes with a win', () => {
  const state = graphState({
    nodes: [
      graphNode('a', 'access', 'a', 'validated', { kind: 'db_admin' }),
      graphNode('d', 'data', 'd', 'verified', { dataClass: 'users', thresholdMet: true }),
    ],
    edges: [graphEdge('a', 'd', 'proves')],
  });
  const lessons = deterministicLessons(state, buildEpisode(state, {}));
  assert.equal(lessons.length, 1);
  const [lesson] = lessons;
  assert.equal(lesson.sourceOutcome, 'admin');
  assert.equal(lesson.wins, 1);
  approx(lesson.confidence, 0.55, 1e-9, 'lesson confidence');
  assert.deepEqual(lesson.when, ['web', 'foothold', 'data_access']);
  assert.deepEqual(lesson.do, ['access_control', 'data_access']);
});

/* ============================================================ the store === */

test('appendLessonRecords round-trips, ignores corrupt lines and folds the latest record', async (t) => {
  const { store } = await tempStore(t);
  assert.deepEqual(await readLessonRecords(store), []);

  const first = lessonDraft({ wins: 1 });
  await appendLessonRecords(store, [{ kind: 'lesson', lesson: first }]);
  await appendFile(store, 'not a json line\n', 'utf8');

  const second = lessonDraft({ wins: 7, confidence: 0.7 });
  assert.equal(second.lessonKey, first.lessonKey);
  await writeLessonSnapshot(store, [second]);

  const records = await readLessonRecords(store);
  assert.equal(records.length, 2);
  assert.equal(records.every((record) => record.kind === 'lesson'), true);

  const lessons = await readLessons(store);
  assert.equal(lessons.length, 1);
  assert.equal(lessons[0].wins, 7);
  approx(lessons[0].confidence, 0.7, 1e-9, 'folded confidence');
});

test('readLessonRecords returns an empty list when the store does not exist', async (t) => {
  const { store } = await tempStore(t);
  assert.deepEqual(await readLessonRecords(store), []);
  assert.deepEqual(await readLessons(store), []);
});

test('appendEpisode writes an episode record beside the lesson store', async (t) => {
  const { dir, store } = await tempStore(t);
  assert.equal(episodeStorePath(store), path.join(dir, 'episodes.jsonl'));

  const episode = { chain: CHAIN, qualifying: true, outcomeClass: 'finding' };
  await appendEpisode(store, episode);
  const raw = await readFile(episodeStorePath(store), 'utf8');
  assert.equal(raw.trim().split('\n').length, 1);

  const [record] = await readLessonRecords(episodeStorePath(store));
  assert.equal(record.kind, 'episode');
  assert.deepEqual(record.episode, episode);
});

test('append helpers create no file for empty input', async (t) => {
  const { store } = await tempStore(t);
  await appendLessonRecords(store, []);
  await appendLessonRecords(store, null);
  await writeLessonSnapshot(store, []);
  await assert.rejects(stat(store), /ENOENT/u);
});

test('appendLessonRecords recovers after a failed write', async (t) => {
  const { dir, store } = await tempStore(t);
  const blocker = path.join(dir, 'blocker');
  await writeFile(blocker, 'x');
  await assert.rejects(appendLessonRecords(path.join(blocker, 'lessons.jsonl'), [{ kind: 'lesson', lesson: lessonDraft() }]));
  await appendLessonRecords(store, [{ kind: 'lesson', lesson: lessonDraft() }]);
  assert.equal((await readLessonRecords(store)).length, 1);
});

test('resolveLessonStore honours absolute, relative and default locations', () => {
  assert.equal(
    resolveLessonStore('/tmp/ws', { lessonStore: '/var/lib/atk/lessons.jsonl' }),
    '/var/lib/atk/lessons.jsonl',
  );
  assert.equal(
    resolveLessonStore('/tmp/ws', { lessonStore: 'memory/lessons.jsonl' }),
    path.resolve('/tmp/ws', 'memory/lessons.jsonl'),
  );
  const fallback = path.join(os.homedir(), '.dsh', 'atkbrain', 'memory', 'lessons.jsonl');
  assert.equal(resolveLessonStore('/tmp/ws', {}), fallback);
  assert.equal(resolveLessonStore('/tmp/ws', undefined), fallback);
  assert.equal(resolveLessonStore('/tmp/ws', { lessonStore: '   ' }), fallback);
  assert.equal(resolveLessonStore('/tmp/ws', { lessonStore: 42 }), fallback);
});

test('foldLessonRecords drops malformed records and keeps the last lesson per key', () => {
  const first = lessonDraft({ wins: 1 });
  const last = lessonDraft({ wins: 9 });
  const folded = foldLessonRecords([
    null,
    3,
    'x',
    { kind: 'lesson' },
    { lesson: {} },
    { lesson: { lessonKey: 42 }, kind: 'lesson' },
    { kind: 'lesson', lesson: first },
    { kind: 'lesson', lesson: last },
  ]);
  assert.equal(folded.length, 1);
  assert.equal(folded[0].wins, 9);
  assert.equal(foldLessonRecords([first]).length, 1);
  assert.deepEqual(foldLessonRecords([]), []);
  assert.deepEqual(foldLessonRecords(undefined), []);
});

/* ================================================== scoring + retrieval === */

test('confidenceFor is monotonic in wins and losses and clamps', () => {
  approx(confidenceFor(0, 0, 0), 0.4);
  approx(confidenceFor(1, 0, 0), 0.52);
  approx(confidenceFor(2, 0, 0), 0.64);
  approx(confidenceFor(0, 1, 0), 0.26);
  approx(confidenceFor(0, 3, 0), 0.18);
  approx(confidenceFor(0, 0, 4), 0.3);
  assert.equal(confidenceFor(99, 0, 0), 0.95);
  assert.equal(confidenceFor(0, 99, 0), 0.18);
});

test('scoreLesson rewards matching technology, tactic and avoid signals', () => {
  const lesson = lessonDraft({ confidence: 0.9 });
  approx(scoreLesson(lesson, new Set(['php', 'weaponize'])), 1.025);
  assert.equal(scoreLesson(lesson, new Set(['python'])), 0);
  assert.equal(scoreLesson(lesson, new Set(['php'])), 0);

  const withAvoid = lessonDraft({ confidence: 0.6, avoid: ['sql_chain'] });
  approx(scoreLesson(withAvoid, new Set(['php', 'weaponize'])), 0.89);
  approx(scoreLesson(withAvoid, new Set(['php', 'weaponize', 'sql_chain'])), 0.97);
  approx(scoreLesson(withAvoid, new Set(['php', 'weaponize']), 0.2), 0.71);

  assert.equal(scoreLesson({ when: [], do: [], avoid: [] }, new Set(['php'])), 0);
});

test('lessonConsumesEvidence requires every drafted tactic to be backed by a signal', () => {
  const lesson = lessonDraft();
  assert.equal(lessonConsumesEvidence(lesson, new Set(['weaponize'])), true);
  assert.equal(lessonConsumesEvidence(lesson, new Set(['php'])), false);
  assert.equal(lessonConsumesEvidence(lesson, new Set(['php', 'weaponize'])), true);
  assert.equal(lessonConsumesEvidence({ when: ['weaponize'], do: ['rce'] }, new Set(['php'])), true);
  assert.equal(lessonConsumesEvidence({ when: [], do: [] }, new Set()), true);
  assert.equal(lessonConsumesEvidence({ when: [], do: ['rce'] }, new Set(['weaponize'])), true);
});

test('retrieveLessons matches tech/tactic signals and drops zero-score or retired lessons', () => {
  const state = graphState({
    nodes: [
      graphNode('t', 'tech', 'php', 'detected', { label: 'PHP' }),
      graphNode('f1', 'finding', 'f1', 'verified', { template: 'rce' }),
      graphNode('f2', 'finding', 'f2', 'verified', { template: 'sqli' }),
    ],
  });
  const sniper = lessonDraft({ confidence: 0.9 });
  const sql = sanitizeLesson({ when: ['php'], do: ['sqli'], chain: 'entry → vuln(sql_chain)', confidence: 0.5 });
  const miss = sanitizeLesson({ when: ['python'], do: ['xxe'], chain: 'entry → vuln(xml_parse)' });
  const retired = sanitizeLesson({
    when: ['php'],
    do: ['rce'],
    avoid: ['upload_bypass'],
    chain: CHAIN,
    confidence: 0.99,
    status: 'retired',
  });

  assert.deepEqual(
    retrieveLessons([sniper, sql, miss, retired], { state }).map((lesson) => lesson.lessonKey),
    [sniper.lessonKey, sql.lessonKey],
  );
});

test('retrieveLessons excludes same-engagement lessons unless includeSelf is set', () => {
  const state = graphState({
    nodes: [graphNode('t', 'tech', 'php', 'detected'), graphNode('f', 'finding', 'f', 'verified', { template: 'rce' })],
  });
  const own = sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, sourceEngagementHash: 'eng-1' });
  const other = sanitizeLesson({
    when: ['php'],
    do: ['rce'],
    chain: 'entry → vuln(weaponize) → goal(data)',
    sourceEngagementHash: 'eng-2',
  });

  assert.deepEqual(
    retrieveLessons([own, other], { state, sourceEngagementHash: 'eng-1' }).map((lesson) => lesson.sourceEngagementHash),
    ['eng-2'],
  );
  assert.equal(retrieveLessons([own], { state, sourceEngagementHash: 'eng-1' }).length, 0);
  assert.equal(retrieveLessons([own], { state, sourceEngagementHash: 'eng-1', includeSelf: true }).length, 1);
  assert.equal(retrieveLessons([own], { state, sourceEngagementHash: 'eng-9' }).length, 1);
});

test('retrieveLessons caps results by limit', () => {
  const state = graphState({
    nodes: [graphNode('t', 'tech', 'php', 'detected'), graphNode('f', 'finding', 'f', 'verified', { template: 'rce' })],
  });
  const avoidTokens = [null, 'sql_chain', 'access_control', 'file_read_chain', 'upload_bypass', 'xml_parse', 'ssrf_as_gateway'];
  const lessons = avoidTokens.map((avoid) => sanitizeLesson({
    when: ['php'],
    do: ['rce'],
    avoid: avoid === null ? [] : [avoid],
    chain: CHAIN,
    confidence: 0.5,
  }));
  assert.equal(new Set(lessons.map((lesson) => lesson.lessonKey)).size, 7);
  assert.equal(retrieveLessons(lessons, { state }).length, 6);
  assert.equal(retrieveLessons(lessons, { state, limit: 2 }).length, 2);
  assert.equal(retrieveLessons(lessons, { state, limit: 0 }).length, 6);
  assert.equal(retrieveLessons(lessons, { state, limit: 500 }).length, 7);
});

test('formatLessonBlock renders an advisory block and stays empty without lessons', () => {
  assert.equal(formatLessonBlock([]), '');
  assert.equal(formatLessonBlock(null), '');

  const lesson = lessonDraft({ confidence: 0.52 });
  const lines = formatLessonBlock([lesson]).split('\n');
  assert.equal(lines[0], '## Evolution experience (advisory only; re-verify on this target)');
  assert.match(lines[1], /^- /u);
  assert.match(lines[1], /route: entry → service\(http\) → vuln\(weaponize\)/u);
  assert.match(lines[1], /tactics: weaponize/u);
  assert.match(lines[1], /when: php/u);
  assert.match(lines[1], /confidence 0\.52/u);

  const noIdea = sanitizeLesson({
    when: ['php'],
    do: ['rce'],
    chain: CHAIN,
    method: 'Confirm the surface with a second read',
  });
  assert.match(formatLessonBlock([noIdea]), /\n- Confirm the surface/u);
});

/* ============================================ reinforcement + merging ===== */

test('reinforceLesson tracks wins, losses and neutral use', () => {
  const base = lessonDraft();

  const win = reinforceLesson(base, 'win');
  assert.equal(win.wins, 1);
  assert.equal(win.uses, 1);
  approx(win.confidence, 0.52);
  assert.equal(win.status, 'active');
  assert.equal(typeof win.lastUsedAt, 'string');

  const loss = reinforceLesson(base, 'loss');
  assert.equal(loss.fails, 1);
  assert.equal(loss.uses, 1);
  approx(loss.confidence, 0.26);

  const neutral = reinforceLesson(base, 'observe');
  assert.equal(neutral.wins, 0);
  assert.equal(neutral.fails, 0);
  assert.equal(neutral.uses, 1);
  approx(neutral.confidence, 0.4);
});

test('reinforceLesson retires a repeatedly losing lesson and markLessonUsed only bumps use', () => {
  const losing = sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, wins: 0, fails: 3, uses: 3 });
  const retired = reinforceLesson(losing, 'loss');
  assert.equal(retired.fails, 4);
  assert.equal(retired.uses, 4);
  assert.equal(retired.status, 'retired');
  assert.ok(retired.confidence <= 0.25);

  const used = markLessonUsed(sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, wins: 0, uses: 3 }));
  assert.equal(used.uses, 4);
  assert.equal(used.wins, 0);
  approx(used.confidence, 0.3);
  assert.equal(typeof used.lastUsedAt, 'string');
});

test('mergeLesson unions tokens, keeps counters and preserves retirement', () => {
  const existing = sanitizeLesson({
    when: ['php'],
    do: ['rce'],
    chain: CHAIN,
    wins: 2,
    fails: 1,
    uses: 5,
    idea: 'short idea',
    status: 'retired',
  });
  const incoming = sanitizeLesson({
    when: ['nginx'],
    do: ['sqli'],
    chain: 'entry → vuln(sql_chain)',
    wins: 1,
    idea: 'a much longer incoming idea text',
    sourceOutcome: 'shell',
  });
  const merged = mergeLesson(existing, incoming);
  assert.deepEqual(merged.when, ['php', 'nginx']);
  assert.deepEqual(merged.do, ['weaponize', 'sql_chain']);
  assert.deepEqual(merged.avoid, []);
  assert.equal(merged.wins, 3);
  assert.equal(merged.fails, 1);
  assert.equal(merged.uses, 5);
  approx(merged.confidence, 0.62);
  assert.equal(merged.status, 'retired');
  assert.equal(merged.idea, 'a much longer incoming idea text');
  assert.equal(merged.chain, 'entry → vuln(sql_chain)');
  assert.equal(merged.sourceOutcome, 'shell');
});

test('mergeLesson only counts presence of incoming wins/fails and sanitizes a fresh draft', () => {
  const existing = sanitizeLesson({ when: ['php'], do: ['rce'], chain: CHAIN, wins: 5, fails: 0, uses: 2 });
  const incoming = sanitizeLesson({ when: ['nginx'], do: ['sql_chain'], chain: 'entry → vuln(sql_chain)', wins: 3, fails: 1 });

  const merged = mergeLesson(existing, incoming);
  assert.equal(merged.wins, 6);
  assert.equal(merged.fails, 1);
  assert.equal(merged.uses, 2);

  const fresh = mergeLesson(null, incoming);
  assert.equal(fresh.lessonKey, incoming.lessonKey);
  assert.equal(fresh.wins, 3);
  assert.equal(mergeLesson(undefined, incoming).lessonKey, incoming.lessonKey);
});

/* ============================================== evolve-reply parsing ===== */

test('parseEvolveLessons reads fenced JSON and returns at most three lessons', () => {
  const fenced = [
    'prose before',
    '```json',
    JSON.stringify({ lessons: [{ a: 1 }, { a: 2 }, { a: 3 }, { a: 4 }] }),
    '```',
    'prose after',
  ].join('\n');
  assert.deepEqual(parseEvolveLessons(fenced), [{ a: 1 }, { a: 2 }, { a: 3 }]);
  assert.deepEqual(parseEvolveLessons('{"lessons":[{"a":1}]}'), [{ a: 1 }]);
  assert.deepEqual(parseEvolveLessons('Here you go: {"lessons":[{"idea":"x"}]} — done'), [{ idea: 'x' }]);
  assert.deepEqual(parseEvolveLessons('```json\n{"lessons":[{"a":1}]}\n```'), [{ a: 1 }]);
});

test('parseEvolveLessons returns an empty list for malformed or lesson-less payloads', () => {
  assert.deepEqual(parseEvolveLessons(''), []);
  assert.deepEqual(parseEvolveLessons(null), []);
  assert.deepEqual(parseEvolveLessons('no json at all'), []);
  assert.deepEqual(parseEvolveLessons('{not json'), []);
  assert.deepEqual(parseEvolveLessons('{"lessons":"nope"}'), []);
  assert.deepEqual(parseEvolveLessons('{"other":[]}'), []);
  assert.deepEqual(parseEvolveLessons('{"lessons":[null,42,{"a":1}]}'), [{ a: 1 }]);
});

test('parseEvolveLessons reads a bare or fenced top-level JSON array', () => {
  assert.deepEqual(parseEvolveLessons('[{"when":["php"]},{"when":["java"]}]'), [
    { when: ['php'] },
    { when: ['java'] },
  ]);
  assert.deepEqual(parseEvolveLessons('Before: [{"a":1}] after'), [{ a: 1 }]);
  assert.deepEqual(parseEvolveLessons('```json\n[{"a":1},{"a":2},{"a":3},{"a":4}]\n```'), [
    { a: 1 },
    { a: 2 },
    { a: 3 },
  ]);
});

/* ============================================================ constants === */

test('exported token sets are frozen and canonical', () => {
  assert.equal(Object.isFrozen(STACK_TOKENS), true);
  assert.equal(Object.isFrozen(CUE_TOKENS), true);
  assert.equal(Object.isFrozen(TACTICS), true);
  assert.equal(STACK_TOKENS.has('php'), true);
  assert.equal(TACTICS.has('weaponize'), true);
  for (const token of STACK_TOKENS) assert.match(token, /^[a-z0-9_]+$/u);
  for (const token of CUE_TOKENS) assert.match(token, /^[a-z0-9_]+$/u);
  for (const token of TACTICS) assert.match(token, /^[a-z0-9_]+$/u);
});
