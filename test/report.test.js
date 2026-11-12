/**
 * Tests for the pure AtkBrain report renderer.
 *
 * The fixture state is built exclusively through `ops.emptyState` + `applyOps`
 * so the test exercises the same shape the Host projection folds from tool
 * results. No real network target or secret is used; the fake secrets exist
 * only to prove they never reach Markdown/JSON/CSV output.
 */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { applyOps, auditOp, edgeOp, emptyState, nodeOp } from '../lib/ops.js';
import { csvEscape, renderReport, suggestedReportName } from '../lib/report.js';
import { nodeId } from '../lib/util.js';

const AT = '2026-10-10T09:00:00.000Z';
const AT_LATER = '2026-10-12T18:30:00.000Z';
const GENERATED_AT = '2026-10-31T12:00:00.000Z';
const CONFIG = Object.freeze({ bulkThresholds: Object.freeze({ pii: 500, financial: 500, regulated: 500, credentials: 50, keys: 1 }) });

const SECRET = 'P@ssw0rd-SUPER-SECRET';
const SECRET_IN_PROBE = 'SECRET-TOKEN-123';
const RAW_EMAIL = 'alice@acme.example';
const RAW_IP = '203.0.113.10';
const INTERNAL_IP = '10.0.0.5';
const SHA_1 = 'a'.repeat(64);
const SHA_2 = 'c'.repeat(64);
const LESSON_APPLIED_KEY = 'a1b2c3d4e5f60718';
const LESSON_UNSAFE_KEY = '0f1e2d3c4b5a6978';
const LESSON_SAFE_IDEA = 'Prefer two independent observation channels before closing an RCE claim';
const LESSON_UNSAFE_TOKENS = ['10.0.0.1', 'http://admin.example/admin', '/admin', 'Sup3rSecret', 'jsmith@acme.example'];

/** `{kind,key}` reference used by edge ops. */
function ref(kind, key) {
  return { kind, key };
}

/** Extract the Markdown slice between two headings. */
function sectionBetween(markdown, start, end) {
  const from = markdown.indexOf(start);
  assert.notEqual(from, -1, `missing section heading: ${start}`);
  const to = end === undefined ? markdown.length : markdown.indexOf(end, from + start.length);
  assert.notEqual(to, -1, `missing section heading: ${end}`);
  return markdown.slice(from, to);
}

/**
 * Synthetic engagement containing host/ip/cidr/service/finding/credential/
 * access/data/evidence/pivot/chain nodes, a merged duplicate, wildcard zones,
 * a validated access path and a verified sensitive-data set.
 */
function buildState() {
  const ids = {
    www: nodeId('host', 'www.acme.example'),
    api: nodeId('host', 'api.acme.example'),
    old: nodeId('host', 'old.acme.example'),
    ipPublic: nodeId('ip', RAW_IP),
    ipInternal: nodeId('ip', INTERNAL_IP),
    data: nodeId('data', 'db:customer_records'),
    access: nodeId('access', 'www.acme.example:user_shell'),
    pivot: nodeId('pivot', 'tunnel:10.0.0.5:22'),
    xss: nodeId('finding', 'finding:xss-search'),
    sqli: nodeId('finding', 'finding:sqli-login'),
    dataExfil: nodeId('finding', 'finding:data-exfil'),
    misconfig: nodeId('finding', 'finding:misconfig'),
    infoLeak: nodeId('finding', 'finding:info-leak'),
    candidate: nodeId('finding', 'finding:open-redirect'),
    fixed: nodeId('finding', 'finding:old-tls'),
    evidence1: nodeId('evidence', 'evidence:repro-001'),
    evidence2: nodeId('evidence', 'evidence:repro-002'),
  };

  let state = emptyState();
  state = applyOps(state, [
    {
      op: 'engagement.set',
      engagement: {
        name: 'Acme External Pentest',
        client: 'Acme Corp',
        authorization: 'SOW-2026-42',
        window: '2026-10-01..2026-10-31',
        mode: 'black-box',
        notes: 'Test engagement; contact security@acme.example',
      },
    },
    {
      op: 'scope.set',
      allow: [
        { type: 'domain', value: 'acme.example' },
        { type: 'ip', value: INTERNAL_IP, ports: [22, 443] },
      ],
      deny: [{ type: 'ip', value: '10.0.0.9' }],
      roe: { maxQps: 5, maxHostsPerAction: 64, maxPortsPerAction: 1024, techniques: ['T0', 'T1', 'T2'] },
      approvedAt: '2026-10-01T00:00:00.000Z',
      approvalId: 'APR-7',
    },
    auditOp('atkbrain_scope', 'scope.set', 'acme.example', { allowCount: 2, denyCount: 1 }),
  ], AT);

  state = applyOps(state, [
    nodeOp('host', 'www.acme.example', 'www.acme.example', {
      fqdn: 'www.acme.example',
      ips: [RAW_IP],
      wildcardStatus: 'explicit',
      realm: 'external',
    }, { status: 'up', tags: ['external'], sources: ['subdomains.txt'], evidenceIds: ['ev_repro_1'] }),
    nodeOp('host', 'api.acme.example', 'api.acme.example', {
      fqdn: 'api.acme.example',
      ips: [INTERNAL_IP],
      wildcardStatus: 'explicit',
      realm: 'internal',
    }, { status: 'up', tags: ['internal'], sources: ['subdomains.txt'] }),
    nodeOp('host', 'random.acme.example', 'random.acme.example', {
      fqdn: 'random.acme.example',
      wildcardStatus: 'suspect',
    }, { status: 'unknown', sources: ['wildcard-probes'] }),
    nodeOp('host', 'old.acme.example', 'old.acme.example', {
      fqdn: 'old.acme.example',
      ip: RAW_IP,
      wildcardStatus: 'explicit',
    }, { status: 'up', sources: ['legacy-export.csv'] }),
    nodeOp('ip', RAW_IP, RAW_IP, { addr: RAW_IP, realm: 'external' }, { status: 'up' }),
    nodeOp('ip', INTERNAL_IP, INTERNAL_IP, { addr: INTERNAL_IP, realm: 'internal' }, { status: 'up' }),
    nodeOp('cidr', '10.0.0.0/24', 'internal range', { realm: 'internal' }, { status: 'known' }),
    nodeOp('wildcard_zone', '*.acme.example', '*.acme.example', {
      cdn: true,
      probes: ['probe-a', 'probe-b', 'probe-c', 'guard'],
      signature: 'same-ip',
    }, { status: 'suspect' }),
    nodeOp('wildcard_zone', '*.old.acme.example', '*.old.acme.example', {
      cdn: false,
      probes: ['guard-1', 'guard-2', 'guard-3'],
      signature: 'random-ip',
    }, { status: 'cleared' }),
    nodeOp('service', 'www.acme.example:443', 'https://www.acme.example:443', {
      port: 443,
      protocol: 'https',
      state: 'open',
      banner: 'nginx/1.25',
    }, { status: 'open', evidenceIds: ['ev_repro_1'] }),
    nodeOp('finding', 'finding:data-exfil', 'Bulk customer data exfiltration', {
      severity: 'medium',
      title: 'Bulk customer data exfiltration',
      impact: { ep: 70, summary: 'Bulk PII exposure' },
      subjectId: ids.data,
      remediation: 'Restrict database egress and rotate the database account.',
    }, { status: 'impacted', verification: 'verified', evidenceIds: ['ev_repro_1'] }),
    nodeOp('finding', 'finding:sqli-login', 'SQL injection in login endpoint', {
      severity: 'high',
      title: 'SQL injection in login endpoint',
      impact: { ep: 85, summary: 'Authentication bypass' },
      subjectId: ids.www,
    }, { status: 'exploited', verification: 'verified', evidenceIds: ['ev_repro_1'] }),
    nodeOp('finding', 'finding:xss-search', 'Reflected XSS, "search" parameter', {
      severity: 'critical',
      title: 'Reflected XSS, "search" parameter',
      cve: ['CVE-2026-0001'],
      cwe: ['CWE-79'],
      impact: { ep: 88, summary: 'Session theft via reflected script' },
      subjectId: ids.www,
      probe: `GET /search?token=${SECRET_IN_PROBE}`,
      remediation: 'Encode reflected output and add a CSP.',
      secondaryVerified: true,
      redteamRating: 'critical',
    }, { status: 'verified', verification: 'verified', evidenceIds: ['ev_repro_1', 'ev_repro_2'] }),
    nodeOp('finding', 'finding:misconfig', 'Security misconfiguration on API', {
      severity: 'high',
      title: 'Security misconfiguration on API',
      impact: { ep: 60, summary: 'Internal API exposure' },
      subjectId: ids.api,
    }, { status: 'verified', verification: 'corroborated', evidenceIds: ['ev_repro_2'] }),
    nodeOp('finding', 'finding:info-leak', 'Verbose error information leak', {
      severity: 'high',
      title: 'Verbose error information leak',
      impact: { ep: 40, summary: 'Stack trace disclosure' },
      subjectId: ids.www,
    }, { status: 'verified', verification: 'verified' }),
    nodeOp('finding', 'finding:open-redirect', 'Open redirect on login', {
      severity: 'low',
      title: 'Open redirect on login',
      impact: { ep: 10, summary: 'Phishing helper' },
      subjectId: ids.www,
      secondaryVerified: false,
      redteamRating: 'low',
      claimGuard: 'unproven-rce',
    }, { status: 'candidate' }),
    nodeOp('finding', 'finding:old-tls', 'Legacy TLS protocol enabled', {
      severity: 'low',
      title: 'Legacy TLS protocol enabled',
      impact: { ep: 5, summary: 'Downgrade risk' },
      subjectId: ids.www,
    }, { status: 'fixed' }),
    nodeOp('credential', 'www.acme.example:jsmith', 'jsmith credential', {
      username: 'jsmith@acme.example',
      secret: SECRET,
      secretMask: 'j***@acme.example',
      secretFp: 'abcd1234',
      kind: 'password',
      privilege: 'user',
      validity: 'valid',
      targetId: ids.www,
    }, { status: 'valid', evidenceIds: ['ev_repro_1'] }),
    nodeOp('access', 'www.acme.example:user_shell', 'user shell on www.acme.example', {
      accessType: 'user_shell',
      privilege: 'user',
      validated: true,
      blastRadius: 'host',
      assetId: ids.www,
    }, { status: 'validated', verification: 'verified', evidenceIds: ['ev_repro_2'] }),
    nodeOp('data', 'db:customer_records', 'Customer records', {
      dataClass: 'pii',
      count: 1234,
      threshold: 500,
      thresholdMet: true,
      subjectId: ids.access,
      samples: [
        {
          fields: ['email', 'phone'],
          masked: { email: 'j***@acme.example', phone: '***1234' },
          hashes: { email: 'abc123', phone: 'def456' },
          rowHash: 'deadbeef',
          raw: { email: RAW_EMAIL, phone: '+1-555-0100' },
        },
        {
          fields: ['email'],
          masked: { email: 'a***@x.example' },
          hashes: { email: 'def456' },
          rowHash: 'cafebabe',
        },
      ],
      hashes: ['sha256:aaa111'],
    }, { status: 'verified', evidenceIds: ['ev_repro_2'] }),
    nodeOp('pivot', 'tunnel:10.0.0.5:22', 'SSH tunnel to internal API', {
      verified: true,
      tunnelType: 'ssh-dynamic',
      localPort: 1080,
      targetId: ids.api,
    }, { status: 'verified', evidenceIds: ['ev_repro_2'] }),
    nodeOp('evidence', 'evidence:repro-001', 'XSS reproduction', {
      path: '.atkbrain/evidence/repro-001.txt',
      mediaType: 'text/plain',
      size: 1234,
      sha256: SHA_1,
      commandHash: 'b'.repeat(32),
      collectedBy: 'atkbrain_probe',
      collectedAt: '2026-10-15T10:00:00.000Z',
      prevHash: '0'.repeat(64),
    }, { status: 'collected' }),
    nodeOp('evidence', 'evidence:repro-002', 'SQLi reproduction', {
      path: '.atkbrain/evidence/repro-002.txt',
      mediaType: 'text/plain',
      size: 2048,
      sha256: SHA_2,
      commandHash: 'd'.repeat(32),
      collectedBy: 'atkbrain_probe',
      collectedAt: '2026-10-16T11:00:00.000Z',
      prevHash: SHA_1,
    }, { status: 'collected' }),
    nodeOp('chain_step', 'chain:subdomains', 'Subdomain enumeration', {
      chainId: 'chain-initial',
      ordinal: 1,
      stage: 'recon',
    }, { status: 'done' }),
    nodeOp('chain_step', 'chain:xss', 'Reflected XSS to session theft', {
      chainId: 'chain-initial',
      ordinal: 2,
      stage: 'initial_access',
      nodeRef: ids.xss,
    }, { status: 'done', evidenceIds: ['ev_repro_1'] }),
    nodeOp('chain_step', 'chain:pivot', 'SSH pivot into internal network', {
      chainId: 'chain-initial',
      ordinal: 3,
      stage: 'lateral_movement',
      nodeRef: ids.pivot,
    }, { status: 'done', evidenceIds: ['ev_repro_2'] }),
    nodeOp('loop', 'acme.example/loop', 'autonomous loop: acme.example', {
      objective: 'Reach validated customer-data access through the external web tier',
      objectiveType: 'impact',
      phase: 'running',
      round: 7,
      maxRounds: 40,
      goalPhase: 'active',
      activation: 'armed',
      ring: 2,
      allowedRing: 2,
      noProgressRounds: 1,
      emptyRounds: 0,
      stopReason: null,
      autoContinue: true,
      appliedLessonKeys: [LESSON_APPLIED_KEY, 'missing-lesson-key'],
      usedLessonKeys: [LESSON_UNSAFE_KEY],
      startedAt: '2026-10-16T09:00:00.000Z',
      lastStepAt: '2026-10-16T12:00:00.000Z',
    }, { status: 'running' }),
    nodeOp('supervision', 'acme.example/supervision/round_plan/7/plan01', 'supervision round_plan r7', {
      type: 'round_plan',
      round: 7,
      verdict: 'verify',
      source: 'deterministic',
      diagnosis: 'Unverified high/critical candidate is present; verification gate is authoritative.',
      nextPlan: 'Verify the high/critical candidates and obtain independent secondary confirmation.',
      mustIntents: ['tsk_verify_1'],
      confidence: 0.6,
      createdAt: '2026-10-16T10:00:00.000Z',
      findingKey: null,
      secondaryVerdict: null,
    }, { status: 'recorded' }),
    nodeOp('supervision', 'acme.example/supervision/finding_verification/7/ver01', 'supervision finding_verification r7', {
      type: 'finding_verification',
      round: 7,
      verdict: 'verified',
      source: 'ai-subagent',
      diagnosis: 'Independent verifier reproduced the reflected marker with a unique nonce.',
      nextPlan: 'Escalate the verified XSS toward session theft and data proof.',
      mustIntents: ['tsk_escalate_1'],
      confidence: 0.88,
      createdAt: '2026-10-16T11:00:00.000Z',
      findingKey: ids.xss,
      secondaryVerdict: 'verified',
      secondaryMode: 'network',
    }, { status: 'recorded' }),
    nodeOp('supervision', 'acme.example/supervision/rating/7/rate01', 'supervision rating r7', {
      type: 'rating',
      round: 7,
      verdict: 'critical',
      source: 'deterministic',
      diagnosis: 'Rating rubric matched execution/admin/bulk impact evidence.',
      nextPlan: 'Proceed to impact proof and collect data evidence.',
      mustIntents: ['tsk_collect_1'],
      confidence: 0.7,
      createdAt: '2026-10-16T12:00:00.000Z',
      findingKey: ids.sqli,
      secondaryVerdict: 'high',
      secondaryMode: 'evidence',
    }, { status: 'recorded' }),
    nodeOp('intent', 'acme.example/intent/6/verify01', 'verify reflected XSS', {
      actionType: 'verify_finding',
      actionId: 'tsk_verify_1',
      round: 6,
      targetLabel: 'www.acme.example',
      priority: 72,
      expectedEvidence: { kind: 'reproduction', acceptTest: 'repeatable request/response with hashes' },
      attempts: 2,
      channelCount: 2,
    }, { status: 'completed' }),
    nodeOp('intent', 'acme.example/intent/7/collect01', 'collect customer data evidence', {
      actionType: 'collect_data_evidence',
      actionId: 'tsk_collect_1',
      round: 7,
      targetLabel: 'Customer records',
      priority: 88,
      expectedEvidence: { kind: 'data-evidence', acceptTest: 'COUNT + at most 10 row hashes' },
      attempts: 0,
      channelCount: 1,
    }, { status: 'open' }),
    nodeOp('lesson', `lesson/${LESSON_APPLIED_KEY}`, 'lesson safe verification', {
      lessonKey: LESSON_APPLIED_KEY,
      idea: LESSON_SAFE_IDEA,
      method: 'Attempt timing and body-marker checks, then record evidence before escalating',
      route: 'verify_finding then impact_proof',
      chain: 'verify then impact_proof',
      when: ['high-candidate'],
      do: ['verify-first'],
      avoid: ['single-channel-refutation'],
      confidence: 0.82,
      wins: 5,
      fails: 1,
      uses: 8,
      status: 'active',
      sourceOutcome: 'impact',
    }, { status: 'active' }),
    nodeOp('lesson', `lesson/${LESSON_UNSAFE_KEY}`, 'lesson unsafe target text', {
      lessonKey: LESSON_UNSAFE_KEY,
      idea: 'Test 10.0.0.1 and http://admin.example/admin for exposure',
      method: 'Open http://10.0.0.1/admin with password=Sup3rSecret as jsmith@acme.example',
      route: 'http://10.0.0.1/admin -> /admin',
      chain: 'https://10.0.0.1/admin',
      confidence: 0.4,
      wins: 0,
      fails: 2,
      uses: 3,
      status: 'active',
      sourceOutcome: 'finding',
    }, { status: 'active' }),
    { op: 'node.merge', from: ref('host', 'old.acme.example'), into: ref('host', 'www.acme.example'), reason: 'duplicate CNAME' },
  ], AT);

  state = applyOps(state, [
    edgeOp(ref('host', 'www.acme.example'), ref('service', 'www.acme.example:443'), 'exposes'),
    edgeOp(ref('host', 'www.acme.example'), ref('ip', RAW_IP), 'resolves_to'),
    edgeOp(ref('cidr', '10.0.0.0/24'), ref('ip', INTERNAL_IP), 'contains'),
    edgeOp(ref('finding', 'finding:xss-search'), ref('host', 'www.acme.example'), 'affects'),
    edgeOp(ref('finding', 'finding:sqli-login'), ref('host', 'www.acme.example'), 'affects'),
    edgeOp(ref('finding', 'finding:info-leak'), ref('host', 'www.acme.example'), 'affects'),
    edgeOp(ref('credential', 'www.acme.example:jsmith'), ref('access', 'www.acme.example:user_shell'), 'authenticates_to'),
    edgeOp(ref('access', 'www.acme.example:user_shell'), ref('data', 'db:customer_records'), 'proves'),
    edgeOp(ref('access', 'www.acme.example:user_shell'), ref('pivot', 'tunnel:10.0.0.5:22'), 'pivots_to'),
    edgeOp(ref('pivot', 'tunnel:10.0.0.5:22'), ref('host', 'api.acme.example'), 'reached_via'),
    edgeOp(ref('evidence', 'evidence:repro-001'), ref('finding', 'finding:xss-search'), 'proves'),
    edgeOp(ref('evidence', 'evidence:repro-002'), ref('access', 'www.acme.example:user_shell'), 'proves'),
    auditOp('atkbrain_probe', 'http.check', 'www.acme.example', { status: 200, title: 'Acme login' }, ['ev_repro_1']),
  ], AT_LATER);

  state = applyOps(state, [
    {
      op: 'stats.patch',
      patch: {
        importedArtifacts: 12,
        rawEntries: 120,
        unique: 18,
        collapsed: 102,
        quarantined: 2,
        conflicts: 1,
        wildcardZones: 2,
        suspects: 2,
        stubNodes: 0,
        refused: 1,
      },
    },
    auditOp('atkbrain_ingest', 'stats.patch', 'dedupe', { collapsed: 102, quarantined: 2 }),
  ], AT_LATER);

  return { state, ids };
}

/** A state with enough assets to prove the Markdown table is bounded. */
function buildLargeAssetState() {
  const ops = [
    { op: 'engagement.set', engagement: { name: 'Truncation Test' } },
    { op: 'scope.set', allow: [{ type: 'domain', value: 'example.test' }], deny: [], roe: {} },
  ];
  for (let index = 0; index < 105; index += 1) {
    const label = `h${String(index).padStart(3, '0')}.example.test`;
    ops.push(nodeOp('host', label, label, { fqdn: label, wildcardStatus: 'explicit' }, { status: 'up' }));
  }
  return applyOps(emptyState(), ops, AT);
}

/** Live-node helper mirroring the renderer's merged/aliased exclusion. */
function liveNodesOf(state) {
  return Object.values(state.nodes).filter((node) => state.aliases[node.id] === undefined && node.status !== 'merged');
}

test('renderReport returns markdown/json/csv/summary with correct summary counts', () => {
  const { state, ids } = buildState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });

  assert.deepEqual(Object.keys(report).sort(), ['assetsCsv', 'findingsCsv', 'json', 'markdown', 'summary']);
  assert.equal(typeof report.markdown, 'string');
  assert.equal(typeof report.json, 'string');
  assert.equal(typeof report.assetsCsv, 'string');
  assert.equal(typeof report.findingsCsv, 'string');

  const liveNodes = liveNodesOf(state);
  const liveIds = new Set(liveNodes.map((node) => node.id));
  const liveEdges = Object.values(state.edges).filter((edge) => liveIds.has(edge.from) && liveIds.has(edge.to));

  assert.equal(report.summary.engagementName, 'Acme External Pentest');
  assert.equal(report.summary.nodes, liveNodes.length);
  assert.equal(report.summary.edges, liveEdges.length);
  assert.equal(report.summary.verifiedFindings, 5);
  assert.equal(report.summary.validatedAccess, 1);
  assert.equal(report.summary.verifiedData, 1);
  assert.equal(report.summary.crownPaths, 1);
  assert.equal(report.summary.wildcard, 2);
  assert.equal(typeof report.summary.wildcard, 'number');

  // The merged duplicate contributes no live identity but is still in state.nodes.
  assert.ok(Object.keys(state.nodes).length > liveNodes.length);
  assert.equal(report.summary.nodes, liveNodes.length - 0);
  assert.equal(state.aliases[ids.old], ids.www);
});

test('markdown contains the twelve required sections plus the appendix', () => {
  const { state } = buildState();
  const { markdown } = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });

  const headings = [
    '## 1. Executive Summary',
    '## 2. Authorization, Scope & Methodology',
    '## 3. Asset Inventory & Dedupe',
    '## 4. Verified Findings',
    '## 5. Attack Chains',
    '## 6. Credentials & Access',
    '## 7. Sensitive Data Evidence',
    '## 8. Internal & Lateral Movement',
    '## 9. Remediation',
    '## 10. Evidence Index & Hash Chain',
    '## 11. Autonomous Loop & Supervision',
    '## 12. Evolution Playbook',
    '## Appendix',
  ];
  for (const heading of headings) assert.ok(markdown.includes(heading), `missing heading: ${heading}`);

  assert.equal((markdown.match(/^## \d+\./gmu) ?? []).length, 12);
  assert.ok(markdown.indexOf('## 10. Evidence Index') < markdown.indexOf('## 11. Autonomous Loop'));
  assert.ok(markdown.indexOf('## 11. Autonomous Loop') < markdown.indexOf('## 12. Evolution Playbook'));
  assert.ok(markdown.indexOf('## 12. Evolution Playbook') < markdown.indexOf('## Appendix'));
  assert.ok(markdown.startsWith('# AtkBrain Engagement Report'));
  assert.ok(markdown.includes(GENERATED_AT));
});

test('authorization, scope, dedupe, wildcard and excluded/suspect content is present', () => {
  const { state } = buildState();
  const { markdown } = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });

  const auth = sectionBetween(markdown, '## 2. Authorization', '## 3. Asset Inventory');
  assert.ok(auth.includes('acme.example'));
  assert.ok(auth.includes('10.0.0.9'), 'deny entry must be listed');
  assert.ok(auth.includes('SOW-2026-42'));
  assert.ok(auth.includes('T2'));
  assert.ok(auth.includes('APR-7'));
  assert.ok(auth.includes('Rules of engagement'));

  const assets = sectionBetween(markdown, '## 3. Asset Inventory', '## 4. Verified Findings');
  assert.ok(assets.includes('Collapsed duplicates'));
  assert.ok(assets.includes('Dedupe reduced 120 raw entries to 18 unique identities (85.0% collapsed; 2 quarantined).'));
  assert.ok(assets.includes('Wildcard DNS classification'));
  assert.ok(assets.includes('suspect'));
  assert.ok(assets.includes('random.acme.example'));
  assert.ok(assets.includes('Excluded identities'));

  const appendix = sectionBetween(markdown, '## Appendix');
  assert.ok(appendix.includes('A.1 Excluded assets'));
  assert.ok(appendix.includes('A.2 Suspect assets'));
  assert.ok(appendix.includes('A.3 Audit summary'));
  assert.ok(appendix.includes('old.acme.example'));
  assert.ok(appendix.includes('merged into'));
  assert.ok(appendix.includes('wildcard host'));
  assert.ok(appendix.includes('Refused / out-of-scope actions: 1'));
});

test('findings are ordered by lifecycle, then severity, then impact.ep, then id', () => {
  const { state } = buildState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });

  const lines = report.findingsCsv.trimEnd().split('\r\n');
  assert.equal(lines[0], 'severity,status,title,subject,verification,impact,cve,cwe,evidenceCount,cvss_score,cvss_rating,cvss_vector');
  const rows = lines.slice(1);
  assert.equal(rows.length, 7);
  assert.deepEqual(rows.map((line) => line.split(',').slice(0, 2)), [
    ['medium', 'impacted'],
    ['high', 'exploited'],
    ['critical', 'verified'],
    ['high', 'verified'],
    ['high', 'verified'],
    ['low', 'candidate'],
    ['low', 'fixed'],
  ]);

  // Impact EP ordering inside the same lifecycle + severity.
  const misconfigIndex = report.findingsCsv.indexOf('Security misconfiguration on API');
  const infoLeakIndex = report.findingsCsv.indexOf('Verbose error information leak');
  assert.ok(misconfigIndex !== -1 && infoLeakIndex !== -1);
  assert.ok(misconfigIndex < infoLeakIndex, 'EP 60 must precede EP 40');

  const findingsSection = sectionBetween(report.markdown, '## 4. Verified Findings', '## 5. Attack Chains');
  assert.ok(findingsSection.includes('Bulk customer data exfiltration'));
  assert.ok(findingsSection.includes('SQL injection in login endpoint'));
  assert.ok(findingsSection.includes('Reflected XSS, "search" parameter'));
  assert.ok(findingsSection.includes('Security misconfiguration on API'));
  assert.ok(findingsSection.includes('Verbose error information leak'));
  assert.ok(!findingsSection.includes('Open redirect on login'), 'candidate findings stay out of the verified section');
  assert.ok(!findingsSection.includes('Legacy TLS protocol enabled'), 'fixed findings stay out of the verified section');
  assert.ok(report.markdown.includes('Candidate (1)'));
});

test('crown path and explicit chain steps appear in markdown and JSON', () => {
  const { state, ids } = buildState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });
  const json = JSON.parse(report.json);

  const chainsSection = sectionBetween(report.markdown, '## 5. Attack Chains', '## 6. Credentials & Access');
  assert.ok(chainsSection.includes('Milestone paths'));
  assert.ok(chainsSection.includes('Customer records'));
  assert.ok(chainsSection.includes('proves'));
  assert.ok(chainsSection.includes('chain-initial'));
  assert.ok(chainsSection.includes('SSH pivot into internal network'));

  assert.equal(json.chains.crown.length, 1);
  const crown = json.chains.crown[0];
  assert.equal(crown.targetId, ids.data);
  assert.equal(crown.targetLabel, 'Customer records');
  assert.equal(crown.steps.length, 1);
  assert.equal(crown.steps[0].kind, 'proves');
  assert.equal(crown.steps[0].from, ids.access);
  assert.equal(crown.steps[0].to, ids.data);

  assert.equal(json.chains.explicit.length, 1);
  assert.equal(json.chains.explicit[0].chainId, 'chain-initial');
  assert.deepEqual(json.chains.explicit[0].steps.map((step) => step.ordinal), [1, 2, 3]);
  assert.equal(json.chains.explicit[0].steps[2].stage, 'lateral_movement');
});

test('JSON export is a re-importable atkbrain/1 graph document', () => {
  const { state } = buildState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });
  const json = JSON.parse(report.json);

  assert.equal(json.schema, 'atkbrain/1');
  assert.equal(json.generatedAt, GENERATED_AT);
  assert.deepEqual(json.summary, report.summary);
  assert.ok(Array.isArray(json.nodes));
  assert.ok(Array.isArray(json.edges));
  assert.ok(Array.isArray(json.frontier));
  assert.equal(json.nodes.length, report.summary.nodes);
  assert.equal(json.edges.length, report.summary.edges);

  const nodeIds = json.nodes.map((node) => node.id);
  assert.equal(new Set(nodeIds).size, nodeIds.length, 'node ids must be unique');
  for (const node of json.nodes) {
    assert.equal(typeof node.id, 'string');
    assert.equal(typeof node.kind, 'string');
    assert.equal(typeof node.label, 'string');
    assert.equal(typeof node.status, 'string');
    assert.equal(typeof node.attrs, 'object');
    assert.ok(!Array.isArray(node.attrs));
  }
  const mergedPresent = json.nodes.some((node) => node.key === 'old.acme.example');
  assert.equal(mergedPresent, false, 'merged identities must not appear in the JSON graph');

  for (const edge of json.edges) {
    assert.ok(nodeIds.includes(edge.from), `edge endpoint missing node: ${edge.from}`);
    assert.ok(nodeIds.includes(edge.to), `edge endpoint missing node: ${edge.to}`);
    assert.equal(typeof edge.kind, 'string');
  }

  assert.ok(json.frontier.length > 0);
  for (const action of json.frontier) {
    assert.equal(typeof action.actionId, 'string');
    assert.equal(typeof action.actionType, 'string');
  }

  assert.ok(Array.isArray(json.scope.allow));
  assert.equal(json.scope.allow.length, 2);
  assert.equal(json.scope.deny.length, 1);
  assert.equal(json.scope.allowCount, 2);
  assert.equal(json.scope.approvedAt, '2026-10-01T00:00:00.000Z');
  assert.equal(json.scope.approvalId, 'APR-7');
  assert.deepEqual(json.scope.roe.techniques, ['T0', 'T1', 'T2']);
  assert.equal(json.engagement.name, 'Acme External Pentest');

  const dataNode = json.nodes.find((node) => node.id === nodeId('data', 'db:customer_records'));
  assert.ok(dataNode !== undefined);
  assert.equal(dataNode.attrs.dataClass, 'pii');
  assert.ok(Array.isArray(dataNode.attrs.samples));
  assert.equal(dataNode.attrs.samples.length, 2);
  for (const sample of dataNode.attrs.samples) {
    assert.ok(Object.prototype.hasOwnProperty.call(sample, 'masked'));
    assert.ok(Object.prototype.hasOwnProperty.call(sample, 'hashes'));
    assert.ok(!Object.prototype.hasOwnProperty.call(sample, 'raw'));
  }

  // Loop/supervision/intent/lesson nodes are part of the same public node set.
  for (const kind of ['loop', 'intent', 'supervision', 'lesson']) {
    assert.ok(json.nodes.some((node) => node.kind === kind), `JSON export must include ${kind} nodes`);
  }
  const unsafeLessonNode = json.nodes.find((node) => node.kind === 'lesson' && node.attrs.lessonKey === LESSON_UNSAFE_KEY);
  assert.ok(unsafeLessonNode !== undefined);
  assert.equal(unsafeLessonNode.attrs.idea, '[redacted-lesson]');
});

test('JSON export round-trips through graph-json import semantics', () => {
  const { state } = buildState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });
  const document = JSON.parse(report.json);

  const byId = new Map(document.nodes.map((node) => [node.id, { kind: node.kind, key: node.key }]));
  const ops = document.nodes.map((node) => ({
    op: 'node.upsert',
    kind: node.kind,
    key: node.key,
    label: node.label,
    attrs: node.attrs,
    status: node.status,
    confidence: node.confidence,
    verification: node.verification,
    tags: node.tags,
    sources: node.sources,
    evidenceIds: node.evidenceIds,
    firstSeen: node.firstSeen,
    lastSeen: node.lastSeen,
  }));
  for (const edge of document.edges) {
    ops.push({
      op: 'edge.upsert',
      from: byId.get(edge.from),
      to: byId.get(edge.to),
      kind: edge.kind,
      confidence: edge.confidence,
      attrs: edge.attrs ?? {},
      evidenceIds: edge.evidenceIds ?? [],
    });
  }

  const reimported = applyOps(emptyState(), ops, AT_LATER);
  assert.equal(liveNodesOf(reimported).length, document.nodes.length, 'every exported node must be re-importable');
  assert.equal(Object.keys(reimported.edges).length, document.edges.length, 'every exported edge must be re-importable');

  const again = renderReport(reimported, { generatedAt: GENERATED_AT, config: CONFIG });
  assert.equal(again.summary.nodes, report.summary.nodes);
  assert.equal(again.summary.verifiedFindings, report.summary.verifiedFindings);
  assert.equal(again.summary.crownPaths, report.summary.crownPaths);
  const againDocument = JSON.parse(again.json);
  assert.deepEqual(againDocument.nodes.map((node) => node.id), document.nodes.map((node) => node.id));
});

test('evidence index carries path/sha256 and the audit hash chain is intact', () => {
  const { state } = buildState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });

  const evidenceSection = sectionBetween(report.markdown, '## 10. Evidence Index & Hash Chain', '## 11. Autonomous Loop & Supervision');
  assert.ok(evidenceSection.includes('.atkbrain/evidence/repro-001.txt'));
  assert.ok(evidenceSection.includes(SHA_1));
  assert.ok(evidenceSection.includes(SHA_2));
  assert.ok(evidenceSection.includes('XSS reproduction'));
  assert.ok(evidenceSection.includes('sha256sum'));
  assert.ok(evidenceSection.includes(`| Retained audit entries | ${state.audit.length} |`));
  assert.ok(evidenceSection.includes('| Hash checks failed | 0 |'));
  assert.ok(evidenceSection.includes('| Prev-hash links failed | 0 |'));
  assert.ok(evidenceSection.includes('| Chain status | intact |'));
  const tailHash = state.audit[state.audit.length - 1].hash;
  assert.ok(evidenceSection.includes(tailHash), 'audit chain tail hash must appear in the report');
});

test('no raw secrets, credentials or PII rows leak into any output format', () => {
  const { state } = buildState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });
  const json = JSON.parse(report.json);

  const outputs = [report.markdown, report.json, report.assetsCsv, report.findingsCsv];
  for (const output of outputs) {
    assert.ok(!output.includes(SECRET), 'raw credential secret leaked');
    assert.ok(!output.includes(SECRET_IN_PROBE), 'raw token leaked from a finding attribute');
    assert.ok(!output.includes(RAW_EMAIL), 'raw PII row leaked');
    assert.ok(!output.includes('+1-555-0100'), 'raw phone row leaked');
    assert.ok(!output.includes('P@ssw0rd'));
    assert.ok(!output.includes('Sup3rSecret'), 'raw lesson secret leaked');
    assert.ok(!output.includes('10.0.0.1'), 'raw lesson target IPv4 leaked');
    assert.ok(!output.includes('http://admin.example/admin'), 'raw lesson URL leaked');
  }

  const credential = json.nodes.find((node) => node.id === nodeId('credential', 'www.acme.example:jsmith'));
  assert.ok(credential !== undefined);
  for (const key of ['secret', 'password', 'token', 'apiKey', 'api_key', 'access_key', 'private_key', 'value']) {
    assert.equal(Object.prototype.hasOwnProperty.call(credential.attrs, key), false, `credential.attrs.${key} must be removed`);
  }
  assert.equal(credential.attrs.secretMask, 'j***@acme.example');
  assert.equal(credential.attrs.secretFp, 'abcd1234');
  assert.equal(credential.attrs.username, 'jsmith@acme.example');

  const finding = json.nodes.find((node) => node.id === nodeId('finding', 'finding:xss-search'));
  assert.ok(finding !== undefined);
  assert.ok(String(finding.attrs.probe).includes('[redacted]'));
  assert.ok(!String(finding.attrs.probe).includes(SECRET_IN_PROBE));

  const dataNode = json.nodes.find((node) => node.id === nodeId('data', 'db:customer_records'));
  assert.ok(dataNode !== undefined);
  const dataSamples = JSON.stringify(dataNode.attrs.samples);
  assert.ok(!dataSamples.includes(RAW_EMAIL));
  assert.ok(dataSamples.includes('masked'));
  assert.ok(dataSamples.includes('hashes'));

  // The masked sample still renders in the human report (fields + masked values + hash).
  const dataSection = sectionBetween(report.markdown, '## 7. Sensitive Data Evidence', '## 8. Internal & Lateral Movement');
  assert.ok(dataSection.includes('1k–4.9k'), 'count must be banded');
  assert.ok(dataSection.includes('j***@acme.example'));
  assert.ok(dataSection.includes('deadbeef'));
  assert.ok(dataSection.includes('threshold'));
});

test('CSV output uses RFC 4180 escaping and correct row counts', () => {
  const { state } = buildState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });
  const live = liveNodesOf(state);
  const assetCount = live.filter((node) => node.kind === 'host' || node.kind === 'ip').length;
  const findingCount = live.filter((node) => node.kind === 'finding').length;

  assert.equal(report.assetsCsv.split('\r\n')[0], 'id,kind,label,status,wildcardStatus,services,findings,sourceCount');
  assert.equal(report.assetsCsv.trimEnd().split('\r\n').length, assetCount + 1);
  assert.ok(report.assetsCsv.endsWith('\r\n'));

  const lines = report.findingsCsv.trimEnd().split('\r\n');
  assert.equal(lines.length, findingCount + 1);
  assert.ok(report.findingsCsv.endsWith('\r\n'));
  assert.ok(
    report.findingsCsv.includes('"Reflected XSS, ""search"" parameter"'),
    'commas and quotes in a title must be RFC 4180 escaped',
  );

  const wwwRow = report.assetsCsv.split('\r\n').find((line) => line.includes(',host,www.acme.example,'));
  assert.ok(wwwRow !== undefined, 'www host row missing from assets CSV');
  const columns = wwwRow.split(',');
  assert.equal(columns[2], 'www.acme.example');
  assert.equal(columns[3], 'up');
  assert.equal(columns[4], 'explicit');
  assert.equal(columns[5], '1', 'www exposes one service');
  assert.equal(columns[6], '5', 'five findings reference www');
  assert.equal(columns[7], '2', 'www inherits the merged duplicate source');

  assert.equal(csvEscape('plain'), 'plain');
  assert.equal(csvEscape('a,b'), '"a,b"');
  assert.equal(csvEscape('he said "hi"'), '"he said ""hi"""');
  assert.equal(csvEscape('line\r\nbreak'), '"line\r\nbreak"');
  assert.equal(csvEscape(null), '');
  assert.equal(csvEscape(undefined), '');
  assert.equal(csvEscape(42), '42');
  assert.equal(csvEscape(true), 'true');
});

test('rendering is deterministic and generatedAt is the only varying input', () => {
  const { state } = buildState();
  const first = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });
  const second = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });
  assert.deepEqual(first, second);

  const later = renderReport(state, { generatedAt: '2026-11-01T00:00:00.000Z', config: CONFIG });
  assert.notEqual(later.markdown, first.markdown);
  assert.equal(later.assetsCsv, first.assetsCsv);
  assert.equal(later.findingsCsv, first.findingsCsv);
  assert.deepEqual(later.summary, first.summary);

  const firstJson = JSON.parse(first.json);
  const laterJson = JSON.parse(later.json);
  laterJson.generatedAt = firstJson.generatedAt;
  assert.deepEqual(laterJson, firstJson);

  const normalizedMarkdown = later.markdown.split('2026-11-01T00:00:00.000Z').join(GENERATED_AT);
  assert.equal(normalizedMarkdown, first.markdown);
});

test('suggestedReportName produces a safe deterministic filename', () => {
  const name = suggestedReportName({ name: 'Acme / External: Pentest!' }, '2026-10-31T12:00:00.000Z');
  assert.equal(name, 'atkbrain-Acme-External-Pentest-2026-10-31.md');
  assert.ok(!/[\\/:*?"<>|]/u.test(name));
  assert.equal(name, suggestedReportName({ name: 'Acme / External: Pentest!' }, '2026-10-31T12:00:00.000Z'));
  assert.equal(suggestedReportName(null, '2026-10-31'), 'atkbrain-engagement-2026-10-31.md');
  assert.equal(suggestedReportName({ client: 'Acme Corp' }, 'not-a-date'), 'atkbrain-Acme-Corp-undated.md');
  assert.equal(suggestedReportName('', '2026-13-99'), 'atkbrain-engagement-2026-13-99.md');
  assert.ok(suggestedReportName({ name: 'a'.repeat(400) }, '2026-10-31').length < 120);
});

test('empty state renders every section with zero counts', () => {
  const report = renderReport(emptyState(), { generatedAt: '2026-01-01T00:00:00.000Z' });
  const json = JSON.parse(report.json);

  assert.equal(report.summary.engagementName, 'Unnamed engagement');
  assert.equal(report.summary.nodes, 0);
  assert.equal(report.summary.edges, 0);
  assert.equal(report.summary.verifiedFindings, 0);
  assert.equal(report.summary.validatedAccess, 0);
  assert.equal(report.summary.verifiedData, 0);
  assert.equal(report.summary.crownPaths, 0);
  assert.equal(report.summary.wildcard, 0);
  assert.equal(json.nodes.length, 0);
  assert.equal(json.edges.length, 0);
  assert.equal((report.markdown.match(/^## \d+\./gmu) ?? []).length, 12);
  assert.ok(report.markdown.includes('## Appendix'));
  assert.ok(report.markdown.includes('no authorized scope is recorded'));
  assert.ok(report.markdown.includes('No `loop` node is recorded'));
  assert.ok(report.markdown.includes('No qualifying high/critical/validated impact outcome was available for distillation'));
  assert.ok(report.markdown.includes('candidate, medium and low findings are not distilled'));
  assert.equal(report.assetsCsv.trimEnd(), 'id,kind,label,status,wildcardStatus,services,findings,sourceCount');
  assert.equal(report.findingsCsv.trimEnd(), 'severity,status,title,subject,verification,impact,cve,cwe,evidenceCount,cvss_score,cvss_rating,cvss_vector');
  assert.equal(report.assetsCsv, 'id,kind,label,status,wildcardStatus,services,findings,sourceCount\r\n');
});

test('self-team brief and AI-distilled skills appear in markdown and JSON', () => {
  let state = buildState().state;
  state = applyOps(state, [
    nodeOp('self_team', 'selfteam/supervision', 'self-supervision team', {
      type: 'supervision', mode: 'subagents', members: [{ role: 'supervisor', name: 'atkbrain-supervisor' }],
      lastBriefAt: AT, lastDistillAt: null, skillCount: 0, skillDir: '/tmp/atkbrain-skills',
    }, { status: 'active' }),
    nodeOp('self_team', 'selfteam/evolution', 'self-evolution team', {
      type: 'evolution', mode: 'subagents', members: [{ role: 'distiller', name: 'atkbrain-evolver' }],
      lastBriefAt: null, lastDistillAt: AT, skillCount: 1, skillDir: '/tmp/atkbrain-skills',
    }, { status: 'active' }),
    nodeOp('supervision', 'supervision:self-team:1', 'self-team brief round 1', {
      type: 'self_team_brief', round: 1, verdict: 'hold', source: 'ai-subagent',
      progressSummary: 'Verified one high finding and a user shell.',
      gained: ['1 verified high finding', '1 validated user shell'],
      missed: ['admin proof is missing'],
      advice: 'Escalate the shell before enumeration.',
      antiDeadlock: ['ban the repeated XSS payload'],
      recommendedNext: ['prove the access objective'],
      deadlockRisk: 'low', artifactPath: '.atkbrain/evidence/selfteam-brief-1.json',
    }, { status: 'recorded' }),
    nodeOp('skill', 'skill:abc123', 'Authentication boundary bypass', {
      skillKey: 'abc123',
      name: 'Authentication boundary bypass',
      summary: 'Generalized auth-boundary bypass path.',
      when: ['php', 'auth_surface'],
      do: ['access_control'],
      avoid: ['content_enum'],
      route: 'entry → vuln(auth_bypass) → foothold(lateral) → goal(impact)',
      preconditions: ['role boundary is presentation-only'],
      steps: ['map boundary', 'verify with a second identity'],
      verification: ['reproduce twice and hash evidence'],
      pitfalls: ['do not claim shell from a version string'],
      confidence: 0.74,
      status: 'active',
      path: '/tmp/atkbrain-skills/auth-boundary/SKILL.md',
      sourceOutcome: 'impact',
    }, { status: 'active', confidence: 0.74 }),
  ], AT_LATER);
  const result = renderReport(state, { config: CONFIG, generatedAt: GENERATED_AT });
  assert.match(result.markdown, /### Self-team brief/);
  assert.match(result.markdown, /Verified one high finding and a user shell/);
  assert.match(result.markdown, /### Distilled path skills/);
  assert.match(result.markdown, /Authentication boundary bypass/);
  assert.match(result.markdown, /auth_bypass/);
  const exported = JSON.parse(result.json);
  const skill = exported.nodes.find((node) => node.kind === 'skill');
  assert.ok(skill, 'skill node missing from graph JSON');
  assert.equal(skill.attrs.route, 'entry → vuln(auth_bypass) → foothold(lateral) → goal(impact)');
  const selfTeam = exported.nodes.find((node) => node.kind === 'self_team');
  assert.ok(selfTeam, 'self_team node missing from graph JSON');
});

test('sections 11 and 12 expose the autonomous loop, supervision, intents and evolution lessons', () => {
  const { state } = buildState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });
  const markdown = report.markdown;
  const loopSection = sectionBetween(markdown, '## 11. Autonomous Loop & Supervision', '## 12. Evolution Playbook');
  const evoSection = sectionBetween(markdown, '## 12. Evolution Playbook', '## Appendix');

  // §11 loop state table.
  assert.ok(loopSection.includes('### Loop state'));
  for (const expected of [
    'running',
    'Reach validated customer-data access',
    'impact',
    '7 / 40',
    'active',
    'armed',
    '| ring | 2 |',
    'noProgressRounds',
    'autoContinue',
  ]) {
    assert.ok(loopSection.includes(expected), `loop state missing: ${expected}`);
  }

  // §11 supervision, intents and verification/rating rows.
  for (const expected of [
    'round_plan',
    'finding_verification',
    'rating',
    'Unverified high/critical candidate is present',
    'tsk_verify_1',
    'verify_finding',
    'collect_data_evidence',
    'secondaryVerified=yes',
    'unproven-rce',
    'redteamRating',
  ]) {
    assert.ok(loopSection.includes(expected), `loop/supervision content missing: ${expected}`);
  }

  // §12 distillation gate + lesson rows.
  assert.ok(evoSection.includes('### Distillation gate'));
  assert.ok(evoSection.includes('Validated access paths'));
  assert.ok(evoSection.includes('### Applied lessons'));
  assert.ok(evoSection.includes('lessonKey'));
  assert.ok(evoSection.includes(LESSON_APPLIED_KEY));
  assert.ok(evoSection.includes(LESSON_UNSAFE_KEY));
  assert.ok(evoSection.includes(LESSON_SAFE_IDEA));
  assert.ok(evoSection.includes('verify_finding then impact_proof'));
  assert.ok(evoSection.includes('0.82'));
  assert.ok(evoSection.includes('missing-lesson-key'));
  assert.ok(evoSection.includes('[redacted-lesson]'), 'unsafe lesson text must print the redaction marker');
  for (const token of LESSON_UNSAFE_TOKENS) {
    assert.ok(!evoSection.includes(token), `unsafe lesson token leaked into §12: ${token}`);
  }

  // The JSON node set carries the same new kinds with lesson text redacted.
  const json = JSON.parse(report.json);
  for (const kind of ['loop', 'intent', 'supervision', 'lesson']) {
    assert.ok(json.nodes.some((node) => node.kind === kind), `JSON must include ${kind} nodes`);
  }
  const unsafeLesson = json.nodes.find((node) => node.kind === 'lesson' && node.attrs.lessonKey === LESSON_UNSAFE_KEY);
  assert.ok(unsafeLesson !== undefined);
  for (const key of ['idea', 'method', 'route', 'chain']) {
    assert.equal(unsafeLesson.attrs[key], '[redacted-lesson]', `lesson.${key} must be redacted in JSON`);
  }
  const safeLesson = json.nodes.find((node) => node.kind === 'lesson' && node.attrs.lessonKey === LESSON_APPLIED_KEY);
  assert.ok(safeLesson !== undefined);
  assert.equal(safeLesson.attrs.idea, LESSON_SAFE_IDEA);
  for (const token of ['10.0.0.1', 'http://admin.example/admin', 'Sup3rSecret']) {
    assert.ok(!report.json.includes(token), `unsafe lesson token leaked into JSON: ${token}`);
  }
});

test('bounded Markdown tables mention truncation while JSON stays complete', () => {
  const state = buildLargeAssetState();
  const report = renderReport(state, { generatedAt: GENERATED_AT, config: CONFIG });
  const json = JSON.parse(report.json);

  assert.equal(report.summary.nodes, 105);
  assert.equal(json.nodes.length, 105, 'JSON must contain every live node');
  assert.ok(report.markdown.includes('Showing 100 of 105 assets'));
  assert.ok(report.markdown.includes('The JSON export carries the complete live node/edge set'));
  assert.equal(report.assetsCsv.trimEnd().split('\r\n').length, 106);
});

test('report module performs no file I/O and never reads the wall clock', async () => {
  const source = await readFile(new URL('../lib/report.js', import.meta.url), 'utf8');

  assert.ok(!/Math\.random/u.test(source), 'Math.random must not be used');
  assert.ok(!/Date\.now/u.test(source), 'Date.now must not be used');
  assert.ok(!/new\s+Date\s*\(/u.test(source), 'new Date() must not be used');
  assert.ok(!/from 'node:fs/u.test(source), 'report.js must not import node:fs');
  assert.ok(!/from 'node:fs\/promises'/u.test(source));
  assert.ok(!/process\.env/u.test(source), 'report.js must not read the environment');
  assert.ok(source.includes('export function renderReport'));
  assert.ok(source.includes('export function suggestedReportName'));
  assert.ok(source.includes('export function csvEscape'));
});
