/** CVSS v3.1 integration through atkbrain_record / atkbrain_supervise / report. */
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';

import { apply } from '../index.js';
import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { renderReport } from '../lib/report.js';

const CVSS_98 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const CVSS_61 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';

function createHarness() {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'cvss-it', authorization: 'AUTH-CVSS-1' } },
    { op: 'scope.set', allow: [{ type: 'cidr', value: '10.0.0.0/24', canonical: '10.0.0.0/24' }], deny: [] },
    nodeOp('host', '10.0.0.1', '10.0.0.1', { fqdn: '10.0.0.1', realm: 'internal' }),
  ]);
  const tools = new Map();
  let workspace;
  const ctx = {
    logger: { warn() {}, info() {} },
    sessionProjections: { stateOf: () => state, register: () => () => {} },
    systemPrompt: { section: () => () => {} },
    effect(fn) {
      const dispose = fn();
      return () => { if (typeof dispose === 'function') dispose(); };
    },
    tools: {
      register(definition) { tools.set(definition.name, definition); return () => {}; },
      get(name) { return tools.get(name); },
    },
    get(name) {
      if (name === 'approval') return { async request() { return 'allowed-once'; } };
      return undefined;
    },
  };
  apply(ctx, {
    requireScopeApproval: false,
    requireTunnelApproval: false,
    lessonStore: path.join(os.tmpdir(), `atkbrain-cvss-${process.pid}-${Math.random().toString(36).slice(2)}.jsonl`),
  });
  let counter = 0;
  async function run(name, args) {
    counter += 1;
    const tool = tools.get(name);
    assert.ok(tool, `tool ${name}`);
    const value = await tool.execute(args, {
      agent: { id: 'parent', session: { id: 'parent', header: { cwd: workspace } } },
      callId: `call-${counter}`,
      name,
      signal: new AbortController().signal,
      arguments: args,
    });
    const meta = tool.output.presentationMeta(args, value);
    if (meta !== undefined) state = applyOps(state, meta.ops, meta.at);
    return value;
  }
  return {
    run,
    state: () => state,
    setWorkspace(dir) { workspace = dir; },
  };
}

async function withHarness(fn) {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-cvss-'));
  const harness = createHarness();
  harness.setWorkspace(workspace);
  try {
    return await fn(harness);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

test('record stores a canonical CVSS v3.1 score, vector and NVD severity', async () => {
  await withHarness(async (harness) => {
    const result = await harness.run('atkbrain_record', {
      nodes: [{
        kind: 'finding',
        attrs: {
          template: 'sqli',
          title: 'SQLi in login',
          severity: 'critical',
          subjectKey: '10.0.0.1',
          cvssVector: CVSS_98,
        },
      }],
    });
    assert.match(result.summary, /recorded/i);
    const finding = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    assert.equal(finding.attrs.cvssVector, CVSS_98);
    assert.equal(finding.attrs.cvssScore, 9.8);
    assert.equal(finding.attrs.cvssRating, 'critical');
    assert.equal(finding.attrs.cvssSeverity, 'CRITICAL');
    assert.equal(finding.attrs.cvssSource, 'nvd-cvss31');
    assert.equal(finding.attrs.cvss.baseScore, 9.8);
  });
});

test('record accepts eight CVSS metrics and rejects a score without a vector', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_record', {
      nodes: [{
        kind: 'finding',
        attrs: {
          template: 'xss',
          title: 'Reflected XSS',
          subjectKey: '10.0.0.1',
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
        },
      }],
    });
    const finding = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    assert.equal(finding.attrs.cvssScore, 6.1);
    assert.equal(finding.attrs.cvssVector, CVSS_61);
    assert.equal(finding.attrs.severity, 'medium');

    await assert.rejects(
      () => harness.run('atkbrain_record', {
        nodes: [{ kind: 'finding', attrs: { template: 'manual', title: 'No vector', subjectKey: '10.0.0.1', cvssScore: 9.8 } }],
      }),
      /must be derived from cvssVector/i,
    );
    await assert.rejects(
      () => harness.run('atkbrain_record', {
        nodes: [{
          kind: 'finding',
          attrs: {
            template: 'manual',
            title: 'No impact',
            subjectKey: '10.0.0.1',
            cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' },
          },
        }],
      }),
      /all None/i,
    );
  });
});

test('supervise rate uses CVSS v3.1 and keeps the operational rating visible', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_record', {
      nodes: [{
        kind: 'finding',
        attrs: {
          template: 'rce',
          title: 'Unproven RCE claim',
          severity: 'critical',
          subjectKey: '10.0.0.1',
          evidence: 'version match only; no command execution marker',
        },
      }],
    });
    const finding = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    const result = await harness.run('atkbrain_supervise', {
      action: 'rate',
      findingId: finding.id,
      cvssVector: CVSS_98,
    });
    assert.match(result.summary, /CVSS v3\.1/);
    assert.match(result.summary, /9\.8 CRITICAL/);
    const updated = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    assert.equal(updated.attrs.cvssScore, 9.8);
    assert.equal(updated.attrs.cvssSeverity, 'CRITICAL');
    assert.equal(updated.attrs.redteamRating, 'medium');
    assert.equal(updated.attrs.ratingSource, 'nvd-cvss31');
    assert.match(updated.attrs.ratingRationale, /claim guard caps/i);

    // A later rate call without explicit metrics reuses the stored vector.
    const stored = await harness.run('atkbrain_supervise', { action: 'rate', findingId: finding.id });
    assert.match(stored.summary, /CVSS v3\.1/);
    assert.match(stored.summary, /9\.8 CRITICAL/);
  });
});

test('a finding written without kind still stores the vector and can be queried by its template', async () => {
  await withHarness(async (harness) => {
    const recorded = await harness.run('atkbrain_record', {
      cvssVector: CVSS_61,
      nodes: [{
        template: 'vuln-reflected-xss-sample',
        title: 'Reflected XSS',
        attrs: { severity: 'medium', subjectKey: '10.0.0.1' },
      }],
    });
    assert.match(recorded.summary, /Recorded/i);
    const finding = Object.values(harness.state().nodes).find((node) => node.kind === 'finding' && node.attrs?.stub !== true);
    assert.equal(finding.attrs.cvssVector, CVSS_61);
    const found = await harness.run('atkbrain_query', { action: 'node', key: 'vuln-reflected-xss-sample' });
    assert.match(found.summary, /XSS/);
  });
});

test('an evidence file placed in nodes is not rejected for a missing kind', async () => {
  await withHarness(async (harness) => {
    const result = await harness.run('atkbrain_record', {
      nodes: [{
        label: 'saved page',
        path: '.atkbrain/surface/page.html',
        sha256: 'ab'.repeat(32),
        mediaType: 'text/html',
      }],
    });
    assert.match(result.summary, /Recorded|Warnings/i);
  });
});

test('report includes CVSS score and vector for a rated finding', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_record', {
      nodes: [{
        kind: 'finding',
        attrs: {
          template: 'sqli',
          title: 'SQLi in login',
          severity: 'critical',
          subjectKey: '10.0.0.1',
          status: 'verified',
          cvssVector: CVSS_98,
          proofType: 'poc_replay',
          proofUrl: 'http://10.0.0.1/login',
          proofDetail: 'UNION payload returned the database version; replay response captured.',
          channels: ['status', 'body'],
        },
      }],
    });
    // mark it verified through a second record call so report's verified register includes it
    const finding = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    await harness.run('atkbrain_record', {
      statusChanges: [{
        id: finding.id,
        status: 'verified',
        verification: 'verified',
        proof: {
          proofType: 'poc_replay',
          proofUrl: 'http://10.0.0.1/login',
          proofDetail: 'UNION payload returned the database version; replay response captured.',
          repro: 'GET /login?id=1%20UNION%20SELECT%20version() returned 200 with the DB banner.',
          channels: ['status', 'body'],
        },
      }],
    });
    const report = renderReport(harness.state(), { generatedAt: '2026-10-31T00:00:00.000Z', config: {} });
    assert.match(report.markdown, /CVSS v3\.1 Base vectors/);
    assert.match(report.markdown, /9\.8/);
    assert.match(report.markdown, /CVSS:3\.1\/AV:N\/AC:L\/PR:N\/UI:N\/S:U\/C:H\/I:H\/A:H/);
    assert.match(report.findingsCsv, /cvss_score,cvss_rating,cvss_vector/);
    assert.match(report.findingsCsv, /9\.8,CRITICAL,CVSS:3\.1/);
  });
});
