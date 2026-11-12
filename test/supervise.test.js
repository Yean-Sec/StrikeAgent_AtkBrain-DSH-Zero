/**
 * Autonomous-loop policy + supervisor tests.
 *
 * These modules are pure decisions: graph snapshot/delta metrics, objective
 * tests, stop/stall gates, candidate-intent routing, refutation and rating
 * guards, plan refinement, and the subagent review/verify wrappers. The tests
 * build minimal graph/loop objects by hand and fake the DSH subagent service,
 * so nothing here touches the network or starts a real child agent.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import * as policy from '../lib/loop/policy.js';
import * as supervisor from '../lib/loop/supervisor.js';
import { shortHash } from '../lib/util.js';

const AT = '2026-10-31T00:00:00.000Z';

/* ------------------------------------------------------------------ */
/* Fixtures                                                            */
/* ------------------------------------------------------------------ */

function node(kind, id, status = 'known', attrs = {}) {
  // Graph nodes carry firstSeen/lastSeen at the top level (see ops.js); accept
  // them in the attrs fixture and hoist them so objective recency is testable.
  const { firstSeen, lastSeen, ...rest } = attrs;
  // Strict CVSS fixtures: a raw high/critical label alone is not a vulnerability.
  if (kind === 'finding' && rest.cvssScore === undefined && ['high', 'critical'].includes(String(rest.severity ?? '').toLowerCase())) {
    rest.cvssScore = rest.severity === 'critical' ? 9.8 : 8.1;
    rest.cvssSeverity = rest.severity === 'critical' ? 'CRITICAL' : 'HIGH';
  }
  return {
    id,
    kind,
    key: id,
    label: attrs.title ?? id,
    status,
    attrs: rest,
    ...(firstSeen === undefined ? {} : { firstSeen }),
    ...(lastSeen === undefined ? {} : { lastSeen }),
  };
}

function graph({ nodes = [], edges = [], scope = { allow: [{ type: 'cidr', value: '10.0.0.0/24' }] }, engagement = { name: 'test-engagement' } } = {}) {
  return {
    nodes: Object.fromEntries(nodes.map((entry) => [entry.id, entry])),
    edges: Object.fromEntries(edges.map((entry, index) => [entry.id ?? `edge-${index}`, entry])),
    scope,
    engagement,
  };
}

function loop(attrs = {}, status = 'running') {
  return {
    id: 'loop_1',
    kind: 'loop',
    key: 'loop',
    label: 'autonomous loop',
    status,
    attrs: { round: 1, ...attrs },
  };
}

function action(actionType, targetId, verdict = 'allow', actionId) {
  return {
    actionId: actionId ?? `${actionType}:${targetId}`,
    actionType,
    targetId,
    targetKind: 'finding',
    targetLabel: targetId,
    priority: 50,
    why: ['fixture action'],
    toolClass: 'http',
    expectedEvidence: {},
    risk: 'low',
    params: {},
    scope: { verdict, reason: verdict, allowedIps: [] },
  };
}

function allowedActions(count) {
  return Array.from({ length: count }, (_, index) => action('enumerate_services', `h${index + 1}`));
}

function ctxWithSubagents(startActivation) {
  return {
    get(name) {
      return name === 'subagents' ? { startActivation } : undefined;
    },
  };
}

function verifierCtx(text, { childId = 'verifier-1' } = {}) {
  return ctxWithSubagents(async () => ({
    childId,
    result: Promise.resolve({ output: [{ type: 'text', text }] }),
    dispose: async () => {},
  }));
}

/* ------------------------------------------------------------------ */
/* Classification helpers                                              */
/* ------------------------------------------------------------------ */

test('findingSeverity prefers redteamRating, then severity, then info', () => {
  assert.equal(policy.findingSeverity({ attrs: { redteamRating: 'critical', severity: 'low' } }), 'critical');
  assert.equal(policy.findingSeverity({ attrs: { severity: 'high' } }), 'high');
  assert.equal(policy.findingSeverity({ attrs: {} }), 'info');
  assert.equal(policy.findingSeverity({}), 'info');
  assert.equal(policy.findingSeverity({ attrs: { severity: 'nonsense' } }), 'info');
});

test('finding/access/data/credential predicates respect kind and status', () => {
  const verifiedHigh = node('finding', 'f-verified', 'verified', { severity: 'high', cvssScore: 8.1, cvssSeverity: 'HIGH' });
  const candidateHigh = node('finding', 'f-candidate', 'candidate', { severity: 'critical', cvssScore: 9.8, cvssSeverity: 'CRITICAL' });
  const fixedHigh = node('finding', 'f-fixed', 'fixed', { severity: 'high', cvssScore: 7.5, cvssSeverity: 'HIGH' });
  const lowCandidate = node('finding', 'f-low', 'candidate', { severity: 'low', cvssScore: 3.1, cvssSeverity: 'LOW' });

  assert.equal(policy.isVerifiedFinding(verifiedHigh), true);
  assert.equal(policy.isVerifiedFinding(node('finding', 'f-exploited', 'exploited')), true);
  assert.equal(policy.isVerifiedFinding(candidateHigh), false);
  assert.equal(policy.isVerifiedFinding(node('access', 'a-verified', 'verified')), false);

  assert.equal(policy.isHighCriticalFinding(verifiedHigh), true);
  assert.equal(policy.isHighCriticalFinding(candidateHigh), true);
  assert.equal(policy.isHighCriticalFinding(lowCandidate), false);

  assert.equal(policy.isCandidateHighCritical(candidateHigh), true);
  assert.equal(policy.isCandidateHighCritical(verifiedHigh), false);
  assert.equal(policy.isCandidateHighCritical(fixedHigh), false);
  assert.equal(policy.isCandidateHighCritical(lowCandidate), false);
  assert.equal(policy.isCandidateHighCritical(node('access', 'a-candidate', 'candidate', { severity: 'high' })), false);

  assert.equal(policy.isValidatedAccess(node('access', 'a1', 'validated')), true);
  assert.equal(policy.isValidatedAccess(node('access', 'a2', 'escalated')), true);
  assert.equal(policy.isValidatedAccess(node('access', 'a3', 'obtained')), false);
  assert.equal(policy.isValidatedAccess(node('finding', 'f1', 'validated')), false);

  assert.equal(policy.isVerifiedData(node('data', 'd1', 'verified')), true);
  assert.equal(policy.isVerifiedData(node('data', 'd2', 'partial')), false);
  assert.equal(policy.isVerifiedData(node('finding', 'f2', 'verified')), false);

  assert.equal(policy.isActiveCredential(node('credential', 'c1', 'valid')), true);
  assert.equal(policy.isActiveCredential(node('credential', 'c2', 'untested')), false);
  assert.equal(policy.isActiveCredential(node('access', 'a4', 'valid')), false);
});

/* ------------------------------------------------------------------ */
/* Snapshot, delta and progress counters                               */
/* ------------------------------------------------------------------ */

function richState() {
  return graph({
    nodes: [
      node('host', 'h1'),
      node('service', 's1', 'open'),
      node('webapp', 'w1', 'live'),
      node('evidence', 'e1', 'valid'),
      node('finding', 'f1', 'verified', { severity: 'critical', cvssScore: 9.8, cvssSeverity: 'CRITICAL' }),
      node('finding', 'f2', 'candidate', { severity: 'high', cvssScore: 8.1, cvssSeverity: 'HIGH' }),
      node('finding', 'f3', 'candidate', { severity: 'low', cvssScore: 3.1, cvssSeverity: 'LOW' }),
      node('finding', 'f4', 'merged', { severity: 'high', cvssScore: 8.1, cvssSeverity: 'HIGH' }),
      node('access', 'a1', 'validated', { kind: 'user_shell', privilege: 'user' }),
      node('access', 'a2', 'escalated', { kind: 'root_shell', privilege: 'root' }),
      node('data', 'd1', 'verified'),
      node('credential', 'c1', 'valid', { used: false }),
      node('credential', 'c2', 'valid', { used: true }),
      node('credential', 'c3', 'invalid'),
      node('task', 't1', 'completed', { actionType: 'subagent_batch' }),
      node('task', 't2', 'artifact_ready', { actionType: 'subagent_batch' }),
      node('intent', 'i1', 'open'),
      node('intent', 'i2', 'claimed'),
      node('intent', 'i3', 'refuted'),
    ],
    edges: [
      { id: 'edge-1', from: 'h1', to: 's1', kind: 'exposes' },
      { id: 'edge-2', from: 's1', to: 'w1', kind: 'exposes' },
    ],
  });
}

test('snapshotGraph counts live nodes and excludes merged ones', () => {
  const snapshot = policy.snapshotGraph(richState());

  assert.equal(snapshot.nodes, 18); // 19 nodes minus the merged finding
  assert.equal(snapshot.edges, 2);
  assert.equal(snapshot.services, 1);
  assert.equal(snapshot.webapps, 1);
  assert.equal(snapshot.evidence, 1);
  assert.equal(snapshot.findings, 3);
  assert.equal(snapshot.verifiedFindings, 1);
  assert.equal(snapshot.highCriticalVerified, 1);
  assert.equal(snapshot.candidateHighCritical, 1);
  assert.equal(snapshot.validatedAccess, 2);
  assert.equal(snapshot.escalatedAccess, 1);
  assert.equal(snapshot.verifiedData, 1);
  assert.equal(snapshot.validCredentials, 2);
  assert.equal(snapshot.unusedCredentials, 1);
  assert.equal(snapshot.crownJewels, 2); // verified data + escalated root access
  assert.equal(snapshot.teamMerged, 1);
  assert.equal(snapshot.teamReady, 1);
  assert.equal(snapshot.openIntents, 2);
  assert.equal(snapshot.claimedIntents, 1);
  assert.equal(snapshot.refutedIntents, 1);
});

test('zeroSnapshot mirrors the snapshot shape with all-zero counters', () => {
  const zero = policy.zeroSnapshot();
  assert.deepEqual(zero, policy.snapshotGraph(graph()));
  assert.equal(Object.keys(zero).length, 20);
});

test('computeRoundDelta classifies quality, weak and no progress', () => {
  const empty = policy.snapshotGraph(graph());
  const hostOnly = policy.snapshotGraph(graph({ nodes: [node('host', 'h1')] }));
  const verifiedFinding = policy.snapshotGraph(graph({ nodes: [node('finding', 'f1', 'verified', { severity: 'high' })] }));
  const service = policy.snapshotGraph(graph({ nodes: [node('service', 's1', 'open')] }));

  const none = policy.computeRoundDelta(empty, empty);
  assert.equal(none.none, true);
  assert.equal(none.weakGain, false);
  assert.equal(none.qualityGain, false);

  const weak = policy.computeRoundDelta(empty, hostOnly);
  assert.equal(weak.newNodes, 1);
  assert.equal(weak.weakGain, true);
  assert.equal(weak.qualityGain, false);
  assert.equal(weak.none, false);

  const quality = policy.computeRoundDelta(empty, verifiedFinding);
  assert.equal(quality.newVerifiedFindings, 1);
  assert.equal(quality.qualityGain, true);
  assert.equal(quality.weakGain, false);

  assert.equal(policy.computeRoundDelta(empty, service).qualityGain, true);
  assert.equal(policy.computeRoundDelta(undefined, undefined).none, true);
});

test('computeRoundDelta clamps negative movement to zero', () => {
  const before = policy.snapshotGraph(graph({
    nodes: [
      node('service', 's1', 'open'),
      node('service', 's2', 'open'),
      node('finding', 'f1', 'verified', { severity: 'high' }),
    ],
  }));
  const after = policy.snapshotGraph(graph({ nodes: [node('service', 's1', 'open')] }));

  const delta = policy.computeRoundDelta(before, after);
  assert.equal(delta.newServices, 0);
  assert.equal(delta.newVerifiedFindings, 0);
  assert.equal(delta.newNodes, 0);
  assert.equal(delta.qualityGain, false);
  assert.equal(delta.none, true);
});

test('progressUpdate resets counters on quality gain', () => {
  const current = graph({ nodes: [node('finding', 'f1', 'verified', { severity: 'high' })] });
  const result = policy.progressUpdate(
    loop({ latestSnapshot: policy.zeroSnapshot(), noProgressRounds: 2, emptyRounds: 4 }),
    current,
    {},
  );

  assert.equal(result.delta.qualityGain, true);
  assert.equal(result.noProgressRounds, 0);
  assert.equal(result.emptyRounds, 0);
  assert.equal(result.promoted, false);
  assert.equal(result.ring, 1);
  assert.deepEqual(result.snapshot, policy.snapshotGraph(current));
});

test('progressUpdate increments no-progress and empty counters without quality gain', () => {
  const result = policy.progressUpdate(
    loop({ latestSnapshot: policy.zeroSnapshot(), noProgressRounds: 2, emptyRounds: 1 }),
    graph(),
    {},
  );

  assert.equal(result.delta.qualityGain, false);
  assert.equal(result.delta.none, true);
  assert.equal(result.noProgressRounds, 3);
  assert.equal(result.emptyRounds, 2);
  assert.equal(result.promoted, false);
});

test('progressUpdate does not promote the scan ring', () => {
  const result = policy.progressUpdate(
    loop({ ring: 1, emptyRounds: 2, latestSnapshot: policy.zeroSnapshot() }),
    graph(),
    {},
  );

  assert.equal(result.emptyRounds, 3);
  assert.equal(result.ring, 1);
  assert.equal(result.promoted, false);
  assert.equal(result.noProgressRounds, 1);
});

test('nextRing stays on ring 1', () => {
  assert.deepEqual(policy.nextRing(loop({ ring: 1, emptyRounds: 2 }), {}), { ring: 1, promoted: false, allowedRing: 1 });
  assert.deepEqual(policy.nextRing(loop({ ring: 1, emptyRounds: 3 }), {}), { ring: 1, promoted: false, allowedRing: 1 });
  assert.deepEqual(policy.nextRing(loop({ ring: 2, emptyRounds: 4 }), {}), { ring: 1, promoted: false, allowedRing: 1 });
  assert.deepEqual(policy.nextRing(loop({ ring: 3, emptyRounds: 99 }), {}), { ring: 1, promoted: false, allowedRing: 1 });
  assert.equal(policy.nextRing(loop({ ring: 1, emptyRounds: 1 }), { loopSpiralPromoteRounds: 1 }).ring, 1);
  assert.equal(policy.nextRing(loop({}), {}).ring, 1);
  assert.equal(policy.nextRing(loop({ ring: 0 }), {}).ring, 1);
});

test('scanProfile clamps the ring and the port budget', () => {
  const ring1 = policy.scanProfile(1, {});
  assert.equal(ring1.ring, 1);
  assert.deepEqual(ring1.ports, [22, 80, 443, 8080, 8443]);
  assert.equal(ring1.portSpec, '22,80,443,8080,8443');
  assert.equal(ring1.wordlistTier, 'small');

  const ring2 = policy.scanProfile(2, {});
  assert.deepEqual(ring2.ports, ring1.ports);
  assert.equal(ring2.wordlistTier, 'small');

  const ring3 = policy.scanProfile(3, {});
  assert.deepEqual(ring3.ports, ring1.ports);
  assert.equal(ring3.wordlistTier, 'small');

  assert.equal(policy.scanProfile(99, {}).ring, 1);
  assert.equal(policy.scanProfile(0, {}).ring, 1);
  assert.equal(policy.scanProfile(undefined, {}).ring, 1);

  const capped = policy.scanProfile(1, { maxPortsPerCall: 2 });
  assert.deepEqual(capped.ports, [22, 80]);
  assert.equal(capped.portSpec, '22,80');
  assert.deepEqual(policy.scanProfile(1, { maxPortsPerCall: -5 }).ports, [22]);
  assert.equal(policy.scanProfile(3, { maxPortsPerCall: 5000 }).ports.length, 5);
});

/* ------------------------------------------------------------------ */
/* Objective completion                                                */
/* ------------------------------------------------------------------ */

test('objectiveAchieved impact counts only post-baseline access or data', () => {
  const accessState = graph({ nodes: [node('access', 'a1', 'validated', { kind: 'user_shell', lastSeen: AT })] });
  const baseline = policy.snapshotGraph(accessState);

  assert.equal(policy.objectiveAchieved(accessState, loop({ objectiveType: 'impact' })), true);
  assert.equal(policy.objectiveAchieved(accessState, loop({ objectiveType: 'impact', baseline })), false);
  assert.equal(policy.objectiveAchieved(accessState, loop({ objectiveType: 'impact', baseline, includeBaseline: true })), true);

  const dataState = graph({ nodes: [node('data', 'd1', 'verified')] });
  assert.equal(policy.objectiveAchieved(dataState, loop({ objectiveType: 'impact' })), true);
  assert.equal(policy.objectiveAchieved(graph(), loop({ objectiveType: 'impact' })), false);
});

test('objectiveAchieved shell requires a recent validated shell access', () => {
  const startedAt = '2026-10-31T00:00:00.000Z';
  const shell = graph({
    nodes: [node('access', 'a1', 'validated', { kind: 'user_shell', lastSeen: '2026-10-31T00:05:00.000Z' })],
  });
  assert.equal(policy.objectiveAchieved(shell, loop({ objectiveType: 'shell', startedAt, baseline: policy.zeroSnapshot() })), true);
  assert.equal(policy.objectiveAchieved(shell, loop({ objectiveType: 'shell' })), true); // no startedAt => recent

  const stale = graph({
    nodes: [node('access', 'a1', 'validated', {
      kind: 'user_shell',
      firstSeen: '2026-10-30T00:00:00.000Z',
      lastSeen: '2026-10-30T00:00:00.000Z',
    })],
  });
  assert.equal(policy.objectiveAchieved(stale, loop({ objectiveType: 'shell', startedAt, baseline: policy.zeroSnapshot() })), false);

  const dbAdmin = graph({
    nodes: [node('access', 'a1', 'validated', { kind: 'db_admin', lastSeen: '2026-10-31T00:05:00.000Z' })],
  });
  assert.equal(policy.objectiveAchieved(dbAdmin, loop({ objectiveType: 'shell', startedAt, baseline: policy.zeroSnapshot() })), false);

  const escalated = graph({
    nodes: [node('access', 'a1', 'escalated', { kind: 'unknown', lastSeen: '2026-10-31T00:05:00.000Z' })],
  });
  assert.equal(policy.objectiveAchieved(escalated, loop({ objectiveType: 'shell', startedAt, baseline: policy.zeroSnapshot() })), true);
});

test('objectiveAchieved admin matches admin panel/database/domain/cloud kinds', () => {
  const adminState = (kind) => graph({ nodes: [node('access', 'a1', 'validated', { kind, lastSeen: AT })] });

  assert.equal(policy.objectiveAchieved(adminState('admin_panel'), loop({ objectiveType: 'admin' })), true);
  assert.equal(policy.objectiveAchieved(adminState('db_admin'), loop({ objectiveType: 'admin' })), true);
  assert.equal(policy.objectiveAchieved(adminState('domain_admin'), loop({ objectiveType: 'admin' })), true);
  assert.equal(policy.objectiveAchieved(adminState('cloud_admin'), loop({ objectiveType: 'admin' })), true);
  assert.equal(policy.objectiveAchieved(adminState('user_shell'), loop({ objectiveType: 'admin' })), false);
});

test('objectiveAchieved data and findings objectives use post-baseline evidence', () => {
  const dataState = graph({ nodes: [node('data', 'd1', 'verified')] });
  assert.equal(policy.objectiveAchieved(dataState, loop({ objectiveType: 'data' })), true);
  assert.equal(policy.objectiveAchieved(dataState, loop({ objectiveType: 'data', baseline: policy.snapshotGraph(dataState) })), false);
  assert.equal(policy.objectiveAchieved(graph({ nodes: [node('access', 'a1', 'validated')] }), loop({ objectiveType: 'data' })), false);

  const high = graph({ nodes: [node('finding', 'f1', 'verified', { severity: 'high' })] });
  assert.equal(policy.objectiveAchieved(high, loop({ objectiveType: 'findings' })), true);
  assert.equal(policy.objectiveAchieved(high, loop({ objectiveType: 'findings', baseline: policy.snapshotGraph(high) })), false);
  assert.equal(policy.objectiveAchieved(high, loop({
    objectiveType: 'findings',
    baseline: policy.snapshotGraph(high),
    includeBaseline: true,
  })), true);

  assert.equal(policy.objectiveAchieved(
    graph({ nodes: [node('finding', 'f1', 'verified', { severity: 'low' })] }),
    loop({ objectiveType: 'findings' }),
  ), false);
  assert.equal(policy.objectiveAchieved(
    graph({ nodes: [node('finding', 'f1', 'candidate', { severity: 'high' })] }),
    loop({ objectiveType: 'findings' }),
  ), false);
});

test('objectiveAchieved falls back to impact for unknown objective types', () => {
  const state = graph({ nodes: [node('access', 'a1', 'validated', { kind: 'user_shell' })] });
  assert.equal(policy.objectiveAchieved(state, loop({ objectiveType: 'bogus' })), true);
  assert.equal(policy.objectiveAchieved(state, loop({})), true);
});

/* ------------------------------------------------------------------ */
/* Supervision scheduling and stop decisions                           */
/* ------------------------------------------------------------------ */

test('supervisionDue dispatches on supervisor mode', () => {
  const changed = graph({ nodes: [node('finding', 'f1', 'verified', { severity: 'high' })] });

  assert.equal(policy.supervisionDue(loop(), changed, null, { supervisorMode: 'deterministic' }), false);
  assert.equal(policy.supervisionDue(loop(), changed, null, { supervisorMode: 'ai' }), true);
  assert.equal(policy.supervisionDue(loop(), graph(), undefined, {}), true);
  assert.equal(policy.supervisionDue(loop(), graph(), null, { supervisorMode: 'auto' }), true);
});

test('supervisionDue auto honours the interval and quality signals', () => {
  const due = (loopAttrs, current, latest, config) => policy.supervisionDue(loop(loopAttrs), current, latest, config);

  assert.equal(due({ round: 5 }, graph(), { attrs: { round: 4 } }, { supervisorInterval: 3 }), false);
  assert.equal(due({ round: 8 }, graph(), { attrs: { round: 4 } }, { supervisorInterval: 3 }), true);

  const high = graph({ nodes: [node('finding', 'f1', 'verified', { severity: 'high' })] });
  assert.equal(due({ round: 5, latestSnapshot: { highCriticalVerified: 0 } }, high, { attrs: { round: 4 } }, {}), true);
  assert.equal(due({ round: 5, latestSnapshot: { highCriticalVerified: 1 } }, high, { attrs: { round: 4 } }, {}), false);

  const access = graph({ nodes: [node('access', 'a1', 'validated', { kind: 'user_shell' })] });
  assert.equal(due({ round: 5, latestSnapshot: {} }, access, { attrs: { round: 4 } }, {}), true);

  const data = graph({ nodes: [node('data', 'd1', 'verified')] });
  assert.equal(due({ round: 5, latestSnapshot: {} }, data, { attrs: { round: 4 } }, {}), true);

  assert.equal(due({ round: 5, noProgressRounds: 1 }, graph(), { attrs: { round: 4 } }, {}), true);
});

test('computeStop stops outside a running phase or without scope', () => {
  assert.equal(policy.computeStop(loop({}, 'paused'), graph(), {}).reason, 'phase-paused');
  assert.equal(policy.computeStop(loop({}, 'complete'), graph(), {}).reason, 'phase-complete');
  assert.equal(policy.computeStop(loop(), graph({ scope: { allow: [] } }), {}).reason, 'scope-empty');
  assert.equal(policy.computeStop(loop(), graph({ engagement: null }), {}).reason, 'scope-empty');
});

test('computeStop stops on an achieved objective or a spent budget', () => {
  const access = graph({ nodes: [node('access', 'a1', 'validated', { kind: 'user_shell' })] });
  const achieved = policy.computeStop(loop({ objectiveType: 'impact' }), access, {});
  assert.equal(achieved.stop, true);
  assert.equal(achieved.reason, 'objective-achieved');
  assert.match(achieved.detail, /objective impact is met/);

  const maxRounds = policy.computeStop(loop({ round: 5, maxRounds: 5 }), graph(), {});
  assert.equal(maxRounds.reason, 'max-rounds');
  assert.match(maxRounds.detail, /round 5\/5/);

  const wall = policy.computeStop(loop({ startedAt: '2020-01-01T00:00:00.000Z' }), graph(), {});
  assert.equal(wall.reason, 'wall-clock');
  assert.match(wall.detail, /wall budget/);

  const stalled = policy.computeStop(loop({ noProgressRounds: 3 }), graph(), {});
  assert.equal(stalled.reason, 'no-progress');
  assert.equal(policy.computeStop(loop({ noProgressRounds: 2 }), graph(), { loopStallRounds: 2 }).reason, 'no-progress');

  const exhausted = policy.computeStop(loop({ ring: 3, emptyRounds: 3 }), graph(), {});
  assert.equal(exhausted.reason, 'exhausted');
});

test('computeStop leaves a healthy loop running', () => {
  const clean = policy.computeStop(loop({ round: 4, maxRounds: 10 }), graph(), {});
  assert.deepEqual(clean, { stop: false, reason: null, detail: null });
  assert.equal(policy.computeStop(loop({ ring: 2, emptyRounds: 99 }), graph(), {}).stop, false);
});

/* ------------------------------------------------------------------ */
/* Candidate intents                                                   */
/* ------------------------------------------------------------------ */

test('candidateIntents forces verification for high/critical candidates', () => {
  const finding = node('finding', 'f1', 'candidate', { severity: 'high', title: 'RCE' });
  const state = graph({ nodes: [finding] });

  const synthetic = policy.candidateIntents(state, loop(), [], {}, undefined);
  assert.equal(synthetic.length, 1);
  assert.equal(synthetic[0].action.actionType, 'verify_finding');
  assert.equal(synthetic[0].action.targetId, 'f1');
  assert.equal(synthetic[0].source, 'verify-gate');
  assert.match(synthetic[0].hypothesis, /reproduce/i);

  const verify = action('verify_finding', 'f1');
  const routed = policy.candidateIntents(state, loop(), [verify], {}, undefined);
  assert.equal(routed.length, 1);
  assert.equal(routed[0].action.actionId, verify.actionId);
  assert.equal(routed[0].source, 'verify-gate');

  const denied = action('verify_finding', 'f1', 'deny');
  const fallback = policy.candidateIntents(state, loop(), [denied], {}, undefined);
  assert.equal(fallback.length, 1);
  assert.equal(fallback[0].action.scope.verdict, 'allow');
  assert.notEqual(fallback[0].action.actionId, denied.actionId);

  const many = graph({
    nodes: [
      node('finding', 'f1', 'candidate', { severity: 'high' }),
      node('finding', 'f2', 'candidate', { severity: 'critical' }),
      node('finding', 'f3', 'candidate', { severity: 'high' }),
    ],
  });
  const capped = policy.candidateIntents(many, loop(), [], {}, undefined);
  assert.equal(capped.length, 2);
  assert.deepEqual(capped.map((entry) => entry.action.targetId), ['f1', 'f2']);
});

test('candidateIntents escalates verified high impact', () => {
  const verified = node('finding', 'f1', 'verified', { severity: 'critical', title: 'RCE' });
  const state = graph({ nodes: [verified] });

  const validate = action('validate_access', 'a1');
  const routed = policy.candidateIntents(state, loop(), [validate], {}, undefined);
  assert.equal(routed.length, 1);
  assert.equal(routed[0].action.actionId, validate.actionId);
  assert.equal(routed[0].source, 'escalate-gate');

  const collect = action('collect_data_evidence', 'a1');
  assert.equal(policy.candidateIntents(state, loop(), [collect], {}, undefined)[0].action.actionType, 'collect_data_evidence');

  const synthetic = policy.candidateIntents(state, loop(), [], {}, undefined);
  assert.equal(synthetic[0].action.actionType, 'escalate_privilege');
  assert.equal(synthetic[0].action.toolClass, 'record');
  assert.equal(synthetic[0].source, 'escalate-gate');

  const both = graph({ nodes: [verified, node('finding', 'f2', 'candidate', { severity: 'high' })] });
  const gated = policy.candidateIntents(both, loop(), [validate], {}, undefined);
  assert.deepEqual(gated.map((entry) => entry.source), ['verify-gate']);
});

test('candidateIntents validates an unused valid credential', () => {
  const fresh = node('credential', 'c1', 'valid', { used: false, privilege: 'svc' });
  const routed = policy.candidateIntents(graph({ nodes: [fresh] }), loop(), [], {}, undefined);
  assert.equal(routed.length, 1);
  assert.equal(routed[0].action.actionType, 'validate_credential');
  assert.equal(routed[0].action.targetId, 'c1');
  assert.equal(routed[0].source, 'credential-gate');

  const frontierCred = action('validate_credential', 'c1');
  assert.equal(
    policy.candidateIntents(graph({ nodes: [fresh] }), loop(), [frontierCred], {}, undefined)[0].action.actionId,
    frontierCred.actionId,
  );

  assert.deepEqual(
    policy.candidateIntents(graph({ nodes: [node('credential', 'c1', 'valid', { used: true })] }), loop(), [], {}, undefined),
    [],
  );
  assert.deepEqual(
    policy.candidateIntents(graph({ nodes: [node('credential', 'c1', 'untested')] }), loop(), [], {}, undefined),
    [],
  );
});

test('candidateIntents merges a ready team artifact before new work', () => {
  const ready = node('task', 't1', 'artifact_ready', { actionType: 'subagent_batch', batchId: 'b1' });
  const candidates = policy.candidateIntents(graph({ nodes: [ready] }), loop(), allowedActions(3), {}, undefined);

  assert.equal(candidates[0].action.actionType, 'merge_team');
  assert.equal(candidates[0].action.toolClass, 'team');
  assert.equal(candidates[0].action.targetId, 't1');
  assert.equal(candidates[0].source, 'policy');
  assert.match(candidates[0].action.why[0], /batch b1 has a ready artifact/);

  const completed = node('task', 't1', 'completed', { actionType: 'subagent_batch' });
  assert.deepEqual(policy.candidateIntents(graph({ nodes: [completed] }), loop(), [], {}, undefined), []);
});

test('candidateIntents skips denied and unknown frontier actions', () => {
  const frontier = [
    action('enumerate_services', 'h1', 'deny'),
    action('enumerate_services', 'h2', 'unknown'),
    action('enumerate_services', 'h3', 'allow'),
  ];
  const candidates = policy.candidateIntents(graph(), loop(), frontier, {}, undefined);

  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].action.targetId, 'h3');
  assert.equal(candidates[0].source, 'frontier');
});

test('candidateIntents caps the action budget from loop and config', () => {
  const frontier = allowedActions(6);

  assert.equal(policy.candidateIntents(graph(), loop(), frontier, {}, undefined).length, 3);
  assert.equal(policy.candidateIntents(graph(), loop({ maxActionsPerRound: 2 }), frontier, {}, undefined).length, 2);
  assert.equal(policy.candidateIntents(graph(), loop(), frontier, { loopMaxActionsPerRound: 1 }, undefined).length, 1);
  assert.equal(policy.candidateIntents(graph(), loop({ maxActionsPerRound: 99 }), frontier, {}, undefined).length, 5);

  const gated = policy.candidateIntents(
    graph({ nodes: [node('credential', 'c1', 'valid', { used: false })] }),
    loop({ maxActionsPerRound: 2 }),
    frontier,
    {},
    undefined,
  );
  assert.equal(gated.length, 2);
  assert.deepEqual(gated.map((entry) => entry.source), ['credential-gate', 'frontier']);
});

test('candidateIntents finishes claimed intents and honours supervisor must-intents', () => {
  const claimed = node('intent', 'i1', 'claimed', { actionId: 'act-1' });
  const inFlight = policy.candidateIntents(
    graph({ nodes: [claimed] }),
    loop(),
    [action('enumerate_services', 'h1', 'allow', 'act-1')],
    {},
    undefined,
  );
  assert.equal(inFlight.length, 1);
  assert.equal(inFlight[0].source, 'in-flight');
  assert.equal(inFlight[0].action.actionId, 'act-1');

  const frontier = [
    action('enumerate_services', 'h1', 'allow', 'act-1'),
    action('enumerate_services', 'h2', 'allow', 'act-2'),
  ];
  const supervised = policy.candidateIntents(graph(), loop(), frontier, {}, { attrs: { mustIntents: ['act-2', 'ghost'] } });
  assert.deepEqual(
    supervised.map((entry) => [entry.action.actionId, entry.source]),
    [['act-2', 'supervisor'], ['act-1', 'frontier']],
  );

  const byTarget = policy.candidateIntents(graph(), loop(), frontier, {}, { attrs: { mustIntents: ['h2'] } });
  assert.equal(byTarget[0].action.actionId, 'act-2');
  assert.equal(byTarget[0].source, 'supervisor');

  const open = node('intent', 'i2', 'open', { actionId: 'act-1' });
  assert.deepEqual(
    policy.candidateIntents(graph({ nodes: [open] }), loop(), frontier, {}, undefined).map((entry) => entry.source),
    ['frontier', 'frontier'],
  );
});

/* ------------------------------------------------------------------ */
/* Refutation and claim guards                                         */
/* ------------------------------------------------------------------ */

test('refutationAllowed requires two independent channels or a forced override', () => {
  const intent = { attrs: { attempts: 1 } };

  const single = policy.refutationAllowed(intent, [{ channel: 'status' }]);
  assert.equal(single.allowed, false);
  assert.match(single.reason, /two distinct observation channels/);

  assert.deepEqual(
    policy.refutationAllowed(intent, [{ channel: 'status' }, { channel: 'body' }]),
    { allowed: true, reason: 'independent observations' },
  );

  assert.equal(policy.refutationAllowed({ attrs: { attempts: 1 } }, [{ channel: 'timing' }, { channel: 'timing' }]).allowed, false);

  const retried = policy.refutationAllowed({ attrs: { attempts: 2 } }, [{ channel: 'status' }]);
  assert.equal(retried.allowed, true);
  assert.equal(retried.reason, 'independent observations');

  assert.equal(policy.refutationAllowed({ attrs: {} }, [{ channel: 'status' }]).allowed, false);
  assert.equal(policy.refutationAllowed({ attrs: {} }, undefined).allowed, false);
  assert.equal(policy.refutationAllowed({ attrs: {} }, [{ channel: '' }, { channel: 'status' }]).allowed, false);

  assert.deepEqual(policy.refutationAllowed(intent, [{ channel: 'status' }], true), { allowed: true, reason: 'force' });
});

test('claimGuardForFinding flags RCE-style claims without execution proof', () => {
  assert.equal(policy.claimGuardForFinding(node('finding', 'f1', 'candidate', {
    title: 'Remote code execution in upload handler',
    evidence: 'POST /upload returned 200 and the payload was stored',
    repro: 'curl -F file=@shell.jsp /upload',
  })), 'unproven-rce');

  assert.equal(policy.claimGuardForFinding(node('finding', 'f2', 'candidate', {
    title: 'RCE via deserialization',
    evidence: 'command executed: uid=0(root) gid=0(root) groups=0(root)',
  })), null);

  assert.equal(policy.claimGuardForFinding(node('finding', 'f3', 'candidate', {
    title: 'RCE via template injection',
    evidence: 'whoami -> www-data',
  })), null);

  assert.equal(policy.claimGuardForFinding(node('finding', 'f4', 'candidate', {
    title: 'RCE via template injection',
    evidence: 'whoami returned www-data but the marker was not proven',
  })), 'unproven-rce');

  assert.equal(policy.claimGuardForFinding(node('finding', 'f5', 'candidate', {
    title: '命令执行漏洞',
    evidence: '未打成，仅版本命中',
  })), 'unproven-rce');

  assert.equal(policy.claimGuardForFinding(node('finding', 'f6', 'candidate', {
    title: 'Reflected XSS in search',
    evidence: 'payload reflected in the response body',
  })), null);

  const labelOnly = { id: 'f7', kind: 'finding', key: 'f7', label: 'getshell via upload', status: 'candidate', attrs: {} };
  assert.equal(policy.claimGuardForFinding(labelOnly), 'unproven-rce');
});

test('ratingForFinding rates critical only for execution, admin or bulk impact', () => {
  assert.equal(policy.ratingForFinding(node('finding', 'f1', 'verified', {
    severity: 'medium',
    title: 'OS command execution',
    evidence: 'id -> uid=33(www-data) gid=33(www-data)',
  })).rating, 'critical');

  const admin = policy.ratingForFinding(node('finding', 'f2', 'verified', {
    severity: 'low',
    title: 'Exposed console',
    impact: 'admin panel access confirmed',
  }));
  assert.equal(admin.rating, 'critical');
  assert.match(admin.rationale, /execution\/admin\/bulk/);

  assert.equal(policy.ratingForFinding(node('finding', 'f3', 'verified', {
    severity: 'medium',
    title: 'Export endpoint',
    impact: 'bulk export of customer rows',
  })).rating, 'critical');

  assert.equal(policy.ratingForFinding(node('finding', 'f4', 'verified', {
    severity: 'medium',
    title: 'Row counter',
    evidence: 'count: 1250 rows returned',
  })).rating, 'critical');

  const unproven = policy.ratingForFinding(node('finding', 'f5', 'verified', {
    severity: 'high',
    title: 'SQL injection',
    evidence: 'one row reflected by an error-based payload',
    impact: 'read-only disclosure',
  }));
  assert.equal(unproven.rating, 'high');
  assert.match(unproven.rationale, /direct-impact finding/);

  assert.equal(policy.ratingForFinding(node('finding', 'f6', 'verified', {
    severity: 'medium',
    title: 'Debug page',
    impact: 'internal config leaked',
  })).rating, 'medium');

  assert.equal(policy.ratingForFinding(node('finding', 'f7', 'verified', {
    severity: 'low',
    title: 'Banner',
    impact: 'version disclosure',
  })).rating, 'low');

  assert.equal(policy.ratingForFinding(node('finding', 'f8', 'verified', {
    severity: 'info',
    title: 'Note',
    impact: 'none',
  })).rating, 'info');

  assert.equal(policy.ratingForFinding({ status: 'verified' }).rating, 'info');
});

test('ratingForFinding keeps a high rating when execution is explicitly unproven', () => {
  const rating = policy.ratingForFinding(node('finding', 'f9', 'verified', {
    severity: 'high',
    title: 'RCE attempt',
    evidence: 'whoami was blocked; not proven',
  }));
  assert.equal(rating.rating, 'high');
  assert.match(rating.rationale, /direct-impact finding/);
});

/* ------------------------------------------------------------------ */
/* Plan refinement                                                     */
/* ------------------------------------------------------------------ */

test('refineSupervisionPlan normalizes untrusted plan fields', () => {
  const out = policy.refineSupervisionPlan({
    verdict: 'explode',
    diagnosis: 'd'.repeat(2000),
    next_plan: 'n'.repeat(4000),
    mustIntents: 'not-an-array',
    preferTactics: Array.from({ length: 20 }, (_, index) => `tactic-${index}`),
    banRepeats: Array.from({ length: 20 }, (_, index) => `repeat-${index}`),
    confidence: 1.7,
    source: 'ai-subagent',
  }, { state: graph(), loop: loop(), frontier: [], intents: [], config: {} });

  assert.equal(out.verdict, 'hold');
  assert.equal(out.diagnosis.length, 1500);
  assert.equal(out.nextPlan.length, 3000);
  assert.deepEqual(out.mustIntents, []);
  assert.equal(out.preferTactics.length, 12);
  assert.equal(out.banRepeats.length, 12);
  assert.equal(out.stopRecommended, false);
  assert.equal(out.stopReason, null);
  assert.equal(out.confidence, 1);
  assert.equal(out.source, 'ai-subagent');

  const clamp = (confidence) => policy.refineSupervisionPlan({ confidence }, {
    state: graph(), loop: loop(), frontier: [], intents: [], config: {},
  }).confidence;
  assert.equal(clamp(-0.4), 0);
  assert.equal(clamp(undefined), 0.5);
  assert.equal(clamp('0.42'), 0.42);
});

test('refineSupervisionPlan drops unknown must-intent ids', () => {
  const frontier = [action('enumerate_services', 'h1', 'allow', 'act-1')];
  const intents = [node('intent', 'intent-1', 'open', { actionId: 'act-2' })];

  const out = policy.refineSupervisionPlan({
    verdict: 'hold',
    mustIntents: ['ghost', 'act-1', 'intent-1', 'act-2'],
  }, { state: graph(), loop: loop(), frontier, intents, config: {} });

  assert.deepEqual(out.mustIntents, ['act-1', 'intent-1', 'act-2']);
  assert.equal(out.verdict, 'hold');

  const many = Array.from({ length: 8 }, (_, index) => action('enumerate_services', `h${index + 1}`, 'allow', `act-${index + 1}`));
  const capped = policy.refineSupervisionPlan({ mustIntents: many.map((entry) => entry.actionId) }, {
    state: graph(), loop: loop(), frontier: many, intents: [], config: {},
  });
  assert.equal(capped.mustIntents.length, 6);
});

test('refineSupervisionPlan forces verification for high candidates', () => {
  const finding = node('finding', 'f1', 'candidate', { severity: 'critical', title: 'RCE' });
  const verify = action('verify_finding', 'f1', 'allow', 'verify-1');

  const out = policy.refineSupervisionPlan({ verdict: 'stop', stopRecommended: true, stopReason: 'done' }, {
    state: graph({ nodes: [finding] }), loop: loop(), frontier: [verify], intents: [], config: {},
  });
  assert.equal(out.verdict, 'verify');
  assert.equal(out.stopRecommended, false);
  assert.deepEqual(out.mustIntents, ['verify-1']);

  const hold = policy.refineSupervisionPlan({ verdict: 'hold' }, {
    state: graph({ nodes: [finding] }), loop: loop(), frontier: [], intents: [], config: {},
  });
  assert.equal(hold.verdict, 'verify');
  assert.deepEqual(hold.mustIntents, []);
});

test('refineSupervisionPlan escalates verified high impact from hold', () => {
  const finding = node('finding', 'f1', 'verified', { severity: 'critical' });
  const validate = action('validate_access', 'a1', 'allow', 'validate-1');

  const escalated = policy.refineSupervisionPlan({ verdict: 'hold' }, {
    state: graph({ nodes: [finding] }), loop: loop(), frontier: [validate], intents: [], config: {},
  });
  assert.equal(escalated.verdict, 'escalate');
  assert.deepEqual(escalated.mustIntents, ['validate-1']);

  const pivoted = policy.refineSupervisionPlan({ verdict: 'pivot' }, {
    state: graph({ nodes: [finding] }), loop: loop(), frontier: [validate], intents: [], config: {},
  });
  assert.equal(pivoted.verdict, 'pivot');
  assert.deepEqual(pivoted.mustIntents, []);
});

test('refineSupervisionPlan downgrades an unearned stop to pivot', () => {
  const downgraded = policy.refineSupervisionPlan({ verdict: 'stop', stopRecommended: true, stopReason: 'done' }, {
    state: graph(), loop: loop(), frontier: [], intents: [], config: {},
  });
  assert.equal(downgraded.verdict, 'pivot');
  assert.equal(downgraded.stopRecommended, false);
  assert.equal(downgraded.stopReason, null);

  const stalled = policy.refineSupervisionPlan({ verdict: 'stop', stopRecommended: true, stopReason: 'done' }, {
    state: graph(), loop: loop({ noProgressRounds: 3 }), frontier: [], intents: [], config: { loopStallRounds: 3 },
  });
  assert.equal(stalled.verdict, 'stop');
  assert.equal(stalled.stopRecommended, true);
  assert.equal(stalled.stopReason, 'done');

  const achievedState = graph({ nodes: [node('access', 'a1', 'validated', { kind: 'user_shell' })] });
  const achieved = policy.refineSupervisionPlan({ verdict: 'stop', stopRecommended: true }, {
    state: achievedState, loop: loop(), frontier: [], intents: [], config: {},
  });
  assert.equal(achieved.verdict, 'stop');
  assert.equal(achieved.stopRecommended, true);
});

test('refineSupervisionPlan blocks stop while a team artifact is ready', () => {
  const ready = node('task', 't1', 'artifact_ready', { actionType: 'subagent_batch' });

  const out = policy.refineSupervisionPlan({ verdict: 'stop', stopRecommended: true, nextPlan: '' }, {
    state: graph({ nodes: [ready] }), loop: loop(), frontier: [], intents: [], config: {},
  });
  assert.equal(out.verdict, 'hold');
  assert.equal(out.stopRecommended, false);
  assert.match(out.nextPlan, /Merge the ready team batch/);

  const custom = policy.refineSupervisionPlan({ verdict: 'stop', nextPlan: 'custom merge order' }, {
    state: graph({ nodes: [ready] }), loop: loop(), frontier: [], intents: [], config: {},
  });
  assert.equal(custom.nextPlan, 'custom merge order');
});

test('refineSupervisionPlan pivots after repeated no-progress rounds', () => {
  const pivot = policy.refineSupervisionPlan({ verdict: 'hold' }, {
    state: graph(), loop: loop({ noProgressRounds: 2 }), frontier: [], intents: [], config: { loopNoProgressRounds: 2 },
  });
  assert.equal(pivot.verdict, 'pivot');

  const hold = policy.refineSupervisionPlan({ verdict: 'hold' }, {
    state: graph(), loop: loop({ noProgressRounds: 1 }), frontier: [], intents: [], config: { loopNoProgressRounds: 2 },
  });
  assert.equal(hold.verdict, 'hold');
});

/* ------------------------------------------------------------------ */
/* Supervisor output parsing                                           */
/* ------------------------------------------------------------------ */

test('parseSupervisorOutput parses fenced and bare JSON plans', () => {
  const payload = JSON.stringify({
    verdict: 'pivot',
    diagnosis: 'stuck on the same vhost',
    next_plan: 'move to the internal range',
    must_intents: ['act-1'],
    prefer_tactics: ['dns', 'tcp'],
    ban_repeats: ['dirb'],
    stop_recommended: false,
    confidence: 0.81,
  });
  const fenced = supervisor.parseSupervisorOutput('Analysis first.\n```json\n' + payload + '\n```\nDone.');

  assert.equal(fenced.verdict, 'pivot');
  assert.equal(fenced.diagnosis, 'stuck on the same vhost');
  assert.equal(fenced.nextPlan, 'move to the internal range');
  assert.deepEqual(fenced.mustIntents, ['act-1']);
  assert.deepEqual(fenced.preferTactics, ['dns', 'tcp']);
  assert.deepEqual(fenced.banRepeats, ['dirb']);
  assert.equal(fenced.stopRecommended, false);
  assert.equal(fenced.confidence, 0.81);
  assert.equal(fenced.source, 'ai-subagent');

  const bare = supervisor.parseSupervisorOutput('{"verdict":"stop","stop_recommended":true,"stop_reason":"objective-achieved"}');
  assert.equal(bare.verdict, 'stop');
  assert.equal(bare.stopRecommended, true);
  assert.equal(bare.stopReason, 'objective-achieved');
  assert.equal(bare.confidence, 0.5);

  const aliases = supervisor.parseSupervisorOutput(JSON.stringify({
    action: 'verify',
    reason: 'candidate needs proof',
    plan: 're-run the payload',
    mustIntents: ['x'],
    stopRecommended: true,
    confidence: '0.4',
  }));
  assert.equal(aliases.verdict, 'verify');
  assert.equal(aliases.diagnosis, 'candidate needs proof');
  assert.equal(aliases.nextPlan, 're-run the payload');
  assert.deepEqual(aliases.mustIntents, ['x']);
  assert.equal(aliases.stopRecommended, true);
  assert.equal(aliases.confidence, 0.4);

  assert.equal(supervisor.parseSupervisorOutput('{"verdict":"explode"}').verdict, 'hold');
  assert.equal(supervisor.parseSupervisorOutput('{}').verdict, 'hold');
});

test('parseSupervisorOutput clips oversized fields and defaults confidence', () => {
  const parsed = supervisor.parseSupervisorOutput(JSON.stringify({
    verdict: 'hold',
    diagnosis: 'd'.repeat(2000),
    nextPlan: 'n'.repeat(4000),
  }));
  assert.equal(parsed.diagnosis.length, 1500);
  assert.equal(parsed.nextPlan.length, 3000);
  assert.equal(parsed.confidence, 0.5);
});

test('parseSupervisorOutput returns null for malformed output', () => {
  assert.equal(supervisor.parseSupervisorOutput('I will not comply'), null);
  assert.equal(supervisor.parseSupervisorOutput('```json\n{oops}\n```'), null);
  assert.equal(supervisor.parseSupervisorOutput(''), null);
  assert.equal(supervisor.parseSupervisorOutput(null), null);
  assert.equal(supervisor.parseSupervisorOutput('[1,2,3]'), null);
});

/* ------------------------------------------------------------------ */
/* Deterministic planner verdicts                                      */
/* ------------------------------------------------------------------ */

test('deterministicPlan stops when the objective is achieved', () => {
  const state = graph({
    nodes: [
      node('access', 'a1', 'validated', { kind: 'user_shell' }),
      node('finding', 'f1', 'candidate', { severity: 'critical', title: 'RCE' }),
    ],
  });
  const plan = supervisor.deterministicPlan({
    state, loop: loop({ objectiveType: 'impact' }), latest: null, frontier: [], config: {},
  });

  assert.equal(plan.verdict, 'stop');
  assert.equal(plan.stopRecommended, true);
  assert.equal(plan.stopReason, 'objective-achieved');
  assert.match(plan.nextPlan, /action=finish outcome=achieved/);
});

test('deterministicPlan verifies high candidates before enumeration', () => {
  const state = graph({ nodes: [node('finding', 'f1', 'candidate', { severity: 'high', title: 'RCE' })] });
  const plan = supervisor.deterministicPlan({
    state,
    loop: loop(),
    latest: null,
    frontier: [action('verify_finding', 'f1', 'allow', 'verify-1')],
    config: {},
  });

  assert.equal(plan.verdict, 'verify');
  assert.match(plan.diagnosis, /Unverified high\/critical candidate/);
  assert.match(plan.nextPlan, /^Verify the high\/critical candidates/);
  assert.deepEqual(plan.mustIntents, ['verify-1']);
  assert.deepEqual(plan.preferTactics, ['verify_finding']);
  assert.equal(plan.stopRecommended, false);
  assert.equal(plan.stopReason, null);
  assert.equal(plan.confidence, 0.6);
  assert.equal(plan.source, 'deterministic');
});

test('deterministicPlan escalates verified high impact', () => {
  const state = graph({ nodes: [node('finding', 'f1', 'verified', { severity: 'critical' })] });
  const plan = supervisor.deterministicPlan({
    state,
    loop: loop(),
    latest: null,
    frontier: [action('validate_access', 'a1', 'allow', 'validate-1')],
    config: {},
  });

  assert.equal(plan.verdict, 'escalate');
  assert.match(plan.diagnosis, /Verified high\/critical impact/);
  assert.match(plan.nextPlan, /Push the verified high\/critical impact/);
  assert.deepEqual(plan.mustIntents, ['validate-1']);
});

test('deterministicPlan raises a verified vulnerability when no foothold exists', () => {
  const state = graph({ nodes: [node('finding', 'f1', 'verified', { title: 'reflected XSS', template: 'xss', cvssScore: 6.1, cvssSeverity: 'MEDIUM', severity: 'medium' })] });
  const plan = supervisor.deterministicPlan({
    state,
    loop: loop(),
    latest: null,
    frontier: [],
    config: {},
  });
  assert.equal(plan.verdict, 'escalate');
  assert.match(plan.nextPlan, /no validated access/);
  assert.doesNotMatch(plan.nextPlan, /skill_get/);
});

test('deterministicPlan pivots after no quality progress', () => {
  const plan = supervisor.deterministicPlan({
    state: graph(),
    loop: loop({ noProgressRounds: 2 }),
    latest: null,
    frontier: [action('enumerate_services', 'h1')],
    config: { loopNoProgressRounds: 2 },
  });

  assert.equal(plan.verdict, 'pivot');
  assert.match(plan.diagnosis, /No quality progress/);
  assert.match(plan.nextPlan, /Change tactic family/);
  assert.equal(plan.stopRecommended, false);
});

test('deterministicPlan holds while an allowed frontier action remains', () => {
  const plan = supervisor.deterministicPlan({
    state: graph(),
    loop: loop(),
    latest: null,
    frontier: [action('enumerate_services', 'h1')],
    config: {},
  });

  assert.equal(plan.verdict, 'hold');
  assert.equal(plan.diagnosis, 'Current path is still actionable.');
  assert.equal(plan.nextPlan, 'Continue the currently assigned intent and finish its evidence contract.');
  assert.deepEqual(plan.mustIntents, ['enumerate_services:h1']);
  assert.deepEqual(plan.preferTactics, ['enumerate_services']);
  assert.equal(plan.stopRecommended, false);
  assert.equal(plan.stopReason, null);
});

test('deterministicPlan pivots or stops when the frontier is empty', () => {
  const pivot = supervisor.deterministicPlan({
    state: graph(), loop: loop(), latest: null, frontier: [], config: {},
  });
  assert.equal(pivot.verdict, 'pivot');
  assert.match(pivot.nextPlan, /No allowed frontier action remains/);
  assert.equal(pivot.stopRecommended, false);

  const stop = supervisor.deterministicPlan({
    state: graph(),
    loop: loop({ noProgressRounds: 3 }),
    latest: null,
    frontier: [],
    config: { loopNoProgressRounds: 5, loopStallRounds: 3 },
  });
  assert.equal(stop.verdict, 'stop');
  assert.equal(stop.stopRecommended, true);
  assert.equal(stop.stopReason, 'no-progress');
});

/* ------------------------------------------------------------------ */
/* reviewWithSubagent                                                  */
/* ------------------------------------------------------------------ */

test('reviewWithSubagent runs one fresh child and parses its plan', async () => {
  const plan = {
    verdict: 'verify',
    diagnosis: 'candidate needs a second run',
    must_intents: ['act-2'],
    confidence: 0.7,
  };
  const calls = [];
  const agent = { id: 'agent-1' };
  const ctx = {
    get(name) {
      assert.equal(name, 'subagents');
      return {
        startActivation: async (request) => {
          calls.push(request);
          return {
            childId: 'c',
            result: Promise.resolve({
              output: [{ type: 'text', text: JSON.stringify(plan) }],
              stopReason: 'end_turn',
            }),
            dispose: async () => {},
          };
        },
      };
    },
  };

  const result = await supervisor.reviewWithSubagent({ ctx, agent, brief: 'supervise this round' });

  assert.equal(result.error, null);
  assert.equal(result.childId, 'c');
  assert.equal(result.stopReason, 'end_turn');
  assert.match(result.promptHash, /^[0-9a-f]{16}$/);
  assert.equal(result.promptHash, shortHash('supervise this round', 16));
  assert.equal(result.plan.verdict, 'verify');
  assert.deepEqual(result.plan.mustIntents, ['act-2']);
  assert.equal(result.plan.confidence, 0.7);
  assert.equal(result.plan.source, 'ai-subagent');

  assert.equal(calls.length, 1);
  assert.equal(calls[0].provider, 'spawn');
  assert.equal(calls[0].label, 'AtkBrain supervisor');
  assert.equal(calls[0].delivery, 'caller');
  assert.equal(calls[0].request.prompt[0].text, 'supervise this round');
  assert.equal(calls[0].request.parent, agent);
  assert.equal(calls[0].signal.aborted, false);
});

test('reviewWithSubagent accepts structured child output and hashes only non-empty briefs', async () => {
  const ctx = ctxWithSubagents(async () => ({
    childId: 'c',
    result: Promise.resolve({ structured: { verdict: 'escalate', next_plan: 'push the access' } }),
    dispose: async () => {},
  }));

  const result = await supervisor.reviewWithSubagent({ ctx, agent: { id: 'a' }, brief: '' });
  assert.equal(result.promptHash, null);
  assert.equal(result.plan.verdict, 'escalate');
  assert.equal(result.plan.nextPlan, 'push the access');
});

test('reviewWithSubagent falls back when the child output is not a JSON plan', async () => {
  let disposed = false;
  const ctx = ctxWithSubagents(async () => ({
    childId: 'child-bad',
    result: Promise.resolve({ output: [{ type: 'text', text: 'I cannot help with that.' }] }),
    dispose: async () => { disposed = true; },
  }));

  const result = await supervisor.reviewWithSubagent({ ctx, agent: { id: 'a' }, brief: 'brief' });

  assert.equal(result.plan, null);
  assert.equal(result.childId, 'child-bad');
  assert.match(result.error, /no parseable JSON plan/);
  assert.equal(disposed, true);
});

test('reviewWithSubagent reports an unmounted subagent service', async () => {
  const missing = await supervisor.reviewWithSubagent({
    ctx: { get: () => undefined },
    agent: { id: 'a' },
    brief: 'b',
  });
  assert.deepEqual(missing, {
    plan: null,
    childId: undefined,
    promptHash: null,
    error: 'subagent service is not mounted',
  });

  const throwing = await supervisor.reviewWithSubagent({
    ctx: { get: () => { throw new Error('service unavailable'); } },
    agent: { id: 'a' },
    brief: 'b',
  });
  assert.equal(throwing.plan, null);
  assert.match(throwing.error, /not mounted/);
});

test('reviewWithSubagent falls back when the child fails', async () => {
  const spawnFailure = await supervisor.reviewWithSubagent({
    ctx: ctxWithSubagents(async () => { throw new Error('spawn failed'); }),
    agent: { id: 'a' },
    brief: 'b',
  });
  assert.equal(spawnFailure.plan, null);
  assert.equal(spawnFailure.childId, undefined);
  assert.equal(spawnFailure.error, 'spawn failed');

  let disposed = false;
  const childFailure = await supervisor.reviewWithSubagent({
    ctx: ctxWithSubagents(async () => ({
      childId: 'child-crash',
      result: Promise.reject(new Error('child crashed')),
      dispose: async () => { disposed = true; },
    })),
    agent: { id: 'a' },
    brief: 'b',
  });
  assert.equal(childFailure.plan, null);
  assert.equal(childFailure.childId, 'child-crash');
  assert.equal(childFailure.error, 'child crashed');
  assert.equal(disposed, true);
});

test('reviewWithSubagent falls back when the child times out', async () => {
  let disposed = false;
  const ctx = ctxWithSubagents(async (request) => ({
    childId: 'child-slow',
    dispose: async () => { disposed = true; },
    result: new Promise((_resolve, reject) => {
      request.signal.addEventListener('abort', () => reject(request.signal.reason ?? new Error('aborted')), { once: true });
    }),
  }));

  const result = await supervisor.reviewWithSubagent({ ctx, agent: { id: 'a' }, brief: 'b', timeoutMs: 1000 });

  assert.equal(result.plan, null);
  assert.equal(result.childId, 'child-slow');
  assert.match(result.error, /supervisor timeout/);
  assert.equal(disposed, true);
});

/* ------------------------------------------------------------------ */
/* verifyWithSubagent                                                  */
/* ------------------------------------------------------------------ */

test('verifyWithSubagent normalizes a verified verdict', async () => {
  const text = JSON.stringify({
    verdict: 'VERIFIED',
    rationale: 'replayed the nonce and observed the same marker',
    evidence_paths: ['artifacts/a.json'],
    observed_marker: 'atk-nonce-1',
    description: '在 /api/search 的 q 参数中，单引号被原样拼入 SQL 查询，响应回显数据库错误并返回一行数据。',
    impact: '攻击者可读取数据库中的业务数据；当前证据只证明单表读取，未证明写入或命令执行。',
    remediation: '对 q 参数使用参数化查询，移除字符串拼接，并对数据库错误做统一处理。',
    repro: '发送带单引号的 q 参数两次，比较错误响应和返回行数。',
    request: 'GET /api/search?q=%27 HTTP/1.1',
    response: 'HTTP/1.1 500 ... SQL syntax error ...',
  });
  const result = await supervisor.verifyWithSubagent({
    ctx: verifierCtx(text),
    agent: { id: 'a' },
    brief: 'verify this',
  });

  assert.equal(result.verdict, 'verified');
  assert.equal(result.rationale, 'replayed the nonce and observed the same marker');
  assert.deepEqual(result.evidencePaths, ['artifacts/a.json']);
  assert.equal(result.observedMarker, 'atk-nonce-1');
  assert.match(result.details.description, /q 参数/u);
  assert.match(result.details.impact, /数据库/u);
  assert.match(result.details.remediation, /参数化查询/u);
  assert.match(result.details.request, /GET \/api\/search/u);
  assert.equal(result.childId, 'verifier-1');
  assert.equal(result.error, null);
});

test('verifyWithSubagent normalizes refuted and unknown verdicts', async () => {
  const refuted = await supervisor.verifyWithSubagent({
    ctx: verifierCtx(JSON.stringify({ verdict: 'refuted', reason: 'marker never echoed' })),
    agent: { id: 'a' },
    brief: 'b',
  });
  assert.equal(refuted.verdict, 'refuted');
  assert.equal(refuted.rationale, 'marker never echoed');
  assert.deepEqual(refuted.evidencePaths, []);
  assert.equal(refuted.observedMarker, null);

  const unknown = await supervisor.verifyWithSubagent({
    ctx: verifierCtx(JSON.stringify({ verdict: 'probably' })),
    agent: { id: 'a' },
    brief: 'b',
  });
  assert.equal(unknown.verdict, 'inconclusive');
});

test('verifyWithSubagent caps evidence paths at ten', async () => {
  const paths = Array.from({ length: 12 }, (_, index) => `artifact-${index}.json`);
  const result = await supervisor.verifyWithSubagent({
    ctx: verifierCtx(JSON.stringify({ verdict: 'verified', evidence_paths: paths })),
    agent: { id: 'a' },
    brief: 'b',
  });

  assert.equal(result.evidencePaths.length, 10);
  assert.deepEqual(result.evidencePaths, paths.slice(0, 10));
});

test('verifyWithSubagent falls back to inconclusive', async () => {
  const missing = await supervisor.verifyWithSubagent({
    ctx: { get: () => undefined },
    agent: { id: 'a' },
    brief: 'b',
  });
  assert.equal(missing.verdict, 'inconclusive');
  assert.match(missing.rationale, /subagent service is not mounted/);
  assert.equal(missing.error, 'subagent service is not mounted');

  const malformed = await supervisor.verifyWithSubagent({
    ctx: verifierCtx('no json here'),
    agent: { id: 'a' },
    brief: 'b',
  });
  assert.equal(malformed.verdict, 'inconclusive');
  assert.equal(malformed.rationale, 'verifier returned no parseable JSON');
  assert.equal(malformed.error, 'parse');

  const thrown = await supervisor.verifyWithSubagent({
    ctx: ctxWithSubagents(async () => { throw new Error('verifier spawn failed'); }),
    agent: { id: 'a' },
    brief: 'b',
  });
  assert.equal(thrown.verdict, 'inconclusive');
  assert.equal(thrown.rationale, 'verifier spawn failed');
  assert.equal(thrown.error, 'verifier spawn failed');
  assert.deepEqual(thrown.evidencePaths, []);
});

/* ------------------------------------------------------------------ */
/* Verifier brief                                                      */
/* ------------------------------------------------------------------ */

test('buildVerifierBrief embeds finding facts, evidence hashes and scope', () => {
  const state = graph({
    nodes: [node('evidence', 'ev-1', 'valid', { relative: 'evidence/sqli.txt', sha256: 'a'.repeat(64) })],
  });
  const finding = {
    id: 'f1',
    kind: 'finding',
    key: 'finding:sqli',
    label: 'SQL injection',
    status: 'verified',
    verification: 'corroborated',
    evidenceIds: ['ev-1', 'missing-evidence'],
    attrs: {
      title: 'SQL injection in /api/search',
      severity: 'high',
      template: 'sqli',
      subjectKey: 'host:app.example.test',
      evidence: 'error-based payload returned one row',
      repro: 'curl -s "https://app.example.test/api/search?q=%27"',
      description: '在 /api/search 的 q 参数中，单引号被拼入 SQL 查询。',
      request: 'GET /api/search?q=%27 HTTP/1.1',
      response: 'HTTP/1.1 500 SQL syntax error',
    },
  };

  const brief = supervisor.buildVerifierBrief({ state, finding, mode: 'evidence' });

  assert.match(brief, /^# AtkBrain finding verification/);
  assert.match(brief, /SQL injection in \/api\/search/);
  assert.match(brief, /severity: high/);
  assert.match(brief, /status: verified/);
  assert.match(brief, /verification: corroborated/);
  assert.match(brief, /template: sqli/);
  assert.match(brief, /subject: host:app\.example\.test/);
  assert.match(brief, /error-based payload returned one row/);
  assert.match(brief, /curl -s/);
  assert.match(brief, /template description: 在 \/api\/search 的 q 参数中/u);
  assert.match(brief, /request: GET \/api\/search\?q=%27 HTTP\/1\.1/u);
  assert.match(brief, /response: HTTP\/1\.1 500 SQL syntax error/u);
  assert.match(brief, /"description":"/u);
  assert.match(brief, /- evidence\/sqli\.txt sha256=a{64}/);
  assert.doesNotMatch(brief, /missing-evidence/);
  assert.match(brief, /Do not use network tools; audit the supplied evidence paths and hashes only\./);
  assert.doesNotMatch(brief, /skill_get/);
  assert.match(brief, /evidence-only mode/);
  assert.match(brief, /（none; evidence-only mode）/);
  assert.match(brief, /\{"verdict":"verified\|refuted\|inconclusive"/);
});

test('buildVerifierBrief includes the exact allow list in network mode', () => {
  const finding = node('finding', 'f2', 'candidate', { title: 'Exposed admin', severity: 'medium' });
  const scopeEntries = [
    { type: 'cidr', value: '10.0.0.0/24' },
    { type: 'host', value: 'app.example.test' },
  ];

  const brief = supervisor.buildVerifierBrief({ state: graph(), finding, mode: 'network', scopeEntries });

  assert.match(brief, /exact allow list below, read-only and rate-limited/);
  assert.match(brief, /\[{"type":"cidr","value":"10\.0\.0\.0\/24"},{"type":"host","value":"app\.example\.test"}\]/);
  assert.doesNotMatch(brief, /Do not use network tools/);
  assert.match(brief, /- none recorded/);
});

test('buildVerifierBrief tolerates a finding without attrs or evidence', () => {
  const finding = {
    id: 'f3',
    kind: 'finding',
    key: 'finding:bare',
    label: 'Bare finding',
    status: 'candidate',
  };

  const brief = supervisor.buildVerifierBrief({ state: graph(), finding });

  assert.match(brief, /title: Bare finding/);
  assert.match(brief, /severity: unknown/);
  assert.match(brief, /verification: unverified/);
  assert.match(brief, /template: manual/);
  assert.match(brief, /subject: finding:bare/);
  assert.match(brief, /evidence: —/);
  assert.match(brief, /repro: —/);
  assert.match(brief, /- none recorded/);
});

test('normalizeVerificationDetails bounds and joins verifier prose', () => {
  const details = supervisor.normalizeVerificationDetails({
    description: ['第一段说明接口。', '第二段说明根因。'],
    impact_zh: '可读取数据库。',
    remediation: '参数化查询。',
    repro: '重复请求两次。',
    request: 'GET /x HTTP/1.1',
    response: 'HTTP/1.1 500',
  });
  assert.match(details.description, /第一段说明接口。\n第二段说明根因。/u);
  assert.match(details.impact, /可读取数据库/u);
  assert.match(details.remediation, /参数化查询/u);
  assert.match(details.repro, /重复请求两次/u);
  assert.equal(details.request, 'GET /x HTTP/1.1');
});

test('supervisor re-exports the policy helpers it clamps with', () => {
  assert.equal(supervisor.candidateIntents, policy.candidateIntents);
  assert.equal(supervisor.refineSupervisionPlan, policy.refineSupervisionPlan);
});
