/** A round does not count while a vulnerability has no foothold. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applyOps, auditOp, emptyState, nodeOp } from '../lib/ops.js';
import { computeFrontier } from '../lib/frontier.js';
import { nextPassDecision } from '../lib/test-passes.js';

function openImpact() {
  return applyOps(emptyState(), [
    { op: 'engagement.set', engagement: { name: 'impact-gate', authorization: 'AUTH-1' } },
    { op: 'scope.set', allow: [{ type: 'host', value: 'app.example', canonical: 'app.example' }], deny: [] },
    nodeOp('webapp', 'https://app.example/', 'app', { url: 'https://app.example/', host: 'app.example' }),
    nodeOp('finding', 'xss', 'reflected script', {
      template: 'xss',
      title: 'reflected script',
      severity: 'medium',
      secondaryVerified: true,
      cvssScore: 6.1,
      cvssSeverity: 'MEDIUM',
    }, { status: 'verified' }),
    nodeOp('coverage', 'app/xss', '/login × xss', { path: '/login', bugClass: 'xss' }, { status: 'open' }),
  ]);
}

test('coverage and notes do not finish a round while impact is open', () => {
  let state = openImpact();
  state = applyOps(state, [
    auditOp('atkbrain_probe', 'http', 'app.example', '200'),
    auditOp('atkbrain_coverage', 'coverage.note', '/login', 'seen'),
    auditOp('atkbrain_record', 'note', null, 'surface only'),
  ]);
  const decision = nextPassDecision(state);
  assert.equal(decision.action, 'reject');
  assert.equal(decision.reason, 'impact');
});

test('recording a higher finding lets the round count', () => {
  let state = openImpact();
  state = applyOps(state, [
    auditOp('atkbrain_record', 'record.impact', 'file read', '1 node'),
  ]);
  const decision = nextPassDecision(state);
  assert.equal(decision.action, 'record');
  assert.equal(decision.basis, 'activity');
});

test('harm escalation is not scheduled on the frontier', () => {
  const actions = computeFrontier(openImpact(), { limit: 20 });
  assert.equal(actions.some((action) => action.actionType === 'escalate_impact'), false);
});
