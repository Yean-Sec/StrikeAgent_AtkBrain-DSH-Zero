/** Supervisor → executor handoff must be visible to the executor, not only stored. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { selfSupervisionStatus } from '../lib/tools/query.js';

function briefState(handoff = true) {
  let state = emptyState();
  const attrs = {
    type: 'self_team_brief',
    verdict: 'hold',
    progressSummary: 'Merged 3 team artifacts and verified the top candidate.',
    gained: ['1 verified finding'],
    missed: ['2 recon-only targets'],
    advice: 'Verify the remaining target gaps before starting new enumeration.',
    antiDeadlock: ['Do not repeat the same subdomain brute force.'],
    recommendedNext: ['Run atkbrain_query action=targets'],
    deadlockRisk: 'medium',
    source: 'ai-subagent',
  };
  if (handoff) {
    attrs.handoff = {
      from: 'supervisor',
      to: 'executor',
      status: 'delivered',
      channel: 'tool_result',
      directive: attrs.advice,
      targetGaps: 2,
    };
  }
  state = applyOps(state, [
    nodeOp('supervision', 'test/self-brief', 'self-team brief', attrs, { status: 'recorded' }),
  ], new Date().toISOString());
  return state;
}

test('latest supervisor brief is exposed as an executor handoff with directive and gaps', () => {
  const status = selfSupervisionStatus(briefState(true), { totals: { recon: 2, untested: 0 } });
  assert.equal(status.due, false);
  assert.equal(status.handoff.to, 'executor');
  assert.equal(status.handoff.from, 'supervisor');
  assert.equal(status.handoff.status, 'delivered');
  assert.match(status.handoff.directive, /target gaps/);
  assert.equal(status.handoff.targetGaps, 2);
  assert.deepEqual(status.latestRecommendedNext, ['Run atkbrain_query action=targets']);
});

test('a stored brief without legacy handoff still surfaces its advice to the executor', () => {
  const status = selfSupervisionStatus(briefState(false), { totals: { recon: 2, untested: 0 } });
  assert.equal(status.handoff, null);
  assert.match(status.latestAdvice, /target gaps/);
  assert.equal(status.targetGaps, 2);
});
