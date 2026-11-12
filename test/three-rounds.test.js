/** One operator message starts three dialogues. Two follow-ups are armed. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applyThreeRounds, continueIdleLead, stopAutomaticRounds } from '../lib/three-rounds.js';
import { nextPassDecision, operatorRoundOpen, passesComplete } from '../lib/test-passes.js';
import { applyOps, emptyState } from '../lib/ops.js';
import { supervisionNodeOp } from '../lib/tools/build.js';

const AUTO_OBJECTIVE = '上一轮已经结束。这是自动送入的下一轮。';

test('an operator message does not arm follow-up dialogues', async () => {
  const calls = [];
  const session = { id: 'lead', header: {} };
  const agent = { id: 'lead', session };
  const goals = {
    current: null,
    get() { return this.current; },
    create(_agent, request) {
      calls.push(['create', request.maxGoalRounds, request.objective]);
      this.current = {
        id: 'goal-next',
        revision: 1,
        phase: 'active',
        activation: 'armed',
        objective: request.objective,
        roundsStarted: 0,
        maxGoalRounds: request.maxGoalRounds,
      };
      return this.current;
    },
    pause() { throw new Error('the follow-up dialogues must stay armed'); },
  };
  const ctx = {
    agents: { get: (id) => (id === 'lead' ? agent : undefined) },
    get(name) { return name === 'goals' ? goals : undefined; },
    sessionProjections: { stateOf: () => ({ nodes: {}, edges: {}, engagement: { name: 'engagement' } }) },
    logger: { warn() {} },
  };
  const result = await applyThreeRounds(ctx, session, { type: 'user/message', seq: 4, data: { source: { kind: 'user' } } });
  assert.equal(result.action, 'disabled');
  assert.equal(calls.length, 0);
  const goalPrompt = await applyThreeRounds(ctx, session, { type: 'user/message', seq: 8, data: { source: { kind: 'goal', round: 1 } } });
  assert.equal(goalPrompt.action, 'disabled');
  assert.equal(calls.length, 0);
});

test('idle leaves the two follow-up dialogues armed', async () => {
  const calls = [];
  const session = { id: 'lead', header: {} };
  const agent = { id: 'lead', session };
  const goals = {
    current: {
      id: 'goal-next',
      revision: 1,
      phase: 'active',
      activation: 'armed',
      objective: '三轮对话的后续一轮。接着测。',
      roundsStarted: 0,
      maxGoalRounds: 2,
    },
    get() { return this.current; },
    pause() { throw new Error('idle must not pause the follow-up dialogues'); },
    create() { throw new Error('idle must not create another goal'); },
  };
  const ctx = {
    agents: { get: (id) => (id === 'lead' ? agent : undefined) },
    get(name) { return name === 'goals' ? goals : undefined; },
    sessionProjections: { stateOf: () => ({ engagement: { name: 'engagement' }, nodes: {}, edges: {} }) },
  };
  const result = await continueIdleLead(ctx, agent);
  assert.equal(result.action, 'none');
  assert.deepEqual(calls, []);
});

test('idle pauses the automatic round once and does not arm a follow-up budget', async () => {
  const calls = [];
  const session = { id: 'lead', header: {} };
  const agent = { id: 'lead', session };
  const goals = {
    current: { id: 'goal-1', revision: 1, phase: 'active', objective: AUTO_OBJECTIVE, maxGoalRounds: 2 },
    get() { return this.current; },
    pause() {
      calls.push('pause');
      this.current = { ...this.current, phase: 'paused' };
      return this.current;
    },
    create() { throw new Error('idle must not create a goal'); },
  };
  const ctx = {
    agents: { get: (id) => (id === 'lead' ? agent : undefined) },
    get(name) { return name === 'goals' ? goals : undefined; },
    sessionProjections: { stateOf: () => ({ engagement: { name: 'engagement' }, nodes: {}, edges: {} }) },
  };
  const first = await continueIdleLead(ctx, agent);
  const second = await continueIdleLead(ctx, agent);
  assert.equal(first.action, 'pause');
  assert.equal(second.action, 'none');
  assert.deepEqual(calls, ['pause']);
});

test('a goal that is not the automatic round is left alone', () => {
  const goals = {
    current: { id: 'loop', revision: 1, phase: 'active', objective: 'prove access', maxGoalRounds: 4 },
    get() { return this.current; },
    pause() { throw new Error('a loop goal must keep running'); },
  };
  assert.deepEqual(stopAutomaticRounds(goals, { id: 'lead' }), { action: 'none' });
});

test('the next pass waits for the next dialogue, not another operator message', () => {
  let state = emptyState();
  state.engagement = { name: 'engagement' };
  state = applyOps(state, [
    supervisionNodeOp(state, { type: 'operator_turn', round: 1, planHash: 'operator-1', eventSeq: 1, verdict: 'hold' }),
  ]);
  assert.equal(operatorRoundOpen(state), true);
  state = applyOps(state, [
    supervisionNodeOp(state, { type: 'test_pass', round: 1, planHash: 'pass-1', basis: 'activity', operatorSeq: 1, verdict: 'hold' }),
  ]);
  assert.equal(operatorRoundOpen(state), false);
  assert.equal(nextPassDecision(state).reason, 'operator');
  state = applyOps(state, [
    supervisionNodeOp(state, { type: 'dialogue_turn', round: 2, planHash: 'dialogue-2', eventSeq: 2, verdict: 'hold' }),
  ]);
  assert.equal(operatorRoundOpen(state), true);
});

test('automatic passes do not finish the three rounds after an operator message', () => {
  let state = emptyState();
  state.engagement = { name: 'engagement' };
  state = applyOps(state, [1, 2, 3].map((round) => supervisionNodeOp(state, {
    type: 'test_pass', round, planHash: `old-${round}`, basis: 'activity', verdict: 'hold',
  })));
  assert.equal(passesComplete(state), true);
  state = applyOps(state, [
    supervisionNodeOp(state, { type: 'operator_turn', round: 1, planHash: 'operator-9', eventSeq: 9, verdict: 'hold' }),
  ]);
  assert.equal(passesComplete(state), false);
  assert.equal(operatorRoundOpen(state), true);
  assert.notEqual(nextPassDecision(state).action, 'complete');
});
