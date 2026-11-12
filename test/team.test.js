/** Parallel asset teams are not registered, and the frontier does not split targets. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { apply } from '../index.js';
import { computeFrontier } from '../lib/frontier.js';
import { applyOps, emptyState, nodeOp } from '../lib/ops.js';

test('atkbrain_team is not registered', () => {
  const tools = new Map();
  const ctx = {
    logger: { warn() {}, info() {} },
    sessionProjections: { stateOf: () => ({ nodes: {}, edges: {} }), register: () => () => {} },
    systemPrompt: { section: () => () => {} },
    effect(fn) { const dispose = fn(); return () => { if (typeof dispose === 'function') dispose(); }; },
    tools: {
      register(definition) { tools.set(definition.name, definition); return () => {}; },
      get(name) { return tools.get(name); },
    },
    get() { return undefined; },
  };
  apply(ctx, { requireScopeApproval: false, requireTunnelApproval: false });
  assert.equal(tools.has('atkbrain_team'), false);
  assert.equal(tools.has('atkbrain_survey'), true);
  assert.equal(tools.has('atkbrain_tunnel'), true);
});

test('several operator targets do not become a parallel team action', () => {
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'three-targets', authorization: 'AUTH-3' } },
    {
      op: 'scope.set',
      allow: [
        { type: 'ip', value: '192.0.2.1', canonical: '192.0.2.1' },
        { type: 'ip', value: '192.0.2.2', canonical: '192.0.2.2' },
      ],
      deny: [],
    },
    nodeOp('ip', '192.0.2.1', '192.0.2.1', { addr: '192.0.2.1', version: 4 }),
    nodeOp('ip', '192.0.2.2', '192.0.2.2', { addr: '192.0.2.2', version: 4 }),
  ]);
  const frontier = computeFrontier(state);
  assert.equal(frontier.some((action) => action.actionType === 'parallel_targets'), false);
  assert.notEqual(frontier[0]?.actionType, 'parallel_targets');
});
