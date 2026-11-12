/** Autonomous loop is not registered in this edition. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { apply } from '../index.js';

test('atkbrain_loop is not registered; survey and tunnel stay', () => {
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
  assert.equal(tools.has('atkbrain_loop'), false);
  assert.equal(tools.has('atkbrain_team'), false);
  assert.equal(tools.has('atkbrain_survey'), true);
  assert.equal(tools.has('atkbrain_tunnel'), true);
});
