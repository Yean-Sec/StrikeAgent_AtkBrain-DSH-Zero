/**
 * Resident teammates must read and write the lead attack graph.
 * Asset workers keep the empty child graph and merge later.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { apply } from '../index.js';
import { LEDGER_EVENT } from '../lib/constants.js';
import { RESIDENT_GRAPH_WRITERS, loadSessionModuleFrom } from '../lib/ledger-host.js';
import { NATIVE_TEAM_SPECS } from '../lib/native-teams.js';
import { applyOps, emptyState, nodeOp } from '../lib/ops.js';

const CVSS = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';

function locateDshBin() {
  const root = join(homedir(), '.npm', '_npx');
  if (!existsSync(root)) return undefined;
  let hashes = [];
  try {
    hashes = readdirSync(root);
  } catch {
    return undefined;
  }
  for (const hash of hashes) {
    const bin = join(root, hash, 'node_modules', '.bin', 'dsh');
    if (existsSync(bin)) return bin;
  }
  return undefined;
}

function createHarness() {
  let leadState = applyOps(emptyState(), [
    nodeOp('finding', 'sample', 'sample finding', { title: 'sample finding', severity: 'low' }),
  ]);
  const records = [];
  const leadSession = {
    id: 'lead',
    header: {},
    appendPluginRecord(type, data) {
      records.push({ type, data });
    },
  };
  const lead = { id: 'lead', session: leadSession };
  const agents = new Map([['lead', lead]]);
  const tools = new Map();
  let projection;
  const ctx = {
    logger: { warn() {}, info() {} },
    sessionProjections: {
      stateOf(session) {
        return session === leadSession ? leadState : emptyState();
      },
      register(definition) {
        projection = definition;
        return () => {};
      },
    },
    systemPrompt: { section: () => () => {} },
    effect(fn) {
      const dispose = fn();
      return () => { if (typeof dispose === 'function') dispose(); };
    },
    tools: {
      register(definition) {
        tools.set(definition.name, definition);
        return () => {};
      },
    },
    agents,
    get(name) {
      if (name === 'agents') return agents;
      if (name === 'agentTeams') {
        return {
          membership(agent) {
            if (agent.id === 'lead') return { role: 'lead' };
            if (RESIDENT_GRAPH_WRITERS.has(agent.id)) return { name: agent.id, role: 'teammate' };
            return { name: agent.id, role: 'teammate' };
          },
        };
      }
      if (name === 'approval') return { async request() { return 'allowed-once'; } };
      return undefined;
    },
  };
  apply(ctx, {});
  function teammate(name, parentId = 'lead') {
    const session = { id: name, header: { parentSession: parentId } };
    const agent = { id: name, session };
    agents.set(name, agent);
    return agent;
  }
  async function run(name, args, agent) {
    const tool = tools.get(name);
    assert.ok(tool, `tool ${name} was not registered`);
    return tool.execute(args, {
      agent,
      callId: `call-${name}`,
      name,
      signal: new AbortController().signal,
      arguments: args,
    });
  }
  return {
    lead,
    leadState: () => leadState,
    records,
    projection,
    teammate,
    run,
    tool: (name) => tools.get(name),
  };
}

test('resident graph writers are exactly the native teammates', () => {
  assert.deepEqual(
    [...RESIDENT_GRAPH_WRITERS].sort(),
    NATIVE_TEAM_SPECS.map((spec) => spec.name).sort(),
  );
});

test('a resident reads the lead graph and a worker still sees its own empty graph', async () => {
  const harness = createHarness();
  const worker = harness.teammate('asset-worker');
  const workerStats = await harness.run('atkbrain_query', { action: 'stats' }, worker);
  assert.match(workerStats.summary, /Graph #0: 0 node/);
  assert.equal(harness.records.length, 0);

  for (const name of RESIDENT_GRAPH_WRITERS) {
    const stats = await harness.run('atkbrain_query', { action: 'stats' }, harness.teammate(name));
    assert.match(stats.summary, /Graph #\d+: [1-9]/, name);
  }

  const finding = Object.values(harness.leadState().nodes).find((node) => node.kind === 'finding');
  const leadRated = await harness.run('atkbrain_supervise', {
    action: 'rate',
    findingId: finding.id,
    cvssVector: CVSS,
  }, harness.lead);
  assert.ok(leadRated.ops.length > 0);
  assert.equal(harness.records.length, 0);

  const verifier = harness.teammate('atk-verifier');
  const rated = await harness.run('atkbrain_supervise', {
    action: 'rate',
    findingId: finding.id,
    cvssVector: CVSS,
  }, verifier);
  assert.match(rated.summary, /CVSS v3\.1/);
  assert.equal(rated.ops.length, 0);
  assert.deepEqual(harness.tool('atkbrain_supervise').output.presentationMeta({}, rated).ops, []);
  assert.equal(harness.records.length, 1);
  assert.equal(harness.records[0].type, LEDGER_EVENT);
  const folded = harness.projection.apply(harness.leadState(), {
    type: harness.records[0].type,
    data: harness.records[0].data,
  });
  const updated = Object.values(folded.nodes).find((node) => node.kind === 'finding');
  assert.equal(updated.attrs.cvssVector, CVSS);
  assert.equal(typeof updated.attrs.cvssScore, 'number');
  assert.ok(updated.attrs.cvssScore > 0);

  const orphan = harness.teammate('atk-verifier-orphan', 'missing');
  orphan.id = 'atk-verifier';
  await assert.rejects(
    () => harness.run('atkbrain_query', { action: 'stats' }, orphan),
    /lead attack graph is not available/,
  );
});

test('the projection folds a lead tool result and ignores a foreign record', () => {
  const harness = createHarness();
  const ops = [nodeOp('host', '10.0.0.1', '10.0.0.1', { fqdn: '10.0.0.1' })];
  const folded = harness.projection.apply(emptyState(), {
    type: 'tool/result',
    data: { meta: { schema: 'atkbrain/1', at: '2026-11-01T00:00:00.000Z', ops } },
  });
  assert.equal(Object.values(folded.nodes).some((node) => node.kind === 'host'), true);
  const base = emptyState();
  assert.equal(harness.projection.apply(base, {
    type: LEDGER_EVENT,
    data: { schema: 'other', ops },
  }), base);
  assert.equal(harness.projection.apply(base, { type: 'user/message', data: {} }), base);
});

const dshBin = locateDshBin();

test('a host plugin record stays off the model transcript and folds into the graph', { skip: dshBin === undefined ? 'host session package is not installed' : false }, async () => {
  const mod = await loadSessionModuleFrom(dshBin);
  assert.equal(typeof mod?.appendPluginRecord, 'function');
  assert.equal(typeof mod?.Session?.create, 'function');
  const session = mod.Session.create('session-lead-ledger');
  const ops = [nodeOp('finding', 'sample', 'sample finding', { title: 'sample finding', severity: 'low' })];
  mod.appendPluginRecord(session, LEDGER_EVENT, {
    schema: 'atkbrain/1',
    at: '2026-11-01T00:00:00.000Z',
    ops,
  });
  const event = session.snapshotEvents().find((item) => item.type === LEDGER_EVENT);
  assert.ok(event);
  assert.equal(event.ignorable, true);
  assert.equal(session.surface.nodes.includes(event.seq), false);
  const harness = createHarness();
  const folded = harness.projection.apply(emptyState(), event);
  const finding = Object.values(folded.nodes).find((node) => node.kind === 'finding');
  assert.equal(finding.attrs.title, 'sample finding');
});
