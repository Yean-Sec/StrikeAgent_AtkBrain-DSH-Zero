/** Native DSH Agent Teams mirror of the five non-Lead AtkBrain teams. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { NATIVE_TEAM_SPECS, clearResidentCooldowns, ensureNativeTeams, notifyResidentTeams, verifierWakeText } from '../lib/native-teams.js';
import { escalationWakeText, pendingEscalations } from '../lib/escalation-queue.js';
import { evidenceStamp } from '../lib/verify-queue.js';
import { bootstrapSelfTeamOps, selfTeamOp } from '../lib/self-teams.js';
import { runSubagentText } from '../lib/loop/supervisor.js';
import { computeFrontier } from '../lib/frontier.js';
import { supervisionMemory } from '../lib/supervision-memory.js';

test('ensureNativeTeams spawns the lower-kebab-case durable teammates and skips existing', async () => {
  const calls = [];
  const agentTeams = {
    async listMembers() {
      return [{ id: 'lead-1', name: 'lead', role: 'lead', status: 'running' }, { id: 'sup-1', name: 'atk-supervisor', role: 'teammate', status: 'inactive' }];
    },
    async spawnTeammate(_agent, request) {
      calls.push(request);
      return { member: { id: `id-${request.name}`, name: request.name, role: 'teammate', status: 'provisioning' } };
    },
  };
  const result = await ensureNativeTeams({ agentTeams, agent: { id: 'lead-1' }, signal: new AbortController().signal });
  assert.equal(result.available, true);
  assert.deepEqual(calls.map((call) => call.name).sort(), ['atk-reporter', 'atk-verifier']);
  assert.equal(result.spawned.length, 2);
  assert.equal(result.existing.length, 1);
  assert.ok(result.spawned.every((member) => /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(member.name)));
  assert.ok(calls.every((call) => call.description.length > 0));
  const verifier = calls.find((call) => call.name === 'atk-verifier');
  assert.match(verifier.prompt[0].text, /end the turn/);
  assert.match(verifier.prompt[0].text, /later conversation/);
  assert.equal(verifier.prompt[0].text.includes('Stop when the Lead has finished'), false);
  assert.match(verifier.prompt[0].text, /that lead graph/);
  assert.doesNotMatch(verifier.prompt[0].text, /skill_get/);
  assert.equal(calls.some((call) => call.name === 'atk-escalator'), false);
  assert.equal(verifier.prompt[0].text.includes('wait_agent'), false);
  assert.equal(verifier.prompt[0].text.includes('exactly READY'), false);
  assert.ok(calls.every((call) => call.prompt[0].text.includes('end the turn')));
  assert.ok(calls.every((call) => !call.prompt[0].text.includes('wait_agent')));
  assert.ok(calls.every((call) => !call.prompt[0].text.includes('no other member is running')));
  assert.ok(calls.every((call) => !call.prompt[0].text.includes('exactly READY')));
  assert.ok(NATIVE_TEAM_SPECS.every((spec) => spec.name !== 'lead'));
});

test('ensureNativeTeams leaves an inactive teammate stopped when there is no queue', async () => {
  const sent = [];
  const agentTeams = {
    async listMembers() {
      return [
        { id: 'lead-1', name: 'lead', role: 'lead', status: 'running' },
        { id: 'sup-9', name: 'atk-supervisor', role: 'teammate', status: 'inactive' },
        { id: 'ver-9', name: 'atk-verifier', role: 'teammate', status: 'running' },
      ];
    },
    async spawnTeammate(_agent, request) {
      return { member: { id: `id-${request.name}`, name: request.name, status: 'provisioning' } };
    },
    async sendMessage(_agent, request) {
      sent.push(request.target);
    },
  };
  await ensureNativeTeams({ agentTeams, agent: { id: 'lead-1' }, signal: new AbortController().signal });
  assert.deepEqual(sent, []);
});

test('an inactive verifier is woken with the pending queue', async () => {
  const sent = [];
  const agentTeams = {
    async listMembers() {
      return [
        { id: 'lead-1', name: 'lead', role: 'lead', status: 'running' },
        { id: 'ver-9', name: 'atk-verifier', role: 'teammate', status: 'inactive' },
      ];
    },
    async spawnTeammate(_agent, request) {
      return { member: { id: `id-${request.name}`, name: request.name, status: 'provisioning' } };
    },
    async sendMessage(_agent, request) {
      sent.push(request);
    },
  };
  const pending = [{ id: 'finding:1', key: 'finding/1', label: 'recorded issue' }];
  await ensureNativeTeams({ agentTeams, agent: { id: 'lead-1' }, signal: new AbortController().signal, pending });
  const verifier = sent.find((message) => message.target === 'atk-verifier');
  assert.ok(verifier);
  assert.match(verifier.content[0].text, /finding:1/);
  assert.match(verifier.content[0].text, /假阳性/);
  assert.equal(verifier.content[0].text.includes('exactly READY'), false);
  assert.match(verifierWakeText(pending), /finding:1/);
  assert.match(verifierWakeText(pending), /后面的对话/);
  assert.equal(verifierWakeText(pending).includes('不要继续开工'), false);
});

test('ensureNativeTeams degrades when the native service is unavailable', async () => {
  const result = await ensureNativeTeams({ agentTeams: null, agent: { id: 'lead-1' }, signal: new AbortController().signal });
  assert.equal(result.available, false);
  assert.deepEqual(result.spawned, []);
});

test('runSubagentText delivers the role brief to the existing native teammate', async () => {
  const messages = [];
  const tasks = [];
  let spawned = 0;
  const ctx = {
    get(name) {
      if (name === 'agentTeams') {
        return {
          async createTask(_agent, request) {
            tasks.push(request);
            return { id: 'task-1', revision: 1 };
          },
          async updateTask(_agent, request) {
            tasks.push(request);
            return { id: request.taskId, revision: 2 };
          },
          async sendMessage(_agent, request) {
            messages.push({ id: 'msg-1', role: 'user', content: request.content });
            messages.push({ id: 'asst-1', role: 'assistant', content: [{ type: 'text', text: '{"lessons":[],"skills":[]}' }] });
            return { messageId: 'msg-1' };
          },
        };
      }
      if (name === 'agents') return { get() { return { session: { deriveMessages: () => messages } }; } };
      if (name === 'subagents') {
        return { async startActivation() { spawned += 1; throw new Error('fresh spawn'); } };
      }
      return undefined;
    },
  };
  const result = await runSubagentText({
    ctx,
    agent: { id: 'lead' },
    brief: 'review the graph',
    signal: new AbortController().signal,
    timeoutMs: 2000,
    label: 'AtkBrain self-evolution team',
    native: { id: 'evo-1', name: 'atk-evolver', teamType: 'evolution' },
  });
  assert.equal(spawned, 0);
  assert.equal(result.via, 'native-team');
  assert.equal(result.childId, 'evo-1');
  assert.match(result.text, /"lessons"/);
  assert.equal(tasks[0].subject, '[AtkBrain] evolution');
  assert.equal(tasks[1].owner, 'atk-evolver');
  assert.equal(tasks[1].action, 'reassign');
  assert.equal(tasks.some((task) => task.action === 'complete' && task.taskId === 'task-1'), true);
});

test('runSubagentText falls back to a fresh child when the native teammate cannot be reached', async () => {
  let spawned = 0;
  const ctx = {
    get(name) {
      if (name === 'agentTeams') return { async sendMessage() { throw new Error('offline'); } };
      if (name === 'agents') return { get() { return { session: { deriveMessages: () => [] } }; } };
      if (name === 'subagents') {
        return {
          async startActivation() {
            spawned += 1;
            return { childId: 'fresh-1', result: Promise.resolve({ output: [{ type: 'text', text: '{"ok":true}' }] }) };
          },
        };
      }
      return undefined;
    },
  };
  const result = await runSubagentText({
    ctx,
    agent: { id: 'lead' },
    brief: 'review',
    signal: new AbortController().signal,
    native: { id: 'evo-1', name: 'atk-evolver', teamType: 'evolution' },
  });
  assert.equal(spawned, 1);
  assert.equal(result.via, 'subagent');
  assert.equal(result.childId, 'fresh-1');
  assert.equal(result.error, null);
});

test('frontier schedules a stale supervision brief and does not schedule evolution', () => {
  let state = emptyState();
  state.engagement = { name: 'demo', authorization: 'operator authorized' };
  state.scope.allow = ['app.example'];
  state = applyOps(state, bootstrapSelfTeamOps(state));
  state = applyOps(state, [
    selfTeamOp(state, 'supervision', { lastBriefAt: '2026-10-31T14:08:00.000Z' }),
    nodeOp('finding', 'finding/exposure', 'exposure', { createdAt: '2026-10-31T14:13:00.000Z', severity: 'medium' }, { status: 'verified' }),
  ]);
  const types = computeFrontier(state, { limit: 100 }).map((action) => action.actionType);
  assert.ok(types.includes('self_brief'));
  assert.equal(types.includes('self_evolve_review'), false);
  assert.equal(types.includes('self_distill'), false);
});

test('supervision stays silent until the graph has something to hand back', () => {
  let state = emptyState();
  state.engagement = { name: 'demo', authorization: 'operator authorized' };
  state.scope.allow = ['app.example'];
  state = applyOps(state, bootstrapSelfTeamOps(state));
  state = applyOps(state, [selfTeamOp(state, 'supervision', {})]);
  state = applyOps(state, [
    nodeOp('webapp', 'https://app.example/', 'https://app.example/', { url: 'https://app.example/', host: 'app.example', endpoints: ['/'] }),
  ]);
  assert.equal(computeFrontier(state, { limit: 100 }).some((action) => action.actionType === 'self_brief'), false);
  state = applyOps(state, [
    nodeOp('tech', 'apache/tomcat/9.0.45', 'Apache Tomcat/9.0.45', { product: 'Tomcat', version: '9.0.45' }),
  ]);
  const brief = computeFrontier(state, { limit: 100 }).find((action) => action.actionType === 'self_brief');
  assert.ok(brief);
  assert.match(brief.why.join(' '), /hand back/i);
});

test('supervision memory restates stored paths and parameter names', () => {
  const rows = supervisionMemory([{
    kind: 'webapp',
    status: 'observed',
    label: 'app',
    attrs: {
      host: 'app.example',
      surfaceInventoried: true,
      endpoints: ['/login.action', '/menu.action'],
      parameterMap: { '/login.action': ['user', 'token'] },
      contextMap: { '/login.action': ['form'] },
      updatedAt: '2026-11-01T00:00:00.000Z',
    },
  }]);
  assert.equal(rows.length, 1);
  assert.match(rows[0].text, /\/login\.action/);
  assert.match(rows[0].text, /user, token/);
  assert.match(rows[0].text, /form/);
  assert.doesNotMatch(rows[0].text, /endpoints \d/);
});

test('an inactive harm-escalation teammate is woken with finding labels only', async () => {
  const sent = [];
  const agentTeams = {
    async listMembers() {
      return [
        { id: 'lead-1', name: 'lead', role: 'lead', status: 'running' },
        { id: 'esc-9', name: 'atk-escalator', role: 'teammate', status: 'inactive' },
      ];
    },
    async spawnTeammate(_agent, request) {
      return { member: { id: `id-${request.name}`, name: request.name, status: 'provisioning' } };
    },
    async sendMessage(_agent, request) {
      sent.push(request);
    },
  };
  const pending = [{ id: 'finding:9', key: 'finding/9', label: '存储型 XSS' }];
  await ensureNativeTeams({
    agentTeams,
    agent: { id: 'lead-1' },
    signal: new AbortController().signal,
    escalationPending: pending,
  });
  assert.equal(sent.some((entry) => entry.target === 'atk-escalator'), false);
  assert.equal(escalationWakeText(pending).includes('利用步骤'), false);
});

test('a running harm-escalation teammate receives the queue after verification', async () => {
  const sent = [];
  const agentTeams = {
    async listMembers() {
      return [{ id: 'esc-9', name: 'atk-escalator', role: 'teammate', status: 'running' }];
    },
    async spawnTeammate() {
      throw new Error('already running');
    },
    async sendMessage(_agent, request) {
      sent.push(request);
    },
  };
  const result = await notifyResidentTeams({
    agentTeams,
    agent: { id: 'lead-1' },
    signal: new AbortController().signal,
    state: { nodes: {} },
    escalationPending: [{ id: 'finding:9', label: 'stored issue' }],
    forceEscalation: true,
  });
  assert.deepEqual(result.sent, []);
  assert.equal(sent.length, 0);
});

test('refuted findings and unchanged escalation attempts leave the harm queue', () => {
  const base = {
    template: 'xss',
    title: '存储型 XSS',
    severity: 'high',
    secondaryVerified: true,
    cvssScore: 8.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    cvssSeverity: 'HIGH',
  };
  let state = applyOps(emptyState(), [
    nodeOp('finding', 'queue/xss', '存储型 XSS', base, { status: 'verified', verification: 'verified' }),
  ]);
  assert.equal(pendingEscalations(state).length, 1);
  state = applyOps(emptyState(), [
    nodeOp('finding', 'queue/xss', '存储型 XSS', { ...base, secondaryVerdict: 'refuted', secondaryVerified: false }, { status: 'candidate' }),
  ]);
  assert.equal(pendingEscalations(state).length, 0);
  state = applyOps(emptyState(), [
    nodeOp('finding', 'queue/xss', '存储型 XSS', base, { status: 'verified', verification: 'verified' }),
  ]);
  const finding = Object.values(state.nodes).find((node) => node.kind === 'finding');
  state = applyOps(state, [{
    op: 'node.upsert',
    kind: 'finding',
    key: finding.key,
    label: finding.label,
    attrs: { escalationAttempts: 3, escalationAttemptEvidence: evidenceStamp(finding) },
    status: finding.status,
  }]);
  assert.equal(pendingEscalations(state).length, 0);
});

test('a later conversation wakes a stopped team again when the work is still due', async () => {
  clearResidentCooldowns();
  const sent = [];
  const agentTeams = {
    async listMembers() {
      return [
        { id: 'ver-9', name: 'atk-verifier', status: 'inactive' },
        { id: 'evo-9', name: 'atk-evolver', status: 'inactive' },
        { id: 'rep-9', name: 'atk-reporter', status: 'inactive' },
        { id: 'sup-9', name: 'atk-supervisor', status: 'inactive' },
        { id: 'esc-9', name: 'atk-escalator', status: 'inactive' },
      ];
    },
    async spawnTeammate() {
      throw new Error('already present');
    },
    async sendMessage(_agent, request) {
      sent.push(request.target);
    },
  };
  const pending = [{ id: 'finding:1', key: 'finding/1', label: 'recorded issue' }];
  const state = {
    nodes: {
      access: { kind: 'access', status: 'validated', key: 'access/1', label: 'shell', attrs: { createdAt: '2026-11-03T00:00:00.000Z' } },
      pass1: { kind: 'supervision', attrs: { type: 'test_pass', round: 1, basis: 'activity' } },
      pass2: { kind: 'supervision', attrs: { type: 'test_pass', round: 2, basis: 'activity' } },
      pass3: { kind: 'supervision', attrs: { type: 'test_pass', round: 3, basis: 'activity' } },
    },
    edges: {},
  };
  await ensureNativeTeams({ agentTeams, agent: { id: 'lead-1' }, signal: new AbortController().signal, pending });
  await notifyResidentTeams({ agentTeams, agent: { id: 'lead-1' }, signal: new AbortController().signal, state, resume: true });
  assert.ok(sent.includes('atk-verifier'));
  assert.equal(sent.includes('atk-evolver'), false);
  assert.ok(sent.includes('atk-reporter'));
  const before = sent.length;
  await ensureNativeTeams({ agentTeams, agent: { id: 'lead-1' }, signal: new AbortController().signal, pending });
  await notifyResidentTeams({ agentTeams, agent: { id: 'lead-1' }, signal: new AbortController().signal, state });
  assert.equal(sent.length, before);
  await ensureNativeTeams({ agentTeams, agent: { id: 'lead-1' }, signal: new AbortController().signal, pending, resume: true });
  await notifyResidentTeams({ agentTeams, agent: { id: 'lead-1' }, signal: new AbortController().signal, state, resume: true });
  assert.ok(sent.slice(before).includes('atk-verifier'));
  assert.equal(sent.slice(before).includes('atk-evolver'), false);
  assert.ok(sent.slice(before).includes('atk-reporter'));
});
