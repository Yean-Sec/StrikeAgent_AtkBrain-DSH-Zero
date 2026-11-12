/** Project completion is gated on a fresh project-level HTML report. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { engagementGaps, projectCompletion } from '../lib/project-completion.js';

function stateWith({ reportPath = null, reportAt = null, reportKind = null, impactAt = null } = {}) {
  const ops = [];
  if (reportPath !== null) {
    ops.push(nodeOp('self_team', 'selfteam/report', '报告撰写团队', {
      type: 'report',
      lastReportPath: reportPath,
      lastReportAt: reportAt,
      ...(reportKind ? { lastReportKind: reportKind } : {}),
    }, { status: 'active' }));
  }
  if (impactAt !== null) {
    ops.push(nodeOp('finding', 'project/finding', 'project finding', {
      title: 'project finding', severity: 'medium', cvssScore: 5.3,
    }, { status: 'verified', verification: 'verified' }));
  }
  let state = emptyState();
  state = applyOps(state, ops, impactAt ?? '2026-10-31T00:00:00.000Z');
  if (impactAt !== null) {
    state.nodes.finding_9d2141af1f6e73e9 = { ...state.nodes.finding_9d2141af1f6e73e9, lastSeen: impactAt };
  }
  return state;
}

function setFindingTime(state, at) {
  state = state; // no-op guard
}

test('project is incomplete without a project HTML report', () => {
  const result = projectCompletion(emptyState());
  assert.equal(result.complete, false);
  assert.match(result.reason, /报告撰写|report/i);
});

test('single-finding report does not complete the project', () => {
  let state = emptyState();
  state = applyOps(state, [
    nodeOp('self_team', 'selfteam/report', '报告撰写团队', {
      type: 'report',
      lastReportPath: '.atkbrain/reports/finding.html',
      lastReportAt: '2026-10-31T02:00:00.000Z',
      lastReportKind: 'finding',
    }, { status: 'active' }),
  ], '2026-10-31T03:00:00.000Z');
  const result = projectCompletion(state);
  assert.equal(result.complete, false);
  assert.match(result.reason, /not a project-level report/i);
});

test('fresh project HTML report after latest impact completes the project', () => {
  let state = emptyState();
  state = applyOps(state, [
    nodeOp('finding', 'project/finding', 'project finding', {
      title: 'project finding', severity: 'medium', cvssScore: 5.3,
    }, { status: 'verified', verification: 'verified' }),
    nodeOp('self_team', 'selfteam/report', '报告撰写团队', {
      type: 'report',
      lastReportPath: '.atkbrain/reports/project.html',
      lastReportAt: '2026-10-31T03:00:00.000Z',
      lastReportKind: 'project',
    }, { status: 'active' }),
  ], '2026-10-31T03:00:00.000Z');
  const finding = Object.values(state.nodes).find((node) => node.kind === 'finding');
  finding.lastSeen = '2026-10-31T02:00:00.000Z';
  const result = projectCompletion(state);
  assert.equal(result.complete, true);
  assert.equal(result.reportKind, 'project');
  assert.equal(result.reportPath, '.atkbrain/reports/project.html');
});

test('a missing page ledger is a hint and does not block a fresh project report', () => {
  let state = emptyState();
  state = applyOps(state, [
    nodeOp('webapp', 'https://app.example', 'https://app.example', { url: 'https://app.example' }),
    nodeOp('self_team', 'selfteam/report', '报告撰写团队', {
      type: 'report',
      lastReportPath: '.atkbrain/reports/project.html',
      lastReportAt: '2026-10-31T03:00:00.000Z',
      lastReportKind: 'project',
    }, { status: 'active' }),
  ], '2026-10-31T03:00:00.000Z');
  const result = projectCompletion(state);
  assert.equal(result.complete, true);
  assert.equal(result.reason, null);
  assert.ok(engagementGaps(state).includes('endpoint_vocab'));
  assert.deepEqual(result.capabilities.missing, []);
});

test('a draft report does not complete the project', () => {
  let state = emptyState();
  state = applyOps(state, [
    nodeOp('self_team', 'selfteam/report', '报告撰写团队', {
      type: 'report',
      lastReportPath: '.atkbrain/reports/project.html',
      lastReportAt: '2026-10-31T03:00:00.000Z',
      lastReportKind: 'draft',
    }, { status: 'active' }),
  ], '2026-10-31T03:00:00.000Z');
  const result = projectCompletion(state);
  assert.equal(result.complete, false);
  assert.equal(result.reportKind, 'draft');
  assert.match(result.reason, /not a project-level report/i);
});

test('a vulnerability without validated access stays a hint after the project report', () => {
  let state = emptyState();
  state = applyOps(state, [
    nodeOp('finding', 'project/xss', 'stored xss', {
      title: '存储型 XSS', severity: 'high', cvssScore: 8.1, secondaryVerified: true,
    }, { status: 'verified', verification: 'verified' }),
    nodeOp('self_team', 'selfteam/report', '报告撰写团队', {
      type: 'report',
      lastReportPath: '.atkbrain/reports/project.html',
      lastReportAt: '2026-10-31T03:00:00.000Z',
      lastReportKind: 'project',
    }, { status: 'active' }),
  ], '2026-10-31T03:00:00.000Z');
  const finding = Object.values(state.nodes).find((node) => node.kind === 'finding');
  finding.lastSeen = '2026-10-31T02:00:00.000Z';
  const result = projectCompletion(state);
  assert.equal(result.complete, true);
  assert.equal(result.reason, null);
  assert.ok(engagementGaps(state).includes('validated access'));
});

test('open coverage cells stay visible and do not block a fresh project report', () => {
  let state = emptyState();
  state = applyOps(state, [
    nodeOp('coverage', 'coverage/login/xss', '/login.action × xss', {
      path: '/login.action', bugClass: 'xss', status: 'open',
    }, { status: 'open' }),
    nodeOp('self_team', 'selfteam/report', '报告撰写团队', {
      type: 'report',
      lastReportPath: '.atkbrain/reports/project.html',
      lastReportAt: '2026-10-31T03:00:00.000Z',
      lastReportKind: 'project',
    }, { status: 'active' }),
  ], '2026-10-31T03:00:00.000Z');
  const result = projectCompletion(state);
  assert.equal(result.complete, true);
  assert.equal(result.reportComplete, true);
  assert.equal(result.coverage.complete, false);
  assert.equal(result.reason, null);
  assert.ok(engagementGaps(state).includes('coverage'));
});
