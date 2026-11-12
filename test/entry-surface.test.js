/** An operator URL is an entry. One login page does not inventory the application. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { applicationExpanded, mergeLedgerAttrs } from '../lib/endpoint-vocab.js';
import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { computeFrontier } from '../lib/frontier.js';
import { deterministicPlan } from '../lib/loop/supervisor.js';
import { fallbackSelfBrief } from '../lib/loop/selftteam.js';

test('a login page stays uninventoried until a second module path appears', () => {
  const login = mergeLedgerAttrs(
    { url: 'http://app.example/login.php', entryPath: '/login.php' },
    '<form action="/login.php"><input name="username"></form>',
    { inventoried: true },
  );
  assert.equal(login.entryPath, '/login.php');
  assert.equal(login.surfaceInventoried, false);
  assert.equal(applicationExpanded(login), false);
  const modules = mergeLedgerAttrs(
    login,
    '<form action="/login.php"><input name="username"></form><form action="/modules/exec.php"></form>',
    { inventoried: true },
  );
  assert.equal(modules.surfaceInventoried, true);
  assert.equal(applicationExpanded(modules), true);
});

test('the frontier inventories the application before verifying the entry finding', () => {
  const state = applyOps(emptyState(), [
    { op: 'engagement.set', engagement: { name: 'entry', authorization: 'AUTH-1' } },
    { op: 'scope.set', allow: [{ type: 'url', value: 'http://app.example/login.php', canonical: 'http://app.example/login.php' }], deny: [] },
    nodeOp('webapp', 'http://app.example/login.php', 'http://app.example/login.php', {
      url: 'http://app.example/login.php',
      host: 'app.example',
      path: '/login.php',
      entryPath: '/login.php',
      title: 'Example App',
      endpoints: ['/login.php'],
      surfaceInventoried: false,
    }),
    nodeOp('finding', 'login-cookie', 'cookie attribute', {
      template: 'cookie',
      title: 'cookie attribute',
      severity: 'high',
    }, { status: 'candidate' }),
  ]);
  const frontier = computeFrontier(state, { limit: 5 });
  assert.equal(frontier[0].actionType, 'expand_application');
  const verify = frontier.findIndex((action) => action.actionType === 'verify_finding');
  assert.ok(verify < 0 || verify > 0);
});

test('a thin application surface tells the supervisor to inventory modules', () => {
  const state = {
    engagement: { name: 'entry' },
    nodes: {
      app: {
        id: 'app',
        kind: 'webapp',
        status: 'open',
        attrs: { entryPath: '/login.php', endpoints: ['/login.php'], url: 'http://app.example/login.php' },
      },
      finding: {
        id: 'finding',
        kind: 'finding',
        status: 'candidate',
        attrs: { severity: 'high', title: 'cookie' },
      },
    },
    edges: {},
    scope: { allow: [{ type: 'host', value: 'app.example' }] },
  };
  const plan = deterministicPlan({
    state,
    loop: { status: 'running', attrs: { objectiveType: 'impact', round: 1 } },
    latest: null,
    frontier: [],
    config: {},
  });
  assert.match(plan.nextPlan, /only an entry/);
  assert.doesNotMatch(plan.nextPlan, /before any new enumeration/);
  const brief = fallbackSelfBrief({
    remembered: [],
    gained: [],
    metrics: { validatedAccess: 0, verifiedFindings: 0, candidateHighCritical: 1 },
    deadlockRisk: 'low',
    surfaceThin: true,
  });
  assert.match(brief.advice, /Inventory the application modules/);
  assert.doesNotMatch(brief.advice, /do not start a second enumeration path/);
});
