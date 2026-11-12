/** Committed tests for A-U hypothesis gates and endpoint vocabulary. */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  EXPECTED_PROOFS,
  HYPOTHESIS_STATUSES,
  hypothesisSummary,
  proposeHypothesis,
  resolveHypothesis,
} from '../lib/hypothesis.js';
import { endpointInventory, harvest, parameterNames, synthesize } from '../lib/endpoint-vocab.js';

test('hypothesis lifecycle enforces evidence and specific refutation', () => {
  const proposed = proposeHypothesis({
    strategy: 'SSRF reaches an internal login page through the image importer',
    targetKey: 'host:app.example',
    bugClass: 'leak',
    expectedProof: 'poc_replay',
  });
  assert.equal(proposed.status, 'open');
  assert.equal(proposed.expectedProof, 'poc_replay');
  assert.ok(HYPOTHESIS_STATUSES.includes(proposed.status));
  assert.ok(EXPECTED_PROOFS.includes(proposed.expectedProof));

  assert.throws(() => resolveHypothesis(proposed, { status: 'verified', channels: ['body'] }), /two|evidence/u);
  const verified = resolveHypothesis(proposed, { status: 'verified', channels: ['body', 'timing'] });
  assert.equal(verified.status, 'verified');
  assert.equal(verified.channels.length, 2);

  assert.throws(() => resolveHypothesis(proposed, { status: 'disproved', note: 'closed' }), /concrete|note/u);
  const disproved = resolveHypothesis(proposed, {
    status: 'disproved',
    note: 'image importer fetched only same-origin /assets paths; no callback from the internal host',
  });
  assert.equal(disproved.status, 'disproved');

  const summary = hypothesisSummary([
    { ...proposed, status: 'open' },
    { ...proposed, targetKey: 'host:two.example', status: 'verified' },
    { ...proposed, targetKey: 'host:three.example', status: 'disproved' },
  ]);
  assert.equal(summary.total, 3);
  assert.equal(summary.open, 1);
  assert.equal(summary.verified, 1);
  assert.equal(summary.disproved, 1);
});

test('endpoint vocabulary reuses only observed words and type/role combinations', () => {
  const page = `
    <a href="/report/ReportDownloadAction.action?id=1">download</a>
    <form action="/user/giffile.action"><input name="userName"></form>
    <script src="/static/app.js"></script>
    <a href="/export">export</a>
  `;
  const { stems, exts, known } = harvest(page);
  assert.ok(known.includes('report/ReportDownloadAction.action'));
  assert.ok(known.includes('user/giffile.action'));
  assert.ok(Object.keys(exts).includes('action'));
  assert.ok(Object.keys(stems).includes('user'));
  const candidates = synthesize(page, { limit: 80 });
  assert.ok(candidates.includes('user/giffile.action'));
  assert.ok(candidates.some((path) => path.includes('giffile') && path.endsWith('.action')));
  assert.ok(!candidates.some((path) => path.includes('/admin/config.php')), 'must not invent unobserved interfaces');
  const params = parameterNames(page);
  assert.ok(params.includes('id'));
  assert.ok(params.includes('userName'));
});

test('endpoint inventory keeps bare .action endpoints and output contexts', () => {
  const page = `
    <form action="shareGroupCard.action" method="get">
      <input type="hidden" name="userId" value="\${userId}">
    </form>
    <script>
      $.ajax({url: "worddetail!execute.action", data: {searchKey: q}});
      var u = "shareGroupCard.action?userId=" + userId;
      document.getElementById("x").onclick = function () { return "${'${searchKey}'}"; };
    </script>
  `;
  const inventory = endpointInventory(page);
  assert.ok(inventory.endpoints.includes('shareGroupCard.action'));
  assert.ok(inventory.endpoints.includes('worddetail!execute.action'));
  assert.ok(inventory.parameters.includes('userId'));
  assert.ok(inventory.parameters.includes('searchKey'));
  assert.ok(inventory.contexts.includes('hidden-input-value'));
  assert.ok(inventory.contexts.includes('inline-event-handler'));
  assert.ok(inventory.contexts.includes('form-action'));
});

test('endpoint inventory generalizes to JSON/fetch API routes and JS parameter objects', () => {
  const page = `
    fetch("/api/share/" + id);
    $.ajax({url: "/v2/items", method: "POST", data: {userId: u, searchKey: q}});
    axios.get("/api/profile/42");
  `;
  const inventory = endpointInventory(page);
  assert.ok(inventory.endpoints.some((endpoint) => endpoint.includes('api/share')), 'fetch route missing');
  assert.ok(inventory.endpoints.some((endpoint) => endpoint.includes('v2/items')), 'ajax route missing');
  assert.ok(inventory.endpoints.some((endpoint) => endpoint.includes('api/profile')), 'axios route missing');
  assert.ok(inventory.parameters.includes('userId'));
  assert.ok(inventory.parameters.includes('searchKey'));
  assert.ok(inventory.jsRoutes.length >= 2);
});
