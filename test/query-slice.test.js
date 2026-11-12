import test from 'node:test';
import assert from 'node:assert/strict';

import { selectGraphSlice } from '../lib/tools/query.js';
import { graphSummary } from '../lib/graph.js';
import { emptyState } from '../lib/ops.js';

test('a short graph slice keeps findings ahead of coverage and evidence', () => {
  const nodes = [];
  for (let index = 0; index < 80; index += 1) {
    nodes.push({ id: `coverage_${index}`, kind: 'coverage', key: `/p/${index}`, status: 'open' });
  }
  for (let index = 0; index < 40; index += 1) {
    nodes.push({ id: `evidence_${index}`, kind: 'evidence', key: `ev/${index}`, status: 'stored' });
  }
  nodes.push({ id: 'finding_search', kind: 'finding', key: 'search/sqli', status: 'verified' });
  const slice = selectGraphSlice(nodes, 100);
  assert.equal(slice.some((node) => node.id === 'finding_search'), true);
  assert.equal(slice[0].kind, 'finding');
});

test('graph summary lists finding ids before bulk coverage ids', () => {
  const state = emptyState();
  state.nodes = {
    coverage_a: { id: 'coverage_a', kind: 'coverage', key: '/a', status: 'open', attrs: {} },
    finding_search: { id: 'finding_search', kind: 'finding', key: 'search/sqli', status: 'verified', attrs: { severity: 'medium' } },
  };
  state.edges = {};
  const summary = graphSummary(state);
  assert.equal(summary.nodeIds[0], 'finding_search');
});
