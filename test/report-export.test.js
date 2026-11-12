/** Report export from the client wire view (button route payload). */
import test from 'node:test';
import assert from 'node:assert/strict';

import { reportStateFromWire, renderReportExport } from '../lib/report-export.js';

function wire() {
  const finding = {
    id: 'finding:f1', kind: 'finding', key: 'f1', label: 'Example finding',
    status: 'verified', confidence: 0.9, verification: 'verified', severity: 'high',
    evidenceCount: 1, degree: 0, tags: [], attest: undefined,
    attrs: {
      title: 'Example finding', severity: 'high', category: 'xss',
      description: 'A reflected value executed in the browser.',
      impact: 'Session compromise.', repro: 'GET /?q=<script>alert(1)</script>',
      proofType: 'poc_replay', proofDetail: 'marker echoed',
      request: 'GET / HTTP/1.1\r\nHost: example.test\r\nCookie: session=secret',
      response: 'HTTP/1.1 200 OK\r\n\r\nsecret reflected',
    },
    evidenceIds: ['ev1'], firstSeen: '2026-10-31T00:00:00.000Z', lastSeen: '2026-10-31T00:01:00.000Z',
  };
  return {
    schema: 'atkbrain/1', seq: 7,
    engagement: { name: 'wire-export', authorization: 'AUTH-WIRE' },
    scope: { allow: [{ type: 'host', value: 'example.test' }], deny: [], allowCount: 1, denyCount: 0 },
    nodes: [finding], edges: [], dedupe: { unique: 1 }, auditTail: [],
  };
}

test('wire report input converts to a renderable report state', () => {
  const state = reportStateFromWire(wire());
  assert.equal(state.engagement.name, 'wire-export');
  assert.equal(Object.keys(state.nodes).length, 1);
  assert.equal(state.nodes['finding:f1'].attrs.title, 'Example finding');
});

test('report export returns markdown, html, json and csv', async () => {
  const ctx = { get: () => undefined };
  const md = await renderReportExport({ wire: wire(), format: 'markdown', ctx, config: {} });
  assert.match(md.filename, /\.md$/u);
  assert.match(md.content, /wire-export/u);
  assert.match(md.content, /Example finding/u);
  assert.equal(md.content.includes('session=secret'), false);

  const html = await renderReportExport({ wire: wire(), format: 'html', ctx, config: {} });
  assert.match(html.filename, /\.html$/u);
  assert.match(html.content, /<!doctype html>/iu);
  assert.match(html.content, /wire-export/u);

  const json = await renderReportExport({ wire: wire(), format: 'json', ctx, config: {} });
  assert.doesNotThrow(() => JSON.parse(json.content));
  assert.match(json.filename, /\.json$/u);

  const csv = await renderReportExport({ wire: wire(), format: 'csv', ctx, config: {} });
  assert.match(csv.filename, /findings\.csv$/u);
  assert.match(csv.content, /Example finding/u);
});
