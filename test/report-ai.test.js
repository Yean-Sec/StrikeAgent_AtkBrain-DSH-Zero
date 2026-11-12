/** Report-writing AI team: facts, parsing, merge and rendered narrative. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { buildReportAiBrief, mergeReportNarrative, parseReportAiOutput, runReportAi } from '../lib/report-ai.js';
import { renderHtmlReport } from '../lib/report-html.js';

function state() {
  return {
    schema: 'atkbrain/1', seq: 3,
    engagement: { name: 'ai-report', authorization: 'AUTH-AI' },
    scope: { allow: [{ type: 'host', value: 'example.test' }], deny: [] },
    nodes: {
      'finding:f1': {
        id: 'finding:f1', kind: 'finding', key: 'f1', label: 'Upload webshell', status: 'verified', verification: 'verified', severity: 'critical',
        attrs: {
          title: 'Upload webshell', severity: 'critical', category: 'rce', description: 'PHP upload served from /uploads.',
          impact: 'www-data command execution.', request: 'GET /uploads/shell.php HTTP/1.1\nCookie: session=SECRET',
          response: 'HTTP/1.1 200 OK\n\nuid=33(www-data)', repro: 'GET /uploads/shell.php?x=id with no auth',
          proofType: 'poc_replay', secondaryVerified: true, redteamRating: 'critical',
        },
        evidenceIds: ['ev1'],
      },
      'finding:f2': {
        id: 'finding:f2', kind: 'finding', key: 'f2', label: 'Candidate only', status: 'candidate', verification: 'unverified', severity: 'high',
        attrs: { title: 'Candidate only', severity: 'high' }, evidenceIds: [],
      },
    },
    edges: {}, aliases: {}, audit: [], stats: {},
  };
}

test('report team facts include verified findings and redact packets', () => {
  const brief = buildReportAiBrief(state());
  assert.equal(brief.findings.length, 1);
  assert.equal(brief.findings[0].id, 'finding:f1');
  assert.equal(JSON.stringify(brief).includes('SECRET'), false);
  assert.equal(brief.findings[0].description.includes('PHP upload'), true);
});

test('report narrative parser accepts only known finding ids', () => {
  const parsed = parseReportAiOutput(JSON.stringify({
    executiveSummary: 'AI summary grounded in facts.',
    conclusion: 'One critical RCE is proven; other impact is unproven.',
    findings: [
      { id: 'finding:f1', description: 'Upload RCE.', impact: 'www-data.', reproduction: 'GET /uploads/shell.php', ratingRationale: 'Verified command echo.' },
      { id: 'finding:unknown', description: 'must be ignored' },
    ],
  }), new Set(['finding:f1']));
  assert.equal(parsed.error, null);
  assert.equal(parsed.narrative.ai, true);
  assert.equal(parsed.narrative.findings.length, 1);
  assert.equal(parsed.narrative.findings[0].id, 'finding:f1');
});

test('merge narrative changes only render state, not source attrs', () => {
  const source = state();
  const merged = mergeReportNarrative(source, {
    ai: true,
    executiveSummary: 'AI summary.',
    conclusion: 'AI conclusion.',
    findings: [{ id: 'finding:f1', description: 'AI description.', impact: 'AI impact.', reproduction: 'AI repro.', ratingRationale: 'AI rationale.' }],
  });
  assert.equal(merged.nodes['finding:f1'].attrs.description, 'AI description.');
  assert.equal(source.nodes['finding:f1'].attrs.description, 'PHP upload served from /uploads.');
});

test('HTML renderer labels AI narrative and preserves deterministic facts', async () => {
  const html = await renderHtmlReport(state(), {
    generatedAt: '2026-10-31T00:00:00.000Z',
    theme: 'light',
    narrative: { ai: true, executiveSummary: 'AI executive summary.', conclusion: 'AI conclusion.', findings: [] },
  });
  assert.match(html, /AI executive summary\./u);
  assert.match(html, /AI conclusion\./u);
  assert.match(html, /AI 撰写/u);
  assert.match(html, /Upload webshell/u);
});

test('runReportAi calls a report subagent and parses its JSON', async () => {
  let called = 0;
  const ctx = {
    get(name) {
      if (name !== 'subagents') return undefined;
      return {
        async startActivation(request) {
          called += 1;
          const prompt = request.request.prompt[0].text;
          assert.match(prompt, /report-writing team/u);
          return {
            childId: 'child-report',
            async dispose() {},
            result: Promise.resolve({
              output: [{ type: 'text', text: JSON.stringify({
                executiveSummary: 'AI summary.',
                conclusion: 'AI conclusion.',
                findings: [{ id: 'finding:f1', description: 'AI desc.', impact: 'AI impact.', reproduction: 'AI repro.', ratingRationale: 'AI rating.' }],
              }) }],
            }),
          };
        },
      };
    },
  };
  const result = await runReportAi({ ctx, agent: { id: 'parent', session: { id: 's' } }, state: state(), timeoutMs: 5000 });
  assert.equal(called, 1);
  assert.equal(result.narrative.ai, true);
  assert.equal(result.error, null);
});
