/**
 * Build a report from the browser's wire graph, without requiring the
 * session object (the route has no agent/session context).
 *
 * The wire view already contains public, redacted node/edge attributes, so the
 * report renderer can produce the same markdown/HTML/JSON/CSV files the agent
 * tool writes under the workspace.
 */
import { renderHtmlReport } from './report-html.js';
import { renderReport, suggestedReportName } from './report.js';
import { detectReportTheme } from './theme.js';

function asObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

/** Convert the client wire view back into the report input shape. */
export function reportStateFromWire(wire) {
  const source = asObject(wire);
  const nodes = Array.isArray(source.nodes) ? source.nodes : [];
  const edges = Array.isArray(source.edges) ? source.edges : [];
  return {
    schema: typeof source.schema === 'string' ? source.schema : 'atkbrain/1',
    seq: Number(source.seq) || 0,
    engagement: asObject(source.engagement),
    scope: asObject(source.scope),
    nodes: Object.fromEntries(nodes.filter((node) => node !== null && typeof node === 'object' && typeof node.id === 'string').map((node) => [node.id, node])),
    edges: Object.fromEntries(edges.filter((edge) => edge !== null && typeof edge === 'object' && typeof edge.id === 'string').map((edge) => [edge.id, edge])),
    aliases: {},
    audit: Array.isArray(source.auditTail) ? source.auditTail : [],
    stats: asObject(source.dedupe),
    lastAction: source.lastAction ?? null,
  };
}

/**
 * @param {{wire:object, format:string, ctx:object, config:object}} input
 * @returns {Promise<{filename:string,mime:string,content:string}>}
 */
export async function renderReportExport({ wire, format, ctx, config = {} }) {
  const state = reportStateFromWire(wire);
  const generatedAt = new Date();
  if (format === 'html') {
    const theme = await detectReportTheme({ ctx, config });
    const content = await renderHtmlReport(state, {
      generatedAt: generatedAt.toISOString(),
      theme: theme.theme,
      themeSource: theme.source,
    });
    return {
      filename: `${suggestedReportName(state.engagement, generatedAt).replace(/\.md$/u, '')}.html`,
      mime: 'text/html; charset=utf-8',
      content,
    };
  }
  const report = renderReport(state, { generatedAt, config });
  if (format === 'json') {
    return {
      filename: `${suggestedReportName(state.engagement, generatedAt).replace(/\.md$/u, '')}.json`,
      mime: 'application/json; charset=utf-8',
      content: report.json,
    };
  }
  if (format === 'csv') {
    return {
      filename: `${suggestedReportName(state.engagement, generatedAt).replace(/\.md$/u, '')}-findings.csv`,
      mime: 'text/csv; charset=utf-8',
      content: report.findingsCsv,
    };
  }
  return {
    filename: suggestedReportName(state.engagement, generatedAt),
    mime: 'text/markdown; charset=utf-8',
    content: report.markdown,
  };
}
