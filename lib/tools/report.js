/**
 * `atkbrain_report` — render and write the engagement report.
 *
 * Rendering is pure (`lib/report.js`); this tool decides file names, writes
 * under the session workspace, and records the report hashes in the audit
 * trail. Markdown, re-importable graph JSON, and CSV exports are supported.
 */
import path from 'node:path';

import { TOOL_NAMES } from '../constants.js';
import { renderReport, suggestedReportName } from '../report.js';
import { invalid } from '../util.js';
import { assertArgs, audit, registerAtkTool, requireEnum } from './common.js';

const FORMATS = ['markdown', 'json', 'csv', 'all'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  properties: {
    format: {
      type: 'string',
      enum: FORMATS,
      description: 'markdown (human report), json (re-importable graph export), csv (asset/finding tables), all.',
    },
    path: {
      type: 'string',
      description: 'Optional workspace-relative output basename (e.g. reports/acme-2026-10). Extensions are added by format.',
    },
    includeEvidence: {
      type: 'boolean',
      description: 'Include the evidence index and audit hash chain (default true).',
    },
  },
};

function cleanBase(value, fallback) {
  const text = String(value ?? fallback ?? 'report')
    .replace(/[^\p{L}\p{N}._/-]+/gu, '-')
    .replace(/^[-/]+|[-/]+$/gu, '')
    .slice(0, 160);
  return text.length > 0 ? text : 'atkbrain-report';
}

export function registerReportTool(ctx, config, deps) {
  registerAtkTool(ctx, config, deps, {
    name: TOOL_NAMES.report,
    callTitle: 'Write engagement report',
    description: 'Render the engagement report from the current attack graph: Markdown for humans, JSON as a re-importable AtkBrain export, and CSV asset/finding tables. Credentials and sensitive-data samples are always redacted. Files are written under the session workspace.',
    parameters: PARAMETERS,
    concurrencySafe: false,
    validate(args) {
      assertArgs(args);
      if (args.format !== undefined) requireEnum(args, 'format', FORMATS);
      if (args.path !== undefined && (typeof args.path !== 'string' || args.path.trim().length === 0)) invalid('path must be a non-empty string');
      if (args.includeEvidence !== undefined && typeof args.includeEvidence !== 'boolean') invalid('includeEvidence must be a boolean');
      return true;
    },
    async run({ args, state, exec, deps: runtime }) {
      const generatedAt = new Date().toISOString();
      const report = renderReport(state, { generatedAt, config });
      const suggested = suggestedReportName(state.engagement, generatedAt).replace(/\.md$/u, '');
      const defaultBase = path.posix.join(config.reportDir ?? '.atkbrain/reports', suggested);
      const base = cleanBase(args.path ?? defaultBase, defaultBase);
      const format = args.format ?? 'all';
      const files = [];

      if (format === 'markdown' || format === 'all') {
        files.push({
          label: 'markdown',
          ...(await runtime.writeReportAt(exec.agent, `${base}.md`, report.markdown)),
        });
      }
      if (format === 'json' || format === 'all') {
        files.push({
          label: 'graph-json',
          ...(await runtime.writeReportAt(exec.agent, `${base}.json`, report.json)),
        });
      }
      if (format === 'csv' || format === 'all') {
        files.push({
          label: 'assets-csv',
          ...(await runtime.writeReportAt(exec.agent, `${base}.assets.csv`, report.assetsCsv)),
        });
        files.push({
          label: 'findings-csv',
          ...(await runtime.writeReportAt(exec.agent, `${base}.findings.csv`, report.findingsCsv)),
        });
      }

      const ops = [
        audit(TOOL_NAMES.report, 'report.write', files.map((file) => file.relative).join(', '), `${files.length} file(s)`, []),
      ];
      const summary = [
        `Report written (${format}): ${files.map((file) => file.relative).join(', ')}.`,
        `Coverage: ${report.summary?.nodes ?? Object.keys(state.nodes).length} node(s), ${report.summary?.verifiedFindings ?? 0} verified finding(s), ${report.summary?.validatedAccess ?? 0} validated access, ${report.summary?.verifiedData ?? 0} verified data evidence, ${report.summary?.crownPaths ?? 0} milestone path(s).`,
        'Secrets and raw PII are redacted; the JSON is re-importable with atkbrain_ingest format=graph-json.',
      ].join(' ');
      return {
        summary,
        ops,
        details: {
          format,
          files,
          summary: report.summary,
          warnings: report.warnings ?? [],
        },
      };
    },
  });
}
