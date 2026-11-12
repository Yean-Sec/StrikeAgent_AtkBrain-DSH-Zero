/**
 * `atkbrain_coverage` — the nine-cell interface x bug-class board.
 */
import { TOOL_NAMES } from '../constants.js';
import { BUG_CLASSES, COVERAGE_STATUSES, checkCoverage, coverageKey, coverageNoteText, coverageSummary, normalizeInterfacePath, noteCoverage, resolveReportedFinding, seedCoverage } from '../coverage.js';
import { familyParameters, ledgerIsThin } from '../endpoint-vocab.js';
import { unrecordedProductVersions } from '../finding-classification.js';
import { invalid, isPlainObject } from '../util.js';
import { coverageNodeOp } from './build.js';
import { assertArgs, audit, optionalInteger, optionalString, registerAtkTool, requireEnum, requireString } from './common.js';

const ACTIONS = ['seed', 'note', 'check', 'list'];
const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'seed nine cells for an interface, note one cell, check the matrix, or list cells.' },
    path: { type: 'string', description: 'Interface path or URL.' },
    target: { type: 'string', description: 'Target host/IP this interface belongs to; binds coverage to the target tree.' },
    paths: { type: 'array', items: { type: 'string' }, description: 'Interfaces to seed (action=seed).' },
    bugClass: { type: 'string', enum: BUG_CLASSES, description: 'Bug class for action=note.' },
    status: { type: 'string', enum: COVERAGE_STATUSES, description: 'Cell status for action=note/list.' },
    channels: { type: 'array', items: { type: 'string' }, description: 'Independent observation channels (status/body/header/timing/side_effect/callback).' },
    evidenceIds: { type: 'array', items: { type: 'string' }, description: 'Evidence node ids supporting the cell.' },
    findingId: { type: 'string', description: 'Finding id for status=reported.' },
    note: { type: 'string', description: 'Concrete observation for seen/refuted.' },
    role: { type: 'string', description: 'Owner role (lead/recon/web-exploit/...).' },
    limit: { type: 'integer', description: 'Open/list limit (1-500).' },
  },
};

function hostOfWebapp(node) {
  const host = String(node?.attrs?.host ?? '').trim().toLowerCase();
  if (host.length > 0) return host;
  try {
    return new URL(String(node?.attrs?.url ?? node?.key ?? '')).hostname.toLowerCase();
  } catch {
    return String(node?.key ?? '').toLowerCase();
  }
}

function hostLedgerReady(state, target) {
  const webapps = Object.values(state.nodes).filter((node) => node.kind === 'webapp' && node.status !== 'merged');
  if (webapps.length === 0) return true;
  const needle = String(target ?? '').trim().toLowerCase();
  const relevant = needle.length === 0
    ? webapps
    : webapps.filter((node) => `${node.key} ${node.label ?? ''} ${node.attrs?.url ?? ''} ${node.attrs?.host ?? ''}`.toLowerCase().includes(needle));
  const pool = relevant.length > 0 ? relevant : webapps;
  const groups = new Map();
  for (const node of pool) {
    const key = hostOfWebapp(node);
    const list = groups.get(key) ?? [];
    list.push(node);
    groups.set(key, list);
  }
  for (const list of groups.values()) {
    if (!list.some((node) => node.attrs?.surfaceInventoried === true)) return false;
  }
  return true;
}

function ledgerForPath(state, ledgerPath) {
  const parameters = [];
  const contexts = [];
  const parameterMap = {};
  const endpoints = [];
  let thin = false;
  for (const node of Object.values(state.nodes)) {
    if (node.kind !== 'webapp') continue;
    const listed = Array.isArray(node.attrs?.endpoints) ? node.attrs.endpoints : [];
    endpoints.push(...listed);
    if (ledgerIsThin(node.attrs ?? {})) thin = true;
    const map = node.attrs?.parameterMap;
    const contextMap = node.attrs?.contextMap;
    if (isPlainObject(map)) {
      for (const [key, names] of Object.entries(map)) {
        if (!Array.isArray(names)) continue;
        const normalized = normalizeInterfacePath(key);
        parameterMap[normalized] = [...(parameterMap[normalized] ?? []), ...names];
        if (normalized === ledgerPath) parameters.push(...names);
      }
    }
    if (isPlainObject(contextMap)) {
      for (const [key, names] of Object.entries(contextMap)) {
        if (normalizeInterfacePath(key) === ledgerPath && Array.isArray(names)) contexts.push(...names);
      }
    }
    if (contexts.length === 0 && Array.isArray(node.attrs?.contexts) && listed.some((item) => normalizeInterfacePath(item) === ledgerPath)) {
      contexts.push(...node.attrs.contexts);
    }
  }
  const extra = familyParameters(endpoints)[ledgerPath] ?? [];
  parameters.push(...extra);
  if (parameters.length > 0 || contexts.length > 0) thin = false;
  return { parameters, contexts, parameterMap, ledgerThin: thin };
}

function coverageHost(args) {
  const explicit = String(args.target ?? '').trim();
  if (explicit.length > 0) return explicit.replace(/^\[|\]$/gu, '');
  const path = String(args.path ?? '').trim();
  if (/^https?:\/\//iu.test(path)) {
    try { return new URL(path).hostname; } catch { return ''; }
  }
  return '';
}

export function registerCoverageTool(ctx, config, runtime) {
  registerAtkTool(ctx, config, runtime, {
    name: TOOL_NAMES.coverage,
    callTitle: 'Coverage board',
    description: 'Track the A-U nine-cell interface coverage board (xss/sqli/cmd/code/file/authz/logic/leak/nday). Seed an interface, mark seen only with two channels or evidence, refute only with a path+class-specific observation, and use check before choosing the next hunt.',
    parameters: PARAMETERS,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (action === 'note') {
        requireString(args, 'path', { max: 1000 });
        requireString(args, 'bugClass', { max: 40 });
        requireEnum(args, 'status', COVERAGE_STATUSES);
      }
      if (action === 'seed' && args.path === undefined && !Array.isArray(args.paths)) invalid('seed requires path or paths');
      if (action === 'list' && args.status !== undefined) requireEnum(args, 'status', COVERAGE_STATUSES);
      if (args.limit !== undefined) optionalInteger(args, 'limit', { min: 1, max: 500 });
      if (args.note !== undefined) optionalString(args, 'note', { max: 1200 });
      return action;
    },
    async run({ args, state }) {
      const existing = Object.values(state.nodes).filter((node) => node.kind === 'coverage');
      if (args.action === 'seed') {
        const paths = args.paths ?? args.path;
        const cells = seedCoverage(paths, { role: args.role ?? 'lead', limit: Math.min(Number(config.coverageMaxCells) || 500, 5000) })
          .map((cell) => ({ ...cell, key: cell.key ?? coverageKey(cell.path, cell.bugClass), targetKey: coverageHost(args) || undefined }));
        const seen = new Set(existing.map((node) => `${node.attrs?.path}#${node.attrs?.bugClass}`));
        const fresh = cells.filter((cell) => !seen.has(cell.key));
        const available = Math.max(0, (Number(config.coverageMaxCells) || 500) - existing.length);
        const ops = fresh.slice(0, available).map((cell) => coverageNodeOp(state, cell));
        return {
          summary: `Seeded ${Math.min(fresh.length, available)} coverage cell(s) for ${new Set(cells.map((cell) => cell.path)).size} interface(s); ${existing.length} cell(s) already recorded.${fresh.length > available ? ` Cap reached (${config.coverageMaxCells}); ${fresh.length - available} cell(s) omitted.` : ''}`,
          ops: [...ops, audit(TOOL_NAMES.coverage, 'coverage.seed', args.path ?? 'paths', `${ops.length} new`, [])],
          details: { cells: cells.slice(0, 50), existing: existing.length, omitted: Math.max(0, fresh.length - available) },
        };
      }

      if (args.action === 'note') {
        const ledgerPath = normalizeInterfacePath(args.path);
        const noteTarget = coverageHost(args) || String(Object.values(state.nodes).find((node) => node.kind === 'coverage' && node.attrs?.path === args.path && node.attrs?.bugClass === args.bugClass)?.attrs?.targetKey ?? '');
        if ((args.status === 'seen' || args.status === 'refuted') && !hostLedgerReady(state, noteTarget)) {
          invalid('this host has no page ledger; call atkbrain_arsenal action=endpoint_vocab on the saved HTML and JavaScript before closing a coverage cell');
        }
        const ledger = ledgerForPath(state, ledgerPath);
        const sibling = [];
        for (const node of Object.values(state.nodes)) {
          if (node.kind !== 'coverage' || normalizeInterfacePath(node.attrs?.path) !== ledgerPath) continue;
          const text = coverageNoteText(node.attrs ?? {});
          if (text.length > 0) sibling.push(text);
        }
        const findingId = resolveReportedFinding(args, Object.values(state.nodes).filter((node) => node.kind === 'finding'));
        const cell = noteCoverage({
          path: args.path,
          bugClass: args.bugClass,
          status: args.status,
          channels: args.channels,
          evidenceIds: args.evidenceIds,
          findingId,
          note: args.note,
          role: args.role,
          parameters: ledger.parameters,
          contexts: ledger.contexts,
          siblingNote: sibling.join('\n'),
          parameterMap: ledger.parameterMap,
          mode: state.engagement?.mode,
          techniques: Array.isArray(state.scope?.roe?.techniques) ? state.scope.roe.techniques : [],
          ledgerThin: ledger.ledgerThin,
          unrecordedVersions: unrecordedProductVersions(Object.values(state.nodes)),
        });
        cell.key = cell.key ?? coverageKey(cell.path, cell.bugClass);
        if (noteTarget.length > 0) cell.targetKey = noteTarget;
        cell.reason = cell.reason ?? cell.note ?? null;
        if (cell.status === 'reported') {
          const target = Object.values(state.nodes).find((node) => node.kind === 'finding' && (node.id === args.findingId || node.key === args.findingId));
          if (target === undefined) invalid(`findingId "${args.findingId}" is not a recorded finding`);
          cell.findingId = target.id;
        }
        return {
          summary: `Coverage ${cell.path} × ${cell.bugClass} -> ${cell.status}.${cell.reason ? ` ${cell.reason.slice(0, 200)}` : ''}`,
          ops: [coverageNodeOp(state, cell), audit(TOOL_NAMES.coverage, 'coverage.note', cell.key, cell.status, cell.evidenceIds ?? [])],
          details: { cell },
        };
      }

      const cells = existing.map((node) => ({
        path: node.attrs?.path ?? '/',
        bugClass: node.attrs?.bugClass ?? 'unknown',
        status: node.status ?? 'open',
        role: node.attrs?.role ?? 'lead',
        reason: node.attrs?.reason ?? null,
        channels: node.attrs?.channels ?? [],
        evidenceIds: node.attrs?.evidenceIds ?? [],
      }));
      if (args.action === 'list') {
        const rows = cells.filter((cell) => args.status === undefined || cell.status === args.status).slice(0, Number(args.limit) || 100);
        return { summary: `${rows.length} coverage cell(s).`, ops: [], details: { cells: rows, summary: coverageSummary(cells) } };
      }
      const result = checkCoverage(cells, { path: args.path, status: args.status });
      const summary = result.summary ?? coverageSummary(cells);
      const open = Array.isArray(result.open) ? result.open : cells.filter((cell) => cell.status === 'open' || cell.status === 'claimed');
      const openLine = open.slice(0, 12).map((cell) => `${cell.path}×${cell.bugClass}`).join(', ');
      return {
        summary: `Coverage: ${summary.total} cell(s), ${(summary.open ?? 0) + (summary.claimed ?? 0)} open/claimed, ${summary.seen ?? 0} seen, ${summary.refuted ?? 0} refuted, ${summary.reported ?? 0} reported.${openLine ? ` Open: ${openLine}.` : ''}`,
        ops: [],
        details: { ...result, summary, open },
      };
    },
  });
}
