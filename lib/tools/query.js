/**
 * `atkbrain_query` — read-only graph queries for the agent.
 *
 * The Client page reads the projection directly; this tool is the model-facing
 * way to inspect counts, nodes, paths and the next-action frontier without
 * dumping the whole graph into the context.
 */
import { TOOL_NAMES } from '../constants.js';
import { computeFrontier, frontierSummary } from '../frontier.js';
import { buildView, coverageBoardSummary, graphSummary, hypothesisSummary, loopSummary, selfTeamSummary, teamSummary } from '../graph.js';
import { computeCrownPaths } from '../path.js';
import { buildTargetTree } from '../targets.js';
import { capabilityAudit } from '../capability-audit.js';
import { projectCompletion } from '../project-completion.js';
import { selfTeamNode } from '../self-teams.js';
import { handoffOverdue, handoffText, supervisionShouldSpeak } from '../supervision-memory.js';
import { listUnreadWorkspaceFiles } from '../workspace-residue.js';
import { publicAttrs } from '../redact.js';
import { evaluateScope, scopeSummary } from '../scope.js';
import { invalid, isPlainObject } from '../util.js';
import {
  assertArgs,
  optionalInteger,
  optionalString,
  registerAtkTool,
  requireEnum,
} from './common.js';

const ACTIONS = ['stats', 'graph', 'node', 'neighbors', 'search', 'path', 'frontier', 'timeline', 'scope', 'chain', 'team', 'loop', 'lessons', 'selftteam', 'skills', 'targets'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'stats | graph | node | neighbors | search | path | frontier | timeline | scope | chain | team | loop | lessons | selftteam | skills | targets' },
    id: { type: 'string', description: 'Node id for node/neighbors.' },
    key: { type: 'string', description: 'Canonical key for node lookup when the id is unknown.' },
    kind: { type: 'string', description: 'Optional node kind filter for neighbors/search.' },
    query: { type: 'string', description: 'Search text for action=search.' },
    target: { type: 'string', description: 'Optional target for action=scope (host/IP/CIDR/URL).' },
    direction: { type: 'string', enum: ['in', 'out', 'both'], description: 'Neighbour direction (default both).' },
    limit: { type: 'integer', description: 'Result limit (1-500, default 100 for lists, 30 for frontier).' },
  },
};

const GRAPH_SLICE_FIRST = ['finding', 'access', 'credential', 'pivot', 'data'];

/** Findings come before coverage and evidence, so a short slice cannot hide every vulnerability. */
export function selectGraphSlice(nodes, limit) {
  const ranked = [...nodes].sort((left, right) => {
    const rank = (node) => {
      const index = GRAPH_SLICE_FIRST.indexOf(node.kind);
      return index === -1 ? GRAPH_SLICE_FIRST.length : index;
    };
    return rank(left) - rank(right) || left.kind.localeCompare(right.kind) || String(left.key ?? '').localeCompare(String(right.key ?? ''));
  });
  return ranked.slice(0, limit);
}

function publicNode(node) {
  return {
    id: node.id,
    kind: node.kind,
    key: node.key,
    label: node.label,
    status: node.status,
    confidence: node.confidence,
    verification: node.verification,
    attrs: publicAttrs(node.kind, node.attrs),
    tags: (node.tags ?? []).slice(0, 20),
    evidenceCount: (node.evidenceIds ?? []).length,
    firstSeen: node.firstSeen,
    lastSeen: node.lastSeen,
  };
}

function looseNodes(state, token, kind) {
  const wanted = String(token ?? '').trim().toLowerCase();
  if (wanted.length === 0) return [];
  return Object.values(state.nodes).filter((node) => {
    if (node.status === 'merged') return false;
    if (kind !== undefined && node.kind !== kind) return false;
    return [node.key, node.id, node.label, node.attrs?.title, node.attrs?.template]
      .some((value) => String(value ?? '').trim().toLowerCase() === wanted);
  }).sort((left, right) => (right.attrs?.stub === true ? 0 : 2) - (left.attrs?.stub === true ? 0 : 2));
}

function findNode(state, args) {
  if (typeof args.id === 'string' && args.id.length > 0) {
    const node = state.nodes[args.id] ?? looseNodes(state, args.id, args.kind)[0];
    if (node === undefined) invalid(`node "${args.id}" is not in the graph; use atkbrain_query action=search`);
    return node;
  }
  if (typeof args.key === 'string' && args.key.length > 0) {
    const matches = looseNodes(state, args.key, args.kind);
    if (matches.length === 0) invalid(`no node with key "${args.key}"${args.kind ? ` and kind ${args.kind}` : ''}`);
    if (matches.length > 1) return { ...matches[0], _matches: matches.length };
    return matches[0];
  }
  invalid('id or key is required for this action');
  return undefined;
}

function edgeList(state, id, direction = 'both', kind, limit = 100) {
  const edges = Object.values(state.edges).filter((edge) => {
    if (kind !== undefined && edge.kind !== kind) return false;
    if (direction === 'out') return edge.from === id;
    if (direction === 'in') return edge.to === id;
    return edge.from === id || edge.to === id;
  }).slice(0, limit);
  return edges.map((edge) => {
    const otherId = edge.from === id ? edge.to : edge.from;
    const other = state.nodes[otherId];
    return {
      id: edge.id,
      from: edge.from,
      to: edge.to,
      kind: edge.kind,
      confidence: edge.confidence,
      direction: edge.from === id ? 'out' : 'in',
      other: other === undefined ? null : { id: other.id, kind: other.kind, key: other.key, label: other.label },
    };
  });
}

function searchNodes(state, query, kind, limit) {
  const terms = query.toLowerCase().split(/\s+/u).filter(Boolean);
  const matches = [];
  for (const node of Object.values(state.nodes)) {
    if (kind !== undefined && node.kind !== kind) continue;
    const haystack = [
      node.id,
      node.kind,
      node.key,
      node.label,
      node.status,
      JSON.stringify(publicAttrs(node.kind, node.attrs)),
      ...(node.tags ?? []),
    ].join('\n').toLowerCase();
    if (terms.every((term) => haystack.includes(term))) matches.push(node);
    if (matches.length > 5000) break;
  }
  return matches.slice(0, limit).map(publicNode);
}

function explicitChains(state) {
  const groups = new Map();
  for (const node of Object.values(state.nodes)) {
    if (node.kind !== 'chain_step') continue;
    const chainId = String(node.attrs?.chainId ?? 'chain');
    let list = groups.get(chainId);
    if (list === undefined) {
      list = [];
      groups.set(chainId, list);
    }
    list.push(node);
  }
  return [...groups.entries()].map(([chainId, steps]) => ({
    chainId,
    steps: steps
      .sort((a, b) => Number(a.attrs?.ordinal ?? 0) - Number(b.attrs?.ordinal ?? 0))
      .map(publicNode),
  })).slice(0, 20);
}

function verificationAdvice(state) {
  const live = Object.values(state.nodes ?? {}).filter((node) => node.status !== 'merged');
  const candidates = live.filter((node) => node.kind === 'finding' && node.status === 'candidate');
  const verified = live.filter((node) => node.kind === 'finding' && ['verified', 'exploited', 'impacted'].includes(node.status));
  if (candidates.length === 0) return null;
  return {
    pendingCandidates: candidates.length,
    verifiedFindings: verified.length,
    hint: `${candidates.length} candidate finding(s) are not verified (${verified.length} verified). Do not call them confirmed vulnerabilities; call atkbrain_query action=frontier for verify_finding actions, then use atkbrain_record statusChanges or atkbrain_selftteam action=verify.`,
  };
}

export function selfSupervisionStatus(state, targetTree) {
  const briefs = Object.values(state.nodes ?? {}).filter((node) => node.kind === 'supervision' && node.attrs?.type === 'self_team_brief');
  const latest = briefs.sort((a, b) => String(b.lastSeen ?? b.firstSeen ?? '').localeCompare(String(a.lastSeen ?? a.firstSeen ?? '')))[0] ?? null;
  const gaps = (targetTree?.totals?.recon ?? 0) + (targetTree?.totals?.untested ?? 0);
  const lastAt = Date.parse(String(latest?.lastSeen ?? latest?.firstSeen ?? latest?.attrs?.createdAt ?? ''));
  const ageMinutes = Number.isFinite(lastAt) ? Math.floor((Date.now() - lastAt) / 60_000) : null;
  const nodes = Object.values(state.nodes ?? {});
  const team = selfTeamNode(state, 'supervision');
  const speak = supervisionShouldSpeak(nodes);
  const due = team !== undefined && handoffOverdue(nodes, team.attrs?.lastBriefAt);
  const sections = speak ? handoffText(nodes) : '';
  const handoff = latest?.attrs?.handoff ?? null;
  return {
    due,
    latestBriefRound: Number(latest?.attrs?.round) || 0,
    latestBriefVerdict: latest?.attrs?.verdict ?? null,
    ageMinutes,
    targetGaps: gaps,
    handoff: handoff === null ? null : {
      from: handoff.from ?? 'supervisor',
      to: handoff.to ?? 'executor',
      status: latest === null ? 'stale' : (due ? 'stale' : 'delivered'),
      channel: handoff.channel ?? 'tool_result',
      deliveredAt: handoff.deliveredAt ?? null,
      directive: String(handoff.directive ?? latest?.attrs?.advice ?? '').slice(0, 1200),
      targetGaps: Number(handoff.targetGaps ?? gaps) || 0,
      supervisorChildId: handoff.supervisorChildId ?? latest?.attrs?.childId ?? null,
    },
    latestAdvice: String(latest?.attrs?.advice ?? '').slice(0, 1200),
    latestMissed: Array.isArray(latest?.attrs?.missed) ? latest.attrs.missed.slice(0, 8) : [],
    latestRecommendedNext: Array.isArray(latest?.attrs?.recommendedNext) ? latest.attrs.recommendedNext.slice(0, 8) : [],
    sections,
    hint: due
      ? `${sections.slice(0, 1800)}\n先调用 atkbrain_selftteam action=brief。`
      : null,
  };
}

function parallelizationAdvice(state, actions = []) {
  const team = teamSummary(state);
  const liveNodes = Object.values(state.nodes ?? {}).filter((node) => node.status !== 'merged');
  const liveAssets = liveNodes.filter((node) => ['host', 'ip', 'domain'].includes(node.kind)).length;
  if ((team.totals?.batches ?? 0) > 0) return null;
  if (liveAssets < 2 && actions.length < 4) return null;
  return {
    recommended: true,
    assets: liveAssets,
    pendingActions: actions.length,
    hint: 'Multiple live assets or pending branches are being processed without team batches. Stop serial recon; call atkbrain_selftteam action=brief, then atkbrain_team action=plan mode=subagents (or spawn subagents) with batchSize=1 and parallelize independent verification branches. Ingest every host returned by survey before planning.',
  };
}

export function registerQueryTool(ctx, config, deps) {
  registerAtkTool(ctx, config, deps, {
    name: TOOL_NAMES.query,
    callTitle: 'Query attack graph',
    description: 'Read-only queries over the session attack graph: stats, a bounded graph slice, one node with neighbours, search, milestone paths, target/cluster coverage, next-action frontier, timeline, scope evaluation and attack chains. Use action=frontier before choosing the next step and action=targets to check every cluster/sub-target.',
    parameters: PARAMETERS,
    concurrencySafe: true,
    validate(args) {
      assertArgs(args);
      requireEnum(args, 'action', ACTIONS);
      if (args.limit !== undefined) optionalInteger(args, 'limit', { min: 1, max: 500 });
      if (args.query !== undefined) optionalString(args, 'query', { max: 500 });
      if (args.target !== undefined) optionalString(args, 'target', { max: 1000 });
      if (args.direction !== undefined) requireEnum(args, 'direction', ['in', 'out', 'both']);
      if (args.id !== undefined) optionalString(args, 'id', { max: 200 });
      if (args.key !== undefined) optionalString(args, 'key', { max: 500 });
      if (args.kind !== undefined) optionalString(args, 'kind', { max: 50 });
      return true;
    },
    async run({ args, state, exec }) {
      const limit = args.limit ?? (args.action === 'frontier' ? 30 : 100);
      if (args.action === 'targets') {
        const tree = buildTargetTree(state);
        const totals = tree.totals;
        const gaps = tree.clusters
          .flatMap((cluster) => cluster.targets.map((target) => ({ cluster: cluster.label, target: target.label, status: target.status, services: target.services, findings: target.findings, coverageSeen: target.coverageSeen })))
          .filter((target) => target.status !== 'tested' && target.status !== 'impacted');
        return {
          summary: `Target coverage: ${totals.clusters} cluster(s), ${totals.targets} target(s); ${totals.tested} tested, ${totals.recon} recon-only, ${totals.untested} untested, ${totals.impacted} impacted; ${totals.vulnerabilities} vulnerability(ies) (not refuted), ${totals.coverageSeen}/${totals.coverageCells} target-bound coverage cells seen, ${totals.unassignedCoverage ?? 0} unbound coverage cell(s). ${gaps.length > 0 ? `Gaps: ${gaps.slice(0, 10).map((gap) => `${gap.target} (${gap.status})`).join(', ')}.` : 'No target gaps.'}`,
          ops: [],
          details: tree,
        };
      }
      if (args.action === 'stats') {
        const summary = graphSummary(state);
        const frontier = frontierSummary(state);
        const team = teamSummary(state);
        const selfTeam = selfTeamSummary(state);
        const coverageBoard = coverageBoardSummary(state);
        const hypotheses = hypothesisSummary(state);
        const parallelization = parallelizationAdvice(state, []);
        const verification = verificationAdvice(state);
        const targetTree = buildTargetTree(state);
        const selfSupervision = selfSupervisionStatus(state, targetTree);
        const capabilities = capabilityAudit(state);
        const completion = projectCompletion(state);
        const supervisorLine = selfSupervision.latestAdvice.length > 0
          ? ` Supervisor→executor (${selfSupervision.handoff?.status ?? (selfSupervision.due ? 'stale' : 'delivered')}): ${selfSupervision.latestAdvice.slice(0, 220)}${selfSupervision.latestAdvice.length > 220 ? '…' : ''}`
          : ' No supervisor brief yet; call atkbrain_selftteam action=brief before acting.';
        return {
          summary: `Graph #${state.seq}: ${summary.counts.nodes} node(s), ${summary.counts.edges} edge(s); ${summary.coverage.findings} finding(s) (${summary.coverage.vulnerabilities} vulnerabilities (not refuted), ${summary.coverage.unscoredFindings} unscored), ${summary.coverage.verifiedFindings} verified, ${summary.coverage.access} access, ${summary.coverage.validatedAccess} validated, ${summary.coverage.verifiedData} verified data evidence; wildcard ${summary.wildcard.confirmed} confirmed / ${summary.wildcard.suspect} suspect; ${frontier.total} pending action(s), ${frontier.denied} denied by scope; ${team.totals.batches} team batch(es), ${team.totals.merged} merged; ${selfTeam.totals.teams} self-team(s), ${selfTeam.totals.skills} skill(s); coverage ${coverageBoard.totals.seen}/${coverageBoard.totals.cells} seen; hypotheses ${hypotheses.totals.open} open.${verification === null ? '' : ` Verification gate: ${verification.hint}`}${parallelization === null ? '' : ` Parallel hint: ${parallelization.hint}`}${selfSupervision.hint === null ? '' : ` ${selfSupervision.hint}`}${supervisorLine} Capability audit: tools ${capabilities.tools.runs} run/${capabilities.tools.failures} failed, skill ${capabilities.skill.calls}, dictionary ${capabilities.dictionary.calls}; gaps: ${capabilities.gaps.join('; ') || 'none'}. Project completion: ${completion.complete ? `complete (${completion.reportPath})` : `incomplete (${completion.reason})`}.`,
          ops: [],
          details: { summary, frontier: frontierSummary(state), team, selfTeam, coverageBoard, hypotheses, parallelization, verification, targets: summary.targets, selfSupervision, capabilities, projectCompletion: completion, supervisorHandoff: selfSupervision.handoff ?? (selfSupervision.latestAdvice ? { from: 'supervisor', to: 'executor', status: selfSupervision.due ? 'stale' : 'delivered', directive: selfSupervision.latestAdvice, targetGaps: selfSupervision.targetGaps } : null) },
        };
      }
      if (args.action === 'graph') {
        const live = Object.values(state.nodes)
          .filter((node) => state.aliases[node.id] === undefined && node.status !== 'merged');
        const nodes = selectGraphSlice(live, limit).map(publicNode);
        const ids = new Set(nodes.map((node) => node.id));
        const edges = Object.values(state.edges)
          .filter((edge) => ids.has(edge.from) && ids.has(edge.to))
          .slice(0, limit * 2)
          .map((edge) => ({ id: edge.id, from: edge.from, to: edge.to, kind: edge.kind, confidence: edge.confidence }));
        const findingTotal = live.filter((node) => node.kind === 'finding').length;
        const findingShown = nodes.filter((node) => node.kind === 'finding').length;
        const truncated = live.length > nodes.length;
        return {
          summary: `Returned ${nodes.length} of ${live.length} node(s) and ${edges.length} edge(s) from graph #${state.seq}, including ${findingShown} of ${findingTotal} finding(s).${truncated ? ' This slice is not the whole graph. A finding missing from the slice is not missing from the graph; look it up with action=node id=<id>.' : ''}`,
          ops: [],
          details: { seq: state.seq, nodes, edges, truncated, findingTotal, findingShown },
        };
      }
      if (args.action === 'node') {
        const node = findNode(state, args);
        const neighbors = edgeList(state, node.id, 'both', undefined, limit);
        return {
          summary: `${node.kind} ${node.label} [${node.id}] status=${node.status} confidence=${node.confidence} verification=${node.verification}; ${neighbors.length} adjacent edge(s).`,
          ops: [],
          details: { node: { ...publicNode(node), ...(node._matches ? { duplicateKeys: node._matches } : {}) }, neighbors },
        };
      }
      if (args.action === 'neighbors') {
        const node = findNode(state, args);
        const neighbors = edgeList(state, node.id, args.direction ?? 'both', args.kind, limit);
        return {
          summary: `${node.label} has ${neighbors.length} matching adjacent edge(s).`,
          ops: [],
          details: { node: { id: node.id, kind: node.kind, label: node.label }, neighbors },
        };
      }
      if (args.action === 'search') {
        const query = args.query;
        if (typeof query !== 'string' || query.trim().length === 0) invalid('query is required for action=search');
        const nodes = searchNodes(state, query.trim(), args.kind, limit);
        return {
          summary: `Search "${query.trim()}" matched ${nodes.length} node(s)${nodes.length === limit ? ' (limit reached)' : ''}.`,
          ops: [],
          details: { query, nodes },
        };
      }
      if (args.action === 'path') {
        const paths = computeCrownPaths(state, { limit: Math.min(limit, 20) });
        return {
          summary: paths.length === 0
            ? 'No milestone path exists yet: add a validated foothold (access) and a milestone target (critical host, privileged access, verified data), then query again.'
            : `${paths.length} milestone path(s) found; cheapest cost ${paths[0].cost} to ${paths[0].targetLabel}.`,
          ops: [],
          details: { paths },
        };
      }
      if (args.action === 'frontier') {
        const actions = computeFrontier(state, { limit });
        const denied = actions.filter((action) => action.scope?.verdict === 'deny').length;
        const allowed = actions.filter((action) => action.scope?.verdict !== 'deny');
        const parallelization = parallelizationAdvice(state, allowed);
        const verification = verificationAdvice(state);
        const targetTree = buildTargetTree(state);
        const selfSupervision = selfSupervisionStatus(state, targetTree);
        const supervisorLine = selfSupervision.due && selfSupervision.sections
          ? ` 御者交接（先 atkbrain_selftteam action=brief）：\n${selfSupervision.sections}`
          : selfSupervision.latestAdvice.length > 0
            ? ` Supervisor→executor (${selfSupervision.handoff?.status ?? (selfSupervision.due ? 'stale' : 'delivered')}): ${selfSupervision.latestAdvice.slice(0, 260)}${selfSupervision.latestAdvice.length > 260 ? '…' : ''}`
            : ' No supervisor brief yet; call atkbrain_selftteam action=brief before acting.';
        const capabilityActions = actions.filter((action) => String(action.actionType).startsWith('invoke_'));
        const capabilityLine = capabilityActions.length === 0
          ? ''
          : ` Capability gate: ${capabilityActions.map((action) => action.actionType).join(', ')}. Execute those calls before more enumeration; search-only and empty scanner output do not count.`;
        const teamActions = actions.filter((action) => action.actionType === 'self_brief' || action.actionType === 'self_distill' || action.actionType === 'self_evolve_review');
        const teamLine = teamActions.length === 0
          ? ''
          : ` Team gate: ${teamActions.map((action) => action.actionType).join(', ')}. Call atkbrain_selftteam for those actions so the preset teammate reviews the current graph.`;
        const base = actions.length === 0
          ? 'No frontier actions are currently available. Set a scope or import assets first.'
          : `${actions.length} next action(s); ${denied} denied by scope. Highest priority: ${actions[0].actionType} on ${actions[0].targetLabel} (${actions[0].priority}).${teamLine}`;
        const unread = await listUnreadWorkspaceFiles(exec?.agent, Object.values(state.nodes ?? {}));
        const unreadLine = unread.length === 0
          ? ''
          : ` 工作目录里有 ${unread.length} 个文件还没进图谱，从者不会再看到它们：${unread.slice(0, 12).join(', ')}。先 atkbrain_ingest。`;
        return {
          summary: `${base}${capabilityLine}${verification === null ? '' : ` Verification gate: ${verification.hint}`}${parallelization === null ? '' : ` Parallel hint: ${parallelization.hint}`}${supervisorLine}${unreadLine}`,
          ops: [],
          details: { actions, parallelization, verification, targets: targetTree, supervisorHandoff: selfSupervision.handoff ?? (selfSupervision.latestAdvice ? { from: 'supervisor', to: 'executor', status: selfSupervision.due ? 'stale' : 'delivered', directive: selfSupervision.latestAdvice, targetGaps: selfSupervision.targetGaps } : null), selfSupervision },
        };
      }
      if (args.action === 'timeline') {
        const auditTail = (state.audit ?? []).slice(-Math.min(limit, 200));
        const steps = explicitChains(state);
        return {
          summary: `${auditTail.length} recent audit entries, ${steps.length} explicit chain(s). Last action: ${state.lastAction?.action ?? 'none'}.`,
          ops: [],
          details: { auditTail, chains: steps },
        };
      }
      if (args.action === 'scope') {
        let evaluation = null;
        if (args.target !== undefined) {
          const targetText = args.target;
          let target;
          if (targetText.includes('/')) target = { type: 'cidr', cidr: targetText };
          else if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(targetText) || targetText.includes(':')) target = { type: 'ip', ip: targetText };
          else if (/^https?:\/\//u.test(targetText)) target = { type: 'url', url: targetText };
          else target = { type: 'host', host: targetText };
          try {
            evaluation = evaluateScope(state.scope, target);
          } catch (error) {
            evaluation = { allowed: false, reason: error instanceof Error ? error.message : String(error) };
          }
        }
        const summary = scopeSummary(state.scope);
        return {
          summary: summary.empty
            ? 'No authorized scope is set; network tools refuse to run.'
            : `Scope has ${summary.allowCount} allow / ${summary.denyCount} deny entries${evaluation === null ? '' : `; target evaluation: ${evaluation.allowed ? 'allowed' : 'denied'} — ${evaluation.reason}`}.`,
          ops: [],
          details: { scope: summary, engagement: state.engagement, evaluation },
        };
      }
      if (args.action === 'team') {
        const team = teamSummary(state);
        return {
          summary: `${team.totals.batches} team batch(es): ${team.totals.planned} planned, ${team.totals.dispatched} dispatched, ${team.totals.artifactReady} artifact-ready, ${team.totals.merged} merged, ${team.totals.failed} failed, ${team.totals.cancelled} cancelled; ${team.totals.assets} asset(s) assigned.`,
          ops: [],
          details: { team },
        };
      }
      if (args.action === 'loop') {
        const loop = loopSummary(state);
        return {
          summary: loop.state === null
            ? 'No autonomous loop is recorded yet. Start one with atkbrain_loop action=start once scope is authorized.'
            : `Loop ${loop.state.phase} round ${loop.state.round}/${loop.state.maxRounds}; goal ${loop.state.goalPhase ?? 'none'} (${loop.state.activation}); ${loop.totals.reviews} supervision review(s), ${loop.totals.openIntents} open intent(s), ${loop.totals.lessons} lesson(s).`,
          ops: [],
          details: { loop },
        };
      }
      if (args.action === 'lessons') {
        const loop = loopSummary(state);
        return {
          summary: `${loop.lessons.length} lesson(s) recorded in this graph; ${loop.lessons.filter((lesson) => lesson.status === 'active').length} active.`,
          ops: [],
          details: { lessons: loop.lessons, applied: loop.state?.appliedLessonKeys ?? [] },
        };
      }
      if (args.action === 'selftteam' || args.action === 'skills') {
        const selfTeam = selfTeamSummary(state);
        const coverageBoard = coverageBoardSummary(state);
        const hypotheses = hypothesisSummary(state);
        if (args.action === 'skills') {
          return {
            summary: `${selfTeam.skills.length} distilled skill(s) in this graph; ${selfTeam.skills.filter((skill) => skill.status === 'active').length} active.`,
            ops: [],
            details: { skills: selfTeam.skills, latestBrief: selfTeam.latestBrief },
          };
        }
        return {
          summary: `${selfTeam.totals.supervisionTeams} supervision team(s), ${selfTeam.totals.verificationTeams} verification & rating team(s), ${selfTeam.totals.reportTeams} report team(s)${selfTeam.latestBrief ? `; latest brief round ${selfTeam.latestBrief.round} (${selfTeam.latestBrief.deadlockRisk} deadlock risk)` : '; no self-team brief yet'}.`,
          ops: [],
          details: { selfTeam },
        };
      }
      // chain
      const chains = explicitChains(state);
      const paths = computeCrownPaths(state, { limit: Math.min(limit, 20) });
      return {
        summary: `${chains.length} explicit chain(s) and ${paths.length} milestone path(s).`,
        ops: [],
        details: { chains, paths },
      };
    },
  });
}
