/**
 * Projection wire view.
 *
 * The Client page must never receive the whole Host state: attributes are
 * redacted, strings/arrays are bounded, and only the most important nodes fit
 * the configured view cap. `view` must reuse its returned reference for an
 * unchanged state because the framework compares views with `Object.is`.
 */
import {
  CHAIN_STAGES,
  NODE_KIND_RANK,
  SEVERITY_RANK,
  STATE_SCHEMA,
} from './constants.js';
import { computeFrontier, frontierSummary } from './frontier.js';
import { crownPathSummary, isCrownJewel } from './path.js';
import { classifyFindingCvss, isVerifiedVulnerabilityNode } from './finding-classification.js';
import { projectCompletion } from './project-completion.js';
import { buildTargetTree } from './targets.js';
import { SELF_TEAM_ORDER } from './self-teams.js';
import { publicAttrs } from './redact.js';
import { canonicalHost, domainInScope, evaluateScope, hostInScope, scopeSummary } from './scope.js';
import { clone, shortHash } from './util.js';

const viewCache = new WeakMap();

const CHAIN_STAGE_RANK = Object.fromEntries(CHAIN_STAGES.map((stage, index) => [stage, index]));

function severityOf(node) {
  return String(node.attrs?.severity ?? 'info').toLowerCase();
}

function nodeScore(node, degree) {
  let score = 1000 - (NODE_KIND_RANK[node.kind] ?? 99) * 7 + Math.min(degree, 80) * 4;
  if (isCrownJewel(node)) score += 400;
  if (node.kind === 'finding') {
    score += (SEVERITY_RANK[severityOf(node)] ?? 0) * 35;
    if (['verified', 'exploited', 'impacted'].includes(node.status)) score += 90;
  }
  if (node.kind === 'access') score += 160 + (['validated', 'escalated'].includes(node.status) ? 80 : 0);
  if (node.kind === 'data') score += 150 + (node.status === 'verified' ? 60 : 0);
  if (node.kind === 'credential') score += 70;
  if (node.kind === 'wildcard_zone') score += 55;
  if (node.kind === 'pivot') score += 80;
  if (node.kind === 'task') score += 20;
  if (node.kind === 'loop') score += 520;
  if (node.kind === 'intent') score += 25;
  if (node.kind === 'supervision') score += 15;
  if (node.kind === 'lesson') score += 10;
  if (node.kind === 'self_team') score += 30;
  if (node.kind === 'skill') score += 25;
  if (node.kind === 'mcp') score += 5;
  if (node.status === 'merged') score -= 1000;
  return score;
}

function buildDegree(state) {
  const degree = new Map();
  for (const edge of Object.values(state.edges)) {
    if (state.nodes[edge.from] === undefined || state.nodes[edge.to] === undefined) continue;
    degree.set(edge.from, (degree.get(edge.from) ?? 0) + 1);
    degree.set(edge.to, (degree.get(edge.to) ?? 0) + 1);
  }
  return degree;
}

function publicEdge(edge) {
  return {
    id: edge.id,
    from: edge.from,
    to: edge.to,
    kind: edge.kind,
    confidence: Number.isFinite(edge.confidence) ? edge.confidence : 0.5,
    ...(Object.keys(edge.attrs ?? {}).length > 0 ? { attrs: publicAttrs('edge', edge.attrs) } : {}),
    evidenceCount: Array.isArray(edge.evidenceIds) ? edge.evidenceIds.length : 0,
  };
}

function publicNode(node, degree) {
  const crown = isCrownJewel(node);
  return {
    id: node.id,
    kind: node.kind,
    key: node.key,
    label: node.label,
    status: node.status,
    confidence: Number.isFinite(node.confidence) ? node.confidence : 0.5,
    verification: node.verification ?? 'unverified',
    attrs: publicAttrs(node.kind, node.attrs),
    tags: Array.isArray(node.tags) ? node.tags.slice(0, 30) : [],
    evidenceCount: Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0,
    degree: degree.get(node.id) ?? 0,
    crown,
    firstSeen: node.firstSeen ?? null,
    lastSeen: node.lastSeen ?? null,
  };
}

function computeCounts(nodes, edges) {
  const byKind = {};
  const bySeverity = {};
  const byStatus = {};
  for (const node of nodes) {
    byKind[node.kind] = (byKind[node.kind] ?? 0) + 1;
    byStatus[node.status] = (byStatus[node.status] ?? 0) + 1;
    if (node.kind === 'finding') {
      const severity = String(node.attrs?.severity ?? 'info').toLowerCase();
      bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;
    }
  }
  return {
    nodes: nodes.length,
    edges: edges.length,
    byKind,
    bySeverity,
    byStatus,
  };
}

function wildcardStats(nodes) {
  const zones = nodes.filter((node) => node.kind === 'wildcard_zone');
  const counts = { confirmed: 0, suspect: 0, inconclusive: 0, cleared: 0 };
  for (const zone of zones) {
    const status = zone.status;
    if (status in counts) counts[status] += 1;
  }
  const hosts = nodes.filter((node) => node.kind === 'host');
  const hostStatuses = { suspect: 0, explicit: 0, unknown: 0, cleared: 0 };
  for (const host of hosts) {
    const status = host.attrs?.wildcardStatus;
    if (status in hostStatuses) hostStatuses[status] += 1;
    else hostStatuses.unknown += 1;
  }
  return { zones: zones.length, ...counts, hosts: hostStatuses };
}

function coverageOf(nodes, edges) {
  const outgoingKinds = new Map();
  const incomingKinds = new Map();
  for (const edge of edges) {
    let out = outgoingKinds.get(edge.from);
    if (out === undefined) {
      out = new Set();
      outgoingKinds.set(edge.from, out);
    }
    out.add(edge.kind);
    let inc = incomingKinds.get(edge.to);
    if (inc === undefined) {
      inc = new Set();
      incomingKinds.set(edge.to, inc);
    }
    inc.add(edge.kind);
  }
  const hosts = nodes.filter((node) => node.kind === 'host' || node.kind === 'ip');
  const assetsWithServices = hosts.filter((node) => outgoingKinds.get(node.id)?.has('exposes') === true).length;
  const verifiedFindings = nodes.filter((node) => node.kind === 'finding' && ['verified', 'exploited', 'impacted'].includes(node.status)).length;
  const findingNodes = nodes.filter((node) => node.kind === 'finding');
  const classifications = new Map(findingNodes.map((node) => [node.id, classifyFindingCvss(node.attrs ?? {})]));
  const vulnerabilities = findingNodes.filter((node) => isVerifiedVulnerabilityNode(node)).length;
  const unscoredFindings = findingNodes.filter((node) => classifications.get(node.id)?.severity === 'unscored').length;
  const validatedAccess = nodes.filter((node) => node.kind === 'access' && ['validated', 'escalated'].includes(node.status)).length;
  const verifiedData = nodes.filter((node) => node.kind === 'data' && node.status === 'verified').length;
  const verifiedPivots = nodes.filter((node) => node.kind === 'pivot' && (node.status === 'verified' || node.attrs?.verified === true)).length;
  const crownJewels = nodes.filter((node) => isCrownJewel(node)).length;
  return {
    assets: hosts.length,
    assetsWithServices,
    assetsWithoutServices: Math.max(0, hosts.length - assetsWithServices),
    services: nodes.filter((node) => node.kind === 'service').length,
    webapps: nodes.filter((node) => node.kind === 'webapp').length,
    findings: findingNodes.length,
    vulnerabilities,
    unscoredFindings,
    verifiedFindings,
    credentials: nodes.filter((node) => node.kind === 'credential').length,
    validatedCredentials: nodes.filter((node) => node.kind === 'credential' && node.status === 'valid').length,
    access: nodes.filter((node) => node.kind === 'access').length,
    validatedAccess,
    data: nodes.filter((node) => node.kind === 'data').length,
    verifiedData,
    pivots: nodes.filter((node) => node.kind === 'pivot').length,
    verifiedPivots,
    crownJewels,
  };
}

function groupChains(nodes) {
  const groups = new Map();
  for (const node of nodes) {
    if (node.kind !== 'chain_step') continue;
    const chainId = String(node.attrs?.chainId ?? 'chain');
    let list = groups.get(chainId);
    if (list === undefined) {
      list = [];
      groups.set(chainId, list);
    }
    list.push(node);
  }
  return [...groups.entries()]
    .map(([chainId, steps]) => ({
      chainId,
      steps: steps
        .sort((a, b) => (Number(a.attrs?.ordinal) || 0) - (Number(b.attrs?.ordinal) || 0))
        .slice(0, 50)
        .map((step) => ({
          id: step.id,
          label: step.label,
          stage: step.attrs?.stage ?? 'recon',
          stageRank: CHAIN_STAGE_RANK[step.attrs?.stage] ?? 0,
          status: step.status,
          nodeRef: step.attrs?.nodeRef ?? null,
          evidenceCount: Array.isArray(step.evidenceIds) ? step.evidenceIds.length : 0,
        })),
    }))
    .sort((a, b) => a.chainId.localeCompare(b.chainId))
    .slice(0, 20);
}

function buildChains(nodes) {
  return groupChains(nodes);
}

function buildTasks(nodes) {
  return nodes
    .filter((node) => node.kind === 'task' && !['done', 'cancelled'].includes(node.status))
    .map((node) => ({
      id: node.id,
      label: node.label,
      status: node.status,
      priority: Number(node.attrs?.priority) || 0,
      actionType: node.attrs?.actionType ?? null,
      targetId: node.attrs?.targetId ?? null,
      why: Array.isArray(node.attrs?.why) ? node.attrs.why.slice(0, 6) : [],
      risk: node.attrs?.risk ?? 'low',
    }))
    .sort((a, b) => b.priority - a.priority || a.label.localeCompare(b.label))
    .slice(0, 100);
}

function buildWildcardZones(nodes) {
  return nodes
    .filter((node) => node.kind === 'wildcard_zone')
    .map((node) => ({
      id: node.id,
      zone: node.key,
      label: node.label,
      status: node.status,
      confidence: node.confidence,
      cdn: node.attrs?.cdn === true,
      signature: publicAttrs('wildcard_zone', { ...node.attrs, probes: node.attrs?.probes?.slice(0, 8) }),
      probeCount: Array.isArray(node.attrs?.probes) ? node.attrs.probes.length : 0,
      lastSeen: node.lastSeen,
    }))
    .sort((a, b) => a.zone.localeCompare(b.zone))
    .slice(0, 200);
}

function buildTeamBatches(nodes) {
  const batches = nodes
    .filter((node) => node.kind === 'task' && node.attrs?.actionType === 'subagent_batch')
    .map((node) => ({
      id: node.id,
      batchId: String(node.attrs?.batchId ?? node.key),
      label: node.label,
      status: node.status,
      assetCount: Number(node.attrs?.assetCount) || (Array.isArray(node.attrs?.assetIds) ? node.attrs.assetIds.length : 0),
      assetLabels: Array.isArray(node.attrs?.assetLabels) ? node.attrs.assetLabels.slice(0, 20) : [],
      mode: node.attrs?.mode ?? null,
      agentName: node.attrs?.agentName ?? null,
      childId: node.attrs?.childId ?? null,
      teamTaskId: node.attrs?.teamTaskId ?? null,
      artifactPath: node.attrs?.artifactPath ?? null,
      artifactReady: ['artifact_ready', 'completed', 'merged'].includes(node.status) || typeof node.attrs?.artifactReadyAt === 'string',
      mergedAt: node.attrs?.mergedAt ?? null,
      error: node.attrs?.error ?? node.attrs?.mergeError ?? null,
    }))
    .sort((a, b) => a.batchId.localeCompare(b.batchId));
  const totals = {
    batches: batches.length,
    assets: batches.reduce((sum, batch) => sum + batch.assetCount, 0),
    planned: batches.filter((batch) => batch.status === 'planned').length,
    dispatched: batches.filter((batch) => batch.status === 'dispatched').length,
    artifactReady: batches.filter((batch) => batch.artifactReady && !['completed', 'merged'].includes(batch.status)).length,
    merged: batches.filter((batch) => batch.status === 'completed' || batch.status === 'merged').length,
    failed: batches.filter((batch) => batch.status === 'failed' || batch.status === 'merge_failed').length,
    cancelled: batches.filter((batch) => batch.status === 'cancelled').length,
  };
  return { batches, totals };
}

/** Compact team-batch summary for the query tool. */
export function teamSummary(state) {
  return buildTeamBatches(Object.values(state.nodes));
}

function buildLoop(nodes) {
  const loopNode = nodes
    .filter((node) => node.kind === 'loop')
    .sort((a, b) => String(b.lastSeen ?? '').localeCompare(String(a.lastSeen ?? '')))[0];
  const supervisions = nodes
    .filter((node) => node.kind === 'supervision')
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0)
      || String(b.lastSeen ?? '').localeCompare(String(a.lastSeen ?? '')))
    .map((node) => ({
      id: node.id,
      round: Number(node.attrs?.round) || 0,
      type: node.attrs?.type ?? 'round_plan',
      verdict: node.attrs?.verdict ?? 'hold',
      source: node.attrs?.source ?? 'deterministic',
      diagnosis: String(node.attrs?.diagnosis ?? '').slice(0, 500),
      nextPlan: String(node.attrs?.nextPlan ?? '').slice(0, 800),
      mustIntents: Array.isArray(node.attrs?.mustIntents) ? node.attrs.mustIntents.slice(0, 6) : [],
      preferTactics: Array.isArray(node.attrs?.preferTactics) ? node.attrs.preferTactics.slice(0, 8) : [],
      banRepeats: Array.isArray(node.attrs?.banRepeats) ? node.attrs.banRepeats.slice(0, 8) : [],
      stopRecommended: node.attrs?.stopRecommended === true,
      stopReason: node.attrs?.stopReason ?? null,
      confidence: Number(node.attrs?.confidence) || 0,
      findingKey: node.attrs?.findingKey ?? null,
      secondaryVerdict: node.attrs?.secondaryVerdict ?? null,
      createdAt: node.attrs?.createdAt ?? node.lastSeen,
    }))
    .slice(0, 20);
  const intents = nodes
    .filter((node) => node.kind === 'intent')
    .sort((a, b) => {
      const active = (node) => (['open', 'claimed'].includes(node.status) ? 1 : 0);
      return active(b) - active(a) || (Number(b.attrs?.priority) || 0) - (Number(a.attrs?.priority) || 0)
        || (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0);
    })
    .slice(0, 30)
    .map((node) => ({
      id: node.id,
      actionType: node.attrs?.actionType ?? 'manual',
      actionId: node.attrs?.actionId ?? null,
      targetLabel: node.attrs?.targetLabel ?? node.label,
      status: node.status,
      priority: Number(node.attrs?.priority) || 0,
      round: Number(node.attrs?.round) || 0,
      expectedEvidence: node.attrs?.expectedEvidence ?? null,
      why: Array.isArray(node.attrs?.why) ? node.attrs.why.slice(0, 5) : [],
      scopeVerdict: node.attrs?.scopeVerdict ?? 'unknown',
      attempts: Number(node.attrs?.attempts) || 0,
      channelCount: Number(node.attrs?.channelCount) || 0,
    }));
  const lessons = nodes
    .filter((node) => node.kind === 'lesson')
    .sort((a, b) => (Number(b.attrs?.confidence) || 0) - (Number(a.attrs?.confidence) || 0)
      || (Number(b.attrs?.uses) || 0) - (Number(a.attrs?.uses) || 0))
    .slice(0, 30)
    .map((node) => ({
      id: node.id,
      lessonKey: node.attrs?.lessonKey ?? node.key,
      idea: String(node.attrs?.idea ?? '').slice(0, 300),
      method: String(node.attrs?.method ?? '').slice(0, 300),
      route: String(node.attrs?.route ?? '').slice(0, 300),
      chain: String(node.attrs?.chain ?? '').slice(0, 300),
      when: Array.isArray(node.attrs?.when) ? node.attrs.when.slice(0, 8) : [],
      do: Array.isArray(node.attrs?.do) ? node.attrs.do.slice(0, 6) : [],
      avoid: Array.isArray(node.attrs?.avoid) ? node.attrs.avoid.slice(0, 6) : [],
      confidence: Number(node.attrs?.confidence) || 0,
      wins: Number(node.attrs?.wins) || 0,
      fails: Number(node.attrs?.fails) || 0,
      uses: Number(node.attrs?.uses) || 0,
      status: node.status,
      sourceOutcome: node.attrs?.sourceOutcome ?? null,
    }));
  const state = loopNode === undefined ? null : {
    id: loopNode.id,
    phase: loopNode.status,
    objective: loopNode.attrs?.objective ?? null,
    objectiveType: loopNode.attrs?.objectiveType ?? 'impact',
    round: Number(loopNode.attrs?.round) || 0,
    maxRounds: Number(loopNode.attrs?.maxRounds) || 0,
    goalId: loopNode.attrs?.goalId ?? null,
    goalRevision: loopNode.attrs?.goalRevision ?? null,
    goalPhase: loopNode.attrs?.goalPhase ?? null,
    activation: loopNode.attrs?.activation ?? 'disarmed',
    ring: Number(loopNode.attrs?.ring) || 1,
    allowedRing: Number(loopNode.attrs?.allowedRing) || 1,
    noProgressRounds: Number(loopNode.attrs?.noProgressRounds) || 0,
    emptyRounds: Number(loopNode.attrs?.emptyRounds) || 0,
    maxActionsPerRound: Number(loopNode.attrs?.maxActionsPerRound) || 3,
    stopReason: loopNode.attrs?.stopReason ?? null,
    autoContinue: loopNode.attrs?.autoContinue === true,
    startedAt: loopNode.attrs?.startedAt ?? null,
    lastStepAt: loopNode.attrs?.lastStepAt ?? null,
    appliedLessonKeys: Array.isArray(loopNode.attrs?.appliedLessonKeys) ? loopNode.attrs.appliedLessonKeys.slice(0, 30) : [],
  };
  return {
    state,
    latest: supervisions[0] ?? null,
    supervisions,
    intents,
    lessons,
    totals: {
      rounds: state?.round ?? 0,
      reviews: supervisions.length,
      lessons: lessons.length,
      appliedLessons: state?.appliedLessonKeys?.length ?? 0,
      openIntents: intents.filter((intent) => ['open', 'claimed'].includes(intent.status)).length,
    },
  };
}

function buildSelfTeam(nodes) {
  const teams = nodes
    .filter((node) => node.kind === 'self_team')
    .map((node) => ({
      id: node.id,
      type: node.attrs?.type ?? 'supervision',
      label: node.label,
      status: node.status,
      mode: node.attrs?.mode ?? 'subagents',
      members: Array.isArray(node.attrs?.members) ? node.attrs.members.slice(0, 8) : [],
      lastBriefAt: node.attrs?.lastBriefAt ?? null,
      lastBriefPath: node.attrs?.lastBriefPath ?? null,
      lastDistillAt: node.attrs?.lastDistillAt ?? null,
      lastVerifyAt: node.attrs?.lastVerifyAt ?? null,
      lastReportAt: node.attrs?.lastReportAt ?? null,
      lastReportPath: node.attrs?.lastReportPath ?? null,
      lastReportTheme: node.attrs?.lastReportTheme ?? null,
      lastReportKind: node.attrs?.lastReportKind ?? null,
      lastFindingReportAt: node.attrs?.lastFindingReportAt ?? null,
      lastFindingReportPath: node.attrs?.lastFindingReportPath ?? null,
      lastFindingReportId: node.attrs?.lastFindingReportId ?? null,
      reportModes: Array.isArray(node.attrs?.reportModes) ? node.attrs.reportModes.slice(0, 4) : [],
      themeSource: node.attrs?.themeSource ?? null,
      verifiedCount: Number(node.attrs?.verifiedCount) || 0,
      ratedCount: Number(node.attrs?.ratedCount) || 0,
      skillCount: Number(node.attrs?.skillCount) || 0,
      skillDir: node.attrs?.skillDir ?? null,
    }))
    .sort((a, b) => {
      const rank = (type) => SELF_TEAM_ORDER.indexOf(type) < 0 ? 99 : SELF_TEAM_ORDER.indexOf(type);
      return rank(a.type) - rank(b.type) || a.type.localeCompare(b.type);
    });
  const skills = nodes
    .filter((node) => node.kind === 'skill')
    .sort((a, b) => (Number(b.attrs?.confidence) || 0) - (Number(a.attrs?.confidence) || 0))
    .slice(0, 30)
    .map((node) => ({
      id: node.id,
      skillKey: node.attrs?.skillKey ?? node.key,
      name: node.attrs?.name ?? node.label,
      summary: String(node.attrs?.summary ?? '').slice(0, 500),
      when: Array.isArray(node.attrs?.when) ? node.attrs.when.slice(0, 8) : [],
      do: Array.isArray(node.attrs?.do) ? node.attrs.do.slice(0, 6) : [],
      avoid: Array.isArray(node.attrs?.avoid) ? node.attrs.avoid.slice(0, 6) : [],
      route: String(node.attrs?.route ?? '').slice(0, 500),
      confidence: Number(node.attrs?.confidence) || 0,
      status: node.status,
      path: node.attrs?.path ?? null,
      sourceOutcome: node.attrs?.sourceOutcome ?? null,
    }));
  const briefNodes = nodes
    .filter((node) => node.kind === 'supervision' && node.attrs?.type === 'self_team_brief')
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0)
      || String(b.lastSeen ?? '').localeCompare(String(a.lastSeen ?? '')));
  const latestBrief = briefNodes.length === 0 ? null : {
    id: briefNodes[0].id,
    round: Number(briefNodes[0].attrs?.round) || 0,
    progressSummary: String(briefNodes[0].attrs?.progressSummary ?? '').slice(0, 1200),
    gained: Array.isArray(briefNodes[0].attrs?.gained) ? briefNodes[0].attrs.gained.slice(0, 8) : [],
    missed: Array.isArray(briefNodes[0].attrs?.missed) ? briefNodes[0].attrs.missed.slice(0, 8) : [],
    advice: String(briefNodes[0].attrs?.advice ?? '').slice(0, 1200),
    antiDeadlock: Array.isArray(briefNodes[0].attrs?.antiDeadlock) ? briefNodes[0].attrs.antiDeadlock.slice(0, 8) : [],
    recommendedNext: Array.isArray(briefNodes[0].attrs?.recommendedNext) ? briefNodes[0].attrs.recommendedNext.slice(0, 8) : [],
    deadlockRisk: briefNodes[0].attrs?.deadlockRisk ?? 'medium',
    source: briefNodes[0].attrs?.source ?? 'deterministic',
    artifactPath: briefNodes[0].attrs?.artifactPath ?? null,
    handoff: briefNodes[0].attrs?.handoff ?? null,
    createdAt: briefNodes[0].attrs?.createdAt ?? briefNodes[0].lastSeen,
  };
  return {
    teams,
    skills,
    latestBrief,
    totals: {
      teams: teams.length,
      skills: skills.length,
      leadTeams: teams.filter((team) => team.type === 'lead').length,
      supervisionTeams: teams.filter((team) => team.type === 'supervision').length,
      evolutionTeams: teams.filter((team) => team.type === 'evolution').length,
      verificationTeams: teams.filter((team) => team.type === 'verification').length,
      escalationTeams: teams.filter((team) => team.type === 'escalation').length,
      reportTeams: teams.filter((team) => team.type === 'report').length,
    },
  };
}

function buildCoverageBoard(nodes) {
  const cells = nodes
    .filter((node) => node.kind === 'coverage')
    .map((node) => ({
      id: node.id,
      path: node.attrs?.path ?? node.key,
      bugClass: node.attrs?.bugClass ?? 'unknown',
      status: node.status ?? node.attrs?.status ?? 'open',
      role: node.attrs?.role ?? 'lead',
      reason: node.attrs?.reason ?? null,
      findingId: node.attrs?.findingId ?? null,
      channels: Array.isArray(node.attrs?.channels) ? node.attrs.channels.slice(0, 12) : [],
      evidenceIds: Array.isArray(node.attrs?.evidenceIds) ? node.attrs.evidenceIds.slice(0, 20) : [],
      hits: Array.isArray(node.attrs?.hits) ? node.attrs.hits.slice(0, 20) : [],
      checkedAt: node.attrs?.checkedAt ?? null,
    }))
    .sort((a, b) => a.path.localeCompare(b.path) || a.bugClass.localeCompare(b.bugClass));
  const byStatus = {};
  const byClass = {};
  for (const cell of cells) {
    byStatus[cell.status] = (byStatus[cell.status] ?? 0) + 1;
    byClass[cell.bugClass] = (byClass[cell.bugClass] ?? 0) + 1;
  }
  return {
    cells: cells.slice(0, 500),
    totals: {
      cells: cells.length,
      open: byStatus.open ?? 0,
      claimed: byStatus.claimed ?? 0,
      seen: byStatus.seen ?? 0,
      refuted: byStatus.refuted ?? 0,
      reported: byStatus.reported ?? 0,
      byClass,
    },
  };
}

function buildHypotheses(nodes) {
  const rows = nodes
    .filter((node) => node.kind === 'hypothesis')
    .map((node) => ({
      id: node.id,
      hypothesisId: node.attrs?.hypothesisId ?? node.key,
      strategy: node.attrs?.strategy ?? node.label,
      bugClass: node.attrs?.bugClass ?? null,
      targetKey: node.attrs?.targetKey ?? null,
      expectedProof: node.attrs?.expectedProof ?? 'poc_replay',
      status: node.status ?? node.attrs?.status ?? 'open',
      reason: node.attrs?.reason ?? null,
      coverageKey: node.attrs?.coverageKey ?? null,
      channels: Array.isArray(node.attrs?.channels) ? node.attrs.channels.slice(0, 12) : [],
      evidenceIds: Array.isArray(node.attrs?.evidenceIds) ? node.attrs.evidenceIds.slice(0, 20) : [],
      updatedAt: node.attrs?.updatedAt ?? null,
    }))
    .sort((a, b) => String(a.hypothesisId).localeCompare(String(b.hypothesisId)));
  return {
    rows: rows.slice(0, 200),
    totals: {
      hypotheses: rows.length,
      open: rows.filter((row) => row.status === 'open').length,
      active: rows.filter((row) => row.status === 'active').length,
      verified: rows.filter((row) => row.status === 'verified').length,
      disproved: rows.filter((row) => row.status === 'disproved').length,
    },
  };
}

/** Compact coverage-board summary for the query tool. */
export function coverageBoardSummary(state) {
  return buildCoverageBoard(Object.values(state.nodes));
}

/** Compact hypothesis summary for the query tool. */
export function hypothesisSummary(state) {
  return buildHypotheses(Object.values(state.nodes));
}

/** Compact self-team summary for the query tool. */
export function selfTeamSummary(state) {
  return buildSelfTeam(Object.values(state.nodes));
}

/** Compact loop summary for the query tool. */
export function loopSummary(state) {
  return buildLoop(Object.values(state.nodes));
}

const PUBLIC_ENGAGEMENT_KEYS = new Set(['id', 'name', 'client', 'authorization', 'window', 'mode', 'roe', 'createdAt', 'notes']);

function buildEngagement(engagement) {
  if (engagement === null || typeof engagement !== 'object') return null;
  const out = {};
  for (const [key, value] of Object.entries(engagement)) {
    if (PUBLIC_ENGAGEMENT_KEYS.has(key)) out[key] = clone(value);
  }
  if (typeof out.id !== 'string' || out.id.length === 0) {
    const seed = `${out.name ?? ''}|${out.authorization ?? ''}|${out.createdAt ?? ''}`;
    out.id = `PRJ-${shortHash(seed, 8).toUpperCase()}`;
  }
  return out;
}

function hostIps(state, node) {
  const ips = Array.isArray(node.attrs?.ips) ? [...node.attrs.ips] : [];
  for (const edge of Object.values(state.edges ?? {})) {
    if (edge.kind !== 'resolves_to' || edge.from !== node.id) continue;
    const to = state.nodes[edge.to];
    if (to?.kind === 'ip') ips.push(to.key);
  }
  return ips;
}

function webappHostName(node) {
  if (typeof node.attrs?.host === 'string' && node.attrs.host.trim().length > 0) return canonicalHost(node.attrs.host);
  try { return canonicalHost(new URL(node.key).hostname); } catch { return ''; }
}

/**
 * The ledger keeps every imported name. The picture shows the approved scope:
 * one host stays one host, and a crawl of that host does not become a cloud of
 * word-page nodes. An empty allow list still shows the whole ledger.
 */
function presentNodes(state) {
  const nodes = Object.values(state.nodes ?? {}).filter((node) => state.aliases?.[node.id] === undefined && node.status !== 'merged');
  if (!Array.isArray(state.scope?.allow) || state.scope.allow.length === 0) return nodes;
  const allowedHosts = new Set();
  for (const node of nodes) {
    if (node.kind === 'host' && hostInScope(state.scope, node.key, hostIps(state, node))) {
      allowedHosts.add(canonicalHost(node.key));
    }
  }
  const allowedIps = new Set();
  for (const edge of Object.values(state.edges ?? {})) {
    if (edge.kind !== 'resolves_to') continue;
    const from = state.nodes[edge.from];
    const to = state.nodes[edge.to];
    if (from?.kind === 'host' && to?.kind === 'ip' && allowedHosts.has(canonicalHost(from.key))) allowedIps.add(to.id);
  }
  for (const node of nodes) {
    if (node.kind === 'ip' && hostInScope(state.scope, node.key)) allowedIps.add(node.id);
  }
  const linkedWebapps = new Set();
  for (const edge of Object.values(state.edges ?? {})) {
    const from = state.nodes[edge.from];
    const to = state.nodes[edge.to];
    if (from?.kind === 'webapp' && to?.kind === 'finding') linkedWebapps.add(from.id);
    if (to?.kind === 'webapp' && from?.kind === 'finding') linkedWebapps.add(to.id);
  }
  const webappsByHost = new Map();
  for (const node of nodes) {
    if (node.kind !== 'webapp') continue;
    const host = webappHostName(node);
    if (!allowedHosts.has(host)) continue;
    if (!webappsByHost.has(host)) webappsByHost.set(host, []);
    webappsByHost.get(host).push(node);
  }
  const keptWebapps = new Set();
  for (const list of webappsByHost.values()) {
    const ranked = [...list].sort((a, b) => String(a.key).length - String(b.key).length || String(a.key).localeCompare(String(b.key)));
    if (ranked.length > 0) keptWebapps.add(ranked[0].id);
    for (const node of ranked) if (linkedWebapps.has(node.id)) keptWebapps.add(node.id);
  }
  return nodes.filter((node) => {
    if (node.kind === 'host') return allowedHosts.has(canonicalHost(node.key));
    if (node.kind === 'domain') return domainInScope(state.scope, node.key);
    if (node.kind === 'ip') return allowedIps.has(node.id);
    if (node.kind === 'cidr' || node.kind === 'segment') {
      try { return evaluateScope(state.scope, { type: 'cidr', cidr: node.key }).allowed; } catch { return false; }
    }
    if (node.kind === 'webapp') return keptWebapps.has(node.id);
    if (node.kind === 'service') {
      const endpoint = typeof node.attrs?.endpoint === 'string' && node.attrs.endpoint.length > 0
        ? node.attrs.endpoint
        : String(node.key).split(':').slice(1, -1).join(':');
      return hostInScope(state.scope, endpoint, hostIps(state, node));
    }
    return true;
  });
}

function computeView(state, config) {
  const allNodes = Object.values(state.nodes);
  const allEdges = Object.values(state.edges);
  const crown = new Set(allNodes.filter(isCrownJewel).map((node) => node.id));
  const degree = buildDegree(state);
  const liveNodes = presentNodes(state);
  const liveNodeIds = new Set(liveNodes.map((node) => node.id));
  const liveEdges = allEdges.filter((edge) => liveNodeIds.has(edge.from) && liveNodeIds.has(edge.to));

  const limit = Math.max(50, Math.min(Number(config?.viewNodeLimit) || 2500, 20000));
  const edgeLimit = Math.max(100, Math.min(Number(config?.viewEdgeLimit) || 6000, 60000));
  const ranked = liveNodes
    .map((node) => ({ node, score: nodeScore(node, degree.get(node.id) ?? 0), crown: crown.has(node.id) }))
    .sort((a, b) => b.score - a.score
      || (NODE_KIND_RANK[a.node.kind] ?? 99) - (NODE_KIND_RANK[b.node.kind] ?? 99)
      || a.node.key.localeCompare(b.node.key));
  const selected = ranked.slice(0, limit).map((entry) => entry.node);
  const selectedIds = new Set(selected.map((node) => node.id));
  const selectedEdges = liveEdges
    .filter((edge) => selectedIds.has(edge.from) && selectedIds.has(edge.to))
    .sort((a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : a.id < b.id ? -1 : 1))
    .slice(0, edgeLimit);

  const nodes = selected.map((node) => publicNode(node, degree));
  const edges = selectedEdges.map(publicEdge);

  const frontier = computeFrontier(state, { limit: 30 });
  const counts = computeCounts(liveNodes, liveEdges);
  const tasks = buildTasks(liveNodes);
  const team = buildTeamBatches(liveNodes);
  const loop = buildLoop(liveNodes);
  const selfTeam = buildSelfTeam(liveNodes);
  const coverageBoard = buildCoverageBoard(liveNodes);
  const hypotheses = buildHypotheses(liveNodes);
  const wildcardZones = buildWildcardZones(liveNodes);
  const explicitChains = buildChains(liveNodes);
  const crownPaths = crownPathSummary(state, 3);
  const presented = {
    ...state,
    nodes: Object.fromEntries(liveNodes.map((node) => [node.id, node])),
    edges: Object.fromEntries(liveEdges.map((edge) => [edge.id, edge])),
  };
  const targetTree = buildTargetTree(presented);
  const completion = projectCompletion(state);

  return {
    schema: STATE_SCHEMA,
    seq: Number(state.seq) || 0,
    engagement: buildEngagement(state.engagement),
    scope: scopeSummary(state.scope),
    counts,
    coverage: coverageOf(liveNodes, liveEdges),
    wildcard: wildcardStats(liveNodes),
    dedupe: clone(state.stats ?? {}),
    nodes,
    edges,
    frontier,
    frontierSummary: frontierSummary(state),
    tasks,
    team,
    loop,
    selfTeam,
    coverageBoard,
    hypotheses,
    wildcardZones,
    chains: { explicit: explicitChains, crown: crownPaths },
    crownPaths,
    targets: targetTree,
    projectCompletion: completion,
    auditTail: (state.audit ?? []).slice(-20).map((entry) => ({
      id: entry.id,
      at: entry.at,
      tool: entry.tool,
      action: entry.action,
      target: entry.target,
      result: entry.result,
      hash: entry.hash,
    })),
    lastAction: state.lastAction ?? null,
    truncated: {
      nodes: liveNodes.length > selected.length,
      edges: liveEdges.length > selectedEdges.length,
      omittedNodes: Math.max(0, liveNodes.length - selected.length),
      omittedEdges: Math.max(0, liveEdges.length - selectedEdges.length),
    },
    caps: { viewNodeLimit: limit, viewEdgeLimit: edgeLimit },
    generatedFromSeq: state.seq,
  };
}

/**
 * Build (or reuse) the client-visible view for one state reference.
 * The WeakMap guarantees `Object.is` stability without recomputing frontier
 * and crown paths on every projection read.
 */
export function buildView(state, config) {
  const cached = viewCache.get(state);
  if (cached !== undefined) return cached;
  const view = computeView(state, config);
  viewCache.set(state, view);
  return view;
}

/** Finding ids come first so a 50-id sample cannot be only coverage and evidence. */
function sampleNodeIds(nodes) {
  const ordered = [...nodes].sort((left, right) => (left.kind === 'finding' ? 0 : 1) - (right.kind === 'finding' ? 0 : 1) || String(left.id).localeCompare(String(right.id)));
  const seen = new Set();
  const ids = [];
  for (const node of ordered) {
    const id = typeof node.id === 'string' ? node.id : '';
    if (id.length === 0 || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
    if (ids.length >= 50) break;
  }
  return ids;
}

/** Compact graph summary used by the query tool and the report. */
export function graphSummary(state) {
  const nodes = Object.values(state.nodes);
  const edges = Object.values(state.edges);
  return {
    seq: state.seq,
    engagement: buildEngagement(state.engagement),
    scope: scopeSummary(state.scope),
    counts: computeCounts(nodes, edges),
    coverage: coverageOf(nodes, edges),
    targets: buildTargetTree(state),
    projectCompletion: projectCompletion(state),
    wildcard: wildcardStats(nodes),
    dedupe: clone(state.stats ?? {}),
    nodeIds: sampleNodeIds(nodes),
    loopTotals: (() => {
      const loop = buildLoop(nodes);
      return {
        phase: loop.state?.phase ?? null,
        round: loop.totals.rounds,
        maxRounds: loop.state?.maxRounds ?? 0,
        reviews: loop.totals.reviews,
        openIntents: loop.totals.openIntents,
        lessons: loop.totals.lessons,
      };
    })(),
    selfTeamTotals: (() => {
      const selfTeam = buildSelfTeam(nodes);
      return {
        teams: selfTeam.totals.teams,
        skills: selfTeam.totals.skills,
        latestBriefRound: selfTeam.latestBrief?.round ?? 0,
        deadlockRisk: selfTeam.latestBrief?.deadlockRisk ?? null,
      };
    })(),
    lastAction: state.lastAction ?? null,
  };
}
