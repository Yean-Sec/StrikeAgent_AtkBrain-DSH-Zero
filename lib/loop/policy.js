/**
 * Pure autonomous-loop policy.
 *
 * Everything here is a deterministic function of graph state, loop state and
 * config. It performs no I/O and starts no agents; the tool layer turns the
 * returned decisions into ops.
 */
import {
  OBJECTIVE_TYPES,
  SEVERITY_RANK,
  SUPERVISOR_VERDICTS,
} from '../constants.js';
import { computeFrontier } from '../frontier.js';
import { isCrownJewel } from '../path.js';
import { classifyFindingCvss } from '../finding-classification.js';
import { applicationExpanded } from '../endpoint-vocab.js';

const VERIFIED_FINDING = new Set(['verified', 'exploited', 'impacted']);
const VALID_ACCESS = new Set(['validated', 'escalated']);
const HIGH = new Set(['critical', 'high']);
const RCE_CLAIM_RE = /\brce\b|remote code|command execution|命令执行|代码执行|getshell/i;
const EXECUTION_PROOF_RE = /\buid=\d+|whoami|www-data|nt authority\\system|canary_ok|command executed|命令执行成功|shell_exec/i;
const NO_EXEC_RE = /未打成|未证明|not proven|no execution|upload_failed|未复现|版本命中/i;

function number(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function liveNodes(state) {
  return Object.values(state.nodes ?? {}).filter((node) => node.status !== 'merged');
}

export function findingSeverity(node) {
  const rated = String(node.attrs?.redteamRating ?? '').toLowerCase();
  if (SEVERITY_RANK[rated] !== undefined) return rated;
  const cvss = String(node.attrs?.cvssRating ?? node.attrs?.cvss?.baseSeverity ?? '').toLowerCase();
  if (SEVERITY_RANK[cvss] !== undefined) return cvss;
  const severity = String(node.attrs?.severity ?? 'info').toLowerCase();
  return SEVERITY_RANK[severity] !== undefined ? severity : 'info';
}

export function isVerifiedFinding(node) {
  return node.kind === 'finding' && VERIFIED_FINDING.has(node.status);
}

export function isHighCriticalFinding(node) {
  const cvss = classifyFindingCvss(node.attrs ?? {});
  return node.kind === 'finding' && cvss.vulnerability === true && cvss.highCritical === true;
}

export function isCandidateHighCritical(node) {
  const cvss = classifyFindingCvss(node.attrs ?? {});
  return node.kind === 'finding'
    && cvss.vulnerability === true
    && cvss.highCritical === true
    && !VERIFIED_FINDING.has(node.status)
    && node.status !== 'fixed';
}

export function isValidatedAccess(node) {
  return node.kind === 'access' && VALID_ACCESS.has(node.status);
}

export function isVerifiedData(node) {
  return node.kind === 'data' && node.status === 'verified';
}

export function isActiveCredential(node) {
  return node.kind === 'credential' && node.status === 'valid';
}

/** Compact, JSON-safe graph metrics used for baseline/delta/stall decisions. */
export function snapshotGraph(state) {
  const nodes = liveNodes(state);
  const edges = Object.values(state.edges ?? {});
  const verified = nodes.filter(isVerifiedFinding);
  const candidateHigh = nodes.filter(isCandidateHighCritical);
  const access = nodes.filter(isValidatedAccess);
  const data = nodes.filter(isVerifiedData);
  const credentials = nodes.filter(isActiveCredential);
  const teamMerged = nodes.filter((node) => node.kind === 'task'
    && node.attrs?.actionType === 'subagent_batch'
    && ['completed', 'merged'].includes(node.status)).length;
  const teamReady = nodes.filter((node) => node.kind === 'task'
    && node.attrs?.actionType === 'subagent_batch'
    && node.status === 'artifact_ready').length;
  return {
    nodes: nodes.length,
    edges: edges.length,
    services: nodes.filter((node) => node.kind === 'service').length,
    webapps: nodes.filter((node) => node.kind === 'webapp').length,
    evidence: nodes.filter((node) => node.kind === 'evidence').length,
    findings: nodes.filter((node) => node.kind === 'finding').length,
    verifiedFindings: verified.length,
    highCriticalVerified: verified.filter((node) => {
      const cvss = classifyFindingCvss(node.attrs ?? {});
      return cvss.vulnerability === true && cvss.highCritical === true;
    }).length,
    candidateHighCritical: candidateHigh.length,
    validatedAccess: access.length,
    escalatedAccess: access.filter((node) => node.status === 'escalated').length,
    verifiedData: data.length,
    validCredentials: credentials.length,
    unusedCredentials: credentials.filter((node) => node.attrs?.used !== true).length,
    crownJewels: nodes.filter((node) => isCrownJewel(node)).length,
    teamMerged,
    teamReady,
    openIntents: nodes.filter((node) => node.kind === 'intent' && ['open', 'claimed'].includes(node.status)).length,
    claimedIntents: nodes.filter((node) => node.kind === 'intent' && node.status === 'claimed').length,
    refutedIntents: nodes.filter((node) => node.kind === 'intent' && node.status === 'refuted').length,
  };
}

export function zeroSnapshot() {
  return {
    nodes: 0, edges: 0, services: 0, webapps: 0, evidence: 0, findings: 0,
    verifiedFindings: 0, highCriticalVerified: 0, candidateHighCritical: 0,
    validatedAccess: 0, escalatedAccess: 0, verifiedData: 0,
    validCredentials: 0, unusedCredentials: 0, crownJewels: 0,
    teamMerged: 0, teamReady: 0, openIntents: 0, claimedIntents: 0, refutedIntents: 0,
  };
}

/** Difference between two snapshots; positive values are progress. */
export function computeRoundDelta(previous, current) {
  const prev = { ...zeroSnapshot(), ...(previous ?? {}) };
  const curr = { ...zeroSnapshot(), ...(current ?? {}) };
  const delta = {
    newNodes: Math.max(0, curr.nodes - prev.nodes),
    newEdges: Math.max(0, curr.edges - prev.edges),
    newServices: Math.max(0, curr.services - prev.services),
    newWebapps: Math.max(0, curr.webapps - prev.webapps),
    newVerifiedFindings: Math.max(0, curr.verifiedFindings - prev.verifiedFindings),
    newHighCritical: Math.max(0, curr.highCriticalVerified - prev.highCriticalVerified),
    newAccess: Math.max(0, curr.validatedAccess - prev.validatedAccess),
    newData: Math.max(0, curr.verifiedData - prev.verifiedData),
    newCredentials: Math.max(0, curr.validCredentials - prev.validCredentials),
    newTeamMerged: Math.max(0, curr.teamMerged - prev.teamMerged),
  };
  delta.qualityGain = delta.newVerifiedFindings > 0
    || delta.newAccess > 0
    || delta.newData > 0
    || delta.newCredentials > 0
    || delta.newTeamMerged > 0
    || delta.newServices > 0
    || delta.newWebapps > 0;
  delta.weakGain = !delta.qualityGain && (delta.newNodes > 0 || delta.newEdges > 0);
  delta.none = !delta.qualityGain && !delta.weakGain;
  return delta;
}

function baselineOf(loop) {
  return { ...zeroSnapshot(), ...(loop.attrs?.baseline ?? {}) };
}

/** Objective-specific completion test, counting only post-start gains by default. */
export function objectiveAchieved(state, loop) {
  const current = snapshotGraph(state);
  const baseline = baselineOf(loop);
  const includeBaseline = loop.attrs?.includeBaseline === true;
  const from = includeBaseline ? zeroSnapshot() : baseline;
  const newAccess = Math.max(0, current.validatedAccess - from.validatedAccess);
  const newEscalated = Math.max(0, current.escalatedAccess - from.escalatedAccess);
  const newData = Math.max(0, current.verifiedData - from.verifiedData);
  const newHigh = Math.max(0, current.highCriticalVerified - from.highCriticalVerified);
  const objectiveType = OBJECTIVE_TYPES.includes(loop.attrs?.objectiveType)
    ? loop.attrs.objectiveType
    : 'impact';
  if (objectiveType === 'impact') return newAccess > 0 || newData > 0;
  const startedAt = String(loop.attrs?.startedAt ?? '');
  const recent = (node) => includeBaseline || startedAt.length === 0
    || String(node.lastSeen ?? '') >= startedAt || String(node.firstSeen ?? '') >= startedAt;
  if (objectiveType === 'shell') {
    const shellKinds = new Set(['user_shell', 'root_shell']);
    return newAccess > 0 && liveNodes(state).some((node) => isValidatedAccess(node) && recent(node)
      && (node.status === 'escalated' || shellKinds.has(String(node.attrs?.kind ?? ''))));
  }
  if (objectiveType === 'admin') {
    const adminKinds = new Set(['admin_panel', 'db_admin', 'domain_admin', 'cloud_admin']);
    return newAccess > 0 && liveNodes(state).some((node) => isValidatedAccess(node) && recent(node)
      && adminKinds.has(String(node.attrs?.kind ?? '')));
  }
  if (objectiveType === 'data') return newData > 0;
  if (objectiveType === 'findings') return newHigh > 0;
  return newAccess > 0 || newData > 0;
}

/** Ring-based scan profile. This edition stays on ring 1. */
export function scanProfile(ring, config) {
  const safeRing = 1;
  void ring;
  const maxPorts = Math.max(1, Math.min(Number(config?.maxPortsPerCall) || 32, 32));
  const profiles = {
    1: {
      ring: 1,
      ports: [22, 80, 443, 8080, 8443],
      wordlistTier: 'small',
      notes: ['top service ports only', 'HTTP fingerprint + safe exposure checks', 'no large directory brute force'],
    },
    2: {
      ring: 2,
      ports: [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017],
      wordlistTier: 'medium',
      notes: ['add database/admin/service ports', 'read live pages and linked content before brute force'],
    },
    3: {
      ring: 3,
      ports: [21, 22, 25, 53, 80, 110, 111, 143, 443, 445, 993, 995, 1080, 1433, 1521, 2049, 2375,
        3306, 3389, 5432, 5900, 6379, 7001, 8000, 8008, 8080, 8443, 8888, 9000, 9090, 9200,
        11211, 27017, 6443, 10250],
      wordlistTier: 'large',
      notes: ['largest allowed port set (capped by maxPortsPerAction)', 'only after rings 1-2 are exhausted'],
    },
  };
  const profile = profiles[safeRing];
  return {
    ...profile,
    ports: profile.ports.slice(0, maxPorts),
    portSpec: profile.ports.slice(0, maxPorts).join(','),
  };
}

/** Scan rings stay on ring 1. Empty rounds do not open a wider port set. */
export function nextRing(loop, config) {
  void loop;
  void config;
  return { ring: 1, promoted: false, allowedRing: 1 };
}

/** Whether the AI supervisor should be consulted this round. */
export function supervisionDue(loop, state, latest, config) {
  const mode = config?.supervisorMode ?? 'auto';
  if (mode === 'deterministic') return false;
  if (mode === 'ai') return true;
  if (latest === undefined || latest === null) return true;
  const round = Number(loop.attrs?.round) || 0;
  const lastRound = Number(latest.attrs?.round) || 0;
  const interval = Math.max(1, Number(config?.supervisorInterval) || 3);
  if (round - lastRound >= interval) return true;
  const previous = loop.attrs?.latestSnapshot ?? {};
  const current = snapshotGraph(state);
  if (current.highCriticalVerified > (previous.highCriticalVerified ?? 0)) return true;
  if (current.validatedAccess > (previous.validatedAccess ?? 0)) return true;
  if (current.verifiedData > (previous.verifiedData ?? 0)) return true;
  if ((Number(loop.attrs?.noProgressRounds) || 0) >= 1) return true;
  return false;
}

/** Stop decision shared by step/status. */
export function computeStop(loop, state, config) {
  const phase = loop.status;
  if (phase !== 'running') return { stop: true, reason: `phase-${phase}`, detail: 'loop is not running' };
  if ((state.scope?.allow?.length ?? 0) === 0 || state.engagement === null) {
    return { stop: true, reason: 'scope-empty', detail: 'no authorized allow list is recorded' };
  }
  if (objectiveAchieved(state, loop)) {
    return { stop: true, reason: 'objective-achieved', detail: `objective ${loop.attrs?.objectiveType ?? 'impact'} is met` };
  }
  const round = Number(loop.attrs?.round) || 0;
  const maxRounds = Number(loop.attrs?.maxRounds) || 0;
  if (maxRounds > 0 && round >= maxRounds) {
    return { stop: true, reason: 'max-rounds', detail: `round ${round}/${maxRounds} reached` };
  }
  const startedAt = Date.parse(String(loop.attrs?.startedAt ?? ''));
  const maxMinutes = Math.max(5, Number(config?.loopMaxWallMinutes) || 360);
  if (Number.isFinite(startedAt) && Date.now() - startedAt >= maxMinutes * 60_000) {
    return { stop: true, reason: 'wall-clock', detail: `wall budget ${maxMinutes} minute(s) reached` };
  }
  const noProgress = Number(loop.attrs?.noProgressRounds) || 0;
  const stall = Math.max(1, Number(config?.loopStallRounds) || 3);
  if (noProgress >= stall) {
    return { stop: true, reason: 'no-progress', detail: `${noProgress} consecutive round(s) without quality progress` };
  }
  const ring = Number(loop.attrs?.ring) || 1;
  const empty = Number(loop.attrs?.emptyRounds) || 0;
  if (ring >= 3 && empty >= Math.max(1, Number(config?.loopSpiralPromoteRounds) || 3)) {
    return { stop: true, reason: 'exhausted', detail: 'largest coverage ring is exhausted without new quality evidence' };
  }
  return { stop: false, reason: null, detail: null };
}

/** Update loop progress counters from a previous snapshot. */
export function progressUpdate(loop, state, config) {
  const current = snapshotGraph(state);
  const previous = loop.attrs?.latestSnapshot ?? loop.attrs?.baseline ?? null;
  const delta = computeRoundDelta(previous, current);
  const noProgress = delta.qualityGain ? 0 : (Number(loop.attrs?.noProgressRounds) || 0) + 1;
  const empty = (delta.newNodes === 0 && delta.newEdges === 0)
    ? (Number(loop.attrs?.emptyRounds) || 0) + 1
    : 0;
  const promotion = nextRing({ attrs: { ...loop.attrs, emptyRounds: empty } }, config);
  return {
    snapshot: current,
    delta,
    noProgressRounds: noProgress,
    emptyRounds: promotion.promoted ? 0 : empty,
    ring: promotion.ring,
    promoted: promotion.promoted,
  };
}

function actionFor(frontier, type, targetId) {
  return frontier.find((action) => action.actionType === type
    && (targetId === undefined || action.targetId === targetId)
    && action.scope?.verdict !== 'deny');
}

function syntheticAction(actionType, target, reason, extra = {}) {
  return {
    actionId: `synthetic:${actionType}:${target.id ?? target.key ?? 'target'}`,
    actionType,
    targetId: target.id ?? target.key ?? 'target',
    targetKind: target.kind ?? 'task',
    targetLabel: target.label ?? target.key ?? target.id ?? actionType,
    priority: 95,
    why: [reason],
    toolClass: extra.toolClass ?? 'record',
    expectedEvidence: extra.expectedEvidence ?? { kind: 'artifact', acceptTest: 're-checkable evidence id + sha256' },
    risk: 'low',
    params: extra.params ?? {},
    scope: { verdict: 'allow', reason: 'local/no network', allowedIps: [] },
  };
}

/** Candidate intents for this round, sorted by policy gates then frontier. */
export function candidateIntents(state, loop, frontier, config, latestSupervision) {
  const nodes = liveNodes(state);
  const maxActions = Math.max(1, Math.min(5, Number(loop.attrs?.maxActionsPerRound)
    || Number(config?.loopMaxActionsPerRound) || 3));
  const candidates = [];
  const push = (action, source, hypothesis) => {
    if (action === undefined) return;
    if (candidates.some((item) => item.action.actionId === action.actionId)) return;
    candidates.push({ action, source, hypothesis });
  };

  const readyTeam = nodes.find((node) => node.kind === 'task'
    && node.attrs?.actionType === 'subagent_batch'
    && node.status === 'artifact_ready');
  if (readyTeam !== undefined) {
    push(syntheticAction('merge_team', readyTeam,
      `team batch ${readyTeam.attrs?.batchId ?? ''} has a ready artifact; merge before new work`,
      { toolClass: 'team' }), 'policy', 'merge the child graph and complete the shared Team task');
    return candidates.slice(0, maxActions);
  }

  const candidatesHigh = nodes.filter(isCandidateHighCritical);
  for (const finding of candidatesHigh.slice(0, 2)) {
    const action = actionFor(frontier, 'verify_finding', finding.id)
      ?? syntheticAction('verify_finding', finding, 'high/critical candidate must be independently verified before new recon');
    push(action, 'verify-gate', 'reproduce the finding, attach evidence, obtain secondary verification');
  }

  if (candidatesHigh.length === 0) {
    const verifiedHigh = nodes.filter((node) => isHighCriticalFinding(node) && isVerifiedFinding(node));
    if (verifiedHigh.length > 0) {
      const access = actionFor(frontier, 'validate_access')
        ?? actionFor(frontier, 'escalate_privilege')
        ?? actionFor(frontier, 'collect_data_evidence');
      if (access !== undefined) {
        push(access, 'escalate-gate', 'verified high/critical impact must be pushed to access or data proof');
      } else {
        push(syntheticAction('escalate_privilege', verifiedHigh[0],
          'verified high/critical finding has no validated impact yet',
          { toolClass: 'record' }), 'escalate-gate', 'prove the strongest reachable impact');
      }
      return candidates.slice(0, maxActions);
    }
  } else {
    return candidates.slice(0, maxActions);
  }

  const unused = nodes.find((node) => isActiveCredential(node) && node.attrs?.used !== true);
  if (unused !== undefined) {
    const action = actionFor(frontier, 'validate_credential', unused.id)
      ?? syntheticAction('validate_credential', unused, 'valid credential is unused; test it once within lockout policy');
    push(action, 'credential-gate', 'validate the credential once and record the resulting access');
  }

  const claimed = nodes.filter((node) => node.kind === 'intent' && node.status === 'claimed');
  for (const intent of claimed.slice(0, 1)) {
    const action = frontier.find((entry) => entry.actionId === intent.attrs?.actionId
      && entry.scope?.verdict !== 'deny' && entry.scope?.verdict !== 'unknown');
    if (action !== undefined) push(action, 'in-flight', 'finish the already-claimed intent before changing direction');
  }

  const planMust = latestSupervision?.attrs?.mustIntents ?? [];
  for (const id of planMust) {
    const action = frontier.find((entry) => (entry.actionId === id || entry.targetId === id)
      && entry.scope?.verdict !== 'deny' && entry.scope?.verdict !== 'unknown');
    if (action !== undefined) push(action, 'supervisor', 'supervisor requested this intent');
  }

  for (const action of frontier) {
    if (action.scope?.verdict === 'deny' || action.scope?.verdict === 'unknown') continue;
    if (candidates.length >= maxActions) break;
    push(action, 'frontier', 'highest-priority allowed frontier action');
  }
  return candidates.slice(0, maxActions);
}

/** Whether a refutation has enough independent observation channels. */
export function refutationAllowed(intent, observations, force = false) {
  if (force) return { allowed: true, reason: 'force' };
  const channels = new Set((Array.isArray(observations) ? observations : [])
    .map((entry) => String(entry?.channel ?? '')).filter(Boolean));
  const attempts = Number(intent?.attrs?.attempts) || 0;
  if (channels.size < 2 && attempts < 2) {
    return {
      allowed: false,
      reason: 'single-channel failure is not a closed attack surface; record at least two distinct observation channels (status/body/timing/header/side_effect) or force',
    };
  }
  return { allowed: true, reason: 'independent observations' };
}

/** Unproven RCE claim detector used by supervision and rating. */
export function claimGuardForFinding(node) {
  const blob = `${node.label ?? ''} ${node.attrs?.title ?? ''} ${node.attrs?.evidence ?? ''} ${node.attrs?.repro ?? ''}`;
  if (!RCE_CLAIM_RE.test(blob)) return null;
  if (EXECUTION_PROOF_RE.test(blob) && !NO_EXEC_RE.test(blob)) return null;
  return 'unproven-rce';
}

/** Deterministic rating rubric; never raises above what the evidence supports. */
export function ratingForFinding(node) {
  const severity = String(node.attrs?.severity ?? 'info').toLowerCase();
  const blob = `${node.attrs?.title ?? ''} ${node.attrs?.evidence ?? ''} ${node.attrs?.impact ?? ''}`.toLowerCase();
  const execution = EXECUTION_PROOF_RE.test(blob) && !NO_EXEC_RE.test(blob);
  const bulk = /count\s*[=:]\s*\d{3,}|bulk|批量|大量|逐行|全部用户/i.test(blob);
  const admin = /admin (?:access|panel|privilege)|管理员权限|获取后台|domain admin|cloud admin|db admin/.test(blob);
  if (execution || admin || bulk) return { rating: 'critical', rationale: 'execution/admin/bulk impact is stated in the evidence' };
  if (HIGH.has(severity)) return { rating: 'high', rationale: 'direct-impact finding without proven execution/bulk impact' };
  if (severity === 'medium') return { rating: 'medium', rationale: 'medium-severity impact per rubric' };
  if (severity === 'low') return { rating: 'low', rationale: 'low-severity impact per rubric' };
  return { rating: 'info', rationale: 'informational only' };
}

/** Normalize a supervisor plan and clamp it to current graph/frontier facts. */
export function refineSupervisionPlan(plan, { state, loop, frontier, intents, config }) {
  const nodes = liveNodes(state);
  const out = {
    verdict: SUPERVISOR_VERDICTS.includes(plan?.verdict) ? plan.verdict : 'hold',
    diagnosis: String(plan?.diagnosis ?? '').slice(0, 1500),
    nextPlan: String(plan?.nextPlan ?? plan?.next_plan ?? '').slice(0, 3000),
    mustIntents: Array.isArray(plan?.mustIntents) ? plan.mustIntents.slice(0, 6) : [],
    preferTactics: Array.isArray(plan?.preferTactics) ? plan.preferTactics.slice(0, 12) : [],
    banRepeats: Array.isArray(plan?.banRepeats) ? plan.banRepeats.slice(0, 12) : [],
    stopRecommended: plan?.stopRecommended === true,
    stopReason: plan?.stopReason ?? null,
    confidence: Number.isFinite(Number(plan?.confidence)) ? Math.max(0, Math.min(1, Number(plan.confidence))) : 0.5,
    source: plan?.source ?? 'deterministic',
  };
  const known = new Set([
    ...frontier.map((action) => action.actionId),
    ...(intents ?? []).map((intent) => intent.attrs?.actionId).filter(Boolean),
    ...(intents ?? []).map((intent) => intent.id),
  ]);
  out.mustIntents = out.mustIntents.filter((id) => known.has(String(id)));
  const candidateHigh = nodes.filter(isCandidateHighCritical);
  const surfaceThin = nodes.some((node) => node.kind === 'webapp' && applicationExpanded(node.attrs ?? {}) !== true);
  if (surfaceThin) {
    const expand = frontier.find((action) => action.actionType === 'expand_application');
    if (expand !== undefined && !out.mustIntents.includes(expand.actionId)) out.mustIntents.unshift(expand.actionId);
    if (out.verdict === 'verify' || out.verdict === 'hold') out.verdict = 'pivot';
    if (out.nextPlan.length === 0 || /before any new enumeration|second enumeration path/iu.test(out.nextPlan)) {
      out.nextPlan = 'The recorded URL is only an entry. Inventory the application modules and seed their interfaces before closing evidence on that page.';
    }
  } else if (candidateHigh.length > 0) {
    out.verdict = 'verify';
    out.stopRecommended = false;
    out.stopReason = null;
    const verify = frontier.find((action) => action.actionType === 'verify_finding');
    if (verify !== undefined && !out.mustIntents.includes(verify.actionId)) out.mustIntents.unshift(verify.actionId);
  } else {
    const verifiedHigh = nodes.filter((node) => isHighCriticalFinding(node) && isVerifiedFinding(node));
    const impact = frontier.find((action) => ['validate_access', 'escalate_privilege', 'collect_data_evidence'].includes(action.actionType));
    if (verifiedHigh.length > 0 && impact !== undefined && out.verdict === 'hold') {
      out.verdict = 'escalate';
      if (!out.mustIntents.includes(impact.actionId)) out.mustIntents.unshift(impact.actionId);
    }
  }
  const readyTeam = nodes.some((node) => node.kind === 'task'
    && node.attrs?.actionType === 'subagent_batch'
    && node.status === 'artifact_ready');
  if (readyTeam) {
    out.verdict = 'hold';
    out.stopRecommended = false;
    out.stopReason = null;
    out.nextPlan = out.nextPlan.length > 0 ? out.nextPlan : 'Merge the ready team batch before starting new enumeration.';
  }
  const noProgress = Number(loop.attrs?.noProgressRounds) || 0;
  if (noProgress >= Math.max(1, Number(config?.loopNoProgressRounds) || 2) && out.verdict === 'hold') {
    out.verdict = 'pivot';
  }
  if (out.verdict === 'stop' && !objectiveAchieved(state, loop)) {
    const stall = Number(config?.loopStallRounds) || 3;
    if (noProgress < stall) {
      out.verdict = 'pivot';
      out.stopRecommended = false;
      out.stopReason = null;
    }
  }
  return out;
}
