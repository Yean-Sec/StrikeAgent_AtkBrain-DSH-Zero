/**
 * Self-team briefs.
 *
 * The supervision team reports what the main team did and gained, recommends a
 * direction, and explicitly calls out deadlock risk. The evolution team receives
 * the generalized high/critical path bundle and returns reusable skills.
 */
import { snapshotGraph } from './policy.js';
import { graphStackTokens, tacticForFinding, cueForFinding } from './memory.js';
import { buildTargetTree } from '../targets.js';
import { capabilityAudit } from '../capability-audit.js';
import { projectCompletion } from '../project-completion.js';
import { classifyFindingCvss } from '../finding-classification.js';
import { handoffText, supervisionMemory, supervisionShouldSpeak } from '../supervision-memory.js';
import { applicationExpanded } from '../endpoint-vocab.js';

function clip(value, length) {
  return String(value ?? '').replace(/\s+/gu, ' ').trim().slice(0, length);
}

function liveNodes(state) {
  return Object.values(state.nodes ?? {}).filter((node) => node.status !== 'merged');
}

function highCritical(node) {
  if (node.kind !== 'finding') return false;
  const cvss = classifyFindingCvss(node.attrs ?? {});
  return cvss.vulnerability === true && cvss.highCritical === true;
}

function verifiedHigh(node) {
  return highCritical(node) && ['verified', 'exploited', 'impacted'].includes(node.status);
}

/** Build the graph/loop progress bundle used by both the AI and fallback reporter. */
export function buildProgressBundle({ state, loop, latest, round }) {
  const current = snapshotGraph(state);
  const baseline = loop?.attrs?.baseline ?? {};
  const nodes = liveNodes(state);
  const intents = nodes
    .filter((node) => node.kind === 'intent')
    .filter((node) => (Number(node.attrs?.round) || 0) >= Math.max(1, (Number(round) || 0) - 2))
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0))
    .slice(0, 20)
    .map((node) => ({
      actionType: node.attrs?.actionType ?? 'unknown',
      target: node.attrs?.targetLabel ?? node.attrs?.targetId ?? '—',
      status: node.status,
      round: Number(node.attrs?.round) || 0,
      result: node.attrs?.result ?? null,
    }));
  const gained = [];
  if ((current.verifiedFindings || 0) > (baseline.verifiedFindings || 0)) {
    gained.push(`${(current.verifiedFindings || 0) - (baseline.verifiedFindings || 0)} new verified finding(s)`);
  }
  if ((current.highCriticalVerified || 0) > (baseline.highCriticalVerified || 0)) {
    gained.push(`${(current.highCriticalVerified || 0) - (baseline.highCriticalVerified || 0)} new high/critical finding(s)`);
  }
  if ((current.validatedAccess || 0) > (baseline.validatedAccess || 0)) {
    gained.push(`${(current.validatedAccess || 0) - (baseline.validatedAccess || 0)} new validated access path(s)`);
  }
  if ((current.verifiedData || 0) > (baseline.verifiedData || 0)) {
    gained.push(`${(current.verifiedData || 0) - (baseline.verifiedData || 0)} new verified data evidence set(s)`);
  }
  if ((current.teamMerged || 0) > (baseline.teamMerged || 0)) {
    gained.push('new team batch merged');
  }
  const repeated = new Map();
  for (const node of nodes.filter((entry) => entry.kind === 'intent')) {
    const key = `${node.attrs?.actionType ?? 'unknown'}|${node.attrs?.targetLabel ?? node.attrs?.targetId ?? '—'}`;
    repeated.set(key, (repeated.get(key) ?? 0) + 1);
  }
  const repeatOffenders = [...repeated.entries()].filter(([, count]) => count >= 2).map(([key, count]) => ({ action: key, count }));
  const deadlockRisk = (Number(loop?.attrs?.noProgressRounds) || 0) >= 2 || repeatOffenders.length > 0
    ? 'high'
    : (Number(loop?.attrs?.noProgressRounds) || 0) >= 1 ? 'medium' : 'low';
  const targetTree = buildTargetTree(state);
  const capabilities = capabilityAudit(state);
  const completion = projectCompletion(state);
  const targetGaps = targetTree.clusters
    .flatMap((cluster) => cluster.targets.map((target) => ({
      cluster: clip(cluster.label, 80),
      target: clip(target.label, 120),
      status: target.status,
      services: target.services,
      webapps: target.webapps,
      findings: target.findings,
      coverageSeen: target.coverageSeen,
    })))
    .filter((target) => target.status !== 'tested' && target.status !== 'impacted')
    .slice(0, 40);
  return {
    round: Number(round) || Number(loop?.attrs?.round) || 0,
    phase: loop?.status ?? 'none',
    objective: loop?.attrs?.objective ?? state.engagement?.name ?? 'engagement',
    objectiveType: loop?.attrs?.objectiveType ?? 'impact',
    ring: Number(loop?.attrs?.ring) || 1,
    noProgressRounds: Number(loop?.attrs?.noProgressRounds) || 0,
    emptyRounds: Number(loop?.attrs?.emptyRounds) || 0,
    metrics: current,
    capabilities,
    projectCompletion: completion,
    targets: {
      totals: targetTree.totals,
      clusters: targetTree.clusters.map((cluster) => ({ label: clip(cluster.label, 120), totals: cluster.totals })),
      gaps: targetGaps,
    },
    gained,
    intents,
    repeatedActions: repeatOffenders,
    deadlockRisk,
    surfaceThin: nodes.some((node) => node.kind === 'webapp' && applicationExpanded(node.attrs ?? {}) !== true),
    remembered: supervisionMemory(nodes).map((row) => ({ kind: row.kind, text: row.text })),
    shouldSpeak: supervisionShouldSpeak(nodes),
    handoff: handoffText(nodes),
    lastSupervision: latest === undefined || latest === null ? null : {
      round: Number(latest.attrs?.round) || 0,
      verdict: latest.attrs?.verdict ?? 'hold',
      diagnosis: clip(latest.attrs?.diagnosis, 600),
      nextPlan: clip(latest.attrs?.nextPlan, 900),
      mustIntents: Array.isArray(latest.attrs?.mustIntents) ? latest.attrs.mustIntents.slice(0, 6) : [],
      banRepeats: Array.isArray(latest.attrs?.banRepeats) ? latest.attrs.banRepeats.slice(0, 8) : [],
    },
    verifiedHigh: nodes
      .filter(verifiedHigh)
      .slice(0, 10)
      .map((node) => ({
        title: clip(node.attrs?.title ?? node.label, 140),
        template: node.attrs?.template ?? 'manual',
        severity: node.attrs?.severity ?? 'unknown',
        tactic: tacticForFinding(node),
        cue: cueForFinding(node),
        evidenceCount: Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0,
        secondaryVerified: node.attrs?.secondaryVerified === true,
      })),
    access: nodes.filter((node) => node.kind === 'access' && ['validated', 'escalated'].includes(node.status)).slice(0, 8).map((node) => ({
      kind: node.attrs?.kind ?? 'access',
      privilege: node.attrs?.privilege ?? 'unknown',
      status: node.status,
    })),
    data: nodes.filter((node) => node.kind === 'data' && node.status === 'verified').slice(0, 8).map((node) => ({
      dataClass: node.attrs?.dataClass ?? 'internal',
      count: Number(node.attrs?.count) || 0,
      thresholdMet: node.attrs?.thresholdMet === true,
    })),
  };
}

export function buildSelfBriefPrompt(bundle) {
  return `You are the AtkBrain self-supervision team (the 御者/supervisor). The 从者 (executor) is the main pentest agent. Your brief is a memory handoff, not an opening speech. You do NOT execute tools, open network connections, or command child agents. Restate what \`remembered\` already records so the executor does not drop it on a long chain, then name what is still open.

## Progress bundle
${JSON.stringify(bundle, null, 2)}

## Output
Return ONE JSON object, no markdown fence, no prose:
{
  "progress_summary": "what the main team did this round and what changed",
  "gained": ["concrete verified gains only; do not invent"],
  "missed": ["what is still unverified or missing"],
  "advice": "what to do next and why",
  "anti_deadlock": ["specific direction change if the same action/target repeats"],
  "recommended_next": ["short executable next steps"],
  "deadlock_risk": "low|medium|high",
  "confidence": 0.0
}

Rules:
- Stay a memory handoff. \`handoff\` is the required seven-section text: 目标, 服务, 危险点, 严重高中低, 凭证, 立足点, 信息. Copy it into the start of progress_summary. A section that says 无 stays 无. \`remembered\` is the stored graph, not the simplified relationship diagram. Do not replace those sections with node counts, and do not tell the executor to start recon when those facts are already recorded.
- \`recommended_next\` is advice only. Do not turn it into a required intent.
- If \`unreadFiles\` is non-empty, those paths were saved on disk and are not in the graph. Put them in \`missed\` and tell the executor to call atkbrain_ingest on those paths before any further probe or scan. Do not paste the file bodies.
- Base every claim on the bundle; no invented findings, access or data.
- If no quality progress, say so and recommend a real pivot; do not prescribe repeating the same action.
- If a high/critical candidate is unverified, recommend verification before new enumeration.
- If a verified vulnerability exists and validated access is still zero, \`recommended_next\` raises that issue toward a foothold. Do not recommend closing coverage cells in bulk. A higher-harm result on the same interface is a new finding, recorded with atkbrain_record, not merged into the lower one.
- If a verified high/critical finding has no access/data proof, recommend impact escalation.
- If \`projectCompletion.complete\` is false, say the project is not complete and require the 报告撰写 team project HTML report before finishing.
- If \`capabilities.gaps\` is non-empty, report which capability family was not actually invoked (tools, skill, dictionary) and recommend the missing call.
- If \`targets.gaps\` contains recon-only or untested targets, name the top gaps and recommend testing them before discovering more assets; never claim every target was tested without coverage evidence.
- If \`targets.totals.tested\` is smaller than \`targets.totals.targets\`, repeat that gap in \`missed\` and \`recommended_next\`.
- Never expose raw secrets, PII or payloads; titles/subjects in the bundle are already redacted.
`;
}

export function parseSelfBrief(text) {
  const raw = String(text ?? '').trim();
  if (!raw) return null;
  let blob = '';
  const fence = /```(?:json)?\s*([\s\S]*?)\s*```/u.exec(raw);
  if (fence) blob = fence[1].trim();
  else {
    const start = raw.indexOf('{');
    const end = raw.lastIndexOf('}');
    if (start >= 0 && end > start) blob = raw.slice(start, end + 1);
  }
  if (!blob) return null;
  try {
    const data = JSON.parse(blob);
    if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
    const list = (value, limit = 8) => (Array.isArray(value) ? value : [])
      .map((entry) => clip(entry, 300)).filter((entry) => entry.length > 0).slice(0, limit);
    const risk = String(data.deadlock_risk ?? 'medium').toLowerCase();
    return {
      progressSummary: clip(data.progress_summary, 1500),
      gained: list(data.gained, 8),
      missed: list(data.missed, 8),
      advice: clip(data.advice, 1500),
      antiDeadlock: list(data.anti_deadlock, 8),
      recommendedNext: list(data.recommended_next, 8),
      deadlockRisk: ['low', 'medium', 'high'].includes(risk) ? risk : 'medium',
      confidence: Number.isFinite(Number(data.confidence)) ? Math.max(0, Math.min(1, Number(data.confidence))) : 0.5,
    };
  } catch {
    return null;
  }
}

/** Deterministic fallback when the AI supervisor is unavailable. */
function withHandoff(summary, bundle) {
  const handoff = String(bundle?.handoff ?? '').trim();
  if (handoff.length === 0 || String(summary ?? '').includes('目标：')) return summary;
  return `${handoff}\n${summary}`;
}

export function fallbackSelfBrief(bundle) {
  const remembered = Array.isArray(bundle.remembered) ? bundle.remembered : [];
  const memoryLine = remembered.slice(0, 8).map((row) => row.text).filter(Boolean).join('; ');
  const gained = bundle.gained.length > 0 ? bundle.gained : ['no new verified quality gain this round'];
  const raiseImpact = (bundle.metrics.validatedAccess ?? 0) === 0 && (bundle.metrics.verifiedFindings ?? 0) > 0;
  const advice = bundle.surfaceThin === true
    ? 'The recorded URL is only an entry. Inventory the application modules and seed their interfaces before closing evidence on that page.'
    : bundle.deadlockRisk === 'high'
    ? 'Stop repeating the same action/target: pivot to a different tactic or verify an open high/critical candidate before new enumeration.'
    : bundle.metrics.candidateHighCritical > 0
      ? 'Verify the open high/critical candidate and obtain secondary confirmation before expanding scope.'
      : raiseImpact
        ? 'A verified finding exists and there is no validated access. Raise it toward command execution or a foothold. Do not refute coverage in bulk. A higher-harm result on the same interface is a new finding.'
        : 'Continue the current intent and finish its evidence contract; do not start a second enumeration path without closing it.';
  return {
    progressSummary: withHandoff(memoryLine.length > 0
      ? `Already recorded, do not drop: ${memoryLine}`
      : `Round ${bundle.round}: ${bundle.phase}; ${bundle.metrics.verifiedFindings} verified finding(s), ${bundle.metrics.validatedAccess} validated access path(s), ${bundle.metrics.verifiedData} verified data set(s).`, bundle),
    gained,
    missed: [
      ...(bundle.metrics.candidateHighCritical > 0 ? [`${bundle.metrics.candidateHighCritical} unverified high/critical candidate(s)`] : []),
      ...(bundle.metrics.validatedAccess === 0 ? ['no validated access path'] : []),
      ...(Array.isArray(bundle.unreadFiles) && bundle.unreadFiles.length > 0 ? [`workspace files not in the graph: ${bundle.unreadFiles.slice(0, 12).join(', ')}`] : []),
    ],
    advice,
    antiDeadlock: bundle.deadlockRisk === 'high'
      ? ['ban the repeated action/target', 'pick an orthogonal tactic or verify an open high-risk item', 'if no allowed frontier remains, finish']
      : ['do not repeat a refuted action without a new observation channel'],
    recommendedNext: bundle.deadlockRisk === 'high'
      ? ['resolve or refute the current intent with two channels', 'pivot to a different tactic/target']
      : raiseImpact
        ? ['raise the verified finding toward a foothold']
        : ['continue the current intent', 'record evidence and resolve it'],
    deadlockRisk: bundle.deadlockRisk,
    confidence: 0.5,
  };
}

/** Merge/sanitize an AI self-brief into a stable report. */
export function normalizeSelfBrief(report, bundle) {
  if (report === null || report === undefined) return fallbackSelfBrief(bundle);
  return {
    progressSummary: withHandoff(report.progressSummary || fallbackSelfBrief(bundle).progressSummary, bundle),
    gained: Array.isArray(report.gained) ? report.gained.slice(0, 8) : [],
    missed: Array.isArray(report.missed) ? report.missed.slice(0, 8) : [],
    advice: report.advice || fallbackSelfBrief(bundle).advice,
    antiDeadlock: Array.isArray(report.antiDeadlock) ? report.antiDeadlock.slice(0, 8) : [],
    recommendedNext: Array.isArray(report.recommendedNext) ? report.recommendedNext.slice(0, 8) : [],
    deadlockRisk: ['low', 'medium', 'high'].includes(report.deadlockRisk) ? report.deadlockRisk : bundle.deadlockRisk,
    confidence: Number.isFinite(Number(report.confidence)) ? Math.max(0, Math.min(1, Number(report.confidence))) : 0.5,
  };
}

export function formatSelfBrief(report) {
  const lines = [
    `监督团队简报（御者→从者）：${report.progressSummary}`,
    `已获得：${report.gained.length > 0 ? report.gained.join('；') : '—'}`,
    `仍缺失：${report.missed.length > 0 ? report.missed.join('；') : '—'}`,
    `建议：${report.advice}`,
    `防死磕：${report.antiDeadlock.length > 0 ? report.antiDeadlock.join('；') : '—'}`,
    `下一步：${report.recommendedNext.length > 0 ? report.recommendedNext.join('；') : '—'}`,
    `死磕风险：${report.deadlockRisk}；置信度：${Number(report.confidence).toFixed(2)}`,
  ];
  return lines.join('\n');
}

export function skillSignals(state) {
  return {
    stack: graphStackTokens(state),
    tactics: Object.values(state.nodes ?? {})
      .filter((node) => node.kind === 'finding')
      .map(tacticForFinding),
  };
}
