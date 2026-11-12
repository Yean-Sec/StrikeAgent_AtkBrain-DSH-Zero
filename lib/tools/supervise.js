/**
 * `atkbrain_supervise` — independent review, secondary verification and rating.
 *
 * review: deterministic gates + optional fresh "御者" subagent that only reads
 * a bounded brief and returns a JSON plan.
 * verify: a separate verifier subagent (network or evidence-only) decides
 * whether a finding is independently reproducible.
 * rate: deterministic red-team rating; unproven RCE claims are capped.
 */
import { TOOL_NAMES } from '../constants.js';
import { applyOps } from '../ops.js';
import { graphOwner } from '../ledger-host.js';
import { requestEscalationWake } from '../native-teams.js';
import { findingAttrs, fromInput as resolveCvss } from '../cvss31.js';
import { evaluateScope } from '../scope.js';
import { computeFrontier } from '../frontier.js';
import { nodeId, nowIso, shortHash, stableStringify, invalid } from '../util.js';
import { redactPacket } from '../redact.js';
import {
  evidenceNodeOp,
  link,
  supervisionNodeOp,
} from './build.js';
import {
  assertArgs,
  audit,
  optionalString,
  registerAtkTool,
  requireEnum,
} from './common.js';
import { nativeTeammate } from '../self-teams.js';
import { claimFinding, evidenceStamp, isTerminalSecondary, releaseFinding } from '../verify-queue.js';
import { hasCvssScore, hardeningScoreRefusal, isHardeningFinding, blendOperational } from '../finding-classification.js';
import { buildSupervisorBrief } from '../loop/brief.js';
import {
  deterministicPlan,
  refineSupervisionPlan,
  buildVerifierBrief,
  reviewWithSubagent,
  verifyWithSubagent,
} from '../loop/supervisor.js';
import { claimGuardForFinding, isCandidateHighCritical, isHighCriticalFinding, isVerifiedFinding, ratingForFinding, supervisionDue } from '../loop/policy.js';

const ACTIONS = ['review', 'verify', 'rate', 'status'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'review the round, verify one finding, rate one finding, or inspect the latest supervision.' },
    findingId: { type: 'string', description: 'Finding node id or canonical key for verify/rate.' },
    mode: { type: 'string', enum: ['auto', 'deterministic', 'ai'], description: 'Review mode; auto consults the AI supervisor when due, ai always, deterministic never.' },
    verifyMode: { type: 'string', enum: ['evidence', 'network'], description: 'Verification mode; network only uses the exact recorded scope and read-only checks.' },
    cvssVector: { type: 'string', description: 'NVD CVSS v3.1 Base vector for action=rate.' },
    cvss: { type: 'object', additionalProperties: true, description: 'CVSS v3.1 Base metrics {AV,AC,PR,UI,S,C,I,A} for action=rate.' },
    force: { type: 'boolean', description: 'Allow review/verify to run even when the loop says the current intent is in flight.' },
  },
};

function latestRoundSupervision(state) {
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'supervision' && node.attrs?.type === 'round_plan')
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0)
      || String(b.lastSeen ?? '').localeCompare(String(a.lastSeen ?? '')))[0];
}

function loopNode(state) {
  return Object.values(state.nodes ?? {}).find((node) => node.kind === 'loop');
}

function findFinding(state, identifier) {
  const matches = Object.values(state.nodes ?? {}).filter((node) => node.kind === 'finding'
    && (node.id === identifier || node.key === identifier));
  return matches.find((node) => node.attrs?.stub !== true) ?? matches[0];
}

function lessonsFromGraph(state) {
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'lesson' && node.status !== 'retired')
    .map((node) => ({
      lessonKey: node.attrs?.lessonKey ?? node.key,
      idea: node.attrs?.idea ?? '',
      method: node.attrs?.method ?? '',
      route: node.attrs?.route ?? '',
      chain: node.attrs?.chain ?? '',
      when: node.attrs?.when ?? [],
      do: node.attrs?.do ?? [],
      avoid: node.attrs?.avoid ?? [],
      confidence: Number(node.attrs?.confidence) || 0.4,
      wins: Number(node.attrs?.wins) || 0,
      fails: Number(node.attrs?.fails) || 0,
      uses: Number(node.attrs?.uses) || 0,
      status: node.status,
    }));
}

function scopeEntriesForFinding(state, finding) {
  const subject = String(finding.attrs?.subjectKey ?? finding.key);
  const url = String(finding.attrs?.proofUrl ?? '').trim();
  const target = url.startsWith('http')
    ? { type: 'url', url }
    : (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(subject) ? { type: 'ip', ip: subject } : { type: 'host', host: subject });
  return (state.scope?.allow ?? []).filter((entry) => {
    try {
      return evaluateScope({ allow: [entry], deny: [] }, target).allowed;
    } catch {
      return false;
    }
  });
}

function verificationDetailPatch(details) {
  const source = details !== null && typeof details === 'object' ? details : {};
  const hasChinese = (value) => /[\u3400-\u9fff]/u.test(String(value ?? ''));
  const patch = {};
  for (const [field, max] of [['description', 4000], ['impact', 4000], ['remediation', 3000], ['repro', 4000]]) {
    const value = String(source[field] ?? '').trim();
    if (value.length > 0 && hasChinese(value)) patch[field] = value.slice(0, max);
  }
  for (const [field, max] of [['request', 8000], ['response', 8000]]) {
    const value = String(source[field] ?? '').trim();
    if (value.length > 0) patch[field] = redactPacket(value, max);
  }
  const coreComplete = ['description', 'impact', 'repro'].every((field) => /[\u3400-\u9fff]/u.test(String(source[field] ?? '')));
  if (Object.keys(patch).length > 0 && coreComplete) {
    patch.secondaryDetailsSource = 'verification-team';
    patch.secondaryDetailsAt = nowIso();
  } else if (Object.keys(patch).length > 0) {
    patch.secondaryDetailPartial = true;
  }
  return patch;
}

function findingUpdateOp(finding, patch, { status, verification, evidenceIds } = {}) {
  return {
    op: 'node.upsert',
    kind: 'finding',
    key: finding.key,
    label: finding.label,
    attrs: { ...finding.attrs, ...patch },
    status: status ?? finding.status,
    confidence: finding.confidence,
    verification: verification ?? finding.verification,
    ...(Array.isArray(evidenceIds) ? { evidenceIds } : {}),
  };
}

/**
 * The lead can call every supervise action. The resident verification teammate
 * can call verify and rate, so the queue keeps moving after the lead stops.
 */
export function superviseCallerAllowed(member, action) {
  if (member === undefined || member === null) return true;
  if (member.role === 'lead') return true;
  return String(member.name ?? '') === 'atk-verifier' && (action === 'verify' || action === 'rate');
}

async function wakeEscalation(toolCtx, exec, state, ops) {
  try {
    const agentTeams = toolCtx.get('agentTeams');
    const lead = graphOwner(toolCtx, exec.agent);
    await requestEscalationWake({
      agentTeams,
      agent: lead,
      signal: exec.signal,
      state: applyOps(state, Array.isArray(ops) ? ops : []),
    });
  } catch {
    /* the next verification or record retries */
  }
}

export function registerSuperviseTool(ctx, config, runtime) {
  registerAtkTool(ctx, config, runtime, {
    name: TOOL_NAMES.supervise,
    callTitle: 'Supervise pentest round',
    description: 'Independent supervision for the autonomous loop: review the graph/round and return a hold/pivot/verify/escalate/stop plan (deterministic or fresh subagent 御者); verify one finding with a separate verifier subagent; rate a finding with a conservative red-team rubric. It never widens scope and never executes network actions itself.',
    parameters: PARAMETERS,
    timeoutMs: 300000,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (args.mode !== undefined) requireEnum(args, 'mode', ['auto', 'deterministic', 'ai']);
      if (args.verifyMode !== undefined) requireEnum(args, 'verifyMode', ['evidence', 'network']);
      if (args.findingId !== undefined) optionalString(args, 'findingId', { max: 500 });
      if (args.cvssVector !== undefined) optionalString(args, 'cvssVector', { max: 500 });
      if (args.cvss !== undefined && (args.cvss === null || typeof args.cvss !== 'object' || Array.isArray(args.cvss))) invalid('cvss must be an object with AV, AC, PR, UI, S, C, I, A');
      if (args.force !== undefined && typeof args.force !== 'boolean') invalid('force must be a boolean');
      if ((action === 'verify' || action === 'rate') && args.findingId === undefined) invalid(`${action} requires findingId`);
      return action;
    },
    async run({ args, state, exec, ctx: toolCtx, config: cfg, deps }) {
      const teams = (() => { try { return toolCtx.get('agentTeams'); } catch { return undefined; } })();
      if (teams !== undefined && teams !== null) {
        try {
          if (!superviseCallerAllowed(teams.membership(exec.agent), args.action)) invalid('atkbrain_supervise requires the Team Lead');
        } catch {
          /* standalone session */
        }
      }
      const loop = loopNode(state);
      const latest = latestRoundSupervision(state);

      if (args.action === 'status') {
        const verifications = Object.values(state.nodes ?? {})
          .filter((node) => node.kind === 'supervision'
            && ['finding_verification', 'rating'].includes(node.attrs?.type))
          .slice(-20)
          .map((node) => ({ id: node.id, type: node.attrs?.type, findingKey: node.attrs?.findingKey, verdict: node.attrs?.secondaryVerdict ?? node.attrs?.verdict, mode: node.attrs?.secondaryMode, at: node.attrs?.createdAt }));
        return {
          summary: latest === undefined
            ? 'No round supervision is recorded yet.'
            : `Latest supervision: round ${latest.attrs?.round ?? 0}, verdict ${latest.attrs?.verdict ?? 'hold'}, source ${latest.attrs?.source ?? 'deterministic'}, stop=${latest.attrs?.stopRecommended === true}. ${verifications.length} finding-level review(s) recorded.`,
          ops: [],
          details: { latest: latest?.attrs ?? null, verifications },
        };
      }

      if (args.action === 'review') {
        const frontier = computeFrontier(state, { limit: 30 });
        const mode = args.mode ?? 'ai';
        const deterministic = deterministicPlan({ state, loop: loop ?? { attrs: {}, status: 'running' }, latest, frontier, config: cfg });
        let plan = deterministic;
        let childId;
        let promptHash;
        let source = 'deterministic';
        let error = null;
        const shouldConsult = mode === 'ai'
          || (mode === 'auto' && supervisionDue(loop ?? { attrs: { round: 0 } }, state, latest, cfg));
        if (shouldConsult) {
          const brief = buildSupervisorBrief({
            state,
            loop: loop ?? { attrs: {}, status: 'running' },
            supervision: latest,
            lessons: lessonsFromGraph(state),
            intents: Object.values(state.nodes ?? {}).filter((node) => node.kind === 'intent' && ['open', 'claimed'].includes(node.status)),
            frontier,
            config: cfg,
          });
          const result = await reviewWithSubagent({
            ctx: toolCtx,
            agent: exec.agent,
            brief,
            signal: exec.signal,
            timeoutMs: cfg.supervisorTimeoutMs,
            native: nativeTeammate(state, 'supervision'),
          });
          childId = result.childId;
          promptHash = result.promptHash;
          error = result.error;
          if (result.plan !== null) {
            plan = refineSupervisionPlan(result.plan, {
              state,
              loop: loop ?? { attrs: {}, status: 'running' },
              frontier,
              intents: Object.values(state.nodes ?? {}).filter((node) => node.kind === 'intent' && ['open', 'claimed'].includes(node.status)),
              config: cfg,
            });
            source = result.via === 'native-team' ? 'native-team' : 'ai-subagent';
          } else {
            source = 'fallback';
          }
        }
        const supervisionOp = supervisionNodeOp(state, {
          type: 'round_plan',
          round: loop?.attrs?.round ?? 0,
          ...plan,
          childId,
          promptHash,
          planHash: shortHash(stableStringify(plan), 16),
          source,
        });
        const ops = [supervisionOp];
        if (loop !== undefined) ops.push(link({ kind: 'supervision', key: supervisionOp.key }, { kind: 'loop', key: loop.key }, 'supervises', { confidence: 0.8 }));
        ops.push(audit(TOOL_NAMES.supervise, 'supervise.review', state.engagement?.name ?? 'engagement', `${plan.verdict}/${source}`, []));
        return {
          summary: `Supervision ${plan.verdict} (${source})${error ? `; fallback: ${error}` : ''}. ${plan.diagnosis ?? ''}\nNext: ${plan.nextPlan || 'continue the current intent'}\nMust: ${(plan.mustIntents ?? []).join(', ') || '—'}; ban: ${(plan.banRepeats ?? []).join(', ') || '—'}.`,
          ops,
          details: { plan, source, childId, promptHash, error },
        };
      }

      if (args.action === 'rate') {
        const finding = findFinding(state, args.findingId);
        if (finding === undefined) invalid(`finding not found: ${args.findingId}`);
        const suppliedCvss = resolveCvss({ cvssVector: args.cvssVector, cvss: args.cvss });
        const storedCvss = suppliedCvss.present === true || typeof finding.attrs?.cvssVector !== 'string'
          ? { present: false }
          : resolveCvss({ cvssVector: finding.attrs.cvssVector });
        const cvss = suppliedCvss.present === true
          ? suppliedCvss
          : (storedCvss.present === true && storedCvss.ok === true ? storedCvss : { present: false });
        if (cvss.present === true) {
          if (cvss.ok !== true) invalid(`invalid CVSS v3.1 input: ${cvss.reason}`);
          if (cvss.rejected === true) invalid(cvss.reason);
          const hardening = hardeningScoreRefusal(finding.attrs, cvss);
          if (hardening !== null) invalid(hardening);
        }
        const guard = claimGuardForFinding(finding);
        let rating;
        let rationale;
        const patch = {};
        if (cvss.present === true) {
          rating = cvss.rating;
          rationale = `NVD CVSS v3.1 ${cvss.vector} base score ${cvss.scoreText} (${cvss.nvdSeverity}); ${cvss.nvdSeverity === 'NONE' ? 'no scored impact' : 'qualitative rating per NVD'}.`;
          Object.assign(patch, findingAttrs(cvss));
          patch.ratingSource = 'nvd-cvss31';
          if (guard !== null && ['critical', 'high'].includes(rating)) {
            rating = 'medium';
            rationale += ' Red-team claim guard caps the operational rating at medium because the RCE/command-execution claim is not proven; the CVSS base score remains visible.';
          }
        } else {
          const fallback = ratingForFinding(finding);
          rating = fallback.rating;
          rationale = `${fallback.rationale} Rating source: heuristic red-team rubric (no CVSS v3.1 vector/metrics supplied).`;
          if (guard !== null && ['critical', 'high'].includes(rating)) {
            rating = 'medium';
            rationale = `${rationale}; capped to medium because the RCE/command-execution claim is not proven`;
          }
          patch.ratingSource = 'heuristic';
        }
        Object.assign(patch, {
          redteamRating: rating,
          ratingRationale: rationale,
          ...(guard ? { claimGuard: guard } : {}),
        });
        const blend = blendOperational({ ...finding.attrs, ...patch });
        patch.redteamRating = blend.red.rating;
        patch.redteamScore = blend.red.score;
        patch.redteamRationale = blend.red.rationale;
        patch.operationalScore = blend.score;
        patch.operationalSeverity = blend.severity;
        patch.severity = blend.severity;
        rationale = `${rationale} 综合结果 ${blend.severity}：红队 ${blend.red.rating} 占 70%，CVSS ${cvss.present === true ? cvss.scoreText : '无'} 占 30%。`;
        patch.ratingRationale = rationale;
        const findingOp = findingUpdateOp(finding, patch);
        const supervisionOp = supervisionNodeOp(state, {
          type: 'rating',
          round: loop?.attrs?.round ?? 0,
          verdict: rating,
          diagnosis: rationale,
          nextPlan: `Use ${rating} for the operational rating; keep the original severity and any CVSS base score visible in the register.`,
          findingKey: finding.key,
          secondaryVerdict: cvss.present === true ? cvss.nvdSeverity : rating,
          source: 'deterministic',
          confidence: cvss.present === true ? 0.9 : 0.7,
          ratingSource: patch.ratingSource,
        });
        const ops = [findingOp, supervisionOp];
        if (loop !== undefined) ops.push(link({ kind: 'supervision', key: supervisionOp.key }, { kind: 'loop', key: loop.key }, 'supervises', { confidence: 0.6 }));
        ops.push(audit(TOOL_NAMES.supervise, 'supervise.rate', finding.key, cvss.present === true ? `${cvss.scoreText} ${cvss.nvdSeverity}->${rating}` : rating, []));
        await wakeEscalation(toolCtx, exec, state, ops);
        return {
          summary: cvss.present === true
            ? `Rated ${finding.label}: CVSS v3.1 ${cvss.vector} = ${cvss.scoreText} ${cvss.nvdSeverity}; operational rating ${rating}. ${rationale}`
            : `Rated ${finding.label} as ${rating} using the heuristic rubric (no CVSS vector/metrics supplied). ${rationale}`,
          ops,
          details: {
            rating,
            rationale,
            ratingSource: patch.ratingSource,
            cvss: cvss.present === true ? { vector: cvss.vector, score: cvss.score, nvdSeverity: cvss.nvdSeverity, rating: cvss.rating } : null,
            claimGuard: guard,
            finding: finding.attrs,
          },
        };
      }

      // verify
      const finding = findFinding(state, args.findingId);
      if (finding === undefined) invalid(`finding not found: ${args.findingId}`);
      if (isTerminalSecondary(finding.attrs)) {
        return {
          summary: `Verification already ${finding.attrs.secondaryVerdict} for ${finding.label}.`,
          ops: [],
          details: { verdict: finding.attrs.secondaryVerdict, skipped: 'terminal', finding: finding.key },
        };
      }
      if (!claimFinding(finding.key)) {
        return {
          summary: `Verification already running for ${finding.label}.`,
          ops: [],
          details: { skipped: 'in-flight', finding: finding.key },
        };
      }
      let callerName = '';
      try { callerName = String(teams?.membership?.(exec.agent)?.name ?? ''); } catch { callerName = ''; }
      const native = callerName === 'atk-verifier' ? undefined : nativeTeammate(state, 'verification');
      try {
      const verifyMode = args.verifyMode ?? 'evidence';
      const scopeEntries = verifyMode === 'network' ? scopeEntriesForFinding(state, finding) : [];
      const brief = buildVerifierBrief({ state, finding, mode: verifyMode, scopeEntries });
      const result = await verifyWithSubagent({
        ctx: toolCtx,
        agent: exec.agent,
        brief,
        signal: exec.signal,
        timeoutMs: cfg.verifierTimeoutMs,
        detachParentSignal: true,
        native,
      });
      const evidence = await deps.writeEvidence(
        exec.agent,
        `verify-${shortHash(finding.key, 10)}`,
        {
          findingKey: finding.key,
          title: finding.attrs?.title ?? finding.label,
          verdict: result.verdict,
          rationale: result.rationale,
          mode: verifyMode,
          observedMarker: result.observedMarker ?? null,
          details: result.details ?? null,
          childId: result.childId ?? null,
          at: nowIso(),
        },
        'application/json',
      );
      const evidenceOp = evidenceNodeOp(state, {
        path: evidence.path,
        relative: evidence.relative,
        mediaType: evidence.mediaType,
        bytes: evidence.bytes,
        sha256: evidence.sha256,
        label: `secondary verification ${finding.label}`,
      });
      const evidenceId = nodeId('evidence', evidenceOp.key);
      const evidenceIds = [...new Set([...(Array.isArray(finding.evidenceIds) ? finding.evidenceIds : []), evidenceId])];
      const verdict = result.verdict === 'verified' || result.verdict === 'refuted' ? result.verdict : null;
      const verified = verdict === 'verified';
      const attempts = (Number(finding.attrs?.secondaryAttempts) || 0) + 1;
      const verifierCvss = (typeof result.cvssVector === 'string' && result.cvssVector.length > 0)
        || (result.cvss !== null && result.cvss !== undefined)
        ? resolveCvss({ cvssVector: result.cvssVector, cvss: result.cvss })
        : null;
      const hardening = isHardeningFinding(finding.attrs);
      const cvssPatch = !hardening && verdict !== null && verifierCvss?.present === true && verifierCvss.ok === true && verifierCvss.rejected !== true
        ? { ...findingAttrs(verifierCvss), ratingSource: 'nvd-cvss31', cvssRationale: verifierCvss.vector }
        : {};
      const scored = hasCvssScore({ ...finding.attrs, ...cvssPatch });
      const closes = verdict === 'refuted' || (verified && (scored || hardening));
      const patch = closes
        ? {
          secondaryVerified: verified,
          secondaryVerdict: verdict,
          secondaryRationale: result.rationale,
          secondaryMode: verifyMode,
          secondaryAt: nowIso(),
          secondaryEvidencePath: evidence.relative,
          secondaryChildId: result.childId ?? null,
          secondaryAttempts: attempts,
          secondaryAttemptEvidence: evidenceStamp(finding),
          ...verificationDetailPatch(result.details),
          ...cvssPatch,
        }
        : {
          secondaryAttempts: attempts,
          secondaryLastError: verified
            ? 'confirmed, waiting for a CVSS v3.1 score'
            : String(result.rationale || result.error || 'inconclusive').slice(0, 2000),
          secondaryLastAt: nowIso(),
          secondaryAttemptEvidence: evidenceStamp(finding),
        };
      const findingOp = findingUpdateOp(finding, patch, {
        status: closes && verified && !['exploited', 'impacted', 'fixed'].includes(finding.status) ? 'verified' : finding.status,
        verification: closes && verified ? 'verified' : finding.verification,
        evidenceIds,
      });
      const supervisionOp = supervisionNodeOp(state, {
        type: 'finding_verification',
        round: loop?.attrs?.round ?? 0,
        verdict: closes ? result.verdict : 'pending',
        diagnosis: result.rationale,
        nextPlan: closes && verified
          ? 'Verification and CVSS rating are both recorded.'
          : (verdict === 'refuted'
            ? 'Secondary verification refuted this finding. Treat it as a false positive.'
            : (verified
              ? 'The check agrees, but the CVSS v3.1 score is missing. Call atkbrain_supervise action=rate before treating it as finished.'
              : 'Secondary verification did not finish. Keep the finding queued.')),
        findingKey: finding.key,
        secondaryVerdict: closes ? verdict : 'pending',
        secondaryMode: verifyMode,
        rationale: result.rationale,
        childId: result.childId,
        source: result.via === 'native-team' ? 'native-team' : (result.childId ? 'ai-subagent' : 'deterministic'),
        confidence: closes && verified ? 0.8 : 0.4,
        evidenceIds: [evidenceId],
      });
      const ops = [evidenceOp, findingOp, supervisionOp];
      ops.push(link({ kind: 'evidence', key: evidenceOp.key }, { kind: 'finding', key: finding.key }, 'proves', { confidence: verified ? 0.9 : 0.4 }));
      if (loop !== undefined) ops.push(link({ kind: 'supervision', key: supervisionOp.key }, { kind: 'loop', key: loop.key }, 'supervises', { confidence: 0.7 }));
      ops.push(audit(TOOL_NAMES.supervise, 'supervise.verify', finding.key, `${result.verdict}/${verifyMode}`, [evidence.sha256]));
      await wakeEscalation(toolCtx, exec, state, ops);
      return {
        summary: closes
          ? `Verification ${result.verdict} (${verifyMode}) for ${finding.label}. ${result.rationale}${result.details?.description ? ` Detail: ${result.details.description.slice(0, 300)}` : ''}${result.error ? ` Warning: ${result.error}` : ''}`
          : (verified
            ? `Verification agrees with ${finding.label}, but it stays in progress until atkbrain_supervise action=rate records a CVSS v3.1 base score. Verification and rating finish together.`
            : `Verification ${result.verdict} (${verifyMode}) for ${finding.label}. ${result.rationale}${result.details?.description ? ` Detail: ${result.details.description.slice(0, 300)}` : ''}${result.error ? ` Warning: ${result.error}` : ''}`),
        ops,
        details: {
          verdict: result.verdict,
          rationale: result.rationale,
          mode: verifyMode,
          evidence: evidence.relative,
          childId: result.childId,
          via: result.via ?? null,
          cvss: result.cvss ?? null,
          cvssVector: result.cvssVector ?? null,
          finding: patch,
        },
      };
      } finally {
        releaseFinding(finding.key);
      }
    },
  });
}
