/**
 * Automatic verification queue.
 *
 * Every recorded finding stays queued until verification and rating finish
 * together. `refuted` is a false positive. `verified` also needs a CVSS v3.1
 * base score; a confirmation without that score stays queued.
 * parallel. The verifier uses its own timeout, so the lead abort does not
 * cancel an in-flight check. Checks that have not finished when the lead
 * tool returns stay queued for the next Lead turn.
 *
 * Network re-checks remain an explicit
 * `atkbrain_supervise action=verify verifyMode=network` action.
 */
import { applyOps } from './ops.js';
import { buildVerifierBrief, verifyWithSubagent } from './loop/supervisor.js';
import { ratingForFinding } from './loop/policy.js';
import { findingAttrs, fromInput } from './cvss31.js';
import { hasCvssScore, isHardeningFinding, reflectedXssAdjustment } from './finding-classification.js';
import { audit } from './tools/common.js';
import {
  evidenceNodeOp,
  link,
  selfTeamNodeOp,
  supervisionNodeOp,
} from './tools/build.js';
import { nodeId, nowIso, shortHash } from './util.js';
import { redactPacket } from './redact.js';
import {
  claimFinding,
  evidenceStamp,
  pendingFindings,
  releaseFinding,
  runnableFindings,
} from './verify-queue.js';

const SEVERITY_RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, info: 0 });

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
  if (Object.keys(patch).length > 0) {
    patch.secondaryDetailsSource = 'verification-team';
    patch.secondaryDetailsAt = nowIso();
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

function attemptPatch(finding, reason) {
  return {
    secondaryAttempts: (Number(finding.attrs?.secondaryAttempts) || 0) + 1,
    secondaryLastError: String(reason ?? 'inconclusive').slice(0, 2000),
    secondaryLastAt: nowIso(),
    secondaryAttemptEvidence: evidenceStamp(finding),
  };
}

function concurrencyOf(config) {
  const requested = Number(config?.autoVerifyConcurrency);
  const value = Number.isFinite(requested) && requested > 0 ? requested : 4;
  return Math.max(1, Math.min(8, value));
}

/**
 * Wait until every check finishes, or until the lead signal aborts.
 * A check keeps its own timeout. Results that land after the abort stay out
 * of this tool result and the finding remains queued.
 */
async function collectUntil(tasks, signal) {
  const collected = [];
  const all = Promise.all(tasks.map(async (task) => {
    const piece = await task;
    collected.push(piece);
    return piece;
  }));
  if (signal === undefined || signal === null) {
    await all;
    return collected.slice();
  }
  await Promise.race([
    all,
    new Promise((resolve) => {
      if (signal.aborted) resolve();
      else signal.addEventListener('abort', () => resolve(), { once: true });
    }),
  ]);
  return collected.slice();
}

async function verifyOne({ ctx, agent, working, finding, writeEvidence, timeoutMs }) {
  const brief = buildVerifierBrief({ state: working, finding, mode: 'evidence', scopeEntries: [] });
  let result;
  try {
    result = await verifyWithSubagent({
      ctx,
      agent,
      brief,
      timeoutMs,
      detachParentSignal: true,
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      ops: [findingUpdateOp(finding, attemptPatch(finding, reason))],
      entry: null,
      error: `${finding.label}: ${reason}`,
    };
  }
  const verdict = String(result?.verdict ?? 'inconclusive').toLowerCase();
  const terminal = verdict === 'verified' || verdict === 'refuted';
  if (!terminal) {
    const reason = result?.error || result?.rationale || 'inconclusive';
    return {
      ops: [findingUpdateOp(finding, attemptPatch(finding, reason))],
      entry: null,
      error: `${finding.label}: ${reason}`,
    };
  }
  const rationale = String(result?.rationale ?? '').slice(0, 3000);
  const evidence = await writeEvidence(agent, `auto-verify-${shortHash(finding.key, 10)}`, {
    findingKey: finding.key,
    title: finding.attrs?.title ?? finding.label,
    verdict,
    rationale,
    details: result?.details ?? null,
    mode: 'evidence',
    auto: true,
    childId: result?.childId ?? null,
    at: nowIso(),
  }, 'application/json');
  const evidenceOp = evidenceNodeOp(working, {
    path: evidence.path,
    relative: evidence.relative,
    mediaType: evidence.mediaType,
    bytes: evidence.bytes,
    sha256: evidence.sha256,
    label: `auto secondary verification ${finding.label}`,
  });
  const evidenceId = nodeId('evidence', evidenceOp.key);
  const evidenceIds = [...new Set([...(Array.isArray(finding.evidenceIds) ? finding.evidenceIds : []), evidenceId])];
  const heuristicRating = ratingForFinding(finding);
  const cvssInput = result?.cvssVector
    ? { cvssVector: result.cvssVector }
    : (result?.cvss ? { cvss: result.cvss } : null);
  const cvssResult = cvssInput === null ? null : fromInput(cvssInput);
  const hardening = isHardeningFinding(finding.attrs);
  const cvssAttrs = !hardening && cvssResult?.ok === true && cvssResult.rejected !== true ? findingAttrs(cvssResult) : {};
  const scored = hardening || hasCvssScore({ ...finding.attrs, ...cvssAttrs });
  if (verdict === 'verified' && !scored) {
    return {
      ops: [
        evidenceOp,
        findingUpdateOp(finding, attemptPatch(finding, 'confirmed, waiting for a CVSS v3.1 score'), { evidenceIds }),
        link({ kind: 'evidence', key: evidenceOp.key }, { kind: 'finding', key: finding.key }, 'proves', { confidence: 0.4 }),
      ],
      entry: null,
      error: null,
    };
  }
  const rating = hardening
    ? { rating: 'info', rationale: '配置暴露，不按漏洞记 CVSS。' }
    : (cvssResult?.ok === true && cvssResult.rejected !== true
      ? { rating: cvssResult.rating, rationale: `CVSS v3.1 ${cvssResult.scoreText} (${cvssResult.nvdSeverity})` }
      : heuristicRating);
  const adjusted = reflectedXssAdjustment({ ...finding.attrs, ...cvssAttrs, title: finding.attrs?.title ?? finding.label });
  const isVerified = verdict === 'verified';
  const patch = {
    ...attemptPatch(finding, rationale),
    secondaryVerified: isVerified,
    secondaryVerdict: verdict,
    secondaryRationale: rationale,
    secondaryMode: 'evidence',
    secondaryAt: nowIso(),
    secondaryEvidencePath: evidence.relative,
    secondaryChildId: result?.childId ?? null,
    secondaryAuto: true,
    ...verificationDetailPatch(result?.details),
    redteamRating: rating.rating,
    ratingSource: cvssAttrs.cvssScore !== undefined ? 'nvd-cvss31' : 'heuristic',
    ratingRationale: adjusted.capped === true
      ? `${rating.rationale} Reflected XSS is capped at medium because the victim must open the link.`
      : rating.rationale,
    ...cvssAttrs,
    ...(adjusted.capped === true ? {
      cvssScore: adjusted.attrs.cvssScore,
      cvssSeverity: adjusted.attrs.cvssSeverity,
      cvssRating: adjusted.attrs.cvssRating,
      severity: 'medium',
      cvssCap: 'reflected-xss',
      cvssCapFrom: adjusted.originalScore,
    } : {}),
  };
  const findingOp = findingUpdateOp(finding, patch, {
    status: isVerified ? 'verified' : finding.status,
    verification: isVerified ? 'verified' : finding.verification,
    evidenceIds,
  });
  const supervisionOp = supervisionNodeOp(working, {
    type: 'finding_verification',
    round: 0,
    verdict,
    diagnosis: rationale,
    nextPlan: isVerified
      ? 'Use this finding in impact escalation; it has independent confirmation.'
      : 'Secondary verification refuted this finding. Treat it as a false positive.',
    findingKey: finding.key,
    secondaryVerdict: verdict,
    secondaryMode: 'evidence',
    rationale,
    childId: result?.childId ?? null,
    source: result?.childId ? 'ai-subagent' : 'deterministic',
    confidence: isVerified ? 0.8 : 0.4,
    evidenceIds: [evidenceId],
    ratingSource: 'heuristic',
  });
  const teamOp = selfTeamNodeOp({
    type: 'verification',
    mode: 'subagents',
    members: [
      { role: 'verifier', name: 'atkbrain-verifier', mode: 'subagent', responsibility: 'independent secondary verification' },
      { role: 'rater', name: 'atkbrain-rater', mode: 'subagent', responsibility: 'CVSS/operational rating' },
    ],
    status: 'active',
    lastVerifyAt: nowIso(),
    verifiedCount: isVerified ? 1 : 0,
    ratedCount: 1,
  });
  const ops = [evidenceOp, findingOp, supervisionOp, teamOp];
  ops.push(link({ kind: 'evidence', key: evidenceOp.key }, { kind: 'finding', key: finding.key }, 'proves', { confidence: isVerified ? 0.9 : 0.4 }));
  ops.push(link({ kind: 'supervision', key: supervisionOp.key }, { kind: 'finding', key: finding.key }, 'supervises', { confidence: 0.7 }));
  ops.push(link({ kind: 'self_team', key: teamOp.key }, { kind: 'finding', key: finding.key }, 'targets', { confidence: 0.75 }));
  ops.push(audit('atkbrain_selftteam', 'selftteam.verify.auto', finding.key, `${verdict}/heuristic`, [evidence.sha256]));
  return {
    ops,
    entry: { finding: finding.key, verdict, rating: rating.rating, childId: result?.childId ?? null, evidence: evidence.relative },
    error: null,
  };
}

/**
 * Verify the next batch of queued findings.
 * Never throws; a failed attempt stays queued and is reported in `errors`.
 */
export async function autoVerifyFindings({
  ctx,
  agent,
  state,
  ops,
  candidates,
  config = {},
  writeEvidence,
  signal,
  timeoutMs = config.verifierTimeoutMs ?? 120000,
} = {}) {
  if (config.autoVerifyFindings === false) return { ops: [], verified: [], errors: [], skipped: 'disabled', queued: [] };
  if (typeof writeEvidence !== 'function') return { ops: [], verified: [], errors: ['evidence writer unavailable'], skipped: 'no-evidence-writer', queued: [] };
  const working = applyOps(state, ops ?? []);
  const priority = new Set((Array.isArray(candidates) ? candidates : []).map((finding) => finding?.key).filter(Boolean));
  const ranked = runnableFindings(Object.values(working.nodes ?? {})).sort((left, right) => {
    const leftFirst = priority.has(left.key) ? 1 : 0;
    const rightFirst = priority.has(right.key) ? 1 : 0;
    if (leftFirst !== rightFirst) return rightFirst - leftFirst;
    const leftRank = SEVERITY_RANK[String(left.attrs?.severity ?? '').toLowerCase()] ?? 0;
    const rightRank = SEVERITY_RANK[String(right.attrs?.severity ?? '').toLowerCase()] ?? 0;
    return rightRank - leftRank || String(left.label ?? '').localeCompare(String(right.label ?? ''));
  });
  const queued = pendingFindings(Object.values(working.nodes ?? {})).map((finding) => finding.key);
  if (signal?.aborted) return { ops: [], verified: [], errors: [], skipped: 'lead-ended', queued };
  if (ranked.length === 0) {
    return {
      ops: [],
      verified: [],
      errors: [],
      skipped: queued.length > 0 ? 'retry-cap' : 'queue-empty',
      queued,
    };
  }
  const batch = [];
  for (const finding of ranked) {
    if (batch.length >= concurrencyOf(config)) break;
    if (!claimFinding(finding.key)) continue;
    batch.push(finding);
  }
  if (batch.length === 0) return { ops: [], verified: [], errors: [], skipped: 'in-flight', queued };
  const tasks = batch.map((finding) => verifyOne({
    ctx,
    agent,
    working,
    finding,
    writeEvidence,
    timeoutMs,
  }).finally(() => releaseFinding(finding.key)));
  let pieces = [];
  try {
    pieces = await collectUntil(tasks, signal);
  } catch (error) {
    return {
      ops: [],
      verified: [],
      errors: [error instanceof Error ? error.message : String(error)],
      skipped: null,
      queued,
    };
  }
  const out = [];
  const verified = [];
  const errors = [];
  for (const piece of pieces) {
    out.push(...piece.ops);
    if (piece.entry !== null) verified.push(piece.entry);
    if (piece.error !== null) errors.push(piece.error);
  }
  const started = new Set(batch.map((finding) => finding.key));
  return {
    ops: out,
    verified,
    errors,
    skipped: null,
    queued: queued.filter((key) => !started.has(key) || !verified.some((entry) => entry.finding === key)),
  };
}
