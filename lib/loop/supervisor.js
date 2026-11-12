/**
 * Supervisor layer.
 *
 * The deterministic planner always runs. An optional fresh subagent ("御者")
 * receives a bounded brief with no raw secrets and returns one JSON plan; its
 * output is then clamped by policy.refineSupervisionPlan. If the model,
 * service, or timeout fails, the deterministic plan is used.
 */
import { shortHash } from '../util.js';
import { candidateIntents, objectiveAchieved, refineSupervisionPlan } from './policy.js';
import { isHardeningFinding, isVulnerabilityNode, secondaryVerificationPassed } from '../finding-classification.js';
import { applicationExpanded } from '../endpoint-vocab.js';

function clip(value, length) {
  const text = String(value ?? '').trim();
  return text.length > length ? text.slice(0, length) : text;
}

function parseJsonObject(text) {
  const raw = String(text ?? '').trim();
  if (!raw) return null;
  const candidates = [];
  const fence = /```(?:json)?\s*(\{[\s\S]*?\})\s*```/u.exec(raw);
  if (fence) candidates.push(fence[1]);
  const first = raw.indexOf('{');
  const last = raw.lastIndexOf('}');
  if (first >= 0 && last > first) candidates.push(raw.slice(first, last + 1));
  candidates.push(raw);
  for (const candidate of candidates) {
    try {
      const value = JSON.parse(candidate);
      if (value && typeof value === 'object' && !Array.isArray(value)) return value;
    } catch {
      /* try next */
    }
  }
  return null;
}

export function parseSupervisorOutput(text) {
  const value = parseJsonObject(text);
  if (value === null) return null;
  const verdict = String(value.verdict ?? value.action ?? 'hold').toLowerCase();
  return {
    verdict: ['hold', 'pivot', 'verify', 'escalate', 'stop'].includes(verdict) ? verdict : 'hold',
    diagnosis: clip(value.diagnosis ?? value.reason, 1500),
    nextPlan: clip(value.next_plan ?? value.nextPlan ?? value.plan, 3000),
    mustIntents: Array.isArray(value.must_intents ?? value.mustIntents) ? (value.must_intents ?? value.mustIntents) : [],
    preferTactics: Array.isArray(value.prefer_tactics ?? value.preferTactics) ? (value.prefer_tactics ?? value.preferTactics) : [],
    banRepeats: Array.isArray(value.ban_repeats ?? value.banRepeats) ? (value.ban_repeats ?? value.banRepeats) : [],
    stopRecommended: value.stop_recommended === true || value.stopRecommended === true,
    stopReason: value.stop_reason ?? value.stopReason ?? null,
    confidence: Number(value.confidence) || 0.5,
    source: 'ai-subagent',
  };
}

/** Deterministic plan from policy gates and frontier; never calls a model. */
export function deterministicPlan({ state, loop, latest, frontier, config }) {
  const candidates = candidateIntents(state, loop, frontier, config, latest);
  const must = candidates.map((entry) => entry.action.actionId).filter(Boolean);
  const liveNodes = Object.values(state.nodes ?? {}).filter((node) => node.status !== 'merged');
  const hasHighCandidate = liveNodes.some((node) => node.kind === 'finding'
    && ['critical', 'high'].includes(String(node.attrs?.redteamRating ?? node.attrs?.severity ?? '').toLowerCase())
    && !['verified', 'exploited', 'impacted', 'fixed'].includes(node.status));
  const verifiedHigh = liveNodes.some((node) => node.kind === 'finding'
    && ['verified', 'exploited', 'impacted'].includes(node.status)
    && ['critical', 'high'].includes(String(node.attrs?.redteamRating ?? node.attrs?.severity ?? '').toLowerCase()));
  const verifiedIssue = liveNodes.some((node) => node.kind === 'finding'
    && !['merged', 'refuted'].includes(node.status)
    && isHardeningFinding(node.attrs ?? {}) === false
    && (isVulnerabilityNode(node) || secondaryVerificationPassed(node.attrs ?? {})));
  const hasFoothold = liveNodes.some((node) => node.kind === 'access' && ['validated', 'escalated'].includes(node.status));
  const surfaceThin = liveNodes.some((node) => node.kind === 'webapp' && applicationExpanded(node.attrs ?? {}) !== true);
  const noProgress = Number(loop.attrs?.noProgressRounds) || 0;
  const stall = Math.max(1, Number(config?.loopStallRounds) || 3);
  let verdict = 'hold';
  let nextPlan = 'Continue the currently assigned intent and finish its evidence contract.';
  if (objectiveAchieved(state, loop)) {
    verdict = 'stop';
    nextPlan = 'Objective is achieved; call atkbrain_loop action=finish outcome=achieved.';
  } else if (surfaceThin) {
    verdict = 'pivot';
    nextPlan = 'The recorded URL is only an entry. Inventory the application modules and seed their interfaces before closing evidence on that page. A high candidate on the entry stays queued for verification and does not block the inventory.';
  } else if (hasHighCandidate) {
    verdict = 'verify';
    nextPlan = 'Verify the high/critical candidates and obtain independent secondary confirmation before any new enumeration.';
  } else if (verifiedHigh) {
    verdict = 'escalate';
    nextPlan = 'Push the verified high/critical impact toward validated access or verified data.';
  } else if (verifiedIssue && !hasFoothold) {
    verdict = 'escalate';
    nextPlan = 'A vulnerability is recorded and there is no validated access. Raise that issue toward command execution or a foothold. Do not refute coverage in bulk. A higher-harm result on the same interface is a new finding.';
  } else if (noProgress >= Math.max(1, Number(config?.loopNoProgressRounds) || 2)) {
    verdict = 'pivot';
    nextPlan = 'Change tactic family or target; the current path has not produced quality progress.';
  } else if (candidates.length === 0) {
    verdict = noProgress >= stall ? 'stop' : 'pivot';
    nextPlan = candidates.length === 0
      ? 'No allowed frontier action remains; if the budget/stall threshold is met, finish the loop.'
      : 'Continue the current intent.';
  }
  return {
    verdict,
    diagnosis: surfaceThin
      ? 'The application surface is still only the entry page.'
      : hasHighCandidate
      ? 'Unverified high/critical candidate is present; verification gate is authoritative.'
      : verifiedHigh
        ? 'Verified high/critical impact has not yet been converted to access/data.'
        : verifiedIssue && !hasFoothold
          ? 'A verified vulnerability has not been raised to a validated foothold.'
          : noProgress >= (Number(config?.loopNoProgressRounds) || 2)
          ? 'No quality progress in recent rounds.'
          : 'Current path is still actionable.',
    nextPlan,
    mustIntents: must.slice(0, 6),
    preferTactics: candidates.map((entry) => entry.action.actionType).slice(0, 6),
    banRepeats: [],
    stopRecommended: verdict === 'stop',
    stopReason: verdict === 'stop' ? (objectiveAchieved(state, loop) ? 'objective-achieved' : 'no-progress') : null,
    confidence: 0.6,
    source: 'deterministic',
  };
}

function outputText(result) {
  if (Array.isArray(result?.output)) {
    return result.output
      .filter((block) => block?.type === 'text' && typeof block.text === 'string')
      .map((block) => block.text)
      .join('\n')
      .trim();
  }
  if (typeof result?.text === 'string') return result.text;
  if (result?.structured !== undefined) return JSON.stringify(result.structured);
  return '';
}

function combinedSignal(signal, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('supervisor timeout')), Math.max(1000, timeoutMs));
  const onAbort = () => controller.abort(signal.reason);
  if (signal !== undefined && signal !== null) {
    if (signal.aborted) controller.abort(signal.reason);
    else signal.addEventListener('abort', onAbort, { once: true });
  }
  return {
    signal: controller.signal,
    dispose() {
      clearTimeout(timer);
      if (signal !== undefined && signal !== null) signal.removeEventListener('abort', onAbort);
    },
  };
}

function serviceGet(ctx, name) {
  try { return ctx.get(name); } catch { return undefined; }
}

function messageText(message) {
  const content = message?.content;
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .filter((block) => block?.type === 'text' && typeof block.text === 'string')
    .map((block) => block.text)
    .join('\n');
}

function assistantAfter(messages, messageId) {
  if (!Array.isArray(messages)) return '';
  const index = messages.findIndex((message) => message?.id === messageId);
  if (index < 0) return '';
  const after = messages.slice(index + 1);
  const last = after[after.length - 1];
  if (last?.role !== 'assistant') return '';
  return messageText(last).trim();
}

function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason instanceof Error ? signal.reason : new Error('aborted'));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal.reason instanceof Error ? signal.reason : new Error('aborted'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function replyText(messages, messageId, beforeIds) {
  const direct = assistantAfter(messages, messageId);
  if (direct.length > 0 && direct !== 'READY') return direct;
  const fresh = messages.filter((message) => message?.id === undefined || !beforeIds.has(message.id));
  const last = fresh[fresh.length - 1];
  if (last?.role !== 'assistant') return '';
  const text = messageText(last).trim();
  return text === 'READY' ? '' : text;
}

/** Read the teammate reply that follows the Lead's Team message. */
async function readNativeReply({ ctx, native, messageId, beforeIds, signal }) {
  const agents = serviceGet(ctx, 'agents');
  let stable = '';
  let ticks = 0;
  while (!signal?.aborted) {
    const child = agents?.get?.(native.id);
    const messages = child?.session?.deriveMessages?.() ?? [];
    const text = replyText(messages, messageId, beforeIds);
    if (text.length > 0 && parseJsonObject(text) !== null) return text;
    if (text.length > 0 && text === stable) {
      ticks += 1;
      if (ticks >= 2) return text;
    } else {
      stable = text;
      ticks = 0;
    }
    await delay(250, signal);
  }
  throw signal?.reason instanceof Error ? signal.reason : new Error(`${native.name} timed out`);
}

/**
 * Wake the durable teammate and wait for its reply.
 * Returns null when Agent Teams cannot address that member, so the caller
 * can fall back to a fresh child.
 */
async function deliverToNative({ ctx, agent, native, brief, signal }) {
  if (!native?.id || !native?.name) return null;
  const teams = serviceGet(ctx, 'agentTeams');
  const agents = serviceGet(ctx, 'agents');
  if (typeof teams?.sendMessage !== 'function' || typeof agents?.get !== 'function') return null;
  const before = agents.get(native.id)?.session?.deriveMessages?.() ?? [];
  const beforeIds = new Set(before.map((message) => message?.id).filter(Boolean));
  let task = null;
  try {
    if (typeof teams.createTask === 'function') {
      const view = await teams.createTask(agent, {
        subject: `[AtkBrain] ${native.teamType ?? native.name}`,
        description: String(brief ?? '').slice(0, 4000),
      });
      if (view?.id !== undefined) {
        task = { id: view.id, revision: view.revision };
        if (typeof teams.updateTask === 'function') {
          const updated = await teams.updateTask(agent, {
            taskId: view.id,
            expectedRevision: view.revision,
            action: 'reassign',
            owner: native.name,
          });
          if (updated?.revision !== undefined) task.revision = updated.revision;
        }
      }
    }
  } catch { /* the Team message is the wake-up; the task board is advisory */ }
  const sent = await teams.sendMessage(agent, {
    target: native.name,
    content: [{ type: 'text', text: String(brief ?? '') }],
    signal,
  });
  const text = await readNativeReply({ ctx, native, messageId: sent?.messageId, beforeIds, signal });
  if (task !== null && typeof teams.updateTask === 'function') {
    try {
      const current = typeof teams.getTask === 'function' ? teams.getTask(agent, task.id) : null;
      if (current === null || current === undefined || current.status === 'in_progress') {
        await teams.updateTask(agent, {
          taskId: task.id,
          expectedRevision: current?.revision ?? task.revision,
          action: 'complete',
        });
      }
    } catch { /* the reply is already in hand */ }
  }
  return { text, childId: native.id, error: null, via: 'native-team' };
}

/**
 * Prefer the already-spawned native teammate. A missing roster falls back to
 * one fresh child. Never throws; the activation is left for the caller to release.
 */
async function acquireRoleText({ ctx, agent, brief, signal, label, native }) {
  if (native?.id && native?.name) {
    try {
      const delivered = await deliverToNative({ ctx, agent, native, brief, signal });
      if (delivered !== null) return { ...delivered, activation: null, stopReason: undefined };
    } catch { /* fresh child still completes the role */ }
  }
  const subagents = serviceGet(ctx, 'subagents');
  if (subagents === undefined || subagents === null) {
    return { text: '', childId: undefined, error: 'subagent service is not mounted', activation: null, via: undefined };
  }
  let activation;
  try {
    activation = await subagents.startActivation({
      provider: 'spawn',
      label,
      delivery: 'caller',
      request: {
        prompt: [{ type: 'text', text: brief }],
        parent: agent,
      },
      signal,
    });
    const result = await activation.result;
    return {
      text: outputText(result),
      childId: activation.childId,
      error: null,
      stopReason: result?.stopReason,
      activation,
      via: 'subagent',
    };
  } catch (error) {
    return {
      text: '',
      childId: activation?.childId,
      error: error instanceof Error ? error.message : String(error),
      activation,
      via: 'subagent',
    };
  }
}

/** Run the role teammate, or one fresh child when no native member exists. Never throws. */
export async function runSubagentText({ ctx, agent, brief, signal, timeoutMs = 90000, label = 'AtkBrain subagent', native }) {
  const combined = combinedSignal(signal, timeoutMs);
  try {
    const acquired = await acquireRoleText({ ctx, agent, brief, signal: combined.signal, label, native });
    if (acquired.error) {
      try { await acquired.activation?.dispose?.(); } catch { /* already settled */ }
    }
    return {
      text: acquired.text,
      childId: acquired.childId,
      error: acquired.error,
      stopReason: acquired.stopReason,
      via: acquired.via,
    };
  } finally {
    combined.dispose();
  }
}

/** Ask the supervision teammate, or one fresh reviewer, for a JSON plan. Never throws. */
export async function reviewWithSubagent({ ctx, agent, brief, signal, timeoutMs = 90000, native }) {
  const combined = combinedSignal(signal, timeoutMs);
  try {
    const acquired = await acquireRoleText({
      ctx, agent, brief, signal: combined.signal, label: 'AtkBrain supervisor', native,
    });
    if (acquired.error === 'subagent service is not mounted') {
      return { plan: null, childId: undefined, promptHash: null, error: acquired.error };
    }
    const promptHash = String(brief ?? '').length > 0 ? shortHash(brief, 16) : null;
    if (acquired.error && acquired.text.length === 0) {
      try { await acquired.activation?.dispose?.(); } catch { /* already settled */ }
      return { plan: null, childId: acquired.childId, promptHash, error: acquired.error, via: acquired.via };
    }
    const plan = parseSupervisorOutput(acquired.text);
    if (plan === null) {
      try { await acquired.activation?.dispose?.(); } catch { /* already settled */ }
      return { plan: null, childId: acquired.childId, promptHash, error: 'supervisor returned no parseable JSON plan', via: acquired.via };
    }
    return { plan, childId: acquired.childId, promptHash, error: null, stopReason: acquired.stopReason, via: acquired.via };
  } finally {
    combined.dispose();
  }
}

function asDetailText(value, max) {
  if (Array.isArray(value)) return clip(value.filter((item) => typeof item === 'string' || typeof item === 'number').join('\n'), max);
  return clip(value, max);
}

/**
 * Normalize the verifier's technical writing fields. The verification & rating
 * team is the authoritative author of the finding detail; the primary executor
 * must not leave the generic template text in place.
 */
export function normalizeVerificationDetails(value) {
  const source = value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const detail = (keys, max) => {
    for (const key of keys) {
      const text = asDetailText(source[key], max).trim();
      if (text.length > 0) return text;
    }
    return '';
  };
  return {
    description: detail(['description', 'description_zh', 'finding_description', 'summary'], 4000),
    impact: detail(['impact', 'impact_zh', 'risk', 'consequence'], 4000),
    remediation: detail(['remediation', 'remediation_zh', 'fix', 'recommendation'], 3000),
    repro: detail(['repro', 'reproduction', 'repro_steps', 'poc'], 4000),
    request: detail(['request', 'http_request', 'request_packet'], 8000),
    response: detail(['response', 'http_response', 'response_packet'], 8000),
    cvssRationale: detail(['cvss_rationale', 'rating_rationale', 'scoring_rationale'], 2000),
  };
}

/** Ask the verification teammate, or one fresh verifier, for a normalized verdict. */
export async function verifyWithSubagent({
  ctx,
  agent,
  brief,
  signal,
  timeoutMs = 120000,
  native,
  detachParentSignal = false,
}) {
  const combined = combinedSignal(detachParentSignal ? undefined : signal, timeoutMs);
  try {
    const acquired = await acquireRoleText({
      ctx, agent, brief, signal: combined.signal, label: 'AtkBrain verifier', native,
    });
    if (acquired.error === 'subagent service is not mounted') {
      return {
        verdict: 'inconclusive',
        rationale: 'subagent service is not mounted; evidence-only audit required',
        childId: undefined,
        error: acquired.error,
      };
    }
    if (acquired.error && acquired.text.length === 0) {
      try { await acquired.activation?.dispose?.(); } catch { /* ignore */ }
      return {
        verdict: 'inconclusive',
        rationale: acquired.error,
        evidencePaths: [],
        childId: acquired.childId,
        error: acquired.error,
        via: acquired.via,
      };
    }
    const parsed = parseJsonObject(acquired.text);
    if (parsed === null) {
      return { verdict: 'inconclusive', rationale: 'verifier returned no parseable JSON', childId: acquired.childId, error: 'parse', via: acquired.via };
    }
    const verdict = String(parsed.verdict ?? 'inconclusive').toLowerCase();
    return {
      verdict: ['verified', 'refuted', 'inconclusive'].includes(verdict) ? verdict : 'inconclusive',
      rationale: clip(parsed.rationale ?? parsed.reason, 2000),
      evidencePaths: Array.isArray(parsed.evidence_paths) ? parsed.evidence_paths.slice(0, 10) : [],
      observedMarker: parsed.observed_marker ? clip(parsed.observed_marker, 500) : null,
      cvss: parsed.cvss && typeof parsed.cvss === 'object' && !Array.isArray(parsed.cvss) ? parsed.cvss : null,
      cvssVector: typeof parsed.cvss_vector === 'string'
        ? clip(parsed.cvss_vector, 200)
        : (typeof parsed.cvssVector === 'string'
          ? clip(parsed.cvssVector, 200)
          : (typeof parsed.vector === 'string' ? clip(parsed.vector, 200) : null)),
      details: normalizeVerificationDetails(parsed),
      childId: acquired.childId,
      error: null,
      via: acquired.via,
    };
  } finally {
    combined.dispose();
  }
}

function evidenceGuidance() {
  return 'Judge only the evidence in this brief. External skills, dictionaries and scanners are not available.';
}

/** Build the verifier prompt for one finding. */
export function buildVerifierBrief({ state, finding, mode = 'evidence', scopeEntries = [] }) {
  const attrs = finding.attrs ?? {};
  const evidence = (finding.evidenceIds ?? []).map((id) => state.nodes?.[id])
    .filter(Boolean)
    .map((node) => ({ id: node.id, path: node.attrs?.relative ?? node.attrs?.path ?? null, sha256: node.attrs?.sha256 ?? null }));
  return `# AtkBrain finding verification

You are an independent verifier. Do not widen scope. Do not perform destructive actions, writes, credential stuffing or persistence. ${
    mode === 'network'
      ? 'You may use the AtkBrain tools only against the exact allow list below, read-only and rate-limited.'
      : 'Do not use network tools; audit the supplied evidence paths and hashes only.'
  }

## Finding
title: ${clip(attrs.title ?? finding.label, 300)}
severity: ${attrs.severity ?? 'unknown'}
status: ${finding.status}
verification: ${finding.verification ?? 'unverified'}
template: ${attrs.template ?? 'manual'}
subject: ${attrs.subjectKey ?? finding.key}
template description: ${attrs.description ? clip(attrs.description, 2500) : '—'}
template impact: ${attrs.impact ? clip(attrs.impact, 2500) : '—'}
template remediation: ${attrs.remediation ? clip(attrs.remediation, 1800) : '—'}
evidence: ${attrs.evidence ? clip(attrs.evidence, 3000) : '—'}
repro: ${attrs.repro ? clip(attrs.repro, 2500) : '—'}
request: ${(attrs.request ?? attrs.httpRequest ?? attrs.pocCurl) ? clip(attrs.request ?? attrs.httpRequest ?? attrs.pocCurl, 5000) : '—'}
response: ${(attrs.response ?? attrs.httpResponse) ? clip(attrs.response ?? attrs.httpResponse, 5000) : '—'}

## Evidence artifacts
${evidence.map((item) => `- ${item.path} sha256=${item.sha256}`).join('\n') || '- none recorded'}

## Constraints
${evidenceGuidance()}

## Exact scope allow list
${scopeEntries.length > 0 ? JSON.stringify(scopeEntries) : '（none; evidence-only mode）'}

## Task
Independently decide whether the claimed impact is reproducible/authentic. If network mode is allowed, perform the minimum read-only re-check that demonstrates the same marker and record what you observed. If evidence-only, verify the artifact exists, hashes match, and the proof is not merely the same error replay.

You are also the technical writer of the finding detail. Replace generic template text with
evidence-grounded Chinese prose. Name the exact endpoint/parameter, what was observed, and the
concrete security consequence. Do not copy the existing generic text, do not write a bare template,
and do not claim impact that the evidence does not show. Keep requests/responses redacted; never
repeat raw secrets, passwords, tokens or PII.

Reply with ONLY this JSON:
{"verdict":"verified|refuted|inconclusive","rationale":"at least 40 chars, explain what you independently observed","description":"中文，2-4 句，具体说明接口/参数/观测点和根因；不要模板套话","impact":"中文，具体说明可利用后果与边界；Medium 也要说明真实影响","remediation":"中文，给出针对该接口/参数的修复措施","repro":"中文，基于证据的可复现步骤","request":"原始请求包（可保留占位符，禁止原始 secret）","response":"关键响应片段","evidence_paths":[],"observed_marker":null,
 "cvss":{"AV":"N|A|L|P","AC":"L|H","PR":"N|L|H","UI":"N|R","S":"U|C","C":"H|L|N","I":"H|L|N","A":"H|L|N"} or null}

Score CVSS only from evidence that is concrete enough to set every Base metric. Do not infer
CVSS metrics from the words critical/high, the template name, or the red-team rating. If the
evidence is insufficient, return "cvss": null.
`;
}

/** Build the prompt used by the verification team's detail writer. */
export function buildDetailBrief({ state, finding }) {
  const attrs = finding.attrs ?? {};
  const evidence = (finding.evidenceIds ?? []).map((id) => state.nodes?.[id])
    .filter(Boolean)
    .map((node) => ({ path: node.attrs?.relative ?? node.attrs?.path ?? null, sha256: node.attrs?.sha256 ?? null }));
  return `# AtkBrain finding detail authoring

You are the technical writer of the verification & rating team. Read the evidence and write a
detailed, evidence-grounded finding detail in Chinese. This is a detail-authoring task, not a
verification verdict: do not change the finding's verification status and do not invent impact.

## Finding
title: ${clip(attrs.title ?? finding.label, 300)}
template: ${attrs.template ?? 'manual'}
severity: ${attrs.severity ?? 'unknown'}
status: ${finding.status}
subject: ${attrs.subjectKey ?? finding.key}
asset: ${attrs.asset ?? attrs.host ?? '—'}
existing description: ${attrs.description ? clip(attrs.description, 2500) : '—'}
existing impact: ${attrs.impact ? clip(attrs.impact, 2500) : '—'}
existing remediation: ${attrs.remediation ? clip(attrs.remediation, 1800) : '—'}
existing repro: ${attrs.repro ? clip(attrs.repro, 2500) : '—'}
request: ${(attrs.request ?? attrs.httpRequest ?? attrs.pocCurl) ? clip(attrs.request ?? attrs.httpRequest ?? attrs.pocCurl, 6000) : '—'}
response: ${(attrs.response ?? attrs.httpResponse) ? clip(attrs.response ?? attrs.httpResponse, 6000) : '—'}

## Evidence artifacts
${evidence.map((item) => `- ${item.path} sha256=${item.sha256}`).join('\n') || '- none recorded'}

## Constraints
${evidenceGuidance()}

## Task
Write a detailed Chinese finding detail from these facts and artifacts. It must be specific enough
for an operator to understand and reproduce the issue without reading the JSON graph:

- name the exact endpoint/path, parameter, payload/marker and observed response;
- explain the root cause, preconditions and what an attacker could actually do;
- state the real impact boundary; do not claim account takeover, RCE or bulk data unless evidenced;
- give concrete, parameter-specific remediation;
- give step-by-step reproduction commands using placeholders where needed;
- preserve the recorded request/response; never insert raw passwords, tokens or PII.

Reply with ONLY this JSON:
{"description":"中文，4-8 句，包含接口/参数/载荷/观测点/根因","impact":"中文，具体后果与边界","remediation":"中文，具体到参数/组件/配置","repro":"中文，分步骤复现","request":"完整请求包（脱敏）","response":"关键响应片段","evidence_note":"哪些证据文件支持结论","confidence":0.0}

Every description, impact and repro value MUST be Chinese prose. If the source record is English,
translate it into Chinese instead of copying the English sentences. Do not copy generic template
phrasing. If evidence is insufficient, say exactly what is missing instead of fabricating details.
`;
}

/** Ask the verification teammate, or one fresh writer, for the finding detail. */
export async function detailWithSubagent({ ctx, agent, brief, signal, timeoutMs = 120000, native }) {
  const combined = combinedSignal(signal, timeoutMs);
  try {
    const acquired = await acquireRoleText({
      ctx, agent, brief, signal: combined.signal, label: 'AtkBrain detail writer', native,
    });
    if (acquired.error && acquired.text.length === 0) {
      try { await acquired.activation?.dispose?.(); } catch { /* ignore */ }
      return { details: null, childId: acquired.childId, error: acquired.error ?? 'subagent service is not mounted', via: acquired.via };
    }
    const parsed = parseJsonObject(acquired.text);
    if (parsed === null) {
      return { details: null, childId: acquired.childId, error: 'detail writer returned no parseable JSON', via: acquired.via };
    }
    const details = normalizeVerificationDetails(parsed);
    details.confidence = Number.isFinite(Number(parsed.confidence)) ? Math.max(0, Math.min(1, Number(parsed.confidence))) : null;
    details.evidenceNote = clip(parsed.evidence_note ?? parsed.evidenceNote, 2000);
    return { details, childId: acquired.childId, error: null, via: acquired.via };
  } finally {
    combined.dispose();
  }
}

export { candidateIntents, refineSupervisionPlan };
