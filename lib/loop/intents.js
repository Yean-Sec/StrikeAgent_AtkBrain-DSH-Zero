/**
 * Intent lifecycle for the autonomous loop.
 *
 * An intent is one hypothesis-bound next action with an expected evidence
 * contract. It is deliberately separate from `task`: the loop claims an
 * intent, executes it, then resolves it as verified/refuted/blocked/stalled.
 */
import { OBSERVATION_CHANNELS } from '../constants.js';
import { intentNodeOp } from '../tools/build.js';

const OPEN = new Set(['open', 'claimed']);
const TERMINAL = new Set(['verified', 'refuted', 'blocked']);

function clip(value, length) {
  const text = String(value ?? '').trim();
  return text.length > length ? text.slice(0, length) : text;
}

function sanitizeObservations(observations) {
  return (Array.isArray(observations) ? observations : []).slice(0, 10).map((entry) => ({
    channel: OBSERVATION_CHANNELS.includes(entry?.channel) ? entry.channel : 'status',
    result: clip(entry?.result, 500),
    at: typeof entry?.at === 'string' ? entry.at : new Date().toISOString(),
  }));
}

export function intentChannelCount(observations) {
  return new Set((Array.isArray(observations) ? observations : [])
    .map((entry) => String(entry?.channel ?? '')).filter(Boolean)).size;
}

export function openIntents(state) {
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'intent' && OPEN.has(node.status))
    .sort((a, b) => (Number(b.attrs?.priority) || 0) - (Number(a.attrs?.priority) || 0)
      || (Number(a.attrs?.round) || 0) - (Number(b.attrs?.round) || 0));
}

export function claimedIntents(state) {
  return openIntents(state).filter((node) => node.status === 'claimed');
}

function existingActionIntent(state, actionId, round) {
  return Object.values(state.nodes ?? {}).find((node) => node.kind === 'intent'
    && node.attrs?.actionId === actionId
    && (Number(node.attrs?.round) || 0) === round
    && !['refuted', 'blocked'].includes(node.status));
}

/** Convert one frontier/policy action into the intent builder input. */
export function intentInputForAction(action, { round, source = 'frontier', supervisorKey = null, status = 'open' }) {
  const expected = action.expectedEvidence ?? null;
  return {
    actionType: action.actionType,
    actionId: action.actionId,
    targetId: action.targetId,
    targetKind: action.targetKind,
    targetLabel: action.targetLabel,
    priority: Number(action.priority) || 0,
    why: Array.isArray(action.why) ? action.why : [],
    hypothesis: `${action.actionType} on ${action.targetLabel ?? action.targetId ?? 'target'}`,
    strategyKey: action.strategyKey ?? null,
    expectedEvidence: expected,
    scopeVerdict: action.scope?.verdict ?? 'unknown',
    round,
    status,
    supervisorKey,
    source,
  };
}

/** Create and/or claim intents for this round. */
export function planIntentOps(state, actions, { round, maxActions = 3, supervisorKey = null } = {}) {
  const ops = [];
  const created = [];
  const claimed = [];
  const limit = Math.max(1, Math.min(5, Number(maxActions) || 3));
  for (const action of (Array.isArray(actions) ? actions : []).slice(0, limit)) {
    const existing = existingActionIntent(state, action.actionId, round);
    if (existing !== undefined) {
      if (existing.status === 'open') {
        ops.push({
          op: 'node.upsert',
          kind: 'intent',
          key: existing.key,
          label: existing.label,
          attrs: {
            ...existing.attrs,
            attempts: (Number(existing.attrs?.attempts) || 0) + 1,
            claimedAt: new Date().toISOString(),
            supervisorKey: supervisorKey ?? existing.attrs?.supervisorKey ?? null,
          },
          status: 'claimed',
          confidence: existing.confidence,
        });
        claimed.push({ id: existing.id, actionId: action.actionId });
      } else {
        claimed.push({ id: existing.id, actionId: action.actionId });
      }
      continue;
    }
    const input = intentInputForAction(action, { round, supervisorKey, status: 'claimed' });
    const op = intentNodeOp(state, input);
    op.attrs.attempts = 1;
    op.attrs.claimedAt = new Date().toISOString();
    ops.push(op);
    created.push({ key: op.key, actionId: action.actionId });
    claimed.push({ key: op.key, actionId: action.actionId });
  }
  return { ops, created, claimed };
}

export function updateIntentOp(intent, patch, status) {
  return {
    op: 'node.upsert',
    kind: 'intent',
    key: intent.key,
    label: patch.label ?? intent.label,
    attrs: {
      ...intent.attrs,
      ...patch,
      observations: sanitizeObservations(patch.observations ?? intent.attrs?.observations ?? []),
      channelCount: intentChannelCount(patch.observations ?? intent.attrs?.observations ?? []),
    },
    status: status ?? intent.status,
    confidence: patch.confidence ?? intent.confidence,
    ...(Array.isArray(patch.evidenceIds) ? { evidenceIds: patch.evidenceIds.slice(0, 20) } : {}),
  };
}

/** Resolve one claimed intent from an explicit tool call. */
export function resolveIntentOp(state, intentId, outcome, { evidenceIds, observations, result, force } = {}) {
  const intent = Object.values(state.nodes ?? {}).find((node) => node.kind === 'intent'
    && (node.id === intentId || node.key === intentId));
  if (intent === undefined) return { error: `intent not found: ${intentId}` };
  if (TERMINAL.has(intent.status)) return { error: `intent ${intent.id} is already ${intent.status}` };
  const cleanObservations = sanitizeObservations(observations ?? intent.attrs?.observations ?? []);
  const attempts = (Number(intent.attrs?.attempts) || 0) + 1;
  const channelCount = intentChannelCount(cleanObservations);
  if (outcome === 'refuted' && channelCount < 2 && force !== true) {
    return {
      error: 'single-channel failure is not a closed attack surface; record at least two distinct observation channels or pass force=true',
      intent,
    };
  }
  const op = updateIntentOp(intent, {
    attempts,
    observations: cleanObservations,
    channelCount,
    resolvedAt: new Date().toISOString(),
    result: clip(result, 1000),
    evidenceIds: Array.isArray(evidenceIds) ? evidenceIds.slice(0, 20) : (Array.isArray(intent.evidenceIds) ? intent.evidenceIds : []),
  }, outcome);
  return { op, intent };
}

function findTarget(state, intent) {
  const targetId = intent.attrs?.targetId;
  const targetKey = intent.attrs?.targetLabel;
  return Object.values(state.nodes ?? {}).find((node) => node.id === targetId || node.key === targetKey);
}

function targetFinding(state, intent) {
  const node = findTarget(state, intent);
  if (node?.kind === 'finding') return node;
  return Object.values(state.nodes ?? {}).find((candidate) => candidate.kind === 'finding'
    && (candidate.id === intent.attrs?.targetId || candidate.key === intent.attrs?.targetId));
}

/** Whether a target changed after the intent was claimed. */
function changedAfterClaim(target, intent) {
  const claimedAt = String(intent.attrs?.claimedAt ?? '');
  if (claimedAt.length === 0) return true;
  const lastSeen = String(target?.lastSeen ?? '');
  const firstSeen = String(target?.firstSeen ?? '');
  return (lastSeen.length > 0 && lastSeen >= claimedAt) || (firstSeen.length > 0 && firstSeen >= claimedAt);
}

/** Infer resolution from graph evidence created during the round. */
export function autoResolveIntent(state, intent) {
  const actionType = String(intent.attrs?.actionType ?? '');
  if (actionType === 'verify_finding') {
    const finding = targetFinding(state, intent);
    if (finding !== undefined && ['verified', 'exploited', 'impacted'].includes(finding.status)
      && (Array.isArray(finding.evidenceIds) ? finding.evidenceIds.length : 0) > 0
      && changedAfterClaim(finding, intent)) {
      return 'verified';
    }
    return null;
  }
  if (actionType === 'validate_access') {
    const target = findTarget(state, intent);
    if (target?.kind === 'access' && target.status === 'validated' && changedAfterClaim(target, intent)) {
      return 'verified';
    }
    return null;
  }
  if (actionType === 'escalate_privilege') {
    const target = findTarget(state, intent);
    if (target?.kind === 'access' && target.status === 'escalated' && changedAfterClaim(target, intent)) {
      return 'verified';
    }
    return null;
  }
  if (actionType === 'collect_data_evidence') {
    const target = findTarget(state, intent);
    if (target?.kind === 'data' && target.status === 'verified' && changedAfterClaim(target, intent)) return 'verified';
    return null;
  }
  if (actionType === 'test_coverage') {
    const target = findTarget(state, intent);
    if (target?.kind !== 'coverage' || !changedAfterClaim(target, intent)) return null;
    if (target.status === 'seen' || target.status === 'reported') return 'verified';
    if (target.status === 'refuted') return 'refuted';
    return null;
  }
  if (actionType === 'test_hypothesis') {
    const target = findTarget(state, intent);
    if (target?.kind !== 'hypothesis' || !changedAfterClaim(target, intent)) return null;
    if (target.status === 'verified') return 'verified';
    if (target.status === 'disproved') return 'refuted';
    if (target.status === 'blocked') return 'blocked';
    return null;
  }
  if (actionType === 'merge_team') {
    const target = findTarget(state, intent);
    if (target?.kind === 'task' && ['completed', 'merged'].includes(target.status) && changedAfterClaim(target, intent)) return 'verified';
    return null;
  }
  if (actionType === 'enumerate_services') {
    const target = findTarget(state, intent);
    if (target === undefined) return null;
    const hasService = Object.values(state.edges ?? {}).some((edge) => edge.from === target.id && edge.kind === 'exposes');
    return hasService && changedAfterClaim(target, intent) ? 'verified' : null;
  }
  return null;
}

/** Resolve all claimed intents that graph evidence now proves were completed. */
export function autoResolveOps(state) {
  const ops = [];
  const resolved = [];
  for (const intent of claimedIntents(state)) {
    const outcome = autoResolveIntent(state, intent);
    if (outcome === null) continue;
    const op = updateIntentOp(intent, {
      resolvedAt: new Date().toISOString(),
      result: 'auto-resolved from graph evidence',
    }, outcome);
    ops.push(op);
    resolved.push({ id: intent.id, outcome });
  }
  return { ops, resolved };
}

/** Mark claimed intents that have gone too long without progress as stalled. */
export function stallStaleIntentOps(state, round, stallAfter = 3) {
  const ops = [];
  const stalled = [];
  for (const intent of claimedIntents(state)) {
    const claimedAt = Date.parse(String(intent.attrs?.claimedAt ?? ''));
    const age = Number.isFinite(claimedAt) ? (Date.now() - claimedAt) / 60_000 : 0;
    const attempts = Number(intent.attrs?.attempts) || 0;
    if (attempts >= stallAfter && age >= 10) {
      ops.push(updateIntentOp(intent, {
        resolvedAt: new Date().toISOString(),
        result: `stalled after ${attempts} attempt(s)`,
      }, 'stalled'));
      stalled.push(intent.id);
    }
  }
  return { ops, stalled };
}
