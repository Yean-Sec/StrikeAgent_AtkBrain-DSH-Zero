/**
 * One operator message starts three dialogues.
 *
 * The first dialogue is the operator's message. Two later dialogues are
 * admitted by the host goal driver after the lead goes idle. They continue
 * the same ledger. A goal prompt is not a new operator message, and the lead
 * must not ask the operator to type the next round.
 */
import { PROJECTION_KEY, STATE_SCHEMA } from './constants.js';
import { pendingEscalations } from './escalation-queue.js';
import { commitLeadLedger } from './ledger-host.js';
import { wakeEngagementTeams } from './native-teams.js';
import { pendingFindings } from './verify-queue.js';
import { supervisionNodeOp } from './tools/build.js';

const OLD_AUTO_MARK = '自动送入的下一轮';
export const FOLLOW_UP_MARK = '三轮对话的后续一轮';
export const FOLLOW_UP_ROUNDS = 2;
export const FOLLOW_UP_OBJECTIVE = '三轮对话的后续一轮。接着同一本账继续测还没关掉的类型，发现更多漏洞。不要停下来请操作员再发一条消息。';

export function operatorTurn(event) {
  if (event?.type !== 'user/message') return false;
  return event.data?.source?.kind === 'user';
}

/** An operator message or an automatic follow-up. Both can still owe the five teams work. */
export function dialogueTurn(event) {
  if (event?.type !== 'user/message') return false;
  const kind = event.data?.source?.kind;
  return kind === 'user' || kind === 'goal';
}

function leadAgent(ctx, session) {
  if (session?.header?.parentSession) return undefined;
  let agents;
  try {
    agents = (ctx.agents && typeof ctx.agents.get === 'function') ? ctx.agents : ctx.get('agents');
  } catch {
    return undefined;
  }
  const agent = agents?.get?.(session.id);
  if (agent?.session !== session) return undefined;
  return agent;
}

function goalsOf(ctx) {
  try {
    return ctx.get('goals');
  } catch {
    return undefined;
  }
}

function isOldAutoGoal(goal) {
  return typeof goal?.objective === 'string' && goal.objective.includes(OLD_AUTO_MARK);
}

export function isFollowUpGoal(goal) {
  return typeof goal?.objective === 'string' && goal.objective.includes(FOLLOW_UP_MARK);
}

/** Stop a previously armed automatic round so idle does not start the next one. */
export function stopAutomaticRounds(goals, agent) {
  if (goals === undefined || goals === null || typeof goals.get !== 'function' || agent === undefined) return { action: 'unavailable' };
  let current;
  try {
    current = goals.get(agent);
  } catch {
    return { action: 'unavailable' };
  }
  if (current === undefined || current === null || !isOldAutoGoal(current)) return { action: 'none' };
  if (current.phase === 'paused' || current.phase === 'complete') return { action: 'none' };
  if (current.phase === 'active' && typeof goals.pause === 'function') {
    try {
      goals.pause(agent, { id: current.id, revision: current.revision });
      return { action: 'pause' };
    } catch {
      /* a raced revision is left for the next message */
    }
  }
  if (typeof goals.disarm === 'function') {
    try {
      goals.disarm(agent);
      return { action: 'disarm' };
    } catch {
      return { action: 'none' };
    }
  }
  return { action: 'none' };
}

function goalRefOf(goal) {
  return { id: goal.id, revision: goal.revision };
}

/**
 * Arm two follow-up dialogues for this operator message.
 * An old fake-user objective is closed first. A foreign loop goal is left alone.
 */
export function ensureFollowUpDialogues(goals, agent) {
  void goals;
  void agent;
  return { action: 'disabled' };
  if (goals === undefined || goals === null || typeof goals.get !== 'function' || typeof goals.create !== 'function' || agent === undefined) {
    return { action: 'unavailable' };
  }
  let current;
  try {
    current = goals.get(agent);
  } catch {
    return { action: 'unavailable' };
  }
  if (current && !isFollowUpGoal(current) && !isOldAutoGoal(current) && current.phase !== 'complete') {
    return { action: 'foreign' };
  }
  if (current && isOldAutoGoal(current) && current.phase !== 'complete') {
    try {
      current = goals.complete(agent, goalRefOf(current));
    } catch {
      return { action: 'unavailable' };
    }
  }
  if (current && isFollowUpGoal(current) && current.phase !== 'complete') {
    const roundsLeft = Number(current.maxGoalRounds) - Number(current.roundsStarted || 0);
    const needsArm = current.phase === 'paused' || current.phase === 'blocked' || current.activation === 'disarmed';
    if (roundsLeft > 0 && needsArm && typeof goals.resume === 'function') {
      try {
        goals.resume(agent, goalRefOf(current));
        return { action: 'resume' };
      } catch {
        if (current.phase === 'active') return { action: 'keep' };
      }
    }
    if (roundsLeft > 0 && current.phase === 'active') return { action: 'keep' };
    if (typeof goals.complete === 'function') {
      try {
        current = goals.complete(agent, goalRefOf(current));
      } catch {
        return { action: 'unavailable' };
      }
    }
  }
  if (current && current.phase !== 'complete') return { action: 'foreign' };
  try {
    const view = goals.create(agent, { objective: FOLLOW_UP_OBJECTIVE, maxGoalRounds: FOLLOW_UP_ROUNDS });
    return { action: 'create', maxGoalRounds: view?.maxGoalRounds ?? FOLLOW_UP_ROUNDS };
  } catch {
    return { action: 'unavailable' };
  }
}

function eventSeq(event) {
  const seq = Number(event?.seq);
  if (Number.isFinite(seq) && seq > 0) return seq;
  return Date.now();
}

/** Remember this operator message on the lead graph. A later pass consumes it. */
async function recordOperatorTurn(ctx, session, event) {
  if (typeof ctx.sessionProjections?.stateOf !== 'function') return;
  let state;
  try {
    state = ctx.sessionProjections.stateOf(session, PROJECTION_KEY);
  } catch {
    return;
  }
  if (state === undefined || state === null) return;
  const seq = eventSeq(event);
  const turns = Object.values(state.nodes ?? {}).filter((node) => node.kind === 'supervision' && node.attrs?.type === 'operator_turn');
  if (turns.some((node) => Number(node.attrs?.eventSeq) === seq)) return;
  const op = supervisionNodeOp(state, {
    type: 'operator_turn',
    round: turns.length + 1,
    planHash: `operator-${seq}`,
    verdict: 'hold',
    diagnosis: 'operator message',
    source: 'operator',
    eventSeq: seq,
  });
  await commitLeadLedger(ctx, session, { schema: STATE_SCHEMA, at: new Date().toISOString(), ops: [op] });
}

/** A goal-driver dialogue opens the next pass. It is not another operator message. */
async function recordDialogueTurn(ctx, session, event) {
  if (event?.data?.source?.kind !== 'goal') return;
  if (typeof ctx.sessionProjections?.stateOf !== 'function') return;
  let state;
  try {
    state = ctx.sessionProjections.stateOf(session, PROJECTION_KEY);
  } catch {
    return;
  }
  if (state === undefined || state === null) return;
  const seq = eventSeq(event);
  const turns = Object.values(state.nodes ?? {}).filter((node) => node.kind === 'supervision' && node.attrs?.type === 'dialogue_turn');
  if (turns.some((node) => Number(node.attrs?.eventSeq) === seq)) return;
  const round = Number(event.data?.source?.round) || turns.length + 1;
  const op = supervisionNodeOp(state, {
    type: 'dialogue_turn',
    round,
    planHash: `dialogue-${seq}`,
    verdict: 'hold',
    diagnosis: 'follow-up dialogue',
    source: 'goal',
    eventSeq: seq,
  });
  await commitLeadLedger(ctx, session, { schema: STATE_SCHEMA, at: new Date().toISOString(), ops: [op] });
}

/** Wake residents that still have work. A new dialogue bypasses the cooldown. */
async function wakeDueResidents(ctx, agent, { force = false } = {}) {
  if (!agent?.session || typeof ctx.sessionProjections?.stateOf !== 'function') return;
  let state;
  try {
    state = ctx.sessionProjections.stateOf(agent.session, PROJECTION_KEY);
  } catch {
    return;
  }
  if (state?.engagement === undefined || state?.engagement === null) return;
  let agentTeams;
  try {
    agentTeams = ctx.get('agentTeams');
  } catch {
    return;
  }
  const pending = pendingFindings(Object.values(state?.nodes ?? {}));
  await wakeEngagementTeams({
    agentTeams,
    agent,
    signal: new AbortController().signal,
    state,
    pending,
    escalationPending: pendingEscalations(state),
    forceVerifier: force && pending.length > 0,
    forceEscalation: force,
    resume: force,
  });
}

/**
 * The operator message is dialogue one and arms two follow-ups.
 * A goal-driver prompt is dialogue two or three on the same ledger.
 */
export async function applyThreeRounds(ctx, session, event) {
  void ctx;
  void session;
  void event;
  return { action: 'disabled' };
  const dialogue = dialogueTurn(event);
  const operator = operatorTurn(event);
  if (!dialogue && !operator) return { action: 'ignore' };
  const agent = leadAgent(ctx, session);
  if (dialogue && agent !== undefined) await wakeDueResidents(ctx, agent, { force: true });
  if (!operator) {
    try {
      await recordDialogueTurn(ctx, session, event);
    } catch (error) {
      ctx.logger?.warn?.(`atk-brain: follow-up dialogue was not recorded: ${error instanceof Error ? error.message : String(error)}`);
    }
    return { action: 'dialogue' };
  }
  const followUp = ensureFollowUpDialogues(goalsOf(ctx), agent);
  try {
    await recordOperatorTurn(ctx, session, event);
  } catch (error) {
    ctx.logger?.warn?.(`atk-brain: operator turn was not recorded: ${error instanceof Error ? error.message : String(error)}`);
  }
  return { action: 'operator', followUp: followUp.action };
}

/** Idle only stops a leftover fake-user goal. The two follow-up dialogues stay armed. */
export async function continueIdleLead(ctx, agent) {
  if (agent?.session?.header?.parentSession) return { action: 'ignore' };
  const stopped = stopAutomaticRounds(goalsOf(ctx), agent);
  return stopped;
}

/** This edition does not arm follow-up dialogues. */
export function installThreeRounds(ctx) {
  void ctx;
  return;
  if (typeof ctx?.on !== 'function') return;
  ctx.on('session/event', (session, event) => {
    void applyThreeRounds(ctx, session, event).catch((error) => {
      ctx.logger?.warn?.(`atk-brain: operator round failed: ${error instanceof Error ? error.message : String(error)}`);
    });
  });
  ctx.on('agent/status', ({ agent, status } = {}) => {
    if (status !== 'idle' || !agent?.session) return;
    void continueIdleLead(ctx, agent).catch((error) => {
      ctx.logger?.warn?.(`atk-brain: automatic round pause failed: ${error instanceof Error ? error.message : String(error)}`);
    });
  });
}
