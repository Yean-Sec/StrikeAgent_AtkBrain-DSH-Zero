/**
 * `atkbrain_loop` — autonomous engagement loop over DSH goals.
 *
 * The tool creates/arms one DSH goal and lets goal-round-driver continue the
 * session. Each goal round calls `action=step`, which folds graph progress,
 * asks the supervisor when due, retrieves evolution lessons, creates/claims
 * intents, and returns one bounded brief. It never performs network I/O itself.
 */
import {
  OBJECTIVE_TYPES,
  SUPERVISOR_VERDICTS,
  TOOL_NAMES,
} from '../constants.js';
import { computeFrontier } from '../frontier.js';
import { resolveSkillDir } from '../loop/skills.js';
import {
  isPlainObject,
  invalid,
  nowIso,
  shortHash,
  stableStringify,
} from '../util.js';
import { link, loopNodeOp, supervisionNodeOp } from './build.js';
import { bootstrapSelfTeamOps } from '../self-teams.js';
import { projectCompletion } from '../project-completion.js';
import { passContinueMessage, passesComplete, testPassNodes } from '../test-passes.js';
import {
  assertArgs,
  audit,
  optionalInteger,
  optionalString,
  registerAtkTool,
  requireEnum,
} from './common.js';
import { buildRoundBrief, buildSupervisorBrief } from '../loop/brief.js';
import {
  completeGoal,
  goalArmed,
  goalSnapshot,
  pauseGoal,
  readGoal,
  resumeGoal,
} from '../loop/goal.js';
import {
  planIntentOps,
  autoResolveOps,
  resolveIntentOp,
  stallStaleIntentOps,
} from '../loop/intents.js';
import {
  candidateIntents,
  computeStop,
  objectiveAchieved,
  progressUpdate,
  refineSupervisionPlan,
  snapshotGraph,
} from '../loop/policy.js';
import { nativeTeammate } from '../self-teams.js';
import {
  deterministicPlan,
  reviewWithSubagent,
} from '../loop/supervisor.js';

const ACTIONS = ['start', 'step', 'status', 'pause', 'resume', 'finish', 'resolve'];
const OUTCOMES = ['verified', 'refuted', 'blocked', 'stalled'];
const FINISH_OUTCOMES = ['achieved', 'stalled', 'budget', 'operator', 'exhausted'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'start a goal-backed loop, run one step, inspect status, pause/resume, finish, or resolve an intent.' },
    objective: { type: 'string', description: 'Human-readable engagement objective (required for start).' },
    objectiveType: { type: 'string', enum: OBJECTIVE_TYPES, description: 'Completion test: impact (default), shell, admin, data or findings.' },
    maxRounds: { type: 'integer', description: 'Maximum AtkBrain rounds including the initial human round (1-200).' },
    maxActions: { type: 'integer', description: 'Maximum intents claimed per round (1-5).' },
    confirm: { type: 'boolean', description: 'Required true for start: the operator explicitly authorized autonomous execution.' },
    supervisorMode: { type: 'string', enum: ['auto', 'deterministic', 'ai'], description: 'Supervisor mode for this loop; defaults to config.' },
    intentId: { type: 'string', description: 'Intent id/key for action=resolve.' },
    outcome: { type: 'string', enum: [...new Set([...OUTCOMES, ...FINISH_OUTCOMES])], description: 'Intent resolution outcome, or finish reason.' },
    observations: {
      type: 'array',
      description: 'Evidence channels observed for a resolve (status/body/timing/header/side_effect).',
      items: { type: 'object', additionalProperties: true },
    },
    evidenceIds: { type: 'array', items: { type: 'string' }, description: 'Evidence node ids supporting a resolve.' },
    force: { type: 'boolean', description: 'Allow resolve=refuted with fewer than two observation channels (rare; document why).' },
    reason: { type: 'string', description: 'Operator-visible reason for pause/finish.' },
    includeBaseline: { type: 'boolean', description: 'Count pre-start access/data toward objective completion (default false).' },
  },
};

function requireLead(ctx, agent) {
  const teams = (() => { try { return ctx.get('agentTeams'); } catch { return undefined; } })();
  if (teams === undefined || teams === null) return;
  try {
    if (teams.membership(agent).role !== 'lead') invalid('atkbrain_loop requires the Team Lead; child agents must return to their Lead');
  } catch {
    /* no membership is acceptable for a standalone session */
  }
}

function currentLoop(state) {
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'loop')
    .sort((a, b) => String(b.lastSeen ?? '').localeCompare(String(a.lastSeen ?? '')))[0];
}

function loopWith(state, loop, patch, status) {
  const attrs = { ...(loop?.attrs ?? {}), ...patch };
  const op = loopNodeOp(state, attrs);
  return {
    ...op,
    ...(loop?.label ? { label: loop.label } : {}),
    status: status ?? attrs.phase ?? loop?.status ?? 'running',
  };
}

function engagementHash(state) {
  return shortHash(`${state.engagement?.name ?? 'engagement'}|${state.engagement?.authorization ?? ''}`, 16);
}

function latestSupervision(state) {
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'supervision'
      && node.attrs?.type !== 'finding_verification'
      && node.attrs?.type !== 'rating'
      && node.attrs?.type !== 'self_team_brief')
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0)
      || String(b.lastSeen ?? '').localeCompare(String(a.lastSeen ?? '')))[0];
}

async function loadLessons() {
  return { store: null, lessons: [], ops: [], applied: [], warnings: [] };
}

function summarizeLoop(loop, extra = '') {
  if (loop === undefined) return 'No autonomous loop exists yet. Start one after scope authorization.';
  const attrs = loop.attrs ?? {};
  return `Loop ${loop.status} round ${attrs.round ?? 0}/${attrs.maxRounds ?? 0}; goal ${attrs.goalPhase ?? 'none'} (${attrs.activation ?? 'disarmed'}); ring ${attrs.ring ?? 1}/3; no-progress ${attrs.noProgressRounds ?? 0}; stop ${attrs.stopReason ?? 'none'}.${extra ? ` ${extra}` : ''}`;
}

function goalFields(view) {
  const snapshot = goalSnapshot(view);
  return snapshot === null ? {} : {
    goalId: snapshot.id,
    goalRevision: snapshot.revision,
    goalPhase: snapshot.phase,
    activation: snapshot.activation,
  };
}

async function supervisorForRound({ ctx, agent, state, loop, latest, frontier, lessons, config, exec, mode }) {
  const deterministic = deterministicPlan({ state, loop, latest, frontier, config });
  const due = mode === 'ai' || (mode !== 'deterministic'
    && (!latest || (Number(loop.attrs?.noProgressRounds) || 0) >= 1
      || Number(loop.attrs?.round) - (Number(latest.attrs?.round) || 0) >= (Number(config.supervisorInterval) || 3)));
  if (!due) {
    const refined = refineSupervisionPlan(
      { ...(latest?.attrs ?? deterministic), source: latest?.attrs?.source ?? 'deterministic' },
      { state, loop, frontier, intents: [], config },
    );
    return { plan: refined, childId: undefined, promptHash: null, source: refined.source, reused: true, error: null };
  }
  const brief = buildSupervisorBrief({ state, loop, supervision: latest, lessons, intents: [], frontier, config });
  const result = await reviewWithSubagent({
    ctx,
    agent,
    brief,
    signal: exec.signal,
    timeoutMs: config.supervisorTimeoutMs,
    native: nativeTeammate(state, 'supervision'),
  });
  if (result.plan === null) {
    return {
      plan: deterministic,
      childId: result.childId,
      promptHash: result.promptHash,
      source: 'fallback',
      reused: false,
      error: result.error,
    };
  }
  const refined = refineSupervisionPlan(result.plan, { state, loop, frontier, intents: [], config });
  return {
    plan: refined,
    childId: result.childId,
    promptHash: result.promptHash,
    source: refined.source,
    reused: false,
    error: null,
  };
}

function selfTeamBootOps(state, cfg, workspace) {
  if (cfg.selfTeamMode === 'off') return [];
  const skillDir = resolveSkillDir(workspace, cfg);
  return bootstrapSelfTeamOps(state).map((op) => ({
    ...op,
    attrs: { ...(op.attrs ?? {}), ...(skillDir ? { skillDir } : {}) },
  }));
}

export function registerLoopTool(ctx, config, runtime) {
  registerAtkTool(ctx, config, runtime, {
    name: TOOL_NAMES.loop,
    callTitle: 'Autonomous pentest loop',
    description: 'Start and drive an authorized autonomous engagement loop backed by a DSH goal. start creates/arms a goal and returns the first round brief; step is called first in every goal round, folds progress, consults the supervisor, retrieves evolution lessons, and claims intents; resolve records intent outcomes; finish completes or pauses the goal. This tool performs no network I/O.',
    parameters: PARAMETERS,
    timeoutMs: 300000,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (args.objectiveType !== undefined) requireEnum(args, 'objectiveType', OBJECTIVE_TYPES);
      if (args.supervisorMode !== undefined) requireEnum(args, 'supervisorMode', ['auto', 'deterministic', 'ai']);
      if (args.maxRounds !== undefined) optionalInteger(args, 'maxRounds', { min: 1, max: 200 });
      if (args.maxActions !== undefined) optionalInteger(args, 'maxActions', { min: 1, max: 5 });
      if (args.confirm !== undefined && typeof args.confirm !== 'boolean') invalid('confirm must be a boolean');
      if (args.includeBaseline !== undefined && typeof args.includeBaseline !== 'boolean') invalid('includeBaseline must be a boolean');
      if (args.intentId !== undefined) optionalString(args, 'intentId', { max: 200 });
      if (args.reason !== undefined) optionalString(args, 'reason', { max: 1000 });
      if (args.outcome !== undefined) requireEnum(args, 'outcome', [...new Set([...OUTCOMES, ...FINISH_OUTCOMES])]);
      if (action === 'start') {
        if (args.confirm !== true) invalid('start requires confirm=true after the operator explicitly authorizes autonomous execution');
        if (typeof args.objective !== 'string' || args.objective.trim().length === 0) invalid('start requires a non-empty objective');
        if (args.objective.length > 2000) invalid('objective is too long (max 2000)');
      }
      if (action === 'resolve' && (args.intentId === undefined || args.outcome === undefined)) {
        invalid('resolve requires intentId and outcome');
      }
      if (action === 'finish' && args.outcome === undefined) invalid('finish requires outcome');
      return action;
    },
    async run({ args, state, exec, ctx: toolCtx, config: cfg, deps }) {
      requireLead(toolCtx, exec.agent);
      const workspace = deps.workspace(exec.agent);
      const action = args.action;
      const sourceHash = engagementHash(state);
      const existing = currentLoop(state);

      if (action === 'start') {
        if (existing !== undefined && existing.status === 'running') {
          return {
            summary: `${summarizeLoop(existing)} The loop is already running; use action=status or action=step.`,
            ops: [],
            details: { loop: existing, idempotent: true },
          };
        }
        if (state.engagement === null || typeof state.engagement?.authorization !== 'string' || state.engagement.authorization.trim().length === 0) {
          invalid('an engagement with a written authorization reference is required before starting an autonomous loop');
        }
        if ((state.scope?.allow?.length ?? 0) === 0) {
          invalid('no authorized allow list is recorded; set atkbrain_scope before starting autonomous execution');
        }
        const objectiveType = args.objectiveType ?? 'impact';
        const maxRounds = Math.min(200, Math.max(1, Number(args.maxRounds) || Number(cfg.loopMaxRounds) || 40));
        const goal = readGoal(toolCtx, exec.agent);
        let view = goal.view;
        if (goal.available) {
          if (view !== undefined && view !== null && view.phase !== 'complete') {
            invalid(`a DSH goal is already active (${view.phase}, ${view.roundsStarted}/${view.maxGoalRounds}); pause/complete it before starting an AtkBrain loop`);
          }
          const created = createStartedGoal(toolCtx, exec.agent, args.objective.trim(), Math.max(1, maxRounds - 1));
          if (!created.ok) invalid(`could not create the DSH goal: ${created.error}`);
          view = created.view;
        }
        const baseline = snapshotGraph(state);
        const autoContinue = goal.available && goalArmed(view);
        const attrs = {
          objective: args.objective.trim(),
          objectiveType,
          phase: 'running',
          round: 1,
          maxRounds,
          ...goalFields(view),
          activation: view?.activation ?? 'disarmed',
          ring: 1,
          allowedRing: 1,
          noProgressRounds: 0,
          emptyRounds: 0,
          maxActionsPerRound: Math.max(1, Math.min(5, Number(args.maxActions) || Number(cfg.loopMaxActionsPerRound) || 3)),
          baseline,
          latestSnapshot: baseline,
          stopReason: null,
          autoContinue,
          usedLessonKeys: [],
          appliedLessonKeys: [],
          startedAt: nowIso(),
          lastStepAt: nowIso(),
          includeBaseline: args.includeBaseline === true,
        };
        const draft = { ...loopNodeOp(state, attrs), attrs, status: 'running', key: `${state.engagement?.name ?? 'eng'}/loop` };
        const loopOp = loopWith(state, undefined, attrs, 'running');
        const frontier = computeFrontier(state, { limit: 30 });
        const latest = undefined;
        const lessonState = await loadLessons({ state, loop: draft, config: cfg, workspace, sourceHash, markUses: true });
        const supervisionResult = await supervisorForRound({
          ctx: toolCtx,
          agent: exec.agent,
          state,
          loop: draft,
          latest,
          frontier,
          lessons: lessonState.lessons,
          config: cfg,
          exec,
          mode: args.supervisorMode ?? cfg.supervisorMode,
        });
        const plan = supervisionResult.plan;
        const supervisionOp = supervisionNodeOp(state, {
          type: 'round_plan',
          round: 1,
          ...plan,
          childId: supervisionResult.childId,
          promptHash: supervisionResult.promptHash,
          planHash: shortHash(stableStringify(plan), 16),
          source: supervisionResult.source,
        });
        const candidates = candidateIntents(state, { ...draft, attrs: { ...attrs, latestSupervisionKey: supervisionOp.key } }, frontier, cfg, { attrs: plan });
        const intentPlan = planIntentOps(state, candidates.map((entry) => entry.action), {
          round: 1,
          maxActions: attrs.maxActionsPerRound,
          supervisorKey: supervisionOp.key,
        });
        loopOp.attrs.usedLessonKeys = lessonState.applied;
        loopOp.attrs.appliedLessonKeys = lessonState.applied;
        loopOp.attrs.latestSupervisionKey = supervisionOp.key;
        const ops = [loopOp, supervisionOp, ...lessonState.ops, ...intentPlan.ops];
        ops.push(link({ kind: 'supervision', key: supervisionOp.key }, { kind: 'loop', key: loopOp.key }, 'supervises', { confidence: 0.8 }));
        for (const intentOp of intentPlan.ops) {
          const targetId = intentOp.attrs?.targetId;
          const target = Object.values(state.nodes).find((node) => node.id === targetId || node.key === targetId);
          if (target !== undefined) {
            ops.push(link({ kind: 'intent', key: intentOp.key }, { kind: target.kind, key: target.key }, 'targets', { confidence: 0.6 }));
          }
        }
        ops.push(audit(TOOL_NAMES.loop, 'loop.start', state.engagement?.name ?? 'engagement', `round 1/${maxRounds}, ${intentPlan.ops.length} intent(s)`, []));
        const selfTeamOps = selfTeamBootOps(state, cfg, workspace);
        ops.push(...selfTeamOps);
        const finalAttrs = { ...attrs, usedLessonKeys: lessonState.applied, appliedLessonKeys: lessonState.applied, latestSupervisionKey: supervisionOp.key };
        const brief = buildRoundBrief({
          state,
          loop: { ...draft, attrs: finalAttrs },
          supervision: { attrs: plan },
          lessons: lessonState.lessons,
          intents: intentPlan.ops.map((op) => ({ id: `intent:${op.key}`, attrs: op.attrs, status: op.status ?? 'open' })),
          frontier,
          config: cfg,
        });
        return {
          summary: `${summarizeLoop({ attrs: finalAttrs, status: 'running' }, `Auto-continue: ${autoContinue ? 'armed' : goal.available ? 'manual (goal disarmed)' : 'manual (no goal service)'}.`)}

${brief.text}`,
          ops,
          details: {
            loop: { attrs: finalAttrs, status: 'running' },
            supervision: plan,
            lessons: lessonState.lessons,
            intents: intentPlan.ops.map((op) => ({ key: op.key, attrs: op.attrs, status: op.status })),
            brief,
            warnings: lessonState.warnings,
            goal: goalSnapshot(view),
            autoContinue,
            selfTeamsBootstrapped: selfTeamOps.length > 0,
          },
        };
      }

      if (existing === undefined) invalid('no autonomous loop exists; call action=start first');

      if (action === 'status') {
        const goal = readGoal(toolCtx, exec.agent);
        const stop = computeStop(existing, state, cfg);
        const latest = latestSupervision(state);
        return {
          summary: `${summarizeLoop(existing, stop.stop ? `STOP RECOMMENDED: ${stop.reason} (${stop.detail}).` : '')}
Goal: ${goal.view ? `${goal.view.phase} ${goal.view.roundsStarted}/${goal.view.maxGoalRounds} activation=${goal.view.activation}` : 'none (manual mode)'}
Auto-continue: ${goal.view ? `goal ${goal.view.phase}, activation ${goal.view.activation}` : existing.attrs?.autoContinue === true ? 'manual (goal unavailable)' : 'manual'}${goal.error ? `; ${goal.error}` : ''}
Latest supervision: ${latest ? `${latest.attrs?.verdict ?? 'hold'} / ${latest.attrs?.source ?? 'deterministic'} / round ${latest.attrs?.round ?? 0}` : 'none'}
Use action=step for the next round, action=finish to stop, or wait for the goal-round driver.`,
          ops: [],
          details: { loop: existing, goal: goalSnapshot(goal.view), stop, latest: latest?.attrs ?? null },
        };
      }

      if (action === 'pause') {
        const goal = readGoal(toolCtx, exec.agent);
        const paused = pauseGoal(toolCtx, exec.agent, goal.view, args.reason);
        const op = loopWith(state, existing, {
          phase: 'paused',
          stopReason: args.reason ?? 'operator-paused',
          lastStepAt: nowIso(),
        }, 'paused');
        const ops = [op, audit(TOOL_NAMES.loop, 'loop.pause', state.engagement?.name ?? 'engagement', args.reason ?? 'operator', [])];
        return {
          summary: `Loop paused at round ${existing.attrs?.round ?? 0}. Goal: ${paused.ok ? `${paused.view?.phase ?? 'paused'} (activation=${paused.view?.activation ?? 'disarmed'})` : paused.error}. Resume with action=resume only after the operator asks to continue.`,
          ops,
          details: { paused, loop: op.attrs },
        };
      }

      if (action === 'resume') {
        const goal = readGoal(toolCtx, exec.agent);
        if (existing.status === 'complete') invalid('this loop is complete; start a new loop for a new objective');
        if (goal.view === undefined || goal.view === null) invalid('no DSH goal exists to resume; start a new loop');
        const resumed = resumeGoal(toolCtx, exec.agent, goal.view);
        if (!resumed.ok) invalid(`goal resume failed: ${resumed.error}`);
        const op = loopWith(state, existing, {
          phase: 'running',
          stopReason: null,
          ...goalFields(resumed.view),
          activation: resumed.view?.activation ?? 'armed',
          lastStepAt: nowIso(),
        }, 'running');
        return {
          summary: `Loop resumed at round ${existing.attrs?.round ?? 0}; goal ${resumed.view?.roundsStarted ?? 0}/${resumed.view?.maxGoalRounds ?? 0} armed. The next goal round or action=step continues the loop.`,
          ops: [op, audit(TOOL_NAMES.loop, 'loop.resume', state.engagement?.name ?? 'engagement', `round ${existing.attrs?.round ?? 0}`, [])],
          details: { goal: goalSnapshot(resumed.view), loop: op.attrs },
        };
      }

      if (action === 'resolve') {
        const resolved = resolveIntentOp(state, args.intentId, args.outcome, {
          evidenceIds: args.evidenceIds,
          observations: args.observations,
          result: args.reason,
          force: args.force === true,
        });
        if (resolved.error !== undefined) invalid(resolved.error);
        const ops = [resolved.op, audit(TOOL_NAMES.loop, 'loop.resolve', args.intentId, `${args.outcome}`, args.evidenceIds ?? [])];
        return {
          summary: `Intent ${args.intentId} resolved as ${args.outcome}.${args.outcome === 'verified' ? ' Evidence attached; high/critical impact still needs secondary verification and rating.' : ''}`,
          ops,
          details: { intent: resolved.intent.attrs, outcome: args.outcome },
        };
      }

      if (action === 'finish') {
        const goal = readGoal(toolCtx, exec.agent);
        const achieved = args.outcome === 'achieved' || objectiveAchieved(state, existing);
        if (achieved && !passesComplete(state)) invalid(passContinueMessage(testPassNodes(state).length));
        const completion = projectCompletion(state);
        if (achieved && !completion.complete) {
          const hint = completion.reportComplete === true
            ? 'close the open coverage cells with evidence or a path-specific refutation first'
            : 'run atkbrain_selftteam action=report reportType=project first';
          invalid(`project completion is gated on a fresh project HTML report and closed coverage: ${completion.reason ?? 'unknown'} — ${hint}`);
        }
        const goalResult = achieved ? completeGoal(toolCtx, exec.agent, goal.view) : pauseGoal(toolCtx, exec.agent, goal.view, args.reason ?? args.outcome);
        const phase = achieved ? 'complete' : 'paused';
        const loopOp = loopWith(state, existing, {
          phase,
          stopReason: args.reason ?? args.outcome,
          ...(goalResult.ok ? goalFields(goalResult.view) : {}),
          lastStepAt: nowIso(),
        }, phase);
        const ops = [loopOp];
        ops.push(audit(TOOL_NAMES.loop, 'loop.finish', state.engagement?.name ?? 'engagement', `${args.outcome ?? (achieved ? 'achieved' : 'stalled')}`, []));
        return {
          summary: `Loop finished as ${phase} (${args.reason ?? args.outcome}). Goal: ${goalResult.ok ? goalResult.view?.phase : goalResult.error}. Workflow complete only after the 报告撰写 team HTML report: ${completion.reportPath ?? 'missing'}.`,
          ops,
          details: {
            achieved,
            phase,
            projectCompletion: completion,
            goal: goalResult.ok ? goalSnapshot(goalResult.view) : null,
          },
        };
      }

      // step
      if (existing.status !== 'running') invalid(`loop is ${existing.status}; resume it or start a new loop`);
      const goal = readGoal(toolCtx, exec.agent);
      if (goal.available && !goal.view) {
        return {
          summary: `The DSH goal is unavailable (${goal.error ?? 'unknown error'}); the loop cannot advance automatically. Repair the goal service or start a manual loop.`,
          ops: [],
          details: { goalError: goal.error },
        };
      }
      if (goal.available && goal.view) {
        if (goal.view.phase !== 'active') {
          return {
            summary: `Goal is ${goal.view.phase}; the loop cannot advance. Resume the goal only on explicit operator request, then call action=step.`,
            ops: [],
            details: { goal: goalSnapshot(goal.view), resumeRequired: goal.view.phase === 'paused' },
          };
        }
        if (!goalArmed(goal.view)) {
          return {
            summary: `Goal is ${goal.view.phase} but activation=${goal.view.activation}; automatic continuation is disarmed (session resume/fork). Ask the operator to resume; do not self-arm.`,
            ops: [],
            details: { goal: goalSnapshot(goal.view), resumeRequired: true },
          };
        }
      }
      const round = goal.available && goal.view ? goal.view.roundsStarted + 1 : (Number(existing.attrs?.round) || 0) + 1;
      if (round <= (Number(existing.attrs?.round) || 0)) {
        const loopDraft = { ...existing, attrs: { ...existing.attrs, round }, status: 'running' };
        const frontier = computeFrontier(state, { limit: 30 });
        const lessons = await loadLessons({ state, loop: loopDraft, config: cfg, workspace, sourceHash, markUses: false });
        const latest = latestSupervision(state);
        const brief = buildRoundBrief({
          state,
          loop: loopDraft,
          supervision: latest,
          lessons: lessons.lessons,
          intents: Object.values(state.nodes ?? {}).filter((node) => node.kind === 'intent' && ['open', 'claimed'].includes(node.status)),
          frontier,
          config: cfg,
        });
        return {
          summary: `Round ${round} was already stepped; returning the current brief without creating duplicate intents.\n\n${brief.text}`,
          ops: [],
          details: { loop: loopDraft, brief, idempotent: true },
        };
      }

      const progress = progressUpdate(existing, state, cfg);
      const loopDraft = {
        ...existing,
        attrs: {
          ...existing.attrs,
          round,
          ...goalFields(goal.view),
          latestSnapshot: progress.snapshot,
          noProgressRounds: progress.noProgressRounds,
          emptyRounds: progress.emptyRounds,
          ring: progress.ring,
          allowedRing: progress.ring,
          lastStepAt: nowIso(),
          autoContinue: goal.available,
        },
        status: 'running',
      };
      const auto = autoResolveOps(state);
      const stale = stallStaleIntentOps(state, round);
      const stop = computeStop(loopDraft, state, cfg);
      if (stop.stop) {
        const loopOp = loopWith(state, existing, {
          ...loopDraft.attrs,
          lastStepAt: nowIso(),
        }, 'running');
        return {
          summary: `STOP RECOMMENDED: ${stop.reason} — ${stop.detail}. Round ${round}/${loopDraft.attrs.maxRounds}; no new intent was created. Call atkbrain_loop action=finish outcome=${stop.reason === 'objective-achieved' ? 'achieved' : stop.reason === 'max-rounds' || stop.reason === 'wall-clock' ? 'budget' : 'stalled'}.\n\n${summarizeLoop(loopDraft)}`,
          ops: [loopOp, ...auto.ops, ...stale.ops, audit(TOOL_NAMES.loop, 'loop.step', state.engagement?.name ?? 'engagement', `stop:${stop.reason}`, [])],
          details: { loop: loopOp.attrs, stop, autoResolved: auto.resolved, stalled: stale.stalled },
        };
      }

      const frontier = computeFrontier(state, { limit: 30 });
      const latest = latestSupervision(state);
      const lessonState = await loadLessons({ state, loop: loopDraft, config: cfg, workspace, sourceHash, markUses: true });
      const supervisionResult = await supervisorForRound({
        ctx: toolCtx,
        agent: exec.agent,
        state,
        loop: loopDraft,
        latest,
        frontier,
        lessons: lessonState.lessons,
        config: cfg,
        exec,
        mode: args.supervisorMode ?? cfg.supervisorMode,
      });
      const plan = supervisionResult.plan;
      let supervisionOp;
      if (supervisionResult.reused && latest !== undefined) {
        supervisionOp = null;
      } else {
        supervisionOp = supervisionNodeOp(state, {
          type: 'round_plan',
          round,
          ...plan,
          childId: supervisionResult.childId,
          promptHash: supervisionResult.promptHash,
          planHash: shortHash(stableStringify(plan), 16),
          source: supervisionResult.source,
        });
      }
      const candidates = candidateIntents(state, loopDraft, frontier, cfg, { attrs: plan });
      const intentPlan = planIntentOps(state, candidates.map((entry) => entry.action), {
        round,
        maxActions: loopDraft.attrs.maxActionsPerRound,
        supervisorKey: supervisionOp?.key ?? latest?.key ?? null,
      });
      const ops = [...auto.ops, ...stale.ops];
      if (supervisionOp !== null) {
        ops.push(supervisionOp);
        ops.push(link({ kind: 'supervision', key: supervisionOp.key }, { kind: 'loop', key: existing.key }, 'supervises', { confidence: 0.8 }));
      }
      ops.push(...lessonState.ops, ...intentPlan.ops);
      for (const intentOp of intentPlan.ops) {
        const targetId = intentOp.attrs?.targetId;
        const target = Object.values(state.nodes).find((node) => node.id === targetId || node.key === targetId);
        const intent = Object.values(state.nodes).find((node) => node.kind === 'intent' && node.key === intentOp.key);
        if (target !== undefined && (intent !== undefined || intentOp.op === 'node.upsert')) {
          ops.push(link({ kind: 'intent', key: intentOp.key }, { kind: target.kind, key: target.key }, 'targets', { confidence: 0.6 }));
        }
      }
      const loopOp = loopWith(state, existing, {
        ...loopDraft.attrs,
        latestSupervisionKey: supervisionOp?.key ?? loopDraft.attrs.latestSupervisionKey ?? null,
        usedLessonKeys: [...new Set([...(loopDraft.attrs.usedLessonKeys ?? []), ...lessonState.applied])].slice(0, 50),
        appliedLessonKeys: lessonState.applied,
        activation: goal.view?.activation ?? loopDraft.attrs.activation,
        autoContinue: goal.available,
      }, 'running');
      ops.unshift(loopOp);
      ops.push(audit(TOOL_NAMES.loop, 'loop.step', state.engagement?.name ?? 'engagement', `round ${round}, ${intentPlan.ops.length} intent(s)`, []));
      const brief = buildRoundBrief({
        state,
        loop: loopOp,
        supervision: supervisionOp ?? latest,
        lessons: lessonState.lessons,
        intents: Object.values(state.nodes ?? {}).filter((node) => node.kind === 'intent' && ['open', 'claimed'].includes(node.status)),
        frontier,
        config: cfg,
      });
      const selfBriefNode = Object.values(state.nodes ?? {})
        .filter((node) => node.kind === 'supervision' && node.attrs?.type === 'self_team_brief')
        .sort((a, b) => String(b.lastSeen ?? '').localeCompare(String(a.lastSeen ?? '')))[0];
      return {
        summary: `${summarizeLoop(loopOp, `Supervisor: ${plan.verdict}/${supervisionResult.source}; intents: ${intentPlan.ops.length}.`)}

${brief.text}`,
        ops,
        details: {
          selfSupervisionHandoff: selfBriefNode?.attrs?.handoff ?? null,
          loop: loopOp.attrs,
          supervision: plan,
          supervisorSource: supervisionResult.source,
          supervisorError: supervisionResult.error,
          lessons: lessonState.lessons,
          lessonWarnings: lessonState.warnings,
          intents: intentPlan.ops.map((op) => ({ key: op.key, attrs: op.attrs, status: op.status })),
          autoResolved: auto.resolved,
          stalled: stale.stalled,
          progress: { delta: progress.delta, noProgressRounds: progress.noProgressRounds, emptyRounds: progress.emptyRounds, ring: progress.ring },
          brief,
        },
      };
    },
  });
}

/** Create the DSH goal through the same adapter used by other loop actions. */
function createStartedGoal(ctx, agent, objective, maxGoalRounds) {
  // Imported lazily to keep the tool module free of a cycle with goal.js.
  const service = (() => { try { return ctx.get('goals'); } catch { return undefined; } })();
  if (service === undefined || service === null) {
    return { ok: false, error: 'DSH goal service is not mounted' };
  }
  try {
    return { ok: true, view: service.create(agent, { objective, maxGoalRounds }) };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}
