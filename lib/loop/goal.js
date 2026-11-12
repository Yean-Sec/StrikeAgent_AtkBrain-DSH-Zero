/**
 * Thin adapter over the DSH goal service.
 *
 * The goal service is the only automatic continuation authority. This module
 * never queues model work itself; when the service is absent the loop runs in
 * manual-step mode and says so explicitly.
 */
export function goalsService(ctx) {
  try {
    return ctx.get('goals');
  } catch {
    return undefined;
  }
}

export function readGoal(ctx, agent) {
  const service = goalsService(ctx);
  if (service === undefined || service === null) {
    return { available: false, view: undefined, error: 'DSH goal service is not mounted; autonomous continuation is unavailable' };
  }
  try {
    const view = service.get(agent);
    return { available: true, view, error: null };
  } catch (error) {
    return { available: true, view: undefined, error: error instanceof Error ? error.message : String(error) };
  }
}

export function goalRef(view) {
  if (view === undefined || view === null) return undefined;
  return { id: view.id, revision: view.revision };
}

export function goalSnapshot(view) {
  if (view === undefined || view === null) return null;
  return {
    id: view.id,
    revision: view.revision,
    objective: view.objective,
    phase: view.phase,
    roundsStarted: view.roundsStarted,
    maxGoalRounds: view.maxGoalRounds,
    activation: view.activation ?? 'disarmed',
    ...(view.blockedReason ? { blockedReason: view.blockedReason } : {}),
  };
}

export function createGoal(ctx, agent, { objective, maxGoalRounds }) {
  const service = goalsService(ctx);
  if (service === undefined || service === null) {
    return { available: false, view: undefined, error: 'DSH goal service is not mounted' };
  }
  try {
    const view = service.create(agent, { objective, maxGoalRounds });
    return { available: true, view, error: null };
  } catch (error) {
    return {
      available: true,
      view: undefined,
      error: error instanceof Error ? error.message : String(error),
      code: error?.code,
    };
  }
}

export function pauseGoal(ctx, agent, view, reason) {
  const service = goalsService(ctx);
  if (service === undefined || service === null || view === undefined || view === null) {
    return { ok: false, error: 'no goal to pause' };
  }
  try {
    return { ok: true, view: service.pause(agent, goalRef(view)), error: null };
  } catch (error) {
    return { ok: false, error: `${error instanceof Error ? error.message : String(error)}${reason ? ` (${reason})` : ''}` };
  }
}

export function resumeGoal(ctx, agent, view) {
  const service = goalsService(ctx);
  if (service === undefined || service === null || view === undefined || view === null) {
    return { ok: false, error: 'no goal to resume' };
  }
  try {
    return { ok: true, view: service.resume(agent, goalRef(view)), error: null };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

export function completeGoal(ctx, agent, view) {
  const service = goalsService(ctx);
  if (service === undefined || service === null || view === undefined || view === null) {
    return { ok: false, error: 'no goal to complete' };
  }
  try {
    return { ok: true, view: service.complete(agent, goalRef(view)), error: null };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

export function blockGoal(ctx, agent, view, code, message) {
  const service = goalsService(ctx);
  if (service === undefined || service === null || view === undefined || view === null) {
    return { ok: false, error: 'no goal to block' };
  }
  try {
    return { ok: true, view: service.block(agent, goalRef(view), { code, message }), error: null };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

/** Whether the goal is active and armed (driver may continue it). */
export function goalArmed(view) {
  return view !== undefined && view !== null && view.phase === 'active' && view.activation === 'armed';
}

export function goalRoundsLeft(view) {
  if (view === undefined || view === null) return null;
  return Math.max(0, Number(view.maxGoalRounds) - Number(view.roundsStarted));
}
