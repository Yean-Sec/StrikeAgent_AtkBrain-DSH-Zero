/**
 * Bind resident teammates to the lead attack graph.
 *
 * A native teammate is a child session. Its tool result is stored on that
 * child log, and the attack-graph view reads the lead session only. Forking
 * the child would copy a stale prefix and still leave later writes on the
 * child. Residents therefore read the live lead projection and append the
 * same ops to the lead log as an ignorable plugin record. Asset workers keep
 * their own graphs; the lead merges those exports separately.
 */
import { createRequire } from 'node:module';
import { existsSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { LEDGER_EVENT, STATE_SCHEMA } from './constants.js';
import { invalid } from './util.js';

export const RESIDENT_GRAPH_WRITERS = new Set([
  'atk-supervisor',
  'atk-verifier',
  'atk-escalator',
  'atk-reporter',
]);

const tails = new WeakMap();
let cachedModule;

function isLedgerPayload(value) {
  return value !== null && typeof value === 'object' && value.schema === STATE_SCHEMA && Array.isArray(value.ops);
}

/** Ops carried by a lead tool result or by a resident plugin record. */
export function ledgerMeta(event) {
  if (event === null || event === undefined || typeof event !== 'object') return undefined;
  if (event.type === 'tool/result' || event.type === 'tool/ptc-dispatch') {
    return isLedgerPayload(event.data?.meta) ? event.data.meta : undefined;
  }
  if (event.type === LEDGER_EVENT && isLedgerPayload(event.data)) return event.data;
  return undefined;
}

function membershipOf(ctx, agent) {
  try {
    const teams = ctx.get('agentTeams');
    if (teams !== undefined && teams !== null && typeof teams.membership === 'function') return teams.membership(agent);
  } catch {
    /* standalone session */
  }
  return undefined;
}

function agentsOf(ctx) {
  try {
    if (ctx.agents !== undefined && ctx.agents !== null && typeof ctx.agents.get === 'function') return ctx.agents;
  } catch {
    /* service getter unavailable */
  }
  try {
    const agents = ctx.get('agents');
    if (agents !== undefined && agents !== null && typeof agents.get === 'function') return agents;
  } catch {
    /* agents service is not provided */
  }
  return undefined;
}

function rootAgent(ctx, agent) {
  const agents = agentsOf(ctx);
  if (agents === undefined) return agent;
  const seen = new Set();
  let current = agent;
  while (typeof current?.session?.header?.parentSession === 'string' && current.session.header.parentSession.length > 0) {
    const parentId = current.session.header.parentSession;
    if (seen.has(parentId)) break;
    seen.add(parentId);
    let parent;
    try {
      parent = agents.get(parentId);
    } catch {
      parent = undefined;
    }
    if (parent?.session === undefined) break;
    current = parent;
  }
  return current;
}

/**
 * Session whose attack graph this caller must read and write.
 * Residents resolve to the lead. Every other caller keeps its own session.
 */
export function graphOwner(ctx, agent) {
  const member = membershipOf(ctx, agent);
  if (member === undefined || member === null || member.role === 'lead') return agent;
  if (!RESIDENT_GRAPH_WRITERS.has(String(member.name ?? ''))) return agent;
  const lead = rootAgent(ctx, agent);
  if (lead?.session === undefined || lead === agent || lead.session === agent.session) {
    invalid('the lead attack graph is not available to this teammate');
  }
  return lead;
}

function candidateFiles(startFile) {
  const files = [];
  const seen = new Set();
  const push = (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    files.push(file);
  };
  const starts = [];
  if (typeof startFile === 'string' && startFile.length > 0) {
    starts.push(startFile);
    try {
      starts.push(realpathSync(startFile));
    } catch {
      /* the start path is not a symlink */
    }
  }
  const base = starts[0] ?? fileURLToPath(import.meta.url);
  try {
    const require = createRequire(base);
    for (const dir of require.resolve.paths('@deepseek-ai/dsh-session') ?? []) {
      push(join(dir, '@deepseek-ai', 'dsh-session', 'lib', 'index.js'));
    }
  } catch {
    /* resolution base is not a file the host can search from */
  }
  for (const start of starts) {
    let dir = dirname(start);
    for (let depth = 0; depth < 8; depth += 1) {
      push(join(dir, 'node_modules', '@deepseek-ai', 'dsh-session', 'lib', 'index.js'));
      push(join(dir, '@deepseek-ai', 'dsh-session', 'lib', 'index.js'));
      push(join(dir, 'dsh-session', 'lib', 'index.js'));
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  return files;
}

/** Load the host session module that can append an ignorable plugin record. */
export async function loadSessionModuleFrom(startFile) {
  if (cachedModule !== undefined) return cachedModule;
  for (const file of candidateFiles(startFile)) {
    if (!existsSync(file)) continue;
    const mod = await import(pathToFileURL(file).href);
    if (typeof mod.appendPluginRecord === 'function') {
      cachedModule = mod;
      return cachedModule;
    }
  }
  return undefined;
}

export function loadSessionModule() {
  return loadSessionModuleFrom(typeof process.argv[1] === 'string' ? process.argv[1] : undefined);
}

function exclusive(session, fn) {
  const previous = tails.get(session) ?? Promise.resolve();
  const run = previous.then(fn, fn);
  tails.set(session, run.then(() => {}, () => {}));
  return run;
}

async function callAppend(append, session, payload) {
  let last;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      append(session, LEDGER_EVENT, payload);
      return;
    } catch (error) {
      last = error;
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes('cannot reenter')) throw error;
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  }
  throw last;
}

async function writeRecord(session, payload) {
  if (typeof session?.appendPluginRecord === 'function') {
    session.appendPluginRecord(LEDGER_EVENT, payload);
    return;
  }
  const mod = await loadSessionModule();
  if (typeof mod?.appendPluginRecord !== 'function') {
    throw new Error('AtkBrain could not write this result onto the lead attack graph');
  }
  await callAppend(mod.appendPluginRecord, session, payload);
}

async function flushSession(ctx, session) {
  try {
    const sessions = ctx?.get?.('sessions');
    if (typeof sessions?.flush === 'function') await sessions.flush(session);
  } catch {
    /* the record is already in the live log */
  }
}

/** Append one resident op batch to the lead session. */
export function commitLeadLedger(ctx, session, payload) {
  return exclusive(session, async () => {
    await writeRecord(session, payload);
    await flushSession(ctx, session);
  });
}
