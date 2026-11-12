/**
 * Native DSH Agent Teams mirror for the five non-Lead AtkBrain teams.
 *
 * The native roster only shows durable teammates created through
 * `agentTeams.spawnTeammate`; graph nodes alone are invisible there.
 * A resident finishes the task in the current message and ends that turn.
 * A later conversation wakes it again when its own work is still due:
 * verification, harm escalation, a supervision handoff, or a
 * project report. One finished Lead turn does not retire the team.
 * Harm escalation is woken when a vulnerability is waiting, the same way
 * verification is. Its message names findings only.
 */
import { escalationWakeText, pendingEscalations } from './escalation-queue.js';
import { projectCompletion } from './project-completion.js';
import { selfTeamNode } from './self-teams.js';
import { handoffOverdue } from './supervision-memory.js';
import { passesComplete } from './test-passes.js';
import { pendingFindings } from './verify-queue.js';

const RESIDENT_TYPES = new Set(['supervision', 'verification', 'escalation', 'report']);
const WAKE_COOLDOWN_MS = 60000;
const lastWakeAt = new Map();
export const NATIVE_TEAM_SPECS = Object.freeze([
  {
    teamType: 'supervision',
    name: 'atk-supervisor',
    description: 'AtkBrain supervisor team (御者): read-only progress/gaps/advice handoff',
  },
  {
    teamType: 'verification',
    name: 'atk-verifier',
    description: 'AtkBrain secondary verification team (二次验证): independent evidence check + CVSS rating',
  },
  {
    teamType: 'escalation',
    name: 'atk-escalator',
    description: 'AtkBrain harm-escalation team (危害提升): raise a recorded finding to a new higher-harm finding',
  },
  {
    teamType: 'report',
    name: 'atk-reporter',
    description: 'AtkBrain report-writing team (报告撰写): project report + single-finding report',
  },
]);

function dutyFor(spec) {
  if (spec.teamType === 'verification') {
    return `When a Team message lists findings, verify each one by calling atkbrain_supervise action=verify with that findingId, then atkbrain_supervise action=rate with a CVSS v3.1 base vector for the same finding. Verification and rating finish together. Verify findings named together in parallel, up to 4 at once, and queue the rest. After one finishes both steps, take the next queued finding. Judge the evidence. Verification succeeds only when the verdict is verified and the CVSS score is stored. Verification fails only when the verdict is refuted, which means a false positive and needs no score. A timeout, a missing verdict, a missing score, or an inconclusive result is still in progress. Do not record that as a false positive. Reflected XSS is at most medium because the victim must open the link. Only stored XSS may be high.`;
  }
  if (spec.teamType === 'escalation') {
    return `When a Team message lists findings, raise the harm of each one inside the recorded scope. Then call atkbrain_query action=node with that finding id. action=graph returns only a slice and can omit findings when coverage and evidence fill it. A finding missing from that slice is still on the lead graph. An open coverage cell is not proof that the finding was never recorded. If action=node returns the finding, call atkbrain_selftteam action=escalate with that findingId. A higher result is a new finding. Do not merge it into the original. The new finding must be this vulnerability's own higher harm, or a later harm that this vulnerability itself enabled. Do not hang an unrelated bug on this finding, and do not reuse another vulnerability's endpoint as the place where the new harm happens. Pass the new title, the new severity, and the proof that the harm increased. Write the title and the proof in Chinese. If the harm did not increase, call the same action with outcome=unchanged. A result without that proof is not a success. If the tool says the finding is not in the escalation queue because it was already raised, report that and stop.`;
  }
  if (spec.teamType === 'supervision') {
    return `When a Team message says the handoff is due, restate seven sections and write 无 for any section that has no record: 目标, 服务, 危险点, 严重高中低, 凭证, 立足点, 信息. Then one next step, as advice rather than a required intent. If the same interface already has a finding of that type, say so. Do not send an opening plan before that message.`;
  }
  return `Write a report only when a Team message assigns a report task. Do not write a report while the named findings are still awaiting secondary verification.`;
}

function residentPrompt(spec) {
  return `You are the AtkBrain ${spec.teamType} team (${spec.name}).

Role:
- ${spec.description}
- You are not the Lead. The Lead is the executor and owns the attack graph.
- Graph tools read and write that lead graph.
- Skills, dictionaries and external scanners are not available.
- ${spec.teamType === 'escalation'
    ? 'Stay inside the recorded scope. Do not widen scope and do not create subagents.'
    : 'Do not run network tools, do not exploit, do not widen scope, and do not create subagents.'}
- Do the task in this message, then end the turn.
- A later conversation may send another Team message. That message is new work. Do it even if the Lead already finished an earlier turn.
- One finished Lead turn does not end this team.
- If this message does not name a finding, a handoff, or a report, stop without doing anything.
- ${dutyFor(spec)}`;
}

function promptFor(spec) {
  return residentPrompt(spec);
}

/** Short queue assigned to the resident verifier. Labels only; no reproduction steps. */
export function verifierWakeText(pending) {
  const rows = (Array.isArray(pending) ? pending : []).slice(0, 20).map((finding) => {
    const id = finding?.id ?? finding?.key ?? '';
    const label = finding?.label ?? finding?.attrs?.title ?? finding?.key ?? id;
    return `- ${id}: ${label}`;
  }).filter((line) => line !== '- : ');
  if (rows.length === 0) return '';
  return `待验证漏洞 ${rows.length} 条。同一批最多并行 4 条，后面的排队。对每一条先调用 atkbrain_supervise action=verify findingId=<id>，再调用 action=rate 写上 CVSS v3.1 分数。验证和评分一起完成：没有分数就还是验证中。验证失败只表示假阳性，不需要分数。做完这一批就结束这一轮。后面的对话如果又列出漏洞，那是新的工作，要继续做。\n${rows.join('\n')}`;
}

function cooled(name, force) {
  if (force === true) return false;
  const at = lastWakeAt.get(name) ?? 0;
  return Date.now() - at < WAKE_COOLDOWN_MS;
}

/** Test hook. Cooldowns are process-local and would otherwise leak between cases. */
export function clearResidentCooldowns() {
  lastWakeAt.clear();
}

/** The project report is due only after three passes, and only when it is missing or stale. */
export function reportDueText(state) {
  if (!passesComplete(state)) return '';
  const completion = projectCompletion(state);
  if (completion.reportComplete === true) return '';
  return '三轮已经记下，项目报告还没有写完，或者已经旧于最新的发现。调用 atkbrain_selftteam action=report reportType=project。上一轮对话结束不等于这个团队结束。';
}

function markWake(name) {
  lastWakeAt.set(name, Date.now());
}

async function sendText(agentTeams, agent, signal, target, text, cooldownKey = target) {
  if (typeof text !== 'string' || text.length === 0 || typeof agentTeams?.sendMessage !== 'function') return false;
  await agentTeams.sendMessage(agent, {
    target,
    content: [{ type: 'text', text }],
    signal,
  });
  markWake(cooldownKey);
  return true;
}

export async function ensureNativeTeams({ agentTeams, agent, signal, pending = [], escalationPending = [], resume = false }) {
  if (agentTeams === undefined || agentTeams === null || typeof agentTeams.spawnTeammate !== 'function') {
    return { available: false, spawned: [], existing: [], errors: [], members: [] };
  }
  let current = [];
  try {
    current = await agentTeams.listMembers(agent);
  } catch {
    current = [];
  }
  const byName = new Map((Array.isArray(current) ? current : []).map((member) => [String(member?.name ?? ''), member]));
  if (byName.has('atk-evolver') && typeof agentTeams.interrupt === 'function') {
    try { await agentTeams.interrupt(agent, 'atk-evolver'); } catch { /* the removed evolution teammate may already be gone */ }
  }
  const spawned = [];
  const existing = [];
  const errors = [];
  for (const spec of NATIVE_TEAM_SPECS) {
    if (spec.teamType === 'escalation') continue;
    const prior = byName.get(spec.name);
    if (prior !== undefined) {
      existing.push({ teamType: spec.teamType, name: spec.name, id: prior.id ?? null, status: prior.status ?? null });
      const queued = spec.teamType === 'verification'
        ? verifierWakeText(pending)
        : (spec.teamType === 'escalation' ? escalationWakeText(escalationPending) : '');
      if (queued.length > 0 && prior.status !== 'running' && typeof agentTeams.sendMessage === 'function' && !cooled(`${spec.name}:role`, resume === true)) {
        try {
          await sendText(agentTeams, agent, signal, spec.name, queued, `${spec.name}:role`);
        } catch {
          /* an inactive verifier is woken on the next record or probe that still has a queue */
        }
      }
      continue;
    }
    try {
      const result = await agentTeams.spawnTeammate(agent, {
        name: spec.name,
        description: spec.description,
        prompt: [{ type: 'text', text: promptFor(spec) }],
        // A fork only copies the lead log through the last finished turn, and
        // the child's tool results stay in the child log. Residents bind graph
        // reads and writes to the live lead session instead.
        context: 'fresh',
        provider: 'spawn',
        signal,
      });
      const member = result?.member ?? result;
      const queued = spec.teamType === 'verification'
        ? verifierWakeText(pending)
        : (spec.teamType === 'escalation' ? escalationWakeText(escalationPending) : '');
      if (queued.length > 0 && member?.status !== 'running' && typeof agentTeams.sendMessage === 'function' && !cooled(`${spec.name}:role`, resume === true)) {
        try {
          await sendText(agentTeams, agent, signal, spec.name, queued, `${spec.name}:role`);
        } catch {
          /* notify retries while the teammate is running */
        }
      }
      spawned.push({
        teamType: spec.teamType,
        name: member?.name ?? spec.name,
        id: member?.id ?? null,
        status: member?.status ?? 'provisioning',
      });
    } catch (error) {
      errors.push({
        teamType: spec.teamType,
        name: spec.name,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return { available: true, spawned, existing, errors, members: [...byName.values()] };
}

/**
 * Tell a running verifier about the queue, tell supervision when the handoff is overdue, and tell the
 * report team when the project report is missing or stale. `resume` means a
 * later conversation is asking again, so the cooldown does not swallow it.
 */
export async function notifyResidentTeams({
  agentTeams,
  agent,
  signal,
  state,
  config,
  pending = [],
  escalationPending = [],
  forceVerifier = false,
  forceEscalation = false,
  justVerified = [],
  resume = false,
} = {}) {
  const sent = [];
  if (agentTeams === undefined || agentTeams === null || typeof agentTeams.sendMessage !== 'function') return { sent };
  let members = [];
  try {
    members = await agentTeams.listMembers(agent);
  } catch {
    members = [];
  }
  const byName = new Map((Array.isArray(members) ? members : []).map((member) => [String(member?.name ?? ''), member]));
  const verifier = byName.get('atk-verifier');
  const queueText = verifierWakeText(pending);
  void escalationPending;
  void forceEscalation;
  const verifierForce = forceVerifier === true || resume === true;
  if (verifier !== undefined && queueText.length > 0 && verifierForce && verifier.status === 'running' && !cooled('atk-verifier:queue', verifierForce)) {
    try {
      if (await sendText(agentTeams, agent, signal, 'atk-verifier', queueText, 'atk-verifier:queue')) sent.push('atk-verifier');
    } catch { /* the next record or query retries */ }
  }
  const supervision = selfTeamNode(state, 'supervision');
  const nodes = Object.values(state?.nodes ?? {});
  if (supervision !== undefined && byName.has('atk-supervisor') && handoffOverdue(nodes, supervision.attrs?.lastBriefAt) && !cooled('atk-supervisor:handoff', resume === true)) {
    try {
      if (await sendText(agentTeams, agent, signal, 'atk-supervisor', '交接已过期。按七段交接，空的写无：目标，服务，危险点，严重高中低，凭证，立足点，信息。然后给一步建议。上一轮对话结束不等于这个团队结束。', 'atk-supervisor:handoff')) sent.push('atk-supervisor');
    } catch { /* the next query retries after the cooldown */ }
  }
  const reportText = reportDueText(state);
  if (reportText.length > 0 && byName.has('atk-reporter') && !cooled('atk-reporter:report', resume === true)) {
    try {
      if (await sendText(agentTeams, agent, signal, 'atk-reporter', reportText, 'atk-reporter:report')) sent.push('atk-reporter');
    } catch { /* the next conversation retries */ }
  }
  return { sent };
}

/** Spawn missing residents, wake stopped ones, and deliver any due team task. */
export async function wakeEngagementTeams({
  agentTeams,
  agent,
  signal,
  state,
  config,
  pending,
  escalationPending,
  forceVerifier = false,
  forceEscalation = false,
  justVerified = [],
  resume = false,
} = {}) {
  void agentTeams;
  void agent;
  void signal;
  void state;
  void config;
  void pending;
  void escalationPending;
  void forceVerifier;
  void forceEscalation;
  void justVerified;
  void resume;
  return {
    native: {
      available: false,
      spawned: [],
      existing: [],
      errors: [],
      skipped: 'native teams are not started automatically in this edition',
    },
    notified: { sent: [] },
  };
  const list = Array.isArray(pending) ? pending : pendingFindings(Object.values(state?.nodes ?? {}));
  const escalation = Array.isArray(escalationPending) ? escalationPending : pendingEscalations(state);
  const native = await ensureNativeTeams({
    agentTeams,
    agent,
    signal,
    pending: list,
    escalationPending: escalation,
    resume: resume === true || forceVerifier === true || forceEscalation === true,
  });
  const notes = await notifyResidentTeams({
    agentTeams,
    agent,
    signal,
    state,
    config,
    pending: list,
    escalationPending: escalation,
    forceVerifier,
    forceEscalation: forceEscalation === true || forceVerifier === true,
    justVerified,
    resume,
  });
  return { native, notes };
}

/** Tell the harm-escalation teammate about included vulnerabilities that are still waiting. */
export async function requestEscalationWake({ agentTeams, agent, signal, state } = {}) {
  const escalationPending = pendingEscalations(state);
  if (escalationPending.length === 0) return { sent: [] };
  return wakeEngagementTeams({
    agentTeams,
    agent,
    signal,
    state,
    escalationPending,
    forceEscalation: true,
  });
}
