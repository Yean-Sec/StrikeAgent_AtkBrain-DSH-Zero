/**
 * Implicit three-pass gate.
 *
 * One operator message starts three dialogues. Each dialogue may record one
 * pass, and only after a probe, a record, or a coverage close that happened
 * after the previous pass. The next dialogue is admitted by the host. An
 * empty authorized frontier ends the sequence instead of spinning.
 */
import { engagementGaps } from './project-completion.js';
import { isHardeningFinding, isVulnerabilityNode, secondaryVerificationPassed } from './finding-classification.js';
import { BUG_CLASSES } from './coverage.js';

export const PASS_LIMIT = 3;
const ACTIVITY_TOOLS = new Set(['atkbrain_probe', 'atkbrain_record']);
const CLOSED_COVERAGE = new Set(['seen', 'refuted', 'reported']);

export function testPassNodes(state) {
  return Object.values(state?.nodes ?? {})
    .filter((node) => node.kind === 'supervision' && node.attrs?.type === 'test_pass')
    .sort((a, b) => (Number(a.attrs?.round) || 0) - (Number(b.attrs?.round) || 0)
      || String(a.attrs?.createdAt ?? '').localeCompare(String(b.attrs?.createdAt ?? '')));
}

export function passBasis(node) {
  const basis = String(node?.attrs?.basis ?? node?.attrs?.diagnosis ?? '');
  return basis === 'exhausted' ? 'exhausted' : 'activity';
}

/**
 * Passes tied to an operator message. Automatic passes recorded before that
 * rule do not count once an operator message is on the graph.
 */
export function qualifyingPasses(state) {
  const passes = testPassNodes(state);
  const tied = passes.filter((node) => Number(node.attrs?.operatorSeq) > 0);
  if (operatorTurns(state).length > 0 || tied.length > 0) return tied;
  return passes;
}

export function passesComplete(state) {
  const passes = qualifyingPasses(state);
  if (passes.some((node) => passBasis(node) === 'exhausted')) return true;
  return passes.length >= PASS_LIMIT;
}

export function operatorTurns(state) {
  return Object.values(state?.nodes ?? {})
    .filter((node) => node.kind === 'supervision' && node.attrs?.type === 'operator_turn')
    .sort((a, b) => (Number(a.attrs?.eventSeq) || 0) - (Number(b.attrs?.eventSeq) || 0));
}

/** The newest operator message. Zero when this session has not recorded one yet. */
export function latestOperatorSeq(state) {
  return operatorTurns(state).reduce((max, node) => Math.max(max, Number(node.attrs?.eventSeq) || 0), 0);
}

function dialogueTurns(state) {
  return Object.values(state?.nodes ?? {})
    .filter((node) => node.kind === 'supervision' && (node.attrs?.type === 'operator_turn' || node.attrs?.type === 'dialogue_turn'));
}

/** The newest operator message or follow-up dialogue. */
export function latestDialogueSeq(state) {
  return dialogueTurns(state).reduce((max, node) => Math.max(max, Number(node.attrs?.eventSeq) || 0), 0);
}

/**
 * One dialogue may record one pass. The next pass needs the next dialogue.
 * Sessions with no recorded dialogue keep the older activity gate.
 */
export function operatorRoundOpen(state) {
  const turns = dialogueTurns(state);
  if (turns.length === 0) return true;
  const consumed = testPassNodes(state).reduce((max, node) => Math.max(max, Number(node.attrs?.operatorSeq) || 0), 0);
  return latestDialogueSeq(state) > consumed;
}

/**
 * A non-hardening vulnerability is on the ledger and nothing has been
 * validated as a foothold. Coverage closes and ordinary probes do not
 * finish a round in that state.
 */
export function impactStillOpen(state) {
  const nodes = Object.values(state?.nodes ?? {}).filter((node) => node?.status !== 'merged');
  const foothold = nodes.some((node) => node.kind === 'access' && ['validated', 'escalated'].includes(node.status));
  if (foothold) return false;
  return nodes.some((node) => {
    if (node.kind !== 'finding' || node.status === 'refuted') return false;
    if (isHardeningFinding(node.attrs ?? {})) return false;
    return isVulnerabilityNode(node) || secondaryVerificationPassed(node.attrs ?? {});
  });
}

function isSurfaceActivity(entry) {
  if (ACTIVITY_TOOLS.has(String(entry?.tool ?? ''))) return true;
  return entry?.tool === 'atkbrain_coverage'
    && entry?.action === 'coverage.note'
    && CLOSED_COVERAGE.has(String(entry?.result ?? ''));
}

function isImpactActivity(entry) {
  const action = String(entry?.action ?? '');
  return action === 'record.impact' || action === 'selftteam.escalate';
}

function activitySince(state, sinceAuditId, accept) {
  const audit = Array.isArray(state?.audit) ? state.audit : [];
  const cursor = String(sinceAuditId ?? '');
  const index = cursor.length === 0 ? -1 : audit.findIndex((entry) => String(entry?.id ?? '') === cursor);
  const slice = index < 0 ? audit : audit.slice(index + 1);
  return slice.some(accept);
}

export function lastAuditId(state) {
  const audit = Array.isArray(state?.audit) ? state.audit : [];
  const last = audit[audit.length - 1];
  return last === undefined ? '' : String(last.id ?? '');
}

/** True when this round's required work landed after `sinceAuditId`. */
export function passActivitySince(state, sinceAuditId) {
  const accept = impactStillOpen(state) ? isImpactActivity : isSurfaceActivity;
  return activitySince(state, sinceAuditId, accept);
}

export function passImpactMessage(count) {
  return `已有漏洞，还没有验证过的立足点。覆盖关闭、普通探测和笔记不能记成第 ${count + 1} 轮。先把更高危害记成新漏洞，或记下验证过的访问、凭据、数据，再调用 atkbrain_selftteam action=pass。不要批量关闭覆盖格。`;
}

export function passWaitMessage(count) {
  return `第 ${count} 轮已经记下。不要在同一次回复里再记一轮，也不要请操作员再发一条消息。下一轮对话会自动开始。不要写项目报告。`;
}

export function passContinueMessage(count) {
  const ledger = '接着同一本账，总目标不变，不另开新交战。图谱里已有的发现、权限和证据都保留。不要把结果交给操作员。不要请操作员再发一条消息。';
  if (count >= PASS_LIMIT) {
    return '三轮对话都已记下。这是一次操作员消息带出的三轮对话。现在写项目报告，并给操作员唯一一份结果。';
  }
  if (count <= 0) {
    return `${ledger}这一轮还没记下。做完这一轮的测试再调用 action=pass，然后结束这次回复。下一轮对话会自动开始。`;
  }
  return `第 ${count} 轮已记下。${ledger}这次回复到这里结束，不要在这次回复里开始下一轮。下一轮对话会自动开始，继续测还没关掉的类型。`;
}

export function passRejectMessage(count, gaps) {
  const list = Array.isArray(gaps) && gaps.length > 0 ? gaps.join('、') : '未关闭的测试面';
  return `这一轮还没有新的探测、记录或覆盖关闭，不能记成下一轮。${passContinueMessage(count)}仍有缺口：${list}。`;
}

const COVERAGE_ROUND_QUOTA = 4;

export function openCoverageClasses(state) {
  const classes = new Set();
  for (const node of Object.values(state?.nodes ?? {})) {
    if (node?.kind !== 'coverage' || !['open', 'claimed'].includes(node.status)) continue;
    const bug = String(node.attrs?.bugClass ?? '');
    if (BUG_CLASSES.includes(bug)) classes.add(bug);
  }
  return [...classes];
}

function classOfAuditTarget(target) {
  const text = String(target ?? '');
  const hash = text.lastIndexOf('#');
  const slash = text.lastIndexOf('/');
  const token = (hash > slash ? text.slice(hash + 1) : text.slice(slash + 1)).trim();
  return BUG_CLASSES.includes(token) ? token : '';
}

export function classesNotedSince(state, sinceAuditId) {
  const audit = Array.isArray(state?.audit) ? state.audit : [];
  const cursor = String(sinceAuditId ?? '');
  const index = cursor.length === 0 ? -1 : audit.findIndex((entry) => String(entry?.id ?? '') === cursor);
  const slice = index < 0 ? audit : audit.slice(index + 1);
  const noted = new Set();
  for (const entry of slice) {
    if (entry?.tool !== 'atkbrain_coverage' || entry?.action !== 'coverage.note') continue;
    if (!['seen', 'refuted', 'reported'].includes(String(entry.result ?? ''))) continue;
    const bug = classOfAuditTarget(entry.target);
    if (bug) noted.add(bug);
  }
  return [...noted];
}

export function passCoverageMessage(count, classes) {
  const list = (Array.isArray(classes) ? classes : []).slice(0, 6).join('、');
  return `这一轮还没铺开覆盖格。仍打开的类型有 ${list}。先对其中至少 ${COVERAGE_ROUND_QUOTA} 类各记一条覆盖（seen、refuted 或 reported），再调用 action=pass。不要只测已经打出来的那一类。`;
}

/** What `action=pass` should do next. */
export function nextPassDecision(state) {
  const passes = qualifyingPasses(state);
  if (passesComplete(state)) {
    return { action: 'complete', count: passes.length, gaps: engagementGaps(state) };
  }
  if (!operatorRoundOpen(state)) {
    return { action: 'reject', count: passes.length, gaps: engagementGaps(state), reason: 'operator' };
  }
  const latest = passes[passes.length - 1];
  const activity = passActivitySince(state, latest?.attrs?.auditCursor ?? '');
  const gaps = engagementGaps(state);
  if (!activity && impactStillOpen(state)) {
    return { action: 'reject', count: passes.length, gaps, reason: 'impact' };
  }
  if (!activity && gaps.length > 0) {
    return { action: 'reject', count: passes.length, gaps };
  }
  const openClasses = openCoverageClasses(state);
  if (openClasses.length >= 2) {
    const noted = classesNotedSince(state, latest?.attrs?.auditCursor ?? '');
    const need = Math.min(COVERAGE_ROUND_QUOTA, openClasses.length);
    if (noted.length < need) {
      return { action: 'reject', count: passes.length, gaps, reason: 'coverage', classes: openClasses };
    }
  }
  return {
    action: 'record',
    count: passes.length,
    round: passes.length + 1,
    basis: activity ? 'activity' : 'exhausted',
    gaps,
    operatorSeq: latestDialogueSeq(state),
  };
}
