/**
 * Harm-escalation queue.
 *
 * An included vulnerability is queued until a higher-harm finding with
 * proof is linked from it, or three unchanged attempts pause it.
 * A refuted finding is not included, so it leaves the queue.
 */
import { SEVERITY_RANK } from './constants.js';
import { isIncludedVulnerabilityNode } from './finding-classification.js';
import { evidenceStamp } from './verify-queue.js';
export const MAX_ESCALATION_ATTEMPTS = 3;

export function escalationAttemptsExhausted(finding) {
  const attempts = Number(finding?.attrs?.escalationAttempts) || 0;
  if (attempts < MAX_ESCALATION_ATTEMPTS) return false;
  return evidenceStamp(finding) === String(finding?.attrs?.escalationAttemptEvidence ?? '');
}

export function severityRankOf(attrs = {}) {
  const raw = String(attrs.severity ?? attrs.cvssSeverity ?? '').toLowerCase();
  return SEVERITY_RANK[raw] ?? 0;
}

function raisedFrom(finding, nodes, edges) {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  return edges.some((edge) => {
    if (edge.kind !== 'escalates_to' || edge.from !== finding.id) return false;
    const target = byId.get(edge.to);
    return String(target?.attrs?.escalationProof ?? '').trim().length > 0;
  });
}

/** Included vulnerabilities that still need a harm-escalation attempt. */
export function pendingEscalations(state) {
  const nodes = Object.values(state?.nodes ?? {}).filter((node) => node?.status !== 'merged');
  const edges = Object.values(state?.edges ?? {});
  return nodes.filter((node) => isIncludedVulnerabilityNode(node)
    && node.attrs?.stub !== true
    && !/^finding_[0-9a-f]{8,}$/iu.test(String(node.key ?? ''))
    && !escalationAttemptsExhausted(node)
    && !raisedFrom(node, nodes, edges));
}

/** Labels only. No reproduction steps and no site names. */
export function escalationWakeText(pending) {
  const rows = (Array.isArray(pending) ? pending : []).slice(0, 20).map((finding) => {
    const id = finding?.id ?? finding?.key ?? '';
    const label = finding?.label ?? finding?.attrs?.title ?? finding?.key ?? id;
    return `- ${id}: ${label}`;
  }).filter((line) => line !== '- : ');
  if (rows.length === 0) return '';
  return `待提升危害的漏洞 ${rows.length} 条。对每一条调用 atkbrain_selftteam action=escalate findingId=<id>。更高危害记成新漏洞，不要并进原来的那条。没有证明危害已经提高就不要记成成功。做完这一批就结束这一轮。后面的对话如果又列出漏洞，那是新的工作，要继续做。\n${rows.join('\n')}`;
}
