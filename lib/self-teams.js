/**
 * The five engagement agent teams, in operator order:
 * 御者 → 从者（Lead）→ 二次验证 → 危害提升 → 报告撰写.
 *
 * 从者 is the main executor (not a spawned subagent); the other four are
 * isolated roles. The report-writing team serves both a project-level report
 * and a single-finding report. Harm escalation starts when a vulnerability
 * is on the ledger, the same way secondary verification does.
 */
import { nodeOp } from './ops.js';
import { nowIso } from './util.js';

export const SELF_TEAM_ORDER = Object.freeze(['lead', 'verification', 'report']);

export const SELF_TEAM_LABELS = Object.freeze({
  supervision: '御者（监督团队）',
  lead: '从者（Lead / Executor）',
  verification: '二次验证团队',
  escalation: '危害提升团队',
  report: '报告撰写团队',
});

export const SELF_TEAM_MEMBERS = Object.freeze({
  supervision: [{ role: 'supervisor', name: '御者', mode: 'subagent', responsibility: '只读图谱，给从者进度/收益/缺口/防死磕建议' }],
  lead: [{ role: 'executor', name: '从者（Lead）', mode: 'main', responsibility: '真实侦查、利用、证据记录，并可创建 Team/subagent 并行工作' }],
  verification: [
    { role: 'verifier', name: '二次验证', mode: 'subagent', responsibility: '独立复核 finding 证据' },
    { role: 'rater', name: '二次验证评级', mode: 'subagent', responsibility: '按 CVSS v3.1 独立评级' },
  ],
  escalation: [{ role: 'escalator', name: '危害提升', mode: 'subagent', responsibility: '在授权范围内把已发现漏洞的危害提高，并记成新漏洞' }],
  report: [{ role: 'reporter', name: '报告撰写', mode: 'subagent', responsibility: '项目总报告 + 单漏洞报告' }],
});

export const SELF_TEAM_MODES = Object.freeze({
  supervision: 'subagents',
  lead: 'main',
  verification: 'subagents',
  escalation: 'subagents',
  report: 'subagents',
});

function existingTeam(state, type) {
  return Object.values(state?.nodes ?? {}).find((node) => node.kind === 'self_team' && node.attrs?.type === type);
}

/** Graph node for one of the five teams, when bootstrap has created it. */
export function selfTeamNode(state, type) {
  return existingTeam(state, type);
}

/**
 * Durable DSH teammate already spawned for this role.
 * Absent when Agent Teams is unavailable or action=native has not run.
 */
export function nativeTeammate(state, type) {
  const node = existingTeam(state, type);
  const id = node?.attrs?.nativeId;
  const name = node?.attrs?.nativeName;
  if (typeof id !== 'string' || id.length === 0 || typeof name !== 'string' || name.length === 0) return undefined;
  return { id, name, teamType: type };
}

export function selfTeamLabel(type) {
  return SELF_TEAM_LABELS[type] ?? type;
}

export function selfTeamSpec(type) {
  return {
    label: selfTeamLabel(type),
    members: SELF_TEAM_MEMBERS[type] ?? [],
    mode: SELF_TEAM_MODES[type] ?? 'subagents',
    reportModes: type === 'report' ? ['project', 'finding'] : [],
  };
}

/** One team node op that preserves the existing key/label when present. */
export function selfTeamOp(state, type, patch = {}) {
  const existing = existingTeam(state, type);
  const spec = selfTeamSpec(type);
  const createdAt = existing?.attrs?.createdAt ?? nowIso();
  const attrs = {
    type,
    mode: patch.mode ?? existing?.attrs?.mode ?? spec.mode,
    members: spec.members,
    reportModes: spec.reportModes,
    nativeName: patch.nativeName ?? existing?.attrs?.nativeName ?? null,
    nativeId: patch.nativeId ?? existing?.attrs?.nativeId ?? null,
    nativeStatus: patch.nativeStatus ?? existing?.attrs?.nativeStatus ?? null,
    lastBriefAt: patch.lastBriefAt ?? existing?.attrs?.lastBriefAt ?? null,
    lastBriefPath: patch.lastBriefPath ?? existing?.attrs?.lastBriefPath ?? null,
    lastDistillAt: patch.lastDistillAt ?? existing?.attrs?.lastDistillAt ?? null,
    lastVerifyAt: patch.lastVerifyAt ?? existing?.attrs?.lastVerifyAt ?? null,
    lastReportAt: patch.lastReportAt ?? existing?.attrs?.lastReportAt ?? null,
    lastReportPath: patch.lastReportPath ?? existing?.attrs?.lastReportPath ?? null,
    lastReportTheme: patch.lastReportTheme ?? existing?.attrs?.lastReportTheme ?? null,
    lastReportKind: patch.lastReportKind ?? existing?.attrs?.lastReportKind ?? null,
    lastFindingReportAt: patch.lastFindingReportAt ?? existing?.attrs?.lastFindingReportAt ?? null,
    lastFindingReportPath: patch.lastFindingReportPath ?? existing?.attrs?.lastFindingReportPath ?? null,
    lastFindingReportId: patch.lastFindingReportId ?? existing?.attrs?.lastFindingReportId ?? null,
    themeSource: patch.themeSource ?? existing?.attrs?.themeSource ?? null,
    verifiedCount: patch.verifiedCount ?? existing?.attrs?.verifiedCount ?? 0,
    ratedCount: patch.ratedCount ?? existing?.attrs?.ratedCount ?? 0,
    skillCount: patch.skillCount ?? existing?.attrs?.skillCount ?? 0,
    skillDir: patch.skillDir ?? existing?.attrs?.skillDir ?? null,
    lastChildId: patch.lastChildId ?? existing?.attrs?.lastChildId ?? null,
    lastChildVia: patch.lastChildVia ?? existing?.attrs?.lastChildVia ?? null,
    createdAt,
    updatedAt: nowIso(),
  };
  const op = nodeOp('self_team', `selfteam/${type}`, spec.label, attrs, {
    status: patch.status ?? existing?.status ?? 'active',
    confidence: 0.7,
  });
  return existing === undefined ? op : { ...op, key: existing.key };
}

/** Create every missing team at engagement bootstrap. */
export function bootstrapSelfTeamOps(state) {
  const ops = [];
  for (const type of SELF_TEAM_ORDER) {
    const existing = existingTeam(state, type);
    if (existing === undefined) {
      ops.push(selfTeamOp(state, type, { status: 'active' }));
      continue;
    }
    const spec = selfTeamSpec(type);
    const missingReportMode = type === 'report' && !Array.isArray(existing.attrs?.reportModes);
    if (existing.label !== spec.label || missingReportMode) {
      ops.push(selfTeamOp(state, type, { status: existing.status ?? 'active' }));
    }
  }
  return ops;
}
