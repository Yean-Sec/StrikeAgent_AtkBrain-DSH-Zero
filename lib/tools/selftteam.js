/**
 * `atkbrain_selftteam` — auxiliary teams around the main pentest team.
 *
 * - supervision team: progress, gains, advice and anti-deadlock reporting.
 * - verification team: independent secondary verification **and** rating in one
 *   team (two roles, one team).
 * - report team: turns the graph into a theme-matched HTML deliverable using
 *   the operator-provided report template.
 */
import { TOOL_NAMES } from '../constants.js';
import { invalid, nodeId, nowIso, shortHash } from '../util.js';
import { applyOps } from '../ops.js';
import { engagementGaps } from '../project-completion.js';
import { supervisionShouldSpeak } from '../supervision-memory.js';
import { listUnreadWorkspaceFiles } from '../workspace-residue.js';
import { detectReportTheme } from '../theme.js';
import { renderHtmlReport, suggestedHtmlReportName } from '../report-html.js';
import { renderFindingHtmlReport, suggestedFindingReportName } from '../report-finding.js';
import { SELF_TEAM_ORDER, bootstrapSelfTeamOps, nativeTeammate, selfTeamOp } from '../self-teams.js';
import { ensureNativeTeams } from '../native-teams.js';
import { attemptsExhausted, isTerminalSecondary } from '../verify-queue.js';
import { mergeReportNarrative, runReportAi } from '../report-ai.js';
import {
  evidenceNodeOp,
  findingNodeOp,
  link,
  ref,
  supervisionNodeOp,
} from './build.js';
import { assertArgs, audit, optionalInteger, optionalString, registerAtkTool, requireEnum } from './common.js';
import {
  buildProgressBundle,
  buildSelfBriefPrompt,
  fallbackSelfBrief,
  formatSelfBrief,
  normalizeSelfBrief,
  parseSelfBrief,
} from '../loop/selftteam.js';
import {
  readSkills,
  resolveSkillDir,
} from '../loop/skills.js';
import { buildDetailBrief, detailWithSubagent, runSubagentText } from '../loop/supervisor.js';
import { redactPacket } from '../redact.js';
import { lastAuditId, latestOperatorSeq, nextPassDecision, passContinueMessage, passCoverageMessage, passImpactMessage, passRejectMessage, passWaitMessage, passesComplete } from '../test-passes.js';
import { escalationAttemptsExhausted, pendingEscalations, severityRankOf } from '../escalation-queue.js';
import { evidenceStamp } from '../verify-queue.js';

const ACTIONS = ['start', 'status', 'native', 'brief', 'detail', 'verify', 'report', 'stop', 'pass'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'start the lead, verification and report teams, optionally start supervision, sync native Agent Teams members, get a supervision brief, have the verification team write finding detail, run independent verification+rating, export a theme-matched HTML report, status, stop, or close one implicit test pass.' },
    team: { type: 'string', enum: ['lead', 'supervision', 'verification', 'report', 'all'], description: 'Limit start/status to one self-team. supervision is optional and is not started with all.' },
    limit: { type: 'integer', description: 'Maximum skills to retrieve/list (1-30).' },
    findingId: { type: 'string', description: 'Finding id or key for action=detail/verify; detail requires it; verify omitted picks the highest-priority unverified finding.' },
    verifyMode: { type: 'string', enum: ['evidence', 'network'], description: 'Secondary verification channel for action=verify (default evidence).' },
    cvssVector: { type: 'string', description: 'Optional CVSS v3.1 Base vector for the rating half of action=verify.' },
    cvss: { type: 'object', description: 'Optional CVSS v3.1 Base metrics for the rating half of action=verify.' },
    reportType: { type: 'string', enum: ['project', 'finding'], description: 'Report scope for action=report: entire project or one finding.' },
    theme: { type: 'string', enum: ['auto', 'light', 'dark'], description: 'HTML report theme for action=report; auto reads the DSH ui-theme preference and falls back to light.' },
    path: { type: 'string', description: 'Optional output basename for action=report.' },
    outcome: { type: 'string', enum: ['raised', 'unchanged'], description: 'Harm-escalation result for action=escalate. raised records a new finding; unchanged records an attempt.' },
    title: { type: 'string', description: 'Title of the new higher-harm finding for action=escalate outcome=raised.' },
    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'], description: 'Severity of the new finding for action=escalate outcome=raised. It must be higher than the source.' },
    proof: { type: 'string', description: 'Proof that the harm increased, for action=escalate outcome=raised. Without this text the raise is not recorded.' },
  },
};

function selfTeamNode(state, type) {
  return Object.values(state.nodes ?? {}).find((node) => node.kind === 'self_team' && node.attrs?.type === type);
}

function latestLoop(state) {
  return Object.values(state.nodes ?? {}).find((node) => node.kind === 'loop');
}

function latestRoundSupervision(state) {
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'supervision' && node.attrs?.type === 'round_plan')
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0))[0];
}

function latestSelfBrief(state) {
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'supervision' && node.attrs?.type === 'self_team_brief')
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0))[0];
}

function findFinding(state, identifier) {
  if (typeof identifier !== 'string' || identifier.length === 0) return undefined;
  return Object.values(state.nodes ?? {}).find((node) => node.kind === 'finding' && (node.id === identifier || node.key === identifier || node.label === identifier));
}

function pickVerificationTarget(state) {
  const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'finding' && !isTerminalSecondary(node.attrs))
    .sort((a, b) => {
      const pausedA = attemptsExhausted(a) ? 1 : 0;
      const pausedB = attemptsExhausted(b) ? 1 : 0;
      if (pausedA !== pausedB) return pausedA - pausedB;
      const verifiedA = ['verified', 'exploited', 'impacted'].includes(a.status) ? 1 : 0;
      const verifiedB = ['verified', 'exploited', 'impacted'].includes(b.status) ? 1 : 0;
      if (verifiedA !== verifiedB) return verifiedA - verifiedB;
      const sevA = rank[String(a.attrs?.severity ?? '').toLowerCase()] || 0;
      const sevB = rank[String(b.attrs?.severity ?? '').toLowerCase()] || 0;
      return sevB - sevA || String(a.label).localeCompare(String(b.label));
    })[0];
}

function detailPatchFrom(details) {
  const source = details !== null && typeof details === 'object' ? details : {};
  const hasChinese = (value) => /[\u3400-\u9fff]/u.test(String(value ?? ''));
  const patch = {};
  for (const [field, max] of [['description', 5000], ['impact', 5000], ['remediation', 4000], ['repro', 5000]]) {
    const value = String(source[field] ?? '').trim();
    if (value.length > 0 && hasChinese(value)) patch[field] = value.slice(0, max);
  }
  for (const [field, max] of [['request', 9000], ['response', 9000]]) {
    const value = String(source[field] ?? '').trim();
    if (value.length > 0) patch[field] = redactPacket(value, max);
  }
  const coreComplete = ['description', 'impact', 'repro'].every((field) => /[\u3400-\u9fff]/u.test(String(source[field] ?? '')));
  if (Object.keys(patch).length > 0 && coreComplete) {
    patch.detailSource = 'ai-verification-team';
    patch.detailAt = nowIso();
  } else if (Object.keys(patch).length > 0) {
    patch.detailPartial = true;
  }
  return patch;
}

function requireLead(ctx, agent, action) {
  const teams = (() => { try { return ctx.get('agentTeams'); } catch { return undefined; } })();
  if (teams === undefined || teams === null) return;
  try {
    const member = teams.membership(agent);
    if (member.role === 'lead') return;
    if (action === 'escalate' && String(member.name ?? '') === 'atk-escalator') return;
    invalid('atkbrain_selftteam requires the Team Lead');
  } catch (error) {
    if (error instanceof Error && error.message === 'atkbrain_selftteam requires the Team Lead') throw error;
    /* standalone session */
  }
}

function teamOp(state, type, patch = {}) {
  return selfTeamOp(state, type, patch);
}

export function registerSelfTeamTool(ctx, config, runtime) {
  registerAtkTool(ctx, config, runtime, {
    name: TOOL_NAMES.selftteam,
    callTitle: 'Five agent teams (御者/从者/二次验证/危害提升/报告撰写)',
    description: 'Manage AtkBrain auxiliary teams around the main pentest team. Verification+rating is ONE team that independently verifies a finding and rates it. The report team exports a light/dark HTML report from the operator template. Supervision is optional and is not started automatically. Harm escalation is not included. Actions: start, brief, verify, pass, report (reportType=project|finding), status, stop.',
    parameters: PARAMETERS,
    timeoutMs: 300000,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (args.team !== undefined) requireEnum(args, 'team', ['lead', 'supervision', 'verification', 'report', 'all']);
      if (args.limit !== undefined) optionalInteger(args, 'limit', { min: 1, max: 30 });
      if (args.verifyMode !== undefined) requireEnum(args, 'verifyMode', ['evidence', 'network']);
      if (args.theme !== undefined) requireEnum(args, 'theme', ['auto', 'light', 'dark']);
      if (args.reportType !== undefined) requireEnum(args, 'reportType', ['project', 'finding']);
      if (args.findingId !== undefined && (typeof args.findingId !== 'string' || args.findingId.trim().length === 0)) invalid('findingId must be a non-empty string');
      if (args.path !== undefined && (typeof args.path !== 'string' || args.path.trim().length === 0)) invalid('path must be a non-empty string');
      if (args.outcome !== undefined) requireEnum(args, 'outcome', ['raised', 'unchanged']);
      if (args.severity !== undefined) requireEnum(args, 'severity', ['critical', 'high', 'medium', 'low', 'info']);
      if (args.title !== undefined) optionalString(args, 'title', { max: 300 });
      if (args.proof !== undefined) optionalString(args, 'proof', { max: 4000 });
      return action;
    },
    async run({ args, state, exec, ctx: toolCtx, config: cfg, deps }) {
      requireLead(toolCtx, exec.agent, args.action);
      const workspace = deps.workspace(exec.agent);
      const skillDir = resolveSkillDir(workspace, cfg);
      const limit = Math.max(1, Math.min(30, Number(args.limit) || Number(cfg.skillTopK) || 6));

      if (args.action === 'start') {
        if (cfg.selfTeamMode === 'off') invalid('selfTeamMode is off; enable it in the AtkBrain config first');
        const ops = [];
        const allTeams = [...SELF_TEAM_ORDER];
        const wanted = args.team === undefined || args.team === 'all' ? allTeams : [args.team];
        if (wanted.includes('escalation')) invalid('the harm-escalation team is not included in this edition');
        for (const type of wanted) {
          ops.push(teamOp(state, type, { status: 'active', ...(type === 'lead' ? { mode: 'main' } : { mode: 'subagents' }), skillDir }));
        }
        ops.push(audit(TOOL_NAMES.selftteam, 'selftteam.start', wanted.join(','), 'auxiliary teams active', []));
        return {
          summary: `Self-teams active: 从者、二次验证和报告撰写已启动。监督团队需要时再单独启动。Report team serves both project and single-finding HTML reports; verification & rating are ONE team (verifier + rater). 从者 is the main executor.`,
          ops,
          details: { teams: wanted, mode: 'subagents', skillDir },
        };
      }

      if (args.action === 'status') {
        const teams = Object.values(state.nodes ?? {}).filter((node) => node.kind === 'self_team');
        const skills = await readSkills(skillDir).catch(() => []);
        const brief = latestSelfBrief(state);
        const filtered = args.team === undefined || args.team === 'all' ? teams : teams.filter((team) => team.attrs?.type === args.team);
        const repairOps = bootstrapSelfTeamOps(state);
        return {
          summary: `${filtered.length} agent team(s) recorded (御者/从者/二次验证/危害提升/报告撰写) (${[...new Set(filtered.map((team) => team.attrs?.type).filter(Boolean))].join('/')})${repairOps.length > 0 ? `；本次自动补齐/迁移 ${repairOps.length} 个团队 -> 五团队` : '；五团队已完整'}; latest brief ${brief ? `round ${brief.attrs?.round ?? 0} (deadlock ${brief.attrs?.deadlockRisk ?? 'unknown'}; handoff ${brief.attrs?.handoff?.status ?? 'legacy'} → ${brief.attrs?.handoff?.to ?? 'executor'})` : 'none'}${(() => { const report = selfTeamNode(state, 'report'); return report?.attrs?.lastReportPath ? `; latest report ${report.attrs.lastReportPath} (${report.attrs.lastReportTheme ?? 'unknown'} / ${report.attrs.themeSource ?? 'unknown'})` : ''; })()}.`,
          ops: repairOps,
          details: {
            teams: filtered.map((team) => ({
              type: team.attrs?.type,
              status: team.status,
              members: team.attrs?.members,
              nativeId: team.attrs?.nativeId ?? null,
              nativeName: team.attrs?.nativeName ?? null,
              nativeStatus: team.attrs?.nativeStatus ?? null,
              lastChildId: team.attrs?.lastChildId ?? null,
              lastChildVia: team.attrs?.lastChildVia ?? null,
              lastBriefAt: team.attrs?.lastBriefAt,
              lastDistillAt: team.attrs?.lastDistillAt,
              lastVerifyAt: team.attrs?.lastVerifyAt,
              lastReportAt: team.attrs?.lastReportAt,
              lastReportPath: team.attrs?.lastReportPath,
              lastReportTheme: team.attrs?.lastReportTheme,
              themeSource: team.attrs?.themeSource,
              verifiedCount: team.attrs?.verifiedCount,
              ratedCount: team.attrs?.ratedCount,
            })),
            skills: skills.slice(0, limit),
            latestBrief: brief?.attrs ?? null,
            repairedTeams: repairOps.map((op) => op.attrs?.type).filter(Boolean),
            skillDir,
          },
        };
      }

      if (args.action === 'native') {
        const agentTeams = (() => { try { return toolCtx.get('agentTeams'); } catch { return undefined; } })();
        const native = await ensureNativeTeams({ agentTeams, agent: exec.agent, signal: exec.signal });
        const ops = bootstrapSelfTeamOps(state);
        for (const member of [...native.spawned, ...native.existing]) {
          if (!SELF_TEAM_ORDER.includes(member.teamType)) continue;
          ops.push(selfTeamOp(state, member.teamType, {
            status: member.status ?? 'active',
            nativeName: member.name,
            nativeId: member.id ?? null,
            nativeStatus: member.status ?? null,
          }));
        }
        const created = native.spawned.map((member) => member.name).join(', ');
        const existing = native.existing.map((member) => member.name).join(', ');
        const failed = native.errors.map((entry) => `${entry.name}: ${entry.error}`).join('; ');
        return {
          summary: native.available
            ? `Native DSH Agent Teams: ${native.spawned.length} spawned${created ? ` (${created})` : ''}, ${native.existing.length} existing${existing ? ` (${existing})` : ''}${failed ? `; failed: ${failed}` : ''}.`
            : 'Native Agent Teams service is not available; graph teams remain recorded.',
          ops,
          details: { native, names: { spawned: native.spawned, existing: native.existing, failed: native.errors } },
        };
      }

      if (args.action === 'stop') {
        const ops = [];
        for (const type of SELF_TEAM_ORDER) {
          if (selfTeamNode(state, type) !== undefined) ops.push(teamOp(state, type, { status: 'stopped' }));
        }
        ops.push(audit(TOOL_NAMES.selftteam, 'selftteam.stop', 'self-teams', 'stopped', []));
        return {
          summary: 'Self-teams stopped. Existing skills and reports remain in the graph/library.',
          ops,
          details: { stopped: true },
        };
      }

      if (args.action === 'brief') {
        if (args.team !== undefined && args.team !== 'all' && args.team !== 'supervision') invalid('brief applies to the supervision team; use action=verify/distill/report for the other teams');
        if (!supervisionShouldSpeak(Object.values(state.nodes ?? {}))) {
          return {
            summary: '监督先不说话。图谱里还没有从者会忘掉的观察，开场不需要简报。',
            ops: [],
            details: { silent: true, reason: 'no recorded work to hand back' },
          };
        }
        const bootstrapOps = bootstrapSelfTeamOps(state);
        const loop = latestLoop(state);
        const latest = latestRoundSupervision(state);
        const round = Number(loop?.attrs?.round) || Number(latest?.attrs?.round) || 0;
        const bundle = buildProgressBundle({ state, loop, latest, round });
        bundle.unreadFiles = await listUnreadWorkspaceFiles(exec.agent, Object.values(state.nodes ?? {}));
        const prompt = buildSelfBriefPrompt(bundle);
        const result = await runSubagentText({
          ctx: toolCtx,
          agent: exec.agent,
          brief: prompt,
          signal: exec.signal,
          timeoutMs: cfg.selfTeamTimeoutMs,
          label: 'AtkBrain self-supervision team',
          native: nativeTeammate(state, 'supervision'),
        });
        const parsed = parseSelfBrief(result.text);
        const report = normalizeSelfBrief(parsed, bundle);
        const source = parsed === null ? 'deterministic' : (result.via === 'native-team' ? 'native-team' : 'ai-subagent');
        const artifact = await deps.writeEvidence(
          exec.agent,
          `selftteam-brief-${round}-${shortHash(JSON.stringify(report), 10)}`,
          { generatedAt: nowIso(), round, bundle, report, source, error: result.error ?? null },
          'application/json',
        );
        const evidenceOp = evidenceNodeOp(state, {
          path: artifact.path,
          relative: artifact.relative,
          mediaType: artifact.mediaType,
          bytes: artifact.bytes,
          sha256: artifact.sha256,
          label: `self-team brief round ${round}`,
        });
        const supervisionOp = supervisionNodeOp(state, {
          type: 'self_team_brief',
          round,
          verdict: report.deadlockRisk === 'high' ? 'pivot' : 'hold',
          diagnosis: report.progressSummary,
          nextPlan: report.advice,
          mustIntents: [],
          banRepeats: [],
          stopRecommended: false,
          confidence: report.confidence,
          source,
          childId: result.childId,
          teamType: 'supervision',
          progressSummary: report.progressSummary,
          gained: report.gained,
          missed: report.missed,
          advice: report.advice,
          antiDeadlock: report.antiDeadlock,
          recommendedNext: report.recommendedNext,
          deadlockRisk: report.deadlockRisk,
          artifactPath: artifact.relative,
          handoff: {
            from: 'supervisor',
            to: 'executor',
            channel: 'tool_result',
            status: 'delivered',
            deliveredAt: nowIso(),
            directive: String(report.advice ?? '').slice(0, 1200),
            targetGaps: Number(bundle?.targets?.totals?.untested ?? 0) + Number(bundle?.targets?.totals?.recon ?? 0),
            source,
            supervisorChildId: result.childId ?? null,
          },
        });
        const ops = [...bootstrapOps, evidenceOp, supervisionOp, teamOp(state, 'supervision', {
          status: 'active',
          lastBriefAt: nowIso(),
          lastBriefPath: artifact.relative,
          lastChildId: result.childId ?? null,
          lastChildVia: result.via ?? null,
          skillDir,
        })];
        const supervisor = selfTeamNode(state, 'supervision');
        if (supervisor !== undefined) ops.push(link({ kind: 'supervision', key: supervisionOp.key }, { kind: 'self_team', key: supervisor.key }, 'reports_to', { confidence: 0.8 }));
        if (loop !== undefined) ops.push(link({ kind: 'supervision', key: supervisionOp.key }, { kind: 'loop', key: loop.key }, 'supervises', { confidence: 0.7 }));
        ops.push(audit(TOOL_NAMES.selftteam, 'selftteam.brief', `round ${round}`, `${source}; deadlock=${report.deadlockRisk}`, [artifact.sha256]));
        return {
          summary: `Supervisor → Executor brief (${source}; executor must read before the next action)${report.deadlockRisk === 'high' ? ' [PIVOT REQUIRED]' : ''}\n${formatSelfBrief(report)}\nArtifact: ${artifact.relative}`,
          ops,
          details: {
            report,
            source,
            bundle,
            artifact,
            repairedTeams: bootstrapOps.map((op) => op.attrs?.type).filter(Boolean),
            handoff: {
              from: 'supervisor',
              to: 'executor',
              channel: 'tool_result',
              status: 'delivered',
              directive: String(report.advice ?? '').slice(0, 1200),
              targetGaps: Number(bundle?.targets?.totals?.untested ?? 0) + Number(bundle?.targets?.totals?.recon ?? 0),
              supervisorChildId: result.childId ?? null,
            },
            error: result.error ?? null,
          },
        };
      }

      if (args.action === 'detail') {
        if (args.team !== undefined && args.team !== 'all' && args.team !== 'verification') {
          invalid('detail applies to the verification & rating team; use action=brief/distill/report for the other teams');
        }
        if (args.findingId === undefined) invalid('detail requires findingId');
        const finding = findFinding(state, args.findingId);
        if (finding === undefined) invalid(`finding not found: ${args.findingId}`);
        const brief = buildDetailBrief({ state, finding });
        const result = await detailWithSubagent({
          ctx: toolCtx,
          agent: exec.agent,
          brief,
          signal: exec.signal,
          timeoutMs: cfg.detailTimeoutMs ?? cfg.verifierTimeoutMs ?? 120000,
          native: nativeTeammate(state, 'verification'),
        });
        if (result.details === null) invalid(`detail writer unavailable: ${result.error ?? 'unknown error'}`);
        const details = result.details;
        const artifact = await deps.writeEvidence(
          exec.agent,
          `detail-${shortHash(finding.key, 10)}`,
          {
            findingKey: finding.key,
            title: finding.attrs?.title ?? finding.label,
            source: 'ai-verification-team',
            details,
            childId: result.childId ?? null,
            at: nowIso(),
          },
          'application/json',
        );
        const evidenceOp = evidenceNodeOp(state, {
          path: artifact.path,
          relative: artifact.relative,
          mediaType: artifact.mediaType,
          bytes: artifact.bytes,
          sha256: artifact.sha256,
          label: `AI detail ${finding.label}`,
        });
        const evidenceId = nodeId('evidence', evidenceOp.key);
        const patch = { ...detailPatchFrom(details), detailEvidencePath: artifact.relative, detailChildId: result.childId ?? null };
        const findingOp = {
          op: 'node.upsert',
          kind: 'finding',
          key: finding.key,
          label: finding.label,
          attrs: { ...finding.attrs, ...patch },
          status: finding.status,
          confidence: finding.confidence,
          verification: finding.verification,
          evidenceIds: [...new Set([...(Array.isArray(finding.evidenceIds) ? finding.evidenceIds : []), evidenceId])],
        };
        const supervisionOp = supervisionNodeOp(state, {
          type: 'finding_detail',
          round: 0,
          verdict: 'recorded',
          diagnosis: String(details.description ?? '').slice(0, 1200),
          nextPlan: 'Use this detail for the finding page/report; verification status is unchanged.',
          findingKey: finding.key,
          childId: result.childId ?? null,
          source: 'ai-subagent',
          confidence: details.confidence ?? 0.7,
          evidenceIds: [evidenceId],
        });
        const ops = [evidenceOp, findingOp, supervisionOp];
        ops.push(link({ kind: 'evidence', key: evidenceOp.key }, { kind: 'finding', key: finding.key }, 'proves', { confidence: 0.8 }));
        const verificationTeam = selfTeamNode(state, 'verification');
        if (verificationTeam !== undefined) ops.push(link({ kind: 'self_team', key: verificationTeam.key }, { kind: 'finding', key: finding.key }, 'targets', { confidence: 0.7 }));
        ops.push(audit(TOOL_NAMES.selftteam, 'selftteam.detail', finding.key, 'ai-verification-team', [artifact.sha256]));
        return {
          summary: `Detail written by verification team for ${finding.label} (status unchanged: ${finding.status}). ${String(details.description ?? '').slice(0, 300)}`,
          ops,
          details: {
            finding: finding.key,
            description: details.description,
            impact: details.impact,
            remediation: details.remediation,
            repro: details.repro,
            evidence: artifact.relative,
            childId: result.childId ?? null,
            detailSource: 'ai-verification-team',
          },
        };
      }

      if (args.action === 'verify') {
        if (args.team !== undefined && args.team !== 'all' && args.team !== 'verification') {
          invalid('verify applies to the verification & rating team; use action=brief/distill/report for the other teams');
        }
        const finding = args.findingId === undefined ? pickVerificationTarget(state) : findFinding(state, args.findingId);
        if (finding === undefined) {
          const candidates = Object.values(state.nodes ?? {})
            .filter((node) => node.kind === 'finding')
            .slice(0, 8)
            .map((node) => `${node.id} (${node.attrs?.title ?? node.label})`);
          invalid(`no finding matched "${args.findingId}"; pass a finding id/key. Available: ${candidates.join('; ') || 'none recorded'}`);
        }
        const superviseTool = (() => {
          try { return toolCtx.tools.get(TOOL_NAMES.supervise); } catch { return undefined; }
        })();
        if (superviseTool === undefined) invalid('atkbrain_supervise is not registered, so the verification team cannot run');
        const callContext = (suffix) => ({
          agent: exec.agent,
          callId: `${exec.callId}-${suffix}`,
          name: TOOL_NAMES.supervise,
          signal: exec.signal,
        });
        const verifyArgs = {
          action: 'verify',
          findingId: finding.id,
          verifyMode: args.verifyMode ?? 'evidence',
        };
        const verifyValue = await superviseTool.execute(verifyArgs, {
          ...callContext('verify'),
          arguments: verifyArgs,
        });
        const verifyOps = Array.isArray(verifyValue?.ops) ? verifyValue.ops : [];
        const working = applyOps(state, verifyOps);
        const verifiedNode = Object.values(working.nodes ?? {}).find((node) => node.kind === 'finding' && node.key === finding.key);
        const rateArgs = { action: 'rate', findingId: finding.id };
        if (args.cvssVector !== undefined) rateArgs.cvssVector = args.cvssVector;
        else if (typeof verifyValue?.details?.cvssVector === 'string' && verifyValue.details.cvssVector.length > 0) {
          rateArgs.cvssVector = verifyValue.details.cvssVector;
        }
        if (args.cvss !== undefined) rateArgs.cvss = args.cvss;
        else if (args.cvssVector === undefined && verifyValue?.details?.cvssVector === undefined
          && verifyValue?.details?.cvss !== null && verifyValue?.details?.cvss !== undefined) {
          rateArgs.cvss = verifyValue.details.cvss;
        }
        let rateValue;
        let rateError = null;
        try {
          rateValue = await superviseTool.execute(rateArgs, {
            ...callContext('rate'),
            arguments: rateArgs,
          });
        } catch (error) {
          rateError = error instanceof Error ? error.message : String(error);
          rateValue = { summary: `Rating failed: ${rateError}`, ops: [] };
        }
        const rateOps = (Array.isArray(rateValue?.ops) ? rateValue.ops : []).map((op) => {
          if (op?.op !== 'node.upsert' || op.kind !== 'finding') return op;
          if (op.key !== finding.key && op.id !== verifiedNode?.id) return op;
          return {
            ...op,
            attrs: { ...(verifiedNode?.attrs ?? {}), ...(op.attrs ?? {}) },
            status: verifiedNode?.status ?? op.status,
            verification: verifiedNode?.verification ?? op.verification,
            evidenceIds: verifiedNode?.evidenceIds ?? op.evidenceIds,
          };
        });
        const verdict = verifyValue?.details?.verdict ?? verifiedNode?.attrs?.secondaryVerdict ?? 'inconclusive';
        const rating = rateValue?.details?.rating ?? verifiedNode?.attrs?.redteamRating ?? null;
        const verificationTeam = selfTeamNode(state, 'verification');
        const ops = [...verifyOps, ...rateOps];
        if (verificationTeam !== undefined) {
          ops.push(link({ kind: 'self_team', key: verificationTeam.key }, { kind: 'finding', key: finding.key }, 'targets', { confidence: 0.75 }));
          for (const op of [...verifyOps, ...rateOps]) {
            if (op?.op === 'node.upsert' && op.kind === 'supervision' && String(op.attrs?.type ?? '').match(/finding_verification|rating/u)) {
              ops.push(link({ kind: 'supervision', key: op.key }, { kind: 'self_team', key: verificationTeam.key }, 'reports_to', { confidence: 0.8 }));
            }
          }
        }
        ops.push(teamOp(state, 'verification', {
          status: 'active',
          lastVerifyAt: nowIso(),
          verifiedCount: (Number(verificationTeam?.attrs?.verifiedCount) || 0) + (verdict === 'verified' ? 1 : 0),
          ratedCount: (Number(verificationTeam?.attrs?.ratedCount) || 0) + (rating === null ? 0 : 1),
          lastChildId: verifyValue?.details?.childId ?? null,
          lastChildVia: verifyValue?.details?.via ?? null,
          skillDir,
        }));
        ops.push(audit(TOOL_NAMES.selftteam, 'selftteam.verify', finding.key, `${verdict}/${rating ?? 'unrated'}`, rateOps.length > 0 ? [] : []));
        return {
          summary: `Verification & rating team: ${finding.label} → verification ${verdict}${rating === null ? '' : `, operational rating ${rating}`}${rateError === null ? '' : `; warning: ${rateError}`}.\n${verifyValue?.summary ?? ''}\n${rateValue?.summary ?? ''}`,
          ops,
          details: {
            finding: finding.key,
            verdict,
            rating,
            verifyMode: args.verifyMode ?? 'evidence',
            ratingSource: rateValue?.details?.ratingSource ?? null,
            rateError,
          },
        };
      }

      if (args.action === 'pass') {
        const decision = nextPassDecision(state);
        if (decision.action === 'complete') {
          return {
            summary: `测试轮次已经结束（已记下 ${decision.count} 轮）。可以写项目报告并给出唯一一份结果。`,
            ops: [],
            details: { complete: true, count: decision.count, gaps: decision.gaps },
          };
        }
        if (decision.action === 'reject') {
          invalid(decision.reason === 'impact'
            ? passImpactMessage(decision.count)
            : decision.reason === 'operator'
              ? passWaitMessage(decision.count)
              : decision.reason === 'coverage'
                ? passCoverageMessage(decision.count, decision.classes)
                : passRejectMessage(decision.count, decision.gaps));
        }
        const exhausted = decision.basis === 'exhausted';
        const ops = [
          supervisionNodeOp(state, {
            type: 'test_pass',
            round: decision.round,
            verdict: exhausted ? 'stop' : 'hold',
            diagnosis: decision.basis,
            basis: decision.basis,
            nextPlan: exhausted
              ? '授权范围内没有剩余缺口。可以写项目报告并给出唯一一份结果。'
              : '接着同一本账，总目标不变，继续整次授权测试。不要把结果交给操作员。',
            source: 'deterministic',
            planHash: `test-pass-${decision.round}-${decision.basis}`,
            auditCursor: lastAuditId(state),
            operatorSeq: decision.operatorSeq ?? latestOperatorSeq(state),
            stopRecommended: exhausted || decision.round >= 3,
          }),
          audit(TOOL_NAMES.selftteam, 'selftteam.pass', `round ${decision.round}`, decision.basis, []),
        ];
        const complete = exhausted || decision.round >= 3;
        return {
          summary: complete
            ? `第 ${decision.round} 轮已记下（${exhausted ? '授权范围内没有剩余缺口' : '三轮已齐'}）。可以写项目报告并给出唯一一份结果。`
            : `第 ${decision.round} 轮已记下。${passContinueMessage(decision.round)}`,
          ops,
          details: { complete, round: decision.round, basis: decision.basis, gaps: decision.gaps },
        };
      }

      if (args.action === 'escalate') {
        invalid('the harm-escalation team is not included in this edition');
        const queued = pendingEscalations(state);
        const source = args.findingId === undefined
          ? queued[0]
          : Object.values(state.nodes ?? {}).find((node) => node.kind === 'finding' && (node.id === args.findingId || node.key === args.findingId || node.label === args.findingId));
        if (source === undefined) invalid('action=escalate requires a finding that is still on the vulnerability page');
        if (String(source.attrs?.secondaryVerdict ?? '').toLowerCase() === 'refuted') invalid('a refuted finding is not escalated');
        if (!queued.some((node) => node.id === source.id)) {
          if (escalationAttemptsExhausted(source)) invalid('这条漏洞的危害提升已暂停，证据没有变化');
          invalid('这条漏洞不在危害提升队列里');
        }
        const outcome = args.outcome ?? 'unchanged';
        if (outcome === 'unchanged') {
          const attempts = (Number(source.attrs?.escalationAttempts) || 0) + 1;
          return {
            summary: `危害提升未提高 ${source.label}。这是第 ${attempts} 次，证据不变时最多 3 次。`,
            ops: [{
              op: 'node.upsert',
              kind: 'finding',
              key: source.key,
              label: source.label,
              attrs: {
                escalationAttempts: attempts,
                escalationAttemptEvidence: evidenceStamp(source),
              },
              status: source.status,
              verification: source.verification,
            }, audit(TOOL_NAMES.selftteam, 'selftteam.escalate', source.key, 'unchanged', [])],
            details: { outcome: 'unchanged', findingId: source.id, attempts },
          };
        }
        const proof = String(args.proof ?? '').trim();
        const givenTitle = String(args.title ?? '').trim();
        const title = givenTitle === '手工记录漏洞' || /^manual(?:-finding)?$/iu.test(givenTitle) ? '漏洞危害提升成功' : givenTitle;
        const severity = String(args.severity ?? '').toLowerCase();
        if (proof.length === 0) invalid('危害提升成功必须写上证明危害已经提高的说明');
        if (title.length === 0) invalid('危害提升成功必须写上新漏洞的名称');
        if (!['critical', 'high', 'medium', 'low', 'info'].includes(severity)) invalid('危害提升成功必须写上新的危害等级');
        if (severityRankOf({ severity }) <= severityRankOf(source.attrs ?? {})) invalid('新漏洞的危害等级必须高于原来的漏洞');
        const fromSeverity = ['critical', 'high', 'medium', 'low', 'info'].includes(String(source.attrs?.severity ?? '').toLowerCase())
          ? String(source.attrs.severity).toLowerCase()
          : 'unknown';
        const endpoint = String(title).match(/(?:^|[\s(])(\/?[A-Za-z0-9_.!-]+\.(?:action|jsp|do|php|aspx))/u);
        const created = findingNodeOp(state, {
          template: typeof args.template === 'string' && args.template.trim().length > 0 ? args.template.trim() : 'manual-finding',
          title,
          severity,
          ...(endpoint !== null ? { interfacePath: endpoint[1].startsWith('/') ? endpoint[1] : `/${endpoint[1]}` } : {}),
          evidence: proof,
          escalationProof: proof,
          escalatedFromId: source.id,
          escalatedFromTitle: source.attrs?.title || source.label,
          escalatedFromSeverity: fromSeverity,
          escalatedToSeverity: severity,
          status: 'candidate',
        });
        const ops = [created];
        const assetIds = new Set();
        for (const edge of Object.values(state.edges ?? {})) {
          if (edge.to !== source.id || edge.kind !== 'affects') continue;
          const asset = state.nodes[edge.from];
          if (asset === undefined || assetIds.has(asset.id)) continue;
          assetIds.add(asset.id);
          ops.push(link(ref(asset.kind, asset.key), ref('finding', created.key), 'affects', { confidence: 0.8 }));
        }
        ops.push(link(ref('finding', source.key), ref('finding', created.key), 'escalates_to', { confidence: 0.9 }));
        ops.push(audit(TOOL_NAMES.selftteam, 'selftteam.escalate', source.key, `raised ${severity}`, []));
        return {
          summary: `危害提升已记下：${source.attrs?.title || source.label} → ${title}，${fromSeverity} → ${severity}。`,
          ops,
          details: {
            outcome: 'raised',
            fromId: source.id,
            toKey: created.key,
            fromTitle: source.attrs?.title || source.label,
            toTitle: title,
            fromSeverity,
            toSeverity: severity,
          },
        };
      }

      if (args.action === 'report') {
        if (args.team !== undefined && args.team !== 'all' && args.team !== 'report') {
          invalid('report applies to the report-writing team; use action=brief/verify/distill for the other teams');
        }
        const reportType = args.reportType ?? (args.findingId === undefined ? 'project' : 'finding');
        if (reportType === 'finding') {
          const finding = Object.values(state.nodes ?? {}).find((node) => node.kind === 'finding'
            && (node.id === args.findingId || node.key === args.findingId || node.label === args.findingId));
          if (finding === undefined) invalid('reportType=finding requires a valid findingId');
          const themeInfo = await detectReportTheme({ ctx: toolCtx, config: cfg, explicit: args.theme ?? 'auto' });
          const generatedAt = nowIso();
          const html = await renderFindingHtmlReport(state, finding.id, {
            generatedAt,
            theme: themeInfo.theme,
            themeSource: themeInfo.source,
            reportTeam: '报告撰写团队',
          });
          const fileName = args.path === undefined
            ? suggestedFindingReportName(state.engagement, finding, generatedAt)
            : (args.path.endsWith('.html') ? args.path : `${args.path}.html`);
          const file = await deps.writeReportFile(exec.agent, fileName, html);
          const reportTeam = selfTeamNode(state, 'report');
          const ops = [teamOp(state, 'report', {
            status: 'active',
            lastFindingReportAt: nowIso(),
            lastFindingReportPath: file.relative,
            lastFindingReportId: finding.id,
            lastReportTheme: themeInfo.theme,
            themeSource: themeInfo.source,
          })];
          if (reportTeam !== undefined) {
            const verification = selfTeamNode(state, 'verification');
            if (verification !== undefined) ops.push(link({ kind: 'self_team', key: reportTeam.key }, { kind: 'self_team', key: verification.key }, 'reports_to', { confidence: 0.6 }));
          }
          ops.push(audit(TOOL_NAMES.selftteam, 'selftteam.finding-report', file.relative, `${themeInfo.theme} via ${themeInfo.source}; finding=${finding.key}`, [file.sha256]));
          return {
            summary: `单漏洞报告已写入 ${file.relative}（${themeInfo.theme} 主题）；finding ${finding.id}；${html.length} bytes，sha256 ${file.sha256.slice(0, 16)}…`,
            ops,
            details: { reportType: 'finding', findingId: finding.id, path: file.relative, absolutePath: file.path, theme: themeInfo.theme, themeSource: themeInfo.source, bytes: file.bytes, sha256: file.sha256 },
          };
        }
        if (!passesComplete(state)) invalid(passContinueMessage(Object.values(state.nodes ?? {}).filter((node) => node.kind === 'supervision' && node.attrs?.type === 'test_pass').length));
        const themeInfo = await detectReportTheme({ ctx: toolCtx, config: cfg, explicit: args.theme ?? 'auto' });
        const generatedAt = nowIso();
        let narrative = null;
        let aiError = null;
        let aiChildId = null;
        let aiVia = null;
        if (cfg.reportAi !== false) {
          const ai = await runReportAi({
            ctx: toolCtx,
            agent: exec.agent,
            state,
            signal: exec.signal,
            timeoutMs: cfg.reportAiTimeoutMs ?? cfg.selfTeamTimeoutMs ?? 120000,
          });
          narrative = ai.narrative;
          aiError = ai.error;
          aiChildId = ai.childId ?? null;
          aiVia = ai.via ?? null;
        }
        const renderState = narrative === null ? state : mergeReportNarrative(state, narrative);
        const html = await renderHtmlReport(renderState, {
          generatedAt,
          theme: themeInfo.theme,
          themeSource: themeInfo.source,
          reportTeam: '报告撰写团队',
          narrative,
        });
        const fileName = args.path === undefined
          ? suggestedHtmlReportName(state.engagement, generatedAt)
          : (args.path.endsWith('.html') ? args.path : `${args.path}.html`);
        const file = await deps.writeReportFile(exec.agent, fileName, html);
        const gaps = engagementGaps(state);
        const reportKind = gaps.length === 0 ? 'project' : 'draft';
        const reportTeam = selfTeamNode(state, 'report');
        const ops = [teamOp(state, 'report', {
          status: 'active',
          lastReportAt: nowIso(),
          lastReportPath: file.relative,
          lastReportKind: reportKind,
          lastReportTheme: themeInfo.theme,
          themeSource: themeInfo.source,
          lastChildId: aiChildId,
          lastChildVia: aiVia,
          skillDir,
        })];
        if (reportTeam !== undefined) {
          const verification = selfTeamNode(state, 'verification');
          if (verification !== undefined) ops.push(link({ kind: 'self_team', key: reportTeam.key }, { kind: 'self_team', key: verification.key }, 'reports_to', { confidence: 0.6 }));
        }
        ops.push(audit(TOOL_NAMES.selftteam, 'selftteam.report', file.relative, `${themeInfo.theme} via ${themeInfo.source}; ${reportKind}`, [file.sha256]));
        const body = `Report team wrote ${file.relative} in ${themeInfo.theme} theme (${themeInfo.source}); ${narrative === null ? `template fallback${aiError ? ` (${aiError})` : ''}` : 'AI narrative'}; ${html.length} bytes, sha256 ${file.sha256.slice(0, 16)}…`;
        return {
          summary: reportKind === 'draft' ? `不要收尾。还缺：${gaps.join('、')}。${body}` : body,
          ops,
          details: { reportType: 'project', reportKind, gaps, path: file.relative, absolutePath: file.path, theme: themeInfo.theme, themeSource: themeInfo.source, bytes: file.bytes, sha256: file.sha256, aiWritten: narrative !== null, aiError, aiChildId },
        };
      }

      invalid('unsupported self-team action');
    },
  });
}
