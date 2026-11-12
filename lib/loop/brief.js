/**
 * Model-facing round / supervisor / evolution briefs.
 *
 * Briefs are bounded strings derived from graph state and loop state. They
 * never include raw credential values or raw sensitive-data samples; findings
 * expose only evidence references and short public text.
 */
import { snapshotGraph, scanProfile, findingSeverity } from './policy.js';
import { buildProgressBundle, fallbackSelfBrief } from './selftteam.js';
import { buildTargetTree } from '../targets.js';
import { formatSkillBlock } from './skills.js';
import { impactStillOpen } from '../test-passes.js';

const MAX_BRIEF = 14000;

function clip(value, length) {
  const text = String(value ?? '').replace(/\s+/gu, ' ').trim();
  return text.length > length ? `${text.slice(0, Math.max(0, length - 1))}…` : text;
}

function expectedText(value, length = 200) {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return clip(value, length);
  try { return clip(JSON.stringify(value), length); } catch { return '—'; }
}

function list(items, limit = 8) {
  return (Array.isArray(items) ? items : []).slice(0, limit).map((item) => clip(item, 180));
}

function loopAttrs(loop) {
  return loop?.attrs ?? {};
}

function findingLines(state, max = 8) {
  const findings = Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'finding' && node.status !== 'merged')
    .sort((a, b) => {
      const rank = (node) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 }[findingSeverity(node)] ?? 0);
      return rank(b) - rank(a) || String(b.lastSeen ?? '').localeCompare(String(a.lastSeen ?? ''));
    })
    .slice(0, max);
  return findings.map((node) => {
    const attrs = node.attrs ?? {};
    return {
      id: node.id,
      key: node.key,
      title: clip(attrs.title ?? node.label, 120),
      template: attrs.template ?? 'manual',
      severity: findingSeverity(node),
      status: node.status,
      verification: node.verification ?? 'unverified',
      secondaryVerified: attrs.secondaryVerified === true,
      redteamRating: attrs.redteamRating ?? null,
      claimGuard: attrs.claimGuard ?? null,
      evidenceIds: Array.isArray(node.evidenceIds) ? node.evidenceIds.slice(0, 4) : [],
    };
  });
}

function accessLines(state) {
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'access')
    .slice(0, 8)
    .map((node) => ({
      id: node.id,
      kind: node.attrs?.kind ?? 'access',
      privilege: node.attrs?.privilege ?? 'unknown',
      status: node.status,
      asset: node.attrs?.assetKey ?? null,
      proof: clip(node.attrs?.proof ?? '', 160),
    }));
}

function credentialLines(state) {
  return Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'credential')
    .slice(0, 8)
    .map((node) => ({
      id: node.id,
      username: node.attrs?.username ?? 'unknown',
      kind: node.attrs?.kind ?? 'password',
      validity: node.status,
      used: node.attrs?.used === true,
      secretMask: node.attrs?.secretMask ?? '[masked]',
      secretFp: node.attrs?.secretFp ?? null,
      privilege: node.attrs?.privilege ?? 'unknown',
    }));
}

function lessonLines(lessons) {
  return (Array.isArray(lessons) ? lessons : []).slice(0, 8).map((lesson) => ({
    key: lesson.lessonKey ?? lesson.key,
    idea: clip(lesson.idea, 220),
    method: clip(lesson.method, 220),
    route: clip(lesson.route ?? lesson.chain, 220),
    when: list(lesson.when, 6),
    do: list(lesson.do, 5),
    avoid: list(lesson.avoid, 5),
    confidence: Number(lesson.confidence) || 0,
  }));
}

function coverageLines(state) {
  const cells = Object.values(state.nodes ?? {}).filter((node) => node.kind === 'coverage');
  const open = cells.filter((node) => node.status === 'open' || node.status === 'claimed');
  return {
    total: cells.length,
    seen: cells.filter((node) => node.status === 'seen' || node.status === 'reported').length,
    open: open.slice(0, 10).map((node) => `${node.attrs?.path ?? node.key}×${node.attrs?.bugClass ?? 'unknown'}`),
  };
}

function hypothesisLines(state) {
  const rows = Object.values(state.nodes ?? {}).filter((node) => node.kind === 'hypothesis');
  const open = rows.filter((node) => node.status === 'open' || node.status === 'active');
  return {
    total: rows.length,
    verified: rows.filter((node) => node.status === 'verified').length,
    open: open.slice(0, 8).map((node) => `${node.attrs?.bugClass ?? 'hypothesis'} @ ${node.attrs?.targetKey ?? node.key}: ${clip(node.attrs?.strategy ?? node.label, 150)}`),
  };
}

function intentLines(intents, max = 8) {
  return (Array.isArray(intents) ? intents : []).slice(0, max).map((intent) => ({
    id: intent.id,
    actionType: intent.attrs?.actionType ?? intent.actionType,
    actionId: intent.attrs?.actionId ?? intent.actionId,
    target: intent.attrs?.targetLabel ?? intent.targetLabel,
    status: intent.status,
    priority: intent.attrs?.priority ?? intent.priority,
    expectedEvidence: intent.attrs?.expectedEvidence ?? intent.expectedEvidence,
    scope: intent.attrs?.scopeVerdict ?? intent.scopeVerdict,
  }));
}

function frontierLines(frontier, max = 10) {
  return (Array.isArray(frontier) ? frontier : [])
    .filter((action) => action.scope?.verdict !== 'deny')
    .slice(0, max)
    .map((action) => ({
      actionId: action.actionId,
      actionType: action.actionType,
      target: action.targetLabel,
      priority: action.priority,
      why: list(action.why, 3),
      scope: action.scope?.verdict,
      risk: action.risk,
    }));
}

function supervisionBlock(supervision) {
  if (supervision === null || supervision === undefined) {
    return 'No supervisor plan yet; deterministic gates below are authoritative.';
  }
  const attrs = supervision.attrs ?? {};
  return [
    `verdict: ${attrs.verdict ?? 'hold'} (${attrs.source ?? 'deterministic'})`,
    `diagnosis: ${clip(attrs.diagnosis, 700)}`,
    `next_plan: ${clip(attrs.nextPlan, 1200)}`,
    `must_intents: ${list(attrs.mustIntents, 6).join(', ') || '—'}`,
    `prefer_tactics: ${list(attrs.preferTactics, 8).join(', ') || '—'}`,
    `ban_repeats: ${list(attrs.banRepeats, 8).join(', ') || '—'}`,
    `stop_recommended: ${attrs.stopRecommended === true ? 'yes' : 'no'}${attrs.stopReason ? ` (${attrs.stopReason})` : ''}`,
  ].join('\n');
}

/** Build the compact, model-visible brief for one autonomous round. */
export function buildRoundBrief({ state, loop, supervision, lessons, intents, frontier, config }) {
  const attrs = loopAttrs(loop);
  const snapshot = snapshotGraph(state);
  const coverage = coverageLines(state);
  const hypotheses = hypothesisLines(state);
  const ring = scanProfile(attrs.ring ?? 1, config);
  const objective = attrs.objective ?? state.engagement?.name ?? 'engagement';
  const objectiveType = attrs.objectiveType ?? 'impact';
  const must = supervision?.attrs?.mustIntents ?? [];
  const selfBriefNode = Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'supervision' && node.attrs?.type === 'self_team_brief')
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0))[0];
  const selfReport = selfBriefNode?.attrs ?? fallbackSelfBrief(buildProgressBundle({
    state,
    loop,
    latest: supervision,
    round: attrs.round,
  }));
  const targetTree = buildTargetTree(state);
  const selfBriefAgeMinutes = selfBriefNode?.lastSeen
    ? Math.max(0, Math.floor((Date.now() - Date.parse(String(selfBriefNode.lastSeen))) / 60_000))
    : null;
  const selfBriefStale = selfBriefNode === undefined || (selfBriefAgeMinutes !== null && selfBriefAgeMinutes >= 10);
  const selfBriefHandoff = selfBriefNode?.attrs?.handoff ?? null;
  const skills = Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'skill' && node.status !== 'retired')
    .sort((a, b) => (Number(b.attrs?.confidence) || 0) - (Number(a.attrs?.confidence) || 0))
    .slice(0, Math.max(1, Number(config?.skillTopK) || 6))
    .map((node) => ({
      name: node.attrs?.name ?? node.label,
      summary: node.attrs?.summary ?? '',
      route: node.attrs?.route ?? '',
      when: node.attrs?.when ?? [],
      do: node.attrs?.do ?? [],
      confidence: Number(node.attrs?.confidence) || 0.5,
      path: node.attrs?.path ?? '',
    }));
  const skillBlock = formatSkillBlock(skills);
  const body = `# AtkBrain autonomous round ${attrs.round ?? 0}/${attrs.maxRounds ?? 0}

## Objective
${clip(objective, 900)}
Type: ${objectiveType}. Round ${attrs.round ?? 0}/${attrs.maxRounds ?? 0}; goal phase ${attrs.goalPhase ?? 'none'}; activation ${attrs.activation ?? 'disarmed'}.
Ring: ${ring.ring}/3 (ports ${ring.portSpec}; wordlist tier ${ring.wordlistTier}).
No-progress rounds: ${attrs.noProgressRounds ?? 0}; empty rounds: ${attrs.emptyRounds ?? 0}; stop: ${attrs.stopReason ?? 'none'}.

## Graph state
nodes=${snapshot.nodes} edges=${snapshot.edges} services=${snapshot.services} webapps=${snapshot.webapps}
verifiedFindings=${snapshot.verifiedFindings} highCriticalVerified=${snapshot.highCriticalVerified} candidateHighCritical=${snapshot.candidateHighCritical}
validatedAccess=${snapshot.validatedAccess} verifiedData=${snapshot.verifiedData} validCredentials=${snapshot.validCredentials} unusedCredentials=${snapshot.unusedCredentials}
teamReady=${snapshot.teamReady} teamMerged=${snapshot.teamMerged} openIntents=${snapshot.openIntents} claimedIntents=${snapshot.claimedIntents}

## Coverage / hypotheses
${impactStillOpen(state)
    ? `coverage=${coverage.total} cells remain open. Do not close them in bulk. A vulnerability is recorded and no validated access exists; raise that issue before more coverage.`
    : `coverage=${coverage.total} cells, ${coverage.seen} seen; open: ${coverage.open.join(', ') || 'none'}`}
hypotheses=${hypotheses.total} total, ${hypotheses.verified} verified; open: ${hypotheses.open.join('; ') || 'none'}

## Self-team progress (御者 → 从者; advisory handoff)
${selfReport.progressSummary ?? '—'}
Gained: ${(selfReport.gained ?? []).join('；') || '—'}
Missing: ${(selfReport.missed ?? []).join('；') || '—'}
Advice: ${selfReport.advice ?? '—'}
Anti-deadlock: ${(selfReport.antiDeadlock ?? []).join('；') || '—'}
Next: ${(selfReport.recommendedNext ?? []).join('；') || '—'}
Deadlock risk: ${selfReport.deadlockRisk ?? 'unknown'} (${selfReport.source ?? selfBriefNode?.attrs?.source ?? 'deterministic'})
Handoff: ${selfBriefNode === undefined ? 'NO AI SELF-BRIEF YET — call atkbrain_selftteam action=brief before acting' : selfBriefStale ? `STALE (${selfBriefAgeMinutes ?? '?'}m old) — call atkbrain_selftteam action=brief again` : `current (${selfBriefAgeMinutes ?? 0}m old; ${selfBriefHandoff?.status ?? 'delivered'} → ${selfBriefHandoff?.to ?? 'executor'})`}
Target coverage: ${targetTree.totals.tested}/${targetTree.totals.targets} tested, ${targetTree.totals.recon} recon-only, ${targetTree.totals.untested} untested; ${(targetTree.totals.unassignedCoverage ?? 0)} unbound coverage cell(s).

${skillBlock.length > 0 ? `${skillBlock}\n` : ''}

## Supervisor plan
${supervisionBlock(supervision)}

## Intents already assigned
${intentLines(intents).map((intent) => `- ${intent.id} | ${intent.actionType} | target ${intent.target} | ${intent.status} | expected ${expectedText(intent.expectedEvidence, 180)}`).join('\n') || '- none yet'}

## Evolution lessons (advisory; re-verify on this target)
${lessonLines(lessons).map((lesson) => `- [${lesson.key}] ${lesson.idea || lesson.method || lesson.route} | route ${lesson.route} | tactics ${lesson.do.join(', ') || '—'} | when ${lesson.when.join(', ') || '—'} | confidence ${lesson.confidence.toFixed(2)}`).join('\n') || '- none matched'}

## Allowed frontier
${frontierLines(frontier).map((action) => `- ${action.actionId} | ${action.actionType} | ${action.target} | p${action.priority} | ${action.why.join('; ')}`).join('\n') || '- no allowed action'}

## This round contract
- Execute at most ${attrs.maxActionsPerRound ?? 3} intent(s) from the assigned list; prefer the first must intent.
- Use atkbrain_probe with the ring port profile above; never widen scope or exceed RoE caps.
- Record concrete evidence (artifact path + sha256, command hash, marker) before marking anything verified.
- High/critical candidates require independent verification and secondary confirmation; verified high/critical impact must be pushed to access/data.
- If a refutation has only one observation channel, mark it stalled, not closed.
- Call atkbrain_loop action=resolve for each intent; then end this turn.
- If stop is required, call atkbrain_loop action=finish; do not invent new work.
- Never write raw secrets/PII to the graph, report, or chat. Credentials are mask/fingerprint only; data samples are redacted.
`;
  return {
    text: body.length > MAX_BRIEF ? `${body.slice(0, MAX_BRIEF)}\n[truncated]` : body,
    snapshot,
    ring,
    objective,
    objectiveType,
    must,
    allowed: frontierLines(frontier, 20),
    intents: intentLines(intents, 20),
    lessons: lessonLines(lessons),
  };
}

/** Brief for the fresh supervisor subagent (no tools; JSON plan only). */
export function buildSupervisorBrief({ state, loop, supervision, lessons, intents, frontier, config }) {
  const attrs = loopAttrs(loop);
  const snapshot = snapshotGraph(state);
  const coverage = coverageLines(state);
  const hypotheses = hypothesisLines(state);
  const previous = supervision?.attrs ?? {};
  const candidates = findingLines(state, 12);
  const evidence = Object.values(state.nodes ?? {})
    .filter((node) => node.kind === 'evidence')
    .slice(-8)
    .map((node) => ({ id: node.id, label: node.label, sha256: node.attrs?.sha256 ?? null, path: node.attrs?.relative ?? node.attrs?.path ?? null }));
  return `# AtkBrain supervisor brief

You are the independent supervisor (御者). The 从者 (executor) is the main pentest agent that will read your plan before acting; it may spawn child subagents. You are read-only: do not call tools, do not execute recon/exploitation, return one JSON object, no markdown fence, no prose.

## Engagement and scope
Engagement: ${clip(state.engagement?.name, 120)}
Authorization: ${clip(state.engagement?.authorization, 120)}
Allow entries: ${state.scope?.allow?.length ?? 0}; deny entries: ${state.scope?.deny?.length ?? 0}; RoE ${JSON.stringify(state.scope?.roe ?? {})}

## Loop
round=${attrs.round ?? 0}/${attrs.maxRounds ?? 0}; phase=${loop.status}; goal phase=${attrs.goalPhase ?? 'none'}; activation=${attrs.activation ?? 'disarmed'}
objectiveType=${attrs.objectiveType ?? 'impact'}; objective=${clip(attrs.objective, 800)}
noProgress=${attrs.noProgressRounds ?? 0}; empty=${attrs.emptyRounds ?? 0}; ring=${attrs.ring ?? 1}/3
previous plan: ${supervisionBlock(supervision)}

## Metrics
${JSON.stringify(snapshot)}

## Candidate / verified findings
${candidates.map((finding) => `- ${finding.id} | ${finding.severity} | ${finding.status} | secondary=${finding.secondaryVerified} | ${finding.title} | guard=${finding.claimGuard ?? 'none'} | evidence=${finding.evidenceIds.join(',') || 'none'}`).join('\n') || '- none'}

## Access and data
${accessLines(state).map((access) => `- ${access.id} | ${access.kind}/${access.privilege} | ${access.status} | asset ${access.asset}`).join('\n') || '- none'}
verifiedData=${snapshot.verifiedData}; threshold=${JSON.stringify(state.config?.bulkThresholds ?? config?.bulkThresholds ?? {})}

## Credentials (masked only)
${credentialLines(state).map((credential) => `- ${credential.id} | ${credential.username}/${credential.kind} | ${credential.validity} | used=${credential.used} | ${credential.secretMask} | ${credential.secretFp ?? ''}`).join('\n') || '- none'}

## Team
teamReady=${snapshot.teamReady}; teamMerged=${snapshot.teamMerged}

## Open intents
${intentLines(intents, 12).map((intent) => `- ${intent.id} | ${intent.actionType} | ${intent.target} | ${intent.status} | expected=${expectedText(intent.expectedEvidence, 160)}`).join('\n') || '- none'}

## Allowed frontier (choose only these ids)
${frontierLines(frontier, 14).map((action) => `- ${action.actionId} | ${action.actionType} | ${action.target} | p${action.priority} | ${action.why.join('; ')}`).join('\n') || '- none'}

## Evolution lessons (advisory)
${lessonLines(lessons).map((lesson) => `- ${lesson.key} | route ${lesson.route} | do ${lesson.do.join(', ')} | when ${lesson.when.join(', ')} | confidence ${lesson.confidence.toFixed(2)}`).join('\n') || '- none'}

## Evidence artifacts
${evidence.map((item) => `- ${item.id} | ${item.label} | ${item.sha256 ?? ''} | ${item.path ?? ''}`).join('\n') || '- none'}

## Decision rules
1. Never widen scope or propose a target whose scope is deny/unknown.
2. High/critical candidate must be verified first; verified high/critical must be pushed to access/data.
3. A single-channel failure is not a closed surface; do not allow false closeout.
4. Unproven RCE must not be rated high/critical.
5. If a team batch artifact is ready, merge it before new enumeration.
6. Prefer hold when the current intent is still open and progressing; pivot only with evidence of stall or a stronger impact path.
7. Stop only when objective is achieved or the loop budget/stall threshold is genuinely exhausted.

## Output JSON schema
{"verdict":"hold|pivot|verify|escalate|stop","diagnosis":"...","next_plan":"...","must_intents":["<actionId or intentId>"],"prefer_tactics":["..."],"ban_repeats":["..."],"stop_recommended":false,"stop_reason":null,"confidence":0.0}
`;
}

/** Brief for the fresh evolution-editor subagent. */
export function buildEvolveBrief({ state, episode, lessons }) {
  return `# AtkBrain evolution editor

You edit a cross-engagement pentest playbook. Read only; do not call tools. Return one JSON object, no markdown fence.

## Qualified episode (already confirmed; do not add hops or hosts)
${JSON.stringify(episode, null, 2)}

## Current playbook (avoid duplicates)
${(lessons ?? []).slice(0, 12).map((lesson) => `- key=${lesson.lessonKey} idea=${clip(lesson.idea, 180)} method=${clip(lesson.method, 180)} route=${clip(lesson.route, 180)} when=${JSON.stringify(lesson.when ?? [])} do=${JSON.stringify(lesson.do ?? [])} avoid=${JSON.stringify(lesson.avoid ?? [])}`).join('\n') || '- empty'}

## Rules
- At most 3 lessons. Each needs idea, method, route and at least one of when/do/avoid/chain.
- when only stack or cue tokens (php/java/nginx/auth_surface/inject_surface/file_read_surface).
- do/avoid only tactic tokens (sqli/ssti/ssrf/file_read_chain/weaponize/auth_surface/info_disclosure/privesc_lateral/...).
- Never include IP, host, port, URL, filesystem path, engagement name, secret, PII, payload, flag, or tool transcript.
- Do not invent a hop that is not in the episode chain.
- Output: {"lessons":[{"action":"upsert|retire","lesson_key":"optional","idea":"...","method":"...","route":"entry → vuln(...) → foothold(...) → goal","when":["php"],"do":["..."],"avoid":["..."],"chain":"..."}]}
`;
}
