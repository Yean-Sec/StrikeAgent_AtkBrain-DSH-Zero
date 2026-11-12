#!/usr/bin/env node
/**
 * Read-only project monitor for one AtkBrain engagement.
 *
 * Usage:
 *   node scripts/monitor-project.mjs --project PRJ-78E2D9EC
 *   node scripts/monitor-project.mjs --project PRJ-78E2D9EC --json
 *
 * It locates the newest session cache containing the project, reconstructs the
 * wire view, and reports:
 *   - scope / five self-teams / native worker state
 *   - verified vs candidate findings and vulnerability classification
 *   - graph staleness vs raw evidence freshness
 *   - project-level HTML report completion
 * It never mutates the graph and never performs network I/O.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { buildView } from '../lib/graph.js';
import { classifyFindingCvss, isIncludedVulnerabilityNode } from '../lib/finding-classification.js';

const SESSION_DIR = path.join(homedir(), '.dsh', 'storages', 'session_projcache', 'sessions');
const REQUIRED_TEAMS = ['evolution', 'supervision', 'lead', 'verification', 'report'];
const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const projectArg = (() => {
  const index = args.indexOf('--project');
  if (index >= 0 && args[index + 1]) return args[index + 1].trim();
  return process.env.ATKBRAIN_PROJECT_ID ?? 'PRJ-78E2D9EC';
})();
const staleMinutes = Number(process.env.ATKBRAIN_MONITOR_STALE_MINUTES ?? 15);

function minutesAgo(iso) {
  const time = Date.parse(String(iso ?? ''));
  if (!Number.isFinite(time)) return null;
  return Math.max(0, Math.round(((Date.now() - time) / 60000) * 10) / 10);
}

function newestFile(dir) {
  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    let best = null;
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const file = path.join(dir, entry.name);
      const stat = statSync(file);
      if (best === null || stat.mtimeMs > best.mtimeMs) best = { path: file, mtimeMs: stat.mtimeMs, size: stat.size };
    }
    return best;
  } catch {
    return null;
  }
}

function loadProject(projectId) {
  const hits = [];
  let entries = [];
  try {
    entries = readdirSync(SESSION_DIR, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
    const file = path.join(SESSION_DIR, entry.name);
    let raw;
    try {
      raw = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    if (!raw.includes(projectId)) continue;
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      continue;
    }
    const graph = parsed?.record?.rows?.atkGraph?.val;
    if (graph?.engagement?.id !== projectId) continue;
    hits.push({ file, parsed, graph });
  }
  if (hits.length === 0) return null;
  hits.sort((a, b) => (Number(b.graph.seq) || 0) - (Number(a.graph.seq) || 0));
  const best = hits[0];
  const rows = best.parsed.record.rows ?? {};
  const state = {
    ...best.graph,
    aliases: best.graph.aliases ?? {},
    stats: best.graph.stats ?? {},
    audit: best.graph.audit ?? [],
  };
  return { ...best, rows, identity: best.parsed.record.identity ?? {}, state };
}

function detectGaps(project) {
  const { graph, rows, state } = project;
  const view = buildView(state);
  const nodes = Object.values(state.nodes ?? {});
  const findings = nodes.filter((node) => node.kind === 'finding');
  const workers = Array.isArray(rows?.agentTeam?.val?.members)
    ? rows.agentTeam.val.members.filter((member) => member.phase === 'active')
    : [];
  const cwd = String(rows?.workingDirectory?.val ?? project.identity?.cwd ?? '');
  const evidenceDir = cwd ? path.join(cwd, '.atkbrain', 'evidence') : '';
  const latestEvidence = evidenceDir ? newestFile(evidenceDir) : null;
  const lastActionAt = view.lastAction?.at ?? graph.audit?.[graph.audit.length - 1]?.at ?? null;
  const lastActionAge = minutesAgo(lastActionAt);
  const evidenceAge = latestEvidence === null ? null : minutesAgo(new Date(latestEvidence.mtimeMs).toISOString());
  const completion = view.projectCompletion ?? { complete: false, reason: 'no completion data' };
  const findingsSummary = findings.map((node) => {
    const cvss = classifyFindingCvss(node.attrs ?? {});
    return {
      title: node.label,
      status: node.status,
      severity: cvss.severity,
      score: cvss.score,
      vulnerability: cvss.vulnerability === true,
      secondaryVerified: node.attrs?.secondaryVerified === true,
      rating: node.attrs?.redteamRating ?? node.attrs?.cvssRating ?? null,
      includedVulnerability: isIncludedVulnerabilityNode(node),
      detailSource: node.attrs?.detailSource ?? node.attrs?.secondaryDetailsSource ?? null,
      detailComplete: /[\u3400-\u9fff]/u.test(String(node.attrs?.description ?? ''))
        && /[\u3400-\u9fff]/u.test(String(node.attrs?.impact ?? ''))
        && /[\u3400-\u9fff]/u.test(String(node.attrs?.repro ?? '')),
    };
  });
  const includedVulns = findingsSummary.filter((finding) => finding.includedVulnerability);
  const verifiedVulns = includedVulns.filter((finding) => finding.secondaryVerified);
  const unscoredVulns = includedVulns.filter((finding) => finding.score === null);
  const missingDetail = includedVulns.filter((finding) => finding.detailComplete !== true);
  const candidateVulns = findingsSummary.filter((finding) => finding.vulnerability && !finding.secondaryVerified);
  const exposureCandidates = findingsSummary.filter((finding) => !finding.vulnerability && finding.status === 'candidate');
  const teams = Array.isArray(view.selfTeam?.teams) ? view.selfTeam.teams : [];
  const teamTypes = new Set(teams.map((team) => team.type));
  const teamDir = cwd ? path.join(cwd, '.atkbrain', 'team') : '';
  let teamArtifacts = [];
  if (teamDir) {
    try {
      teamArtifacts = readdirSync(teamDir, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => {
          const graphFile = path.join(teamDir, entry.name, 'graph.json');
          try {
            const stat = statSync(graphFile);
            return { worker: entry.name, graph: graphFile, bytes: stat.size, ageMinutes: minutesAgo(new Date(stat.mtimeMs).toISOString()) };
          } catch {
            return { worker: entry.name, graph: null, bytes: 0, ageMinutes: null };
          }
        });
    } catch {
      teamArtifacts = [];
    }
  }
  const alerts = [];

  if ((graph.scope?.allow ?? []).length === 0) alerts.push('SCOPE_EMPTY');
  if (!graph.engagement?.authorization) alerts.push('AUTHORIZATION_MISSING');
  const missingTeams = REQUIRED_TEAMS.filter((type) => !teamTypes.has(type));
  if (missingTeams.length > 0) alerts.push(`TEAMS_MISSING:${missingTeams.join(',')}`);
  if (completion.complete !== true) alerts.push(`PROJECT_INCOMPLETE:${completion.reason ?? 'report missing'}`);
  if (completion.complete === false && workers.length === 0 && (lastActionAge ?? 0) >= staleMinutes) {
    alerts.push(`STALLED:${lastActionAge}m`);
  }
  if (completion.complete === false
    && workers.length > 0
    && (lastActionAge ?? 0) >= 10
    && evidenceAge !== null
    && evidenceAge >= 10) {
    alerts.push(`STALLED_ACTIVE_WORKERS:${lastActionAge}m_no_graph_or_evidence_update`);
  }
  if (latestEvidence !== null && lastActionAt !== null && latestEvidence.mtimeMs > Date.parse(lastActionAt) + 3 * 60000) {
    alerts.push('EVIDENCE_NEWER_THAN_GRAPH:workers_may_not_have_merged');
  }
  if (workers.length > 0) alerts.push(`WORKERS_ACTIVE:${workers.map((member) => member.name).join(',')}`);
  const readyArtifacts = teamArtifacts.filter((artifact) => artifact.graph !== null);
  if (readyArtifacts.length > 0) alerts.push(`TEAM_ARTIFACTS_READY:${readyArtifacts.map((artifact) => artifact.worker).join(',')}`);
  const missingArtifacts = teamArtifacts.filter((artifact) => artifact.graph === null);
  if (missingArtifacts.length > 0) alerts.push(`TEAM_ARTIFACTS_MISSING:${missingArtifacts.map((artifact) => artifact.worker).join(',')}`);
  if (candidateVulns.length > 0) alerts.push(`UNVERIFIED_VULNERABILITIES:${candidateVulns.length}`);
  if (unscoredVulns.length > 0) alerts.push(`UNSCORED_VULNERABILITIES:${unscoredVulns.length}`);
  if (missingDetail.length > 0) alerts.push(`MISSING_AI_DETAIL:${missingDetail.length}`);
  if (exposureCandidates.length > 0) alerts.push(`CANDIDATE_EXPOSURES:${exposureCandidates.length}`);
  if (includedVulns.length > 0 && completion.complete !== true) alerts.push('VULNERABILITY_WITHOUT_PROJECT_REPORT');

  return {
    generatedAt: new Date().toISOString(),
    projectId: graph.engagement.id,
    name: graph.engagement.name,
    sessionFile: project.file,
    cwd,
    seq: graph.seq,
    authorization: Boolean(graph.engagement.authorization),
    scope: (graph.scope?.allow ?? []).map((entry) => entry.value),
    lastAction: { at: lastActionAt, ageMinutes: lastActionAge, tool: view.lastAction?.tool ?? null, action: view.lastAction?.action ?? null },
    workers: workers.map((member) => ({ name: member.name, description: member.description })),
    teams: teams.map((team) => ({ type: team.type, label: team.label, status: team.status })),
    counts: view.coverage,
    findings: findingsSummary,
    teamArtifacts,
    vulnerabilityCounts: { included: includedVulns.length, verified: verifiedVulns.length, pending: candidateVulns.length, unscored: unscoredVulns.length, missingDetail: missingDetail.length },
    evidence: {
      directory: evidenceDir,
      files: latestEvidence === null ? 0 : readdirSync(evidenceDir, { withFileTypes: true }).filter((entry) => entry.isFile()).length,
      latestFile: latestEvidence?.path ?? null,
      latestAgeMinutes: evidenceAge,
    },
    completion,
    alerts,
    healthy: !alerts.some((alert) => /^(SCOPE_EMPTY|AUTHORIZATION_MISSING|STALLED|EVIDENCE_NEWER_THAN_GRAPH)/.test(alert)),
  };
}

const project = loadProject(projectArg);
if (project === null) {
  console.error(`project not found in session cache: ${projectArg}`);
  process.exit(2);
}
const report = detectGaps(project);
if (jsonOutput) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}
console.log(`# ${report.projectId} — ${report.name}`);
console.log('');
console.log(`- generated: ${report.generatedAt}`);
console.log(`- session: ${report.sessionFile}`);
console.log(`- workspace: ${report.cwd || '—'}`);
console.log(`- scope: ${report.scope.join(', ') || '—'}`);
console.log(`- seq: ${report.seq}`);
console.log(`- last action: ${report.lastAction.tool ?? '—'}/${report.lastAction.action ?? '—'} ${report.lastAction.at ?? '—'} (${report.lastAction.ageMinutes ?? '—'} min ago)`);
console.log(`- workers active: ${report.workers.map((worker) => worker.name).join(', ') || 'none'}`);
console.log(`- teams: ${report.teams.map((team) => `${team.label}=${team.status}`).join('; ') || 'none'}`);
console.log(`- counts: ${JSON.stringify(report.counts)}`);
console.log(`- vulnerabilities: ${JSON.stringify(report.vulnerabilityCounts)}`);
console.log(`- completion: ${report.completion.complete ? `complete (${report.completion.reportPath})` : `incomplete (${report.completion.reason})`}`);
console.log(`- evidence: ${report.evidence.files} file(s), latest ${report.evidence.latestAgeMinutes ?? '—'} min ago`);
console.log('');
console.log('## findings');
for (const finding of report.findings) {
  console.log(`- [${finding.status}] ${finding.title} | ${finding.severity}${finding.score === null ? '' : ` ${finding.score}`} | vulnerability=${finding.vulnerability} secondary=${finding.secondaryVerified} rating=${finding.rating ?? '—'}`);
}
if (report.findings.length === 0) console.log('- none');
console.log('');
console.log('## alerts');
for (const alert of report.alerts) console.log(`- ${alert}`);
if (report.alerts.length === 0) console.log('- none');
