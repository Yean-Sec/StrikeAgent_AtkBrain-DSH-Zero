/**
 * Project completion gate.
 *
 * A project is complete when the 报告撰写 team has exported a fresh
 * project-level HTML report. Coverage gaps, a missing page ledger and a
 * vulnerability without validated access stay visible as hints.
 */
import { isIncludedVulnerabilityNode } from './finding-classification.js';

function missingCapabilityCalls() {
  return [];
}

function activeNodes(state) {
  return Object.values(state?.nodes ?? {}).filter((node) => node.status !== 'merged');
}

function ledgerMissing(nodes) {
  const webapps = nodes.filter((node) => node.kind === 'webapp');
  return webapps.length > 0 && webapps.some((node) => node.attrs?.surfaceInventoried !== true);
}

function openCoverage(nodes) {
  return nodes.filter((node) => node.kind === 'coverage'
    && ['open', 'claimed'].includes(String(node.status ?? ''))
    && !node.attrs?.mergedInto);
}

function vulnerabilityWithoutAccess(nodes) {
  const vuln = nodes.some((node) => node.kind === 'finding' && node.status !== 'refuted' && isIncludedVulnerabilityNode(node));
  const access = nodes.some((node) => node.kind === 'access' && ['validated', 'escalated'].includes(String(node.status ?? '')));
  return vuln && !access;
}

/** Calls still required before a project report can be treated as finished. */
export function engagementGaps(state) {
  const nodes = activeNodes(state);
  const gaps = [...missingCapabilityCalls(state)];
  if (ledgerMissing(nodes)) gaps.push('endpoint_vocab');
  if (openCoverage(nodes).length > 0) gaps.push('coverage');
  if (vulnerabilityWithoutAccess(nodes)) gaps.push('validated access');
  return gaps;
}

export function projectCompletion(state) {
  const nodes = activeNodes(state);
  const reportTeam = nodes.find((node) => node.kind === 'self_team' && node.attrs?.type === 'report');
  const attrs = reportTeam?.attrs ?? {};
  const reportPath = String(attrs.lastReportPath ?? '').trim();
  const reportAt = String(attrs.lastReportAt ?? '').trim();
  const reportKind = String(attrs.lastReportKind ?? (reportPath.endsWith('.html') ? 'project' : '')).toLowerCase();
  const reportMs = Date.parse(reportAt);
  const impactNodes = nodes.filter((node) => ['finding', 'access', 'data', 'credential'].includes(node.kind));
  let latestImpactMs = 0;
  let latestImpactAt = null;
  for (const node of impactNodes) {
    const at = Date.parse(String(node.lastSeen ?? node.firstSeen ?? node.attrs?.createdAt ?? ''));
    if (Number.isFinite(at) && at > latestImpactMs) {
      latestImpactMs = at;
      latestImpactAt = new Date(at).toISOString();
    }
  }
  const hasReport = reportPath.endsWith('.html') && reportKind === 'project' && Number.isFinite(reportMs);
  const freshReport = hasReport && (latestImpactMs === 0 || reportMs >= latestImpactMs);
  const openCells = openCoverage(nodes)
    .map((node) => ({ path: String(node.attrs?.path ?? node.key ?? '/'), bugClass: String(node.attrs?.bugClass ?? 'unknown') }));
  const coverageComplete = openCells.length === 0;
  const missingCapabilities = missingCapabilityCalls(state);
  const capabilitiesComplete = missingCapabilities.length === 0;
  const fresh = freshReport;
  let reason;
  if (reportTeam === undefined) reason = '报告撰写 team has not been started';
  else if (reportPath.length === 0) reason = 'no project HTML report has been written';
  else if (reportKind !== 'project') reason = 'latest report is not a project-level report';
  else if (!reportPath.endsWith('.html')) reason = 'project report must be HTML';
  else if (!Number.isFinite(reportMs)) reason = 'project report has no valid completion timestamp';
  else if (!freshReport) reason = `project report is older than the latest finding/access/data update (${latestImpactAt ?? 'unknown'})`;
  else reason = null;
  return {
    complete: fresh,
    reportComplete: freshReport,
    reportPath: reportPath.length > 0 ? reportPath : null,
    reportAt: Number.isFinite(reportMs) ? new Date(reportMs).toISOString() : null,
    reportKind: reportKind || null,
    latestImpactAt,
    coverage: {
      complete: coverageComplete,
      open: openCells.length,
      sample: openCells.slice(0, 12),
    },
    capabilities: {
      complete: capabilitiesComplete,
      missing: missingCapabilities,
    },
    reason,
  };
}
