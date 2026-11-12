/**
 * AI report-writing team.
 *
 * The deterministic renderer remains responsible for tables, counts and
 * evidence indexes. The report team only writes narrative prose from a bounded,
 * redacted facts packet, and every finding note must cite an existing node id.
 */
import { nativeTeammate } from './self-teams.js';
import { runSubagentText } from './loop/supervisor.js';
import { publicAttrs } from './redact.js';

const MAX_FINDINGS = 20;
const MAX_TEXT = 4000;

function clip(value, max = MAX_TEXT) {
  return String(value ?? '').trim().slice(0, max);
}

function findingFacts(node) {
  const attrs = node.attrs ?? {};
  const publicNode = { ...attrs, ...publicAttrs('finding', attrs) };
  return {
    id: node.id,
    key: node.key,
    title: clip(publicNode.title ?? node.label, 220),
    severity: node.severity ?? publicNode.severity ?? 'info',
    category: clip(publicNode.category ?? publicNode.template ?? 'unknown', 80),
    status: node.status,
    verification: node.verification,
    secondaryVerified: publicNode.secondaryVerified === true,
    evidenceCount: Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0,
    description: clip(publicNode.description ?? publicNode.impact ?? publicNode.evidence, 1200),
    impact: clip(publicNode.impact ?? publicNode.impactDetail, 1200),
    repro: clip(publicNode.repro ?? publicNode.proofDetail, 1800),
    request: clip(publicNode.request ?? publicNode.httpRequest ?? publicNode.pocCurl, 1400),
    response: clip(publicNode.response ?? publicNode.httpResponse, 1400),
    cvss: clip(publicNode.cvssVector ?? publicNode.cvssRating ?? publicNode.redteamRating, 300),
  };
}

export function buildReportAiBrief(state) {
  const nodes = Object.values(state.nodes ?? {}).filter((node) => node.status !== 'merged');
  const findings = nodes
    .filter((node) => node.kind === 'finding' && ['verified', 'exploited', 'impacted'].includes(String(node.status)))
    .sort((a, b) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 }[b.severity] ?? 0) - ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 }[a.severity] ?? 0))
    .slice(0, MAX_FINDINGS)
    .map(findingFacts);
  const access = nodes.filter((node) => node.kind === 'access' && ['validated', 'escalated'].includes(String(node.status)))
    .slice(0, 10).map((node) => ({ id: node.id, label: clip(node.label, 120), privilege: clip(node.attrs?.privilege, 80), proof: clip(node.attrs?.proof, 300) }));
  const data = nodes.filter((node) => node.kind === 'data' && String(node.status) === 'verified')
    .slice(0, 10).map((node) => ({ id: node.id, label: clip(node.label, 120), dataClass: clip(node.attrs?.dataClass, 80), count: Number(node.attrs?.count) || 0 }));
  const verifiedCount = findings.length;
  return {
    engagement: {
      name: clip(state.engagement?.name, 120),
      authorization: clip(state.engagement?.authorization, 120),
      scopeAllow: Array.isArray(state.scope?.allow) ? state.scope.allow.length : 0,
    },
    counts: {
      findings: nodes.filter((node) => node.kind === 'finding').length,
      verifiedFindings: verifiedCount,
      assets: nodes.filter((node) => ['host', 'ip', 'domain'].includes(node.kind)).length,
      services: nodes.filter((node) => ['service', 'webapp', 'tech'].includes(node.kind)).length,
      validatedAccess: access.length,
      verifiedData: data.length,
    },
    findings,
    access,
    data,
  };
}

export function buildReportAiPrompt(brief) {
  return `You are the AtkBrain report-writing team. Write the narrative portions of an authorized penetration-test report in Chinese.

Return ONLY one JSON object, no markdown fences, with this shape:
{
  "executiveSummary": "3-6 sentences, factual, only from FACTS",
  "conclusion": "2-4 sentences about what is proven and what is not proven",
  "findings": [
    {
      "id": "must exactly match a finding id in FACTS",
      "description": "what was found and where",
      "impact": "only verified impact; explicitly separate unproven impact",
      "reproduction": "manual reproduction steps based on repro/request/response",
      "ratingRationale": "red-team/CVSS rationale grounded in verified evidence"
    }
  ]
}

Rules:
- Use only facts in FACTS. Never invent a host, path, credential, count, CVE, impact, or attack step.
- Do NOT include raw passwords, tokens, cookies, private keys, or PII. The facts packet is already redacted.
- For each finding, describe request/response only if present; if absent, say the packet was not recorded.
- Executive summary must state the verified count and the main proven impact; mention unproven items as unproven.
- Findings not marked verified must not be written as confirmed.
- Write in customer-facing Chinese, not as an internal graph inspector.
- Do not mention internal JSON field names, schema names, node ids, access_/data_ ids, booleans like secondaryVerified, or the word count(s). Use natural language: 已确认、待二次复核、证据不足.
- If the graph contains conflicting verification signals, describe the conflict in plain language without dumping raw fields or ids.
- Keep each field under 1200 Chinese characters. Return every finding in FACTS at most once.

FACTS:
${JSON.stringify(brief, null, 2)}`;
}

export function parseReportAiOutput(text, allowedIds) {
  const raw = String(text ?? '').trim();
  if (raw.length === 0) return { narrative: null, error: 'report team returned empty output' };
  const candidates = [];
  const fence = /```(?:json)?\s*(\{[\s\S]*?\})\s*```/u.exec(raw);
  if (fence !== null) candidates.push(fence[1]);
  const first = raw.indexOf('{');
  const last = raw.lastIndexOf('}');
  if (first >= 0 && last > first) candidates.push(raw.slice(first, last + 1));
  candidates.push(raw);
  for (const candidate of candidates) {
    try {
      const value = JSON.parse(candidate);
      if (value === null || typeof value !== 'object' || Array.isArray(value)) continue;
      const ids = allowedIds instanceof Set ? allowedIds : new Set(allowedIds ?? []);
      const findings = (Array.isArray(value.findings) ? value.findings : [])
        .filter((row) => row !== null && typeof row === 'object' && typeof row.id === 'string' && ids.has(row.id))
        .slice(0, MAX_FINDINGS)
        .map((row) => ({
          id: row.id,
          description: clip(row.description, 1400),
          impact: clip(row.impact, 1400),
          reproduction: clip(row.reproduction ?? row.repro, 1800),
          ratingRationale: clip(row.ratingRationale ?? row.rating_rationale, 1200),
        }))
        .filter((row) => row.description || row.impact || row.reproduction || row.ratingRationale);
      const narrative = {
        executiveSummary: clip(value.executiveSummary ?? value.executive_summary, 2200),
        conclusion: clip(value.conclusion, 1200),
        findings,
        ai: true,
      };
      if (narrative.executiveSummary.length === 0 && narrative.findings.length === 0) continue;
      return { narrative, error: null };
    } catch {
      /* try next candidate */
    }
  }
  return { narrative: null, error: 'report team returned no parseable JSON narrative' };
}

/** Merge AI prose into a shallow copy of graph state for rendering only. */
export function mergeReportNarrative(state, narrative) {
  if (narrative === null || narrative === undefined) return state;
  const nodes = { ...(state.nodes ?? {}) };
  for (const note of narrative.findings ?? []) {
    const node = nodes[note.id];
    if (node === undefined) continue;
    const attrs = { ...(node.attrs ?? {}), aiNarrative: true };
    if (note.description) attrs.description = note.description;
    if (note.impact) attrs.impact = note.impact;
    if (note.reproduction) attrs.repro = note.reproduction;
    if (note.ratingRationale) attrs.ratingRationale = note.ratingRationale;
    nodes[note.id] = { ...node, attrs };
  }
  return { ...state, nodes };
}

/** Run the report-writing subagent. Never throws; returns null narrative on failure. */
export async function runReportAi({ ctx, agent, state, signal, timeoutMs = 120000 }) {
  const brief = buildReportAiBrief(state);
  const allowedIds = new Set(brief.findings.map((finding) => finding.id));
  if (brief.findings.length === 0) {
    return { narrative: null, error: 'no verified findings to write', childId: undefined, brief };
  }
  const result = await runSubagentText({
    ctx,
    agent,
    brief: buildReportAiPrompt(brief),
    signal,
    timeoutMs,
    label: 'AtkBrain report-writing team',
    native: nativeTeammate(state, 'report'),
  });
  if (result.error !== null && result.text.length === 0) {
    return { narrative: null, error: result.error, childId: result.childId, via: result.via, brief };
  }
  const parsed = parseReportAiOutput(result.text, allowedIds);
  return { narrative: parsed.narrative, error: parsed.error, childId: result.childId, via: result.via, brief };
}
