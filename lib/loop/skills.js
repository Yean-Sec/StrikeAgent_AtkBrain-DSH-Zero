/**
 * Cross-engagement path skills.
 *
 * The evolution team uses AI to turn confirmed high/critical attack paths into
 * reusable SKILL.md packages. This module owns the generalized path bundle,
 * skill sanitization, global storage, retrieval and prompt formatting.
 */
import { readdir, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { ensureDir, sha256Hex, shortHash, writeFileSecure } from '../util.js';
import {
  CUE_TOKENS,
  STACK_TOKENS,
  TACTICS,
  cueForFinding,
  graphSignals,
  graphStackTokens,
  normalizeSkillTokens,
  qualifiesForEvolution,
  sanitizeSkillChain,
  sanitizeSkillText,
  tacticForFinding,
  winningChain,
} from './memory.js';

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function textArray(values, { when = [], limit = 8, maxLength = 360 } = {}) {
  const out = [];
  for (const value of Array.isArray(values) ? values : []) {
    const text = sanitizeSkillText(value, { when, maxLength });
    if (text.length === 0 || out.includes(text)) continue;
    out.push(text);
    if (out.length >= limit) break;
  }
  return out;
}

export function slugifySkill(name) {
  const slug = String(name ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '')
    .slice(0, 48);
  return slug.length > 0 ? slug : 'skill';
}

/** Resolve the global skill library; a configured relative path is workspace-relative. */
export function resolveSkillDir(workspace, config) {
  const configured = typeof config?.skillDir === 'string' ? config.skillDir.trim() : '';
  if (configured.length > 0) {
    return path.isAbsolute(configured) ? configured : path.resolve(workspace, configured);
  }
  return path.join(os.homedir(), '.dsh', 'atkbrain', 'skills');
}

/** Sanitize one AI-produced skill before it can touch disk or graph state. */
export function sanitizeSkill(raw, { sourceEngagementHash = null, sourceOutcome = null } = {}) {
  if (raw === null || typeof raw !== 'object') return null;
  const name = sanitizeSkillText(raw.name, { maxLength: 90 });
  const summary = sanitizeSkillText(raw.summary ?? raw.description, { maxLength: 600 });
  const when = normalizeSkillTokens(raw.when ?? raw.cues, new Set([...STACK_TOKENS, ...CUE_TOKENS]), 8);
  const doTokens = normalizeSkillTokens(raw.do ?? raw.tactics, TACTICS, 6);
  const avoid = normalizeSkillTokens(raw.avoid, TACTICS, 6);
  const route = sanitizeSkillChain(raw.route ?? raw.chain);
  if (name.length === 0 || summary.length === 0 || route.length === 0 || doTokens.length === 0) return null;
  if (!/\(/u.test(route)) return null;
  const preconditions = textArray(raw.preconditions, { when, limit: 8 });
  const verification = textArray(raw.verification, { when, limit: 8 });
  const steps = textArray(raw.steps, { when, limit: 8 });
  const pitfalls = textArray(raw.pitfalls, { when, limit: 8 });
  if (verification.length === 0 || steps.length === 0) return null;
  const canonical = {
    version: 1,
    name,
    summary,
    when,
    do: doTokens,
    avoid,
    route,
    preconditions,
    verification,
    steps,
    pitfalls,
    confidence: clamp(Number(raw.confidence) || 0.5, 0.2, 0.95),
    status: raw.status === 'retired' ? 'retired' : 'active',
    sourceEngagementHash,
    sourceOutcome,
    sourceFindingClasses: Array.isArray(raw.sourceFindingClasses)
      ? raw.sourceFindingClasses.slice(0, 8).map((entry) => String(entry).replace(/[^A-Za-z0-9:_-]/gu, '').slice(0, 80))
      : [],
    createdAt: typeof raw.createdAt === 'string' ? raw.createdAt : new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  const key = String(raw.skillKey ?? shortHash(`${canonical.name}|${canonical.route}|${canonical.when.join(',')}|${canonical.do.join(',')}`, 16));
  return {
    ...canonical,
    skillKey: key,
    slug: `${slugifySkill(canonical.name)}-${key.slice(0, 6)}`,
  };
}

/** Render a DSH-style SKILL.md package. */
export function skillMarkdown(skill) {
  const front = [
    '---',
    `name: ${JSON.stringify(skill.name)}`,
    `description: ${JSON.stringify(skill.summary)}`,
    'atkbrain_skill: 1',
    `route: ${JSON.stringify(skill.route)}`,
    `when: ${JSON.stringify(skill.when)}`,
    `do: ${JSON.stringify(skill.do)}`,
    `avoid: ${JSON.stringify(skill.avoid)}`,
    `confidence: ${Number(skill.confidence).toFixed(2)}`,
    '---',
  ];
  const list = (values) => (values.length > 0 ? values.map((value) => `- ${value}`).join('\n') : '- —');
  return `${front.join('\n')}

# ${skill.name}

${skill.summary}

## When
${list(skill.when)}

## Route
\`${skill.route}\`

## Do
${list(skill.do)}

## Avoid
${list(skill.avoid)}

## Preconditions
${list(skill.preconditions)}

## Steps
${list(skill.steps)}

## Verification
${list(skill.verification)}

## Pitfalls
${list(skill.pitfalls)}

## Provenance
- source outcome: ${skill.sourceOutcome ?? '—'}
- source finding classes: ${skill.sourceFindingClasses.join(', ') || '—'}
- source engagement hash: ${skill.sourceEngagementHash ?? '—'}
- skill key: \`${skill.skillKey}\`
`;
}

/** Persist one skill package under the global library. */
export async function writeSkill(dir, skill) {
  const target = path.join(dir, skill.slug);
  await ensureDir(target);
  const markdownPath = path.join(target, 'SKILL.md');
  const jsonPath = path.join(target, 'skill.json');
  const markdown = skillMarkdown(skill);
  await writeFileSecure(markdownPath, markdown);
  await writeFileSecure(jsonPath, `${JSON.stringify({ ...skill, path: markdownPath }, null, 2)}\n`);
  return { dir: target, path: markdownPath, jsonPath, markdown, sha256: sha256Hex(markdown) };
}

/** Read the global skill library; malformed packages are ignored. */
export async function readSkills(dir) {
  let entries = [];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  const skills = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    try {
      const raw = await readFile(path.join(dir, entry.name, 'skill.json'), 'utf8');
      const parsed = JSON.parse(raw);
      const clean = sanitizeSkill(parsed, {
        sourceEngagementHash: parsed.sourceEngagementHash ?? null,
        sourceOutcome: parsed.sourceOutcome ?? null,
      });
      if (clean === null) continue;
      skills.push({ ...clean, path: typeof parsed.path === 'string' ? parsed.path : path.join(dir, entry.name, 'SKILL.md') });
    } catch {
      /* one corrupt skill package must not poison the library */
    }
  }
  return skills.sort((a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name));
}

export function scoreSkill(skill, signals) {
  const when = new Set(skill.when ?? []);
  const doTokens = new Set(skill.do ?? []);
  const whenHit = [...when].filter((token) => signals.has(token)).length;
  const doHit = [...doTokens].filter((token) => signals.has(token)).length;
  if (whenHit === 0 && doHit === 0) return 0;
  return Number(skill.confidence ?? 0.5) * 0.5 + 0.3 * whenHit + 0.2 * doHit;
}

export function retrieveSkills(skills, { state, limit = 6, sourceEngagementHash = null, includeSelf = false } = {}) {
  const signals = graphSignals(state);
  const ranked = (Array.isArray(skills) ? skills : [])
    .filter((skill) => skill.status === 'active')
    .filter((skill) => includeSelf || !sourceEngagementHash || skill.sourceEngagementHash !== sourceEngagementHash)
    .map((skill) => ({ skill, score: scoreSkill(skill, signals) }))
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score || b.skill.confidence - a.skill.confidence)
    .slice(0, Math.max(1, Math.min(20, Number(limit) || 6)));
  return ranked.map((entry) => entry.skill);
}

export function formatSkillBlock(skills) {
  if (!Array.isArray(skills) || skills.length === 0) return '';
  const lines = ['## Distilled path skills (advisory; verify on this target)'];
  for (const skill of skills) {
    lines.push(`- ${skill.name}: ${skill.summary} | route: ${skill.route} | when: ${(skill.when ?? []).join(', ') || '—'} | do: ${(skill.do ?? []).join(', ') || '—'} | confidence ${Number(skill.confidence).toFixed(2)}${skill.path ? ` | ${skill.path}` : ''}`);
  }
  return lines.join('\n');
}

/** Extract the skills JSON object from a model reply. */
export function parseSkillOutput(text) {
  const raw = String(text ?? '').trim();
  if (!raw) return [];
  let blob = '';
  const fence = /```(?:json)?\s*([\s\S]*?)\s*```/u.exec(raw);
  if (fence) blob = fence[1].trim();
  else {
    const start = raw.indexOf('{');
    const end = raw.lastIndexOf('}');
    if (start >= 0 && end > start) blob = raw.slice(start, end + 1);
  }
  if (!blob) return [];
  try {
    const data = JSON.parse(blob);
    const list = Array.isArray(data) ? data : data.skills;
    return Array.isArray(list) ? list.slice(0, 3).filter((entry) => entry && typeof entry === 'object') : [];
  } catch {
    return [];
  }
}

function accessTactic(node) {
  const kind = String(node.attrs?.kind ?? '');
  if (/admin|domain|cloud|db_admin/.test(kind)) return 'access_control';
  if (/db_read|data/.test(kind)) return 'data_access';
  return 'privesc_lateral';
}

/** Build the generalized high/critical path bundle sent to the AI evolution team. */
export function buildSkillBundle(state, loop, config) {
  const qualification = qualifiesForEvolution(state, config);
  if (!qualification.qualified) {
    return {
      qualified: false,
      reasons: qualification.reasons,
      candidateHigh: qualification.candidateHigh.length,
    };
  }
  const tactics = [...new Set([
    ...qualification.verifiedHigh.map(tacticForFinding),
    ...qualification.access.map(accessTactic),
    ...(qualification.data.length > 0 ? ['data_access'] : []),
  ])].slice(0, 8);
  const cues = [...new Set([
    ...qualification.verifiedHigh.map(cueForFinding),
    ...(qualification.access.length > 0 ? ['foothold'] : []),
    ...(qualification.data.length > 0 ? ['data_access'] : []),
  ])].slice(0, 8);
  const chain = winningChain(state);
  return {
    qualified: true,
    objectiveType: loop?.attrs?.objectiveType ?? 'impact',
    stack: graphStackTokens(state),
    tactics,
    cues,
    route: chain.join(' → '),
    findingClasses: qualification.verifiedHigh.map((node) => `${node.attrs?.template ?? 'finding'}:${node.attrs?.severity ?? 'unknown'}`),
    accessKinds: qualification.access.map((node) => String(node.attrs?.kind ?? 'access')),
    dataClasses: qualification.data.map((node) => String(node.attrs?.dataClass ?? 'internal')),
    sourceOutcome: qualification.access.length > 0 ? 'impact' : qualification.data.length > 0 ? 'data' : 'finding',
    sourceEngagementHash: shortHash(`${state.engagement?.name ?? 'engagement'}|${state.engagement?.authorization ?? ''}`, 16),
    candidateHigh: qualification.candidateHigh.length,
  };
}

export function formatSkillBundle(bundle) {
  return JSON.stringify(bundle, null, 2);
}
