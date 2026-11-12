/**
 * Cross-engagement evolution memory.
 *
 * Only qualified outcomes (verified high/critical findings, validated access,
 * verified bulk data) are distilled. Lessons are generalized to tactics, stack
 * tokens and a type chain; hosts, ports, URLs, paths, engagement names, secrets
 * and PII are rejected before anything is written.
 *
 * Storage is an append-only JSONL file (default under ~/.dsh/atkbrain/memory),
 * folded by lessonKey on read. No graph state is required to read it, so a new
 * engagement can retrieve old playbooks.
 */
import { appendFile, mkdir, open, readFile, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { computeCrownPaths } from '../path.js';
import { shortHash } from '../util.js';
import {
  findingSeverity,
  isCandidateHighCritical,
  isHighCriticalFinding,
  isVerifiedData,
  isVerifiedFinding,
  isValidatedAccess,
  claimGuardForFinding,
} from './policy.js';

const MIN_CONF = 0.18;
const MAX_CONF = 0.95;
const MAX_LESSON_LINES = 5000;
const MAX_LESSON_BYTES = 5 * 1024 * 1024;

export const STACK_TOKENS = Object.freeze(new Set([
  'php', 'java', 'python', 'node', 'nodejs', 'ruby', 'go', 'dotnet', 'aspnet',
  'nginx', 'apache', 'iis', 'tomcat', 'jetty', 'weblogic', 'websphere',
  'spring', 'struts', 'thinkphp', 'laravel', 'django', 'flask', 'express',
  'wordpress', 'drupal', 'joomla', 'magento', 'shopify',
  'mysql', 'mariadb', 'postgres', 'postgresql', 'mssql', 'oracle', 'mongodb',
  'redis', 'memcached', 'elasticsearch', 'kafka', 'rabbitmq', 'ldap', 'ad',
  'docker', 'k8s', 'kubernetes', 'cloud', 'aws', 'azure', 'gcp',
  'graphql', 'rest', 'soap', 'jwt', 'oauth', 'saml',
]));

export const CUE_TOKENS = Object.freeze(new Set([
  'web', 'auth_surface', 'inject_surface', 'file_read_surface', 'upload_surface',
  'deserialize_surface', 'debug_endpoint', 'template_surface', 'object_store',
  'graphql_surface', 'json_api', 'xml_surface', 'foothold', 'credential',
  'data_access', 'internal', 'admin_surface', 'cloud_surface',
]));

export const TACTIC_ALIASES = Object.freeze({
  unauth: 'access_control',
  unauthenticated: 'access_control',
  auth_bypass: 'access_control',
  authz: 'access_control',
  idor: 'access_control',
  ssrf: 'ssrf_as_gateway',
  lfi: 'file_read_chain',
  rfi: 'file_read_chain',
  file_read: 'file_read_chain',
  path_traversal: 'file_read_chain',
  fileread: 'file_read_chain',
  rce: 'weaponize',
  command_injection: 'weaponize',
  code_execution: 'weaponize',
  file_upload: 'upload_bypass',
  sqli: 'sql_chain',
  xxe: 'xml_parse',
  deserialization: 'restricted_deserialize',
  privilege_escalation: 'privesc_lateral',
  privesc: 'privesc_lateral',
  info_disclosure: 'info_disclosure',
  information_disclosure: 'info_disclosure',
  info_leak: 'info_disclosure',
  source_leak: 'source_leak',
  secret_leak: 'credential',
  debug: 'debug',
  fingerprint: 'fingerprint',
  content_enum: 'content_enum',
  web_inject: 'web_inject',
});

export const TACTICS = Object.freeze(new Set([
  'content_enum', 'fingerprint', 'auth_surface', 'inject_surface', 'web_inject',
  'file_read_chain', 'upload_bypass', 'access_control', 'info_disclosure',
  'source_leak', 'debug', 'credential', 'weaponize', 'privesc_lateral',
  'lateral', 'data_access', 'ssrf_as_gateway', 'xml_parse', 'restricted_deserialize',
  'sql_chain', 'finding_read_loot', 'hop_auth', 'protocol_model', 'reverse_binary',
  'misconfig', 'admin_surface',
]));

const TEMPLATE_TACTICS = Object.freeze({
  'exposed-env-file': ['credential', 'info_disclosure'],
  'exposed-git-repository': ['source_leak'],
  'exposed-git-config': ['source_leak'],
  'exposed-git-head': ['source_leak'],
  'directory-listing': ['info_disclosure', 'content_enum'],
  'directory-listing-stale-entry': ['info_disclosure'],
  'actuator-env-exposed': ['debug', 'info_disclosure'],
  'actuator-health-public': ['debug'],
  'actuator-root-exposed': ['debug'],
  'admin-interface-reachable': ['auth_surface', 'admin_surface'],
  'apache-server-status': ['info_disclosure', 'debug'],
  'api-docs-exposed': ['info_disclosure'],
  'phpinfo-exposed': ['info_disclosure', 'debug'],
  'exposed-phpinfo': ['info_disclosure', 'debug'],
  'server-version-disclosure': ['info_disclosure', 'fingerprint'],
  'technology-disclosure': ['fingerprint', 'info_disclosure'],
  'technology-fingerprint': ['fingerprint'],
  'missing-security-headers': ['misconfig'],
  'security-txt-present': ['info_disclosure'],
  'tomcat-manager-protected': ['auth_surface'],
  'swagger-ui-exposed': ['info_disclosure'],
  'graphql-introspection': ['graphql_surface', 'info_disclosure'],
  'default-credentials': ['credential', 'access_control'],
  'weak-password': ['credential', 'access_control'],
  'sqli': ['sql_chain', 'inject_surface'],
  'sql-injection': ['sql_chain', 'inject_surface'],
  'xss': ['web_inject'],
  'ssrf': ['ssrf_as_gateway'],
  'open-redirect': ['redirect'],
  'file-read': ['file_read_chain'],
  'path-traversal': ['file_read_chain'],
  'file-upload': ['upload_bypass'],
  'rce': ['weaponize'],
  'command-injection': ['weaponize'],
  'deserialization': ['restricted_deserialize'],
  'xxe': ['xml_parse'],
  'auth-bypass': ['access_control', 'auth_surface'],
});

const FINDING_CATEGORY_TACTICS = Object.freeze({
  sqli: 'sql_chain',
  sql_injection: 'sql_chain',
  xss: 'web_inject',
  ssrf: 'ssrf_as_gateway',
  xxe: 'xml_parse',
  rce: 'weaponize',
  command_injection: 'weaponize',
  code_execution: 'weaponize',
  file_read: 'file_read_chain',
  file_write: 'file_read_chain',
  file_upload: 'upload_bypass',
  lfi: 'file_read_chain',
  path_traversal: 'file_read_chain',
  auth_bypass: 'access_control',
  unauth: 'access_control',
  idor: 'access_control',
  privilege_escalation: 'privesc_lateral',
  privesc: 'privesc_lateral',
  data_leak: 'data_access',
  mass_disclosure: 'data_access',
  data_access: 'data_access',
  info_disclosure: 'info_disclosure',
  credential: 'credential',
  default_credentials: 'credential',
});

const FORBIDDEN_TEXT_RE = /(?:\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}\b|https?:\/\/|(?:^|\s)\/[A-Za-z0-9_.~/-]{2,}|-----BEGIN |[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\bport\s+\d{1,5}\b|(?<![\w]):\d{2,5}\b|\b(?=[0-9a-f:]*::)[0-9a-f:]{3,}\b|(?:\bpassword\b|\bpasswd\b|\bsecret\b|\btoken\b|\bapi[_-]?key\b)\s*[:=]\s*\S+)/iu;
const FORBIDDEN_TOKEN_RE = /(?:\b\d{1,3}(?:\.\d{1,3}){3}\b|^[a-z0-9.-]+\.[a-z]{2,}$|:\d{2,5}$|\/)/iu;

let appendChain = Promise.resolve();

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function normToken(value) {
  return String(value ?? '').trim().toLowerCase();
}

function uniqueTokens(values, allowed, limit = 8) {
  const out = [];
  for (const value of Array.isArray(values) ? values : []) {
    const raw = normToken(value).replace(/[^a-z0-9_ -]/gu, '_').replace(/[\s-]+/gu, '_');
    const token = TACTIC_ALIASES[raw] ?? raw;
    if (!token || token.length > 48 || !allowed.has(token)) continue;
    if (FORBIDDEN_TOKEN_RE.test(token)) continue;
    if (!out.includes(token)) out.push(token);
    if (out.length >= limit) break;
  }
  return out;
}

export function tacticForFinding(node) {
  const attrs = node?.attrs ?? {};
  const template = normToken(attrs.template ?? '');
  const category = normToken(attrs.category ?? '');
  const categoryTactic = FINDING_CATEGORY_TACTICS[category];
  for (const token of [...(TEMPLATE_TACTICS[template] ?? []), ...(categoryTactic ? [categoryTactic] : [])]) {
    const canonical = TACTIC_ALIASES[token] ?? token;
    if (TACTICS.has(canonical)) return canonical;
  }
  for (const candidate of [category, template]) {
    const canonical = TACTIC_ALIASES[candidate] ?? candidate;
    if (TACTICS.has(canonical)) return canonical;
  }
  return 'finding_read_loot';
}

export function cueForFinding(node) {
  const template = normToken(node?.attrs?.template ?? '');
  if (/auth|admin|login|credential|password/.test(template)) return 'auth_surface';
  if (/sqli|inject|xss|template/.test(template)) return 'inject_surface';
  if (/upload/.test(template)) return 'upload_surface';
  if (/file|git|env|backup|source|config/.test(template)) return 'file_read_surface';
  if (/deserial/.test(template)) return 'deserialize_surface';
  if (/actuator|phpinfo|debug|server-status|console/.test(template)) return 'debug_endpoint';
  if (/graphql/.test(template)) return 'graphql_surface';
  if (/xml|soap/.test(template)) return 'xml_surface';
  return 'web';
}

export function stackTokensOf(values) {
  const out = [];
  for (const value of Array.isArray(values) ? values : []) {
    const text = normToken(value);
    for (const token of STACK_TOKENS) {
      if (text === token || text.includes(token)) {
        if (!out.includes(token)) out.push(token);
      }
    }
  }
  return out.slice(0, 8);
}

export function graphStackTokens(state) {
  const values = [];
  for (const node of Object.values(state.nodes ?? {})) {
    if (node.kind === 'tech') values.push(node.key, node.label, ...(node.tags ?? []));
    if (node.kind === 'webapp') values.push(node.attrs?.server, ...(node.tags ?? []));
    if (node.kind === 'service') values.push(node.attrs?.protocol, ...(node.tags ?? []));
  }
  return stackTokensOf(values);
}

/** Graph signals used for lesson matching. */
export function graphSignals(state) {
  const signals = new Set(graphStackTokens(state));
  for (const node of Object.values(state.nodes ?? {})) {
    if (node.kind === 'finding') {
      signals.add(tacticForFinding(node));
      signals.add(cueForFinding(node));
    }
    if (node.kind === 'access') signals.add('foothold');
    if (node.kind === 'credential') signals.add('credential');
    if (node.kind === 'data') signals.add('data_access');
    if (node.kind === 'intent') {
      const type = String(node.attrs?.actionType ?? '');
      if (type.includes('verify') || type.includes('enumerate')) signals.add('recon');
      if (type.includes('access') || type.includes('escalate')) signals.add('foothold');
    }
  }
  if (Object.values(state.nodes ?? {}).some((node) => node.kind === 'host' && node.attrs?.realm === 'internal')) {
    signals.add('internal');
  }
  return signals;
}

function generalNodeToken(node) {
  if (node === undefined) return '';
  if (node.kind === 'host' || node.kind === 'ip' || node.kind === 'domain') return 'entry';
  if (node.kind === 'service') {
    const protocol = normToken(node.attrs?.protocol ?? '');
    return ['http', 'https', 'ssh', 'ftp', 'smb', 'redis', 'mysql', 'postgresql', 'mongodb'].includes(protocol)
      ? `service(${protocol})`
      : 'service';
  }
  if (node.kind === 'webapp') return 'service(http)';
  if (node.kind === 'finding') return `vuln(${tacticForFinding(node)})`;
  if (node.kind === 'credential') return 'cred(credential)';
  if (node.kind === 'access') {
    const kind = normToken(node.attrs?.kind ?? 'access');
    return `foothold(${kind || 'access'})`;
  }
  if (node.kind === 'data') return 'goal(data)';
  if (node.kind === 'pivot') return 'pivot';
  return '';
}

/** Generalize an ordered node-id path into a transferable type chain. */
export function generalizeChainFromIds(state, nodeIds) {
  const chain = [];
  for (const id of Array.isArray(nodeIds) ? nodeIds : []) {
    const token = generalNodeToken(state.nodes?.[id]);
    if (!token) continue;
    if (chain[chain.length - 1] === token) continue;
    chain.push(token);
  }
  return chain;
}

function fallbackChain(state) {
  const chain = ['entry'];
  const nodes = Object.values(state.nodes ?? {});
  if (nodes.some((node) => node.kind === 'webapp' || node.kind === 'service')) chain.push('service(http)');
  const findings = nodes.filter((node) => node.kind === 'finding')
    .sort((a, b) => (isVerifiedFinding(b) ? 1 : 0) - (isVerifiedFinding(a) ? 1 : 0));
  const tactics = [...new Set(findings.slice(0, 3).map(tacticForFinding))];
  for (const tactic of tactics) chain.push(`vuln(${tactic})`);
  const access = nodes.find((node) => isValidatedAccess(node));
  if (access !== undefined) chain.push(`foothold(${normToken(access.attrs?.kind ?? 'access')})`);
  if (nodes.some((node) => isVerifiedData(node))) chain.push('goal(data)');
  return chain;
}

export function winningChain(state) {
  const paths = computeCrownPaths(state, { limit: 1 });
  if (paths.length > 0) {
    const chain = generalizeChainFromIds(state, paths[0].nodes);
    if (chain.length > 1) return chain;
  }
  return fallbackChain(state);
}

function scrubChain(value) {
  const text = String(value ?? '').trim();
  if (text.length === 0) return '';
  const raw = text.includes('→') ? text.split('→') : text.split('->');
  const out = [];
  for (const part of raw) {
    const token = part.trim().toLowerCase();
    if (!token) continue;
    if (!/^[a-z_]+(?:\([a-z0-9_]+\))?$/u.test(token)) continue;
    if (!out.includes(token)) out.push(token);
  }
  return out.join(' → ');
}

function keepThought(value, when) {
  const text = String(value ?? '').replace(/\s+/gu, ' ').trim();
  if (text.length < 8 || text.length > 240) return '';
  if (FORBIDDEN_TEXT_RE.test(text)) return '';
  const lowered = text.toLowerCase();
  for (const stack of STACK_TOKENS) {
    if (when.includes(stack)) continue;
    if (new RegExp(`(?:^|[^a-z0-9])${stack}(?:[^a-z0-9]|$)`, 'u').test(lowered)) return '';
  }
  return text;
}

/** Reject/clean one lesson draft before it can reach disk or graph state. */
export function sanitizeLesson(raw) {
  if (raw === null || typeof raw !== 'object') return null;
  const when = uniqueTokens(raw.when ?? raw.tech ?? raw.cues, new Set([...STACK_TOKENS, ...CUE_TOKENS]), 8);
  const doTokens = uniqueTokens(raw.do ?? raw.techniques, TACTICS, 6);
  const avoid = uniqueTokens(raw.avoid ?? raw.failed_techniques, TACTICS, 6);
  const chain = scrubChain(raw.chain ?? raw.winning_chain ?? raw.route);
  const idea = keepThought(raw.idea, when);
  const method = keepThought(raw.method, when);
  const route = keepThought(raw.route, when) || chain;
  if (doTokens.length === 0 && avoid.length === 0 && chain.length === 0 && !(idea && method)) return null;
  if (chain.length > 0 && !/\(/u.test(chain)) return null;
  const confidence = clamp(Number(raw.confidence) || 0.4, MIN_CONF, MAX_CONF);
  const lessonKey = lessonKeyFor({ when, do: doTokens, avoid, chain });
  return {
    lessonKey,
    idea,
    method,
    route,
    chain,
    when,
    do: doTokens,
    avoid,
    confidence,
    wins: Math.max(0, Number(raw.wins) || 0),
    fails: Math.max(0, Number(raw.fails) || 0),
    uses: Math.max(0, Number(raw.uses) || 0),
    status: raw.status === 'retired' ? 'retired' : 'active',
    sourceEngagementHash: typeof raw.sourceEngagementHash === 'string' ? raw.sourceEngagementHash.slice(0, 32) : null,
    sourceOutcome: ['shell', 'data', 'admin', 'finding', 'impact', null].includes(raw.sourceOutcome) ? raw.sourceOutcome : null,
    sourceFindingClasses: Array.isArray(raw.sourceFindingClasses)
      ? raw.sourceFindingClasses.slice(0, 12).map((entry) => String(entry).replace(/[^A-Za-z0-9:_-]/gu, '').slice(0, 80))
      : [],
    createdAt: typeof raw.createdAt === 'string' ? raw.createdAt : new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastUsedAt: typeof raw.lastUsedAt === 'string' ? raw.lastUsedAt : null,
  };
}


/** Sanitize one free-text skill field; rejects target identifiers, ports and secrets. */
export function sanitizeSkillText(value, { when = [], maxLength = 800 } = {}) {
  const text = String(value ?? '').replace(/\s+/gu, ' ').trim();
  if (text.length < 8 || text.length > maxLength) return '';
  if (FORBIDDEN_TEXT_RE.test(text)) return '';
  const allowed = new Set(Array.isArray(when) ? when : []);
  const lowered = text.toLowerCase();
  for (const stack of STACK_TOKENS) {
    if (allowed.has(stack)) continue;
    if (new RegExp(`(?:^|[^a-z0-9])${stack}(?:[^a-z0-9]|$)`, 'u').test(lowered)) return '';
  }
  return text;
}

/** Normalize token arrays for skills using the same allowlists as lessons. */
export function normalizeSkillTokens(values, allowed, limit = 8) {
  return uniqueTokens(values, allowed, limit);
}

/** Normalize a type chain for a skill. */
export function sanitizeSkillChain(value) {
  return scrubChain(value);
}

export function lessonKeyFor({ when, do: doTokens, avoid, chain }) {
  const raw = [
    [...(when ?? [])].sort().join(','),
    [...(doTokens ?? [])].sort().join(','),
    [...(avoid ?? [])].sort().join(','),
    String(chain ?? ''),
  ].join('|');
  return shortHash(raw, 16);
}

export function confidenceFor(wins, fails, uses) {
  let base = 0.4 + 0.12 * Math.max(0, Number(wins) || 0) - 0.14 * Math.max(0, Number(fails) || 0);
  if ((Number(uses) || 0) >= 4 && (Number(wins) || 0) === 0) base -= 0.1;
  return clamp(base, MIN_CONF, MAX_CONF);
}

function dataThresholdMet(node, config) {
  if (node.attrs?.thresholdMet === true) return true;
  const threshold = Number(config?.bulkThresholds?.[node.attrs?.dataClass]) || 0;
  return threshold > 0 && Number(node.attrs?.count) >= threshold;
}

/** Whether current graph evidence qualifies for evolution. */
export function qualifiesForEvolution(state, config) {
  const nodes = Object.values(state.nodes ?? {});
  const verifiedHigh = nodes.filter((node) => isVerifiedFinding(node)
    && isHighCriticalFinding(node)
    && !claimGuardForFinding(node)
    && (node.attrs?.secondaryVerified === true || node.status === 'exploited' || node.status === 'impacted')
    && (Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0) > 0);
  const access = nodes.filter((node) => isValidatedAccess(node));
  const data = nodes.filter((node) => isVerifiedData(node) && dataThresholdMet(node, config));
  const candidateHigh = nodes.filter((node) => isCandidateHighCritical(node));
  return {
    qualified: verifiedHigh.length > 0 || access.length > 0 || data.length > 0,
    verifiedHigh,
    access,
    data,
    candidateHigh,
    reasons: [
      ...(verifiedHigh.length > 0 ? [`${verifiedHigh.length} verified high/critical finding(s)`] : []),
      ...(access.length > 0 ? [`${access.length} validated access path(s)`] : []),
      ...(data.length > 0 ? [`${data.length} verified bulk-data evidence set(s)`] : []),
    ],
  };
}

function outcomeClassOf({ access, data }) {
  if (access.length === 0 && data.length === 0) return 'finding';
  if (access.some((node) => ['admin_panel', 'db_admin', 'domain_admin', 'cloud_admin'].includes(String(node.attrs?.kind)))) return 'admin';
  if (data.length > 0) return 'data';
  if (access.length > 0) return 'shell';
  return 'finding';
}

/** Build a host-free episode for storage / AI refinement / lesson drafts. */
export function buildEpisode(state, { sourceEngagementHash = null, outcome = null, config = {}, loop = null } = {}) {
  const qualification = qualifiesForEvolution(state, config);
  const nodes = Object.values(state.nodes ?? {});
  const tactics = [...new Set([
    ...qualification.verifiedHigh.map(tacticForFinding),
    ...qualification.access.map((node) => {
      const kind = String(node.attrs?.kind ?? '');
      if (/admin|db_admin|domain|cloud/.test(kind)) return 'access_control';
      if (/db_read|data/.test(kind)) return 'data_access';
      return 'privesc_lateral';
    }),
    ...(qualification.data.length > 0 ? ['data_access'] : []),
  ])];
  const cues = [...new Set([
    ...qualification.verifiedHigh.map(cueForFinding),
    ...(qualification.access.length > 0 ? ['foothold'] : []),
    ...(qualification.data.length > 0 ? ['data_access'] : []),
  ])];
  const failed = [...new Set(nodes.filter((node) => node.kind === 'intent' && node.status === 'refuted')
    .map((node) => String(node.attrs?.actionType ?? '').replace(/^verify_|^enumerate_|^validate_/u, ''))
    .filter(Boolean))];
  const chain = winningChain(state);
  return {
    occurredAt: new Date().toISOString(),
    objective: String(loop?.attrs?.objective ?? state.engagement?.name ?? 'engagement').slice(0, 300),
    outcomeClass: outcome ?? outcomeClassOf(qualification),
    targetFp: graphStackTokens(state).join('|') || 'web',
    chain: chain.join(' → '),
    tactics: tactics.slice(0, 8),
    cues: cues.slice(0, 8),
    failedTechniques: failed.slice(0, 6),
    findingClasses: qualification.verifiedHigh.map((node) => `${node.attrs?.template ?? 'finding'}:${findingSeverity(node)}`),
    accessKinds: qualification.access.map((node) => String(node.attrs?.kind ?? 'access')),
    dataClasses: qualification.data.map((node) => String(node.attrs?.dataClass ?? 'internal')),
    sourceEngagementHash,
    qualifying: qualification.qualified,
  };
}

function defaultIdea(tactics, stack) {
  const tactic = tactics[0] ?? 'finding_read_loot';
  const tech = stack.slice(0, 3).join('/') || 'web';
  return `On ${tech}, the ${tactic} path is worth probing because it converts an observed surface into a re-checkable high-impact result.`;
}

function defaultMethod(tactics) {
  const tactic = tactics[0] ?? 'finding_read_loot';
  return `Confirm the ${tactic} surface with a non-destructive probe, record the exact evidence, then push the verified impact toward access or data.`;
}

/** Deterministic lesson drafts; AI refinement is optional and re-sanitized. */
export function deterministicLessons(state, episode) {
  if (!episode.qualifying) return [];
  const stack = [...new Set((episode.targetFp ?? '').split('|').filter(Boolean))];
  const when = [...new Set([...stack, ...episode.cues])].slice(0, 8);
  const doTokens = episode.tactics.length > 0 ? episode.tactics.slice(0, 4) : ['finding_read_loot'];
  const avoid = (episode.failedTechniques ?? []).slice(0, 3);
  const base = {
    when,
    do: doTokens,
    avoid,
    chain: episode.chain,
    route: episode.chain,
    idea: defaultIdea(doTokens, stack),
    method: defaultMethod(doTokens),
    confidence: episode.outcomeClass === 'finding' ? 0.45 : 0.55,
    wins: episode.outcomeClass === 'finding' ? 0 : 1,
    fails: 0,
    uses: 0,
    sourceEngagementHash: episode.sourceEngagementHash,
    sourceOutcome: episode.outcomeClass,
    sourceFindingClasses: episode.findingClasses,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  const lesson = sanitizeLesson(base);
  return lesson === null ? [] : [lesson];
}

/** Extract a JSON lesson list from a free-form model reply. */
export function parseEvolveLessons(text) {
  const raw = String(text ?? '').trim();
  if (!raw) return [];
  let blob = '';
  const fence = /```(?:json)?\s*([\s\S]*?)\s*```/u.exec(raw);
  if (fence) blob = fence[1].trim();
  else {
    const starts = [raw.indexOf('{'), raw.indexOf('[')].filter((index) => index >= 0);
    const start = starts.length === 0 ? -1 : Math.min(...starts);
    if (start >= 0) {
      const open = raw[start];
      const close = open === '{' ? '}' : ']';
      let depth = 0;
      let inString = false;
      let escaped = false;
      for (let index = start; index < raw.length; index += 1) {
        const character = raw[index];
        if (inString) {
          if (escaped) escaped = false;
          else if (character === '\\') escaped = true;
          else if (character === '"') inString = false;
          continue;
        }
        if (character === '"') { inString = true; continue; }
        if (character === open) depth += 1;
        else if (character === close) {
          depth -= 1;
          if (depth === 0) { blob = raw.slice(start, index + 1); break; }
        }
      }
    }
  }
  if (!blob) return [];
  try {
    const data = JSON.parse(blob);
    const list = Array.isArray(data) ? data : data.lessons;
    if (!Array.isArray(list)) return [];
    return list.slice(0, 3).filter((entry) => entry && typeof entry === 'object');
  } catch {
    return [];
  }
}

/** Merge a lesson draft into an existing lesson, preserving outcome counters. */
export function mergeLesson(existing, incoming) {
  if (existing === undefined || existing === null) return sanitizeLesson(incoming);
  const when = [...new Set([...(existing.when ?? []), ...(incoming.when ?? [])])].slice(0, 8);
  const doTokens = [...new Set([...(existing.do ?? []), ...(incoming.do ?? [])])].slice(0, 6);
  const avoid = [...new Set([...(existing.avoid ?? []), ...(incoming.avoid ?? [])])].slice(0, 6);
  const merged = {
    ...existing,
    ...incoming,
    when,
    do: doTokens,
    avoid,
    idea: (String(incoming.idea ?? '').length > String(existing.idea ?? '').length ? incoming.idea : existing.idea) ?? '',
    method: (String(incoming.method ?? '').length > String(existing.method ?? '').length ? incoming.method : existing.method) ?? '',
    route: incoming.route || existing.route,
    chain: incoming.chain || existing.chain,
    wins: Number(existing.wins ?? 0) + (incoming.wins ? 1 : 0),
    fails: Number(existing.fails ?? 0) + (incoming.fails ? 1 : 0),
    uses: Number(existing.uses ?? 0),
    status: existing.status === 'retired' ? 'retired' : 'active',
    sourceEngagementHash: incoming.sourceEngagementHash ?? existing.sourceEngagementHash,
    sourceOutcome: incoming.sourceOutcome ?? existing.sourceOutcome,
  };
  merged.confidence = confidenceFor(merged.wins, merged.fails, merged.uses);
  return sanitizeLesson(merged);
}

export function lessonConsumesEvidence(lesson, signals) {
  const required = (lesson.do ?? []).map((entry) => TACTIC_ALIASES[entry] ?? entry).filter(Boolean);
  if (required.length === 0) return true;
  return required.every((token) => signals.has(token) || (lesson.when ?? []).includes(token));
}

export function scoreLesson(lesson, signals, confidence = lesson.confidence) {
  const when = new Set(lesson.when ?? []);
  const doTokens = new Set((lesson.do ?? []).map((entry) => TACTIC_ALIASES[entry] ?? entry));
  const whenHit = [...when].filter((token) => signals.has(token)).length;
  const doHit = [...doTokens].filter((token) => signals.has(token)).length;
  const stackHit = [...when].filter((token) => STACK_TOKENS.has(token) && signals.has(token)).length;
  if (whenHit === 0 && doHit === 0 && stackHit === 0) return 0;
  if (!lessonConsumesEvidence(lesson, signals)) return 0;
  const avoidHit = (lesson.avoid ?? []).some((token) => signals.has(token));
  return Number(confidence ?? 0.4) * 0.45 + 0.28 * whenHit + 0.22 * doHit + 0.12 * stackHit + (avoidHit ? 0.08 : 0);
}

/** Fold append-only records into the latest lesson per key. */
export function foldLessonRecords(records) {
  const map = new Map();
  for (const record of Array.isArray(records) ? records : []) {
    if (!record || typeof record !== 'object') continue;
    const lesson = record.lesson ?? record;
    if (!lesson || typeof lesson !== 'object' || typeof lesson.lessonKey !== 'string') continue;
    const clean = sanitizeLesson(lesson);
    if (clean === null) continue;
    map.set(clean.lessonKey, clean);
  }
  return [...map.values()];
}

export function retrieveLessons(records, {
  state,
  limit = 6,
  sourceEngagementHash = null,
  includeSelf = false,
} = {}) {
  const signals = graphSignals(state);
  const lessons = foldLessonRecords(records)
    .filter((lesson) => lesson.status === 'active')
    .filter((lesson) => includeSelf || !sourceEngagementHash || lesson.sourceEngagementHash !== sourceEngagementHash);
  const ranked = lessons
    .map((lesson) => ({ lesson, score: scoreLesson(lesson, signals) }))
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score || b.lesson.confidence - a.lesson.confidence)
    .slice(0, Math.max(1, Math.min(20, Number(limit) || 6)));
  return ranked.map((entry) => entry.lesson);
}

export function formatLessonBlock(lessons) {
  if (!Array.isArray(lessons) || lessons.length === 0) return '';
  const lines = ['## Evolution experience (advisory only; re-verify on this target)'];
  for (const lesson of lessons) {
    lines.push(`- ${lesson.idea || lesson.method || lesson.route} | route: ${lesson.route} | tactics: ${(lesson.do ?? []).join(', ') || '—'} | when: ${(lesson.when ?? []).join(', ') || '—'} | confidence ${Number(lesson.confidence).toFixed(2)}`);
  }
  return lines.join('\n');
}

export function reinforceLesson(lesson, outcome) {
  const next = { ...lesson };
  if (outcome === 'win') next.wins = (Number(next.wins) || 0) + 1;
  else if (outcome === 'loss') next.fails = (Number(next.fails) || 0) + 1;
  next.uses = (Number(next.uses) || 0) + 1;
  next.lastUsedAt = new Date().toISOString();
  next.confidence = confidenceFor(next.wins, next.fails, next.uses);
  if (next.uses >= 4 && next.wins === 0 && next.confidence <= 0.25) next.status = 'retired';
  return sanitizeLesson(next);
}

export function markLessonUsed(lesson) {
  const next = {
    ...lesson,
    uses: (Number(lesson.uses) || 0) + 1,
    lastUsedAt: new Date().toISOString(),
  };
  next.confidence = confidenceFor(next.wins, next.fails, next.uses);
  return sanitizeLesson(next);
}

/** Resolve the lesson store path; defaults to a user-level cross-engagement store. */
export function resolveLessonStore(workspace, config) {
  const configured = typeof config?.lessonStore === 'string' ? config.lessonStore.trim() : '';
  if (configured.length > 0) {
    return path.isAbsolute(configured) ? configured : path.resolve(workspace, configured);
  }
  return path.join(os.homedir(), '.dsh', 'atkbrain', 'memory', 'lessons.jsonl');
}

export function episodeStorePath(lessonStore) {
  return path.join(path.dirname(lessonStore), 'episodes.jsonl');
}

async function readTail(filePath) {
  try {
    const info = await stat(filePath);
    if (!info.isFile() || info.size === 0) return [];
    const size = Math.min(info.size, MAX_LESSON_BYTES);
    const start = Math.max(0, info.size - size);
    const handle = await open(filePath, 'r');
    try {
      const buffer = Buffer.alloc(size);
      await handle.read(buffer, 0, size, start);
      const text = buffer.toString('utf8');
      const lines = text.split('\n');
      if (start > 0) lines.shift();
      return lines.filter((line) => line.trim().length > 0).slice(-MAX_LESSON_LINES);
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

export async function readLessonRecords(lessonStore) {
  const lines = await readTail(lessonStore);
  const records = [];
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === 'object') records.push(parsed);
    } catch {
      /* one corrupt line must not poison the playbook */
    }
  }
  return records;
}

export async function appendLessonRecords(lessonStore, records) {
  if (!Array.isArray(records) || records.length === 0) return;
  const text = records.map((record) => JSON.stringify(record)).join('\n') + '\n';
  const write = async () => {
    await mkdir(path.dirname(lessonStore), { recursive: true });
    await appendFile(lessonStore, text, { encoding: 'utf8', mode: 0o600 });
  };
  appendChain = appendChain.then(write, write);
  return appendChain;
}

export async function appendEpisode(lessonStore, episode) {
  const file = episodeStorePath(lessonStore);
  const text = JSON.stringify({ kind: 'episode', episode }) + '\n';
  const write = async () => {
    await mkdir(path.dirname(file), { recursive: true });
    await appendFile(file, text, { encoding: 'utf8', mode: 0o600 });
  };
  appendChain = appendChain.then(write, write);
  return appendChain;
}

export async function readLessons(lessonStore) {
  return foldLessonRecords(await readLessonRecords(lessonStore));
}

export async function writeLessonSnapshot(lessonStore, lessons) {
  if (!Array.isArray(lessons) || lessons.length === 0) return;
  await appendLessonRecords(lessonStore, lessons.map((lesson) => ({ kind: 'lesson', lesson })));
}
