/**
 * Dependency-free helpers shared by the Host half and its unit tests.
 *
 * Nothing here imports a DSH package on purpose: the bundle is a linked local
 * package and must not depend on the installation's module resolver.
 */
import { createHash, createHmac } from 'node:crypto';
import { createReadStream, realpathSync } from 'node:fs';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SECRET_KEY_PATTERN } from './constants.js';

/** Error type for actionable, model-correctable tool input problems. */
export class InputError extends Error {
  constructor(message, code = 'ATK_INVALID_ARGS') {
    super(message);
    this.name = 'InputError';
    this.code = code;
  }
}

/** Throw one actionable input error. */
export function invalid(message) {
  throw new InputError(message);
}

/** Hex SHA-256 of a string or buffer. */
export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

/** First `length` hex characters of the SHA-256 of `value`. */
export function shortHash(value, length = 18) {
  return sha256Hex(String(value)).slice(0, length);
}

/** Stable, short, prefixed node id for a canonical key. */
export function nodeId(kind, key) {
  return `${String(kind).replace(/[^a-z_]/g, '')}_${shortHash(`${kind}\u001f${key}`, 18)}`;
}

/** Stable, short edge id for a directed triple. */
export function edgeId(from, kind, to) {
  return `edg_${shortHash(`${from}\u001f${kind}\u001f${to}`, 18)}`;
}

/** Stable action id, used to dedupe frontier proposals. */
export function actionId(type, targetId, params = '') {
  return `tsk_${shortHash(`${type}\u001f${targetId}\u001f${params}`, 18)}`;
}

/** HMAC-SHA-256 prefix used to fingerprint secrets without storing them. */
export function hmac16(salt, value) {
  return createHmac('sha256', String(salt || 'atkbrain')).update(String(value)).digest('hex').slice(0, 16);
}

/** Current time as an ISO string (the only wall-clock source in tools). */
export function nowIso() {
  return new Date().toISOString();
}

/** Epoch milliseconds as an ISO string, for imported observation timestamps. */
export function isoFrom(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value).toISOString();
  if (typeof value === 'string' && value.length > 0) {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return new Date(parsed).toISOString();
  }
  return nowIso();
}

/** Plain JSON object test. */
export function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Detached JSON clone. */
export function clone(value) {
  if (value === undefined) return value;
  try {
    return structuredClone(value);
  } catch {
    return JSON.parse(JSON.stringify(value));
  }
}

/** UTF-8 byte length without allocating a buffer when possible. */
export function byteLength(value) {
  return Buffer.byteLength(String(value), 'utf8');
}

/** Truncate a string to at most `max` characters, appending an ellipsis marker. */
export function truncate(value, max = 2000) {
  const text = String(value ?? '');
  if (text.length <= max) return text;
  return `${text.slice(0, Math.max(0, max - 1))}\u2026`;
}

/** Sorted unique strings. */
export function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === 'string' && value.length > 0))].sort();
}

/** Union of two string arrays, sorted for deterministic output. */
export function unionStrings(a = [], b = []) {
  return uniqueStrings([...(Array.isArray(a) ? a : []), ...(Array.isArray(b) ? b : [])]);
}

/** Clamp a number. */
export function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

/** Array coercion. */
export function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

/** Non-empty trimmed string or undefined. */
export function asString(value) {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

/** Finite number or undefined. */
export function asNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/** Boolean coercion with a default. */
export function asBoolean(value, fallback = false) {
  return typeof value === 'boolean' ? value : fallback;
}

/** Validate a value against an allowed set. */
export function oneOf(value, allowed) {
  return allowed.includes(value) ? value : undefined;
}

/** Stable JSON serialization with sorted object keys (for hashes). */
export function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

/** JSON parse that returns undefined instead of throwing. */
export function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * Parse a human port specification.
 * Accepts `80`, `80,443`, `8000-8100`, `80,443,8000-8010` and whitespace or
 * semicolon separators. Claims are rejected instead of silently skipped.
 */
export function parsePortsSpec(spec, maxPorts = 1024) {
  const text = String(spec ?? '').trim();
  if (text.length === 0) invalid('ports is empty; pass e.g. "80,443,8000-8100"');
  const ports = new Set();
  for (const part of text.split(/[\s,;]+/u)) {
    if (part.length === 0) continue;
    const range = /^(\d{1,5})-(\d{1,5})$/u.exec(part);
    if (range !== null) {
      const start = Number(range[1]);
      const end = Number(range[2]);
      if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end > 65535 || start > end) {
        invalid(`invalid port range "${part}" (expected 1-65535 and start <= end)`);
      }
      if (end - start > 4096) invalid(`port range "${part}" is too large; scan at most 4097 ports per range`);
      for (let port = start; port <= end; port += 1) ports.add(port);
    } else {
      const port = Number(part);
      if (!Number.isInteger(port) || port < 1 || port > 65535) invalid(`invalid port "${part}" (expected 1-65535)`);
      ports.add(port);
    }
    if (ports.size > maxPorts) invalid(`too many ports: ${ports.size} > maxPortsPerCall ${maxPorts}`);
  }
  if (ports.size === 0) invalid('ports resolved to an empty set');
  return [...ports].sort((a, b) => a - b);
}

/** Abort-aware sleep. */
export function sleep(ms, signal) {
  if (!(ms > 0)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error('aborted'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener?.('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal.reason ?? new Error('aborted'));
    };
    signal?.addEventListener?.('abort', onAbort, { once: true });
  });
}

/** Settle a promise with a timeout; the original promise keeps running. */
export function withTimeout(promise, ms, label = 'operation') {
  if (!(ms > 0)) return promise;
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

/** Bounded-concurrency map preserving input order. */
export async function mapLimit(items, limit, mapper, signal) {
  const list = [...items];
  const results = new Array(list.length);
  let index = 0;
  const workerCount = Math.max(1, Math.min(limit, list.length));
  await Promise.all(Array.from({ length: workerCount }, async () => {
    for (;;) {
      if (signal?.aborted) throw signal.reason ?? new Error('aborted');
      const current = index;
      index += 1;
      if (current >= list.length) return;
      results[current] = await mapper(list[current], current);
    }
  }));
  return results;
}

/** Read a bounded UTF-8 file. */
export async function readTextFile(filePath, maxBytes = 50 * 1024 * 1024) {
  const info = await stat(filePath);
  if (info.size > maxBytes) {
    invalid(`file ${filePath} is ${info.size} bytes; the limit is ${maxBytes} bytes`);
  }
  return await readFile(filePath, 'utf8');
}

/** SHA-256 of a file without loading it in memory. */
export async function fileSha256(filePath) {
  const hash = createHash('sha256');
  await new Promise((resolve, reject) => {
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', resolve);
  });
  return hash.digest('hex');
}

/** Create a directory with secret-agent-friendly permissions. */
export async function ensureDir(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
}

/** Write a file with restrictive permissions. */
export async function writeFileSecure(filePath, data) {
  await ensureDir(path.dirname(filePath));
  await writeFile(filePath, data, { mode: 0o600 });
}

/** The session workspace, falling back to the process cwd. */
export function workspaceOf(agent) {
  return agent?.session?.header?.cwd || process.cwd();
}

function pluginPackageRoot() {
  return path.resolve(fileURLToPath(new URL('..', import.meta.url)));
}

/** The AtkBrain source checkout. Test runs must not store files here. */
export function isSourceTree(dir) {
  const target = path.resolve(dir);
  let plugin = pluginPackageRoot();
  let resolved = target;
  try { plugin = realpathSync(plugin); } catch { /* the package directory is the path itself */ }
  try { resolved = realpathSync(target); } catch { /* a new directory may not exist yet */ }
  if (isInside(plugin, resolved) || isInside(resolved, plugin)) return true;
  if (path.basename(plugin) === 'atk-brain' && isInside(path.dirname(plugin), resolved)) return true;
  return false;
}

/**
 * The directory the operator created for this test.
 * Evidence, reports and team files are stored here, never in the source checkout.
 */
export function runRoot(agent) {
  const workspace = path.resolve(workspaceOf(agent));
  if (isSourceTree(workspace)) throw new InputError('测试记录不能写进源代码目录，请换一个新建的测试目录');
  return workspace;
}

/** A plugin-owned relative path, not a file that belongs to the project. */
export function isPluginArtifactRelative(value) {
  const rel = String(value ?? '').trim().replace(/\\/gu, '/').replace(/^\.\//u, '');
  return rel === '.atkbrain' || rel.startsWith('.atkbrain/');
}

/** Map a logical `.atkbrain/...` path onto this session's private directory. */
export function artifactAbsolute(agent, relative) {
  const rel = String(relative ?? '').trim().replace(/\\/gu, '/').replace(/^\.\//u, '');
  if (rel.length === 0 || rel.startsWith('..') || rel.includes('/../') || path.isAbsolute(rel)) {
    throw new InputError('artifact path must be a relative .atkbrain path');
  }
  const logical = isPluginArtifactRelative(rel) ? rel : path.posix.join('.atkbrain', rel);
  return path.resolve(runRoot(agent), logical);
}

/** Logical `.atkbrain/...` path when `absolute` is inside this session's private directory. */
export function logicalArtifactRelative(agent, absolute) {
  const rel = path.relative(runRoot(agent), path.resolve(absolute)).replace(/\\/gu, '/');
  if (rel.length === 0 || rel.startsWith('..') || path.isAbsolute(rel)) return null;
  return rel;
}

/**
 * Open a path inside the test directory.
 * Logical `.atkbrain/...` paths stay in that directory, not in the source checkout.
 */
export function resolveArtifact(agent, workspace, input) {
  const text = String(input ?? '').trim();
  if (text.length === 0) invalid('path is empty');
  if (isPluginArtifactRelative(text)) return artifactAbsolute(agent, text);
  const absolute = resolvePath(workspace, text);
  const fromWorkspace = path.relative(path.resolve(workspace), absolute).replace(/\\/gu, '/');
  if (isPluginArtifactRelative(fromWorkspace)) return artifactAbsolute(agent, fromWorkspace);
  return absolute;
}

/** Resolve a user-supplied path against the session workspace. */
export function resolvePath(workspace, input) {
  const text = String(input ?? '').trim();
  if (text.length === 0) invalid('path is empty');
  return path.isAbsolute(text) ? path.normalize(text) : path.resolve(workspace, text);
}

/** Whether `child` is inside `parent` after resolution. */
export function isInside(parent, child) {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

/** Safe filename component. */
export function safeFileName(value, fallback = 'atkbrain') {
  const text = String(value ?? '')
    .replace(/[^\p{L}\p{N}._-]+/gu, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
  return text.length > 0 ? text : fallback;
}

/** Human count like 1.2k. */
export function formatCount(value) {
  const number = Number(value) || 0;
  if (number >= 1_000_000) return `${(number / 1_000_000).toFixed(1)}m`;
  if (number >= 1_000) return `${(number / 1_000).toFixed(1)}k`;
  return String(number);
}

/** Text content block for a tool result. */
export function textBlock(text) {
  return [{ type: 'text', text: String(text) }];
}

/** Remove obvious secret values from an object before it enters graph state. */
export function stripSecrets(value, depth = 0) {
  if (depth > 6) return undefined;
  if (Array.isArray(value)) return value.slice(0, 100).map((entry) => stripSecrets(entry, depth + 1)).filter((entry) => entry !== undefined);
  if (!isPlainObject(value)) return value;
  const out = {};
  for (const [key, entry] of Object.entries(value)) {
    if (SECRET_KEY_PATTERN.test(key)) continue;
    if (entry === undefined) continue;
    out[key] = stripSecrets(entry, depth + 1);
  }
  return out;
}

/** Compact one-line JSON for logs. */
export function logJson(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
