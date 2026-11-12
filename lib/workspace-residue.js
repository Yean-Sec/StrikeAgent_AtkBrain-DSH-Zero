/**
 * Files the executor saved on disk and then dropped.
 *
 * The graph is what later turns read. A page, header or tool file that never
 * becomes an evidence node is invisible after the turn that wrote it. Reports
 * and graph exports are deliverables, not forgotten observations.
 */
import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';

import { fileSha256, isSourceTree, workspaceOf } from './util.js';

const SKIP_TOP = new Set(['node_modules', '.git', 'reports', 'atk-brain', 'dist', 'coverage', '.cursor']);
const SKIP_SEGMENT = new Set(['node_modules', '.git', 'lib', 'test', 'src', 'dist']);
const OBSERVATION_EXT = new Set(['.html', '.htm', '.txt', '.hdr', '.xml', '.js', '.bin', '.har']);
const FILE_CAP = 80;

function normalizeRel(value) {
  return String(value ?? '').trim().replace(/\\/gu, '/').replace(/^\.\//u, '');
}

/** A saved observation, not a report, export, or project source tree. */
export function observationRelative(relative) {
  const rel = normalizeRel(relative);
  if (rel.length === 0 || rel.startsWith('..') || rel.includes('/../')) return false;
  const parts = rel.split('/').filter(Boolean);
  if (parts.length === 0 || parts.some((part) => SKIP_SEGMENT.has(part))) return false;
  if (parts[0] === '.atkbrain') return false;
  if (SKIP_TOP.has(parts[0]) || parts[0].startsWith('.')) return false;
  return OBSERVATION_EXT.has(path.posix.extname(rel).toLowerCase());
}

function linkedWorkspacePaths(nodes) {
  const linked = new Set();
  for (const node of Array.isArray(nodes) ? nodes : []) {
    const attrs = node?.attrs ?? {};
    for (const value of [attrs.relative, attrs.path, attrs.secondaryEvidencePath, attrs.artifactPath]) {
      const text = normalizeRel(value);
      if (text.length === 0) continue;
      linked.add(text);
      const marker = '.atkbrain/';
      const at = text.lastIndexOf(marker);
      if (at >= 0) linked.add(text.slice(at));
    }
  }
  return linked;
}

function isLinked(linked, relative) {
  if (linked.has(relative)) return true;
  const suffix = `/${relative}`;
  for (const item of linked) {
    if (item.endsWith(suffix)) return true;
  }
  return false;
}

/** Paths in `files` that no graph node points at. */
export function unreadWorkspaceFiles(nodes, files) {
  const linked = linkedWorkspacePaths(nodes);
  const out = [];
  for (const file of Array.isArray(files) ? files : []) {
    const rel = normalizeRel(file?.relative ?? file);
    if (!observationRelative(rel) || isLinked(linked, rel)) continue;
    out.push(rel);
    if (out.length >= FILE_CAP) break;
  }
  return out;
}

async function walk(dir, rel, depth, files) {
  if (files.length >= FILE_CAP || depth > 4) return;
  let dirents;
  try {
    dirents = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const dirent of dirents) {
    if (files.length >= FILE_CAP || dirent.name === '.DS_Store') continue;
    const childRel = rel.length > 0 ? `${rel}/${dirent.name}` : dirent.name;
    if (dirent.isDirectory()) {
      if (depth === 0 && (SKIP_TOP.has(dirent.name) || dirent.name.startsWith('.'))) continue;
      await walk(path.join(dir, dirent.name), childRel, depth + 1, files);
      continue;
    }
    if (!dirent.isFile()) continue;
    if (observationRelative(childRel)) files.push({ relative: childRel });
  }
}

/** Observation files in the session workspace that the graph does not reference. */
export async function listUnreadWorkspaceFiles(agent, nodes) {
  const root = workspaceOf(agent);
  const files = [];
  await walk(root, '', 0, files);
  return unreadWorkspaceFiles(nodes, files);
}

/**
 * Evidence files the plugin or the model saved in this test directory.
 * They belong to the test and must not block the next probe. The caller
 * records any file the graph does not already point at.
 */
export async function unlinkedPluginEvidence(agent, nodes) {
  const root = workspaceOf(agent);
  if (isSourceTree(root)) return [];
  const dir = path.join(root, '.atkbrain', 'evidence');
  let names;
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  const linked = linkedWorkspacePaths(nodes);
  const out = [];
  for (const name of names) {
    if (out.length >= 40 || name === '.DS_Store') continue;
    const ext = path.posix.extname(name).toLowerCase();
    if (!OBSERVATION_EXT.has(ext)) continue;
    const relative = `.atkbrain/evidence/${name}`;
    if (isLinked(linked, relative)) continue;
    const absolute = path.join(dir, name);
    let info;
    try {
      info = await stat(absolute);
    } catch {
      continue;
    }
    if (!info.isFile() || info.size <= 0) continue;
    out.push({
      path: absolute,
      relative,
      sha256: await fileSha256(absolute),
      bytes: info.size,
      mediaType: ext === '.json' ? 'application/json' : 'text/plain',
    });
  }
  return out;
}
