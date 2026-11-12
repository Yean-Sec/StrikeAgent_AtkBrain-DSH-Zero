/**
 * Weighted shortest paths from realized footholds to crown-jewel targets.
 *
 * The graph is small enough (bounded by the Host state caps) for a
 * deterministic multi-source Dijkstra. Edge weights follow the plan:
 * structural membership is cheap, exploit/credential/pivot edges are dearer,
 * and every weight is divided by confidence so uncertain links cost more.
 */
import { NODE_KIND_RANK } from './constants.js';
import { shortHash } from './util.js';

const EDGE_WEIGHT = Object.freeze({
  contains: 0.5,
  resolves_to: 0.5,
  cname: 0.5,
  hosted_on: 0.5,
  exposes: 3,
  affects: 3,
  authenticates_to: 2,
  controls: 1,
  pivots_to: 4,
  reached_via: 1,
  proves: 0,
  derived_from: 0,
  merged_into: 0,
  duplicate_of: 0,
});

const CROWN_PRIVILEGES = new Set(['admin', 'root', 'domain_admin', 'cloud_admin', 'db_admin', 'administrator']);

/** Whether one node represents a high-value target. */
export function isCrownJewel(node) {
  if (node === undefined || node === null) return false;
  const attrs = node.attrs ?? {};
  if (attrs.crownJewel === true) return true;
  if (Number(attrs.criticality) >= 4) return true;
  if (Array.isArray(attrs.tags) && attrs.tags.includes('crown_jewel')) return true;
  if (node.kind === 'data' && (node.status === 'verified' || attrs.thresholdMet === true)) return true;
  if (node.kind === 'credential' && CROWN_PRIVILEGES.has(String(attrs.privilege))) return true;
  if (node.kind === 'access' && CROWN_PRIVILEGES.has(String(attrs.privilege))) return true;
  if (node.kind === 'host' && attrs.crownJewel === true) return true;
  return false;
}

/** Realized footholds usable as path sources. */
function isFoothold(node) {
  if (node === undefined || node === null) return false;
  if (node.kind === 'access') return ['obtained', 'validated', 'escalated'].includes(node.status) || node.attrs?.validated === true;
  if (node.kind === 'pivot') return node.status === 'verified' || node.attrs?.verified === true;
  return false;
}

/** Minimal binary heap keyed by (cost, pathKey). */
class Heap {
  constructor() {
    this.items = [];
  }

  get size() {
    return this.items.length;
  }

  push(item) {
    this.items.push(item);
    let index = this.items.length - 1;
    while (index > 0) {
      const parent = (index - 1) >> 1;
      if (this.compare(this.items[parent], this.items[index]) <= 0) break;
      [this.items[parent], this.items[index]] = [this.items[index], this.items[parent]];
      index = parent;
    }
  }

  pop() {
    const top = this.items[0];
    const last = this.items.pop();
    if (this.items.length > 0 && last !== undefined) {
      this.items[0] = last;
      let index = 0;
      for (;;) {
        const left = index * 2 + 1;
        const right = left + 1;
        let smallest = index;
        if (left < this.items.length && this.compare(this.items[left], this.items[smallest]) < 0) smallest = left;
        if (right < this.items.length && this.compare(this.items[right], this.items[smallest]) < 0) smallest = right;
        if (smallest === index) break;
        [this.items[smallest], this.items[index]] = [this.items[index], this.items[smallest]];
        index = smallest;
      }
    }
    return top;
  }

  compare(a, b) {
    if (a.cost !== b.cost) return a.cost - b.cost;
    return a.pathKey < b.pathKey ? -1 : a.pathKey > b.pathKey ? 1 : 0;
  }
}

function edgeCost(edge) {
  const base = EDGE_WEIGHT[edge.kind] ?? 1;
  const confidence = Number.isFinite(edge.confidence) ? Math.max(0.1, edge.confidence) : 0.5;
  return base / confidence;
}

/** Build adjacency once per path computation. */
function buildAdjacency(state) {
  const outgoing = new Map();
  for (const edge of Object.values(state.edges)) {
    if (state.nodes[edge.from] === undefined || state.nodes[edge.to] === undefined) continue;
    let list = outgoing.get(edge.from);
    if (list === undefined) {
      list = [];
      outgoing.set(edge.from, list);
    }
    list.push(edge);
  }
  for (const list of outgoing.values()) {
    list.sort((a, b) => (a.to < b.to ? -1 : a.to > b.to ? 1 : a.id < b.id ? -1 : 1));
  }
  return outgoing;
}

/** Reconstruct an ordered step list from the predecessor map. */
function reconstruct(targetId, prev) {
  const steps = [];
  const nodes = [targetId];
  let current = targetId;
  let guard = 0;
  while (guard < 512) {
    guard += 1;
    const parent = prev.get(current);
    if (parent === undefined) break;
    steps.unshift({
      from: parent.from,
      to: current,
      edgeId: parent.edgeId,
      kind: parent.kind,
      cost: parent.cost,
    });
    nodes.unshift(parent.from);
    current = parent.from;
  }
  // `unshift` already builds the path from source to target.
  return { steps, nodes };
}

/**
 * Multi-source Dijkstra to crown-jewel nodes.
 * @returns {{chainId:string, targetId:string, cost:number, steps:object[], nodes:string[], pathKey:string}[]}
 */
export function computeCrownPaths(state, options = {}) {
  const limit = Number.isInteger(options.limit) ? Math.max(1, Math.min(20, options.limit)) : 3;
  const maxRelaxations = Number.isInteger(options.maxRelaxations) ? options.maxRelaxations : 250000;
  const sources = Object.values(state.nodes).filter(isFoothold);
  const targets = Object.values(state.nodes).filter(isCrownJewel);
  if (sources.length === 0 || targets.length === 0) return [];

  const adjacency = buildAdjacency(state);
  const dist = new Map();
  const prev = new Map();
  const heap = new Heap();
  for (const source of sources) {
    const cost = 0;
    dist.set(source.id, cost);
    heap.push({ id: source.id, cost, pathKey: source.id });
  }

  let relaxations = 0;
  const settled = new Set();
  while (heap.size > 0 && relaxations < maxRelaxations) {
    const current = heap.pop();
    if (settled.has(current.id)) continue;
    settled.add(current.id);
    const base = dist.get(current.id);
    if (current.cost > base) continue;
    for (const edge of adjacency.get(current.id) ?? []) {
      relaxations += 1;
      if (relaxations > maxRelaxations) break;
      const nextCost = current.cost + edgeCost(edge);
      const previous = dist.get(edge.to);
      if (previous !== undefined && previous <= nextCost) continue;
      dist.set(edge.to, nextCost);
      prev.set(edge.to, {
        from: current.id,
        edgeId: edge.id,
        kind: edge.kind,
        cost: nextCost - current.cost,
      });
      heap.push({ id: edge.to, cost: nextCost, pathKey: `${current.pathKey}>${edge.to}` });
    }
  }

  const results = [];
  for (const target of targets) {
    const cost = dist.get(target.id);
    if (cost === undefined) continue;
    const path = reconstruct(target.id, prev);
    const pathKey = path.nodes.join('>');
    results.push({
      chainId: `crown_${shortHash(`${pathKey}`, 18)}`,
      targetId: target.id,
      targetKind: target.kind,
      targetLabel: target.label,
      cost: Number(cost.toFixed(3)),
      ...path,
      pathKey,
      rank: NODE_KIND_RANK[target.kind] ?? 99,
    });
  }
  results.sort((a, b) => a.cost - b.cost || a.rank - b.rank || (a.pathKey < b.pathKey ? -1 : 1));
  const seen = new Set();
  const unique = [];
  for (const result of results) {
    if (seen.has(result.pathKey)) continue;
    seen.add(result.pathKey);
    unique.push(result);
    if (unique.length >= limit) break;
  }
  return unique;
}

/** Compact crown-path summary for the wire view. */
export function crownPathSummary(state, limit = 3) {
  return computeCrownPaths(state, { limit }).map((path) => ({
    chainId: path.chainId,
    targetId: path.targetId,
    targetKind: path.targetKind,
    targetLabel: path.targetLabel,
    cost: path.cost,
    nodes: path.nodes,
    steps: path.steps,
  }));
}
