/**
 * Cluster / target coverage tree.
 *
 * A cluster is one entered scope domain (or a registrable-domain / IP group
 * when no anchor exists). Each child target is a live host/IP; interfaces,
 * findings, coverage, access and data are rolled up under it so a multi-target
 * engagement can prove every target was actually tested.
 */
import { canonicalHost } from './scope.js';
import { classifyFindingCvss, isVerifiedVulnerabilityNode } from './finding-classification.js';

const TWO_LEVEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'com.au', 'net.au', 'org.au', 'co.jp', 'com.br', 'com.hk', 'com.tw', 'co.kr', 'co.in',
  'com.sg', 'com.mx', 'com.tr', 'com.ru',
]);

function canonical(value) {
  const text = String(value ?? '').trim().replace(/^https?:\/\//iu, '').split('/')[0].replace(/^\[|\]$/gu, '');
  return canonicalHost(text) || text.toLowerCase();
}

function isIp(value) {
  const text = String(value ?? '');
  return /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(text) || (/^[0-9a-f:]+$/iu.test(text) && text.includes(':'));
}

function registrableDomain(host) {
  const labels = canonical(host).split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (TWO_LEVEL_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}

function scopeAnchors(state) {
  const allow = Array.isArray(state?.scope?.allow) ? state.scope.allow : [];
  const anchors = [];
  for (const entry of allow) {
    const type = String(entry?.type ?? '').toLowerCase();
    if (type !== 'domain' && type !== 'host') continue;
    const value = canonical(entry.value ?? entry.canonical ?? '');
    if (value.length === 0 || isIp(value) || value.includes('*')) continue;
    if (!anchors.includes(value)) anchors.push(value);
  }
  return anchors;
}

function anchorForHost(host, anchors) {
  const value = canonical(host);
  let matched = null;
  for (const anchor of anchors) {
    if (value === anchor || value.endsWith(`.${anchor}`)) {
      if (matched === null || anchor.length > matched.length) matched = anchor;
    }
  }
  return matched;
}

function endpointHost(value) {
  let text = String(value ?? '').trim();
  if (text.includes('://')) text = text.slice(text.indexOf('://') + 3);
  text = text.split('/')[0].split('?')[0].split('#')[0];
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end > 0) text = text.slice(1, end);
  } else if (text.split(':').length === 2 && /^\d+$/u.test(text.split(':')[1])) {
    text = text.split(':')[0];
  }
  return canonical(text);
}

function ipAllowedByScope(host, allowEntries) {
  const value = canonical(host);
  for (const entry of allowEntries) {
    const type = String(entry?.type ?? '').toLowerCase();
    const allowed = canonical(entry?.value ?? entry?.canonical ?? '');
    if (type === 'ip' && allowed === value) return true;
    if (type === 'cidr') {
      const [network, bitsText] = allowed.split('/');
      if (!/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(value) || !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(network)) continue;
      const bits = Number(bitsText);
      if (!Number.isInteger(bits) || bits < 0 || bits > 32) continue;
      const toInt = (ip) => ip.split('.').reduce((acc, part) => (acc * 256) + Number(part), 0);
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      if ((toInt(value) & mask) === (toInt(network) & mask)) return true;
    }
  }
  return false;
}

function nodeHost(node) {
  const attrs = node.attrs ?? {};
  const raw = attrs.fqdn ?? attrs.addr ?? attrs.host ?? attrs.hostname ?? node.label;
  return canonical(raw);
}

export function buildTargetTree(state) {
  const nodes = Object.values(state?.nodes ?? {}).filter((node) => node.status !== 'merged');
  const edges = Object.values(state?.edges ?? {});
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const anchors = scopeAnchors(state);
  const adjacency = new Map();
  for (const edge of edges) {
    if (!byId.has(edge.from) || !byId.has(edge.to)) continue;
    if (!adjacency.has(edge.from)) adjacency.set(edge.from, new Set());
    if (!adjacency.has(edge.to)) adjacency.set(edge.to, new Set());
    adjacency.get(edge.from).add(edge.to);
    adjacency.get(edge.to).add(edge.from);
  }
  const allowEntries = Array.isArray(state?.scope?.allow) ? state.scope.allow : [];
  const domainHostExists = nodes.some((node) => node.kind === 'host');
  // Resolved IPs are infrastructure, not child targets, unless the operator
  // explicitly authorized an IP/CIDR or there is no domain host at all.
  const hostNodes = nodes.filter((node) => node.kind === 'host' || (node.kind === 'ip' && (!domainHostExists || ipAllowedByScope(nodeHost(node), allowEntries))));
  const domainNodes = nodes.filter((node) => node.kind === 'domain');
  const targets = new Map();
  const targetByHost = new Map();
  function ensureTarget(node) {
    if (targets.has(node.id)) return targets.get(node.id);
    const host = targetIdentity(nodeHost(node))?.host || nodeHost(node);
    if (targetByHost.has(host)) {
      const existing = targetByHost.get(host);
      existing.nodeIds.push(node.id);
      return existing;
    }
    const anchor = anchorForHost(host, anchors);
    const clusterLabel = anchor
      ?? (isIp(host) ? `${host.split('.').slice(0, 3).join('.')}.0/24` : registrableDomain(host))
      ?? host;
    const clusterKey = `cluster:${clusterLabel}`;
    const target = {
      id: node.id,
      kind: node.kind,
      label: node.label,
      host,
      clusterKey,
      clusterLabel,
      services: 0,
      webapps: 0,
      tech: 0,
      interfaces: 0,
      findings: 0,
      verifiedFindings: 0,
      vulnerabilities: 0,
      unscoredFindings: 0,
      coverageCells: 0,
      coverageSeen: 0,
      access: 0,
      data: 0,
      credentials: 0,
      status: 'untested',
      nodeIds: [],
    };
    targets.set(node.id, target);
    targetByHost.set(host, target);
    return target;
  }
  for (const node of hostNodes) ensureTarget(node);
  // A domain without a host node is still a target (e.g. an apex only observed in DNS).
  for (const node of domainNodes) {
    const host = nodeHost(node);
    if (![...targets.values()].some((target) => target.host === host)) ensureTarget(node);
  }
  const targetByNode = new Map();
  // Direct interface membership: host -> service/webapp/tech, plus attrs matching.
  for (const node of nodes) {
    if (node.kind !== 'service' && node.kind !== 'webapp' && node.kind !== 'tech') continue;
    const attrs = node.attrs ?? {};
    const candidates = [attrs.endpoint, attrs.host, attrs.url, attrs.fqdn, node.label];
    for (const candidate of candidates) {
      const host = targetIdentity(candidate)?.host || endpointHost(candidate);
      const target = [...targets.values()].find((entry) => entry.host === host);
      if (target !== undefined) {
        targetByNode.set(node.id, target);
        if (node.kind === 'service') target.services += 1;
        else if (node.kind === 'webapp') target.webapps += 1;
        else target.tech += 1;
        target.nodeIds.push(node.id);
        break;
      }
    }
  }
  // Coverage cells can carry an explicit targetKey even without graph edges.
  for (const node of nodes) {
    if (node.kind !== 'coverage') continue;
    const rawHost = node.attrs?.targetKey ?? node.attrs?.host ?? '';
    const host = targetIdentity(rawHost)?.host || endpointHost(rawHost);
    if (host.length === 0) continue;
    const target = [...targets.values()].find((entry) => entry.host === host);
    if (target === undefined) continue;
    targetByNode.set(node.id, target);
    target.coverageCells += 1;
    if (node.status === 'seen') target.coverageSeen += 1;
    target.nodeIds.push(node.id);
  }
  const unassignedCoverageNodes = nodes.filter((node) => node.kind === 'coverage' && !targetByNode.has(node.id));

  // Multi-source BFS assigns findings/coverage/access/data to their nearest target.
  const queue = [...targets.values()].map((target) => target.id);
  const visited = new Set(queue);
  for (const id of targetByNode.keys()) {
    visited.add(id);
    queue.push(id);
  }
  for (let depth = 0; depth < 5 && queue.length > 0; depth += 1) {
    const next = [];
    for (const id of queue) {
      const target = targets.get(id) ?? targetByNode.get(id);
      if (target === undefined) continue;
      for (const neighbour of adjacency.get(id) ?? []) {
        if (visited.has(neighbour)) continue;
        const node = byId.get(neighbour);
        if (node === undefined) continue;
        if (node.kind === 'host' || node.kind === 'ip' || node.kind === 'domain') continue;
        visited.add(neighbour);
        targetByNode.set(neighbour, target);
        target.nodeIds.push(neighbour);
        if (node.kind === 'service') target.services += 1;
        else if (node.kind === 'webapp') target.webapps += 1;
        else if (node.kind === 'tech') target.tech += 1;
        else if (node.kind === 'finding') {
          target.findings += 1;
          const cvss = classifyFindingCvss(node.attrs ?? {});
          if (isVerifiedVulnerabilityNode(node)) target.vulnerabilities += 1;
          if (cvss.severity === 'unscored') target.unscoredFindings += 1;
          if (['verified', 'exploited', 'impacted'].includes(node.status)) target.verifiedFindings += 1;
        } else if (node.kind === 'coverage') {
          target.coverageCells += 1;
          if (node.status === 'seen') target.coverageSeen += 1;
        } else if (node.kind === 'access') target.access += 1;
        else if (node.kind === 'data') target.data += 1;
        else if (node.kind === 'credential') target.credentials += 1;
        next.push(neighbour);
      }
    }
    queue.splice(0, queue.length, ...next);
  }
  for (const target of targets.values()) {
    target.interfaces = target.services + target.webapps;
    target.status = target.access + target.data > 0
      ? 'impacted'
      : (target.coverageSeen > 0 || target.verifiedFindings > 0)
        ? 'tested'
        : (target.interfaces > 0 || target.findings > 0) ? 'recon' : 'untested';
  }
  const clusters = new Map();
  for (const target of targets.values()) {
    if (!clusters.has(target.clusterKey)) {
      clusters.set(target.clusterKey, {
        id: target.clusterKey,
        label: target.clusterLabel,
        kind: 'cluster',
        targets: [],
        totals: { targets: 0, tested: 0, recon: 0, untested: 0, impacted: 0, services: 0, webapps: 0, findings: 0, vulnerabilities: 0, coverageSeen: 0, coverageCells: 0, access: 0, data: 0 },
      });
    }
    const cluster = clusters.get(target.clusterKey);
    cluster.targets.push(target);
    cluster.totals.targets += 1;
    cluster.totals[target.status] += 1;
    for (const key of ['services', 'webapps', 'findings', 'vulnerabilities', 'coverageSeen', 'coverageCells', 'access', 'data']) cluster.totals[key] += target[key];
  }
  const clusterList = [...clusters.values()]
    .map((cluster) => ({ ...cluster, targets: cluster.targets.sort((a, b) => a.label.localeCompare(b.label)) }))
    .sort((a, b) => a.label.localeCompare(b.label));
  const totals = {
    clusters: clusterList.length,
    targets: targets.size,
    tested: 0,
    recon: 0,
    untested: 0,
    impacted: 0,
    services: 0,
    webapps: 0,
    findings: 0,
    vulnerabilities: 0,
    coverageSeen: 0,
    coverageCells: 0,
    access: 0,
    data: 0,
    unassignedCoverage: unassignedCoverageNodes.length,
    unassignedCoverageSeen: unassignedCoverageNodes.filter((node) => node.status === 'seen').length,
  };
  for (const cluster of clusterList) {
    for (const key of ['tested', 'recon', 'untested', 'impacted', 'services', 'webapps', 'findings', 'vulnerabilities', 'coverageSeen', 'coverageCells', 'access', 'data']) totals[key] += cluster.totals[key];
  }
  return { clusters: clusterList, totals };
}

const CONCRETE_ALLOW_TYPES = new Set(['ip', 'host', 'domain', 'url']);

function splitHostPort(value) {
  let text = String(value ?? '').trim();
  if (text.length === 0) return null;
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//iu, '');
  text = text.split('/')[0].split('?')[0].split('#')[0].trim();
  if (text.length === 0) return null;
  let host = text;
  let port;
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end <= 1) return null;
    host = text.slice(1, end);
    const rest = text.slice(end + 1);
    if (rest.startsWith(':') && /^\d+$/u.test(rest.slice(1))) port = Number(rest.slice(1));
  } else {
    const colon = text.lastIndexOf(':');
    if (colon > 0 && text.indexOf(':') === colon && /^\d+$/u.test(text.slice(colon + 1))) {
      host = text.slice(0, colon);
      port = Number(text.slice(colon + 1));
    }
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) port = undefined;
  return { host, port };
}

/**
 * One target is one IP, or one first-level subdomain.
 * Ports never split a target: a.bac.com and a.bac.com:8003 are the same target.
 * A deeper name belongs to its first-level subdomain. A different IP, a different
 * first-level subdomain, or the bare registrable domain is another target.
 */
export function targetIdentity(value) {
  const split = splitHostPort(value);
  if (split === null) return null;
  const host = canonical(split.host);
  if (host.length === 0 || host.includes('*')) return null;
  if (isIp(host)) return { key: `ip:${host}`, host, port: split.port, kind: 'ip' };
  const registered = registrableDomain(host);
  const hostLabels = host.split('.').filter(Boolean);
  const registeredLabels = registered.split('.').filter(Boolean);
  if (registered.length === 0 || hostLabels.length <= registeredLabels.length) {
    return { key: `name:${host}`, host, port: split.port, kind: 'apex' };
  }
  const first = hostLabels.slice(-(registeredLabels.length + 1)).join('.');
  return { key: `name:${first}`, host: first, port: split.port, kind: 'sub' };
}

/** Operator-named targets. A CIDR is a range, not one of these tracks. */
export function concreteAllowTargets(state) {
  const allow = Array.isArray(state?.scope?.allow) ? state.scope.allow : [];
  const tracks = new Map();
  for (const entry of allow) {
    const type = String(entry?.type ?? '').toLowerCase();
    if (!CONCRETE_ALLOW_TYPES.has(type)) continue;
    const value = String(entry?.value ?? entry?.canonical ?? '').trim();
    const identity = targetIdentity(value);
    if (identity === null) continue;
    let track = tracks.get(identity.key);
    if (track === undefined) {
      track = {
        key: identity.key,
        kind: identity.kind,
        type: identity.kind === 'ip' ? 'ip' : (identity.kind === 'apex' ? 'host' : 'domain'),
        value: identity.host,
        canonical: identity.host,
        ports: [],
      };
      tracks.set(identity.key, track);
    }
    const ports = [
      ...(Array.isArray(entry?.ports) ? entry.ports : []),
      ...(identity.port !== undefined ? [identity.port] : []),
    ];
    for (const port of ports) {
      if (Number.isInteger(port) && port > 0 && port <= 65535 && !track.ports.includes(port)) track.ports.push(port);
    }
  }
  for (const track of tracks.values()) track.ports.sort((a, b) => a - b);
  return [...tracks.values()];
}
