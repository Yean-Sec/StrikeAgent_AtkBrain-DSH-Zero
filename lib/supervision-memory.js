/**
 * What the executor already recorded and could forget on a long chain.
 *
 * This reads the stored graph, not the relationship diagram. The diagram keeps
 * one node per host and drops nodes past the view cap. The stored webapp still
 * holds the path list, parameter names and output contexts.
 *
 * Setup alone (teams, scope, one untouched host) is not a handoff.
 * The supervisor stays silent until `supervisionShouldSpeak` is true.
 */
import { isHardeningFinding } from './finding-classification.js';

function stamp(node) {
  return String(node?.attrs?.updatedAt ?? node?.attrs?.createdAt ?? node?.lastSeen ?? node?.firstSeen ?? '');
}

function clip(value, length) {
  return String(value ?? '').replace(/\s+/gu, ' ').trim().slice(0, length);
}

function names(value, cap) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const entry of value) {
    const text = clip(entry, 80);
    if (text.length === 0 || out.includes(text)) continue;
    out.push(text);
    if (out.length >= cap) break;
  }
  return out;
}

function mapLines(map, pathCap, nameCap) {
  if (map === null || typeof map !== 'object' || Array.isArray(map)) return [];
  const lines = [];
  for (const [path, value] of Object.entries(map)) {
    if (lines.length >= pathCap) break;
    const listed = names(value, nameCap);
    if (listed.length === 0) continue;
    lines.push(`${clip(path, 80)}: ${listed.join(', ')}`);
  }
  return lines;
}

function webappText(attrs, host) {
  const endpoints = Array.isArray(attrs.endpoints) ? attrs.endpoints : [];
  const shown = names(endpoints, 16);
  const hidden = Math.max(0, endpoints.length - shown.length);
  const parameters = mapLines(attrs.parameterMap, 8, 8);
  const contexts = mapLines(attrs.contextMap, 6, 6);
  const parts = [];
  if (shown.length > 0) parts.push(`路径 ${shown.join('、')}${hidden > 0 ? `（另有 ${hidden} 条）` : ''}`);
  if (parameters.length > 0) parts.push(`参数 ${parameters.join('；')}`);
  if (contexts.length > 0) parts.push(`输出 ${contexts.join('；')}`);
  if (parts.length === 0) return '';
  return clip([host, ...parts].filter(Boolean).join('；'), 900);
}

const MEMORY_RANK = {
  webapp: 0,
  tech: 1,
  service: 2,
  finding: 3,
  access: 4,
  credential: 5,
  data: 6,
  capability: 7,
  evidence: 8,
  coverage: 9,
};

function collect(nodes) {
  const rows = [];
  for (const node of Array.isArray(nodes) ? nodes : []) {
    if (node?.status === 'merged') continue;
    const attrs = node.attrs ?? {};
    if (node.kind === 'finding') {
      const where = [attrs.path, attrs.endpoint, attrs.parameter, attrs.bugClass].map((value) => clip(value, 80)).filter(Boolean).join(' ');
      rows.push({ kind: 'finding', at: stamp(node), text: clip(`${attrs.title ?? node.label} [${node.status}]${where.length > 0 ? ` @ ${where}` : ''}`, 240) });
    } else if (node.kind === 'tech') {
      const version = attrs.version ? ` ${attrs.version}` : '';
      rows.push({ kind: 'tech', at: stamp(node), text: clip(`${attrs.product ?? node.label}${version}`, 120) });
    } else if (node.kind === 'service') {
      const endpoint = clip(attrs.endpoint ?? attrs.host ?? node.label, 120);
      const port = attrs.port !== undefined && attrs.port !== null && String(attrs.port).length > 0 ? `:${attrs.port}` : '';
      const proto = clip(attrs.protocol ?? attrs.transport ?? '', 16);
      if (endpoint.length === 0) continue;
      rows.push({ kind: 'service', at: stamp(node), text: clip(`${proto} ${endpoint}${port}`.trim(), 160) });
    } else if (node.kind === 'webapp') {
      const endpoints = Array.isArray(attrs.endpoints) ? attrs.endpoints.length : 0;
      const params = attrs.parameterMap && typeof attrs.parameterMap === 'object' ? Object.keys(attrs.parameterMap).length : 0;
      const host = clip(attrs.host ?? attrs.url ?? node.label, 160);
      if (host.length === 0) continue;
      rows.push({
        kind: 'webapp',
        at: stamp(node),
        text: webappText(attrs, host),
        inventoried: attrs.surfaceInventoried === true,
        endpoints,
        params,
      });
    } else if (node.kind === 'coverage') {
      const note = clip(attrs.note ?? attrs.reason ?? '', 180);
      if (note.length === 0 && !['seen', 'refuted', 'reported'].includes(String(node.status ?? ''))) continue;
      rows.push({ kind: 'coverage', at: stamp(node), text: clip(`${attrs.path ?? '/'} × ${attrs.bugClass ?? '?'} ${node.status}${note ? `: ${note}` : ''}`, 240) });
    } else if (node.kind === 'evidence' && (attrs.origin === 'arsenal' || attrs.toolName)) {
      rows.push({ kind: 'evidence', at: stamp(node), text: clip(`${attrs.toolName ?? 'evidence'} ${attrs.success === true ? 'ok' : node.status}`, 120) });
    } else if (node.kind === 'access' || node.kind === 'credential' || node.kind === 'data') {
      rows.push({ kind: node.kind, at: stamp(node), text: clip(`${node.label} [${node.status}]`, 160) });
    } else if (node.kind === 'task' && attrs.actionType === 'capability' && node.status === 'completed' && attrs.success === true) {
      rows.push({ kind: 'capability', at: stamp(node), text: clip(`${attrs.capabilityAction ?? attrs.capability} ${attrs.capabilityName ?? ''}`, 160) });
    }
  }
  return rows;
}

/** Stored-graph facts the executor can forget. The relationship diagram is not this list. */
export function supervisionMemory(nodes) {
  const rows = collect(nodes);
  rows.sort((left, right) => (MEMORY_RANK[left.kind] ?? 9) - (MEMORY_RANK[right.kind] ?? 9));
  return rows.slice(0, 80);
}

/**
 * True once the executor has something a later turn could drop.
 * One untouched application is still the opening and stays silent.
 */
export function supervisionShouldSpeak(nodes) {
  const rows = collect(nodes);
  const heavy = rows.some((row) => ['finding', 'coverage', 'tech', 'evidence', 'access', 'credential', 'data', 'capability'].includes(row.kind));
  const apps = rows.filter((row) => row.kind === 'webapp');
  const substantialApp = apps.some((row) => row.inventoried === true || row.params > 0 || row.endpoints > 1);
  return heavy || apps.length >= 2 || substantialApp;
}

export function latestMemoryStamp(nodes) {
  let latest = '';
  for (const row of collect(nodes)) {
    if (row.at > latest) latest = row.at;
  }
  return latest;
}

const HEAVY_KINDS = new Set(['finding', 'tech', 'access', 'credential', 'data']);
const BULK_KINDS = new Set(['coverage', 'evidence', 'capability', 'webapp', 'service']);
const DANGER_PATH_RE = /(?:download|export|upload|include|attach|readfile|getfile|login|signin|sign-in|admin|manager|console|debug|backup|error|exception)/iu;
const FRONT_RE = /cdn|proxy|\bwaf\b|cloudflare|akamai|fastly|cloudfront/iu;

function live(nodes) {
  return (Array.isArray(nodes) ? nodes : []).filter((node) => node && node.status !== 'merged');
}

function supervisionTeam(nodes) {
  return live(nodes).find((node) => node.kind === 'self_team' && node.attrs?.type === 'supervision');
}

/**
 * The handoff is overdue once the graph holds work the executor could forget.
 * An empty engagement, or one with no supervision team, stays silent.
 * One new finding, product, access, credential or data row is enough.
 * Coverage, evidence, capability calls, the page ledger and services add up,
 * and eight of those since the last brief is enough too.
 */
export function handoffOverdue(nodes, lastBriefAt) {
  const list = live(nodes);
  if (supervisionTeam(list) === undefined || !supervisionShouldSpeak(list)) return false;
  const briefAt = String(lastBriefAt ?? supervisionTeam(list)?.attrs?.lastBriefAt ?? '');
  const unread = list.filter((node) => {
    const at = stamp(node);
    return briefAt.length === 0 || at > briefAt;
  });
  if (unread.some((node) => HEAVY_KINDS.has(node.kind))) return true;
  let bulk = 0;
  for (const node of unread) {
    if (BULK_KINDS.has(node.kind)) {
      bulk += 1;
      continue;
    }
    if (node.kind === 'task' && node.attrs?.capability && node.status === 'completed') bulk += 1;
  }
  return bulk >= 8;
}

function hostOf(service) {
  return String(service.attrs?.endpoint ?? service.attrs?.host ?? service.label ?? '').toLowerCase();
}

function serviceLines(nodes) {
  const services = live(nodes).filter((node) => node.kind === 'service');
  const httpsHosts = new Set(services.filter((node) => node.attrs?.protocol === 'https' || Number(node.attrs?.port) === 443).map(hostOf));
  const lines = [];
  for (const service of services.slice(0, 8)) {
    const proto = clip(service.attrs?.protocol ?? '', 16);
    const port = service.attrs?.port !== undefined && service.attrs?.port !== null ? `:${service.attrs.port}` : '';
    let clear = '';
    const plain = proto === 'http' || Number(service.attrs?.port) === 80;
    if (plain && httpsHosts.has(hostOf(service))) {
      const noted = String(service.attrs?.cleartext ?? '');
      if (noted === 'redirects') clear = '明文跳到加密';
      else if (noted === 'stays') clear = '明文仍在提供应用';
      else clear = '明文未核对';
    }
    lines.push([`${proto} ${hostOf(service)}${port}`.trim(), clear].filter(Boolean).join(' '));
  }
  const fronted = live(nodes).some((node) => node.kind === 'tech' && FRONT_RE.test(`${node.label ?? ''} ${node.attrs?.product ?? ''} ${node.attrs?.vendor ?? ''}`));
  const checked = live(nodes).some((node) => node.kind === 'host' && node.attrs?.vhostChecked === true);
  if (checked) lines.push('源站虚拟主机已核对');
  else if (fronted || live(nodes).some((node) => node.kind === 'host')) lines.push('源站虚拟主机未核对');
  return lines;
}

function dangerLines(nodes) {
  const lines = [];
  for (const node of live(nodes)) {
    if (node.kind === 'coverage' && (node.status === 'open' || node.status === 'claimed') && lines.length < 8) {
      lines.push(`${clip(node.attrs?.path ?? '/', 80)}×${clip(node.attrs?.bugClass ?? '?', 24)} 仍开`);
    }
  }
  for (const node of live(nodes)) {
    if (node.kind !== 'webapp' || lines.length >= 14) continue;
    const endpoints = Array.isArray(node.attrs?.endpoints) ? node.attrs.endpoints : [];
    for (const path of endpoints) {
      if (lines.length >= 14) break;
      if (!DANGER_PATH_RE.test(String(path))) continue;
      lines.push(clip(path, 80));
    }
    const contexts = [
      ...(Array.isArray(node.attrs?.contexts) ? node.attrs.contexts : []),
      ...mapLines(node.attrs?.contextMap, 4, 4),
    ];
    for (const context of contexts) {
      if (lines.length >= 16) break;
      lines.push(`输出 ${clip(context, 80)}`);
    }
  }
  return [...new Set(lines)].slice(0, 16);
}

function severityLine(nodes) {
  const bands = { 高: [], 中: [], 低: [], 加固: [] };
  for (const node of live(nodes)) {
    if (node.kind !== 'finding') continue;
    const title = clip(node.attrs?.title ?? node.label, 80);
    if (title.length === 0) continue;
    if (isHardeningFinding(node.attrs ?? {})) {
      bands.加固.push(title);
      continue;
    }
    const raw = String(node.attrs?.redteamRating ?? node.attrs?.severity ?? node.attrs?.cvssRating ?? '').toLowerCase();
    const band = raw === 'critical' || raw === 'high' ? '高' : (raw === 'medium' ? '中' : '低');
    bands[band].push(title);
  }
  const part = (name) => `${name}：${bands[name].length > 0 ? bands[name].slice(0, 4).join('、') : '无'}`;
  const hardening = bands.加固.length > 0 ? `；加固：${bands.加固.slice(0, 3).join('、')}（不是漏洞）` : '；加固：无';
  return `${part('高')}；${part('中')}；${part('低')}${hardening}`;
}

function credentialLines(nodes) {
  const lines = [];
  for (const node of live(nodes)) {
    if (node.kind !== 'credential' || lines.length >= 6) continue;
    const kind = clip(node.attrs?.kind ?? node.attrs?.type ?? 'credential', 40);
    const user = clip(node.attrs?.username ?? '', 40);
    const mask = clip(node.attrs?.secretMask ?? '', 40);
    lines.push([kind, user, mask.length > 0 ? mask : '已掩码'].filter(Boolean).join(' '));
  }
  return lines;
}

function accessLines(nodes) {
  const lines = [];
  for (const node of live(nodes)) {
    if (node.kind !== 'access' || !['validated', 'escalated'].includes(node.status) || lines.length >= 6) continue;
    lines.push(clip(`${node.attrs?.kind ?? node.label} ${node.attrs?.privilege ?? ''} ${node.status}`, 120));
  }
  return lines;
}

function infoLines(nodes) {
  const lines = [];
  for (const node of live(nodes)) {
    if (lines.length >= 10) break;
    if (node.kind === 'tech') {
      const version = node.attrs?.version ? ` ${node.attrs.version}` : '';
      lines.push(clip(`技术栈 ${node.attrs?.product ?? node.label}${version}`, 120));
    } else if (node.kind === 'data') {
      lines.push(clip(`数据 ${node.attrs?.dataClass ?? node.label}`, 80));
    } else if (node.kind === 'finding' && /stack|trace|exception|错误|堆栈|版本|version|leak/iu.test(`${node.attrs?.title ?? ''} ${node.label ?? ''}`)) {
      lines.push(clip(`错误页 ${node.attrs?.title ?? node.label}`, 120));
    }
  }
  return lines;
}

/** Seven labeled sections. An empty section says 无 so the gap stays visible. */
export function handoffSections(nodes) {
  const list = live(nodes);
  const targets = [];
  const seenTargets = new Set();
  for (const node of list) {
    let text = '';
    if (node.kind === 'host') text = clip(node.attrs?.fqdn ?? node.label ?? node.key, 120);
    else if (node.kind === 'webapp') text = webappText(node.attrs ?? {}, clip(node.attrs?.host ?? node.attrs?.url ?? node.label, 120));
    if (text.length === 0 || seenTargets.has(text)) continue;
    seenTargets.add(text);
    targets.push(text);
    if (targets.length >= 4) break;
  }
  const services = serviceLines(list);
  const dangers = dangerLines(list);
  const credentials = credentialLines(list);
  const footholds = accessLines(list);
  const info = infoLines(list);
  return [
    { title: '目标', body: targets.length > 0 ? targets.join('；') : '无' },
    { title: '服务', body: services.length > 0 ? services.join('；') : '无' },
    { title: '危险点', body: dangers.length > 0 ? dangers.join('；') : '无' },
    { title: '严重高中低', body: severityLine(list) },
    { title: '凭证', body: credentials.length > 0 ? credentials.join('；') : '无' },
    { title: '立足点', body: footholds.length > 0 ? footholds.join('；') : '无' },
    { title: '信息', body: info.length > 0 ? info.join('；') : '无' },
  ];
}

export function handoffText(nodes) {
  return handoffSections(nodes).map((section) => `${section.title}：${section.body}`).join('\n');
}
