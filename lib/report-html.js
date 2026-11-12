/**
 * Dynamic HTML report renderer built on the operator-provided
 * `intranet-lab-report.html` design.
 *
 * The template stylesheet is used verbatim for the dark report. The light
 * report keeps the exact layout and appends a palette override only. Content is
 * projected from the sanitized attack graph: findings, assets, paths, access,
 * data and verification/rating team results.
 */
import { readFile } from 'node:fs/promises';

import { computeCrownPaths } from './path.js';
import { publicNodeForReport } from './redact.js';
import { localizedFindingDetails, localizedFindingTitle } from './finding-i18n.js';

const TEMPLATE_URL = new URL('../assets/intranet-lab-report.html', import.meta.url);
let templatePromise;

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_LABEL = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};
const SEVERITY_CLASS = {
  critical: 'crit',
  high: 'high',
  medium: 'med',
  low: 'low',
  info: 'info',
};
const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&#39;');
}

function attr(value) {
  return escapeHtml(value);
}

function redactRenderedText(value) {
  return String(value ?? '')
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/gu, (email) => {
      const at = email.lastIndexOf('@');
      return at <= 0 ? '***' : `${email.slice(0, 1)}***${at > 1 ? email.slice(at - 1, at) : ''}${email.slice(at)}`;
    })
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu, '[redacted-jwt]')
    .replace(/-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/gu, '[redacted-private-key]')
    .replace(/\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['"]?[^\s'"]+/giu, '$1=[redacted]');
}

function clean(value, max = 800) {
  const text = redactRenderedText(value).replace(/\s+/gu, ' ').trim();
  return escapeHtml(text.length > max ? `${text.slice(0, Math.max(1, max - 1))}…` : text);
}

function textList(value, max = 8) {
  if (Array.isArray(value)) return value.map((entry) => clean(entry, 300)).filter((entry) => entry.length > 0).slice(0, max);
  const text = clean(value, 800);
  return text.length > 0 ? [text] : [];
}

function jsonText(value, max = 500) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return clean(value, max);
  try {
    return clean(JSON.stringify(value), max);
  } catch {
    return '';
  }
}

function severityOf(node) {
  const attrs = node.attrs ?? {};
  const raw = String(attrs.cvssSeverity ?? attrs.severity ?? attrs.cvss?.baseSeverity ?? 'info').toLowerCase();
  return SEVERITY_ORDER.includes(raw) ? raw : 'info';
}

function statusLabel(node) {
  const status = String(node.status ?? 'unknown');
  if (status === 'verified' || status === 'exploited' || status === 'impacted') return '已验证';
  if (status === 'candidate') return '待验证';
  if (status === 'fixed') return '已修复';
  return status;
}

function isVerified(node) {
  return ['verified', 'exploited', 'impacted'].includes(String(node.status ?? ''));
}

function findingTitle(node) {
  const attrs = node.attrs ?? {};
  const raw = String(attrs.title ?? node.label ?? node.key ?? node.id ?? '未命名发现');
  return node.kind === 'finding' ? localizedFindingTitle(attrs.template ?? attrs.category, raw) : raw;
}

function findingSubject(node) {
  const attrs = node.attrs ?? {};
  return String(attrs.subjectLabel ?? attrs.subjectKey ?? attrs.targetLabel ?? attrs.targetId ?? node.label ?? '—');
}

function findingType(node) {
  return String(node.attrs?.template ?? node.attrs?.kind ?? node.kind ?? 'finding');
}

function cvssText(node) {
  const attrs = node.attrs ?? {};
  const score = Number(attrs.cvssScore ?? attrs.cvss?.baseScore);
  const vector = String(attrs.cvssVector ?? attrs.cvss?.vector ?? '');
  const severity = String(attrs.cvssSeverity ?? attrs.cvss?.baseSeverity ?? '');
  if (!Number.isFinite(score)) return '';
  return `${score.toFixed(1)}${severity.length > 0 ? ` ${severity}` : ''}${vector.length > 0 ? ` · ${vector}` : ''}`;
}

function genericRemediation(node) {
  const type = findingType(node).toLowerCase();
  if (/rce|command|sandbox|exec/u.test(type)) return '隔离并升级受影响组件，移除不必要的执行能力，给执行入口增加服务端鉴权与沙箱边界，并验证 canary 不再可写入。';
  if (/sqli|sql/u.test(type)) return '使用参数化查询或 ORM 绑定参数，限制数据库账号权限，关闭详细数据库错误回显，并对输入做服务端校验。';
  if (/xss|script/u.test(type)) return '对所有输出做上下文编码，启用严格 CSP，移除危险 HTML 注入点，并回归验证唯一标记不再执行。';
  if (/credential|default_password|weak_password|admin_access/u.test(type)) return '轮换默认/泄露凭证，强制多因素认证，限制管理入口来源，并对全量账号做弱口令排查。';
  if (/exposure|exposed|unauth|disclosure|leak|source/u.test(type)) return '移除公网/未授权访问，关闭目录与配置文件的静态暴露，轮换已泄露密钥，并在网关层增加默认拒绝策略。';
  if (/upload/u.test(type)) return '对上传内容做类型/内容双重校验，上传目录禁止执行与匿名读取，使用随机不可枚举文件名并做病毒扫描。';
  return '按最小权限和默认拒绝原则收敛暴露面，修复后使用同一证据链复验并保留回归记录。';
}

function impactText(node) {
  const attrs = node.attrs ?? {};
  const raw = attrs.impact ?? attrs.description ?? '';
  const text = jsonText(raw, 700);
  if (text.length > 0) return text;
  const localized = localizedFindingDetails(attrs.template ?? attrs.category).impact;
  if (localized.length > 0) return localized;
  if (isVerified(node)) return `该发现已通过可复现验证，影响面以攻击图 access/data 节点和证据哈希为准。`;
  return '该发现目前仍是候选，报告中不将其视为已证实的业务影响；需要二次验证后再升级结论。';
}

function verificationText(node) {
  const attrs = node.attrs ?? {};
  const secondary = attrs.secondaryVerified === true ? '独立二次验证：通过' : '独立二次验证：未记录';
  const rating = attrs.redteamRating ? `运营评级：${String(attrs.redteamRating)}` : '运营评级：未评级';
  const cvss = cvssText(node);
  return [secondary, rating, cvss].filter((entry) => entry.length > 0).join(' · ');
}

function methodText(node) {
  const attrs = node.attrs ?? {};
  const type = findingType(node).toLowerCase();
  const subject = findingSubject(node);
  const lines = [];
  if (/xss|script/u.test(type)) {
    lines.push(`在 ${subject} 的可控输入位置注入唯一标记，观察响应是否按 HTML/JS 上下文解析。`);
    lines.push('第二次使用不同标记重复请求，并保存两次响应哈希；只有标记稳定回显或执行才升级为已验证。');
  } else if (/sqli|sql/u.test(type)) {
    lines.push(`在 ${subject} 的查询参数上使用时间/布尔差分与唯一标记，比较基线与注入响应。`);
    lines.push('使用只读语义复现，避免写入业务数据；记录两次独立请求的差异。');
  } else if (/rce|command|exec|sandbox/u.test(type)) {
    lines.push(`在 ${subject} 上执行最小化、带唯一 nonce 的命令回显，并确认输出来自目标而不是本地容器。`);
    lines.push('第二次使用不同 nonce 复现，保存命令输出、主机标识和证据哈希。');
  } else if (/credential|default_password|admin_access|unauth/u.test(type)) {
    lines.push(`先确认 ${subject} 的认证边界，使用匿名对照请求验证未授权响应。`);
    lines.push('仅在授权与锁定策略允许时做最小次数凭证验证，成功后记录管理员专属页面/角色标记。');
  } else {
    lines.push(`对 ${subject} 发送最小化、可重复的只读请求，记录基线响应与异常响应。`);
    lines.push('用第二条独立观察通道复核（状态码之外的响应体、哈希、时间差或角色差异）。');
  }
  return lines;
}

function assetRole(node) {
  const kind = String(node.kind ?? '');
  if (kind === 'domain') return '入口域名';
  if (kind === 'ip') return '网络地址';
  if (kind === 'host') return '主机 / 资产';
  return kind;
}

function normalizeNarrative(value) {
  if (value === null || value === undefined || typeof value !== 'object') return null;
  const summary = String(value.executiveSummary ?? '').trim().slice(0, 3000);
  const conclusion = String(value.conclusion ?? '').trim().slice(0, 1500);
  const findings = Array.isArray(value.findings) ? value.findings : [];
  if (summary.length === 0 && conclusion.length === 0 && findings.length === 0) return null;
  return { executiveSummary: summary, conclusion, findings, ai: value.ai === true };
}

function buildModel(state) {
  const allNodes = Object.values(state.nodes ?? {})
    .filter((node) => state.aliases?.[node.id] === undefined && node.status !== 'merged')
    .map((node) => {
      const pub = publicNodeForReport(node);
      if (pub.kind !== 'finding') return pub;
      const attrs = { ...(pub.attrs ?? {}) };
      const title = localizedFindingTitle(attrs.template ?? attrs.category, attrs.title ?? pub.label);
      return { ...pub, label: title, attrs: { ...attrs, title } };
    });
  const edges = Object.values(state.edges ?? {});
  const findings = allNodes.filter((node) => node.kind === 'finding');
  const assets = allNodes.filter((node) => ['host', 'ip', 'domain'].includes(node.kind));
  const services = allNodes.filter((node) => ['service', 'webapp', 'tech'].includes(node.kind));
  const access = allNodes.filter((node) => node.kind === 'access');
  const data = allNodes.filter((node) => node.kind === 'data');
  const evidence = allNodes.filter((node) => node.kind === 'evidence');
  const credentials = allNodes.filter((node) => node.kind === 'credential');
  const severityCounts = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));
  for (const finding of findings) severityCounts[severityOf(finding)] += 1;
  const verifiedFindings = findings.filter(isVerified);
  const verifiedSeverity = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));
  for (const finding of verifiedFindings) verifiedSeverity[severityOf(finding)] += 1;
  const orderedFindings = findings.slice().sort((a, b) => {
    const life = (isVerified(b) ? 1 : 0) - (isVerified(a) ? 1 : 0);
    if (life !== 0) return life;
    const sev = (SEVERITY_RANK[severityOf(b)] || 0) - (SEVERITY_RANK[severityOf(a)] || 0);
    if (sev !== 0) return sev;
    return findingTitle(a).localeCompare(findingTitle(b));
  });
  const validatedAccess = access.filter((node) => ['validated', 'escalated'].includes(String(node.status ?? '')));
  const verifiedData = data.filter((node) => String(node.status ?? '') === 'verified');
  const crownPaths = computeCrownPaths(state, { limit: 3 }).map((path) => ({
    ...path,
    nodes: path.nodes.map((id) => {
      const node = state.nodes?.[id];
      return node === undefined ? { id, label: id, kind: 'unknown', status: 'unknown', severity: 'info' } : {
        id,
        label: node.label ?? id,
        kind: node.kind ?? 'unknown',
        status: node.status ?? 'unknown',
        severity: severityOf(node),
      };
    }),
  }));
  const selfBrief = allNodes
    .filter((node) => node.kind === 'supervision' && node.attrs?.type === 'self_team_brief')
    .sort((a, b) => (Number(b.attrs?.round) || 0) - (Number(a.attrs?.round) || 0))[0] ?? null;
  const verifiedHigh = verifiedFindings.filter((node) => ['critical', 'high'].includes(severityOf(node)));
  const secondaryVerifiedCount = findings.filter((node) => node.attrs?.secondaryVerified === true).length;
  const highestVerified = verifiedFindings.slice().sort((a, b) => (SEVERITY_RANK[severityOf(b)] || 0) - (SEVERITY_RANK[severityOf(a)] || 0))[0] ?? null;
  const scope = state.scope ?? {};
  const engagement = state.engagement ?? {};
  return {
    engagement,
    nodeCount: allNodes.length,
    edgeCount: edges.length,
    findings: orderedFindings,
    severityCounts,
    verifiedSeverity,
    verifiedCount: verifiedFindings.length,
    secondaryVerifiedCount,
    assets,
    services,
    access,
    validatedAccess,
    data,
    verifiedData,
    evidence,
    credentials,
    crownPaths,
    verifiedHigh,
    highestVerified,
    selfBrief,
    riskRating: highestVerified === null ? 'low' : severityOf(highestVerified),
    scopeAllow: Array.isArray(scope.allow) ? scope.allow.length : Number(scope.allowCount) || 0,
    scopeDeny: Array.isArray(scope.deny) ? scope.deny.length : Number(scope.denyCount) || 0,
    authorization: String(engagement.authorization ?? '—'),
    window: String(engagement.window ?? '—'),
    mode: String(engagement.mode ?? '—'),
  };
}

function severityChip(severity) {
  const cls = SEVERITY_CLASS[severity] || 'low';
  return `<span class="sev-chip ${cls}">${escapeHtml(SEVERITY_LABEL[severity] || severity)}</span>`;
}

function renderCover(model, generatedAt, theme) {
  const name = escapeHtml(model.engagement.name ?? 'AtkBrain 授权渗透测试');
  const critical = model.severityCounts.critical || 0;
  const high = model.severityCounts.high || 0;
  const goal = model.validatedAccess.length > 0
    ? `已落地 ${model.validatedAccess.length} 条权限路径`
    : model.verifiedData.length > 0
      ? `已验证 ${model.verifiedData.length} 组敏感数据证据`
      : '尚未形成已落地权限路径';
  const risk = model.riskRating.toUpperCase();
  return `<header class="cover"><div class="grain"></div><div class="inner">
<div class="brand"><span class="dot"></span>AtkBrain · 授权渗透测试交付报告</div>
<span class="tag">AUTHORIZED PENTEST · ${escapeHtml(generatedAt.slice(0, 10))}</span>
<h1>${name}<br><span class="accent">攻击路径与影响验证报告</span></h1>
<p class="sub">覆盖 ${model.assets.length} 个资产、${model.services.length} 个服务面，记录 ${model.findings.length} 项发现（严重 ${critical} / 高危 ${high}）。${goal}；当前最高已验证风险为 ${escapeHtml(risk)}。</p>
<div class="meta">
<div class="m"><b>授权引用</b> · ${escapeHtml(model.authorization)}</div>
<div class="m"><b>测试窗口</b> · ${escapeHtml(model.window)}</div>
<div class="m"><b>范围</b> · allow ${model.scopeAllow} / deny ${model.scopeDeny}</div>
<div class="m"><b>攻击图</b> · ${model.nodeCount} 节点 / ${model.edgeCount} 边</div>
</div>
<div class="goal-badge"><span class="flag">${goal}</span><span>二次验证 ${model.secondaryVerifiedCount} 项 · 报告主题 ${theme === 'dark' ? '深色模板' : '浅色排版'}</span></div>
</div></header>
<div class="rule"></div>`;
}

function renderSummary(model) {
  const top = model.findings.slice(0, 5);
  const topItems = top.map((node) => `<li><span class="tag-sev ${SEVERITY_CLASS[severityOf(node)]}">${escapeHtml(SEVERITY_LABEL[severityOf(node)])}</span><span>${clean(findingTitle(node), 220)} — ${clean(statusLabel(node), 40)}。</span></li>`).join('');
  const conclusions = model.findings.slice(0, 6).map((node) => `<li><span class="tag-sev ${SEVERITY_CLASS[severityOf(node)]}">${escapeHtml(SEVERITY_LABEL[severityOf(node)])}</span><span>${clean(findingTitle(node), 200)}；${clean(findingSubject(node), 80)}；${clean(statusLabel(node), 40)}。</span></li>`).join('');
  const evidenceLine = model.selfBrief === null
    ? '自监督团队尚未留下本轮 brief；报告内容仍以图谱、证据和二次验证记录为准。'
    : '报告团队在生成前读取了自监督简报与二次验证记录，但正文只采用图谱中 verified/access/data 的可复核结论；内部简报原文不嵌入交付报告。';
  return `<section class="sec" id="summary">
<div class="sec-head"><span class="num">01</span><h2>执行摘要</h2><span class="en">Executive Summary</span></div>
<div class="sum-grid">
<div class="sum-card"><h3><span class="dot"></span>测试概况与结论</h3>
<p>${model.narrative?.executiveSummary ? clean(model.narrative.executiveSummary, 3000) : `本次授权测试围绕 <code>${escapeHtml(model.engagement.name ?? 'engagement')}</code> 的攻击面展开，图谱记录 ${model.assets.length} 个资产、${model.services.length} 个服务面和 ${model.findings.length} 项发现。以下结论只基于已验证发现、access/data 节点和报告团队可复核的图谱字段。`}</p>
<ul>${topItems || '<li>暂无已验证发现；请先完成验证并补充证据。</li>'}</ul>
<p style="margin-top:12px;color:var(--body-strong)">整体风险：<b style="color:var(--error)">${escapeHtml(SEVERITY_LABEL[model.riskRating] || model.riskRating)}</b>。已验证 ${model.verifiedCount} 项；已验证 access ${model.validatedAccess.length} 条，敏感数据证据 ${model.verifiedData.length} 组。</p>
</div>
<div class="sum-card"><h3><span class="dot"></span>关键结论</h3>
<ul class="concl">${conclusions || '<li>暂无足够证据形成关键结论。</li>'}</ul>${model.narrative?.conclusion ? `<p style="margin-top:12px;color:var(--body-strong)"><b>结论：</b>${clean(model.narrative.conclusion, 1500)}</p>` : ''}
<p style="margin-top:12px;font-size:13px;color:var(--body-strong)">报告团队说明：${evidenceLine}</p>
</div></div>
<div class="sum-foot"><b>验证口径：</b>严重/高危结论必须以可复现证据和二次验证为准；候选发现不会在报告中升级为已验证。敏感数据只呈现类别、计数区间、样本哈希和证据工件，不展示原始 PII 或 secret。攻击行为仅针对授权范围，本报告不包含 payload 或可直接重放的凭据。</div>
</section>`;
}

function renderKpis(model) {
  return `<div class="kpis" style="margin-top:22px">
<div class="kpi"><div class="k-ico">🧾</div><div class="k-num">${model.findings.length}</div><div class="k-label">发现总数</div></div>
<div class="kpi crit"><div class="k-ico">🔥</div><div class="k-num">${model.severityCounts.critical}</div><div class="k-label">严重 Critical</div></div>
<div class="kpi high"><div class="k-ico">⚠️</div><div class="k-num">${model.severityCounts.high}</div><div class="k-label">高危 High</div></div>
<div class="kpi"><div class="k-ico">📄</div><div class="k-num">${model.severityCounts.medium} / ${model.severityCounts.low + model.severityCounts.info}</div><div class="k-label">中危 / 低危与信息</div></div>
<div class="kpi teal"><div class="k-ico">🖥️</div><div class="k-num">${model.services.length}</div><div class="k-label">服务面节点</div></div>
<div class="kpi"><div class="k-ico">✅</div><div class="k-num">${model.verifiedCount}</div><div class="k-label">已验证发现</div></div>
<div class="kpi goal"><div class="k-ico">🏁</div><div class="k-num">${model.validatedAccess.length}</div><div class="k-label">已落地权限路径</div></div>
<div class="kpi"><div class="k-ico">🎯</div><div class="k-num">${model.verifiedData.length}</div><div class="k-label">已验证数据证据</div></div>
</div>`;
}

function renderCharts(model) {
  const max = Math.max(1, ...SEVERITY_ORDER.map((severity) => model.severityCounts[severity]));
  const bars = SEVERITY_ORDER.map((severity, index) => {
    const count = model.severityCounts[severity];
    const width = Math.round((count / max) * 420);
    const y = 16 + index * 40;
    return `<text x="0" y="${y + 15}" font-size="13" fill="var(--body)">${escapeHtml(SEVERITY_LABEL[severity])} ${severity}</text>
<rect x="150" y="${y}" width="420" height="20" rx="10" fill="var(--surface-soft)" stroke="var(--hairline)"/>
<rect x="150" y="${y}" width="${width}" height="20" rx="10" fill="${severityFill(severity)}"><title>${count} 条</title></rect>
<text x="${150 + width + 10}" y="${y + 15}" font-size="13" font-weight="700" fill="var(--ink)">${count}</text>`;
  }).join('');
  const verified = model.verifiedCount;
  const pending = Math.max(0, model.findings.length - verified);
  return `<section class="sec" id="stats">
<div class="sec-head"><span class="num">02</span><h2>发现严重度分布</h2><span class="en">Severity &amp; Verification</span></div>
<div class="charts">
<div class="chart-card"><h4>严重度分布（${model.findings.length} 项发现）</h4>
<svg viewBox="0 0 760 220" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto" role="img" aria-label="漏洞严重度分布">${bars}</svg>
<div class="note">严重 / 高危共 ${model.severityCounts.critical + model.severityCounts.high} 项；其余为中危、低危与信息记录。图表按全量发现统计，正文的已验证结论单独标注。</div></div>
<div class="chart-card"><h4>验证状态分布</h4>
<div class="verify-panel">
<div class="verify-legend">
<div class="row"><i style="background:var(--success)"></i>已验证 <b>${verified}</b></div>
<div class="row"><i style="background:var(--warning)"></i>待验证 <b>${pending}</b></div>
<div class="row"><i style="background:var(--muted-soft)"></i>独立二次验证通过 <b>${model.secondaryVerifiedCount}</b></div>
</div>
</div>
<div class="note">已验证口径为 finding 的 verified / exploited / impacted 生命周期；候选发现保留在总表中，但不会被写作已利用。</div></div>
</div>
</section>`;
}

function pathNodeClass(node) {
  if (node.kind === 'data' || node.kind === 'access' && node.status === 'escalated') return 'goal';
  if (node.severity === 'critical' || node.severity === 'high') return 'crit';
  if (node.kind === 'finding' || node.kind === 'access') return 'warn';
  return 'info';
}

function renderPath(model) {
  if (model.crownPaths.length === 0) {
    return `<section class="sec" id="path">
<div class="sec-head"><span class="num">03</span><h2>关键攻击路径</h2><span class="en">Attack Path</span></div>
<p class="sec-sub">当前图谱尚未形成从已落地 foothold 到里程碑的路径。报告只呈现已验证关系，不用推测路径填充版面。</p>
</section>`;
  }
  const boards = model.crownPaths.map((path) => {
    const nodes = path.nodes.map((node) => `<div class="pn ${pathNodeClass(node)}"><div class="pk">${escapeHtml(node.kind)}</div><div class="pt">${clean(node.label, 80)}</div><div class="pd">${escapeHtml(node.status)} · ${escapeHtml(SEVERITY_LABEL[node.severity] || node.severity)}</div></div>`).join('<div class="parrow"><span class="line"></span><span>关系</span></div>');
    return `<div class="path-row">${nodes}</div>`;
  }).join('<div class="parrow down"><span class="line"></span><span>继续</span></div>');
  return `<section class="sec" id="path">
<div class="sec-head"><span class="num">03</span><h2>关键攻击路径</h2><span class="en">Attack Path</span></div>
<p class="sec-sub">从已落地 foothold 通向里程碑的加权最短路径；路径只使用图谱中已记录的关系，不补充未验证节点。</p>
<div class="path-board"><div class="path-rows">${boards}</div>
<div class="path-legend"><span><i class="l-crit"></i>关键缺陷</span><span><i class="l-warn"></i>过渡 / 扩展节点</span><span><i class="l-info"></i>情报与服务节点</span><span><i class="l-goal"></i>权限/数据目标</span></div></div>
<p class="path-caption">共 ${model.crownPaths.length} 条路径；每条路径的目标、节点链和成本均可回到攻击图谱中核对。</p>
</section>`;
}

function renderAssets(model) {
  const cards = model.assets.slice(0, 24).map((node) => {
    const attrs = node.attrs ?? {};
    const nodeFindings = model.findings.filter((finding) => findingSubject(finding) === node.label || findingSubject(finding).includes(node.label)).length;
    const nodeServices = model.services.filter((service) => String(service.label).includes(String(node.label))).length;
    const wildcard = attrs.wildcardStatus ? `<span class="chip">泛解析 ${escapeHtml(String(attrs.wildcardStatus))}</span>` : '';
    return `<div class="asset"><div class="a-name">${clean(node.label, 90)}</div><div class="a-role">${escapeHtml(assetRole(node))} · ${escapeHtml(String(node.status ?? 'unknown'))}</div>
<div class="a-badges"><span class="chip">${nodeFindings} 项关联发现</span>${nodeServices > 0 ? `<span class="chip teal">${nodeServices} 个服务面</span>` : ''}${wildcard}</div>
<div class="a-desc">${isVerified(node) ? '已纳入验证范围，相关证据已记录。' : '资产已纳入授权范围，结论以关联发现为准。'}</div>
<div class="a-line">${clean(findingSubject(model.findings.find((finding) => findingSubject(finding) === node.label) ?? { attrs: {} }), 120) || '暂无直接关联发现'}</div></div>`;
  }).join('');
  return `<section class="sec" id="assets">
<div class="sec-head"><span class="num">04</span><h2>资产画像</h2><span class="en">Assets in Scope</span></div>
<p class="sec-sub">授权范围内资产 ${model.assets.length} 个，服务面节点 ${model.services.length} 个；以下按图谱资产顺序展示，详细服务与端口回到攻击图谱和证据索引核对。</p>
<div class="assets">${cards || '<p class="sec-sub">暂无资产节点。</p>'}</div>
${model.assets.length > 24 ? `<p class="sec-sub">仅展示前 24 个资产；完整列表见攻击图谱。</p>` : ''}
</section>`;
}

function renderIndex(model) {
  const rows = model.findings.map((node, index) => `<tr><td>${index + 1}</td><td><span class="s-dot" style="background:${severityFill(severityOf(node))}"></span>${escapeHtml(SEVERITY_LABEL[severityOf(node)])}</td><td>${clean(findingTitle(node), 180)}<br><span style="color:var(--muted-soft);font-size:12px">${clean(findingSubject(node), 90)}</span></td><td>${escapeHtml(findingType(node))}</td><td>${escapeHtml(statusLabel(node))}</td><td><a class="anchor" href="#vuln-${index}">跳转</a></td></tr>`).join('');
  return `<section class="sec" id="list">
<div class="sec-head"><span class="num">05</span><h2>发现清单总表</h2><span class="en">Findings Index</span></div>
<table class="tbl"><thead><tr><th style="width:56px">#</th><th style="width:90px">严重度</th><th>漏洞 / 发现</th><th style="width:150px">类型</th><th style="width:90px">状态</th><th style="width:64px">锚点</th></tr></thead><tbody>${rows || '<tr><td colspan="6">暂无发现记录。</td></tr>'}</tbody></table>
</section>`;
}

function findingCard(node, index) {
  const severity = severityOf(node);
  const attrs = node.attrs ?? {};
  const title = findingTitle(node);
  const cvss = cvssText(node);
  const evidenceCount = Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0;
  const remediation = String(attrs.remediation ?? attrs.fix ?? '').trim() || localizedFindingDetails(attrs.template ?? attrs.category).remediation;
  const cve = attrs.cve ? ` · ${String(attrs.cve)}` : '';
  const cwe = attrs.cwe ? ` · ${String(attrs.cwe)}` : '';
  const proofType = String(attrs.proofType ?? '').trim();
  const proofDetail = String(attrs.proofDetail ?? '').trim();
  const repro = String(attrs.repro ?? '').trim();
  return `<article class="vf ${SEVERITY_CLASS[severity]}" id="vuln-${index}">
<div class="vhead"><div class="vtitle-row">${severityChip(severity)}<h3>${clean(title, 220)}</h3></div>
<div class="vmeta"><span>类型 ${escapeHtml(findingType(node))}</span><span>状态 <b style="color:${isVerified(node) ? 'var(--ok)' : 'var(--warning)'}">${escapeHtml(statusLabel(node))}</b></span><span>主体 ${clean(findingSubject(node), 120)}</span>${cvss.length > 0 ? `<span>CVSS ${clean(cvss, 160)}</span>` : ''}${cve.length + cwe.length > 0 ? `<span>${escapeHtml(cve + cwe)}</span>` : ''}</div></div>
<div class="vbody">
<div class="vsec"><h4><span class="tick">①</span> 简介 / 影响</h4><p>${clean(impactText(node), 700)}</p></div>
<div class="vsec"><h4><span class="tick">②</span> 验证 / 复现路径</h4><ol>${methodText(node).map((line) => `<li>${clean(line, 300)}</li>`).join('')}</ol>
<p style="font-size:13px;color:var(--muted)"><b>验证记录：</b>${clean(verificationText(node), 350)}；证据工件 ${evidenceCount} 个。</p>${proofType.length > 0 ? `<p style="font-size:13px;color:var(--muted)"><b>证明类型：</b>${clean(proofType, 80)}${proofDetail.length > 0 ? ` · ${clean(proofDetail, 500)}` : ''}</p>` : ''}${repro.length > 0 ? `<details class="ev"><summary>PoC / 复现输入（已清洗）</summary><div class="ev-body"><pre style="white-space:pre-wrap;word-break:break-word;font-size:11px">${clean(repro, 1800)}</pre></div></details>` : ''}</div>
<div class="vsec"><h4><span class="tick g">③</span> 修复建议</h4><div class="fix-grid">
<div class="fix-box"><h5 class="now">⚠ 立即缓解</h5><ul><li>${clean(remediation || genericRemediation(node), 500)}</li><li>对相关入口增加最小权限、默认拒绝和审计日志。</li></ul></div>
<div class="fix-box"><h5 class="root">✔ 长期治理</h5><ul><li>把该根因纳入基线扫描和回归测试，修复后用同一证据链复验。</li><li>对同类资产做横向排查，避免仅修复单点。</li></ul></div></div></div>
<details class="ev"><summary>证据索引（${evidenceCount} 个工件）</summary><div class="ev-body"><div class="row"><span class="k">finding</span><span>${escapeHtml(node.id)}</span></div><div class="row"><span class="k">主体</span><span>${clean(findingSubject(node), 200)}</span></div><div class="row"><span class="k">状态</span><span>${escapeHtml(statusLabel(node))} · ${clean(verificationText(node), 250)}</span></div><div class="row"><span class="k">说明</span><span>原始证据、样本和命令输出不嵌入本报告；请通过攻击图谱 evidence 节点与 sha256 工件核验。</span></div></div></details>
</div></article>`;
}

function renderFindings(model) {
  const groups = [
    { severity: 'critical', num: '06', title: '严重发现' },
    { severity: 'high', num: '07', title: '高危发现' },
    { severity: 'medium', num: '08', title: '中危发现' },
    { severity: 'low', num: '09', title: '低危 / 信息' },
  ];
  return groups.map((group) => {
    const list = model.findings.filter((node) => group.severity === 'low'
      ? ['low', 'info'].includes(severityOf(node))
      : severityOf(node) === group.severity);
    const cards = list.map((node) => findingCard(node, model.findings.indexOf(node))).join('');
    return `<section class="sec" id="${group.severity === 'low' ? 'low' : group.severity}">
<div class="sec-head"><span class="num">${group.num}</span><h2>${group.title}（${group.severity === 'low' ? 'Low / Info' : SEVERITY_LABEL[group.severity]} · ${list.length} 项）</h2><span class="en">${group.severity === 'low' ? 'Low / Informational' : `${group.severity} findings`}</span></div>
${list.length === 0 ? '<p class="sec-sub">该严重度暂无发现记录。</p>' : cards}
</section>`;
  }).join('');
}

function renderFooter(model, themeInfo, generatedAt) {
  return `<footer><span>AtkBrain · 授权渗透测试交付报告 · ${escapeHtml(model.engagement.name ?? 'engagement')}</span><span>报告团队：${escapeHtml(model.reportTeam ?? '报告撰写团队')}${model.narrative?.ai === true ? ' · AI 撰写' : ' · 模板生成'} · 主题：${themeInfo.theme}（${escapeHtml(themeInfo.source)}） · 生成于 ${escapeHtml(generatedAt)}</span></footer>`;
}

function severityFill(severity) {
  if (severity === 'critical') return 'var(--crit)';
  if (severity === 'high') return 'var(--high)';
  if (severity === 'medium') return 'var(--med)';
  if (severity === 'low') return 'var(--low)';
  return 'var(--muted)';
}

function lightOverrides() {
  return `<style id="atk-report-light-override">
:root{
 --primary:#b4533a;--primary-active:#8f3f2c;--ink:#111827;--body:#374151;--body-strong:#1f2937;
 --muted:#6b7280;--muted-soft:#9ca3af;--hairline:#e5e7eb;--hairline-soft:#edf0f3;
 --canvas:#ffffff;--surface-soft:#f6eee4;--surface-card:#faf6f1;--surface-cream-strong:#f3e9de;
 --surface-dark:#f6eee4;--surface-dark-elevated:#ffffff;--surface-dark-soft:#eadfce;
 --on-dark:#111827;--on-dark-soft:#4b5563;--accent-teal:#0f766e;--accent-amber:#b45309;
 --success:#15803d;--warning:#a16207;--error:#ef4444;--node-danger:#f97316;--node-vuln:#ef4444;--node-goal:#b91c1c;--lateral:#5b4bdb;
 --paper:#ffffff;--card:#faf6f1;--coral:#b4533a;--coral-deep:#8f3f2c;--hair:#eadfce;--crit:#ef4444;--high:#f97316;--med:#f59e0a;--low:#14b8a6;--ok:#15803d;--dark:#f6eee4;
}
body{background:#fff;color:var(--body)}
.cover{background:linear-gradient(135deg,#fff 0%,#f7f1ec 100%);color:var(--ink);border-bottom:1px solid var(--hairline)}
.cover .grain{background:radial-gradient(900px 340px at 12% -10%,rgba(180,83,58,.12),transparent 60%),radial-gradient(700px 300px at 95% 15%,rgba(15,118,110,.08),transparent 55%)}
.cover .brand{color:var(--muted)}.cover h1{color:var(--ink)}.cover h1 .accent{color:var(--primary-active)}
.cover .sub{color:var(--muted)}.cover .tag{color:var(--primary-active);border-color:rgba(180,83,58,.4)}
.cover .meta .m{background:#fff;border-color:var(--hairline);color:var(--muted)}.cover .meta .m b{color:var(--ink)}
.cover .goal-badge{background:#fff;border-color:rgba(185,28,28,.35);color:var(--ink)}
.cover .goal-badge .flag{color:var(--node-goal)}
.cover .rule{opacity:.8}
.tbl th{background:#f6eee4;color:var(--ink)}
.tbl tr:nth-child(even) td{background:#faf6f1}
pre{background:#faf6f1;color:var(--body);border:1px solid var(--hairline)}pre .c{color:var(--muted)}
.vf,.kpi,.chart-card,.asset,.sum-card{background:#faf6f1}
.vhead,.fix-box,.sum-foot,.path-board,.asset-map,.chip{background:#f6eee4}
.kpi.goal{background:#faf6f1;border-color:var(--hairline)}.kpi.goal .k-num{color:var(--node-goal)}.kpi.goal .k-label{color:var(--muted)}
details.ev{background:#fff}
.pn{background:#fffdf8}.pn.goal{background:var(--error);color:#fff}
.sum-card{border-color:#eadfce;box-shadow:none}
.sum-card p,.sum-card ul li{color:#1c1917}
.sum-card .tag-sev.crit{background:#ef4444;color:#fff}
.sum-card .tag-sev.high{background:#f97316;color:#fff}
.sum-card .tag-sev.med{background:#f59e0a;color:#1c1917}
.sum-card .tag-sev.low{background:#14b8a6;color:#fff}
.sum-card .tag-sev.info{background:#94a3b8;color:#fff}
.sev-chip.med{background:#f59e0a;color:#1c1917}
.sev-chip.low{background:#14b8a6;color:#fff}
.sev-chip.info{background:#94a3b8;color:#fff}
.chip.crit{background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.35);color:#dc2626}
.chip.high{background:rgba(249,115,22,.14);border-color:rgba(249,115,22,.4);color:#c2410c}
.chip.med{background:rgba(245,158,10,.18);border-color:rgba(245,158,10,.45);color:#b45309}
.chip.low{background:rgba(20,184,166,.14);border-color:rgba(20,184,166,.4);color:#0f766e}
</style>`;
}


export async function renderHtmlReport(state, { generatedAt, theme = 'light', themeSource = 'argument', reportTeam = '报告撰写团队', narrative = null } = {}) {
  if (templatePromise === undefined) templatePromise = readFile(TEMPLATE_URL, 'utf8');
  const template = await templatePromise;
  const styleMatch = /<style>([\s\S]*?)<\/style>/u.exec(template);
  if (styleMatch === null) throw new Error('report template has no <style> block');
  const baseCss = styleMatch[1];
  const model = buildModel(state);
  model.narrative = normalizeNarrative(narrative);
  model.reportTeam = reportTeam;
  const generated = generatedAt ?? new Date().toISOString();
  const themeInfo = { theme: theme === 'dark' ? 'dark' : 'light', source: themeSource };
  const title = `${model.engagement.name ?? 'AtkBrain'} — 授权渗透测试报告`;
  const baseStyle = `<style>${baseCss}\n.footer-note{font-size:12px;color:var(--muted)}</style>`;
  const lightCss = themeInfo.theme === 'light' ? lightOverrides() : '';
  return `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
${baseStyle}
${lightCss}
</head>
<body class="atk-report atk-report--${themeInfo.theme}">
${renderCover(model, generated, themeInfo.theme)}
<main class="wrap">
${renderSummary(model)}
${renderKpis(model)}
${renderCharts(model)}
${renderPath(model)}
${renderAssets(model)}
${renderIndex(model)}
${renderFindings(model)}
${renderFooter(model, themeInfo, generated)}
</main>
</body></html>`;
}

export function suggestedHtmlReportName(engagement, date) {
  const name = String(engagement?.name ?? engagement ?? 'engagement').replace(/[\\/:*?"<>|\s]+/gu, '-').replace(/^-+|-+$/gu, '').slice(0, 80) || 'engagement';
  const stamp = typeof date === 'string' && /^\d{4}-\d{2}-\d{2}/u.test(date) ? date.slice(0, 10) : 'undated';
  return `atkbrain-report-${name}-${stamp}.html`;
}
