/**
 * Single-vulnerability HTML report for the 报告撰写 team.
 *
 * The project report is built from the whole sanitized graph; this report is
 * deliberately limited to one finding and its evidence, request/response and
 * remediation. It never embeds raw secrets or raw PII.
 */
import { classifyFindingCvss } from './finding-classification.js';
import { localizedFindingDetails, localizedFindingTitle } from './finding-i18n.js';

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&#39;');
}

function redact(value) {
  return String(value ?? '')
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/gu, (email) => {
      const at = email.lastIndexOf('@');
      return at <= 0 ? '***' : `${email.slice(0, 1)}***${email.slice(at)}`;
    })
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu, '[redacted-jwt]')
    .replace(/-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/gu, '[redacted-private-key]')
    .replace(/\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['"]?[^\s'"]+/giu, '$1=[redacted]');
}

function clean(value, max = 1200) {
  const text = redact(value).replace(/\s+/gu, ' ').trim();
  return escapeHtml(text.length > max ? `${text.slice(0, Math.max(1, max - 1))}…` : text);
}

function block(value, max = 1600) {
  const text = redact(value).trim();
  return escapeHtml(text.length > max ? `${text.slice(0, Math.max(1, max - 1))}…` : text);
}

function findingOf(state, findingId) {
  const wanted = String(findingId ?? '').trim();
  if (wanted.length === 0) return undefined;
  return Object.values(state.nodes ?? {}).find((node) => node.kind === 'finding'
    && (node.id === wanted || node.key === wanted || node.label === wanted));
}

function evidenceRows(state, finding) {
  const ids = Array.isArray(finding.evidenceIds) ? finding.evidenceIds : [];
  const nodes = ids.map((id) => state.nodes?.[id]).filter(Boolean);
  return nodes.map((node) => ({
    label: node.label ?? node.key ?? node.id,
    path: node.attrs?.relative ?? node.attrs?.path ?? '—',
    sha256: node.attrs?.sha256 ?? '—',
    mediaType: node.attrs?.mediaType ?? '—',
  }));
}

function statusText(node) {
  const labels = {
    candidate: '候选（未验证）',
    verified: '已验证',
    exploited: '已利用',
    impacted: '已影响',
    fixed: '已修复',
    attempted: '尝试过',
  };
  return labels[node.status] ?? String(node.status ?? '未知');
}

function cvssText(node) {
  const attrs = node.attrs ?? {};
  const score = Number(attrs.cvssScore ?? attrs.cvss?.baseScore);
  if (!Number.isFinite(score)) return null;
  const severity = String(attrs.cvssSeverity ?? attrs.cvss?.baseSeverity ?? '').toUpperCase();
  const vector = String(attrs.cvssVector ?? attrs.cvss?.vector ?? '');
  const classification = classifyFindingCvss(attrs);
  return {
    score: score.toFixed(1),
    severity,
    vector,
    classification: classification.vulnerability ? '漏洞' : '安全发现',
    classificationNote: classification.vulnerability
      ? '已按漏洞类确认；CVSS 仅表示严重度。'
      : '属于暴露/加固项，未证明为可利用漏洞。',
  };
}

export async function renderFindingHtmlReport(state, findingId, {
  generatedAt = new Date().toISOString(),
  theme = 'light',
  themeSource = 'argument',
  reportTeam = '报告撰写团队',
} = {}) {
  const finding = findingOf(state, findingId);
  if (finding === undefined) throw new Error(`finding "${findingId}" was not found in the graph`);
  const attrs = finding.attrs ?? {};
  const details = localizedFindingDetails(attrs.template ?? attrs.category);
  const title = localizedFindingTitle(attrs.template ?? attrs.category, attrs.title ?? finding.label ?? finding.key);
  const cvss = cvssText(finding);
  const classification = classifyFindingCvss(attrs);
  const subject = attrs.subjectLabel ?? attrs.subjectKey ?? attrs.targetLabel ?? attrs.targetId ?? finding.label ?? '—';
  const evidence = evidenceRows(state, finding);
  const repro = attrs.repro ?? attrs.poc ?? attrs.proofDetail ?? '';
  const request = attrs.request ?? attrs.httpRequest ?? attrs.pocCurl ?? '';
  const response = attrs.response ?? attrs.httpResponse ?? '';
  const chineseOr = (value, fallback) => (/[\u3400-\u9fff]/u.test(String(value ?? '')) ? value : fallback);
  const description = chineseOr(attrs.description, details.description);
  const impact = chineseOr(attrs.impact, details.impact);
  const remediation = chineseOr(attrs.remediation, details.remediation);
  const vulnerability = classification.vulnerability === true;
  const reportKind = vulnerability ? '单漏洞报告' : '单发现报告';
  const overviewTitle = vulnerability ? '① 漏洞简介与影响' : '① 已验证发现简介与影响';
  const verification = attrs.secondaryVerified === true
    ? `独立二次验证：${attrs.secondaryVerdict ?? 'verified'}${attrs.secondaryRationale ? ` · ${attrs.secondaryRationale}` : ''}`
    : (attrs.verification ?? finding.verification ?? '未二次验证');
  const reportLabel = reportTeam;
  const dark = theme === 'dark';
  const bg = dark ? '#151412' : '#f5f4ef';
  const panel = dark ? '#23211d' : '#ffffff';
  const text = dark ? '#f1eee4' : '#292723';
  const muted = dark ? '#a8a092' : '#6d675b';
  const line = dark ? '#3b3730' : '#ddd8cc';
  const accent = classification.vulnerability ? (dark ? '#f87171' : '#b91c1c') : (dark ? '#fbbf24' : '#a16207');
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} — ${reportKind}</title>
<style>
:root{color-scheme:${dark ? 'dark' : 'light'}}
*{box-sizing:border-box}body{margin:0;background:${bg};color:${text};font:14px/1.7 -apple-system,BlinkMacSystemFont,"Noto Sans SC","Microsoft YaHei",sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:28px 22px 48px}.banner{padding:8px 12px;border:1px solid ${line};border-radius:8px;color:${muted};font-size:12px;margin-bottom:18px}
.cover{padding:26px 24px;background:${panel};border:1px solid ${line};border-radius:14px;margin-bottom:18px;border-top:4px solid ${accent}}
h1{font-size:26px;line-height:1.35;margin:8px 0 12px}h2{font-size:17px;margin:0 0 8px}h3{font-size:13px;margin:0 0 6px;color:${muted};text-transform:uppercase;letter-spacing:.06em}
.meta{display:flex;flex-wrap:wrap;gap:8px 16px;color:${muted};font-size:12px}.pill{display:inline-flex;gap:4px;align-items:center;padding:3px 8px;border:1px solid ${line};border-radius:999px;color:${accent};font-weight:700}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:16px 0}
.card{background:${panel};border:1px solid ${line};border-radius:10px;padding:14px 16px}.card p{margin:0;color:${text}}
.section{background:${panel};border:1px solid ${line};border-radius:10px;padding:16px;margin:12px 0}.section pre{white-space:pre-wrap;word-break:break-word;background:${dark ? '#171511' : '#f7f5ef'};border:1px solid ${line};border-radius:8px;padding:10px;font-size:12px;max-height:340px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:12px}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid ${line};vertical-align:top}th{color:${muted};font-weight:600}
.note{color:${muted};font-size:12px}.footer{margin-top:22px;color:${muted};font-size:11px}
@media print{body{background:#fff;color:#111}.section,.cover,.card{break-inside:avoid}}
</style></head><body><main class="wrap">
<div class="banner">授权渗透测试 · ${reportKind} · ${escapeHtml(reportLabel)} · 生成时间 ${escapeHtml(generatedAt)}</div>
<section class="cover">
<h3>${reportKind} · ${escapeHtml(statusText(finding))}</h3>
<h1>${escapeHtml(title)}</h1>
<div class="meta">
<span class="pill">${escapeHtml(cvss ? `${cvss.score} ${cvss.severity}` : '未评分')} · ${escapeHtml(classification.vulnerability ? '漏洞' : cvss ? '安全发现' : '未评分')}</span>
<span>主体：${escapeHtml(subject)}</span><span>状态：${escapeHtml(statusText(finding))}</span><span>编号：${escapeHtml(finding.id ?? finding.key ?? '—')}</span>
</div>
<p class="note">${escapeHtml(cvss ? cvss.classificationNote : '没有 CVSS v3.1 Base score，尚不能定级。')}</p>
</section>
<section class="section"><h2>${overviewTitle}</h2><p>${clean(description, 2200)}</p><p>${clean(impact, 2200)}</p></section>
<section class="section"><h2>② 验证与复现</h2><p><b>状态：</b>${escapeHtml(statusText(finding))} · <b>验证：</b>${clean(verification, 1200)}</p>${repro ? `<h3>复现步骤 / PoC</h3><pre>${block(repro, 4000)}</pre>` : ''}${request ? `<h3>请求</h3><pre>${block(request, 3000)}</pre>` : ''}${response ? `<h3>响应</h3><pre>${block(response, 3000)}</pre>` : ''}</section>
<section class="section"><h2>③ 修复建议</h2><p>${clean(remediation, 2400)}</p></section>
<section class="section"><h2>④ 证据与评级</h2>
<table><thead><tr><th>项目</th><th>内容</th></tr></thead><tbody>
<tr><td>CVSS v3.1</td><td>${escapeHtml(cvss ? `${cvss.score} · ${cvss.severity} · ${cvss.vector}` : '未评分')}</td></tr>
<tr><td>判定</td><td>${escapeHtml(cvss ? cvss.classification : '未评分 / 不计为漏洞')}</td></tr>
<tr><td>二次验证</td><td>${clean(verification, 1200)}</td></tr>
<tr><td>证据工件</td><td>${evidence.length === 0 ? '—' : evidence.map((item) => `${escapeHtml(item.label)} · ${escapeHtml(item.path)} · sha256 ${escapeHtml(String(item.sha256).slice(0, 16))}…`).join('<br>')}</td></tr>
</tbody></table>
<p class="note">本报告只嵌入清洗后的文字与证据索引，不嵌入原始密钥、PII 或完整利用 payload；原始证据请通过攻击图谱 evidence 节点核对 sha256。</p>
</section>
<div class="footer">StrikeAgent_AtkBrain-DSH-Zero · ${escapeHtml(reportLabel)} · ${reportKind}</div>
</main></body></html>`;
}

export function suggestedFindingReportName(engagement, finding, date) {
  const eng = String(engagement?.name ?? engagement ?? 'engagement').replace(/[\\/:*?"<>|\s]+/gu, '-').replace(/^-+|-+$/gu, '').slice(0, 60) || 'engagement';
  const id = String(finding?.id ?? finding?.key ?? 'finding').replace(/[^A-Za-z0-9_-]+/gu, '-').replace(/^-+|-+$/gu, '').slice(0, 50) || 'finding';
  const stamp = typeof date === 'string' && /^\d{4}-\d{2}-\d{2}/u.test(date) ? date.slice(0, 10) : 'undated';
  return `atkbrain-finding-report-${eng}-${id}-${stamp}.html`;
}
