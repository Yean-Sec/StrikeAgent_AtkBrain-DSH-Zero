/**
 * AtkBrain — browser side of the attack-graph Session view.
 *
 * This file is a build-free client bundle: it only registers a factory with the
 * DSH module loader. Nothing runs until the framework materializes the factory;
 * the single top-level statement is the loader registration itself.
 *
 * Hard constraints enforced by the client module system:
 *  - the only external module is `react`; no vendor UI packages are imported;
 *  - no JSX and no build step;
 *  - the view is a plain function component registered into
 *    `conversation.view` under the id `atk-graph`;
 *  - the Host projection (`atkGraph`) may be absent or partial at any moment,
 *    so every read is defensive;
 *  - styles live in a component-local style element and chrome colors come
 *    from `--dsw-*` theme tokens, so light/dark themes follow automatically.
 *
 * The graph is a presentation-only projection: this file never calls Host
 * services, tools, network APIs, or writes to the DOM outside its own subtree.
 */
window.__ModuleLoader__.load({
  id: '@local/atk-brain',
  factory: (require) => {
    const React = require('react');
    const h = React.createElement;

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    /** Locale namespace owned by this plugin (client-side dictionaries). */
    const NS = 'atkbrain';
    /** Host session-projection key carrying the attack-graph wire view. */
    const PROJECTION_KEY = 'atkGraph';
    /** Hard render caps: the SVG stays responsive even for very large graphs. */
    const MAX_RENDER_NODES = 800;
    const MAX_RENDER_EDGES = 1500;
    /** Layout metrics (SVG user units). */
    const PAD_X = 40;
    const PAD_Y = 28;
    const COL_W = 202;
    const ROW_H = 62;
    const NODE_W = 176;
    const NODE_H = 46;
    const HEADER_H = 44;
    const CHAIN_STAGES = [
      'recon',
      'initial_access',
      'execution',
      'persistence',
      'privilege_escalation',
      'credential_access',
      'lateral_movement',
      'collection',
      'exfiltration',
      'impact_proof',
    ];
    const CHAIN_STAGE_RANK = {};
    CHAIN_STAGES.forEach((stage, index) => {
      CHAIN_STAGE_RANK[stage] = index;
    });

    /** Node kinds in presentation order (kept in sync with lib/constants.js). */
    const NODE_KIND_RANK = {
      target: 8,
      domain: 10,
      wildcard_zone: 12,
      host: 20,
      ip: 24,
      cidr: 28,
      segment: 32,
      service: 40,
      webapp: 44,
      tech: 48,
      finding: 60,
      credential: 64,
      access: 70,
      pivot: 74,
      data: 80,
      evidence: 84,
      task: 90,
      chain_step: 94,
      loop: 4,
      intent: 96,
      supervision: 97,
      lesson: 98,
      unknown: 99,
    };

    /** Edge kinds in presentation order (kept in sync with lib/constants.js). */
    const EDGE_KIND_RANK = {
      contains: 1,
      resolves_to: 2,
      cname: 3,
      hosted_on: 4,
      exposes: 5,
      affects: 6,
      authenticates_to: 7,
      controls: 8,
      pivots_to: 9,
      reached_via: 10,
      proves: 11,
      derived_from: 12,
      merged_into: 13,
      duplicate_of: 14,
      escalates_to: 21,
    };

    const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1, unscored: 0, unknown: 0 };
    const SEVERITY_LIST = ['critical', 'high', 'medium', 'low', 'info'];
    const VERIFIED_STATUSES = ['verified', 'exploited', 'impacted', 'validated', 'escalated', 'valid'];
    /** Team-batch lifecycle ranks (planned → dispatched → artifact → merged). */
    const TEAM_STATUS_RANK = {
      planned: 1,
      dispatched: 2,
      artifact_ready: 3,
      completed: 4,
      merged: 5,
      failed: 6,
      merge_failed: 7,
      cancelled: 8,
    };

    /** Fixed palette: category hues are graph semantics, not theme chrome. */
    const KIND_COLOR = {
      target: '#7c5cff',
      domain: '#6b8afd',
      wildcard_zone: '#8b5cf6',
      host: '#0ea5e9',
      ip: '#06b6d4',
      cidr: '#14b8a6',
      segment: '#10b981',
      service: '#f59e0b',
      webapp: '#f97316',
      tech: '#eab308',
      finding: '#ef4444',
      credential: '#a855f7',
      access: '#ec4899',
      pivot: '#d946ef',
      data: '#e11d48',
      evidence: '#64748b',
      task: '#38bdf8',
      chain_step: '#f472b6',
      loop: '#2dd4bf',
      intent: '#84cc16',
      supervision: '#fb923c',
      lesson: '#facc15',
      self_team: '#22d3ee',
      skill: '#a3e635',
      mcp: '#2dd4bf',
      unknown: '#6b7280',
    };
    const SEVERITY_COLOR = {
      critical: '#dc2626',
      high: '#ef4444',
      medium: '#f59e0b',
      low: '#3b82f6',
      info: '#64748b',
      unscored: '#94a3b8',
      unknown: '#6b7280',
    };
    const EDGE_COLOR = {
      exposes: '#38bdf8',
      hosted_on: '#38bdf8',
      affects: '#94a3b8',
      proves: '#f59e0b',
      controls: '#ef4444',
      pivots_to: '#ec4899',
      reached_via: '#ec4899',
      authenticates_to: '#a855f7',
      contains: '#64748b',
      resolves_to: '#64748b',
      cname: '#64748b',
      derived_from: '#64748b',
      learned_from: '#a3e635',
      distills: '#a3e635',
      reports_to: '#22d3ee',
      escalates_to: '#ef4444',
      supervises: '#fb923c',
      applies_to: '#facc15',
      targets: '#f472b6',
      merged_into: '#64748b',
      duplicate_of: '#64748b',
    };

    function edgeColor(edge) {
      return EDGE_COLOR[edge.kind] || 'var(--dsw-alias-label-tertiary)';
    }

    /** Layered layout: one column per attack-surface stage. */
    const LAYERED_COLUMNS = [
      { id: 'entry', label: 'graph.stage.entry', kinds: ['domain', 'wildcard_zone'] },
      { id: 'target', label: 'graph.stage.target', kinds: ['target'] },
      { id: 'asset', label: 'graph.stage.asset', kinds: ['host', 'ip', 'cidr', 'segment'] },
      { id: 'service', label: 'graph.stage.service', kinds: ['service', 'webapp', 'tech'] },
      { id: 'finding', label: 'graph.stage.finding', kinds: ['finding', 'credential'] },
      { id: 'access', label: 'graph.stage.access', kinds: ['access', 'pivot'] },
      { id: 'data', label: 'graph.stage.data', kinds: ['data', 'evidence'] },
      { id: 'task', label: 'graph.stage.task', kinds: ['task', 'chain_step', 'loop', 'intent', 'supervision', 'lesson'] },
    ];
    const OTHER_COLUMN = { id: 'other', label: 'graph.stage.other', kinds: [] };
    const LAYERED_COLUMN_OF_KIND = {};
    LAYERED_COLUMNS.forEach((column, index) => {
      for (const kind of column.kinds) LAYERED_COLUMN_OF_KIND[kind] = index;
    });

    // ---------------------------------------------------------------------
    // Dictionaries (zh is the key-set source of truth; en mirrors every key)
    // ---------------------------------------------------------------------

    const zh = {
      'view.label': '攻击图谱',
      title: '攻击图谱',
      subtitle: '会话攻击面关系视图',
      'waiting.title': '等待攻防图谱数据…',
      'waiting.hint': '数据到达后图谱会自动出现，无需刷新。',
      'waiting.instructions': '在对话中让 agent 导入资产：把资产文档、扫描结果或主机列表发给它，并让它用 AtkBrain 记录资产与关系。',
      'empty.title': '图谱还是空的',
      'empty.hint': '当前会话还没有任何资产节点。',
      'empty.instructions': '在对话中让 agent 导入资产：提供资产文档、DNS/端口扫描结果或主机列表，让它调用 AtkBrain 的摄取工具建立资产与关系节点。',
      'error.title': '攻击图谱渲染失败',
      'error.message': '页面组件出现异常，已隔离以保护会话。',
      'error.retry': '重试',
      'header.engagement': '交战',
      'header.noEngagement': '未命名交战',
      'header.projectId': '项目 ID',
      'header.projectIdHint': '点击复制项目 ID；用于在多个项目中定位和优化对应项目。',
      'header.projectComplete': '项目完成',
      'header.projectPending': '项目未完成',
      'header.projectCompleteHint': '项目级 HTML 报告已由报告撰写团队生成，且覆盖最新 finding/access/data。',
      'header.projectPendingHint': '必须由报告撰写团队生成项目级 HTML 报告后，项目才算完成。',
      'header.scope': '授权范围',
      'header.scopeEmpty': '未设置范围',
      'header.scopeOk': '已授权 {allow} 项',
      'header.scopeDeny': '拒绝 {deny} 项',
      'header.seq': 'seq {seq}',
      'header.exportReport': '导出报告',
      'report.formats': '更多格式',
      'report.markdown': 'Markdown 报告',
      'report.html': 'HTML 报告',
      'report.json': 'JSON 图谱',
      'report.csv': '漏洞 CSV',
      'report.exporting': '生成中…',
      'report.exportFailed': '报告导出失败',
      'header.lastAction': '最近动作',
      'stat.assets': '资产',
      'stat.services': '服务',
      'stat.findings': '发现',
      'stat.vulnerabilities': '漏洞',
      'stat.discoveries': '发现',
      'stat.access': '权限',
      'stat.data': '数据',
      'target.summary': '集群与目标覆盖',
      'target.cluster': '集群',
      'target.target': '目标',
      'target.services': '服务',
      'target.interfaces': '接口',
      'target.findings': '发现',
      'target.vulnerabilities': '漏洞',
      'target.access': '权限',
      'target.data': '数据',
      'target.coverage': '深测覆盖',
      'target.status': '状态',
      'target.status.tested': '已测试',
      'target.status.recon': '仅侦察',
      'target.status.untested': '未测试',
      'target.status.impacted': '已影响',
      'target.empty': '还没有目标资产',
      'target.emptyHint': '导入域名/IP 或执行 probe 后，这里会显示集群及每个子目标的覆盖。',
      'target.summaryLine': '{clusters} 个集群 · {targets} 个目标 · {tested} 已测试 / {recon} 仅侦察 / {untested} 未测试 / {impacted} 已影响',
      'target.clusterSummary': '{targets} 个目标 · {tested} 已测试',
      'target.coverageShort': '{seen}/{cells} 格',
      'target.gapWarning': '仍有 {untested} 个未测试、{recon} 个仅侦察目标；先补目标覆盖，不要宣称全部域名已测试。',
      'target.unboundWarning': '有 {cells} 个覆盖格未绑定到目标（{seen} 个已看），目标级覆盖不完整；重新 seed 时请带 target=<资产域名>。',
      'group.assets': '资产',
      'group.services': '服务',
      'group.findings': '发现',
      'group.vulnerabilities': '漏洞',
      'group.candidates': '候选',
      'group.verified': '已验',
      'group.title': '目标详情',
      'group.members': '成员节点',
      'group.expand': '展开到图谱',
      'group.collapse': '收起目标',
      'group.expanded': '已展开',
      'group.memberHint': '点击成员查看节点详情；展开后会显示在图谱中。',
      'toolbar.groupTargets': '目标归纳',
      'toolbar.groupHint': '多资产时自动归纳为目标组；点击目标查看成员。',
      'graph.targetGroups': '已归纳 {groups} 个目标 · 折叠 {hidden} 个节点',
      'graph.unverifiedFindings': '{count} 个漏洞候选尚未通过二次验证，不要当作已确认漏洞。',
      'graph.cvssSummary': '共 {total} 项漏洞：验证成功 {verified}，验证中 {pending}，验证失败 {refuted}。验证失败只表示二次验证判为假阳性。同一接口同一类型只保留一条。',
      'stat.findingsVerified': '{verified}/{total} 已验证',
      'graph.legendTargets': '目标',
      'stat.credentials': '凭证',
      'stat.crown': '里程碑',
      'stat.batches': '批次',
      'stat.batchesMerged': '批次 · 已合并 {count}',
      'stat.rounds': '轮次',
      'stat.lessons': '经验',
      'stat.lessonsApplied': '经验 · 已应用 {count}',
      'stat.wildcardExcluded': '泛解析排除',
      'stat.openHint': '点击查看{label}详情',
      'stat.detailCount': '共 {count} 个节点',
      'stat.detailEmpty': '没有匹配的节点。',
      'stat.detailHint': '点击行在图中聚焦；按 Esc 关闭。',
      'toolbar.aria': '图谱工具栏',
      'toolbar.search': '搜索',
      'toolbar.searchPlaceholder': '搜索标签 / 键 / 类型 / 属性',
      'toolbar.layoutLayered': '层级',
      'toolbar.layoutChain': '攻击链',
      'toolbar.kind': '类型',
      'toolbar.kindAll': '全部类型',
      'toolbar.severity': '严重度',
      'toolbar.severityAll': '全部严重度',
      'toolbar.verifiedOnly': '仅已验证',
      'toolbar.attackView': '攻击视图',
      'toolbar.fullView': '完整视图',
      'graph.attackHidden': '已隐藏 {count} 个未通过二次验证/未纳入漏洞的节点',
      'graph.attackHint': '攻击视图只显示完成了二次验证并已评级的 finding，以及资产、服务、权限与数据；切换完整视图可显示全部节点。',
      'proxy.title': '出口代理',
      'proxy.enabled': '已启用',
      'proxy.disabled': '未启用',
      'proxy.pending': '等待出口',
      'proxy.blocked': '已阻断',
      'proxy.noExit': '出口未检测',
      'proxy.loopback': '回环直连',
      'proxy.enable': '启用',
      'proxy.disable': '停用',
      'proxy.test': '测试出口',
      'proxy.rotate': '轮换出口',
      'proxy.unavailable': '代理状态接口不可用；让 agent 运行 atkbrain_proxy action=status。',
      'toolbar.showWildcard': '显示泛解析可疑',
      'toolbar.fit': '适配',
      'toolbar.fullscreen': '全屏',
      'toolbar.exitFullscreen': '退出全屏',
      'toolbar.zoomIn': '放大',
      'toolbar.zoomOut': '缩小',
      'toolbar.reset': '重置视图',
      'toolbar.clearFilters': '清除筛选',
      'toolbar.results': '显示 {shown}/{total} 个节点',
      'toolbar.zoomLevel': '缩放 {percent}%',
      'graph.aria': '攻击图谱关系图',
      'graph.legend': '图例',
      'graph.legendEdges': '曲线表示关系；选中节点会高亮其路径，悬停连线可查看类型与置信度',
      'graph.legendHigh': '高危 / 严重',
      'graph.panHint': '滚轮缩放 · 拖拽平移',
      'graph.activity': '实时活动',
      'graph.working': '正在执行',
      'graph.idle': '待命',
      'graph.focus': '路径焦点',
      'graph.flow': '数据流动',
      'graph.emptyFiltered': '没有符合当前筛选的节点',
      'graph.emptyFilteredHint': '调整搜索、类型或严重度筛选后再试。',
      'graph.nodeCount': '{count} 个节点',
      'graph.edgeCount': '{count} 条边',
      'graph.stage.entry': '入口',
      'graph.stage.target': '目标',
      'graph.stage.internal': '内网目标',
      'graph.stage.asset': '资产',
      'graph.stage.service': '服务',
      'graph.stage.finding': '漏洞',
      'graph.stage.access': '权限',
      'graph.stage.data': '数据',
      'graph.stage.task': '任务',
      'graph.stage.other': '其他',
      'graph.truncatedNodes': '节点过多，仅渲染 {shown} 个（已省略 {omitted} 个），请用筛选缩小范围。',
      'graph.truncatedEdges': '连线过多，仅渲染 {shown} 条（已省略 {omitted} 条），请用筛选缩小范围。',
      'graph.hostTruncated': '图谱一次放不下：还有 {nodes} 个节点、{edges} 条边留在账本里，没有画出来。',
      'graph.edgeLabel': '{kind} · {confidence}%',
      'chain.stage.recon': '侦察',
      'chain.stage.initial_access': '初始访问',
      'chain.stage.execution': '执行',
      'chain.stage.persistence': '持久化',
      'chain.stage.privilege_escalation': '权限提升',
      'chain.stage.credential_access': '凭证获取',
      'chain.stage.lateral_movement': '横向移动',
      'chain.stage.collection': '收集',
      'chain.stage.exfiltration': '外泄',
      'chain.stage.impact_proof': '影响证明',
      'chain.stage.unknown': '未知阶段',
      'edge.contains': '包含',
      'edge.resolves_to': '解析到',
      'edge.cname': 'CNAME',
      'edge.hosted_on': '托管于',
      'edge.exposes': '暴露服务',
      'edge.affects': '影响',
      'edge.authenticates_to': '认证到',
      'edge.controls': '控制',
      'edge.pivots_to': '横向到',
      'edge.reached_via': '经由到达',
      'edge.proves': '证据证明',
      'edge.derived_from': '派生自',
      'edge.merged_into': '合并到',
      'edge.duplicate_of': '重复于',
      'edge.applies_to': '适用于',
      'edge.supervises': '监督',
      'edge.learned_from': '学习自',
      'edge.distills': '蒸馏为',
      'edge.reports_to': '汇报给',
      'edge.escalates_to': '危害提升至',
      'edge.unknown': '关联',
      'kind.target': '目标',
      'kind.domain': '域名',
      'kind.wildcard_zone': '泛解析区',
      'kind.host': '主机',
      'kind.ip': 'IP',
      'kind.cidr': 'IP 段',
      'kind.segment': '网段',
      'kind.service': '服务',
      'kind.webapp': 'Web 应用',
      'kind.tech': '技术',
      'kind.finding': '漏洞',
      'kind.credential': '凭证',
      'kind.access': '权限',
      'kind.pivot': '跳板',
      'kind.data': '数据',
      'kind.evidence': '证据',
      'kind.task': '任务',
      'kind.chain_step': '攻击链步骤',
      'kind.loop': '自主循环',
      'kind.intent': '意图',
      'kind.supervision': '监督',
      'kind.lesson': '经验',
      'kind.self_team': '自团队',
      'kind.skill': '路径技能',
      'kind.unknown': '未知',
      'severity.critical': '严重',
      'severity.high': '高危',
      'severity.medium': '中危',
      'severity.low': '低危',
      'severity.info': '信息',
      'severity.unscored': '未评分',
      'severity.unknown': '未知',
      'status.verified': '已验证',
      'status.exploited': '已利用',
      'status.impacted': '已影响',
      'status.candidate': '候选',
      'status.fixed': '已修复',
      'status.attempted': '已尝试',
      'status.obtained': '已获取',
      'status.validated': '已验证',
      'status.escalated': '已提权',
      'status.lost': '已丢失',
      'status.untested': '未测试',
      'status.valid': '有效',
      'status.invalid': '无效',
      'status.expired': '已过期',
      'status.claimed': '声称',
      'status.partial': '部分',
      'status.confirmed': '已确认',
      'status.suspect': '可疑',
      'status.inconclusive': '不确定',
      'status.cleared': '已排除',
      'status.pending': '待执行',
      'status.running': '执行中',
      'status.done': '已完成',
      'status.planned': '已计划',
      'status.dispatched': '已派发',
      'status.artifact_ready': '产物就绪',
      'status.completed': '已完成',
      'status.failed': '失败',
      'status.merge_failed': '合并失败',
      'status.active': '进行中',
      'status.paused': '已暂停',
      'status.stopped': '已停止',
      'status.exhausted': '轮次耗尽',
      'status.complete': '已完成',
      'status.blocked': '已阻塞',
      'status.recorded': '已记录',
      'status.open': '未完成',
      'status.retired': '已退役',
      'status.cancelled': '已取消',
      'status.merged': '已合并',
      'status.unknown': '未知',
      'verification.refuted': '已否定',
      'verification.unverified': '未验证',
      'verification.corroborated': '已佐证',
      'verification.verified': '已验证',
      'verification.passed': '验证成功',
      'verification.pending': '验证中',
      'verification.failed': '验证失败',
      'risk.none': '无',
      'risk.low': '低',
      'risk.medium': '中',
      'risk.high': '高',
      'tab.aria': '数据页签',
      'data.expand': '展开数据',
      'data.collapse': '收起数据',
      'tab.assets': '资产',
      'tab.services': '服务',
      'tab.targets': '目标覆盖',
      'tab.vulnerabilities': '漏洞',
      'tab.findings': '发现',
      'tab.access': '权限',
      'tab.data': '数据',
      'tab.chains': '攻击链',
      'tab.wildcard': '泛解析',
      'tab.tasks': '任务',
      'tab.team': '团队',
      'tab.loop': '循环',
      'tab.settings': '设置',
      'table.empty': '{tab}暂无数据',
      'table.emptyHint': '导入资产或让 agent 记录结果后，这里会自动填充。',
      'table.emptyVulnHint': '当前没有通过二次验证和评级的漏洞；先运行 atkbrain_selftteam action=verify 后再查看。',
      'table.searchEmpty': '没有匹配当前搜索的记录。',
      'table.sortHint': '点击表头排序',
      'table.rowSelect': '查看 {label} 详情',
      'col.label': '标签',
      'col.vulnType': '漏洞类型',
      'col.escalation': '危害提升',
      'col.kind': '类型',
      'col.status': '状态',
      'col.severity': '严重度',
      'col.cvss': 'CVSS',
      'col.vulnerability': '是否漏洞',
      'finding.verdictVulnerability': '漏洞',
      'finding.verdictVerifiedVulnerability': '已验证漏洞',
      'finding.verdictPendingVulnerability': '待二次验证漏洞',
      'finding.verdictRefutedVulnerability': '二次验证未通过',
      'finding.verdictNotVulnerability': '安全发现',
      'finding.verdictUnscored': '未评分',
      'col.confidence': '置信度',
      'col.verification': '验证',
      'col.degree': '关联',
      'col.evidence': '证据',
      'col.crown': '里程碑',
      'col.wildcard': '泛解析',
      'col.port': '端口',
      'col.protocol': '协议',
      'col.banner': 'Banner',
      'col.title': '标题',
      'col.url': 'URL',
      'col.username': '用户名',
      'col.privilege': '权限',
      'col.validity': '有效性',
      'col.dataClass': '数据分类',
      'col.count': '数量',
      'col.chain': '链',
      'col.stage': '阶段',
      'col.ordinal': '序号',
      'col.actionType': '动作',
      'col.priority': '优先级',
      'col.risk': '风险',
      'col.why': '原因',
      'col.zone': '区',
      'col.cdn': 'CDN',
      'col.probes': '探测',
      'col.lastSeen': '最近出现',
      'col.batchId': '批次 ID',
      'col.assets': '资产数',
      'col.agent': '执行人',
      'col.mode': '模式',
      'col.artifact': '产物',
      'col.mergedAt': '合并时间',
      'col.verdict': '判定',
      'col.source': '来源',
      'col.round': '轮次',
      'col.createdAt': '时间',
      'col.expectedEvidence': '期望证据',
      'col.lessonKey': '经验键',
      'col.route': '路径',
      'col.idea': '思路',
      'col.wins': '胜',
      'col.fails': '负',
      'col.uses': '使用',
      'col.target': '目标',
      'col.cost': '代价',
      'col.steps': '步骤',
      'detail.title': '节点详情',
      'detail.close': '关闭详情',
      'detail.empty': '在图中选择一个节点，或点击下方表格行查看详情。',
      'detail.kind': '类型',
      'detail.status': '状态',
      'detail.confidence': '置信度',
      'detail.verification': '验证级别',
      'detail.evidence': '证据数',
      'detail.degree': '关联数',
      'detail.tags': '标签',
      'detail.attrs': '属性',
      'detail.attrsEmpty': '没有可展示的属性',
      'detail.otherAttrs': '其他属性',
      'detail.edges': '关联边',
      'detail.related': '和它相连的',
      'detail.edgesEmpty': '没有关联边',
      'detail.copyId': '复制 ID',
      'detail.copyJson': '复制 JSON',
      'detail.copied': '已复制到剪贴板',
      'detail.copyFailed': '复制失败，可手动选择下方文本',
      'detail.focus': '在图中聚焦',
      'detail.json': '节点 JSON',
      'detail.firstSeen': '首次出现',
      'detail.lastSeen': '最近出现',
      'detail.out': '出',
      'detail.in': '入',
      'detail.hidden': '该节点被当前筛选隐藏，点击「在图中聚焦」可恢复。',
      'detail.findingOverview': '漏洞简介',
      'detail.verifiedOverview': '安全发现简介',
      'detail.detailSourceTeam': '技术详情由二次验证/评级团队根据证据撰写。',
      'detail.aiDetail': 'AI 详情',
      'detail.aiDetailReady': 'AI 详情已完成',
      'detail.factHost': '目标',
      'detail.accessStory': '这是已经拿到的权限，包括落在哪台机器、什么身份。',
      'detail.pivotStory': '这是横向要去的下一台机器，还没有完全控制。',
      'detail.credentialStory': '这是一条凭证。这里只显示账号和脱敏结果，不显示口令原文。',
      'detail.dataStory': '这是已经读到的数据。',
      'detail.hostStory': '这是一台主机。',
      'detail.serviceStory': '这是一个端口上的服务。',
      'detail.webappStory': '这是一个网站。',
      'detail.genericStory': '这是图谱中的一个节点。',
      'detail.factPrivilege': '身份',
      'detail.factAccount': '账号',
      'detail.factWhere': '位置',
      'detail.factAmount': '数量',
      'detail.factAddress': '地址',
      'detail.factParameter': '参数',
      'detail.factCVSS': 'CVSS',
      'detail.factVerification': '验证状态',
      'detail.aiDetailPending': 'AI 详情待生成',
      'detail.aiDetailPendingShort': 'AI 详情尚未生成；下方先展示已验证证据摘要，执行 atkbrain_selftteam action=detail findingId=<id> 生成完整中文详情。',
      'detail.escalation': '危害提升',
      'detail.escalationProof': '提升证明',
      'detail.originalRecord': '原始技术记录（英文）',
      'detail.originalRecordHint': '以下为已验证的原始技术记录；AI 中文重写尚未完成。',
      'detail.originalDescription': '根因描述',
      'detail.originalImpact': '危害',
      'detail.originalReproduction': '复现',
      'detail.detailSourcePending': '当前为模板中文摘要，尚未由 AI 撰写；运行 atkbrain_selftteam action=detail findingId=<id> 或 verify 生成完整详情。',
      'detail.englishDetailNote': '原始技术记录为英文，已在上方转换为中文摘要；运行 action=detail 或 verify 后由 AI 团队写入完整中文详情。',
      'detail.findingOverviewPlain': '发现简介',
      'detail.vulnerabilityLabel': '漏洞',
      'detail.verifiedFindingLabel': '安全发现',
      'detail.findingLabel': '发现',
      'detail.findingImpact': '危害',
      'detail.findingRating': '红队评级',
      'detail.findingRepro': '手动复现',
      'detail.request': '请求包',
      'detail.response': '响应包',
      'detail.requestMissing': '未记录请求包；可在 atkbrain_record 的 finding.attrs 中补 request/response。',
      'detail.responseMissing': '未记录响应包。',
      'detail.secondaryVerified': '已二次验证',
      'detail.notSecondaryVerified': '未二次验证',
      'detail.downloadMd': '下载 Markdown',
      'detail.proof': '证明',
      'detail.ratingRationale': '评级理由',
      'detail.noDescription': '暂无简介；请补充 description/impact 和请求响应。',
      'detail.remediation': '修复建议',
      'detail.secondaryCheck': '二次验证',
      'detail.evidenceFiles': '证据文件',
      'detail.noEvidence': '没有关联证据文件。',
      'detail.derivedExpiredDescription': '目标 {subject} 的 TLS 证书已过期（{when}）。客户端证书校验会失败。',
      'detail.derivedExpiredImpact': '证书过期会导致客户端拒绝连接或诱导用户忽略证书警告，增加中间人风险；依赖证书校验的服务可用性也会受影响。',
      'detail.derivedExpiredRepro': 'atkbrain_probe action=tls target={host} port={port}\n# 或\nopenssl s_client -connect {host}:{port} -servername {host}',
      'detail.derivedTlsRequest': 'TLS ClientHello\nSNI={host}',
      'detail.derivedTlsResponse': 'TLS ServerHello / 证书\nsubject={subject}\nnotAfter={when}',
      'detail.derivedDescription': '{title}：{evidence}',
      'detail.derivedEvidenceDescription': '{title}：探测响应中存在对应暴露特征，证据已保存到证据文件。',
      'detail.derivedXssDescription': '在 {subject} 的 {parameter} 参数中，输入被原样写入 HTML 响应；证据中的 payload 未做上下文编码，可闭合原有标签并执行脚本。',
      'detail.derivedXssImpact': '攻击者可诱导已登录用户在站点上下文执行脚本，读取页面数据或以用户身份发起操作；实际影响取决于会话与页面权限。',
      'detail.derivedSqliImpact': '攻击者可读取或篡改数据库数据；若数据库账户权限较高，影响可能进一步扩大。',
      'detail.derivedRceImpact': '攻击者可借助该输入在目标服务上执行命令，具体权限取决于服务账户和系统限制。',
      'detail.derivedXssRepro': '发送携带唯一标记的 {parameter} 参数两次，比较响应中标记是否被原样反射；再用无害的 svg/onload 载体确认上下文。',
      'detail.remediationXss': '对 {parameter} 参数按输出上下文做 HTML/属性/JavaScript 编码，使用白名单校验回调地址，并启用 CSP 作为兜底。',
      'detail.derivedSqliDescription': '在 {subject} 的参数输入进入 SQL 查询，证据中存在可复现的数据库错误或数据差异。',
      'detail.remediationSqli': '对查询参数使用参数化查询/预编译语句，禁止字符串拼接，并统一处理数据库错误。',
      'detail.derivedRceDescription': '在 {subject} 的输入路径上存在可复现的命令执行证据，响应中记录了独立标记。',
      'detail.remediationRce': '移除 shell 调用，使用固定参数列表与允许列表，限制服务账户权限。',
      'detail.derivedImpactInfo': '该发现属于暴露面/加固项，尚未验证直接入侵影响；需要结合其他证据评估。',
      'detail.derivedImpact': '该发现可能扩大攻击面；实际影响以验证结果和 access/data 节点为准。',
      'detail.derivedRepro': '用 atkbrain_probe 或等价只读请求复现两次，比较状态码、响应体和证据哈希；未复现前保持 candidate。',
      'detail.derivedRemediation': '按 finding 模板修复后重新探测；未验证前保持 candidate，不要写成已确认漏洞。',
      'detail.remediationExpired': '续期证书并启用到期监控；确认客户端校验证书链和有效期。',
      'detail.remediationHeaders': '配置 HSTS/CSP/X-Content-Type-Options 等安全响应头，并移除不必要的版本信息。',
      'detail.remediationRobots': '审计 robots.txt 暴露的路径，移除敏感路径或改为需要认证的入口。',
      'detail.remediationAdmin': '限制管理入口的来源和认证，启用 MFA/速率限制，避免匿名访问管理页。',
      'detail.remediationGeneric': '按 finding 模板修复并重新验证；未验证前保持 candidate。',
      'detail.noRequestButEvidence': '未记录原始请求包；下方证据文件保存了实际观测。',
      'detail.secondaryEvidence': '验证证据：{path}',
      'detail.cvss': 'CVSS',
      'detail.cvssVerdict': 'CVSS 判定',
      'detail.unscoredVerdict': '未评分：没有 CVSS v3.1 Base 分数，尚不能定级。',
      'detail.vulnerabilityUnscoredVerdict': '漏洞：尚未评分；二次验证/评级团队必须补齐 CVSS v3.1 Base score。',
      'detail.refutedVulnerabilityVerdict': '二次验证未通过：该 finding 不纳入漏洞页。',
      'detail.nonVulnerabilityCvss': '安全发现：CVSS {score}（{severity}），属于暴露/加固项，不计为可利用漏洞。',
      'detail.vulnerabilityCvss': '漏洞：CVSS {score}（{severity}），已按漏洞类确认。',
      'detail.cvssScore': 'CVSS {score}（{severity}）',
      'detail.ratingCritical': '严重：存在命令执行、管理员权限或批量数据影响证据。',
      'detail.ratingHigh': '高危：存在直接影响，但尚未证明命令执行或批量影响。',
      'detail.ratingMedium': '中危：中等影响，需要结合验证结果评估。',
      'detail.ratingLow': '低危：影响有限。',
      'detail.ratingInfo': '信息：仅为暴露面或信息项。',
      'detail.secondaryVerifiedGeneric': '独立复核通过：证据文件可复现，未发现矛盾。',
      'detail.secondaryRefutedGeneric': '独立复核未通过：证据不足或无法复现。',
      'detail.secondaryInconclusiveGeneric': '独立复核不确定：现有证据不足以确认。',
      'detail.categoryTls': 'TLS 证书',
      'detail.categoryHeaders': '安全响应头',
      'detail.categoryDisclosure': '技术信息泄露',
      'detail.categoryRobots': 'robots.txt',
      'detail.categoryFingerprint': '技术指纹',
      'detail.categoryExposure': '暴露面',
      'detail.categoryGeneric': '安全配置',
      'detail.evidencePackets': '证据与报文',
      'detail.rawAttrs': '原始属性',
      'detail.edgeEvidence': '证据 {count}',
      'chain.explicit': '显式攻击链',
      'chain.crown': '里程碑路径',
      'chain.toRce': '到达远程代码执行',
      'chain.empty': '还没有走到远程代码执行',
      'chain.chainId': '攻击链 {id}',
      'chain.noSteps': '没有步骤',
      'notice.hiddenWildcard': '已隐藏 {count} 个泛解析可疑主机，可在工具栏显示。',
      'team.title': '团队批次',
      'team.statusFilter': '状态',
      'team.statusAll': '全部状态',
      'team.summary': '显示 {shown}/{total} 个批次',
      'team.empty': '还没有团队批次',
      'team.emptyHint': '让 Lead 运行 atkbrain_team action=plan 创建批次，再运行 action=dispatch 派发给子 agent。',
      'team.emptyFiltered': '没有匹配当前筛选的团队批次',
      'team.artifactReady': '产物已就绪',
      'team.artifactPending': '产物未就绪',
      'verdict.hold': '保持',
      'verdict.pivot': '转向',
      'verdict.verify': '验证',
      'verdict.escalate': '升级',
      'verdict.stop': '停止',
      'verdict.verified': '已证实',
      'verdict.refuted': '已否定',
      'verdict.inconclusive': '不确定',
      'verdict.unknown': '未知',
      'supervision.round_plan': '轮次计划',
      'supervision.verification': '证据复核',
      'supervision.unknown': '未知类型',
      'source.deterministic': '确定性',
      'source.model': '模型',
      'source.subagent': '子代理',
      'source.unknown': '未知来源',
      'activation.armed': '已激活',
      'activation.disarmed': '未激活',
      'loop.title': '自主循环',
      'loop.state': '循环状态',
      'loop.phase': '阶段',
      'loop.round': '轮次',
      'loop.objective': '目标',
      'loop.objectiveType': '目标类型',
      'loop.goalPhase': '目标阶段',
      'loop.activation': '激活',
      'loop.ring': '环',
      'loop.ringValue': '环 / 允许环',
      'loop.noProgress': '无进展轮次',
      'loop.emptyRounds': '空轮次',
      'loop.maxActions': '每轮动作上限',
      'loop.stopReason': '停止原因',
      'loop.autoContinue': '自动续跑',
      'loop.startedAt': '启动时间',
      'loop.lastStepAt': '最近步进',
      'loop.appliedLessons': '已应用经验',
      'loop.disarmedWarn': '循环 goal 处于未激活（disarmed）状态，自动续跑不会发生；需要 Lead 恢复目标。',
      'loop.supervision': '监督',
      'loop.latestSupervision': '最新监督',
      'loop.verdict': '判定',
      'loop.secondaryVerdict': '次判定',
      'loop.source': '来源',
      'loop.confidence': '置信度',
      'loop.diagnosis': '诊断',
      'loop.nextPlan': '下一步计划',
      'loop.mustIntents': '必须意图',
      'loop.preferTactics': '偏好战术',
      'loop.banRepeats': '禁止重复',
      'loop.stopRecommended': '建议停止',
      'loop.supervisionHistory': '监督历史',
      'loop.supervisionEmpty': '还没有监督记录；运行 atkbrain_supervise action=review 生成轮次计划。',
      'loop.intents': '意图',
      'loop.emptyIntents': '还没有意图；运行 atkbrain_loop action=start 生成下一轮意图。',
      'loop.lessons': '进化经验',
      'loop.emptyLessons': '还没有经验沉淀；循环复盘后会自动记录 lesson。',
      'loop.empty': '自主循环尚未启动',
      'loop.emptyHint': '让 Lead 运行 atkbrain_loop action=start 启动自主循环，再用 atkbrain_supervise action=review 生成监督计划。',
      'settings.title': '设置',
      'settings.hint': '配置代理与 FOFA / 鹰图 Hunter / 360 Quake。',
      'settings.refresh': '刷新',
      'settings.checkAll': '一键体检',
      'settings.checking': '体检中…',
      'settings.normal': '正常',
      'settings.abnormal': '异常',
      'settings.resources': '资源体检',
      'settings.skills': '技能',
      'settings.tools': '渗透工具',
      'settings.dicts': '字典',
      'settings.expected': '期望 {count}',
      'settings.actual': '实际 {count}',
      'settings.missing': '缺失 {count}',
      'settings.usable': '可用 {count}',
      'settings.present': '文件在位 {count}',
      'settings.configured': '已配置',
      'settings.notConfigured': '未配置',
      'settings.proxy': '出口代理',
      'settings.proxyHint': 'HTTP(S) 全局代理；回环直连。',
      'settings.proxyUrl': '代理 URL',
      'settings.proxyMode': '模式',
      'settings.proxyNoProxy': 'NO_PROXY',
      'settings.saveProxy': '保存并启用',
      'settings.disableProxy': '停用代理',
      'settings.testProxy': '测试出口',
      'settings.proxySaved': '代理配置已保存',
      'settings.survey': '测绘源',
      'settings.surveyHint': '密钥只写入本机 0600 设置文件，页面只显示掩码。',
      'settings.fofa': 'FOFA',
      'settings.hunter': '鹰图 Hunter',
      'settings.quake': '360 Quake',
      'settings.enabled': '启用',
      'settings.baseUrl': 'API 地址',
      'settings.email': '邮箱（FOFA 可选）',
      'settings.apiKey': 'API Key',
      'settings.keyEnv': '环境变量名',
      'settings.keyConfigured': '已配置 {mask}',
      'settings.save': '保存',
      'settings.testKey': '测试密钥',
      'settings.testing': '测试中…',
      'settings.requiredKey': '请先填写 API Key',
      'settings.saved': '已保存',
      'settings.failed': '失败',
      'settings.clearKey': '清除密钥',
      'loop.coverage': '覆盖表',
      'loop.coverageHint': '接口 × 九类漏洞；未覆盖格是下一轮优先项，覆盖表不会画进攻击图。',
      'loop.coverageTotals': '共 {cells} 格 · 已看 {seen} · 未覆盖 {open}',
      'loop.coverageDuties': '漏洞发现职责',
      'loop.dutyName.xss': 'cov-xss',
      'loop.duty.xss': '跨站脚本。先看输入落在正文、属性、事件还是脚本里，再按那个位置闭合。这个接口已经记下的参数，闭合时必须点名。和别的接口共用页面，也算这一口。输入已经进入这些位置时不能否证。JSON 里回显不算这格测完。',
      'loop.dutyName.sqli': 'cov-sqli',
      'loop.duty.sqli': 'SQL 注入。对每个新的字符串参数做一次引号差分。',
      'loop.dutyName.cmd': 'cov-cmd',
      'loop.duty.cmd': '命令执行。对每个新的字符串参数做一次命令元字符差分。',
      'loop.dutyName.code': 'cov-code',
      'loop.duty.code': '代码执行。对每个新的字符串参数做一次模板或表达式探测，也包括反序列化。',
      'loop.dutyName.file': 'cov-file',
      'loop.duty.file': '文件读取。路径、文件名、模板、图像、导出、包含都做路径差分。没有上传不能把这格写成测完。跳到对象存储或带签名的地址是观察，不是否证。',
      'loop.dutyName.authz': 'cov-authz',
      'loop.duty.authz': '越权。无会话访问一次，再更换对象标识访问一次。同一接口已经出现方法名分发时，不能只写成公开读取。',
      'loop.dutyName.logic': 'cov-logic',
      'loop.duty.logic': '业务逻辑。看数量、状态、步骤和价格。登录、改密、找回密码要写明失败次数有没有被限制。写成没有限制或没有锁定时，不能否证。',
      'loop.dutyName.leak': 'cov-leak',
      'loop.duty.leak': '信息泄露。看 swagger、.git、配置，以及带调用栈的报错。响应里已经有调用栈、异常页或版本时，不能否证。',
      'loop.dutyName.nday': 'cov-nday',
      'loop.duty.nday': '已知漏洞。先确认产品或版本，再查公开漏洞。没有版本就停。',
      'loop.hypotheses': '假设',
      'loop.hypothesisHint': '持久假设需要两个通道或证据才能验证；否证必须点名目标和观测。',
      'loop.hypothesisEmpty': '还没有持久假设。',
      'loop.hypothesisTotals': '共 {total} 个 · 开放 {open} · 已验证 {verified}',
      'teamRoster.title': '五智能体团队',
      'teamRoster.empty': '设置授权范围后自动启动：御者、从者（Lead）、二次验证、危害提升、报告撰写。',
      'teamRoster.reportModes': '项目报告 + 单漏洞报告',
      'teamRoster.pending': '待启动',
      'loop.selfTeam': '五个智能体团队',
      'loop.selfTeamHint': '御者、从者（Lead）、二次验证、危害提升、报告撰写；御者只读并给从者交接，危害提升把更高危害记成新漏洞，报告团队负责项目总报告和单漏洞报告。',
      'loop.supervisionTeam': '御者',
      'loop.evolutionTeam': '自进化',
      'loop.leadTeam': '从者（Lead）',
      'loop.evolutionTeam': '自进化团队',
      'loop.verificationTeam': '二次验证',
      'loop.escalationTeam': '危害提升',
      'loop.reportTeam': '报告撰写',
      'loop.lastVerifyAt': '最近验证',
      'loop.lastReportAt': '最近报告',
      'loop.reportPath': '报告文件',
      'loop.findingReportPath': '单漏洞报告',
      'loop.teamResponsibility': '职责',
      'loop.briefPath': '简报文件',
      'loop.reportTheme': '报告主题',
      'loop.verifiedCount': '已验证',
      'loop.ratedCount': '已评级',
      'loop.selfTeamEmpty': '五团队尚未创建；设置 scope 会自动启动，或运行 atkbrain_selftteam action=start。',
      'loop.selfBriefEmpty': '还没有御者简报；运行 atkbrain_selftteam action=brief。',
      'loop.handoff': '御者 → 从者',
      'loop.handoffDelivered': '简报已送达执行者',
      'loop.handoffStale': '简报已过期',
      'loop.handoffMissing': '暂无执行者交接',
      'loop.handoffLegacy': '历史简报（未记录交接）',
      'loop.gained': '已获得',
      'loop.missed': '仍缺失',
      'loop.advice': '建议',
      'loop.antiDeadlock': '防死磕',
      'loop.recommendedNext': '下一步',
      'loop.deadlockRisk': '死磕风险',
      'loop.skillLibrary': '路径技能库',
      'loop.skillEmpty': '没有可复用的路径技能。',
      'loop.skillCount': '技能 {count}',
      'loop.skillCountLabel': '技能数',
      'loop.members': '成员',
      'loop.lastBriefAt': '最近简报',
      'loop.lastDistillAt': '最近蒸馏',
      'col.skillName': '技能',
      'col.skillRoute': '路径',
      'col.skillPath': 'SKILL.md',
      'bool.true': '是',
      'bool.false': '否',
    };

    const en = {
      'view.label': 'Attack Graph',
      title: 'Attack Graph',
      subtitle: 'Session attack-surface relationship view',
      'waiting.title': 'Waiting for graph data…',
      'waiting.hint': 'The graph appears automatically as soon as data arrives; no refresh needed.',
      'waiting.instructions': 'Ask the agent in this conversation to import assets: hand it asset documents, scan output, or a host list and let it record assets and relationships with AtkBrain.',
      'empty.title': 'The graph is empty',
      'empty.hint': 'No asset nodes exist in this session yet.',
      'empty.instructions': 'Ask the agent in this conversation to import assets: provide asset documents, DNS/port scan results, or a host list so it can ingest assets and relationships.',
      'error.title': 'Attack-graph view failed to render',
      'error.message': 'A component exception was contained so the conversation keeps working.',
      'error.retry': 'Retry',
      'header.engagement': 'Engagement',
      'header.noEngagement': 'Unnamed engagement',
      'header.projectId': 'Project ID',
      'header.projectIdHint': 'Click to copy the project ID so this engagement can be selected and optimized separately.',
      'header.projectComplete': 'Project complete',
      'header.projectPending': 'Project incomplete',
      'header.projectCompleteHint': 'The report-writing team has produced a project HTML report covering the latest finding/access/data state.',
      'header.projectPendingHint': 'The project is complete only after the report-writing team produces the project-level HTML report.',
      'header.scope': 'Scope',
      'header.scopeEmpty': 'No scope',
      'header.scopeOk': '{allow} allowed',
      'header.scopeDeny': '{deny} denied',
      'header.seq': 'seq {seq}',
      'header.exportReport': 'Export report',
      'report.formats': 'More formats',
      'report.markdown': 'Markdown report',
      'report.html': 'HTML report',
      'report.json': 'JSON graph',
      'report.csv': 'Findings CSV',
      'report.exporting': 'Generating…',
      'report.exportFailed': 'Report export failed',
      'header.lastAction': 'Last action',
      'stat.assets': 'Assets',
      'stat.services': 'Services',
      'stat.findings': 'Findings',
      'stat.vulnerabilities': 'Vulnerabilities',
      'stat.discoveries': 'Discoveries',
      'stat.access': 'Access',
      'stat.data': 'Data',
      'target.summary': 'Clusters & target coverage',
      'target.cluster': 'Cluster',
      'target.target': 'Target',
      'target.services': 'Services',
      'target.interfaces': 'Interfaces',
      'target.findings': 'Findings',
      'target.vulnerabilities': 'Vulnerabilities',
      'target.access': 'Access',
      'target.data': 'Data',
      'target.coverage': 'Coverage',
      'target.status': 'Status',
      'target.status.tested': 'Tested',
      'target.status.recon': 'Recon only',
      'target.status.untested': 'Untested',
      'target.status.impacted': 'Impacted',
      'target.empty': 'No target assets yet',
      'target.emptyHint': 'Import domains/IPs or run a probe; clusters and per-target coverage will appear here.',
      'target.summaryLine': '{clusters} clusters · {targets} targets · {tested} tested / {recon} recon-only / {untested} untested / {impacted} impacted',
      'target.clusterSummary': '{targets} targets · {tested} tested',
      'target.coverageShort': '{seen}/{cells} cells',
      'target.gapWarning': '{untested} untested and {recon} recon-only targets remain; close target coverage before claiming every domain was tested.',
      'target.unboundWarning': '{cells} coverage cell(s) are not bound to a target ({seen} seen); per-target coverage is incomplete. Pass target=<asset-host> when reseeding.',
      'group.assets': 'assets',
      'group.services': 'services',
      'group.findings': 'discoveries',
      'group.vulnerabilities': 'vulnerabilities',
      'group.candidates': 'candidates',
      'group.verified': 'verified',
      'group.title': 'Target detail',
      'group.members': 'Member nodes',
      'group.expand': 'Expand in graph',
      'group.collapse': 'Collapse target',
      'group.expanded': 'Expanded',
      'group.memberHint': 'Click a member for node details; expanding adds members to the graph.',
      'toolbar.groupTargets': 'Group targets',
      'toolbar.groupHint': 'Group multi-asset graphs into targets; click a target to list members.',
      'graph.targetGroups': 'Grouped into {groups} target(s) · {hidden} node(s) folded',
      'graph.unverifiedFindings': '{count} candidate finding(s) are not independently verified; do not treat them as confirmed vulnerabilities.',
      'graph.cvssSummary': '{total} vulnerability(ies): {verified} verified, {pending} in progress, {refuted} failed as false positives.',
      'stat.findingsVerified': '{verified}/{total} verified',
      'graph.legendTargets': 'Targets',
      'stat.credentials': 'Credentials',
      'stat.crown': 'Milestones',
      'stat.batches': 'Batches',
      'stat.batchesMerged': 'Batches · {count} merged',
      'stat.rounds': 'Rounds',
      'stat.lessons': 'Lessons',
      'stat.lessonsApplied': 'Lessons · {count} applied',
      'stat.wildcardExcluded': 'Wildcard excluded',
      'stat.openHint': 'Click for {label} details',
      'stat.detailCount': '{count} nodes',
      'stat.detailEmpty': 'No matching nodes.',
      'stat.detailHint': 'Click a row to focus it in the graph; press Esc to close.',
      'toolbar.aria': 'Graph toolbar',
      'toolbar.search': 'Search',
      'toolbar.searchPlaceholder': 'Search label / key / kind / attrs',
      'toolbar.layoutLayered': 'Layered',
      'toolbar.layoutChain': 'Attack chain',
      'toolbar.kind': 'Kind',
      'toolbar.kindAll': 'All kinds',
      'toolbar.severity': 'Severity',
      'toolbar.severityAll': 'All severities',
      'toolbar.verifiedOnly': 'Verified only',
      'toolbar.attackView': 'Attack view',
      'toolbar.fullView': 'Full view',
      'graph.attackHidden': '{count} nodes without secondary verification / not included hidden',
      'graph.attackHint': 'Shows only findings with secondary verification and a rating, plus assets, services, access and data; switch to full view for everything.',
      'proxy.title': 'Egress proxy',
      'proxy.enabled': 'Enabled',
      'proxy.disabled': 'Disabled',
      'proxy.pending': 'Waiting for egress',
      'proxy.blocked': 'Blocked',
      'proxy.noExit': 'No exit test',
      'proxy.loopback': 'loopback direct',
      'proxy.enable': 'Enable',
      'proxy.disable': 'Disable',
      'proxy.test': 'Test egress',
      'proxy.rotate': 'Rotate exit',
      'proxy.unavailable': 'Proxy status route unavailable; ask the agent to run atkbrain_proxy action=status.',
      'toolbar.showWildcard': 'Show wildcard suspects',
      'toolbar.fit': 'Fit',
      'toolbar.fullscreen': 'Fullscreen',
      'toolbar.exitFullscreen': 'Exit fullscreen',
      'toolbar.zoomIn': 'Zoom in',
      'toolbar.zoomOut': 'Zoom out',
      'toolbar.reset': 'Reset view',
      'toolbar.clearFilters': 'Clear filters',
      'toolbar.results': 'Showing {shown}/{total} nodes',
      'toolbar.zoomLevel': 'Zoom {percent}%',
      'graph.aria': 'Attack-graph relationship diagram',
      'graph.legend': 'Legend',
      'graph.legendEdges': 'Curved edges show relationships; selecting a node highlights its path and hovering reveals kind and confidence',
      'graph.legendHigh': 'High / critical',
      'graph.panHint': 'Scroll to zoom · drag to pan',
      'graph.activity': 'Live activity',
      'graph.working': 'Working',
      'graph.idle': 'Idle',
      'graph.focus': 'Path focus',
      'graph.flow': 'Flow',
      'graph.emptyFiltered': 'No nodes match the current filters',
      'graph.emptyFilteredHint': 'Adjust the search, kind, or severity filter and try again.',
      'graph.nodeCount': '{count} nodes',
      'graph.edgeCount': '{count} edges',
      'graph.stage.entry': 'Entry',
      'graph.stage.target': 'Target',
      'graph.stage.internal': 'Internal target',
      'graph.stage.asset': 'Assets',
      'graph.stage.service': 'Services',
      'graph.stage.finding': 'Findings',
      'graph.stage.access': 'Access',
      'graph.stage.data': 'Data',
      'graph.stage.task': 'Tasks',
      'graph.stage.other': 'Other',
      'graph.truncatedNodes': 'Too many nodes: rendering {shown} (omitted {omitted}). Narrow the filters.',
      'graph.truncatedEdges': 'Too many edges: rendering {shown} (omitted {omitted}). Narrow the filters.',
      'graph.hostTruncated': 'Host projection truncated: {nodes} more nodes / {edges} more edges were not sent.',
      'graph.edgeLabel': '{kind} · {confidence}%',
      'chain.stage.recon': 'Recon',
      'chain.stage.initial_access': 'Initial access',
      'chain.stage.execution': 'Execution',
      'chain.stage.persistence': 'Persistence',
      'chain.stage.privilege_escalation': 'Privilege escalation',
      'chain.stage.credential_access': 'Credential access',
      'chain.stage.lateral_movement': 'Lateral movement',
      'chain.stage.collection': 'Collection',
      'chain.stage.exfiltration': 'Exfiltration',
      'chain.stage.impact_proof': 'Impact proof',
      'chain.stage.unknown': 'Unknown stage',
      'edge.contains': 'contains',
      'edge.resolves_to': 'resolves to',
      'edge.cname': 'CNAME',
      'edge.hosted_on': 'hosted on',
      'edge.exposes': 'exposes',
      'edge.affects': 'affects',
      'edge.authenticates_to': 'authenticates to',
      'edge.controls': 'controls',
      'edge.pivots_to': 'pivots to',
      'edge.reached_via': 'reached via',
      'edge.proves': 'proves',
      'edge.derived_from': 'derived from',
      'edge.merged_into': 'merged into',
      'edge.duplicate_of': 'duplicate of',
      'edge.applies_to': 'applies to',
      'edge.supervises': 'supervises',
      'edge.learned_from': 'learned from',
      'edge.distills': 'distills',
      'edge.reports_to': 'reports to',
      'edge.escalates_to': 'escalates to',
      'edge.unknown': 'related',
      'kind.target': 'Target',
      'kind.domain': 'Domain',
      'kind.wildcard_zone': 'Wildcard zone',
      'kind.host': 'Host',
      'kind.ip': 'IP',
      'kind.cidr': 'CIDR',
      'kind.segment': 'Segment',
      'kind.service': 'Service',
      'kind.webapp': 'Web app',
      'kind.tech': 'Technology',
      'kind.finding': 'Finding',
      'kind.credential': 'Credential',
      'kind.access': 'Access',
      'kind.pivot': 'Pivot',
      'kind.data': 'Data',
      'kind.evidence': 'Evidence',
      'kind.task': 'Task',
      'kind.chain_step': 'Chain step',
      'kind.loop': 'Autonomous loop',
      'kind.intent': 'Intent',
      'kind.supervision': 'Supervision',
      'kind.lesson': 'Lesson',
      'kind.self_team': 'Self-team',
      'kind.skill': 'Path skill',
      'kind.unknown': 'Unknown',
      'severity.critical': 'Critical',
      'severity.high': 'High',
      'severity.medium': 'Medium',
      'severity.low': 'Low',
      'severity.info': 'Info',
      'severity.unscored': 'Unscored',
      'severity.unknown': 'Unknown',
      'status.verified': 'Verified',
      'status.exploited': 'Exploited',
      'status.impacted': 'Impacted',
      'status.candidate': 'Candidate',
      'status.fixed': 'Fixed',
      'status.attempted': 'Attempted',
      'status.obtained': 'Obtained',
      'status.validated': 'Validated',
      'status.escalated': 'Escalated',
      'status.lost': 'Lost',
      'status.untested': 'Untested',
      'status.valid': 'Valid',
      'status.invalid': 'Invalid',
      'status.expired': 'Expired',
      'status.claimed': 'Claimed',
      'status.partial': 'Partial',
      'status.confirmed': 'Confirmed',
      'status.suspect': 'Suspect',
      'status.inconclusive': 'Inconclusive',
      'status.cleared': 'Cleared',
      'status.pending': 'Pending',
      'status.running': 'Running',
      'status.done': 'Done',
      'status.planned': 'Planned',
      'status.dispatched': 'Dispatched',
      'status.artifact_ready': 'Artifact ready',
      'status.completed': 'Completed',
      'status.failed': 'Failed',
      'status.merge_failed': 'Merge failed',
      'status.active': 'Active',
      'status.paused': 'Paused',
      'status.stopped': 'Stopped',
      'status.exhausted': 'Exhausted',
      'status.complete': 'Complete',
      'status.blocked': 'Blocked',
      'status.recorded': 'Recorded',
      'status.open': 'Open',
      'status.retired': 'Retired',
      'status.cancelled': 'Cancelled',
      'status.merged': 'Merged',
      'status.unknown': 'Unknown',
      'verification.refuted': 'Refuted',
      'verification.unverified': 'Unverified',
      'verification.corroborated': 'Corroborated',
      'verification.verified': 'Verified',
      'verification.passed': 'Verified',
      'verification.pending': 'In progress',
      'verification.failed': 'Failed',
      'risk.none': 'None',
      'risk.low': 'Low',
      'risk.medium': 'Medium',
      'risk.high': 'High',
      'tab.aria': 'Data tabs',
      'data.expand': 'Show data',
      'data.collapse': 'Hide data',
      'tab.assets': 'Assets',
      'tab.services': 'Services',
      'tab.targets': 'Targets',
      'tab.vulnerabilities': 'Vulnerabilities',
      'tab.findings': 'Findings',
      'tab.access': 'Access',
      'tab.data': 'Data',
      'tab.chains': 'Attack chains',
      'tab.wildcard': 'Wildcard',
      'tab.tasks': 'Tasks',
      'tab.team': 'Team',
      'tab.loop': 'Loop',
      'tab.settings': 'Settings',
      'table.empty': 'No {tab} data yet',
      'table.emptyHint': 'Import assets or record results through the agent and this table fills automatically.',
      'table.emptyVulnHint': 'No vulnerability has passed secondary verification and rating yet. Run atkbrain_selftteam action=verify first.',
      'table.searchEmpty': 'No records match the current search.',
      'table.sortHint': 'Click a header to sort',
      'table.rowSelect': 'Inspect {label}',
      'col.label': 'Label',
      'col.vulnType': 'Vulnerability type',
      'col.escalation': 'Harm escalation',
      'col.kind': 'Kind',
      'col.status': 'Status',
      'col.severity': 'Severity',
      'col.cvss': 'CVSS',
      'col.vulnerability': 'Vulnerability',
      'finding.verdictVulnerability': 'Vulnerability',
      'finding.verdictVerifiedVulnerability': 'Verified vulnerability',
      'finding.verdictPendingVulnerability': 'Awaiting secondary verification',
      'finding.verdictRefutedVulnerability': 'Secondary verification failed',
      'finding.verdictNotVulnerability': 'Security finding',
      'finding.verdictUnscored': 'Unscored',
      'col.confidence': 'Confidence',
      'col.verification': 'Verification',
      'col.degree': 'Links',
      'col.evidence': 'Evidence',
      'col.crown': 'Milestone',
      'col.wildcard': 'Wildcard',
      'col.port': 'Port',
      'col.protocol': 'Protocol',
      'col.banner': 'Banner',
      'col.title': 'Title',
      'col.url': 'URL',
      'col.username': 'Username',
      'col.privilege': 'Privilege',
      'col.validity': 'Validity',
      'col.dataClass': 'Data class',
      'col.count': 'Count',
      'col.chain': 'Chain',
      'col.stage': 'Stage',
      'col.ordinal': 'Ordinal',
      'col.actionType': 'Action',
      'col.priority': 'Priority',
      'col.risk': 'Risk',
      'col.why': 'Why',
      'col.zone': 'Zone',
      'col.cdn': 'CDN',
      'col.probes': 'Probes',
      'col.lastSeen': 'Last seen',
      'col.batchId': 'Batch ID',
      'col.assets': 'Assets',
      'col.agent': 'Agent',
      'col.mode': 'Mode',
      'col.artifact': 'Artifact',
      'col.mergedAt': 'Merged',
      'col.verdict': 'Verdict',
      'col.source': 'Source',
      'col.round': 'Round',
      'col.createdAt': 'Time',
      'col.expectedEvidence': 'Expected evidence',
      'col.lessonKey': 'Lesson key',
      'col.route': 'Route',
      'col.idea': 'Idea',
      'col.wins': 'Wins',
      'col.fails': 'Fails',
      'col.uses': 'Uses',
      'col.target': 'Target',
      'col.cost': 'Cost',
      'col.steps': 'Steps',
      'detail.title': 'Node details',
      'detail.close': 'Close details',
      'detail.empty': 'Select a node in the graph, or click a table row below.',
      'detail.kind': 'Kind',
      'detail.status': 'Status',
      'detail.confidence': 'Confidence',
      'detail.verification': 'Verification',
      'detail.evidence': 'Evidence',
      'detail.degree': 'Links',
      'detail.tags': 'Tags',
      'detail.attrs': 'Attributes',
      'detail.attrsEmpty': 'No displayable attributes',
      'detail.otherAttrs': 'Other attributes',
      'detail.edges': 'Adjacent edges',
      'detail.related': 'Connected to',
      'detail.edgesEmpty': 'No adjacent edges',
      'detail.copyId': 'Copy ID',
      'detail.copyJson': 'Copy JSON',
      'detail.copied': 'Copied to clipboard',
      'detail.copyFailed': 'Copy failed; select the text below manually',
      'detail.focus': 'Focus in graph',
      'detail.json': 'Node JSON',
      'detail.firstSeen': 'First seen',
      'detail.lastSeen': 'Last seen',
      'detail.out': 'out',
      'detail.in': 'in',
      'detail.hidden': 'This node is hidden by the current filters. Use "Focus in graph" to restore it.',
      'detail.findingOverview': 'Vulnerability overview',
      'detail.verifiedOverview': 'Security finding overview',
      'detail.detailSourceTeam': 'Technical detail written by the verification & rating team from evidence.',
      'detail.aiDetail': 'AI detail',
      'detail.aiDetailReady': 'AI detail ready',
      'detail.factHost': 'Target',
      'detail.accessStory': 'This is a foothold: which machine it landed on, and as whom.',
      'detail.pivotStory': 'This is the next machine in a lateral move. It is not fully controlled yet.',
      'detail.credentialStory': 'This is a credential. The account and a masked value are shown; the secret is not.',
      'detail.dataStory': 'This is data that was read.',
      'detail.hostStory': 'This is a host.',
      'detail.serviceStory': 'This is a service on an open port.',
      'detail.webappStory': 'This is a website.',
      'detail.genericStory': 'This is a node in the graph.',
      'detail.factPrivilege': 'Identity',
      'detail.factAccount': 'Account',
      'detail.factWhere': 'Where',
      'detail.factAmount': 'Amount',
      'detail.factAddress': 'Address',
      'detail.factParameter': 'Parameter',
      'detail.factCVSS': 'CVSS',
      'detail.factVerification': 'Verification',
      'detail.aiDetailPending': 'AI detail pending',
      'detail.aiDetailPendingShort': 'AI detail is not written yet; the verified evidence summary is shown below. Run atkbrain_selftteam action=detail findingId=<id> for the full Chinese detail.',
      'detail.escalation': 'Harm escalation',
      'detail.escalationProof': 'Escalation proof',
      'detail.originalRecord': 'Original technical record (English)',
      'detail.originalRecordHint': 'Verified original technical record; the Chinese AI rewrite is still pending.',
      'detail.originalDescription': 'Root cause',
      'detail.originalImpact': 'Impact',
      'detail.originalReproduction': 'Reproduction',
      'detail.detailSourcePending': 'This is a template summary, not AI-written detail; run atkbrain_selftteam action=detail findingId=<id> (or verify) to generate the full detail.',
      'detail.englishDetailNote': 'The original technical record is in English and was summarized in Chinese above; run action=detail or verify to have the AI team write the full Chinese detail.',
      'detail.findingOverviewPlain': 'Finding overview',
      'detail.vulnerabilityLabel': 'Vulnerability',
      'detail.verifiedFindingLabel': 'Security finding',
      'detail.findingLabel': 'Finding',
      'detail.findingImpact': 'Impact',
      'detail.findingRating': 'Red-team rating',
      'detail.findingRepro': 'Manual reproduction',
      'detail.request': 'Request',
      'detail.response': 'Response',
      'detail.requestMissing': 'No request packet recorded; add request/response to finding.attrs via atkbrain_record.',
      'detail.responseMissing': 'No response packet recorded.',
      'detail.secondaryVerified': 'Secondary verified',
      'detail.notSecondaryVerified': 'Not secondary verified',
      'detail.downloadMd': 'Download Markdown',
      'detail.proof': 'Proof',
      'detail.ratingRationale': 'Rating rationale',
      'detail.noDescription': 'No overview yet; add description/impact and request/response evidence.',
      'detail.remediation': 'Remediation',
      'detail.secondaryCheck': 'Secondary verification',
      'detail.evidenceFiles': 'Evidence files',
      'detail.noEvidence': 'No linked evidence file.',
      'detail.derivedExpiredDescription': 'The TLS certificate for {subject} expired at {when}; certificate validation fails.',
      'detail.derivedExpiredImpact': 'Expired certificates cause clients to reject the connection or train users to ignore warnings, increasing MITM risk and breaking certificate-validating services.',
      'detail.derivedExpiredRepro': 'atkbrain_probe action=tls target={host} port={port}\n# or\nopenssl s_client -connect {host}:{port} -servername {host}',
      'detail.derivedTlsRequest': 'TLS ClientHello\nSNI={host}',
      'detail.derivedTlsResponse': 'TLS ServerHello / Certificate\nsubject={subject}\nnotAfter={when}',
      'detail.derivedDescription': '{title}: {evidence}',
      'detail.derivedEvidenceDescription': '{title}: the response contains the corresponding exposure signal; the evidence artifact is linked below.',
      'detail.derivedXssDescription': 'On {subject}, the {parameter} parameter is written into the HTML response without encoding; the evidence payload breaks out of the original context and executes script.',
      'detail.derivedXssImpact': 'An attacker can make an authenticated user execute script in the site context, read page data or act as that user; actual impact depends on session and page privileges.',
      'detail.derivedSqliImpact': 'An attacker may read or modify database data; impact grows with the database account privileges.',
      'detail.derivedRceImpact': 'An attacker may execute commands on the target through this input; privileges depend on the service account and host restrictions.',
      'detail.derivedXssRepro': 'Send the {parameter} parameter with a unique marker twice, compare the reflected response, then confirm execution with a harmless svg/onload carrier.',
      'detail.remediationXss': 'Encode the {parameter} parameter for the output context (HTML/attribute/JavaScript), validate callback URLs with an allowlist, and add CSP as defence in depth.',
      'detail.derivedSqliDescription': 'On {subject}, user input reaches a SQL query and the evidence contains a reproducible database error or data difference.',
      'detail.remediationSqli': 'Use parameterized/prepared queries, never string concatenation, and normalize database error handling.',
      'detail.derivedRceDescription': 'On {subject}, the input path contains reproducible command-execution evidence with a unique marker in the response.',
      'detail.remediationRce': 'Remove shell invocation, use fixed argument lists and an allowlist, and restrict the service account.',
      'detail.derivedImpactInfo': 'This is an exposure/hardening signal without a verified direct compromise impact; evaluate it with other evidence.',
      'detail.derivedImpact': 'This finding may expand the attack surface; impact is bounded by verification and access/data evidence.',
      'detail.derivedRepro': 'Reproduce twice with atkbrain_probe or equivalent read-only requests and compare status, body and evidence hash; keep candidate until reproduced.',
      'detail.derivedRemediation': 'Fix the finding template, re-probe, and keep it candidate until verified; never present it as a confirmed vulnerability.',
      'detail.remediationExpired': 'Renew the certificate and enable expiry monitoring; confirm clients validate chain and validity.',
      'detail.remediationHeaders': 'Configure HSTS/CSP/X-Content-Type-Options and remove unnecessary version headers.',
      'detail.remediationRobots': 'Audit paths exposed in robots.txt and remove sensitive paths or require authentication.',
      'detail.remediationAdmin': 'Restrict admin entry points by source and authentication, enable MFA/rate limits, and avoid anonymous admin exposure.',
      'detail.remediationGeneric': 'Fix the finding template and re-verify; keep candidate until verified.',
      'detail.noRequestButEvidence': 'No raw request packet was recorded; the linked evidence file contains the actual observation.',
      'detail.secondaryEvidence': 'Verification evidence: {path}',
      'detail.cvss': 'CVSS',
      'detail.cvssVerdict': 'CVSS verdict',
      'detail.unscoredVerdict': 'Unscored: no CVSS v3.1 Base score, so severity is not established yet.',
      'detail.vulnerabilityUnscoredVerdict': 'Vulnerability: not scored yet; the verification/rating team must supply CVSS v3.1 Base metrics.',
      'detail.refutedVulnerabilityVerdict': 'Secondary verification failed: this finding is not included in the vulnerability tab.',
      'detail.nonVulnerabilityCvss': 'Security finding: CVSS {score} ({severity}); this is an exposure/hardening item, not a demonstrated exploitable vulnerability.',
      'detail.vulnerabilityCvss': 'Vulnerability: CVSS {score} ({severity}); confirmed by vulnerability class.',
      'detail.cvssVerdict': 'CVSS verdict',
      'detail.unscoredVerdict': 'Unscored: no CVSS v3.1 Base score, so severity is not established yet.',
      'detail.vulnerabilityUnscoredVerdict': 'Vulnerability: not scored yet; the verification/rating team must supply CVSS v3.1 Base metrics.',
      'detail.refutedVulnerabilityVerdict': 'Secondary verification failed: this finding is not included in the vulnerability tab.',
      'detail.nonVulnerabilityCvss': 'Security finding: CVSS {score} ({severity}); this is an exposure/hardening item, not a demonstrated exploitable vulnerability.',
      'detail.vulnerabilityCvss': 'Vulnerability: CVSS {score} ({severity}); confirmed by vulnerability class.',
      'detail.cvssScore': 'CVSS {score} ({severity})',
      'detail.ratingCritical': 'Critical: execution, admin privilege or bulk-data impact is evidenced.',
      'detail.ratingHigh': 'High: direct-impact finding without proven execution or bulk impact.',
      'detail.ratingMedium': 'Medium: moderate impact, evaluate with verification evidence.',
      'detail.ratingLow': 'Low: limited impact.',
      'detail.ratingInfo': 'Info: exposure or informational signal only.',
      'detail.secondaryVerifiedGeneric': 'Independent verification passed: the evidence artifact is reproducible and no contradiction was found.',
      'detail.secondaryRefutedGeneric': 'Independent verification failed: the evidence is insufficient or could not be reproduced.',
      'detail.secondaryInconclusiveGeneric': 'Independent verification is inconclusive: the available evidence is insufficient.',
      'detail.categoryTls': 'TLS certificate',
      'detail.categoryHeaders': 'Security headers',
      'detail.categoryDisclosure': 'Technology disclosure',
      'detail.categoryRobots': 'robots.txt',
      'detail.categoryFingerprint': 'Technology fingerprint',
      'detail.categoryExposure': 'Exposure',
      'detail.categoryGeneric': 'Security configuration',
      'detail.evidencePackets': 'Evidence & packets',
      'detail.rawAttrs': 'Raw attributes',
      'detail.edgeEvidence': 'evidence {count}',
      'chain.explicit': 'Explicit attack chains',
      'chain.crown': 'Milestone paths',
      'chain.toRce': 'Path to code execution',
      'chain.empty': 'No path to code execution yet',
      'chain.chainId': 'Chain {id}',
      'chain.noSteps': 'No steps',
      'notice.hiddenWildcard': 'Hid {count} wildcard-suspect hosts; toggle them on in the toolbar.',
      'team.title': 'Team batches',
      'team.statusFilter': 'Status',
      'team.statusAll': 'All statuses',
      'team.summary': 'Showing {shown}/{total} batches',
      'team.empty': 'No team batches yet',
      'team.emptyHint': 'Ask the Lead to run atkbrain_team action=plan to create batches, then action=dispatch to fan them out to subagents.',
      'team.emptyFiltered': 'No team batches match the current filter',
      'team.artifactReady': 'Artifact ready',
      'team.artifactPending': 'Artifact pending',
      'verdict.hold': 'Hold',
      'verdict.pivot': 'Pivot',
      'verdict.verify': 'Verify',
      'verdict.escalate': 'Escalate',
      'verdict.stop': 'Stop',
      'verdict.verified': 'Verified',
      'verdict.refuted': 'Refuted',
      'verdict.inconclusive': 'Inconclusive',
      'verdict.unknown': 'Unknown',
      'supervision.round_plan': 'Round plan',
      'supervision.verification': 'Verification',
      'supervision.unknown': 'Unknown type',
      'source.deterministic': 'Deterministic',
      'source.model': 'Model',
      'source.subagent': 'Subagent',
      'source.unknown': 'Unknown source',
      'activation.armed': 'Armed',
      'activation.disarmed': 'Disarmed',
      'loop.title': 'Autonomous loop',
      'loop.state': 'Loop state',
      'loop.phase': 'Phase',
      'loop.round': 'Round',
      'loop.objective': 'Objective',
      'loop.objectiveType': 'Objective type',
      'loop.goalPhase': 'Goal phase',
      'loop.activation': 'Activation',
      'loop.ring': 'Ring',
      'loop.ringValue': 'Ring / allowed ring',
      'loop.noProgress': 'No-progress rounds',
      'loop.emptyRounds': 'Empty rounds',
      'loop.maxActions': 'Max actions per round',
      'loop.stopReason': 'Stop reason',
      'loop.autoContinue': 'Auto-continue',
      'loop.startedAt': 'Started',
      'loop.lastStepAt': 'Last step',
      'loop.appliedLessons': 'Applied lessons',
      'loop.disarmedWarn': 'The loop goal is disarmed, so automatic continuation will not run; the Lead must resume the goal.',
      'loop.supervision': 'Supervision',
      'loop.latestSupervision': 'Latest supervision',
      'loop.verdict': 'Verdict',
      'loop.secondaryVerdict': 'Secondary verdict',
      'loop.source': 'Source',
      'loop.confidence': 'Confidence',
      'loop.diagnosis': 'Diagnosis',
      'loop.nextPlan': 'Next plan',
      'loop.mustIntents': 'Must intents',
      'loop.preferTactics': 'Preferred tactics',
      'loop.banRepeats': 'Banned repeats',
      'loop.stopRecommended': 'Stop recommended',
      'loop.supervisionHistory': 'Supervision history',
      'loop.supervisionEmpty': 'No supervision yet; run atkbrain_supervise action=review to produce a round plan.',
      'loop.intents': 'Intents',
      'loop.emptyIntents': 'No intents yet; run atkbrain_loop action=start to plan the next round.',
      'loop.lessons': 'Evolved lessons',
      'loop.emptyLessons': 'No lessons yet; loop reviews record lessons automatically.',
      'loop.empty': 'The autonomous loop has not started',
      'loop.emptyHint': 'Ask the Lead to run atkbrain_loop action=start to start the loop, then atkbrain_supervise action=review to produce a supervision plan.',
      'settings.title': 'Settings',
      'settings.hint': 'Configure the egress proxy and FOFA / Hunter / 360 Quake.',
      'settings.refresh': 'Refresh',
      'settings.checkAll': 'Run full check',
      'settings.checking': 'Checking…',
      'settings.normal': 'Normal',
      'settings.abnormal': 'Abnormal',
      'settings.resources': 'Resource health',
      'settings.skills': 'Skills',
      'settings.tools': 'Pentest tools',
      'settings.dicts': 'Dictionaries',
      'settings.expected': 'expected {count}',
      'settings.actual': 'actual {count}',
      'settings.missing': 'missing {count}',
      'settings.usable': '{count} usable',
      'settings.present': '{count} files present',
      'settings.configured': 'Configured',
      'settings.notConfigured': 'Not configured',
      'settings.proxy': 'Egress proxy',
      'settings.proxyHint': 'Global HTTP(S) proxy; loopback stays direct.',
      'settings.proxyUrl': 'Proxy URL',
      'settings.proxyMode': 'Mode',
      'settings.proxyNoProxy': 'NO_PROXY',
      'settings.saveProxy': 'Save & enable',
      'settings.disableProxy': 'Disable proxy',
      'settings.testProxy': 'Test egress',
      'settings.proxySaved': 'Proxy settings saved',
      'settings.survey': 'Survey providers',
      'settings.surveyHint': 'Keys are stored only in the local 0600 settings file; the page shows a mask.',
      'settings.fofa': 'FOFA',
      'settings.hunter': 'Hunter (Qianxin)',
      'settings.quake': '360 Quake',
      'settings.enabled': 'Enabled',
      'settings.baseUrl': 'API base URL',
      'settings.email': 'Email (FOFA optional)',
      'settings.apiKey': 'API key',
      'settings.keyEnv': 'Env var name',
      'settings.keyConfigured': 'Configured {mask}',
      'settings.save': 'Save',
      'settings.testKey': 'Test key',
      'settings.testing': 'Testing…',
      'settings.requiredKey': 'Enter an API key first',
      'settings.saved': 'Saved',
      'settings.failed': 'Failed',
      'settings.clearKey': 'Clear key',
      'loop.coverage': 'Coverage board',
      'loop.coverageHint': 'Interface x nine bug classes. Open cells drive the next hunt and stay off the graph canvas.',
      'loop.coverageTotals': '{cells} cells · {seen} seen · {open} open',
      'loop.coverageDuties': 'Vulnerability discovery duties',
      'loop.dutyName.xss': 'cov-xss',
      'loop.duty.xss': 'Cross-site scripting. See whether input lands in body, attribute, event, or script, then close that context. Name every parameter already stored for this path. A page shared with another interface still counts. A note that says the input already landed cannot refute the cell. JSON reflection does not close this cell.',
      'loop.dutyName.sqli': 'cov-sqli',
      'loop.duty.sqli': 'SQL injection. Run one quote differential for each new string parameter.',
      'loop.dutyName.cmd': 'cov-cmd',
      'loop.duty.cmd': 'Command execution. Run one command-metacharacter differential for each new string parameter.',
      'loop.dutyName.code': 'cov-code',
      'loop.duty.code': 'Code execution. Run one template or expression check for each new string parameter, including deserialization.',
      'loop.dutyName.file': 'cov-file',
      'loop.duty.file': 'File read. Path, filename, template, image, export, and include each need a path differential. The absence of an upload does not close this cell. A redirect or signed object URL is an observation, not a refutation.',
      'loop.dutyName.authz': 'cov-authz',
      'loop.duty.authz': 'Authorization. Request once with no session, then once with a different object id. Method dispatch on the same path is not closed by calling the read public.',
      'loop.dutyName.logic': 'cov-logic',
      'loop.duty.logic': 'Business logic. Check quantity, status, step, and price. An authentication path stays open until the note says whether repeated failures are limited. A note that says there is no rate limit or no lockout cannot refute the cell.',
      'loop.dutyName.leak': 'cov-leak',
      'loop.duty.leak': 'Information disclosure. Check swagger, .git, config, and errors that include a stack. A note that already shows a stack, exception page, or version cannot refute the cell.',
      'loop.dutyName.nday': 'cov-nday',
      'loop.duty.nday': 'Known vulnerabilities. Confirm the product or version first, then check public issues. Stop when no version is known.',
      'loop.hypotheses': 'Hypotheses',
      'loop.hypothesisHint': 'A persistent hypothesis needs two channels or evidence; a refutation must name the target and observation.',
      'loop.hypothesisEmpty': 'No persistent hypothesis yet.',
      'loop.hypothesisTotals': '{total} total · {open} open · {verified} verified',
      'teamRoster.title': 'Five agent teams',
      'teamRoster.empty': 'Setting the authorized scope auto-starts: supervisor, executor (Lead), secondary verification, harm escalation and report-writing.',
      'teamRoster.reportModes': 'Project report + finding report',
      'teamRoster.pending': 'Pending',
      'loop.selfTeam': 'Five agent teams',
      'loop.selfTeamHint': 'Supervisor, executor (Lead), secondary verification, harm escalation and report-writing; harm escalation records a higher result as a new finding.',
      'loop.supervisionTeam': 'Supervisor',
      'loop.evolutionTeam': 'Self-evolution',
      'loop.leadTeam': 'Executor (Lead)',
      'loop.evolutionTeam': 'Evolution team',
      'loop.verificationTeam': 'Secondary verification',
      'loop.escalationTeam': 'Harm escalation',
      'loop.reportTeam': 'Report-writing',
      'loop.lastVerifyAt': 'Last verify',
      'loop.lastReportAt': 'Last report',
      'loop.reportPath': 'Report file',
      'loop.findingReportPath': 'Finding report',
      'loop.teamResponsibility': 'Responsibility',
      'loop.briefPath': 'Brief file',
      'loop.reportTheme': 'Report theme',
      'loop.verifiedCount': 'Verified',
      'loop.ratedCount': 'Rated',
      'loop.selfTeamEmpty': 'The five teams are not recorded yet; setting scope auto-starts them, or run atkbrain_selftteam action=start.',
      'loop.selfBriefEmpty': 'No supervisor brief yet; run atkbrain_selftteam action=brief.',
      'loop.handoff': 'Supervisor → Executor',
      'loop.handoffDelivered': 'Brief delivered to executor',
      'loop.handoffStale': 'Brief is stale',
      'loop.handoffMissing': 'No executor handoff',
      'loop.handoffLegacy': 'Legacy brief (handoff not recorded)',
      'loop.gained': 'Gained',
      'loop.missed': 'Missing',
      'loop.advice': 'Advice',
      'loop.antiDeadlock': 'Anti-deadlock',
      'loop.recommendedNext': 'Next',
      'loop.deadlockRisk': 'Deadlock risk',
      'loop.skillLibrary': 'Path skill library',
      'loop.skillEmpty': 'No reusable path skill.',
      'loop.skillCount': 'Skills {count}',
      'loop.skillCountLabel': 'Skill count',
      'loop.members': 'Members',
      'loop.lastBriefAt': 'Last brief',
      'loop.lastDistillAt': 'Last distill',
      'col.skillName': 'Skill',
      'col.skillRoute': 'Route',
      'col.skillPath': 'SKILL.md',
      'bool.true': 'yes',
      'bool.false': 'no',
    };

    // ---------------------------------------------------------------------
    // Defensive value helpers
    // ---------------------------------------------------------------------

    function isPlainObject(value) {
      return value !== null && typeof value === 'object' && !Array.isArray(value);
    }

    function asArray(value) {
      return Array.isArray(value) ? value : [];
    }

    function asObject(value) {
      return isPlainObject(value) ? value : {};
    }

    function asString(value, fallback) {
      return typeof value === 'string' && value.length > 0 ? value : (fallback === undefined ? '' : fallback);
    }

    function asNumber(value, fallback) {
      const parsed = typeof value === 'number' ? value : Number(value);
      return Number.isFinite(parsed) ? parsed : fallback;
    }

    function asCount(value) {
      const parsed = asNumber(value, 0);
      return parsed > 0 ? Math.floor(parsed) : 0;
    }

    function clamp(value, min, max) {
      if (value < min) return min;
      if (value > max) return max;
      return value;
    }

    function clamp01(value) {
      return clamp(asNumber(value, 0), 0, 1);
    }

    function percent(value) {
      return `${Math.round(clamp01(value) * 100)}%`;
    }

    function truncateText(text, max) {
      const source = String(text);
      if (source.length <= max) return source;
      return `${source.slice(0, Math.max(1, max - 1))}…`;
    }

    /** Truncate SVG labels by approximate display width (CJK counts double). */
    function truncateByWidth(text, maxUnits) {
      const source = String(text);
      let units = 0;
      let out = '';
      for (const char of source) {
        const wide = /[\u1100-\u11ff\u2e80-\u9fff\uac00-\ud7af\uf900-\ufaff\uff00-\uffef]/u.test(char);
        const width = wide ? 2 : 1;
        if (units + width > maxUnits) return `${out}…`;
        out += char;
        units += width;
      }
      return out;
    }

    function formatTime(value) {
      if (typeof value !== 'string' || value.length === 0) return '—';
      return value.length > 19 ? value.slice(0, 19).replace('T', ' ') : value;
    }

    function jsonReplacer() {
      const seen = new WeakSet();
      return function replacer(key, value) {
        if (typeof value === 'string' && value.length > 600) return `${value.slice(0, 600)}…`;
        if (Array.isArray(value)) {
          if (value.length > 60) return value.slice(0, 60).concat(['…']);
          return value;
        }
        if (value !== null && typeof value === 'object') {
          if (seen.has(value)) return '[circular]';
          seen.add(value);
        }
        return value;
      };
    }

    function safeJson(value) {
      try {
        return JSON.stringify(value, jsonReplacer(), 2);
      } catch (error) {
        return String(value);
      }
    }

    function compactJson(value) {
      try {
        const text = JSON.stringify(value, jsonReplacer());
        return text === undefined ? '' : text;
      } catch (error) {
        return '';
      }
    }

    /** Human-readable one-line rendering of an attribute value. */
    function valueText(value) {
      if (value === null || value === undefined) return '—';
      if (typeof value === 'string') return truncateText(value, 220);
      if (typeof value === 'number' || typeof value === 'boolean') return String(value);
      if (Array.isArray(value)) {
        const parts = value.slice(0, 8).map((item) => (isPlainObject(item) || Array.isArray(item) ? truncateText(compactJson(item), 80) : String(item)));
        if (value.length > 8) parts.push(`…+${value.length - 8}`);
        return parts.length === 0 ? '[]' : parts.join(', ');
      }
      return truncateText(compactJson(value), 240);
    }

    /** Translate a vocabulary word, falling back to the raw wire value. */
    function localized(t, group, value) {
      const raw = value === undefined || value === null || value === '' ? 'unknown' : String(value);
      const key = `${group}.${raw}`;
      const translated = typeof t === 'function' ? t(key) : key;
      return typeof translated === 'string' && translated !== key ? translated : raw;
    }

    // ---------------------------------------------------------------------
    // Wire-view normalization (every field optional, every array bounded)
    // ---------------------------------------------------------------------

    function unwrapGraph(rawValue) {
      if (!isPlainObject(rawValue)) return null;
      if (Array.isArray(rawValue.nodes) || rawValue.schema !== undefined || isPlainObject(rawValue.counts)) return rawValue;
      const inner = rawValue.value;
      if (isPlainObject(inner) && (Array.isArray(inner.nodes) || inner.schema !== undefined)) return inner;
      return rawValue;
    }

    const CROWN_PRIVILEGES = new Set(['admin', 'root', 'domain_admin', 'cloud_admin', 'db_admin', 'administrator']);

    const KIND_IMPORTANCE = {
      access: 420,
      data: 400,
      credential: 330,
      pivot: 300,
      finding: 250,
      wildcard_zone: 240,
      host: 200,
      webapp: 150,
      service: 140,
      evidence: 120,
      tech: 90,
      ip: 80,
      domain: 70,
      cidr: 60,
      segment: 50,
      task: 40,
      chain_step: 30,
      loop: 520,
      intent: 280,
      supervision: 300,
      lesson: 260,
      unknown: 0,
    };

    function severityOfNode(rawKind, attrs) {
      if (rawKind !== 'finding') return null;
      const raw = String(attrs.severity === undefined ? 'info' : attrs.severity).toLowerCase();
      return SEVERITY_LIST.indexOf(raw) >= 0 ? raw : 'info';
    }

    function buildNodeSearch(id, kind, key, label, status, verification, tags, attrs) {
      const parts = [id, kind, key, label, status, verification];
      for (const tag of tags) parts.push(tag);
      let seen = 0;
      for (const attrKey of Object.keys(attrs)) {
        if (seen >= 50) break;
        seen += 1;
        const value = attrs[attrKey];
        if (typeof value === 'string') {
          parts.push(value);
        } else if (typeof value === 'number' || typeof value === 'boolean') {
          parts.push(String(value));
        } else if (Array.isArray(value)) {
          for (const item of value.slice(0, 6)) {
            if (typeof item === 'string' || typeof item === 'number') parts.push(String(item));
          }
        }
      }
      return truncateText(parts.join(' ').toLowerCase(), 2400);
    }

    // Chinese display titles for known finding templates. This also localizes
    // nodes recorded before the Host-side templates were translated.
    const FINDING_TITLE_ZH = {
      'cors-wildcard': '宽松 CORS 策略',
      'missing-security-headers': '缺少安全响应头',
      'server-version-disclosure': '服务器版本泄露',
      'technology-disclosure': 'X-Powered-By 技术泄露',
      'technology-fingerprint': '技术栈指纹',
      'directory-listing': '目录列表启用',
      'exposed-git-repository': 'Git 仓库元数据暴露',
      'exposed-git-config': 'Git 配置暴露',
      'exposed-env-file': '环境变量文件暴露',
      'exposed-svn-metadata': 'SVN 元数据暴露',
      'exposed-ds-store': 'macOS .DS_Store 文件暴露',
      'apache-server-status': 'Apache server-status 暴露',
      'apache-server-info': 'Apache server-info 暴露',
      'actuator-root-exposed': 'Spring Actuator 根端点暴露',
      'actuator-env-exposed': 'Spring Actuator /env 暴露',
      'actuator-health-public': 'Actuator 健康端点公开',
      'actuator-heapdump-exposed': 'Spring Actuator heapdump 可下载',
      'api-docs-exposed': 'API 文档暴露',
      'graphql-endpoint-exposed': 'GraphQL 端点可访问',
      'admin-interface-reachable': '管理界面可访问',
      'admin-interface-protected': '管理界面要求认证',
      'tomcat-manager-exposed': 'Tomcat Manager 可访问',
      'tomcat-manager-protected': 'Tomcat Manager 要求认证',
      'admin-console-exposed': '应用服务器控制台暴露',
      'jenkins-exposed': 'Jenkins 可访问',
      'phpinfo-exposed': 'phpinfo() 信息暴露',
      'phpmyadmin-exposed': 'phpMyAdmin 可访问',
      'wordpress-admin-exposed': 'WordPress 管理页可访问',
      'robots-sensitive-paths': 'robots.txt 暴露敏感路径',
      'sitemap-exposed': 'Sitemap 暴露',
      'permissive-crossdomain-policy': '宽松的 crossdomain.xml',
      'metrics-exposed': 'Metrics 指标端点暴露',
      'health-endpoint-public': '健康检查端点公开',
      'debug-endpoint-exposed': '调试/追踪端点暴露',
      'heapdump-exposed': 'JVM heap dump 可下载',
      'jolokia-exposed': 'Jolokia JMX 端点暴露',
      'h2-console-exposed': 'H2 数据库控制台可访问',
      'druid-console-exposed': 'Druid 控制台可访问',
      'nacos-console-exposed': 'Nacos 控制台可访问',
      'eureka-exposed': 'Eureka 注册中心端点暴露',
      'solr-admin-exposed': 'Solr 管理界面可访问',
      'kibana-exposed': 'Kibana 可访问',
      'backup-archive-exposed': '备份压缩包可下载',
      'backup-config-exposed': '源码/配置备份暴露',
      'webinf-exposed': 'WEB-INF/web.xml 暴露',
      'security-txt-present': 'security.txt 已发布',
      'sensitive-path-protected': '敏感路径要求认证',
      'self-signed-certificate': '自签名 TLS 证书',
      'expired-certificate': 'TLS 证书已过期',
      'certificate-expiring-soon': 'TLS 证书即将过期',
      'weak-tls-version': '弱 TLS 协议',
      'weak-tls-cipher': '弱 TLS 加密套件',
      'expired-tls-certificate': 'TLS 证书已过期',
      'self-signed-tls-certificate': '自签名 TLS 证书',
      'weak-tls-protocol': '弱 TLS 协议',
      'sandbox-boundary-divergence': '沙箱边界与 Host 网络能力差异',
      'manual-finding': '漏洞危害提升成功',
      'manual': '漏洞危害提升成功',
    };
    const FINDING_DETAIL_ZH = {
      'expired-certificate': {
        impact: '证书过期会导致客户端拒绝连接或诱导用户忽略证书警告，增加中间人风险；依赖证书校验的服务可用性也会受影响。',
        remediation: '续期证书并启用到期监控；确认客户端校验证书链和有效期。',
      },
      'expired-tls-certificate': {
        impact: '证书过期会导致客户端拒绝连接或诱导用户忽略证书警告，增加中间人风险；依赖证书校验的服务可用性也会受影响。',
        remediation: '续期证书并启用到期监控；确认客户端校验证书链和有效期。',
      },
      'missing-security-headers': {
        impact: '缺少安全响应头会降低浏览器对点击劫持、内容嗅探、XSS 和降级攻击的防护能力。',
        remediation: '配置 HSTS、CSP、X-Content-Type-Options、X-Frame-Options 等安全响应头。',
      },
      'technology-disclosure': {
        impact: '泄露的技术栈和版本信息可帮助攻击者匹配已知漏洞，降低攻击成本。',
        remediation: '移除 X-Powered-By、Server 版本等非必要指纹响应头。',
      },
      'server-version-disclosure': {
        impact: '服务器版本泄露可帮助攻击者匹配已知漏洞。',
        remediation: '隐藏生产环境的服务器版本横幅。',
      },
      'robots-sensitive-paths': {
        impact: 'robots.txt 暴露的路径可能指向后台、备份或内部资源。',
        remediation: '审计 robots.txt，移除敏感路径，并用认证或网络 ACL 保护这些资源。',
      },
      'technology-fingerprint': {
        impact: '技术指纹本身不构成入侵，但会缩小攻击者的漏洞匹配范围。',
        remediation: '保持组件版本受支持并已打补丁；不要依赖隐藏版本来防护。',
      },
      'wordpress-admin-exposed': {
        impact: '公开可访问的管理入口会扩大暴力破解和凭证攻击面。',
        remediation: '限制管理入口来源，启用 MFA 和登录速率限制。',
      },
    };
    function translateEnglishFindingTitle(raw) {
      const text = String(raw ?? '').trim();
      if (text.length === 0) return null;
      if (/[\u3400-\u9fff]/u.test(text)) return text;
      const lower = text.toLowerCase();
      const patterns = [
        [/^struts2\s+2\.3\.x identified/i, '识别到 Struts2 2.3.x（可能存在 S2-045/CVE-2017-5638 OGNL 远程代码执行）'],
        [/^struts2 dynamic method invocation enabled.*$/i, 'Struts2 动态方法调用已启用（可能允许调用任意方法）'],
        [/^internal dependency and code-path disclosure via uncaught exception/i, '未捕获异常导致内部依赖与代码路径泄露'],
        [/^internet-exposed tomcat manager\/host-manager on (.+)/i, 'Tomcat Manager/Host-Manager 暴露在互联网（$1）'],
        [/^outdated apache tomcat (.+) with known cves/i, 'Apache Tomcat $1 版本过旧，存在已知 CVE'],
        [/^reflected xss in (.+)/i, '反射型 XSS（$1）'],
        [/^reflected xss via (.+)/i, '反射型 XSS（$1）'],
        [/^stack trace and postgresql schema disclosure via (.+)/i, '堆栈跟踪与 PostgreSQL 结构泄露（$1）'],
        [/^stack trace disclosure via (.+)/i, '堆栈跟踪泄露（$1）'],
        [/^outdated apache tomcat (.+)/i, 'Apache Tomcat $1 版本过旧'],
        [/^permissive crossdomain\.xml(?: \(domain=\*\) on (.+))?$/i, '宽松 crossdomain.xml（允许所有来源）'],
        [/^tomcat manager requires authentication$/i, 'Tomcat Manager 要求认证'],
        [/^server version disclosed$/i, '服务器版本泄露'],
        [/^self-signed tls certificate$/i, '自签名 TLS 证书'],
        [/^expired tls certificate$/i, 'TLS 证书已过期'],
        [/^tomcat sample applications.*$/i, 'Tomcat 示例应用与 snoop Servlet 暴露'],
        [/^missing security headers and tomcat version disclosure$/i, '缺少安全响应头并泄露 Tomcat 版本'],
        [/^outdated apache tomcat (.+) \(.+\)$/i, 'Apache Tomcat $1 版本过旧（存在已知 CVE）'],
        [/^reflected xss[ —-]+(.+)$/i, '反射型 XSS（$1）'],
        [/^internet-exposed apache tomcat manager.*$/i, 'Tomcat Manager 暴露在互联网'],
        [/^security headers absent.*$/i, '缺少安全响应头'],
        [/^crossdomain\.xml permits all origins$/i, 'crossdomain.xml 允许所有来源'],
        [/^session cookie missing secure and samesite attributes$/i, '会话 Cookie 缺少 Secure 和 SameSite 属性'],
        [/^struts2 dmi.*$/i, 'Struts2 DMI（!method）已启用'],
        [/^unauthenticated stack trace, internal schema and tomcat version disclosure.*$/i, '未认证堆栈跟踪、内部结构与 Tomcat 版本泄露'],
        [/^stack traces leak internal class paths.*$/i, '堆栈跟踪泄露内部类路径与数据库结构'],
        [/^b\.(.+?) https service dead.*$/i, 'HTTPS 服务不可用（$1）'],
        [/^tomcat manager requires authentication$/i, 'Tomcat Manager 要求认证'],
        [/^tomcat manager\/host-manager on (.+)/i, 'Tomcat Manager/Host-Manager 暴露（$1）'],
      ];
      for (const [pattern, replacement] of patterns) {
        if (pattern.test(text)) return text.replace(pattern, replacement);
      }
      if (/^potential (.*)/iu.test(text)) return `潜在${text.replace(/^potential\s+/iu, '')}`;
      if (/^cve-\d{4}-\d+/iu.test(text)) return `CVE 漏洞：${text}`;
      return null;
    }

    const FAMILY_TITLE_ZH = {
      'reflected-xss': '反射型 XSS',
      'xss-reflected': '反射型 XSS',
      'stored-xss': '存储型 XSS',
      'xss-stored': '存储型 XSS',
      xss: 'XSS',
      sqli: 'SQL 注入',
      'sql-injection': 'SQL 注入',
      rce: '远程代码执行',
      'command-injection': '命令执行',
      cmd: '命令执行',
      ssti: '模板注入',
      xxe: 'XXE',
      ssrf: 'SSRF',
      lfi: '文件包含',
      'path-traversal': '路径穿越',
      idor: '越权',
      csrf: 'CSRF',
    };

    /** A ledger key is not a title. Name the bug class, and the interface when the key has one. */
    function titleFromLedgerKey(text) {
      const parts = String(text ?? '').split('/').map((part) => part.trim()).filter((part) => part.length > 0);
      if (parts.length < 2) return null;
      const family = FAMILY_TITLE_ZH[parts[parts.length - 1].toLowerCase()];
      if (family === undefined) return null;
      const interfacePart = parts.slice(0, -1).reverse().find((part) => /\.(?:action|jsp|php|do|aspx|asp|html|xml|json|cgi)$/iu.test(part));
      return interfacePart === undefined ? family : `${family}（/${interfacePart.replace(/^\/+/u, '')}）`;
    }

    function findingTitleZh(template, fallback) {
      const key = String(template ?? '').toLowerCase();
      const raw = String(fallback ?? '').trim();
      let candidate = raw;
      if (FINDING_TITLE_ZH[key] !== undefined && (raw.length === 0 || raw === '手工记录漏洞' || /^manual(?:-finding)?$/iu.test(raw) || !/[\u3400-\u9fff]/u.test(raw))) candidate = FINDING_TITLE_ZH[key];
      else if (key.startsWith('exposed-service-')) candidate = `暴露的高危服务（${key.slice('exposed-service-'.length)}）`;
      else {
        const translated = translateEnglishFindingTitle(raw);
        if (translated !== null) candidate = translated;
        else {
          const fromKey = titleFromLedgerKey(raw);
          if (fromKey !== null) candidate = fromKey;
        }
      }
      if (/^finding_[0-9a-f]{8,}$/iu.test(candidate)) return '未命名发现';
      return polishFindingTitle(template, candidate.length > 0 ? candidate : raw);
    }

    const VULNERABILITY_CLASS_RE = /xss|cross[- ]site\s*scripting|sqli|sql\s*injection|sql\s*注入|注入|rce|remote\s*code|command\s*injection|命令执行|代码执行|code\s*execution|deseriali[sz]ation|反序列化|xxe|ssti|template\s*injection|模板注入|path\s*traversal|directory\s*traversal|lfi|rfi|file\s*inclusion|文件包含|file\s*read|任意文件读取|ssrf|server[- ]side\s*request|csrf|cross[- ]site\s*request\s*forgery|open[-\s]*redirect|url[-\s]*redirect|auth(?:entication|orization)?\s*bypass|认证绕过|权限绕过|idor|越权|privilege\s*escalation|提权|cve-\d{4}-\d+|密码重置|race\s*condition|逻辑漏洞/iu;
    const EXPOSURE_CLASS_RE = /missing\s*(?:security\s*)?header|security\s*header|header\s*缺失|technology\s*disclosure|version\s*disclosure|server\s*version|指纹|robots\.txt|directory\s*listing|目录遍历|directory\s*index|admin.*exposed|manager.*exposed|examples|docs|snoop|certificate|证书|tls|self[- ]signed|weak\s*cipher|弱加密|信息泄露|stack\s*trace|exception|错误堆栈|公开.*管理|exposed.*admin/iu;
    const HARDENING_RE = /missing\s*(?:security\s*)?header|security[- ]headers?|header\s*缺失|缺少安全响应头|安全响应头|certificate|证书|robots\.txt|technology\s*disclosure|version\s*disclosure|server\s*version|技术栈指纹|指纹|fingerprint|directory\s*listing|目录列表|crossdomain|allow-access-from|permissive-crossdomain/iu;
    const FAMILY_RULES = [
      ['xss-stored', /(?<!非)(?<!不是)(?<!并非)(?<!not\s)(?<!non[- ]?)(?:stored\s*xss|persistent\s*xss|存储型|存储式)/iu],
      ['xss-reflected', /xss|cross[- ]site\s*scripting|跨站脚本|反射型|反射式/iu],
      ['sqli', /sqli|sql\s*injection|sql\s*注入/iu],
      ['cmd', /command\s*injection|命令执行|os\s*command/iu],
      ['code', /远程代码|代码执行|remote\s*code|rce|模板注入|ssti|deseriali/iu],
      ['file', /path\s*traversal|directory\s*traversal|文件包含|任意文件|file\s*read|lfi|rfi/iu],
      ['authz', /idor|越权|权限绕过|认证绕过|authorization|authz/iu],
      ['logic', /逻辑漏洞|race\s*condition|业务逻辑/iu],
      ['leak', /信息泄露|stack\s*trace|错误堆栈|报错/iu],
      ['nday', /cve-\d{4}-\d+|nday|已知漏洞/iu],
    ];
    const METRIC_ZH = {
      AV: { N: '攻击向量是网络（AV:N），不需要本地访问', A: '攻击向量是相邻网络（AV:A）', L: '攻击向量是本地（AV:L）', P: '攻击向量是物理接触（AV:P）' },
      AC: { L: '攻击复杂度低（AC:L）', H: '攻击复杂度高（AC:H）' },
      PR: { N: '不需要账号权限（PR:N）', L: '需要低权限（PR:L）', H: '需要高权限（PR:H）' },
      UI: { N: '不需要受害者配合（UI:N）', R: '需要受害者进行一次操作（UI:R）' },
      S: { U: '影响停在当前组件（S:U）', C: '影响超出当前组件（S:C）' },
      C: { H: '机密性影响高（C:H）', L: '机密性影响低（C:L）', N: '不影响机密性（C:N）' },
      I: { H: '完整性影响高（I:H）', L: '完整性影响低（I:L）', N: '不影响完整性（I:N）' },
      A: { H: '可用性影响高（A:H）', L: '可用性影响低（A:L）', N: '不影响可用性（A:N）' },
    };

    function findingClassText(attrs) {
      return `${attrs?.template ?? ''} ${attrs?.category ?? ''} ${attrs?.title ?? ''} ${attrs?.label ?? ''} ${attrs?.cwe ?? ''}`;
    }

    function isHardeningFinding(attrs) {
      return HARDENING_RE.test(findingClassText(attrs));
    }

    function xssPlacement(attrs) {
      const own = findingOwnText(`${attrs?.title ?? ''} ${attrs?.label ?? ''}`);
      const text = /xss|跨站脚本|反射型|反射式|存储型|存储式|file[\s-]*read|任意文件|\brce\b|代码执行|命令执行/iu.test(own)
        ? own
        : findingClassText(attrs);
      if (!/xss|cross[- ]site\s*scripting|跨站脚本|反射型|反射式|存储型|存储式/iu.test(text)) return null;
      if (/(?<!非)(?<!不是)(?<!并非)(?<!not\s)(?<!non[- ]?)(?:stored\s*xss|persistent\s*xss|存储型|存储式)/iu.test(text)) return 'stored';
      return 'reflected';
    }

    function findingInterfacePath(attrs) {
      const blobs = [attrs?.interfacePath, attrs?.endpoint, attrs?.path, attrs?.url, attrs?.proofUrl, attrs?.title, attrs?.label];
      for (let index = 0; index < blobs.length; index += 1) {
        const text = String(blobs[index] ?? '').trim();
        if (text.length === 0) continue;
        const match = /(\/[a-z0-9._~!$&'()*+,;=:@%-]+(?:\/[a-z0-9._~!$&'()*+,;=:@%-]+)*)/iu.exec(text);
        if (match !== null) {
          const normalized = match[1].replace(/\/+$/u, '');
          return normalized.length > 0 ? normalized : '/';
        }
      }
      return '/';
    }

    function findingFamily(attrs) {
      if (isHardeningFinding(attrs)) {
        const text = findingClassText(attrs);
        if (/header|响应头/iu.test(text)) return 'hardening-headers';
        if (/cert|证书|tls/iu.test(text)) return 'hardening-tls';
        return 'hardening';
      }
      const text = findingClassText(attrs);
      for (let index = 0; index < FAMILY_RULES.length; index += 1) {
        if (FAMILY_RULES[index][1].test(text)) return FAMILY_RULES[index][0];
      }
      return String(attrs?.template ?? 'finding');
    }

    function findingTypeZh(template, title) {
      const named = findingHarmName(template, title);
      if (named.name !== '其他漏洞') return named.name;
      const text = `${template ?? ''} ${title ?? ''}`;
      if (/\bssrf\b|server[- ]side\s*request/iu.test(text)) return 'SSRF';
      const family = findingFamily({ template, title, label: title, category: template });
      const names = {
        'xss-stored': '存储型 XSS',
        'xss-reflected': '反射型 XSS',
        sqli: 'SQL 注入',
        cmd: '命令执行',
        code: '远程代码执行',
        file: '任意文件读取',
        authz: '越权',
        logic: '逻辑漏洞',
        leak: '信息泄露',
        nday: '已知漏洞',
      };
      return names[family] ?? '其他漏洞';
    }

    function findingLocator(text, harmName) {
      const source = String(text ?? '');
      const paths = [...source.matchAll(/([A-Za-z0-9_.!-]+\.(?:action|jsp|php|do|aspx|asp|xml|html|cgi))/giu)].map((match) => match[1]);
      const name = String(harmName ?? '');
      if (name.includes('远程代码执行') || name.includes('管理后台') || name.includes('服务中断')) {
        if (/tomcat manager/iu.test(source)) return 'Tomcat Manager';
        const manager = paths.find((path) => /manager/iu.test(path));
        if (manager !== undefined) return manager;
      }
      if (name.includes('任意文件')) {
        const filePath = paths.find((path) => /file|download|read|include/iu.test(path));
        if (filePath !== undefined) return filePath;
      }
      if (paths.length > 0) return paths[0];
      const products = [
        ['tomcat manager', 'Tomcat Manager'],
        ['struts2', 'Struts2'],
        ['weblogic', 'WebLogic'],
        ['jenkins', 'Jenkins'],
        ['spring', 'Spring'],
      ];
      const lower = source.toLowerCase();
      for (const [needle, label] of products) {
        if (lower.includes(needle)) return label;
      }
      return '';
    }

    function findingOwnText(text) {
      return String(text ?? '')
        .replace(/\((?:escalated|raised) from[^)]*\)/giu, ' ')
        .replace(/\s+/gu, ' ')
        .trim();
    }

    function findingCauseText(text) {
      const source = findingOwnText(text);
      const match = source.match(/(?:enabled by|disclosed by|via credential disclosed by|from the)\s+(.+)$/iu);
      return match === null ? '' : match[1].trim();
    }

    function findingHarmText(text) {
      return findingOwnText(text)
        .replace(/(?:enabled by|disclosed by|via credential disclosed by|from the)\s+.+$/iu, ' ')
        .replace(/\s+/gu, ' ')
        .trim();
    }

    function findingHostHint(text) {
      const source = String(text ?? '');
      const ip = source.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/u);
      if (ip !== null) return ip[0];
      const host = source.match(/\b(?:db|admin|member|beta)\.[a-z0-9.-]+\.[a-z]{2,}\b/iu);
      return host === null ? '' : host[0].toLowerCase();
    }

    function findingHarmName(template, raw) {
      const harm = findingHarmText(raw);
      const signaled = /xss|rce|代码执行|命令执行|file[\s-]*read|任意文件|path[\s-]*traversal|stack[\s-]*trace|堆栈|database|postgresql|数据库|credential|api key|clientsecret|clientid|manager|s3|presign|takeover|支付|undeploy|outage/iu.test(harm);
      const text = signaled ? harm : `${template ?? ''} ${harm}`;
      let name = '其他漏洞';
      if (/stack[\s-]*trace|堆栈/iu.test(text) && !/\brce\b|代码执行|命令执行|file[\s-]*read|任意文件|database|postgresql|数据库/iu.test(text)) name = '堆栈跟踪泄露';
      else if (/crossdomain|跨域/iu.test(text)) name = '宽松的跨域策略';
      else if (/\bdebug\b|调试/iu.test(text)) name = '调试页面';
      else if (/\brce\b|remote\s*code|代码执行|命令执行|getshell|war[- ]deploy/iu.test(text)) name = '远程代码执行';
      else if (/takeover|账户接管|payment operation/iu.test(text)) name = '账户接管';
      else if (/api key|clientsecret|clientid|password stored|credentials exposed|凭据泄露/iu.test(text)) name = '敏感凭据泄露';
      else if (/undeploy|outage|服务中断/iu.test(text)) name = '服务中断';
      else if (/postgresql|database|数据库/iu.test(text)) name = '数据库访问';
      else if (/object read|云存储读取/iu.test(text)) name = '云存储读取';
      else if (/signing oracle|presign|云存储签名/iu.test(text)) name = '云存储签名';
      else if (/manager admin|manager access|管理后台|manager credential/iu.test(text)) name = '管理后台未授权访问';
      else if (/arbitrary file|file[\s-]*read|任意文件|path[\s-]*traversal/iu.test(text)) name = '任意文件读取';
      else if (/xss|跨站脚本|反射型/iu.test(text)) name = '反射型 XSS';
      return {
        name,
        unauth: /unauthenticated|未授权/iu.test(text) && name.includes('未授权') === false,
        locator: findingLocator(harm.length > 0 ? harm : text, name),
      };
    }

    function formatHarmName(named) {
      if (named === null || named === undefined) return '';
      if (named.name === '其他漏洞' && named.locator.length === 0) return '';
      const head = `${named.unauth ? '未授权' : ''}${named.name}`;
      return named.locator.length > 0 ? `${head}（${named.locator}）` : head;
    }

    function harmClassOf(name) {
      const text = String(name ?? '');
      if (text.includes('远程代码执行')) return 'rce';
      if (text.includes('任意文件')) return 'file';
      if (text.includes('数据库')) return 'data';
      if (text.includes('敏感凭据')) return 'cred';
      if (text.includes('管理后台')) return 'admin';
      if (text.includes('云存储读取')) return 'cloud';
      if (text.includes('云存储签名')) return 'sign';
      if (text.includes('账户接管')) return 'account';
      if (text.includes('堆栈') || text.includes('信息泄露')) return 'leak';
      if (text.includes('XSS')) return 'xss';
      if (text.includes('服务中断')) return 'avail';
      return 'other';
    }

    function harmEnables(fromName, toName) {
      const from = harmClassOf(fromName);
      const to = harmClassOf(toName);
      const table = {
        file: ['cred', 'admin', 'rce', 'data', 'cloud', 'sign', 'account'],
        cred: ['admin', 'rce', 'account', 'data'],
        admin: ['rce', 'data', 'avail', 'account'],
        rce: ['data', 'admin', 'avail', 'account'],
        sign: ['cloud', 'cred'],
        leak: ['cred'],
      };
      return (table[from] ?? []).includes(to);
    }

    function composedFindingTitle(template, raw) {
      const named = findingHarmName(template, raw);
      const title = formatHarmName(named);
      const host = findingHostHint(raw);
      if (title.length === 0 || host.length === 0 || title.includes(host)) return title;
      if (title.endsWith('）')) return `${title.slice(0, -1)} · ${host}）`;
      return `${title}（${host}）`;
    }

    function tidyMixedTitle(text) {
      return String(text).replace(/（[^）]*）/gu, (group) => {
        if (!/\b(?:via|with|through|parameter|exposed|unauthenticated|disclosure|leaked|using|from|page|and|or)\b/iu.test(group)) return group;
        const path = group.match(/[A-Za-z0-9_.-]+\.(?:action|jsp|php|do|aspx|asp|xml|html|cgi)/iu);
        if (path !== null) return `（${path[0]}）`;
        const ident = group.match(/[A-Za-z][\w.-]{2,}/u);
        return ident === null ? '' : `（${ident[0]}）`;
      });
    }

    function polishFindingTitle(template, title) {
      const text = String(title ?? '').trim();
      if (text.length === 0) return composedFindingTitle(template, template);
      if (/^finding_[0-9a-f]{8,}$/iu.test(text)) return '未命名发现';
      if (/[\u3400-\u9fff]/u.test(text)) return tidyMixedTitle(text);
      return composedFindingTitle(template, text);
    }

    function harmBand(attrs) {
      const text = findingClassText(attrs);
      if (/getshell|remote\s*code|代码执行|命令执行|command\s*execution|反序列化|webshell|\brce\b|validated foothold|foothold/iu.test(text)) return 'exec';
      const classified = classifyFindingCvss(attrs);
      if (classified.severity === 'critical') return 'exec';
      if (classified.severity === 'high') return 'high';
      if (classified.severity === 'medium') return 'medium';
      if (classified.severity === 'low') return 'low';
      return 'info';
    }

    function recordIdentity(node) {
      const raw = `${node.key} ${node.attrs?.assetKey ?? ''}`.toLowerCase();
      if (node.kind === 'access' || node.kind === 'pivot') {
        const match = raw.match(/(tomcat-manager|shell\/tomcat|database\/[a-z0-9_-]+)/u);
        return match === null ? '' : `${node.kind}:${match[1]}`;
      }
      if (node.kind !== 'data') return '';
      const scheme = raw.match(/data:[^:\s/]+?:([a-z0-9_-]+)/u);
      let token = scheme === null ? '' : scheme[1];
      if (token.length === 0) {
        const named = raw.match(/(tb[_-][a-z0-9_-]+|wcc[_-][a-z0-9_-]+)/u);
        token = named === null ? '' : named[1];
      }
      token = token.replace(/[_-]+/gu, '').replace(/pii$/u, '');
      return token.length >= 8 ? `data:${token}` : '';
    }

    function sameRecord(left, right) {
      if (left.length === 0 || right.length === 0 || left.split(':')[0] !== right.split(':')[0]) return false;
      if (left === right) return true;
      const kind = left.split(':')[0];
      const a = left.slice(kind.length + 1);
      const b = right.slice(kind.length + 1);
      const short = a.length <= b.length ? a : b;
      const long = a.length <= b.length ? b : a;
      return short.length >= 8 && long.startsWith(short);
    }

    function recordKeepScore(node) {
      let score = node.attrs?.stub === true || node.label === node.key ? 0 : 5;
      if (node.status === 'verified' || node.status === 'validated' || node.status === 'escalated') score += 4;
      else if (node.status === 'obtained') score += 3;
      else if (node.status === 'claimed') score += 1;
      score += Math.min(node.evidenceCount || 0, 3);
      return score;
    }

    function findingGroupKey(node) {
      const attrs = node.attrs || {};
      if (attrs.stub === true || /^finding_[0-9a-f]{8,}$/iu.test(String(node.key || ''))) return `solo:${node.id}`;
      const harm = findingHarmText(node.sourceLabel || node.label || attrs.title || '');
      const named = findingHarmName('', harm);
      if (named.name === '其他漏洞' && named.locator.length === 0) return `solo:${node.id}`;
      return `${findingHostHint(harm)}|${formatHarmName(named)}`;
    }

    function parseCvssMetrics(vector) {
      const text = String(vector ?? '');
      const metrics = {};
      const parts = text.split('/');
      for (let index = 0; index < parts.length; index += 1) {
        const pair = parts[index].split(':');
        if (pair.length === 2 && METRIC_ZH[pair[0]] !== undefined) metrics[pair[0]] = pair[1];
      }
      return metrics;
    }

    function redTeamJudgement(attrs) {
      const text = `${findingClassText(attrs)} ${attrs?.evidence ?? ''} ${attrs?.impact ?? ''} ${attrs?.proof ?? ''} ${attrs?.description ?? ''}`;
      if (isHardeningFinding(attrs)) return { rating: 'info', score: 0, rationale: '配置暴露或过时客户端策略，红队不能直接利用。' };
      if (/uid=\d+|whoami|命令执行成功|command executed|已证明以应用权限执行命令|validated foothold/iu.test(text) && !/未打成|未证明|not proven|未复现|no command execution|version match only/iu.test(text)) {
        return { rating: 'critical', score: 9.5, rationale: '已经打出命令执行或立足点。' };
      }
      if (/\brce\b|remote\s*code|命令执行|代码执行|getshell/iu.test(text)) return { rating: 'medium', score: 5.5, rationale: '声称能执行命令，但没有打成的证据。' };
      if (/(?<!非)(?<!不是)(?<!并非)(?<!not\s)(?<!non[- ]?)(?:stored\s*xss|persistent\s*xss|存储型|存储式)/iu.test(text)) return { rating: 'high', score: 7.5, rationale: '存储型脚本会在其他人正常访问时触发。' };
      if (/xss|跨站脚本|反射型|反射式/iu.test(text)) return { rating: 'medium', score: 5.5, rationale: '需要受害者打开链接。' };
      if (/sqli|sql\s*注入|任意文件|file\s*read|文件读取/iu.test(text)) return { rating: 'high', score: 7.5, rationale: '能读到数据或文件。' };
      if (/越权|认证绕过|权限绕过|auth(?:entication|orization)?\s*bypass/iu.test(text)) return { rating: 'high', score: 7.5, rationale: '能绕过认证或越权。' };
      if (/stack|堆栈|报错|信息泄露|\bleak\b/iu.test(text)) return { rating: 'low', score: 2.5, rationale: '只看到报错或信息，还不能直接控制目标。' };
      return { rating: 'low', score: 2.5, rationale: '没有打出可利用的影响。' };
    }

    function blendOperational(attrs, cvssScore) {
      const red = redTeamJudgement(attrs);
      const score = cvssScore === null || cvssScore === undefined
        ? red.score
        : Math.round((red.score * 0.7 + cvssScore * 0.3) * 10) / 10;
      const severity = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'info';
      return { red, score, severity };
    }

    /** CVSS is the NVD score. The shown severity is red team 70% and CVSS 30%. */
    function classifyFindingCvss(attrs) {
      const nested = isPlainObject(attrs?.cvss) ? attrs.cvss : {};
      const rawScore = attrs?.cvssScore ?? nested.baseScore ?? attrs?.cvss31?.baseScore;
      let score = Number(rawScore);
      const placement = xssPlacement(attrs);
      const originalScore = Number.isFinite(score) ? score : null;
      let capped = false;
      if (placement === 'reflected' && Number.isFinite(score) && score >= 7) {
        score = 6.1;
        capped = true;
      }
      const rawSeverity = String(attrs?.cvssSeverity ?? nested.baseSeverity ?? attrs?.cvss31?.baseSeverity ?? '').toLowerCase();
      const text = findingClassText(attrs);
      const hardening = isHardeningFinding(attrs);
      const exposureClass = EXPOSURE_CLASS_RE.test(text) && !VULNERABILITY_CLASS_RE.test(text);
      const nvdSeverity = Number.isFinite(score) && score > 0
        ? (score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low')
        : (['critical', 'high', 'medium', 'low', 'info'].includes(rawSeverity) ? rawSeverity : 'unscored');
      const usableScore = Number.isFinite(score) && score >= 0 && score <= 10 ? score : null;
      const blend = blendOperational(attrs, usableScore);
      const vulnerability = hardening === false && exposureClass === false && (VULNERABILITY_CLASS_RE.test(text)
        || (Number.isFinite(score) && score >= 7));
      return {
        score: usableScore,
        severity: blend.severity,
        nvdSeverity,
        vulnerability,
        highCritical: nvdSeverity === 'critical' || nvdSeverity === 'high',
        hardening,
        capped,
        originalScore,
        placement,
        redteamRating: blend.red.rating,
        redteamRationale: blend.red.rationale,
        operationalScore: blend.score,
      };
    }

    function footholdPlace(node) {
      const attrs = node?.attrs || {};
      if (typeof attrs.hostname === 'string' && attrs.hostname.trim().length > 0) return attrs.hostname.trim();
      if (typeof attrs.host === 'string' && attrs.host.trim().length > 0 && attrs.host !== 'unknown') return attrs.host.trim();
      if (typeof attrs.ip === 'string' && attrs.ip.trim().length > 0) return attrs.ip.trim();
      const ip = String(node?.label || '').match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/u);
      return ip === null ? '' : ip[0];
    }

    function privilegeZh(value) {
      const text = String(value ?? '').trim();
      if (text.length === 0 || text === 'unknown' || text === '—') return '';
      if (/uid\s*=\s*0|\broot\b/iu.test(text)) return 'root';
      if (/superuser/iu.test(text)) return '数据库超级用户';
      if (/manager-gui/iu.test(text)) return '管理入口';
      const named = text.match(/uid\s*=\s*\d+\(([^)]+)\)/iu);
      if (named !== null) return `系统用户 ${named[1]}`;
      return text;
    }

    function serviceZh(value) {
      const text = String(value ?? '').toLowerCase();
      if (text.length === 0) return '';
      if (/tomcat|manager/.test(text)) return '管理入口';
      if (/postgres|database/.test(text)) return '数据库';
      if (/paypal|payment/.test(text)) return '支付接口';
      if (/mail/.test(text)) return '邮件服务';
      if (/aws|s3|cloud/.test(text)) return '云存储';
      return '';
    }

    function footholdTitle(node) {
      const attrs = node?.attrs || {};
      const blob = `${node?.label ?? ''} ${node?.key ?? ''} ${attrs.kind ?? ''} ${attrs.accessType ?? ''} ${attrs.privilege ?? ''} ${attrs.service ?? ''} ${attrs.panel ?? ''} ${attrs.role ?? ''}`;
      const place = footholdPlace(node);
      const where = place.length > 0 ? `（${place}）` : '';
      const unfinished = attrs.stub === true || node?.status === 'attempted' || node?.status === 'untested';
      if (node?.kind === 'pivot') return place.length > 0 ? `跳板线索${where}` : '跳板线索';
      if (node?.kind === 'credential') {
        if (unfinished) return '尚未验证的凭据';
        const service = serviceZh(attrs.service);
        if (service.length > 0) return `${service}凭据${where}`;
        if (/admin/iu.test(blob)) return `应用管理员凭据${where}`;
        return `已验证凭据${where}`;
      }
      if (unfinished) {
        if (/tomcat|manager/iu.test(blob)) return `管理入口权限${where}（尚未拿到）`;
        return '尚未拿到的权限';
      }
      const identity = `${attrs.privilege ?? ''} ${attrs.accessType ?? ''}`;
      if (/uid\s*=\s*0|\broot-shell\b|\broot\b/iu.test(identity)) return `root 权限${where}`;
      if (/superuser|postgres/iu.test(String(attrs.privilege ?? ''))) return `数据库超级用户${where}`;
      if (/remote-shell|uid\s*=\s*\d+/iu.test(identity)) return `服务器命令权限${where}`;
      if (/manager/iu.test(blob)) return `管理后台权限${where}`;
      if (/shell/iu.test(blob)) return `服务器命令权限${where}`;
      return `已拿到的权限${where}`;
    }

    function footholdStory(node) {
      const attrs = node?.attrs || {};
      const place = footholdPlace(node);
      const who = privilegeZh(attrs.privilege) || privilegeZh(attrs.role);
      const unfinished = attrs.stub === true || node?.status === 'attempted' || node?.status === 'untested';
      if (node?.kind === 'pivot') {
        return place.length > 0
          ? `这是一条跳板线索，指向 ${place}。它还不是已经拿到的权限，当前没有进入这台机器。`
          : '这是一条跳板线索，还没有进入目标机器。';
      }
      if (node?.kind === 'credential') {
        if (unfinished) return '这里只记了一个凭据名字，还没有验证。口令不会显示。';
        const account = typeof attrs.username === 'string' ? attrs.username.trim() : '';
        const service = serviceZh(attrs.service);
        return `这是一条已验证的凭据，不是漏洞。漏洞说明的是哪里能被利用；凭据说明的是拿来登录的账号。${place.length > 0 ? `它出现在 ${place}。` : ''}${account.length > 0 ? `账号是 ${account}。` : ''}${service.length > 0 ? `用于${service}。` : ''}口令原文不显示。`;
      }
      if (unfinished) return '这里只记了一次尝试，权限还没有拿到，所以没有机器和身份。';
      return `这是已经拿到的权限，不是漏洞。漏洞说明的是哪里能被利用；这里说明利用之后实际落到了什么身份。${place.length > 0 ? `机器是 ${place}。` : ''}${who.length > 0 ? `身份是 ${who}。` : ''}`;
    }

    function dataTitle(node) {
      const attrs = node?.attrs || {};
      const text = `${node?.label ?? ''} ${node?.key ?? ''} ${attrs.dataClass ?? ''}`;
      const count = Number(attrs.count) || 0;
      let name = '已读取的数据';
      if (/history|search/iu.test(text)) name = '用户历史数据';
      else if (/order/iu.test(text)) name = '订单数据';
      else if (/user/iu.test(text)) name = '用户数据';
      return count > 0 ? `${name}（${count} 条）` : name;
    }

    function normalizeNode(raw, index) {
      const attrs = asObject(raw.attrs);
      const kind = asString(raw.kind, 'unknown');
      const id = asString(raw.id, asString(raw.key, `node-${index}`));
      const key = asString(raw.key, id);
      const label = asString(raw.label, key);
      const template = asString(attrs.template, asString(attrs.category, 'unknown'));
      const localizedLabel = kind === 'finding'
        ? findingTitleZh(template, asString(attrs.title, label))
        : (kind === 'access' || kind === 'credential' || kind === 'pivot')
          ? footholdTitle({ kind, label, key, status: asString(raw.status, 'unknown'), attrs })
          : (kind === 'data')
            ? dataTitle({ kind, label, key, attrs })
            : label;
      const localizedAttrs = kind === 'finding' ? { ...attrs, title: localizedLabel } : attrs;
      const findingType = kind === 'finding' ? findingTypeZh(template, `${asString(attrs.title, '')} ${label} ${localizedLabel}`) : '';
      const tags = asArray(raw.tags).filter((tag) => typeof tag === 'string' && tag.length > 0).slice(0, 30);
      const privilege = String(attrs.privilege === undefined ? '' : attrs.privilege);
      const crown = raw.crown === true
        || attrs.crownJewel === true
        || tags.indexOf('crown_jewel') >= 0
        || asNumber(attrs.criticality, 0) >= 4
        || ((kind === 'credential' || kind === 'access') && CROWN_PRIVILEGES.has(privilege));
      const cvss = kind === 'finding' ? classifyFindingCvss(attrs) : null;
      return {
        id,
        kind,
        key,
        label: localizedLabel,
        sourceLabel: kind === 'finding' ? label : '',
        findingType,
        status: asString(raw.status, 'unknown'),
        confidence: clamp01(asNumber(raw.confidence, 0.5)),
        verification: asString(raw.verification, 'unverified'),
        attrs: localizedAttrs,
        tags,
        evidenceCount: asCount(raw.evidenceCount),
        degree: asCount(raw.degree),
        adjDegree: 0,
        crown,
        hardening: cvss?.hardening === true,
        severity: cvss === null ? severityOfNode(kind, attrs) : cvss.severity,
        cvssScore: cvss?.score ?? null,
        cvssSeverity: cvss?.nvdSeverity && cvss.nvdSeverity !== 'unscored' ? cvss.nvdSeverity : null,
        redteamRating: cvss?.redteamRating ?? null,
        redteamRationale: cvss?.redteamRationale ?? null,
        operationalScore: cvss?.operationalScore ?? null,
        cvssCapped: cvss?.capped === true,
        cvssOriginalScore: cvss?.originalScore ?? null,
        xssPlacement: cvss?.placement ?? null,
        isVulnerability: cvss?.vulnerability === true,
        firstSeen: typeof raw.firstSeen === 'string' ? raw.firstSeen : null,
        lastSeen: typeof raw.lastSeen === 'string' ? raw.lastSeen : null,
        search: buildNodeSearch(id, kind, key, localizedLabel, asString(raw.status, 'unknown'), asString(raw.verification, 'unverified'), tags, attrs),
      };
    }

    function normalizeEdge(raw, index) {
      const from = asString(raw.from);
      const to = asString(raw.to);
      if (from.length === 0 || to.length === 0 || from === to) return null;
      const kind = asString(raw.kind, 'unknown');
      return {
        id: asString(raw.id, `${from}|${kind}|${to}|${index}`),
        from,
        to,
        kind,
        confidence: clamp01(asNumber(raw.confidence, 0.5)),
        evidenceCount: asCount(raw.evidenceCount),
        attrs: asObject(raw.attrs),
      };
    }

    function countKinds(nodes) {
      const byKind = {};
      for (const node of nodes) byKind[node.kind] = (byKind[node.kind] === undefined ? 0 : byKind[node.kind]) + 1;
      return byKind;
    }

    function normalizeCounts(rawCounts, nodes, edges) {
      const source = asObject(rawCounts);
      const byKind = countKinds(nodes);
      const bySeverity = {};
      const byStatus = {};
      for (const node of nodes) {
        byStatus[node.status] = (byStatus[node.status] === undefined ? 0 : byStatus[node.status]) + 1;
        if (node.kind === 'finding') {
          const severity = node.severity || 'info';
          bySeverity[severity] = (bySeverity[severity] === undefined ? 0 : bySeverity[severity]) + 1;
        }
      }
      const rawByKind = asObject(source.byKind);
      for (const kind of Object.keys(rawByKind)) byKind[kind] = asCount(rawByKind[kind]);
      const rawBySeverity = asObject(source.bySeverity);
      for (const severity of Object.keys(rawBySeverity)) bySeverity[severity] = asCount(rawBySeverity[severity]);
      const rawByStatus = asObject(source.byStatus);
      for (const status of Object.keys(rawByStatus)) byStatus[status] = asCount(rawByStatus[status]);
      return {
        nodes: asCount(source.nodes) || nodes.length,
        edges: asCount(source.edges) || edges.length,
        byKind,
        bySeverity,
        byStatus,
      };
    }

    function normalizeCoverage(rawCoverage, nodes, edges, outgoing) {
      const source = asObject(rawCoverage);
      const byKind = countKinds(nodes);
      const hosts = (byKind.host || 0) + (byKind.ip || 0);
      const assetsWithServices = nodes.filter((node) => {
        if (node.kind !== 'host' && node.kind !== 'ip') return false;
        return (outgoing.get(node.id) || []).some((edge) => edge.kind === 'exposes');
      }).length;
      const countStatus = (kind, statuses) => nodes.filter((node) => node.kind === kind && statuses.indexOf(node.status) >= 0).length;
      const pick = (name, fallback) => (Number.isFinite(Number(source[name])) ? Number(source[name]) : fallback);
      return {
        assets: pick('assets', hosts),
        assetsWithServices: pick('assetsWithServices', assetsWithServices),
        services: pick('services', byKind.service || 0),
        webapps: pick('webapps', byKind.webapp || 0),
        findings: pick('findings', byKind.finding || 0),
        vulnerabilities: nodes.filter((node) => node.kind === 'finding' && node.includedVulnerability === true).length,
        unscoredFindings: nodes.filter((node) => node.kind === 'finding' && node.severity === 'unscored').length,
        verifiedFindings: pick('verifiedFindings', countStatus('finding', ['verified', 'exploited', 'impacted'])),
        credentials: pick('credentials', byKind.credential || 0),
        validatedCredentials: pick('validatedCredentials', countStatus('credential', ['valid'])),
        access: pick('access', byKind.access || 0),
        validatedAccess: pick('validatedAccess', countStatus('access', ['validated', 'escalated'])),
        data: pick('data', byKind.data || 0),
        verifiedData: pick('verifiedData', countStatus('data', ['verified'])),
        pivots: pick('pivots', byKind.pivot || 0),
        verifiedPivots: pick('verifiedPivots', nodes.filter((node) => node.kind === 'pivot' && (node.status === 'verified' || node.attrs.verified === true)).length),
        crownJewels: pick('crownJewels', nodes.filter((node) => node.crown).length),
      };
    }

    function normalizeScope(rawScope) {
      const source = asObject(rawScope);
      const allow = asArray(source.allow).filter(isPlainObject);
      const deny = asArray(source.deny).filter(isPlainObject);
      const allowCount = asCount(source.allowCount) || allow.length;
      const denyCount = asCount(source.denyCount) || deny.length;
      const normalizeEntries = (entries) => entries.slice(0, 200).map((entry) => ({
        type: asString(entry.type, ''),
        value: asString(entry.value, ''),
        ports: asString(entry.ports, ''),
        note: asString(entry.note, ''),
      })).filter((entry) => entry.value.length > 0);
      return {
        allow: normalizeEntries(allow),
        deny: normalizeEntries(deny),
        allowCount,
        denyCount,
        empty: source.empty === true || allowCount === 0,
        roe: asObject(source.roe),
        updatedAt: typeof source.updatedAt === 'string' ? source.updatedAt : null,
      };
    }

    function normalizeEngagement(rawEngagement) {
      if (!isPlainObject(rawEngagement)) return null;
      return {
        id: asString(rawEngagement.id, ''),
        name: asString(rawEngagement.name, ''),
        client: asString(rawEngagement.client, ''),
        mode: asString(rawEngagement.mode, ''),
        authorization: asString(rawEngagement.authorization, ''),
      };
    }

    function normalizeWildcard(rawWildcard, nodes) {
      const source = asObject(rawWildcard);
      const hosts = asObject(source.hosts);
      const suspects = asCount(hosts.suspect) || nodes.filter((node) => node.kind === 'host' && node.attrs.wildcardStatus === 'suspect').length;
      return {
        zones: asCount(source.zones),
        confirmed: asCount(source.confirmed),
        suspect: asCount(source.suspect),
        inconclusive: asCount(source.inconclusive),
        cleared: asCount(source.cleared),
        hostSuspects: suspects,
        hostExplicit: asCount(hosts.explicit),
        hostUnknown: asCount(hosts.unknown),
      };
    }

    function normalizeTruncated(rawTruncated) {
      const source = asObject(rawTruncated);
      return {
        nodes: source.nodes === true,
        edges: source.edges === true,
        omittedNodes: asCount(source.omittedNodes),
        omittedEdges: asCount(source.omittedEdges),
      };
    }

    function normalizeTasks(rawTasks) {
      return asArray(rawTasks).filter(isPlainObject).slice(0, 300).map((task, index) => ({
        id: asString(task.id, `task-${index}`),
        label: asString(task.label, asString(task.id, `task ${index + 1}`)),
        status: asString(task.status, 'unknown'),
        priority: asNumber(task.priority, 0),
        actionType: asString(task.actionType, 'unknown'),
        targetId: typeof task.targetId === 'string' ? task.targetId : null,
        why: asArray(task.why).filter((entry) => typeof entry === 'string').slice(0, 6),
        risk: asString(task.risk, 'low'),
      }));
    }

    /** Normalize the team-orchestration batch projection (every field optional). */
    function normalizeTeam(rawTeam) {
      const source = asObject(rawTeam);
      const batches = asArray(source.batches).filter(isPlainObject).slice(0, 500).map((batch, index) => {
        const status = asString(batch.status, 'unknown');
        const artifactReady = batch.artifactReady === true
          || status === 'artifact_ready'
          || status === 'completed'
          || status === 'merged';
        return {
          id: asString(batch.id, `team-batch-${index}`),
          batchId: asString(batch.batchId, asString(batch.id, `batch-${index + 1}`)),
          label: asString(batch.label, asString(batch.batchId, asString(batch.id, `batch ${index + 1}`))),
          status,
          assetCount: asCount(batch.assetCount),
          assetLabels: asArray(batch.assetLabels).filter((entry) => typeof entry === 'string').slice(0, 20),
          mode: asString(batch.mode, ''),
          agentName: asString(batch.agentName, ''),
          childId: asString(batch.childId, ''),
          teamTaskId: asString(batch.teamTaskId, ''),
          artifactPath: asString(batch.artifactPath, ''),
          artifactReady,
          mergedAt: typeof batch.mergedAt === 'string' ? batch.mergedAt : null,
          error: asString(batch.error, ''),
        };
      });
      const totalsSource = asObject(source.totals);
      const countBy = (predicate) => batches.filter(predicate).length;
      return {
        batches,
        totals: {
          batches: asNumber(totalsSource.batches, batches.length),
          assets: asNumber(totalsSource.assets, batches.reduce((sum, batch) => sum + batch.assetCount, 0)),
          planned: asNumber(totalsSource.planned, countBy((batch) => batch.status === 'planned')),
          dispatched: asNumber(totalsSource.dispatched, countBy((batch) => batch.status === 'dispatched')),
          artifactReady: asNumber(totalsSource.artifactReady, countBy((batch) => batch.artifactReady && batch.status !== 'completed' && batch.status !== 'merged')),
          merged: asNumber(totalsSource.merged, countBy((batch) => batch.status === 'completed' || batch.status === 'merged')),
          failed: asNumber(totalsSource.failed, countBy((batch) => batch.status === 'failed' || batch.status === 'merge_failed')),
          cancelled: asNumber(totalsSource.cancelled, countBy((batch) => batch.status === 'cancelled')),
        },
      };
    }

    /** Normalize the autonomous-loop projection (state, supervision, intents, lessons). */
    function normalizeLoop(rawLoop) {
      const source = asObject(rawLoop);
      const rawState = isPlainObject(source.state) ? source.state : null;
      const state = rawState === null ? null : {
        id: asString(rawState.id, ''),
        phase: asString(rawState.phase, 'unknown'),
        objective: asString(rawState.objective, ''),
        objectiveType: asString(rawState.objectiveType, ''),
        round: asCount(rawState.round),
        maxRounds: asCount(rawState.maxRounds),
        goalId: asString(rawState.goalId, ''),
        goalRevision: Number.isFinite(Number(rawState.goalRevision)) ? Number(rawState.goalRevision) : null,
        goalPhase: asString(rawState.goalPhase, ''),
        activation: asString(rawState.activation, 'disarmed'),
        ring: asNumber(rawState.ring, 1),
        allowedRing: asNumber(rawState.allowedRing, 1),
        noProgressRounds: asCount(rawState.noProgressRounds),
        emptyRounds: asCount(rawState.emptyRounds),
        maxActionsPerRound: asNumber(rawState.maxActionsPerRound, 3),
        stopReason: asString(rawState.stopReason, ''),
        autoContinue: rawState.autoContinue === true,
        startedAt: typeof rawState.startedAt === 'string' ? rawState.startedAt : null,
        lastStepAt: typeof rawState.lastStepAt === 'string' ? rawState.lastStepAt : null,
        appliedLessonKeys: asArray(rawState.appliedLessonKeys).filter((entry) => typeof entry === 'string').slice(0, 30),
      };
      const supervisions = asArray(source.supervisions).filter(isPlainObject).slice(0, 100).map((row, index) => ({
        id: asString(row.id, `supervision-${index}`),
        round: asCount(row.round),
        type: asString(row.type, 'unknown'),
        verdict: asString(row.verdict, 'unknown'),
        source: asString(row.source, 'unknown'),
        diagnosis: asString(row.diagnosis, ''),
        nextPlan: asString(row.nextPlan, ''),
        mustIntents: asArray(row.mustIntents).filter((entry) => typeof entry === 'string').slice(0, 6),
        preferTactics: asArray(row.preferTactics).filter((entry) => typeof entry === 'string').slice(0, 8),
        banRepeats: asArray(row.banRepeats).filter((entry) => typeof entry === 'string').slice(0, 8),
        stopRecommended: row.stopRecommended === true,
        stopReason: asString(row.stopReason, ''),
        confidence: clamp01(asNumber(row.confidence, 0.5)),
        findingKey: asString(row.findingKey, ''),
        secondaryVerdict: asString(row.secondaryVerdict, ''),
        createdAt: typeof row.createdAt === 'string' ? row.createdAt : null,
      }));
      const intents = asArray(source.intents).filter(isPlainObject).slice(0, 100).map((row, index) => ({
        id: asString(row.id, `intent-${index}`),
        actionType: asString(row.actionType, 'unknown'),
        actionId: asString(row.actionId, ''),
        targetLabel: asString(row.targetLabel, asString(row.id, `intent ${index + 1}`)),
        status: asString(row.status, 'unknown'),
        priority: asNumber(row.priority, 0),
        round: asCount(row.round),
        expectedEvidence: row.expectedEvidence === undefined ? null : row.expectedEvidence,
        why: asArray(row.why).filter((entry) => typeof entry === 'string').slice(0, 5),
        scopeVerdict: asString(row.scopeVerdict, 'unknown'),
        attempts: asCount(row.attempts),
        channelCount: asCount(row.channelCount),
      }));
      const lessons = asArray(source.lessons).filter(isPlainObject).slice(0, 100).map((row, index) => ({
        id: asString(row.id, `lesson-${index}`),
        lessonKey: asString(row.lessonKey, asString(row.id, `lesson-${index + 1}`)),
        idea: asString(row.idea, ''),
        method: asString(row.method, ''),
        route: asString(row.route, ''),
        chain: asString(row.chain, ''),
        when: asArray(row.when).filter((entry) => typeof entry === 'string').slice(0, 8),
        do: asArray(row.do).filter((entry) => typeof entry === 'string').slice(0, 6),
        avoid: asArray(row.avoid).filter((entry) => typeof entry === 'string').slice(0, 6),
        confidence: clamp01(asNumber(row.confidence, 0.5)),
        wins: asCount(row.wins),
        fails: asCount(row.fails),
        uses: asCount(row.uses),
        status: asString(row.status, 'unknown'),
        sourceOutcome: asString(row.sourceOutcome, ''),
      }));
      const totalsSource = asObject(source.totals);
      return {
        state,
        latest: supervisions.length > 0 ? supervisions[0] : null,
        supervisions,
        intents,
        lessons,
        totals: {
          rounds: asNumber(totalsSource.rounds, state === null ? 0 : state.round),
          reviews: asNumber(totalsSource.reviews, supervisions.length),
          lessons: asNumber(totalsSource.lessons, lessons.length),
          appliedLessons: asNumber(totalsSource.appliedLessons, state === null ? 0 : state.appliedLessonKeys.length),
          openIntents: asNumber(totalsSource.openIntents, intents.filter((intent) => intent.status === 'open' || intent.status === 'claimed').length),
        },
      };
    }

    function normalizeTargets(rawTargets) {
      const source = asObject(rawTargets);
      const clusters = asArray(source.clusters).filter(isPlainObject).slice(0, 80).map((cluster, index) => ({
        id: asString(cluster.id, `cluster-${index}`),
        label: asString(cluster.label, `cluster-${index}`),
        kind: asString(cluster.kind, 'cluster'),
        totals: asObject(cluster.totals),
        targets: asArray(cluster.targets).filter(isPlainObject).slice(0, 500).map((target) => ({
          id: asString(target.id, ''),
          kind: asString(target.kind, 'target'),
          label: asString(target.label, 'target'),
          host: asString(target.host, ''),
          status: asString(target.status, 'untested'),
          services: asCount(target.services),
          webapps: asCount(target.webapps),
          interfaces: asCount(target.interfaces),
          findings: asCount(target.findings),
          verifiedFindings: asCount(target.verifiedFindings),
          vulnerabilities: asCount(target.vulnerabilities),
          unscoredFindings: asCount(target.unscoredFindings),
          coverageCells: asCount(target.coverageCells),
          coverageSeen: asCount(target.coverageSeen),
          access: asCount(target.access),
          data: asCount(target.data),
          credentials: asCount(target.credentials),
        })),
      }));
      const totals = asObject(source.totals);
      return {
        clusters,
        totals: {
          clusters: asCount(totals.clusters) || clusters.length,
          targets: asCount(totals.targets) || clusters.reduce((sum, cluster) => sum + cluster.targets.length, 0),
          tested: asCount(totals.tested),
          recon: asCount(totals.recon),
          untested: asCount(totals.untested),
          impacted: asCount(totals.impacted),
          services: asCount(totals.services),
          webapps: asCount(totals.webapps),
          findings: asCount(totals.findings),
          vulnerabilities: asCount(totals.vulnerabilities),
          coverageSeen: asCount(totals.coverageSeen),
          coverageCells: asCount(totals.coverageCells),
          access: asCount(totals.access),
          data: asCount(totals.data),
          unassignedCoverage: asCount(totals.unassignedCoverage),
          unassignedCoverageSeen: asCount(totals.unassignedCoverageSeen),
        },
      };
    }

    function normalizeCoverageBoard(rawBoard) {
      const source = asObject(rawBoard);
      const cells = asArray(source.cells).filter(isPlainObject).slice(0, 500).map((cell) => ({
        id: asString(cell.id, ''),
        path: asString(cell.path, '/'),
        bugClass: asString(cell.bugClass, 'unknown'),
        status: asString(cell.status, 'open'),
        role: asString(cell.role, 'lead'),
        reason: asString(cell.reason, ''),
        findingId: asString(cell.findingId, ''),
        channels: asArray(cell.channels).filter((item) => typeof item === 'string').slice(0, 12),
        evidenceIds: asArray(cell.evidenceIds).filter((item) => typeof item === 'string').slice(0, 20),
      }));
      const totals = asObject(source.totals);
      return {
        cells,
        totals: {
          cells: asNumber(totals.cells, cells.length),
          open: asNumber(totals.open, cells.filter((cell) => cell.status === 'open').length),
          claimed: asNumber(totals.claimed, cells.filter((cell) => cell.status === 'claimed').length),
          seen: asNumber(totals.seen, cells.filter((cell) => cell.status === 'seen').length),
          refuted: asNumber(totals.refuted, cells.filter((cell) => cell.status === 'refuted').length),
          reported: asNumber(totals.reported, cells.filter((cell) => cell.status === 'reported').length),
        },
      };
    }

    function normalizeHypotheses(rawHypotheses) {
      const source = asObject(rawHypotheses);
      const rows = asArray(source.rows).filter(isPlainObject).slice(0, 200).map((row) => ({
        id: asString(row.id, ''),
        hypothesisId: asString(row.hypothesisId, ''),
        strategy: asString(row.strategy, ''),
        bugClass: asString(row.bugClass, ''),
        targetKey: asString(row.targetKey, ''),
        expectedProof: asString(row.expectedProof, 'poc_replay'),
        status: asString(row.status, 'open'),
        reason: asString(row.reason, ''),
        channels: asArray(row.channels).filter((item) => typeof item === 'string').slice(0, 12),
        evidenceIds: asArray(row.evidenceIds).filter((item) => typeof item === 'string').slice(0, 20),
      }));
      const totals = asObject(source.totals);
      return {
        rows,
        totals: {
          hypotheses: asNumber(totals.hypotheses, rows.length),
          open: asNumber(totals.open, rows.filter((row) => row.status === 'open').length),
          active: asNumber(totals.active, rows.filter((row) => row.status === 'active').length),
          verified: asNumber(totals.verified, rows.filter((row) => row.status === 'verified').length),
          disproved: asNumber(totals.disproved, rows.filter((row) => row.status === 'disproved').length),
        },
      };
    }

    function normalizeSelfTeam(rawSelfTeam) {
      const source = asObject(rawSelfTeam);
      const teams = asArray(source.teams).filter(isPlainObject).slice(0, 20).map((team, index) => ({
        id: asString(team.id, `selfteam-${index}`),
        type: asString(team.type, 'supervision'),
        label: asString(team.label, asString(team.type, `selfteam ${index + 1}`)),
        status: asString(team.status, 'unknown'),
        mode: asString(team.mode, 'subagents'),
        members: asArray(team.members).filter(isPlainObject).slice(0, 8).map((member) => ({
          role: asString(member.role, 'member'),
          name: asString(member.name, ''),
          mode: asString(member.mode, ''),
          responsibility: asString(member.responsibility, ''),
        })),
        lastBriefAt: typeof team.lastBriefAt === 'string' ? team.lastBriefAt : null,
        lastBriefPath: asString(team.lastBriefPath, ''),
        lastDistillAt: typeof team.lastDistillAt === 'string' ? team.lastDistillAt : null,
        lastVerifyAt: typeof team.lastVerifyAt === 'string' ? team.lastVerifyAt : null,
        lastReportAt: typeof team.lastReportAt === 'string' ? team.lastReportAt : null,
        lastReportPath: asString(team.lastReportPath, ''),
        lastReportTheme: asString(team.lastReportTheme, ''),
        lastFindingReportAt: typeof team.lastFindingReportAt === 'string' ? team.lastFindingReportAt : null,
        lastFindingReportPath: asString(team.lastFindingReportPath, ''),
        lastFindingReportId: asString(team.lastFindingReportId, ''),
        reportModes: asArray(team.reportModes).filter((entry) => typeof entry === 'string').slice(0, 4),
        themeSource: asString(team.themeSource, ''),
        verifiedCount: asCount(team.verifiedCount),
        ratedCount: asCount(team.ratedCount),
        skillCount: asCount(team.skillCount),
        skillDir: asString(team.skillDir, ''),
      }));
      const skills = asArray(source.skills).filter(isPlainObject).slice(0, 100).map((skill, index) => ({
        id: asString(skill.id, `skill-${index}`),
        skillKey: asString(skill.skillKey, `skill-${index}`),
        name: asString(skill.name, asString(skill.skillKey, `skill ${index + 1}`)),
        summary: asString(skill.summary, ''),
        when: asArray(skill.when).filter((entry) => typeof entry === 'string').slice(0, 8),
        do: asArray(skill.do).filter((entry) => typeof entry === 'string').slice(0, 6),
        avoid: asArray(skill.avoid).filter((entry) => typeof entry === 'string').slice(0, 6),
        route: asString(skill.route, ''),
        confidence: clamp01(asNumber(skill.confidence, 0.5)),
        status: asString(skill.status, 'unknown'),
        path: asString(skill.path, ''),
        sourceOutcome: asString(skill.sourceOutcome, ''),
      }));
      const rawBrief = isPlainObject(source.latestBrief) ? source.latestBrief : null;
      const latestBrief = rawBrief === null ? null : {
        id: asString(rawBrief.id, ''),
        round: asCount(rawBrief.round),
        progressSummary: asString(rawBrief.progressSummary, ''),
        gained: asArray(rawBrief.gained).filter((entry) => typeof entry === 'string').slice(0, 8),
        missed: asArray(rawBrief.missed).filter((entry) => typeof entry === 'string').slice(0, 8),
        advice: asString(rawBrief.advice, ''),
        antiDeadlock: asArray(rawBrief.antiDeadlock).filter((entry) => typeof entry === 'string').slice(0, 8),
        recommendedNext: asArray(rawBrief.recommendedNext).filter((entry) => typeof entry === 'string').slice(0, 8),
        deadlockRisk: asString(rawBrief.deadlockRisk, 'medium'),
        source: asString(rawBrief.source, 'unknown'),
        artifactPath: asString(rawBrief.artifactPath, ''),
        handoff: isPlainObject(rawBrief.handoff) ? {
          from: asString(rawBrief.handoff.from, 'supervisor'),
          to: asString(rawBrief.handoff.to, 'executor'),
          status: asString(rawBrief.handoff.status, 'legacy'),
          channel: asString(rawBrief.handoff.channel, 'tool_result'),
          deliveredAt: typeof rawBrief.handoff.deliveredAt === 'string' ? rawBrief.handoff.deliveredAt : null,
          directive: asString(rawBrief.handoff.directive, ''),
          targetGaps: asCount(rawBrief.handoff.targetGaps),
          supervisorChildId: asString(rawBrief.handoff.supervisorChildId, ''),
        } : (asString(rawBrief.advice, '').length > 0 ? {
          from: 'supervisor',
          to: 'executor',
          status: 'legacy',
          channel: 'tool_result',
          deliveredAt: null,
          directive: asString(rawBrief.advice, ''),
          targetGaps: 0,
        } : null),
        createdAt: typeof rawBrief.createdAt === 'string' ? rawBrief.createdAt : null,
      };
      const totalsSource = asObject(source.totals);
      return {
        teams,
        skills,
        latestBrief,
        totals: {
          teams: asNumber(totalsSource.teams, teams.length),
          skills: asNumber(totalsSource.skills, skills.length),
          leadTeams: asNumber(totalsSource.leadTeams, teams.filter((team) => team.type === 'lead').length),
          supervisionTeams: asNumber(totalsSource.supervisionTeams, teams.filter((team) => team.type === 'supervision').length),
          evolutionTeams: asNumber(totalsSource.evolutionTeams, teams.filter((team) => team.type === 'evolution').length),
          verificationTeams: asNumber(totalsSource.verificationTeams, teams.filter((team) => team.type === 'verification').length),
          reportTeams: asNumber(totalsSource.reportTeams, teams.filter((team) => team.type === 'report').length),
        },
      };
    }

    function normalizeWildcardZones(rawZones) {
      return asArray(rawZones).filter(isPlainObject).slice(0, 300).map((zone, index) => ({
        id: asString(zone.id, `zone-${index}`),
        zone: asString(zone.zone, asString(zone.label, `zone-${index}`)),
        label: asString(zone.label, asString(zone.zone, `zone-${index}`)),
        status: asString(zone.status, 'unknown'),
        confidence: clamp01(asNumber(zone.confidence, 0.5)),
        cdn: zone.cdn === true,
        signature: asObject(zone.signature),
        probeCount: asCount(zone.probeCount),
        lastSeen: typeof zone.lastSeen === 'string' ? zone.lastSeen : null,
      }));
    }

    function normalizeChainSteps(rawSteps, chainId) {
      return asArray(rawSteps).filter(isPlainObject).slice(0, 80).map((step, index) => ({
        id: asString(step.id, `${chainId}:step:${index}`),
        label: asString(step.label, asString(step.id, `step ${index + 1}`)),
        stage: asString(step.stage, 'unknown'),
        stageRank: Number.isFinite(Number(step.stageRank)) ? Number(step.stageRank) : (CHAIN_STAGE_RANK[asString(step.stage, 'unknown')] === undefined ? CHAIN_STAGES.length : CHAIN_STAGE_RANK[asString(step.stage, 'unknown')]),
        status: asString(step.status, 'unknown'),
        nodeRef: typeof step.nodeRef === 'string' ? step.nodeRef : null,
        evidenceCount: asCount(step.evidenceCount),
        ordinal: index,
      }));
    }

    function normalizeChains(rawChains, rawCrownPaths) {
      const source = asObject(rawChains);
      const explicit = asArray(source.explicit).filter(isPlainObject).slice(0, 40).map((group, index) => {
        const chainId = asString(group.chainId, `chain-${index}`);
        return { chainId, steps: normalizeChainSteps(group.steps, chainId) };
      });
      const rawCrown = Array.isArray(rawCrownPaths) ? rawCrownPaths : asArray(source.crown);
      const crown = rawCrown.filter(isPlainObject).slice(0, 40).map((path, index) => {
        const chainId = asString(path.chainId, `crown-${index}`);
        return {
          chainId,
          targetId: asString(path.targetId, ''),
          targetKind: asString(path.targetKind, 'unknown'),
          targetLabel: asString(path.targetLabel, asString(path.targetId, `crown ${index + 1}`)),
          cost: asNumber(path.cost, 0),
          nodeIds: asArray(path.nodes).filter((entry) => typeof entry === 'string').slice(0, 80),
          steps: asArray(path.steps).filter(isPlainObject).slice(0, 80).map((step) => ({
            from: asString(step.from, ''),
            to: asString(step.to, ''),
            kind: asString(step.kind, 'unknown'),
            edgeId: asString(step.edgeId, ''),
            cost: asNumber(step.cost, 0),
          })),
        };
      });
      return { explicit, crown };
    }

    function normalizeProjectCompletion(raw) {
      const source = asObject(raw);
      return {
        complete: source.complete === true,
        reportPath: asString(source.reportPath, ''),
        reportAt: typeof source.reportAt === 'string' ? source.reportAt : null,
        reportKind: asString(source.reportKind, ''),
        latestImpactAt: typeof source.latestImpactAt === 'string' ? source.latestImpactAt : null,
        reason: asString(source.reason, ''),
      };
    }

    function normalizeGraph(rawValue) {
      const raw = unwrapGraph(rawValue);
      if (raw === null) return null;
      const nodes = [];
      const byId = new Map();
      let duplicateNodes = 0;
      asArray(raw.nodes).forEach((entry, index) => {
        if (!isPlainObject(entry)) return;
        const node = normalizeNode(entry, index);
        if (byId.has(node.id)) {
          duplicateNodes += 1;
          return;
        }
        byId.set(node.id, node);
        nodes.push(node);
      });
      const edges = [];
      const edgeIds = new Set();
      let danglingEdges = 0;
      asArray(raw.edges).forEach((entry, index) => {
        if (!isPlainObject(entry)) return;
        const edge = normalizeEdge(entry, index);
        if (edge === null) return;
        if (!byId.has(edge.from) || !byId.has(edge.to)) {
          danglingEdges += 1;
          return;
        }
        if (edgeIds.has(edge.id)) return;
        edgeIds.add(edge.id);
        edges.push(edge);
      });
      const outgoing = new Map();
      const incoming = new Map();
      for (const edge of edges) {
        let out = outgoing.get(edge.from);
        if (out === undefined) {
          out = [];
          outgoing.set(edge.from, out);
        }
        out.push(edge);
        let inc = incoming.get(edge.to);
        if (inc === undefined) {
          inc = [];
          incoming.set(edge.to, inc);
        }
        inc.push(edge);
      }
      for (const edge of edges) {
        if (edge.kind !== 'escalates_to') continue;
        const source = byId.get(edge.from);
        const raised = byId.get(edge.to);
        if (source === undefined || raised === undefined || source.kind !== 'finding') continue;
        const proof = String(raised.attrs?.escalationProof ?? '').trim();
        if (proof.length === 0) continue;
        const raisedTitle = raised.label === '手工记录漏洞' ? '漏洞危害提升成功' : raised.label;
        source.raisedTo = {
          title: raisedTitle,
          fromSeverity: raised.attrs?.escalatedFromSeverity || source.attrs?.severity,
          toSeverity: raised.attrs?.escalatedToSeverity || raised.attrs?.severity,
          proof,
        };
      }
      const verifiedFindingIds = new Set();
      const ratedFindingKeys = new Set();
      for (const supervision of nodes.filter((node) => node.kind === 'supervision')) {
        const attrs = supervision.attrs || {};
        if (attrs.type === 'finding_verification' && String(attrs.verdict ?? '').toLowerCase() === 'verified') {
          for (const edge of edges) {
            if (edge.from === supervision.id && edge.kind === 'supervises') verifiedFindingIds.add(edge.to);
          }
        }
        if (attrs.type === 'rating' && typeof attrs.findingKey === 'string') ratedFindingKeys.add(attrs.findingKey);
      }
      for (const node of nodes) {
        if (node.kind === 'finding') {
          const attrs = node.attrs || {};
          const verdict = String(attrs.secondaryVerdict ?? '').toLowerCase();
          const secondaryVerified = attrs.secondaryVerified === true
            || verdict === 'verified'
            || verifiedFindingIds.has(node.id);
          const nested = isPlainObject(attrs.cvss) ? attrs.cvss : {};
          const score = Number(attrs.cvssScore ?? nested.baseScore);
          const vector = typeof attrs.cvssVector === 'string' ? attrs.cvssVector : (typeof nested.vector === 'string' ? nested.vector : '');
          const severityName = String(attrs.cvssSeverity ?? nested.baseSeverity ?? '').toLowerCase();
          const scored = Number.isFinite(score) && score >= 0 && score <= 10 && (
            vector.startsWith('CVSS:')
            || attrs.ratingSource === 'nvd-cvss31'
            || ['none', 'low', 'medium', 'high', 'critical', 'info'].includes(severityName)
          );
          const rated = scored
            || attrs.redteamRating !== undefined
            || attrs.cvssRating !== undefined
            || attrs.ratingSource !== undefined
            || ratedFindingKeys.has(node.key);
          const secondaryRefuted = verdict === 'refuted';
          const pairDone = secondaryVerified && scored;
          node.secondaryVerified = secondaryVerified;
          node.rated = rated;
          node.refuted = secondaryRefuted;
          node.qualified = pairDone;
          node.verificationState = secondaryRefuted ? 'failed' : (pairDone ? 'passed' : 'pending');
          const placeholder = attrs.stub === true || /^finding_[0-9a-f]{8,}$/iu.test(String(node.key || ''));
          node.includedVulnerability = placeholder === false && isHardeningFinding(attrs) === false && secondaryRefuted === false;
        }
      }
      const findingGroups = new Map();
      for (const node of nodes) {
        if (node.kind !== 'finding') continue;
        const groupKey = findingGroupKey(node);
        const group = findingGroups.get(groupKey);
        if (group === undefined) findingGroups.set(groupKey, [node]);
        else group.push(node);
      }
      const droppedFindingIds = new Set();
      for (const group of findingGroups.values()) {
        if (group.length < 2) continue;
        group.sort((left, right) => {
          const rank = (node) => (Number(node.attrs?.cvssScore) || Number(node.cvssScore) || 0)
            + (String(node.attrs?.escalationProof ?? '').length > 0 ? 20 : 0)
            + (node.secondaryVerified === true ? 1 : 0);
          return rank(right) - rank(left);
        });
        group[0].mergedCount = group.length;
        for (let index = 1; index < group.length; index += 1) droppedFindingIds.add(group[index].id);
      }
      if (droppedFindingIds.size > 0) {
        const keeperOf = new Map();
        for (const group of findingGroups.values()) {
          if (group.length < 2) continue;
          for (let index = 1; index < group.length; index += 1) keeperOf.set(group[index].id, group[0].id);
        }
        for (const edge of edges) {
          if (keeperOf.has(edge.from)) edge.from = keeperOf.get(edge.from);
          if (keeperOf.has(edge.to)) edge.to = keeperOf.get(edge.to);
        }
        for (let index = nodes.length - 1; index >= 0; index -= 1) {
          if (droppedFindingIds.has(nodes[index].id)) {
            byId.delete(nodes[index].id);
            nodes.splice(index, 1);
          }
        }
        const seenEdge = new Set();
        for (let index = edges.length - 1; index >= 0; index -= 1) {
          const edge = edges[index];
          const signature = `${edge.from}|${edge.kind}|${edge.to}`;
          if (edge.from === edge.to || seenEdge.has(signature)) edges.splice(index, 1);
          else seenEdge.add(signature);
        }
        outgoing.clear();
        incoming.clear();
        for (const edge of edges) {
          let out = outgoing.get(edge.from);
          if (out === undefined) {
            out = [];
            outgoing.set(edge.from, out);
          }
          out.push(edge);
          let inc = incoming.get(edge.to);
          if (inc === undefined) {
            inc = [];
            incoming.set(edge.to, inc);
          }
          inc.push(edge);
        }
      }
      const stubAttempts = new Set();
      for (const node of nodes) {
        if (node.kind === 'data' && node.attrs?.stub === true) {
          const provedData = nodes.some((other) => other.id !== node.id && other.kind === 'data' && other.attrs?.stub !== true);
          if (provedData) stubAttempts.add(node.id);
          continue;
        }
        if ((node.kind !== 'access' && node.kind !== 'credential') || node.attrs?.stub !== true) continue;
        const key = String(node.key || '').toLowerCase();
        if (key.length === 0) continue;
        const proved = nodes.some((other) => other.id !== node.id
          && other.kind === node.kind
          && other.attrs?.stub !== true
          && String(other.attrs?.assetKey || '').toLowerCase() === key);
        if (proved) stubAttempts.add(node.id);
      }
      if (stubAttempts.size > 0) {
        for (let index = nodes.length - 1; index >= 0; index -= 1) {
          if (!stubAttempts.has(nodes[index].id)) continue;
          byId.delete(nodes[index].id);
          nodes.splice(index, 1);
        }
        for (let index = edges.length - 1; index >= 0; index -= 1) {
          if (stubAttempts.has(edges[index].from) || stubAttempts.has(edges[index].to)) edges.splice(index, 1);
        }
        outgoing.clear();
        incoming.clear();
        for (const edge of edges) {
          let out = outgoing.get(edge.from);
          if (out === undefined) {
            out = [];
            outgoing.set(edge.from, out);
          }
          out.push(edge);
          let inc = incoming.get(edge.to);
          if (inc === undefined) {
            inc = [];
            incoming.set(edge.to, inc);
          }
          inc.push(edge);
        }
      }
      const folded = new Map();
      const pool = nodes.filter((node) => node.kind === 'access' || node.kind === 'pivot' || node.kind === 'data');
      const consumed = new Set();
      for (let left = 0; left < pool.length; left += 1) {
        if (consumed.has(pool[left].id)) continue;
        const identity = recordIdentity(pool[left]);
        const group = [pool[left]];
        for (let right = left + 1; right < pool.length; right += 1) {
          if (consumed.has(pool[right].id)) continue;
          if (!sameRecord(identity, recordIdentity(pool[right]))) continue;
          group.push(pool[right]);
        }
        if (group.length < 2) continue;
        group.sort((a, b) => recordKeepScore(b) - recordKeepScore(a) || a.id.localeCompare(b.id));
        for (let index = 1; index < group.length; index += 1) {
          consumed.add(group[index].id);
          folded.set(group[index].id, group[0].id);
        }
      }
      if (folded.size > 0) {
        for (const edge of edges) {
          if (folded.has(edge.from)) edge.from = folded.get(edge.from);
          if (folded.has(edge.to)) edge.to = folded.get(edge.to);
        }
        const seenEdge = new Set();
        for (let index = edges.length - 1; index >= 0; index -= 1) {
          const edge = edges[index];
          const signature = `${edge.from}|${edge.kind}|${edge.to}`;
          if (edge.from === edge.to || seenEdge.has(signature)) edges.splice(index, 1);
          else seenEdge.add(signature);
        }
        for (let index = nodes.length - 1; index >= 0; index -= 1) {
          if (!folded.has(nodes[index].id)) continue;
          byId.delete(nodes[index].id);
          nodes.splice(index, 1);
        }
        outgoing.clear();
        incoming.clear();
        for (const edge of edges) {
          let out = outgoing.get(edge.from);
          if (out === undefined) {
            out = [];
            outgoing.set(edge.from, out);
          }
          out.push(edge);
          let inc = incoming.get(edge.to);
          if (inc === undefined) {
            inc = [];
            incoming.set(edge.to, inc);
          }
          inc.push(edge);
        }
      }
      for (const node of nodes) {
        node.adjDegree = (outgoing.get(node.id) || []).length + (incoming.get(node.id) || []).length;
      }
      const chains = normalizeChains(raw.chains, raw.crownPaths);
      const coverage = normalizeCoverage(raw.coverage, nodes, edges, outgoing);
      const lastAction = isPlainObject(raw.lastAction)
        ? {
          tool: asString(raw.lastAction.tool, ''),
          action: asString(raw.lastAction.action, ''),
          at: typeof raw.lastAction.at === 'string' ? raw.lastAction.at : null,
        }
        : null;
      return {
        raw,
        nodes,
        byId,
        edges,
        outgoing,
        incoming,
        counts: normalizeCounts(raw.counts, nodes, edges),
        coverage,
        scope: normalizeScope(raw.scope),
        engagement: normalizeEngagement(raw.engagement),
        wildcard: normalizeWildcard(raw.wildcard, nodes),
        truncated: normalizeTruncated(raw.truncated),
        caps: asObject(raw.caps),
        chains,
        crownPaths: chains.crown,
        tasks: normalizeTasks(raw.tasks),
        team: normalizeTeam(raw.team),
        loop: normalizeLoop(raw.loop),
        selfTeam: normalizeSelfTeam(raw.selfTeam),
        targets: normalizeTargets(raw.targets),
        projectCompletion: normalizeProjectCompletion(raw.projectCompletion),
        coverageBoard: normalizeCoverageBoard(raw.coverageBoard),
        hypotheses: normalizeHypotheses(raw.hypotheses),
        wildcardZones: normalizeWildcardZones(raw.wildcardZones),
        seq: asNumber(raw.seq, 0),
        lastAction,
        dedupe: asObject(raw.dedupe),
        duplicateNodes,
        danglingEdges,
      };
    }

    // ---------------------------------------------------------------------
    // Filtering, capping, layout and selection helpers (pure, memo-safe)
    // ---------------------------------------------------------------------

    function verificationState(node) {
      if (node?.verificationState === 'passed' || node?.verificationState === 'pending' || node?.verificationState === 'failed') {
        return node.verificationState;
      }
      const attrs = node?.attrs || {};
      const verdict = String(attrs.secondaryVerdict ?? '').toLowerCase();
      if (verdict === 'refuted') return 'failed';
      const score = Number(attrs.cvssScore);
      const vector = typeof attrs.cvssVector === 'string' ? attrs.cvssVector : '';
      const scored = Number.isFinite(score) && score >= 0 && score <= 10 && (vector.startsWith('CVSS:') || attrs.ratingSource === 'nvd-cvss31');
      if ((attrs.secondaryVerified === true || verdict === 'verified') && scored) return 'passed';
      return 'pending';
    }

    function isVerifiedNode(node) {
      return node.verification === 'verified' || VERIFIED_STATUSES.indexOf(node.status) >= 0;
    }

    function isWildcardSuspect(node) {
      return node.kind === 'host' && node.attrs.wildcardStatus === 'suspect';
    }

    function passesFilters(node, filters) {
      if (!filters.showWildcard && isWildcardSuspect(node)) return false;
      if (filters.kind !== 'all' && node.kind !== filters.kind) return false;
      if (filters.severity !== 'all' && node.kind === 'finding' && node.severity !== filters.severity) return false;
      if (filters.verifiedOnly && !isVerifiedNode(node)) return false;
      if (filters.query.length > 0 && node.search.indexOf(filters.query) < 0) return false;
      return true;
    }

    const HIDDEN_CANVAS_KINDS = new Set(['coverage', 'hypothesis', 'mcp', 'lesson', 'self_team', 'skill', 'evidence', 'supervision']);

    const ATTACK_VIEW_KINDS = new Set([
      'domain', 'wildcard_zone', 'host', 'ip', 'cidr', 'segment',
      'service', 'webapp', 'tech', 'finding', 'credential', 'access', 'pivot', 'data',
    ]);

    /**
     * Attack view keeps path-bearing nodes, high/critical candidates, and all
     * verified findings. A verified Medium is still a finding (not a CVSS
     * vulnerability), but hiding it made confirmed XSS/exposure disappear.
     */
    function isAttackViewNode(node) {
      if (node.kind === 'finding' && node.refuted === true) return false;
      if (node.crown === true) return true;
      if (node.kind === 'finding') return node.includedVulnerability === true && node.refuted !== true;
      return ATTACK_VIEW_KINDS.has(node.kind);
    }

    function filterModel(model, filters) {
      if (model === null) return null;
      const attackOnly = filters.attackOnly !== false;
      const visible = [];
      let hiddenWildcard = 0;
      let hiddenByAttack = 0;
      for (const node of model.nodes) {
        if (HIDDEN_CANVAS_KINDS.has(node.kind)) continue;
        if (node.kind === 'finding' && node.refuted === true) continue;
        if (isWildcardSuspect(node)) hiddenWildcard += 1;
        if (attackOnly && !isAttackViewNode(node)) {
          hiddenByAttack += 1;
          continue;
        }
        if (passesFilters(node, filters)) visible.push(node);
      }
      const visibleIds = new Set(visible.map((node) => node.id));
      const edges = model.edges.filter((edge) => visibleIds.has(edge.from) && visibleIds.has(edge.to));
      return {
        visible,
        edges,
        hiddenWildcard,
        hiddenByAttack,
        totalVisible: visible.length,
        totalNodes: model.nodes.length,
        totalEdges: model.edges.length,
        filtersActive: filters.kind !== 'all'
          || filters.severity !== 'all'
          || filters.verifiedOnly
          || filters.query.length > 0,
      };
    }

    function nodeImportance(node) {
      const severity = node.severity === null ? 0 : (SEVERITY_RANK[node.severity] || 0);
      return (node.crown ? 5000 : 0) + severity * 60 + node.adjDegree * 6 + (KIND_IMPORTANCE[node.kind] || 0);
    }

    function capForRender(filtered) {
      let nodes = filtered.visible;
      let omittedNodes = 0;
      if (nodes.length > MAX_RENDER_NODES) {
        nodes = nodes.slice()
          .sort((a, b) => nodeImportance(b) - nodeImportance(a) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id))
          .slice(0, MAX_RENDER_NODES);
        omittedNodes = filtered.visible.length - nodes.length;
      }
      const renderedIds = new Set(nodes.map((node) => node.id));
      const candidateEdges = filtered.edges.filter((edge) => renderedIds.has(edge.from) && renderedIds.has(edge.to));
      let edges = candidateEdges;
      let omittedEdges = 0;
      if (candidateEdges.length > MAX_RENDER_EDGES) {
        edges = candidateEdges.slice()
          .sort((a, b) => b.confidence - a.confidence
            || (EDGE_KIND_RANK[a.kind] === undefined ? 99 : EDGE_KIND_RANK[a.kind]) - (EDGE_KIND_RANK[b.kind] === undefined ? 99 : EDGE_KIND_RANK[b.kind])
            || a.id.localeCompare(b.id))
          .slice(0, MAX_RENDER_EDGES);
        omittedEdges = candidateEdges.length - edges.length;
      }
      return { nodes, edges, omittedNodes, omittedEdges, candidateEdgeCount: candidateEdges.length };
    }

    const TARGET_GROUP_MIN_ASSETS = 2;
    const TARGET_GROUP_MAX_SIGNALS = 12;
    const TARGET_GROUP_MAX_EXPANDED = 90;
    const TARGET_ASSET_KINDS = new Set(['domain', 'wildcard_zone', 'host', 'ip', 'cidr', 'segment']);
    const TARGET_TWO_LEVEL_SUFFIXES = new Set([
      'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
      'com.au', 'net.au', 'org.au', 'co.jp', 'com.br', 'com.hk', 'com.tw', 'co.kr', 'co.in',
      'com.sg', 'com.mx', 'com.tr', 'com.ru',
    ]);

    function isTargetIp(value) {
      const s = String(value ?? '').trim();
      return /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(s) || (/^[0-9a-f:]+$/iu.test(s) && s.indexOf(':') >= 0);
    }

    function parseTargetHost(value) {
      let raw = String(value ?? '').trim();
      if (raw.length === 0) return '';
      if (raw.indexOf('://') >= 0) raw = raw.slice(raw.indexOf('://') + 3).split('/')[0].split('?')[0].split('#')[0];
      raw = raw.split('/')[0].trim();
      if (raw.startsWith('[')) {
        const end = raw.indexOf(']');
        raw = end > 0 ? raw.slice(1, end) : raw.replace(/^\[/u, '');
      } else if (!isTargetIp(raw) && raw.split(':').length === 2) {
        raw = raw.split(':')[0];
      }
      if (isTargetIp(raw)) return raw.toLowerCase();
      return raw.replace(/^www\./iu, '').toLowerCase().replace(/\.$/u, '');
    }

    function nodeTargetHost(node) {
      const attrs = node.attrs ?? {};
      const candidates = [
        attrs.fqdn, attrs.hostname, attrs.host, attrs.addr, attrs.ip, attrs.url,
      ];
      if (TARGET_ASSET_KINDS.has(node.kind) || node.kind === 'service' || node.kind === 'webapp' || node.kind === 'tech') candidates.push(node.label);
      for (const candidate of candidates) {
        const host = parseTargetHost(candidate);
        if (host.length > 0) return host;
      }
      return '';
    }

    function registrableDomainOf(host) {
      const parts = String(host ?? '').toLowerCase().split('.').filter(Boolean);
      if (parts.length <= 2) return parts.join('.');
      const lastTwo = parts.slice(-2).join('.');
      if (TARGET_TWO_LEVEL_SUFFIXES.has(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
      return lastTwo;
    }

    function scopeDomainAnchors(model) {
      const allow = Array.isArray(model.scope?.allow) ? model.scope.allow : [];
      const anchors = [];
      for (const entry of allow) {
        const raw = typeof entry === 'string' ? entry : (entry?.value ?? entry?.canonical ?? entry?.domain ?? '');
        const host = parseTargetHost(raw);
        if (host.length === 0 || isTargetIp(host)) continue;
        if (host.indexOf('*') >= 0) continue;
        if (!anchors.includes(host)) anchors.push(host);
      }
      return anchors;
    }

    function firstLevelHost(host) {
      const registered = registrableDomainOf(host);
      const hostParts = String(host ?? '').split('.').filter(Boolean);
      const registeredParts = String(registered ?? '').split('.').filter(Boolean);
      if (registered.length === 0 || hostParts.length <= registeredParts.length) return host;
      return hostParts.slice(-(registeredParts.length + 1)).join('.');
    }

    function targetBaseKeyForHost(host, _anchors) {
      const normalized = parseTargetHost(host);
      if (normalized.length === 0) return '';
      if (isTargetIp(normalized)) return `ip:${normalized}`;
      return `name:${firstLevelHost(normalized)}`;
    }

    function targetGroupId(key) {
      let hash = 0;
      for (let index = 0; index < key.length; index += 1) hash = ((hash * 31) + key.charCodeAt(index)) | 0;
      const slug = key.replace(/[^a-zA-Z0-9._-]+/gu, '-').replace(/^-+|-+$/gu, '').slice(0, 22);
      return `target:${Math.abs(hash).toString(36)}:${slug || 'group'}`;
    }

    function targetGroupSummary(counts, t) {
      const findingSuffix = counts.findings > 0
        ? ` · ${counts.findings} ${t('group.vulnerabilities')}`
        : '';
      return `${counts.assets} ${t('group.assets')} · ${counts.services} ${t('group.services')}${findingSuffix}`;
    }

    function isGraphSignal(node) {
      if (node.crown === true) return true;
      if (node.kind === 'access' || node.kind === 'pivot' || node.kind === 'data') return true;
      return node.kind === 'finding' && node.includedVulnerability === true;
    }

    /**
     * One target is one IP, or one first-level subdomain.
     * Different ports of that IP or subdomain stay on the same card.
     * a.bac.com and a.bac.com:8003 are one target. a.bac.com and b.bac.com are two.
     * The graph keeps target cards and high-signal nodes, hiding bulk assets/services/findings
     * behind a target detail popup and an explicit expand action.
     */
    function buildTargetGroups(model, filtered, { expanded = new Set(), t } = {}) {
      const assetNodes = filtered.visible.filter((node) => TARGET_ASSET_KINDS.has(node.kind));
      if (assetNodes.length < 2) return null;
      const anchors = scopeDomainAnchors(model);
      const byNodeId = model.byId;
      const baseKeys = new Map();
      for (const node of assetNodes) {
        const host = nodeTargetHost(node);
        const key = targetBaseKeyForHost(host.length > 0 ? host : node.label, anchors);
        if (key.length > 0) baseKeys.set(node.id, key);
      }
      const parent = new Map();
      function find(key) {
        let current = key;
        while (parent.has(current) && parent.get(current) !== current) current = parent.get(current);
        parent.set(key, current);
        return current;
      }
      function union(first, second) {
        const a = find(first);
        const b = find(second);
        if (a !== b) parent.set(b, a);
      }
      for (const key of baseKeys.values()) if (!parent.has(key)) parent.set(key, key);
      if (anchors.length === 0) {
        const ipAssets = new Map();
        function addIpAsset(ip, nodeId) {
          if (!ipAssets.has(ip)) ipAssets.set(ip, new Set());
          ipAssets.get(ip).add(nodeId);
        }
        for (const edge of filtered.edges) {
          const from = byNodeId.get(edge.from);
          const to = byNodeId.get(edge.to);
          if (from === undefined || to === undefined) continue;
          if (to.kind === 'ip' && TARGET_ASSET_KINDS.has(from.kind)) addIpAsset(to.label, from.id);
          if (from.kind === 'ip' && TARGET_ASSET_KINDS.has(to.kind)) addIpAsset(from.label, to.id);
        }
        for (const node of assetNodes) if (node.kind === 'ip') addIpAsset(node.label, node.id);
        for (const ids of ipAssets.values()) {
          const keys = [...new Set([...ids].map((id) => baseKeys.get(id)).filter(Boolean))];
          for (let index = 1; index < keys.length; index += 1) union(keys[0], keys[index]);
        }
      }
      for (const edge of filtered.edges) {
        const from = byNodeId.get(edge.from);
        const to = byNodeId.get(edge.to);
        if (from === undefined || to === undefined) continue;
        const host = from.kind === 'host' ? from : (to.kind === 'host' ? to : null);
        const address = from.kind === 'ip' ? from : (to.kind === 'ip' ? to : null);
        if (host === null || address === null) continue;
        const hostKey = baseKeys.get(host.id);
        const addressKey = baseKeys.get(address.id);
        if (hostKey !== undefined && addressKey !== undefined) union(hostKey, addressKey);
      }
      for (const node of assetNodes) {
        if (node.kind !== 'host') continue;
        const hostKey = baseKeys.get(node.id);
        if (hostKey === undefined) continue;
        const listed = Array.isArray(node.attrs?.ips) ? node.attrs.ips : [];
        for (const ip of listed) {
          const normalized = parseTargetHost(ip);
          if (normalized.length === 0) continue;
          for (const other of assetNodes) {
            if (other.kind !== 'ip') continue;
            if (parseTargetHost(other.label) !== normalized && parseTargetHost(other.attrs?.ip) !== normalized) continue;
            const addressKey = baseKeys.get(other.id);
            if (addressKey !== undefined) union(hostKey, addressKey);
          }
        }
      }
      const groups = new Map();
      const nodeGroup = new Map();
      for (const node of assetNodes) {
        const base = baseKeys.get(node.id);
        if (base === undefined) continue;
        const root = find(base);
        if (!groups.has(root)) groups.set(root, { root, members: new Set(), labels: [] });
        const group = groups.get(root);
        group.members.add(node.id);
        const host = nodeTargetHost(node);
        if (host.length > 0 && !group.labels.includes(host)) group.labels.push(host);
        nodeGroup.set(node.id, root);
      }
      const adjacency = new Map();
      for (const edge of filtered.edges) {
        if (!adjacency.has(edge.from)) adjacency.set(edge.from, new Set());
        if (!adjacency.has(edge.to)) adjacency.set(edge.to, new Set());
        adjacency.get(edge.from).add(edge.to);
        adjacency.get(edge.to).add(edge.from);
      }
      function groupForNode(node) {
        if (nodeGroup.has(node.id)) return nodeGroup.get(node.id);
        const targetId = typeof node.attrs?.targetId === 'string' ? node.attrs.targetId : '';
        if (targetId.length > 0 && nodeGroup.has(targetId)) return nodeGroup.get(targetId);
        const queue = [node.id];
        const seen = new Set([node.id]);
        for (let depth = 0; depth < 5 && queue.length > 0; depth += 1) {
          const next = [];
          for (const id of queue) {
            for (const neighbour of adjacency.get(id) ?? []) {
              if (seen.has(neighbour)) continue;
              seen.add(neighbour);
              if (nodeGroup.has(neighbour)) return nodeGroup.get(neighbour);
              next.push(neighbour);
            }
          }
          queue.splice(0, queue.length, ...next);
        }
        const host = nodeTargetHost(node);
        if (host.length > 0) {
          const key = targetBaseKeyForHost(host, anchors);
          if (key.length > 0) {
            if (!groups.has(key)) groups.set(key, { root: key, members: new Set(), labels: [host] });
            nodeGroup.set(node.id, key);
            return key;
          }
        }
        return null;
      }
      for (const node of filtered.visible) {
        if (TARGET_ASSET_KINDS.has(node.kind)) continue;
        const groupKey = groupForNode(node);
        if (groupKey === null) continue;
        const group = groups.get(groupKey);
        if (group === undefined) continue;
        group.members.add(node.id);
        nodeGroup.set(node.id, groupKey);
      }
      function labelForGroup(group) {
        const hostnames = group.labels.filter((host) => !isTargetIp(host));
        if (hostnames.length > 0) {
          const anchorsMatched = anchors.filter((anchor) => hostnames.some((host) => host === anchor || host.endsWith(`.${anchor}`)));
          if (anchorsMatched.length > 0) return anchorsMatched.sort((a, b) => b.length - a.length)[0];
          const domains = hostnames.map(registrableDomainOf).filter(Boolean);
          if (domains.length > 0) return domains.sort((a, b) => a.length - b.length || a.localeCompare(b))[0];
          return hostnames[0];
        }
        if (group.root.startsWith('ip:')) return group.root.slice(3);
        if (group.root.startsWith('anchor:')) return group.root.slice(7);
        if (group.root.startsWith('zone:')) return group.root.slice(5);
        return group.root.replace(/^(machine|target):/u, '');
      }
      const visibleNodes = [];
      const visibleIds = new Set();
      const edges = [];
      const groupNodes = [];
      const groupByNode = new Map();
      const orderedGroups = [...groups.values()].sort((a, b) => b.members.size - a.members.size || labelForGroup(a).localeCompare(labelForGroup(b)));
      for (const group of orderedGroups) {
        const label = labelForGroup(group);
        const groupId = targetGroupId(group.root);
        const memberIds = [...group.members];
        for (const id of memberIds) groupByNode.set(id, groupId);
        const counts = { assets: 0, services: 0, findings: 0, vulnerabilities: 0, verifiedFindings: 0, access: 0, data: 0, credentials: 0 };
        for (const id of memberIds) {
          const node = byNodeId.get(id);
          if (node === undefined) continue;
          if (TARGET_ASSET_KINDS.has(node.kind)) counts.assets += 1;
          else if (node.kind === 'service' || node.kind === 'webapp' || node.kind === 'tech') counts.services += 1;
          else if (node.kind === 'finding') {
            counts.findings += 1;
            if (node.includedVulnerability === true) counts.vulnerabilities += 1;
            if (['verified', 'exploited', 'impacted'].includes(node.status)) counts.verifiedFindings += 1;
          }
          else if (node.kind === 'access' || node.kind === 'pivot') counts.access += 1;
          else if (node.kind === 'data') counts.data += 1;
          else if (node.kind === 'credential') counts.credentials += 1;
        }
        const isExpanded = expanded.has(groupId);
        const signalIds = memberIds.filter((id) => {
          const node = byNodeId.get(id);
          return node !== undefined && isGraphSignal(node);
        }).sort((a, b) => {
          const first = byNodeId.get(a);
          const second = byNodeId.get(b);
          const rank = (node) => node.crown ? 0 : (node.kind === 'access' ? 1 : (node.kind === 'data' ? 2 : 3));
          return rank(first) - rank(second) || second.evidenceCount - first.evidenceCount;
        });
        const keptIds = isExpanded
          ? memberIds.slice(0, TARGET_GROUP_MAX_EXPANDED)
          : signalIds.slice(0, TARGET_GROUP_MAX_SIGNALS);
        const groupNode = {
          id: groupId,
          kind: 'target',
          key: group.root,
          label,
          status: 'unknown',
          confidence: 1,
          verification: 'verified',
          severity: null,
          crown: false,
          attrs: {
            targetGroup: true,
            zone: group.root,
            members: memberIds,
            counts,
            groupSummary: targetGroupSummary(counts, t),
            expanded: isExpanded,
          },
          tags: ['target-group'],
          evidenceCount: 0,
          degree: keptIds.length,
          adjDegree: keptIds.length,
          firstSeen: null,
          lastSeen: null,
        };
        groupNodes.push(groupNode);
        visibleNodes.push(groupNode);
        visibleIds.add(groupNode.id);
        for (const id of keptIds) {
          const node = byNodeId.get(id);
          if (node === undefined) continue;
          if (!visibleIds.has(id)) {
            visibleNodes.push(node);
            visibleIds.add(id);
          }
          edges.push({
            id: `target-edge:${groupId}:${id}`,
            from: groupId,
            to: id,
            kind: 'contains',
            confidence: 1,
            attrs: { targetGroup: true },
            evidenceCount: 0,
          });
        }
      }
      for (const node of filtered.visible) {
        if (visibleIds.has(node.id) || nodeGroup.has(node.id)) continue;
        if (!isGraphSignal(node)) continue;
        visibleNodes.push(node);
        visibleIds.add(node.id);
      }
      const hiddenCount = filtered.visible.length - visibleNodes.length + groupNodes.length;
      const outgoing = new Map();
      const incoming = new Map();
      for (const edge of edges) {
        if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
        if (!incoming.has(edge.to)) incoming.set(edge.to, []);
        outgoing.get(edge.from).push(edge);
        incoming.get(edge.to).push(edge);
      }
      return {
        ...filtered,
        visible: visibleNodes,
        nodes: visibleNodes,
        edges,
        byId: new Map([...model.byId, ...groupNodes.map((node) => [node.id, node])]),
        outgoing,
        incoming,
        groupByNode,
        groupCount: groupNodes.length,
        hiddenNodeCount: Math.max(0, hiddenCount),
        targetGrouped: true,
      };
    }

    function layeredColumnOf(node) {
      const column = LAYERED_COLUMN_OF_KIND[node.kind];
      return column === undefined ? LAYERED_COLUMNS.length : column;
    }

    const CHAIN_SURFACE_KINDS = new Set(['target', 'domain', 'wildcard_zone', 'host', 'ip', 'cidr', 'segment', 'service', 'webapp', 'tech']);

    function chainColumnOf(node) {
      if (node.kind === 'chain_step') {
        const stage = asString(node.attrs.stage, 'unknown');
        if (CHAIN_STAGE_RANK[stage] !== undefined) return 20 + CHAIN_STAGE_RANK[stage];
        return 40;
      }
      if (CHAIN_SURFACE_KINDS.has(node.kind)) return 0;
      if (node.kind === 'finding') return 1;
      if (node.kind === 'credential') return 2;
      if (node.kind === 'access' || node.kind === 'pivot') return 3;
      if (node.kind === 'data') return 4;
      return 5;
    }

    function chainHeaderLabel(column, t) {
      if (column === 0) return t('graph.stage.target');
      if (column === 1) return t('graph.stage.finding');
      if (column === 2) return t('kind.credential');
      if (column === 3) return t('graph.stage.access');
      if (column === 4) return t('graph.stage.data');
      if (column >= 20 && column < 20 + CHAIN_STAGES.length) return t(`chain.stage.${CHAIN_STAGES[column - 20]}`);
      return t('chain.stage.unknown');
    }

    function severityRankOf(node) {
      return node.severity === null ? 0 : (SEVERITY_RANK[node.severity] || 0);
    }

    function sortLayeredColumn(a, b) {
      const kindDelta = (NODE_KIND_RANK[a.kind] === undefined ? 99 : NODE_KIND_RANK[a.kind]) - (NODE_KIND_RANK[b.kind] === undefined ? 99 : NODE_KIND_RANK[b.kind]);
      if (kindDelta !== 0) return kindDelta;
      const severityDelta = severityRankOf(b) - severityRankOf(a);
      if (severityDelta !== 0) return severityDelta;
      return a.label.localeCompare(b.label) || a.id.localeCompare(b.id);
    }

    function sortChainColumn(a, b) {
      const stageA = chainColumnOf(a);
      const stageB = chainColumnOf(b);
      if (stageA !== stageB) return stageA - stageB;
      const chainA = asString(a.attrs.chainId, '');
      const chainB = asString(b.attrs.chainId, '');
      if (chainA !== chainB) return chainA.localeCompare(chainB);
      const ordinalA = asNumber(a.attrs.ordinal, Number.MAX_SAFE_INTEGER);
      const ordinalB = asNumber(b.attrs.ordinal, Number.MAX_SAFE_INTEGER);
      if (ordinalA !== ordinalB) return ordinalA - ordinalB;
      return a.label.localeCompare(b.label) || a.id.localeCompare(b.id);
    }

    const PATH_EDGE_KINDS = new Set(['affects', 'exposes', 'controls', 'authenticates_to', 'pivots_to', 'reached_via', 'proves', 'hosted_on', 'contains', 'derived_from', 'escalates_to']);
    const PATH_ROLE_ORDER = { target: 0, service: 1, finding: 2, credential: 3, access: 4, internal: 5, data: 6 };

    function isPrivateIpv4(value) {
      const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(String(value ?? ''));
      if (match === null) return false;
      const parts = match.slice(1).map(Number);
      if (parts.some((part) => part > 255)) return false;
      const [a, b] = parts;
      if (a === 10 || a === 127) return true;
      if (a === 192 && b === 168) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      return false;
    }

    function isLoopbackHost(host) {
      const name = String(host ?? '').toLowerCase();
      return name === '127.0.0.1' || name === '::1' || name === 'localhost' || name === '0.0.0.0';
    }

    function isInternalDns(host) {
      return /\.(internal|local|lan|corp|intranet|home\.arpa)$/iu.test(String(host ?? ''));
    }

    function scopeDeclaresHost(model, host) {
      const wanted = String(host ?? '').toLowerCase();
      if (wanted.length === 0) return false;
      const allow = Array.isArray(model?.scope?.allow) ? model.scope.allow : [];
      return allow.some((entry) => {
        const value = parseTargetHost(typeof entry === 'string' ? entry : (entry?.value ?? ''));
        if (value.length === 0) return false;
        return value === wanted || wanted.endsWith(`.${value}`) || value.endsWith(`.${wanted}`);
      });
    }

    function isScopeInternalAsset(node, model) {
      if (!TARGET_ASSET_KINDS.has(node.kind)) return false;
      const host = nodeTargetHost(node);
      if (host.length === 0) return false;
      const declared = node.attrs?.declared === true || scopeDeclaresHost(model, host);
      if (isLoopbackHost(host)) return declared;
      if (!isPrivateIpv4(host) && !isInternalDns(host)) return false;
      return declared;
    }

    function pivotAssetIds(nodes, edges, model) {
      const byId = new Map(nodes.map((node) => [node.id, node]));
      const dest = new Set();
      function consider(id, fromPivotEdge) {
        const node = byId.get(id);
        if (node === undefined || !TARGET_ASSET_KINDS.has(node.kind)) return;
        const host = nodeTargetHost(node);
        if (host.length === 0 || isLoopbackHost(host)) return;
        const publicScope = scopeDeclaresHost(model, host) && !isPrivateIpv4(host) && !isInternalDns(host);
        if (publicScope) return;
        const internalShape = isPrivateIpv4(host) || isInternalDns(host) || (!host.includes('.') && node.attrs?.realm === 'internal');
        if (fromPivotEdge === true || internalShape) dest.add(node.id);
      }
      const findingIds = new Set(nodes.filter((node) => node.kind === 'finding').map((node) => node.id));
      const bridgeIds = new Set(nodes.filter((node) => node.kind === 'access' || node.kind === 'pivot' || node.kind === 'credential').map((node) => node.id));
      const linked = new Set();
      for (const edge of edges) {
        if (edge.kind === 'pivots_to' || edge.kind === 'reached_via') consider(edge.to, true);
        if (findingIds.has(edge.from) && bridgeIds.has(edge.to)) linked.add(edge.to);
        if (findingIds.has(edge.to) && bridgeIds.has(edge.from)) linked.add(edge.from);
      }
      for (const edge of edges) {
        const bridge = bridgeIds.has(edge.from) ? edge.from : (bridgeIds.has(edge.to) ? edge.to : null);
        if (bridge === null || !linked.has(bridge)) continue;
        consider(bridge === edge.from ? edge.to : edge.from, edge.kind === 'pivots_to' || edge.kind === 'reached_via');
      }
      return dest;
    }

    function pathHeaderFor(role, t) {
      if (role === 'target') return t('graph.stage.target');
      if (role === 'service') return t('graph.stage.service');
      if (role === 'finding') return t('graph.stage.finding');
      if (role === 'credential') return t('kind.credential');
      if (role === 'access') return t('graph.stage.access');
      if (role === 'internal') return t('graph.stage.internal');
      if (role === 'data') return t('graph.stage.data');
      return t('graph.stage.other');
    }

    /**
     * Brief folds surface assets into a target card. Detailed keeps services and
     * credentials that sit on a hop. Columns follow path depth, and an internal
     * target is only a scoped internal address or a pivot destination.
     */
    function buildPathGraph(model, filtered, { detail = false, t }) {
      if (filtered === null) return null;
      const sourceNodes = filtered.visible;
      const sourceEdges = filtered.edges;
      const bySource = new Map(sourceNodes.map((node) => [node.id, node]));
      const internal = new Set(pivotAssetIds(sourceNodes, sourceEdges, model));
      for (const node of sourceNodes) {
        if (isScopeInternalAsset(node, model)) internal.add(node.id);
      }
      function namesOf(node) {
        const attrs = node?.attrs ?? {};
        const values = [attrs.host, attrs.hostname, attrs.ip, attrs.addr, attrs.fqdn, nodeTargetHost(node)];
        if (node?.kind === 'host' || node?.kind === 'ip' || node?.kind === 'access' || node?.kind === 'pivot') values.push(node.label);
        const found = [];
        for (const value of values) {
          const host = parseTargetHost(value);
          if (host.length > 0 && host !== 'null' && host !== 'unknown') found.push(host);
        }
        const ips = String(node?.label ?? '').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/gu) ?? [];
        return [...new Set(found.concat(ips))].filter((name) => /^(?:\d{1,3}\.){3}\d{1,3}$/u.test(name) || /^[a-z0-9.-]+\.[a-z]{2,}$/iu.test(name));
      }
      const webCounts = new Map();
      for (const node of sourceNodes) {
        if (node.kind !== 'webapp') continue;
        const host = nodeTargetHost(node);
        if (host.length === 0) continue;
        webCounts.set(host, (webCounts.get(host) || 0) + 1);
      }
      const allowHosts = [];
      for (const entry of model.scope?.allow ?? []) {
        const host = parseTargetHost(typeof entry === 'string' ? entry : (entry?.value ?? ''));
        if (host.length > 0) allowHosts.push(host);
      }
      let primaryHost = allowHosts[0] ?? '';
      let primaryCount = primaryHost.length > 0 ? Number.MAX_SAFE_INTEGER : -1;
      for (const [host, count] of webCounts) {
        if (primaryHost.length === 0 && count > primaryCount) {
          primaryHost = host;
          primaryCount = count;
        }
      }
      const lateralGroups = [];
      function rememberLateral(names, label) {
        const useful = names.filter((name) => {
          if (name === primaryHost || (primaryHost.length > 0 && name.endsWith(`.${primaryHost}`))) return false;
          return !allowHosts.some((host) => name === host || name.endsWith(`.${host}`));
        });
        if (useful.length === 0) return;
        let group = lateralGroups.find((item) => useful.some((name) => item.names.has(name)));
        if (group === undefined) {
          group = { key: `lateral:${useful[0]}`, names: new Set(), label: label || useful[0] };
          lateralGroups.push(group);
        }
        for (const name of useful) group.names.add(name);
        if (typeof label === 'string' && label.length > 0 && !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(label)) group.label = label;
      }
      for (const node of sourceNodes) {
        const reached = (node.kind === 'access' && ['validated', 'obtained', 'escalated', 'verified'].includes(String(node.status)))
          || (node.kind === 'pivot' && ['obtained', 'validated', 'verified', 'escalated'].includes(String(node.status)));
        if (!reached) continue;
        const attrs = node.attrs ?? {};
        rememberLateral(namesOf(node), String(attrs.hostname || attrs.host || attrs.ip || '').trim());
      }
      const lateralOf = new Map();
      for (const node of sourceNodes) {
        if (!TARGET_ASSET_KINDS.has(node.kind)) continue;
        const names = namesOf(node);
        const group = lateralGroups.find((item) => names.some((name) => item.names.has(name)));
        if (group === undefined) continue;
        lateralOf.set(node.id, group);
        internal.add(node.id);
      }
      const anchors = scopeDomainAnchors(model);
      const groupOf = new Map();
      const groups = new Map();
      function ensureGroup(key, label, internalTarget) {
        let group = groups.get(key);
        if (group === undefined) {
          group = { id: targetGroupId(`${internalTarget ? 'in:' : ''}${key}`), key, label, internalTarget, members: [] };
          groups.set(key, group);
        }
        return group;
      }
      const linkOf = new Map();
      for (const edge of sourceEdges) {
        if (!linkOf.has(edge.from)) linkOf.set(edge.from, []);
        if (!linkOf.has(edge.to)) linkOf.set(edge.to, []);
        linkOf.get(edge.from).push(edge.to);
        linkOf.get(edge.to).push(edge.from);
      }
      function namedGroupKey(node) {
        const host = nodeTargetHost(node);
        if (host.length === 0 || isTargetIp(host)) return '';
        return targetBaseKeyForHost(host, anchors);
      }
      for (const node of sourceNodes) {
        const surface = TARGET_ASSET_KINDS.has(node.kind) || node.kind === 'service' || node.kind === 'webapp' || node.kind === 'tech';
        if (!surface) continue;
        if (detail === true && (node.kind === 'service' || node.kind === 'webapp')) continue;
        if (internal.has(node.id) && TARGET_ASSET_KINDS.has(node.kind)) {
          const lateral = lateralOf.get(node.id);
          const host = lateral?.label || nodeTargetHost(node) || node.label;
          const key = lateral?.key || `internal:${host}`;
          const group = ensureGroup(key, host, true);
          if (lateral !== undefined) group.names = lateral.names;
          group.members.push(node.id);
          groupOf.set(node.id, group.id);
          continue;
        }
        const surfaceHost = nodeTargetHost(node);
        if (isTargetIp(surfaceHost) && TARGET_ASSET_KINDS.has(node.kind)) {
          const privateAddress = isPrivateIpv4(surfaceHost);
          const group = ensureGroup(privateAddress ? `internal:${surfaceHost}` : `ip:${surfaceHost}`, surfaceHost, privateAddress);
          group.members.push(node.id);
          groupOf.set(node.id, group.id);
          continue;
        }
        if (internal.has(node.id) || isTargetIp(surfaceHost) || !surfaceHost.includes('.')) continue;
        const key = namedGroupKey(node);
        if (key.length === 0) continue;
        const host = nodeTargetHost(node);
        const label = key.startsWith('name:') ? key.slice(5) : (key.startsWith('anchor:') ? key.slice(7) : (key.startsWith('zone:') ? key.slice(5) : host));
        const group = ensureGroup(key, label, false);
        group.members.push(node.id);
        groupOf.set(node.id, group.id);
      }
      for (const node of sourceNodes) {
        if (groupOf.has(node.id) || internal.has(node.id)) continue;
        if (detail === true && (node.kind === 'service' || node.kind === 'webapp' || node.kind === 'tech')) continue;
        const surface = TARGET_ASSET_KINDS.has(node.kind) || node.kind === 'service' || node.kind === 'webapp' || node.kind === 'tech';
        if (!surface) continue;
        let joined = null;
        const queue = [node.id];
        const seen = new Set(queue);
        for (let depth = 0; depth < 3 && queue.length > 0 && joined === null; depth += 1) {
          const next = [];
          for (const id of queue) {
            for (const neighbour of linkOf.get(id) ?? []) {
              if (seen.has(neighbour)) continue;
              seen.add(neighbour);
              if (groupOf.has(neighbour)) {
                const group = [...groups.values()].find((item) => item.id === groupOf.get(neighbour));
                if (group !== undefined && group.internalTarget !== true) {
                  joined = group;
                  break;
                }
              }
              next.push(neighbour);
            }
            if (joined !== null) break;
          }
          queue.splice(0, queue.length, ...next);
        }
        if (joined === null) continue;
        joined.members.push(node.id);
        groupOf.set(node.id, joined.id);
      }
      const candidate = new Set();
      for (const group of groups.values()) candidate.add(group.id);
      for (const node of sourceNodes) {
        if (groupOf.has(node.id)) continue;
        if (node.kind === 'finding' && node.includedVulnerability === true && node.refuted !== true) candidate.add(node.id);
        else if (node.kind === 'access' || node.kind === 'pivot' || node.kind === 'data') candidate.add(node.id);
        else if (detail === true && (node.kind === 'service' || node.kind === 'webapp' || node.kind === 'credential')) candidate.add(node.id);
      }
      const adjacency = new Map();
      for (const edge of sourceEdges) {
        if (!PATH_EDGE_KINDS.has(edge.kind)) continue;
        if (!adjacency.has(edge.from)) adjacency.set(edge.from, []);
        if (!adjacency.has(edge.to)) adjacency.set(edge.to, []);
        adjacency.get(edge.from).push(edge.to);
        adjacency.get(edge.to).push(edge.from);
      }
      function repOf(id) {
        if (groupOf.has(id)) return groupOf.get(id);
        return candidate.has(id) ? id : null;
      }
      const membersOf = new Map();
      for (const group of groups.values()) membersOf.set(group.id, group.members);
      const shortcuts = [];
      const seenShortcut = new Set();
      function pathRoleRank(id) {
        for (const group of groups.values()) {
          if (group.id !== id) continue;
          return group.internalTarget === true ? PATH_ROLE_ORDER.internal : PATH_ROLE_ORDER.target;
        }
        const kind = bySource.get(id)?.kind;
        if (kind === 'finding') return PATH_ROLE_ORDER.finding;
        if (kind === 'credential') return PATH_ROLE_ORDER.credential;
        if (kind === 'access' || kind === 'pivot') return PATH_ROLE_ORDER.access;
        if (kind === 'data') return PATH_ROLE_ORDER.data;
        if (kind === 'service' || kind === 'webapp') return PATH_ROLE_ORDER.service;
        return PATH_ROLE_ORDER.target;
      }
      for (const repId of candidate) {
        const seeds = membersOf.get(repId) ?? [repId];
        const queue = seeds.slice();
        const visited = new Set(seeds);
        while (queue.length > 0) {
          const current = queue.shift();
          for (const next of adjacency.get(current) ?? []) {
            if (visited.has(next)) continue;
            visited.add(next);
            const nextRep = repOf(next);
            if (nextRep !== null && nextRep !== repId) {
              const left = pathRoleRank(repId);
              const right = pathRoleRank(nextRep);
              const from = left <= right ? repId : nextRep;
              const to = left <= right ? nextRep : repId;
              const key = `${from}>${to}`;
              if (!seenShortcut.has(key)) {
                seenShortcut.add(key);
                shortcuts.push({
                  id: `path:${from}:${to}`,
                  from,
                  to,
                  kind: 'reached_via',
                  confidence: 1,
                  evidenceCount: 0,
                  attrs: { path: true },
                });
              }
              continue;
            }
            queue.push(next);
          }
        }
      }
      function addShortcut(from, to) {
        if (from === to || from === undefined || to === undefined) return;
        const key = `${from}>${to}`;
        if (seenShortcut.has(key)) return;
        seenShortcut.add(key);
        shortcuts.push({
          id: `path:${from}:${to}`,
          from,
          to,
          kind: 'reached_via',
          confidence: 1,
          evidenceCount: 0,
          attrs: { path: true },
        });
      }
      const externalGroups = [...groups.values()].filter((group) => group.internalTarget !== true);
      function hostOf(node) {
        const subject = String(node?.attrs?.subjectKey ?? '').trim();
        const candidates = [
          node?.attrs?.host,
          node?.attrs?.hostname,
          node?.attrs?.url,
          node?.sourceLabel,
          node?.label,
        ];
        if (subject.length > 0 && subject !== 'unknown' && subject !== 'null') candidates.unshift(subject);
        for (const value of candidates) {
          const host = parseTargetHost(value);
          if (host.length > 0 && host !== 'unknown' && host !== 'null') return host;
          const ip = String(value ?? '').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/u);
          if (ip !== null) return ip[0];
        }
        return '';
      }
      function bestParentForFinding(node) {
        const host = hostOf(node);
        const services = [...candidate]
          .map((id) => bySource.get(id))
          .filter((item) => item !== undefined && (item.kind === 'service' || item.kind === 'webapp'));
        const service = services.find((item) => host.length > 0 && hostOf(item) === host)
          ?? services.find((item) => host.length > 0 && hostOf(item).endsWith(`.${host}`));
        if (service !== undefined) return service.id;
        let best = null;
        let bestLen = -1;
        for (const group of externalGroups) {
          const label = String(group.label ?? '').toLowerCase();
          if (host.length === 0 || label.length === 0) continue;
          if (host === label || host.endsWith(`.${label}`) || label.endsWith(`.${host}`)) {
            if (label.length > bestLen) {
              best = group.id;
              bestLen = label.length;
            }
          }
        }
        return best ?? externalGroups[0]?.id;
      }
      function reachableFrom(roots) {
        const seen = new Set(roots.filter((id) => id !== undefined));
        const queue = [...seen];
        const nextOf = new Map();
        for (const edge of shortcuts) {
          if (!nextOf.has(edge.from)) nextOf.set(edge.from, []);
          if (!nextOf.has(edge.to)) nextOf.set(edge.to, []);
          nextOf.get(edge.from).push(edge.to);
          nextOf.get(edge.to).push(edge.from);
        }
        while (queue.length > 0) {
          const id = queue.shift();
          for (const next of nextOf.get(id) ?? []) {
            if (seen.has(next)) continue;
            seen.add(next);
            queue.push(next);
          }
        }
        return seen;
      }
      const placed = reachableFrom([
        ...externalGroups.map((group) => group.id),
        ...[...candidate].filter((id) => {
          const node = bySource.get(id);
          return node?.kind === 'service' || node?.kind === 'webapp';
        }),
      ]);
      for (const id of candidate) {
        const node = bySource.get(id);
        if (node?.kind !== 'finding' || placed.has(id)) continue;
        const parent = bestParentForFinding(node);
        if (parent !== undefined) addShortcut(parent, id);
      }
      function footholdHost(node) {
        const raw = String(node.attrs?.host ?? node.attrs?.target ?? '');
        const from = /\bfrom\s+([A-Za-z0-9._-]+)/iu.exec(raw);
        const host = (from !== null ? from[1] : raw.split(':')[0]).trim().toLowerCase();
        if (host.length === 0 || isLoopbackHost(host)) return '';
        if (scopeDeclaresHost(model, host) && !isPrivateIpv4(host) && !isInternalDns(host) && host.includes('.')) return '';
        if (host.includes('.') && !isPrivateIpv4(host) && !isInternalDns(host)) return '';
        return host;
      }
      const pivotFindingIds = [...candidate].filter((id) => {
        const node = bySource.get(id);
        if (node?.kind !== 'finding') return false;
        const type = node.findingType || findingTypeZh(node.attrs?.template, node.label);
        return type === '远程代码执行' || type === '任意文件读取' || type === 'SSRF' || type === '命令执行';
      });
      for (const id of [...candidate]) {
        const node = bySource.get(id);
        if (node === undefined || (node.kind !== 'access' && node.kind !== 'pivot')) continue;
        const parents = pivotFindingIds.length > 0 ? pivotFindingIds : externalGroups.slice(0, 1).map((group) => group.id);
        for (const parent of parents) addShortcut(parent, id);
        const names = namesOf(node);
        const lateral = lateralGroups.find((item) => names.some((name) => item.names.has(name)));
        if (lateral === undefined) continue;
        const group = ensureGroup(lateral.key, lateral.label, true);
        group.names = lateral.names;
        if (!candidate.has(group.id)) candidate.add(group.id);
        addShortcut(id, group.id);
      }
      const accessIds = [...candidate].filter((id) => {
        const node = bySource.get(id);
        return node?.kind === 'access' || node?.kind === 'pivot';
      });
      for (const id of candidate) {
        const node = bySource.get(id);
        if (node?.kind !== 'data') continue;
        const parents = accessIds.length > 0 ? accessIds : externalGroups.slice(0, 1).map((group) => group.id);
        for (const parent of parents) addShortcut(parent, id);
      }
      const outgoing = new Map();
      const incoming = new Map();
      for (const edge of shortcuts) {
        if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
        if (!incoming.has(edge.to)) incoming.set(edge.to, []);
        outgoing.get(edge.from).push(edge);
        incoming.get(edge.to).push(edge);
      }
      const groupById = new Map([...groups.values()].map((group) => [group.id, group]));
      const roots = [...candidate].filter((id) => {
        const group = groupById.get(id);
        return group !== undefined && group.internalTarget !== true && (incoming.get(id) ?? []).length === 0;
      });
      const start = roots.length > 0 ? roots : [...candidate].filter((id) => groupById.has(id));
      const depth = new Map();
      const queue = start.map((id) => ({ id, d: 0 }));
      for (const id of start) depth.set(id, 0);
      if (start.length === 0) {
        for (const id of candidate) depth.set(id, 0);
      }
      while (queue.length > 0) {
        const item = queue.shift();
        for (const edge of outgoing.get(item.id) ?? []) {
          if (depth.has(edge.to)) continue;
          depth.set(edge.to, item.d + 1);
          queue.push({ id: edge.to, d: item.d + 1 });
        }
      }
      for (const id of candidate) {
        const node = bySource.get(id);
        if (node?.kind !== 'finding' || depth.has(id)) continue;
        const parent = bestParentForFinding(node);
        if (parent === undefined) continue;
        const before = shortcuts.length;
        addShortcut(parent, id);
        if (shortcuts.length !== before) {
          if (!outgoing.has(parent)) outgoing.set(parent, []);
          outgoing.get(parent).push(shortcuts[shortcuts.length - 1]);
        }
        depth.set(id, (depth.get(parent) ?? 0) + 1);
      }
      for (let pass = 0; pass < 8; pass += 1) {
        for (const edge of shortcuts) {
          if (!depth.has(edge.from)) continue;
          const next = depth.get(edge.from) + 1;
          if ((depth.get(edge.to) ?? -1) < next) depth.set(edge.to, next);
        }
      }
      const phase = new Map();
      const phaseQueue = start.map((id) => ({ id, p: 0 }));
      for (const id of start) phase.set(id, 0);
      if (start.length === 0) {
        for (const id of candidate) phase.set(id, 0);
      }
      while (phaseQueue.length > 0) {
        const item = phaseQueue.shift();
        const leavingInternal = groupById.get(item.id)?.internalTarget === true;
        for (const edge of outgoing.get(item.id) ?? []) {
          const next = leavingInternal ? item.p + 1 : item.p;
          if (phase.has(edge.to) && phase.get(edge.to) <= next) continue;
          phase.set(edge.to, next);
          phaseQueue.push({ id: edge.to, p: next });
        }
      }
      const columnOf = (id, role) => (phase.get(id) ?? 0) * 10 + (PATH_ROLE_ORDER[role] ?? 9);
      function roleOf(id) {
        const group = groupById.get(id);
        if (group !== undefined) return group.internalTarget === true ? 'internal' : 'target';
        const node = bySource.get(id);
        if (node === undefined) return 'other';
        if (node.kind === 'finding') return 'finding';
        if (node.kind === 'access' || node.kind === 'pivot') return 'access';
        if (node.kind === 'credential') return 'credential';
        if (node.kind === 'data') return 'data';
        if (node.kind === 'service' || node.kind === 'webapp') return 'service';
        return 'other';
      }
      const visibleNodes = [];
      const visibleIds = new Set();
      for (const group of groups.values()) {
        if (!depth.has(group.id) && start.includes(group.id) === false && roots.length > 0) continue;
        const counts = { assets: 0, services: 0, findings: 0 };
        for (const id of group.members) {
          const node = bySource.get(id);
          if (node === undefined) continue;
          if (TARGET_ASSET_KINDS.has(node.kind)) counts.assets += 1;
          else if (node.kind === 'service' || node.kind === 'webapp' || node.kind === 'tech') counts.services += 1;
        }
        const role = group.internalTarget === true ? 'internal' : 'target';
        const node = {
          id: group.id,
          kind: 'target',
          key: group.key,
          label: group.label,
          status: 'unknown',
          confidence: 1,
          verification: 'verified',
          severity: null,
          crown: false,
          pathColumn: columnOf(group.id, role),
          pathHeader: pathHeaderFor(role, t),
          attrs: {
            targetGroup: true,
            internalTarget: group.internalTarget === true,
            members: group.members,
            counts,
            groupSummary: group.internalTarget === true
              ? pathHeaderFor('internal', t)
              : `${counts.assets} ${t('group.assets')} · ${counts.services} ${t('group.services')}`,
          },
          tags: ['target-group'],
          evidenceCount: 0,
          degree: group.members.length,
          adjDegree: group.members.length,
          firstSeen: null,
          lastSeen: null,
        };
        visibleNodes.push(node);
        visibleIds.add(node.id);
      }
      for (const id of candidate) {
        if (groupById.has(id) || !depth.has(id)) continue;
        const role = roleOf(id);
        if (PATH_ROLE_ORDER[role] === undefined) continue;
        const node = bySource.get(id);
        if (node === undefined) continue;
        visibleNodes.push({
          ...node,
          pathColumn: columnOf(id, role),
          pathHeader: pathHeaderFor(role, t),
        });
        visibleIds.add(id);
      }
      const edges = shortcuts.filter((edge) => visibleIds.has(edge.from) && visibleIds.has(edge.to));
      const edgeOut = new Map();
      const edgeIn = new Map();
      for (const edge of edges) {
        if (!edgeOut.has(edge.from)) edgeOut.set(edge.from, []);
        if (!edgeIn.has(edge.to)) edgeIn.set(edge.to, []);
        edgeOut.get(edge.from).push(edge);
        edgeIn.get(edge.to).push(edge);
      }
      const groupByNode = new Map();
      for (const group of groups.values()) {
        for (const id of group.members) groupByNode.set(id, group.id);
      }
      const byId = new Map(model.byId);
      for (const node of visibleNodes) byId.set(node.id, node);
      return {
        ...filtered,
        visible: visibleNodes,
        nodes: visibleNodes,
        edges,
        byId,
        outgoing: edgeOut,
        incoming: edgeIn,
        groupByNode,
        groupCount: groups.size,
        hiddenNodeCount: Math.max(0, sourceNodes.length - visibleNodes.length),
        targetGrouped: true,
      };
    }

    function layoutGraph(rendered, mode, t) {
      const usePath = rendered.nodes.some((node) => Number.isFinite(node.pathColumn));
      const columns = new Map();
      for (const node of rendered.nodes) {
        const column = usePath ? node.pathColumn : (mode === 'chain' ? chainColumnOf(node) : layeredColumnOf(node));
        let group = columns.get(column);
        if (group === undefined) {
          group = [];
          columns.set(column, group);
        }
        group.push(node);
      }
      for (const group of columns.values()) group.sort(mode === 'chain' ? sortChainColumn : sortLayeredColumn);
      const usedColumns = [...columns.keys()].sort((a, b) => a - b);
      const displayOf = new Map(usedColumns.map((column, index) => [column, index]));
      let maxRows = 0;
      for (const group of columns.values()) {
        if (group.length > maxRows) maxRows = group.length;
      }
      const rowHeight = maxRows > 10 ? 52 : (maxRows > 7 ? 56 : ROW_H);
      const positions = new Map();
      const positionedNodes = [];
      for (const column of usedColumns) {
        const group = columns.get(column);
        if (group === undefined) continue;
        const displayColumn = displayOf.get(column);
        for (let row = 0; row < group.length; row += 1) {
          const node = group[row];
          const x = PAD_X + displayColumn * COL_W;
          const y = PAD_Y + HEADER_H + row * rowHeight;
          positions.set(node.id, { x, y, column: displayColumn, stageColumn: column, row });
          positionedNodes.push({ node, x, y, column: displayColumn, stageColumn: column, row });
        }
      }
      const headers = usedColumns.map((column) => {
        let label;
        const sample = (columns.get(column) ?? [])[0];
        if (usePath && sample !== undefined && typeof sample.pathHeader === 'string') {
          label = sample.pathHeader;
        } else if (mode === 'chain') {
          label = chainHeaderLabel(column, t);
        } else if (column < LAYERED_COLUMNS.length) {
          label = t(LAYERED_COLUMNS[column].label);
        } else {
          label = t(OTHER_COLUMN.label);
        }
        const displayColumn = displayOf.get(column);
        return {
          column,
          displayColumn,
          label,
          count: (columns.get(column) ?? []).length,
          x: PAD_X + displayColumn * COL_W + NODE_W / 2,
          bandX: PAD_X + displayColumn * COL_W - 12,
          bandWidth: NODE_W + 24,
        };
      });
      const columnCount = usedColumns.length;
      const width = PAD_X * 2 + Math.max(1, columnCount - 1) * COL_W + NODE_W;
      const bodyTop = PAD_Y + HEADER_H;
      const bodyHeight = Math.max(1, maxRows) * rowHeight;
      const height = PAD_Y * 2 + HEADER_H + bodyHeight;
      const edgeViews = [];
      for (const edge of rendered.edges) {
        const source = positions.get(edge.from);
        const target = positions.get(edge.to);
        if (source === undefined || target === undefined) continue;
        let x1;
        let y1;
        let x2;
        let y2;
        let d;
        if (source.column === target.column) {
          x1 = source.x + NODE_W / 2;
          y1 = source.y + NODE_H;
          x2 = target.x + NODE_W / 2;
          y2 = target.y;
          const bend = Math.max(26, Math.abs(y2 - y1) * 0.34);
          const direction = y2 >= y1 ? 1 : -1;
          d = `M ${x1} ${y1} C ${x1} ${y1 + bend * direction}, ${x2} ${y2 - bend * direction}, ${x2} ${y2}`;
        } else {
          const forward = target.column > source.column;
          x1 = forward ? source.x + NODE_W : source.x;
          y1 = source.y + NODE_H / 2;
          x2 = forward ? target.x : target.x + NODE_W;
          y2 = target.y + NODE_H / 2;
          const distance = Math.abs(x2 - x1);
          const bend = Math.max(30, distance * 0.42);
          const sign = forward ? 1 : -1;
          d = `M ${x1} ${y1} C ${x1 + sign * bend} ${y1}, ${x2 - sign * bend} ${y2}, ${x2} ${y2}`;
        }
        edgeViews.push({
          edge,
          d,
          x1,
          y1,
          x2,
          y2,
          midX: (x1 + x2) / 2,
          midY: (y1 + y2) / 2 - 5,
        });
      }
      return {
        nodes: positionedNodes,
        edges: edgeViews,
        positions,
        headers,
        width,
        height,
        bodyTop,
        bodyHeight,
        columnCount,
        maxRows,
      };
    }

    function buildHighlight(model, selectedId) {
      const highlight = { selected: null, neighbors: new Set(), edges: new Set() };
      if (model === null || typeof selectedId !== 'string') return highlight;
      const node = model.byId.get(selectedId);
      if (node === undefined) return highlight;
      highlight.selected = node;
      highlight.neighbors.add(node.id);
      const incident = (model.outgoing.get(node.id) || []).concat(model.incoming.get(node.id) || []);
      for (const edge of incident) {
        highlight.edges.add(edge.id);
        highlight.neighbors.add(edge.from);
        highlight.neighbors.add(edge.to);
      }
      return highlight;
    }

    /** Adjacent edges of one node, both directions, with resolved neighbours. */
    function adjacentEdgesOf(model, nodeId) {
      if (model === null || typeof nodeId !== 'string') return [];
      const list = [];
      for (const edge of model.outgoing.get(nodeId) || []) {
        list.push({ edge, direction: 'out', neighbour: model.byId.get(edge.to) || null });
      }
      for (const edge of model.incoming.get(nodeId) || []) {
        list.push({ edge, direction: 'in', neighbour: model.byId.get(edge.from) || null });
      }
      list.sort((a, b) => {
        const rankA = EDGE_KIND_RANK[a.edge.kind] === undefined ? 99 : EDGE_KIND_RANK[a.edge.kind];
        const rankB = EDGE_KIND_RANK[b.edge.kind] === undefined ? 99 : EDGE_KIND_RANK[b.edge.kind];
        if (rankA !== rankB) return rankA - rankB;
        return a.edge.id.localeCompare(b.edge.id);
      });
      return list;
    }

    function nodeColor(node) {
      if (node === null || node === undefined) return KIND_COLOR.unknown;
      const shown = findingDisplaySeverity(node);
      if (shown !== null) return SEVERITY_COLOR[shown] || KIND_COLOR.finding;
      if (node.severity !== null && node.severity !== undefined) return SEVERITY_COLOR[node.severity] || KIND_COLOR.finding;
      return KIND_COLOR[node.kind] || KIND_COLOR.unknown;
    }

    /** Graph cards follow the CVSS band. The blended judgement stays in the detail pane. */
    function findingDisplaySeverity(node) {
      if (node === null || node === undefined || node.kind !== 'finding') return null;
      const cvss = String(node.cvssSeverity ?? '').toLowerCase();
      if (cvss.length > 0 && cvss !== 'unscored' && typeof node.cvssScore === 'number' && Number.isFinite(node.cvssScore)) return cvss;
      if (node.severity === null || node.severity === undefined) return null;
      return String(node.severity).toLowerCase();
    }

    function edgeLabelText(t, edge) {
      const kind = localized(t, 'edge', edge.kind);
      return t('graph.edgeLabel', { kind, confidence: Math.round(edge.confidence * 100) });
    }

    // ---------------------------------------------------------------------
    // Generic table sorting
    // ---------------------------------------------------------------------

    function sortValue(row, key) {
      const value = row.sortValues === undefined ? row[key] : row.sortValues[key];
      if (value === undefined || value === null) return '';
      return value;
    }

    function compareValues(a, b) {
      if (typeof a === 'number' && typeof b === 'number') return a - b;
      if (typeof a === 'number') return -1;
      if (typeof b === 'number') return 1;
      return String(a).localeCompare(String(b));
    }

    function sortRows(rows, sort, fallbackKey) {
      if (sort === null || sort === undefined) return rows;
      const key = sort.key === undefined ? fallbackKey : sort.key;
      if (key === undefined || key === null) return rows;
      const direction = sort.dir === 'desc' ? -1 : 1;
      return rows.slice().sort((a, b) => {
        const delta = compareValues(sortValue(a, key), sortValue(b, key));
        if (delta !== 0) return delta * direction;
        return compareValues(sortValue(a, 'label'), sortValue(b, 'label'));
      });
    }

    // ---------------------------------------------------------------------
    // Component-local styles (theme tokens only for chrome; palette for graph)
    // ---------------------------------------------------------------------

    const STYLE_TEXT = `
.atk-root{position:relative;display:flex;flex-direction:column;flex:1 1 auto;height:100%;min-height:0;overflow:hidden;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-family:var(--dsw-font-family);font-size:13px;line-height:1.4}
.atk-root *,.atk-root *::before,.atk-root *::after{box-sizing:border-box}
.atk-report-export{position:relative;display:flex;align-items:center;gap:5px}
.atk-report-menu{position:absolute;top:calc(100% + 5px);right:0;z-index:30;display:flex;flex-direction:column;min-width:150px;padding:4px;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-md);background:var(--dsw-alias-bg-layer-1);box-shadow:0 8px 20px rgba(0,0,0,.16)}
.atk-report-menu-item{border:0;border-radius:var(--dsw-radius-sm);background:transparent;color:var(--dsw-alias-label-primary);font:inherit;font-size:11px;text-align:left;padding:6px 8px;cursor:pointer}
.atk-report-menu-item:hover{background:var(--dsw-alias-interactive-bg-hover)}
.atk-report-error{font-size:9.5px;color:var(--dsw-alias-state-error-primary);max-width:160px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.atk-header{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:12px 16px 4px;flex:none}
.atk-heading{display:flex;flex-direction:column;gap:1px;min-width:0}
.atk-title{font-size:16px;font-weight:600;margin:0;color:var(--dsw-alias-label-primary)}
.atk-subtitle{font-size:11px;color:var(--dsw-alias-label-tertiary)}
.atk-badges{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-left:auto}
.atk-badge{display:inline-flex;align-items:center;gap:4px;max-width:260px;padding:2px 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-sm);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-secondary);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.atk-badge--ok{color:var(--dsw-alias-state-success-primary);border-color:var(--dsw-alias-state-success-secondary,var(--dsw-alias-border-l2))}
.atk-badge--warn{color:var(--dsw-alias-state-warn-label);border-color:var(--dsw-alias-state-warn-secondary,var(--dsw-alias-border-l2))}
.atk-badge--accent{color:var(--dsw-alias-state-business-primary);border-color:var(--dsw-alias-state-business-tertiary,var(--dsw-alias-border-l2))}
.atk-badge-strong{color:var(--dsw-alias-label-primary);font-weight:600}
.atk-status-row{display:flex;flex-wrap:wrap;align-items:center;gap:6px 14px;padding:2px 16px 4px;flex:none}
.atk-status-row .atk-stats,.atk-status-row .atk-proxy-strip{padding:0;border-top:0;flex:0 1 auto}
.atk-stats{display:flex;flex-wrap:wrap;gap:16px;padding:6px 16px 8px;flex:none}
.atk-stat{display:flex;flex-direction:column;min-width:44px}
.atk-stat-value{font-size:15px;font-weight:600;color:var(--dsw-alias-label-primary);font-variant-numeric:tabular-nums}
.atk-stat-label{font-size:10px;color:var(--dsw-alias-label-tertiary);white-space:nowrap}
.atk-stat--accent .atk-stat-value{color:var(--dsw-alias-state-business-primary)}
.atk-stat--danger .atk-stat-value{color:var(--dsw-alias-state-error-primary)}
.atk-stat{appearance:none;border:1px solid transparent;background:transparent;font:inherit;color:inherit;text-align:left;padding:3px 6px;margin:-3px -6px;border-radius:7px;cursor:pointer;transition:background .12s ease,border-color .12s ease}
.atk-stat:hover{border-color:var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-2)}

.atk-stat[aria-pressed="true"]{background:var(--dsw-alias-state-business-tertiary)}
.atk-stat:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:2px}
.atk-stat-detail-list{display:flex;flex-direction:column;gap:2px;max-height:360px;overflow:auto}
.atk-stat-detail-row{display:grid;grid-template-columns:54px minmax(0,1fr) auto;gap:6px;align-items:center;width:100%;padding:4px 6px;border:0;border-radius:var(--dsw-radius-sm);background:transparent;font:inherit;color:inherit;text-align:left;cursor:pointer}
.atk-stat-detail-row:hover{background:var(--dsw-alias-interactive-bg-hover)}
.atk-stat-detail-kind{font-size:9.5px;color:var(--dsw-alias-label-tertiary);white-space:nowrap}
.atk-stat-detail-label{font-size:11px;color:var(--dsw-alias-label-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.atk-stat-detail-state{font-size:9.5px;color:var(--dsw-alias-label-tertiary);white-space:nowrap}
.atk-proxy-strip{display:flex;flex-wrap:wrap;align-items:center;gap:5px 8px;padding:0 16px 8px;flex:none;border-top:1px solid var(--dsw-alias-border-l2);padding-top:6px}
.atk-proxy-title{font-size:10.5px;color:var(--dsw-alias-label-tertiary);font-weight:600;letter-spacing:.03em}
.atk-proxy-dot{width:8px;height:8px;border-radius:50%;flex:none}
.atk-proxy-dot--ok{background:var(--dsw-alias-state-success-primary)}
.atk-proxy-dot--pending{background:var(--dsw-alias-state-warn-label)}
.atk-proxy-dot--error{background:var(--dsw-alias-state-error-primary)}
.atk-proxy-dot--off{background:var(--dsw-alias-label-tertiary)}
.atk-proxy-main{font-size:11px;font-weight:600;color:var(--dsw-alias-label-primary)}
.atk-proxy-detail{font-size:9.5px;color:var(--dsw-alias-label-tertiary);white-space:nowrap}
.atk-proxy-note{font-size:9px;color:var(--dsw-alias-label-tertiary);opacity:.75;white-space:nowrap}
.atk-proxy-hint{font-size:9.5px;color:var(--dsw-alias-state-warn-label);max-width:420px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.atk-toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:6px 8px;padding:0 16px 8px;flex:none}
.atk-toolbar-group{display:inline-flex;align-items:center;gap:4px;min-height:28px}
.atk-toolbar-label{font-size:11px;color:var(--dsw-alias-label-tertiary)}
.atk-field,.atk-select,.atk-btn{min-height:30px;padding:5px 10px;border:1px solid color-mix(in srgb,var(--dsw-alias-label-tertiary) 32%,var(--dsw-alias-border-l2));border-radius:7px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);font-family:inherit;font-size:12px;font-weight:520}
.atk-field{min-width:200px;flex:1 1 220px;max-width:340px;background:var(--dsw-alias-bg-base)}
.atk-field::placeholder{color:var(--dsw-alias-label-tertiary)}
.atk-select{appearance:none;-webkit-appearance:none;padding-right:27px;background-color:var(--dsw-alias-bg-layer-1);background-image:linear-gradient(45deg,transparent 50%,var(--dsw-alias-label-tertiary) 50%),linear-gradient(135deg,var(--dsw-alias-label-tertiary) 50%,transparent 50%);background-position:calc(100% - 13px) 50%,calc(100% - 9px) 50%;background-size:5px 5px,5px 5px;background-repeat:no-repeat;cursor:pointer}
.atk-select:hover,.atk-field:hover{border-color:color-mix(in srgb,var(--dsw-alias-label-tertiary) 58%,var(--dsw-alias-border-l2))}
.atk-select:focus,.atk-field:focus{border-color:var(--dsw-alias-state-business-primary);box-shadow:0 0 0 2px color-mix(in srgb,var(--dsw-alias-state-business-primary) 16%,transparent);outline:none}
.atk-btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;cursor:pointer;white-space:nowrap;box-shadow:0 1px 1px rgba(15,23,42,.05),inset 0 1px 0 rgba(255,255,255,.35);transition:background .12s ease,border-color .12s ease,box-shadow .12s ease,transform .08s ease}
.atk-btn:hover{background:var(--dsw-alias-bg-layer-2);border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 45%,var(--dsw-alias-border-l2));box-shadow:0 2px 5px rgba(15,23,42,.08),inset 0 1px 0 rgba(255,255,255,.45)}
.atk-btn:active{transform:translateY(1px);box-shadow:inset 0 1px 2px rgba(15,23,42,.16)}
.atk-btn[aria-pressed="true"]{border-color:var(--dsw-alias-state-business-primary);background:color-mix(in srgb,var(--dsw-alias-state-business-primary) 14%,var(--dsw-alias-bg-layer-1));color:var(--dsw-alias-state-business-primary);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--dsw-alias-state-business-primary) 26%,transparent)}
.atk-btn:disabled{opacity:.42;cursor:not-allowed;transform:none;box-shadow:none}
.atk-btn-icon{width:30px;height:30px;min-height:30px;justify-content:center;padding:0;text-align:center;font-size:15px;line-height:1;border-radius:8px}
.atk-btn.atk-btn-primary{background:var(--dsw-alias-state-business-primary);border-color:var(--dsw-alias-state-business-primary);color:#fff;font-weight:650;box-shadow:0 2px 5px color-mix(in srgb,var(--dsw-alias-state-business-primary) 28%,transparent),inset 0 1px 0 rgba(255,255,255,.22)}
.atk-btn.atk-btn-primary:hover{background:color-mix(in srgb,var(--dsw-alias-state-business-primary) 88%,#000);border-color:var(--dsw-alias-state-business-primary);color:#fff;box-shadow:0 3px 8px color-mix(in srgb,var(--dsw-alias-state-business-primary) 34%,transparent)}
.atk-btn-ghost{background:transparent;border-color:color-mix(in srgb,var(--dsw-alias-label-tertiary) 38%,var(--dsw-alias-border-l2));box-shadow:none;color:var(--dsw-alias-label-secondary)}
.atk-btn-ghost:hover{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary)}
.atk-btn-seg{border-radius:6px}
.atk-btn-toggle{padding-left:8px;padding-right:9px}
.atk-btn-toggle::before{content:'';width:10px;height:10px;flex:none;border:1.5px solid color-mix(in srgb,var(--dsw-alias-label-tertiary) 65%,transparent);border-radius:3px;background:var(--dsw-alias-bg-layer-1);box-shadow:inset 0 0 0 1.5px var(--dsw-alias-bg-layer-1)}
.atk-btn-toggle[aria-pressed="true"]::before{background:var(--dsw-alias-state-business-primary);border-color:var(--dsw-alias-state-business-primary);box-shadow:inset 0 0 0 1.5px var(--dsw-alias-bg-layer-1)}
.atk-spacer{flex:1 1 auto}
.atk-body{display:flex;flex:1 1 auto;min-height:0;gap:0;padding:0 16px 6px}
.atk-graph-panel{display:flex;flex-direction:column;flex:1 1 auto;min-width:0;min-height:0;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-lg);background:var(--dsw-alias-bg-layer-1);overflow:hidden}
.atk-graph-panel:fullscreen,.atk-graph-panel:-webkit-full-screen{width:100%;height:100%;border:0;border-radius:0;background:var(--dsw-alias-bg-base)}
.atk-graph-head{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;padding:6px 10px;border-bottom:1px solid var(--dsw-alias-border-l2);color:var(--dsw-alias-label-tertiary);font-size:11px;flex:none}
.atk-graph-head-strong{color:var(--dsw-alias-label-secondary);font-weight:600}
.atk-graph-head-muted{color:var(--dsw-alias-label-tertiary);font-size:10.5px}
.atk-canvas{position:relative;flex:1 1 auto;min-height:0;overflow:hidden;cursor:grab;touch-action:none;user-select:none;-webkit-user-select:none;overscroll-behavior:contain;background:linear-gradient(180deg,color-mix(in srgb,var(--dsw-alias-bg-layer-2) 62%,var(--dsw-alias-bg-base)) 0%,var(--dsw-alias-bg-layer-1) 100%)}
.atk-canvas--dragging{cursor:grabbing}
.atk-svg{display:block;width:100%;height:100%}
.atk-graph-grid{pointer-events:none;opacity:.55}
.atk-graph-paper{pointer-events:none;opacity:.9}
.atk-stages{pointer-events:none}
.atk-stage-pill{fill:var(--dsw-alias-bg-layer-1);stroke:var(--dsw-alias-border-l2);stroke-width:1}
.atk-stage-label{font-size:10px;font-weight:650;fill:var(--dsw-alias-label-secondary);letter-spacing:.06em;pointer-events:none}
.atk-stage-count{fill:var(--dsw-alias-label-tertiary);font-weight:500;letter-spacing:0}
.atk-node{cursor:pointer;outline:none}
.atk-node-card{fill:var(--dsw-alias-bg-layer-1);stroke:var(--atk-node-accent,var(--dsw-alias-border-l2));stroke-width:1.4}
.atk-node:hover .atk-node-card{stroke:var(--atk-node-accent,var(--dsw-alias-state-business-primary));stroke-width:2}
.atk-node--selected .atk-node-card{stroke:var(--atk-node-accent,var(--dsw-alias-state-business-primary));stroke-width:2.6;fill:var(--dsw-alias-bg-layer-2)}
.atk-node:focus-visible .atk-node-card{stroke:var(--atk-node-accent,var(--dsw-alias-state-business-primary));stroke-width:2.4}
.atk-node-dot{pointer-events:none}
.atk-node-label{font-size:11px;font-weight:600;fill:var(--dsw-alias-label-primary);pointer-events:none}
.atk-node:hover .atk-node-label,.atk-node--selected .atk-node-label{fill:var(--dsw-alias-state-business-primary)}
.atk-node-kind{font-size:8.8px;fill:var(--dsw-alias-label-tertiary);pointer-events:none}
.atk-node-crown{font-size:9px;fill:var(--dsw-alias-state-warn-label);pointer-events:none}
.atk-node-hit{fill:transparent;stroke:none;pointer-events:all}
.atk-edge{fill:none;stroke-linecap:round;stroke-linejoin:round;pointer-events:none}
.atk-edge-hit{fill:none;stroke:transparent;stroke-width:13;cursor:pointer;pointer-events:stroke}
.atk-edge--flowing{stroke-dasharray:6 7;animation:atk-edge-dash 1.15s linear infinite}
@keyframes atk-edge-dash{to{stroke-dashoffset:-26}}
.atk-edge-glow{fill:none;stroke:var(--dsw-alias-state-business-primary);stroke-width:5;stroke-opacity:.12;stroke-linecap:round;pointer-events:none}
.atk-edge-label{font-size:9px;fill:var(--dsw-alias-label-secondary);stroke:var(--dsw-alias-bg-layer-1);stroke-width:3.5;paint-order:stroke;stroke-linejoin:round;pointer-events:none}
.atk-legend{display:flex;flex-wrap:wrap;align-items:center;gap:4px 12px;padding:6px 10px;border-top:1px solid var(--dsw-alias-border-l2);font-size:10.5px;color:var(--dsw-alias-label-secondary);flex:none}
.atk-legend-title{font-weight:600;color:var(--dsw-alias-label-tertiary)}
.atk-legend-item{display:inline-flex;align-items:center;gap:4px;white-space:nowrap}
.atk-legend-note{color:var(--dsw-alias-label-tertiary);flex:1 1 240px;min-width:160px}
.atk-dot{display:inline-block;width:8px;height:8px;border-radius:2px;flex:none}
.atk-detail--finding{width:430px}
.atk-finding-actions{display:flex;align-items:center;gap:6px;margin-left:auto;flex:none}
.atk-finding-pills{display:flex;flex-wrap:wrap;gap:5px}
.atk-finding-pill{display:inline-flex;align-items:center;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;padding:2px 8px;font-size:9.5px;font-weight:600;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-base);white-space:nowrap}
.atk-finding-pill--critical{background:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary);color:#fff}
.atk-finding-pill--high{background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 16%,transparent);border-color:var(--dsw-alias-state-error-primary);color:var(--dsw-alias-state-error-primary)}
.atk-finding-pill--medium{background:color-mix(in srgb,var(--dsw-alias-state-warn-label) 16%,transparent);border-color:var(--dsw-alias-state-warn-label);color:var(--dsw-alias-state-warn-label)}
.atk-finding-pill--low{background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 14%,transparent);border-color:var(--dsw-alias-state-success-primary);color:var(--dsw-alias-state-success-primary)}
.atk-finding-pill--info{background:color-mix(in srgb,var(--dsw-alias-state-business-primary) 12%,transparent);border-color:var(--dsw-alias-state-business-primary);color:var(--dsw-alias-state-business-primary)}
.atk-finding-pill--status{color:var(--dsw-alias-state-success-primary);border-color:var(--dsw-alias-state-success-primary)}
.atk-finding-pill--ok{color:var(--dsw-alias-state-success-primary);border-color:var(--dsw-alias-state-success-primary)}
.atk-finding-pill--bad{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}
.atk-finding-pill--muted{color:var(--dsw-alias-label-tertiary)}
.atk-finding-pill--rating{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}
.atk-finding-pill--category{font-family:var(--font-mono);font-weight:500}
.atk-finding-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(112px,1fr));gap:6px;margin:8px 0 2px}
.atk-fact{display:flex;flex-direction:column;gap:2px;padding:7px 9px;border:1px solid var(--dsw-alias-border-l2);border-radius:7px;background:var(--dsw-alias-bg-layer-1)}
.atk-fact-label{font-size:9px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--dsw-alias-label-tertiary)}
.atk-fact-value{font-size:11px;font-weight:600;color:var(--dsw-alias-label-primary);word-break:break-all}
.atk-finding-section{display:flex;flex-direction:column;gap:6px;border:1px solid var(--dsw-alias-border-l2);border-radius:8px;padding:10px 12px;background:var(--dsw-alias-bg-layer-1)}
.atk-finding-section--overview{background:color-mix(in srgb,var(--dsw-alias-state-warn-label) 6%,var(--dsw-alias-bg-layer-1))}


.atk-finding-section--verify{background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 5%,var(--dsw-alias-bg-layer-1))}
.atk-finding-section--original{background:var(--dsw-alias-bg-base)}
.atk-finding-section h4{margin:0;font-size:11.5px;font-weight:700;letter-spacing:.03em;color:var(--dsw-alias-label-primary)}
.atk-finding-section p{margin:0;font-size:11px;line-height:1.65;color:var(--dsw-alias-label-secondary);white-space:pre-wrap;word-break:break-word}
.atk-detail-callout{display:flex;gap:6px;align-items:flex-start;padding:6px 8px;border:1px dashed var(--dsw-alias-border-l2);border-radius:6px;font-size:10px;line-height:1.5;color:var(--dsw-alias-label-tertiary);background:var(--dsw-alias-bg-base)}
.atk-original-block{display:flex;flex-direction:column;gap:5px;font-size:10.5px;line-height:1.6;color:var(--dsw-alias-label-secondary);white-space:pre-wrap}
.atk-original-label{font-size:9.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--dsw-alias-label-tertiary)}
.atk-packet-body .atk-http-method{color:var(--dsw-alias-state-business-primary);font-weight:700}
.atk-packet-body .atk-http-path{color:var(--dsw-alias-label-primary);font-weight:600}
.atk-packet-body .atk-http-version{color:var(--dsw-alias-label-tertiary)}
.atk-packet-body .atk-http-status{font-weight:700}
.atk-packet-body .atk-http-status--ok{color:var(--dsw-alias-state-success-primary)}
.atk-packet-body .atk-http-status--warn{color:var(--dsw-alias-state-warn-label)}
.atk-packet-body .atk-http-header{color:var(--dsw-alias-state-success-primary);font-weight:600}
.atk-packet-body .atk-http-value{color:var(--dsw-alias-label-primary)}
.atk-packet-body .atk-http-hit{background:color-mix(in srgb,var(--dsw-alias-state-warn-label) 26%,transparent);color:var(--dsw-alias-state-warn-label);border-radius:2px;padding:0 2px;font-weight:600}

.atk-finding-repro{max-height:180px;overflow:auto;padding:6px 8px;border-radius:var(--dsw-radius-sm);background:var(--dsw-alias-bg-base);border:1px solid var(--dsw-alias-border-l3);font-size:10px}
.atk-packet{border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-sm);overflow:hidden;background:var(--dsw-alias-bg-base)}
.atk-packet-head{padding:4px 9px;font-size:9.5px;font-weight:600;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-1);border-bottom:1px solid var(--dsw-alias-border-l2)}
.atk-packet-body{margin:0;padding:8px 10px;max-height:260px;overflow:auto;font-family:var(--font-mono);font-size:10px;line-height:1.55;color:var(--dsw-alias-label-primary);white-space:pre-wrap;word-break:break-word}
.atk-packet-empty{padding:8px 10px;font-size:10px;color:var(--dsw-alias-label-tertiary)}
.atk-node--target .atk-node-card{stroke-width:1.8;fill:color-mix(in srgb,var(--dsw-alias-bg-layer-1) 88%,var(--atk-node-accent) 12%)}
.atk-node--target .atk-node-label{font-weight:700}
.atk-target-detail{width:min(780px,90vw)}
.atk-target-counts{display:flex;flex-wrap:wrap;gap:6px}
.atk-target-count{display:inline-flex;align-items:baseline;gap:4px;padding:3px 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;background:var(--dsw-alias-bg-layer-2);font-size:10px;color:var(--dsw-alias-label-tertiary)}
.atk-target-count b{font-size:13px;color:var(--dsw-alias-label-primary);font-variant-numeric:tabular-nums}
.atk-target-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.atk-target-member-list{display:flex;flex-direction:column;gap:2px;max-height:340px;overflow:auto;padding-right:2px}
.atk-target-member{display:grid;grid-template-columns:72px minmax(0,1fr) auto auto;align-items:center;gap:7px;width:100%;padding:5px 7px;border:1px solid transparent;border-radius:6px;background:transparent;color:var(--dsw-alias-label-primary);font:inherit;font-size:11px;text-align:left;cursor:pointer}
.atk-target-member:hover{background:var(--dsw-alias-bg-layer-2);border-color:var(--dsw-alias-border-l2)}
.atk-target-member-kind{color:var(--dsw-alias-label-tertiary);font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.atk-target-member-label{font-weight:550;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.atk-target-member-sev{font-size:9px;font-weight:700;padding:1px 5px;border-radius:999px;border:1px solid currentColor}
.atk-target-member-sev--critical{color:var(--dsw-alias-state-error-primary)}
.atk-target-member-sev--high{color:var(--dsw-alias-state-warn-label)}
.atk-target-member-status{font-size:9.5px;color:var(--dsw-alias-label-tertiary);white-space:nowrap}
@media (max-width:640px){.atk-target-member{grid-template-columns:58px minmax(0,1fr) auto}.atk-target-member-status{display:none}}
.atk-detail{display:flex;flex-direction:column;gap:8px;width:344px;flex:none;min-height:0;overflow:auto;padding:10px 12px;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-lg);background:var(--dsw-alias-bg-layer-1)}
.atk-detail-head{display:flex;align-items:flex-start;gap:8px}
.atk-detail-title{font-size:13px;font-weight:600;margin:0;word-break:break-word;color:var(--dsw-alias-label-primary)}
.atk-detail-close{margin-left:auto;flex:none}
.atk-detail-section{display:flex;flex-direction:column;gap:4px;border-top:1px solid var(--dsw-alias-border-l3);padding-top:8px}
.atk-detail-section-title{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:600;color:var(--dsw-alias-label-tertiary);margin:0}
.atk-kv{display:grid;grid-template-columns:minmax(74px,102px) minmax(0,1fr);gap:2px 8px;margin:0;font-size:11.5px}
.atk-kv dt{color:var(--dsw-alias-label-tertiary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.atk-kv dd{margin:0;color:var(--dsw-alias-label-primary);word-break:break-word;min-width:0}
.atk-kv-mono{font-family:var(--dsw-font-mono);font-size:10.5px}
.atk-tags{display:flex;flex-wrap:wrap;gap:4px}
.atk-tag{padding:1px 6px;border-radius:var(--dsw-radius-xs,4px);background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l3);color:var(--dsw-alias-label-secondary);font-size:10px}
.atk-attr-list{display:flex;flex-direction:column;gap:6px}
.atk-attr-row{display:flex;flex-direction:column;gap:1px}
.atk-attr-key{font-family:var(--dsw-font-mono);font-size:10px;color:var(--dsw-alias-label-tertiary)}
.atk-attr-value{font-size:11.5px;color:var(--dsw-alias-label-primary);word-break:break-word;white-space:pre-wrap}
.atk-collapse{border:1px solid var(--dsw-alias-border-l3);border-radius:var(--dsw-radius-sm);padding:4px 8px;background:var(--dsw-alias-bg-layer-2)}
.atk-collapse summary{cursor:pointer;font-size:11px;color:var(--dsw-alias-label-secondary)}
.atk-json{width:100%;min-height:96px;resize:vertical;margin-top:6px;padding:6px;border:1px solid var(--dsw-alias-border-l3);border-radius:var(--dsw-radius-sm);background:var(--dsw-alias-markdown-code-block);color:var(--dsw-alias-label-secondary);font-family:var(--dsw-font-mono);font-size:10px;line-height:1.35}
.atk-edge-list{display:flex;flex-direction:column;gap:1px}
.atk-edge-item{display:flex;align-items:baseline;gap:6px;width:100%;padding:3px 4px;border:0;border-radius:var(--dsw-radius-xs,4px);background:transparent;color:var(--dsw-alias-label-primary);font-family:inherit;font-size:11px;text-align:left;cursor:pointer}
.atk-edge-item:hover{background:var(--dsw-alias-interactive-bg-hover)}
.atk-edge-dir{font-size:10px;color:var(--dsw-alias-label-tertiary);flex:none}
.atk-edge-kind{font-weight:500;flex:none}
.atk-edge-conf{color:var(--dsw-alias-label-tertiary);flex:none;font-size:10px}
.atk-edge-neighbour{color:var(--dsw-alias-state-business-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.atk-detail-actions{display:flex;flex-wrap:wrap;gap:6px}
.atk-live{position:absolute;width:1px;height:1px;margin:-1px;padding:0;border:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.atk-settings{display:flex;flex-direction:column;gap:12px;flex:1 1 auto;min-height:0;overflow:auto;padding:4px 2px 12px}
.atk-settings-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}
.atk-settings-head h3{margin:0;font-size:15px;color:var(--dsw-alias-label-primary)}
.atk-settings-section{border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-md);background:var(--dsw-alias-bg-layer-1);padding:10px 12px}
.atk-settings-section-head{display:flex;align-items:baseline;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.atk-settings-section-head h4{margin:0;font-size:12px;color:var(--dsw-alias-label-primary)}
.atk-settings-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px}
.atk-settings-card{border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-sm);padding:8px 9px;background:var(--dsw-alias-bg-base);min-width:0}
.atk-settings-card--ok{border-color:color-mix(in srgb,var(--dsw-alias-state-success-primary) 45%,var(--dsw-alias-border-l2))}
.atk-settings-card--error{border-color:color-mix(in srgb,var(--dsw-alias-state-error-primary) 50%,var(--dsw-alias-border-l2))}
.atk-settings-card--warn{border-color:color-mix(in srgb,var(--dsw-alias-state-warn-label) 50%,var(--dsw-alias-border-l2))}
.atk-settings-card-head{display:flex;align-items:center;justify-content:space-between;gap:6px;margin-bottom:5px}
.atk-settings-card-head strong{font-size:11px;color:var(--dsw-alias-label-primary)}
.atk-settings-status{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:600}
.atk-settings-status--ok{color:var(--dsw-alias-state-success-primary)}
.atk-settings-status--bad{color:var(--dsw-alias-state-error-primary)}
.atk-settings-dot{width:7px;height:7px;border-radius:50%;flex:none;background:var(--dsw-alias-state-error-primary)}
.atk-settings-dot--ok{background:var(--dsw-alias-state-success-primary)}
.atk-settings-dot--warn{background:var(--dsw-alias-state-warn-label)}
.atk-settings-line{font-size:9.5px;color:var(--dsw-alias-label-tertiary);line-height:1.5;word-break:break-word}
.atk-settings-error{color:var(--dsw-alias-state-error-primary);font-size:10.5px}
.atk-settings-notice{color:var(--dsw-alias-state-success-primary);font-size:10.5px}
.atk-settings-proxy{display:flex;flex-direction:column;gap:7px}
.atk-settings-proxy-state{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:10.5px;color:var(--dsw-alias-label-secondary)}
.atk-settings-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:6px}
.atk-settings-field{display:flex;flex-direction:column;gap:2px;font-size:9px;color:var(--dsw-alias-label-tertiary)}
.atk-settings-field input,.atk-settings-field select{height:24px;padding:0 6px;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-sm);background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-size:10px;min-width:0}
.atk-settings-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.atk-settings-survey-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:8px}
.atk-settings-survey{border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-sm);padding:8px;display:flex;flex-direction:column;gap:5px;background:var(--dsw-alias-bg-base)}
.atk-settings-survey-head{display:flex;align-items:center;justify-content:space-between;gap:6px;font-size:11px;color:var(--dsw-alias-label-primary)}
.atk-settings-check{display:flex;align-items:center;gap:4px;font-size:9.5px;color:var(--dsw-alias-label-tertiary)}
.atk-settings-test{font-size:9.5px;line-height:1.4;color:var(--dsw-alias-label-tertiary)}
.atk-settings-test.ok{color:var(--dsw-alias-state-success-primary)}
.atk-settings-test.error{color:var(--dsw-alias-state-error-primary)}
.atk-loop{display:flex;flex-direction:column;gap:10px;flex:1 1 auto;min-height:0;overflow:auto;padding:2px 2px 8px}
.atk-loop-section{display:flex;flex-direction:column;gap:6px;flex:none;padding:8px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-md);background:var(--dsw-alias-bg-layer-1)}
.atk-coverage-duties{display:flex;flex-direction:column;gap:4px;margin:8px 0}
.atk-coverage-duties .atk-selftteam-line-label{min-width:72px}
.atk-coverage-grid{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 2px}
.atk-coverage-cell{display:flex;align-items:center;gap:6px;max-width:100%;padding:4px 8px;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-sm);background:var(--dsw-alias-bg-layer-1);font-size:10px}
.atk-coverage-cell strong{font-weight:600;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.atk-coverage-class{color:var(--dsw-alias-label-tertiary);font-size:9px}
.atk-loop-section-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.atk-loop-section-title{margin:0;font-size:12px;font-weight:600;color:var(--dsw-alias-label-secondary)}
.atk-loop-subtitle{margin:4px 0 0;font-size:11px;font-weight:600;color:var(--dsw-alias-label-tertiary)}
.atk-loop-body{display:flex;flex-direction:column;gap:6px}
.atk-loop-text{margin:0;font-size:11.5px;color:var(--dsw-alias-label-primary);white-space:pre-wrap;word-break:break-word}
.atk-loop-meta{display:flex;flex-wrap:wrap;gap:4px 10px;font-size:11px;color:var(--dsw-alias-label-tertiary)}
.atk-loop-chips{display:flex;flex-wrap:wrap;align-items:center;gap:4px}
.atk-loop-chip-label{font-size:10.5px;color:var(--dsw-alias-label-tertiary)}
.atk-loop-section .atk-table-wrap{max-height:260px}
.atk-selftteam-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:6px}
.atk-selftteam-card{display:flex;flex-direction:column;gap:5px;padding:7px 8px;border:1px solid var(--dsw-alias-border-l3);border-radius:var(--dsw-radius-sm);background:var(--dsw-alias-bg-layer-2)}
.atk-selftteam-card-head{display:flex;align-items:center;justify-content:space-between;gap:6px;font-size:11.5px;color:var(--dsw-alias-label-primary)}
.atk-selftteam-card .atk-kv{grid-template-columns:auto minmax(0,1fr)}
.atk-selftteam-brief{display:flex;flex-direction:column;gap:5px;padding:7px 8px;border:1px solid var(--dsw-alias-border-l3);border-radius:var(--dsw-radius-sm);background:var(--dsw-alias-bg-layer-2)}
.atk-selftteam-brief-head{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:11.5px;color:var(--dsw-alias-label-primary)}
.atk-selftteam-lines{display:flex;flex-direction:column;gap:3px}
.atk-selftteam-line{display:flex;gap:6px;font-size:11px;color:var(--dsw-alias-label-secondary);word-break:break-word}
.atk-selftteam-line-label{flex:none;color:var(--dsw-alias-label-tertiary);min-width:48px}
.atk-notice{display:flex;align-items:center;gap:6px;padding:4px 8px;border-radius:var(--dsw-radius-sm);font-size:11px;color:var(--dsw-alias-state-warn-label);background:var(--dsw-alias-state-warn-tertiary,transparent)}
.atk-notice--info{color:var(--dsw-alias-label-secondary)}
.atk-activity{position:absolute;top:10px;left:10px;z-index:4;display:flex;align-items:center;gap:7px;max-width:min(560px,calc(100% - 20px));padding:7px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;background:color-mix(in srgb,var(--dsw-alias-bg-layer-1) 88%,transparent);box-shadow:0 3px 14px rgba(0,0,0,.08);pointer-events:none;backdrop-filter:blur(6px)}
.atk-activity-pulse{width:8px;height:8px;border-radius:50%;flex:none;background:var(--dsw-alias-state-business-primary);box-shadow:0 0 0 0 color-mix(in srgb,var(--dsw-alias-state-business-primary) 55%,transparent);animation:atk-activity-pulse 1.6s ease-out infinite}
@keyframes atk-activity-pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--dsw-alias-state-business-primary) 45%,transparent)}70%{box-shadow:0 0 0 8px transparent}100%{box-shadow:0 0 0 0 transparent}}
.atk-activity-title{font-size:9px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--dsw-alias-label-tertiary);white-space:nowrap}
.atk-activity-text{font-size:11px;font-weight:650;color:var(--dsw-alias-label-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.atk-flow-dot{filter:drop-shadow(0 0 3px color-mix(in srgb,var(--dsw-alias-state-business-primary) 70%,transparent))}
.atk-node--active .atk-node-card{animation:atk-node-active 1.8s ease-in-out infinite}
@keyframes atk-node-active{0%,100%{stroke-width:1.6}50%{stroke-width:3.2}}
.atk-modal-layer{position:absolute;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;padding:24px;background:rgba(10,12,16,.42);backdrop-filter:blur(2px);overflow:auto}
.atk-modal{width:min(920px,92vw);max-height:88vh;overflow:auto;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-lg);background:var(--dsw-alias-bg-layer-1);box-shadow:0 24px 80px rgba(0,0,0,.28)}
.atk-modal .atk-detail,.atk-modal .atk-detail--finding{width:100%;max-height:none;border:0;border-radius:0;background:transparent;padding:14px 18px 18px}
.atk-modal .atk-stat-detail{width:100%}
.atk-modal .atk-detail-head{position:sticky;top:0;z-index:1;background:var(--dsw-alias-bg-layer-1);padding-bottom:6px}
@media (max-width:920px){.atk-modal-layer{padding:8px}.atk-modal{width:100%;max-height:94vh}}
.atk-project-id{display:inline-flex;align-items:center;user-select:text;-webkit-user-select:text;cursor:text}
.atk-project-id .atk-badge{max-width:none;user-select:text;-webkit-user-select:text;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.atk-targets{display:flex;flex-direction:column;gap:8px;flex:1 1 auto;min-height:0;overflow:auto;padding:2px 2px 8px}
.atk-target-summary{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;padding:8px 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-md);background:var(--dsw-alias-bg-layer-1)}
.atk-target-summary-title{font-size:12px;font-weight:650;color:var(--dsw-alias-label-primary)}
.atk-target-pill{font-size:11px;color:var(--dsw-alias-label-secondary)}
.atk-target-gap{font-size:10.5px;color:var(--dsw-alias-state-warn-label)}
.atk-target-table-wrap{flex:1 1 auto;min-height:120px}
.atk-target-table td{white-space:nowrap}
.atk-target-cluster td{background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-secondary);font-weight:600;border-top:1px solid var(--dsw-alias-border-l2)}
.atk-target-cluster-note{font-size:10px;font-weight:500;color:var(--dsw-alias-label-tertiary)}
.atk-target-row td:first-child{padding-left:22px}
.atk-target-name{font-weight:600;color:var(--dsw-alias-label-primary)}
.atk-target-status{display:inline-flex;padding:1px 6px;border-radius:999px;border:1px solid var(--dsw-alias-border-l2);font-size:10px;font-weight:600}
.atk-target-status--tested{color:var(--dsw-alias-state-success-primary);border-color:var(--dsw-alias-state-success-primary)}
.atk-target-status--recon{color:var(--dsw-alias-state-warn-label);border-color:var(--dsw-alias-state-warn-label)}
.atk-target-status--untested{color:var(--dsw-alias-label-tertiary)}
.atk-target-status--impacted{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}
.atk-lower{display:flex;flex-direction:column;flex:0 0 auto;max-height:none;min-height:0;gap:4px;padding:0 16px 8px;overflow:hidden}
.atk-lower--expanded{max-height:30vh;overflow:auto}
.atk-lower-head{display:flex;align-items:center;gap:8px;min-width:0}
.atk-lower-head .atk-tabs{flex:1 1 auto;min-width:0}
.atk-lower-toggle{flex:none;font-size:10px;padding:3px 7px;min-height:24px}
.atk-tabs{display:flex;gap:4px;overflow-x:auto;border-bottom:0;flex:none;scrollbar-width:thin;padding:2px 0}
.atk-tab{display:inline-flex;align-items:center;gap:5px;padding:5px 10px;border:1px solid transparent;border-radius:7px;background:transparent;color:var(--dsw-alias-label-secondary);font-family:inherit;font-size:12px;font-weight:520;white-space:nowrap;cursor:pointer;transition:background .12s ease,border-color .12s ease}
.atk-tab:hover{color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-layer-2);border-color:var(--dsw-alias-border-l2)}
.atk-tab[aria-selected="true"]{color:var(--dsw-alias-state-business-primary);background:color-mix(in srgb,var(--dsw-alias-state-business-primary) 13%,var(--dsw-alias-bg-layer-1));border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 55%,var(--dsw-alias-border-l2));box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--dsw-alias-state-business-primary) 18%,transparent)}
.atk-tab-count{padding:0 4px;border-radius:999px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-tertiary);font-size:10px;font-variant-numeric:tabular-nums}
.atk-table-wrap{flex:1 1 auto;min-height:0;overflow:auto;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-md);background:var(--dsw-alias-bg-layer-1)}
.atk-table{width:100%;border-collapse:collapse;font-size:11.5px}
.atk-table thead th{position:sticky;top:0;z-index:1;background:var(--dsw-alias-bg-layer-2);border-bottom:1px solid var(--dsw-alias-border-l2);color:var(--dsw-alias-label-tertiary);font-weight:600;text-align:left;white-space:nowrap}
.atk-table td,.atk-table th{padding:4px 8px;border-bottom:1px solid var(--dsw-alias-border-l3);vertical-align:top}
.atk-table tbody tr{cursor:pointer}
.atk-table tbody tr:hover td{background:var(--dsw-alias-interactive-bg-hover)}
.atk-table tbody tr[aria-selected="true"] td{background:var(--dsw-alias-state-business-tertiary)}
.atk-table td{color:var(--dsw-alias-label-primary);max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.atk-table td.atk-cell-wrap{white-space:normal}
.atk-sort{display:inline-flex;align-items:center;gap:3px;padding:2px 5px;margin:-2px -5px;border:1px solid transparent;border-radius:5px;background:transparent;color:inherit;font:inherit;font-weight:600;cursor:pointer}
.atk-sort:hover{background:var(--dsw-alias-bg-layer-1);border-color:var(--dsw-alias-border-l2)}
.atk-sort:hover{color:var(--dsw-alias-label-primary)}
.atk-sort-arrow{font-size:9px;color:var(--dsw-alias-state-business-primary)}
.atk-empty{display:flex;flex:1 1 auto;flex-direction:column;align-items:center;justify-content:center;gap:6px;min-height:150px;padding:26px 20px;text-align:center}
.atk-empty-title{font-size:13px;font-weight:600;color:var(--dsw-alias-label-secondary)}
.atk-empty-hint{font-size:11.5px;color:var(--dsw-alias-label-tertiary);max-width:520px}
.atk-empty-instructions{font-size:11.5px;color:var(--dsw-alias-label-secondary);max-width:560px;padding:8px 12px;border:1px dashed var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-md);background:var(--dsw-alias-bg-layer-1)}
.atk-spinner{display:inline-block;width:22px;height:22px;border-radius:50%;border:2px solid var(--dsw-alias-border-l3);border-top-color:var(--dsw-alias-state-business-primary);animation:atk-brain-spin .9s linear infinite}
.atk-fallback{display:flex;align-items:center;justify-content:center;padding:24px;background:var(--dsw-alias-bg-base)}
.atk-fallback-card{display:flex;flex-direction:column;gap:8px;max-width:520px;padding:16px;border:1px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-lg);background:var(--dsw-alias-bg-layer-1)}
.atk-fallback-title{font-size:13px;font-weight:600;color:var(--dsw-alias-state-error-primary)}
.atk-fallback-body{font-size:11.5px;color:var(--dsw-alias-label-secondary)}
.atk-fallback-error{max-height:120px;margin:0;padding:6px;overflow:auto;border-radius:var(--dsw-radius-sm);background:var(--dsw-alias-markdown-code-block);color:var(--dsw-alias-label-tertiary);font-family:var(--dsw-font-mono);font-size:10px;white-space:pre-wrap}
.atk-root button:focus-visible,.atk-root input:focus-visible,.atk-root select:focus-visible,.atk-root summary:focus-visible,.atk-root textarea:focus-visible,.atk-node:focus-visible{outline:2px solid var(--dsw-focus-ring-color,var(--dsw-alias-state-business-primary));outline-offset:1px}
.atk-root .atk-btn{display:inline-flex;align-items:center}
@keyframes atk-brain-spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}
@media (max-width:920px){.atk-body{flex-direction:column}.atk-field{max-width:none}}
@media (prefers-reduced-motion:reduce){.atk-spinner{animation:none}}
`;

    function styleNode() {
      return h('style', { key: 'atk-brain-style' }, STYLE_TEXT);
    }

    // ---------------------------------------------------------------------
    // Small presentational building blocks
    // ---------------------------------------------------------------------

    function Badge(props) {
      const tone = props.tone === undefined ? '' : ` atk-badge--${props.tone}`;
      return h('span', {
        className: `atk-badge${tone}`,
        title: props.title === undefined ? undefined : props.title,
      }, props.label === undefined ? props.children : props.label);
    }

    function StatItem(props) {
      const tone = props.tone === undefined ? '' : ` atk-stat--${props.tone}`;
      const content = [
        h('span', { key: 'value', className: 'atk-stat-value' }, props.value),
        h('span', { key: 'label', className: 'atk-stat-label' }, props.label),
      ];
      if (typeof props.onClick !== 'function') {
        return h('div', { className: `atk-stat${tone}` }, content);
      }
      return h('button', {
        type: 'button',
        className: `atk-stat${tone}`,
        title: props.title,
        'aria-label': props.title,
        'aria-pressed': props.active === true,
        onClick: props.onClick,
      }, content);
    }

    function Notice(props) {
      const tone = props.tone === 'info' ? ' atk-notice--info' : '';
      return h('div', { className: `atk-notice${tone}`, role: 'status' }, props.children);
    }

    function EmptyState(props) {
      return h('div', { className: 'atk-empty' },
        props.waiting === true ? h('span', { className: 'atk-spinner', 'aria-hidden': 'true' }) : null,
        h('div', { className: 'atk-empty-title' }, props.title),
        props.hint === undefined ? null : h('div', { className: 'atk-empty-hint' }, props.hint),
        props.instructions === undefined ? null : h('div', { className: 'atk-empty-instructions' }, props.instructions));
    }

    function Legend(props) {
      const t = props.t;
      const item = (key, color, label) => h('span', { key, className: 'atk-legend-item' },
        h('span', { className: 'atk-dot', style: { background: color }, 'aria-hidden': 'true' }),
        label);
      return h('div', { className: 'atk-legend', 'aria-label': t('graph.legend') },
        h('span', { className: 'atk-legend-title' }, t('graph.legend')),
        item('targets', KIND_COLOR.target, t('graph.legendTargets')),
        item('assets', KIND_COLOR.host, t('stat.assets')),
        item('services', KIND_COLOR.service, t('stat.services')),
        item('high', SEVERITY_COLOR.critical, t('graph.legendHigh')),
        item('access', KIND_COLOR.access, t('stat.access')),
        item('data', KIND_COLOR.data, t('stat.data')),
        item('crown', 'var(--dsw-alias-state-business-primary)', t('stat.crown')),
        h('span', { className: 'atk-legend-note' }, t('graph.legendEdges')));
    }

    /** React error boundary: one bad render must never take the slot down. */
    class AtkErrorBoundary extends React.Component {
      constructor(props) {
        super(props);
        this.state = { error: null };
        this.reset = this.reset.bind(this);
      }

      static getDerivedStateFromError(error) {
        return { error: error instanceof Error ? error : new Error(String(error)) };
      }

      componentDidCatch(error, info) {
        try {
          if (typeof console !== 'undefined' && typeof console.error === 'function') {
            console.error('atk-brain: attack-graph view crashed', error, info);
          }
        } catch (ignored) {
          // Logging must never rethrow into React.
        }
      }

      reset() {
        this.setState({ error: null });
      }

      render() {
        const error = this.state === null || this.state === undefined ? null : this.state.error;
        if (error) {
          const t = typeof this.props.t === 'function' ? this.props.t : (key) => key;
          const message = error instanceof Error && typeof error.message === 'string' ? error.message : String(error);
          return h('div', { className: 'atk-root atk-fallback', role: 'alert' },
            styleNode(),
            h('div', { className: 'atk-fallback-card' },
              h('div', { className: 'atk-fallback-title' }, t('error.title')),
              h('div', { className: 'atk-fallback-body' }, t('error.message')),
              h('pre', { className: 'atk-fallback-error' }, truncateText(message, 400)),
              h('button', { type: 'button', className: 'atk-btn', onClick: this.reset }, t('error.retry'))));
        }
        return this.props.children === undefined ? null : this.props.children;
      }
    }

    // ---------------------------------------------------------------------
    // SVG graph canvas
    // ---------------------------------------------------------------------

    function markerIdFor(sessionId) {
      const raw = sessionId === undefined || sessionId === null ? 'session' : String(sessionId);
      return `atk-brain-arrow-${raw.replace(/[^a-zA-Z0-9_-]/g, '-')}`;
    }

    /**
     * Memoized edge layer: pan/zoom must not rebuild 1500 edge elements, so the
     * layer only re-renders when layout, selection, hover or edge pinning change.
     */
    const GraphStageLayer = React.memo(function GraphStageLayer(props) {
      const layout = props.layout;
      return h('g', { className: 'atk-stages' },
        layout.headers.map((header) => h('g', { key: `stage-${header.column}` },
        h('rect', {
          className: 'atk-stage-pill',
          x: header.x - (header.bandWidth - 18) / 2,
          y: PAD_Y + 5,
          width: header.bandWidth - 18,
          height: 28,
          rx: 14,
        }),
        h('text', {
          className: 'atk-stage-label',
          x: header.x,
          y: PAD_Y + 23,
          textAnchor: 'middle',
        }, header.label, h('tspan', { className: 'atk-stage-count' }, `  ${header.count}`)))));
    });

    /** Edge layer: curved paths, de-emphasized by default, highlighted on focus. */
    const GraphEdgesLayer = React.memo(function GraphEdgesLayer(props) {
      const t = props.t;
      const highlight = props.highlight;
      const activeEdgeId = props.activeEdgeId;
      const markerId = props.markerId;
      const flowEdges = props.flowEdges instanceof Set ? props.flowEdges : new Set();
      return h('g', { className: 'atk-edges' }, props.layout.edges.map((edgeView) => {
        const edge = edgeView.edge;
        const isActive = activeEdgeId === edge.id;
        const isHighlighted = highlight.edges.has(edge.id);
        const isFlowing = flowEdges.has(edge.id);
        const dimmed = highlight.selected !== null && !isHighlighted;
        const color = isActive || isHighlighted ? 'var(--dsw-alias-state-business-primary)' : edgeColor(edge);
        const opacity = isActive ? 1 : (isHighlighted ? 0.9 : (dimmed ? 0.06 : 0.3 + edge.confidence * 0.22));
        return h('g', { key: `edge-${edge.id}`, className: 'atk-edge-group' },
          isHighlighted
            ? h('path', { className: 'atk-edge-glow', d: edgeView.d })
            : null,
          h('path', {
            className: isFlowing ? 'atk-edge atk-edge--flowing' : 'atk-edge',
            d: edgeView.d,
            stroke: color,
            strokeWidth: isActive ? 2.4 : (isHighlighted ? 1.7 : 1.15),
            strokeOpacity: opacity,
            strokeDasharray: edge.kind === 'pivot' || edge.kind === 'pivots_to' ? '5 3' : undefined,
            markerEnd: `url(#${markerId})`,
          }),
          h('path', {
            className: 'atk-edge-hit',
            d: edgeView.d,
            onPointerEnter: () => props.onHoverEdge(edge.id),
            onPointerLeave: () => props.onHoverEdge(null),
            onClick: (event) => {
              event.stopPropagation();
              props.onSelectEdge(edge.id);
            },
          }),
          h('title', null, `${edgeLabelText(t, edge)} · ${t('detail.edgeEvidence', { count: edge.evidenceCount })}`),
          isFlowing
            ? h('circle', { className: 'atk-flow-dot', r: 3.2, fill: color },
              h('animateMotion', { path: edgeView.d, dur: '2.4s', repeatCount: 'indefinite' }))
            : null,
          isActive
            ? h('text', {
              className: 'atk-edge-label',
              x: edgeView.midX,
              y: edgeView.midY,
              textAnchor: 'middle',
            }, edgeLabelText(t, edge))
            : null);
      }));
    });

    /** Node layer: card-style cards whose outer border carries the kind/severity color. */
    const GraphNodesLayer = React.memo(function GraphNodesLayer(props) {
      const t = props.t;
      const highlight = props.highlight;
      const activeNodeId = props.activeNodeId;
      return h('g', { className: 'atk-nodes' }, props.layout.nodes.map((positioned) => {
        const node = positioned.node;
        const color = nodeColor(node);
        const severity = node.kind === 'finding'
          ? findingDisplaySeverity(node)
          : (node.severity === null ? null : String(node.severity).toLowerCase());
        const accent = severity !== null ? (SEVERITY_COLOR[severity] || color) : color;
        const isSelected = highlight.selected !== null && highlight.selected.id === node.id;
        const isNeighbour = highlight.neighbors.has(node.id);
        const dimmed = highlight.selected !== null && !isNeighbour;
        const kindLabel = localized(t, 'kind', node.kind);
        const statusLabel = node.status === 'unknown' ? '' : localized(t, 'status', node.status);
        const groupSummary = node.kind === 'target' ? String(node.attrs?.groupSummary ?? '') : '';
        const metaParts = groupSummary.length > 0
          ? [groupSummary]
          : (node.kind === 'finding' && severity !== null
            ? [localized(t, 'severity', severity), statusLabel]
            : [kindLabel, statusLabel]);
        const meta = metaParts.filter((part) => part.length > 0).join(' · ');
        const labelLimit = node.crown ? 19 : (node.kind === 'target' ? 24 : 22);
        const className = `atk-node atk-node--${node.kind}${isSelected ? ' atk-node--selected' : ''}${activeNodeId === node.id ? ' atk-node--active' : ''}${dimmed ? ' atk-node--dimmed' : ''}`;
        return h('g', {
          key: `node-${node.id}`,
          className,
          transform: `translate(${positioned.x} ${positioned.y})`,
          opacity: dimmed ? 0.22 : 1,
          style: { '--atk-node-accent': accent },
          role: 'button',
          tabIndex: 0,
          'aria-label': `${node.label} (${kindLabel})`,
          onPointerDown: (event) => event.stopPropagation(),
          onClick: (event) => {
            event.stopPropagation();
            props.onSelectNode(node.id);
          },
          onKeyDown: (event) => {
            if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
              event.preventDefault();
              props.onSelectNode(node.id);
            }
          },
        },
        h('title', null, `${node.label} — ${meta}`),
        h('rect', {
          className: 'atk-node-card',
          width: NODE_W,
          height: NODE_H,
          rx: 10,
        }),
        h('circle', {
          className: 'atk-node-dot',
          cx: 18,
          cy: 16,
          r: 3.2,
          fill: color,
        }),
        node.crown ? h('text', { className: 'atk-node-crown', x: NODE_W - 17, y: 18 }, '★') : null,
        h('text', { className: 'atk-node-label', x: 27, y: 19 }, truncateByWidth(node.label, labelLimit)),
        h('text', {
          className: 'atk-node-kind',
          x: 12,
          y: 35,
          fill: node.kind === 'finding' && severity !== null ? accent : undefined,
        }, truncateByWidth(meta, 32)),
        h('rect', {
          className: 'atk-node-hit',
          width: NODE_W,
          height: NODE_H,
          rx: 10,
        }));
      }));
    });

    function GraphCanvas(props) {
      const t = props.t;
      const layout = props.layout;
      const highlight = props.highlight;
      const view = props.view;
      const [dragging, setDragging] = React.useState(false);
      const dragRef = React.useRef(null);
      const markerId = markerIdFor(props.sessionId);
      const flowEdges = props.flowEdges instanceof Set ? props.flowEdges : new Set();
      const activity = props.activity ?? null;
      const dotId = `${markerId}-dot`;
      const gridId = `${markerId}-grid`;
      const worldSize = 120000;
      const worldOrigin = -worldSize / 2;
      const activeEdgeId = props.hoveredEdgeId || props.pinnedEdgeId;

      function handleWheel(event) {
        if (event === null || event === undefined) return;
        const raw = asNumber(event.deltaY, 0);
        if (raw === 0) return;
        if (typeof event.preventDefault === 'function') event.preventDefault();
        if (typeof event.stopPropagation === 'function') event.stopPropagation();
        const mode = asNumber(event.deltaMode, 0);
        const delta = mode === 1 ? raw * 16 : mode === 2 ? raw * 400 : raw;
        const factor = Math.min(2, Math.max(0.5, Math.exp(-delta * 0.0015)));
        if (typeof props.onZoomAt === 'function') {
          props.onZoomAt(factor, asNumber(event.clientX, 0), asNumber(event.clientY, 0));
        }
      }

      React.useEffect(() => {
        const node = props.wrapperRef === null || props.wrapperRef === undefined ? null : props.wrapperRef.current;
        if (node === null || node === undefined || typeof node.addEventListener !== 'function') return undefined;
        function onNativeWheel(event) {
          handleWheel(event);
        }
        node.addEventListener('wheel', onNativeWheel, { passive: false });
        return () => node.removeEventListener('wheel', onNativeWheel);
      }, []);

      function handlePointerDown(event) {
        if (event === null || event === undefined) return;
        if (typeof event.button === 'number' && event.button !== 0) return;
        const target = event.currentTarget;
        if (target && typeof target.setPointerCapture === 'function' && typeof event.pointerId === 'number') {
          try {
            target.setPointerCapture(event.pointerId);
          } catch (ignored) {
            // Pointer capture is best-effort (older engines, synthetic events).
          }
        }
        dragRef.current = {
          startX: asNumber(event.clientX, 0),
          startY: asNumber(event.clientY, 0),
          originX: view.x,
          originY: view.y,
          moved: false,
        };
        setDragging(true);
      }

      function handlePointerMove(event) {
        const drag = dragRef.current;
        if (drag === null || drag === undefined) return;
        const dx = asNumber(event.clientX, 0) - drag.startX;
        const dy = asNumber(event.clientY, 0) - drag.startY;
        if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
        props.setView((current) => ({ x: drag.originX + dx, y: drag.originY + dy, k: current.k }));
      }

      function handlePointerUp() {
        const drag = dragRef.current;
        dragRef.current = null;
        setDragging(false);
        if (drag !== null && drag !== undefined && drag.moved !== true) props.onBackground();
      }

      function handlePointerCancel() {
        dragRef.current = null;
        setDragging(false);
      }

      return h('div', {
        className: dragging ? 'atk-canvas atk-canvas--dragging' : 'atk-canvas',
        ref: props.wrapperRef,
        onPointerDown: handlePointerDown,
        onPointerMove: handlePointerMove,
        onPointerUp: handlePointerUp,
        onPointerCancel: handlePointerCancel,
        onPointerLeave: handlePointerCancel,
      },
      h('svg', {
        className: 'atk-svg',
        role: 'img',
        'aria-label': t('graph.aria'),
      },
      h('defs', null,
        h('pattern', {
          id: dotId,
          width: 18,
          height: 18,
          patternUnits: 'userSpaceOnUse',
        }, h('circle', {
          cx: 1.4,
          cy: 1.4,
          r: 1.15,
          fill: 'var(--dsw-alias-border-l3)',
          fillOpacity: 0.78,
        })),
        h('pattern', {
          id: gridId,
          width: 100,
          height: 100,
          patternUnits: 'userSpaceOnUse',
        }, h('path', {
          d: 'M 100 0 L 0 0 0 100',
          fill: 'none',
          stroke: 'var(--dsw-alias-border-l2)',
          strokeOpacity: 0.38,
          strokeWidth: 1,
        })),
        h('marker', {
          id: markerId,
          viewBox: '0 0 10 10',
          refX: 9,
          refY: 5,
          markerWidth: 6,
          markerHeight: 6,
          orient: 'auto-start-reverse',
        }, h('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: 'var(--dsw-alias-label-tertiary)' }))),
      h('g', { transform: `translate(${view.x} ${view.y}) scale(${view.k})` },
        h('rect', {
          className: 'atk-graph-grid',
          x: worldOrigin,
          y: worldOrigin,
          width: worldSize,
          height: worldSize,
          fill: `url(#${gridId})`,
        }),
        h('rect', {
          className: 'atk-graph-paper',
          x: worldOrigin,
          y: worldOrigin,
          width: worldSize,
          height: worldSize,
          fill: `url(#${dotId})`,
        }),
        h(GraphStageLayer, { layout }),
        h(GraphEdgesLayer, {
          t,
          layout,
          highlight,
          activeEdgeId,
          markerId,
          flowEdges,
          onHoverEdge: props.onHoverEdge,
          onSelectEdge: props.onSelectEdge,
        }),
        h(GraphNodesLayer, {
          t,
          layout,
          highlight,
          activeNodeId: activity?.targetId ?? null,
          onSelectNode: props.onSelectNode,
        })),
      activity === null ? null : h('div', { className: 'atk-activity', title: activity.detail ?? activity.label },
        h('span', { className: 'atk-activity-pulse', 'aria-hidden': 'true' }),
        h('span', { className: 'atk-activity-title' }, t('graph.activity')),
        h('span', { className: 'atk-activity-text' }, activity.from && activity.to ? `${activity.from} → ${activity.to}` : activity.label))));
    }

    // ---------------------------------------------------------------------
    // Right-hand detail pane
    // ---------------------------------------------------------------------

    /** Target group detail: one target summarizes its assets/services/findings. */
    function TargetGroupPane(props) {
      const t = props.t;
      const group = props.group;
      const counts = group.attrs?.counts ?? {};
      const memberIds = Array.isArray(group.attrs?.members) ? group.attrs.members : [];
      const members = memberIds.map((id) => props.model.byId.get(id)).filter(Boolean).slice(0, 90);
      const ranked = members.slice().sort((a, b) => {
        const first = TARGET_ASSET_KINDS.has(a.kind) ? 0 : (a.kind === 'service' || a.kind === 'webapp' ? 1 : (a.kind === 'finding' ? 3 : 2));
        const second = TARGET_ASSET_KINDS.has(b.kind) ? 0 : (b.kind === 'service' || b.kind === 'webapp' ? 1 : (b.kind === 'finding' ? 3 : 2));
        return first - second || a.label.localeCompare(b.label);
      });
      const countChips = [
        ['assets', counts.assets, t('group.assets')],
        ['services', counts.services, t('group.services')],
        ['vulnerabilities', counts.vulnerabilities, t('group.vulnerabilities')],
        ['findings', counts.findings, t('group.findings')],
        ['verifiedFindings', counts.verifiedFindings, t('group.verified')],
        ['access', counts.access, t('stat.access')],
        ['data', counts.data, t('stat.data')],
        ['credentials', counts.credentials, t('stat.credentials')],
      ].filter((entry) => Number(entry[1]) > 0);
      return h('div', { className: 'atk-detail atk-target-detail' },
        h('div', { className: 'atk-detail-head' },
          h('h3', { className: 'atk-detail-title' }, `${t('group.title')} · ${group.label}`),
          h('button', {
            type: 'button',
            className: 'atk-btn atk-btn-icon atk-detail-close',
            'aria-label': t('detail.close'),
            onClick: props.onClose,
          }, '×')),
        h('div', { className: 'atk-target-counts' },
          countChips.map((entry) => h('span', { key: entry[0], className: 'atk-target-count' },
            h('b', null, String(entry[1])), h('span', null, entry[2])))),
        h('div', { className: 'atk-target-actions' },
          h('button', {
            type: 'button',
            className: group.attrs?.expanded === true ? 'atk-btn atk-btn-ghost' : 'atk-btn atk-btn-primary',
            onClick: props.onToggleExpand,
          }, group.attrs?.expanded === true ? t('group.collapse') : t('group.expand')),
          h('span', { className: 'atk-empty-hint' }, t('group.memberHint'))),
        h('div', { className: 'atk-detail-section' },
          h('h4', { className: 'atk-detail-section-title' }, t('group.members'), h('span', { className: 'atk-tab-count' }, String(members.length))),
          ranked.length === 0
            ? h('div', { className: 'atk-empty-hint' }, t('detail.empty'))
            : h('div', { className: 'atk-target-member-list' }, ranked.map((node) => h('button', {
              key: node.id,
              type: 'button',
              className: 'atk-target-member',
              title: `${node.key} · ${node.id}`,
              onClick: () => props.onSelectNode(node.id),
            },
            h('span', { className: 'atk-target-member-kind' }, localized(t, 'kind', node.kind)),
            h('span', { className: 'atk-target-member-label' }, truncateText(node.label, 90)),
            node.severity === null ? null : h('span', { className: `atk-target-member-sev atk-target-member-sev--${node.severity}` }, localized(t, 'severity', node.severity)),
            h('span', { className: 'atk-target-member-status' }, localized(t, 'status', node.status)))))),
        h('div', { className: 'atk-live', role: 'status' }, group.label));
    }

    const ATTR_PRIORITY = {
      finding: ['severity', 'verification', 'impact', 'cve', 'cwe', 'cvss', 'repro', 'remediation', 'target', 'evidence'],
      credential: ['username', 'secretMask', 'secretFp', 'kind', 'validity', 'privilege', 'realm', 'targetId'],
      access: ['kind', 'privilege', 'osUser', 'proof', 'validated', 'targetId', 'sourceAccessId'],
      data: ['dataClass', 'count', 'thresholdMet', 'samples', 'fields'],
      host: ['fqdn', 'addr', 'realm', 'wildcardStatus', 'criticality', 'crownJewel', 'os'],
      ip: ['addr', 'realm', 'criticality', 'crownJewel'],
      service: ['port', 'protocol', 'banner', 'service', 'tls'],
      webapp: ['url', 'status', 'title', 'server', 'tech'],
      wildcard_zone: ['signature', 'probes', 'cdn', 'apex', 'reason'],
      task: ['actionType', 'priority', 'why', 'risk', 'targetId', 'toolClass'],
      chain_step: ['chainId', 'stage', 'ordinal', 'nodeRef'],
      evidence: ['path', 'mediaType', 'size', 'sha256', 'collectedBy', 'collectedAt'],
    };

    function nodeAttrValueText(t, node, key, value) {
      if ((key === 'severity' && node.kind === 'finding')) return localized(t, 'severity', String(value));
      if (key === 'verification') return localized(t, 'verification', String(value));
      if (key === 'validity') return localized(t, 'status', String(value));
      if (key === 'risk') return localized(t, 'risk', String(value));
      if (key === 'stage') return localized(t, 'chain.stage', String(value));
      return valueText(value);
    }

    function packetText(value) {
      if (typeof value === 'string') return value;
      if (value === null || value === undefined) return '';
      try { return JSON.stringify(value, null, 2); } catch { return String(value); }
    }

    function normalizePacketText(text) {
      let value = String(text ?? '');
      const escaped = (value.match(/\\r\\n|\\n|\\r/g) || []).length;
      const real = (value.match(/\n/g) || []).length;
      if (escaped > 0 && escaped >= real) {
        value = value.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\r/g, '\n').replace(/\\t/g, '\t');
      }
      return value.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    }

    function redactPacketClient(text) {
      return normalizePacketText(text)
        .replace(/^(\s*(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key|api-key)\s*:\s*).*$/gimu, '$1[redacted]')
        .replace(/((?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|session)\s*[=:]\s*)([^&\s;,'"]+)/giu, '$1[redacted]')
        .replace(/([?&](?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|session)=)[^&\s]+/giu, '$1[redacted]');
    }

    function findingPackets(node) {
      const attrs = node.attrs || {};
      const request = packetText(attrs.request ?? attrs.httpRequest ?? attrs.pocCurl ?? '');
      const response = packetText(attrs.response ?? attrs.httpResponse ?? '');
      const repro = packetText(attrs.repro ?? attrs.proofDetail ?? '');
      return {
        request: redactPacketClient(request),
        response: redactPacketClient(response),
        repro: redactPacketClient(repro),
      };
    }

    function findingMarkdown(node, details) {
      const attrs = node.attrs || {};
      const packets = details === undefined ? findingPackets(node) : { request: details.request, response: details.response, repro: details.repro };
      const title = String(attrs.title || node.label || 'finding');
      const lines = [
        `# ${title}`,
        '',
        `- severity: ${node.severity || 'info'}`,
        `- status: ${node.status || 'candidate'}`,
        `- verification: ${node.verification || 'unverified'}`,
        `- category: ${details?.categoryText || attrs.category || attrs.template || '未知'}`,
        `- secondary_verified: ${attrs.secondaryVerified === true ? '是' : '否'}`,
        attrs.cvssVector ? `- cvss: ${attrs.cvssVector}` : null,
        '',
        `## ${details?.overviewLabel || '漏洞简介'}`,
        String(details?.description || attrs.description || attrs.impact || attrs.evidence || '—'),
        '',
        '## 危害',
        String(details?.impact || attrs.impact || attrs.impactDetail || '—'),
        '',
        '## CVSS 判定',
        findingCvssVerdictText(t, node),
        '',
        '## 请求包',
        '```http',
        packets.request || '(not recorded)',
        '```',
        '',
        '## 响应包',
        '```http',
        packets.response || '(not recorded)',
        '```',
        '',
        '## 复现说明',
        packets.repro || '—',
        '',
        '## 修复建议',
        String(details?.remediation || attrs.remediation || '—'),
        '',
        '## 二次验证',
        details?.secondary?.verdict ? `${localized(t, 'verification', details.secondary.verdict)}：${details?.secondaryText || details.secondary.rationale || '—'}` : '—',
        '',
        `evidence: ${Array.isArray(node.evidenceIds) ? node.evidenceIds.length : 0}`,
      ].filter((line) => line !== null);
      return lines.join('\n');
    }

    function findingSubjectParts(node) {
      const attrs = node.attrs ?? {};
      const subject = String(attrs.subjectKey ?? attrs.url ?? attrs.target ?? node.label ?? '').trim();
      let host = subject.replace(/^https?:\/\//iu, '').split('/')[0];
      if (host.startsWith('[')) {
        const end = host.indexOf(']');
        host = end > 0 ? host.slice(1, end) : host;
      }
      let port = String(attrs.port ?? '').trim();
      if (port.length === 0 && !host.startsWith('[') && host.split(':').length === 2 && /^\d+$/u.test(host.split(':')[1])) {
        port = String(host.split(':')[1]);
        host = host.split(':')[0];
      }
      if (port.length === 0) port = '443';
      return { subject, host, port };
    }

    function findingCvssVerdictText(t, node) {
      if (node === null || node === undefined || node.kind !== 'finding') return '—';
      const shown = node.isVulnerability === true || node.includedVulnerability === true;
      if (shown && node.refuted === true) return t('detail.refutedVulnerabilityVerdict');
      const attrs = node.attrs || {};
      const vector = String(attrs.cvssVector ?? (attrs.cvss && attrs.cvss.vector) ?? '');
      const metrics = parseCvssMetrics(vector);
      const reasons = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
        .map((key) => (METRIC_ZH[key] && metrics[key] ? METRIC_ZH[key][metrics[key]] : null))
        .filter((line) => line !== null);
      const parts = [];
      if (node.cvssScore === null || node.cvssScore === undefined) {
        parts.push(shown ? t('detail.vulnerabilityUnscoredVerdict') : t('detail.unscoredVerdict'));
      } else {
        const score = Number(node.cvssScore);
        const severity = localized(t, 'severity', node.cvssSeverity || node.severity || 'info');
        parts.push(shown
          ? t('detail.vulnerabilityCvss', { score: score.toFixed(1), severity })
          : t('detail.nonVulnerabilityCvss', { score: score.toFixed(1), severity }));
      }
      if (reasons.length > 0) parts.push(`分数来自这八个指标：${reasons.join('；')}。`);
      else parts.push('这条记录没有 CVSS v3.1 向量，不能按八个指标解释分数。');
      if (node.redteamRating) {
        const shownSeverity = localized(t, 'severity', node.severity || 'info');
        const redLabel = localized(t, 'severity', node.redteamRating);
        parts.push(`红队视角是${redLabel}：${node.redteamRationale || ''}综合结果按红队 70%、CVSS 30%，严重度是${shownSeverity}。`);
      }
      if (node.xssPlacement === 'reflected') {
        parts.push('这是反射型 XSS：受害者必须自己打开构造后的链接，需要用户交互，最高到中危。存储型 XSS 可以在其他用户正常访问时触发，才可以评为高危。');
        if (node.cvssCapped === true && Number.isFinite(Number(node.cvssOriginalScore))) {
          parts.push(`记录里的分数是 ${Number(node.cvssOriginalScore).toFixed(1)}，已按反射型上限调整为 ${Number(node.cvssScore).toFixed(1)}。`);
        }
      } else if (node.xssPlacement === 'stored') {
        parts.push('这是存储型 XSS：内容留在服务端，其他用户访问时即可触发，因此可以评为高危。');
      }
      return parts.join('');
    }

    function findingCategoryZh(t, template, title) {
      const text = `${template} ${title}`.toLowerCase();
      if (/tls|certificate/iu.test(text)) return t('detail.categoryTls');
      if (/security-header|header/iu.test(text)) return t('detail.categoryHeaders');
      if (/disclosure|powered|server-version/iu.test(text)) return t('detail.categoryDisclosure');
      if (/robots/iu.test(text)) return t('detail.categoryRobots');
      if (/fingerprint|technology/iu.test(text)) return t('detail.categoryFingerprint');
      if (/exposure|exposed|listing|admin|backup|actuator|swagger|metrics|debug/iu.test(text)) return t('detail.categoryExposure');
      return t('detail.categoryGeneric');
    }

    function localizedRatingText(t, rating, raw) {
      const value = String(raw ?? '').trim();
      if (/[\u3400-\u9fff]/u.test(value)) return value;
      const key = String(rating ?? '').toLowerCase();
      if (key === 'critical') return t('detail.ratingCritical');
      if (key === 'high') return t('detail.ratingHigh');
      if (key === 'medium') return t('detail.ratingMedium');
      if (key === 'low') return t('detail.ratingLow');
      return t('detail.ratingInfo');
    }

    function localizedSecondaryText(t, secondary) {
      const rationale = String(secondary?.rationale ?? '').trim();
      if (/[\u3400-\u9fff]/u.test(rationale)) return rationale;
      const verdict = String(secondary?.verdict ?? '').toLowerCase();
      if (verdict === 'verified') return t('detail.secondaryVerifiedGeneric');
      if (verdict === 'refuted') return t('detail.secondaryRefutedGeneric');
      return t('detail.secondaryInconclusiveGeneric');
    }

    function findingDetailsFor(t, node, incident) {
      const attrs = node.attrs ?? {};
      const template = String(attrs.template ?? attrs.category ?? '').toLowerCase();
      const title = String(attrs.title || node.label || 'finding');
      const rate = String(attrs.redteamRating ?? attrs.cvssRating ?? '').trim();
      const subjectParts = findingSubjectParts(node);
      const evidenceNodes = (Array.isArray(incident) ? incident : [])
        .map((entry) => entry?.neighbour)
        .filter((neighbour) => neighbour !== null && neighbour !== undefined && neighbour.kind === 'evidence');
      const evidenceText = String(attrs.evidence ?? attrs.proofDetail ?? '').trim();
      const whenMatch = /(?:expired at|notAfter[=:]\s*)([^\s;]+)/iu.exec(`${evidenceText} ${title}`);
      const when = whenMatch === null ? evidenceText : whenMatch[1];
      const zhDetail = FINDING_DETAIL_ZH[template] ?? {};
      const tlsFinding = /tls|certificate/iu.test(template) || /TLS|certificate/iu.test(title);
      const expired = /expired/iu.test(template) || /expired/iu.test(title);
      const classText = `${template} ${title}`;
      const xssFinding = /xss|cross[- ]site\s*scripting/iu.test(classText);
      const sqliFinding = /sqli|sql\s*injection|sql\s*注入/iu.test(classText);
      const rceFinding = /rce|remote\s*code|command\s*injection|命令执行|代码执行/iu.test(classText);
      const requestMatch = /[?&]([A-Za-z][A-Za-z0-9_-]*)=/u.exec(String(attrs.request ?? attrs.httpRequest ?? attrs.pocCurl ?? ''));
      const parameter = (requestMatch === null ? '' : requestMatch[1])
        || (/succLoginRedirect/iu.test(classText) ? 'succLoginRedirect' : '')
        || (/hint/iu.test(classText) ? 'hint' : '')
        || '目标参数';
      const chineseOnly = (value) => /[\u3400-\u9fff]/u.test(String(value ?? ''));
      const rawDescription = String(attrs.description ?? '').trim();
      const rawImpact = String(attrs.impact ?? attrs.impactDetail ?? '').trim();
      const rawRepro = String(attrs.repro ?? '').trim();
      let description = chineseOnly(rawDescription) ? rawDescription : '';
      let impact = chineseOnly(rawImpact) ? rawImpact : '';
      let repro = chineseOnly(rawRepro) ? rawRepro : '';
      const aiDetailComplete = description.length > 0 && chineseOnly(rawImpact) && chineseOnly(rawRepro);
      const originalDetail = {
        description: !chineseOnly(rawDescription) && rawDescription.length > 0 ? rawDescription : '',
        impact: !chineseOnly(rawImpact) && rawImpact.length > 0 ? rawImpact : '',
        repro: !chineseOnly(rawRepro) && rawRepro.length > 0 ? rawRepro : '',
      };
      if (xssFinding && /该发现可能扩大攻击面|实际影响以验证结果|属于暴露面或配置问题/u.test(impact)) impact = '';
      if (xssFinding && /用 atkbrain_probe 或等价|未复现前保持 candidate/u.test(repro)) repro = '';
      let request = String(attrs.request ?? attrs.httpRequest ?? attrs.pocCurl ?? '').trim();
      let response = String(attrs.response ?? attrs.httpResponse ?? '').trim();
      const genericDescription = /探测响应中存在对应暴露特征|该发现属于暴露面|corresponding exposure signal/iu.test(description);
      if (description.length === 0 || genericDescription) {
        description = xssFinding
          ? t('detail.derivedXssDescription', { subject: subjectParts.subject || title, parameter })
          : sqliFinding
            ? t('detail.derivedSqliDescription', { subject: subjectParts.subject || title })
            : rceFinding
              ? t('detail.derivedRceDescription', { subject: subjectParts.subject || title })
              : expired
                ? t('detail.derivedExpiredDescription', { subject: subjectParts.subject || title, when: when || evidenceText || '—' })
                : (tlsFinding
                  ? t('detail.derivedDescription', { title, evidence: evidenceText || '—' })
                  : t('detail.derivedEvidenceDescription', { title }));
      }
      if (impact.length === 0 && zhDetail.impact !== undefined) impact = zhDetail.impact;
      if (impact.length === 0) {
        const severity = String(node.severity ?? attrs.severity ?? 'info').toLowerCase();
        impact = xssFinding
          ? t('detail.derivedXssImpact')
          : sqliFinding
            ? t('detail.derivedSqliImpact')
            : rceFinding
              ? t('detail.derivedRceImpact')
              : expired || tlsFinding
                ? t('detail.derivedExpiredImpact')
                : (['info', 'low'].includes(severity) ? t('detail.derivedImpactInfo') : t('detail.derivedImpact'));
      }
      if (repro.length === 0) {
        repro = xssFinding
          ? t('detail.derivedXssRepro', { parameter })
          : expired || tlsFinding
            ? t('detail.derivedExpiredRepro', { host: subjectParts.host, port: subjectParts.port })
            : t('detail.derivedRepro');
      }
      if (request.length === 0 && (expired || tlsFinding)) request = t('detail.derivedTlsRequest', { host: subjectParts.host });
      if (response.length === 0 && (expired || tlsFinding)) {
        response = t('detail.derivedTlsResponse', {
          subject: subjectParts.subject || subjectParts.host,
          when: when || '—',
          evidence: evidenceText || '—',
        });
      }
      const genericRemediation = /按 finding 模板修复|限制管理入口|未验证前保持候选/u.test(String(attrs.remediation ?? ''));
      let remediation = String(((chineseOnly(attrs.remediation) && !(xssFinding && genericRemediation)) ? attrs.remediation : '')
        || (xssFinding ? '' : zhDetail.remediation)
        || '').trim();
      if (remediation.length === 0) {
        if (xssFinding) remediation = t('detail.remediationXss', { parameter });
        else if (sqliFinding) remediation = t('detail.remediationSqli');
        else if (rceFinding) remediation = t('detail.remediationRce');
        else if (expired) remediation = t('detail.remediationExpired');
        else if (/header|powered|xss-protection/iu.test(template + title)) remediation = t('detail.remediationHeaders');
        else if (/robots/iu.test(template + title)) remediation = t('detail.remediationRobots');
        else if (/admin|login/iu.test(template + title)) remediation = t('detail.remediationAdmin');
        else remediation = t('detail.derivedRemediation');
      }
      const secondary = {
        verdict: String(attrs.secondaryVerdict ?? '').trim(),
        rationale: String(attrs.secondaryRationale ?? '').trim(),
        evidencePath: String(attrs.secondaryEvidencePath ?? '').trim(),
        verified: attrs.secondaryVerified === true,
      };
      const shown = node.isVulnerability === true || node.includedVulnerability === true;
      const overviewLabel = shown
        ? t('detail.findingOverview')
        : (node.qualified === true ? t('detail.verifiedOverview') : t('detail.findingOverviewPlain'));
      const kindLabel = shown
        ? t('detail.vulnerabilityLabel')
        : (node.qualified === true ? t('detail.verifiedFindingLabel') : t('detail.findingLabel'));
      const source = String(attrs.secondaryDetailsSource ?? attrs.detailSource ?? '').trim();
      const detailsSource = aiDetailComplete && ['verification-team', 'ai-verification-team'].includes(source) ? source : '';
      const detailPending = !aiDetailComplete;
      const originalDetailText = originalDetail.description || originalDetail.impact || originalDetail.repro;
      return {
        description,
        overviewLabel,
        kindLabel,
        aiDetailComplete,
        detailPending,
        originalDetail,
        originalDetailText,
        impact,
        repro: redactPacketClient(repro),
        request: redactPacketClient(request),
        response: redactPacketClient(response),
        remediation,
        secondary,
        detailsSource,
        evidenceNodes,
        template,
        subject: subjectParts.subject,
        parameter,
        ratingText: localizedRatingText(t, rate, attrs.redteamRationale || attrs.ratingRationale),
        secondaryText: localizedSecondaryText(t, secondary),
        categoryText: findingCategoryZh(t, template, title),
        cvss: String(attrs.cvssVector ?? '').trim(),
        cvssScore: attrs.cvssScore === undefined ? null : attrs.cvssScore,
        cvssSeverity: String(attrs.cvssSeverity ?? '').trim(),
      };
    }

    function soleExternalHost(model) {
      if (model === null || model === undefined) return '';
      const labels = [];
      for (const node of model.nodes || []) {
        if (node.kind !== 'host') continue;
        const label = String(node.attrs?.host || node.label || '').trim();
        if (label.length === 0 || label === 'unknown' || label === 'null') continue;
        if (isLoopbackHost(label) || isPrivateIpv4(label) || isInternalDns(label)) continue;
        if (!labels.includes(label)) labels.push(label);
      }
      return labels.length === 1 ? labels[0] : '';
    }

    function FindingDetailPane(props) {
      const t = props.t;
      const node = props.node;
      const attrs = node.attrs || {};
      const details = findingDetailsFor(t, node, props.incident);
      const packets = {
        request: details.request,
        response: details.response,
        repro: details.repro,
      };
      const fact = (label, value) => h('div', { className: 'atk-fact' },
        h('span', { className: 'atk-fact-label' }, label),
        h('span', { className: 'atk-fact-value' }, value || '—'));
      const cvssFact = node.cvssScore === null || node.cvssScore === undefined
        ? (node.severity === 'unscored' ? t('severity.unscored') : '—')
        : `${Number(node.cvssScore).toFixed(1)} ${localized(t, 'severity', node.cvssSeverity || node.severity || 'info')}`;
      const description = details.description;
      const impact = details.impact;
      const escalation = escalationView(t, node);
      function download() {
        try {
          if (typeof document === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined') return;
          const blob = new Blob([findingMarkdown(node, details)], { type: 'text/markdown;charset=utf-8' });
          const url = URL.createObjectURL(blob);
          const anchor = document.createElement('a');
          anchor.href = url;
          anchor.download = `${String(node.key || 'finding').replace(/[^a-z0-9_-]+/giu, '-').slice(-80)}.md`;
          anchor.click();
          URL.revokeObjectURL(url);
        } catch {
          /* clipboard/fallback is handled by the generic JSON copy */
        }
      }
      const highlightPacketText = (text) => {
        const pattern = /(<script[^>]*>|<\/script>|onload|onerror|alert\([^)]*\)|XSS_PROOF[^"'\s;]*|value="">|%22%3E|<\?php)/giu;
        const parts = String(text).split(pattern);
        return parts.map((part, index) => (index % 2 === 1
          ? h('span', { key: `hit-${index}`, className: 'atk-http-hit' }, part)
          : part));
      };
      const packetLine = (line, index) => {
        const status = /^(HTTP\/\d(?:\.\d)?)\s+(\d{3})(.*)$/u.exec(line);
        if (status !== null) {
          const code = Number(status[2]);
          return h('span', { key: `line-${index}` },
            h('span', { className: 'atk-http-version' }, status[1]),
            ' ',
            h('span', { className: `atk-http-status ${code >= 200 && code < 400 ? 'atk-http-status--ok' : 'atk-http-status--warn'}` }, status[2]),
            h('span', null, highlightPacketText(status[3])),
            index === 0 ? null : '');
        }
        const request = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)(?:\s+(HTTP\/\S+))?$/u.exec(line);
        if (request !== null) {
          return h('span', { key: `line-${index}` },
            h('span', { className: 'atk-http-method' }, request[1]),
            ' ',
            h('span', { className: 'atk-http-path' }, request[2]),
            request[3] ? h('span', { className: 'atk-http-version' }, ` ${request[3]}`) : null);
        }
        const header = /^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$/u.exec(line);
        if (header !== null) {
          return h('span', { key: `line-${index}` },
            h('span', { className: 'atk-http-header' }, `${header[1]}:`),
            ' ',
            h('span', { className: 'atk-http-value' }, highlightPacketText(header[2])));
        }
        return h('span', { key: `line-${index}` }, highlightPacketText(line));
      };
      const renderPacket = (text) => {
        const lines = String(text).split('\n');
        return lines.map((line, index) => h('span', { key: `packet-line-${index}` },
          packetLine(line, index),
          index < lines.length - 1 ? '\n' : ''));
      };
      const packet = (label, text, missing) => h('div', { className: 'atk-packet' },
        h('div', { className: 'atk-packet-head' }, label),
        text.length > 0
          ? h('pre', { className: 'atk-packet-body' }, renderPacket(text))
          : h('div', { className: 'atk-packet-empty' }, missing));
      const usableHost = (value) => {
        const host = String(value ?? '').replace(/^https?:\/\//iu, '').split('/')[0].trim();
        if (host.length === 0 || host === 'unknown' || host === 'null' || host === '—') return '';
        return host;
      };
      const linkedSubject = (Array.isArray(props.incident) ? props.incident : [])
        .map((entry) => entry?.neighbour)
        .find((item) => item && (item.kind === 'host' || item.kind === 'webapp' || item.kind === 'service' || item.kind === 'domain' || item.kind === 'ip' || item.kind === 'target'));
      const subjectLabel = usableHost(details.subject)
        || (linkedSubject ? (usableHost(linkedSubject.attrs?.host) || usableHost(linkedSubject.label) || linkedSubject.label) : '')
        || usableHost(attrs.url)
        || usableHost(attrs.host)
        || usableHost(props.hostFallback)
        || '—';
      return h('div', { className: 'atk-detail atk-detail--finding' },
        h('div', { className: 'atk-detail-head' },
          h('h3', { className: 'atk-detail-title' }, node.label),
          h('div', { className: 'atk-finding-actions' },
            h('button', { type: 'button', className: 'atk-btn', onClick: download }, t('detail.downloadMd')),
            h('button', { type: 'button', className: 'atk-btn atk-btn-icon', 'aria-label': t('detail.close'), onClick: props.onClose }, '×'))),
        h('div', { className: 'atk-finding-facts' },
          fact(t('col.vulnType'), node.findingType || findingTypeZh(attrs.template, node.label)),
          fact(t('detail.factCVSS'), cvssFact),
          fact(t('detail.factVerification'), t(`verification.${verificationState(node)}`)),
          fact(t('detail.factHost'), subjectLabel),
          fact(t('detail.factParameter'), details.parameter),
          fact(t('detail.aiDetail'), details.aiDetailComplete ? t('detail.aiDetailReady') : t('detail.aiDetailPending'))),
        h('div', { className: 'atk-finding-section atk-finding-section--overview' },
          h('h4', null, details.overviewLabel),
          h('p', null, description || impact || t('detail.noDescription')),
          details.detailPending
            ? h('div', { className: 'atk-detail-callout' }, t('detail.aiDetailPendingShort'))
            : h('div', { className: 'atk-detail-callout' }, t('detail.detailSourceTeam'))),
        details.originalDetailText.length > 0
          ? h('div', { className: 'atk-finding-section atk-finding-section--original' },
            h('h4', null, t('detail.originalRecord')),
            h('div', { className: 'atk-empty-hint' }, t('detail.originalRecordHint')),
            details.originalDetail.description.length > 0
              ? h('div', { className: 'atk-original-block' }, h('span', { className: 'atk-original-label' }, t('detail.originalDescription')), details.originalDetail.description)
              : null,
            details.originalDetail.impact.length > 0
              ? h('div', { className: 'atk-original-block' }, h('span', { className: 'atk-original-label' }, t('detail.originalImpact')), details.originalDetail.impact)
              : null,
            details.originalDetail.repro.length > 0
              ? h('div', { className: 'atk-original-block' }, h('span', { className: 'atk-original-label' }, t('detail.originalReproduction')), details.originalDetail.repro)
              : null)
          : null,
        h('div', { className: 'atk-finding-section atk-finding-section--impact' },
          h('h4', null, t('detail.findingImpact')),
          h('p', null, impact || String(attrs.evidence || '') || t('detail.attrsEmpty'))),
        escalation === null
          ? null
          : h('div', { className: 'atk-finding-section atk-finding-section--escalation' },
            h('h4', null, t('detail.escalation')),
            h('p', null, `${escalation.fromTitle} → ${escalation.toTitle}`),
            h('p', null, `${escalation.fromSeverity} → ${escalation.toSeverity}`),
            h('h4', null, t('detail.escalationProof')),
            h('p', null, escalation.proof)),
        h('div', { className: 'atk-finding-section atk-finding-section--fix' },
          h('h4', null, t('detail.remediation')),
          h('p', null, details.remediation || t('detail.derivedRemediation'))),
        h('div', { className: 'atk-finding-section atk-finding-section--cvss' },
          h('h4', null, t('detail.cvssVerdict')),
          h('p', null, findingCvssVerdictText(t, node))),
        details.secondary.verdict || details.secondary.rationale
          ? h('div', { className: 'atk-finding-section atk-finding-section--verify' },
            h('h4', null, t('detail.secondaryCheck')),
            h('p', null, [details.secondary.verdict ? localized(t, 'verification', details.secondary.verdict) : '', localizedSecondaryText(t, details.secondary)].filter(Boolean).join('：') || '—'),
            details.secondary.evidencePath.length > 0 ? h('p', { className: 'atk-empty-hint' }, t('detail.secondaryEvidence', { path: details.secondary.evidencePath })) : null)
          : null,
        h('div', { className: 'atk-finding-section atk-finding-section--repro' },
          h('h4', null, t('detail.findingRepro')),
          packets.repro.length > 0 ? h('p', { className: 'atk-finding-repro' }, packets.repro) : h('p', { className: 'atk-empty-hint' }, t('detail.requestMissing')),
          packet(t('detail.request'), packets.request, details.evidenceNodes.length > 0 ? t('detail.noRequestButEvidence') : t('detail.requestMissing')),
          packet(t('detail.response'), packets.response, t('detail.responseMissing')),
          h('div', { className: 'atk-finding-section atk-finding-section--original' },
            h('h4', null, t('detail.evidenceFiles')),
            details.evidenceNodes.length === 0
              ? h('div', { className: 'atk-empty-hint' }, t('detail.noEvidence'))
              : h('div', { className: 'atk-finding-repro' }, details.evidenceNodes.map((evidence) => `${String(evidence.attrs?.relative ?? evidence.attrs?.path ?? evidence.key)}${evidence.attrs?.sha256 ? `\nsha256=${evidence.attrs.sha256}` : ''}`).join('\n\n')))),
        h('div', { className: 'atk-detail-section' },
          h('h4', { className: 'atk-detail-section-title' }, t('detail.edges'), h('span', { className: 'atk-tab-count' }, String(props.incident.length))),
          props.incident.length === 0 ? h('div', { className: 'atk-empty-hint' }, t('detail.edgesEmpty')) : null),
        h('div', { className: 'atk-detail-actions' },
          h('button', { type: 'button', className: 'atk-btn', onClick: () => props.onFocus(node.id) }, t('detail.focus')),
          h('button', { type: 'button', className: 'atk-btn', onClick: () => props.copyText(node.id, 'id') }, t('detail.copyId')),
          h('button', { type: 'button', className: 'atk-btn', onClick: () => props.copyText(props.jsonText, 'json') }, t('detail.copyJson'))),
        h('details', { className: 'atk-collapse' },
          h('summary', null, t('detail.json')),
          h('textarea', { className: 'atk-json', readOnly: true, spellCheck: false, 'aria-label': t('detail.json'), value: props.jsonText })),
        h('div', { className: 'atk-live', role: 'status', 'aria-live': 'polite' }, props.copiedMessage));
    }

    function DetailPane(props) {
      const t = props.t;
      const model = props.model;
      const node = props.node === undefined ? null : props.node;
      const [copied, setCopied] = React.useState(null);
      const timerRef = React.useRef(null);
      const incident = React.useMemo(() => adjacentEdgesOf(model, node === null ? null : node.id), [model, node]);
      const attrKeys = React.useMemo(() => {
        if (node === null) return [];
        const attrs = node.attrs;
        const ordered = [];
        const seen = new Set();
        for (const key of ATTR_PRIORITY[node.kind] || []) {
          if (Object.prototype.hasOwnProperty.call(attrs, key) && attrs[key] !== undefined && !seen.has(key)) {
            seen.add(key);
            ordered.push(key);
          }
        }
        const rest = Object.keys(attrs)
          .filter((key) => !seen.has(key) && attrs[key] !== undefined)
          .sort((a, b) => a.localeCompare(b));
        return ordered.concat(rest).slice(0, 40);
      }, [node]);
      const jsonText = React.useMemo(() => {
        if (node === null) return '';
        const adjacent = incident.slice(0, 80).map((entry) => ({
          edgeId: entry.edge.id,
          direction: entry.direction,
          kind: entry.edge.kind,
          confidence: entry.edge.confidence,
          evidenceCount: entry.edge.evidenceCount,
          nodeId: entry.neighbour === null ? (entry.direction === 'out' ? entry.edge.to : entry.edge.from) : entry.neighbour.id,
          label: entry.neighbour === null ? null : entry.neighbour.label,
        }));
        return safeJson({
          node: {
            id: node.id,
            kind: node.kind,
            key: node.key,
            label: node.label,
            status: node.status,
            confidence: node.confidence,
            verification: node.verification,
            crown: node.crown,
            evidenceCount: node.evidenceCount,
            degree: node.adjDegree,
            tags: node.tags,
            attrs: node.attrs,
            firstSeen: node.firstSeen,
            lastSeen: node.lastSeen,
          },
          adjacentEdges: adjacent,
        });
      }, [node, incident]);
      React.useEffect(() => () => {
        if (timerRef.current !== null && typeof clearTimeout === 'function') {
          clearTimeout(timerRef.current);
          timerRef.current = null;
        }
      }, []);

      function showCopied(kind) {
        setCopied(kind);
        if (typeof setTimeout !== 'function') return;
        if (timerRef.current !== null) clearTimeout(timerRef.current);
        timerRef.current = setTimeout(() => {
          timerRef.current = null;
          setCopied(null);
        }, 2600);
      }

      function copyText(text, kind) {
        try {
          if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            const result = navigator.clipboard.writeText(text);
            if (result && typeof result.then === 'function') {
              result.then(() => showCopied(kind), () => showCopied('fail'));
              return;
            }
            showCopied(kind);
            return;
          }
        } catch (ignored) {
          // Clipboard API can be unavailable or denied; fall back to the textarea.
        }
        showCopied('fail');
      }

      const copiedMessage = copied === 'fail'
        ? t('detail.copyFailed')
        : (copied === null ? '' : t('detail.copied'));

      if (node === null) {
        return h('div', { className: 'atk-detail' },
          h('div', { className: 'atk-detail-head' },
            h('h3', { className: 'atk-detail-title' }, t('detail.title')),
            h('button', {
              type: 'button',
              className: 'atk-btn atk-btn-icon atk-detail-close',
              'aria-label': t('detail.close'),
              onClick: props.onClose,
            }, '×')),
          props.nodeId === null || props.nodeId === undefined
            ? h('div', { className: 'atk-empty-hint' }, t('detail.empty'))
            : h('div', { className: 'atk-empty-hint' }, t('detail.hidden')),
          h('div', { className: 'atk-live', role: 'status', 'aria-live': 'polite' }, copiedMessage));
      }

      if (node.kind === 'finding') {
        return h(FindingDetailPane, {
          t,
          node,
          incident,
          hostFallback: soleExternalHost(model),
          jsonText,
          copyText,
          copiedMessage,
          onClose: props.onClose,
          onFocus: props.onFocus,
        });
      }
      const kindLabel = localized(t, 'kind', node.kind);
      const attrs = node.attrs || {};
      const textOf = (...keys) => {
        for (const key of keys) {
          const value = attrs[key];
          if (typeof value === 'number' && Number.isFinite(value)) return String(value);
          if (typeof value !== 'string') continue;
          const trimmed = value.trim();
          if (trimmed.length === 0 || trimmed === 'null' || trimmed === 'unknown') continue;
          if (/secret|password|token|passwd/iu.test(key)) continue;
          return trimmed.length > 280 ? `${trimmed.slice(0, 280)}…` : trimmed;
        }
        return '';
      };
      const facts = [];
      const addFact = (label, value) => {
        if (value.length > 0) facts.push([label, value]);
      };
      let summary = t('detail.genericStory');
      if (node.kind === 'access' || node.kind === 'credential' || node.kind === 'pivot') {
        summary = footholdStory(node);
        addFact(t('detail.factHost'), footholdPlace(node));
        addFact(t('detail.factAddress'), textOf('ip', 'addr'));
        addFact(t('detail.factPrivilege'), privilegeZh(textOf('privilege', 'role', 'user', 'osUser')));
        addFact(t('detail.factAccount'), node.kind === 'credential' ? textOf('username') : '');
        const service = serviceZh(textOf('service'));
        if (service.length > 0) addFact(t('detail.factWhere'), service);
      } else if (node.kind === 'data') {
        summary = t('detail.dataStory');
        addFact(t('detail.factWhere'), textOf('dataClass', 'table', 'name'));
        addFact(t('detail.factAmount'), textOf('count', 'rows'));
        addFact(t('detail.factHost'), textOf('host', 'subjectKey'));
      } else if (node.kind === 'host' || node.kind === 'ip' || node.kind === 'domain') {
        summary = t('detail.hostStory');
        addFact(t('detail.factHost'), textOf('fqdn', 'hostname', 'host') || node.label);
        addFact(t('detail.factAddress'), textOf('addr', 'ip'));
        addFact(t('detail.factWhere'), textOf('realm', 'os'));
      } else if (node.kind === 'service') {
        summary = t('detail.serviceStory');
        addFact(t('col.port'), textOf('port'));
        addFact(t('col.protocol'), textOf('protocol', 'transport'));
        addFact(t('col.title'), textOf('banner', 'service', 'title'));
        addFact(t('detail.factHost'), textOf('endpoint', 'host'));
      } else if (node.kind === 'webapp') {
        summary = t('detail.webappStory');
        addFact(t('detail.factHost'), textOf('url', 'host'));
        addFact(t('col.title'), textOf('title', 'server'));
        addFact(t('detail.factWhere'), textOf('tech'));
      } else if (node.kind === 'target') {
        summary = attrs.internalTarget === true ? t('detail.pivotStory') : t('detail.hostStory');
        addFact(t('detail.factWhere'), textOf('groupSummary'));
      }
      addFact(t('detail.status'), localized(t, 'status', node.status));
      const displayTitle = node.label === node.key
        ? (facts.find((fact) => fact[0] === t('detail.factHost'))?.[1] || node.label)
        : node.label;
      return h('div', { className: 'atk-detail' },
        h('div', { className: 'atk-detail-head' },
          h('h3', { className: 'atk-detail-title' }, displayTitle),
          h('button', {
            type: 'button',
            className: 'atk-btn atk-btn-icon atk-detail-close',
            'aria-label': t('detail.close'),
            onClick: props.onClose,
          }, '×')),
        h('div', { className: 'atk-tags' },
          h('span', {
            className: 'atk-tag',
            style: { color: nodeColor(node), borderColor: nodeColor(node) },
          }, kindLabel),
          node.crown ? h('span', { className: 'atk-tag' }, `★ ${t('stat.crown')}`) : null),
        props.inGraph === false
          ? h(Notice, { tone: 'info' }, t('detail.hidden'))
          : null,
        h('p', { className: 'atk-detail-callout' }, summary),
        h('div', { className: 'atk-finding-facts' }, facts.map((fact) => h('div', { key: fact[0], className: 'atk-fact' },
          h('span', { className: 'atk-fact-label' }, fact[0]),
          h('span', { className: 'atk-fact-value' }, fact[1])))),
        h('div', { className: 'atk-detail-section' },
          h('h4', { className: 'atk-detail-section-title' }, t('detail.related'), h('span', { className: 'atk-tab-count' }, String(incident.length))),
          incident.length === 0
            ? h('div', { className: 'atk-empty-hint' }, t('detail.edgesEmpty'))
            : h('div', { className: 'atk-edge-list' }, incident.slice(0, 80).map((entry) => {
              const neighbourId = entry.neighbour === null
                ? (entry.direction === 'out' ? entry.edge.to : entry.edge.from)
                : entry.neighbour.id;
              const neighbourLabel = entry.neighbour === null ? neighbourId : entry.neighbour.label;
              return h('button', {
                key: `${entry.edge.id}-${entry.direction}`,
                type: 'button',
                className: 'atk-edge-item',
                title: `${localized(t, 'edge', entry.edge.kind)} · ${percent(entry.edge.confidence)} · ${neighbourLabel}`,
                onClick: () => props.onSelectNode(neighbourId),
              },
              h('span', { className: 'atk-edge-dir' }, entry.direction === 'out' ? '→' : '←'),
              h('span', { className: 'atk-edge-kind' }, localized(t, 'edge', entry.edge.kind)),
              h('span', { className: 'atk-edge-conf' }, percent(entry.edge.confidence)),
              h('span', { className: 'atk-edge-neighbour' }, neighbourLabel),
              entry.edge.evidenceCount > 0
                ? h('span', { className: 'atk-edge-conf' }, t('detail.edgeEvidence', { count: entry.edge.evidenceCount }))
                : null);
            }))),
        h('div', { className: 'atk-detail-actions' },
          h('button', { type: 'button', className: 'atk-btn', onClick: () => props.onFocus(node.id) }, t('detail.focus')),
          h('button', { type: 'button', className: 'atk-btn', onClick: () => copyText(node.id, 'id') }, t('detail.copyId')),
          h('button', { type: 'button', className: 'atk-btn', onClick: () => copyText(jsonText, 'json') }, t('detail.copyJson'))),
        h('details', { className: 'atk-collapse' },
          h('summary', null, t('detail.json')),
          h('textarea', {
            className: 'atk-json',
            readOnly: true,
            spellCheck: false,
            'aria-label': t('detail.json'),
            value: jsonText,
          })),
        h('div', { className: 'atk-live', role: 'status', 'aria-live': 'polite' }, copiedMessage));
    }

    // ---------------------------------------------------------------------
    // Tables
    // ---------------------------------------------------------------------

    function SortTable(props) {
      const t = props.t;
      const columns = props.columns;
      const rows = props.rows;
      const sort = props.sort;
      const selectedId = props.selectedId;
      const content = rows.length === 0
        ? h(EmptyState, { title: props.emptyTitle, hint: props.emptyHint })
        : h('table', { className: 'atk-table', 'aria-label': props.ariaLabel },
          h('thead', null,
            h('tr', null, columns.map((column) => {
              const active = sort !== null && sort !== undefined && sort.key === column.key;
              return h('th', {
                key: column.key,
                scope: 'col',
                'aria-sort': active ? (sort.dir === 'desc' ? 'descending' : 'ascending') : 'none',
              }, h('button', {
                type: 'button',
                className: 'atk-sort',
                title: t('table.sortHint'),
                onClick: () => props.onSort(column.key),
              }, column.label, active ? h('span', { className: 'atk-sort-arrow' }, sort.dir === 'desc' ? '▼' : '▲') : null));
            }))),
          h('tbody', null, rows.map((row) => h('tr', {
            key: row.id,
            tabIndex: 0,
            'aria-selected': row.id === selectedId || (row.selectId !== undefined && row.selectId === selectedId),
            'aria-label': t('table.rowSelect', { label: row.label }),
            onClick: () => props.onSelect(row),
            onKeyDown: (event) => {
              if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
                event.preventDefault();
                props.onSelect(row);
              }
            },
          }, columns.map((column) => h('td', {
            key: column.key,
            className: column.wrap === true ? 'atk-cell-wrap' : undefined,
            title: column.title === undefined ? undefined : column.title(row),
          }, column.render === undefined ? valueText(sortValue(row, column.key)) : column.render(row)))))));
      if (props.bare === true) return content;
      return h('div', { className: 'atk-table-wrap' }, content);
    }

    function toggleSort(current, key, defaultDirection) {
      if (current !== null && current !== undefined && current.key === key) {
        return { key, dir: current.dir === 'desc' ? 'asc' : 'desc' };
      }
      return { key, dir: defaultDirection === undefined ? 'asc' : defaultDirection };
    }

    function nodeRowsFor(model, kinds, search, extraSort) {
      const rows = [];
      for (const node of model.nodes) {
        if (kinds.indexOf(node.kind) < 0) continue;
        if (search.length > 0 && node.search.indexOf(search) < 0) continue;
        const sortValues = {
          label: node.label,
          vulnType: node.findingType || '',
          kind: node.kind,
          status: node.status,
          severity: node.severity === null ? -1 : (SEVERITY_RANK[node.severity] || 0),
          verification: node.verification,
          confidence: node.confidence,
          links: node.adjDegree,
          evidence: node.evidenceCount,
          crown: node.crown ? 1 : 0,
          wildcard: asString(node.attrs.wildcardStatus, ''),
          port: asNumber(node.attrs.port, -1),
          protocol: asString(node.attrs.protocol, ''),
          title: asString(node.attrs.title, asString(node.attrs.url, asString(node.attrs.banner, asString(node.attrs.fqdn, '')))),
          privilege: asString(node.attrs.privilege, ''),
          validity: asString(node.attrs.validity, ''),
          dataClass: asString(node.attrs.dataClass, ''),
          count: asNumber(node.attrs.count, 0),
          cvss: verificationState(node) === 'passed' && typeof node.cvssScore === 'number' && Number.isFinite(node.cvssScore) ? node.cvssScore : -1,
        };
        if (extraSort !== undefined) {
          for (const key of Object.keys(extraSort)) sortValues[key] = extraSort[key](node);
        }
        rows.push({ id: node.id, selectId: node.id, label: node.label, node, sortValues });
      }
      return rows;
    }

    function labelCell(t, row) {
      return h('span', { title: row.node === undefined ? row.label : row.node.key },
        row.node !== undefined && row.node.crown === true ? '★ ' : '',
        truncateText(row.label, 64));
    }

    function escalationSeverityLabel(t, value) {
      const raw = String(value ?? '').toLowerCase();
      if (raw === 'critical' || raw === 'high' || raw === 'medium' || raw === 'low' || raw === 'info') return localized(t, 'severity', raw);
      return t('severity.unscored');
    }

    function displayFindingTitle(text) {
      const raw = String(text ?? '').trim();
      if (raw.length === 0) return '';
      return findingTitleZh('', raw);
    }

    function chineseEscalationText(proof, fromTitle, toTitle, fromSeverity, toSeverity) {
      let text = redactPacketClient(String(proof ?? ''));
      const pairs = [
        [/same target\s+\S+\.?/giu, '同一目标。'],
        [/harm increased from/giu, '危害从'],
        [/authenticated control of the tomcat manager web console/giu, '已认证控制 Tomcat 管理控制台'],
        [/high,\s*administrative ui access with war-deploy capability but no data access/giu, '高危的管理界面和部署能力，但还读不到数据'],
        [/to authenticated access to the production postgresql database that backs the site/giu, '提升为已认证访问支撑该网站的生产数据库'],
        [/\(critical,\s*data-plane confidentiality\/integrity,?/giu, '（严重，数据的机密性和完整性，'],
        [/cvss\s*3\.1/giu, 'CVSS 3.1'],
        [/proven\s+\d{4}-\d{2}-\d{2}\s*:/giu, '已验证：'],
        [/through the manager foothold a \d+-byte war was deployed/giu, '通过管理控制台立足点部署了应用'],
        [/\(upload http 200\)/giu, '（上传成功）'],
        [/command execution as uid=\d+\([^)]+\) was obtained/giu, '已获得应用用户的命令执行'],
        [/the jdbc credential was read server-side through [^.;]+/giu, '在服务器上读到了数据库连接配置'],
        [/the credential itself was never passed through the agent/giu, '凭证原文没有经过智能体'],
        [/a psql against [\d.:]+ returned[^.]+\./giu, '在本机数据库上查询成功。'],
        [/a census of \d+ public tables returned[^.]+\./giu, '统计了公开表的规模。'],
        [/evidence\s+\S+/giu, '证据已写入测试目录。'],
        [/command channel echoed nonce \S+\.?/giu, '命令通道回显了校验标记。'],
        [/cleanup:/giu, '清理：'],
        [/temporary \/\S+ context was undeployed[^.]+\./giu, '临时应用已卸载。'],
        [/cmd\.jsp then returned 404/giu, '临时页面之后返回 404'],
        [/this is verified database access, not a theoretical db reach\.?/giu, '这是已验证的数据库访问，不是推测。'],
        [/unauthenticated tomcat manager admin access/giu, '未授权的 Tomcat 管理入口'],
        [/via credential disclosed by/giu, '凭据来自'],
        [/file-read/giu, '任意文件读取'],
        [/escalated from/giu, '提升自'],
        [/stack-trace disclosure/giu, '堆栈跟踪泄露'],
        [/jdbc:[^\s]+/giu, '数据库连接'],
      ];
      for (const [pattern, replacement] of pairs) text = text.replace(pattern, replacement);
      text = text.replace(/(?:password|passwd|pwd)\s*[=:]\s*\S+/giu, '口令已脱敏');
      if (/[\u3400-\u9fff]/u.test(text)) {
        text = text.replace(/\b(?:[A-Za-z]+(?:'[A-Za-z]+)?\s+){5,}[A-Za-z]+(?:'[A-Za-z]+)?\b/gu, '');
        text = text.replace(/\s{2,}/gu, ' ').replace(/\s+([，。])/gu, '$1').trim();
      }
      if (!/[\u3400-\u9fff]/u.test(text)) {
        return `危害从${fromSeverity}提升到${toSeverity}。原来是${fromTitle}，提升后是${toTitle}。`;
      }
      return text;
    }

    function escalationView(t, node) {
      const attrs = node?.attrs || {};
      const raised = node?.raisedTo;
      if (raised !== undefined && raised !== null) {
        const fromTitle = displayFindingTitle(node.sourceLabel || node.label) || node.label;
        const toTitle = raised.title || '漏洞危害提升成功';
        if (fromTitle.length === 0 || fromTitle === toTitle) return null;
        const fromSeverity = escalationSeverityLabel(t, raised.fromSeverity);
        const toSeverity = escalationSeverityLabel(t, raised.toSeverity);
        return {
          fromTitle,
          toTitle,
          fromSeverity,
          toSeverity,
          proof: chineseEscalationText(raised.proof, fromTitle, toTitle, fromSeverity, toSeverity),
        };
      }
      const proof = String(attrs.escalationProof ?? '').trim();
      if (proof.length === 0) return null;
      const source = node?.sourceLabel || node?.label || attrs.title || '';
      const toNamed = findingHarmName('', findingHarmText(source));
      let toTitle = formatHarmName(toNamed);
      if (toTitle.length === 0 || toTitle === '其他漏洞' || source === '手工记录漏洞' || /^manual(?:-finding)?$/iu.test(source)) toTitle = '漏洞危害提升成功';
      const cause = findingCauseText(source);
      const causeNamed = cause.length > 0 ? findingHarmName('', cause) : null;
      const storedNamed = findingHarmName('', findingOwnText(attrs.escalatedFromTitle));
      const fromNamed = causeNamed !== null && causeNamed.name !== '其他漏洞' ? causeNamed : storedNamed;
      const fromTitle = formatHarmName(fromNamed) || displayFindingTitle(attrs.escalatedFromTitle);
      if (fromTitle.length === 0 || fromTitle === toTitle) return null;
      if (toNamed.name !== '其他漏洞' && !harmEnables(fromNamed.name, toNamed.name) && toTitle !== '漏洞危害提升成功') return null;
      const fromSeverity = escalationSeverityLabel(t, attrs.escalatedFromSeverity);
      const toSeverity = escalationSeverityLabel(t, attrs.escalatedToSeverity || attrs.severity);
      return {
        fromTitle,
        toTitle,
        fromSeverity,
        toSeverity,
        proof: chineseEscalationText(proof, fromTitle, toTitle, fromSeverity, toSeverity),
      };
    }

    function severityCell(t, row) {
      const node = row.node;
      if (node === undefined || node.severity === null) return '—';
      if (node.kind === 'finding' && verificationState(node) !== 'passed') return t('severity.unscored');
      return h('span', { style: { color: SEVERITY_COLOR[node.severity] || KIND_COLOR.finding } }, localized(t, 'severity', node.severity));
    }

    function findingVerdict(t, node) {
      if (node === undefined || node.kind !== 'finding') return '—';
      if (node.isVulnerability === true || node.includedVulnerability === true) {
        if (node.refuted === true) return t('finding.verdictRefutedVulnerability');
        return node.qualified === true ? t('finding.verdictVerifiedVulnerability') : t('finding.verdictPendingVulnerability');
      }
      if (node.severity === 'unscored') return t('finding.verdictUnscored');
      return t('finding.verdictNotVulnerability');
    }

    function columnsForTab(tab, t) {
      const label = { key: 'label', label: t('col.label'), render: (row) => labelCell(t, row) };
      const kind = { key: 'kind', label: t('col.kind'), render: (row) => localized(t, 'kind', row.node.kind) };
      const status = { key: 'status', label: t('col.status'), render: (row) => localized(t, 'status', row.node.status) };
      const links = { key: 'links', label: t('col.degree'), render: (row) => String(row.node.adjDegree) };
      const evidence = { key: 'evidence', label: t('col.evidence'), render: (row) => String(row.node.evidenceCount) };
      const verification = { key: 'verification', label: t('col.verification'), render: (row) => localized(t, 'verification', row.node.verification) };
      const confidence = { key: 'confidence', label: t('col.confidence'), render: (row) => percent(row.node.confidence) };
      if (tab === 'services') {
        return [
          label,
          kind,
          { key: 'port', label: t('col.port'), render: (row) => (asNumber(row.node.attrs.port, -1) < 0 ? '—' : String(row.node.attrs.port)) },
          { key: 'protocol', label: t('col.protocol'), render: (row) => asString(row.node.attrs.protocol, '—') },
          { key: 'title', label: t('col.title'), render: (row) => truncateText(asString(row.node.attrs.title, asString(row.node.attrs.url, asString(row.node.attrs.banner, '—'))), 60) },
          status,
          links,
        ];
      }
      if (tab === 'findings' || tab === 'vulnerabilities') {
        return [
          label,
          {
            key: 'vulnType',
            label: t('col.vulnType'),
            render: (row) => {
              if (row.node.kind === 'access') return '权限';
              if (row.node.kind === 'credential') return '凭据';
              if (row.node.kind === 'pivot') return '跳板';
              if (row.node.kind === 'data') return '数据证据';
              return row.node.findingType || findingTypeZh(row.node.attrs?.template, `${row.node.attrs?.title ?? ''} ${row.node.label}`);
            },
          },
          {
            key: 'escalation',
            label: t('col.escalation'),
            render: (row) => {
              const view = escalationView(t, row.node);
              if (view === null) return '—';
              return h('span', { className: 'atk-escalation-cell' }, `${view.fromTitle} → ${view.toTitle}`, h('br'), `${view.fromSeverity} → ${view.toSeverity}`);
            },
          },
          {
            key: 'cvss',
            label: t('col.cvss'),
            render: (row) => {
              if (verificationState(row.node) !== 'passed') return t('severity.unscored');
              const score = row.node.cvssScore;
              if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 10) return t('severity.unscored');
              const severity = asString(row.node.cvssSeverity, '').toLowerCase();
              const label = severity.length > 0 ? localized(t, 'severity', severity) : '';
              return h('span', { style: { color: SEVERITY_COLOR[severity] || KIND_COLOR.finding } }, `${score.toFixed(1)}${label ? ` ${label}` : ''}`);
            },
          },
          {
            key: 'verification',
            label: t('col.verification'),
            render: (row) => t(`verification.${verificationState(row.node)}`),
          },
          evidence,
          links,
        ];
      }
      if (tab === 'access') {
        return [
          label,
          kind,
          status,
          { key: 'privilege', label: t('col.privilege'), render: (row) => privilegeZh(row.node.attrs.privilege) || '—' },
          { key: 'validity', label: t('col.validity'), render: (row) => {
            const text = String(row.node.attrs.validity ?? '').toLowerCase();
            if (text === 'validated' || text === 'valid') return '已验证';
            if (text === 'invalid' || text === 'rejected') return '无效';
            if (text.length === 0 || text === 'unknown' || text === 'untested') return '—';
            return row.node.attrs.validity;
          } },
          verification,
          links,
        ];
      }
      if (tab === 'data') {
        return [
          label,
          kind,
          { key: 'dataClass', label: t('col.dataClass'), render: (row) => asString(row.node.attrs.dataClass, '—') },
          { key: 'count', label: t('col.count'), render: (row) => String(asNumber(row.node.attrs.count, 0)) },
          status,
          evidence,
          links,
        ];
      }
      return [
        label,
        kind,
        status,
        { key: 'wildcard', label: t('col.wildcard'), render: (row) => asString(row.node.attrs.wildcardStatus, '—') },
        links,
        { key: 'crown', label: t('col.crown'), render: (row) => (row.node.crown ? t('bool.true') : '') },
      ];
    }

    const TAB_SPECS = {
      assets: { kinds: ['host', 'ip', 'cidr', 'segment'], defaultSort: { key: 'links', dir: 'desc' } },
      services: { kinds: ['service', 'webapp', 'tech'], defaultSort: { key: 'port', dir: 'asc' } },
      vulnerabilities: { kinds: ['finding'], defaultSort: { key: 'severity', dir: 'desc' } },
      access: { kinds: ['credential', 'access', 'pivot'], defaultSort: { key: 'kind', dir: 'asc' } },
      data: { kinds: ['data'], defaultSort: { key: 'count', dir: 'desc' } },
    };

    function NodeDataTable(props) {
      const t = props.t;
      const spec = TAB_SPECS[props.tab] || TAB_SPECS.assets;
      const [sort, setSort] = React.useState(spec.defaultSort);
      const rows = React.useMemo(() => nodeRowsFor(props.model, spec.kinds, props.search).filter((row) => {
        if (props.tab === 'vulnerabilities' || props.tab === 'findings') return row.node?.includedVulnerability === true && row.node?.refuted !== true;
        return spec.predicate === undefined || spec.predicate(row.node);
      }), [props.model, spec.kinds, spec.predicate, props.search, props.tab]);
      const sorted = React.useMemo(() => sortRows(rows, sort, 'label'), [rows, sort]);
      const columns = React.useMemo(() => columnsForTab(props.tab, t), [props.tab, t]);
      const emptyHint = props.tab === 'vulnerabilities'
        ? t('table.emptyVulnHint')
        : t('table.emptyHint');
      return h(SortTable, {
        t,
        columns,
        rows: sorted,
        sort,
        onSort: (key) => setSort((current) => toggleSort(current, key, 'asc')),
        selectedId: props.selectedId,
        onSelect: props.onSelect,
        ariaLabel: t(`tab.${props.tab}`),
        emptyTitle: t('table.empty', { tab: t(`tab.${props.tab}`) }),
        emptyHint,
      });
    }

    function taskRows(model, search) {
      const rows = [];
      for (const task of model.tasks) {
        const haystack = `${task.label} ${task.actionType} ${task.status} ${task.risk} ${task.why.join(' ')}`.toLowerCase();
        if (search.length > 0 && haystack.indexOf(search) < 0) continue;
        rows.push({
          id: task.id,
          selectId: task.id,
          label: task.label,
          task,
          sortValues: {
            label: task.label,
            actionType: task.actionType,
            priority: task.priority,
            risk: task.risk,
            status: task.status,
          },
        });
      }
      return rows;
    }

    function TasksTable(props) {
      const t = props.t;
      const [sort, setSort] = React.useState({ key: 'priority', dir: 'desc' });
      const rows = React.useMemo(() => taskRows(props.model, props.search), [props.model, props.search]);
      const sorted = React.useMemo(() => sortRows(rows, sort, 'label'), [rows, sort]);
      const columns = React.useMemo(() => [
        { key: 'label', label: t('col.label'), render: (row) => labelCell(t, row) },
        { key: 'actionType', label: t('col.actionType'), render: (row) => row.task.actionType },
        { key: 'priority', label: t('col.priority'), render: (row) => row.task.priority.toFixed(1) },
        { key: 'risk', label: t('col.risk'), render: (row) => localized(t, 'risk', row.task.risk) },
        { key: 'status', label: t('col.status'), render: (row) => localized(t, 'status', row.task.status) },
        { key: 'why', label: t('col.why'), wrap: true, render: (row) => truncateText(row.task.why.join('; '), 120) },
      ], [t]);
      return h(SortTable, {
        t,
        columns,
        rows: sorted,
        sort,
        onSort: (key) => setSort((current) => toggleSort(current, key, 'desc')),
        selectedId: props.selectedId,
        onSelect: props.onSelect,
        ariaLabel: t('tab.tasks'),
        emptyTitle: t('table.empty', { tab: t('tab.tasks') }),
        emptyHint: t('table.emptyHint'),
      });
    }

    function teamStatusOptions(model) {
      const seen = new Set();
      for (const batch of model.team.batches) seen.add(batch.status);
      return [...seen].sort((a, b) => {
        const rankA = TEAM_STATUS_RANK[a] === undefined ? 99 : TEAM_STATUS_RANK[a];
        const rankB = TEAM_STATUS_RANK[b] === undefined ? 99 : TEAM_STATUS_RANK[b];
        return rankA - rankB || a.localeCompare(b);
      });
    }

    function teamStatusColor(status) {
      if (status === 'failed' || status === 'merge_failed') return 'var(--dsw-alias-state-error-primary)';
      if (status === 'merged' || status === 'completed') return 'var(--dsw-alias-state-success-primary)';
      if (status === 'artifact_ready') return 'var(--dsw-alias-state-business-primary)';
      if (status === 'planned' || status === 'dispatched') return 'var(--dsw-alias-state-warn-label)';
      return 'var(--dsw-alias-label-secondary)';
    }

    function teamRows(model, search, statusFilter) {
      const rows = [];
      for (const batch of model.team.batches) {
        if (statusFilter !== 'all' && batch.status !== statusFilter) continue;
        const haystack = `${batch.batchId} ${batch.label} ${batch.status} ${batch.agentName} ${batch.childId} ${batch.mode} ${batch.artifactPath} ${batch.error}`.toLowerCase();
        if (search.length > 0 && haystack.indexOf(search) < 0) continue;
        rows.push({
          id: batch.id,
          selectId: batch.id,
          label: batch.batchId,
          batch,
          sortValues: {
            batchId: batch.batchId,
            status: TEAM_STATUS_RANK[batch.status] === undefined ? 99 : TEAM_STATUS_RANK[batch.status],
            assets: batch.assetCount,
            agent: batch.agentName.length > 0 ? batch.agentName : batch.childId,
            mode: batch.mode,
            artifact: batch.artifactPath,
            mergedAt: batch.mergedAt === null ? '' : batch.mergedAt,
          },
        });
      }
      return rows;
    }

    function TeamTable(props) {
      const t = props.t;
      const [sort, setSort] = React.useState({ key: 'batchId', dir: 'asc' });
      const [statusFilter, setStatusFilter] = React.useState('all');
      const batches = props.model.team.batches;
      const options = React.useMemo(() => teamStatusOptions(props.model), [props.model]);
      const activeFilter = statusFilter === 'all' || options.indexOf(statusFilter) >= 0 ? statusFilter : 'all';
      const rows = React.useMemo(
        () => teamRows(props.model, props.search, activeFilter),
        [props.model, props.search, activeFilter],
      );
      const sorted = React.useMemo(() => sortRows(rows, sort, 'batchId'), [rows, sort]);
      const columns = React.useMemo(() => [
        {
          key: 'batchId',
          label: t('col.batchId'),
          render: (row) => h('span', { className: 'atk-kv-mono', title: row.batch.label }, truncateText(row.batch.batchId, 30)),
        },
        {
          key: 'status',
          label: t('col.status'),
          render: (row) => h('span', {
            style: { color: teamStatusColor(row.batch.status) },
            title: row.batch.error.length > 0 ? row.batch.error : undefined,
          }, localized(t, 'status', row.batch.status)),
        },
        {
          key: 'assets',
          label: t('col.assets'),
          title: (row) => (row.batch.assetLabels.length > 0 ? row.batch.assetLabels.join(', ') : undefined),
          render: (row) => String(row.batch.assetCount),
        },
        {
          key: 'agent',
          label: t('col.agent'),
          title: (row) => {
            if (row.batch.agentName.length > 0) return row.batch.agentName;
            if (row.batch.childId.length > 0) return row.batch.childId;
            return undefined;
          },
          render: (row) => {
            if (row.batch.agentName.length > 0) return truncateText(row.batch.agentName, 26);
            if (row.batch.childId.length > 0) return truncateText(row.batch.childId, 26);
            return '—';
          },
        },
        {
          key: 'mode',
          label: t('col.mode'),
          render: (row) => (row.batch.mode.length > 0 ? row.batch.mode : '—'),
        },
        {
          key: 'artifact',
          label: t('col.artifact'),
          render: (row) => {
            if (row.batch.artifactPath.length === 0) return '—';
            const marker = row.batch.artifactReady ? '✓' : '…';
            const stateLabel = row.batch.artifactReady ? t('team.artifactReady') : t('team.artifactPending');
            return h('span', { title: `${stateLabel} · ${row.batch.artifactPath}` }, `${marker} ${truncateText(row.batch.artifactPath, 40)}`);
          },
        },
        { key: 'mergedAt', label: t('col.mergedAt'), render: (row) => formatTime(row.batch.mergedAt) },
      ], [t]);
      const filtered = props.search.length > 0 || activeFilter !== 'all';
      const emptyTitle = batches.length === 0
        ? t('team.empty')
        : (filtered ? t('team.emptyFiltered') : t('team.empty'));
      const emptyHint = batches.length === 0 ? t('team.emptyHint') : t('table.searchEmpty');
      return h('div', { style: { display: 'flex', flexDirection: 'column', flex: '1 1 auto', minHeight: 0 } },
        batches.length === 0
          ? null
          : h('div', {
            style: { display: 'flex', alignItems: 'center', gap: '8px', flex: 'none', padding: '0 2px 6px' },
          },
          h('label', { className: 'atk-toolbar-label' }, t('team.statusFilter')),
          h('select', {
            className: 'atk-select',
            value: activeFilter,
            'aria-label': t('team.statusFilter'),
            onChange: (event) => setStatusFilter(event.target.value),
          },
          h('option', { value: 'all' }, t('team.statusAll')),
          options.map((status) => h('option', { key: status, value: status }, localized(t, 'status', status)))),
          h('span', { className: 'atk-spacer' }),
          h('span', { className: 'atk-toolbar-label' }, t('team.summary', { shown: rows.length, total: batches.length }))),
        h(SortTable, {
          t,
          columns,
          rows: sorted,
          sort,
          onSort: (key) => setSort((current) => toggleSort(current, key, 'asc')),
          selectedId: props.selectedId,
          onSelect: props.onSelect,
          ariaLabel: t('team.title'),
          emptyTitle,
          emptyHint,
        }));
    }

    const LOOP_VERDICT_RANK = { hold: 1, pivot: 2, verify: 3, escalate: 4, stop: 5, unknown: 0 };
    const LOOP_INTENT_STATUS_RANK = { open: 1, claimed: 2, blocked: 3, completed: 4, merged: 5, unknown: 9 };
    const LOOP_LESSON_STATUS_RANK = { active: 1, retired: 2, unknown: 9 };

    function verdictColor(verdict) {
      if (verdict === 'stop') return 'var(--dsw-alias-state-error-primary)';
      if (verdict === 'escalate') return 'var(--dsw-alias-state-business-primary)';
      if (verdict === 'verify') return 'var(--dsw-alias-state-warn-label)';
      if (verdict === 'pivot') return 'var(--dsw-alias-label-secondary)';
      if (verdict === 'hold') return 'var(--dsw-alias-label-tertiary)';
      return 'var(--dsw-alias-label-secondary)';
    }

    function expectedEvidenceText(value) {
      if (value === null || value === undefined) return '—';
      return truncateText(valueText(value), 90);
    }

    function loopSupervisionRows(loop, search) {
      const rows = [];
      for (const row of loop.supervisions) {
        const haystack = `${row.round} ${row.type} ${row.verdict} ${row.source} ${row.diagnosis} ${row.nextPlan}`.toLowerCase();
        if (search.length > 0 && haystack.indexOf(search) < 0) continue;
        rows.push({
          id: row.id,
          selectId: row.id,
          label: `${row.round} · ${row.verdict}`,
          round: row.round,
          type: row.type,
          verdict: row.verdict,
          source: row.source,
          confidence: row.confidence,
          createdAt: row.createdAt,
          sortValues: {
            round: row.round,
            type: row.type,
            verdict: LOOP_VERDICT_RANK[row.verdict] === undefined ? 0 : LOOP_VERDICT_RANK[row.verdict],
            source: row.source,
            confidence: row.confidence,
            createdAt: row.createdAt === null ? '' : row.createdAt,
          },
        });
      }
      return rows;
    }

    function loopIntentRows(loop, search) {
      const rows = [];
      for (const row of loop.intents) {
        const evidence = expectedEvidenceText(row.expectedEvidence);
        const haystack = `${row.id} ${row.actionType} ${row.targetLabel} ${row.status} ${row.scopeVerdict} ${evidence}`.toLowerCase();
        if (search.length > 0 && haystack.indexOf(search) < 0) continue;
        rows.push({
          id: row.id,
          selectId: row.id,
          label: `${row.actionType} · ${row.targetLabel}`,
          actionType: row.actionType,
          actionId: row.actionId,
          targetLabel: row.targetLabel,
          status: row.status,
          priority: row.priority,
          round: row.round,
          expectedEvidence: row.expectedEvidence,
          scopeVerdict: row.scopeVerdict,
          sortValues: {
            actionType: row.actionType,
            targetLabel: row.targetLabel,
            status: LOOP_INTENT_STATUS_RANK[row.status] === undefined ? 9 : LOOP_INTENT_STATUS_RANK[row.status],
            priority: row.priority,
            round: row.round,
            expectedEvidence: evidence,
          },
        });
      }
      return rows;
    }

    function loopLessonRows(loop, search) {
      const rows = [];
      for (const row of loop.lessons) {
        const haystack = `${row.lessonKey} ${row.idea} ${row.method} ${row.route} ${row.chain} ${row.status} ${row.when.join(' ')}`.toLowerCase();
        if (search.length > 0 && haystack.indexOf(search) < 0) continue;
        rows.push({
          id: row.id,
          selectId: row.id,
          label: row.lessonKey,
          lessonKey: row.lessonKey,
          idea: row.idea,
          method: row.method,
          route: row.route,
          chain: row.chain,
          confidence: row.confidence,
          wins: row.wins,
          fails: row.fails,
          uses: row.uses,
          status: row.status,
          sortValues: {
            lessonKey: row.lessonKey,
            route: row.route,
            idea: row.idea,
            confidence: row.confidence,
            wins: row.wins,
            fails: row.fails,
            uses: row.uses,
            status: LOOP_LESSON_STATUS_RANK[row.status] === undefined ? 9 : LOOP_LESSON_STATUS_RANK[row.status],
          },
        });
      }
      return rows;
    }

    function SettingsPanel(props) {
      const t = props.t;
      const [data, setData] = React.useState(null);
      const [error, setError] = React.useState('');
      const [notice, setNotice] = React.useState('');
      const [busy, setBusy] = React.useState('');
      const [proxyForm, setProxyForm] = React.useState({ url: '', mode: 'local', noProxy: '' });
      const [surveyForms, setSurveyForms] = React.useState({});
      const [surveyTests, setSurveyTests] = React.useState({});

      async function readJson(response) {
        const text = await response.text();
        let value;
        try { value = text.length > 0 ? JSON.parse(text) : {}; } catch { throw new Error(text.slice(0, 240)); }
        if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
        return value;
      }
      async function load() {
        try {
          const response = await fetch('/atkbrain/settings/status', { cache: 'no-store' });
          const value = await readJson(response);
          setData(value);
          setError('');
          setSurveyForms((current) => {
            const next = { ...current };
            for (const [id, provider] of Object.entries(value.settings?.survey || {})) {
              if (next[id] === undefined) next[id] = {
                enabled: provider.enabled === true,
                baseUrl: provider.baseUrl || '',
                email: provider.email || '',
                apiKey: '',
                keyEnv: provider.keyEnv || '',
              };
            }
            return next;
          });
        } catch (err) {
          setError(err instanceof Error ? err.message : String(err));
        }
      }
      async function postSettings(body) {
        const response = await fetch('/atkbrain/settings', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        });
        return await readJson(response);
      }
      async function checkAll() {
        setBusy('check');
        setNotice('');
        try {
          const value = await postSettings({ action: 'check' });
          setData(value);
          setError('');
          setNotice(t('settings.saved'));
        } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
        finally { setBusy(''); }
      }
      async function saveSurvey(id) {
        const form = surveyForms[id] || {};
        setBusy(`save:${id}`);
        setNotice('');
        try {
          const value = await postSettings({
            action: 'saveSurvey',
            provider: id,
            config: {
              enabled: form.enabled === true,
              baseUrl: form.baseUrl,
              email: form.email,
              keyEnv: form.keyEnv,
              apiKey: form.apiKey,
            },
          });
          setData((current) => current === null ? current : { ...current, settings: value.settings, survey: value.survey });
          setSurveyForms((current) => ({ ...current, [id]: { ...(current[id] || {}), apiKey: '' } }));
          setNotice(`${t('settings.saved')} · ${id.toUpperCase()}`);
          setError('');
        } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
        finally { setBusy(''); }
      }
      async function clearSurvey(id) {
        setBusy(`clear:${id}`);
        try {
          const value = await postSettings({ action: 'saveSurvey', provider: id, config: { clearKey: true } });
          setData((current) => current === null ? current : { ...current, settings: value.settings, survey: value.survey });
          setSurveyTests((current) => ({ ...current, [id]: { ok: true, message: t('settings.saved') } }));
          setNotice(t('settings.saved'));
        } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
        finally { setBusy(''); }
      }
      async function testSurvey(id) {
        setBusy(`test:${id}`);
        try {
          const value = await postSettings({ action: 'testSurvey', provider: id });
          setSurveyTests((current) => ({ ...current, [id]: value }));
        } catch (err) {
          setSurveyTests((current) => ({ ...current, [id]: { ok: false, message: err instanceof Error ? err.message : String(err) } }));
        } finally { setBusy(''); }
      }
      async function saveProxy() {
        setBusy('proxy');
        setNotice('');
        try {
          const body = { action: 'enable', mode: proxyForm.mode };
          if (proxyForm.url.trim().length > 0) body.url = proxyForm.url.trim();
          if (proxyForm.noProxy.trim().length > 0) body.noProxy = proxyForm.noProxy.trim();
          const response = await fetch('/atkbrain/proxy', {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
          });
          await readJson(response);
          setProxyForm({ url: '', mode: proxyForm.mode, noProxy: proxyForm.noProxy });
          setNotice(t('settings.proxySaved'));
          await load();
        } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
        finally { setBusy(''); }
      }
      async function proxyAction(action) {
        setBusy(`proxy:${action}`);
        try {
          const response = await fetch('/atkbrain/proxy', {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action }),
          });
          await readJson(response);
          setNotice(action === 'disable' ? t('settings.proxySaved') : '');
          await load();
        } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
        finally { setBusy(''); }
      }
      React.useEffect(() => { void load(); }, []);

      if (data === null) {
        return h('div', { className: 'atk-settings' },
          h('div', { className: 'atk-settings-head' }, h('h3', null, t('settings.title')), h('span', { className: 'atk-empty-hint' }, t('settings.hint'))),
          error.length > 0 ? h('div', { className: 'atk-settings-error' }, error) : h('div', { className: 'atk-empty-hint' }, t('settings.checking')));
      }

      const survey = data.settings?.survey || {};
      const proxy = data.proxy || {};
      const providers = ['fofa', 'hunter', 'quake'];
      const providerSection = h('section', { className: 'atk-settings-section' },
        h('div', { className: 'atk-settings-section-head' }, h('h4', null, t('settings.survey')), h('span', { className: 'atk-empty-hint' }, t('settings.surveyHint'))),
        h('div', { className: 'atk-settings-survey-grid' }, providers.map((id) => {
          const form = surveyForms[id] || { enabled: false, baseUrl: '', email: '', apiKey: '', keyEnv: '' };
          const meta = survey[id] || {};
          const test = surveyTests[id];
          return h('div', { key: id, className: 'atk-settings-survey' },
            h('div', { className: 'atk-settings-survey-head' },
              h('strong', null, t(`settings.${id}`)),
              h('label', { className: 'atk-settings-check' }, h('input', { type: 'checkbox', checked: form.enabled === true, onChange: (event) => setSurveyForms((current) => ({ ...current, [id]: { ...form, enabled: event.target.checked } })) }), t('settings.enabled'))),
            h('label', { className: 'atk-settings-field' }, t('settings.baseUrl'), h('input', { value: form.baseUrl, onChange: (event) => setSurveyForms((current) => ({ ...current, [id]: { ...form, baseUrl: event.target.value } })) })),
            id === 'fofa' ? h('label', { className: 'atk-settings-field' }, t('settings.email'), h('input', { value: form.email, onChange: (event) => setSurveyForms((current) => ({ ...current, [id]: { ...form, email: event.target.value } })) })) : null,
            h('label', { className: 'atk-settings-field' }, t('settings.apiKey'), h('input', { type: 'password', autocomplete: 'off', value: form.apiKey, placeholder: meta.configured ? t('settings.keyConfigured', { mask: meta.keyMask || '******' }) : '', onChange: (event) => setSurveyForms((current) => ({ ...current, [id]: { ...form, apiKey: event.target.value } })) })),
            h('label', { className: 'atk-settings-field' }, t('settings.keyEnv'), h('input', { value: form.keyEnv, onChange: (event) => setSurveyForms((current) => ({ ...current, [id]: { ...form, keyEnv: event.target.value } })) })),
            h('div', { className: 'atk-settings-actions' },
              h('button', { type: 'button', className: 'atk-btn atk-btn-primary', disabled: busy !== '', onClick: () => saveSurvey(id) }, t('settings.save')),
              h('button', { type: 'button', className: 'atk-btn', disabled: busy !== '' || meta.configured !== true, onClick: () => testSurvey(id) }, busy === `test:${id}` ? t('settings.testing') : t('settings.testKey')),
              meta.configured ? h('button', { type: 'button', className: 'atk-btn', disabled: busy !== '', onClick: () => clearSurvey(id) }, t('settings.clearKey')) : null),
            test ? h('div', { className: `atk-settings-test ${test.ok ? 'ok' : 'error'}` }, `${test.ok ? '✓' : '✕'} ${test.message || test.error || ''}`) : null);
        })));
      const proxySection = h('section', { className: 'atk-settings-section' },
        h('div', { className: 'atk-settings-section-head' }, h('h4', null, t('settings.proxy')), h('span', { className: 'atk-empty-hint' }, t('settings.proxyHint'))),
        h('div', { className: 'atk-settings-proxy' },
          h('div', { className: 'atk-settings-proxy-state' },
            h('span', { className: `atk-settings-dot atk-settings-dot--${proxy.blocked ? 'error' : proxy.active ? 'ok' : 'warn'}` }),
            h('strong', null, proxy.enabled ? (proxy.blocked ? t('proxy.blocked') : t('proxy.enabled')) : t('proxy.disabled')),
            h('span', { className: 'atk-empty-hint' }, `${proxy.mode || 'local'} · ${proxy.exitIp || t('proxy.noExit')}${proxy.error ? ` · ${proxy.error}` : ''}`)),
          h('div', { className: 'atk-settings-fields' },
            h('label', { className: 'atk-settings-field' }, t('settings.proxyUrl'), h('input', { value: proxyForm.url, placeholder: proxy.current?.proxy || 'http://127.0.0.1:7897', onChange: (event) => setProxyForm({ ...proxyForm, url: event.target.value }) })),
            h('label', { className: 'atk-settings-field' }, t('settings.proxyMode'), h('select', { value: proxyForm.mode, onChange: (event) => setProxyForm({ ...proxyForm, mode: event.target.value }) }, ['custom', 'local', 'direct', 'provider'].map((mode) => h('option', { key: mode, value: mode }, mode)))),
            h('label', { className: 'atk-settings-field' }, t('settings.proxyNoProxy'), h('input', { value: proxyForm.noProxy, placeholder: 'localhost,127.0.0.1', onChange: (event) => setProxyForm({ ...proxyForm, noProxy: event.target.value }) }))),
          h('div', { className: 'atk-settings-actions' },
            h('button', { type: 'button', className: 'atk-btn atk-btn-primary', disabled: busy !== '', onClick: saveProxy }, t('settings.saveProxy')),
            h('button', { type: 'button', className: 'atk-btn', disabled: busy !== '' || proxy.enabled !== true, onClick: () => proxyAction('disable') }, t('settings.disableProxy')),
            h('button', { type: 'button', className: 'atk-btn', disabled: busy !== '', onClick: () => proxyAction('test') }, t('settings.testProxy')))));

      return h('div', { className: 'atk-settings' },
        h('div', { className: 'atk-settings-head' },
          h('div', null, h('h3', null, t('settings.title')), h('span', { className: 'atk-empty-hint' }, t('settings.hint'))),
          h('div', { className: 'atk-settings-actions' },
            h('button', { type: 'button', className: 'atk-btn', disabled: busy !== '', onClick: () => load() }, t('settings.refresh')),
            h('button', { type: 'button', className: 'atk-btn atk-btn-primary', disabled: busy !== '', onClick: checkAll }, busy === 'check' ? t('settings.checking') : t('settings.checkAll')))),
        error.length > 0 ? h('div', { className: 'atk-settings-error' }, error) : null,
        notice.length > 0 ? h('div', { className: 'atk-settings-notice' }, notice) : null,
        proxySection,
        providerSection);
    }

    function LoopPanel(props) {
      const t = props.t;
      const loop = props.model.loop;
      const selfTeam = props.model.selfTeam;
      const search = props.search;
      const [supervisionSort, setSupervisionSort] = React.useState(null);
      const [intentSort, setIntentSort] = React.useState(null);
      const [lessonSort, setLessonSort] = React.useState(null);
      const [skillSort, setSkillSort] = React.useState(null);
      const supervisionRows = React.useMemo(() => loopSupervisionRows(loop, search), [loop, search]);
      const intentRows = React.useMemo(() => loopIntentRows(loop, search), [loop, search]);
      const lessonRows = React.useMemo(() => loopLessonRows(loop, search), [loop, search]);
      const supervisionSorted = React.useMemo(() => sortRows(supervisionRows, supervisionSort, 'round'), [supervisionRows, supervisionSort]);
      const intentSorted = React.useMemo(() => sortRows(intentRows, intentSort, 'priority'), [intentRows, intentSort]);
      const lessonSorted = React.useMemo(() => sortRows(lessonRows, lessonSort, 'confidence'), [lessonRows, lessonSort]);
      const skillRows = React.useMemo(() => {
        const query = search.trim().toLowerCase();
        return selfTeam.skills.filter((skill) => {
          if (query.length === 0) return true;
          return `${skill.name} ${skill.route} ${skill.when.join(' ')} ${skill.do.join(' ')} ${skill.path}`.toLowerCase().indexOf(query) >= 0;
        }).map((skill) => ({
          id: skill.id,
          selectId: skill.id,
          name: skill.name,
          route: skill.route,
          confidence: skill.confidence,
          status: skill.status,
          path: skill.path,
          sortValues: { name: skill.name, route: skill.route, confidence: skill.confidence, status: skill.status },
        }));
      }, [selfTeam, search]);
      const skillSorted = React.useMemo(() => sortRows(skillRows, skillSort, 'confidence'), [skillRows, skillSort]);
      const supervisionColumns = React.useMemo(() => [
        { key: 'round', label: t('col.round'), render: (row) => String(row.round) },
        {
          key: 'verdict',
          label: t('col.verdict'),
          render: (row) => h('span', { style: { color: verdictColor(row.verdict) } }, localized(t, 'verdict', row.verdict)),
        },
        { key: 'type', label: t('col.kind'), render: (row) => localized(t, 'supervision', row.type) },
        { key: 'source', label: t('col.source'), render: (row) => localized(t, 'source', row.source) },
        { key: 'createdAt', label: t('col.createdAt'), render: (row) => formatTime(row.createdAt) },
      ], [t]);
      const intentColumns = React.useMemo(() => [
        { key: 'actionType', label: t('col.actionType'), render: (row) => row.actionType },
        { key: 'targetLabel', label: t('col.target'), render: (row) => h('span', { title: row.targetLabel }, truncateText(row.targetLabel, 48)) },
        { key: 'status', label: t('col.status'), render: (row) => localized(t, 'status', row.status) },
        { key: 'priority', label: t('col.priority'), render: (row) => String(row.priority) },
        {
          key: 'expectedEvidence',
          label: t('col.expectedEvidence'),
          render: (row) => h('span', { title: expectedEvidenceText(row.expectedEvidence) }, expectedEvidenceText(row.expectedEvidence)),
        },
        { key: 'round', label: t('col.round'), render: (row) => String(row.round) },
      ], [t]);
      const lessonColumns = React.useMemo(() => [
        {
          key: 'lessonKey',
          label: t('col.lessonKey'),
          render: (row) => h('span', { className: 'atk-kv-mono', title: row.lessonKey }, truncateText(row.lessonKey, 28)),
        },
        { key: 'route', label: t('col.route'), render: (row) => truncateText(row.route.length > 0 ? row.route : '—', 40) },
        { key: 'idea', label: t('col.idea'), wrap: true, render: (row) => truncateText(row.idea.length > 0 ? row.idea : '—', 90) },
        { key: 'confidence', label: t('col.confidence'), render: (row) => percent(row.confidence) },
        { key: 'wins', label: t('col.wins'), render: (row) => String(row.wins) },
        { key: 'fails', label: t('col.fails'), render: (row) => String(row.fails) },
        { key: 'uses', label: t('col.uses'), render: (row) => String(row.uses) },
        { key: 'status', label: t('col.status'), render: (row) => localized(t, 'status', row.status) },
      ], [t]);
      const skillColumns = React.useMemo(() => [
        { key: 'name', label: t('col.skillName'), wrap: true, render: (row) => truncateText(row.name, 60) },
        { key: 'route', label: t('col.skillRoute'), wrap: true, render: (row) => h('span', { className: 'atk-kv-mono' }, truncateText(row.route.length > 0 ? row.route : '—', 80)) },
        { key: 'confidence', label: t('col.confidence'), render: (row) => percent(row.confidence) },
        { key: 'status', label: t('col.status'), render: (row) => localized(t, 'status', row.status) },
        { key: 'path', label: t('col.skillPath'), render: (row) => h('span', { className: 'atk-kv-mono', title: row.path }, truncateText(row.path, 42)) },
      ], [t]);
      const state = loop.state;
      const latest = loop.latest;
      const isEmpty = state === null
        && loop.supervisions.length === 0
        && loop.intents.length === 0
        && loop.lessons.length === 0
        && selfTeam.teams.length === 0
        && selfTeam.skills.length === 0
        && selfTeam.latestBrief === null;
      if (isEmpty) {
        return h(EmptyState, { title: t('loop.empty'), hint: t('loop.emptyHint') });
      }
      const stateSection = h('section', { className: 'atk-loop-section', key: 'loop-state' },
        h('div', { className: 'atk-loop-section-head' },
          h('h4', { className: 'atk-loop-section-title' }, t('loop.state')),
          state === null ? null : h(Badge, {
            tone: state.activation === 'armed' ? 'ok' : 'warn',
            label: `${t('loop.activation')} · ${localized(t, 'activation', state.activation)}`,
          }),
          state === null ? null : h(Badge, { label: `${t('loop.phase')} · ${localized(t, 'status', state.phase)}` }),
          state === null ? null : h(Badge, {
            label: `${t('loop.round')} · ${state.round}/${state.maxRounds > 0 ? state.maxRounds : '—'}`,
          })),
        state === null
          ? h('div', { className: 'atk-empty-hint' }, t('loop.emptyHint'))
          : h('div', { className: 'atk-loop-body' },
            state.activation !== 'armed' ? h(Notice, { tone: 'warn' }, t('loop.disarmedWarn')) : null,
            h('dl', { className: 'atk-kv' },
              h('dt', null, t('loop.objective')), h('dd', null, state.objective.length > 0 ? state.objective : '—'),
              h('dt', null, t('loop.objectiveType')), h('dd', null, state.objectiveType.length > 0 ? state.objectiveType : '—'),
              h('dt', null, t('loop.goalPhase')), h('dd', null, state.goalPhase.length > 0
                ? `${localized(t, 'status', state.goalPhase)}${state.goalId.length > 0 ? ` · ${state.goalId}` : ''}`
                : '—'),
              h('dt', null, t('loop.ringValue')), h('dd', null, `${state.ring} / ${state.allowedRing}`),
              h('dt', null, t('loop.noProgress')), h('dd', null, `${state.noProgressRounds} · ${t('loop.emptyRounds')} ${state.emptyRounds}`),
              h('dt', null, t('loop.maxActions')), h('dd', null, String(state.maxActionsPerRound)),
              h('dt', null, t('loop.autoContinue')), h('dd', null, state.autoContinue ? t('bool.true') : t('bool.false')),
              h('dt', null, t('loop.stopReason')), h('dd', null, state.stopReason.length > 0 ? state.stopReason : '—'),
              h('dt', null, t('loop.startedAt')), h('dd', { className: 'atk-kv-mono' }, formatTime(state.startedAt)),
              h('dt', null, t('loop.lastStepAt')), h('dd', { className: 'atk-kv-mono' }, formatTime(state.lastStepAt)),
              h('dt', null, t('loop.appliedLessons')), h('dd', null, String(state.appliedLessonKeys.length)))));
      const supervisionSection = h('section', { className: 'atk-loop-section', key: 'loop-supervision' },
        h('div', { className: 'atk-loop-section-head' },
          h('h4', { className: 'atk-loop-section-title' }, t('loop.supervision')),
          latest === null ? null : h(Badge, {
            tone: latest.verdict === 'stop' ? 'warn' : 'accent',
            label: `${t('loop.latestSupervision')} · ${localized(t, 'verdict', latest.verdict)}`,
          }),
          latest === null ? null : h('span', { className: 'atk-loop-meta' },
            `${t('loop.round')} ${latest.round} · ${t('loop.source')} ${localized(t, 'source', latest.source)} · ${t('loop.confidence')} ${percent(latest.confidence)}`)),
        latest === null
          ? h('div', { className: 'atk-empty-hint' }, t('loop.supervisionEmpty'))
          : h('div', { className: 'atk-loop-body' },
            h('div', { className: 'atk-loop-meta' },
              h('span', null, `${t('loop.verdict')}: ${localized(t, 'verdict', latest.verdict)}`),
              latest.secondaryVerdict.length > 0
                ? h('span', null, `${t('loop.secondaryVerdict')}: ${localized(t, 'verdict', latest.secondaryVerdict)}`)
                : null,
              latest.findingKey.length > 0 ? h('span', null, `finding: ${latest.findingKey}`) : null,
              latest.stopRecommended
                ? h('span', { style: { color: 'var(--dsw-alias-state-error-primary)' } },
                  `${t('loop.stopRecommended')}${latest.stopReason.length > 0 ? `: ${latest.stopReason}` : ''}`)
                : null),
            latest.diagnosis.length > 0 ? h('p', { className: 'atk-loop-text' }, `${t('loop.diagnosis')}: ${latest.diagnosis}`) : null,
            latest.nextPlan.length > 0 ? h('p', { className: 'atk-loop-text' }, `${t('loop.nextPlan')}: ${latest.nextPlan}`) : null,
            latest.mustIntents.length > 0
              ? h('div', { className: 'atk-loop-chips' },
                h('span', { className: 'atk-loop-chip-label' }, t('loop.mustIntents')),
                latest.mustIntents.map((id) => h('span', { key: `must-${id}`, className: 'atk-tag' }, id)))
              : null,
            latest.banRepeats.length > 0
              ? h('div', { className: 'atk-loop-chips' },
                h('span', { className: 'atk-loop-chip-label' }, t('loop.banRepeats')),
                latest.banRepeats.map((entry) => h('span', { key: `ban-${entry}`, className: 'atk-tag' }, entry)))
              : null,
            latest.preferTactics.length > 0
              ? h('div', { className: 'atk-loop-chips' },
                h('span', { className: 'atk-loop-chip-label' }, t('loop.preferTactics')),
                latest.preferTactics.map((entry) => h('span', { key: `prefer-${entry}`, className: 'atk-tag' }, entry)))
              : null),
        h('h5', { className: 'atk-loop-subtitle' }, t('loop.supervisionHistory')),
        loop.supervisions.length === 0
          ? h('div', { className: 'atk-empty-hint' }, t('loop.supervisionEmpty'))
          : h(SortTable, {
            t,
            columns: supervisionColumns,
            rows: supervisionSorted,
            sort: supervisionSort,
            onSort: (key) => setSupervisionSort((current) => toggleSort(current, key, 'desc')),
            selectedId: props.selectedId,
            onSelect: props.onSelect,
            ariaLabel: t('loop.supervisionHistory'),
            emptyTitle: t('table.searchEmpty'),
            emptyHint: t('table.emptyHint'),
          }));
      const intentsSection = h('section', { className: 'atk-loop-section', key: 'loop-intents' },
        h('div', { className: 'atk-loop-section-head' },
          h('h4', { className: 'atk-loop-section-title' }, t('loop.intents')),
          h('span', { className: 'atk-tab-count' }, String(loop.totals.openIntents))),
        loop.intents.length === 0
          ? h('div', { className: 'atk-empty-hint' }, t('loop.emptyIntents'))
          : h(SortTable, {
            t,
            columns: intentColumns,
            rows: intentSorted,
            sort: intentSort,
            onSort: (key) => setIntentSort((current) => toggleSort(current, key, 'desc')),
            selectedId: props.selectedId,
            onSelect: props.onSelect,
            ariaLabel: t('loop.intents'),
            emptyTitle: t('table.searchEmpty'),
            emptyHint: t('table.emptyHint'),
          }));
      const lessonsSection = h('section', { className: 'atk-loop-section', key: 'loop-lessons' },
        h('div', { className: 'atk-loop-section-head' },
          h('h4', { className: 'atk-loop-section-title' }, t('loop.lessons')),
          h('span', { className: 'atk-tab-count' }, String(loop.totals.lessons))),
        loop.lessons.length === 0
          ? h('div', { className: 'atk-empty-hint' }, t('loop.emptyLessons'))
          : h(SortTable, {
            t,
            columns: lessonColumns,
            rows: lessonSorted,
            sort: lessonSort,
            onSort: (key) => setLessonSort((current) => toggleSort(current, key, 'desc')),
            selectedId: props.selectedId,
            onSelect: props.onSelect,
            ariaLabel: t('loop.lessons'),
            emptyTitle: t('table.searchEmpty'),
            emptyHint: t('table.emptyHint'),
          }));
      const riskTone = selfTeam.latestBrief === null ? 'warn' : (selfTeam.latestBrief.deadlockRisk === 'high' ? 'warn' : 'ok');
      const brief = selfTeam.latestBrief;
      const fullList = (label, values) => (Array.isArray(values) && values.length > 0
        ? h('div', { className: 'atk-selftteam-line' },
          h('span', { className: 'atk-selftteam-line-label' }, label),
          h('span', null, values.join('；')))
        : null);
      const teamLabel = (type) => {
        if (type === 'evolution') return t('loop.evolutionTeam');
        if (type === 'lead') return t('loop.leadTeam');
        if (type === 'verification') return t('loop.verificationTeam');
        if (type === 'escalation') return t('loop.escalationTeam');
        if (type === 'report') return t('loop.reportTeam');
        return t('loop.supervisionTeam');
      };
      const roster = selfTeam.teams.filter((team) => team.type !== 'evolution');
      const teamCards = roster.length === 0
        ? h('div', { className: 'atk-empty-hint' }, t('loop.selfTeamEmpty'))
        : h('div', { className: 'atk-selftteam-grid' }, roster.map((team) => {
          const rows = [];
          if (team.type === 'lead') {
            const leadMember = team.members[0] ?? {};
            rows.push(h('dt', { key: 'l-mode-dt' }, t('loop.members')), h('dd', { key: 'l-mode-dd' }, `${leadMember.name || '从者（Lead）'} · ${leadMember.mode || 'main'}`));
            rows.push(h('dt', { key: 'l-resp-dt' }, t('loop.teamResponsibility')), h('dd', { key: 'l-resp-dd' }, leadMember.responsibility || '真实侦查与利用，并可创建子智能体'));
          } else if (team.type === 'verification') {
            rows.push(h('dt', { key: 'v-dt' }, t('loop.lastVerifyAt')), h('dd', { key: 'v-dd' }, formatTime(team.lastVerifyAt)));
            rows.push(h('dt', { key: 'vc-dt' }, t('loop.verifiedCount')), h('dd', { key: 'vc-dd' }, String(team.verifiedCount)));
            rows.push(h('dt', { key: 'rc-dt' }, t('loop.ratedCount')), h('dd', { key: 'rc-dd' }, String(team.ratedCount)));
          } else if (team.type === 'report') {
            rows.push(h('dt', { key: 'r-dt' }, t('loop.lastReportAt')), h('dd', { key: 'r-dd' }, formatTime(team.lastReportAt)));
            rows.push(h('dt', { key: 'rt-dt' }, t('loop.reportTheme')), h('dd', { key: 'rt-dd' }, team.lastReportTheme.length > 0 ? `${team.lastReportTheme}${team.themeSource.length > 0 ? ` · ${team.themeSource}` : ''}` : '—'));
            rows.push(h('dt', { key: 'rp-dt' }, t('loop.reportPath')), h('dd', { key: 'rp-dd', className: 'atk-kv-mono', title: team.lastReportPath }, team.lastReportPath.length > 0 ? truncateText(team.lastReportPath, 46) : '—'));
            rows.push(h('dt', { key: 'frp-dt' }, t('loop.findingReportPath')), h('dd', { key: 'frp-dd', className: 'atk-kv-mono', title: team.lastFindingReportPath }, team.lastFindingReportPath.length > 0 ? truncateText(team.lastFindingReportPath, 46) : '—'));
          } else if (team.type === 'supervision') {
            rows.push(h('dt', { key: 'lb-dt' }, t('loop.lastBriefAt')), h('dd', { key: 'lb-dd' }, formatTime(team.lastBriefAt)));
            rows.push(h('dt', { key: 'lbp-dt' }, t('loop.briefPath')), h('dd', { key: 'lbp-dd', className: 'atk-kv-mono' }, team.lastBriefPath.length > 0 ? truncateText(team.lastBriefPath, 46) : '—'));
          } else {
            rows.push(h('dt', { key: 'ld-dt' }, t('loop.lastDistillAt')), h('dd', { key: 'ld-dd' }, formatTime(team.lastDistillAt)));
            rows.push(h('dt', { key: 'sc-dt' }, t('loop.skillCountLabel')), h('dd', { key: 'sc-dd' }, String(team.skillCount)));
            rows.push(h('dt', { key: 'sd-dt' }, t('col.skillPath')), h('dd', { key: 'sd-dd', className: 'atk-kv-mono' }, team.skillDir.length > 0 ? truncateText(team.skillDir, 40) : '—'));
          }
          return h('div', { key: team.id, className: 'atk-selftteam-card' },
            h('div', { className: 'atk-selftteam-card-head' },
              h('strong', null, teamLabel(team.type)),
              h(Badge, { tone: team.status === 'active' ? 'ok' : 'warn', label: localized(t, 'status', team.status) })),
            h('div', { className: 'atk-empty-hint' }, `${t('loop.members')}: ${team.members.map((member) => member.name.length > 0 ? member.name : member.role).join(' · ') || '—'}`),
            h('dl', { className: 'atk-kv' }, rows));
        }));
      const briefBlock = brief === null
        ? h('div', { className: 'atk-empty-hint' }, t('loop.selfBriefEmpty'))
        : h('div', { className: 'atk-selftteam-brief' },
          h('div', { className: 'atk-selftteam-brief-head' },
            h('strong', null, `${t('loop.handoff')} · ${brief.progressSummary.length > 0 ? truncateText(brief.progressSummary, 90) : '—'}`),
            h(Badge, {
              tone: brief.handoff === null ? 'warn' : brief.handoff.status === 'delivered' ? 'ok' : 'warn',
              label: brief.handoff === null ? t('loop.handoffMissing') : brief.handoff.status === 'delivered' ? t('loop.handoffDelivered') : brief.handoff.status === 'legacy' ? t('loop.handoffLegacy') : t('loop.handoffStale'),
            }),
            h(Badge, { tone: riskTone, label: `${t('loop.deadlockRisk')} · ${localized(t, 'risk', brief.deadlockRisk)}` }),
            h(Badge, { label: `${t('loop.round')} · ${brief.round}` })),
          h('div', { className: 'atk-selftteam-lines' },
            fullList(t('loop.gained'), brief.gained),
            fullList(t('loop.missed'), brief.missed),
            brief.advice.length > 0 ? fullList(t('loop.advice'), [brief.advice]) : null,
            fullList(t('loop.antiDeadlock'), brief.antiDeadlock),
            fullList(t('loop.recommendedNext'), brief.recommendedNext)),
          brief.artifactPath.length > 0 ? h('div', { className: 'atk-empty-hint' }, brief.artifactPath) : null);
      const coverageBoard = props.model.coverageBoard;
      const hypotheses = props.model.hypotheses;
      const openCells = coverageBoard.cells.filter((cell) => cell.status === 'open' || cell.status === 'claimed').slice(0, 30);
      const openHypotheses = hypotheses.rows.filter((row) => row.status === 'open' || row.status === 'active').slice(0, 20);
      const coverageSection = h('section', { className: 'atk-loop-section', key: 'loop-coverage' },
        h('div', { className: 'atk-loop-section-head' },
          h('h4', { className: 'atk-loop-section-title' }, t('loop.coverage')),
          h('span', { className: 'atk-empty-hint' }, t('loop.coverageHint')),
          h(Badge, { label: t('loop.coverageTotals', { cells: coverageBoard.totals.cells, seen: coverageBoard.totals.seen, open: coverageBoard.totals.open }) })),
        h('div', { className: 'atk-coverage-duties' }, ['xss', 'sqli', 'cmd', 'code', 'file', 'authz', 'logic', 'leak', 'nday'].map((bugClass) => h('div', { key: bugClass, className: 'atk-selftteam-line' },
          h('span', { className: 'atk-selftteam-line-label' }, t(`loop.dutyName.${bugClass}`)),
          h('span', null, t(`loop.duty.${bugClass}`))))),
        openCells.length === 0
          ? h('div', { className: 'atk-empty-hint' }, t('loop.coverageTotals', { cells: coverageBoard.totals.cells, seen: coverageBoard.totals.seen, open: coverageBoard.totals.open }))
          : h('div', { className: 'atk-coverage-grid' }, openCells.map((cell) => h('div', { key: `${cell.path}#${cell.bugClass}`, className: 'atk-coverage-cell' },
            h('strong', null, cell.path),
            h('span', { className: 'atk-coverage-class' }, cell.bugClass),
            h(Badge, { tone: cell.status === 'claimed' ? 'warn' : 'muted', label: localized(t, 'status', cell.status) })))),
        h('div', { className: 'atk-loop-section-head', style: { marginTop: '12px' } },
          h('h5', { className: 'atk-loop-subtitle' }, t('loop.hypotheses')),
          h('span', { className: 'atk-empty-hint' }, t('loop.hypothesisHint')),
          h(Badge, { label: t('loop.hypothesisTotals', { total: hypotheses.totals.hypotheses, open: hypotheses.totals.open, verified: hypotheses.totals.verified }) })),
        openHypotheses.length === 0
          ? h('div', { className: 'atk-empty-hint' }, t('loop.hypothesisEmpty'))
          : h('div', { className: 'atk-selftteam-lines' }, openHypotheses.map((row) => h('div', { key: row.hypothesisId || row.strategy, className: 'atk-selftteam-line' },
            h('span', { className: 'atk-selftteam-line-label' }, `${row.bugClass || 'hypothesis'} · ${row.targetKey || '—'}`),
            h('span', null, row.strategy)))));

      const selfTeamSection = h('section', { className: 'atk-loop-section', key: 'loop-self-team' },
        h('div', { className: 'atk-loop-section-head' },
          h('h4', { className: 'atk-loop-section-title' }, t('loop.selfTeam')),
          h('span', { className: 'atk-empty-hint' }, t('loop.selfTeamHint')),
          h(Badge, { label: t('loop.skillCount', { count: 0 }) })),
        teamCards,
        briefBlock);
      return h('div', { className: 'atk-loop' }, stateSection, coverageSection, supervisionSection, intentsSection, lessonsSection, selfTeamSection);
    }

    function wildcardRows(model, search) {
      const rows = [];
      for (const zone of model.wildcardZones) {
        const haystack = `${zone.zone} ${zone.label} ${zone.status}`.toLowerCase();
        if (search.length > 0 && haystack.indexOf(search) < 0) continue;
        rows.push({
          id: zone.id,
          selectId: zone.id,
          label: zone.zone,
          zone,
          sortValues: {
            label: zone.zone,
            status: zone.status,
            confidence: zone.confidence,
            cdn: zone.cdn ? 1 : 0,
            probes: zone.probeCount,
            lastSeen: zone.lastSeen === null ? '' : zone.lastSeen,
          },
        });
      }
      return rows;
    }

    function WildcardTable(props) {
      const t = props.t;
      const [sort, setSort] = React.useState({ key: 'label', dir: 'asc' });
      const rows = React.useMemo(() => wildcardRows(props.model, props.search), [props.model, props.search]);
      const sorted = React.useMemo(() => sortRows(rows, sort, 'label'), [rows, sort]);
      const columns = React.useMemo(() => [
        { key: 'label', label: t('col.zone'), render: (row) => labelCell(t, { label: row.zone.zone }) },
        { key: 'status', label: t('col.status'), render: (row) => localized(t, 'status', row.zone.status) },
        { key: 'confidence', label: t('col.confidence'), render: (row) => percent(row.zone.confidence) },
        { key: 'cdn', label: t('col.cdn'), render: (row) => (row.zone.cdn ? t('bool.true') : t('bool.false')) },
        { key: 'probes', label: t('col.probes'), render: (row) => String(row.zone.probeCount) },
        { key: 'lastSeen', label: t('col.lastSeen'), render: (row) => formatTime(row.zone.lastSeen) },
      ], [t]);
      return h(SortTable, {
        t,
        columns,
        rows: sorted,
        sort,
        onSort: (key) => setSort((current) => toggleSort(current, key, 'asc')),
        selectedId: props.selectedId,
        onSelect: props.onSelect,
        ariaLabel: t('tab.wildcard'),
        emptyTitle: t('table.empty', { tab: t('tab.wildcard') }),
        emptyHint: t('table.emptyHint'),
      });
    }

    function isRceNode(node) {
      return node?.kind === 'finding' && String(node.findingType || '').includes('远程代码执行');
    }

    function enablingParent(model, node) {
      const incoming = model.incoming?.get(node.id) || [];
      const toName = findingHarmName('', node.sourceLabel || node.label).name;
      for (const edge of incoming) {
        if (edge.kind !== 'escalates_to') continue;
        const parent = model.byId.get(edge.from);
        if (parent === undefined || parent.kind !== 'finding') continue;
        const fromName = findingHarmName('', parent.sourceLabel || parent.label).name;
        if (harmEnables(fromName, toName)) return parent;
      }
      return null;
    }

    function managerAccessFor(model, source) {
      const host = findingHostHint(source);
      return model.nodes.find((node) => node.kind === 'access'
        && String(node.label).includes('管理后台权限')
        && (host.length === 0 ? !/\d{1,3}(?:\.\d{1,3}){3}/u.test(node.label) : node.label.includes(host)));
    }

    function rceChains(model) {
      if (model === null || model === undefined) return [];
      const direct = [];
      const reused = [];
      for (const rce of model.nodes.filter(isRceNode)) {
        const steps = [];
        const seen = new Set();
        let current = rce;
        while (current !== null && current !== undefined && !seen.has(current.id)) {
          seen.add(current.id);
          steps.unshift(current);
          current = enablingParent(model, current);
        }
        const source = rce.sourceLabel || rce.label || '';
        if (/manager/iu.test(source) && steps.every((step) => !String(step.label).includes('管理后台'))) {
          const access = managerAccessFor(model, source);
          if (access !== undefined && !seen.has(access.id)) steps.splice(Math.max(steps.length - 1, 0), 0, access);
        }
        const usable = steps.filter((step) => step !== undefined && String(step.label || '').length > 0);
        if (usable.length === 1 && /reuse|reused|credential/iu.test(source)) reused.push(rce);
        else if (usable.length > 0) direct.push(usable);
      }
      for (const rce of reused) {
        const host = findingHostHint(rce.sourceLabel || rce.label || '');
        const base = direct.find((steps) => steps.some((step) => isRceNode(step) && findingHostHint(step.sourceLabel || step.label) !== host));
        direct.push(base === undefined ? [rce] : [...base, rce]);
      }
      const chains = [];
      const seen = new Set();
      for (const steps of direct) {
        const key = steps.map((step) => step.label).join('>');
        if (seen.has(key)) continue;
        const covered = direct.some((other) => other.length > steps.length && steps.every((step) => other.some((item) => item.id === step.id)));
        if (covered) continue;
        seen.add(key);
        chains.push(steps);
      }
      return chains;
    }

    function ChainsTable(props) {
      const t = props.t;
      const chains = React.useMemo(() => rceChains(props.model), [props.model]);
      return h('div', { className: 'atk-table-wrap' },
        h('div', { style: { padding: '8px 10px 4px' } },
          h('h4', { className: 'atk-detail-section-title' }, t('chain.toRce'), h('span', { className: 'atk-tab-count' }, String(chains.length)))),
        chains.length === 0
          ? h('div', { className: 'atk-empty-hint', style: { padding: '2px 10px 8px' } }, t('chain.empty'))
          : h('div', { style: { display: 'flex', flexDirection: 'column', gap: '8px', padding: '4px 10px 10px' } },
            chains.map((steps) => h('div', {
              key: steps.map((step) => step.id).join('>'),
              style: { display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '4px' },
            }, steps.map((step, index) => h(React.Fragment, { key: step.id },
              index === 0 ? null : h('span', { style: { color: 'var(--dsw-alias-label-tertiary)' } }, '→'),
              h('button', {
                type: 'button',
                className: 'atk-btn',
                onClick: () => props.onSelect({ id: step.id, selectId: step.id }),
              }, step.label)))))));
    }

    // ---------------------------------------------------------------------
    // Header, stats, toolbar and tabs
    // ---------------------------------------------------------------------

    const TAB_ORDER = ['assets', 'targets', 'services', 'vulnerabilities', 'access', 'data', 'chains', 'wildcard', 'tasks', 'team', 'loop', 'settings'];

    function tabCount(tab, model) {
      if (model === null) return 0;
      if (tab === 'assets') return model.coverage.assets;
      if (tab === 'targets') return model.targets?.totals?.targets ?? 0;
      if (tab === 'services') return model.coverage.services;
      if (tab === 'vulnerabilities' || tab === 'findings') {
        return model.nodes.filter((node) => node.kind === 'finding' && node.includedVulnerability === true).length;
      }
      if (tab === 'access') return model.nodes.filter((node) => node.kind === 'access' || node.kind === 'credential' || node.kind === 'pivot').length;
      if (tab === 'data') return model.nodes.filter((node) => node.kind === 'data').length;
      if (tab === 'chains') return rceChains(model).length;
      if (tab === 'wildcard') return model.wildcardZones.length;
      if (tab === 'tasks') return model.tasks.length;
      if (tab === 'team') return model.team.totals.batches;
      if (tab === 'loop') return model.loop.totals.rounds;
      if (tab === 'settings') return 0;
      return 0;
    }

    function ReportExportButton(props) {
      const t = props.t;
      const model = props.model;
      const sessionId = props.sessionId;
      const [open, setOpen] = React.useState(false);
      const [busy, setBusy] = React.useState('');
      const [error, setError] = React.useState('');
      async function exportFormat(format) {
        setBusy(format);
        setError('');
        try {
          if (typeof fetch !== 'function') throw new Error('fetch unavailable');
          const response = await fetch('/atkbrain/report/export', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ format, model, sessionId }),
          });
          const text = await response.text();
          let value;
          try { value = JSON.parse(text); } catch { throw new Error(text.slice(0, 300)); }
          if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
          if (typeof Blob === 'undefined' || typeof URL === 'undefined' || typeof document === 'undefined') throw new Error('browser download unavailable');
          const blob = new Blob([value.content], { type: value.mime || 'application/octet-stream' });
          const url = URL.createObjectURL(blob);
          const anchor = document.createElement('a');
          anchor.href = url;
          anchor.download = value.filename || `atkbrain-report.${format === 'html' ? 'html' : format === 'json' ? 'json' : 'md'}`;
          anchor.click();
          URL.revokeObjectURL(url);
          setOpen(false);
        } catch (err) {
          setError(err instanceof Error ? err.message : String(err));
        } finally {
          setBusy('');
        }
      }
      const formats = [
        { key: 'markdown', label: t('report.markdown') },
        { key: 'html', label: t('report.html') },
        { key: 'json', label: t('report.json') },
        { key: 'csv', label: t('report.csv') },
      ];
      return h('div', { className: 'atk-report-export' },
        h('button', {
          type: 'button',
          className: 'atk-btn atk-btn-primary',
          disabled: busy !== '',
          onClick: () => exportFormat('html'),
        }, busy === 'html' ? t('report.exporting') : t('header.exportReport')),
        h('button', {
          type: 'button',
          className: 'atk-btn atk-btn-icon',
          'aria-haspopup': 'menu',
          'aria-expanded': open ? 'true' : 'false',
          'aria-label': t('report.formats'),
          disabled: busy !== '',
          onClick: () => { setOpen((value) => !value); setError(''); },
        }, '▾'),
        open ? h('div', { className: 'atk-report-menu', role: 'menu' },
          formats.map((entry) => h('button', {
            key: entry.key,
            type: 'button',
            role: 'menuitem',
            className: 'atk-report-menu-item',
            disabled: busy !== '',
            onClick: () => exportFormat(entry.key),
          }, entry.label))) : null,
        error.length > 0 ? h('span', { className: 'atk-report-error', title: error }, t('report.exportFailed')) : null);
    }

    function GraphHeader(props) {
      const t = props.t;
      const model = props.model;
      const sessionId = props.sessionId;
      const engagement = model.engagement;
      const engagementName = engagement !== null && engagement.name.length > 0 ? engagement.name : t('header.noEngagement');
      const projectId = engagement !== null ? engagement.id : '';
      const completion = model.projectCompletion;
      const engagementTitle = engagement === null
        ? ''
        : [engagement.client, engagement.mode, engagement.authorization].filter((entry) => entry.length > 0).join(' · ');
      const scope = model.scope;
      const scopeLabel = scope.empty
        ? t('header.scopeEmpty')
        : `${t('header.scopeOk', { allow: scope.allowCount })}${scope.denyCount > 0 ? ` · ${t('header.scopeDeny', { deny: scope.denyCount })}` : ''}`;
      return h('div', { className: 'atk-header' },
        h('div', { className: 'atk-heading' },
          h('h2', { className: 'atk-title' }, t('title')),
          h('span', { className: 'atk-subtitle' }, t('subtitle'))),
        h('div', { className: 'atk-badges' },
          h(Badge, {
            tone: 'accent',
            label: `${t('header.engagement')} · ${engagementName}`,
            title: engagementTitle,
          }),
          h(Badge, { tone: scope.empty ? 'warn' : 'ok', label: `${t('header.scope')} · ${scopeLabel}` }),
          model.lastAction === null
            ? null
            : h(Badge, {
              label: `${t('header.lastAction')} · ${model.lastAction.tool}/${model.lastAction.action}`,
              title: model.lastAction.at === null ? '' : formatTime(model.lastAction.at),
            }),
          h(Badge, { tone: 'accent', label: t('header.seq', { seq: model.seq }) }),
          projectId.length > 0
            ? h('span', { className: 'atk-project-id', title: t('header.projectIdHint') },
              h(Badge, { tone: 'accent', label: `${t('header.projectId')} · ${projectId}` }))
            : null,
          engagement === null ? null : h(Badge, {
            tone: completion.complete ? 'ok' : 'warn',
            label: completion.complete ? t('header.projectComplete') : t('header.projectPending'),
            title: completion.complete ? t('header.projectCompleteHint') : `${t('header.projectPendingHint')}${completion.reason ? ` ${completion.reason}` : ''}`,
          }),
          h(ReportExportButton, { t, model, sessionId })));
    }

    function GraphStats(props) {
      const t = props.t;
      const coverage = props.model.coverage;

      const accessLabel = coverage.validatedAccess > 0
        ? `${t('stat.access')} · ${coverage.validatedAccess}`
        : t('stat.access');
      const dataLabel = coverage.verifiedData > 0
        ? `${t('stat.data')} · ${coverage.verifiedData}`
        : t('stat.data');
      const teamTotals = props.model.team.totals;
      const batchLabel = teamTotals.merged > 0
        ? t('stat.batchesMerged', { count: teamTotals.merged })
        : t('stat.batches');
      const loopState = props.model.loop.state;
      const loopTotals = props.model.loop.totals;
      const roundsValue = loopState === null ? '0' : `${loopState.round}/${loopState.maxRounds > 0 ? loopState.maxRounds : '—'}`;
      const lessonsLabel = loopTotals.appliedLessons > 0
        ? t('stat.lessonsApplied', { count: loopTotals.appliedLessons })
        : t('stat.lessons');
      const onStat = props.onStat;
      const activeStat = props.activeStat;
      const open = (key, label, value, extra) => h(StatItem, {
        label,
        value,
        ...(extra || {}),
        title: t('stat.openHint', { label }),
        active: activeStat === key,
        onClick: () => onStat(key),
      });
      return h('div', { className: 'atk-stats' },
        open('assets', t('stat.assets'), String(coverage.assets)),
        open('services', t('stat.services'), String(coverage.services)),
        open('vulnerabilities', t('stat.vulnerabilities'), String(coverage.vulnerabilities), { tone: coverage.vulnerabilities > 0 ? 'danger' : undefined }),
        open('access', accessLabel, String(coverage.access)),
        open('data', dataLabel, String(coverage.data)),
        open('crown', t('stat.crown'), String(coverage.crownJewels), { tone: 'accent' }),
        open('batches', batchLabel, String(teamTotals.batches)),
        open('rounds', t('stat.rounds'), roundsValue),
        open('lessons', lessonsLabel, String(loopTotals.lessons)),
        open('wildcardExcluded', t('stat.wildcardExcluded'), String(props.hiddenWildcard)));
    }

    function statDetailFor(model, key, t) {
      const nodes = model.nodes;
      let label;
      let matched;
      if (key === 'assets') {
        label = t('stat.assets');
        matched = nodes.filter((node) => node.kind === 'host' || node.kind === 'ip');
      } else if (key === 'services') {
        label = t('stat.services');
        matched = nodes.filter((node) => node.kind === 'service');
      } else if (key === 'vulnerabilities') {
        label = t('stat.vulnerabilities');
        matched = nodes.filter((node) => node.kind === 'finding' && node.includedVulnerability === true);
      } else if (key === 'findings' || key === 'discoveries') {
        label = t('stat.discoveries');
        matched = nodes.filter((node) => node.kind === 'finding');
      } else if (key === 'access') {
        label = t('stat.access');
        matched = nodes.filter((node) => node.kind === 'access');
      } else if (key === 'data') {
        label = t('stat.data');
        matched = nodes.filter((node) => node.kind === 'data');
      } else if (key === 'crown') {
        label = t('stat.crown');
        matched = nodes.filter((node) => node.crown === true);
      } else if (key === 'batches') {
        label = t('stat.batches');
        matched = nodes.filter((node) => node.kind === 'task' && node.attrs.actionType === 'subagent_batch');
      } else if (key === 'rounds') {
        label = t('stat.rounds');
        matched = nodes.filter((node) => node.kind === 'loop');
      } else if (key === 'lessons') {
        label = t('stat.lessons');
        matched = nodes.filter((node) => node.kind === 'lesson');
      } else if (key === 'wildcardExcluded') {
        label = t('stat.wildcardExcluded');
        matched = nodes.filter((node) => isWildcardSuspect(node));
      } else {
        label = key;
        matched = [];
      }
      const sorted = matched.slice().sort((a, b) => nodeImportance(b) - nodeImportance(a) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
      return { key, label, nodes: sorted };
    }

    function StatDetailPane(props) {
      const t = props.t;
      const detail = props.detail;
      const rows = detail.nodes.slice(0, 80);
      const list = rows.length === 0
        ? h('div', { className: 'atk-empty-hint' }, t('stat.detailEmpty'))
        : h('div', { className: 'atk-stat-detail-list' }, rows.map((node) => h('button', {
          key: node.id,
          type: 'button',
          className: 'atk-stat-detail-row',
          title: `${node.key} · ${node.id}`,
          onClick: () => props.onSelect(node.id),
        },
        h('span', { className: 'atk-stat-detail-kind' }, localized(t, 'kind', node.kind)),
        h('span', { className: 'atk-stat-detail-label' }, truncateText(node.label, 96)),
        h('span', { className: 'atk-stat-detail-state' }, localized(t, 'status', node.status)))));
      return h('div', { className: 'atk-detail atk-stat-detail' },
        h('div', { className: 'atk-detail-head' },
          h('h3', { className: 'atk-detail-title', title: detail.label }, `${detail.label} · ${detail.nodes.length}`),
          h('button', {
            type: 'button',
            className: 'atk-btn atk-btn-icon atk-detail-close',
            'aria-label': t('detail.close'),
            onClick: props.onClose,
          }, '×')),
        h('div', { className: 'atk-empty-hint' }, t('stat.detailHint')),
        h('div', { className: 'atk-detail-section' },
          h('h4', { className: 'atk-detail-section-title' }, t('stat.detailCount', { count: detail.nodes.length })),
          list));
    }

    function ProxyStatusBar(props) {
      const t = props.t;
      const [status, setStatus] = React.useState(null);
      const [error, setError] = React.useState(false);
      const [busy, setBusy] = React.useState('');
      const [nonce, setNonce] = React.useState(0);
      React.useEffect(() => {
        let disposed = false;
        let timer = null;
        async function load() {
          try {
            if (typeof fetch !== 'function') throw new Error('fetch unavailable');
            const response = await fetch('/atkbrain/proxy/status', { cache: 'no-store' });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const value = await response.json();
            if (!disposed) { setStatus(value); setError(false); }
          } catch {
            if (!disposed) setError(true);
          }
        }
        void load();
        timer = setInterval(() => { void load(); }, 15000);
        return () => { disposed = true; if (timer !== null) clearInterval(timer); };
      }, [nonce]);
      async function act(action) {
        setBusy(action);
        try {
          if (typeof fetch !== 'function') throw new Error('fetch unavailable');
          const response = await fetch('/atkbrain/proxy', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action }),
          });
          const value = await response.json();
          if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
          setStatus(value);
          setError(false);
        } catch (err) {
          setError(true);
          setStatus((current) => ({ ...(current || {}), error: err instanceof Error ? err.message : String(err) }));
        } finally {
          setBusy('');
          setNonce((value) => value + 1);
        }
      }
      const current = status || {};
      const enabled = current.enabled === true;
      const blocked = current.blocked === true;
      const tone = blocked || current.error ? 'error' : enabled ? (current.active ? 'ok' : 'pending') : 'off';
      const label = blocked ? t('proxy.blocked') : enabled ? (current.active ? t('proxy.enabled') : t('proxy.pending')) : t('proxy.disabled');
      return h('div', { className: 'atk-proxy-strip', role: 'status', 'aria-label': t('proxy.title') },
        h('span', { className: 'atk-proxy-title' }, t('proxy.title')),
        h('span', { className: `atk-proxy-dot atk-proxy-dot--${tone}`, 'aria-hidden': 'true' }),
        h('span', { className: 'atk-proxy-main' }, `${label} · ${current.mode || 'local'}`),
        h('span', { className: 'atk-proxy-detail' }, current.exitIp ? `exit ${current.exitIp}${current.masked === true ? ' (masked)' : current.masked === false ? ' (same as direct)' : ''}` : t('proxy.noExit')),
        h('span', { className: 'atk-proxy-detail' }, `pool ${current.pool?.live ?? 0}/${current.pool?.total ?? 0}`),
        h('span', { className: 'atk-proxy-note' }, t('proxy.loopback')),
        h('button', { type: 'button', className: 'atk-btn atk-btn-ghost', disabled: busy !== '' || !enabled, onClick: () => act('disable') }, t('proxy.disable')),
        h('button', { type: 'button', className: enabled ? 'atk-btn atk-btn-ghost' : 'atk-btn atk-btn-primary', disabled: busy !== '' || enabled, onClick: () => act('enable') }, t('proxy.enable')),
        h('button', { type: 'button', className: 'atk-btn atk-btn-ghost', disabled: busy !== '', onClick: () => act('test') }, t('proxy.test')),
        h('button', { type: 'button', className: 'atk-btn atk-btn-icon', disabled: busy !== '' || !enabled, title: t('proxy.rotate'), 'aria-label': t('proxy.rotate'), onClick: () => act('rotate') }, '↻'),
        error ? h('span', { className: 'atk-proxy-hint' }, t('proxy.unavailable')) : null,
        current.error ? h('span', { className: 'atk-proxy-hint', title: current.error }, String(current.error).slice(0, 140)) : null);
    }

    function GraphToolbar(props) {
      const t = props.t;
      const view = props.view;
      const shown = props.layout === null ? 0 : props.layout.nodes.length;
      const total = props.filtered === null ? 0 : props.filtered.totalVisible;
      return h('div', { className: 'atk-toolbar', role: 'toolbar', 'aria-label': t('toolbar.aria') },
        h('span', { className: 'atk-spacer' }),
        h('span', { className: 'atk-toolbar-label' }, t('toolbar.zoomLevel', { percent: Math.round(view.k * 100) })),
        h('button', {
          type: 'button',
          className: 'atk-btn atk-btn-icon',
          'aria-label': t('toolbar.zoomOut'),
          title: t('toolbar.zoomOut'),
          onClick: () => props.onZoom(1 / 1.25),
        }, '−'),
        h('button', {
          type: 'button',
          className: 'atk-btn atk-btn-icon',
          'aria-label': t('toolbar.zoomIn'),
          title: t('toolbar.zoomIn'),
          onClick: () => props.onZoom(1.25),
        }, '+'),
        h('button', { type: 'button', className: 'atk-btn', onClick: props.onFit }, t('toolbar.fit')),
        h('button', { type: 'button', className: 'atk-btn', onClick: props.onReset }, t('toolbar.reset')),
        h('button', {
          type: 'button',
          className: 'atk-btn',
          'aria-pressed': props.fullscreen === true,
          onClick: props.onFullscreen,
        }, props.fullscreen === true ? t('toolbar.exitFullscreen') : t('toolbar.fullscreen')),
        h('span', { className: 'atk-toolbar-label' }, t('toolbar.results', { shown, total })));
    }

    function TabBar(props) {
      const t = props.t;
      const active = props.active;
      const onTab = props.onTab;
      function handleKeyDown(event) {
        if (event === null || event === undefined) return;
        if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
        event.preventDefault();
        const index = TAB_ORDER.indexOf(active);
        const offset = event.key === 'ArrowRight' ? 1 : TAB_ORDER.length - 1;
        onTab(TAB_ORDER[(index + offset) % TAB_ORDER.length]);
      }
      return h('div', {
        className: 'atk-tabs',
        role: 'tablist',
        'aria-label': t('tab.aria'),
        onKeyDown: handleKeyDown,
      }, TAB_ORDER.map((tab) => {
        const count = tabCount(tab, props.model);
        return h('button', {
          key: tab,
          type: 'button',
          role: 'tab',
          id: `atk-tab-${tab}`,
          className: 'atk-tab',
          'aria-selected': active === tab,
          'aria-controls': `atk-panel-${tab}`,
          tabIndex: active === tab ? 0 : -1,
          onClick: () => onTab(tab),
        }, t(`tab.${tab}`), count > 0 ? h('span', { className: 'atk-tab-count' }, String(count)) : null);
      }));
    }

    function TargetsPanel(props) {
      const t = props.t;
      const tree = props.model.targets ?? { clusters: [], totals: {} };
      const totals = tree.totals ?? {};
      if (tree.clusters.length === 0) {
        return h('div', { className: 'atk-targets' }, h(EmptyState, { title: t('target.empty'), hint: t('target.emptyHint') }));
      }
      const statusText = (status) => t(`target.status.${status}`) !== `target.status.${status}` ? t(`target.status.${status}`) : status;
      const statusClass = (status) => `atk-target-status atk-target-status--${status}`;
      const cell = (value) => h('td', null, String(value));
      const rows = [];
      for (const cluster of tree.clusters) {
        rows.push(h('tr', { key: `cluster-${cluster.id}`, className: 'atk-target-cluster' },
          h('td', { colSpan: 1 }, h('strong', null, cluster.label)),
          cell(cluster.totals.services), cell((cluster.totals.services ?? 0) + (cluster.totals.webapps ?? 0)),
          cell(cluster.totals.findings), cell(cluster.totals.vulnerabilities),
          cell(cluster.totals.access), cell(cluster.totals.data),
          cell(t('target.coverageShort', { seen: cluster.totals.coverageSeen, cells: cluster.totals.coverageCells })),
          h('td', null, h('span', { className: 'atk-target-cluster-note' }, t('target.clusterSummary', { targets: cluster.totals.targets, tested: cluster.totals.tested })))));
        for (const target of cluster.targets) {
          rows.push(h('tr', {
            key: `target-${target.id}`,
            className: 'atk-target-row',
            onClick: () => props.onSelect({ id: target.id, selectId: target.id }),
          },
          h('td', null, h('span', { className: 'atk-target-name' }, target.label)),
          cell(target.services), cell(target.interfaces), cell(target.findings), cell(target.vulnerabilities),
          cell(target.access), cell(target.data), cell(t('target.coverageShort', { seen: target.coverageSeen, cells: target.coverageCells })),
          h('td', null, h('span', { className: statusClass(target.status) }, statusText(target.status)))));
        }
      }
      const gaps = (totals.untested ?? 0) + (totals.recon ?? 0);
      return h('div', { className: 'atk-targets' },
        h('div', { className: 'atk-target-summary' },
          h('span', { className: 'atk-target-summary-title' }, t('target.summary')),
          h('span', { className: 'atk-target-pill' }, t('target.summaryLine', {
            clusters: totals.clusters ?? tree.clusters.length,
            targets: totals.targets ?? 0,
            tested: totals.tested ?? 0,
            recon: totals.recon ?? 0,
            untested: totals.untested ?? 0,
            impacted: totals.impacted ?? 0,
          })),
          gaps > 0 ? h('span', { className: 'atk-target-gap' }, t('target.gapWarning', { untested: totals.untested ?? 0, recon: totals.recon ?? 0 })) : null,
          (totals.unassignedCoverage ?? 0) > 0 ? h('span', { className: 'atk-target-gap' }, t('target.unboundWarning', { cells: totals.unassignedCoverage, seen: totals.unassignedCoverageSeen ?? 0 })) : null),
        h('div', { className: 'atk-table-wrap atk-target-table-wrap' },
          h('table', { className: 'atk-table atk-target-table', 'aria-label': t('target.summary') },
            h('thead', null, h('tr', null,
              h('th', null, t('target.target')),
              h('th', null, t('target.services')),
              h('th', null, t('target.interfaces')),
              h('th', null, t('target.findings')),
              h('th', null, t('target.vulnerabilities')),
              h('th', null, t('target.access')),
              h('th', null, t('target.data')),
              h('th', null, t('target.coverage')),
              h('th', null, t('target.status')))),
            h('tbody', null, rows))));
    }

    function TabPanel(props) {
      const t = props.t;
      const common = {
        t,
        model: props.model,
        search: props.search,
        selectedId: props.selectedId,
        onSelect: props.onSelect,
      };
      let content;
      if (props.tab === 'targets') content = h(TargetsPanel, Object.assign({ key: props.tab }, common));
      else if (props.tab === 'chains') content = h(ChainsTable, common);
      else if (props.tab === 'wildcard') content = h(WildcardTable, common);
      else if (props.tab === 'tasks') content = h(TasksTable, common);
      else if (props.tab === 'team') content = h(TeamTable, common);
      else if (props.tab === 'loop') content = h(LoopPanel, common);
      else if (props.tab === 'settings') content = h(SettingsPanel, common);
      else content = h(NodeDataTable, Object.assign({ key: props.tab, tab: props.tab }, common));
      return h('div', {
        id: `atk-panel-${props.tab}`,
        role: 'tabpanel',
        'aria-labelledby': `atk-tab-${props.tab}`,
        style: { display: 'flex', flexDirection: 'column', flex: '1 1 auto', minHeight: 0 },
      }, content);
    }

    // ---------------------------------------------------------------------
    // Main Session view
    // ---------------------------------------------------------------------

    function AtkGraphViewInner(props) {
      const t = typeof props.t === 'function' ? props.t : (key) => key;
      const [search, setSearch] = React.useState('');
      const [attackOnly, setAttackOnly] = React.useState(true);
      const [kindFilter, setKindFilter] = React.useState('all');
      const [severityFilter, setSeverityFilter] = React.useState('all');
      const [verifiedOnly, setVerifiedOnly] = React.useState(false);
      const [showWildcard, setShowWildcard] = React.useState(false);
      const graphDetail = true;
      const [expandedGroups, setExpandedGroups] = React.useState(() => new Set());
      const [view, setView] = React.useState({ x: 0, y: 0, k: 1 });
      const [selectedId, setSelectedId] = React.useState(null);
      const [hoveredEdgeId, setHoveredEdgeId] = React.useState(null);
      const [pinnedEdgeId, setPinnedEdgeId] = React.useState(null);
      const [tab, setTab] = React.useState('assets');
      const [lowerExpanded, setLowerExpanded] = React.useState(false);
      const [statDetailKey, setStatDetailKey] = React.useState(null);
      const [pendingFocus, setPendingFocus] = React.useState(null);
      const wrapperRef = React.useRef(null);
      const graphPanelRef = React.useRef(null);
      const [graphFullscreen, setGraphFullscreen] = React.useState(false);
      const autoFitRef = React.useRef(false);
      const pendingCenterRef = React.useRef(null);

      const rawProjection = typeof props.useProjection === 'function' ? props.useProjection(PROJECTION_KEY) : undefined;
      const model = React.useMemo(() => normalizeGraph(rawProjection), [rawProjection]);
      const filters = React.useMemo(() => ({
        query: search.trim().toLowerCase(),
        kind: kindFilter,
        severity: severityFilter,
        verifiedOnly,
        showWildcard,
        attackOnly,
      }), [search, kindFilter, severityFilter, verifiedOnly, showWildcard, attackOnly]);
      const filtered = React.useMemo(() => filterModel(model, filters), [model, filters]);
      const targetAssetCount = filtered === null ? 0 : filtered.visible.filter((node) => TARGET_ASSET_KINDS.has(node.kind)).length;
      const targetGroupingAvailable = filtered !== null && targetAssetCount >= TARGET_GROUP_MIN_ASSETS;
      const targetGroupingActive = graphDetail === false && targetGroupingAvailable;
      const grouped = React.useMemo(() => (
        filtered === null ? null : buildPathGraph(model, filtered, { detail: graphDetail, t })
      ), [model, filtered, graphDetail, t]);
      const graphFiltered = grouped ?? filtered;
      const graphModel = grouped ?? model;
      const rendered = React.useMemo(() => (graphFiltered === null ? null : capForRender(graphFiltered)), [graphFiltered]);
      const layout = React.useMemo(() => (rendered === null ? null : layoutGraph(rendered, 'chain', t)), [rendered, t]);
      const highlight = React.useMemo(() => buildHighlight(graphModel, selectedId), [graphModel, selectedId]);
      const selectedNode = graphModel === null || selectedId === null ? null : (graphModel.byId.get(selectedId) || null);
      const selectedVisible = layout !== null && selectedId !== null && layout.positions.has(selectedId);
      const statDetail = React.useMemo(() => (
        model === null || statDetailKey === null ? null : statDetailFor(model, statDetailKey, t)
      ), [model, statDetailKey, t]);

      const activity = React.useMemo(() => {
        if (model === null) return { label: t('graph.idle'), from: null, to: null, targetId: null, detail: null };
        if (selectedNode !== null) {
          return {
            label: `${t('graph.focus')} · ${selectedNode.label}`,
            from: null,
            to: selectedNode.label,
            targetId: selectedNode.id,
            detail: selectedNode.label,
          };
        }
        const task = model.tasks.find((entry) => ['active', 'claimed', 'running', 'pending'].includes(entry.status))
          ?? model.tasks.find((entry) => entry.targetId !== null);
        const targetId = task?.targetId ?? null;
        const target = targetId === null ? null : model.byId.get(targetId) ?? null;
        const incoming = targetId === null ? null : model.edges.find((edge) => edge.to === targetId) ?? null;
        const source = incoming === null ? null : model.byId.get(incoming.from) ?? null;
        if (task !== null && task !== undefined) {
          return {
            label: `${task.actionType}${target === null ? '' : ` → ${target.label}`}`,
            from: source?.label ?? null,
            to: target?.label ?? null,
            targetId,
            detail: task.why.join('; ') || task.actionType,
          };
        }
        if (model.lastAction !== null) {
          return {
            label: `${model.lastAction.tool}/${model.lastAction.action}`,
            from: null,
            to: null,
            targetId: null,
            detail: model.lastAction.at,
          };
        }
        return { label: t('graph.idle'), from: null, to: null, targetId: null, detail: null };
      }, [model, selectedNode, t]);

      const flowEdges = React.useMemo(() => {
        if (graphModel === null) return new Set();
        const sourceEdges = graphModel.edges ?? [];
        if (highlight.selected !== null) return new Set(highlight.edges);
        let targetId = activity.targetId;
        if (targetId !== null && targetId !== undefined && grouped?.groupByNode?.has(targetId)) {
          targetId = grouped.groupByNode.get(targetId);
        }
        if (targetId !== null && targetId !== undefined) {
          const incident = sourceEdges.filter((edge) => edge.from === targetId || edge.to === targetId);
          if (incident.length > 0) return new Set(incident.map((edge) => edge.id).slice(0, 8));
        }
        // The path graph's later hops (finding to access, internal target, data) do not
        // all touch the first target card, so they have to stay in the flow with it.
        const signalEdges = grouped === null
          ? sourceEdges.filter((edge) => edge.confidence >= 0.8).slice(0, 5)
          : sourceEdges.filter((edge) => {
            const from = String(edge.from);
            const to = String(edge.to);
            return from.startsWith('target:') || to.startsWith('target:') || edge.attrs?.path === true
              || edge.kind === 'reached_via' || edge.kind === 'pivots_to' || edge.kind === 'escalates_to';
          });
        const chosen = signalEdges.length > 0 ? signalEdges : sourceEdges.slice(0, 5);
        return new Set(chosen.map((edge) => edge.id));
      }, [graphModel, grouped, highlight, activity]);

      React.useEffect(() => {
        if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') return undefined;
        function handleKey(event) {
          if (event !== null && event !== undefined && event.key === 'Escape') {
            setSelectedId(null);
            setPinnedEdgeId(null);
            setStatDetailKey(null);
          }
        }
        window.addEventListener('keydown', handleKey);
        return () => window.removeEventListener('keydown', handleKey);
      }, []);

      React.useEffect(() => {
        if (typeof document === 'undefined' || typeof document.addEventListener !== 'function') return undefined;
        function onFullscreenChange() {
          setGraphFullscreen(document.fullscreenElement === graphPanelRef.current);
        }
        document.addEventListener('fullscreenchange', onFullscreenChange);
        return () => document.removeEventListener('fullscreenchange', onFullscreenChange);
      }, []);

      function toggleGraphFullscreen() {
        const panel = graphPanelRef.current;
        if (panel === null || typeof document === 'undefined') return;
        if (document.fullscreenElement === panel) {
          if (typeof document.exitFullscreen === 'function') document.exitFullscreen();
          return;
        }
        if (typeof panel.requestFullscreen === 'function') panel.requestFullscreen();
      }

      // One-shot focus requests from other views (openView('atk-graph', nodeId)).
      React.useEffect(() => {
        const request = props.viewRequest;
        if (request === null || request === undefined || typeof request !== 'object') return;
        if (request.view !== 'atk-graph') return;
        if (typeof props.completeViewRequest === 'function') props.completeViewRequest();
        if (typeof request.focus === 'string' && request.focus.length > 0) setPendingFocus(request.focus);
      }, [props.viewRequest]);

      React.useEffect(() => {
        if (pendingFocus === null || model === null) return;
        if (!model.byId.has(pendingFocus)) {
          setPendingFocus(null);
          return;
        }
        focusNode(pendingFocus);
        setPendingFocus(null);
      }, [pendingFocus, model]);

      // Frame the first populated graph once the canvas has been measured.
      React.useEffect(() => {
        if (autoFitRef.current || layout === null || layout.nodes.length === 0) return;
        autoFitRef.current = true;
        fitView();
      }, [layout]);

      // Finish a focus request whose node only becomes visible after filters clear.
      React.useEffect(() => {
        const pending = pendingCenterRef.current;
        if (pending === null || layout === null) return;
        if (!centerOnNode(pending)) pendingCenterRef.current = null;
      }, [layout]);

      function clearFilters() {
        setSearch('');
        setKindFilter('all');
        setSeverityFilter('all');
        setVerifiedOnly(false);
        setShowWildcard(false);
        setPinnedEdgeId(null);
      }

      const selectNode = React.useCallback((nodeId) => {
        if (typeof nodeId !== 'string' || nodeId.length === 0) return;
        setStatDetailKey(null);
        setSelectedId(nodeId);
        setPinnedEdgeId(null);
      }, []);

      /** Center the current view on a positioned node; false when it is not rendered. */
      function centerOnNode(nodeId) {
        if (layout === null) return false;
        const position = layout.positions.get(nodeId);
        if (position === undefined) return false;
        const wrapper = wrapperRef.current;
        if (wrapper === null || wrapper === undefined || typeof wrapper.getBoundingClientRect !== 'function') return true;
        const rect = wrapper.getBoundingClientRect();
        const width = rect !== null && rect !== undefined && rect.width > 0 ? rect.width : 900;
        const height = rect !== null && rect !== undefined && rect.height > 0 ? rect.height : 520;
        const k = clamp(view.k, 0.5, 1.6);
        const centerX = position.x + NODE_W / 2;
        const centerY = position.y + NODE_H / 2;
        setView({ k, x: width / 2 - centerX * k, y: height / 2 - centerY * k });
        return true;
      }

      function focusNode(nodeId) {
        if (model === null || typeof nodeId !== 'string') return;
        setStatDetailKey(null);
        setSelectedId(nodeId);
        if (centerOnNode(nodeId)) return;
        if (grouped?.groupByNode?.has(nodeId)) {
          const groupId = grouped.groupByNode.get(nodeId);
          setExpandedGroups((current) => new Set([...current, groupId]));
        }
        // Hidden by a filter: clear them, then center once the new layout exists.
        pendingCenterRef.current = nodeId;
        setAttackOnly(false);
        setSearch('');
        setKindFilter('all');
        setSeverityFilter('all');
        setVerifiedOnly(false);
        setShowWildcard(true);
      }

      function fitView() {
        if (layout === null) return;
        const wrapper = wrapperRef.current;
        if (wrapper === null || wrapper === undefined || typeof wrapper.getBoundingClientRect !== 'function') {
          setView({ x: 0, y: 0, k: 1 });
          return;
        }
        const rect = wrapper.getBoundingClientRect();
        const width = rect !== null && rect !== undefined && rect.width > 0 ? rect.width : 900;
        const height = rect !== null && rect !== undefined && rect.height > 0 ? rect.height : 520;
        const k = clamp(Math.min((width - 28) / Math.max(layout.width, 1), (height - 28) / Math.max(layout.height, 1)), 0.12, 1.6);
        setView({ k, x: (width - layout.width * k) / 2, y: (height - layout.height * k) / 2 });
      }

      function zoomAt(factor, clientX, clientY) {
        const wrapper = wrapperRef.current;
        let px;
        let py;
        if (wrapper !== null && wrapper !== undefined && typeof wrapper.getBoundingClientRect === 'function') {
          const rect = wrapper.getBoundingClientRect();
          const left = rect !== null && rect !== undefined ? Number(rect.left) || 0 : 0;
          const top = rect !== null && rect !== undefined ? Number(rect.top) || 0 : 0;
          const width = rect !== null && rect !== undefined && rect.width > 0 ? rect.width : 900;
          const height = rect !== null && rect !== undefined && rect.height > 0 ? rect.height : 520;
          px = Number.isFinite(clientX) ? clientX - left : width / 2;
          py = Number.isFinite(clientY) ? clientY - top : height / 2;
        } else {
          px = 450;
          py = 260;
        }
        setView((current) => {
          const nextK = clamp(current.k * factor, 0.15, 3);
          const scale = nextK / current.k;
          return {
            k: nextK,
            x: px - (px - current.x) * scale,
            y: py - (py - current.y) * scale,
          };
        });
      }

      function zoomBy(factor) {
        const wrapper = wrapperRef.current;
        let clientX = 0;
        let clientY = 0;
        if (wrapper !== null && wrapper !== undefined && typeof wrapper.getBoundingClientRect === 'function') {
          const rect = wrapper.getBoundingClientRect();
          clientX = (Number(rect.left) || 0) + (rect.width > 0 ? rect.width / 2 : 450);
          clientY = (Number(rect.top) || 0) + (rect.height > 0 ? rect.height / 2 : 260);
        }
        zoomAt(factor, clientX, clientY);
      }

      function openStat(key) {
        setStatDetailKey(key);
        setSelectedId(null);
        setPinnedEdgeId(null);
        if (key === 'batches') setTab('team');
        else if (key === 'rounds' || key === 'lessons') setTab('loop');
        else if (key === 'wildcardExcluded') { setShowWildcard(true); setTab('wildcard'); }
        else if (key === 'vulnerabilities' || key === 'findings' || key === 'discoveries') setTab('vulnerabilities');
        else if (key === 'access' || key === 'data') setTab(key);
        else if (key === 'assets' || key === 'services') setTab(key);
      }

      function selectFromTable(row) {
        if (row === null || row === undefined) return;
        const id = typeof row.selectId === 'string' && row.selectId.length > 0 ? row.selectId : row.id;
        if (typeof id !== 'string' || id.length === 0) return;
        if (model !== null && model.byId.has(id)) {
          focusNode(id);
          return;
        }
        setSelectedId(id);
      }

      if (model === null) {
        return h('div', { className: 'atk-root' },
          styleNode(),
          h('div', { className: 'atk-header' },
            h('div', { className: 'atk-heading' },
              h('h2', { className: 'atk-title' }, t('title')),
              h('span', { className: 'atk-subtitle' }, t('subtitle')))),
          h('div', { className: 'atk-body' },
            h('div', { className: 'atk-graph-panel' },
              h(EmptyState, {
                waiting: true,
                title: t('waiting.title'),
                hint: t('waiting.hint'),
                instructions: t('waiting.instructions'),
              }))));
      }

      const isEmpty = model.nodes.length === 0;
      const noticeItems = [];
      if (filtered !== null && filtered.hiddenWildcard > 0 && !showWildcard) {
        noticeItems.push({ key: 'hidden-wildcard', tone: 'info', text: t('notice.hiddenWildcard', { count: filtered.hiddenWildcard }) });
      }
      if (rendered !== null && rendered.omittedNodes > 0) {
        noticeItems.push({ key: 'cap-nodes', tone: 'warn', text: t('graph.truncatedNodes', { shown: rendered.nodes.length, omitted: rendered.omittedNodes }) });
      }
      if (rendered !== null && rendered.omittedEdges > 0) {
        noticeItems.push({ key: 'cap-edges', tone: 'warn', text: t('graph.truncatedEdges', { shown: rendered.edges.length, omitted: rendered.omittedEdges }) });
      }
      if (model.truncated.omittedNodes > 0 || model.truncated.omittedEdges > 0) {
        noticeItems.push({
          key: 'host-cap',
          tone: 'info',
          text: t('graph.hostTruncated', { nodes: model.truncated.omittedNodes, edges: model.truncated.omittedEdges }),
        });
      }

      let canvasContent;
      if (layout !== null && layout.nodes.length > 0) {
        canvasContent = h(GraphCanvas, {
          t,
          layout,
          highlight,
          hoveredEdgeId,
          pinnedEdgeId,
          view,
          setView,
          onZoomAt: zoomAt,
          sessionId: props.sessionId,
          wrapperRef,
          onSelectNode: selectNode,
          onHoverEdge: setHoveredEdgeId,
          onSelectEdge: setPinnedEdgeId,
          activity,
          flowEdges,
          onBackground: () => {
            setSelectedId(null);
            setPinnedEdgeId(null);
            setStatDetailKey(null);
          },
        });
      } else if (!isEmpty) {
        canvasContent = h('div', { className: 'atk-empty' },
          h('div', { className: 'atk-empty-title' }, t('graph.emptyFiltered')),
          h('div', { className: 'atk-empty-hint' }, t('graph.emptyFilteredHint')),
          h('button', { type: 'button', className: 'atk-btn', onClick: clearFilters }, t('toolbar.clearFilters')));
      } else {
        canvasContent = h(EmptyState, {
          title: t('empty.title'),
          hint: t('empty.hint'),
          instructions: t('empty.instructions'),
        });
      }

      return h('div', { className: 'atk-root' },
        styleNode(),
        h(GraphHeader, { t, model, sessionId: props.sessionId }),
        h('div', { className: 'atk-status-row' },
          h(GraphStats, {
            t,
            model,
            hiddenWildcard: filtered === null || showWildcard ? 0 : filtered.hiddenWildcard,
            onStat: openStat,
            activeStat: statDetailKey,
          }),
          h(ProxyStatusBar, { t })),
        isEmpty ? null : h(GraphToolbar, {
          t,
          model,
          view,
          layout,
          filtered,
          search,
          kindFilter,
          severityFilter,
          verifiedOnly,
          showWildcard,
          onSearch: setSearch,
          onKind: setKindFilter,
          onSeverity: setSeverityFilter,
          onVerifiedOnly: setVerifiedOnly,
          onShowWildcard: setShowWildcard,
          targetGroupingActive,
          hiddenByAttack: filtered === null ? 0 : filtered.hiddenByAttack,
          onZoom: zoomBy,
          onFit: fitView,
          onReset: () => setView({ x: 0, y: 0, k: 1 }),
          fullscreen: graphFullscreen,
          onFullscreen: toggleGraphFullscreen,
          filtersActive: filtered === null ? false : filtered.filtersActive,
          onClearFilters: clearFilters,
        }),
        h('div', { className: 'atk-body' },
          h('div', { className: 'atk-graph-panel', ref: graphPanelRef },
            h('div', { className: 'atk-graph-head' },
              h('span', { className: 'atk-graph-head-strong' }, t('view.label')),
              h('span', null, t('graph.nodeCount', { count: layout === null ? 0 : layout.nodes.length })),
              h('span', null, t('graph.edgeCount', { count: layout === null ? 0 : layout.edges.length })),
              filtered !== null && filtered.hiddenByAttack > 0
                ? h('span', { className: 'atk-graph-head-muted', title: t('graph.attackHint') }, t('graph.attackHidden', { count: filtered.hiddenByAttack }))
                : null,
              h('span', { className: 'atk-spacer' }),
              h('span', null, t('graph.panHint'))),
            noticeItems.length === 0
              ? null
              : h('div', { style: { display: 'flex', flexDirection: 'column', gap: '2px', padding: '4px 10px 0' } },
                noticeItems.map((notice) => h(Notice, { key: notice.key, tone: notice.tone }, notice.text))),
            canvasContent,
            layout === null || layout.nodes.length === 0 ? null : h(Legend, { t, model })),
          ),
        selectedNode !== null || statDetail !== null
          ? h('div', {
            className: 'atk-modal-layer',
            role: 'presentation',
            onClick: () => { setStatDetailKey(null); setSelectedId(null); },
          }, h('div', {
            className: 'atk-modal',
            role: 'dialog',
            'aria-modal': 'true',
            'aria-label': t('detail.title'),
            onClick: (event) => event.stopPropagation(),
          }, statDetail !== null
            ? h(StatDetailPane, {
              t,
              detail: statDetail,
              onClose: () => setStatDetailKey(null),
              onSelect: (nodeId) => { setStatDetailKey(null); focusNode(nodeId); },
            })
            : selectedNode !== null && selectedNode.kind === 'target'
              ? h(TargetGroupPane, {
                t,
                group: selectedNode,
                model,
                onClose: () => setSelectedId(null),
                onSelectNode: (nodeId) => setSelectedId(nodeId),
                onToggleExpand: () => {
                  setExpandedGroups((current) => {
                    const next = new Set(current);
                    if (next.has(selectedNode.id)) next.delete(selectedNode.id);
                    else next.add(selectedNode.id);
                    return next;
                  });
                },
              })
              : h(DetailPane, {
              t,
              model,
              node: selectedNode,
              nodeId: selectedId,
              inGraph: selectedVisible,
              onClose: () => setSelectedId(null),
              onSelectNode: selectNode,
              onFocus: focusNode,
            })))
          : null,
        isEmpty
          ? null
          : h('div', { className: lowerExpanded ? 'atk-lower atk-lower--expanded' : 'atk-lower' },
            h('div', { className: 'atk-lower-head' },
              h(TabBar, {
                t,
                model,
                active: tab,
                onTab: (next) => { setTab(next); setLowerExpanded(true); },
              }),
              h('button', {
                type: 'button',
                className: 'atk-btn atk-lower-toggle',
                onClick: () => setLowerExpanded((value) => !value),
              }, lowerExpanded ? t('data.collapse') : t('data.expand'))),
            lowerExpanded
              ? h(TabPanel, {
                t,
                tab,
                model,
                search: search.trim().toLowerCase(),
                selectedId,
                onSelect: selectFromTable,
              })
              : null),
        h('div', { className: 'atk-live', role: 'status', 'aria-live': 'polite' },
          selectedNode === null ? '' : `${localized(t, 'kind', selectedNode.kind)}: ${selectedNode.label}`));
    }

    /** Registered conversation view: one error boundary around the real page. */
    function AtkGraphView(props) {
      const t = typeof props.t === 'function' ? props.t : (key) => key;
      return h(AtkErrorBoundary, { t }, h(AtkGraphViewInner, props));
    }

    // ---------------------------------------------------------------------
    // Plugin registration
    // ---------------------------------------------------------------------

    /** Services this client plugin reads from the surrounding composition. */
    const inject = ['slots', 'locale'];

    function apply(ctx) {
      ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'atk-brain: dictionaries');
      const t = ctx.locale.bind(NS);
      ctx.slots.inject('conversation.view', () => ctx.slots.register({
        name: 'conversation.view',
        id: 'atk-graph',
        order: 20,
        locale: NS,
        label: () => t('view.label'),
      }, AtkGraphView));
    }

    return { inject, apply };
  },
});
