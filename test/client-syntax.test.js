/**
 * Contract tests for the build-free browser bundle `atk-brain/client.js`.
 *
 * There is no bundler and no DOM here: the test mocks the loader global and the
 * single `react` external, materializes the real factory, applies the plugin to
 * a fake client context, and asserts the registration + dictionary contract.
 * Visual behavior is covered by the browser; this file guards the wire seams.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const CLIENT_URL = new URL('../client.js', import.meta.url);
const code = readFileSync(CLIENT_URL, 'utf8');

/** Minimal React face: the factory references these while defining components. */
function createMockReact() {
  class Component {
    constructor(props) {
      this.props = props ?? {};
      this.state = {};
    }

    setState(partial) {
      const next = typeof partial === 'function' ? partial(this.state, this.props) : partial;
      this.state = { ...this.state, ...(next ?? {}) };
    }
  }

  function createElement(type, props, ...children) {
    const normalized = props === null || props === undefined ? {} : { ...props };
    if (children.length === 1) normalized.children = children[0];
    else if (children.length > 1) normalized.children = children;
    return { type, props: normalized };
  }

  return {
    createElement,
    Component,
    Fragment: 'fragment',
    memo: (component) => component,
    useState: (initial) => [typeof initial === 'function' ? initial() : initial, () => {}],
    useEffect: () => undefined,
    useMemo: (factory) => factory(),
    useCallback: (fn) => fn,
    useRef: (initial) => ({ current: initial }),
    useSyncExternalStore: (subscribe, snapshot) => snapshot(),
  };
}

/** Load the bundle exactly like the DSH client module loader does. */
function loadBundle() {
  const mockReact = createMockReact();
  let registration = null;
  const sandbox = {
    window: {
      __ModuleLoader__: {
        load(entry) {
          registration = entry;
        },
      },
    },
    console,
    setTimeout,
    clearTimeout,
  };
  vm.runInNewContext(code, sandbox, { filename: 'atk-brain/client.js' });
  assert.ok(registration !== null, 'client.js did not call window.__ModuleLoader__.load');
  const required = [];
  const plugin = registration.factory((specifier) => {
    required.push(specifier);
    if (specifier === 'react') return mockReact;
    throw new Error(`unexpected external module: ${specifier}`);
  });
  return { registration, plugin, required, mockReact };
}

/** Fake host-side client context capturing the locale + slot registrations. */
function createFakeContext() {
  const captured = { dictionaries: null, namespace: null, injection: null, definition: null, component: null, effectLabels: [] };
  const ctx = {
    effect(callback, label) {
      captured.effectLabels.push(label);
      const disposer = callback();
      assert.equal(typeof disposer, 'function', `effect "${label}" must return a disposer`);
      return disposer;
    },
    locale: {
      register(namespace, dictionaries) {
        captured.namespace = namespace;
        captured.dictionaries = dictionaries;
        return () => {};
      },
      bind(namespace) {
        return (key, params) => {
          const table = captured.dictionaries;
          const template = (table?.zh?.[key]) ?? (table?.en?.[key]) ?? key;
          if (params === undefined || params === null) return template;
          return template.replace(/\{(\w+)\}/g, (match, name) => (name in params ? String(params[name]) : match));
        };
      },
    },
    slots: {
      inject(name, callback) {
        captured.injection = name;
        callback();
      },
      register(definition, component) {
        captured.definition = definition;
        captured.component = component;
        return () => {};
      },
    },
  };
  return { ctx, captured };
}

function appliedPlugin() {
  const bundle = loadBundle();
  const { ctx, captured } = createFakeContext();
  bundle.plugin.apply(ctx);
  return { ...bundle, ctx, captured };
}

test('bundle registers one loader factory and only requires react', () => {
  const { registration, plugin, required } = loadBundle();
  assert.equal(registration.id, '@local/atk-brain');
  assert.equal(typeof registration.factory, 'function');
  assert.deepEqual([...required], ['react']);
  assert.equal(typeof plugin.apply, 'function');
  assert.deepEqual([...plugin.inject], ['slots', 'locale']);
});

test('apply registers the atkbrain dictionaries and the conversation view', () => {
  const { captured } = appliedPlugin();
  assert.deepEqual(captured.effectLabels, ['atk-brain: dictionaries']);
  assert.equal(captured.namespace, 'atkbrain');
  assert.equal(captured.injection, 'conversation.view');
  assert.equal(captured.definition.name, 'conversation.view');
  assert.equal(captured.definition.id, 'atk-graph');
  assert.equal(captured.definition.order, 20);
  assert.equal(captured.definition.locale, 'atkbrain');
  assert.equal(typeof captured.definition.label, 'function');
  assert.equal(captured.definition.label(), '攻击图谱');
  assert.equal(typeof captured.component, 'function');
});

test('zh and en dictionaries expose the same complete keys', () => {
  const { captured } = appliedPlugin();
  const dictionaries = captured.dictionaries;
  assert.ok(dictionaries?.zh && dictionaries?.en);
  assert.deepEqual(Object.keys(dictionaries.zh).sort(), Object.keys(dictionaries.en).sort());
  for (const [key, value] of Object.entries(dictionaries.zh)) {
    assert.equal(typeof value, 'string', `zh.${key} must be a string`);
    assert.ok(value.length > 0, `zh.${key} must not be empty`);
    assert.equal(typeof dictionaries.en[key], 'string', `en.${key} must be a string`);
    assert.ok(dictionaries.en[key].length > 0, `en.${key} must not be empty`);
  }
  for (const required of [
    'view.label',
    'title',
    'waiting.title',
    'empty.title',
    'error.title',
    'stat.assets',
    'stat.batches',
    'stat.rounds',
    'stat.lessons',
    'tab.assets',
    'tab.team',
    'tab.loop',
    'loop.title',
    'loop.empty',
    'loop.emptyHint',
    'verdict.hold',
    'activation.disarmed',
    'col.verdict',
    'col.lessonKey',
    'detail.title',
    'col.batchId',
    'team.title',
    'team.empty',
    'team.emptyHint',
    'team.summary',
    'status.artifact_ready',
  ]) {
    assert.ok(dictionaries.zh[required] !== undefined, `missing zh.${required}`);
    assert.ok(dictionaries.en[required] !== undefined, `missing en.${required}`);
  }
});

test('all eleven conversation-view tabs have localized labels', () => {
  const { captured } = appliedPlugin();
  const tabs = ['assets', 'services', 'findings', 'access', 'data', 'chains', 'wildcard', 'tasks', 'team', 'loop', 'settings'];
  assert.equal(tabs.length, 11);
  for (const tab of tabs) {
    assert.ok(captured.dictionaries.zh[`tab.${tab}`] !== undefined, `missing zh tab.${tab}`);
    assert.ok(captured.dictionaries.en[`tab.${tab}`] !== undefined, `missing en tab.${tab}`);
  }
  assert.equal(captured.dictionaries.zh['verification.passed'], '验证成功');
  assert.equal(captured.dictionaries.zh['verification.pending'], '验证中');
  assert.equal(captured.dictionaries.zh['verification.failed'], '验证失败');
  assert.equal(code.includes("'findings', 'access'"), false);
  assert.equal(captured.dictionaries.zh['tab.team'], '团队');
  assert.equal(captured.dictionaries.en['tab.team'], 'Team');
  assert.equal(captured.dictionaries.zh['tab.loop'], '循环');
  assert.equal(captured.dictionaries.en['tab.loop'], 'Loop');
});

test('team batch vocabulary is localized in both languages', () => {
  const { captured } = appliedPlugin();
  const dictionaries = captured.dictionaries;
  const statuses = ['planned', 'dispatched', 'artifact_ready', 'completed', 'merged', 'failed', 'merge_failed', 'cancelled'];
  for (const status of statuses) {
    assert.ok(dictionaries.zh[`status.${status}`] !== undefined, `missing zh status.${status}`);
    assert.ok(dictionaries.en[`status.${status}`] !== undefined, `missing en status.${status}`);
  }
  for (const key of ['team.title', 'team.statusFilter', 'team.statusAll', 'team.summary', 'team.empty', 'team.emptyHint', 'team.emptyFiltered', 'team.artifactReady', 'team.artifactPending', 'col.assets', 'col.agent', 'col.mode', 'col.artifact', 'col.mergedAt', 'stat.batchesMerged']) {
    assert.ok(dictionaries.zh[key] !== undefined, `missing zh.${key}`);
    assert.ok(dictionaries.en[key] !== undefined, `missing en.${key}`);
  }
});

test('every literal dictionary key used in the bundle exists in both locales', () => {
  const { captured } = appliedPlugin();
  const dictionaries = captured.dictionaries;
  const keys = new Set();
  for (const pattern of [/\bt\(\s*'([^'$]+)'/g, /\bt\(\s*"([^"$]+)"/g]) {
    let match;
    while ((match = pattern.exec(code)) !== null) keys.add(match[1]);
  }
  assert.ok(keys.size > 40, `expected a substantial dictionary surface, found ${keys.size} literal keys`);
  const missing = [...keys].filter((key) => dictionaries.zh[key] === undefined || dictionaries.en[key] === undefined);
  assert.deepEqual(missing, [], `missing dictionary keys: ${missing.join(', ')}`);
});

test('view label follows the active locale', () => {
  const { captured } = appliedPlugin();
  assert.equal(captured.dictionaries.en['view.label'], 'Attack Graph');
  assert.equal(captured.dictionaries.zh['view.label'], '攻击图谱');
});

test('loop / supervision / intent / lesson vocabulary is localized in both languages', () => {
  const { captured } = appliedPlugin();
  const dictionaries = captured.dictionaries;
  const literalKeys = [
    'tab.loop', 'stat.rounds', 'stat.lessons', 'stat.lessonsApplied',
    'loop.title', 'loop.state', 'loop.phase', 'loop.round', 'loop.objective', 'loop.objectiveType',
    'loop.goalPhase', 'loop.activation', 'loop.ringValue', 'loop.noProgress', 'loop.emptyRounds',
    'loop.maxActions', 'loop.stopReason', 'loop.autoContinue', 'loop.startedAt', 'loop.lastStepAt',
    'loop.appliedLessons', 'loop.disarmedWarn', 'loop.supervision', 'loop.latestSupervision',
    'loop.verdict', 'loop.secondaryVerdict', 'loop.source', 'loop.confidence', 'loop.diagnosis',
    'loop.nextPlan', 'loop.mustIntents', 'loop.preferTactics', 'loop.banRepeats',
    'loop.stopRecommended', 'loop.supervisionHistory', 'loop.supervisionEmpty', 'loop.intents',
    'loop.emptyIntents', 'loop.lessons', 'loop.emptyLessons', 'loop.empty', 'loop.emptyHint',
    'col.verdict', 'col.source', 'col.round', 'col.createdAt', 'col.expectedEvidence',
    'col.lessonKey', 'col.route', 'col.idea', 'col.wins', 'col.fails', 'col.uses',
    'kind.loop', 'kind.intent', 'kind.supervision', 'kind.lesson',
  ];
  for (const key of literalKeys) {
    assert.ok(dictionaries.zh[key] !== undefined, `missing zh.${key}`);
    assert.ok(dictionaries.en[key] !== undefined, `missing en.${key}`);
  }
  const families = {
    verdict: ['hold', 'pivot', 'verify', 'escalate', 'stop', 'verified', 'refuted', 'inconclusive', 'unknown'],
    supervision: ['round_plan', 'verification', 'unknown'],
    source: ['deterministic', 'model', 'subagent', 'unknown'],
    activation: ['armed', 'disarmed'],
    status: ['active', 'paused', 'stopped', 'exhausted', 'complete', 'blocked', 'recorded', 'open', 'claimed', 'retired'],
  };
  for (const [family, values] of Object.entries(families)) {
    for (const value of values) {
      assert.ok(dictionaries.zh[`${family}.${value}`] !== undefined, `missing zh ${family}.${value}`);
      assert.ok(dictionaries.en[`${family}.${value}`] !== undefined, `missing en ${family}.${value}`);
    }
  }
});

test('header stats open a clickable right-side detail pane', () => {
  const { captured } = appliedPlugin();
  const dictionaries = captured.dictionaries;
  for (const key of ['stat.openHint', 'stat.detailCount', 'stat.detailEmpty', 'stat.detailHint']) {
    assert.ok(dictionaries.zh[key] !== undefined, `missing zh.${key}`);
    assert.ok(dictionaries.en[key] !== undefined, `missing en.${key}`);
  }
  assert.ok(code.includes('function StatDetailPane'), 'StatDetailPane missing');
  assert.ok(code.includes('function statDetailFor'), 'statDetailFor missing');
  assert.ok(code.includes("className: 'atk-stat-detail-row'"), 'stat detail row missing');
  assert.ok(code.includes("onStat: openStat"), 'stats are not wired to openStat');
  assert.ok(code.includes("'aria-pressed': props.active === true"), 'stat buttons lack pressed state');
});

test('self-team brief and distilled skills are localized in both languages', () => {
  const { captured } = appliedPlugin();
  const dictionaries = captured.dictionaries;
  for (const key of [
    'loop.selfTeam', 'loop.selfTeamHint', 'loop.supervisionTeam', 'loop.evolutionTeam',
    'loop.selfTeamEmpty', 'loop.selfBriefEmpty', 'loop.gained', 'loop.missed', 'loop.advice',
    'loop.verificationTeam', 'loop.reportTeam', 'loop.lastVerifyAt', 'loop.lastReportAt', 'loop.reportTheme',
    'loop.verifiedCount', 'loop.ratedCount',
    'loop.antiDeadlock', 'loop.recommendedNext', 'loop.deadlockRisk', 'loop.skillLibrary',
    'loop.skillEmpty', 'loop.skillCount', 'loop.members', 'loop.lastBriefAt', 'loop.lastDistillAt',
    'col.skillName', 'col.skillRoute', 'col.skillPath', 'kind.self_team', 'kind.skill',
    'edge.distills', 'edge.reports_to', 'edge.learned_from',
  ]) {
    assert.ok(dictionaries.zh[key] !== undefined, `missing zh.${key}`);
    assert.ok(dictionaries.en[key] !== undefined, `missing en.${key}`);
  }
  assert.ok(code.includes('function normalizeSelfTeam'), 'normalizeSelfTeam missing');
  assert.ok(code.includes("key: 'loop-self-team'"), 'self-team loop section missing');
  assert.equal(code.includes("ariaLabel: t('loop.skillLibrary')"), false, 'distilled skill table leaves with self-evolution');
});

test('graph canvas uses a non-passive mouse-wheel zoom around the cursor', () => {
  assert.ok(code.includes("addEventListener('wheel', onNativeWheel, { passive: false })"), 'native non-passive wheel listener missing');
  assert.match(code, /h\(GraphCanvas,[\s\S]{0,500}?onZoomAt: zoomAt/u, 'onZoomAt must be wired to GraphCanvas (not the toolbar)');
  assert.ok(code.includes('px - (px - current.x) * scale'), 'cursor-centered zoom math missing');
  assert.ok(code.includes("'graph.panHint': '滚轮缩放 · 拖拽平移'"), 'zh wheel hint missing');
  assert.ok(code.includes("'graph.panHint': 'Scroll to zoom · drag to pan'"), 'en wheel hint missing');
});

test('attack-graph redesign has a compact attack view and card-style nodes', () => {
  const { captured } = appliedPlugin();
  for (const key of ['toolbar.attackView', 'toolbar.fullView', 'graph.attackHidden', 'graph.attackHint', 'graph.legendHigh']) {
    assert.ok(captured.dictionaries.zh[key] !== undefined, `missing zh.${key}`);
    assert.ok(captured.dictionaries.en[key] !== undefined, `missing en.${key}`);
  }
  assert.ok(code.includes('function isAttackViewNode'), 'attack-view predicate missing');
  assert.ok(code.includes('hiddenByAttack'), 'hiddenByAttack count missing');
  assert.ok(code.includes('function GraphStageLayer'), 'stage band layer missing');
  assert.ok(code.includes("className: 'atk-node-card'"), 'card node missing');
  assert.ok(code.includes("className: 'atk-edge-glow'"), 'edge glow missing');
  assert.ok(code.includes('M ${x1} ${y1} C'), 'curved edge path missing');
  assert.match(code, /function chainHeaderLabel/u, 'chain headers must name the target column');
  assert.ok(code.includes("return t('graph.stage.target')"), 'host, address and service share one target column');
  assert.ok(code.includes('const usedColumns = [...columns.keys()].sort'), 'empty chain columns stay hidden');
  assert.ok(code.includes('function buildPathGraph'), 'path layout missing');
  assert.ok(code.includes('const graphDetail = true'), 'path layout must stay detailed');
  assert.equal(code.includes("'toolbar.layoutBrief'"), false);
  assert.equal(code.includes("'toolbar.layoutDetail'"), false);
  assert.equal(code.includes("t('toolbar.layout')"), false);
  assert.ok(code.includes("'graph.stage.internal'"), 'internal target column missing');
  assert.ok(code.includes("'col.vulnType'"), 'vulnerability type column missing');
  assert.equal(code.includes("key: 'severity', label: t('col.severity')"), false, 'severity column must leave the vulnerability table');
  assert.ok(code.includes('SEVERITY_COLOR[severity]'), 'CVSS severity must use the severity color');
  assert.ok(code.includes('cvss: verificationState(node)'), 'the CVSS column must sort by the numeric score');
  assert.ok(code.includes('function footholdTitle'), 'access and credential rows need a Chinese label');
  assert.ok(code.includes('function footholdStory'), 'opening an access row must explain what was obtained');
  assert.ok(code.includes("'vulnerabilities', 'access', 'data'"), 'access and data are their own tabs');
  assert.ok(code.includes('function rceChains'), 'the attack chain is the path to code execution');
  assert.ok(code.includes('`ip:${surfaceHost}`'), 'a public IP target must stay a target card');
  assert.ok(code.includes('allowHosts.some'), 'every authorized target stays in the target column');
  assert.ok(code.includes("t('chain.toRce')"), 'the attack chain heading names code execution');
  assert.ok(code.includes('function findingDisplaySeverity'), 'graph cards must color the CVSS band');
  assert.ok(code.includes('node.refuted !== true'), 'a refuted finding stays off the attack graph');
  assert.ok(code.includes('&& secondaryRefuted === false'), 'a refuted finding stays off the vulnerability table');
  assert.ok(code.includes('function bestParentForFinding'), 'verified findings must attach to a target even when several targets are shown');
  assert.ok(code.includes('function recordIdentity'), 'repeated access and data cards collapse to one');
  assert.ok(code.includes('groupByNode,'), 'path layout must name which node belongs to a target card');
  assert.ok(code.includes('lateralGroups'), 'a reached machine must appear as its own internal target');
  assert.ok(code.includes('function chineseEscalationText'), 'escalation proof must be shown in Chinese');
  assert.ok(code.includes('function displayFindingTitle'), 'escalation names must use the Chinese finding title');
  assert.ok(code.includes('function normalizePacketText'), 'request and response packets must turn escaped newlines into real lines');
  assert.equal(code.includes("t('toolbar.verifiedOnly')"), false, 'graph filter row must leave the relationship view');
  assert.ok(code.includes('requestFullscreen'), 'the relationship graph must be able to fill the screen');
  const codeName = code.indexOf("name = '远程代码执行'");
  const fileName = code.indexOf("name = '任意文件读取'");
  assert.ok(codeName > 0 && fileName > codeName, 'an escalated result must not keep the original file-read name');
  assert.ok(code.includes('function findingOwnText'), 'escalation titles must ignore the ancestor boilerplate');
  assert.ok(code.includes('function harmEnables'), 'an escalation must be this vulnerability or a harm it directly enabled');
  assert.equal(/name = '远程代码执行'[\s\S]{0,220}tomcat manager/u.test(code), false, 'mentioning Tomcat Manager must not by itself rename the vulnerability to code execution');
  assert.ok(code.includes("if (tab === 'loop') return model.loop.totals.rounds"), 'loop tab counts rounds, not every supervision record');
  assert.ok(code.includes("'col.escalation'"), 'harm escalation column missing');
  assert.ok(code.includes('function escalationView'), 'harm escalation detail missing');
  assert.ok(code.includes('漏洞危害提升成功'), 'a recorded raise is named as a successful harm escalation');
  assert.ok(code.includes('source.raisedTo'), 'the original vulnerability shows the raise in the escalation column');
  assert.ok(code.includes("'escalates_to'"), 'harm escalation edge missing');
  assert.ok(code.includes('String(coverage.vulnerabilities)'), 'the vulnerability stat counts the vulnerability page, not every finding');
});

test('status strip keeps the proxy and does not offer the removed connection strip', () => {
  const { captured } = appliedPlugin();
  for (const key of ['header.exportReport', 'report.formats', 'report.markdown', 'report.html', 'report.json', 'report.csv', 'settings.title', 'settings.resources', 'settings.normal', 'settings.abnormal', 'settings.tools', 'settings.dicts', 'settings.survey', 'settings.fofa', 'settings.hunter', 'settings.quake', 'tab.settings', 'proxy.title', 'proxy.enabled', 'proxy.disabled', 'proxy.blocked', 'proxy.test', 'proxy.loopback', 'proxy.unavailable', 'loop.coverage', 'loop.hypotheses']) {
    assert.ok(captured.dictionaries.zh[key] !== undefined, `missing zh.${key}`);
    assert.ok(captured.dictionaries.en[key] !== undefined, `missing en.${key}`);
  }
  for (const key of ['settings.mcp', 'mcp.title', 'mcp.ego', 'mcp.yakit']) {
    assert.equal(captured.dictionaries.zh[key], undefined, `unexpected zh.${key}`);
    assert.equal(captured.dictionaries.en[key], undefined, `unexpected en.${key}`);
  }
  assert.equal(code.includes('function McpStatusBar'), false);
  assert.equal(code.includes('function normalizeMcp'), false);
  assert.equal(code.includes("fetch('/atkbrain/mcp/status'"), false);
  assert.equal(code.includes('Ego Lite'), false);
  assert.equal(code.includes('Yakit'), false);
  assert.ok(code.includes('function ProxyStatusBar'), 'ProxyStatusBar missing');
  assert.ok(code.includes("fetch('/atkbrain/proxy/status'"), 'proxy status route not polled');
  assert.ok(code.includes("className: 'atk-proxy-strip'"), 'proxy strip markup missing');
  assert.ok(code.includes('HIDDEN_CANVAS_KINDS'), 'hidden operational kinds missing');
  assert.ok(code.includes('function SettingsPanel'), 'SettingsPanel missing');
  assert.ok(code.includes('function ReportExportButton'), 'ReportExportButton missing');
  assert.ok(code.includes("fetch('/atkbrain/report/export'"), 'report export route not wired');
  assert.ok(code.includes("fetch('/atkbrain/settings/status'"), 'settings status route not polled');
  assert.ok(code.includes("fetch('/atkbrain/settings'"), 'settings control route missing');
});

test('multi-asset graph folds into target cards with expandable details', () => {
  for (const token of [
    'function buildTargetGroups',
    'TARGET_GROUP_MIN_ASSETS',
    'targetGroupingActive',
    "kind: 'target'",
    'atk-node--target',
    'function TargetGroupPane',
    'group.expand',
  ]) {
    assert.ok(code.includes(token), `missing target grouping token: ${token}`);
  }
  const { captured } = appliedPlugin();
  for (const key of ['group.title', 'group.members', 'group.expand', 'toolbar.groupTargets', 'graph.targetGroups']) {
    assert.ok(captured.dictionaries.zh[key] !== undefined, `missing zh.${key}`);
    assert.ok(captured.dictionaries.en[key] !== undefined, `missing en.${key}`);
  }
});

test('crown-jewel display terminology is milestone', () => {
  const { captured } = appliedPlugin();
  const { zh, en } = captured.dictionaries;
  assert.equal(zh['stat.crown'], '里程碑');
  assert.equal(zh['col.crown'], '里程碑');
  assert.equal(zh['chain.crown'], '里程碑路径');
  assert.equal(en['stat.crown'], 'Milestones');
  assert.equal(en['col.crown'], 'Milestone');
  assert.equal(en['chain.crown'], 'Milestone paths');
});

test('graph uses a modal detail and in-graph activity animation', () => {
  for (const token of [
    "className: 'atk-modal-layer'",
    "className: 'atk-modal'",
    "className: 'atk-flow-dot'",
    "animateMotion",
    "className: 'atk-activity'",
    "atk-node--active",
    "atk-graph-grid",
    "worldSize",
  ]) {
    assert.ok(code.includes(token), `missing graph UI token: ${token}`);
  }
  assert.ok(code.includes(".atk-lower{display:flex"), 'lower tabs layout missing');
  assert.ok(code.includes('function ReportExportButton'), 'report export button missing');
});

test('bundle is a single loader registration with no forbidden sources', () => {
  assert.equal((code.match(/__ModuleLoader__\.load\(/g) ?? []).length, 1);
  assert.equal((code.match(/require\(\s*['"]react['"]\s*\)/g) ?? []).length, 1);
  assert.ok(!/document\.head|document\.body/.test(code), 'client.js must not touch document head/body');
  assert.ok(!/@deepseek-ai\//.test(code), 'client.js must not reference vendor client packages');
  assert.ok(!/require\(\s*['"]@/.test(code), 'client.js must not require scoped packages');
  assert.ok(!/^\s*(import|export)\s/m.test(code), 'client.js must stay a loader-registered classic bundle');
});
