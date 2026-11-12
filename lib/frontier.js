/**
 * Deterministic next-action frontier.
 *
 * The frontier is a pure projection of graph state + scope: no network calls
 * and no randomness. The agent is expected to call `atkbrain_query
 * action=frontier`, execute one action at a time, and record evidence.
 */
import { isPrivateIp, parseCidr } from './cidr.js';
import { BUG_CLASSES, COVERAGE_DUTIES, normalizeInterfacePath } from './coverage.js';
import { classSurface, observedProducts } from './surface.js';
import { applicationExpanded, artifactSiblingPaths, directoryPaths, ledgerIsThin, ledgerPath } from './endpoint-vocab.js';
import { harmRank, isHardeningFinding, isVulnerabilityNode, pathsWithFinding, secondaryVerificationPassed, unrecordedProductVersions } from './finding-classification.js';
import { selfTeamNode } from './self-teams.js';
import { handoffOverdue } from './supervision-memory.js';
import { attemptsExhausted, isTerminalSecondary } from './verify-queue.js';
import { RISK_PENALTY } from './constants.js';
import { isCrownJewel } from './path.js';
import { evaluateScope } from './scope.js';
import { concreteAllowTargets } from './targets.js';
import { actionId, clamp } from './util.js';

const IMPACT = Object.freeze({
  set_scope: 100,
  validate_access: 85,
  escalate_privilege: 90,
  collect_data_evidence: 88,
  validate_credential: 78,
  verify_finding: 72,
  establish_pivot: 70,
  enumerate_internal_range: 65,
  enumerate_services: 62,
  test_hypothesis: 76,
  test_coverage: 58,
  confirm_wildcard_zone: 45,
  enrich_asset: 40,
  resolve_identity: 38,
  report_findings: 55,
});

const EVIDENCE_VALUE = Object.freeze({
  set_scope: 90,
  validate_access: 95,
  escalate_privilege: 90,
  collect_data_evidence: 100,
  validate_credential: 80,
  verify_finding: 85,
  establish_pivot: 80,
  enumerate_internal_range: 65,
  enumerate_services: 60,
  test_hypothesis: 82,
  test_coverage: 64,
  confirm_wildcard_zone: 55,
  enrich_asset: 45,
  resolve_identity: 40,
  report_findings: 90,
});

function buildIndex(state) {
  const outgoing = new Map();
  const incoming = new Map();
  for (const edge of Object.values(state.edges)) {
    if (state.nodes[edge.from] === undefined || state.nodes[edge.to] === undefined) continue;
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
  return { outgoing, incoming };
}

function hasOutgoing(index, id, kind) {
  return (index.outgoing.get(id) ?? []).some((edge) => edge.kind === kind);
}

function hasIncoming(index, id, kind) {
  return (index.incoming.get(id) ?? []).some((edge) => edge.kind === kind);
}

function serviceEndpoint(state, index, service) {
  const links = index.incoming.get(service.id) ?? [];
  for (const edge of links) {
    if (edge.kind !== 'exposes') continue;
    const endpoint = state.nodes[edge.from];
    if (endpoint?.kind === 'host' || endpoint?.kind === 'ip') return endpoint;
  }
  return undefined;
}

function isInternalNode(state, index, node) {
  if (node.kind === 'ip') return isPrivateIp(node.attrs?.addr ?? node.key);
  if (node.kind === 'host') return node.attrs?.realm === 'internal';
  if (node.kind === 'cidr') {
    if (node.attrs?.realm === 'internal') return true;
    const cidr = parseCidr(node.key);
    return cidr !== undefined && isPrivateIp(cidr.version === 4
      ? `${Number((cidr.network >> 24n) & 0xffn)}.${Number((cidr.network >> 16n) & 0xffn)}.${Number((cidr.network >> 8n) & 0xffn)}.${Number(cidr.network & 0xffn)}`
      : undefined);
  }
  if (node.kind === 'segment') return node.attrs?.realm !== 'external';
  if (node.kind === 'service') {
    const endpoint = serviceEndpoint(state, index, node);
    return endpoint !== undefined && isInternalNode(state, index, endpoint);
  }
  return false;
}

function targetForNode(node) {
  if (node.kind === 'host') {
    return {
      type: 'host',
      host: node.attrs?.fqdn ?? node.key,
      ips: Array.isArray(node.attrs?.ips) ? node.attrs.ips : [],
    };
  }
  if (node.kind === 'ip') return { type: 'ip', ip: node.attrs?.addr ?? node.key };
  if (node.kind === 'cidr') return { type: 'cidr', cidr: node.key };
  if (node.kind === 'url' || node.kind === 'webapp') {
    return { type: 'url', url: node.attrs?.url ?? node.key, port: node.attrs?.port };
  }
  return undefined;
}

function scopeForNode(state, index, node) {
  let target;
  if (node.kind === 'service') {
    const endpoint = serviceEndpoint(state, index, node);
    target = endpoint === undefined ? undefined : targetForNode(endpoint);
    if (target !== undefined) target.port = Number(node.attrs?.port) || undefined;
  } else {
    target = targetForNode(node);
  }
  if (target === undefined) return { verdict: 'unknown', reason: 'no network target for this node', allowedIps: [] };
  try {
    const result = evaluateScope(state.scope, target);
    if (result.allowed) return { verdict: 'allow', reason: result.reason, allowedIps: result.allowedIps };
    if (state.scope?.allow?.length === 0) return { verdict: 'unknown', reason: 'scope.allow is empty', allowedIps: [] };
    return { verdict: 'deny', reason: result.reason, allowedIps: [] };
  } catch (error) {
    return { verdict: 'unknown', reason: error instanceof Error ? error.message : String(error), allowedIps: [] };
  }
}

function adjacentToCrown(state, index, id) {
  const links = [...(index.outgoing.get(id) ?? []), ...(index.incoming.get(id) ?? [])];
  return links.some((edge) => {
    const other = state.nodes[edge.from === id ? edge.to : edge.from];
    return other !== undefined && isCrownJewel(other);
  });
}

function makeAction(state, node, input) {
  const risk = input.risk ?? 'low';
  const scope = input.scope ?? scopeForNode(state, input.index ?? buildIndex(state), node);
  const feasibility = scope.verdict === 'allow' ? 90 : scope.verdict === 'deny' ? 5 : 55;
  const crown = isCrownJewel(node) ? 95 : adjacentToCrown(state, input.index ?? buildIndex(state), node.id) ? 65 : 35;
  const novelty = input.novelty ?? 70;
  const base = 0.30 * (IMPACT[input.type] ?? 40)
    + 0.25 * crown
    + 0.20 * feasibility
    + 0.15 * (EVIDENCE_VALUE[input.type] ?? 50)
    + 0.10 * novelty
    - (RISK_PENALTY[risk] ?? 0);
  const priority = scope.verdict === 'deny' ? Math.min(5, Math.round(base)) : clamp(Math.round(base), 1, 100);
  const params = input.params ?? {};
  return {
    actionId: actionId(input.type, node.id, JSON.stringify(params)),
    actionType: input.type,
    targetId: node.id,
    targetKind: node.kind,
    targetLabel: node.label,
    priority,
    why: [...(input.why ?? []), ...(scope.verdict === 'deny' ? [`scope: ${scope.reason}`] : [])],
    toolClass: input.toolClass ?? 'tcp',
    expectedEvidence: input.expectedEvidence ?? { kind: 'artifact', acceptTest: 'a re-checkable artifact path + sha256' },
    risk,
    approvalRequired: input.approvalRequired === true,
    status: 'pending',
    params,
    scope,
  };
}

/** Build a small action list, one per target/kind. */
function collect(state) {
  const index = buildIndex(state);
  const nodes = Object.values(state.nodes).filter((node) => node.status !== 'merged');
  const actions = [];
  const scopeEmpty = (state.scope?.allow?.length ?? 0) === 0 || state.engagement === null;

  if (scopeEmpty) {
    actions.push({
      actionId: actionId('set_scope', 'engagement', ''),
      actionType: 'set_scope',
      targetId: 'engagement',
      targetKind: 'engagement',
      targetLabel: state.engagement?.name ?? 'engagement scope',
      priority: 100,
      why: ['scope.allow is empty', 'authorized engagement scope is required before any network action'],
      toolClass: 'setup',
      expectedEvidence: { kind: 'scope', acceptTest: 'engagement authorization reference + allow/deny entries recorded' },
      risk: 'none',
      approvalRequired: true,
      status: 'pending',
      params: {},
      scope: { verdict: 'unknown', reason: 'scope not set', allowedIps: [] },
    });
    return actions;
  }

  const split = operatorSplitAction(state);
  if (split !== null) return [split];

  for (const node of nodes) {
    const scope = scopeForNode(state, index, node);

    if (node.kind === 'host' || node.kind === 'ip') {
      if (!hasOutgoing(index, node.id, 'exposes')) {
        actions.push(makeAction(state, node, {
          index,
          scope,
          type: 'enumerate_services',
          toolClass: 'tcp',
          risk: 'low',
          why: [`${node.kind} has no observed service`],
          expectedEvidence: { kind: 'service-inventory', acceptTest: 'port/state/banner JSONL artifact with sha256' },
          params: { target: node.attrs?.fqdn ?? node.attrs?.addr ?? node.key, ports: 'common' },
        }));
      }
      if (node.kind === 'host' && !hasOutgoing(index, node.id, 'resolves_to') && node.attrs?.wildcardStatus !== 'suspect') {
        actions.push(makeAction(state, node, {
          index,
          scope,
          type: 'resolve_identity',
          toolClass: 'dns',
          risk: 'none',
          novelty: 55,
          why: ['host has no recorded A/AAAA/CNAME resolution'],
          expectedEvidence: { kind: 'dns-answer', acceptTest: 'resolver answers + wildcard classification' },
          params: { target: node.attrs?.fqdn ?? node.key },
        }));
      }
      if (isInternalNode(state, index, node) && !hasIncoming(index, node.id, 'reached_via')) {
        const hasPivot = [...(index.incoming.get(node.id) ?? [])].some((edge) => edge.kind === 'pivots_to');
        if (!hasPivot) {
          actions.push(makeAction(state, node, {
            index,
            scope,
            type: 'establish_pivot',
            toolClass: 'tunnel',
            risk: 'medium',
            approvalRequired: true,
            why: ['internal target is known but no verified pivot reaches it'],
            expectedEvidence: { kind: 'pivot-proof', acceptTest: 'far-side nonce round-trip through the tunnel' },
            params: { target: node.attrs?.fqdn ?? node.attrs?.addr ?? node.key },
          }));
        }
      }
      if ((node.attrs?.crownJewel === true || Number(node.attrs?.criticality) >= 3) && !hasOutgoing(index, node.id, 'exposes')) {
        actions.push(makeAction(state, node, {
          index,
          scope,
          type: 'enrich_asset',
          toolClass: 'http',
          risk: 'low',
          novelty: 50,
          why: ['high-value asset has no web/service fingerprint'],
          expectedEvidence: { kind: 'fingerprint', acceptTest: 'HTTP status/title/headers + TLS certificate JSON' },
          params: { target: node.attrs?.fqdn ?? node.attrs?.addr ?? node.key },
        }));
      }
    }

    if (node.kind === 'hypothesis' && ['open', 'active'].includes(node.status)) {
      actions.push(makeAction(state, node, {
        index,
        scope: { verdict: 'unknown', reason: 'hypothesis is tested against the recorded target', allowedIps: [] },
        type: 'test_hypothesis',
        toolClass: 'http',
        risk: 'low',
        novelty: 70,
        why: [String(node.attrs?.strategy ?? 'open hypothesis')],
        expectedEvidence: { kind: 'hypothesis-proof', acceptTest: 'two independent channels or a replayable proof; refutation must name target and observation' },
        params: {
          hypothesis: node.attrs?.hypothesisId ?? node.key,
          target: node.attrs?.targetKey ?? node.label,
          expectedProof: node.attrs?.expectedProof ?? 'poc_replay',
          bugClass: node.attrs?.bugClass ?? null,
        },
      }));
    }

    if (node.kind === 'coverage' && ['open', 'claimed'].includes(node.status)) {
      actions.push(makeAction(state, node, {
        index,
        type: 'test_coverage',
        toolClass: 'http',
        risk: 'low',
        novelty: 55,
        why: [
          COVERAGE_DUTIES[node.attrs?.bugClass]?.duty
            ?? `interface ${node.attrs?.path ?? node.key} has not been tested for ${node.attrs?.bugClass ?? 'the class'}`,
        ],
        expectedEvidence: { kind: 'coverage-proof', acceptTest: 'two channels or evidence for seen; the class duty must be met; JSON-only XSS, upload-absent file, and version-less known-vuln notes do not close the cell' },
        scope: { verdict: 'allow', reason: 'coverage cell is an already recorded in-scope interface', allowedIps: [] },
        params: {
          path: node.attrs?.path ?? node.key,
          bugClass: node.attrs?.bugClass ?? 'unknown',
          coverage: node.key,
        },
      }));
    }

    if (node.kind === 'cidr' && isInternalNode(state, index, node)) {
      const inside = nodes.filter((candidate) => candidate.kind === 'ip'
        && (index.incoming.get(candidate.id) ?? []).some((edge) => edge.kind === 'contains' && edge.from === node.id));
      if (inside.length < 2) {
        actions.push(makeAction(state, node, {
          index,
          scope,
          type: 'enumerate_internal_range',
          toolClass: 'tcp',
          risk: 'medium',
          approvalRequired: true,
          why: [`internal range has only ${inside.length} discovered host(s)`],
          expectedEvidence: { kind: 'internal-inventory', acceptTest: 'host/port inventory artifact + scope re-check' },
          params: { target: node.key },
        }));
      }
    }

    if (node.kind === 'finding' && node.status !== 'merged' && !isTerminalSecondary(node.attrs)) {
      const paused = attemptsExhausted(node);
      const action = makeAction(state, node, {
        index,
        scope,
        type: 'verify_finding',
        toolClass: 'http',
        risk: 'low',
        why: paused
          ? ['secondary verification has no verified or refuted verdict', 'automatic retries are paused until new evidence arrives', 'this finding stays queued for the next Lead turn']
          : ['secondary verification has not finished', 'a timeout or a missing verdict is still in progress', 'call atkbrain_supervise action=verify; the verification team drains the same queue'],
        expectedEvidence: { kind: 'reproduction', acceptTest: 'repeatable request/response or timing proof with hashes' },
        params: { target: node.label },
      });
      if ((node.tags ?? []).includes('exposure') || node.attrs?.source === 'plugin') action.exposure = true;
      actions.push(action);
    }

    if (node.kind === 'credential' && node.status === 'untested') {
      const target = state.nodes[node.attrs?.targetId];
      actions.push(makeAction(state, target ?? node, {
        index,
        scope: target === undefined ? { verdict: 'unknown', reason: 'credential target not resolved', allowedIps: [] } : scopeForNode(state, index, target),
        type: 'validate_credential',
        toolClass: 'auth',
        risk: 'low',
        why: ['credential has not been validated', 'respect lockout policy and rate limits'],
        expectedEvidence: { kind: 'auth-proof', acceptTest: 'single successful authentication + privilege mapping' },
        params: { credential: node.id, target: target?.label ?? node.label },
      }));
    }

    if (node.kind === 'access' && node.status === 'obtained') {
      actions.push(makeAction(state, node, {
        index,
        scope: { verdict: 'allow', reason: 'access proof is local to the foothold', allowedIps: [] },
        type: 'validate_access',
        toolClass: 'shell',
        risk: 'low',
        why: ['access is obtained but not validated'],
        expectedEvidence: { kind: 'shell-proof', acceptTest: 'id; hostname; uname -a output with engagement nonce' },
        params: { access: node.id, asset: node.attrs?.assetId },
      }));
    }

    if (node.kind === 'access' && ['obtained', 'validated', 'escalated'].includes(node.status)) {
      const privilege = String(node.attrs?.privilege ?? 'unknown');
      const elevated = ['root', 'domain_admin', 'cloud_admin', 'administrator', 'db_admin'].includes(privilege);
      if (!elevated) {
        actions.push(makeAction(state, node, {
          index,
          scope: { verdict: 'allow', reason: 'privilege escalation is executed on the foothold', allowedIps: [] },
          type: 'escalate_privilege',
          toolClass: 'admin',
          risk: 'medium',
          approvalRequired: true,
          why: [`privilege is "${privilege}", not elevated`],
          expectedEvidence: { kind: 'elevation-proof', acceptTest: 'elevated identity/role proof + nonce, no persistence unless RoE allows' },
          params: { access: node.id, asset: node.attrs?.assetId },
        }));
      }
      const linkedData = nodes.some((candidate) => candidate.kind === 'data'
        && (candidate.attrs?.subjectId === node.id || candidate.key.includes(node.id) || candidate.key.includes(node.attrs?.assetId ?? '\u0000')));
      if (!linkedData) {
        actions.push(makeAction(state, node, {
          index,
          scope: { verdict: 'allow', reason: 'collection is executed from the foothold', allowedIps: [] },
          type: 'collect_data_evidence',
          toolClass: 'data',
          risk: 'high',
          approvalRequired: true,
          why: ['validated access has no sensitive-data evidence'],
          expectedEvidence: { kind: 'data-evidence', acceptTest: 'metadata + COUNT + <=10 row hashes; raw data never stored' },
          params: { access: node.id, asset: node.attrs?.assetId },
        }));
      }
    }

    if (node.kind === 'wildcard_zone' && ['suspect', 'inconclusive'].includes(node.status)) {
      actions.push(makeAction(state, node, {
        index,
        scope: { verdict: 'unknown', reason: 'DNS classification is a read-only inspection', allowedIps: [] },
        type: 'confirm_wildcard_zone',
        toolClass: 'dns',
        risk: 'none',
        novelty: 55,
        why: [`wildcard zone status is "${node.status}"`],
        expectedEvidence: { kind: 'wildcard-signature', acceptTest: '>=3 randomized probes + guard probe + stable signature' },
        params: { target: node.key },
      }));
    }
  }

  void escalateImpactActions;
  actions.push(...capabilityGateActions(state, nodes));
  actions.push(...surfaceGapActions(state, nodes));
  actions.push(...expandApplicationActions(state, nodes));
  actions.push(...prerequisiteGapActions(state, nodes));
  actions.push(...observedSurfaceActions(state, nodes));
  actions.push(...coverageDutyActions(state, nodes));
  actions.push(...teamGateActions(state, nodes));

  const hasCrown = nodes.some((node) => isCrownJewel(node));
  const verifiedEvidence = nodes.some((node) => node.kind === 'finding' && ['verified', 'exploited', 'impacted'].includes(node.status))
    || nodes.some((node) => node.kind === 'access' && ['validated', 'escalated'].includes(node.status))
    || nodes.some((node) => node.kind === 'data' && node.status === 'verified');
  if (hasCrown || verifiedEvidence) {
    const pseudo = {
      id: 'report',
      kind: 'engagement',
      key: 'report',
      label: 'engagement report',
      status: 'unknown',
      attrs: {},
    };
    actions.push(makeAction(state, pseudo, {
      index,
      scope: { verdict: 'allow', reason: 'report writing is local', allowedIps: [] },
      type: 'report_findings',
      toolClass: 'report',
      risk: 'none',
      novelty: 60,
      why: [hasCrown ? 'milestone target or privileged access exists' : 'verified evidence exists'],
      expectedEvidence: { kind: 'report', acceptTest: 'Markdown/JSON report with evidence index and redaction' },
      params: {},
    }));
  }

  // Deduplicate by actionId, keeping the highest priority.
  const byId = new Map();
  for (const action of actions) {
    const previous = byId.get(action.actionId);
    if (previous === undefined || action.priority > previous.priority) byId.set(action.actionId, action);
  }
  promoteInterfaceSchedule([...byId.values()]);
  return [...byId.values()]
    .sort((a, b) => b.priority - a.priority || a.actionType.localeCompare(b.actionType) || a.targetId.localeCompare(b.targetId))
    .slice(0, 200);
}

/** One open cell per interface, the earliest class still open, so one path does not fill the frontier. */
function promoteInterfaceSchedule(actions) {
  const cells = actions.filter((action) => action.actionType === 'test_coverage' && action.params?.coverage);
  const byPath = new Map();
  for (const action of cells) {
    const path = String(action.params?.path ?? '');
    if (path.length === 0) continue;
    const list = byPath.get(path) ?? [];
    list.push(action);
    byPath.set(path, list);
  }
  for (const path of [...byPath.keys()].sort()) {
    const list = byPath.get(path);
    list.sort((left, right) => BUG_CLASSES.indexOf(left.params?.bugClass) - BUG_CLASSES.indexOf(right.params?.bugClass));
    list[0].priority = Math.max(list[0].priority, 86);
    list[0].why = [`this interface is next: test ${path} for ${list[0].params?.bugClass} before choosing another path`, ...list[0].why];
  }
}

function postureGap(state) {
  const mode = String(state.engagement?.mode ?? '').trim().toLowerCase();
  const lowMode = mode === 'view' || mode === 'collect' || mode === 'validate';
  const techniques = Array.isArray(state.scope?.roe?.techniques) ? state.scope.roe.techniques.map(String) : [];
  const missingT3 = !techniques.includes('T3');
  if (!lowMode && !missingT3) return null;
  return { mode: mode || 'unset', lowMode, missingT3 };
}

function localCapabilityScope() {
  return { verdict: 'allow', reason: 'capability call stays inside the recorded engagement scope', allowedIps: [] };
}

/**
 * A confirmed issue below command-execution is not the end of the path.
 * The next step raises that issue; a higher-harm result stays a separate finding.
 */
function escalateImpactActions(state, nodes) {
  const hasFoothold = nodes.some((node) => node.kind === 'access' && ['validated', 'escalated'].includes(node.status));
  if (hasFoothold) return [];
  const actionable = nodes.filter((node) => {
    if (node.kind !== 'finding' || node.status === 'merged' || node.status === 'refuted') return false;
    if (isHardeningFinding(node.attrs ?? {})) return false;
    return isVulnerabilityNode(node) || secondaryVerificationPassed(node.attrs ?? {});
  });
  if (actionable.length === 0) return [];
  const best = actionable.reduce((top, node) => (harmRank(node.attrs ?? {}) > harmRank(top.attrs ?? {}) ? node : top));
  if (harmRank(best.attrs ?? {}) >= 4) return [];
  const scope = localCapabilityScope();
  return [{
    actionId: actionId('escalate_impact', best.id, 'higher-harm'),
    actionType: 'escalate_impact',
    targetId: best.id,
    targetKind: 'finding',
    targetLabel: best.label,
    priority: 96,
    why: [
      'a vulnerability is recorded and no validated access exists',
      'raise that confirmed issue toward command execution or a validated foothold',
      'if the new result is the same interface and type but higher harm, record it as its own finding',
    ],
    toolClass: 'record',
    expectedEvidence: { kind: 'finding', acceptTest: 'a separate higher-harm finding, or a validated access node' },
    risk: 'medium',
    approvalRequired: false,
    status: 'pending',
    params: { tool: 'atkbrain_record', note: 'record a higher-harm result as a new finding; do not merge it into the lower one' },
    scope,
  }];
}

function capabilityGateActions(state, nodes) {
  const webapps = nodes.filter((node) => node.kind === 'webapp');
  const httpServices = nodes.filter((node) => node.kind === 'service' && /https?/iu.test(String(node.attrs?.protocol ?? '')));
  if (webapps.length === 0 && httpServices.length === 0) return [];
  const anchor = webapps[0] ?? httpServices[0];
  const scope = localCapabilityScope();
  const actions = [];
  const posture = postureGap(state);
  if (posture !== null) {
    actions.push({
      actionId: actionId('raise_posture', anchor.id, 'intrusive'),
      actionType: 'raise_posture',
      targetId: anchor.id,
      targetKind: anchor.kind,
      targetLabel: anchor.label,
      priority: 95,
      why: [
        'view, collect, and validate, or a technique list without T3, cannot refute xss, sqli, cmd, code, or file',
        'set mode intrusive and techniques T0-T3 before treating those classes as tested',
        'this does not replace the operator authorization',
      ],
      toolClass: 'scope',
      expectedEvidence: { kind: 'scope', acceptTest: 'atkbrain_scope action=set mode=intrusive techniques T0-T3' },
      risk: 'none',
      approvalRequired: false,
      status: 'pending',
      params: {
        tool: 'atkbrain_scope',
        action: 'set',
        engagement: { mode: 'intrusive' },
        roe: { techniques: ['T0', 'T1', 'T2', 'T3'] },
      },
      scope,
    });
  }
  return actions;
}

/**
 * The graph shows one application per host. Paths, parameters and contexts
 * stay on that node. These actions keep the ledger ahead of the coverage board:
 * unseeded paths, cleartext versus TLS, and a trailing-dot host when a proxy
 * or CDN is already on the graph.
 */
function expandApplicationActions(state, nodes) {
  const thin = nodes.filter((node) => node.kind === 'webapp' && applicationExpanded(node.attrs ?? {}) !== true);
  if (thin.length === 0) return [];
  const page = thin[0];
  const attrs = page.attrs ?? {};
  const entry = String(attrs.entryPath ?? attrs.path ?? attrs.url ?? page.label ?? '');
  const login = /login|signin|sign-in|logon/iu.test(entry);
  const session = nodes.some((node) => node.kind === 'access' && ['validated', 'escalated'].includes(node.status));
  const scope = localCapabilityScope();
  const why = [
    'the operator URL is an entry point, not the whole application',
    'inventory menus, modules, JavaScript routes and links before closing evidence on this page',
  ];
  if (login && session !== true) why.push('this entry is a login page and there is no validated session; inventory the modules behind it');
  return [{
    actionId: actionId('expand_application', page.id, entry || 'entry'),
    actionType: 'expand_application',
    targetId: page.id,
    targetKind: page.kind,
    targetLabel: page.label,
    priority: 98,
    why,
    toolClass: 'arsenal',
    expectedEvidence: { kind: 'surface', acceptTest: 'a second module path on the webapp ledger' },
    risk: 'none',
    approvalRequired: false,
    status: 'pending',
    params: { tool: 'atkbrain_arsenal', action: 'endpoint_vocab', target: attrs.host ?? attrs.url ?? page.key },
    scope,
  }];
}

function surfaceGapActions(state, nodes) {
  const webapps = nodes.filter((node) => node.kind === 'webapp');
  if (webapps.length === 0) return [];
  const anchor = webapps[0];
  const scope = localCapabilityScope();
  const actions = [];
  const bare = webapps.filter((node) => node.attrs?.surfaceInventoried !== true || ledgerIsThin(node.attrs ?? {}));
  if (bare.length > 0) {
    const page = bare[0];
    actions.push({
      actionId: actionId('inventory_surface', page.id, 'ledger'),
      actionType: 'inventory_surface',
      targetId: page.id,
      targetKind: page.kind,
      targetLabel: page.label,
      priority: ledgerIsThin(page.attrs ?? {}) ? 93 : 90,
      why: [
        ledgerIsThin(page.attrs ?? {})
          ? 'many paths are stored and the parameter or output-context ledger is still thin; a varying path segment counts as a parameter'
          : 'this application has no page ledger yet',
        'call endpoint_vocab with the saved HTML and JavaScript before closing coverage',
      ],
      toolClass: 'arsenal',
      expectedEvidence: { kind: 'surface', acceptTest: 'atkbrain_arsenal action=endpoint_vocab target=<host> text=<saved HTML/JS>' },
      risk: 'none',
      approvalRequired: false,
      status: 'pending',
      params: { tool: 'atkbrain_arsenal', action: 'endpoint_vocab', target: page.attrs?.host ?? page.attrs?.url ?? page.key },
      scope,
    });
  }
  const seeded = new Set(nodes.filter((node) => node.kind === 'coverage').map((node) => normalizeInterfacePath(node.attrs?.path)));
  const pending = [];
  for (const node of webapps) {
    const paths = Array.isArray(node.attrs?.endpoints) ? node.attrs.endpoints : [];
    for (const path of paths) {
      const clean = normalizeInterfacePath(path);
      if (clean.length === 0 || seeded.has(clean) || pending.includes(clean)) continue;
      pending.push(clean);
    }
  }
  if (pending.length > 0) {
    actions.push({
      actionId: actionId('seed_coverage', anchor.id, pending[0]),
      actionType: 'seed_coverage',
      targetId: anchor.id,
      targetKind: anchor.kind,
      targetLabel: anchor.label,
      priority: 90,
      why: [
        'discovered interfaces are in the surface ledger and not on the coverage board',
        'the graph keeps one application node; the ledger holds every path and parameter',
      ],
      toolClass: 'coverage',
      expectedEvidence: { kind: 'coverage', acceptTest: 'atkbrain_coverage action=seed for the ledger paths' },
      risk: 'none',
      approvalRequired: false,
      status: 'pending',
      params: { tool: 'atkbrain_coverage', action: 'seed', paths: pending.slice(0, 24) },
      scope,
    });
  }
  const services = nodes.filter((node) => node.kind === 'service');
  const byHost = new Map();
  for (const service of services) {
    const host = String(service.attrs?.endpoint ?? service.attrs?.host ?? '').toLowerCase();
    if (host.length === 0) continue;
    const bag = byHost.get(host) ?? { http: null, https: false };
    const proto = String(service.attrs?.protocol ?? '');
    const port = Number(service.attrs?.port);
    if (proto === 'http' || port === 80) bag.http = service;
    if (proto === 'https' || port === 443) bag.https = true;
    byHost.set(host, bag);
  }
  for (const [host, bag] of byHost) {
    if (bag.http === null || !bag.https) continue;
    const noted = String(bag.http.attrs?.cleartext ?? '');
    if (noted === 'redirects' || noted === 'stays') continue;
    actions.push({
      actionId: actionId('check_transport', bag.http.id, host),
      actionType: 'check_transport',
      targetId: bag.http.id,
      targetKind: 'service',
      targetLabel: bag.http.label,
      priority: 94,
      why: [
        'this host answers on both cleartext and TLS',
        'record whether cleartext redirects to TLS or still serves the application before seeding more coverage',
      ],
      toolClass: 'record',
      expectedEvidence: { kind: 'service', acceptTest: 'service attrs.cleartext is redirects or stays' },
      risk: 'none',
      approvalRequired: false,
      status: 'pending',
      params: { tool: 'atkbrain_record', kind: 'service', key: bag.http.key, attrs: { cleartext: 'redirects or stays' } },
      scope,
    });
    break;
  }
  const fronted = nodes.some((node) => node.kind === 'tech' && /cdn|proxy|\bwaf\b|cloudflare|akamai|fastly|cloudfront/iu.test(`${node.label} ${node.attrs?.product ?? ''} ${node.attrs?.vendor ?? ''}`));
  if (fronted) {
    const host = nodes.find((node) => node.kind === 'host' && node.attrs?.vhostChecked !== true);
    if (host !== undefined) {
      actions.push({
        actionId: actionId('check_vhost', host.id, 'trailing-dot'),
        actionType: 'check_vhost',
        targetId: host.id,
        targetKind: 'host',
        targetLabel: host.label,
        priority: 94,
        why: [
          'a proxy or CDN is already on the graph and the origin virtual host has not been compared',
          'record the trailing-dot hostname and the default site before seeding more coverage',
          'a different site is a new application and must be added to the ledger before it is called tested',
        ],
        toolClass: 'record',
        expectedEvidence: { kind: 'host', acceptTest: 'host attrs.vhostChecked is true after the trailing-dot response is compared' },
        risk: 'none',
        approvalRequired: false,
        status: 'pending',
        params: { tool: 'atkbrain_record', kind: 'host', key: host.key, attrs: { vhostChecked: true } },
        scope,
      });
    }
  }
  const unrecorded = nodes.find((node) => node.kind === 'coverage'
    && node.status === 'seen'
    && !pathsWithFinding(nodes, node.attrs?.bugClass).has(normalizeInterfacePath(node.attrs?.path)));
  if (unrecorded !== undefined) {
    actions.push({
      actionId: actionId('record_observation', unrecorded.id, unrecorded.attrs?.bugClass ?? 'seen'),
      actionType: 'record_observation',
      targetId: unrecorded.id,
      targetKind: 'coverage',
      targetLabel: unrecorded.label,
      priority: 84,
      why: [
        'this coverage cell was exercised and no finding was recorded for it',
        'write the observation as its own finding, or refute the cell with a note that names the stored parameters',
      ],
      toolClass: 'record',
      expectedEvidence: { kind: 'finding', acceptTest: 'a finding for this path and class, or a refuted coverage note' },
      risk: 'none',
      approvalRequired: false,
      status: 'pending',
      params: { tool: 'atkbrain_record', path: unrecorded.attrs?.path, bugClass: unrecorded.attrs?.bugClass },
      scope,
    });
  }
  return actions;
}

/**
 * One next step per open bug class, carrying that class's close rule.
 * Unseeded web targets get a single seed step for the nine classes.
 */
function coverageDutyActions(state, nodes) {
  const webapps = nodes.filter((node) => node.kind === 'webapp');
  const httpServices = nodes.filter((node) => node.kind === 'service' && /https?/iu.test(String(node.attrs?.protocol ?? '')));
  if (webapps.length === 0 && httpServices.length === 0) return [];
  const anchor = webapps[0] ?? httpServices[0];
  const scope = localCapabilityScope();
  const cells = nodes.filter((node) => node.kind === 'coverage');
  if (cells.length === 0) {
    return [{
      actionId: actionId('seed_coverage', anchor.id, 'nine'),
      actionType: 'seed_coverage',
      targetId: anchor.id,
      targetKind: anchor.kind,
      targetLabel: anchor.label,
      priority: 90,
      why: ['web target has interfaces but no nine-class coverage row', 'seed xss, sqli, cmd, code, file, authz, logic, leak, and nday before calling the surface tested'],
      toolClass: 'coverage',
      expectedEvidence: { kind: 'coverage', acceptTest: 'atkbrain_coverage action=seed for each discovered interface' },
      risk: 'none',
      approvalRequired: false,
      status: 'pending',
      params: { tool: 'atkbrain_coverage', action: 'seed' },
      scope,
    }];
  }
  const actions = [];
  for (const bugClass of BUG_CLASSES) {
    const surface = classSurface(nodes, bugClass);
    const already = pathsWithFinding(nodes, bugClass);
    const openPaths = surface.open.filter((path) => !already.has(path));
    if (openPaths.length === 0) continue;
    const duty = COVERAGE_DUTIES[bugClass];
    const openCell = cells.find((node) => node.attrs?.bugClass === bugClass && node.attrs?.path === openPaths[0]);
    const why = [duty.duty];
    if (already.size > 0) why.push('interfaces that already have this finding type are not scheduled again');
    if (openPaths.length > 1) why.push(`${openPaths.length} interfaces of this class are still open; closing one does not close the others, including a shared response page`);
    if (surface.closed > 0) why.push('another interface of this class was already closed; continue across the remaining surface');
    if (surface.implied.length > 0) why.push(`observed parameter names that keep this class open: ${surface.implied.slice(0, 8).join(', ')}`);
    actions.push({
      actionId: actionId('cover_class', anchor.id, bugClass),
      actionType: 'test_coverage',
      targetId: openCell?.id ?? anchor.id,
      targetKind: 'coverage',
      targetLabel: `${openPaths[0]} × ${bugClass}`,
      priority: 84,
      why,
      toolClass: 'coverage',
      expectedEvidence: { kind: 'coverage-proof', acceptTest: `${duty.role} on each open interface, not only the first` },
      risk: 'low',
      approvalRequired: false,
      status: 'pending',
      params: {
        tool: 'atkbrain_coverage',
        action: 'note',
        path: openPaths[0],
        paths: openPaths.slice(0, 12),
        bugClass,
        parameters: surface.implied.slice(0, 12),
      },
      scope,
    });
  }
  const products = observedProducts(nodes);
  const versioned = nodes.find((node) => node.kind === 'tech' && String(node.attrs?.version ?? '').length > 0);
  const stackQuery = versioned
    ? `${versioned.attrs?.product ?? versioned.label ?? ''} ${versioned.attrs?.version}`.trim()
    : products[0];
  const nday = classSurface(nodes, 'nday');
  if (stackQuery && (cells.length === 0 || nday.open.length > 0)) {
    actions.push({
      actionId: actionId('follow_stack', anchor.id, stackQuery),
      actionType: 'follow_stack',
      targetId: anchor.id,
      targetKind: anchor.kind,
      targetLabel: stackQuery,
      priority: 87,
      why: [
        'a product or version label is already on the graph',
        'keep the known-vuln cell open until that version is recorded on a tech node',
        'stop the known-vuln cell when no version was recorded',
      ],
      toolClass: 'query',
      expectedEvidence: { kind: 'tech', acceptTest: `product and version "${stackQuery}" recorded before the known-vuln cell is closed` },
      risk: 'none',
      approvalRequired: false,
      status: 'pending',
      params: { tool: 'atkbrain_query', action: 'search', query: stackQuery },
      scope,
    });
  }
  return actions;
}

/** Version and credential gaps that are already visible on the graph. */
function prerequisiteGapActions(state, nodes) {
  const scope = localCapabilityScope();
  const actions = [];
  const missing = unrecordedProductVersions(nodes);
  if (missing.length > 0) {
    const anchor = nodes.find((node) => node.kind === 'finding') ?? nodes[0];
    actions.push({
      actionId: actionId('record_stack_tech', anchor?.id ?? 'stack', missing[0]),
      actionType: 'record_stack_tech',
      targetId: anchor?.id ?? 'stack',
      targetKind: anchor?.kind ?? 'finding',
      targetLabel: anchor?.label ?? missing[0],
      priority: 92,
      why: [
        `an error page already names ${missing[0]} and that version is not a tech node`,
        'record the product and version; leave the known-vuln cell open until then',
      ],
      toolClass: 'record',
      expectedEvidence: { kind: 'tech', acceptTest: 'atkbrain_record kind=tech with this product and version' },
      risk: 'none',
      approvalRequired: false,
      status: 'pending',
      params: { tool: 'atkbrain_record', kind: 'tech', productVersion: missing[0] },
      scope,
    });
  }
  const material = nodes.some((node) => node.kind === 'finding' && /读到|读取到|配置文件|对象地址|presign|signed url|object url|对象存储/iu.test(`${node.attrs?.title ?? ''} ${node.attrs?.description ?? ''} ${node.label ?? ''}`));
  const credential = nodes.some((node) => node.kind === 'credential');
  if (material && !credential) {
    const anchor = nodes.find((node) => node.kind === 'finding') ?? nodes[0];
    actions.push({
      actionId: actionId('record_credential_gap', anchor?.id ?? 'credential', 'masked'),
      actionType: 'record_credential_gap',
      targetId: anchor?.id ?? 'credential',
      targetKind: anchor?.kind ?? 'finding',
      targetLabel: anchor?.label ?? 'credential',
      priority: 90,
      why: [
        'a finding already says a config or object was read and no credential is recorded',
        'record one masked credential and validate it once; do not stop on the finding page',
      ],
      toolClass: 'record',
      expectedEvidence: { kind: 'credential', acceptTest: 'atkbrain_record kind=credential with secretMask, then one validation' },
      risk: 'none',
      approvalRequired: false,
      status: 'pending',
      params: { tool: 'atkbrain_record', kind: 'credential' },
      scope,
    });
  }
  return actions;
}

/**
 * Schedule a memory handoff once the graph holds work the executor could forget.
 * An empty engagement does not get an opening brief.
 */
function teamGateActions(state, nodes) {
  const engagementReady = state.engagement !== null && (state.scope?.allow?.length ?? 0) > 0;
  if (!engagementReady) return [];
  const scope = localCapabilityScope();
  const actions = [];
  const supervision = selfTeamNode(state, 'supervision');
  if (supervision !== undefined && handoffOverdue(nodes, supervision.attrs?.lastBriefAt)) {
    const briefAt = String(supervision.attrs?.lastBriefAt ?? '');
    actions.push({
        actionId: actionId('self_brief', supervision.id, briefAt || 'memory'),
        actionType: 'self_brief',
        targetId: supervision.id,
        targetKind: 'self_team',
        targetLabel: supervision.label,
        priority: 97,
        why: [
          'the executor can forget a long chain',
          'hand back 目标、服务、危险点、严重高中低、凭证、立足点、信息; an empty section says 无',
          'do not brief an empty engagement',
        ],
        toolClass: 'selftteam',
        expectedEvidence: { kind: 'supervision', acceptTest: 'atkbrain_selftteam action=brief' },
        risk: 'none',
        approvalRequired: false,
        status: 'pending',
        params: { tool: 'atkbrain_selftteam', action: 'brief' },
        scope,
      });
  }
  return actions;
}

/**
 * Two or more operator-named targets are three separate single-target jobs
 * running at once, not one lead thread that walks them in turn.
 * Returns the only next action until every target's worker has been merged.
 */
function operatorSplitAction(state) {
  void state;
  return null;
  const tracks = concreteAllowTargets(state);
  if (tracks.length < 2) return null;
  const tasks = Object.values(state.nodes ?? {}).filter((node) => node.kind === 'task'
    && node.attrs?.actionType === 'subagent_batch'
    && !['merged', 'failed', 'cancelled'].includes(node.status));
  const statusOf = new Map();
  for (const task of tasks) {
    const keys = [
      ...(Array.isArray(task.attrs?.operatorTargets) ? task.attrs.operatorTargets : []),
      ...(Array.isArray(task.attrs?.assetKeys) ? task.attrs.assetKeys : []),
    ].map((key) => String(key));
    for (const track of tracks) {
      if (keys.includes(track.canonical) || keys.includes(track.value)) statusOf.set(track.canonical, task.status);
    }
  }
  const missing = tracks.filter((track) => !statusOf.has(track.canonical));
  const planned = tracks.filter((track) => statusOf.get(track.canonical) === 'planned');
  const running = tracks.filter((track) => ['dispatched', 'artifact_ready', 'completed'].includes(statusOf.get(track.canonical)));
  if (missing.length === 0 && planned.length === 0 && running.length === 0) return null;
  const step = planned.length > 0 ? 'dispatch' : (missing.length > 0 ? 'plan' : 'status');
  const why = [
    `${tracks.length} operator targets are on the allow list`,
    'each target gets the same procedure as a single target, and those procedures run at the same time',
    'do not probe or record these targets in the lead thread',
  ];
  if (step === 'plan') why.push('plan one batch per operator target, then dispatch those batches together');
  else if (step === 'dispatch') why.push('the batches are planned; dispatch them together before this round ends');
  else why.push('the workers are running; check status and merge their graphs, and do not retest their targets here');
  return {
    actionId: actionId('parallel_targets', 'engagement', `${step}:${tracks.map((track) => track.canonical).sort().join(',')}`),
    actionType: 'parallel_targets',
    targetId: 'engagement',
    targetKind: 'engagement',
    targetLabel: tracks.map((track) => track.canonical).join(', '),
    priority: 99,
    why,
    toolClass: 'team',
    expectedEvidence: {
      kind: 'team-batch',
      acceptTest: step === 'status'
        ? 'atkbrain_team action=status, then action=merge when a child graph is ready'
        : `atkbrain_team action=${step} mode=subagents`,
    },
    risk: 'none',
    approvalRequired: false,
    status: 'pending',
    params: { tool: 'atkbrain_team', action: step, mode: 'subagents', strategy: 'targets' },
    scope: { verdict: 'allow', reason: 'splitting operator targets is local', allowedIps: [] },
  };
}

/** Compute the top `limit` next actions for the wire view or the query tool. */
const ELEVATED_PRIVILEGE = new Set(['root', 'domain_admin', 'cloud_admin', 'administrator', 'db_admin']);
const PASSWORD_FIELD_RE = /^(?:password|passwd|pwd)$/iu;

function recordedPaths(nodes) {
  const paths = [];
  for (const node of nodes) {
    if (node.kind === 'webapp') {
      if (Array.isArray(node.attrs?.endpoints)) paths.push(...node.attrs.endpoints);
      if (node.attrs?.path) paths.push(node.attrs.path);
      if (node.attrs?.entryPath) paths.push(node.attrs.entryPath);
    }
    if (node.kind === 'coverage' && node.attrs?.path) paths.push(node.attrs.path);
  }
  return paths;
}

function pathWorked(nodes, path) {
  const key = ledgerPath(path);
  if (key.length === 0) return false;
  return nodes.some((node) => {
    const candidate = ledgerPath(node.attrs?.path ?? '');
    if (candidate !== key) return false;
    if (node.kind === 'finding') return true;
    return node.kind === 'coverage' && node.status !== 'open' && node.status !== 'claimed';
  });
}

function applicationOrigin(nodes) {
  for (const node of nodes) {
    if (node.kind !== 'webapp') continue;
    try {
      const url = new URL(String(node.attrs?.url ?? node.key ?? ''));
      if (url.protocol === 'http:' || url.protocol === 'https:') return url.origin;
    } catch { /* the next recorded application may have a usable URL */ }
  }
  return '';
}

function passwordPath(node) {
  const map = node?.attrs?.parameterMap;
  if (map && typeof map === 'object') {
    for (const [path, names] of Object.entries(map)) {
      if (Array.isArray(names) && names.some((name) => PASSWORD_FIELD_RE.test(String(name)))) return path;
    }
  }
  const names = Array.isArray(node?.attrs?.parameters) ? node.attrs.parameters : [];
  if (names.some((name) => PASSWORD_FIELD_RE.test(String(name)))) {
    return node.attrs?.entryPath || node.attrs?.path || '/';
  }
  return '';
}

function cookieRecorded(node) {
  const headers = node?.attrs?.headers;
  if (!headers || typeof headers !== 'object') return false;
  const value = headers['set-cookie'] ?? headers['Set-Cookie'];
  if (Array.isArray(value)) return value.length > 0;
  return typeof value === 'string' && value.length > 0;
}

function surfaceAction(scope, { id, type, label, priority, why, params, evidence }) {
  return {
    actionId: id,
    actionType: type,
    targetId: id,
    targetKind: 'webapp',
    targetLabel: label,
    priority,
    why,
    toolClass: 'http',
    expectedEvidence: evidence,
    risk: 'low',
    approvalRequired: false,
    status: 'pending',
    params,
    scope,
  };
}

/** Sibling files, directory revisits, session rotation, and foothold follow-ups. */
function observedSurfaceActions(state, nodes) {
  const scope = localCapabilityScope();
  const actions = [];
  const origin = applicationOrigin(nodes);
  const known = new Set(recordedPaths(nodes).map((path) => ledgerPath(path)).filter((path) => path.length > 0));
  if (origin.length > 0) {
    const siblings = artifactSiblingPaths(recordedPaths(nodes)).filter((path) => !known.has(path) && !pathWorked(nodes, path)).slice(0, 6);
    for (const path of siblings) {
      actions.push(surfaceAction(scope, {
        id: actionId('probe_sibling', origin, path),
        type: 'probe_sibling',
        label: path,
        priority: 88,
        why: [
          'this file is already on the ledger',
          'request the same path plus one backup suffix, with no session cookie',
          'record a finding only when the body is source text and not the same document as the site root',
        ],
        params: { tool: 'atkbrain_probe', action: 'http', url: `${origin}${path}`, session: 'none' },
        evidence: { kind: 'source-sibling', acceptTest: 'source text at the sibling path, or the same document as the site root' },
      }));
    }
    const directories = directoryPaths(recordedPaths(nodes)).filter((path) => !pathWorked(nodes, path)).slice(0, 4);
    for (const path of directories) {
      actions.push(surfaceAction(scope, {
        id: actionId('revisit_directory', origin, path),
        type: 'revisit_directory',
        label: path,
        priority: 88,
        why: [
          'this directory is already on the ledger',
          'request it again with no session cookie',
          'a listing alone stays a hardening note; a listed file the server executes is a separate code-execution finding',
        ],
        params: { tool: 'atkbrain_probe', action: 'http', url: `${origin}${path}`, session: 'none' },
        evidence: { kind: 'directory-revisit', acceptTest: 'directory listing, or code execution when a listed file is served as code' },
      }));
    }
  }
  const login = nodes.find((node) => node.kind === 'webapp' && passwordPath(node).length > 0 && cookieRecorded(node));
  const sessionRecorded = nodes.some((node) => node.kind === 'finding' && ['session-not-rotated', 'session-rotated'].includes(String(node.attrs?.template ?? '')));
  if (login && !sessionRecorded) {
    const path = passwordPath(login);
    actions.push(surfaceAction(scope, {
      id: actionId('check_session_rotation', login.id, path),
      type: 'check_session_rotation',
      label: path,
      priority: 86,
      why: [
        'a password field and a Set-Cookie are already recorded',
        'compare the cookie before and after that login request',
        'record a finding only when the identifier does not change, or a client-supplied identifier is accepted unchanged',
      ],
      params: { tool: 'atkbrain_record', kind: 'finding', template: 'session-not-rotated', path },
      evidence: { kind: 'session-rotation', acceptTest: 'the identifier changed, or it stayed the same and that fact is recorded' },
    }));
  }
  const access = nodes.find((node) => node.kind === 'access'
    && ['validated', 'escalated'].includes(node.status)
    && !ELEVATED_PRIVILEGE.has(String(node.attrs?.privilege ?? '').toLowerCase()));
  if (access) {
    const owned = nodes.some((node) => node.kind === 'finding' && node.attrs?.template === 'webroot-process-owner');
    if (!owned) {
      actions.push(surfaceAction(scope, {
        id: actionId('compare_process_owner', access.id, 'owner'),
        type: 'compare_process_owner',
        label: access.label,
        priority: 89,
        why: [
          'validated access is not an elevated privilege',
          'compare that process identity with the owner of the files the recorded application serves',
          'record a separate file-write finding only when they are the same identity',
        ],
        params: { tool: 'atkbrain_record', kind: 'finding', template: 'webroot-process-owner', access: access.id },
        evidence: { kind: 'process-owner', acceptTest: 'the process identity and the file owner, recorded only when they match' },
      }));
    }
    const credential = nodes.find((node) => node.kind === 'credential');
    const hashed = nodes.some((node) => node.kind === 'data' && Array.isArray(node.attrs?.hashes) && node.attrs.hashes.length > 0);
    if (credential && !hashed) {
      actions.push(surfaceAction(scope, {
        id: actionId('record_data_sample', credential.id, 'sample'),
        type: 'record_data_sample',
        label: credential.label,
        priority: 88,
        why: [
          'a credential is recorded and no data proof with hashes exists yet',
          'record one bounded proof: a row count and hashes, never the raw rows',
        ],
        params: { tool: 'atkbrain_record', kind: 'data', credential: credential.id },
        evidence: { kind: 'data-sample', acceptTest: 'row count plus hashes; raw rows are rejected' },
      }));
    }
  }
  return actions;
}

export function computeFrontier(state, { limit = 30 } = {}) {
  const all = collect(state);
  const exposure = [];
  const rest = [];
  for (const action of all) {
    if (action.actionType === 'verify_finding' && action.exposure === true) exposure.push(action);
    else rest.push(action);
  }
  const merged = [...rest, ...exposure.slice(0, 2)];
  return merged.slice(0, Math.max(1, Math.min(200, limit)));
}

/** Counts used by the report and the UI header. */
export function frontierSummary(state) {
  const actions = collect(state);
  return {
    total: actions.length,
    pending: actions.filter((action) => action.status === 'pending').length,
    denied: actions.filter((action) => action.scope?.verdict === 'deny').length,
    top: actions.slice(0, 10),
  };
}
