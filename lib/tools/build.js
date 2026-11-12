/**
 * Op builders shared by the Host tools.
 *
 * Keys are canonical (`host:fqdn`, `ip:addr`, `service:transport:endpoint:port`,
 * ...) so an upsert from any tool merges with the same graph identity.
 */
import { canonicalIp, isPrivateIp, parseCidr } from '../cidr.js';
import { canonicalHost } from '../scope.js';
import { nowIso, shortHash, stableStringify } from '../util.js';
import { edgeOp, nodeOp } from '../ops.js';
import { localizedFindingTitle } from '../finding-i18n.js';
import { findingFamily, findingInterfacePath, findingMergeKey, reflectedXssAdjustment } from '../finding-classification.js';

/** Engagement prefix used by operational keys. */
export function engagementKey(state) {
  return state?.engagement?.name ? String(state.engagement.name) : 'eng';
}

/** Hostname realm heuristic. */
export function inferRealm(host) {
  const name = canonicalHost(host);
  if (name.length === 0) return 'external';
  if (isPrivateIp(name)) return 'internal';
  if (!name.includes('.')) return 'internal';
  if (/\.(internal|local|lan|corp|intranet|home\.arpa)$/u.test(name)) return 'internal';
  return 'external';
}

/** Naive registrable-domain derivation (last two labels). */
export function registrableDomain(host) {
  const name = canonicalHost(host);
  const labels = name.split('.').filter(Boolean);
  if (labels.length < 2) return undefined;
  return labels.slice(-2).join('.');
}

/** Base attrs for a host node. */
export function hostNodeOp(host, extras = {}) {
  const fqdn = canonicalHost(host);
  return nodeOp('host', fqdn, extras.label ?? fqdn, {
    fqdn,
    realm: extras.realm ?? inferRealm(fqdn),
    wildcardStatus: extras.wildcardStatus ?? 'unknown',
    ips: Array.isArray(extras.ips) ? extras.ips : [],
    declared: extras.declared === true,
    ...(extras.criticality !== undefined ? { criticality: extras.criticality } : {}),
    ...(extras.crownJewel === true ? { crownJewel: true } : {}),
    ...(extras.attrs ?? {}),
  }, {
    ...(Array.isArray(extras.tags) ? { tags: extras.tags } : {}),
    ...(Array.isArray(extras.sources) ? { sources: extras.sources } : {}),
    ...(extras.status !== undefined ? { status: extras.status } : {}),
    ...(extras.confidence !== undefined ? { confidence: extras.confidence } : {}),
  });
}

/** Base attrs for an IP node. */
export function ipNodeOp(ip, extras = {}) {
  const address = canonicalIp(ip) ?? String(ip);
  return nodeOp('ip', address, extras.label ?? address, {
    addr: address,
    version: address.includes(':') ? 6 : 4,
    realm: extras.realm ?? (isPrivateIp(address) ? 'internal' : 'external'),
    ...(extras.ptr ? { ptr: extras.ptr } : {}),
    ...(extras.asn ? { asn: extras.asn } : {}),
    ...(extras.org ? { org: extras.org } : {}),
    ...(extras.sharedInfra === true ? { sharedInfra: true } : {}),
    ...(extras.attrs ?? {}),
  }, {
    ...(Array.isArray(extras.tags) ? { tags: extras.tags } : {}),
    ...(Array.isArray(extras.sources) ? { sources: extras.sources } : {}),
    ...(extras.confidence !== undefined ? { confidence: extras.confidence } : {}),
  });
}

/** Base attrs for a domain / zone node. */
export function domainNodeOp(domain, extras = {}) {
  const name = canonicalHost(domain);
  return nodeOp('domain', name, extras.label ?? name, {
    name,
    ...(extras.registrable ? { registrable: extras.registrable } : {}),
    ...(extras.wildcardZoneId ? { wildcardZoneId: extras.wildcardZoneId } : {}),
    ...(extras.realm ? { realm: extras.realm } : {}),
    ...(extras.attrs ?? {}),
  }, {
    ...(Array.isArray(extras.tags) ? { tags: extras.tags } : {}),
    ...(Array.isArray(extras.sources) ? { sources: extras.sources } : {}),
  });
}

/** Base attrs for a CIDR node. */
export function cidrNodeOp(cidr, extras = {}) {
  const canonical = parseCidr(cidr)?.canonical ?? cidr;
  return nodeOp('cidr', canonical, extras.label ?? canonical, {
    network: canonical.split('/')[0],
    prefix: Number(canonical.split('/')[1]),
    version: canonical.includes(':') ? 6 : 4,
    realm: extras.realm ?? (isPrivateIp(canonical.split('/')[0]) ? 'internal' : 'external'),
    ...(extras.segmentId ? { segmentId: extras.segmentId } : {}),
    ...(extras.attrs ?? {}),
  }, {
    ...(Array.isArray(extras.tags) ? { tags: extras.tags } : {}),
    ...(Array.isArray(extras.sources) ? { sources: extras.sources } : {}),
  });
}

/** Base attrs for a segment node. */
export function segmentNodeOp(label, extras = {}) {
  return nodeOp('segment', label, extras.displayLabel ?? label, {
    label,
    realm: extras.realm ?? 'internal',
    cidrs: Array.isArray(extras.cidrs) ? extras.cidrs : [],
    ...(extras.enclave ? { enclave: extras.enclave } : {}),
    ...(extras.attrs ?? {}),
  }, {
    ...(Array.isArray(extras.sources) ? { sources: extras.sources } : {}),
  });
}

/** Wildcard-zone node built from `probeWildcardZone`'s result. */
export function wildcardZoneNodeOp(zone, result, extras = {}) {
  const name = canonicalHost(zone);
  return nodeOp('wildcard_zone', `*.${name}`, extras.label ?? `*.${name}`, {
    zone: name,
    signature: result?.signature ?? {},
    probes: Array.isArray(result?.probes) ? result.probes.slice(0, 12) : [],
    cdn: result?.cdn === true,
    apex: result?.apex === true,
    confidence: result?.confidence ?? 0,
    reason: result?.reason ?? null,
    ...(extras.attrs ?? {}),
  }, {
    status: result?.status ?? 'inconclusive',
    confidence: result?.confidence ?? 0,
    ...(Array.isArray(extras.sources) ? { sources: extras.sources } : {}),
  });
}

/** Service node keyed by transport+endpoint+port. */
export function serviceNodeOp(endpoint, port, extras = {}) {
  const transport = extras.transport ?? 'tcp';
  const protocol = extras.protocol ?? undefined;
  const key = `${transport}:${endpoint}:${port}`;
  return nodeOp('service', key, extras.label ?? `${endpoint}:${port}`, {
    endpoint,
    port,
    transport,
    state: extras.state ?? 'open',
    ...(protocol ? { protocol } : {}),
    ...(extras.banner ? { banner: String(extras.banner).slice(0, 2000) } : {}),
    ...(extras.tls ? { tls: extras.tls } : {}),
    ...(extras.authRequired !== undefined ? { authRequired: extras.authRequired } : {}),
    ...(extras.attrs ?? {}),
  }, {
    confidence: extras.confidence ?? 0.6,
    ...(Array.isArray(extras.sources) ? { sources: extras.sources } : {}),
  });
}

/** Web application node keyed by canonical URL. */
export function webappNodeOp(url, extras = {}) {
  return nodeOp('webapp', url, extras.label ?? url, {
    url,
    scheme: extras.scheme ?? (url.startsWith('https://') ? 'https' : 'http'),
    host: extras.host ?? undefined,
    port: extras.port ?? undefined,
    path: extras.path ?? '/',
    ...(extras.entryPath || extras.path ? { entryPath: String(extras.entryPath || extras.path).slice(0, 300) } : {}),
    ...(extras.status !== undefined ? { status: extras.status } : {}),
    ...(extras.title ? { title: String(extras.title).slice(0, 500) } : {}),
    ...(extras.server ? { server: String(extras.server).slice(0, 300) } : {}),
    ...(Array.isArray(extras.techIds) ? { techIds: extras.techIds } : {}),
    ...(extras.authRequired !== undefined ? { authRequired: extras.authRequired } : {}),
    ...(extras.attrs ?? {}),
  }, {
    confidence: extras.confidence ?? 0.6,
    ...(Array.isArray(extras.sources) ? { sources: extras.sources } : {}),
  });
}

/** Technology node keyed by vendor/product/version. */
export function techNodeOp(name, extras = {}) {
  const [vendor, product, version] = String(name).split('/');
  return nodeOp('tech', name, extras.label ?? name, {
    vendor: vendor ?? 'unknown',
    product: product ?? name,
    ...(version ? { version } : {}),
    ...(extras.evidence ? { evidence: extras.evidence } : {}),
  }, { confidence: extras.confidence ?? 0.5 });
}

/** Finding node. */
export function findingNodeOp(state, input) {
  const engagement = engagementKey(state);
  const adjusted = reflectedXssAdjustment(input);
  const source = { ...input, ...adjusted.attrs };
  const subjectKey = source.subjectKey ?? source.subjectId ?? 'unknown';
  const template = source.template ?? 'manual-finding';
  const key = findingMergeKey(engagement, source);
  const passed = source.secondaryVerified === true || String(source.secondaryVerdict ?? '').toLowerCase() === 'verified';
  let severity = ['critical', 'high', 'medium', 'low', 'info'].includes(source.severity) ? source.severity : 'info';
  if (adjusted.capped === true) severity = 'medium';
  const displayTitle = localizedFindingTitle(template, source.title ?? template);
  const requested = source.status ?? 'candidate';
  const status = passed ? (requested === 'candidate' ? 'verified' : requested) : (requested === 'verified' || requested === 'validated' ? 'candidate' : requested);
  const verificationStatus = passed ? 'verified' : 'unverified';
  return nodeOp('finding', key, displayTitle, {
    template,
    title: displayTitle,
    severity,
    status,
    subjectId: input.subjectId ?? null,
    subjectKey,
    ...(input.cve ? { cve: input.cve } : {}),
    ...(input.cwe ? { cwe: input.cwe } : {}),
    ...(input.cvss ? { cvss: input.cvss } : {}),
    ...(input.impact ? { impact: input.impact } : {}),
    ...(input.verification ? { verification: input.verification } : {}),
    ...(input.repro ? { repro: String(input.repro).slice(0, 8000) } : {}),
    ...(input.request ? { request: String(input.request).slice(0, 12000) } : {}),
    ...(input.response ? { response: String(input.response).slice(0, 12000) } : {}),
    ...(input.httpRequest ? { httpRequest: String(input.httpRequest).slice(0, 12000) } : {}),
    ...(input.httpResponse ? { httpResponse: String(input.httpResponse).slice(0, 12000) } : {}),
    ...(input.pocCurl ? { pocCurl: String(input.pocCurl).slice(0, 8000) } : {}),
    ...(input.pocPython ? { pocPython: String(input.pocPython).slice(0, 8000) } : {}),
    ...(input.redteamRationale ? { redteamRationale: String(input.redteamRationale).slice(0, 4000) } : {}),
    ...(input.ratingRationale ? { ratingRationale: String(input.ratingRationale).slice(0, 4000) } : {}),
    ...(input.proofType ? { proofType: String(input.proofType) } : {}),
    ...(input.proofUrl ? { proofUrl: String(input.proofUrl).slice(0, 2000) } : {}),
    ...(input.proofCanary ? { proofCanary: String(input.proofCanary).slice(0, 500) } : {}),
    ...(input.proofDetail ? { proofDetail: String(input.proofDetail).slice(0, 8000) } : {}),
    ...(Array.isArray(input.channels) ? { channels: input.channels.slice(0, 12).map(String) } : {}),
    ...(input.secondaryVerified === true ? { secondaryVerified: true } : {}),
    ...(input.secondaryVerdict ? { secondaryVerdict: String(input.secondaryVerdict).slice(0, 500) } : {}),
    ...(input.redteamRating ? { redteamRating: String(input.redteamRating).slice(0, 40) } : {}),
    ...(input.ratingRubric ? { ratingRubric: String(input.ratingRubric).slice(0, 2000) } : {}),
    ...(input.issueFamily ? { issueFamily: String(input.issueFamily).slice(0, 80) } : {}),
    ...(input.interfacePath ? { interfacePath: String(input.interfacePath).slice(0, 400) } : {}),
    ...(input.harmBand ? { harmBand: String(input.harmBand).slice(0, 40) } : {}),
    ...(input.containerBound === true ? { containerBound: true } : {}),
    ...(input.remediation ? { remediation: input.remediation } : {}),
    ...(input.evidence ? { evidence: String(input.evidence).slice(0, 4000) } : {}),
    ...(input.escalatedFromId ? { escalatedFromId: String(input.escalatedFromId).slice(0, 200) } : {}),
    ...(input.escalatedFromTitle ? { escalatedFromTitle: String(input.escalatedFromTitle).slice(0, 300) } : {}),
    ...(input.escalatedFromSeverity ? { escalatedFromSeverity: String(input.escalatedFromSeverity).slice(0, 20) } : {}),
    ...(input.escalatedToSeverity ? { escalatedToSeverity: String(input.escalatedToSeverity).slice(0, 20) } : {}),
    ...(input.escalationProof ? { escalationProof: String(input.escalationProof).slice(0, 4000) } : {}),
    ...(input.attrs ?? {}),
    interfacePath: findingInterfacePath(source),
    issueFamily: findingFamily(source),
    severity,
    ...(adjusted.capped === true ? {
      cvssScore: 6.1,
      cvssSeverity: 'MEDIUM',
      cvssRating: 'medium',
      cvssCap: 'reflected-xss',
      cvssCapFrom: adjusted.originalScore,
    } : {}),
  }, {
    status,
    confidence: input.confidence ?? 0.6,
    verification: verificationStatus,
    ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds } : {}),
  });
}

/** Credential node. Raw secrets are never accepted; only a mask + fingerprint. */
export function credentialNodeOp(state, input) {
  const engagement = engagementKey(state);
  const username = String(input.username ?? 'unknown');
  const realm = String(input.realm ?? 'external');
  const fingerprint = String(input.secretFp ?? input.secretMask ?? username);
  const key = `${engagement}/${realm}/${username}/${fingerprint}`;
  return nodeOp('credential', key, input.label ?? `${realm}/${username}`, {
    username,
    kind: input.kind ?? 'password',
    realm,
    secretMask: input.secretMask ?? '[redacted]',
    secretFp: input.secretFp ?? null,
    validity: input.validity ?? 'untested',
    privilege: input.privilege ?? 'unknown',
    ...(input.targetId ? { targetId: input.targetId } : {}),
    ...(input.sourceAccessId ? { sourceAccessId: input.sourceAccessId } : {}),
    ...(input.attrs ?? {}),
  }, {
    status: input.validity ?? 'untested',
    confidence: input.confidence ?? 0.5,
  });
}

/** Access / foothold node. */
export function accessNodeOp(state, input) {
  const engagement = engagementKey(state);
  const assetKey = input.assetKey ?? input.assetId ?? 'unknown';
  const key = `${engagement}/${assetKey}/${input.kind ?? 'access'}/${input.privilege ?? 'user'}`;
  return nodeOp('access', key, input.label ?? `${input.kind ?? 'access'} on ${assetKey}`, {
    assetId: input.assetId ?? null,
    assetKey,
    kind: input.kind ?? 'access',
    privilege: input.privilege ?? 'user',
    status: input.status ?? 'obtained',
    ...(input.osUser ? { osUser: input.osUser } : {}),
    ...(input.transport ? { transport: input.transport } : {}),
    ...(input.persistence ? { persistence: input.persistence } : {}),
    ...(input.proof ? { proof: String(input.proof).slice(0, 2000) } : {}),
    ...(Array.isArray(input.reachableSegments) ? { reachableSegments: input.reachableSegments } : {}),
    ...(input.attrs ?? {}),
  }, {
    status: input.status ?? 'obtained',
    confidence: input.confidence ?? 0.7,
    verification: input.verification?.status ?? (input.status === 'validated' ? 'verified' : 'unverified'),
    ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds } : {}),
  });
}

/** Pivot node (one realized tunnel/route). */
export function pivotNodeOp(state, input) {
  const engagement = engagementKey(state);
  const key = `${engagement}/${input.accessId ?? 'operator'}/${input.targetKey ?? input.targetId ?? 'target'}/${input.transport ?? 'socks5'}`;
  return nodeOp('pivot', key, input.label ?? `${input.transport ?? 'socks5'} -> ${input.targetKey ?? 'target'}`, {
    accessId: input.accessId ?? null,
    targetId: input.targetId ?? null,
    targetKey: input.targetKey ?? null,
    transport: input.transport ?? 'socks5',
    ...(input.localEndpoint ? { localEndpoint: input.localEndpoint } : {}),
    ...(input.remoteEndpoint ? { remoteEndpoint: input.remoteEndpoint } : {}),
    verified: input.verified === true,
    tunnelId: input.tunnelId ?? null,
    ...(input.attrs ?? {}),
  }, {
    status: input.verified === true ? 'verified' : 'obtained',
    confidence: input.confidence ?? 0.6,
  });
}

/** Sensitive-data evidence node; samples must already be redacted. */
export function dataNodeOp(state, input) {
  const engagement = engagementKey(state);
  const key = `${engagement}/${input.subjectId ?? 'unknown'}/${input.dataClass ?? 'internal'}/${input.seq ?? '001'}`;
  return nodeOp('data', key, input.label ?? `${input.dataClass ?? 'data'} evidence`, {
    subjectId: input.subjectId ?? null,
    dataClass: input.dataClass ?? 'internal',
    count: Number.isFinite(input.count) ? input.count : 0,
    countMethod: input.countMethod ?? 'unknown',
    thresholdMet: input.thresholdMet === true,
    samples: Array.isArray(input.samples) ? input.samples.slice(0, 10) : [],
    hashes: Array.isArray(input.hashes) ? input.hashes.slice(0, 50) : [],
    ...(input.schema ? { schema: input.schema } : {}),
    ...(input.attrs ?? {}),
  }, {
    status: input.status ?? 'claimed',
    confidence: input.confidence ?? 0.6,
    verification: input.verification?.status ?? 'unverified',
    ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds } : {}),
  });
}

/** Evidence artifact node. */
export function evidenceNodeOp(state, input) {
  const sha = String(input.sha256 ?? shortHash(stableStringify(input), 32));
  return nodeOp('evidence', sha, input.label ?? `evidence ${sha.slice(0, 12)}`, {
    path: input.path ?? null,
    relative: input.relative ?? null,
    mediaType: input.mediaType ?? 'application/octet-stream',
    size: Number.isFinite(input.bytes) ? input.bytes : (Number.isFinite(input.size) ? input.size : null),
    sha256: sha,
    commandHash: input.commandHash ?? null,
    collectedBy: input.collectedBy ?? 'plugin',
    collectedAt: input.collectedAt ?? nowIso(),
    ...(typeof input.origin === 'string' && input.origin.trim().length > 0 ? { origin: input.origin.trim().slice(0, 40) } : {}),
    ...(input.toolName ? { toolName: String(input.toolName).slice(0, 80) } : {}),
    ...(input.toolArgsHash ? { toolArgsHash: String(input.toolArgsHash).slice(0, 80) } : {}),
    ...(Number.isFinite(input.exitCode) ? { exitCode: input.exitCode } : {}),
    ...(typeof input.success === 'boolean' ? { success: input.success } : {}),
    ...(typeof input.timedOut === 'boolean' ? { timedOut: input.timedOut } : {}),
    ...(Number.isFinite(input.durationMs) ? { durationMs: input.durationMs } : {}),
    ...(Array.isArray(input.scopeTargets) ? { scopeTargets: input.scopeTargets.slice(0, 20).map(String) } : {}),
    ...(input.errorSummary ? { errorSummary: String(input.errorSummary).slice(0, 500) } : {}),
    ...(input.prevHash ? { prevHash: input.prevHash } : {}),
  }, {
    confidence: 1,
    verification: 'verified',
  });
}

/** One capability invocation (skill or dictionary) for the audit trail. */
export function capabilityNodeOp(state, input) {
  const engagement = engagementKey(state);
  const capability = String(input.capability ?? 'capability');
  const name = String(input.name ?? 'unknown').slice(0, 160);
  const seed = stableStringify({ capability, name, action: input.action ?? null, at: input.at ?? null, summary: input.summary ?? null });
  return nodeOp('task', `${engagement}/capability/${capability}/${shortHash(seed, 12)}`, input.label ?? `能力 · ${capability} · ${name}`, {
    actionType: 'capability',
    capability,
    capabilityName: name,
    capabilityAction: input.action ?? null,
    success: input.success !== false,
    summary: input.summary ? String(input.summary).slice(0, 500) : null,
    target: input.target ? String(input.target).slice(0, 300) : null,
    at: input.at ?? nowIso(),
  }, {
    status: input.success === false ? 'failed' : 'completed',
    confidence: 0.8,
  });
}

/** Task node. */
export function taskNodeOp(state, input) {
  const engagement = engagementKey(state);
  const key = `${engagement}/${input.actionType}/${input.targetId ?? 'target'}/${shortHash(stableStringify(input.params ?? {}), 8)}`;
  return nodeOp('task', key, input.label ?? input.actionType, {
    actionType: input.actionType,
    targetId: input.targetId ?? null,
    priority: Number.isFinite(input.priority) ? input.priority : 0,
    why: Array.isArray(input.why) ? input.why.slice(0, 10) : [],
    toolClass: input.toolClass ?? 'tcp',
    expectedEvidence: input.expectedEvidence ?? null,
    risk: input.risk ?? 'low',
    scopeVerdict: input.scopeVerdict ?? 'unknown',
    ...(input.attrs ?? {}),
  }, {
    status: input.status ?? 'pending',
    confidence: 0.4,
  });
}

/** Autonomous-loop state node (one per engagement). */
export function loopNodeOp(state, input = {}) {
  const engagement = engagementKey(state);
  return nodeOp('loop', `${engagement}/loop`, input.label ?? `autonomous loop: ${engagement}`, {
    objective: String(input.objective ?? '').slice(0, 1000),
    objectiveType: input.objectiveType ?? 'impact',
    phase: input.phase ?? 'running',
    round: Number(input.round) || 0,
    maxRounds: Number(input.maxRounds) || 0,
    goalId: input.goalId ?? null,
    goalRevision: input.goalRevision ?? null,
    goalPhase: input.goalPhase ?? null,
    activation: input.activation ?? 'disarmed',
    ring: Number(input.ring) || 1,
    allowedRing: Number(input.allowedRing) || 1,
    noProgressRounds: Number(input.noProgressRounds) || 0,
    emptyRounds: Number(input.emptyRounds) || 0,
    maxActionsPerRound: Number(input.maxActionsPerRound) || 3,
    baseline: input.baseline ?? {},
    latestSnapshot: input.latestSnapshot ?? {},
    stopReason: input.stopReason ?? null,
    autoContinue: input.autoContinue === true,
    usedLessonKeys: Array.isArray(input.usedLessonKeys) ? input.usedLessonKeys.slice(0, 50) : [],
    appliedLessonKeys: Array.isArray(input.appliedLessonKeys) ? input.appliedLessonKeys.slice(0, 50) : [],
    startedAt: input.startedAt ?? nowIso(),
    lastStepAt: input.lastStepAt ?? null,
    latestSupervisionKey: input.latestSupervisionKey ?? null,
  }, {
    status: input.phase ?? 'running',
    confidence: 0.8,
  });
}

/** One hypothesis / next-action intent in the loop. */
export function intentNodeOp(state, input) {
  const engagement = engagementKey(state);
  const round = Number(input.round) || 0;
  const key = `${engagement}/intent/${round}/${shortHash(String(input.actionId ?? input.actionType ?? 'intent'), 10)}`;
  return nodeOp('intent', key, input.label ?? input.actionType ?? 'intent', {
    actionType: input.actionType ?? 'manual',
    actionId: input.actionId ?? null,
    targetId: input.targetId ?? null,
    targetKind: input.targetKind ?? null,
    targetLabel: input.targetLabel ?? null,
    priority: Number(input.priority) || 0,
    why: Array.isArray(input.why) ? input.why.slice(0, 10) : [],
    hypothesis: input.hypothesis ? String(input.hypothesis).slice(0, 1000) : null,
    strategyKey: input.strategyKey ?? null,
    expectedEvidence: input.expectedEvidence ?? null,
    scopeVerdict: input.scopeVerdict ?? 'unknown',
    round,
    attempts: Number(input.attempts) || 0,
    observations: Array.isArray(input.observations) ? input.observations.slice(0, 10) : [],
    channelCount: Number(input.channelCount) || 0,
    claimedAt: input.claimedAt ?? null,
    resolvedAt: input.resolvedAt ?? null,
    result: input.result ? String(input.result).slice(0, 1000) : null,
    supervisorKey: input.supervisorKey ?? null,
  }, {
    status: input.status ?? 'open',
    confidence: input.confidence ?? 0.5,
    ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds } : {}),
  });
}

/** One supervisor plan or finding-verification record. */
export function supervisionNodeOp(state, input) {
  const engagement = engagementKey(state);
  const type = input.type ?? 'round_plan';
  const round = Number(input.round) || 0;
  const identity = `${type}/${round}/${input.planHash ?? shortHash(stableStringify({
    verdict: input.verdict,
    nextPlan: input.nextPlan,
    findingKey: input.findingKey,
  }), 12)}`;
  return nodeOp('supervision', `${engagement}/supervision/${identity}`, input.label ?? `supervision ${type}`, {
    type,
    round,
    verdict: input.verdict ?? 'hold',
    diagnosis: input.diagnosis ? String(input.diagnosis).slice(0, 1500) : '',
    nextPlan: input.nextPlan ? String(input.nextPlan).slice(0, 3000) : '',
    mustIntents: Array.isArray(input.mustIntents) ? input.mustIntents.slice(0, 6) : [],
    preferTactics: Array.isArray(input.preferTactics) ? input.preferTactics.slice(0, 12) : [],
    banRepeats: Array.isArray(input.banRepeats) ? input.banRepeats.slice(0, 12) : [],
    stopRecommended: input.stopRecommended === true,
    stopReason: input.stopReason ?? null,
    confidence: Number.isFinite(input.confidence) ? input.confidence : 0.5,
    source: input.source ?? 'deterministic',
    childId: input.childId ?? null,
    promptHash: input.promptHash ?? null,
    planHash: input.planHash ?? null,
    findingKey: input.findingKey ?? null,
    secondaryVerdict: input.secondaryVerdict ?? null,
    secondaryMode: input.secondaryMode ?? null,
    ratingSource: input.ratingSource ?? null,
    teamType: input.teamType ?? null,
    progressSummary: input.progressSummary ? String(input.progressSummary).slice(0, 2000) : null,
    gained: Array.isArray(input.gained) ? input.gained.slice(0, 8) : [],
    missed: Array.isArray(input.missed) ? input.missed.slice(0, 8) : [],
    advice: input.advice ? String(input.advice).slice(0, 2000) : null,
    antiDeadlock: Array.isArray(input.antiDeadlock) ? input.antiDeadlock.slice(0, 8) : [],
    recommendedNext: Array.isArray(input.recommendedNext) ? input.recommendedNext.slice(0, 8) : [],
    deadlockRisk: input.deadlockRisk ?? null,
    artifactPath: input.artifactPath ?? null,
    handoff: input.handoff && typeof input.handoff === 'object' && !Array.isArray(input.handoff) ? input.handoff : null,
    rationale: input.rationale ? String(input.rationale).slice(0, 3000) : null,
    ...(input.basis ? { basis: String(input.basis).slice(0, 40) } : {}),
    ...(input.auditCursor ? { auditCursor: String(input.auditCursor).slice(0, 80) } : {}),
    ...(Number.isFinite(Number(input.eventSeq)) ? { eventSeq: Number(input.eventSeq) } : {}),
    ...(Number.isFinite(Number(input.operatorSeq)) ? { operatorSeq: Number(input.operatorSeq) } : {}),
    createdAt: input.createdAt ?? nowIso(),
  }, {
    status: input.status ?? 'recorded',
    confidence: Number.isFinite(input.confidence) ? input.confidence : 0.5,
    ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds } : {}),
  });
}

/** One auxiliary self-team (supervision or evolution). */
export function selfTeamNodeOp(input) {
  const allowed = new Set(['lead', 'supervision', 'evolution', 'verification', 'escalation', 'report']);
  const type = allowed.has(input.type) ? input.type : 'supervision';
  const labels = {
    lead: '从者（Lead / Executor）',
    supervision: '御者（监督团队）',
    evolution: '自进化团队',
    verification: '二次验证团队',
    escalation: '危害提升团队',
    report: '报告撰写团队',
  };
  return nodeOp('self_team', `selfteam/${type}`, input.label ?? labels[type], {
    type,
    mode: input.mode ?? 'subagents',
    reportModes: type === 'report' ? ['project', 'finding'] : [],
    nativeName: input.nativeName ?? null,
    nativeId: input.nativeId ?? null,
    nativeStatus: input.nativeStatus ?? null,
    lastFindingReportAt: input.lastFindingReportAt ?? null,
    lastFindingReportPath: input.lastFindingReportPath ?? null,
    lastFindingReportId: input.lastFindingReportId ?? null,
    members: Array.isArray(input.members) ? input.members.slice(0, 8) : [],
    lastBriefAt: input.lastBriefAt ?? null,
    lastBriefPath: input.lastBriefPath ?? null,
    lastDistillAt: input.lastDistillAt ?? null,
    lastVerifyAt: input.lastVerifyAt ?? null,
    lastReportAt: input.lastReportAt ?? null,
    lastReportPath: input.lastReportPath ?? null,
    lastReportTheme: input.lastReportTheme ?? null,
    lastReportKind: input.lastReportKind ?? null,
    themeSource: input.themeSource ?? null,
    verifiedCount: Number(input.verifiedCount) || 0,
    ratedCount: Number(input.ratedCount) || 0,
    skillCount: Number(input.skillCount) || 0,
    skillDir: input.skillDir ?? null,
    createdAt: input.createdAt ?? nowIso(),
    updatedAt: input.updatedAt ?? nowIso(),
  }, {
    status: input.status ?? 'active',
    confidence: 0.7,
  });
}

/** One distilled reusable path skill. */
export function skillNodeOp(input) {
  const key = String(input.skillKey ?? 'unknown');
  return nodeOp('skill', `skill/${key}`, input.label ?? input.name ?? `skill ${key.slice(0, 12)}`, {
    skillKey: key,
    name: input.name ?? 'skill',
    summary: String(input.summary ?? '').slice(0, 800),
    when: Array.isArray(input.when) ? input.when.slice(0, 8) : [],
    do: Array.isArray(input.do) ? input.do.slice(0, 6) : [],
    avoid: Array.isArray(input.avoid) ? input.avoid.slice(0, 6) : [],
    route: String(input.route ?? '').slice(0, 500),
    preconditions: Array.isArray(input.preconditions) ? input.preconditions.slice(0, 8) : [],
    verification: Array.isArray(input.verification) ? input.verification.slice(0, 8) : [],
    steps: Array.isArray(input.steps) ? input.steps.slice(0, 8) : [],
    pitfalls: Array.isArray(input.pitfalls) ? input.pitfalls.slice(0, 8) : [],
    confidence: Number.isFinite(input.confidence) ? input.confidence : 0.5,
    status: input.status ?? 'active',
    slug: input.slug ?? null,
    path: input.path ?? null,
    sourceEngagementHash: input.sourceEngagementHash ?? null,
    sourceOutcome: input.sourceOutcome ?? null,
    sourceFindingClasses: Array.isArray(input.sourceFindingClasses) ? input.sourceFindingClasses.slice(0, 8) : [],
    createdAt: input.createdAt ?? nowIso(),
    updatedAt: input.updatedAt ?? nowIso(),
  }, {
    status: input.status ?? 'active',
    confidence: Number.isFinite(input.confidence) ? input.confidence : 0.5,
  });
}

/** One cross-engagement evolution lesson (key is global, not engagement-scoped). */
export function lessonNodeOp(input) {
  const key = `lesson/${input.lessonKey ?? 'unknown'}`;
  return nodeOp('lesson', key, input.label ?? `lesson ${String(input.lessonKey ?? '').slice(0, 12)}`, {
    lessonKey: input.lessonKey ?? 'unknown',
    idea: String(input.idea ?? '').slice(0, 500),
    method: String(input.method ?? '').slice(0, 500),
    route: String(input.route ?? '').slice(0, 500),
    chain: String(input.chain ?? '').slice(0, 500),
    when: Array.isArray(input.when) ? input.when.slice(0, 8) : [],
    do: Array.isArray(input.do) ? input.do.slice(0, 6) : [],
    avoid: Array.isArray(input.avoid) ? input.avoid.slice(0, 6) : [],
    confidence: Number.isFinite(input.confidence) ? input.confidence : 0.4,
    wins: Number(input.wins) || 0,
    fails: Number(input.fails) || 0,
    uses: Number(input.uses) || 0,
    status: input.status ?? 'active',
    sourceEngagementHash: input.sourceEngagementHash ?? null,
    sourceOutcome: input.sourceOutcome ?? null,
    sourceFindingClasses: Array.isArray(input.sourceFindingClasses) ? input.sourceFindingClasses.slice(0, 12) : [],
    createdAt: input.createdAt ?? nowIso(),
    updatedAt: input.updatedAt ?? nowIso(),
    lastUsedAt: input.lastUsedAt ?? null,
  }, {
    status: input.status ?? 'active',
    confidence: Number.isFinite(input.confidence) ? input.confidence : 0.4,
  });
}

/** Attack-chain step node. */
export function chainStepNodeOp(state, input) {
  const engagement = engagementKey(state);
  const chainId = input.chainId ?? `${engagement}-chain`;
  const ordinal = Number.isInteger(input.ordinal) ? input.ordinal : 1;
  return nodeOp('chain_step', `${chainId}/${ordinal}`, input.label ?? `${input.stage ?? 'step'} #${ordinal}`, {
    chainId,
    ordinal,
    stage: input.stage ?? 'recon',
    nodeRef: input.nodeRef ?? null,
    ...(input.edgeRef ? { edgeRef: input.edgeRef } : {}),
    ...(input.result ? { result: String(input.result).slice(0, 1000) } : {}),
    ...(input.attrs ?? {}),
  }, {
    status: input.status ?? 'recorded',
    confidence: input.confidence ?? 0.7,
    ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds } : {}),
  });
}

/** Directed edge between two canonical refs. */
export function link(from, to, kind, extras = {}) {
  return edgeOp(from, to, kind, extras.attrs ?? {}, {
    confidence: extras.confidence ?? 0.6,
    ...(Array.isArray(extras.evidenceIds) ? { evidenceIds: extras.evidenceIds } : {}),
  });
}

/** `{kind,key}` node reference. */
export function ref(kind, key) {
  return { kind, key };
}

/** Derive the subject ref of a finding from an endpoint. */
export function subjectRefForEndpoint(endpoint) {
  if (endpoint.kind === 'host' || endpoint.kind === 'ip') return ref(endpoint.kind, endpoint.key);
  return undefined;
}

function coverageNoteAttrs(input) {
  const note = typeof input.note === 'string' ? input.note.trim() : '';
  const reason = typeof input.reason === 'string' ? input.reason.trim() : '';
  const text = note || reason;
  if (text.length === 0) return {};
  return {
    note: (note || reason).slice(0, 1000),
    reason: (reason || note).slice(0, 1000),
  };
}

/** One interface x bug-class coverage cell (hidden operational state). */
export function coverageNodeOp(state, input) {
  const engagement = engagementKey(state);
  const path = String(input.path ?? '/').replace(/\/+$/u, '') || '/';
  const bugClass = String(input.bugClass ?? 'unknown');
  return nodeOp('coverage', `${engagement}/coverage/${path}/${bugClass}`, input.label ?? `${path} × ${bugClass}`, {
    path,
    bugClass,
    status: input.status ?? 'open',
    role: input.role ?? 'lead',
    ...(input.dutyRole ? { dutyRole: String(input.dutyRole).slice(0, 40) } : {}),
    ...(input.duty ? { duty: String(input.duty).slice(0, 400) } : {}),
    ...(input.targetKey ? { targetKey: String(input.targetKey).slice(0, 300) } : {}),
    ...coverageNoteAttrs(input),
    ...(input.findingId ? { findingId: String(input.findingId).slice(0, 200) } : {}),
    ...(Array.isArray(input.channels) ? { channels: input.channels.slice(0, 12).map(String) } : {}),
    ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds.slice(0, 40).map(String) } : {}),
    ...(Array.isArray(input.hits) ? { hits: input.hits.slice(0, 40).map(String) } : {}),
    checkedAt: input.checkedAt ?? nowIso(),
  }, {
    status: input.status ?? 'open',
    confidence: input.status === 'seen' || input.status === 'reported' ? 0.8 : 0.5,
  });
}

/** One persistent hypothesis (hidden operational state). */
export function hypothesisNodeOp(state, input) {
  const engagement = engagementKey(state);
  const seed = `${input.strategy ?? ''}|${input.targetKey ?? ''}|${input.bugClass ?? ''}`;
  const id = String(input.id ?? shortHash(seed, 16));
  return nodeOp('hypothesis', `${engagement}/hypothesis/${id}`, input.label ?? String(input.strategy ?? 'hypothesis').slice(0, 160), {
    hypothesisId: id,
    strategy: String(input.strategy ?? '').slice(0, 1600),
    bugClass: input.bugClass ? String(input.bugClass) : null,
    targetKey: input.targetKey ? String(input.targetKey) : null,
    expectedProof: input.expectedProof ?? 'poc_replay',
    status: input.status ?? 'open',
    ...(input.reason ? { reason: String(input.reason).slice(0, 1200) } : {}),
    ...(input.coverageKey ? { coverageKey: String(input.coverageKey) } : {}),
    ...(Array.isArray(input.channels) ? { channels: input.channels.slice(0, 12).map(String) } : {}),
    ...(Array.isArray(input.evidenceIds) ? { evidenceIds: input.evidenceIds.slice(0, 40).map(String) } : {}),
    updatedAt: input.updatedAt ?? nowIso(),
  }, {
    status: input.status ?? 'open',
    confidence: input.status === 'verified' ? 0.8 : 0.5,
  });
}

/** Honeypot / do-not-touch marker. */
export function honeypotNodeOp(state, input) {
  const engagement = engagementKey(state);
  const key = String(input.key ?? input.targetKey ?? 'unknown');
  return nodeOp('honeypot', `${engagement}/honeypot/${key}`, input.label ?? `honeypot ${key}`, {
    targetKey: key,
    reason: input.reason ? String(input.reason).slice(0, 1200) : null,
    severity: input.severity ?? 'high',
    ...(input.attrs ?? {}),
  }, { status: input.status ?? 'active', confidence: 0.7 });
}
