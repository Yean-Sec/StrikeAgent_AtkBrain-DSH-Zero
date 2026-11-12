/**
 * Shared constants for the AtkBrain workbench.
 *
 * The plugin keeps all durable state in the session log. The lead's own tools
 * fold `tool/result` metadata into one wire projection. A resident teammate
 * writes the same ops as an ignorable plugin record on the lead session,
 * because its tool result stays in the child session. These constants define
 * the vocabulary of that state and are shared by the Host tools, the
 * projection's pure fold, the report renderer, and (as a copy) the Client page.
 */

export const STATE_SCHEMA = 'atkbrain/1';
export const PROJECTION_KEY = 'atkGraph';
export const PROJECTION_STATE_VERSION = 1;
/** Ignorable lead-session record for graph ops written by a resident teammate. */
export const LEDGER_EVENT = 'plugin:atkbrain/ledger';

export const TOOL_PREFIX = 'atkbrain_';
export const TOOL_NAMES = Object.freeze({
  scope: 'atkbrain_scope',
  ingest: 'atkbrain_ingest',
  probe: 'atkbrain_probe',
  record: 'atkbrain_record',
  query: 'atkbrain_query',
  report: 'atkbrain_report',
  tunnel: 'atkbrain_tunnel',
  team: 'atkbrain_team',
  loop: 'atkbrain_loop',
  supervise: 'atkbrain_supervise',
  arsenal: 'atkbrain_arsenal',
  coverage: 'atkbrain_coverage',
  hypothesis: 'atkbrain_hypothesis',
  proxy: 'atkbrain_proxy',
  survey: 'atkbrain_survey',
  selftteam: 'atkbrain_selftteam',
});

/** Node kinds, in presentation order. */
export const NODE_KINDS = Object.freeze([
  'loop',
  'domain',
  'wildcard_zone',
  'host',
  'ip',
  'cidr',
  'segment',
  'service',
  'webapp',
  'tech',
  'finding',
  'credential',
  'access',
  'pivot',
  'data',
  'evidence',
  'task',
  'coverage',
  'hypothesis',
  'honeypot',
  'chain_step',
  'intent',
  'supervision',
  'lesson',
  'self_team',
  'skill',
  'mcp',
]);

/** Layout / importance rank for one kind (lower is closer to the root). */
export const NODE_KIND_RANK = Object.freeze({
  loop: 4,
  self_team: 6,
  domain: 10,
  wildcard_zone: 12,
  host: 20,
  ip: 24,
  cidr: 28,
  segment: 32,
  service: 40,
  webapp: 44,
  tech: 48,
  honeypot: 58,
  finding: 60,
  credential: 64,
  access: 70,
  pivot: 74,
  data: 80,
  evidence: 84,
  task: 90,
  coverage: 91,
  hypothesis: 92,
  chain_step: 94,
  intent: 96,
  supervision: 97,
  lesson: 98,
  skill: 99,
  mcp: 100,
  unknown: 99,
});

/** Directed edge kinds and their semantics. */
export const EDGE_KINDS = Object.freeze([
  'contains',
  'resolves_to',
  'cname',
  'hosted_on',
  'exposes',
  'affects',
  'authenticates_to',
  'controls',
  'pivots_to',
  'reached_via',
  'proves',
  'derived_from',
  'merged_into',
  'duplicate_of',
  'supervises',
  'targets',
  'learned_from',
  'applies_to',
  'distills',
  'reports_to',
  'escalates_to',
]);

export const EDGE_KIND_RANK = Object.freeze({
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
  supervises: 15,
  targets: 16,
  learned_from: 17,
  applies_to: 18,
  distills: 19,
  reports_to: 20,
  escalates_to: 21,
});

export const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);
export const SEVERITY_RANK = Object.freeze({ critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0 });

export const FINDING_STATUSES = Object.freeze(['candidate', 'verified', 'exploited', 'impacted', 'fixed']);
export const FINDING_STATUS_RANK = Object.freeze({ candidate: 1, verified: 2, exploited: 3, impacted: 4, fixed: 5 });

export const ACCESS_STATUSES = Object.freeze(['attempted', 'obtained', 'validated', 'escalated', 'lost']);
export const ACCESS_STATUS_RANK = Object.freeze({ attempted: 1, obtained: 2, validated: 3, escalated: 4, lost: 5 });

export const CREDENTIAL_VALIDITY = Object.freeze(['untested', 'valid', 'invalid', 'expired']);
export const CREDENTIAL_VALIDITY_RANK = Object.freeze({ untested: 0, invalid: 1, valid: 2, expired: 3 });

export const DATA_STATUSES = Object.freeze(['claimed', 'partial', 'verified']);
export const DATA_STATUS_RANK = Object.freeze({ claimed: 1, partial: 2, verified: 3 });

export const WILDCARD_STATUSES = Object.freeze(['confirmed', 'suspect', 'inconclusive', 'cleared']);

export const COVERAGE_STATUSES = Object.freeze(['open', 'claimed', 'seen', 'refuted', 'reported']);
export const COVERAGE_STATUS_RANK = Object.freeze({ open: 1, claimed: 2, seen: 3, refuted: 4, reported: 5 });
export const HYPOTHESIS_STATUSES = Object.freeze(['open', 'active', 'verified', 'disproved', 'deferred', 'blocked']);
export const HYPOTHESIS_STATUS_RANK = Object.freeze({ open: 1, active: 2, blocked: 1, deferred: 1, disproved: 4, verified: 5 });
/** Operational state that stays out of the attack-graph canvas. */
export const HIDDEN_GRAPH_KINDS = Object.freeze(['coverage', 'hypothesis', 'mcp', 'lesson', 'self_team', 'skill', 'evidence', 'supervision']);


export const LOOP_STATUSES = Object.freeze(['running', 'paused', 'complete', 'blocked', 'stopped']);
export const LOOP_STATUS_RANK = Object.freeze({ stopped: 0, blocked: 1, paused: 1, running: 2, complete: 3 });

export const INTENT_STATUSES = Object.freeze(['open', 'claimed', 'verified', 'refuted', 'blocked', 'stalled']);
export const INTENT_STATUS_RANK = Object.freeze({ stalled: 0, open: 1, blocked: 1, refuted: 2, claimed: 2, verified: 3 });

export const LESSON_STATUSES = Object.freeze(['active', 'retired']);
export const LESSON_STATUS_RANK = Object.freeze({ retired: 1, active: 2 });

export const OBSERVATION_CHANNELS = Object.freeze(['status', 'body', 'timing', 'header', 'side_effect']);

export const OBJECTIVE_TYPES = Object.freeze(['impact', 'shell', 'admin', 'data', 'findings']);

export const MCP_STATUSES = Object.freeze(['checking', 'connected', 'empty', 'error']);
export const MCP_STATUS_RANK = Object.freeze({ error: 0, checking: 1, empty: 2, connected: 3 });

export const SELF_TEAM_STATUSES = Object.freeze(['active', 'standby', 'stopped']);
export const SELF_TEAM_STATUS_RANK = Object.freeze({ stopped: 0, standby: 1, active: 2 });
export const SKILL_STATUSES = Object.freeze(['active', 'retired']);
export const SKILL_STATUS_RANK = Object.freeze({ retired: 1, active: 2 });

export const SUPERVISOR_VERDICTS = Object.freeze(['hold', 'pivot', 'verify', 'escalate', 'stop']);


export const VERIFICATION_LEVELS = Object.freeze(['refuted', 'unverified', 'corroborated', 'verified']);
export const VERIFICATION_RANK = Object.freeze({ refuted: 0, unverified: 1, corroborated: 2, verified: 3 });

export const CHAIN_STAGES = Object.freeze([
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
]);

export const ACCESS_TYPES = Object.freeze([
  'none',
  'info_leak',
  'auth_bypass',
  'user_shell',
  'db_read',
  'db_admin',
  'admin_panel',
  'root_shell',
  'domain_admin',
  'cloud_admin',
]);

export const ACCESS_TYPE_SCORE = Object.freeze({
  none: 0,
  info_leak: 10,
  auth_bypass: 35,
  db_read: 50,
  user_shell: 55,
  admin_panel: 60,
  db_admin: 70,
  root_shell: 80,
  cloud_admin: 85,
  domain_admin: 90,
});

export const BLAST_RADIUS = Object.freeze(['service', 'host', 'subnet', 'segment', 'domain', 'tenant', 'multi_tenant']);

export const DATA_CLASSES = Object.freeze([
  'public',
  'internal',
  'confidential',
  'pii',
  'customer_records',
  'financial',
  'regulated',
  'credentials',
  'source_code',
  'internal_docs',
  'keys_tokens',
]);

export const RISK_LEVELS = Object.freeze(['none', 'low', 'medium', 'high']);
export const RISK_PENALTY = Object.freeze({ none: 0, low: 5, medium: 20, high: 45 });

export const DEFAULT_CONFIG = Object.freeze({
  enabled: true,
  offline: false,
  requireScope: true,
  requireScopeApproval: true,
  requireTunnelApproval: true,
  maxNodes: 20000,
  maxEdges: 60000,
  viewNodeLimit: 2500,
  viewEdgeLimit: 6000,
  auditLimit: 500,
  wildcardProbes: 3,
  wildcardRounds: 2,
  dnsConcurrency: 6,
  dnsTimeoutMs: 3000,
  dnsResolvers: [],
  probeConcurrency: 8,
  probeTimeoutMs: 4000,
  maxPortsPerCall: 32,
  maxHttpBodyBytes: 1048576,
  followRedirects: 3,
  allowTunnels: true,
  tunnelStartupTimeoutMs: 8000,
  reportDir: '.atkbrain/reports',
  evidenceDir: '.atkbrain/evidence',
  teamDir: '.atkbrain/team',
  teamBatchSize: 8,
  teamMaxBatches: 4,
  loopMaxRounds: 40,
  loopMaxWallMinutes: 360,
  loopNoProgressRounds: 2,
  loopStallRounds: 3,
  loopSpiralPromoteRounds: 3,
  loopMaxActionsPerRound: 3,
  supervisorMode: 'auto',
  supervisorInterval: 3,
  supervisorTimeoutMs: 90000,
  verifierTimeoutMs: 120000,
  autoVerifyFindings: false,
  autoVerifyMaxFindings: 2,
  autoVerifyConcurrency: 4,
  evolveAi: true,
  evolveTimeoutMs: 90000,
  lessonTopK: 6,
  lessonStore: '',
  skillDir: '',
  reportTheme: 'auto',
  arsenalRoot: '',
  arsenalToolTimeoutMs: 120000,
  arsenalMaxOutputBytes: 262144,
  arsenalMaxSkillBytes: 32768,
  coverageMaxCells: 500,
  coverageAutoSeed: false,
  requireProofForVerified: true,
  requireTwoChannelsForHigh: true,
  huntDispatchOnly: false,
  proxyEnabled: false,
  proxyMode: 'local',
  proxyUrl: '',
  proxyUrlEnv: 'ATKBRAIN_PROXY_URL',
  proxyLocalUrl: 'http://127.0.0.1:7897',
  proxyPool: [],
  proxyProviderUrl: '',
  proxyNoProxy: '',
  proxyFailClosed: true,
  proxyEchoUrl: 'http://ip.sb',
  proxyCheckIntervalMs: 15000,
  proxyTimeoutMs: 8000,
  proxyApplyToProbe: true,
  proxyBypassPrivate: false,
  reportAi: false,
  reportAiTimeoutMs: 120000,
  selfTeamMode: 'subagents',
  selfTeamTimeoutMs: 90000,
  skillTopK: 6,
  pythonPath: null,
  bulkThresholds: Object.freeze({
    pii: 500,
    financial: 500,
    regulated: 500,
    credentials: 50,
    keys: 1,
  }),
});

/** Frequently exposed service ports and a best-effort protocol label. */
export const COMMON_PORTS = Object.freeze([
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 636,
  873, 993, 995, 1080, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389,
  5432, 5601, 5900, 5984, 6379, 7001, 7002, 8000, 8008, 8080, 8081,
  8088, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 15672,
  27017, 27018, 50070, 6443, 10250, 10255,
]);

export const PORT_PROTOCOLS = Object.freeze({
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  110: 'pop3',
  111: 'rpcbind',
  135: 'msrpc',
  139: 'netbios',
  143: 'imap',
  389: 'ldap',
  443: 'https',
  445: 'smb',
  636: 'ldaps',
  873: 'rsync',
  993: 'imaps',
  995: 'pop3s',
  1080: 'socks',
  1433: 'mssql',
  1521: 'oracle',
  2049: 'nfs',
  2375: 'docker',
  2376: 'docker-tls',
  3000: 'http-alt',
  3306: 'mysql',
  3389: 'rdp',
  5432: 'postgresql',
  5601: 'kibana',
  5900: 'vnc',
  5984: 'couchdb',
  6379: 'redis',
  7001: 'weblogic',
  7002: 'weblogic-tls',
  8000: 'http-alt',
  8008: 'http-alt',
  8080: 'http-alt',
  8081: 'http-alt',
  8088: 'http-alt',
  8443: 'https-alt',
  8888: 'http-alt',
  9000: 'http-alt',
  9090: 'http-alt',
  9200: 'elasticsearch',
  9300: 'elasticsearch-transport',
  10000: 'webmin',
  11211: 'memcached',
  15672: 'rabbitmq-management',
  27017: 'mongodb',
  27018: 'mongodb',
  50070: 'hdfs-namenode',
  6443: 'kubernetes-api',
  10250: 'kubelet',
  10255: 'kubelet-readonly',
});

/** High-value service ports whose open exposure is itself a candidate finding. */
export const HIGH_VALUE_PORTS = Object.freeze(new Set([
  2375, 2376, 3306, 5432, 6379, 9200, 9300, 11211, 27017, 27018,
  6443, 10250, 10255, 50070, 15672, 7001, 7002,
]));

/** Safe, read-only paths used by the HTTP exposure checks. */
export const DEFAULT_EXPOSURE_PATHS = Object.freeze(['/']);

/** Recognized secret-ish keys that must never enter graph state. */
export const SECRET_KEY_PATTERN = /(^|_|\.)(password|passwd|pwd|secret|token|apikey|api_key|access_key|private_key|cookie|authorization|bearer|ntlm|hash)$/i;

/** Evidence media types we keep as references, never as inline content. */
export const EVIDENCE_MEDIA_TYPES = Object.freeze({
  text: 'text/plain',
  json: 'application/json',
  jsonl: 'application/x-ndjson',
  png: 'image/png',
  jpeg: 'image/jpeg',
  pdf: 'application/pdf',
  html: 'text/html',
  other: 'application/octet-stream',
});
