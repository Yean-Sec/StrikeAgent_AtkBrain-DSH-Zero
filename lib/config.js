/**
 * Plugin configuration resolution.
 *
 * The bundle deliberately exports no Cordis `Config` schema: the Host loader
 * passes a row's raw `config` object through unchanged when a plugin declares
 * none. We therefore apply defaults, type checks and warnings here so a typo in
 * `cordis.patch.yml` is visible without ever preventing activation.
 */
import { DEFAULT_CONFIG } from './constants.js';
import { clone, isPlainObject } from './util.js';

const BOOLEAN_KEYS = new Set(['autoVerifyFindings', 'reportAi', 'coverageAutoSeed', 'requireProofForVerified', 'requireTwoChannelsForHigh', 'huntDispatchOnly', 'proxyEnabled', 'proxyFailClosed', 'proxyApplyToProbe', 'proxyBypassPrivate',
  'enabled',
  'offline',
  'requireScope',
  'requireScopeApproval',
  'requireTunnelApproval',
  'allowTunnels',
  'evolveAi',
]);

const NUMBER_KEYS = new Set([
  'maxNodes',
  'maxEdges',
  'viewNodeLimit',
  'viewEdgeLimit',
  'auditLimit',
  'wildcardProbes',
  'wildcardRounds',
  'dnsConcurrency',
  'dnsTimeoutMs',
  'probeConcurrency',
  'probeTimeoutMs',
  'maxPortsPerCall',
  'maxHttpBodyBytes',
  'followRedirects',
  'tunnelStartupTimeoutMs',
  'teamBatchSize',
  'teamMaxBatches',
  'loopMaxRounds',
  'loopMaxWallMinutes',
  'loopNoProgressRounds',
  'loopStallRounds',
  'loopSpiralPromoteRounds',
  'loopMaxActionsPerRound',
  'supervisorInterval',
  'supervisorTimeoutMs',
  'verifierTimeoutMs',
  'autoVerifyMaxFindings',
  'autoVerifyConcurrency',
  'evolveTimeoutMs',
  'lessonTopK',
  'selfTeamTimeoutMs',
  'reportAiTimeoutMs',
  'skillTopK',
  'arsenalToolTimeoutMs',
  'arsenalMaxOutputBytes',
  'arsenalMaxSkillBytes',
  'coverageMaxCells',
  'proxyCheckIntervalMs',
  'proxyTimeoutMs',
]);

const STRING_KEYS = new Set(['reportDir', 'evidenceDir', 'teamDir', 'lessonStore', 'skillDir', 'arsenalRoot', 'proxyUrl', 'proxyUrlEnv', 'proxyLocalUrl', 'proxyProviderUrl', 'proxyNoProxy', 'proxyEchoUrl']);

function nonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

function positiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

/** Resolve the effective configuration and describe any ignored values. */
export function resolveConfig(raw) {
  const config = clone(DEFAULT_CONFIG);
  const warnings = [];
  if (raw !== undefined && raw !== null && !isPlainObject(raw)) {
    warnings.push('config is not an object; using defaults');
    return { config: applyEnvironment(config), warnings };
  }
  const input = raw ?? {};

  for (const [key, value] of Object.entries(input)) {
    if (key === 'bulkThresholds') {
      if (!isPlainObject(value)) {
        warnings.push('bulkThresholds must be an object; using defaults');
        continue;
      }
      for (const [name, threshold] of Object.entries(value)) {
        if (!(name in config.bulkThresholds)) {
          warnings.push(`bulkThresholds.${name} is unknown; ignored`);
          continue;
        }
        if (!nonNegativeInteger(threshold)) {
          warnings.push(`bulkThresholds.${name} must be a non-negative integer; ignored`);
          continue;
        }
        config.bulkThresholds[name] = threshold;
      }
      continue;
    }
    if (BOOLEAN_KEYS.has(key)) {
      if (typeof value !== 'boolean') warnings.push(`${key} must be a boolean; ignored`);
      else config[key] = value;
      continue;
    }
    if (NUMBER_KEYS.has(key)) {
      if (!positiveInteger(value)) {
        warnings.push(`${key} must be a positive integer; ignored`);
        continue;
      }
      if (key === 'wildcardProbes' && value < 3) {
        warnings.push('wildcardProbes must be at least 3; using 3');
        config[key] = 3;
        continue;
      }
      if (key === 'wildcardRounds' && value < 1) {
        warnings.push('wildcardRounds must be at least 1; using 1');
        config[key] = 1;
        continue;
      }
      if (key === 'teamBatchSize') {
        config[key] = Math.min(50, Math.max(1, value));
        continue;
      }
      if (key === 'teamMaxBatches') {
        config[key] = Math.min(8, Math.max(1, value));
        continue;
      }
      if (key === 'loopMaxRounds') {
        config[key] = Math.min(200, Math.max(1, value));
        continue;
      }
      if (key === 'loopMaxWallMinutes') {
        config[key] = Math.min(1440, Math.max(5, value));
        continue;
      }
      if (key === 'loopNoProgressRounds' || key === 'loopStallRounds' || key === 'loopSpiralPromoteRounds') {
        config[key] = Math.min(20, Math.max(1, value));
        continue;
      }
      if (key === 'loopMaxActionsPerRound') {
        config[key] = Math.min(5, Math.max(1, value));
        continue;
      }
      if (key === 'supervisorInterval' || key === 'lessonTopK' || key === 'skillTopK') {
        config[key] = Math.min(20, Math.max(1, value));
        continue;
      }
      if (key === 'arsenalToolTimeoutMs') {
        config[key] = Math.min(600000, Math.max(1000, value));
        continue;
      }
      if (key === 'arsenalMaxOutputBytes') {
        config[key] = Math.min(2097152, Math.max(4096, value));
        continue;
      }
      if (key === 'arsenalMaxSkillBytes') {
        config[key] = Math.min(262144, Math.max(1024, value));
        continue;
      }
      if (key === 'coverageMaxCells') {
        config[key] = Math.min(5000, Math.max(1, value));
        continue;
      }
      if (key === 'proxyCheckIntervalMs') {
        config[key] = Math.min(300000, Math.max(5000, value));
        continue;
      }
      if (key === 'proxyTimeoutMs') {
        config[key] = Math.min(60000, Math.max(1000, value));
        continue;
      }
      if (key === 'supervisorTimeoutMs' || key === 'verifierTimeoutMs' || key === 'evolveTimeoutMs' || key === 'selfTeamTimeoutMs' || key === 'reportAiTimeoutMs') {
        config[key] = Math.min(300000, Math.max(5000, value));
        continue;
      }
      config[key] = value;
      continue;
    }
    if (key === 'selfTeamMode') {
      if (!['subagents', 'off'].includes(value)) {
        warnings.push('selfTeamMode must be subagents or off; ignored');
        continue;
      }
      config.selfTeamMode = value;
      continue;
    }
    if (key === 'proxyMode') {
      if (!['direct', 'custom', 'local', 'provider'].includes(value)) {
        warnings.push('proxyMode must be direct, custom, local or provider; ignored');
        continue;
      }
      config.proxyMode = value;
      continue;
    }
    if (key === 'reportTheme') {
      if (!['auto', 'light', 'dark'].includes(value)) {
        warnings.push('reportTheme must be auto, light or dark; ignored');
        continue;
      }
      config.reportTheme = value;
      continue;
    }
    if (key === 'supervisorMode') {
      if (!['auto', 'deterministic', 'ai'].includes(value)) {
        warnings.push('supervisorMode must be auto, deterministic or ai; ignored');
        continue;
      }
      config.supervisorMode = value;
      continue;
    }
    if (STRING_KEYS.has(key)) {
      if ((key === 'lessonStore' || key === 'skillDir' || key === 'arsenalRoot' || key === 'proxyUrl' || key === 'proxyProviderUrl' || key === 'proxyNoProxy') && typeof value === 'string' && value.trim().length === 0) {
        config[key] = '';
        continue;
      }
      if (typeof value !== 'string' || value.trim().length === 0) {
        warnings.push(`${key} must be a non-empty string; ignored`);
        continue;
      }
      config[key] = value.trim();
      continue;
    }
    if (key === 'proxyPool') {
      if (!Array.isArray(value)) {
        warnings.push('proxyPool must be an array of proxy URLs; ignored');
        continue;
      }
      config.proxyPool = value.filter((entry) => typeof entry === 'string' && /^https?:\/\//iu.test(entry.trim())).map((entry) => entry.trim()).slice(0, 200);
      continue;
    }
    if (key === 'pythonPath') {
      if (value === null || value === undefined) {
        config.pythonPath = null;
      } else if (typeof value === 'string' && value.trim().length > 0) {
        config.pythonPath = value.trim();
      } else {
        warnings.push('pythonPath must be a non-empty string or null; ignored');
      }
      continue;
    }
    if (key === 'dnsResolvers') {
      if (!Array.isArray(value)) {
        warnings.push('dnsResolvers must be an array of "ip" or "ip:port" strings; ignored');
        continue;
      }
      const resolvers = [];
      for (const entry of value) {
        if (typeof entry === 'string' && /^[0-9a-fA-F:.\[\]]+(?::\d{1,5})?$/u.test(entry.trim())) {
          resolvers.push(entry.trim().replace(/^\[|\]$/gu, ''));
        } else {
          warnings.push(`dnsResolvers entry ${JSON.stringify(entry)} is not an ip[:port]; ignored`);
        }
      }
      config.dnsResolvers = resolvers;
      continue;
    }
    warnings.push(`unknown config key "${key}" ignored`);
  }

  return { config: applyEnvironment(config), warnings };
}

/** Environment overrides that are useful for tests and lab runs. */
function applyEnvironment(config) {
  if (process.env.PENTEST_OFFLINE === '1') return { ...config, offline: true };
  if (process.env.PENTEST_OFFLINE === '0' && config.offline === true) return { ...config, offline: false };
  return config;
}

/** Whether the plugin may run network operations at all. */
export function networkEnabled(config) {
  return config.enabled !== false;
}

/** One-line effective-config summary for the plugin log line. */
export function describeConfig(config) {
  return `enabled=${config.enabled} scope=${config.requireScope} offline=${config.offline} maxNodes=${config.maxNodes} viewNodeLimit=${config.viewNodeLimit} loop=${config.supervisorMode}`;
}
