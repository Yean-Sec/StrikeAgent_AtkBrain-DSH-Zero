/**
 * `atkbrain_proxy` — control the process-wide DSH egress proxy.
 */
import { TOOL_NAMES } from '../constants.js';
import { invalid } from '../util.js';
import { assertArgs, audit, optionalString, registerAtkTool, requireEnum } from './common.js';

const ACTIONS = ['status', 'enable', 'disable', 'set', 'test', 'rotate', 'pool', 'mode'];
const MODES = ['direct', 'custom', 'local', 'provider'];
const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'Inspect or control the DSH-wide HTTP(S) egress proxy.' },
    url: { type: 'string', description: 'Proxy URL for set/test/pool, e.g. http://127.0.0.1:7890.' },
    mode: { type: 'string', enum: MODES, description: 'direct, custom, local or provider.' },
    noProxy: { type: 'string', description: 'NO_PROXY host suffixes; loopback is always direct.' },
    failClosed: { type: 'boolean', description: 'Block external egress when no proxy is live.' },
    pool: { type: 'array', items: { type: 'string' }, description: 'Proxy URLs to add/use.' },
    providerUrl: { type: 'string', description: 'Opt-in provider list URL (text or JSON).' },
    localUrl: { type: 'string', description: 'Local proxy URL for mode=local.' },
    note: { type: 'string', description: 'Operator note.' },
  },
};

export function registerProxyTool(ctx, config, runtime, manager) {
  registerAtkTool(ctx, config, runtime, {
    name: TOOL_NAMES.proxy,
    callTitle: 'DSH egress proxy',
    description: 'Enable/disable and inspect the process-wide HTTP(S) proxy used by DSH model calls, web tools, child tools and AtkBrain network probes. Loopback stays direct; SOCKS5 is only for AtkBrain probes/tunnels. Credentials are masked in status.',
    parameters: PARAMETERS,
    timeoutMs: 300000,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (action === 'set') {
        if (args.url !== undefined) optionalString(args, 'url', { max: 2000 });
        if (args.mode !== undefined) requireEnum(args, 'mode', MODES);
      }
      if (action === 'mode') requireEnum(args, 'mode', MODES);
      if (action === 'test' && args.url !== undefined) optionalString(args, 'url', { max: 2000 });
      if (args.noProxy !== undefined) optionalString(args, 'noProxy', { max: 4000 });
      if (args.providerUrl !== undefined) optionalString(args, 'providerUrl', { max: 4000 });
      if (args.localUrl !== undefined) optionalString(args, 'localUrl', { max: 2000 });
      if (args.pool !== undefined) {
        if (!Array.isArray(args.pool) || args.pool.some((entry) => typeof entry !== 'string')) invalid('pool must be an array of proxy URLs');
        if (args.pool.length > 200) invalid('pool is limited to 200 entries');
      }
      return action;
    },
    async run({ args }) {
      let result;
      if (args.action === 'status') {
        result = manager.status();
        return {
          summary: `Proxy ${result.enabled ? 'enabled' : 'disabled'} (${result.mode}); ${result.blocked ? 'BLOCKED fail-closed' : result.active ? 'active' : 'inactive'}; exit ${result.exitIp ?? 'unknown'}${result.directIp ? ` / direct ${result.directIp}` : ''}${result.error ? `; error: ${result.error}` : ''}. Loopback stays direct.`,
          ops: [],
          details: result,
        };
      }
      if (args.action === 'enable') {
        result = await manager.enable({ url: args.url, mode: args.mode, noProxy: args.noProxy, failClosed: args.failClosed });
        return {
          summary: `Proxy enable requested: ${result.enabled ? 'enabled' : 'disabled'} ${result.mode}, active=${result.active}, blocked=${result.blocked}, exit=${result.exitIp ?? 'unknown'}.${result.error ? ` ${result.error}` : ''}`,
          ops: [audit(TOOL_NAMES.proxy, 'proxy.enable', result.mode, `${result.active ? 'active' : 'blocked'} ${result.exitIp ?? ''}`.slice(0, 200), [])],
          details: result,
        };
      }
      if (args.action === 'disable') {
        result = await manager.disable();
        return {
          summary: `Proxy disabled; DSH egress is direct again (loopback remains direct).`,
          ops: [audit(TOOL_NAMES.proxy, 'proxy.disable', 'egress', 'direct', [])],
          details: result,
        };
      }
      if (args.action === 'test') {
        result = await manager.test(args.url);
        return {
          summary: result.ok
            ? `Proxy test OK: ${result.proxy}, exit ${result.proxyIp}${result.directIp ? `, direct ${result.directIp}` : ''}, masked=${result.masked === null ? 'unknown' : result.masked}.`
            : `Proxy test failed: ${result.error ?? 'unknown error'}.`,
          ops: [],
          details: result,
        };
      }
      if (args.action === 'rotate') {
        result = await manager.rotate();
        return {
          summary: `Proxy rotated: active=${result.active}, exit=${result.exitIp ?? 'unknown'}${result.error ? `; ${result.error}` : ''}.`,
          ops: [audit(TOOL_NAMES.proxy, 'proxy.rotate', result.mode, result.exitIp ?? 'unknown', [])],
          details: result,
        };
      }
      result = await manager.handle(args.action, args);
      return {
        summary: `Proxy ${args.action}: ${result.enabled ? 'enabled' : 'disabled'}, ${result.mode}, active=${result.active}, blocked=${result.blocked}${result.error ? `; ${result.error}` : ''}.`,
        ops: [audit(TOOL_NAMES.proxy, `proxy.${args.action}`, args.url ? manager.mask(args.url) : 'config', result.mode ?? '', [])],
        details: result,
      };
    },
  });
}
