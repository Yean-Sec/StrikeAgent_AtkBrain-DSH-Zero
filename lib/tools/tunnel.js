/**
 * `atkbrain_tunnel` — open SSH dynamic/local tunnels or register an existing
 * SOCKS5 proxy. Tunnels are spawned by the Host process and cleaned up when
 * the plugin unloads.
 */
import { TOOL_NAMES } from '../constants.js';
import { canonicalIp } from '../cidr.js';
import { canonicalHost } from '../scope.js';
import { invalid, nodeId } from '../util.js';
import { link, pivotNodeOp, ref } from './build.js';
import {
  assertArgs,
  audit,
  optionalInteger,
  optionalString,
  registerAtkTool,
  requestApproval,
  requireEnum,
  requireString,
  scopeGuard,
} from './common.js';

const ACTIONS = ['open', 'close', 'list', 'register'];
const TYPES = ['ssh-dynamic', 'ssh-local', 'socks5'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'open an SSH tunnel, register an existing SOCKS5 proxy, close one, or list active tunnels.' },
    id: { type: 'string', description: 'Tunnel id for action=close.' },
    type: { type: 'string', enum: TYPES, description: 'ssh-dynamic (SOCKS5 on localPort), ssh-local (local forward), or socks5 (register an existing proxy).' },
    host: { type: 'string', description: 'SSH jump host or SOCKS5 proxy host.' },
    port: { type: 'integer', description: 'SSH port (default 22) or SOCKS5 proxy port.' },
    user: { type: 'string', description: 'SSH username; keys/agent only, never a password.' },
    keyPath: { type: 'string', description: 'Optional private-key path for ssh.' },
    localPort: { type: 'integer', description: 'Local loopback port to bind (>=1024). Required for SSH tunnels.' },
    targetHost: { type: 'string', description: 'ssh-local forward target host.' },
    targetPort: { type: 'integer', description: 'ssh-local forward target port.' },
    viaAccessId: { type: 'string', description: 'Optional access node id that provides this pivot.' },
    label: { type: 'string', description: 'Human label for the pivot node.' },
  },
};

export function registerTunnelTool(ctx, config, deps) {
  registerAtkTool(ctx, config, deps, {
    name: TOOL_NAMES.tunnel,
    callTitle: 'Open pivot tunnel',
    description: 'Create an authorized pivot into an internal network: SSH dynamic SOCKS5, SSH local forward, or register an existing SOCKS5 proxy. The tunnel runs in the DSH Host process and is scope-checked and approval-gated. Pass its id as `via` to atkbrain_probe.',
    parameters: PARAMETERS,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (action === 'close') {
        requireString(args, 'id', { max: 100 });
        return true;
      }
      if (action === 'list') return true;
      const type = requireEnum(args, 'type', TYPES);
      const host = requireString(args, 'host', { max: 300 });
      if (host.length > 0) {
        const ip = canonicalIp(host);
        if (ip === undefined && canonicalHost(host).length === 0) invalid('host must be a valid hostname or IP');
      }
      if (args.port !== undefined) optionalInteger(args, 'port', { min: 1, max: 65535 });
      if (args.localPort !== undefined) optionalInteger(args, 'localPort', { min: 1024, max: 65535 });
      if (type === 'ssh-dynamic' || type === 'ssh-local') {
        if (args.localPort === undefined) invalid('localPort (>=1024) is required for SSH tunnels');
        if (args.keyPath !== undefined) optionalString(args, 'keyPath', { max: 1000 });
        if (type === 'ssh-local') {
          requireString(args, 'targetHost', { max: 300 });
          if (args.targetPort === undefined) invalid('targetPort is required for ssh-local');
          optionalInteger(args, 'targetPort', { min: 1, max: 65535 });
        }
      }
      if (type === 'socks5' && args.port === undefined) invalid('port is required for a SOCKS5 proxy');
      return true;
    },
    async run({ args, state, exec, config: cfg, deps: runtime }) {
      if (cfg.allowTunnels !== true) invalid('tunnels are disabled in the plugin configuration (allowTunnels: false)');

      if (args.action === 'list') {
        const active = runtime.tunnels.list();
        const pivots = Object.values(state.nodes).filter((node) => node.kind === 'pivot');
        return {
          summary: `${active.length} active tunnel(s); ${pivots.length} pivot node(s) recorded.`
            + (active.length > 0 ? ` Active: ${active.map((tunnel) => `${tunnel.id} ${tunnel.type} -> ${tunnel.remote.host}:${tunnel.remote.port}`).join('; ')}.` : ''),
          ops: [],
          details: { active, pivots: pivots.map((node) => ({ id: node.id, label: node.label, status: node.status, attrs: node.attrs })) },
        };
      }

      if (args.action === 'close') {
        const entry = runtime.tunnels.getEntry(args.id);
        if (entry === undefined) invalid(`tunnel "${args.id}" is not known`);
        runtime.tunnels.close(args.id);
        const pivot = Object.values(state.nodes).find((node) => node.kind === 'pivot' && (node.attrs?.tunnelId === args.id || node.key.includes(args.id)));
        const ops = [];
        if (pivot !== undefined) {
          ops.push({
            op: 'node.upsert',
            kind: 'pivot',
            key: pivot.key,
            label: pivot.label,
            attrs: { ...(pivot.attrs ?? {}), closedAt: new Date().toISOString() },
            status: 'closed',
            confidence: pivot.confidence,
          });
        }
        ops.push(audit(TOOL_NAMES.tunnel, 'tunnel.close', args.id, 'closed', []));
        return { summary: `Tunnel ${args.id} closed.${pivot ? ` Pivot node ${pivot.id} marked closed.` : ''}`, ops, details: { id: args.id, closed: true } };
      }

      // open / register
      const host = canonicalIp(args.host) ?? canonicalHost(args.host);
      const port = args.port ?? (args.type === 'socks5' ? 1080 : 22);
      let approval = { approved: true, outcome: 'not-required', approvalId: null };

      if (args.type !== 'socks5') {
        const target = canonicalIp(host) !== undefined ? { type: 'ip', ip: host } : { type: 'host', host };
        await scopeGuard({ deps: runtime, state, config: cfg, target, signal: exec.signal, resolve: true });
        approval = await requestApproval({
          ctx,
          exec,
          config: cfg,
          enabled: cfg.requireTunnelApproval === true,
          reason: `Open a ${args.type} pivot via ${host}:${port} (localPort ${args.localPort ?? 'none'}).`,
          displayReason: `AtkBrain wants to open a ${args.type} tunnel through ${host}:${port}. This is the host-plane path into the internal network.`,
        });
      }

      if (args.viaAccessId !== undefined) {
        const access = state.nodes[args.viaAccessId];
        if (access === undefined || access.kind !== 'access') {
          invalid(`viaAccessId "${args.viaAccessId}" is not an access node; record the foothold first or omit viaAccessId for an operator-provided proxy`);
        }
      }
      let tunnel;
      if (args.type === 'socks5') {
        tunnel = runtime.tunnels.register({
          type: 'socks5',
          host,
          port,
          localPort: args.localPort ?? port,
          label: args.label,
        });
      } else {
        tunnel = await runtime.tunnels.openSsh({
          type: args.type,
          host,
          port,
          user: args.user,
          keyPath: args.keyPath,
          localPort: args.localPort,
          targetHost: args.targetHost,
          targetPort: args.targetPort,
          label: args.label,
          signal: exec.signal,
        });
      }

      const targetKey = args.type === 'ssh-local' && args.targetHost ? canonicalHost(args.targetHost) : host;
      const pivot = pivotNodeOp(state, {
        accessId: args.viaAccessId,
        targetKey,
        transport: args.type,
        localEndpoint: `127.0.0.1:${tunnel.localPort ?? port}`,
        remoteEndpoint: `${host}:${port}`,
        verified: false,
        tunnelId: tunnel.id,
        label: args.label ?? tunnel.label,
      });
      const ops = [pivot, audit(TOOL_NAMES.tunnel, 'tunnel.open', `${host}:${port}`, `${tunnel.id} (${args.type})`, [])];
      if (args.viaAccessId !== undefined) {
        const access = state.nodes[args.viaAccessId];
        ops.push(link(ref('access', access.key), ref('pivot', pivot.key), 'pivots_to', { confidence: 0.7, attrs: { tunnelId: tunnel.id } }));
      }
      if (args.type === 'ssh-local' && args.targetHost) {
        ops.push(link(ref('pivot', pivot.key), ref('host', canonicalHost(args.targetHost)), 'pivots_to', { confidence: 0.6, attrs: { transport: 'ssh-local' } }));
      }
      const pivotId = nodeId('pivot', pivot.key);
      const summary = [
        `Tunnel ${tunnel.id} is ${tunnel.status}: ${args.type} ${host}:${port} -> 127.0.0.1:${tunnel.localPort ?? port}.`,
        args.type === 'socks5' ? 'Use it with atkbrain_probe via=<id>.' : `Approval: ${approval.outcome}. Use it with atkbrain_probe via=${tunnel.id}.`,
        'Verify reachability with a far-side nonce before marking the pivot verified.',
      ].join(' ');
      return {
        summary,
        ops,
        details: { tunnel, approval, pivot: { key: pivot.key, id: pivotId, label: pivot.label } },
      };
    },
  });
}
