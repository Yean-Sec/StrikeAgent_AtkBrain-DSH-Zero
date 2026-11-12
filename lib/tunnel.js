/**
 * Host-plane tunnel manager.
 *
 * Tunnels are spawned from the DSH Host process (not the model's bash), which
 * is the deliberate path to a real intranet. Every tunnel is scope-checked and
 * approval-gated by the caller; this module owns process lifetimes only.
 */
import { spawn } from 'node:child_process';
import { connect } from 'node:net';

import { sleep, shortHash } from './util.js';

const MAX_TUNNELS = 16;
const STDERR_RING = 40;

function validPort(port) {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/** Probe a local TCP port until it accepts or the deadline passes. */
async function waitForPort(port, timeoutMs, signal) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (signal?.aborted) throw signal.reason ?? new Error('aborted');
    const ok = await new Promise((resolve) => {
      const socket = connect({ host: '127.0.0.1', port });
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(value);
      };
      socket.setTimeout(500, () => finish(false));
      socket.once('connect', () => finish(true));
      socket.once('error', () => finish(false));
    });
    if (ok) return true;
    await sleep(120, signal);
  }
  return false;
}

/** Create the tunnel registry bound to one plugin instance. */
export function createTunnelManager({ config, logger } = {}) {
  const tunnels = new Map();
  let disposed = false;

  function record(id, entry) {
    entry.stderr = [];
    entry.createdAt = new Date().toISOString();
    tunnels.set(id, entry);
    return entry;
  }

  function capture(entry, stream) {
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      for (const line of String(chunk).split('\n')) {
        if (line.trim().length === 0) continue;
        entry.stderr.push(line.trim().slice(0, 500));
        if (entry.stderr.length > STDERR_RING) entry.stderr.shift();
      }
    });
  }

  function publicView(entry) {
    return {
      id: entry.id,
      type: entry.type,
      status: entry.status,
      localPort: entry.localPort,
      remote: entry.remote,
      via: entry.via ?? null,
      startedAt: entry.createdAt,
      stderr: entry.stderr.slice(-10),
    };
  }

  function register({ type, host, port, localPort, targetHost, targetPort, username, password, label }) {
    if (disposed) throw new Error('tunnel manager is disposed');
    if (tunnels.size >= MAX_TUNNELS) throw new Error(`tunnel cap reached (${MAX_TUNNELS})`);
    if (!['socks5', 'ssh-dynamic', 'ssh-local'].includes(type)) throw new Error(`unsupported tunnel type: ${type}`);
    const id = `tun_${shortHash(`${type}\u001f${host}\u001f${port}\u001f${Date.now()}\u001f${tunnels.size}`, 14)}`;
    const entry = {
      id,
      type,
      status: 'active',
      localPort: validPort(localPort) ? localPort : (type === 'socks5' ? port : undefined),
      remote: { host, port },
      via: { type: 'socks5', host: type === 'socks5' ? host : '127.0.0.1', port: type === 'socks5' ? port : localPort },
      label: label ?? `${type} ${host}:${port}`,
      child: null,
      stderr: [],
      username,
      password,
    };
    record(id, entry);
    return publicView(entry);
  }

  async function openSsh({ type, host, port = 22, user, keyPath, localPort, targetHost, targetPort, label, signal }) {
    if (disposed) throw new Error('tunnel manager is disposed');
    if (tunnels.size >= MAX_TUNNELS) throw new Error(`tunnel cap reached (${MAX_TUNNELS})`);
    if (process.platform === 'win32') throw new Error('ssh tunnels are not supported on this host; register an existing SOCKS5 proxy instead');
    if (!validPort(port)) throw new Error(`invalid ssh port: ${port}`);
    if (!validPort(localPort)) throw new Error('localPort is required (1024-65535) for ssh tunnels');
    if (localPort < 1024) throw new Error('localPort must be >= 1024');
    if (tunnels.has(localPort)) throw new Error(`localPort ${localPort} is already used by another tunnel`);
    if (type === 'ssh-local' && (!validPort(targetPort) || typeof targetHost !== 'string')) {
      throw new Error('ssh-local requires targetHost and targetPort');
    }

    const args = [
      '-N',
      '-o', 'ExitOnForwardFailure=yes',
      '-o', 'ServerAliveInterval=30',
      '-o', 'ServerAliveCountMax=3',
      '-o', 'StrictHostKeyChecking=accept-new',
      '-p', String(port),
      ...(keyPath ? ['-i', keyPath] : []),
      ...(type === 'ssh-dynamic'
        ? ['-D', `127.0.0.1:${localPort}`]
        : ['-L', `127.0.0.1:${localPort}:${targetHost}:${targetPort}`]),
      user ? `${user}@${host}` : host,
    ];
    const child = spawn('ssh', args, { stdio: ['ignore', 'ignore', 'pipe'], env: process.env });
    const id = `tun_${shortHash(`${type}\u001f${host}\u001f${port}\u001f${localPort}\u001f${Date.now()}`, 14)}`;
    const entry = {
      id,
      type,
      status: 'starting',
      localPort,
      remote: { host, port, user },
      via: { type: 'socks5', host: '127.0.0.1', port: localPort },
      label: label ?? `${type} ${host}:${port} -> 127.0.0.1:${localPort}`,
      child,
      stderr: [],
      createdAt: new Date().toISOString(),
      target: type === 'ssh-local' ? { host: targetHost, port: targetPort } : null,
    };
    record(id, entry);
    capture(entry, child.stderr);
    child.once('error', (error) => {
      entry.status = 'failed';
      entry.error = error instanceof Error ? error.message : String(error);
      logger?.warn?.(`atk-brain: tunnel ${id} failed: ${entry.error}`);
    });
    child.once('exit', (code, signalName) => {
      if (entry.status !== 'closed') entry.status = 'closed';
      entry.exit = { code, signal: signalName };
      logger?.info?.(`atk-brain: tunnel ${id} exited (${code ?? signalName ?? 'unknown'})`);
    });

    const ready = await waitForPort(localPort, config?.tunnelStartupTimeoutMs ?? 8000, signal);
    if (!ready || child.exitCode !== null) {
      entry.status = 'failed';
      try { child.kill('SIGTERM'); } catch { /* already gone */ }
      throw new Error(`tunnel did not become ready on 127.0.0.1:${localPort}${entry.stderr.length > 0 ? `: ${entry.stderr.slice(-3).join(' | ')}` : ''}`);
    }
    entry.status = 'active';
    return publicView(entry);
  }

  function get(id) {
    const entry = tunnels.get(id);
    if (entry === undefined || entry.status !== 'active') return undefined;
    return entry.via;
  }

  function getEntry(id) {
    return tunnels.get(id);
  }

  function close(id) {
    const entry = tunnels.get(id);
    if (entry === undefined) return false;
    if (entry.child !== null) {
      try { entry.child.kill('SIGTERM'); } catch { /* already gone */ }
    }
    entry.status = 'closed';
    return true;
  }

  function list() {
    return [...tunnels.values()]
      .filter((entry) => entry.status === 'active' || entry.status === 'starting')
      .map(publicView);
  }

  function dispose() {
    disposed = true;
    for (const entry of tunnels.values()) {
      if (entry.child !== null) {
        try { entry.child.kill('SIGTERM'); } catch { /* already gone */ }
      }
      entry.status = 'closed';
    }
  }

  return { register, openSsh, get, getEntry, close, list, dispose };
}
