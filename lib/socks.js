/**
 * Minimal SOCKS5 client (RFC 1928 + RFC 1929 username/password auth).
 *
 * This is the lowest-level network primitive of the probe layer, so it also
 * owns the shared offline / loopback guards used by every other network module.
 * Nothing here imports a DSH package: only Node built-ins and local helpers.
 */
import net from 'node:net';

import { parseIp } from './cidr.js';
import { InputError, invalid } from './util.js';

const SOCKS_VERSION = 0x05;
const AUTH_VERSION = 0x01;
const MAX_DOMAIN_LENGTH = 255;

/** Whether network egress is globally disabled (`PENTEST_OFFLINE=1` / config). */
export function isOfflineMode(options) {
  if (process.env.PENTEST_OFFLINE === '1') return true;
  if (typeof options?.offline === 'boolean') return options.offline;
  return false;
}

/** Whether a hostname or IP literal is loopback-only. */
export function isLoopbackHost(host) {
  const text = String(host ?? '').trim().toLowerCase();
  if (text.length === 0) return false;
  const bare = text.startsWith('[') && text.endsWith(']') ? text.slice(1, -1) : text;
  const parsed = parseIp(bare);
  if (parsed !== undefined) {
    if (parsed.version === 4) return parsed.canonical.startsWith('127.');
    if (parsed.mapped !== undefined) return parsed.mapped.startsWith('127.');
    return parsed.value === 1n || parsed.value === 0n;
  }
  const name = bare.replace(/\.+$/u, '');
  return name === 'localhost' || name === 'localhost.localdomain' || name.endsWith('.localhost');
}

/**
 * Throw before opening any socket when offline mode is active and `host` is
 * not a loopback target. Callers invoke this at the top of every network entry
 * point so no egress (not even a DNS query) can start while offline.
 */
export function assertNetworkAllowed(host, options, action = 'connect') {
  if (!isOfflineMode(options)) return;
  if (isLoopbackHost(host)) return;
  throw new InputError(
    `offline mode: refusing to ${action} to non-loopback host "${host}" (PENTEST_OFFLINE=1)`,
    'ATK_OFFLINE',
  );
}

/** An Error carrying the conventional `ETIMEDOUT` code. */
export function timeoutError(message) {
  const error = new Error(message);
  error.name = 'TimeoutError';
  error.code = 'ETIMEDOUT';
  return error;
}

/** Whether an error represents a timeout (own or platform-generated). */
export function isTimeoutError(error) {
  const code = String(error?.code ?? '').toUpperCase();
  if (code === 'ETIMEDOUT' || code === 'ETIMEOUT' || code === 'ATK_TIMEOUT') return true;
  if (error?.name === 'TimeoutError') return true;
  return /timed out|timeout/i.test(String(error?.message ?? ''));
}

/** Whether an error was caused by an aborted signal. */
export function isAbortError(error, signal) {
  if (signal?.aborted === true) return true;
  if (error?.name === 'AbortError') return true;
  return String(error?.code ?? '').toUpperCase() === 'ABORT_ERR';
}

/** Error used for an aborted operation. */
export function abortError(signal) {
  if (signal?.reason instanceof Error) return signal.reason;
  const error = new Error('operation aborted');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortError(signal);
}

/**
 * Read exactly `length` bytes from a socket while retaining any look-ahead
 * bytes, so a protocol upgrade (TLS/HTTP over SOCKS) never loses data.
 */
class SocketReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.pending = [];
    this.failure = undefined;
    this.detached = false;
    this.onData = (chunk) => {
      if (this.detached) return;
      this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
      this.pump();
    };
    this.onError = (error) => this.fail(error);
    this.onEnd = () => this.fail(new InputError('SOCKS5 proxy closed the connection unexpectedly', 'ATK_SOCKS'));
    socket.on('data', this.onData);
    socket.on('error', this.onError);
    socket.on('end', this.onEnd);
  }

  readExact(length, label = 'bytes') {
    if (!Number.isInteger(length) || length < 0) throw new Error(`invalid SOCKS5 read length for ${label}`);
    return new Promise((resolve, reject) => {
      if (this.failure !== undefined) {
        reject(this.failure);
        return;
      }
      if (length === 0) {
        resolve(Buffer.alloc(0));
        return;
      }
      if (this.buffer.length >= length) {
        const out = Buffer.from(this.buffer.subarray(0, length));
        this.buffer = this.buffer.subarray(length);
        resolve(out);
        return;
      }
      this.pending.push({ length, label, resolve, reject });
    });
  }

  pump() {
    while (this.pending.length > 0) {
      const next = this.pending[0];
      if (this.failure !== undefined) {
        this.pending.shift();
        next.reject(this.failure);
        continue;
      }
      if (this.buffer.length < next.length) break;
      this.pending.shift();
      const out = Buffer.from(this.buffer.subarray(0, next.length));
      this.buffer = this.buffer.subarray(next.length);
      next.resolve(out);
    }
    if (this.failure !== undefined) {
      for (const entry of this.pending.splice(0)) entry.reject(this.failure);
    }
  }

  fail(error) {
    if (this.failure !== undefined) return;
    this.failure = error instanceof Error ? error : new Error(String(error));
    this.pump();
  }

  /** Stop observing the socket, pause it, and hand back unread bytes. */
  detach() {
    this.detached = true;
    this.socket.pause();
    this.socket.removeListener('data', this.onData);
    this.socket.removeListener('error', this.onError);
    this.socket.removeListener('end', this.onEnd);
    const leftover = this.buffer;
    this.buffer = Buffer.alloc(0);
    return leftover;
  }
}

/** Connect a plain TCP socket with timeout and abort support. */
function connectSocket(host, port, timeoutMs, signal) {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = net.connect({ host, port });
    const finish = (handler, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener?.('abort', onAbort);
      socket.removeListener('error', onError);
      socket.removeListener('connect', onConnect);
      handler(value);
    };
    const timer = setTimeout(() => {
      finish(reject, timeoutError(`SOCKS5 proxy connection to ${host}:${port} timed out after ${timeoutMs}ms`));
      socket.destroy();
    }, timeoutMs);
    function onError(error) {
      finish(reject, error);
    }
    function onConnect() {
      finish(resolve, socket);
    }
    function onAbort() {
      finish(reject, abortError(signal));
      socket.destroy();
    }
    socket.once('error', onError);
    socket.once('connect', onConnect);
    signal?.addEventListener?.('abort', onAbort, { once: true });
  });
}

/** Encode a SOCKS5 destination address (ATYP + address bytes). */
function encodeAddress(host) {
  const version = net.isIP(host);
  if (version === 4) {
    const parsed = parseIp(host);
    const value = Number(parsed.value);
    const out = Buffer.alloc(5);
    out[0] = 0x01;
    out.writeUInt32BE(value >>> 0, 1);
    return out;
  }
  if (version === 6) {
    const parsed = parseIp(host);
    const out = Buffer.alloc(17);
    out[0] = 0x04;
    let value = parsed.value;
    for (let index = 15; index >= 0; index -= 1) {
      out[1 + index] = Number(value & 0xffn);
      value >>= 8n;
    }
    return out;
  }
  const name = Buffer.from(host, 'utf8');
  if (name.length === 0) invalid('SOCKS5 target host is empty');
  if (name.length > MAX_DOMAIN_LENGTH) invalid(`SOCKS5 target host exceeds ${MAX_DOMAIN_LENGTH} bytes`);
  return Buffer.concat([Buffer.from([0x03, name.length]), name]);
}

const REPLY_MESSAGES = Object.freeze({
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
});

/**
 * A target-level SOCKS5 CONNECT failure (refused/unreachable target), as
 * opposed to a proxy/handshake/authentication failure. Network probes map this
 * to a per-port state instead of aborting the whole scan.
 */
export class SocksConnectError extends Error {
  constructor(replyCode, reason) {
    super(`SOCKS5 connect failed: ${reason}`);
    this.name = 'SocksConnectError';
    this.code = 'ATK_SOCKS_CONNECT';
    this.socksReply = replyCode;
  }
}

function replyError(code) {
  const reason = REPLY_MESSAGES[code] ?? `unknown reply code 0x${code.toString(16).padStart(2, '0')}`;
  return new SocksConnectError(code, reason);
}

/**
 * Open a TCP connection to `target` through a SOCKS5 proxy.
 *
 * @param {{host:string,port:number,username?:string,password?:string}} proxy
 * @param {{host:string,port:number}} target
 * @param {{timeoutMs?:number,signal?:AbortSignal,offline?:boolean}} [options]
 * @returns {Promise<import('node:net').Socket>} connected, paused socket
 */
export async function connectViaSocks5(proxy, target, options = {}) {
  const proxyHost = String(proxy?.host ?? '').trim();
  const proxyPort = Number(proxy?.port);
  const targetHost = String(target?.host ?? '').trim();
  const targetPort = Number(target?.port);
  if (proxyHost.length === 0) invalid('SOCKS5 proxy host is required');
  if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
    invalid('SOCKS5 proxy port must be an integer between 1 and 65535');
  }
  if (targetHost.length === 0) invalid('SOCKS5 target host is required');
  if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
    invalid('SOCKS5 target port must be an integer between 1 and 65535');
  }
  assertNetworkAllowed(proxyHost, options, 'connect to SOCKS5 proxy');
  assertNetworkAllowed(targetHost, options, 'reach SOCKS5 target');

  const timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0 ? Math.floor(options.timeoutMs) : 8000;
  const { signal } = options;
  throwIfAborted(signal);

  const username = typeof proxy.username === 'string' && proxy.username.length > 0 ? proxy.username : undefined;
  const password = typeof proxy.password === 'string' ? proxy.password : undefined;
  if (username === undefined && password !== undefined) invalid('SOCKS5 password requires a username');

  const socket = await connectSocket(proxyHost, proxyPort, timeoutMs, signal);
  const reader = new SocketReader(socket);

  const abortAndFail = (error) => {
    reader.fail(error);
    socket.destroy();
  };
  const onAbort = () => abortAndFail(abortError(signal));
  signal?.addEventListener?.('abort', onAbort, { once: true });

  const handshake = (async () => {
    const methods = username !== undefined ? [0x00, 0x02] : [0x00];
    socket.write(Buffer.from([SOCKS_VERSION, methods.length, ...methods]));
    const greeting = await reader.readExact(2, 'greeting');
    if (greeting[0] !== SOCKS_VERSION) {
      throw new InputError(`SOCKS5 proxy returned unsupported version 0x${greeting[0].toString(16)}`, 'ATK_SOCKS');
    }
    const method = greeting[1];
    if (method === 0xff) {
      throw new InputError('SOCKS5 proxy rejected all offered authentication methods', 'ATK_SOCKS');
    }
    if (method === 0x02) {
      if (username === undefined) {
        throw new InputError('SOCKS5 proxy requires username/password authentication but none was supplied', 'ATK_SOCKS_AUTH');
      }
      const userBytes = Buffer.from(username, 'utf8');
      const passwordBytes = Buffer.from(password ?? '', 'utf8');
      if (userBytes.length === 0 || userBytes.length > 255) invalid('SOCKS5 username must be 1-255 bytes');
      if (passwordBytes.length > 255) invalid('SOCKS5 password must be at most 255 bytes');
      socket.write(Buffer.concat([
        Buffer.from([AUTH_VERSION, userBytes.length]),
        userBytes,
        Buffer.from([passwordBytes.length]),
        passwordBytes,
      ]));
      const auth = await reader.readExact(2, 'authentication reply');
      if (auth[0] !== AUTH_VERSION) {
        throw new InputError('SOCKS5 proxy returned an invalid authentication version', 'ATK_SOCKS_AUTH');
      }
      if (auth[1] !== 0x00) {
        throw new InputError(`SOCKS5 authentication failed (status 0x${auth[1].toString(16)})`, 'ATK_SOCKS_AUTH');
      }
    } else if (method !== 0x00) {
      throw new InputError(`SOCKS5 proxy selected unsupported authentication method 0x${method.toString(16)}`, 'ATK_SOCKS');
    }

    const portBytes = Buffer.alloc(2);
    portBytes.writeUInt16BE(targetPort, 0);
    socket.write(Buffer.concat([Buffer.from([SOCKS_VERSION, 0x01, 0x00]), encodeAddress(targetHost), portBytes]));

    const head = await reader.readExact(4, 'connect reply');
    if (head[0] !== SOCKS_VERSION) throw new InputError('SOCKS5 proxy returned an invalid connect reply version', 'ATK_SOCKS');
    if (head[1] !== 0x00) throw replyError(head[1]);
    const addressType = head[3];
    let addressLength;
    if (addressType === 0x01) addressLength = 4;
    else if (addressType === 0x04) addressLength = 16;
    else if (addressType === 0x03) {
      const lengthByte = await reader.readExact(1, 'bound address length');
      addressLength = 1 + lengthByte[0];
    } else {
      throw new InputError(`SOCKS5 proxy returned unsupported bound address type 0x${addressType.toString(16)}`, 'ATK_SOCKS');
    }
    await reader.readExact(addressLength + 2, 'bound address');
  })();

  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = timeoutError(`SOCKS5 handshake with ${proxyHost}:${proxyPort} timed out after ${timeoutMs}ms`);
      abortAndFail(error);
      reject(error);
    }, timeoutMs);
  });

  try {
    await Promise.race([handshake, timeout]);
  } catch (error) {
    socket.destroy();
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener?.('abort', onAbort);
  }

  const leftover = reader.detach();
  if (leftover.length > 0) socket.unshift(leftover);
  return socket;
}
