/**
 * Local SOCKS5 server used to exercise the SOCKS client, TCP/HTTP/TLS probes
 * over a pivot, and handshake timeout/authentication failures.
 *
 * Binds 127.0.0.1:11080 by default. Supports no-auth and username/password
 * (RFC 1929). Requests to port 9 stall without a reply so tests can assert the
 * client-side handshake timeout; everything else is tunneled to the requested
 * target (in tests, the local HTTP/TLS fixture on loopback).
 */
import net from 'node:net';

const SOCKS_VERSION = 0x05;
const AUTH_VERSION = 0x01;
const STALL_PORT = 9;

class Reader {
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
    this.onClose = () => this.fail(new Error('SOCKS client closed the connection'));
    socket.on('data', this.onData);
    socket.on('error', this.onError);
    socket.on('close', this.onClose);
  }

  readExact(length) {
    return new Promise((resolve, reject) => {
      if (this.failure !== undefined) {
        reject(this.failure);
        return;
      }
      if (this.buffer.length >= length) {
        const out = Buffer.from(this.buffer.subarray(0, length));
        this.buffer = this.buffer.subarray(length);
        resolve(out);
        return;
      }
      this.pending.push({ length, resolve, reject });
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
      if (this.buffer.length < next.length) return;
      this.pending.shift();
      const out = Buffer.from(this.buffer.subarray(0, next.length));
      this.buffer = this.buffer.subarray(next.length);
      next.resolve(out);
    }
  }

  fail(error) {
    if (this.failure !== undefined) return;
    this.failure = error instanceof Error ? error : new Error(String(error));
    this.pump();
  }

  detach() {
    this.detached = true;
    this.socket.pause();
    this.socket.removeListener('data', this.onData);
    this.socket.removeListener('error', this.onError);
    this.socket.removeListener('close', this.onClose);
    const leftover = this.buffer;
    this.buffer = Buffer.alloc(0);
    return leftover;
  }
}

function socksReply(code, addressType = 0x01) {
  return Buffer.from([SOCKS_VERSION, code, 0x00, addressType, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

async function readAddress(reader, addressType) {
  if (addressType === 0x01) {
    const raw = await reader.readExact(4);
    return [...raw].join('.');
  }
  if (addressType === 0x04) {
    const raw = await reader.readExact(16);
    const groups = [];
    for (let index = 0; index < 8; index += 1) groups.push(raw.readUInt16BE(index * 2).toString(16));
    return groups.join(':');
  }
  if (addressType === 0x03) {
    const lengthByte = await reader.readExact(1);
    const raw = await reader.readExact(lengthByte[0]);
    return raw.toString('utf8');
  }
  throw new Error(`unsupported SOCKS5 address type 0x${Number(addressType).toString(16)}`);
}

function handleClient(socket, config) {
  const reader = new Reader(socket);
  const connection = {
    target: null,
    method: 'none',
    authenticated: false,
    at: Date.now(),
    closed: false,
  };
  config.connections.push(connection);
  socket.once('close', () => {
    connection.closed = true;
  });

  const run = async () => {
    // Greeting -----------------------------------------------------------------
    const greetingHead = await reader.readExact(2);
    if (greetingHead[0] !== SOCKS_VERSION) throw new Error('bad SOCKS version');
    const methodCount = greetingHead[1];
    const methods = await reader.readExact(methodCount);
    const offered = new Set([...methods]);
    let method = 0xff;
    if (config.requireAuth && offered.has(0x02)) method = 0x02;
    else if (!config.requireAuth && offered.has(0x00)) method = 0x00;
    else if (offered.has(0x02)) method = 0x02;
    socket.write(Buffer.from([SOCKS_VERSION, method]));
    if (method === 0xff) {
      socket.destroy();
      return;
    }
    connection.method = method === 0x02 ? 'username/password' : 'none';

    // Optional username/password authentication --------------------------------
    if (method === 0x02) {
      const authHead = await reader.readExact(2);
      if (authHead[0] !== AUTH_VERSION) throw new Error('bad auth version');
      const username = (await reader.readExact(authHead[1])).toString('utf8');
      const passwordLength = (await reader.readExact(1))[0];
      const password = (await reader.readExact(passwordLength)).toString('utf8');
      const valid = config.users.some((user) => user.username === username && (user.password ?? '') === password);
      socket.write(Buffer.from([AUTH_VERSION, valid ? 0x00 : 0x01]));
      if (!valid) {
        socket.destroy();
        return;
      }
      connection.authenticated = true;
      connection.user = username;
    }

    // CONNECT request ----------------------------------------------------------
    const head = await reader.readExact(4);
    if (head[0] !== SOCKS_VERSION) throw new Error('bad request version');
    if (head[1] !== 0x01) {
      socket.write(socksReply(0x07));
      socket.destroy();
      return;
    }
    const host = await readAddress(reader, head[3]);
    const port = (await reader.readExact(2)).readUInt16BE(0);
    connection.target = { host, port };
    if (port === STALL_PORT) {
      // Deliberate stall: used to exercise the client handshake timeout.
      return;
    }
    const upstream = net.connect({ host, port });
    upstream.once('error', () => {
      socket.write(socksReply(0x05));
      socket.destroy();
    });
    upstream.once('connect', () => {
      if (socket.destroyed) {
        upstream.destroy();
        return;
      }
      socket.write(socksReply(0x00));
      const leftover = reader.detach();
      if (leftover.length > 0) upstream.write(leftover);
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
    upstream.on('close', () => {
      if (!socket.destroyed) socket.destroy();
    });
  };

  run().catch(() => {
    try {
      socket.destroy();
    } catch {
      // ignore
    }
  });
}

/**
 * Start the SOCKS5 fixture.
 * @param {{host?:string,port?:number,users?:{username:string,password?:string}[],requireAuth?:boolean}} [options]
 */
export async function startSocksFixture(options = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 11080;
  const users = Array.isArray(options.users) && options.users.length > 0
    ? options.users
    : [{ username: 'atkuser', password: 'atkpass' }];
  const requireAuth = options.requireAuth === true;
  const connections = [];
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    handleClient(socket, { users, requireAuth, connections });
  });
  server.on('error', () => {});
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.removeListener('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.removeListener('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
  let closed = false;
  const boundPort = server.address()?.port ?? port;
  return {
    server,
    host,
    port: boundPort,
    url: `socks5://${host}:${boundPort}`,
    users,
    connections,
    close: () => new Promise((resolve) => {
      if (closed) {
        resolve();
        return;
      }
      closed = true;
      for (const socket of sockets) {
        try {
          socket.destroy();
        } catch {
          // ignore
        }
      }
      try {
        server.close(() => resolve());
      } catch {
        resolve();
      }
    }),
  };
}
