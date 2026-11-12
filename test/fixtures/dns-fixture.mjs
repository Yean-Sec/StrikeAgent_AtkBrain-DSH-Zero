/**
 * Local UDP DNS server used by the wildcard/DNS integration tests.
 *
 * Binds 127.0.0.1:15353 by default: mDNS already owns UDP 5353 on macOS, so the
 * fixture stays clear of it. It implements just enough of the DNS wire format
 * (A/AAAA/CNAME/NS/SOA questions, name compression in answers) to exercise the
 * production resolver without any external network traffic.
 *
 * Behaviour for zone `wildcard.test` (configurable):
 *   - apex            -> NS + SOA + A
 *   - real.<zone>     -> specific A (192.0.2.7)
 *   - cname.<zone>    -> CNAME edge.cdn.example.net + A 192.0.2.70
 *   - servfail.<zone> -> SERVFAIL
 *   - drop.<zone>     -> no response (timeout)
 *   - empty.<zone>    -> NOERROR, no answers
 *   - any other label -> wildcard A 192.0.2.66
 *   - anything else   -> NXDOMAIN (this is the guard answer for *.invalid)
 */
import dgram from 'node:dgram';

const TYPE = Object.freeze({ A: 1, NS: 2, CNAME: 5, SOA: 6, AAAA: 28 });
const RCODE = Object.freeze({ NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3 });

/** Encode a DNS name without compression. */
function encodeName(name) {
  const labels = String(name).replace(/\.+$/u, '').split('.').filter((label) => label.length > 0);
  const parts = [];
  for (const label of labels) {
    const bytes = Buffer.from(label, 'ascii');
    if (bytes.length === 0 || bytes.length > 63) throw new Error(`invalid DNS label "${label}"`);
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function ipv4Bytes(address) {
  const parts = address.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    throw new Error(`invalid IPv4 address "${address}"`);
  }
  return Buffer.from(parts);
}

function ipv6Bytes(groups) {
  const buffer = Buffer.alloc(16);
  groups.forEach((group, index) => buffer.writeUInt16BE(group, index * 2));
  return buffer;
}

function soaRdata(zone) {
  const fixed = Buffer.alloc(20);
  fixed.writeUInt32BE(1, 0);
  fixed.writeUInt32BE(3600, 4);
  fixed.writeUInt32BE(600, 8);
  fixed.writeUInt32BE(86400, 12);
  fixed.writeUInt32BE(60, 16);
  return Buffer.concat([encodeName(`ns1.${zone}`), encodeName(`hostmaster.${zone}`), fixed]);
}

function answer(type, rdata) {
  return { type, rdata };
}

/** Parse the single question of a DNS request. */
function parseQuery(message) {
  if (message.length < 12) return null;
  const id = message.readUInt16BE(0);
  const questionCount = message.readUInt16BE(4);
  if (questionCount < 1) return null;
  let offset = 12;
  const labels = [];
  while (offset < message.length) {
    const length = message[offset];
    offset += 1;
    if (length === 0) break;
    if ((length & 0xc0) !== 0) return null;
    if (offset + length > message.length) return null;
    labels.push(message.toString('ascii', offset, offset + length));
    offset += length;
  }
  if (offset + 4 > message.length) return null;
  const type = message.readUInt16BE(offset);
  offset += 2;
  offset += 2; // qclass
  return { id, name: labels.join('.').toLowerCase(), type, questionBytes: message.subarray(12, offset) };
}

function buildResponse(request, result) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(request.id, 0);
  header.writeUInt16BE(0x8180 | (result.rcode ?? 0), 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(result.answers.length, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  const records = result.answers.map((record) => {
    const fixed = Buffer.alloc(12);
    fixed.writeUInt16BE(0xc00c, 0); // pointer back to the question name
    fixed.writeUInt16BE(record.type, 2);
    fixed.writeUInt16BE(1, 4); // IN
    fixed.writeUInt32BE(60, 6); // TTL
    fixed.writeUInt16BE(record.rdata.length, 10);
    return Buffer.concat([fixed, record.rdata]);
  });
  return Buffer.concat([header, request.questionBytes, ...records]);
}

function resolveQuery(zone, wildcardIp, name, type) {
  const empty = { rcode: RCODE.NOERROR, answers: [] };
  const nxdomain = { rcode: RCODE.NXDOMAIN, answers: [] };
  if (name === zone) {
    if (type === TYPE.NS) return { rcode: RCODE.NOERROR, answers: [answer(TYPE.NS, encodeName(`ns1.${zone}`))] };
    if (type === TYPE.SOA) return { rcode: RCODE.NOERROR, answers: [answer(TYPE.SOA, soaRdata(zone))] };
    if (type === TYPE.A) return { rcode: RCODE.NOERROR, answers: [answer(TYPE.A, ipv4Bytes('192.0.2.1'))] };
    return empty;
  }
  if (!name.endsWith(`.${zone}`)) return nxdomain;
  const label = name.slice(0, -(zone.length + 1));
  if (label.includes('.')) return nxdomain;
  switch (label) {
    case 'servfail':
      return { rcode: RCODE.SERVFAIL, answers: [] };
    case 'drop':
      return null; // silence: exercises the resolver timeout path
    case 'empty':
      return empty;
    case 'real':
      if (type === TYPE.A) return { rcode: RCODE.NOERROR, answers: [answer(TYPE.A, ipv4Bytes('192.0.2.7'))] };
      return empty;
    case 'cname':
      if (type === TYPE.CNAME) {
        return { rcode: RCODE.NOERROR, answers: [answer(TYPE.CNAME, encodeName('edge.cdn.example.net'))] };
      }
      if (type === TYPE.A) return { rcode: RCODE.NOERROR, answers: [answer(TYPE.A, ipv4Bytes('192.0.2.70'))] };
      return empty;
    default:
      if (type === TYPE.A) return { rcode: RCODE.NOERROR, answers: [answer(TYPE.A, ipv4Bytes(wildcardIp))] };
      if (type === TYPE.AAAA) {
        return { rcode: RCODE.NOERROR, answers: [answer(TYPE.AAAA, ipv6Bytes([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x66]))] };
      }
      return empty;
  }
}

/**
 * Start the DNS fixture.
 * @param {{host?:string,port?:number,zone?:string,wildcardIp?:string}} [options]
 * @returns {Promise<{server:import('node:dgram').Socket,host:string,port:number,zone:string,queries:object[],close:()=>Promise<void>}>}
 */
export async function startDnsFixture(options = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 15353;
  const zone = String(options.zone ?? 'wildcard.test').trim().toLowerCase().replace(/\.+$/u, '');
  const wildcardIp = options.wildcardIp ?? '192.0.2.66';
  const queries = [];
  const server = dgram.createSocket('udp4');

  server.on('message', (message, remote) => {
    const request = parseQuery(message);
    if (request === null) return;
    if (queries.length < 5000) queries.push({ name: request.name, type: request.type });
    const result = resolveQuery(zone, wildcardIp, request.name, request.type);
    if (result === null) return;
    let response;
    try {
      response = buildResponse(request, result);
    } catch {
      return;
    }
    server.send(response, remote.port, remote.address);
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
    server.bind(port, host);
  });

  let closed = false;
  const close = () => new Promise((resolve) => {
    if (closed) {
      resolve();
      return;
    }
    closed = true;
    try {
      server.close(() => resolve());
    } catch {
      resolve();
    }
  });

  const boundPort = server.address()?.port ?? port;
  return { server, host, port: boundPort, zone, wildcardIp, queries, close };
}
