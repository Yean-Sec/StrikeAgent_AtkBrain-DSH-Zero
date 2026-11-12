/**
 * Wildcard-DNS detection tests.
 *
 * Fifteen fake-resolver scenarios from the engagement plan (true wildcard, no
 * wildcard, CDN CNAME, round-robin records, real subdomains, partial NXDOMAIN,
 * SERVFAIL, missing apex, parent/child zones, geo CNAME, delegation, resolver
 * synthesis, CNAME loops, flapping, secondary CNAME+IP chains) plus the
 * classifier/resolver contracts and one end-to-end run against the local UDP
 * DNS fixture on 127.0.0.1:15353.
 *
 * Every test uses loopback/offline-safe fixtures only.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { createResolver } from '../lib/dns.js';
import {
  assignWildcardZones,
  classifyHostAnswers,
  computeWildcardSignature,
  generateProbeLabels,
  isCdnCname,
  probeWildcardZone,
} from '../lib/wildcard.js';
import { startDnsFixture } from './fixtures/dns-fixture.mjs';

const SALT = 'atkbrain-wildcard-test-salt';
const ZONE = 'wildcard.test';

const ok = (answers = []) => ({ status: 'ok', answers });
const nxdomain = () => ({ status: 'nxdomain', answers: [] });
const servfail = () => ({ status: 'servfail', answers: [] });

/** Build a fake resolver backed by a query function and an apex answer. */
function fakeResolver(queryFunction, options = {}) {
  return {
    query: async (name, type) => queryFunction(name, type),
    apexExists: async (zone) => (typeof options.apexFn === 'function' ? options.apexFn(zone) : options.apex !== false),
  };
}

/** A resolver whose first `answeredLabels` random labels resolve to `ip`. */
function orderedResolver({ ip = '192.0.2.66', answeredLabels = Number.MAX_SAFE_INTEGER, apex = true } = {}) {
  const order = new Map();
  const resolver = fakeResolver((name, type) => {
    if (name.endsWith('.invalid')) return nxdomain();
    if (!order.has(name)) order.set(name, order.size);
    if (order.get(name) >= answeredLabels) return nxdomain();
    if (type === 'A') return ok([ip]);
    return ok([]);
  }, { apex });
  return { resolver, order };
}

test('1. true wildcard zone is confirmed from >=3 labels over >=2 rounds', async () => {
  const resolver = fakeResolver((name, type) => {
    if (name.endsWith('.invalid')) return nxdomain();
    if (type === 'A') return ok(['192.0.2.66']);
    if (type === 'AAAA') return ok(['2001:db8::66']);
    return ok([]);
  }, { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'confirmed');
  assert.equal(result.zone, ZONE);
  assert.equal(result.apex, true);
  assert.equal(result.cdn, false);
  assert.equal(result.probes.length, 6);
  assert.deepEqual(result.signature.a, ['192.0.2.66']);
  assert.deepEqual(result.signature.aaaa, ['2001:db8::66']);
  assert.deepEqual(result.signature.cnameTemplates, []);
  assert.ok(result.confidence >= 0.9, `confidence ${result.confidence} should be high`);
  assert.match(result.reason, /same signature/u);
  assert.deepEqual(result.warnings, []);
  for (const probe of result.probes) {
    assert.equal(typeof probe.label, 'string');
    assert.equal(probe.status, 'ok');
    assert.ok(Array.isArray(probe.a) && Array.isArray(probe.aaaa) && Array.isArray(probe.cname));
  }
});

test('2. zone without wildcard is cleared', async () => {
  const resolver = fakeResolver((name) => (name.endsWith('.invalid') ? nxdomain() : nxdomain()), { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'cleared');
  assert.equal(result.apex, true);
  assert.deepEqual(result.signature, { a: [], aaaa: [], cnameTemplates: [] });
  assert.equal(result.probes.length, 6);
  assert.ok(result.confidence >= 0.8, `confidence ${result.confidence}`);
  assert.match(result.reason, /no wildcard/u);
});

test('3. CDN-fronted CNAME wildcard is confirmed and flagged as CDN', async () => {
  const resolver = fakeResolver((name, type) => {
    if (name.endsWith('.invalid')) return nxdomain();
    if (type === 'CNAME') return ok([`${name.split('.')[0]}.edge.cloudfront.net`]);
    return ok([]);
  }, { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'confirmed');
  assert.equal(result.cdn, true);
  assert.deepEqual(result.signature.cnameTemplates, ['{label}.edge.cloudfront.net']);
  assert.ok(result.warnings.some((warning) => /CDN/iu.test(warning)));
  assert.ok(result.confidence >= 0.85);
});

test('4. round-robin A records form a stable sorted signature', async () => {
  let counter = 0;
  const resolver = fakeResolver((name, type) => {
    if (name.endsWith('.invalid')) return nxdomain();
    if (type !== 'A') return ok([]);
    counter += 1;
    return ok(counter % 2 === 0 ? ['192.0.2.66', '192.0.2.67'] : ['192.0.2.67', '192.0.2.66']);
  }, { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'confirmed');
  assert.deepEqual(result.signature.a, ['192.0.2.66', '192.0.2.67']);
});

test('5. hosts with unique records are classified explicit, pool matches suspect', async () => {
  const resolver = fakeResolver((name, type) => {
    if (name.endsWith('.invalid')) return nxdomain();
    if (type === 'A') return ok(['192.0.2.66']);
    return ok([]);
  }, { apex: true });
  const zone = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(zone.status, 'confirmed');

  const suspect = classifyHostAnswers(`random.${ZONE}`, { status: 'ok', a: ['192.0.2.66'] }, zone);
  assert.equal(suspect.status, 'suspect');
  assert.ok(suspect.confidence >= 0.65);
  assert.match(suspect.reason, /wildcard pool/u);

  const explicit = classifyHostAnswers(`real.${ZONE}`, { status: 'ok', a: ['192.0.2.7'] }, zone);
  assert.equal(explicit.status, 'explicit');
  assert.ok(explicit.confidence >= 0.75);
  assert.match(explicit.reason, /outside the wildcard pool/u);
});

test('6. partial NXDOMAIN responses are suspect (flapping/partial coverage)', async () => {
  const { resolver } = orderedResolver({ answeredLabels: 3, apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'suspect');
  assert.match(result.reason, /only 3\/6 random labels answered/u);
  assert.ok(result.confidence <= 0.65);
});

test('7. all-SERVFAIL probes are inconclusive', async () => {
  const resolver = fakeResolver((name) => (name.endsWith('.invalid') ? nxdomain() : servfail()), { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'inconclusive');
  assert.match(result.reason, /all 6 random-label probes failed/u);
  assert.ok(result.confidence <= 0.3);
});

test('8. missing apex with negative probes is cleared', async () => {
  const resolver = fakeResolver(() => nxdomain(), { apex: false });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'cleared');
  assert.equal(result.apex, false);
  assert.match(result.reason, /zone apex does not resolve/u);
});

test('9. parent and child zones keep independent signatures', async () => {
  const resolver = fakeResolver((name, type) => {
    if (name.endsWith('.invalid')) return nxdomain();
    if (type !== 'A') return ok([]);
    if (name.endsWith(`.dev.parent.test`)) return ok(['192.0.2.10']);
    if (name.endsWith('.parent.test')) return ok(['192.0.2.20']);
    return nxdomain();
  }, { apexFn: (zone) => zone === 'parent.test' });

  const parent = await probeWildcardZone(resolver, 'parent.test', { salt: SALT });
  const child = await probeWildcardZone(resolver, 'dev.parent.test', { salt: SALT });
  assert.equal(parent.status, 'confirmed');
  assert.equal(child.status, 'confirmed');
  assert.deepEqual(parent.signature.a, ['192.0.2.20']);
  assert.deepEqual(child.signature.a, ['192.0.2.10']);
  assert.equal(child.apex, false);
  assert.ok(child.warnings.some((warning) => /parent zone/u.test(warning)));
});

test('10. geo-varying CNAME wildcard is suspect (unstable template)', async () => {
  const seen = new Map();
  const resolver = fakeResolver((name, type) => {
    if (name.endsWith('.invalid')) return nxdomain();
    if (!seen.has(name)) seen.set(name, seen.size);
    if (type === 'CNAME') return ok([`geo-${seen.get(name) % 2}.example.net`]);
    return ok([]);
  }, { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'suspect');
  assert.match(result.reason, /unstable/u);
  assert.ok(result.confidence <= 0.65);
});

test('11. delegated/empty (NODATA) wildcard probes are cleared with a warning', async () => {
  const resolver = fakeResolver((name) => (name.endsWith('.invalid') ? nxdomain() : ok([])), { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'cleared');
  assert.ok(result.warnings.some((warning) => /NODATA/u.test(warning)));
});

test('12. resolver synthesis (guard .invalid answers) is inconclusive', async () => {
  const resolver = fakeResolver((name, type) => (type === 'A' ? ok(['10.0.0.1']) : ok([])), { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'inconclusive');
  assert.match(result.reason, /\.invalid/u);
  assert.ok(result.warnings.some((warning) => /guard name/u.test(warning)));
  assert.ok(result.confidence <= 0.3);
});

test('13. CNAME/DNS errors are inconclusive, never confirmed', async () => {
  const resolver = {
    query: async () => {
      const error = new Error('queryCNAME EFORMERR: CNAME loop');
      error.code = 'EFORMERR';
      throw error;
    },
    apexExists: async () => true,
  };
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'inconclusive');
  assert.ok(result.warnings.length > 0);
  assert.ok(result.confidence <= 0.3);
});

test('14. flapping wildcard answers are suspect, not confirmed', async () => {
  const seen = new Map();
  const resolver = fakeResolver((name, type) => {
    if (name.endsWith('.invalid')) return nxdomain();
    if (!seen.has(name)) seen.set(name, seen.size);
    if (type !== 'A') return ok([]);
    return ok([seen.get(name) % 2 === 0 ? '192.0.2.66' : '192.0.2.67']);
  }, { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'suspect');
  assert.match(result.reason, /unstable/u);
  assert.equal(result.signature.a.length, 1);
});

test('15. secondary CNAME+IP wildcard chain keeps both signature parts', async () => {
  const resolver = fakeResolver((name, type) => {
    if (name.endsWith('.invalid')) return nxdomain();
    if (type === 'CNAME') return ok([`${name.split('.')[0]}.edge.zone2.test`]);
    if (type === 'A') return ok(['192.0.2.88']);
    return ok([]);
  }, { apex: true });
  const result = await probeWildcardZone(resolver, ZONE, { salt: SALT });
  assert.equal(result.status, 'confirmed');
  assert.deepEqual(result.signature.a, ['192.0.2.88']);
  assert.deepEqual(result.signature.cnameTemplates, ['{label}.edge.zone2.test']);
});

test('classifier reports unknown on resolver errors and CNAME template matches', () => {
  const zone = {
    status: 'confirmed',
    zone: ZONE,
    signature: { a: ['192.0.2.66'], aaaa: [], cnameTemplates: ['{label}.edge.cloudfront.net'] },
  };
  const unknown = classifyHostAnswers(`x.${ZONE}`, { status: 'timeout' }, zone);
  assert.equal(unknown.status, 'unknown');
  assert.ok(unknown.confidence <= 0.3);

  const suspect = classifyHostAnswers(`host.${ZONE}`, { status: 'ok', cname: ['host.edge.cloudfront.net'] }, zone);
  assert.equal(suspect.status, 'suspect');
  assert.match(suspect.reason, /template/u);

  const distinct = classifyHostAnswers(`host.${ZONE}`, { status: 'ok', cname: ['host.internal.example'] }, zone);
  assert.equal(distinct.status, 'explicit');
  assert.match(distinct.reason, /distinct from the wildcard template/u);

  const clearedZone = classifyHostAnswers(`host.${ZONE}`, { status: 'ok', a: ['192.0.2.7'] }, { status: 'cleared', zone: ZONE, signature: { a: [], aaaa: [], cnameTemplates: [] } });
  assert.equal(clearedZone.status, 'explicit');
});

test('helper: probe labels are deterministic, unique and alphanumeric; CDN matching works', () => {
  const first = generateProbeLabels({ zone: ZONE, salt: SALT, rounds: 2, probes: 3 });
  const second = generateProbeLabels({ zone: ZONE, salt: SALT, rounds: 2, probes: 3 });
  assert.deepEqual(first, second);
  assert.equal(first.length, 6);
  assert.equal(new Set(first.map((entry) => entry.label)).size, 6);
  for (const entry of first) assert.match(entry.label, /^[a-z0-9]{10}$/u);
  assert.equal(isCdnCname('x.edge.cloudfront.net'), true);
  assert.equal(isCdnCname('x.edge.cloudfront.net.example'), false);
  assert.equal(isCdnCname('plain.example.com'), false);
  const signature = computeWildcardSignature([
    { label: 'aaaa', status: 'ok', a: ['192.0.2.1'], aaaa: [], cname: [] },
    { label: 'bbbb', status: 'ok', a: ['192.0.2.1'], aaaa: [], cname: [] },
  ]);
  assert.equal(signature.stable, true);
  assert.deepEqual(signature.signature.a, ['192.0.2.1']);
});

test('assignWildcardZones classifies hosts without deleting any', async () => {
  const zone = {
    zone: ZONE,
    status: 'confirmed',
    confidence: 0.95,
    signature: { a: ['192.0.2.66'], aaaa: [], cnameTemplates: [] },
  };
  const hosts = [
    { host: `a.${ZONE}`, a: ['192.0.2.66'] },
    { host: `real.${ZONE}`, a: ['192.0.2.7'] },
    { host: 'other.example', a: ['192.0.2.9'] },
  ];
  const results = assignWildcardZones(hosts, [zone]);
  assert.equal(results.length, 3);
  assert.equal(results[0].status, 'suspect');
  assert.equal(results[1].status, 'explicit');
  assert.equal(results[2].status, 'unknown');
  assert.equal(results[2].zone, null);
});

test('createResolver maps DNS errors, retries once and enforces offline mode', async () => {
  let retryCalls = 0;
  const impl = {
    resolve4: async (name) => {
      if (name === 'nx.test') {
        const error = new Error('queryA ENOTFOUND nx.test');
        error.code = 'ENOTFOUND';
        throw error;
      }
      if (name === 'servfail.test') {
        const error = new Error('queryA ESERVFAIL servfail.test');
        error.code = 'SERVFAIL';
        throw error;
      }
      if (name === 'timeout.test') {
        const error = new Error('queryA ETIMEOUT timeout.test');
        error.code = 'ETIMEOUT';
        throw error;
      }
      if (name === 'nodata.test') {
        const error = new Error('queryA ENODATA nodata.test');
        error.code = 'ENODATA';
        throw error;
      }
      if (name === 'retry.test') {
        retryCalls += 1;
        if (retryCalls === 1) {
          const error = new Error('queryA ESERVFAIL retry.test');
          error.code = 'SERVFAIL';
          throw error;
        }
        return ['192.0.2.9'];
      }
      return ['192.0.2.1'];
    },
    resolve6: async () => [],
    resolveCname: async () => [],
    resolveNs: async () => [],
    resolveSoa: async () => ({ nsname: 'ns1.test' }),
  };
  const resolver = createResolver({ impl, timeoutMs: 100, retries: 1 });
  assert.deepEqual(await resolver.query('nx.test', 'A'), {
    status: 'nxdomain',
    answers: [],
    error: 'queryA ENOTFOUND nx.test',
  });
  assert.equal((await resolver.query('servfail.test', 'A')).status, 'servfail');
  assert.equal((await resolver.query('timeout.test', 'A')).status, 'timeout');
  assert.deepEqual(await resolver.query('nodata.test', 'A'), { status: 'ok', answers: [] });
  assert.deepEqual(await resolver.query('retry.test', 'A'), { status: 'ok', answers: ['192.0.2.9'] });
  assert.ok(retryCalls >= 2, 'servfail should be retried at least once');
  assert.equal((await resolver.query('ok.test', 'NOTATYPE')).status, 'error');

  const hanging = createResolver({
    impl: { resolve4: () => new Promise(() => {}), resolve6: async () => [], resolveCname: async () => [], resolveNs: async () => [], resolveSoa: async () => ({}) },
    timeoutMs: 30,
    retries: 0,
  });
  const timedOut = await hanging.query('hang.test', 'A');
  assert.equal(timedOut.status, 'timeout');
  assert.match(timedOut.error, /timed out/u);

  const offlineResolver = createResolver({ impl, offline: true });
  await assert.rejects(offlineResolver.query('example.com', 'A'), /offline mode: refusing to resolve/u);
  assert.equal((await offlineResolver.query('localhost', 'A')).status, 'ok');
});

test('DNS fixture: real resolver against 127.0.0.1:15353 confirms a wildcard zone', async (t) => {
  const fixture = await startDnsFixture({ port: 15353, zone: ZONE });
  t.after(() => fixture.close());
  const resolver = createResolver({ servers: ['127.0.0.1:15353'], timeoutMs: 1000, retries: 1 });

  assert.equal(await resolver.apexExists(ZONE), true);
  assert.equal(await resolver.apexExists('missing.invalid'), false);

  const real = await resolver.resolveHost(`real.${ZONE}`);
  assert.equal(real.status, 'ok');
  assert.deepEqual(real.a, ['192.0.2.7']);

  const cname = await resolver.resolveHost(`cname.${ZONE}`);
  assert.equal(cname.status, 'ok');
  assert.deepEqual(cname.cname, ['edge.cdn.example.net']);
  assert.deepEqual(cname.a, ['192.0.2.70']);

  const missing = await resolver.resolveHost('does-not-exist.invalid');
  assert.equal(missing.status, 'nxdomain');

  const wildcard = await probeWildcardZone(resolver, ZONE, { salt: SALT, probes: 3, rounds: 2, timeoutMs: 1000 });
  assert.equal(wildcard.status, 'confirmed');
  assert.deepEqual(wildcard.signature.a, ['192.0.2.66']);
  assert.deepEqual(wildcard.signature.aaaa, ['2001:db8::66']);
  assert.equal(wildcard.cdn, false);
  assert.ok(fixture.queries.some((query) => query.name.endsWith(`.${ZONE}`)));

  const servfail = await resolver.query(`servfail.${ZONE}`, 'A');
  assert.equal(servfail.status, 'servfail');
});

test('dns fixture answers the guard name with NXDOMAIN for *.invalid', async (t) => {
  const fixture = await startDnsFixture({ port: 15353, zone: ZONE });
  t.after(() => fixture.close());
  const resolver = createResolver({ servers: ['127.0.0.1:15353'], timeoutMs: 1000 });
  const guard = await resolver.query('random-guard.atkbrain.invalid', 'A');
  assert.equal(guard.status, 'nxdomain');
});
