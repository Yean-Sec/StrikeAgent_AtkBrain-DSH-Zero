/**
 * Unit tests for asset normalization and document parsing.
 *
 * Every fixture is synthetic (documentation ranges 192.0.2.0/24 and
 * 2001:db8::/32); no network access happens in these tests.
 */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  ASSET_KINDS,
  OBSERVATION_KINDS,
  canonicalHost,
  canonicalizeUrl,
  classifyToken,
  cleanToken,
  detectDocumentFormat,
  normalizeAsset,
  parseAssetDocument,
  parseDelimited,
  parseObservationsJsonl,
  sniffDelimiter,
} from '../lib/normalize.js';

const FIXTURES = new URL('./fixtures/assets/', import.meta.url);

async function fixture(name) {
  return readFile(new URL(name, FIXTURES), 'utf8');
}

function keysOf(records) {
  return records.map((record) => `${record.kind}|${record.key}`);
}

test('canonicalHost applies IDNA, lowercases and strips trailing dots', () => {
  assert.equal(canonicalHost('BÜCHER.Example.COM.'), 'xn--bcher-kva.example.com');
  assert.equal(canonicalHost('buecher.example.com..'), 'buecher.example.com');
  assert.equal(canonicalHost('  WWW.Example.COM  '), 'www.example.com');
  assert.equal(canonicalHost('2001:0DB8::1'), '2001:db8::1');
  assert.equal(canonicalHost('[2001:db8::1]'), '2001:db8::1');
  assert.equal(canonicalHost(''), '');
});

test('canonicalHost/cleanToken strip invisible, bidi and zero-width characters', () => {
  assert.equal(cleanToken('exa\u200Bmple.com'), 'example.com');
  assert.equal(canonicalHost('exa\u200Bmple.com'), 'example.com');
  assert.equal(canonicalHost('exam\u200Dple.com'), 'example.com');
  assert.equal(canonicalHost('exam\u00ADple.com'), 'example.com');
  assert.equal(canonicalHost('\u202Eexample.com\u202C'), 'example.com');
  assert.equal(canonicalHost('\u200Eexample.com\u200E'), 'example.com');
  assert.equal(canonicalHost('\uFEFFexample.com'), 'example.com');
  assert.equal(canonicalHost('example\u3002com'), 'example.com');
  assert.equal(canonicalHost('example\uFF0Ecom'), 'example.com');
  assert.equal(canonicalHost('ｅｘａｍｐｌｅ．ｃｏｍ'), 'example.com');
  assert.equal(cleanToken('\u00A0example.com\u3000'), 'example.com');
});

test('canonicalHost rejects malformed labels and numeric TLDs', () => {
  assert.equal(canonicalHost('-bad.example.com'), '');
  assert.equal(canonicalHost('bad-.example.com'), '');
  assert.equal(canonicalHost('bad host.example.com'), '');
  assert.equal(canonicalHost('10.0.0.256'), '');
  assert.equal(canonicalHost('host.example.123'), '');
});

test('classifyToken canonicalizes URLs and removes userinfo', () => {
  const record = classifyToken('https://admin:sup3rsecret@BÜCHER.Example.COM.:443/login?next=%2Fhome#frag');
  assert.equal(record.kind, 'url');
  assert.equal(record.canonical, 'https://xn--bcher-kva.example.com/login?next=%2Fhome');
  assert.equal(record.attrs.path, '/login');
  assert.equal(record.attrs.query, 'next=%2Fhome');
  assert.equal(record.attrs.host, 'xn--bcher-kva.example.com');
  assert.equal(record.attrs.port, undefined);
  assert.equal(record.attrs.hasUserinfo, true);
  assert.equal(record.attrs.credentialHint.hasPassword, true);
  const serialized = JSON.stringify(record);
  assert.equal(serialized.includes('sup3rsecret'), false);
  assert.equal(serialized.includes('admin'), false);

  assert.equal(canonicalizeUrl('HTTPS://Example.COM:443/Path?Q=1#F').canonical, 'https://example.com/Path?Q=1');
  assert.equal(classifyToken('https://example.com/').canonical, 'https://example.com');
  assert.equal(classifyToken('https://example.com:8443/x').attrs.port, 8443);
});

test('classifyToken infers a scheme for schemeless URLs', () => {
  assert.equal(classifyToken('example.com/path?x=1').canonical, 'https://example.com/path?x=1');
  assert.equal(classifyToken('example.com:8080/health').canonical, 'http://example.com:8080/health');
  assert.equal(classifyToken('example.com:443/secure').canonical, 'https://example.com/secure');
  assert.equal(classifyToken('/just/a/path'), null);
  assert.equal(classifyToken('?only=query'), null);
  assert.equal(classifyToken('relative/path'), null);
});

test('classifyToken splits host:port and classifies apex/subdomain/wildcard', () => {
  const domain = classifyToken('example.com:8443');
  assert.equal(domain.kind, 'domain');
  assert.equal(domain.canonical, 'example.com');
  assert.equal(domain.attrs.port, 8443);

  const host = classifyToken('API.Example.COM:8443');
  assert.equal(host.kind, 'host');
  assert.equal(host.canonical, 'api.example.com');
  assert.equal(host.attrs.port, 8443);

  assert.equal(classifyToken('example.com').kind, 'domain');
  assert.equal(classifyToken('www.example.com').kind, 'host');
  assert.equal(classifyToken('example.co.uk').kind, 'domain');
  assert.equal(classifyToken('shop.example.co.uk').kind, 'host');
  assert.equal(classifyToken('web01').kind, 'host');
  assert.equal(classifyToken('report.docx', { strict: true }), null);

  const wildcard = classifyToken('*.example.com');
  assert.equal(wildcard.kind, 'domain');
  assert.equal(wildcard.canonical, '*.example.com');
  assert.equal(wildcard.attrs.wildcard, true);
  assert.equal(wildcard.attrs.zone, 'example.com');
});

test('classifyToken canonicalizes IPv4, IPv6 and bracketed forms', () => {
  assert.equal(classifyToken('192.0.2.10').canonical, '192.0.2.10');
  const ipWithPort = classifyToken('192.0.2.10:443');
  assert.equal(ipWithPort.kind, 'ip');
  assert.equal(ipWithPort.canonical, '192.0.2.10');
  assert.equal(ipWithPort.attrs.port, 443);

  assert.equal(
    classifyToken('2001:0db8:0000:0000:0000:0000:0000:0001').canonical,
    '2001:db8::1',
  );
  const bracketed = classifyToken('[2001:DB8::1]:8443');
  assert.equal(bracketed.kind, 'ip');
  assert.equal(bracketed.canonical, '2001:db8::1');
  assert.equal(bracketed.attrs.port, 8443);
  assert.equal(bracketed.value, '[2001:db8::1]:8443');
  assert.equal(classifyToken('::1').canonical, '::1');
});

test('classifyToken canonicalizes CIDRs and rejects bad prefixes as CIDR attempts', () => {
  assert.equal(classifyToken('192.0.2.7/24').canonical, '192.0.2.0/24');
  assert.equal(classifyToken('2001:db8::/32').canonical, '2001:db8::/32');
  assert.equal(classifyToken('10.0.0.0/33'), null);
  assert.equal(normalizeAsset('10.0.0.0/33').reason, 'invalid-cidr');
});

test('IPv4 leading zeros are quarantined instead of re-interpreted', () => {
  assert.equal(classifyToken('010.001.001.001'), null);
  const quarantined = normalizeAsset('010.001.001.001');
  assert.equal(quarantined.ok, false);
  assert.equal(quarantined.quarantine, true);
  assert.equal(quarantined.reason, 'ipv4-leading-zero');

  const withPort = normalizeAsset('010.1.1.1:8080');
  assert.equal(withPort.ok, false);
  assert.equal(withPort.reason, 'ipv4-leading-zero');

  const withCidr = normalizeAsset('010.0.0.0/24');
  assert.equal(withCidr.ok, false);
  assert.equal(withCidr.reason, 'ipv4-leading-zero');

  // WHATWG URL would read the leading-zero host as octal; refuse it instead.
  assert.equal(classifyToken('https://010.0.0.0/x'), null);
  assert.equal(normalizeAsset('https://010.0.0.0/x').reason, 'invalid-url');
});

test('normalizeAsset returns canonical records and strips secret attributes', () => {
  const record = normalizeAsset({
    kind: 'host',
    value: 'WWW.Example.COM.',
    port: 8080,
    attrs: { password: 'hunter2', token: 'abc', note: 'edge' },
  });
  assert.equal(record.ok, true);
  assert.equal(record.kind, 'host');
  assert.equal(record.key, 'www.example.com');
  assert.equal(record.value, 'www.example.com', 'value is the canonical identity, port stays in attrs');
  assert.equal(record.attrs.port, 8080);
  assert.equal(record.attrs.note, 'edge');
  assert.equal('password' in record.attrs, false);
  assert.equal('token' in record.attrs, false);
  assert.equal(JSON.stringify(record).includes('hunter2'), false);
});

test('normalizeAsset handles kind hints and failure reasons', () => {
  const asHost = normalizeAsset({ kind: 'host', value: 'example.com' });
  assert.equal(asHost.kind, 'host');
  assert.equal(asHost.attrs.fqdn, 'example.com');
  assert.equal('domain' in asHost.attrs, false);

  const asDomain = normalizeAsset({ kind: 'domain', value: 'www.example.com' });
  assert.equal(asDomain.kind, 'domain');
  assert.equal(asDomain.attrs.domain, 'www.example.com');

  assert.equal(normalizeAsset('').reason, 'empty');
  assert.equal(normalizeAsset('not a host!!').reason, 'not-asset');
  assert.equal(normalizeAsset('bad_host!.example.com').reason, 'invalid-host');
  assert.equal(normalizeAsset('https://exa mple.com/x').reason, 'invalid-url');
  assert.equal(normalizeAsset(undefined).ok, false);
  assert.equal(normalizeAsset(42).reason, 'invalid-input');
  assert.equal(normalizeAsset({ kind: 'host' }).reason, 'missing-value');
  assert.equal(ASSET_KINDS.length, 5);
});

test('normalizeAsset masks credential-looking tokens', () => {
  const quarantined = normalizeAsset('admin:s3cret@example.com');
  assert.equal(quarantined.ok, false);
  assert.equal(quarantined.reason, 'credential-like');
  assert.equal(quarantined.raw.includes('s3cret'), false);
});

test('parseDelimited implements RFC4180 quoting, CRLF and comments', () => {
  const parsed = parseDelimited('a,"b,c","d""e"\r\n"f\ng",h,i\r\n');
  assert.deepEqual(parsed.rows, [['a', 'b,c', 'd"e'], ['f\ng', 'h', 'i']]);

  const commented = parseDelimited('# comment row\n// another comment\nhost,port\nwww.example.com,443\n');
  assert.deepEqual(commented.rows, [['host', 'port'], ['www.example.com', '443']]);

  const unclosed = parseDelimited('"unterminated,field\nnext,row\n');
  assert.equal(unclosed.warnings.some((warning) => warning.reason === 'unclosed-quote'), true);
});

test('sniffDelimiter recognises comma, tab, semicolon and pipe', () => {
  assert.equal(sniffDelimiter('a,b,c\n1,2,3\n'), ',');
  assert.equal(sniffDelimiter('a\tb\tc\n1\t2\t3\n'), '\t');
  assert.equal(sniffDelimiter('a;b;c\n1;2;3\n'), ';');
  assert.equal(sniffDelimiter('a|b|c\n1|2|3\n'), '|');
});

test('detectDocumentFormat uses extensions first, then content shape', () => {
  assert.equal(detectDocumentFormat('assets.csv', ''), 'csv');
  assert.equal(detectDocumentFormat('assets.tsv', ''), 'tsv');
  assert.equal(detectDocumentFormat('assets.json', ''), 'json');
  assert.equal(detectDocumentFormat('assets.jsonl', ''), 'jsonl');
  assert.equal(detectDocumentFormat('notes.md', ''), 'markdown');
  assert.equal(detectDocumentFormat('targets.list', 'a.example.com\nb.example.com'), 'txt');
  assert.equal(detectDocumentFormat('blob', '{"a":1}'), 'json');
  assert.equal(detectDocumentFormat('blob', '{"a":1}\n{"b":2}\n'), 'jsonl');
  assert.equal(detectDocumentFormat('blob', 'a\tb\n1\t2\n'), 'tsv');
  assert.equal(detectDocumentFormat('blob', 'a,b,c\n1,2,3\n'), 'csv');
  assert.equal(detectDocumentFormat('blob', '| a | b |\n| --- | --- |\n| 1 | 2 |\n'), 'markdown');
  assert.equal(detectDocumentFormat('blob', 'just some words'), 'txt');
});

test('parseAssetDocument parses the TXT fixture with comments, IDN and quarantine', async () => {
  const text = await fixture('assets.txt');
  const result = parseAssetDocument(text, { filename: 'assets.txt' });
  assert.equal(result.stats.format, 'txt');
  assert.equal(result.warnings.length, 0);
  assert.equal(result.records.length, 15);
  assert.equal(result.stats.duplicates, 3);
  assert.equal(result.stats.quarantined, 1);
  assert.equal(result.quarantined[0].reason, 'ipv4-leading-zero');

  const keys = keysOf(result.records);
  assert.equal(keys.filter((key) => key === 'domain|example.com').length, 3);
  assert.equal(keys.filter((key) => key === 'host|www.example.com').length, 2);
  assert.ok(keys.includes('domain|*.example.com'));
  assert.ok(keys.includes('ip|192.0.2.10'));
  assert.ok(keys.includes('ip|2001:db8::1'));
  assert.ok(keys.includes('cidr|192.0.2.0/24'));
  assert.ok(keys.includes('url|https://example.com/login?next=%2Fhome'));
  assert.ok(keys.includes('url|http://example.com:8080/health'));
  assert.ok(keys.includes('host|api.example.com'));
  assert.ok(keys.includes('host|web01'));
  assert.ok(keys.includes('host|buecher.example.com'));
  assert.ok(keys.includes('host|sso.example.co.uk'));

  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes('example-pass'), false);
  assert.equal(serialized.includes('demo:'), false);
});

test('parseAssetDocument parses quoted CSV with header mapping and quarantine', async () => {
  const text = await fixture('assets.csv');
  const result = parseAssetDocument(text, { filename: 'assets.csv' });
  assert.equal(result.stats.format, 'csv');
  assert.equal(result.records.length, 4);

  const host = result.records.find((record) => record.kind === 'host' && record.key === 'www.example.com');
  assert.equal(host.attrs.port, 443);
  assert.equal(host.value, 'www.example.com');
  const url = result.records.find((record) => record.key === 'https://www.example.com/login');
  assert.equal(url.kind, 'url');
  assert.equal(url.attrs.port, 443);
  assert.ok(result.records.some((record) => record.key === 'https://api.example.com:8443/v1?x=1'));

  assert.equal(result.quarantined.length, 1);
  assert.equal(result.quarantined[0].reason, 'ipv4-leading-zero');
  assert.equal(result.warnings.some((warning) => warning.reason === 'invalid-asset'), true);
  assert.equal(JSON.stringify(result).includes('primary, edge'), false);
});

test('parseAssetDocument parses nested JSON targets, domains and networks', async () => {
  const text = await fixture('assets.json');
  const result = parseAssetDocument(text, { filename: 'assets.json' });
  assert.equal(result.stats.format, 'json');
  const keys = keysOf(result.records);
  assert.ok(keys.includes('host|www.example.com'));
  assert.ok(keys.includes('url|https://api.example.com:8443/v1?x=1'));
  assert.ok(keys.includes('domain|example.com'));
  assert.ok(keys.includes('host|sso.example.co.uk'));
  assert.ok(keys.includes('cidr|192.0.2.0/24'));
  assert.ok(keys.includes('cidr|2001:db8:1234::/48'));

  const host = result.records.find((record) => record.kind === 'host');
  assert.equal(host.attrs.port, 443);
  assert.equal(host.attrs.service, 'nginx');
  assert.equal(JSON.stringify(result).includes('leaked-but-stripped'), false);
  // `nginx` (a bare service label) and prose text must not become fake hosts.
  assert.equal(keys.includes('host|nginx'), false);
});

test('parseAssetDocument parses JSONL lines and warns on malformed lines', async () => {
  const text = await fixture('assets.jsonl');
  const result = parseAssetDocument(text, { filename: 'assets.jsonl' });
  assert.equal(result.stats.format, 'jsonl');
  const keys = keysOf(result.records);
  assert.ok(keys.includes('host|www.example.com'));
  assert.ok(keys.includes('domain|example.com'));
  assert.ok(keys.includes('url|https://api.example.com:8443/v1?x=1'));
  assert.ok(keys.includes('host|web01'));
  assert.ok(keys.includes('ip|192.0.2.11'));
  assert.ok(keys.includes('ip|2001:db8::11'));
  assert.equal(result.warnings.some((warning) => warning.reason === 'invalid-json-line' && warning.line === 5), true);
  assert.equal(result.quarantined.some((entry) => entry.reason === 'ipv4-leading-zero'), true);
});

test('parseAssetDocument parses Markdown tables and bullet lines', async () => {
  const text = await fixture('assets.md');
  const result = parseAssetDocument(text, { filename: 'assets.md' });
  assert.equal(result.stats.format, 'markdown');
  const keys = keysOf(result.records);
  assert.ok(keys.includes('host|www.example.com'));
  assert.ok(keys.includes('url|https://www.example.com/login'));
  assert.ok(keys.includes('host|api.example.com'));
  assert.ok(keys.includes('url|https://api.example.com:8443/v1'));
  assert.ok(keys.includes('host|internal.example.com'));
  assert.ok(keys.includes('ip|192.0.2.32'));
  assert.equal(result.quarantined.some((entry) => entry.reason === 'ipv4-leading-zero'), true);
});

test('parseAssetDocument parses TSV with a header row', async () => {
  const result = parseAssetDocument(await fixture('assets.tsv'), { filename: 'assets.tsv' });
  assert.equal(result.stats.format, 'tsv');
  const host = result.records.find((record) => record.kind === 'host' && record.key === 'www.example.com');
  assert.equal(host.attrs.port, 443);
  assert.ok(result.records.some((record) => record.key === 'https://api.example.com:8443/v1'));
});

test('parseAssetDocument enforces a byte cap', () => {
  assert.throws(() => parseAssetDocument('a'.repeat(1000), { format: 'txt', maxBytes: 100 }), /limit/u);
});

test('parseObservationsJsonl normalizes valid observation kinds', async () => {
  const text = await fixture('observations.jsonl');
  const result = parseObservationsJsonl(text);
  assert.equal(result.records.length, 7);
  assert.deepEqual(
    result.records.map((record) => record.kind),
    ['service', 'http', 'finding', 'dns', 'host', 'finding', 'dns'],
  );
  assert.deepEqual(new Set(result.records.map((record) => record.kind)), new Set(OBSERVATION_KINDS));

  const service = result.records[0];
  assert.equal(service.key, 'www.example.com:443');
  assert.equal(service.attrs.protocol, 'https');
  assert.equal(service.attrs.banner, 'nginx/1.24.0');
  assert.equal(service.attrs.tls, true);
  assert.equal('password' in service.attrs, false);

  const http = result.records[1];
  assert.equal(http.key, 'https://www.example.com/login?next=%2Fhome');
  assert.equal(http.attrs.status, 200);
  assert.equal(http.attrs.title, 'Edge admin');
  assert.equal(http.attrs.server, 'nginx');
  assert.deepEqual(http.attrs.techs, ['nginx', 'react']);
  assert.deepEqual(http.attrs.headers, { 'content-type': 'text/html' });
  assert.equal(http.attrs.hasUserinfo, true);

  const finding = result.records[2];
  assert.equal(finding.label, 'Exposed admin panel');
  assert.equal(finding.attrs.severity, 'high');
  assert.equal(finding.attrs.status, 'verified');
  assert.equal(finding.attrs.cve, 'CVE-2024-12345');
  assert.equal(finding.attrs.cwe, 'CWE-284');
  assert.equal(finding.attrs.cvss, 9.8);
  assert.match(finding.key, /^finding_[0-9a-f]{16}$/u);

  const dns = result.records[3];
  assert.equal(dns.key, 'api.example.com');
  assert.deepEqual(dns.attrs.addresses, ['192.0.2.10', '2001:db8::1']);
  assert.equal(dns.attrs.cname, 'edge.example.com');
  assert.equal(dns.attrs.ttl, 300);

  const host = result.records[4];
  assert.equal(host.key, 'web01');
  assert.deepEqual(host.attrs.ips, ['192.0.2.11']);
  assert.equal(host.attrs.os, 'linux');
  assert.equal(host.attrs.state, 'up');
  assert.deepEqual(host.attrs.tags, ['edge', 'prod']);

  // The `type` fallback is only used when it names an observation kind.
  assert.equal(result.records[6].key, 'legacy.example.com');
  assert.equal(result.records[6].attrs.recordType, 'A');
});

test('parseObservationsJsonl warns on invalid lines and unknown kinds', async () => {
  const result = parseObservationsJsonl(await fixture('observations.jsonl'));
  const warningKey = (warning) => `${warning.line}:${warning.reason}`;
  assert.deepEqual(result.warnings.map(warningKey), [
    '6:service-missing-port',
    '7:unknown-kind',
    '8:unknown-severity',
    '8:unknown-finding-status',
    '9:invalid-json',
    '10:not-an-object',
    '11:http-invalid-url',
  ]);
  assert.equal(result.warnings.every((warning) => typeof warning.line === 'number'), true);

  const serialized = JSON.stringify(result);
  for (const secret of ['hunter2', 'admin:secret', 'sid=abc', 'Bearer xyz']) {
    assert.equal(serialized.includes(secret), false, `observation output leaked ${secret}`);
  }
});

test('parseObservationsJsonl mirrors canonical fields for graph builders', async () => {
  const result = parseObservationsJsonl(await fixture('observations.jsonl'));
  const service = result.records[0];
  assert.equal(service.host, 'www.example.com');
  assert.equal(service.port, 443);
  assert.equal(service.transport, 'tcp');
  assert.equal(service.protocol, 'https');
  assert.equal(service.banner, 'nginx/1.24.0');

  const http = result.records[1];
  assert.equal(http.url, 'https://www.example.com/login?next=%2Fhome');
  assert.equal(http.status, 200);
  assert.equal(http.title, 'Edge admin');
  assert.deepEqual(http.techs, ['nginx', 'react']);

  const finding = result.records[2];
  assert.equal(finding.title, 'Exposed admin panel');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.status, 'verified');
  assert.equal(finding.subject, 'https://www.example.com/login');

  const dns = result.records[3];
  assert.equal(dns.host, 'api.example.com');
  assert.deepEqual(dns.a, ['192.0.2.10']);
  assert.deepEqual(dns.aaaa, ['2001:db8::1']);
  assert.deepEqual(dns.cname, ['edge.example.com']);

  const host = result.records[4];
  assert.equal(host.host, 'web01');
  assert.deepEqual(host.ips, ['192.0.2.11']);
});

test('parseObservationsJsonl is deterministic and caps input size', async () => {
  const text = await fixture('observations.jsonl');
  const first = parseObservationsJsonl(text);
  const second = parseObservationsJsonl(text);
  assert.deepEqual(first, second);

  assert.throws(() => parseObservationsJsonl('x'.repeat(5000), { maxBytes: 100 }), /limit/u);
  const truncated = parseObservationsJsonl(text, { maxLines: 2 });
  assert.equal(truncated.records.length, 2);
});

test('fixture parsing never echoes raw credentials or secrets', async () => {
  const documents = ['assets.txt', 'assets.csv', 'assets.json', 'assets.jsonl', 'assets.md'];
  for (const name of documents) {
    const result = parseAssetDocument(await fixture(name), { filename: name });
    const serialized = JSON.stringify(result);
    for (const secret of ['example-pass', 'leaked-but-stripped', 'admin:secret', 'hunter2']) {
      assert.equal(serialized.includes(secret), false, `${name} leaked ${secret}`);
    }
  }
});

test('classifyToken is pure and deterministic', () => {
  const input = 'https://user:pass@Example.COM/path?q=1';
  assert.deepEqual(classifyToken(input), classifyToken(input));
  assert.equal(JSON.stringify(classifyToken(input)).includes('pass'), false);
  assert.equal(ASSET_KINDS.includes(classifyToken('example.com').kind), true);
});
