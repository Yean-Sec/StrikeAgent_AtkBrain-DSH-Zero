/**
 * Unit tests for ingestion dispatch, duplicate merging and document extraction.
 *
 * Office extraction tests use the Python interpreter bundled with the DSH
 * runtime. When no interpreter with python-docx/openpyxl/python-pptx is found
 * the tests are skipped with an explicit reason instead of failing.
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  mergeNormalized,
  observationSchema,
  parseAssetRecords,
} from '../lib/ingest.js';
import { capturedObservationPath, filterOpsToScope, graphJsonOps } from '../lib/tools/ingest.js';
import {
  DocumentExtractionError,
  extractDocumentText,
  findPython,
} from '../lib/doc.js';

const execFileAsync = promisify(execFile);
const FIXTURES = fileURLToPath(new URL('./fixtures/assets/', import.meta.url));

async function fixture(name) {
  return readFile(path.join(FIXTURES, name), 'utf8');
}

function keysOf(records) {
  return records.map((record) => `${record.kind}|${record.key}`);
}

let officeCache;

/** Resolve (and lazily generate) the Office fixtures with bundled Python. */
async function officeFixtures() {
  if (officeCache !== undefined) return officeCache;
  const python = await findPython({ modules: ['docx', 'openpyxl', 'pptx'] });
  if (python.command === undefined) {
    officeCache = {
      skipped: `no Python 3 with python-docx/openpyxl/python-pptx (tried: ${python.tried.join(', ')})`,
    };
    return officeCache;
  }
  const officeDir = path.join(FIXTURES, 'office');
  const expected = ['assets.docx', 'assets.xlsx', 'assets.pptx'].map((name) => path.join(officeDir, name));
  if (!expected.every((file) => existsSync(file))) {
    await mkdir(officeDir, { recursive: true });
    const script = path.join(FIXTURES, 'generate-office-fixtures.py');
    await execFileAsync(python.command, [script, officeDir], {
      timeout: 60000,
      maxBuffer: 8 * 1024 * 1024,
    });
  }
  officeCache = { python, dir: officeDir };
  return officeCache;
}

test('parseAssetRecords dispatches by filename and content', async () => {
  const cases = [
    ['assets.txt', 'txt'],
    ['assets.csv', 'csv'],
    ['assets.tsv', 'tsv'],
    ['assets.json', 'json'],
    ['assets.jsonl', 'jsonl'],
    ['assets.md', 'markdown'],
  ];
  for (const [name, format] of cases) {
    const result = parseAssetRecords(await fixture(name), { filename: name });
    assert.equal(result.stats.format, format, `${name} should parse as ${format}`);
    assert.ok(result.records.length > 0, `${name} should yield records`);
  }
  const override = parseAssetRecords('www.example.com\n', { format: 'txt', filename: 'targets.csv' });
  assert.equal(override.stats.format, 'txt');
  assert.deepEqual(keysOf(override.records), ['host|www.example.com']);
});

test('parseAssetRecords handles RFC4180 quoting, CRLF and delimiter sniffing', () => {
  const quoted = parseAssetRecords(
    'Host,Note\r\n"www.example.com","says ""hello"", world"\r\n"api.example.com","multi\nline"\r\n',
    { format: 'csv' },
  );
  assert.deepEqual(keysOf(quoted.records), ['host|www.example.com', 'host|api.example.com']);

  const semicolon = parseAssetRecords('host;port\nwww.example.com;443\n', { format: 'csv' });
  assert.equal(semicolon.records[0].attrs.port, 443);

  const pipe = parseAssetRecords('host|port\napi.example.com|8443\n', { format: 'csv' });
  assert.equal(pipe.records[0].attrs.port, 8443);

  const tsv = parseAssetRecords('host\tport\nwww.example.com\t8080\n', { format: 'tsv' });
  assert.equal(tsv.records[0].attrs.port, 8080);

  const comments = parseAssetRecords('# comment\n// comment\nwww.example.com\n', { format: 'txt' });
  assert.deepEqual(keysOf(comments.records), ['host|www.example.com']);
});

test('parseAssetRecords supports the host-tool "lines" format for extracted text', () => {
  const prose = parseAssetRecords('www.example.com\napi.example.com\n', { format: 'lines', filename: 'assets.docx' });
  assert.equal(prose.stats.format, 'txt');
  assert.deepEqual(keysOf(prose.records), ['host|www.example.com', 'host|api.example.com']);

  const table = parseAssetRecords('host\tport\nwww.example.com\t443\napi.example.com\t8443\n', {
    format: 'lines',
    filename: 'assets.xlsx',
  });
  assert.equal(table.stats.format, 'tsv');
  assert.deepEqual(
    table.records.map((record) => `${record.key}|${record.attrs.port ?? ''}`),
    ['www.example.com|443', 'api.example.com|8443'],
  );
});

test('mergeNormalized deduplicates, unions attributes and reports conflicts', () => {
  const records = [
    { kind: 'host', key: 'www.example.com', label: 'www', attrs: { port: 443, tags: ['a'], fqdn: 'www.example.com' } },
    { kind: 'host', key: 'www.example.com', label: 'www', attrs: { port: 8443, tags: ['b'] } },
    { kind: 'host', key: 'www.example.com', label: 'other', attrs: { fqdn: 'other.example.com' } },
    { kind: 'ip', key: '192.0.2.10', attrs: { addr: '192.0.2.10' } },
    { kind: '', key: 'broken' },
  ];
  const merged = mergeNormalized(records);
  assert.equal(merged.unique.length, 2);
  assert.equal(merged.duplicates['host|www.example.com'], 3);
  assert.equal(merged.stats.duplicates, 2);
  assert.equal(merged.stats.conflicts, 2);
  assert.equal(merged.stats.invalid, 1);

  const host = merged.unique[0];
  assert.equal(host.kind, 'host');
  assert.equal(host.key, 'www.example.com');
  assert.equal(host.label, 'www', 'first label wins');
  assert.equal(host.attrs.port, 443, 'first port wins');
  assert.deepEqual(host.attrs.ports, [443, 8443]);
  assert.deepEqual(host.attrs.tags, ['a', 'b']);
  assert.deepEqual(
    merged.conflicts.map((conflict) => conflict.field).sort(),
    ['fqdn', 'label'],
  );
  assert.equal(JSON.stringify(merged.unique[1]), JSON.stringify({ kind: 'ip', key: '192.0.2.10', attrs: { addr: '192.0.2.10' } }));
});

test('mergeNormalized unions observation address lists and counts duplicates', () => {
  const merged = mergeNormalized([
    { kind: 'dns', key: 'api.example.com', attrs: { addresses: ['192.0.2.2'] } },
    { kind: 'dns', key: 'api.example.com', attrs: { addresses: ['192.0.2.1'] } },
    { kind: 'dns', key: 'api.example.com', attrs: { cname: 'edge.example.com' } },
  ]);
  assert.equal(merged.unique.length, 1);
  assert.equal(merged.duplicates['dns|api.example.com'], 3);
  assert.deepEqual(merged.unique[0].attrs.addresses, ['192.0.2.1', '192.0.2.2']);
  assert.equal(merged.unique[0].attrs.cname, 'edge.example.com');
});

test('mergeNormalized collapses fixture duplicates end to end', async () => {
  const parsed = parseAssetRecords(await fixture('assets.txt'), { filename: 'assets.txt' });
  const merged = mergeNormalized(parsed.records);
  assert.equal(parsed.records.length, 15);
  assert.equal(merged.unique.length, 12);
  assert.equal(merged.stats.duplicates, 3);
  assert.equal(merged.duplicates['domain|example.com'], 3);
  assert.equal(merged.duplicates['host|www.example.com'], 2);
  assert.ok(keysOf(merged.unique).includes('cidr|192.0.2.0/24'));
});

test('mergeNormalized tolerates empty and non-array input', () => {
  assert.deepEqual(mergeNormalized([]), {
    unique: [],
    duplicates: {},
    conflicts: [],
    stats: { input: 0, unique: 0, duplicates: 0, conflicts: 0, invalid: 0 },
  });
  assert.equal(mergeNormalized(undefined).unique.length, 0);
});

test('observationSchema documents the accepted JSONL shapes', () => {
  assert.equal(Object.isFrozen(observationSchema), true);
  assert.deepEqual([...observationSchema.kinds], ['service', 'http', 'finding', 'dns', 'host']);
  assert.deepEqual([...observationSchema.service.required], ['host', 'port']);
  assert.deepEqual([...observationSchema.finding.required], ['title']);
  assert.match(observationSchema.secretHandling, /SECRET_KEY_PATTERN/u);
  assert.equal(observationSchema.limits.maxBytes, 16 * 1024 * 1024);
  assert.equal(typeof observationSchema.http.key, 'string');
});

test('extractDocumentText reads plain-text documents', async () => {
  const result = await extractDocumentText(path.join(FIXTURES, 'assets.csv'));
  assert.equal(result.via, 'text');
  assert.equal(result.format, 'csv');
  assert.match(result.text, /www\.example\.com/u);
  assert.deepEqual(result.warnings, []);
});

test('extractDocumentText returns unsupported guidance for PDFs', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-doc-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'report.pdf');
  await writeFile(file, '%PDF-1.4\n%%EOF\n');
  const result = await extractDocumentText(file);
  assert.equal(result.unsupported, true);
  assert.equal(result.format, 'pdf');
  assert.equal(typeof result.guidance, 'string');
  assert.match(result.guidance, /pdftotext/u);
});

test('extractDocumentText rejects legacy Office formats with an actionable error', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-doc-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'legacy.doc');
  await writeFile(file, 'legacy binary content');
  await assert.rejects(extractDocumentText(file), (error) => {
    assert.equal(error instanceof DocumentExtractionError, true);
    assert.equal(error.code, 'ATK_DOC_EXTRACTOR');
    assert.match(error.guidance, /docx/u);
    return true;
  });
});

test('extractDocumentText rejects oversized and missing files', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-doc-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'big.txt');
  await writeFile(file, 'www.example.com\n'.repeat(50));
  await assert.rejects(extractDocumentText(file, { maxBytes: 32 }), (error) => {
    assert.equal(error.code, 'ATK_DOC_EXTRACTOR');
    assert.match(error.message, /limit/u);
    return true;
  });
  await assert.rejects(extractDocumentText(path.join(dir, 'does-not-exist.txt')), (error) => {
    assert.equal(error.code, 'ATK_DOC_EXTRACTOR');
    return true;
  });
});

test('findPython reports the interpreter candidates it tried', async () => {
  const attempted = await findPython({ modules: [] });
  assert.equal(Array.isArray(attempted.tried), true);
  assert.equal(attempted.tried.length > 0, true);
  if (attempted.command === undefined) {
    assert.equal(Array.isArray(attempted.missing), true);
    return;
  }
  assert.match(attempted.version ?? '', /^\d+\.\d+/u);
});

test('extractDocumentText extracts .docx fixtures with bundled Python', async (t) => {
  const fixtures = await officeFixtures();
  if (fixtures.skipped !== undefined) {
    t.skip(fixtures.skipped);
    return;
  }
  const file = path.join(fixtures.dir, 'assets.docx');
  const result = await extractDocumentText(file, { pythonPath: fixtures.python.command });
  assert.equal(result.via, 'python');
  assert.equal(result.format, 'txt');
  assert.equal(result.documentFormat, 'docx');
  assert.match(result.text, /Asset inventory/u);
  assert.match(result.text, /www\.example\.com/u);
  assert.match(result.text, /report\.example\.com/u);

  const parsed = parseAssetRecords(result.text, { format: result.format });
  const keys = keysOf(parsed.records);
  assert.ok(keys.includes('host|report.example.com'));
  assert.ok(keys.includes('ip|192.0.2.20'));
});

test('extractDocumentText extracts .xlsx fixtures with bundled Python', async (t) => {
  const fixtures = await officeFixtures();
  if (fixtures.skipped !== undefined) {
    t.skip(fixtures.skipped);
    return;
  }
  const file = path.join(fixtures.dir, 'assets.xlsx');
  const result = await extractDocumentText(file, { pythonPath: fixtures.python.command });
  assert.equal(result.via, 'python');
  assert.equal(result.format, 'tsv');
  assert.equal(result.documentFormat, 'xlsx');
  assert.match(result.text, /# sheet: Assets/u);
  assert.match(result.text, /www\.example\.com/u);

  const parsed = parseAssetRecords(result.text, { format: 'lines', filename: 'assets.xlsx' });
  const keys = keysOf(parsed.records);
  assert.ok(keys.includes('host|www.example.com'));
  assert.ok(keys.includes('url|https://www.example.com'));
  assert.ok(keys.includes('host|internal.example.com'));
  assert.ok(keys.includes('ip|192.0.2.16'));
  const host = parsed.records.find((record) => record.kind === 'host' && record.key === 'www.example.com');
  assert.equal(host.attrs.port, 443);
});

test('extractDocumentText extracts .pptx fixtures with bundled Python', async (t) => {
  const fixtures = await officeFixtures();
  if (fixtures.skipped !== undefined) {
    t.skip(fixtures.skipped);
    return;
  }
  const file = path.join(fixtures.dir, 'assets.pptx');
  const result = await extractDocumentText(file, { pythonPath: fixtures.python.command });
  assert.equal(result.via, 'python');
  assert.equal(result.format, 'txt');
  assert.equal(result.documentFormat, 'pptx');
  assert.match(result.text, /www\.example\.com/u);
  assert.match(result.text, /cdn\.example\.com/u);
  assert.match(result.text, /192\.0\.2\.30/u);
});

test('extractDocumentText wraps Python extraction failures as ATK_DOC_EXTRACTOR', async (t) => {
  const fixtures = await officeFixtures();
  if (fixtures.skipped !== undefined) {
    t.skip(fixtures.skipped);
    return;
  }
  const dir = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-doc-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'broken.docx');
  await writeFile(file, 'this is definitely not a zip archive');
  await assert.rejects(
    extractDocumentText(file, { pythonPath: fixtures.python.command }),
    (error) => {
      assert.equal(error instanceof DocumentExtractionError, true);
      assert.equal(error.code, 'ATK_DOC_EXTRACTOR');
      assert.match(error.message, /python extractor|OPEN_FAILED/u);
      assert.equal(typeof error.guidance, 'string');
      return true;
    },
  );
});

test('child graph merge does not overwrite parent self-team report state', () => {
  const document = {
    schema: 'atkbrain/1',
    engagement: { name: 'merge-test' },
    nodes: [{
      id: 'self_team_child_report',
      kind: 'self_team',
      key: 'selfteam/report',
      label: '报告撰写团队',
      status: 'running',
      attrs: {
        type: 'report',
        reportModes: ['project', 'finding'],
        lastReportAt: null,
        lastReportPath: null,
        lastReportKind: null,
        lastFindingReportAt: null,
        lastFindingReportPath: null,
        nativeId: 'child-native-id',
        nativeStatus: 'running',
      },
    }],
    edges: [],
  };
  const result = graphJsonOps(document, { source: 'child-graph' });
  const op = result.ops.find((entry) => entry.op === 'node.upsert' && entry.kind === 'self_team');
  assert.ok(op);
  assert.deepEqual(op.attrs.reportModes, ['project', 'finding']);
  assert.equal(op.attrs.type, 'report');
  assert.equal(op.attrs.lastReportPath, undefined);
  assert.equal(op.attrs.lastReportAt, undefined);
  assert.equal(op.attrs.nativeId, undefined);
  assert.equal(op.attrs.nativeStatus, undefined);
});

test('captured pages and evidence files are not asset lists', () => {
  assert.equal(capturedObservationPath('wc/page.html'), true);
  assert.equal(capturedObservationPath('.atkbrain/evidence/tool-katana-1.txt'), true);
  assert.equal(capturedObservationPath('.atkbrain/surface/home.html'), true);
  assert.equal(capturedObservationPath('hosts.txt'), false);
  assert.equal(capturedObservationPath('assets.csv'), false);
});

test('ingest drops hosts and urls outside the approved host', () => {
  const scope = {
    allow: [{ type: 'host', value: 'app.example.test', canonical: 'app.example.test' }],
    deny: [],
  };
  const ops = [
    { op: 'node.upsert', kind: 'host', key: 'app.example.test' },
    { op: 'node.upsert', kind: 'host', key: 'prototype.copy' },
    { op: 'node.upsert', kind: 'host', key: 'head' },
    { op: 'node.upsert', kind: 'domain', key: 'example.test' },
    { op: 'node.upsert', kind: 'domain', key: 'google.com' },
    { op: 'node.upsert', kind: 'webapp', key: 'https://app.example.test/login', attrs: { host: 'app.example.test' } },
    { op: 'node.upsert', kind: 'webapp', key: 'https://cdn.example.net/app.js', attrs: { host: 'cdn.example.net' } },
    { op: 'edge.upsert', from: { kind: 'host', key: 'app.example.test' }, to: { kind: 'webapp', key: 'https://app.example.test/login' }, kind: 'exposes' },
    { op: 'edge.upsert', from: { kind: 'host', key: 'prototype.copy' }, to: { kind: 'webapp', key: 'https://cdn.example.net/app.js' }, kind: 'exposes' },
  ];
  const filtered = filterOpsToScope(scope, ops);
  const hosts = filtered.ops.filter((op) => op.kind === 'host').map((op) => op.key);
  assert.deepEqual(hosts, ['app.example.test']);
  assert.equal(filtered.ops.some((op) => op.kind === 'webapp' && op.attrs?.host === 'cdn.example.net'), false);
  assert.equal(filtered.ops.some((op) => op.kind === 'domain' && op.key === 'example.test'), true);
  assert.equal(filtered.ops.some((op) => op.kind === 'domain' && op.key === 'google.com'), false);
  assert.equal(filtered.ops.some((op) => op.op === 'edge.upsert' && op.from?.key === 'prototype.copy'), false);
  assert.ok(filtered.dropped >= 4);
});
