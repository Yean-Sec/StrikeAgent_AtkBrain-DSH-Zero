/**
 * Document text extraction for AtkBrain ingestion.
 *
 * Plain-text formats are read directly. Office Open XML documents (.docx,
 * .xlsx, .pptx) are extracted with the Python 3 interpreter bundled with the
 * Harness runtime (openpyxl / python-docx / python-pptx). The Python process is
 * started with `execFile` (never a shell), the file path is passed as argv, and
 * the child emits one JSON object per line on stdout.
 *
 * Discovery order for the interpreter:
 *   1. `options.pythonPath` (from plugin config)
 *   2. `$DSH_PYTHON`
 *   3. `$DSH_HOME/dsh-runtimes/<runtime>/dependencies/python/bin/python3`
 *   4. `python3` / `python` on `PATH`
 *
 * Failures are actionable `DocumentExtractionError`s with code
 * `ATK_DOC_EXTRACTOR`. PDFs are deliberately not extracted and return
 * `{unsupported:true, guidance}` instead of throwing.
 */
import { execFile } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
import { open, readFile, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { detectDocumentFormat } from './normalize.js';
import { isPlainObject, truncate } from './util.js';

const execFileAsync = promisify(execFile);

const DEFAULT_MAX_BYTES = 32 * 1024 * 1024;
const PYTHON_TIMEOUT_MS = 60000;
const PYTHON_MAX_BUFFER = 32 * 1024 * 1024;
const PROBE_TIMEOUT_MS = 20000;
const MAX_STDOUT_WARNINGS = 20;

/** Error raised when a document cannot be extracted; always code ATK_DOC_EXTRACTOR. */
export class DocumentExtractionError extends Error {
  constructor(message, { code = 'ATK_DOC_EXTRACTOR', guidance, cause } = {}) {
    super(message);
    this.name = 'DocumentExtractionError';
    this.code = code;
    this.guidance = guidance;
    if (cause !== undefined) this.cause = cause;
  }
}

const TEXT_EXTENSIONS = new Set([
  '.txt', '.text', '.list', '.lst', '.log', '.csv', '.tsv', '.tab',
  '.json', '.jsonl', '.ndjson', '.md', '.markdown', '.mdx', '.yaml', '.yml',
]);

const LEGACY_OFFICE_EXTENSIONS = new Set([
  '.doc', '.docm', '.dot', '.dotx', '.xls', '.xlsm', '.xlsb', '.ppt', '.pptm',
  '.pot', '.potx', '.odt', '.ods', '.odp', '.rtf', '.wps',
]);

/** Python probe: prints `{version, missing}`; sys.argv[1:] are importable module names. */
const PYTHON_PROBE_SCRIPT = [
  'import importlib.util, json, sys',
  'missing = []',
  'for name in sys.argv[1:]:',
  '    try:',
  '        if importlib.util.find_spec(name) is None:',
  '            missing.append(name)',
  '    except Exception:',
  '        missing.append(name)',
  'print(json.dumps({"version": sys.version.split()[0], "missing": missing}))',
].join('\n');

/** python-docx extractor: paragraphs then table rows, JSONL on stdout. */
const DOCX_SCRIPT = [
  'import json, sys',
  '',
  'def emit(payload):',
  '    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\\n")',
  '',
  'path = sys.argv[1]',
  'try:',
  '    from docx import Document',
  'except Exception as exc:',
  '    emit({"type": "error", "code": "MISSING_LIB", "message": "python-docx is not importable: %s" % exc})',
  '    sys.exit(3)',
  'try:',
  '    document = Document(path)',
  'except Exception as exc:',
  '    emit({"type": "error", "code": "OPEN_FAILED", "message": "cannot open docx: %s" % exc})',
  '    sys.exit(4)',
  'emit({"type": "meta", "format": "docx"})',
  'for paragraph in document.paragraphs:',
  '    text = (paragraph.text or "").strip()',
  '    if text:',
  '        emit({"type": "line", "text": text})',
  'for table in document.tables:',
  '    for row in table.rows:',
  '        cells = [(cell.text or "").strip() for cell in row.cells]',
  '        if any(cells):',
  '            emit({"type": "row", "cells": cells})',
  'emit({"type": "meta", "format": "docx", "done": True})',
].join('\n');

/** openpyxl extractor: one `sheet` marker plus `row` records per sheet. */
const XLSX_SCRIPT = [
  'import json, sys',
  '',
  'def emit(payload):',
  '    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\\n")',
  '',
  'MAX_SHEETS = 64',
  'MAX_ROWS = 20000',
  'MAX_COLUMNS = 256',
  'path = sys.argv[1]',
  'try:',
  '    from openpyxl import load_workbook',
  'except Exception as exc:',
  '    emit({"type": "error", "code": "MISSING_LIB", "message": "openpyxl is not importable: %s" % exc})',
  '    sys.exit(3)',
  'try:',
  '    workbook = load_workbook(path, read_only=True, data_only=True)',
  'except Exception as exc:',
  '    emit({"type": "error", "code": "OPEN_FAILED", "message": "cannot open xlsx: %s" % exc})',
  '    sys.exit(4)',
  'emit({"type": "meta", "format": "xlsx"})',
  'row_count = 0',
  'stopped = False',
  'for sheet_index, sheet in enumerate(workbook.worksheets):',
  '    if sheet_index >= MAX_SHEETS:',
  '        emit({"type": "truncated", "scope": "sheets"})',
  '        break',
  '    emit({"type": "sheet", "name": str(sheet.title)})',
  '    for row in sheet.iter_rows(values_only=True):',
  '        if row_count >= MAX_ROWS:',
  '            emit({"type": "truncated", "scope": "rows"})',
  '            stopped = True',
  '            break',
  '        cells = []',
  '        for value in row[:MAX_COLUMNS]:',
  '            cells.append("" if value is None else str(value).strip())',
  '        if any(cells):',
  '            emit({"type": "row", "cells": cells})',
  '            row_count += 1',
  '    if stopped:',
  '        break',
  'try:',
  '    workbook.close()',
  'except Exception:',
  '    pass',
  'emit({"type": "meta", "format": "xlsx", "done": True})',
].join('\n');

/** python-pptx extractor: shape text and table rows in slide order. */
const PPTX_SCRIPT = [
  'import json, sys',
  '',
  'def emit(payload):',
  '    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\\n")',
  '',
  'MAX_SLIDES = 500',
  'path = sys.argv[1]',
  'try:',
  '    from pptx import Presentation',
  'except Exception as exc:',
  '    emit({"type": "error", "code": "MISSING_LIB", "message": "python-pptx is not importable: %s" % exc})',
  '    sys.exit(3)',
  'try:',
  '    presentation = Presentation(path)',
  'except Exception as exc:',
  '    emit({"type": "error", "code": "OPEN_FAILED", "message": "cannot open pptx: %s" % exc})',
  '    sys.exit(4)',
  'emit({"type": "meta", "format": "pptx"})',
  'for slide_index, slide in enumerate(presentation.slides):',
  '    if slide_index >= MAX_SLIDES:',
  '        emit({"type": "truncated", "scope": "slides"})',
  '        break',
  '    for shape in slide.shapes:',
  '        try:',
  '            if getattr(shape, "has_text_frame", False):',
  '                text = (shape.text_frame.text or "").strip()',
  '                if text:',
  '                    emit({"type": "line", "text": text})',
  '            if getattr(shape, "has_table", False):',
  '                for row in shape.table.rows:',
  '                    cells = [(cell.text or "").strip() for cell in row.cells]',
  '                    if any(cells):',
  '                        emit({"type": "row", "cells": cells})',
  '        except Exception:',
  '            continue',
  'emit({"type": "meta", "format": "pptx", "done": True})',
].join('\n');

const OFFICE_FORMATS = Object.freeze({
  '.docx': Object.freeze({ modules: ['docx'], pipPackages: ['python-docx'], parseFormat: 'txt', script: DOCX_SCRIPT, documentFormat: 'docx' }),
  '.xlsx': Object.freeze({ modules: ['openpyxl'], pipPackages: ['openpyxl'], parseFormat: 'tsv', script: XLSX_SCRIPT, documentFormat: 'xlsx' }),
  '.pptx': Object.freeze({ modules: ['pptx'], pipPackages: ['python-pptx'], parseFormat: 'txt', script: PPTX_SCRIPT, documentFormat: 'pptx' }),
});

const probeCache = new Map();

/** Whether a path is an executable regular file. */
function isExecutableFile(filePath) {
  try {
    const info = statSync(filePath);
    return info.isFile() && (info.mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

/** Ordered Python interpreter candidates. */
function pythonCandidates(explicitPath) {
  const candidates = [];
  const push = (candidate) => {
    if (typeof candidate !== 'string') return;
    const value = candidate.trim();
    if (value.length === 0 || candidates.includes(value)) return;
    candidates.push(value);
  };
  push(explicitPath);
  push(process.env.DSH_PYTHON);
  const home = typeof process.env.DSH_HOME === 'string' && process.env.DSH_HOME.length > 0
    ? process.env.DSH_HOME
    : path.join(os.homedir(), '.dsh');
  const runtimesRoot = path.join(home, 'dsh-runtimes');
  try {
    const runtimes = readdirSync(runtimesRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort((left, right) => left.localeCompare(right));
    for (const runtime of runtimes) {
      const candidate = path.join(runtimesRoot, runtime, 'dependencies', 'python', 'bin', 'python3');
      if (isExecutableFile(candidate)) push(candidate);
    }
  } catch {
    // No bundled runtimes directory: fall through to PATH candidates.
  }
  push('python3');
  push('python');
  for (const candidate of ['/usr/bin/python3', '/usr/local/bin/python3', '/opt/homebrew/bin/python3']) {
    if (isExecutableFile(candidate)) push(candidate);
  }
  return candidates;
}

/** Probe one interpreter for a version and a list of importable modules. */
async function probePython(command, modules) {
  const cacheKey = `${command}\u001f${modules.join(',')}`;
  if (probeCache.has(cacheKey)) return probeCache.get(cacheKey);
  let result;
  try {
    const { stdout } = await execFileAsync(command, ['-c', PYTHON_PROBE_SCRIPT, ...modules], {
      timeout: PROBE_TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
      encoding: 'utf8',
      windowsHide: true,
    });
    const lines = String(stdout ?? '').trim().split(/\r?\n/u);
    const last = lines[lines.length - 1];
    const parsed = JSON.parse(last);
    if (typeof parsed?.version === 'string') {
      result = {
        version: parsed.version,
        missing: Array.isArray(parsed.missing) ? parsed.missing.filter((name) => typeof name === 'string') : [],
      };
    }
  } catch {
    result = undefined;
  }
  probeCache.set(cacheKey, result);
  return result;
}

/**
 * Locate a Python 3 interpreter that can import the requested modules.
 *
 * @param {{pythonPath?:string, modules?:string[]}} [options]
 * @returns {Promise<{command?:string, version?:string, missing:string[], tried:string[]}>}
 *          `command` is undefined when no interpreter could even be started.
 */
export async function findPython(options = {}) {
  const opts = isPlainObject(options) ? options : {};
  const requested = Array.isArray(opts.modules)
    ? opts.modules.filter((module) => typeof module === 'string' && /^[a-z0-9_.]+$/iu.test(module))
    : [];
  const tried = [];
  let runnable;
  for (const command of pythonCandidates(opts.pythonPath)) {
    tried.push(command);
    const probe = await probePython(command, requested);
    if (probe === undefined) continue;
    if (probe.missing.length === 0) {
      return { command, version: probe.version, missing: [], tried };
    }
    if (runnable === undefined) {
      runnable = { command, version: probe.version, missing: probe.missing };
    }
  }
  if (runnable !== undefined) return { ...runnable, tried };
  return { command: undefined, version: undefined, missing: requested, tried };
}

/** Parse the JSONL stream emitted by an embedded extractor script. */
function parseExtractorJsonl(stdout) {
  const meta = { format: undefined, truncated: false };
  const textParts = [];
  const warnings = [];
  let error;
  const lines = String(stdout ?? '').split(/\r?\n/u);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    if (!line.startsWith('{')) {
      if (warnings.length < MAX_STDOUT_WARNINGS) {
        warnings.push({ reason: 'python-stdout', raw: truncate(line, 200) });
      }
      continue;
    }
    let payload;
    try {
      payload = JSON.parse(line);
    } catch {
      if (warnings.length < MAX_STDOUT_WARNINGS) {
        warnings.push({ reason: 'python-invalid-jsonl', raw: truncate(line, 200) });
      }
      continue;
    }
    if (payload === null || typeof payload !== 'object') continue;
    if (payload.type === 'meta') {
      if (typeof payload.format === 'string') meta.format = payload.format;
      if (payload.done === true) meta.done = true;
      if (payload.truncated === true) meta.truncated = true;
    } else if (payload.type === 'error') {
      error = {
        code: typeof payload.code === 'string' ? payload.code : 'EXTRACT_FAILED',
        message: typeof payload.message === 'string' ? payload.message : 'extraction failed',
      };
    } else if (payload.type === 'line') {
      if (typeof payload.text === 'string' && payload.text.length > 0) textParts.push(payload.text);
    } else if (payload.type === 'row') {
      const cells = Array.isArray(payload.cells) ? payload.cells : [];
      const rowText = cells
        .map((cell) => (cell === null || cell === undefined ? '' : String(cell)))
        .join('\t')
        .replace(/\t+$/u, '');
      if (rowText.trim().length > 0) textParts.push(rowText);
    } else if (payload.type === 'sheet') {
      const name = typeof payload.name === 'string'
        ? payload.name.replace(/\s+/gu, ' ').trim().slice(0, 80)
        : '';
      textParts.push(name.length > 0 ? `# sheet: ${name}` : '# sheet');
    } else if (payload.type === 'truncated') {
      meta.truncated = true;
    }
  }
  return { text: textParts.join('\n'), meta, warnings, error };
}

/** Run one embedded extractor script against a file path. */
async function runPythonExtractor(command, script, filePath) {
  let stdout = '';
  let stderr = '';
  let failure;
  try {
    const result = await execFileAsync(command, ['-c', script, filePath], {
      timeout: PYTHON_TIMEOUT_MS,
      maxBuffer: PYTHON_MAX_BUFFER,
      encoding: 'utf8',
      windowsHide: true,
      env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    });
    stdout = String(result.stdout ?? '');
    stderr = String(result.stderr ?? '');
  } catch (error) {
    failure = error;
    if (error !== null && typeof error === 'object') {
      if (typeof error.stdout === 'string') stdout = error.stdout;
      if (typeof error.stderr === 'string') stderr = error.stderr;
    }
  }
  const parsed = parseExtractorJsonl(stdout);
  const base = path.basename(filePath);
  if (parsed.error !== undefined) {
    const code = parsed.error.code;
    const missingLibrary = code === 'MISSING_LIB';
    throw new DocumentExtractionError(
      `python extractor for ${base} reported ${code}: ${truncate(parsed.error.message, 500)}`,
      {
        guidance: missingLibrary
          ? 'Install the missing Python package (pip install python-docx openpyxl python-pptx) in the interpreter selected by config.pythonPath or $DSH_PYTHON, then retry.'
          : 'Verify the file opens in its native application (offices files can be encrypted or truncated), then retry or convert it to plain text.',
      },
    );
  }
  if (failure !== undefined) {
    const timedOut = failure.killed === true || /timed out|ETIMEDOUT/iu.test(String(failure.message ?? ''));
    const detail = truncate(String(stderr.length > 0 ? stderr : failure.message ?? 'unknown error'), 500);
    throw new DocumentExtractionError(
      timedOut
        ? `python extraction of ${base} timed out after ${PYTHON_TIMEOUT_MS}ms`
        : `python extraction of ${base} failed: ${detail}`,
      {
        guidance: timedOut
          ? 'The document may be very large. Split it or raise the extraction timeout in the tool configuration.'
          : `Python ran but could not extract ${base}. Check that the bundled interpreter has ${'python-docx/openpyxl/python-pptx'} installed, or set config.pythonPath.`,
      },
    );
  }
  return parsed;
}

/** Return a stable "unsupported" result for PDFs (never silent). */
function pdfUnsupported(filePath) {
  return {
    unsupported: true,
    format: 'pdf',
    documentFormat: 'pdf',
    text: '',
    via: 'none',
    file: path.basename(filePath),
    warnings: [],
    guidance: 'PDF text extraction is not bundled with AtkBrain. Convert the PDF to text first (for example: `pdftotext report.pdf report.txt`), then ingest the .txt file; or export the source document to .docx/.xlsx and ingest that.',
  };
}

/** Read a plain-text document. */
async function extractPlainText(filePath, maxBytes) {
  const buffer = await readFile(filePath);
  if (buffer.length > maxBytes) {
    throw new DocumentExtractionError(
      `${path.basename(filePath)} is ${buffer.length} bytes; extraction limit is ${maxBytes} bytes`,
      { guidance: 'Raise maxBytes for this document or split it before ingesting.' },
    );
  }
  const text = buffer.toString('utf8');
  const warnings = [];
  const nulIndex = buffer.indexOf(0);
  if (nulIndex >= 0) warnings.push({ reason: 'nul-bytes', offset: nulIndex });
  const format = detectDocumentFormat(path.basename(filePath), text);
  return { text, format, via: 'text', documentFormat: format, file: path.basename(filePath), warnings };
}

/** Sniff a file's leading bytes into a coarse kind. */
async function sniffFileKind(filePath) {
  let handle;
  try {
    handle = await open(filePath, 'r');
    const buffer = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const head = buffer.subarray(0, bytesRead);
    if (head.length >= 4 && head[0] === 0x25 && head[1] === 0x50 && head[2] === 0x44 && head[3] === 0x46) return 'pdf';
    if (head.length >= 2 && head[0] === 0x50 && head[1] === 0x4b) return 'zip';
    if (head.includes(0)) return 'binary';
    return 'text';
  } finally {
    await handle?.close();
  }
}

/** Extract an Office Open XML document with bundled Python. */
async function extractOffice(filePath, spec, options) {
  const base = path.basename(filePath);
  const python = await findPython({ pythonPath: options.pythonPath, modules: spec.modules });
  if (python.command === undefined) {
    const missing = python.missing.length > 0 ? python.missing.join(', ') : spec.modules.join(', ');
    throw new DocumentExtractionError(
      `cannot extract ${base}: no Python 3 interpreter with required modules (${missing}) was found`,
      {
        guidance: `Install Python 3 with ${spec.pipPackages.map((name) => `pip install ${name}`).join(' and ')}, then set config.pythonPath or $DSH_PYTHON to that interpreter. Tried: ${python.tried.join(', ')}`,
      },
    );
  }
  const extracted = await runPythonExtractor(python.command, spec.script, filePath);
  const warnings = [...extracted.warnings];
  if (extracted.meta.truncated === true) warnings.push({ reason: 'extraction-truncated' });
  if (extracted.text.trim().length === 0) warnings.push({ reason: 'empty-document' });
  return {
    text: extracted.text,
    format: spec.parseFormat,
    via: 'python',
    documentFormat: extracted.meta.format ?? spec.documentFormat,
    python: python.command,
    file: base,
    warnings,
  };
}

/**
 * Extract text from a document file.
 *
 * @param {string} filePath absolute or workspace-relative document path.
 * @param {{pythonPath?:string, maxBytes?:number}} [options]
 * @returns {Promise<{
 *   text:string, format:string, via:'python'|'text'|'none', documentFormat?:string,
 *   warnings:object[], file?:string, python?:string, unsupported?:true, guidance?:string
 * }>}
 * @throws {DocumentExtractionError} with code `ATK_DOC_EXTRACTOR` when the file
 *         cannot be read, exceeds `maxBytes`, or Python/Office libraries are missing.
 */
export async function extractDocumentText(filePath, options = {}) {
  const opts = isPlainObject(options) ? options : {};
  if (typeof filePath !== 'string' || filePath.trim().length === 0) {
    throw new DocumentExtractionError('filePath is required', {
      guidance: 'Pass a path to a .txt/.csv/.tsv/.json/.jsonl/.md/.docx/.xlsx/.pptx file.',
    });
  }
  const target = filePath.trim();
  const maxBytes = Number.isFinite(opts.maxBytes) && opts.maxBytes > 0 ? opts.maxBytes : DEFAULT_MAX_BYTES;
  let info;
  try {
    info = await stat(target);
  } catch (error) {
    throw new DocumentExtractionError(`cannot access ${target}: ${error.message}`, {
      guidance: 'Verify the path exists and is readable by the Host process.',
      cause: error,
    });
  }
  if (!info.isFile()) {
    throw new DocumentExtractionError(`${target} is not a regular file`, {
      guidance: 'Pass a file path, not a directory.',
    });
  }
  if (info.size > maxBytes) {
    throw new DocumentExtractionError(`${target} is ${info.size} bytes; extraction limit is ${maxBytes} bytes`, {
      guidance: 'Raise maxBytes for this document or split it before ingesting.',
    });
  }
  const extension = path.extname(target).toLowerCase();
  if (extension === '.pdf') return pdfUnsupported(target);
  if (TEXT_EXTENSIONS.has(extension)) return await extractPlainText(target, maxBytes);
  const office = OFFICE_FORMATS[extension];
  if (office !== undefined) return await extractOffice(target, office, opts);
  if (LEGACY_OFFICE_EXTENSIONS.has(extension)) {
    throw new DocumentExtractionError(
      `${path.basename(target)} uses a legacy/binary Office or RTF format (${extension}) that AtkBrain cannot parse`,
      {
        guidance: 'Re-save the document as .docx/.xlsx/.pptx (or export it to .txt/.csv) and ingest that file.',
      },
    );
  }
  const kind = await sniffFileKind(target);
  if (kind === 'pdf') return pdfUnsupported(target);
  if (kind === 'zip') {
    throw new DocumentExtractionError(
      `${path.basename(target)} looks like a ZIP-based document but has no usable extension (${extension || 'none'})`,
      { guidance: 'Rename it to .docx/.xlsx/.pptx if that is what it is, or convert it to plain text first.' },
    );
  }
  if (kind === 'text') return await extractPlainText(target, maxBytes);
  throw new DocumentExtractionError(`unsupported document type for ${path.basename(target)}`, {
    guidance: 'Supported inputs: plain text (txt/csv/tsv/json/jsonl/md), .docx, .xlsx, .pptx. Convert PDFs and legacy Office files to text first.',
  });
}
