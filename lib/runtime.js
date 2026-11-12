/**
 * Per-plugin runtime: shared resolver, tunnel registry, workspace file helpers.
 *
 * Everything here is process-local. Durable graph state comes exclusively from
 * the session projection; these resources only support live collection.
 */
import path from 'node:path';

import { createResolver } from './dns.js';
import { createTunnelManager } from './tunnel.js';
import { runProbe } from './probe.js';
import {
  byteLength,
  ensureDir,
  artifactAbsolute,
  InputError,
  isPluginArtifactRelative,
  isSourceTree,
  safeFileName,
  sha256Hex,
  workspaceOf,
  writeFileSecure,
} from './util.js';

/** Create one runtime owned by a plugin activation. */
export function createRuntime({ ctx, config, logger }) {
  const resolver = createResolver({
    servers: config.dnsResolvers,
    timeoutMs: config.dnsTimeoutMs,
    offline: config.offline === true,
  });
  const tunnels = createTunnelManager({ config, logger });
  let stateProxy = null;

  function workspace(agent) {
    return workspaceOf(agent);
  }

  function directory(agent, configured, fallback) {
    const target = typeof configured === 'string' && configured.length > 0 ? configured : fallback;
    if (path.isAbsolute(target)) {
      if (isSourceTree(workspace(agent)) || isSourceTree(target)) throw new InputError('测试记录不能写进源代码目录，请换一个新建的测试目录');
      return target;
    }
    const logical = isPluginArtifactRelative(target) ? target : `.atkbrain/${target.replace(/^\.?\//u, '')}`;
    return artifactAbsolute(agent, logical);
  }

  /**
   * Write one evidence artifact under the session workspace.
   * @returns {{path:string, relative:string, sha256:string, bytes:number, mediaType:string}}
   */
  async function writeEvidence(agent, name, content, mediaType = 'application/json') {
    const text = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
    const directoryPath = directory(agent, config.evidenceDir, '.atkbrain/evidence');
    const extension = mediaType === 'application/x-ndjson' ? '.jsonl' : mediaType === 'text/plain' ? '.txt' : '.json';
    const base = safeFileName(name, 'evidence');
    const fileName = `${base}-${sha256Hex(text).slice(0, 10)}${extension}`;
    const absolute = path.join(directoryPath, fileName);
    await ensureDir(directoryPath);
    await writeFileSecure(absolute, text);
    const logicalDir = path.isAbsolute(String(config.evidenceDir ?? ''))
      ? null
      : String(config.evidenceDir ?? '.atkbrain/evidence').replace(/\\/gu, '/');
    return {
      path: absolute,
      relative: logicalDir === null ? fileName : path.posix.join(logicalDir, fileName),
      sha256: sha256Hex(text),
      bytes: byteLength(text),
      mediaType,
    };
  }

  /**
   * Write one report file under the session workspace.
   * @returns {{path:string, relative:string, sha256:string, bytes:number}}
   */
  async function writeReportFile(agent, fileName, content) {
    const directoryPath = directory(agent, config.reportDir, '.atkbrain/reports');
    const storedName = safeFileName(fileName, 'report');
    const absolute = path.join(directoryPath, storedName);
    await ensureDir(directoryPath);
    await writeFileSecure(absolute, content);
    const logicalDir = path.isAbsolute(String(config.reportDir ?? ''))
      ? null
      : String(config.reportDir ?? '.atkbrain/reports').replace(/\\/gu, '/');
    return {
      path: absolute,
      relative: logicalDir === null ? storedName : path.posix.join(logicalDir, storedName),
      sha256: sha256Hex(content),
      bytes: byteLength(content),
    };
  }

  async function writeReportAt(agent, relativePath, content) {
    const logical = String(relativePath ?? '').trim().replace(/\\/gu, '/').replace(/^\.\//u, '');
    if (!isPluginArtifactRelative(logical) || logical.includes('..')) {
      throw new Error(`report path must stay in the private run directory: ${relativePath}`);
    }
    const absolute = artifactAbsolute(agent, logical);
    await ensureDir(path.dirname(absolute));
    await writeFileSecure(absolute, content);
    return {
      path: absolute,
      relative: logical,
      sha256: sha256Hex(content),
      bytes: byteLength(content),
    };
  }

  function dispose() {
    tunnels.dispose();
  }

  async function probe(request, options = {}) {
    return runProbe(request, {
      config,
      resolver,
      signal: options.signal,
      scopeGuard: options.scopeGuard,
      proxy: options.proxy ?? stateProxy,
    });
  }

  return {
    config,
    logger,
    resolver,
    tunnels,
    workspace,
    writeEvidence,
    writeReportFile,
    writeReportAt,
    probe,
    runProbe: probe,
    set proxy(value) { stateProxy = value; },
    get proxy() { return stateProxy; },
    dispose,
  };
}
