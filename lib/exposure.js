/**
 * Safe, read-only web exposure checks.
 *
 * Only `GET`/`HEAD` requests are issued against a fixed list of well-known
 * read-only paths (`DEFAULT_PATHS`). No credentials are tested, no POST bodies
 * and no attack payloads are sent: findings are evidence-backed observations
 * (exposed metadata, listings, missing headers) that the agent can review.
 *
 * Evidence is sanitized: environment/property values are replaced by key names
 * before a finding can enter graph state.
 */
import { DEFAULT_EXPOSURE_PATHS, SEVERITY_RANK } from './constants.js';
import { httpProbe, normaliseVia } from './net.js';
import { InputError, clamp, mapLimit, sha256Hex } from './util.js';
import { localizedFindingDetails, localizedFindingTitle } from './finding-i18n.js';

/** Safe read-only paths probed by default (see constants.js for the source list). */
export const DEFAULT_PATHS = Object.freeze([...DEFAULT_EXPOSURE_PATHS]);

const MAX_FINDINGS = 200;
const MAX_EVIDENCE = 300;
const MAX_BODY_BYTES = 262144;

const DIRECTORY_LISTING_PATTERNS = Object.freeze([
  /<title>\s*index of\b/iu,
  /<h1>\s*index of\b/iu,
  /directory listing for/iu,
  /parent directory<\/a>/iu,
  /\[to parent directory\]/iu,
]);

const ENV_LINE_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/u;
const SENSITIVE_AUTH_PATHS = new Set([
  '/admin',
  '/admin/',
  '/manager/html',
  '/console',
  '/actuator',
  '/actuator/env',
  '/actuator/heapdump',
  '/swagger-ui.html',
  '/v2/api-docs',
  '/v3/api-docs',
  '/openapi.json',
]);

function truncate(value, max = MAX_EVIDENCE) {
  const text = String(value ?? '').replace(/\s+/gu, ' ').trim();
  return text.length > max ? `${text.slice(0, max - 1)}\u2026` : text;
}

function snippet(body, max = 160) {
  return truncate(String(body ?? '').slice(0, max * 2), max);
}

/** One normalized finding object; every field is always present. */
function makeFinding({ template, title, severity, statusCode, path, evidence, recommendation }) {
  const details = localizedFindingDetails(template);
  return {
    template,
    title: localizedFindingTitle(template, title),
    severity,
    statusCode: Number.isInteger(statusCode) ? statusCode : null,
    path: typeof path === 'string' ? path : '/',
    evidence: truncate(evidence),
    description: `${localizedFindingTitle(template, title)}：探测响应中存在对应暴露特征，证据已保存到证据文件。`,
    impact: details.impact,
    recommendation: details.remediation,
    ...(recommendation ? { technicalRecommendation: recommendation } : {}),
  };
}

/** Whether a response body is an HTML directory index. */
export function isDirectoryListing(body) {
  const text = String(body ?? '');
  return DIRECTORY_LISTING_PATTERNS.some((pattern) => pattern.test(text));
}

/** Whether a response body looks like a dotenv file (never returns values). */
export function looksLikeEnvFile(body) {
  const text = String(body ?? '');
  if (text.trimStart().startsWith('<')) return false;
  if (text.length > 100_000) return false;
  const lines = text.split(/\r?\n/u).filter((line) => line.trim().length > 0);
  if (lines.length === 0) return false;
  return lines.some((line) => ENV_LINE_PATTERN.test(line));
}

/** Key names from a dotenv body, never values. */
export function maskEnvBody(body) {
  const keys = [];
  for (const line of String(body ?? '').split(/\r?\n/u)) {
    const match = ENV_LINE_PATTERN.exec(line);
    if (match !== null) keys.push(match[1]);
    if (keys.length >= 10) break;
  }
  return keys.length > 0 ? `keys: ${keys.join(', ')} (values redacted)` : 'environment file body (values redacted)';
}

/** Property names from a Spring actuator/env body, never values. */
function maskPropertySources(body) {
  const text = String(body ?? '');
  const keys = [];
  const pattern = /"(?:name|key)"\s*:\s*"([^"]{1,80})"/gu;
  let match;
  while ((match = pattern.exec(text)) !== null && keys.length < 8) keys.push(match[1]);
  return keys.length > 0 ? `property keys: ${keys.join(', ')} (values redacted)` : 'actuator environment data (values redacted)';
}

function htmlTitle(response) {
  return typeof response.title === 'string' ? response.title : undefined;
}

/** Hash, title and length of a successful document, used to spot a catch-all page. */
export function documentBaseline(response) {
  if (response === null || typeof response !== 'object') return null;
  const status = Number(response.status) || 0;
  if (status < 200 || status >= 300) return null;
  const body = String(response.body ?? '');
  if (body.length === 0) return null;
  return {
    hash: sha256Hex(body),
    length: body.length,
    title: htmlTitle(response) ?? '',
  };
}

/** True when this response is the same document as the site root. */
export function sameDocument(response, baseline) {
  if (baseline === null || baseline === undefined || response === null || typeof response !== 'object') return false;
  const body = String(response.body ?? '');
  if (body.length === 0 || Number(baseline.length) === 0 || typeof baseline.hash !== 'string') return false;
  if (sha256Hex(body) === baseline.hash) return true;
  const title = htmlTitle(response) ?? '';
  return baseline.title.length > 0 && title === baseline.title && body.length === baseline.length;
}

function looksLikeHtml(body, contentType) {
  return contentType.includes('text/html') || /^\s*</u.test(body);
}

const EXECUTABLE_FILE_RE = /\.(?:php|phtml|jsp|aspx|ashx|cgi|action|do)(?:\?|"|'|\s|>|$)/iu;

function artifactSiblingPath(pathName) {
  return /\.(?:bak|old|swp)$|~$/iu.test(String(pathName ?? ''));
}

function looksLikeSource(body, contentType) {
  const text = String(body ?? '');
  if (text.length === 0) return false;
  if (/<\?(?:php|=)/iu.test(text) && !/<\s*html[\s>]/iu.test(text)) return true;
  if (looksLikeHtml(body, contentType)) return false;
  const assignments = text.match(/^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*[=:]/gmu) ?? [];
  return assignments.length >= 2;
}

/** One rule for every Set-Cookie: HTTPS needs Secure, and every cookie needs HttpOnly. */
export function cookieFlagFindings(headers = {}, { https = false, path = '/', status = 200 } = {}) {
  const raw = headers?.['set-cookie'];
  const lines = Array.isArray(raw) ? raw : (typeof raw === 'string' && raw.length > 0 ? [raw] : []);
  const findings = [];
  for (const line of lines) {
    const text = String(line ?? '');
    const name = text.split('=')[0].trim();
    if (name.length === 0) continue;
    const missing = [];
    if (!/;\s*httponly\b/iu.test(text)) missing.push('HttpOnly');
    if (https && !/;\s*secure\b/iu.test(text)) missing.push('Secure');
    if (missing.length === 0) continue;
    findings.push(makeFinding({
      template: 'session-cookie-flags',
      title: 'Session cookie is missing a browser protection flag',
      severity: 'low',
      statusCode: status,
      path,
      evidence: `${name} missing ${missing.join(', ')}`,
      recommendation: 'Set HttpOnly on session cookies and Secure when the application is served over HTTPS.',
    }));
  }
  return findings;
}

function heapDumpBody(body, contentType) {
  if (looksLikeHtml(body, contentType)) return false;
  return body.startsWith('JAVA PROFILE') || contentType.includes('octet-stream') || contentType.includes('hprof');
}

function archiveBody(body, contentType) {
  if (looksLikeHtml(body, contentType)) return false;
  return body.startsWith('PK\u0003\u0004') || contentType.includes('zip') || contentType.includes('octet-stream');
}

function corsFindings(path, response) {
  const headers = response.headers ?? {};
  const allowOrigin = String(headers['access-control-allow-origin'] ?? '');
  if (allowOrigin !== '*') return [];
  const allowCredentials = String(headers['access-control-allow-credentials'] ?? '').toLowerCase() === 'true';
  const findings = [
    makeFinding({
      template: 'cors-wildcard',
      title: 'Permissive CORS policy (Access-Control-Allow-Origin: *)',
      severity: allowCredentials ? 'high' : 'medium',
      statusCode: response.status,
      path,
      evidence: `Access-Control-Allow-Origin: *${allowCredentials ? ' with Access-Control-Allow-Credentials: true' : ''}`,
      recommendation: 'Restrict Access-Control-Allow-Origin to the trusted application origins and remove wildcard CORS from authenticated endpoints.',
    }),
  ];
  return findings;
}

/**
 * Classify one HTTP response for a single probed path.
 * @returns {object[]} findings
 */
export function classifyExposure(path, response, context = {}) {
  const findings = [];
  if (response === null || typeof response !== 'object') return findings;
  const body = String(response.body ?? '');
  const headers = response.headers ?? {};
  const contentType = String(headers['content-type'] ?? '').toLowerCase();
  const status = Number(response.status) || 0;
  const ok = status >= 200 && status < 300;
  const authChallenge = status === 401 || status === 407;
  const add = (template, title, severity, evidence, recommendation) => {
    findings.push(makeFinding({ template, title, severity, statusCode: status, path, evidence, recommendation }));
  };
  const pathName = typeof path === 'string' && path.length > 0 ? path : '/';
  if (sameDocument(response, context.baseline)) return findings;

  findings.push(...corsFindings(pathName, response));
  if (ok && isDirectoryListing(body)) {
    add(
      'directory-listing',
      'Directory listing enabled',
      'medium',
      `HTML directory index returned for ${pathName} (title: ${htmlTitle(response) ?? 'n/a'})`,
      'Disable automatic directory indexes on the web server and return 404 for directories without an explicit index.',
    );
    if (EXECUTABLE_FILE_RE.test(body)) {
      add(
        'served-executable',
        'Listed file is served for execution',
        'high',
        `Index for ${pathName} names a file the server treats as code`,
        'Disable directory indexes and do not execute files from a directory that can be listed.',
      );
    }
  }
  if (ok && artifactSiblingPath(pathName) && looksLikeSource(body, contentType)) {
    add(
      'exposed-source-sibling',
      'Sibling source file is downloadable',
      'high',
      `Backup-style path ${pathName} returned source text`,
      'Remove sibling backup and editor files from the web root.',
    );
  }

  switch (pathName) {
    case '/.git/HEAD':
      if (ok && /^ref:\s+/mu.test(body)) {
        add('exposed-git-repository', 'Git repository metadata exposed', 'critical', `/.git/HEAD returned: ${snippet(body, 120)}`, 'Block access to .git/ and remove repository metadata from the web root; rotate any exposed secrets.');
      }
      break;
    case '/.git/config':
      if (ok && /\[core\]/iu.test(body)) {
        add('exposed-git-config', 'Git config exposed', 'high', 'Git config file returned with a [core] section', 'Block access to .git/ and review the repository for committed secrets.');
      }
      break;
    case '/.env':
      if (ok && looksLikeEnvFile(body)) {
        add('exposed-env-file', 'Environment file exposed', 'critical', maskEnvBody(body), 'Remove .env from the web root, rotate exposed credentials, and deny dotfile access at the web server.');
      }
      break;
    case '/.svn/entries':
      if (ok && body.trim().length > 0) {
        add('exposed-svn-metadata', 'Subversion metadata exposed', 'medium', 'SVN entries file returned', 'Block access to .svn/ and remove VCS metadata from the web root.');
      }
      break;
    case '/.DS_Store':
      if (ok && body.includes('Bud1')) {
        add('exposed-ds-store', 'macOS .DS_Store file exposed', 'low', 'DS_Store header returned; directory structure may leak', 'Deny access to .DS_Store and other OS metadata files.');
      }
      break;
    case '/server-status':
      if (ok && /Apache Server Status/iu.test(body)) {
        add('apache-server-status', 'Apache server-status exposed', 'medium', 'Apache Server Status page returned', 'Restrict /server-status to localhost via the web server configuration.');
      }
      break;
    case '/server-info':
      if (ok && /Apache Server Information/iu.test(body)) {
        add('apache-server-info', 'Apache server-info exposed', 'medium', 'Apache Server Information page returned', 'Restrict /server-info to trusted administrators.');
      }
      break;
    case '/actuator':
      if (ok) add('actuator-root-exposed', 'Spring Actuator endpoint exposed', 'medium', `Actuator root returned HTTP ${status}`, 'Expose only health/info endpoints and require authentication for actuator management endpoints.');
      break;
    case '/actuator/env':
      if (ok && /propertySources|activeProfiles/iu.test(body)) {
        add('actuator-env-exposed', 'Spring Actuator /env exposed', 'high', maskPropertySources(body), 'Disable or authenticate actuator env endpoints; they frequently disclose credentials and configuration.');
      }
      break;
    case '/actuator/health':
      if (ok && /"status"\s*:\s*"UP"/iu.test(body)) {
        add('actuator-health-public', 'Actuator health endpoint public', 'info', 'Health endpoint returned {"status":"UP"}', 'Consider restricting detailed health information to internal monitoring.');
      }
      break;
    case '/actuator/heapdump':
      if (ok && heapDumpBody(body, contentType)) {
        add('actuator-heapdump-exposed', 'Spring Actuator heapdump downloadable', 'critical', `Heap dump response returned (${body.length} bytes decoded)`, 'Disable the heapdump endpoint immediately; heap dumps contain credentials and session tokens.');
      }
      break;
    case '/swagger-ui.html':
    case '/swagger-ui/index.html':
    case '/v2/api-docs':
    case '/v3/api-docs':
    case '/openapi.json':
    case '/api/swagger.json':
      if (ok && /swagger|openapi|"paths"/iu.test(body)) {
        add('api-docs-exposed', 'API documentation exposed', 'medium', `API description returned for ${pathName}`, 'Restrict API documentation to authenticated users or disable it in production.');
      }
      break;
    case '/graphql':
    case '/graphiql':
      if (ok && /graphql|graphiql/iu.test(body)) {
        add('graphql-endpoint-exposed', 'GraphQL endpoint reachable', 'low', `GraphQL response returned for ${pathName}`, 'Require authentication, disable introspection in production, and enforce query depth/cost limits.');
      }
      break;
    case '/admin':
    case '/admin/':
      if (ok) {
        add('admin-interface-reachable', 'Admin interface reachable', 'low', `Admin interface returned HTTP ${status} (title: ${htmlTitle(response) ?? 'n/a'})`, 'Require strong authentication and network-level restrictions for administrative interfaces.');
      } else if (authChallenge) {
        add('admin-interface-protected', 'Admin interface requires authentication', 'info', `HTTP ${status} authentication challenge returned`, 'Keep the interface authenticated and restricted to trusted networks.');
      }
      break;
    case '/manager/html':
      if (ok && /tomcat|manager/iu.test(body)) {
        add('tomcat-manager-exposed', 'Tomcat Manager accessible', 'medium', 'Tomcat Manager page returned', 'Restrict the Tomcat Manager application to localhost/administrators and review manager credentials.');
      } else if (authChallenge) {
        add('tomcat-manager-protected', 'Tomcat Manager requires authentication', 'info', `HTTP ${status} challenge returned`, 'Keep manager access restricted and rotate the manager credentials.');
      }
      break;
    case '/console':
      if (ok && /weblogic|jboss|admin console/iu.test(body)) {
        add('admin-console-exposed', 'Application server console exposed', 'medium', 'Application server administration console returned', 'Restrict the administration console to trusted management networks.');
      }
      break;
    case '/jenkins/':
      if (ok && /jenkins/iu.test(body)) {
        add('jenkins-exposed', 'Jenkins reachable', 'low', 'Jenkins page returned', 'Require authentication and limit network exposure of CI/CD controllers.');
      }
      break;
    case '/phpinfo.php':
      if (ok && /phpinfo\(\)|PHP Version/iu.test(body)) {
        add('phpinfo-exposed', 'phpinfo() output exposed', 'medium', 'phpinfo page returned', 'Remove phpinfo scripts from production and restrict PHP configuration disclosure.');
      }
      break;
    case '/phpMyAdmin/':
      if (ok && /phpmyadmin/iu.test(body)) {
        add('phpmyadmin-exposed', 'phpMyAdmin reachable', 'low', 'phpMyAdmin page returned', 'Restrict database administration interfaces to trusted networks and enforce MFA where possible.');
      }
      break;
    case '/wp-admin/':
    case '/wp-login.php':
      if (ok && /wordpress|wp-content|wp-login/iu.test(body)) {
        add('wordpress-admin-exposed', 'WordPress administration page reachable', 'info', 'WordPress login/admin page returned', 'Enforce authentication hardening and rate limiting for WordPress administration.');
      }
      break;
    case '/robots.txt': {
      if (ok) {
        const disallowed = body
          .split(/\r?\n/u)
          .filter((line) => /disallow:\s*\S*(admin|backup|private|internal|config|secret)/iu.test(line))
          .slice(0, 4);
        if (disallowed.length > 0) {
          add('robots-sensitive-paths', 'robots.txt reveals sensitive paths', 'low', disallowed.join(' | '), 'Do not rely on robots.txt for access control; verify the listed paths are protected.');
        }
      }
      break;
    }
    case '/sitemap.xml':
      if (ok && /<urlset/iu.test(body)) {
        add('sitemap-exposed', 'Sitemap exposed', 'info', snippet(body, 120), 'Review the sitemap for unintended publicly discoverable resources.');
      }
      break;
    case '/crossdomain.xml':
      if (ok && /allow-access-from[^>]*domain\s*=\s*["']\*["']/iu.test(body)) {
        add('permissive-crossdomain-policy', 'Permissive crossdomain.xml', 'info', 'crossdomain.xml allows access from domain="*"', 'Restrict allow-access-from to trusted origins or remove the crossdomain policy.');
      }
      break;
    case '/metrics':
      if (ok && /#\s*(?:HELP|TYPE)\s/u.test(body)) {
        add('metrics-exposed', 'Metrics endpoint exposed', 'medium', 'Prometheus/OpenMetrics data returned', 'Require authentication and network restrictions for metrics endpoints.');
      }
      break;
    case '/health':
      if (ok) {
        add('health-endpoint-public', 'Health endpoint public', 'info', `HTTP ${status} health response`, 'Expose only a minimal health response to untrusted networks.');
      }
      break;
    case '/debug':
    case '/trace':
      if (ok) {
        add('debug-endpoint-exposed', 'Debug/trace endpoint exposed', 'low', `${pathName} returned HTTP ${status}`, 'Disable debug and tracing endpoints in production.');
      }
      break;
    case '/heapdump':
      if (ok && heapDumpBody(body, contentType)) {
        add('heapdump-exposed', 'JVM heap dump downloadable', 'critical', `Heap dump response returned (${body.length} bytes decoded)`, 'Remove heap dumps from the web root and rotate any credentials present in them.');
      }
      break;
    case '/jolokia/':
      if (ok && /jolokia|"value"/iu.test(body)) {
        add('jolokia-exposed', 'Jolokia JMX endpoint exposed', 'medium', 'Jolokia response returned', 'Require authentication and restrict JMX-over-HTTP endpoints.');
      }
      break;
    case '/h2-console':
      if (ok && /h2|console/iu.test(body)) {
        add('h2-console-exposed', 'H2 database console reachable', 'low', 'H2 console page returned', 'Disable the H2 web console in production or restrict it to localhost.');
      }
      break;
    case '/druid/index.html':
      if (ok && /druid/iu.test(body)) {
        add('druid-console-exposed', 'Druid console reachable', 'low', 'Druid console returned', 'Restrict database console access to trusted networks.');
      }
      break;
    case '/nacos/':
      if (ok && /nacos/iu.test(body)) {
        add('nacos-console-exposed', 'Nacos console reachable', 'low', 'Nacos console page returned', 'Require authentication and restrict the Nacos console.');
      }
      break;
    case '/eureka/':
      if (ok && /eureka|instances/iu.test(body)) {
        add('eureka-exposed', 'Eureka registry endpoints exposed', 'low', 'Eureka response returned', 'Require authentication for the registry and avoid exposing instance metadata publicly.');
      }
      break;
    case '/solr/':
      if (ok && /solr/iu.test(body)) {
        add('solr-admin-exposed', 'Solr admin interface reachable', 'low', 'Solr administration page returned', 'Restrict Solr admin endpoints to trusted networks.');
      }
      break;
    case '/kibana':
      if (ok && /kibana/iu.test(body)) {
        add('kibana-exposed', 'Kibana reachable', 'low', 'Kibana page returned', 'Require authentication and restrict Kibana network exposure.');
      }
      break;
    case '/backup.zip':
      if (ok && archiveBody(body, contentType)) {
        add('backup-archive-exposed', 'Backup archive downloadable', 'high', `Backup archive returned (content-type: ${contentType || 'unknown'})`, 'Remove backup archives from the web root and store them in access-controlled storage.');
      }
      break;
    case '/config.php.bak':
      if (ok && body.includes('<?php') && !looksLikeHtml(body, contentType)) {
        add('backup-config-exposed', 'Source/config backup exposed', 'high', 'Backup configuration file returned', 'Remove backup files from the web root and rotate any credentials contained in them.');
      }
      break;
    case '/WEB-INF/web.xml':
      if (ok && /<web-app/iu.test(body)) {
        add('webinf-exposed', 'WEB-INF/web.xml exposed', 'high', 'Java web application descriptor returned', 'Block /WEB-INF/ access at the reverse proxy and review the descriptor for internal paths.');
      }
      break;
    case '/.well-known/security.txt':
      if (ok) {
        add('security-txt-present', 'security.txt published', 'info', snippet(body, 120), 'Keep the security contact information current.');
      }
      break;
    default:
      break;
  }

  if (authChallenge && SENSITIVE_AUTH_PATHS.has(pathName) && !findings.some((finding) => finding.template.endsWith('-protected'))) {
    add('sensitive-path-protected', 'Sensitive path requires authentication', 'info', `HTTP ${status} authentication challenge returned`, 'Keep authentication in place and verify it cannot be bypassed.');
  }

  return findings;
}

/** Header findings for a response that was already stored. Missing headers stay hardening. */
export function recordedHeaderFindings(headers, { https = false, status = 200, path = '/' } = {}) {
  return classifyRoot({ protocol: https ? 'https:' : 'http:' }, { status, headers, body: '' });
}

/** Security-header, CORS and fingerprint findings for the root document. */
function classifyRoot(base, response) {
  const findings = [];
  const headers = response.headers ?? {};
  const status = Number(response.status) || 0;
  if (status < 200 || status >= 300) return findings;
  const missing = [];
  if (headers['x-content-type-options'] === undefined) missing.push('X-Content-Type-Options');
  if (headers['x-frame-options'] === undefined && !/frame-ancestors/iu.test(String(headers['content-security-policy'] ?? ''))) missing.push('X-Frame-Options');
  if (headers['content-security-policy'] === undefined) missing.push('Content-Security-Policy');
  if (headers['referrer-policy'] === undefined) missing.push('Referrer-Policy');
  const https = base.protocol === 'https:';
  if (https && headers['strict-transport-security'] === undefined) missing.push('Strict-Transport-Security');
  findings.push(...cookieFlagFindings(headers, { https, path: '/', status }));
  if (missing.length > 0) {
    findings.push(makeFinding({
      template: 'missing-security-headers',
      title: 'Missing security headers',
      severity: https && missing.includes('Strict-Transport-Security') ? 'medium' : 'low',
      statusCode: status,
      path: '/',
      evidence: `missing: ${missing.join(', ')}`,
      recommendation: 'Add the missing security response headers (CSP, frame protection, content-type sniffing and HSTS on HTTPS).',
    }));
  }
  findings.push(...corsFindings('/', response));
  const server = String(headers.server ?? '').trim();
  if (/[A-Za-z][A-Za-z0-9-]*\/\d+\.\d+/u.test(server)) {
    findings.push(makeFinding({
      template: 'server-version-disclosure',
      title: 'Server version disclosed',
      severity: 'low',
      statusCode: status,
      path: '/',
      evidence: `Server: ${server}`,
      recommendation: 'Suppress detailed server version banners in production.',
    }));
  }
  if (typeof headers['x-powered-by'] === 'string' && headers['x-powered-by'].trim().length > 0) {
    findings.push(makeFinding({
      template: 'technology-disclosure',
      title: 'Technology disclosed via X-Powered-By',
      severity: 'low',
      statusCode: status,
      path: '/',
      evidence: `X-Powered-By: ${headers['x-powered-by']}`,
      recommendation: 'Remove X-Powered-By and similar technology disclosure headers.',
    }));
  }
  if (Array.isArray(response.techs) && response.techs.length > 0) {
    findings.push(makeFinding({
      template: 'technology-fingerprint',
      title: 'Technology fingerprint',
      severity: 'info',
      statusCode: status,
      path: '/',
      evidence: `detected: ${response.techs.join(', ')}`,
      recommendation: 'Confirm detected software versions are supported and patched; do not rely on obscurity for protection.',
    }));
  }
  return findings;
}

function parseBaseUrl(input) {
  const text = String(input ?? '').trim();
  if (text.length === 0) throw new InputError('baseUrl is empty', 'ATK_INVALID_ARGS');
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new InputError(`invalid baseUrl "${text}"`, 'ATK_INVALID_ARGS');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new InputError(`unsupported baseUrl scheme "${url.protocol}"`, 'ATK_INVALID_ARGS');
  }
  url.hash = '';
  return url;
}

async function safeGet(url, options) {
  try {
    return await httpProbe(url, {
      method: 'GET',
      timeoutMs: options.timeoutMs,
      maxBodyBytes: options.maxBodyBytes,
      followRedirects: 0,
      headers: options.headers,
      signal: options.signal,
      offline: options.offline,
      ...(options.via !== null ? { via: options.via } : {}),
    });
  } catch (error) {
    if (error instanceof InputError) throw error;
    return undefined;
  }
}

function finaliseFindings(findings) {
  const byKey = new Map();
  for (const finding of findings) {
    const key = `${finding.template}\u001f${finding.path}`;
    const existing = byKey.get(key);
    if (existing === undefined) {
      byKey.set(key, finding);
      continue;
    }
    const existingRank = SEVERITY_RANK[existing.severity] ?? 0;
    const incomingRank = SEVERITY_RANK[finding.severity] ?? 0;
    if (incomingRank > existingRank) byKey.set(key, finding);
  }
  return [...byKey.values()]
    .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) || a.path.localeCompare(b.path) || a.template.localeCompare(b.template))
    .slice(0, MAX_FINDINGS);
}

/**
 * Run the safe exposure checks against one base URL.
 *
 * @param {string} baseUrlInput origin or URL to probe
 * @param {object} [options] {paths,timeoutMs,maxBodyBytes,via,signal,offline,concurrency,headers}
 * @returns {Promise<object[]>} findings sorted by severity
 */
export async function runExposureChecks(baseUrlInput, options = {}) {
  const base = parseBaseUrl(baseUrlInput);
  const listed = Array.isArray(options.paths)
    ? options.paths.map((entry) => String(entry).trim()).filter((entry) => entry.length > 0)
    : [...DEFAULT_PATHS];
  const extra = Array.isArray(options.extraPaths)
    ? options.extraPaths.map((entry) => String(entry).trim()).filter((entry) => entry.length > 0)
    : [];
  const paths = [...new Set([...extra, ...listed])];
  const timeoutMs = Number.isInteger(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : 5000;
  const maxBodyBytes = Number.isInteger(options.maxBodyBytes) && options.maxBodyBytes > 0 ? options.maxBodyBytes : MAX_BODY_BYTES;
  const concurrency = clamp(Number.isInteger(options.concurrency) && options.concurrency > 0 ? options.concurrency : 6, 1, 16);
  const via = options.via === undefined || options.via === null ? null : normaliseVia(options.via);
  const requestOptions = {
    timeoutMs,
    maxBodyBytes,
    via,
    signal: options.signal,
    offline: options.offline,
    headers: options.headers,
  };

  const findings = [];
  const root = await safeGet(base.href, requestOptions);
  const baseline = documentBaseline(root);
  if (root !== undefined) findings.push(...classifyRoot(base, root));

  const perPath = await mapLimit(paths, concurrency, async (path) => {
    if (options.signal?.aborted) return [];
    let target;
    try {
      target = new URL(path, base);
    } catch {
      return [];
    }
    const response = await safeGet(target.href, requestOptions);
    if (response === undefined) return [];
    return classifyExposure(target.pathname, response, { baseline });
  }, options.signal);

  for (const list of perPath) findings.push(...list);
  return finaliseFindings(findings);
}
