/**
 * Attack-surface roles derived from names the target already exposed.
 *
 * Nothing here names a project, host, or a private bug list. A parameter or
 * product token is useful only because it is already on the graph.
 */

const ROLE_RULES = Object.freeze([
  Object.freeze({ role: 'file', classes: Object.freeze(['file']), tokens: Object.freeze(['file', 'path', 'template', 'include', 'export', 'upload', 'image', 'download', 'filename', 'attach']) }),
  Object.freeze({ role: 'authz', classes: Object.freeze(['authz']), tokens: Object.freeze(['id', 'uid', 'user', 'owner', 'account', 'order', 'object']) }),
  Object.freeze({ role: 'logic', classes: Object.freeze(['logic']), tokens: Object.freeze(['price', 'qty', 'quantity', 'amount', 'step', 'status', 'count']) }),
  Object.freeze({ role: 'redirect', classes: Object.freeze(['xss']), tokens: Object.freeze(['redirect', 'return', 'callback', 'next', 'goto', 'url']) }),
  Object.freeze({ role: 'code', classes: Object.freeze(['code', 'cmd']), tokens: Object.freeze(['cmd', 'exec', 'command', 'expr', 'template']) }),
  Object.freeze({ role: 'input', classes: Object.freeze(['xss', 'sqli']), tokens: Object.freeze(['search', 'query', 'keyword', 'name', 'key', 'q']) }),
]);

function nameTokens(name) {
  return String(name ?? '')
    .replace(/([a-z\d])([A-Z])/gu, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/u)
    .filter((token) => token.length > 0);
}

const BOARD_CLASSES = new Set(['xss', 'sqli', 'authz', 'leak']);

function ruleMatches(name, rule) {
  const parts = nameTokens(name);
  if (parts.some((part) => rule.tokens.includes(part))) return true;
  const flat = parts.join('');
  return rule.tokens.some((token) => token.length >= 4 && flat.includes(token));
}

const GENERIC_PRODUCT = new Set([
  'unknown', 'http', 'https', 'tcp', 'udp', 'tls', 'ssl', 'web', 'service', 'server', 'generic',
]);

function asStrings(value, limit = 80) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const entry of value) {
    const text = String(entry ?? '').trim();
    if (text.length === 0 || text.length > 80 || seen.has(text.toLowerCase())) continue;
    seen.add(text.toLowerCase());
    out.push(text);
    if (out.length >= limit) break;
  }
  return out;
}

/** Bug classes implied by one observed parameter name. */
export function classesForParameter(name) {
  const text = String(name ?? '').trim();
  if (text.length === 0) return [];
  const classes = [];
  for (const rule of ROLE_RULES) {
    if (!ruleMatches(text, rule)) continue;
    for (const bugClass of rule.classes) {
      if (!BOARD_CLASSES.has(bugClass) || classes.includes(bugClass)) continue;
      classes.push(bugClass);
    }
  }
  return classes;
}

/** Roles implied by one observed parameter name. */
export function rolesForParameter(name) {
  const text = String(name ?? '').trim();
  if (text.length === 0) return [];
  return ROLE_RULES.filter((rule) => ruleMatches(text, rule)).map((rule) => rule.role);
}

/** Parameter names already stored on webapps, findings, or coverage cells. */
export function observedParameters(nodes) {
  const names = [];
  const seen = new Set();
  for (const node of nodes) {
    const bags = [node?.attrs?.parameters, node?.attrs?.parameterNames];
    if (typeof node?.attrs?.parameter === 'string') bags.push([node.attrs.parameter]);
    for (const bag of bags) {
      for (const name of asStrings(bag)) {
        const key = name.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        names.push(name);
      }
    }
  }
  return names;
}

/** Product or version labels already stored on tech or service nodes. */
export function observedProducts(nodes) {
  const labels = [];
  const seen = new Set();
  for (const node of nodes) {
    if (node?.kind !== 'tech' && node?.kind !== 'service') continue;
    const parts = [node.attrs?.product, node.attrs?.version, node.label, node.attrs?.server, node.attrs?.banner];
    for (const part of parts) {
      const text = String(part ?? '').trim();
      if (text.length < 2 || text.length > 80) continue;
      const key = text.toLowerCase();
      if (GENERIC_PRODUCT.has(key) || seen.has(key)) continue;
      if (/^(https?|tcp|udp)\/\d{1,5}$/iu.test(text) || /^\d{1,5}$/u.test(text) || /^[a-z0-9.-]+:\d{1,5}$/iu.test(text)) continue;
      seen.add(key);
      labels.push(text);
    }
  }
  return labels.slice(0, 8);
}

/**
 * Open paths for one class, plus whether another interface of that class was
 * already closed. Closing one interface does not close the rest.
 */
export function classSurface(nodes, bugClass) {
  const cells = nodes.filter((node) => node?.kind === 'coverage' && node.attrs?.bugClass === bugClass);
  const open = [];
  let closed = 0;
  const seen = new Set();
  for (const cell of cells) {
    const path = String(cell.attrs?.path ?? '').trim();
    if (path.length === 0 || seen.has(path)) continue;
    seen.add(path);
    if (cell.status === 'open' || cell.status === 'claimed') open.push(path);
    else if (cell.status === 'seen' || cell.status === 'refuted' || cell.status === 'reported') closed += 1;
  }
  const implied = [];
  for (const name of observedParameters(nodes)) {
    if (classesForParameter(name).includes(bugClass) && !implied.includes(name)) implied.push(name);
  }
  return { open, closed, implied };
}
