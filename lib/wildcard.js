/**
 * Wildcard-DNS detection and host classification.
 *
 * The algorithm follows the engagement plan:
 *   1. send >= 3 high-entropy labels (HMAC-SHA256 of salt+zone+index) over
 *      >= 2 rounds and ask A/AAAA/CNAME for each,
 *   2. guard against resolvers that synthesize everything by requiring a
 *      negative answer for `<random>.invalid`,
 *   3. check that the zone apex actually exists (NS/SOA),
 *   4. derive a stable signature (A/AAAA sets + CNAME templates with
 *      `{label}` substitution) and detect CDN-fronted wildcards,
 *   5. report confirmed / suspect / inconclusive / cleared with a confidence.
 *
 * Wildcard probing never deletes or rewrites host records: hosts are classified,
 * their observed answers are returned as evidence, and callers decide what to
 * store.
 */
import { createHmac, randomBytes } from 'node:crypto';

import { canonicalIp } from './cidr.js';
import { canonicalHost } from './scope.js';
import { abortError } from './socks.js';
import { clamp, invalid } from './util.js';

const ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
const LABEL_LENGTH = 10;
const DEFAULT_PROBES = 3;
const DEFAULT_ROUNDS = 2;
/** A confirmed verdict needs at least this many probes across this many rounds. */
export const MIN_PROBES = 3;
export const MIN_ROUNDS = 2;
const MAX_PROBES = 20;
const MAX_ROUNDS = 6;
const MAX_WARNINGS = 20;

/** CNAME suffixes that indicate a wildcard is fronted by shared CDN infra. */
export const CDN_CNAME_SUFFIXES = Object.freeze([
  'cloudfront.net',
  'akamai.net',
  'akamaiedge.net',
  'akamaitechnologies.com',
  'edgesuite.net',
  'edgekey.net',
  'fastly.net',
  'fastlylb.net',
  'azureedge.net',
  'trafficmanager.net',
  'cloudflare.net',
  'cloudflare.com',
  'herokudns.com',
  'herokussl.com',
  'cdn77.org',
  'stackpathdns.com',
  'incapdns.net',
  'msecnd.net',
  'lldns.net',
  'googlehosted.com',
  'fbcdn.net',
  'amazonaws.com',
]);

function positiveInteger(value, fallback) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function asStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((entry) => typeof entry === 'string' && entry.trim().length > 0).map((entry) => entry.trim());
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function normaliseCname(value) {
  return String(value ?? '').trim().toLowerCase().replace(/\.+$/u, '');
}

function hasAnswers(probe) {
  return probe.a.length > 0 || probe.aaaa.length > 0 || probe.cname.length > 0;
}

function summariseStatuses(probes) {
  const counts = new Map();
  for (const probe of probes) counts.set(probe.status, (counts.get(probe.status) ?? 0) + 1);
  return [...counts.entries()].map(([status, count]) => `${status}:${count}`).join(', ') || 'none';
}

/**
 * Generate the randomized probe labels for a zone. `salt` makes the set stable
 * for tests/evidence while random per run when omitted.
 * @returns {{label:string,round:number}[]}
 */
export function generateProbeLabels({ zone, salt, rounds = DEFAULT_ROUNDS, probes = DEFAULT_PROBES } = {}) {
  const zoneName = canonicalHost(zone);
  if (zoneName.length === 0) invalid('wildcard zone is empty');
  const roundCount = clamp(positiveInteger(rounds, DEFAULT_ROUNDS), 1, MAX_ROUNDS);
  const probeCount = clamp(positiveInteger(probes, DEFAULT_PROBES), 1, MAX_PROBES);
  const hmacSalt = String(salt ?? randomBytes(16).toString('hex'));
  const seen = new Set();
  const labels = [];
  for (let round = 0; round < roundCount; round += 1) {
    for (let index = 0; index < probeCount; index += 1) {
      labels.push({ label: makeLabel(hmacSalt, `${zoneName}\u001f${round}\u001f${index}`, seen), round });
    }
  }
  return labels;
}

/** One HMAC-SHA256 derived alphanumeric label, unique within `seen`. */
function makeLabel(hmacSalt, seed, seen) {
  let nonce = 0;
  for (;;) {
    const digest = createHmac('sha256', hmacSalt).update(`${seed}\u001f${nonce}`).digest();
    let label = '';
    for (let byte = 0; byte < LABEL_LENGTH; byte += 1) {
      label += ALPHABET[digest[byte] % ALPHABET.length];
    }
    if (!seen.has(label)) {
      seen.add(label);
      return label;
    }
    nonce += 1;
  }
}

/** Guard label lives in the reserved `.invalid` TLD. */
function guardLabelFor(zone, salt) {
  const hmacSalt = String(salt ?? randomBytes(16).toString('hex'));
  return makeLabel(hmacSalt, `guard\u001f${zone}`, new Set());
}

/** Whether a CNAME target resolves through known shared CDN infrastructure. */
export function isCdnCname(value) {
  const target = normaliseCname(value).replace(/\{label\}/gu, 'x');
  if (target.length === 0) return false;
  return CDN_CNAME_SUFFIXES.some((suffix) => target === suffix || target.endsWith(`.${suffix}`));
}

/**
 * Turn a CNAME target into a template by substituting the probe label.
 * This keeps the signature stable across independent probe labels.
 */
function cnameTemplate(target, probeLabel) {
  const name = normaliseCname(target);
  if (name.startsWith(`${probeLabel}.`)) return `{label}${name.slice(probeLabel.length)}`;
  if (name === probeLabel) return '{label}';
  return name;
}

/**
 * Derive the stable signature from probe observations.
 * @returns {{signature:{a:string[],aaaa:string[],cnameTemplates:string[]}, stable:boolean, distinct:number}}
 */
export function computeWildcardSignature(probes) {
  const answered = probes.filter((probe) => probe.status === 'ok' && hasAnswers(probe));
  if (answered.length === 0) {
    return { signature: { a: [], aaaa: [], cnameTemplates: [] }, stable: true, distinct: 0 };
  }
  const counts = new Map();
  for (const probe of answered) {
    const entry = {
      a: uniqueSorted(asStringArray(probe.a).map((ip) => canonicalIp(ip) ?? ip)),
      aaaa: uniqueSorted(asStringArray(probe.aaaa).map((ip) => canonicalIp(ip) ?? ip)),
      cnameTemplates: uniqueSorted(asStringArray(probe.cname).map((target) => cnameTemplate(target, probe.label))),
    };
    const key = JSON.stringify(entry);
    const current = counts.get(key);
    if (current === undefined) counts.set(key, { entry, count: 1 });
    else current.count += 1;
  }
  const ranked = [...counts.values()].sort((a, b) => b.count - a.count);
  return { signature: ranked[0].entry, stable: ranked.length === 1, distinct: ranked.length };
}

/**
 * Confidence formula for a wildcard verdict.
 * Base confidence per verdict plus evidence strength (coverage, stability,
 * probe/round minimums, guard result), minus a CDN uncertainty penalty.
 * Clamped to 0.05..0.95 so a probe never claims absolute certainty.
 */
export function computeWildcardConfidence(status, signals = {}) {
  const base = { confirmed: 0.55, suspect: 0.32, inconclusive: 0.12, cleared: 0.55 }[status] ?? 0.2;
  const answeredRatio = clamp(Number(signals.answeredRatio) || 0, 0, 1);
  const strength = 0.18 * answeredRatio
    + (signals.stable === true ? 0.08 : 0)
    + (signals.rounds >= MIN_ROUNDS ? 0.06 : 0)
    + (signals.probes >= MIN_PROBES ? 0.06 : 0);
  const guard = signals.guardNegative === true ? 0.07 : -0.25;
  const cdnPenalty = signals.cdn === true ? 0.05 : 0;
  const apexAdjust = signals.status === 'confirmed' && signals.apex === false ? -0.05 : 0;
  const apexBonus = signals.status === 'cleared' && signals.apex === true ? 0.08 : 0;
  let confidence = base + strength + guard - cdnPenalty + apexAdjust + apexBonus;
  if (status === 'inconclusive') confidence = Math.min(confidence, 0.3);
  if (status === 'suspect') confidence = Math.min(confidence, 0.65);
  return Number(clamp(confidence, 0.05, 0.95).toFixed(2));
}

function combineStatuses(results) {
  if (results.some((result) => result?.status === 'ok')) return 'ok';
  if (results.every((result) => result?.status === 'nxdomain')) return 'nxdomain';
  if (results.some((result) => result?.status === 'timeout')) return 'timeout';
  if (results.some((result) => result?.status === 'servfail')) return 'servfail';
  return 'error';
}

async function queryLabel(resolver, fqdn, options) {
  const queryOptions = { timeoutMs: options.timeoutMs, signal: options.signal };
  const [a, aaaa, cname] = await Promise.all([
    resolver.query(fqdn, 'A', queryOptions),
    resolver.query(fqdn, 'AAAA', queryOptions),
    resolver.query(fqdn, 'CNAME', queryOptions),
  ]);
  return {
    status: combineStatuses([a, aaaa, cname]),
    a: uniqueSorted(asStringArray(a?.answers).map((ip) => canonicalIp(ip) ?? ip)),
    aaaa: uniqueSorted(asStringArray(aaaa?.answers).map((ip) => canonicalIp(ip) ?? ip)),
    cname: uniqueSorted(asStringArray(cname?.answers).map(normaliseCname)),
  };
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortError(signal);
}

/**
 * Probe one zone for wildcard DNS behaviour.
 *
 * @param {object} resolver object with `query(name, type)` and `apexExists(zone)`
 * @param {string} zoneInput zone apex to probe
 * @param {object} [options] {probes=3, rounds=2, timeoutMs=3000, signal, salt}
 */
export async function probeWildcardZone(resolver, zoneInput, options = {}) {
  if (resolver === null || typeof resolver !== 'object' || typeof resolver.query !== 'function') {
    invalid('probeWildcardZone requires a resolver with a query() method');
  }
  const zone = canonicalHost(zoneInput);
  if (zone.length === 0) invalid('wildcard zone is empty');
  const probeCount = clamp(positiveInteger(options.probes, DEFAULT_PROBES), 1, MAX_PROBES);
  const rounds = clamp(positiveInteger(options.rounds, DEFAULT_ROUNDS), 1, MAX_ROUNDS);
  const timeoutMs = positiveInteger(options.timeoutMs, 3000);
  const { signal } = options;
  const warnings = [];
  const warn = (message) => {
    if (warnings.length < MAX_WARNINGS && !warnings.includes(message)) warnings.push(message);
  };

  const labels = generateProbeLabels({ zone, salt: options.salt, rounds, probes: probeCount });
  const guardLabel = guardLabelFor(zone, options.salt);
  const queryOptions = { timeoutMs, signal };

  if (signal?.aborted) throw abortError(signal);
  let apex = false;
  try {
    apex = typeof resolver.apexExists === 'function' ? (await resolver.apexExists(zone)) === true : false;
  } catch (error) {
    warn(`zone apex check failed: ${String(error?.message ?? error)}`);
    apex = false;
  }

  throwIfAborted(signal);
  let guard;
  try {
    guard = await queryLabel(resolver, `${guardLabel}.invalid`, queryOptions);
  } catch (error) {
    if (signal?.aborted) throw abortError(signal);
    guard = { status: 'error', a: [], aaaa: [], cname: [], error: String(error?.message ?? error) };
  }
  const guardSynthetic = guard.status === 'ok' && hasAnswers(guard);
  const guardNegative = guard.status === 'nxdomain' || (guard.status === 'ok' && !hasAnswers(guard));
  if (guardSynthetic) {
    warn(`resolver synthesized answers for the guard name ${guardLabel}.invalid; wildcard evidence is unreliable`);
  } else if (!guardNegative) {
    warn(`guard probe ${guardLabel}.invalid returned ${guard.status}; wildcard evidence is unreliable`);
  } else if (guard.status !== 'nxdomain') {
    warn(`guard name ${guardLabel}.invalid returned NODATA instead of NXDOMAIN; treated as negative`);
  }

  const probes = [];
  for (const entry of labels) {
    throwIfAborted(signal);
    try {
      const observed = await queryLabel(resolver, `${entry.label}.${zone}`, queryOptions);
      probes.push({ label: entry.label, status: observed.status, a: observed.a, aaaa: observed.aaaa, cname: observed.cname });
    } catch (error) {
      if (signal?.aborted) throw abortError(signal);
      probes.push({ label: entry.label, status: 'error', a: [], aaaa: [], cname: [] });
      warn(`probe ${entry.label}.${zone} failed: ${String(error?.message ?? error)}`);
    }
  }

  const { signature, stable, distinct } = computeWildcardSignature(probes);
  const answered = probes.filter((probe) => probe.status === 'ok' && hasAnswers(probe));
  const answeredRatio = probes.length === 0 ? 0 : answered.length / probes.length;
  const failed = probes.filter((probe) => probe.status === 'timeout' || probe.status === 'servfail' || probe.status === 'error');
  const emptyOk = probes.filter((probe) => probe.status === 'ok' && !hasAnswers(probe));
  const cdn = signature.cnameTemplates.some(isCdnCname)
    || probes.some((probe) => probe.cname.some(isCdnCname));

  let status;
  let reason;
  if (guardSynthetic) {
    status = 'inconclusive';
    reason = `resolver synthesized records for the guard name ${guardLabel}.invalid; wildcard evidence is unreliable`;
  } else if (!guardNegative) {
    status = 'inconclusive';
    reason = `guard probe ${guardLabel}.invalid did not return NXDOMAIN (status: ${guard.status}); wildcard evidence is unreliable`;
  } else if (answered.length === 0) {
    if (failed.length === probes.length && probes.length > 0) {
      status = 'inconclusive';
      reason = `all ${probes.length} random-label probes failed (${summariseStatuses(probes)}); cannot determine wildcard state`;
    } else if (failed.length > 0) {
      status = 'suspect';
      reason = `${failed.length}/${probes.length} random-label probes failed (${summariseStatuses(failed)}); wildcard state is uncertain`;
      warn('partial probe failures; rerun with a different resolver to confirm');
    } else {
      status = 'cleared';
      reason = apex
        ? `zone apex resolves but all ${probes.length} random labels were negative; no wildcard records observed`
        : `zone apex does not resolve and all ${probes.length} random labels were negative; no wildcard zone`;
      if (emptyOk.length > 0) {
        warn(`${emptyOk.length}/${probes.length} probes returned NODATA (possible delegation or a non-wildcard empty zone)`);
      }
    }
  } else if (answered.length === probes.length && stable) {
    if (probes.length >= MIN_PROBES && rounds >= MIN_ROUNDS) {
      status = 'confirmed';
      reason = `${answered.length} high-entropy labels across ${rounds} rounds all resolved to the same signature`;
      if (!apex) warn('zone apex did not resolve; the confirmed wildcard may belong to a parent zone');
      if (cdn) warn('wildcard CNAME points at a CDN; matching hosts may be shared infrastructure, not engagement assets');
    } else {
      status = 'suspect';
      reason = `consistent wildcard answers, but ${probes.length} probes / ${rounds} rounds is below the >=${MIN_PROBES} probes / >=${MIN_ROUNDS} rounds confirmation bar`;
    }
  } else if (answered.length < probes.length) {
    status = 'suspect';
    reason = `only ${answered.length}/${probes.length} random labels answered (${summariseStatuses(probes)}); possible flapping or partial wildcard coverage`;
  } else {
    status = 'suspect';
    reason = `wildcard answers were unstable across ${distinct} distinct signatures; cannot derive a stable signature`;
  }

  const confidence = computeWildcardConfidence(status, {
    answeredRatio,
    stable,
    rounds,
    probes: probes.length,
    guardNegative,
    cdn,
    apex,
    status,
  });

  return {
    status,
    confidence,
    zone,
    signature,
    probes,
    cdn,
    apex,
    reason,
    warnings,
  };
}

function normaliseAnswerInput(answers) {
  if (Array.isArray(answers)) {
    return { status: 'ok', a: asStringArray(answers), aaaa: [], cname: [] };
  }
  if (answers === null || typeof answers !== 'object') {
    return { status: 'error', a: [], aaaa: [], cname: [] };
  }
  return {
    status: typeof answers.status === 'string' ? answers.status : 'ok',
    a: asStringArray(answers.a),
    aaaa: asStringArray(answers.aaaa),
    cname: asStringArray(answers.cname).map(normaliseCname),
  };
}

function normaliseSignature(signature) {
  if (signature === null || typeof signature !== 'object') {
    return { a: [], aaaa: [], cnameTemplates: [] };
  }
  return {
    a: uniqueSorted(asStringArray(signature.a).map((ip) => canonicalIp(ip) ?? ip)),
    aaaa: uniqueSorted(asStringArray(signature.aaaa).map((ip) => canonicalIp(ip) ?? ip)),
    cnameTemplates: uniqueSorted(asStringArray(signature.cnameTemplates).map(normaliseCname)),
  };
}

/** Render a `{label}` CNAME template for the labels the host contributes to the zone. */
function renderTemplates(templates, hostName, zoneName) {
  const candidates = new Set(['']);
  if (zoneName.length > 0 && hostName.endsWith(`.${zoneName}`)) {
    const prefix = hostName.slice(0, -(zoneName.length + 1));
    candidates.add(prefix);
    candidates.add(prefix.split('.')[0]);
  }
  const rendered = new Set();
  for (const template of templates) {
    if (!template.includes('{label}')) {
      rendered.add(template);
      continue;
    }
    for (const candidate of candidates) rendered.add(template.replace(/\{label\}/gu, candidate));
  }
  return [...rendered];
}

/**
 * Classify one host's DNS answers against a known wildcard signature.
 *
 * @returns {{status:'suspect'|'explicit'|'unknown', confidence:number, reason:string}}
 */
export function classifyHostAnswers(host, answers, zone) {
  const hostName = canonicalHost(host);
  const observed = normaliseAnswerInput(answers);
  const zoneObject = typeof zone === 'string' ? { zone: canonicalHost(zone) } : (zone ?? {});
  const zoneName = canonicalHost(zoneObject.zone ?? '');
  const zoneStatus = typeof zoneObject.status === 'string' ? zoneObject.status : undefined;
  const signature = normaliseSignature(zoneObject.signature ?? zoneObject);
  if (['timeout', 'servfail', 'error'].includes(observed.status)) {
    return {
      status: 'unknown',
      confidence: 0.15,
      reason: `DNS answers for ${hostName || 'host'} are unavailable (${observed.status}); wildcard origin cannot be classified`,
    };
  }

  const answerIps = uniqueSorted([...observed.a, ...observed.aaaa].map((ip) => canonicalIp(ip) ?? ip));
  const cnames = uniqueSorted(observed.cname.map(normaliseCname));
  const poolIps = new Set([...signature.a, ...signature.aaaa]);
  const hasSignature = poolIps.size > 0 || signature.cnameTemplates.length > 0;

  if (!hasSignature) {
    if (zoneStatus === 'cleared') {
      if (answerIps.length > 0 || cnames.length > 0) {
        return {
          status: 'explicit',
          confidence: 0.85,
          reason: `zone ${zoneName || '(unknown)'} has no wildcard signature; ${hostName} resolves to its own records`,
        };
      }
      return {
        status: 'explicit',
        confidence: 0.7,
        reason: `zone ${zoneName || '(unknown)'} has no wildcard signature and ${hostName} does not resolve`,
      };
    }
    if (answerIps.length > 0 || cnames.length > 0) {
      return {
        status: 'explicit',
        confidence: 0.6,
        reason: `no wildcard signature is known for the zone; ${hostName} resolves to its own records`,
      };
    }
    return {
      status: 'unknown',
      confidence: 0.2,
      reason: `no wildcard signature is known for the zone and no answers were observed for ${hostName}`,
    };
  }

  const ipOutside = poolIps.size > 0 ? answerIps.filter((ip) => !poolIps.has(ip)) : [];
  if (ipOutside.length > 0) {
    return {
      status: 'explicit',
      confidence: 0.8,
      reason: `A/AAAA record(s) ${ipOutside.slice(0, 3).join(', ')} are outside the wildcard pool (${[...poolIps].slice(0, 3).join(', ')})`,
    };
  }

  const rendered = renderTemplates(signature.cnameTemplates, hostName, zoneName);
  const cnameDistinct = cnames.filter((target) => !rendered.includes(target));
  const cnameMatch = cnames.filter((target) => rendered.includes(target));
  if (cnameDistinct.length > 0 && cnameMatch.length === 0) {
    return {
      status: 'explicit',
      confidence: 0.75,
      reason: `CNAME target ${cnameDistinct.slice(0, 2).join(', ')} is distinct from the wildcard template(s) ${signature.cnameTemplates.slice(0, 2).join(', ')}`,
    };
  }

  if (answerIps.length > 0) {
    if (poolIps.size === 0) {
      return {
        status: 'unknown',
        confidence: 0.35,
        reason: 'the wildcard signature has no IP pool; A/AAAA records cannot be compared',
      };
    }
    return {
      status: 'suspect',
      confidence: zoneStatus === 'confirmed' ? 0.8 : 0.65,
      reason: `answers fall inside the wildcard pool (${[...poolIps].slice(0, 3).join(', ')}); likely wildcard synthesis`,
    };
  }

  if (cnameMatch.length > 0) {
    return {
      status: 'suspect',
      confidence: zoneStatus === 'confirmed' ? 0.8 : 0.65,
      reason: `CNAME target matches the wildcard template(s): ${cnameMatch.slice(0, 2).join(', ')}`,
    };
  }

  if (observed.status === 'nxdomain') {
    return {
      status: 'explicit',
      confidence: 0.7,
      reason: `${hostName} does not resolve; no wildcard synthesis was observed`,
    };
  }
  return {
    status: 'explicit',
    confidence: 0.6,
    reason: `${hostName} has no A/AAAA/CNAME records; the wildcard signature does not apply`,
  };
}

/**
 * Assign the best-matching wildcard zone to each host without ever deleting or
 * mutating the input hosts. Returns one classification per input host.
 */
export function assignWildcardZones(hosts, zones) {
  const zoneList = (Array.isArray(zones) ? zones : [])
    .map((zone) => (typeof zone === 'string' ? { zone: canonicalHost(zone) } : zone))
    .filter((zone) => zone !== null && typeof zone === 'object' && canonicalHost(zone.zone ?? '').length > 0)
    .map((zone) => ({ ...zone, zone: canonicalHost(zone.zone ?? '') }));
  const results = [];
  for (const entry of Array.isArray(hosts) ? hosts : []) {
    const descriptor = typeof entry === 'string' ? { host: entry } : (entry ?? {});
    const hostName = canonicalHost(descriptor.host ?? descriptor.name ?? '');
    if (hostName.length === 0) continue;
    let best;
    for (const zone of zoneList) {
      if (hostName === zone.zone || hostName.endsWith(`.${zone.zone}`)) {
        if (best === undefined || zone.zone.length > best.zone.length) best = zone;
      }
    }
    if (best === undefined) {
      results.push({
        host: hostName,
        zone: null,
        status: 'unknown',
        confidence: 0.2,
        reason: 'no wildcard zone covers this host',
      });
      continue;
    }
    const classification = classifyHostAnswers(hostName, {
      status: descriptor.status,
      a: descriptor.a,
      aaaa: descriptor.aaaa,
      cname: descriptor.cname,
    }, best);
    results.push({ host: hostName, zone: best.zone, ...classification });
  }
  return results;
}
