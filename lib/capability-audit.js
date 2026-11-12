/**
 * Capability audit stub.
 *
 * Skills, dictionaries and external scanners are not installed. The stats
 * shape stays stable so older readers do not break, and it no longer reports
 * those families as missing work.
 */

export function capabilityAudit() {
  return {
    tools: { runs: 0, successes: 0, failures: 0, names: [], rows: [] },
    jsUrlExtractor: { used: false, required: false, names: [], webapps: 0 },
    skill: { calls: 0, failures: 0, names: [], used: false, missing: [], stackUsed: false },
    dictionary: { calls: 0, failures: 0, names: [], used: false },
    used: { tools: false, skill: false, dictionary: false },
    gaps: [],
  };
}
