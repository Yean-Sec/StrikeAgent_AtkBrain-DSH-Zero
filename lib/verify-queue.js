/**
 * Secondary-verification queue.
 *
 * A finding stays queued until the verification team finishes both halves.
 * `refuted` leaves the queue. `verified` leaves only together with a CVSS score.
 * The lead's own status is not a verdict. A timeout, a missing score, or an
 * inconclusive check records an attempt and leaves the finding queued.
 * Automatic retries stop after three attempts until the evidence changes.
 */

import { hasCvssScore, isHardeningFinding } from './finding-classification.js';

export const MAX_AUTO_ATTEMPTS = 3;

/**
 * Finished means both halves of the verification team are done.
 * `refuted` is a false positive and needs no score.
 * `verified` stays in the queue until a CVSS v3.1 base score is stored.
 */
export function isTerminalSecondary(attrs) {
  const verdict = String(attrs?.secondaryVerdict ?? '').toLowerCase();
  if (verdict === 'refuted') return true;
  if (verdict === 'verified' && isHardeningFinding(attrs)) return true;
  return verdict === 'verified' && hasCvssScore(attrs);
}

/** Fingerprint of the evidence a retry should notice. */
export function evidenceStamp(finding) {
  const attrs = finding?.attrs ?? {};
  const ids = Array.isArray(finding?.evidenceIds) ? [...finding.evidenceIds].sort().join(',') : '';
  return [ids, attrs.evidence, attrs.request, attrs.response, attrs.repro, attrs.proofDetail]
    .map((value) => String(value ?? ''))
    .join('\n');
}

/** Automatic retries are paused until the evidence stamp changes. */
export function attemptsExhausted(finding) {
  const attempts = Number(finding?.attrs?.secondaryAttempts) || 0;
  if (attempts < MAX_AUTO_ATTEMPTS) return false;
  return evidenceStamp(finding) === String(finding?.attrs?.secondaryAttemptEvidence ?? '');
}

/** Every non-terminal finding, including ones whose automatic retries are paused. */
export function pendingFindings(nodes) {
  const list = Array.isArray(nodes) ? nodes : Object.values(nodes ?? {});
  return list.filter((node) => node?.kind === 'finding'
    && node.status !== 'merged'
    && node.attrs?.stub !== true
    && !/^finding_[0-9a-f]{8,}$/iu.test(String(node.key ?? ''))
    && !isTerminalSecondary(node.attrs));
}

/** Pending findings the automatic drain may start now. */
export function runnableFindings(nodes) {
  return pendingFindings(nodes).filter((node) => !attemptsExhausted(node));
}

const inflight = new Set();

/** Claim one finding so two drains do not verify it at the same time. */
export function claimFinding(key) {
  const id = String(key ?? '');
  if (id.length === 0 || inflight.has(id)) return false;
  inflight.add(id);
  return true;
}

/** Release a claim when the attempt finishes or is abandoned. */
export function releaseFinding(key) {
  inflight.delete(String(key ?? ''));
}
