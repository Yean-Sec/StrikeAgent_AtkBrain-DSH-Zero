/** CVSS v3.1 Base Score calculator tests. */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  BASE_KEYS,
  CVSS_VERSION,
  findingAttrs,
  formatVector,
  fromInput,
  normalizeMetrics,
  nvdRejectReason,
  parseVector,
  qualitative,
  ratingLabel,
  roundup,
  score,
} from '../lib/cvss31.js';

const LOG4SHELL = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
const NETWORK_CRITICAL = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const XSS = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
const AUTHENTICATED = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';
const LOCAL = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';
const NO_IMPACT = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';

test('matches known NVD CVSS v3.1 base scores', () => {
  const cases = [
    [LOG4SHELL, 10.0, 'CRITICAL', 'critical'],
    [NETWORK_CRITICAL, 9.8, 'CRITICAL', 'critical'],
    [AUTHENTICATED, 8.8, 'HIGH', 'high'],
    [LOCAL, 7.8, 'HIGH', 'high'],
    [XSS, 6.1, 'MEDIUM', 'medium'],
  ];
  for (const [vector, expectedScore, expectedSeverity, expectedRating] of cases) {
    const result = score(vector);
    assert.equal(result.ok, true, vector);
    assert.equal(result.rejected, false, vector);
    assert.equal(result.score, expectedScore, vector);
    assert.equal(result.nvdSeverity, expectedSeverity, vector);
    assert.equal(result.rating, expectedRating, vector);
    assert.equal(result.vector, vector);
  }
});

test('NVD does not score a vector with no C/I/A impact', () => {
  const result = score(NO_IMPACT);
  assert.equal(result.ok, true);
  assert.equal(result.rejected, true);
  assert.equal(result.score, 0);
  assert.equal(result.nvdSeverity, 'NONE');
  assert.equal(result.rating, 'info');
  assert.match(result.reason, /all None/i);
  assert.match(nvdRejectReason(result.metrics), /all None/i);
});

test('parses canonical, optional metrics and human aliases', () => {
  const parsed = parseVector(LOG4SHELL);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.metrics, { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' });
  assert.equal(parsed.vector, LOG4SHELL);

  const withOptional = parseVector(`${LOG4SHELL}/E:F/RL:O/RC:C`);
  assert.equal(withOptional.ok, true);
  assert.deepEqual(withOptional.ignored, ['E', 'RL', 'RC']);
  assert.equal(withOptional.vector, LOG4SHELL);

  const words = normalizeMetrics({
    AV: 'NETWORK', AC: 'LOW', PR: 'NONE', UI: 'NONE', S: 'CHANGED', C: 'HIGH', I: 'HIGH', A: 'HIGH',
  });
  assert.equal(words.ok, true);
  assert.equal(words.metrics.AV, 'N');
  assert.equal(words.metrics.S, 'C');

  const chinese = normalizeMetrics({
    AV: '网络', AC: '低', PR: '无', UI: '无', S: '改变', C: '高', I: '高', A: '高',
  });
  assert.equal(chinese.ok, true);
  assert.equal(chinese.metrics.AV, 'N');
  assert.equal(chinese.metrics.PR, 'N');
});

test('rejects malformed, missing, duplicate and conflicting metrics', () => {
  assert.equal(parseVector('').ok, false);
  assert.equal(parseVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').ok, false);
  assert.equal(parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H').ok, false);
  assert.equal(parseVector(`${NETWORK_CRITICAL}/AV:N`).ok, false);
  assert.equal(parseVector('CVSS:3.1/ZZ:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').ok, false);
  assert.equal(parseVector('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').ok, false);
  assert.equal(normalizeMetrics({ AV: 'N' }).ok, false);

  const conflict = fromInput({
    cvssVector: NETWORK_CRITICAL,
    cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' },
  });
  assert.equal(conflict.ok, false);
  assert.match(conflict.reason, /different vectors/i);

  const missing = fromInput({ cvss: { AV: 'N', AC: 'L' } });
  assert.equal(missing.ok, false);
  assert.match(missing.reason, /missing/i);
});

test('Scope changed increases the PR weight for the same privileges', () => {
  const unchanged = score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H');
  const changed = score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H');
  assert.equal(unchanged.ok, true);
  assert.equal(changed.ok, true);
  assert.ok(changed.score > unchanged.score);
  assert.equal(changed.nvdSeverity, 'CRITICAL');
});

test('qualitative boundaries follow NVD scale', () => {
  assert.equal(qualitative(0), 'NONE');
  assert.equal(qualitative(0.1), 'LOW');
  assert.equal(qualitative(3.9), 'LOW');
  assert.equal(qualitative(4.0), 'MEDIUM');
  assert.equal(qualitative(6.9), 'MEDIUM');
  assert.equal(qualitative(7.0), 'HIGH');
  assert.equal(qualitative(8.9), 'HIGH');
  assert.equal(qualitative(9.0), 'CRITICAL');
  assert.equal(qualitative(10), 'CRITICAL');
  assert.equal(ratingLabel(0), 'info');
  assert.equal(ratingLabel(6.1), 'medium');
});

test('Appendix A Roundup uses one decimal place without float drift', () => {
  assert.equal(roundup(4.02), 4.1);
  assert.equal(roundup(4.0), 4.0);
  assert.equal(roundup(4.0001), 4.1);
  assert.equal(roundup(9.799999999), 9.8);
});

test('scope changed plus low confidentiality is NVD medium 4.7', () => {
  const result = score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N');
  assert.equal(result.ok, true);
  assert.equal(result.score, 4.7);
  assert.equal(result.nvdSeverity, 'MEDIUM');
});

test('formatVector and fromInput produce the storable finding attrs', () => {
  const metrics = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' };
  assert.equal(formatVector(metrics), NETWORK_CRITICAL);
  const resolved = fromInput({ cvss: metrics });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.present, true);
  assert.equal(resolved.score, 9.8);
  const attrs = findingAttrs(resolved);
  assert.equal(attrs.cvssVector, NETWORK_CRITICAL);
  assert.equal(attrs.cvssScore, 9.8);
  assert.equal(attrs.cvssRating, 'critical');
  assert.equal(attrs.cvssSeverity, 'CRITICAL');
  assert.equal(attrs.cvssSource, 'nvd-cvss31');
  assert.equal(attrs.cvss.version, CVSS_VERSION);
  assert.equal(attrs.cvss.baseScore, 9.8);
  assert.deepEqual(BASE_KEYS, ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']);
});

test('fromInput reports absence without failing', () => {
  const result = fromInput({});
  assert.equal(result.ok, true);
  assert.equal(result.present, false);
  assert.deepEqual(findingAttrs(result), {});
});

test('optional Temporal/Environmental metrics do not change the Base score', () => {
  const base = score(NETWORK_CRITICAL);
  const withOptional = score(`${NETWORK_CRITICAL}/E:P/RL:T/RC:R/CR:H/IR:H/AR:H`);
  assert.equal(withOptional.ok, true);
  assert.equal(withOptional.score, base.score);
  assert.equal(withOptional.vector, base.vector);
});
