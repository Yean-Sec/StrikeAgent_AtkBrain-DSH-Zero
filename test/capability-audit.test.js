/** Skills, dictionaries and scanners are no longer required capabilities. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { capabilityAudit } from '../lib/capability-audit.js';

test('capability audit does not demand skills, dictionaries or scanners', () => {
  const audit = capabilityAudit();
  assert.deepEqual(audit.gaps, []);
  assert.equal(audit.skill.missing.length, 0);
  assert.equal(audit.tools.runs, 0);
  assert.equal(audit.dictionary.calls, 0);
});
