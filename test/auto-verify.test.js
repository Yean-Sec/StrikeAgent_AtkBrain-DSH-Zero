/** Verification queue: every non-terminal finding, in parallel, timeout is not a verdict. */
import test from 'node:test';
import assert from 'node:assert/strict';

import { autoVerifyFindings } from '../lib/auto-verify.js';
import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { evidenceStamp, isTerminalSecondary, pendingFindings } from '../lib/verify-queue.js';
import { superviseCallerAllowed } from '../lib/tools/supervise.js';

function state() {
  let value = emptyState();
  value = applyOps(value, [
    { op: 'engagement.set', engagement: { name: 'auto-verify-it', authorization: 'AUTH-AUTO' } },
    nodeOp('host', 'app.example.test', 'app.example.test', { fqdn: 'app.example.test' }),
    {
      op: 'node.upsert',
      kind: 'finding',
      key: 'finding/rce-app',
      label: 'RCE in upload',
      status: 'candidate',
      verification: 'unverified',
      confidence: 0.7,
      attrs: { title: 'RCE in upload', severity: 'critical', template: 'manual-rce', subjectKey: 'app.example.test', evidence: 'nonce proof' },
    },
  ]);
  return value;
}

test('auto verification launches verifier, records evidence and rating', async () => {
  let activation = 0;
  const ctx = {
    get(name) {
      if (name !== 'subagents') return undefined;
      return {
        async startActivation(request) {
          activation += 1;
          assert.match(request.request.prompt[0].text, /independent verifier/u);
          return {
            childId: 'child-auto-verifier',
            async dispose() {},
            result: Promise.resolve({ output: [{ type: 'text', text: JSON.stringify({
              verdict: 'verified',
              rationale: 'Independent evidence audit reproduced the nonce marker from the artifact.',
              description: '上传接口在文件名参数中执行命令，独立回放记录了同一 nonce 标记。',
              impact: '已证明以应用权限执行命令，可继续读取主机信息；证据未证明 root。',
              remediation: '禁止在文件名/路径参数上调用 shell，改用固定参数列表和允许列表。',
              repro: '重新上传携带 nonce 的文件名并读取响应中的标记。',
              request: 'POST /upload HTTP/1.1',
              response: 'nonce-1 echoed',
              evidence_paths: [],
              observed_marker: 'nonce-1',
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            }) }] }),
          };
        },
      };
    },
  };
  const candidates = [{ key: 'finding/rce-app', label: 'RCE in upload', attrs: { severity: 'critical' } }];
  const result = await autoVerifyFindings({
    ctx,
    agent: { id: 'parent', session: { id: 'parent' } },
    state: state(),
    ops: [],
    candidates,
    config: { autoVerifyFindings: true, autoVerifyMaxFindings: 2 },
    writeEvidence: async () => ({ path: '/tmp/auto.json', relative: '.atkbrain/evidence/auto.json', mediaType: 'application/json', bytes: 10, sha256: 'a'.repeat(64) }),
    timeoutMs: 5000,
  });
  assert.equal(activation, 1);
  assert.equal(result.errors.length, 0);
  assert.equal(result.verified.length, 1);
  assert.equal(result.verified[0].verdict, 'verified');
  const findingOp = result.ops.find((op) => op.op === 'node.upsert' && op.kind === 'finding');
  assert.equal(findingOp.attrs.secondaryVerified, true);
  assert.equal(findingOp.attrs.secondaryVerdict, 'verified');
  assert.match(findingOp.attrs.description, /文件名参数/u);
  assert.match(findingOp.attrs.impact, /应用权限/u);
  assert.equal(findingOp.attrs.secondaryDetailsSource, 'verification-team');
  assert.equal(findingOp.attrs.ratingSource, 'nvd-cvss31');
  assert.equal(typeof findingOp.attrs.cvssScore, 'number');
  assert.ok(['critical', 'high'].includes(findingOp.attrs.redteamRating));
  assert.ok(result.ops.some((op) => op.op === 'node.upsert' && op.kind === 'self_team'));
  assert.ok(result.ops.some((op) => op.op === 'node.upsert' && op.kind === 'supervision'));
});

function verifierCtx(onStart) {
  return {
    get(name) {
      if (name !== 'subagents') return undefined;
      return {
        async startActivation() {
          if (onStart !== undefined) await onStart();
          return {
            childId: 'child-medium',
            async dispose() {},
            result: Promise.resolve({ output: [{ type: 'text', text: JSON.stringify({
              verdict: 'verified',
              rationale: 'The response body contains the same exception text as the recorded evidence.',
              description: '未授权响应返回了完整异常文本，独立回放得到同一段文本。',
              impact: '异常文本暴露了类名和调用路径。',
              remediation: '生产环境关闭详细错误页。',
              repro: '重复记录中的请求并比对响应正文。',
            }) }] }),
          };
        },
      };
    },
  };
}

test('a lead-verified finding and a header finding both enter the queue', async () => {
  let prompts = 0;
  const recorded = applyOps(state(), [
    nodeOp('finding', 'finding/stack', 'production stack trace', { title: 'production stack trace', severity: 'medium', evidence: 'exception text' }, { status: 'verified' }),
    nodeOp('finding', 'finding/headers', 'Missing security headers', { title: 'Missing security headers', severity: 'low', evidence: 'no CSP' }, { status: 'candidate' }),
  ]);
  const again = await autoVerifyFindings({
    ctx: verifierCtx(() => { prompts += 1; }),
    agent: { id: 'parent', session: { id: 'parent' } },
    state: recorded,
    ops: [],
    candidates: [],
    config: { autoVerifyFindings: true, autoVerifyConcurrency: 4 },
    writeEvidence: async () => ({ path: '/tmp/auto.json', relative: '.atkbrain/evidence/auto.json', mediaType: 'application/json', bytes: 10, sha256: 'c'.repeat(64) }),
    timeoutMs: 5000,
  });
  assert.equal(prompts, 3);
  assert.equal(again.verified.length, 1);
  const folded = applyOps(recorded, again.ops);
  assert.equal(pendingFindings(Object.values(folded.nodes)).length, 2);
  const header = Object.values(folded.nodes).find((node) => node.attrs?.title === 'Missing security headers');
  assert.equal(header.attrs.secondaryVerdict, 'verified');
  assert.equal(header.attrs.redteamRating, 'info');
  assert.equal(header.attrs.cvssScore, undefined);
});

test('same-batch findings start together and the overflow stays queued', async () => {
  let started = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const recorded = applyOps(state(), [
    nodeOp('finding', 'finding/a', 'A', { title: 'A', severity: 'low', evidence: 'a' }, { status: 'candidate' }),
    nodeOp('finding', 'finding/b', 'B', { title: 'B', severity: 'low', evidence: 'b' }, { status: 'candidate' }),
    nodeOp('finding', 'finding/c', 'C', { title: 'C', severity: 'low', evidence: 'c' }, { status: 'candidate' }),
  ]);
  const running = autoVerifyFindings({
    ctx: verifierCtx(async () => {
      started += 1;
      if (started === 1) await gate;
    }),
    agent: { id: 'parent', session: { id: 'parent' } },
    state: recorded,
    ops: [],
    config: { autoVerifyConcurrency: 1 },
    writeEvidence: async () => ({ path: '/tmp/auto.json', relative: '.atkbrain/evidence/auto.json', mediaType: 'application/json', bytes: 10, sha256: 'd'.repeat(64) }),
    timeoutMs: 5000,
  });
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(started, 1);
  release();
  const result = await running;
  assert.equal(result.verified.length, 0);
  assert.equal(result.queued.length, 4);
});

test('a timeout records an attempt and does not write a failed verdict', async () => {
  const ctx = {
    get(name) {
      if (name !== 'subagents') return undefined;
      return {
        async startActivation() {
          return {
            childId: 'child-timeout',
            async dispose() {},
            result: Promise.resolve({ output: [{ type: 'text', text: 'not json' }] }),
          };
        },
      };
    },
  };
  const result = await autoVerifyFindings({
    ctx,
    agent: { id: 'parent', session: { id: 'parent' } },
    state: state(),
    ops: [],
    config: { autoVerifyConcurrency: 4 },
    writeEvidence: async () => ({ path: '/tmp/auto.json', relative: 'auto.json', mediaType: 'application/json', bytes: 1, sha256: 'b'.repeat(64) }),
    timeoutMs: 5000,
  });
  const findingOp = result.ops.find((op) => op.kind === 'finding');
  assert.equal(findingOp.attrs.secondaryVerified, undefined);
  assert.equal(findingOp.attrs.secondaryVerdict, undefined);
  assert.equal(findingOp.attrs.secondaryAttempts, 1);
  assert.match(findingOp.attrs.secondaryLastError, /parse/u);
  const folded = applyOps(state(), result.ops);
  assert.equal(pendingFindings(Object.values(folded.nodes)).some((node) => node.key === 'finding/rce-app'), true);
});

test('a refuted verdict leaves the queue and the verification teammate may call verify', async () => {
  const ctx = {
    get(name) {
      if (name !== 'subagents') return undefined;
      return {
        async startActivation() {
          return {
            childId: 'child-refute',
            async dispose() {},
            result: Promise.resolve({ output: [{ type: 'text', text: JSON.stringify({ verdict: 'refuted', rationale: 'The recorded response does not contain the claimed marker.' }) }] }),
          };
        },
      };
    },
  };
  const result = await autoVerifyFindings({
    ctx,
    agent: { id: 'parent', session: { id: 'parent' } },
    state: state(),
    ops: [],
    writeEvidence: async () => ({ path: '/tmp/auto.json', relative: 'auto.json', mediaType: 'application/json', bytes: 1, sha256: 'e'.repeat(64) }),
    timeoutMs: 5000,
  });
  const findingOp = result.ops.find((op) => op.kind === 'finding');
  assert.equal(findingOp.attrs.secondaryVerdict, 'refuted');
  const folded = applyOps(state(), result.ops);
  assert.equal(pendingFindings(Object.values(folded.nodes)).some((node) => node.key === 'finding/rce-app'), false);
  assert.equal(superviseCallerAllowed({ role: 'teammate', name: 'atk-verifier' }, 'verify'), true);
  assert.equal(superviseCallerAllowed({ role: 'teammate', name: 'atk-verifier' }, 'review'), false);
  assert.equal(superviseCallerAllowed({ role: 'teammate', name: 'atk-evolver' }, 'verify'), false);
  assert.equal(superviseCallerAllowed({ role: 'lead', name: 'lead' }, 'review'), true);
});

test('three attempts without new evidence stay queued but are not started again', async () => {
  let activation = 0;
  const recorded = applyOps(emptyState(), [
    { op: 'engagement.set', engagement: { name: 'auto-verify-it', authorization: 'AUTH-AUTO' } },
    nodeOp('finding', 'finding/paused', 'paused', {
      title: 'paused',
      severity: 'high',
      evidence: 'same',
      secondaryAttempts: 3,
      secondaryAttemptEvidence: evidenceStamp({ attrs: { evidence: 'same' }, evidenceIds: [] }),
    }, { status: 'verified' }),
  ]);
  const result = await autoVerifyFindings({
    ctx: {
      get(name) {
        if (name !== 'subagents') return undefined;
        return { async startActivation() { activation += 1; throw new Error('should not start'); } };
      },
    },
    agent: { id: 'parent', session: { id: 'parent' } },
    state: recorded,
    ops: [],
    writeEvidence: async () => ({ path: '/tmp/auto.json', relative: 'auto.json', mediaType: 'application/json', bytes: 1, sha256: 'f'.repeat(64) }),
  });
  assert.equal(activation, 0);
  assert.equal(result.skipped, 'retry-cap');
  assert.equal(result.queued.length, 1);
});

test('verified without a CVSS score stays queued and refuted does not', () => {
  assert.equal(isTerminalSecondary({ secondaryVerdict: 'verified' }), false);
  assert.equal(isTerminalSecondary({ secondaryVerdict: 'verified', secondaryVerified: true, cvssScore: 5.3, cvssSeverity: 'MEDIUM', ratingSource: 'nvd-cvss31' }), true);
  assert.equal(isTerminalSecondary({ secondaryVerdict: 'refuted', secondaryVerified: false }), true);
  assert.equal(pendingFindings([
    { kind: 'finding', key: 'a', status: 'verified', attrs: { secondaryVerdict: 'verified' } },
    { kind: 'finding', key: 'b', status: 'verified', attrs: { secondaryVerdict: 'verified', cvssScore: 3.1, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', ratingSource: 'nvd-cvss31' } },
    { kind: 'finding', key: 'finding_d79a6faae7c5345b8f', status: 'verified', attrs: { stub: true, secondaryVerdict: 'verified' } },
  ]).map((node) => node.key).join(','), 'a');
});
