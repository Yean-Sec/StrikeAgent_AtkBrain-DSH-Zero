/**
 * Self-team tests: supervision brief + AI path-skill distillation.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';

import { apply } from '../index.js';
import { applyOps, emptyState, nodeOp } from '../lib/ops.js';
import { buildSkillBundle, readSkills } from '../lib/loop/skills.js';
import { buildMethodology } from '../lib/prompt.js';

function seeded({ verified = true } = {}) {
  const nodes = [
    nodeOp('host', '10.0.0.9', '10.0.0.9', { fqdn: '10.0.0.9', realm: 'internal' }),
  ];
  if (verified) {
    nodes.push(nodeOp('evidence', 'self-team/10.0.0.9/xss/evidence', 'xss evidence', {
      path: '/tmp/self-team-xss.json',
      relative: '.atkbrain/evidence/self-team-xss.json',
      sha256: 'b'.repeat(64),
      mediaType: 'application/json',
      size: 64,
    }, { status: 'recorded', verification: 'verified' }));
    nodes.push(nodeOp('finding', 'self-team/10.0.0.9/xss', 'High XSS verified', {
      template: 'xss',
      title: '存储型 XSS verified',
      severity: 'high',
      cvssScore: 8.1,
      cvssSeverity: 'HIGH',
      subjectKey: '10.0.0.9',
      evidence: 'marker reflected twice; sha256 canary',
      secondaryVerified: true,
      claimGuard: null,
    }, { status: 'verified', verification: 'verified', evidenceIds: ['evidence:self-team/10.0.0.9/xss/evidence'] }));
    nodes.push(nodeOp('access', 'self-team/10.0.0.9/shell/user', 'user shell', {
      assetKey: '10.0.0.9',
      kind: 'user_shell',
      privilege: 'user',
      status: 'validated',
      proof: 'uid=0 canary',
    }, { status: 'validated', verification: 'verified' }));
  }
  let state = emptyState();
  state = applyOps(state, [
    { op: 'engagement.set', engagement: { name: 'self-team-it', authorization: 'AUTH-SELF-1' } },
    { op: 'scope.set', allow: [{ type: 'cidr', value: '10.0.0.0/24', canonical: '10.0.0.0/24' }], deny: [] },
    ...nodes,
  ]);
  return state;
}

function createHarness({ subagents = true, seed = {}, config = {} } = {}) {
  let state = seeded(seed);
  const tools = new Map();
  const calls = { activations: 0 };
  const subagentService = subagents ? {
    async startActivation(request) {
      calls.activations += 1;
      const prompt = String(request?.request?.prompt?.[0]?.text ?? '');
      let text;
      if (prompt.includes('# AtkBrain finding verification')) {
        text = JSON.stringify({
          verdict: 'verified',
          rationale: 'The verifier reproduced the unique marker and the stored evidence hash matches the recorded artifact.',
          description: '登录回调参数 succLoginRedirect 未做转义，独立复核在响应中观察到可执行脚本标记。',
          impact: '攻击者可诱导已登录用户执行脚本；证据只证明反射型脚本执行，未证明账户接管。',
          remediation: '对 succLoginRedirect 做服务端白名单校验和输出编码，并添加 CSP。',
          repro: '发送带标记的回调参数两次，比较响应中的参数原样反射。',
          request: 'GET /login.action?succLoginRedirect=%22%3E%3Csvg/onload=marker%3E HTTP/1.1',
          response: '<svg/onload=marker>',
          evidence_paths: [],
          observed_marker: 'atkbrain-self-team-canary',
        });
      } else if (prompt.includes('# AtkBrain finding detail authoring')) {
        text = JSON.stringify({
          description: 'GET /login.action 的 succLoginRedirect 参数被原样写入 hidden input 的 value 属性；单引号和尖括号可闭合属性，证据中的独立标记在响应第 241 行以 svg/onload 形式出现，且控制参数 userName 被转义，证明缺陷只在该参数。',
          impact: '攻击者可诱导已登录用户打开构造 URL，在 dictionary 源执行脚本，实施登录页覆盖或同源操作；JSESSIONID 为 HttpOnly，不能直接窃取 Cookie，未证明账户接管。',
          remediation: '对 succLoginRedirect 做服务端 URL 白名单校验，并按 HTML 属性上下文编码；增加 CSP script-src 限制，错误页关闭详细堆栈。',
          repro: '1) GET /login.action?succLoginRedirect=%22%3E%3Csvg/onload=marker%3E 两次；2) 比较响应第 241 行是否原样出现 svg/onload；3) 用 userName 控制参数确认其被转义。',
          request: 'GET /login.action?succLoginRedirect=%22%3E%3Csvg/onload=marker%3E HTTP/1.1\nHost: dictionary.writtenchinese.com',
          response: '<input type="hidden" name="succLoginRedirect" value=""><svg/onload=marker>',
          evidence_note: 'Lead 独立响应文件 lead-xss-login-redirect.html（sha256 28b6ab54...）',
          confidence: 0.95,
        });
      } else if (prompt.includes('self-evolution team')) {
        text = JSON.stringify({
          skills: [{
            name: 'Authentication boundary bypass',
            summary: 'A generalized authentication boundary confusion path with reproducible high-impact proof.',
            when: ['php', 'auth_surface'],
            do: ['access_control'],
            avoid: ['content_enum'],
            route: 'entry → vuln(auth_bypass) → foothold(lateral) → goal(impact)',
            preconditions: ['A role boundary is enforced only in the presentation layer'],
            steps: ['map the authentication boundary and enumerate role-specific responses', 'verify the bypass with a second identity and a unique marker'],
            verification: ['reproduce the bypass twice and store an evidence hash', 'show a role-specific response that the anonymous control lacks'],
            pitfalls: ['do not claim shell from a version string', 'do not treat a single 200 response as access proof'],
            confidence: 0.74,
          }],
        });
      } else {
        text = JSON.stringify({
          progress_summary: 'The main team verified one high XSS and validated a user shell; the path is confirmed.',
          gained: ['1 verified high finding', '1 validated user shell'],
          missed: ['admin panel proof is still missing'],
          advice: 'Escalate the validated shell toward data or admin proof before new enumeration.',
          anti_deadlock: ['ban repeating the same XSS payload on the same target'],
          recommended_next: ['prove access objective from the validated shell'],
          deadlock_risk: 'low',
          confidence: 0.8,
        });
      }
      return {
        childId: `self-child-${calls.activations}`,
        result: Promise.resolve({ output: [{ type: 'text', text }], stopReason: 'end' }),
        dispose: async () => {},
      };
    },
  } : undefined;
  const ctx = {
    logger: { warn() {}, info() {} },
    sessionProjections: { stateOf: () => state, register: () => () => {} },
    systemPrompt: { section: () => () => {} },
    effect(fn) { const dispose = fn(); return () => { if (typeof dispose === 'function') dispose(); }; },
    tools: { register(definition) { tools.set(definition.name, definition); return () => {}; }, get(name) { return tools.get(name); } },
    get(name) {
      if (name === 'subagents') return subagentService;
      if (name === 'approval') return { async request() { return 'allowed-once'; } };
      return undefined;
    },
  };
  apply(ctx, {
    requireScopeApproval: false,
    requireTunnelApproval: false,
    lessonStore: path.join(os.tmpdir(), `atkbrain-self-lesson-${process.pid}-${Math.random().toString(36).slice(2)}.jsonl`),
    selfTeamTimeoutMs: 5000,
    ...config,
  });
  let counter = 0;
  async function run(name, args) {
    counter += 1;
    const tool = tools.get(name);
    assert.ok(tool, `tool ${name} registered`);
    const value = await tool.execute(args, {
      agent: { id: 'parent', session: { id: 'parent', header: { cwd: workspace } } },
      callId: `self-call-${counter}`,
      name,
      signal: new AbortController().signal,
      arguments: args,
    });
    const meta = tool.output.presentationMeta(args, value);
    if (meta !== undefined) state = applyOps(state, meta.ops, meta.at);
    return value;
  }
  let workspace;
  return {
    calls,
    run,
    state: () => state,
    setWorkspace(dir) { workspace = dir; },
  };
}

async function withHarness(fn, options = {}) {
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-self-'));
  const skillDir = await mkdtemp(path.join(os.tmpdir(), 'atkbrain-skills-'));
  const harness = createHarness({ ...options, config: { skillDir, ...(options.config ?? {}) } });
  harness.setWorkspace(workspace);
  try {
    return await fn(harness, workspace, skillDir);
  } finally {
    await rm(workspace, { recursive: true, force: true });
    await rm(skillDir, { recursive: true, force: true });
  }
}

async function closeThreePasses(harness) {
  for (let i = 0; i < 3; i += 1) {
    const passes = Object.values(harness.state().nodes).filter((node) => node.kind === 'supervision' && node.attrs?.type === 'test_pass');
    if (passes.some((node) => node.attrs?.basis === 'exhausted') || passes.length >= 3) return;
    await harness.run('atkbrain_record', { note: `implicit pass marker ${i}` });
    await harness.run('atkbrain_selftteam', { action: 'pass' });
  }
}

test('start creates lead, verification and report without the harm-escalation team', async () => {
  await withHarness(async (harness) => {
    const started = await harness.run('atkbrain_selftteam', { action: 'start' });
    assert.match(started.summary, /Self-teams active/i);
    const teams = Object.values(harness.state().nodes).filter((node) => node.kind === 'self_team');
    assert.equal(teams.length, 3);
    assert.deepEqual(teams.map((team) => team.attrs.type).sort(), ['lead', 'report', 'verification']);
    assert.ok(teams.every((team) => team.status === 'active'));
    assert.ok(teams.every((team) => Array.isArray(team.attrs.members) && team.attrs.members.length >= 1));
    const verification = teams.find((team) => team.attrs.type === 'verification');
    assert.equal(verification.attrs.members.length, 2, 'verification and rating must be one team with two roles');
  });
});

test('an empty engagement does not get an opening supervision brief', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    const result = await harness.run('atkbrain_selftteam', { action: 'brief' });
    assert.match(result.summary, /先不说话/);
    assert.equal(result.details.silent, true);
    assert.equal(Object.values(harness.state().nodes).some((node) => node.kind === 'supervision' && node.attrs?.type === 'self_team_brief'), false);
  }, { seed: { verified: false } });
});

test('brief records what was done/gained, advice and anti-deadlock in graph state', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    const result = await harness.run('atkbrain_selftteam', { action: 'brief' });
    assert.match(result.summary, /监督团队简报|verified one high/);
    const briefs = Object.values(harness.state().nodes).filter((node) => node.kind === 'supervision' && node.attrs.type === 'self_team_brief');
    assert.equal(briefs.length, 1);
    assert.equal(briefs[0].attrs.source, 'ai-subagent');
    assert.ok(briefs[0].attrs.gained.length >= 1);
    assert.ok(briefs[0].attrs.advice.length > 0);
    assert.ok(briefs[0].attrs.antiDeadlock.length >= 1);
    assert.equal(briefs[0].attrs.deadlockRisk, 'low');
    assert.match(briefs[0].attrs.artifactPath, /selftteam-brief/);
    const supervisionTeam = Object.values(harness.state().nodes).find((node) => node.kind === 'self_team' && node.attrs.type === 'supervision');
    assert.ok(supervisionTeam.attrs.lastBriefAt);
  });
});

test('distill and skills are no longer self-team actions', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    await assert.rejects(() => harness.run('atkbrain_selftteam', { action: 'distill' }), /action|enum|distill/i);
    await assert.rejects(() => harness.run('atkbrain_selftteam', { action: 'skills' }), /action|enum|skills/i);
    const teams = Object.values(harness.state().nodes).filter((node) => node.kind === 'self_team');
    assert.equal(teams.some((team) => team.attrs.type === 'evolution'), false);
  });
});

test('start creates five teams and verify runs verification + rating as one team', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    const teams = Object.values(harness.state().nodes).filter((node) => node.kind === 'self_team');
    assert.equal(teams.length, 3);
    assert.deepEqual(teams.map((team) => team.attrs.type).sort(), ['lead', 'report', 'verification']);
    const verification = teams.find((team) => team.attrs.type === 'verification');
    assert.equal(verification.attrs.members.length, 2, 'verification + rating must be one team with two roles');
    assert.deepEqual(verification.attrs.members.map((member) => member.role), ['verifier', 'rater']);

    const finding = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    const result = await harness.run('atkbrain_selftteam', { action: 'verify', findingId: finding.id });
    assert.match(result.summary, /Verification & rating team/i);
    assert.equal(result.details.verdict, 'verified');
    assert.ok(result.details.rating, 'rating half did not run');
    const updated = Object.values(harness.state().nodes).find((node) => node.kind === 'self_team' && node.attrs.type === 'verification');
    assert.equal(updated.attrs.verifiedCount, 1);
    assert.equal(updated.attrs.ratedCount, 1);
    assert.ok(updated.attrs.lastVerifyAt);
    const findingAfter = Object.values(harness.state().nodes).find((node) => node.kind === 'finding' && node.key === finding.key);
    assert.equal(findingAfter.attrs.secondaryVerified, true);
    assert.match(findingAfter.attrs.description, /succLoginRedirect/u);
    assert.match(findingAfter.attrs.impact, /脚本执行/u);
    assert.equal(findingAfter.attrs.secondaryDetailsSource, 'verification-team');
    assert.ok(findingAfter.attrs.redteamRating);
    assert.ok(Object.values(harness.state().nodes).some((node) => node.kind === 'supervision' && node.attrs.type === 'finding_verification'));
    assert.ok(Object.values(harness.state().nodes).some((node) => node.kind === 'supervision' && node.attrs.type === 'rating'));
  });
});

test('detail action has the verification team write AI detail without changing verification status', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    const before = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    const result = await harness.run('atkbrain_selftteam', { action: 'detail', findingId: before.id });
    assert.equal(result.details.detailSource, 'ai-verification-team');
    assert.match(result.details.description, /succLoginRedirect/u);
    assert.match(result.details.impact, /JSESSIONID/u);
    const after = Object.values(harness.state().nodes).find((node) => node.kind === 'finding' && node.key === before.key);
    assert.equal(after.status, before.status, 'detail action must not change verification status');
    assert.equal(after.attrs.detailSource, 'ai-verification-team');
    assert.match(after.attrs.description, /hidden input/u);
    assert.match(after.attrs.remediation, /白名单校验/u);
    assert.ok(Object.values(harness.state().nodes).some((node) => node.kind === 'supervision' && node.attrs.type === 'finding_detail'));
  });
});

test('an unfinished project report stays a draft and says not to stop', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    await harness.run('atkbrain_selftteam', { action: 'brief' });
    await harness.run('atkbrain_record', {
      nodes: [{ kind: 'webapp', key: 'http://10.0.0.9/', attrs: { url: 'http://10.0.0.9/', host: '10.0.0.9' } }],
    });
    await closeThreePasses(harness);
    const result = await harness.run('atkbrain_selftteam', { action: 'report', theme: 'light' });
    assert.match(result.summary, /不要收尾/);
    assert.match(result.summary, /endpoint_vocab/);
    assert.equal(result.details.reportKind, 'draft');
    const team = Object.values(harness.state().nodes).find((node) => node.kind === 'self_team' && node.attrs.type === 'report');
    assert.equal(team.attrs.lastReportKind, 'draft');
  });
});

test('report team exports a theme-matched HTML file from the operator template', async () => {
  await withHarness(async (harness, workspace) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    await harness.run('atkbrain_selftteam', { action: 'brief' });
    await closeThreePasses(harness);
    const result = await harness.run('atkbrain_selftteam', { action: 'report', theme: 'light' });
    assert.match(result.summary, /Report team wrote/i);
    assert.equal(result.details.theme, 'light');
    assert.ok(result.details.path.endsWith('.html'));
    const { readFile } = await import('node:fs/promises');
    const html = await readFile(result.details.absolutePath, 'utf8');
    assert.ok(html.includes('atk-report-light-override'));
    assert.ok(html.includes('执行摘要'));
    assert.ok(html.includes('存储型 XSS'));
    const team = Object.values(harness.state().nodes).find((node) => node.kind === 'self_team' && node.attrs.type === 'report');
    assert.equal(team.attrs.lastReportTheme, 'light');
    assert.ok(team.attrs.lastReportPath.endsWith('.html'));
    assert.ok(workspace.length > 0);
  });
});

test('report team exports a single-finding HTML report without raw secrets', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    await harness.run('atkbrain_selftteam', { action: 'brief' });
    const finding = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    const result = await harness.run('atkbrain_selftteam', { action: 'report', reportType: 'finding', findingId: finding.id, theme: 'light' });
    assert.match(result.summary, /单漏洞报告/);
    assert.equal(result.details.reportType, 'finding');
    assert.equal(result.details.findingId, finding.id);
    assert.ok(result.details.path.includes('finding-report'));
    const { readFile } = await import('node:fs/promises');
    const html = await readFile(result.details.absolutePath, 'utf8');
    assert.ok(html.includes('单漏洞报告'));
    assert.ok(html.includes('CVSS'));
    assert.ok(html.includes('二次验证'));
    const team = Object.values(harness.state().nodes).find((node) => node.kind === 'self_team' && node.attrs.type === 'report');
    assert.equal(team.attrs.lastFindingReportId, finding.id);
    assert.ok(team.attrs.lastFindingReportPath.endsWith('.html'));
  });
});

test('brief degrades to a deterministic progress report when the AI worker is unavailable', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    const result = await harness.run('atkbrain_selftteam', { action: 'brief' });
    assert.match(result.summary, /监督团队简报/);
    const brief = Object.values(harness.state().nodes).find((node) => node.kind === 'supervision' && node.attrs.type === 'self_team_brief');
    assert.equal(brief.attrs.source, 'deterministic');
    assert.ok(brief.attrs.progressSummary.length > 0);
    assert.ok(brief.attrs.antiDeadlock.length >= 1);
  }, { subagents: false });
});

test('a workspace file that never entered the graph blocks the next probe until ingest', async () => {
  await withHarness(async (harness, workspace) => {
    const { mkdir, writeFile } = await import('node:fs/promises');
    await mkdir(`${workspace}/wc`, { recursive: true });
    await writeFile(`${workspace}/wc/page.html`, '<html><title>saved page</title></html>');
    await assert.rejects(
      harness.run('atkbrain_coverage', { action: 'seed', path: '/health' }),
      (error) => {
        assert.match(String(error.message), /wc\/page\.html/);
        assert.match(String(error.message), /atkbrain_ingest/);
        return true;
      },
    );
    const ingested = await harness.run('atkbrain_ingest', { paths: ['wc/page.html'] });
    assert.match(ingested.summary, /import|Imported|已|evidence|1 /i);
    const seeded = await harness.run('atkbrain_coverage', { action: 'seed', path: '/health' });
    assert.match(seeded.summary, /Seeded/);
  }, { seed: { verified: false } });
});

test('an empty engagement does not block coverage or probes', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    const seeded = await harness.run('atkbrain_coverage', { action: 'seed', path: '/health' });
    assert.match(seeded.summary, /Seeded/);
  }, { seed: { verified: false } });
});

test('an overdue handoff blocks the project report and leaves probing open', async () => {
  await withHarness(async (harness) => {
    await harness.run('atkbrain_selftteam', { action: 'start' });
    await harness.run('atkbrain_selftteam', { action: 'start', team: 'supervision' });
    try {
      await harness.run('atkbrain_probe', { action: 'http', url: 'http://10.0.0.9/' });
    } catch (error) {
      assert.doesNotMatch(String(error.message), /御者要先交接/);
    }
    await assert.rejects(
      harness.run('atkbrain_selftteam', { action: 'report', reportType: 'project', theme: 'light' }),
      (error) => {
        const message = String(error.message);
        assert.match(message, /御者要先交接/);
        assert.match(message, /目标：/);
        assert.match(message, /服务：/);
        assert.match(message, /危险点：/);
        assert.match(message, /严重高中低：/);
        assert.match(message, /凭证：无/);
        assert.match(message, /立足点：/);
        assert.match(message, /信息：/);
        assert.match(message, /action=brief/);
        return true;
      },
    );
  });
});

test('skill bundle qualification exposes only generalized fields', async () => {
  const state = seeded();
  const bundle = buildSkillBundle(state, null, {});
  assert.equal(bundle.qualified, true);
  assert.ok(Array.isArray(bundle.stack));
  assert.ok(bundle.route.includes('→'));
  assert.ok(bundle.findingClasses.length >= 1);
  assert.ok(!JSON.stringify(bundle).includes('10.0.0.9'), 'bundle must not contain a raw host');
});

test('one operator message is one turn and does not arm follow-ups', async () => {
  const text = buildMethodology({});
  assert.match(text, /One operator message is one turn/);
  assert.match(text, /Do not arm follow-up dialogues/);
  assert.match(text, /atkbrain_survey/);
  assert.match(text, /atkbrain_tunnel/);
  assert.doesNotMatch(text, /atkbrain_loop action=step/);
  assert.doesNotMatch(text, /atkbrain_team action=plan/);
  await withHarness(async (harness) => {
    await harness.run('atkbrain_coverage', { action: 'seed', path: '/login', target: '10.0.0.9' });
    await assert.rejects(
      () => harness.run('atkbrain_selftteam', { action: 'pass' }),
      /不能记成下一轮/,
    );
    await assert.rejects(
      () => harness.run('atkbrain_selftteam', { action: 'report', reportType: 'project', theme: 'light' }),
      (error) => {
        const message = String(error.message);
        assert.match(message, /不要把结果交给操作员/);
        assert.match(message, /图谱里已有/);
        assert.match(message, /总目标/);
        assert.match(message, /不另开新交战/);
        return true;
      },
    );
    const finding = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    const single = await harness.run('atkbrain_selftteam', { action: 'report', reportType: 'finding', findingId: finding.id, theme: 'light' });
    assert.match(single.summary, /单漏洞报告/);
    assert.doesNotMatch(single.summary, /不要把结果交给操作员/);
    await harness.run('atkbrain_record', { note: 'first pass checked the open login cell' });
    await assert.rejects(
      () => harness.run('atkbrain_selftteam', { action: 'pass' }),
      /铺开覆盖格/,
    );
    for (const bug of ['xss', 'sqli']) {
      await harness.run('atkbrain_coverage', {
        action: 'note',
        path: '/login',
        bugClass: bug,
        status: 'seen',
        channels: ['status', 'body'],
        note: '/login 参数 q 的状态码和响应正文已对照，8 failures then HTTP 429 and a lockout; repeated failures are limited',
      });
    }
    const first = await harness.run('atkbrain_selftteam', { action: 'pass' });
    assert.equal(first.details.round, 1);
    assert.equal(first.details.basis, 'activity');
    await assert.rejects(
      () => harness.run('atkbrain_selftteam', { action: 'pass' }),
      /铺开覆盖格|不能记成下一轮/,
    );
    await assert.rejects(
      () => harness.run('atkbrain_selftteam', { action: 'report', reportType: 'project', theme: 'light' }),
      /不要把结果交给操作员/,
    );
  }, { config: { reportAi: false } });
});

test('an empty authorized frontier ends the three-pass sequence', async () => {
  await withHarness(async (harness) => {
    const marked = await harness.run('atkbrain_selftteam', { action: 'pass' });
    assert.equal(marked.details.basis, 'exhausted');
    assert.equal(marked.details.complete, true);
    const report = await harness.run('atkbrain_selftteam', { action: 'report', reportType: 'project', theme: 'light' });
    assert.doesNotMatch(report.summary, /不要把结果交给操作员/);
  }, { config: { reportAi: false } });
});

test('harm escalation is rejected', async () => {
  await withHarness(async (harness) => {
    const source = Object.values(harness.state().nodes).find((node) => node.kind === 'finding');
    await assert.rejects(
      () => harness.run('atkbrain_selftteam', {
        action: 'escalate', findingId: source.id, outcome: 'raised', title: '远程代码执行', severity: 'critical',
        proof: '同一接口上确认可以执行系统命令，原来只能执行脚本。命令回显标记已记入证据。',
      }),
      /action|escalat|not included/i,
    );
    assert.equal(Object.values(harness.state().edges).some((item) => item.kind === 'escalates_to'), false);
    await assert.rejects(
      () => harness.run('atkbrain_selftteam', { action: 'start', team: 'escalation' }),
      /team|escalat|not included/i,
    );
  });
});
