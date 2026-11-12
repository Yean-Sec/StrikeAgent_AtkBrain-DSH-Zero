/**
 * `atkbrain_team` — orchestrate DSH Agent Teams teammates and subagents for
 * per-asset pentesting, then merge their graph exports into the parent graph.
 *
 * The tool is deliberately a coordinator, not a second agent runner:
 *  - `plan` turns in-scope assets into deterministic batches and a complete
 *    child prompt/artifact contract;
 *  - `dispatch` starts one teammate (`agentTeams.spawnTeammate`) or one
 *    subagent (`subagents.startActivation`) per batch;
 *  - `status` joins graph task state with the live roster/child catalog and
 *    artifact readiness;
 *  - `merge` calls the regular `atkbrain_ingest` tool for each child graph JSON
 *    and folds its ops into the parent graph;
 *  - teammates get a shared Team task created and assigned, and it is completed
 *    on merge.
 */
import path from 'node:path';
import { stat } from 'node:fs/promises';

import { TOOL_NAMES } from '../constants.js';
import { buildTargetTree, concreteAllowTargets, targetIdentity } from '../targets.js';
import { evaluateScope } from '../scope.js';
import {
  invalid,
  isPlainObject,
  nowIso,
  resolveArtifact,
  shortHash,
  stableStringify,
} from '../util.js';
import { evidenceNodeOp } from './build.js';
import {
  assertArgs,
  audit,
  optionalInteger,
  registerAtkTool,
  requireEnum,
  requireString,
} from './common.js';

const ACTIONS = ['plan', 'dispatch', 'status', 'merge', 'stop'];
const MODES = ['teammates', 'subagents'];
const BATCH_ACTION = 'subagent_batch';
const ACTIVE_BATCH_STATUSES = new Set(['planned', 'dispatched', 'artifact_ready', 'completed', 'merged']);
const FINISHED_BATCH_STATUSES = new Set(['completed', 'merged', 'cancelled']);

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: {
      type: 'string',
      enum: ACTIONS,
      description: 'plan batches, dispatch them as Team teammates or subagents, inspect status, merge child graph exports, or stop running batches.',
    },
    mode: {
      type: 'string',
      enum: MODES,
      description: 'teammates uses the durable Agent Teams roster and shared task board; subagents uses one-shot DSH subagents. Default teammates.',
    },
    batchSize: { type: 'integer', description: 'Assets per batch (1-50, default from config teamBatchSize). Operator-named targets are never packed: each one is its own batch.' },
    maxBatches: { type: 'integer', description: 'Maximum batches to plan/dispatch (1-8, default from config teamMaxBatches).' },
    assetIds: {
      type: 'array',
      items: { type: 'string' },
      description: 'Optional subset of asset node ids or canonical keys to plan.',
    },
    force: { type: 'boolean', description: 'Re-plan/re-merge assets or artifacts already handled.' },
    batchId: { type: 'string', description: 'Optional single batch id for merge/stop.' },
  },
};

function slug(value, fallback = 'engagement') {
  const text = String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '')
    .slice(0, 48);
  return text.length > 0 ? text : fallback;
}

function isLead(ctx, agent) {
  const teams = ctx.get('agentTeams');
  if (teams === undefined || teams === null) return true;
  try {
    return teams.membership(agent).role === 'lead';
  } catch {
    return true;
  }
}

function requireLead(ctx, agent) {
  if (!isLead(ctx, agent)) invalid('atkbrain_team plan/dispatch/merge/stop require the Team Lead; a teammate must return to its Lead instead');
}

function assetTarget(node) {
  if (node.kind === 'host') {
    return { type: 'host', host: node.key, ips: Array.isArray(node.attrs?.ips) ? node.attrs.ips : [] };
  }
  if (node.kind === 'ip') return { type: 'ip', ip: node.attrs?.addr ?? node.key };
  if (node.kind === 'webapp') return { type: 'url', url: node.attrs?.url ?? node.key, port: node.attrs?.port };
  return undefined;
}

function scopeForAsset(state, node) {
  const target = assetTarget(node);
  if (target === undefined) return { eligible: false, reason: 'not a network asset' };
  if ((state.scope?.allow?.length ?? 0) === 0) return { eligible: false, reason: 'scope.allow is empty' };
  try {
    const evaluation = evaluateScope(state.scope, target);
    return { eligible: evaluation.allowed, reason: evaluation.reason };
  } catch (error) {
    return { eligible: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

function buildServiceMap(state) {
  const served = new Set();
  for (const edge of Object.values(state.edges)) {
    if (edge.kind === 'exposes') served.add(edge.from);
  }
  return served;
}

function assetScore(node, served) {
  let score = 0;
  if (node.attrs?.crownJewel === true) score += 1000;
  score += (Number(node.attrs?.criticality) || 0) * 100;
  if (!served.has(node.id)) score += 30;
  if (node.kind === 'host') score += 50;
  if (node.kind === 'ip') score += 40;
  if (node.kind === 'webapp') score += 20;
  return score;
}

function batchTasks(state) {
  return Object.values(state.nodes).filter((node) => node.kind === 'task' && node.attrs?.actionType === BATCH_ACTION);
}

function findBatchTask(state, batchId) {
  return batchTasks(state).find((node) => node.attrs?.batchId === batchId);
}

function assignedAssetIds(state, { includePlanned = false } = {}) {
  const assigned = new Set();
  const statuses = includePlanned
    ? new Set(['dispatched', 'artifact_ready', 'completed', 'merged'])
    : ACTIVE_BATCH_STATUSES;
  for (const task of batchTasks(state)) {
    if (!statuses.has(task.status)) continue;
    for (const assetId of Array.isArray(task.attrs?.assetIds) ? task.attrs.assetIds : []) assigned.add(assetId);
    for (const key of Array.isArray(task.attrs?.assetKeys) ? task.attrs.assetKeys : []) assigned.add(key);
  }
  return assigned;
}

function assetLabel(node) {
  return `${node.kind}:${node.key}`;
}

function nodeBelongsToTrack(node, track) {
  const attrs = node.attrs ?? {};
  const fields = [node.key, node.label, attrs.addr, attrs.fqdn, attrs.host, attrs.hostname, attrs.endpoint, attrs.url];
  return fields.some((field) => targetIdentity(field)?.key === track.key);
}

function buildOperatorBatches({ state, config, args, tracks }) {
  const assigned = args.force === true ? new Set() : assignedAssetIds(state, { includePlanned: args.includePlanned === true });
  const openTracks = tracks.filter((track) => !assigned.has(track.canonical) && !assigned.has(track.value));
  const maxBatches = Math.max(1, Math.min(8, Number(args.maxBatches) || openTracks.length || 1));
  const selectedTracks = openTracks.slice(0, maxBatches);
  const engagementSlug = slug(state.engagement.name, 'engagement');
  const engagement = {
    name: state.engagement.name,
    ...(state.engagement.client ? { client: state.engagement.client } : {}),
    authorization: state.engagement.authorization,
    ...(state.engagement.window ? { window: state.engagement.window } : {}),
    mode: state.engagement.mode ?? 'collect',
    ...(state.engagement.roe ? { roe: state.engagement.roe } : {}),
  };
  const deny = Array.isArray(state.scope?.deny) ? state.scope.deny : [];
  const batches = [];
  for (const track of selectedTracks) {
    const matched = Object.values(state.nodes).filter((node) => ['host', 'ip', 'webapp'].includes(node.kind)
      && node.status !== 'merged'
      && nodeBelongsToTrack(node, track));
    const assets = matched.length > 0
      ? matched.map((node) => ({
        id: node.id,
        key: node.key,
        kind: node.kind,
        label: assetLabel(node),
        score: 0,
        node,
      }))
      : [{
        id: `allow:${track.canonical}`,
        key: track.canonical,
        kind: track.type === 'url' ? 'webapp' : track.type,
        label: `${track.type}:${track.canonical}`,
        score: 0,
        node: null,
      }];
    const assetKeys = assets.map((asset) => `${asset.kind}:${asset.key}`).sort();
    const batchId = `b${batches.length + 1}-${shortHash(assetKeys.join('|'), 8)}`;
    const allow = [{
      type: track.type,
      value: track.value,
      canonical: track.canonical,
    }];
    const artifactBase = path.posix.join(config.teamDir ?? '.atkbrain/team', engagementSlug, batchId);
    const artifactPath = `${artifactBase}.json`;
    const prompt = buildChildPrompt({
      engagement,
      mode: args.mode ?? 'teammates',
      batchId,
      batchIndex: batches.length + 1,
      batchCount: selectedTracks.length,
      assets,
      allow,
      deny,
      artifactBase,
      artifactPath,
      exclusive: true,
      namedPorts: track.ports,
    });
    batches.push({
      batchId,
      assets,
      allow,
      deny,
      artifactBase,
      artifactPath,
      prompt,
      promptHash: shortHash(prompt, 16),
      operatorTargets: [track.canonical],
    });
  }
  const skipped = tracks
    .filter((track) => !selectedTracks.includes(track))
    .map((track) => ({ id: track.canonical, key: track.canonical, kind: track.type, reason: assigned.has(track.canonical) ? 'already assigned to an active batch' : 'beyond maxBatches' }));
  return {
    batches,
    skipped,
    candidateCount: tracks.length,
    selectedCount: selectedTracks.length,
    engagement,
    engagementSlug,
    batchSize: 1,
    maxBatches,
    strategy: 'operator',
    operatorSplit: true,
  };
}

function buildBatches({ state, config, args }) {
  if (state.engagement === null || typeof state.engagement?.name !== 'string') {
    invalid('an authorized engagement is required before team planning; call atkbrain_scope action=set first');
  }
  if ((state.scope?.allow?.length ?? 0) === 0) {
    invalid('no authorized scope is set; call atkbrain_scope with the engagement allow list before team planning');
  }
  const requested = Array.isArray(args.assetIds) ? new Set(args.assetIds.map(String)) : undefined;
  const tracks = concreteAllowTargets(state);
  if (tracks.length >= 2 && requested === undefined) return buildOperatorBatches({ state, config, args, tracks });
  const assigned = args.force === true ? new Set() : assignedAssetIds(state, { includePlanned: args.includePlanned === true });
  const served = buildServiceMap(state);
  const candidates = [];
  const skipped = [];
  for (const node of Object.values(state.nodes)) {
    if (!['host', 'ip', 'webapp'].includes(node.kind)) continue;
    if (node.status === 'merged') continue;
    if (requested !== undefined && !requested.has(node.id) && !requested.has(node.key) && !requested.has(node.label)) continue;
    if (assigned.has(node.id) || assigned.has(node.key)) {
      skipped.push({ id: node.id, key: node.key, kind: node.kind, reason: 'already assigned to an active batch' });
      continue;
    }
    const scope = scopeForAsset(state, node);
    if (!scope.eligible) {
      skipped.push({ id: node.id, key: node.key, kind: node.kind, reason: scope.reason });
      continue;
    }
    candidates.push({
      id: node.id,
      key: node.key,
      kind: node.kind,
      label: assetLabel(node),
      score: assetScore(node, served),
      node,
    });
  }
  const strategy = args.strategy === 'targets' ? 'targets' : 'assets';
  let targetMeta = new Map();
  if (strategy === 'targets') {
    const tree = buildTargetTree(state);
    const statusRank = { untested: 3, recon: 2, tested: 1, impacted: 0 };
    for (const cluster of tree.clusters) {
      for (const target of cluster.targets) {
        targetMeta.set(target.host, {
          cluster: cluster.label,
          status: target.status,
          rank: statusRank[target.status] ?? 0,
        });
      }
    }
    for (const candidate of candidates) {
      const meta = targetMeta.get(candidate.key) ?? targetMeta.get(candidate.node?.attrs?.fqdn ?? '');
      candidate.target = meta ?? null;
    }
    candidates.sort((a, b) => (b.target?.rank ?? 0) - (a.target?.rank ?? 0)
      || String(a.target?.cluster ?? '').localeCompare(String(b.target?.cluster ?? ''))
      || b.score - a.score
      || a.kind.localeCompare(b.kind)
      || a.key.localeCompare(b.key));
  } else {
    candidates.sort((a, b) => b.score - a.score || a.kind.localeCompare(b.kind) || a.key.localeCompare(b.key));
  }
  const batchSize = Math.max(1, Math.min(50, Number(args.batchSize) || config.teamBatchSize || 8));
  const maxBatches = Math.max(1, Math.min(8, Number(args.maxBatches) || config.teamMaxBatches || 4));
  const selected = candidates.slice(0, batchSize * maxBatches);
  const engagementSlug = slug(state.engagement.name, 'engagement');
  const engagement = {
    name: state.engagement.name,
    ...(state.engagement.client ? { client: state.engagement.client } : {}),
    authorization: state.engagement.authorization,
    ...(state.engagement.window ? { window: state.engagement.window } : {}),
    mode: state.engagement.mode ?? 'collect',
    ...(state.engagement.roe ? { roe: state.engagement.roe } : {}),
  };
  const deny = Array.isArray(state.scope?.deny) ? state.scope.deny : [];
  const batches = [];
  for (let index = 0; index < selected.length; index += batchSize) {
    const assets = selected.slice(index, index + batchSize);
    if (assets.length === 0) continue;
    const assetKeys = assets.map((asset) => `${asset.kind}:${asset.key}`).sort();
    const batchId = `b${batches.length + 1}-${shortHash(assetKeys.join('|'), 8)}`;
    const allow = assets.map((asset) => {
      if (asset.kind === 'host') return { type: 'host', value: asset.key };
      if (asset.kind === 'ip') return { type: 'ip', value: asset.key };
      return { type: 'url', value: asset.key };
    });
    const artifactBase = path.posix.join(
      config.teamDir ?? '.atkbrain/team',
      engagementSlug,
      batchId,
    );
    const artifactPath = `${artifactBase}.json`;
    const prompt = buildChildPrompt({
      engagement,
      mode: args.mode ?? 'teammates',
      batchId,
      batchIndex: batches.length + 1,
      batchCount: Math.ceil(selected.length / batchSize),
      assets,
      allow,
      deny,
      artifactBase,
      artifactPath,
    });
    batches.push({
      batchId,
      assets,
      allow,
      deny,
      artifactBase,
      artifactPath,
      prompt,
      promptHash: shortHash(prompt, 16),
    });
  }
  return { batches, skipped, candidateCount: candidates.length, selectedCount: selected.length, engagement, engagementSlug, batchSize, maxBatches, strategy };
}

function buildChildPrompt({ engagement, mode, batchId, batchIndex, batchCount, assets, allow, deny, artifactBase, artifactPath, exclusive = false, namedPorts = [] }) {
  const assetLines = assets.map((asset) => `- ${asset.kind}: \`${asset.key}\` (${asset.label})`).join('\n');
  const allowJson = JSON.stringify(allow, null, 2);
  const denyJson = JSON.stringify(deny, null, 2);
  const engagementJson = JSON.stringify(engagement, null, 2);
  const inlineAssetText = assets.map((asset) => asset.key).join('\n');
  return `You are an AtkBrain penetration-testing ${mode === 'teammates' ? 'teammate' : 'subagent'} (batch ${batchIndex}/${batchCount}) working for the Team Lead inside DeepSeek Harness.

## Authorization
Use exactly this engagement and scope. Do NOT widen it, do NOT add allow entries, and do NOT probe anything outside the listed assets.

Engagement:
\`\`\`json
${engagementJson}
\`\`\`

Allow list for this batch:
\`\`\`json
${allowJson}
\`\`\`

Deny list inherited from the Lead (always wins):
\`\`\`json
${denyJson}
\`\`\`

## Your assets (only these)
${assetLines}

## Required workflow
1. Call \`atkbrain_scope\` with:
   \`\`\`json
   {"action":"set","engagement":${JSON.stringify(engagement)},"allow":${JSON.stringify(allow)},"deny":${JSON.stringify(deny)}}
   \`\`\`
2. Seed your own graph with the asset list:
   \`\`\`json
   {"text":${JSON.stringify(inlineAssetText)},"format":"lines","probeWildcard":false,"tags":["subagent","${batchId}"]}
   \`\`\`
   Use \`atkbrain_ingest\` with that payload.
3. Probe each asset with \`atkbrain_probe\`:
   - \`action=tcp\` with ports "22,80,443,445,3306,5432,6379,8080,8443,9200,27017" (or the ports the Lead provided);
   - \`action=http\` for URLs / HTTP endpoints with checks ["fingerprint","exposure"];
   - \`action=tls\` where relevant.
4. Verify findings before marking them verified. Use \`atkbrain_record\` for findings, access, credentials (mask only), data evidence (redacted samples only), pivots and chain steps.
4b. Web surface inventory is mandatory for every webapp: fetch all same-origin HTML/JS bundles and forms.
   Call \`atkbrain_arsenal action=endpoint_vocab target=<host> text=<saved HTML and JavaScript>\`.
   It returns concrete bare endpoints, form/JS routes, parameters, output contexts, and seeds coverage cells.
   Enumerate every .action/.do/.jsp endpoint from JS strings, $.ajax/fetch URLs, form actions, hidden inputs and query
   parameters. A missing endpoint is a coverage gap, not a negative result.
4c. Before closing, compare known output points already on the graph for the observed product and version.
   For each parameter that reaches HTML, classify the context and test:
   HTML body <svg onload=...>; attribute/hidden value \"><svg/onload=...>; inline event/script string
   \');alert(1);// and \\';alert(1);//; href/src URL javascript:alert(1). A body reflection alone is candidate,
   not verified. Use browser execution or a second channel, then repeat the same parameter for SQLi, open redirect,
   SSRF, authz/IDOR, path/file and command/template classes.
5. For every discovered interface, seed the nine-cell coverage board with the owning target:
   \`atkbrain_coverage action=seed path=<path-or-url> target=<your-asset-host>\`.
   Every coverage cell must carry a target so the Lead can prove each sub-target was tested.
6. Do not perform destructive actions. Do not store raw secrets or raw PII in tool arguments, graph state or artifacts.
7. When finished, export your graph:
   \`\`\`json
   {"format":"json","path":${JSON.stringify(artifactBase)}}
   \`\`\`
   Call \`atkbrain_report\` with that payload. It writes \`${artifactPath}\`.
8. Hash the artifact (for example with \`bash\`: \`shasum -a 256 ${artifactPath}\`) and reply with ONLY this JSON object:
   \`\`\`json
   {"artifact":${JSON.stringify(artifactPath)},"sha256":"<sha256>","summary":"<one paragraph>","findings":<number>,"access":<number>,"data":<number>,"open_questions":[]}
   \`\`\`

Rules:
- Work only on the listed assets; if a target is denied by scope, stop and report it instead of bypassing.
${exclusive ? `- This batch is one target. A target is one IP, or one first-level subdomain: different ports of that IP or subdomain stay in this batch, and a deeper name under that subdomain stays here too. Run the same full procedure a single-target engagement runs. Do not test a different IP or a different first-level subdomain. Do not copy a finding, access, credential, data row, coverage note, or evidence file onto another target. Every record must name this target, and the evidence file must come from this target. A note without that file is not a result.
${namedPorts.length > 0 ? `- The operator named port(s) ${namedPorts.join(', ')}. Finish those services before any other port on this same target.\n` : ''}` : ''}- You are not the Team Lead: do not spawn more subagents or teammates.
- Prefer Host-plane \`atkbrain_probe\` over bash network commands so the scope guard and evidence trail stay intact.
- Keep the artifact free of raw secrets/PII; the Lead will merge your graph JSON.
`;
}

function batchTaskOp(state, batch, { status, extra = {}, planPath, mode }) {
  const existing = findBatchTask(state, batch.batchId);
  const base = {
    op: 'node.upsert',
    kind: 'task',
    key: existing?.key ?? `eng/${BATCH_ACTION}/${batch.batchId}/${shortHash(batch.promptHash, 8)}`,
    label: existing?.label ?? `Batch ${batch.batchId}: ${batch.assets.length} asset(s)`,
    attrs: {
      ...(existing?.attrs ?? {}),
      actionType: BATCH_ACTION,
      batchId: batch.batchId,
      assetIds: batch.assets.map((asset) => asset.id),
      assetKeys: batch.assets.map((asset) => asset.key),
      assetLabels: batch.assets.map((asset) => asset.label),
      assetCount: batch.assets.length,
      ...(Array.isArray(batch.operatorTargets) ? { operatorTargets: batch.operatorTargets } : {}),
      artifactBase: batch.artifactBase,
      artifactPath: batch.artifactPath,
      promptHash: batch.promptHash,
      ...(planPath !== undefined ? { planPath } : {}),
      ...(mode !== undefined ? { mode } : {}),
      ...extra,
    },
    status: status ?? existing?.status ?? 'planned',
    confidence: 0.5,
  };
  return base;
}

function batchesFromTasks({ state, config, args, mode }) {
  const engagementSlug = slug(state.engagement?.name, 'engagement');
  const engagement = {
    name: state.engagement?.name,
    ...(state.engagement?.client ? { client: state.engagement.client } : {}),
    authorization: state.engagement?.authorization,
    ...(state.engagement?.window ? { window: state.engagement.window } : {}),
    mode: state.engagement?.mode ?? 'collect',
    ...(state.engagement?.roe ? { roe: state.engagement.roe } : {}),
  };
  const deny = Array.isArray(state.scope?.deny) ? state.scope.deny : [];
  const requested = Array.isArray(args.assetIds) ? new Set(args.assetIds.map(String)) : undefined;
  const tasks = batchTasks(state)
    .filter((task) => ['planned', 'failed', 'cancelled'].includes(task.status))
    .filter((task) => {
      if (requested === undefined) return true;
      const ids = Array.isArray(task.attrs?.assetIds) ? task.attrs.assetIds : [];
      const keys = Array.isArray(task.attrs?.assetKeys) ? task.attrs.assetKeys : [];
      return [...ids, ...keys].some((value) => requested.has(value));
    })
    .sort((a, b) => String(a.attrs?.batchId ?? '').localeCompare(String(b.attrs?.batchId ?? '')));
  const batches = [];
  for (const task of tasks) {
    const ids = new Set(Array.isArray(task.attrs?.assetIds) ? task.attrs.assetIds : []);
    const keys = new Set(Array.isArray(task.attrs?.assetKeys) ? task.attrs.assetKeys : []);
    const assets = Object.values(state.nodes)
      .filter((node) => ['host', 'ip', 'webapp'].includes(node.kind) && (ids.has(node.id) || keys.has(node.key)))
      .filter((node) => scopeForAsset(state, node).eligible)
      .map((node) => ({
        id: node.id,
        key: node.key,
        kind: node.kind,
        label: assetLabel(node),
        node,
      }));
    if (assets.length === 0) continue;
    const batchId = String(task.attrs?.batchId ?? `b${batches.length + 1}`);
    const allow = assets.map((asset) => {
      if (asset.kind === 'host') return { type: 'host', value: asset.key };
      if (asset.kind === 'ip') return { type: 'ip', value: asset.key };
      return { type: 'url', value: asset.key };
    });
    const artifactBase = typeof task.attrs?.artifactBase === 'string'
      ? task.attrs.artifactBase
      : path.posix.join(config.teamDir ?? '.atkbrain/team', engagementSlug, batchId);
    const artifactPath = typeof task.attrs?.artifactPath === 'string'
      ? task.attrs.artifactPath
      : `${artifactBase}.json`;
    const prompt = buildChildPrompt({
      engagement,
      mode,
      batchId,
      batchIndex: batches.length + 1,
      batchCount: tasks.length,
      assets,
      allow,
      deny,
      artifactBase,
      artifactPath,
    });
    batches.push({
      batchId,
      assets,
      allow,
      deny,
      artifactBase,
      artifactPath,
      prompt,
      promptHash: shortHash(prompt, 16),
    });
  }
  return {
    batches,
    skipped: [],
    candidateCount: batches.reduce((sum, batch) => sum + batch.assets.length, 0),
    selectedCount: batches.reduce((sum, batch) => sum + batch.assets.length, 0),
    engagement,
    engagementSlug,
    batchSize: 0,
    maxBatches: 0,
  };
}

function summarizeBatches(batches) {
  return batches.map((batch) => `${batch.batchId} (${batch.assets.length} asset(s))`).join(', ');
}

export function registerTeamTool(ctx, config, deps) {
  registerAtkTool(ctx, config, deps, {
    name: TOOL_NAMES.team,
    callTitle: 'Orchestrate pentest team',
    description: 'Plan and orchestrate parallel per-asset pentesting with DSH Agent Teams teammates or subagents. plan turns in-scope assets into deterministic batches and child prompts (strategy=targets orders cluster/sub-target gaps first); dispatch starts one teammate/subagent per batch; status joins the live roster with artifact readiness; merge folds child graph JSON back into this attack graph; stop interrupts running batches. Teammates also receive a shared Team task that is completed on merge.',
    parameters: PARAMETERS,
    timeoutMs: 300000,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (args.mode !== undefined) requireEnum(args, 'mode', MODES);
      if (args.batchSize !== undefined) optionalInteger(args, 'batchSize', { min: 1, max: 50 });
      if (args.maxBatches !== undefined) optionalInteger(args, 'maxBatches', { min: 1, max: 8 });
      if (args.assetIds !== undefined) {
        if (!Array.isArray(args.assetIds) || args.assetIds.some((id) => typeof id !== 'string')) {
          invalid('assetIds must be an array of asset node ids or canonical keys');
        }
        if (args.assetIds.length > 500) invalid('assetIds contains too many entries (max 500)');
      }
      if (args.force !== undefined && typeof args.force !== 'boolean') invalid('force must be a boolean');
      if (args.batchId !== undefined) requireString(args, 'batchId', { max: 100 });
      if (action === 'dispatch' && args.mode === undefined) {
        // default handled at execution; validation only checks explicit values.
      }
      return true;
    },
    async run({ args, state, exec, ctx: toolCtx, config: cfg, deps: runtime }) {
      const action = args.action;
      let mode = args.mode;
      if (mode === undefined) {
        // The five native role teams occupy the durable roster; batch workers
        // should be subagents unless the operator explicitly asks for teammates.
        const agentTeams = (() => { try { return toolCtx.get('agentTeams'); } catch { return undefined; } })();
        let members = [];
        try {
          if (agentTeams !== undefined && agentTeams !== null && typeof agentTeams.listMembers === 'function') {
            members = await agentTeams.listMembers(exec.agent);
          }
        } catch { members = []; }
        const hasNativeRoles = Array.isArray(members) && members.some((member) => ['atk-supervisor', 'atk-verifier', 'atk-escalator', 'atk-reporter'].includes(String(member?.name ?? '')));
        mode = hasNativeRoles ? 'subagents' : 'teammates';
      }
      const workspace = runtime.workspace(exec.agent);

      if (action === 'plan') {
        requireLead(toolCtx, exec.agent);
        const plan = buildBatches({ state, config: cfg, args: { ...args, mode } });
        const targetTree = buildTargetTree(state);
        const targetGaps = (targetTree.totals.recon ?? 0) + (targetTree.totals.untested ?? 0);
        if (plan.batches.length === 0) {
          return {
            summary: `No unassigned, in-scope assets to batch (${plan.candidateCount} candidate(s), ${plan.skipped.length} skipped). Set a scope/import assets, or use force=true to re-plan assigned assets.`
              + (plan.skipped.length > 0 ? `\nSkipped: ${plan.skipped.slice(0, 5).map((entry) => `${entry.key} (${entry.reason})`).join('; ')}` : ''),
            ops: [audit(TOOL_NAMES.team, 'team.plan', 'assets', 'no batches', [])],
            details: { plan: { ...plan, batches: plan.batches.map(({ prompt, ...rest }) => rest) } },
          };
        }
        const planArtifact = await runtime.writeEvidence(
          exec.agent,
          `team-plan-${plan.engagementSlug}-${shortHash(stableStringify(plan.batches.map((batch) => batch.batchId)), 10)}`,
          {
            generatedAt: nowIso(),
            engagement: plan.engagement,
            mode,
            batches: plan.batches.map((batch) => ({
              batchId: batch.batchId,
              assets: batch.assets.map(({ node: _node, ...asset }) => asset),
              allow: batch.allow,
              deny: batch.deny,
              artifactPath: batch.artifactPath,
              promptHash: batch.promptHash,
              prompt: batch.prompt,
            })),
          },
          'application/json',
        );
        const ops = [
          evidenceNodeOp(state, {
            path: planArtifact.path,
            relative: planArtifact.relative,
            mediaType: planArtifact.mediaType,
            bytes: planArtifact.bytes,
            sha256: planArtifact.sha256,
            label: `team plan ${plan.engagementSlug}`,
          }),
        ];
        for (const batch of plan.batches) {
          const existing = findBatchTask(state, batch.batchId);
          if (existing !== undefined && existing.status !== 'failed' && existing.status !== 'cancelled') continue;
          ops.push(batchTaskOp(state, batch, { status: 'planned', planPath: planArtifact.relative, mode }));
        }
        ops.push(audit(TOOL_NAMES.team, 'team.plan', plan.engagementSlug, `${plan.batches.length} batch(es), ${plan.selectedCount} asset(s)`, [planArtifact.sha256]));
        return {
          summary: `Planned ${plan.batches.length} batch(es) with strategy=${plan.strategy ?? 'assets'} for ${plan.selectedCount} in-scope asset(s): ${summarizeBatches(plan.batches)}.\nPlan artifact: ${planArtifact.relative}.\n${plan.operatorSplit === true ? 'Each operator target has its own batch. Dispatch them together; do not test those targets in the lead thread, and do not copy one target\'s result onto another.\n' : ''}Target coverage: ${targetTree.totals.clusters} cluster(s), ${targetTree.totals.targets} target(s), ${targetTree.totals.tested} tested / ${targetTree.totals.recon} recon-only / ${targetTree.totals.untested} untested; ${targetGaps} gap(s) before all targets are covered.\nNext: atkbrain_team action=dispatch mode=${mode} (or read the plan artifact and spawn teammates manually).${targetGaps > 0 ? ' Prioritise batches for recon/untested targets and pass target=<asset-host> to atkbrain_coverage.' : ''}`
            + (plan.skipped.length > 0 ? `\nSkipped ${plan.skipped.length} asset(s): ${plan.skipped.slice(0, 5).map((entry) => `${entry.key} (${entry.reason})`).join('; ')}` : ''),
          ops,
          details: {
            batches: plan.batches.map(({ prompt, ...batch }) => ({ ...batch, prompt })),
            planArtifact,
            skipped: plan.skipped,
            targets: targetTree,
            mode,
            strategy: plan.strategy ?? 'assets',
          },
        };
      }

      if (action === 'dispatch') {
        requireLead(toolCtx, exec.agent);
        const teams = toolCtx.get('agentTeams');
        const subagents = toolCtx.get('subagents');
        if (mode === 'teammates' && (teams === undefined || teams === null)) {
          invalid('mode=teammates requires the DSH Agent Teams service; install @deepseek-ai/dsh-experimental-agent-team or use mode=subagents');
        }
        if (mode === 'subagents' && (subagents === undefined || subagents === null)) {
          invalid('mode=subagents requires the DSH subagent service; install @deepseek-ai/dsh-subagent or use mode=teammates');
        }
        const hasPlannedBatches = batchTasks(state).some((task) => ['planned', 'failed', 'cancelled'].includes(task.status));
        const plan = hasPlannedBatches
          ? batchesFromTasks({ state, config: cfg, args, mode })
          : buildBatches({ state, config: cfg, args: { ...args, mode, includePlanned: true } });
        const pending = plan.batches.filter((batch) => {
          const existing = findBatchTask(state, batch.batchId);
          if (existing === undefined) return true;
          return !FINISHED_BATCH_STATUSES.has(existing.status) && existing.status !== 'dispatched' && existing.status !== 'artifact_ready';
        });
        if (pending.length === 0) {
          return {
            summary: `No batch needs dispatch (${plan.batches.length} planned, all active or finished). Use atkbrain_team action=status or action=merge.`,
            ops: [],
            details: { batches: plan.batches.map(({ prompt, ...batch }) => batch) },
          };
        }
        const ops = [];
        const dispatched = [];
        const warnings = [];
        for (const batch of pending) {
          const existing = findBatchTask(state, batch.batchId);
          const attempt = Math.max(1, (Number(existing?.attrs?.attempts) || 0) + 1);
          const teamName = `atk-${batch.batchId}${attempt > 1 ? `-r${attempt}` : ''}`.slice(0, 80);
          const description = `AtkBrain ${batch.batchId}: ${batch.assets.length} asset(s)`;
          let childId;
          let agentName;
          let teamTaskId;
          let teamTaskRevision;
          try {
            if (mode === 'teammates') {
              const spawned = await teams.spawnTeammate(exec.agent, {
                name: teamName,
                description,
                prompt: [{ type: 'text', text: batch.prompt }],
                context: 'fresh',
                provider: 'spawn',
                signal: exec.signal,
              });
              const member = spawned?.member ?? spawned;
              childId = member?.id;
              agentName = member?.name ?? teamName;
              try {
                const view = await teams.createTask(exec.agent, {
                  subject: `[AtkBrain] ${batch.batchId}: ${batch.assets.length} asset(s)`,
                  description: `Pentest batch ${batch.batchId}.\n\nAssets:\n${batch.assets.map((asset) => `- ${asset.label}`).join('\n')}\n\nArtifact: ${batch.artifactPath}\n\nPrompt: delivered to ${agentName}. The Lead merges the child graph JSON.`,
                  writeScopes: [batch.artifactBase],
                });
                teamTaskId = view.id;
                teamTaskRevision = view.revision;
                if (agentName !== undefined) {
                  const updated = await teams.updateTask(exec.agent, {
                    taskId: view.id,
                    expectedRevision: view.revision,
                    action: 'reassign',
                    owner: agentName,
                  });
                  teamTaskRevision = updated.revision;
                }
              } catch (error) {
                warnings.push(`${batch.batchId}: teammate spawned but Team task setup failed: ${error instanceof Error ? error.message : String(error)}`);
              }
            } else {
              const activation = await subagents.startActivation({
                provider: 'spawn',
                label: description,
                request: {
                  prompt: [{ type: 'text', text: batch.prompt }],
                  parent: exec.agent,
                },
                signal: exec.signal,
                delivery: 'parent',
              });
              childId = activation?.childId;
              agentName = childId;
            }
            ops.push(batchTaskOp(state, batch, {
              status: 'dispatched',
              mode,
              planPath: existing?.attrs?.planPath,
              extra: {
                agentName,
                childId,
                attempts: attempt,
                dispatchedAt: nowIso(),
                ...(teamTaskId !== undefined ? { teamTaskId } : {}),
                ...(teamTaskRevision !== undefined ? { teamTaskRevision } : {}),
              },
            }));
            dispatched.push({ batchId: batch.batchId, agentName, childId, teamTaskId, mode, artifactPath: batch.artifactPath });
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            warnings.push(`${batch.batchId}: dispatch failed: ${message}`);
            ops.push(batchTaskOp(state, batch, {
              status: 'failed',
              mode,
              planPath: existing?.attrs?.planPath,
              extra: {
                attempts: attempt,
                error: message,
                failedAt: nowIso(),
              },
            }));
          }
        }
        ops.push(audit(TOOL_NAMES.team, 'team.dispatch', mode, `${dispatched.length} dispatched / ${pending.length} pending`, []));
        const summary = `Dispatched ${dispatched.length}/${pending.length} batch(es) as ${mode}: ${dispatched.map((entry) => `${entry.batchId}->${entry.agentName ?? entry.childId ?? 'unknown'}`).join(', ') || 'none'}.`
          + `${warnings.length > 0 ? `\nWarnings: ${warnings.slice(0, 5).join('; ')}` : ''}`
          + `\nNext: atkbrain_team action=status; when artifacts are ready, atkbrain_team action=merge.`;
        return {
          summary,
          ops,
          details: { dispatched, warnings, mode },
        };
      }

      if (action === 'status') {
        const teams = toolCtx.get('agentTeams');
        const subagents = toolCtx.get('subagents');
        const members = (() => {
          if (teams === undefined || teams === null) return [];
          try { return teams.listMembers(exec.agent); } catch { return []; }
        })();
        let children = [];
        let childrenWarning;
        if (subagents !== undefined && subagents !== null) {
          try {
            children = await subagents.listChildren(exec.agent.session.id, exec.signal);
          } catch (error) {
            childrenWarning = error instanceof Error ? error.message : String(error);
          }
        }
        const memberByName = new Map(members.map((member) => [member.name ?? member.target, member]));
        const childrenById = new Map(children.map((entry) => [entry.id, entry]));
        const rows = [];
        const ops = [];
        for (const task of batchTasks(state)) {
          if (args.batchId !== undefined && task.attrs?.batchId !== args.batchId) continue;
          const artifactPath = task.attrs?.artifactPath;
          let artifactReady = false;
          let artifactBytes;
          let artifactMtime;
          if (typeof artifactPath === 'string') {
            try {
              const absolute = resolveArtifact(exec.agent, workspace, artifactPath);
              const info = await stat(absolute);
              artifactReady = info.isFile() && info.size > 0;
              artifactBytes = info.size;
              artifactMtime = info.mtime.toISOString();
            } catch {
              artifactReady = false;
            }
          }
          const agentName = task.attrs?.agentName;
          const childId = task.attrs?.childId;
          const member = agentName !== undefined ? memberByName.get(agentName) : undefined;
          const child = childId !== undefined ? childrenById.get(childId) : undefined;
          const liveStatus = member?.status ?? child?.status;
          rows.push({
            batchId: task.attrs?.batchId,
            label: task.label,
            status: task.status,
            assets: task.attrs?.assetCount ?? 0,
            agentName,
            childId,
            mode: task.attrs?.mode,
            liveStatus,
            artifactPath,
            artifactReady,
            artifactBytes,
            artifactMtime,
            teamTaskId: task.attrs?.teamTaskId,
            mergedAt: task.attrs?.mergedAt ?? null,
          });
          if (artifactReady && task.status === 'dispatched') {
            ops.push({
              op: 'node.upsert',
              kind: 'task',
              key: task.key,
              label: task.label,
              attrs: { ...task.attrs, artifactReadyAt: nowIso() },
              status: 'artifact_ready',
              confidence: task.confidence,
            });
          }
        }
        const ready = rows.filter((row) => row.artifactReady && row.status !== 'merged' && row.status !== 'completed').length;
        const active = rows.filter((row) => ['planned', 'dispatched', 'artifact_ready'].includes(row.status)).length;
        const next = active === 0
          ? 'All batches are merged, failed or cancelled; run atkbrain_report format=all (or atkbrain_team action=plan for new assets).'
          : ready > 0
            ? 'atkbrain_team action=merge'
            : 'wait for children; native wait_agent / list_agents can help.';
        return {
          summary: `${rows.length} batch(es): ${rows.filter((row) => row.status === 'merged' || row.status === 'completed').length} merged, ${ready} artifact(s) ready, ${rows.filter((row) => row.status === 'dispatched').length} running/awaiting.`
            + (childrenWarning !== undefined ? `\nSubagent catalog unavailable: ${childrenWarning}` : '')
            + (rows.length > 0 ? `\nBatches: ${rows.slice(0, 8).map((row) => `${row.batchId}[${row.status}${row.liveStatus !== undefined ? `/${row.liveStatus}` : ''}${row.artifactReady ? ',artifact-ready' : ''}]`).join('; ')}` : '')
            + `\nNext: ${next}`,
          ops,
          details: { batches: rows, members, children: children.slice(0, 50), childrenWarning },
        };
      }

      if (action === 'merge') {
        requireLead(toolCtx, exec.agent);
        const tasks = batchTasks(state).filter((task) => args.batchId === undefined || task.attrs?.batchId === args.batchId);
        const ready = [];
        const warnings = [];
        for (const task of tasks) {
          const artifactPath = task.attrs?.artifactPath;
          if (typeof artifactPath !== 'string') continue;
          if (!args.force && (task.status === 'merged' || task.status === 'completed')) continue;
          try {
            const absolute = resolveArtifact(exec.agent, workspace, artifactPath);
            const info = await stat(absolute);
            if (!info.isFile() || info.size === 0) continue;
            ready.push({ task, artifactPath, absolute });
          } catch {
            // Artifact not written yet.
          }
        }
        if (ready.length === 0) {
          return {
            summary: 'No child artifacts are ready to merge. Run atkbrain_team action=status; children write .atkbrain/team/<engagement>/<batch>.json.',
            ops: [],
            details: { batches: tasks.length },
          };
        }
        const ingestTool = toolCtx.tools.get(TOOL_NAMES.ingest);
        if (ingestTool === undefined) invalid('atkbrain_ingest is not registered, so child artifacts cannot be merged');
        const teams = toolCtx.get('agentTeams');
        const ops = [];
        const merged = [];
        for (let index = 0; index < ready.length; index += 1) {
          const { task, artifactPath } = ready[index];
          const format = artifactPath.endsWith('.jsonl') ? 'observations' : 'graph-json';
          try {
            const ingestValue = await ingestTool.execute({
              paths: [artifactPath],
              format,
              probeWildcard: false,
              tags: ['team-merge', String(task.attrs?.batchId ?? 'batch')],
            }, {
              agent: exec.agent,
              callId: `${exec.callId}-merge-${index}`,
              name: TOOL_NAMES.ingest,
              signal: exec.signal,
              arguments: { paths: [artifactPath], format, probeWildcard: false },
            });
            const ingestOps = Array.isArray(ingestValue?.ops) ? ingestValue.ops : [];
            ops.push(...ingestOps);
            ops.push({
              op: 'node.upsert',
              kind: 'task',
              key: task.key,
              label: task.label,
              attrs: {
                ...task.attrs,
                mergedAt: nowIso(),
                mergeSummary: ingestValue?.summary,
                mergedOps: ingestOps.length,
              },
              status: 'completed',
              confidence: task.confidence,
            });
            ops.push(audit(TOOL_NAMES.team, 'team.merge', String(task.attrs?.batchId ?? 'batch'), `${ingestOps.length} op(s)`, []));
            const childName = task.attrs?.agentName;
            const teamTaskId = task.attrs?.teamTaskId;
            if (teams !== undefined && teams !== null && typeof teamTaskId === 'string') {
              try {
                const view = teams.getTask(exec.agent, teamTaskId);
                if (view.status === 'in_progress') {
                  await teams.updateTask(exec.agent, {
                    taskId: teamTaskId,
                    expectedRevision: view.revision,
                    action: 'complete',
                  });
                }
              } catch (error) {
                warnings.push(`${task.attrs?.batchId}: graph merged but Team task completion failed: ${error instanceof Error ? error.message : String(error)}`);
              }
            }
            merged.push({ batchId: task.attrs?.batchId, agentName: childName, artifactPath, ops: ingestOps.length, summary: ingestValue?.summary });
          } catch (error) {
            warnings.push(`${task.attrs?.batchId}: merge failed: ${error instanceof Error ? error.message : String(error)}`);
            ops.push({
              op: 'node.upsert',
              kind: 'task',
              key: task.key,
              label: task.label,
              attrs: { ...task.attrs, mergeError: error instanceof Error ? error.message : String(error), mergeFailedAt: nowIso() },
              status: 'merge_failed',
              confidence: task.confidence,
            });
          }
        }
        const summary = `Merged ${merged.length}/${ready.length} child artifact(s).`
          + (merged.length > 0 ? ` Ops: ${merged.map((entry) => `${entry.batchId}:${entry.ops}`).join(', ')}.` : '')
          + (warnings.length > 0 ? `\nWarnings: ${warnings.slice(0, 5).join('; ')}` : '')
          + ' Next: run atkbrain_selftteam action=brief (the graph changed and targets may still be recon-only), atkbrain_query action=targets to check cluster/sub-target coverage, then atkbrain_query action=stats and atkbrain_report format=all when the team is finished.';
        return {
          summary,
          ops,
          details: { merged, warnings, ready: ready.length },
        };
      }

      // stop
      requireLead(toolCtx, exec.agent);
      const teams = toolCtx.get('agentTeams');
      const subagents = toolCtx.get('subagents');
      const ops = [];
      const stopped = [];
      const warnings = [];
      for (const task of batchTasks(state)) {
        if (args.batchId !== undefined && task.attrs?.batchId !== args.batchId) continue;
        if (FINISHED_BATCH_STATUSES.has(task.status) && task.status !== 'cancelled') continue;
        if (task.status === 'planned') {
          ops.push({
            op: 'node.upsert',
            kind: 'task',
            key: task.key,
            label: task.label,
            attrs: { ...task.attrs, stoppedAt: nowIso() },
            status: 'cancelled',
            confidence: task.confidence,
          });
          stopped.push({ batchId: task.attrs?.batchId, mode: task.attrs?.mode, status: 'planned->cancelled' });
          continue;
        }
        try {
          if (task.attrs?.mode === 'teammates' && teams !== undefined && teams !== null && task.attrs?.agentName) {
            await teams.interrupt(exec.agent, task.attrs.agentName);
          } else if (task.attrs?.mode === 'subagents' && subagents !== undefined && subagents !== null && task.attrs?.childId) {
            subagents.interrupt(task.attrs.childId, { kind: 'ancestor', agent: exec.agent });
          }
          ops.push({
            op: 'node.upsert',
            kind: 'task',
            key: task.key,
            label: task.label,
            attrs: { ...task.attrs, stoppedAt: nowIso() },
            status: 'cancelled',
            confidence: task.confidence,
          });
          const teamTaskId = task.attrs?.teamTaskId;
          if (teams !== undefined && teams !== null && typeof teamTaskId === 'string') {
            try {
              const view = teams.getTask(exec.agent, teamTaskId);
              if (view.status === 'in_progress') {
                await teams.updateTask(exec.agent, {
                  taskId: teamTaskId,
                  expectedRevision: view.revision,
                  action: 'reassign',
                });
              }
            } catch (error) {
              warnings.push(`${task.attrs?.batchId}: Team task release failed: ${error instanceof Error ? error.message : String(error)}`);
            }
          }
          stopped.push({ batchId: task.attrs?.batchId, mode: task.attrs?.mode });
        } catch (error) {
          warnings.push(`${task.attrs?.batchId}: stop failed: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      ops.push(audit(TOOL_NAMES.team, 'team.stop', 'batches', `${stopped.length} stopped`, []));
      return {
        summary: `Stopped ${stopped.length} batch(es).`
          + (warnings.length > 0 ? `\nWarnings: ${warnings.slice(0, 5).join('; ')}` : '')
          + ' Running teammates/subagents may finish their current turn; use native list_agents to confirm.',
        ops,
        details: { stopped, warnings },
      };
    },
  });
}
