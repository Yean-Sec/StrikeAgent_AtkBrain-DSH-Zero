/**
 * `atkbrain_hypothesis` — persistent, evidence-gated hypotheses.
 */
import { TOOL_NAMES } from '../constants.js';
import { EXPECTED_PROOFS, HYPOTHESIS_STATUSES, proposeHypothesis, resolveHypothesis, hypothesisSummary, listHypotheses } from '../hypothesis.js';
import { invalid } from '../util.js';
import { hypothesisNodeOp } from './build.js';
import { assertArgs, audit, optionalInteger, optionalString, registerAtkTool, requireEnum, requireString } from './common.js';

const ACTIONS = ['propose', 'resolve', 'list'];
const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'Propose, resolve or list persistent hypotheses.' },
    id: { type: 'string', description: 'Hypothesis id/key for action=resolve.' },
    strategy: { type: 'string', description: 'Concrete hypothesis and test strategy.' },
    targetKey: { type: 'string', description: 'Target/host/service key the hypothesis applies to.' },
    bugClass: { type: 'string', description: 'Optional bug/tactic class.' },
    expectedProof: { type: 'string', enum: EXPECTED_PROOFS, description: 'Expected proof strength.' },
    coverageKey: { type: 'string', description: 'Optional related coverage cell key.' },
    status: { type: 'string', enum: HYPOTHESIS_STATUSES, description: 'Resolution status.' },
    channels: { type: 'array', items: { type: 'string' }, description: 'Independent observation channels.' },
    evidenceIds: { type: 'array', items: { type: 'string' }, description: 'Evidence node ids.' },
    note: { type: 'string', description: 'Concrete resolution observation.' },
    limit: { type: 'integer', description: 'List limit (1-200).' },
  },
};

export function registerHypothesisTool(ctx, config, runtime) {
  registerAtkTool(ctx, config, runtime, {
    name: TOOL_NAMES.hypothesis,
    callTitle: 'Persistent hypothesis',
    description: 'Propose and resolve evidence-gated hypotheses. Verified requires two independent channels or an evidence artifact; disproved/blocked requires a concrete observation. Frontier prioritizes open hypotheses before generic enumeration.',
    parameters: PARAMETERS,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (action === 'propose') {
        requireString(args, 'strategy', { max: 1500 });
        requireString(args, 'targetKey', { max: 400 });
      }
      if (action === 'resolve') {
        requireString(args, 'id', { max: 500 });
        requireEnum(args, 'status', HYPOTHESIS_STATUSES.filter((status) => !['open', 'active', 'deferred'].includes(status)));
      }
      if (args.limit !== undefined) optionalInteger(args, 'limit', { min: 1, max: 200 });
      if (args.note !== undefined) optionalString(args, 'note', { max: 1500 });
      return action;
    },
    async run({ args, state }) {
      const rows = Object.values(state.nodes).filter((node) => node.kind === 'hypothesis');
      if (args.action === 'propose') {
        if (rows.length >= 200) invalid('hypothesis cap reached (200); resolve or defer existing hypotheses before proposing more');
        const proposed = proposeHypothesis(args);
        const node = hypothesisNodeOp(state, proposed);
        return {
          summary: `Hypothesis proposed: ${proposed.strategy.slice(0, 160)} (target ${proposed.targetKey}, expected proof ${proposed.expectedProof}).`,
          ops: [node, audit(TOOL_NAMES.hypothesis, 'hypothesis.propose', proposed.targetKey, proposed.strategy.slice(0, 160), [])],
          details: { id: node.key, hypothesis: proposed },
        };
      }

      if (args.action === 'resolve') {
        const node = rows.find((row) => row.id === args.id || row.key === args.id || row.attrs?.hypothesisId === args.id);
        if (node === undefined) invalid(`unknown hypothesis: ${args.id}`);
        const updated = resolveHypothesis({ ...(node.attrs ?? {}), id: node.attrs?.hypothesisId }, {
          status: args.status,
          channels: args.channels,
          evidenceIds: args.evidenceIds,
          note: args.note,
        });
        const merged = { ...updated, reason: updated.reason ?? updated.note ?? null };
        const op = hypothesisNodeOp(state, { ...merged, id: node.attrs?.hypothesisId ?? node.key });
        return {
          summary: `Hypothesis ${node.attrs?.hypothesisId ?? node.key} -> ${merged.status}.${merged.reason ? ` ${merged.reason.slice(0, 240)}` : ''}`,
          ops: [op, audit(TOOL_NAMES.hypothesis, 'hypothesis.resolve', node.key, `${merged.status} ${merged.reason ?? ''}`.slice(0, 200), merged.evidenceIds ?? [])],
          details: { hypothesis: merged },
        };
      }

      const values = rows.map((node) => ({
        id: node.attrs?.hypothesisId ?? node.key,
        strategy: node.attrs?.strategy ?? node.label,
        targetKey: node.attrs?.targetKey ?? null,
        bugClass: node.attrs?.bugClass ?? null,
        expectedProof: node.attrs?.expectedProof ?? 'poc_replay',
        status: node.status ?? 'open',
        reason: node.attrs?.reason ?? null,
        channels: node.attrs?.channels ?? [],
        evidenceIds: node.attrs?.evidenceIds ?? [],
      })).filter((row) => args.status === undefined || row.status === args.status).slice(0, Number(args.limit) || 100);
      return {
        summary: `${values.length} hypothesis/hypotheses; ${JSON.stringify(hypothesisSummary(rows))}.`,
        ops: [],
        details: { hypotheses: listHypotheses(values, { status: args.status }), summary: hypothesisSummary(rows) },
      };
    },
  });
}
