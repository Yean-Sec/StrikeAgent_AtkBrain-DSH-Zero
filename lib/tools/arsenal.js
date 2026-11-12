/**
 * `atkbrain_arsenal` — in-process endpoint inventory.
 *
 * The vendored skill library, dictionaries, wordlists and external scanner
 * binaries are not part of this workbench. The only remaining action reads
 * HTML/JS the caller already has and records it on the page ledger.
 */
import { TOOL_NAMES } from '../constants.js';
import { invalid } from '../util.js';
import { endpointInventory, harvest, mergeLedgerAttrs, pageTextSupplied, surfaceLedger, synthesize } from '../endpoint-vocab.js';
import {
  assertArgs,
  optionalString,
  registerAtkTool,
  requireEnum,
  requireString,
} from './common.js';

const ACTIONS = ['endpoint_vocab'];

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  required: ['action'],
  properties: {
    action: { type: 'string', enum: ACTIONS, description: 'Inventory endpoints, parameters and output contexts from HTML or JavaScript the caller already fetched. Does not run external tools.' },
    target: { type: 'string', description: 'Host or URL already on the graph. When set, the ledger is stored on that application. Coverage cells are not seeded.' },
    text: { type: 'string', description: 'HTML/JS/response text (max 200 KB).' },
  },
};

export function registerArsenalTool(ctx, config, runtime) {
  registerAtkTool(ctx, config, runtime, {
    name: TOOL_NAMES.arsenal,
    callTitle: 'Endpoint inventory',
    description: 'Inventory endpoints, parameters and output contexts from HTML or JavaScript already in hand. Stores the page ledger when target is set and does not seed coverage cells. Skills, dictionaries and external pentest tools are not available.',
    parameters: PARAMETERS,
    timeoutMs: 30000,
    concurrencySafe: true,
    validate(args) {
      assertArgs(args);
      const action = requireEnum(args, 'action', ACTIONS);
      if (action === 'endpoint_vocab') requireString(args, 'text', { max: 200000 });
      if (args.target !== undefined) optionalString(args, 'target', { max: 2000 });
      return action;
    },
    async run({ args, state }) {
      if (args.action !== 'endpoint_vocab') invalid('skills, dictionaries and external pentest tools are not available');
      const candidates = synthesize(args.text, { limit: 400 });
      const known = harvest(args.text).known.length;
      const inventory = endpointInventory(args.text, { limit: 200 });
      const ledger = surfaceLedger(args.text);
      const surfaceOps = [];
      if (args.target && (ledger.parameters.length > 0 || ledger.contexts.length > 0 || ledger.endpoints.length > 0)) {
        const needle = String(args.target).toLowerCase();
        const webapp = Object.values(state.nodes).find((node) => node.kind === 'webapp'
          && `${node.key} ${node.label} ${node.attrs?.url ?? ''} ${node.attrs?.host ?? ''}`.toLowerCase().includes(needle));
        if (webapp !== undefined) {
          surfaceOps.push({
            op: 'node.upsert',
            kind: 'webapp',
            key: webapp.key,
            label: webapp.label,
            attrs: mergeLedgerAttrs(webapp.attrs ?? {}, args.text, { inventoried: pageTextSupplied(args.text) }),
          });
        }
      }
      return {
        summary: `Endpoint surface: ${inventory.endpoints.length} concrete endpoint(s) (${inventory.endpoints.slice(0, 8).join(', ') || 'none'}), ${inventory.parameters.length} parameter name(s), contexts: ${inventory.contexts.join(', ') || 'none'}; ${candidates.length} candidate path(s) from ${known} known path(s). Ledger only; coverage cells are not seeded.`,
        ops: surfaceOps,
        details: {
          endpoints: inventory.endpoints,
          queryParams: inventory.queryParams,
          contexts: inventory.contexts,
          parameters: inventory.parameters,
          candidates,
          known,
          coverageSeeded: 0,
        },
      };
    },
  });
}
