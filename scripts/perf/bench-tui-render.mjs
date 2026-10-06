/**
 * Measures the TUI's pure render path: how long it takes to build a screen
 * model and flatten it to terminal text.
 *
 * This is the loop that runs on every keystroke, every mouse move, and every
 * animation tick. Nothing here touches a vault, a key, or a datastore: the
 * fixtures are synthetic payloads from the TUI test suite.
 */
import {
  buildTuiScreenModel,
  renderTuiScreenText,
} from '../../packages/tui/src/screen-model.ts';
import {
  createInitialTuiState,
  filteredItemIndexes,
  selectedFields,
  transitionTui,
} from '../../packages/tui/src/state.ts';
import { group, item, secondItem } from '../../packages/tui/test/fixtures.ts';

import { parseArgs, throughput } from './harness.mjs';

const itemCounts = (parseArgs(process.argv).items ?? '50,500,2000')
  .split(',')
  .map(Number);
const iterations = Number.parseInt(parseArgs(process.argv).iterations ?? '200', 10);

const results = { iterations, scenarios: {} };
let cursor = 0;
for (const itemCount of itemCounts) {
  results.scenarios[`items-${itemCount}`] = await measure(itemCount);
}
console.log(JSON.stringify(results, null, 2));

/**
 * Builds a browser state holding `itemCount` synthetic items. Each item carries
 * searchable text in every field the filter scans, which is the worst realistic
 * case for `filteredItemIndexes`.
 */
function stateWithItems(itemCount) {
  let state = transitionTui(createInitialTuiState(), { type: 'start' }).state;
  state = transitionTui(state, {
    type: 'groups-loaded',
    requestId: 1,
    groups: [group],
  }).state;
  const items = [
    item,
    secondItem,
    ...Array.from({ length: Math.max(0, itemCount - 2) }, (_, index) => ({
      ...item,
      id: `item.${String(index).padStart(6, '0')}`,
      title: `Synthetic Credential ${String(index).padStart(6, '0')}`,
      aliases: [`alias-${index}`],
    })),
  ];
  return transitionTui(state, {
    type: 'items-loaded',
    requestId: 2,
    groupId: group.id,
    items,
  }).state;
}

async function measure(itemCount) {
  const state = stateWithItems(itemCount);
  const searched = { ...state, query: 'synthetic' };
  // Selectors cache by their real inputs (items-array identity, query), so a
  // rotating set of states whose items arrays are distinct-but-equivalent
  // copies makes every measured call a cold miss, while per-item normalization
  // stays warm exactly as it would be while a user types. Building the copies
  // is outside the measured calls.
  const cold = rotatingStates(state, 64);
  const coldSearched = rotatingStates(searched, 64);
  return {
    buildScreenModelEmptyQuery: await throughput(() => buildTuiScreenModel(state, 0), {
      iterations,
      warmup: Math.floor(iterations / 4),
    }),
    buildScreenModelWithQuery: await throughput(
      () => buildTuiScreenModel(searched, 0),
      {
        iterations,
        warmup: Math.floor(iterations / 4),
      },
    ),
    renderScreenText: await throughput(
      () => renderTuiScreenText(buildTuiScreenModel(searched, 0)),
      { iterations, warmup: Math.floor(iterations / 4) },
    ),
    filteredItemIndexesCold: await throughput(
      () => {
        cursor += 1;
        filteredItemIndexes(coldSearched[cursor % coldSearched.length]);
      },
      { iterations, warmup: 0 },
    ),
    filteredItemIndexesWarm: await throughput(() => filteredItemIndexes(searched), {
      iterations,
      warmup: Math.floor(iterations / 4),
    }),
    buildScreenModelColdQuery: await throughput(
      () => {
        cursor += 1;
        buildTuiScreenModel(coldSearched[cursor % coldSearched.length], 0);
      },
      { iterations, warmup: 0 },
    ),
    selectedFields: await throughput(() => selectedFields(state), {
      iterations,
      warmup: Math.floor(iterations / 4),
    }),
  };
}

/** Distinct item-array identities with equivalent contents, one per state. */
function rotatingStates(state, count) {
  return Array.from({ length: count }, () => ({ ...state, items: [...state.items] }));
}
