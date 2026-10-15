import { performance } from 'node:perf_hooks';
import { allCommands } from '../../packages/tui/src/app/commands.ts';
import {
  createInitialAppRouterState,
  filteredCredentials,
} from '../../packages/tui/src/app/router.ts';

// Synthetic metadata only. Queries exceed the bounded result cache to measure
// successive typing rather than repeated hits for one already-filtered view.
const base = createInitialAppRouterState();
const state = {
  ...base,
  screen: 'credentials',
  snapshot: {
    ...base.snapshot,
    credentials: Array.from({ length: 10_000 }, (_, index) => ({
      name: `Synthetic-Credential-${String(index).padStart(5, '0')}`,
      maskedValue: '********',
    })),
  },
};
function measure(operation, iterations) {
  for (let index = 0; index < 100; index += 1) operation(index);
  const started = performance.now();
  for (let index = 0; index < iterations; index += 1) operation(index);
  return (performance.now() - started) / iterations;
}
console.log(
  JSON.stringify(
    {
      commandLookupMeanMs: measure(() => allCommands(state), 100_000),
      search10000MeanMs: measure((index) => {
        filteredCredentials({
          ...state,
          credentialFilter: String(index % 64).padStart(2, '0'),
        });
      }, 1_000),
    },
    null,
    2,
  ),
);
