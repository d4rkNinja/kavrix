#!/usr/bin/env node
/**
 * Non-interactive screen inventory smoke for CI.
 * Does not open a TTY Ink session; it asserts the exported screen catalog and
 * router navigation helpers remain complete.
 */
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

const expected = [
  'home',
  'profiles',
  'vaults',
  'credentials',
  'doctor',
  'recovery',
  'run',
  'policy',
  'agent',
  'browse',
  'help',
  'showcase',
];

async function main() {
  const entry = pathToFileURL(resolve(root, 'packages/tui/dist/index.js')).href;
  const tui = await import(entry);
  const inventory = tui.listScreenInventory();
  if (JSON.stringify(inventory) !== JSON.stringify(expected)) {
    console.error('Screen inventory mismatch.');
    console.error('expected', expected);
    console.error('actual', inventory);
    process.exitCode = 1;
    return;
  }

  let state = tui.createInitialAppRouterState({ ascii: true, color: false });
  for (const screen of expected) {
    state = tui.navigateToScreen(state, screen);
    if (state.screen !== screen) {
      console.error(`Failed to navigate to ${screen}`);
      process.exitCode = 1;
      return;
    }
  }

  const presentation = tui.resolveAppPresentation({
    platform: 'win32',
    term: 'xterm',
    noColor: true,
  });
  if (presentation.ascii !== true || presentation.color !== false) {
    console.error('Presentation defaults failed', presentation);
    process.exitCode = 1;
    return;
  }

  console.log(`tui-smoke ok: ${inventory.length} screens`);
  console.log(inventory.join('\n'));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
