/* global process */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const workerState = globalThis;

if (workerState.__kavrixIsolatedTestHome__ === undefined) {
  const isolatedHome = mkdtempSync(join(tmpdir(), 'kavrix-test-home-'));
  process.env.USERPROFILE = isolatedHome;
  process.env.HOME = isolatedHome;
  process.env.XDG_CONFIG_HOME = join(isolatedHome, '.config');
  process.once('exit', () => {
    try {
      rmSync(isolatedHome, { recursive: true, force: true, maxRetries: 2 });
    } catch {
      reportLeftover(isolatedHome);
    }
  });
  workerState.__kavrixIsolatedTestHome__ = isolatedHome;
}

function reportLeftover(directory) {
  process.stderr.write(`kavrix test home not removed: ${directory}\n`);
}
