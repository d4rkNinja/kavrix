/* global process */
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { setWindowsUserOnlyAcl } from '../packages/key-files/dist/windows-acl.js';

const workerState = globalThis;

if (workerState.__kavrixIsolatedTestHome__ === undefined) {
  // Resolve short-name/junction forms before ACL harden so ensureSecureDirectory
  // and product realpath checks see the same canonical path (Windows exit 14).
  const isolatedHome = realpathSync(mkdtempSync(join(tmpdir(), 'kavrix-test-home-')));
  if (process.platform === 'win32') {
    await setWindowsUserOnlyAcl(isolatedHome);
  }
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
