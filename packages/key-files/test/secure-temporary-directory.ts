import { realpathSync } from 'node:fs';
import { mkdtemp, writeFile } from 'node:fs/promises';

import { setWindowsUserOnlyAcl } from '../src/windows-acl.js';

export async function createSecureTestDirectory(prefix: string): Promise<string> {
  // Resolve OS temp symlinks/junctions (macOS /var → /private/var, Windows
  // short names) *before* hardening ACLs so the ACL lands on the path callers
  // and product realpath checks actually use.
  const directory = realpathSync(await mkdtemp(prefix));
  if (process.platform === 'win32') {
    await setWindowsUserOnlyAcl(directory);
  }
  return directory;
}

export async function writeSecureTestFile(
  path: string,
  data: string | Uint8Array,
  options: Readonly<{ mode?: number }> = {},
): Promise<void> {
  await writeFile(path, data, { ...options, mode: options.mode ?? 0o600 });
  if (process.platform === 'win32') {
    await setWindowsUserOnlyAcl(path);
  }
}
