import { execFile } from 'node:child_process';
import { link, mkdtemp, open, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

import { describe, expect, it } from 'vitest';

import { readPortableKeyFile, writePortableKeyFile } from '../src/index.js';
import { setWindowsUserOnlyAcl } from '../src/windows-acl.js';

const execFileAsync = promisify(execFile);
const runPlatformIntegration = process.env['KAVRIX_KEY_FILE_INTEGRATION'] === '1';
const UNBOUND = { kind: 'unbound' } as const;
const UNPROTECTED = { kind: 'unprotected' } as const;

describe.runIf(runPlatformIntegration)('real platform key-file policy', () => {
  it('round-trips and rejects link-count and broad-permission variants', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-platform-key-file-'));
    const path = join(directory, 'portable-key.cvk');
    const alias = join(directory, 'portable-key-alias.cvk');
    const portableKey = new Uint8Array(32).fill(0x5a);
    let loadedKey: Uint8Array | undefined;

    try {
      if (process.platform === 'win32') await setWindowsUserOnlyAcl(directory);
      await writePortableKeyFile(path, portableKey, UNBOUND, {
        protection: UNPROTECTED,
      });
      const metadata = await stat(path);
      expect(metadata.isFile()).toBe(true);
      if (process.platform !== 'win32') {
        expect(metadata.mode & 0o777).toBe(0o600);
      }

      const loaded = await readPortableKeyFile(path, UNPROTECTED, UNBOUND);
      loadedKey = loaded.key;
      expect(loadedKey).toEqual(portableKey);

      await link(path, alias);
      await expect(readPortableKeyFile(path, UNPROTECTED)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await rm(alias, { force: true });

      if (process.platform === 'win32') {
        await grantWindowsEveryoneRead(path);
        await expect(readPortableKeyFile(path, UNPROTECTED)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
        await setWindowsUserOnlyAcl(path);
      } else {
        const handle = await open(path, 'r+');
        try {
          await handle.chmod(0o640);
        } finally {
          await handle.close();
        }
        await expect(readPortableKeyFile(path, UNPROTECTED)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
      }
    } finally {
      loadedKey?.fill(0);
      portableKey.fill(0);
      await rm(directory, { force: true, recursive: true });
    }
  }, 30_000);
});

async function grantWindowsEveryoneRead(path: string): Promise<void> {
  const systemRoot = process.env['SystemRoot'];
  if (systemRoot === undefined) throw new Error('SystemRoot is required on Windows');
  await execFileAsync(join(systemRoot, 'System32', 'icacls.exe'), [
    path,
    '/grant',
    '*S-1-1-0:(R)',
  ]);
}
