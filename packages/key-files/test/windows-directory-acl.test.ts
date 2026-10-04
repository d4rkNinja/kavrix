import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

import {
  setWindowsUserOnlyAcl,
  verifyWindowsDirectoryAcl,
} from '../src/windows-acl.js';
import { ensureSecureDirectory } from '../src/filesystem.js';

const execFileAsync = promisify(execFile);

describe.runIf(process.platform === 'win32')(
  'real Windows parent directory permissions',
  () => {
    it('accepts inherit-only creator-owner grants but rejects grants that modify the parent', async () => {
      const directory = await mkdtemp(join(tmpdir(), 'kavrix-parent-acl-'));
      try {
        await setWindowsUserOnlyAcl(directory);
        const icacls = String.raw`C:\Windows\System32\icacls.exe`;
        await execFileAsync(icacls, [directory, '/grant', '*S-1-3-0:(OI)(CI)(IO)(F)']);
        await expect(verifyWindowsDirectoryAcl(directory)).resolves.toBeUndefined();
        await expect(
          ensureSecureDirectory(join(directory, 'protected-child')),
        ).resolves.toBe(join(directory, 'protected-child'));
        await execFileAsync(icacls, [directory, '/grant', '*S-1-1-0:(M)']);
        await expect(verifyWindowsDirectoryAcl(directory)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
  },
);
