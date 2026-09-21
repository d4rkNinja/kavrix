import { chmod, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { classifyCliFailure } from '../src/cli-errors.js';
import { SessionUnlockError } from '../src/session-unlock.js';
import { ensureKavrixConfig } from '../src/kavrix-config.js';

const directories: string[] = [];

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) =>
      rm(directory, { force: true, recursive: true }).catch(() => undefined),
    ),
  );
});

describe('session unlock error classification', () => {
  it('maps session unlock failure codes to stable exit codes', () => {
    const cases: ReadonlyArray<{
      readonly code: SessionUnlockError['code'];
      readonly exitCode: number;
    }> = [
      { code: 'unavailable', exitCode: 14 },
      { code: 'expired', exitCode: 14 },
      { code: 'keychain-unavailable', exitCode: 15 },
      { code: 'tampered', exitCode: 16 },
    ];
    for (const { code, exitCode } of cases) {
      const result = classifyCliFailure(
        new SessionUnlockError(code, `session: ${code}.`),
      );
      expect(result.exitCode, code).toBe(exitCode);
      expect(result.message).toContain(code);
    }
  });
});

describe('ensureKavrixConfig self-heal', () => {
  it('hardens an existing unsafe kavrix home and config reference', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-config-heal-'),
    );
    directories.push(directory);
    const kavrixHome = join(directory, '.kavrix');
    await mkdir(kavrixHome, { mode: 0o755 });
    if (process.platform !== 'win32') {
      await chmod(kavrixHome, 0o755);
    }
    const configPath = join(kavrixHome, 'config.toml');
    await writeFile(configPath, '# stale unsafe reference\n', { mode: 0o644 });
    if (process.platform !== 'win32') {
      const { chmod: rechmod } = await import('node:fs/promises');
      await rechmod(configPath, 0o644);
    }

    const path = await ensureKavrixConfig();
    expect(path).toContain('.kavrix');
    if (process.platform !== 'win32') {
      expect((await stat(kavrixHome)).mode & 0o777).toBe(0o700);
      expect((await stat(configPath)).mode & 0o777).toBe(0o600);
    }
  });

  it('succeeds on a fresh home and creates the onboarding reference', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-config-fresh-'),
    );
    directories.push(directory);
    const kavrixHome = join(directory, '.kavrix');
    await mkdir(kavrixHome, { mode: 0o700 });

    const path = await ensureKavrixConfig();
    expect(path.endsWith('config.toml')).toBe(true);
    const content = await readFile(path, 'utf8');
    expect(content).toMatch(/Kavrix/);
  });
});
