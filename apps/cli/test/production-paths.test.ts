import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { CliUsageError } from '../src/errors.js';
import { resolveCliDataPaths } from '../src/production/paths.js';

describe('production CLI data paths', () => {
  it('gives a non-empty absolute CREDS_HOME precedence and deterministic children', () => {
    const home = isAbsolute('D:\\kavrix-test') ? 'D:\\kavrix-test' : '/tmp/kavrix-test';
    const paths = resolveCliDataPaths(
      {
        CREDS_HOME: `  ${home}  `,
        APPDATA: resolve(home, 'ignored-appdata'),
        XDG_DATA_HOME: resolve(home, 'ignored-xdg'),
      },
      process.platform,
    );

    expect(paths.home).toBe(resolve(home));
    expect(paths.writerLease).toBe(join(paths.home, 'cli.writer.lock'));
    expect(paths.profileStore).toBe(join(paths.home, 'profiles.db'));
    expect(paths.initializationJournal).toBe(join(paths.home, 'init-journal.db'));
    expect(paths.joinJournal).toBe(join(paths.home, 'join-journal.db'));
    expect(paths.rotationJournal).toBe(
      join(paths.home, 'portable-key-rotation-journal.db'),
    );
    expect(paths.sealedSecrets).toBe(join(paths.home, 'sealed'));
  });

  it('treats an empty override as absent for Windows, macOS, and XDG defaults', () => {
    const platformRoot = resolve(homedir(), 'kavrix-platform-test');

    expect(
      resolveCliDataPaths({ CREDS_HOME: '  ', APPDATA: platformRoot }, 'win32').home,
    ).toBe(join(platformRoot, 'kavrix'));
    expect(resolveCliDataPaths({ CREDS_HOME: '' }, 'darwin').home).toBe(
      join(homedir(), 'Library', 'Application Support', 'kavrix'),
    );
    expect(
      resolveCliDataPaths({ CREDS_HOME: '\t', XDG_DATA_HOME: platformRoot }, 'linux')
        .home,
    ).toBe(join(platformRoot, 'kavrix'));
  });

  it('rejects relative overrides and never falls back to the working directory', () => {
    expect(() =>
      resolveCliDataPaths({ CREDS_HOME: 'relative/kavrix' }, process.platform),
    ).toThrow(CliUsageError);

    const resolved = resolveCliDataPaths({}, 'linux');
    expect(resolved.home).toBe(join(homedir(), '.local', 'share', 'kavrix'));
    expect(resolved.home).not.toBe(resolve('.'));
    expect(isAbsolute(resolved.home)).toBe(true);
  });

  it('accepts only traversal-safe vault identifiers in store file names', () => {
    const home = resolve(homedir(), 'kavrix-path-test');
    const paths = resolveCliDataPaths({ CREDS_HOME: home });

    expect(paths.vaultStore('vault.primary_1~ok')).toBe(
      join(home, 'vault-vault.primary_1~ok.db'),
    );
    for (const invalid of ['', '../escape', 'bad/name', 'bad\\name', '.hidden']) {
      expect(() => paths.vaultStore(invalid)).toThrow(CliUsageError);
    }
  });
});
