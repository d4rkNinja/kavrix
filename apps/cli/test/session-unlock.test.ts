import { rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import {
  enableSessionUnlock,
  isKeychainUnavailable,
  macKeychainStoreCommand,
  platformKeychainPort,
  resolveSessionUnlock,
  SessionUnlockError,
  sessionUnlockAccountFor,
  type SessionUnlockPort,
} from '../src/session-unlock.js';

const directories: string[] = [];

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) =>
      rm(directory, { force: true, recursive: true }).catch(() => undefined),
    ),
  );
});

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-session-unlock-${label}-`),
  );
  directories.push(directory);
  return directory;
}

describe('macOS keychain store framing', () => {
  it('frames the write as one stdin command line for `security -i`', () => {
    const account = sessionUnlockAccountFor({
      profileId: 'default',
      keyFile: '/tmp/owner.key',
    });
    const line = macKeychainStoreCommand('kavrix-session-unlock', account, 'QUJDREVG');
    expect(line).toBe(
      `add-generic-password -s kavrix-session-unlock -a ${account} -U -w QUJDREVG`,
    );
    // Every token is whitespace-free so the command-line split is unambiguous
    // and the base64 wrapping key never has to travel through argv.
    for (const token of line.split(' ')) {
      expect(token.length).toBeGreaterThan(0);
      expect(token).not.toMatch(/\s/u);
    }
  });

  it('fails closed when any part could split the stdin command line', () => {
    expect(() => macKeychainStoreCommand('kavrix session', 'su-abc', 'QUJD')).toThrow(
      SessionUnlockError,
    );
    expect(() =>
      macKeychainStoreCommand('kavrix-session-unlock', 'su abc', 'QUJD'),
    ).toThrow(SessionUnlockError);
    expect(() =>
      macKeychainStoreCommand('kavrix-session-unlock', 'su-abc', 'QU JD'),
    ).toThrow(SessionUnlockError);
    expect(() => macKeychainStoreCommand('', 'su-abc', 'QUJD')).toThrow(
      SessionUnlockError,
    );
  });
});

describe('session enable', () => {
  it('stores the wrapping key exactly once and resolves it back', async () => {
    const directory = await scratch('enable');
    const keyFile = join(directory, 'owner.key');
    const stored: string[] = [];
    const port: SessionUnlockPort = {
      store: async (valueB64) => {
        stored.push(valueB64);
      },
      load: async () => stored.at(-1) ?? null,
      remove: async () => {
        stored.length = 0;
      },
    };
    const target = { profileId: 'profile-enable', keyFile };
    const status = await enableSessionUnlock({
      target,
      passphrase: 'correct horse battery staple',
      ttlHours: 3,
      port,
    });
    expect(status.enabled).toBe(true);
    expect(status.ttlHours).toBe(3);
    // Regression: the store call used to run twice verbatim, which on Windows
    // made PasswordVault.Add reject the already-stored credential and fail
    // `session enable` after the sealed file had already been written.
    expect(stored).toHaveLength(1);
    const resolved = await resolveSessionUnlock({ target, port });
    expect(resolved?.passphrase).toBe('correct horse battery staple');
  });
});

describe('session resolve fail-safe paths', () => {
  it('reads a missing sealed session file as no session, corruption as tampered', async () => {
    const directory = await scratch('missing-file');
    const keyFile = join(directory, 'owner.key');
    const wrappingKey = Buffer.alloc(32, 7).toString('base64url');
    const target = { profileId: 'profile-missing', keyFile };
    const port: SessionUnlockPort = {
      store: async () => undefined,
      load: async () => wrappingKey,
      remove: async () => undefined,
    };
    // The keychain half exists but the sealed file does not: removing either
    // half revokes the session, so this is "no session", not tampering. The
    // protected reader reports ENOENT as KEY_FILE_NOT_FOUND, which the check
    // must recognize the same way as a raw ENOENT code.
    await expect(resolveSessionUnlock({ target, port })).resolves.toBeNull();

    await writeFile(`${keyFile}.session`, 'not a session document', {
      mode: 0o600,
    });
    await expect(resolveSessionUnlock({ target, port })).rejects.toMatchObject({
      code: 'tampered',
    });
  });

  it('treats only keychain-unavailable as no stored session', () => {
    expect(
      isKeychainUnavailable(
        new SessionUnlockError(
          'keychain-unavailable',
          'The operating system credential store is unavailable.',
        ),
      ),
    ).toBe(true);
    for (const code of ['unavailable', 'tampered', 'expired'] as const) {
      expect(isKeychainUnavailable(new SessionUnlockError(code, 'x'))).toBe(false);
    }
    expect(isKeychainUnavailable(new Error('boom'))).toBe(false);
  });

  it('reports no stored session when the platform store has no entry', async () => {
    // On Linux this reaches the fixed fail-safe branch directly: a missing
    // secret-tool binary surfaces as keychain-unavailable and load maps it to
    // null. On Windows/macOS the same call exercises the not-found path.
    const account = sessionUnlockAccountFor({
      profileId: 'profile-absent',
      keyFile: join(tmpdir(), 'kavrix-absent.key'),
    });
    await expect(platformKeychainPort(account).load()).resolves.toBeNull();
  });
});
