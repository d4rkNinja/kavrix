import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { PortableKeyFileError } from '../src/errors.js';
import { SealedSecretStore, sealedEntryFactory } from '../src/sealed-secret-store.js';

const SERVICE = 'dev.kavrix.credentials';
const ACCOUNT = 'v1:api-session:vault-1:device-1';
const SECRET = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

// Argon2id at production parameters dominates the runtime of every case here.
const TIMEOUT_MS = 60_000;

let directory: string;

function storeAt(
  path: string,
  passphrase = 'correct horse battery staple',
): SealedSecretStore {
  return new SealedSecretStore({
    directory: path,
    passphrase: () => Promise.resolve(Buffer.from(passphrase, 'utf8')),
  });
}

/**
 * Narrowing with an assertion is banned in this repository; each case creates
 * exactly one sealed file first, so a missing one is a test bug and a hard
 * failure is the honest signal.
 */
function requireSealFile(files: readonly string[]): string {
  const sealed = files.find((file) => file.endsWith('.seal'));
  if (sealed === undefined) {
    throw new Error('Expected a .seal file to exist before reading it.');
  }
  return sealed;
}

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-sealed-'));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

describe('SealedSecretStore', () => {
  it(
    'round-trips a secret through a fresh process-equivalent instance',
    async () => {
      const writer = storeAt(directory);
      await writer.store(SERVICE, ACCOUNT, SECRET);
      await writer.close();

      const reader = storeAt(directory);
      try {
        expect(await reader.load(SERVICE, ACCOUNT)).toStrictEqual(SECRET);
      } finally {
        await reader.close();
      }
    },
    TIMEOUT_MS,
  );

  it(
    'never writes the plaintext secret to disk',
    async () => {
      const store = storeAt(directory);
      try {
        await store.store(SERVICE, ACCOUNT, SECRET);
      } finally {
        await store.close();
      }

      const files = await readdir(directory);
      expect(files.length).toBeGreaterThan(0);
      for (const file of files) {
        const bytes = await readFile(join(directory, file));
        expect(bytes.includes(Buffer.from(SECRET))).toBe(false);
      }
    },
    TIMEOUT_MS,
  );

  it(
    'rejects a secret sealed under a different passphrase',
    async () => {
      const writer = storeAt(directory, 'first passphrase');
      await writer.store(SERVICE, ACCOUNT, SECRET);
      await writer.close();

      const attacker = storeAt(directory, 'second passphrase');
      try {
        await expect(attacker.load(SERVICE, ACCOUNT)).rejects.toThrow(
          PortableKeyFileError,
        );
      } finally {
        await attacker.close();
      }
    },
    TIMEOUT_MS,
  );

  it(
    'refuses to open an envelope moved to another account',
    async () => {
      const store = storeAt(directory);
      try {
        await store.store(SERVICE, ACCOUNT, SECRET);
        const other = 'v1:device-unlock:vault-1:device-1:slot-1';
        const sealed = requireSealFile(await readdir(directory));

        // Transplant the envelope onto the filename the other account reads.
        const envelope = await readFile(join(directory, sealed));
        const factory = sealedEntryFactory(store);
        await factory(SERVICE, other).setSecret(SECRET);
        const otherFiles = (await readdir(directory)).filter(
          (file) => file.endsWith('.seal') && file !== sealed,
        );
        expect(otherFiles).toHaveLength(1);
        await writeFile(join(directory, requireSealFile(otherFiles)), envelope);

        await expect(store.load(SERVICE, other)).rejects.toThrow(PortableKeyFileError);
      } finally {
        await store.close();
      }
    },
    TIMEOUT_MS,
  );

  it(
    'detects a flipped ciphertext byte',
    async () => {
      const store = storeAt(directory);
      try {
        await store.store(SERVICE, ACCOUNT, SECRET);
        const path = join(directory, requireSealFile(await readdir(directory)));
        const bytes = await readFile(path);
        expect(bytes.length).toBeGreaterThan(0);
        const last = bytes.length - 1;
        bytes.writeUInt8(bytes.readUInt8(last) ^ 0x01, last);
        await writeFile(path, bytes);

        await expect(store.load(SERVICE, ACCOUNT)).rejects.toThrow(
          PortableKeyFileError,
        );
      } finally {
        await store.close();
      }
    },
    TIMEOUT_MS,
  );

  it('reports a missing entry as null rather than failing', async () => {
    const store = storeAt(directory);
    try {
      expect(await store.load(SERVICE, ACCOUNT)).toBeNull();
    } finally {
      await store.close();
    }
  });

  it(
    'deletes an entry idempotently',
    async () => {
      const store = storeAt(directory);
      try {
        await store.store(SERVICE, ACCOUNT, SECRET);
        await store.delete(SERVICE, ACCOUNT);
        await store.delete(SERVICE, ACCOUNT);
        expect(await store.load(SERVICE, ACCOUNT)).toBeNull();
      } finally {
        await store.close();
      }
    },
    TIMEOUT_MS,
  );

  it(
    'keeps distinct accounts cryptographically separated',
    async () => {
      const store = storeAt(directory);
      const second = Uint8Array.from({ length: 32 }, () => 0xab);
      try {
        await store.store(SERVICE, ACCOUNT, SECRET);
        await store.store(SERVICE, 'v1:api-session:vault-2:device-2', second);
        expect(await store.load(SERVICE, ACCOUNT)).toStrictEqual(SECRET);
        expect(
          await store.load(SERVICE, 'v1:api-session:vault-2:device-2'),
        ).toStrictEqual(second);
      } finally {
        await store.close();
      }
    },
    TIMEOUT_MS,
  );
});
