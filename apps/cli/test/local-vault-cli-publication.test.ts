import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { Readable } from 'node:stream';
import { join } from 'node:path';

import * as keyFiles from '@kavrix/key-files';
import { PortableKeyFileError } from '@kavrix/key-files';
import { EncryptedVaultStoreError, FileLocalVaultStore } from '@kavrix/storage';
import { afterEach, describe, expect, it, vi } from 'vitest';

const aclMocks = vi.hoisted(() => ({
  set: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
  verifyDirectory: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
  verify: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
}));
const randomUuidState = vi.hoisted(() => ({
  next: undefined as string | undefined,
}));

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return {
    ...actual,
    randomUUID: (): ReturnType<typeof actual.randomUUID> =>
      (randomUuidState.next ?? actual.randomUUID()) as ReturnType<
        typeof actual.randomUUID
      >,
  };
});

vi.mock('@kavrix/key-files/windows-acl', () => ({
  setWindowsUserOnlyAcl: aclMocks.set,
  verifyWindowsDirectoryAcl: aclMocks.verifyDirectory,
  verifyWindowsUserOnlyAcl: aclMocks.verify,
}));

import { buildLocalCli, sanitizeJsonValue } from '../src/local-vault-cli.js';

const PASSPHRASE = 'local-vault-test-passphrase';
const RECOVERY_PASSPHRASE = 'local-vault-recovery-passphrase';
const NEW_PASSPHRASE = 'local-vault-new-passphrase';
const directories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  randomUuidState.next = undefined;
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function runWithStdin(args: readonly string[], input: string): Promise<void> {
  const original = process.stdin;
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: Readable.from([input]),
  });
  try {
    await buildLocalCli().parseAsync(['node', 'kavrix', ...args]);
  } finally {
    Object.defineProperty(process, 'stdin', {
      configurable: true,
      value: original,
    });
  }
}

async function paths(): Promise<
  Readonly<{ directory: string; data: string; key: string; anchor: string }>
> {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-local-publication-'));
  directories.push(directory);
  const key = join(directory, 'vault.key');
  return {
    directory,
    data: join(directory, 'vault.data'),
    key,
    anchor: `${key}.anchor`,
  };
}

function initArgs(data: string, key: string): string[] {
  return [
    'init',
    '--datastore',
    'file',
    '--data-file',
    data,
    '--key-file',
    key,
    '--passphrase-stdin',
  ];
}

describe('legacy local-vault publication boundaries', () => {
  it.each([
    ['--database', 'invalid database!'],
    ['--collection', 'invalid collection!'],
  ] as const)(
    'rejects invalid MongoDB routing from %s before reading protected input',
    async (option, value) => {
      const target = await paths();
      const failure = runWithStdin(
        ['init', '--datastore', 'mongodb', option, value, '--key-file', target.key],
        '',
      );

      await expect(failure).rejects.toThrow(/MongoDB .* name is invalid\./u);
      await expect(access(target.key)).rejects.toMatchObject({ code: 'ENOENT' });
    },
  );

  it('preserves a newly-created key after a later datastore create rejection', async () => {
    const target = await paths();
    vi.spyOn(FileLocalVaultStore.prototype, 'create').mockRejectedValueOnce(
      new EncryptedVaultStoreError('conflict', 'create rejected'),
    );

    const failure = runWithStdin(
      initArgs(target.data, target.key),
      `${PASSPHRASE}\n${PASSPHRASE}\n`,
    );
    await expect(failure).rejects.toMatchObject({
      name: 'LocalVaultPublicationError',
    });
    expect((await readFile(target.key)).byteLength).toBeGreaterThan(0);
    await expect(access(target.anchor)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(target.data)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('retains key and anchor when close fails after datastore create', async () => {
    const target = await paths();
    vi.spyOn(FileLocalVaultStore.prototype, 'close').mockRejectedValueOnce(
      new Error('injected close failure'),
    );

    const output: string[] = [];
    const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      return true;
    });
    try {
      const failure = runWithStdin(
        initArgs(target.data, target.key),
        `${PASSPHRASE}\n${PASSPHRASE}\n`,
      );
      await expect(failure).rejects.toMatchObject({
        name: 'LocalVaultPublicationError',
      });
      await expect(failure).rejects.toThrow(
        'The vault operation may have committed; protected local artifacts were retained.',
      );
    } finally {
      write.mockRestore();
    }
    expect(output.join('')).toBe('');
    const [data, key, anchor] = await Promise.all([
      readFile(target.data),
      readFile(target.key),
      readFile(target.anchor),
    ]);
    expect(data.byteLength).toBeGreaterThan(0);
    expect(key.byteLength).toBeGreaterThan(0);
    expect(anchor.byteLength).toBeGreaterThan(0);
  });

  it('preserves a key when its create publication becomes uncertain', async () => {
    const target = await paths();
    const originalWrite = keyFiles.writePortableKeyFile;
    vi.spyOn(keyFiles, 'writePortableKeyFile').mockImplementationOnce(
      async (...arguments_) => {
        await originalWrite(...arguments_);
        throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
      },
    );

    const failure = runWithStdin(
      initArgs(target.data, target.key),
      `${PASSPHRASE}\n${PASSPHRASE}\n`,
    );
    await expect(failure).rejects.toMatchObject({
      name: 'LocalVaultPublicationError',
    });
    expect((await readFile(target.key)).byteLength).toBeGreaterThan(0);
    await expect(access(target.anchor)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(target.data)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports a committed datastore deletion without deleting local artifacts', async () => {
    const target = await paths();
    await runWithStdin(
      initArgs(target.data, target.key),
      `${PASSPHRASE}\n${PASSPHRASE}\n`,
    );
    randomUuidState.next = '00000000-0000-4000-8000-000000000000';
    const originalDelete = FileLocalVaultStore.prototype.delete;
    vi.spyOn(FileLocalVaultStore.prototype, 'delete').mockImplementationOnce(
      async function (...arguments_) {
        await originalDelete.apply(this, arguments_);
        throw new Error('injected post-delete failure');
      },
    );

    const failure = runWithStdin(
      [
        'destroy',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
        '--confirmation-stdin',
      ],
      [PASSPHRASE, 'DESTROY default', 'DELETE REVISION 0 000000000000', ''].join('\n'),
    );
    await expect(failure).rejects.toMatchObject({
      name: 'LocalVaultPublicationError',
    });
    expect((await readFile(target.key)).byteLength).toBeGreaterThan(0);
    expect((await readFile(target.anchor)).byteLength).toBeGreaterThan(0);

    const reopened = await FileLocalVaultStore.open(target.data);
    try {
      await expect(reopened.get('default')).resolves.toBeNull();
    } finally {
      await reopened.close();
    }
  });

  it('preserves a recovery kit after a later datastore update rejection', async () => {
    const target = await paths();
    await runWithStdin(
      initArgs(target.data, target.key),
      `${PASSPHRASE}\n${PASSPHRASE}\n`,
    );
    const recoveryFile = join(target.directory, 'recovery.kit');
    const [beforeData, beforeKey, beforeAnchor] = await Promise.all([
      readFile(target.data),
      readFile(target.key),
      readFile(target.anchor),
    ]);
    vi.spyOn(FileLocalVaultStore.prototype, 'update').mockRejectedValueOnce(
      new EncryptedVaultStoreError('conflict', 'update rejected'),
    );

    const failure = runWithStdin(
      [
        'recovery',
        'create',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--recovery-file',
        recoveryFile,
        '--passphrase-stdin',
        '--recovery-passphrase-stdin',
      ],
      `${PASSPHRASE}\n${RECOVERY_PASSPHRASE}\n`,
    );
    await expect(failure).rejects.toMatchObject({
      name: 'LocalVaultPublicationError',
    });
    expect((await readFile(recoveryFile)).byteLength).toBeGreaterThan(0);
    const [afterData, afterKey, afterAnchor] = await Promise.all([
      readFile(target.data),
      readFile(target.key),
      readFile(target.anchor),
    ]);
    expect(afterData.equals(beforeData)).toBe(true);
    expect(afterKey.equals(beforeKey)).toBe(true);
    expect(afterAnchor.equals(beforeAnchor)).toBe(true);
  });

  it('preserves a recovery kit when its create publication becomes uncertain', async () => {
    const target = await paths();
    await runWithStdin(
      initArgs(target.data, target.key),
      `${PASSPHRASE}\n${PASSPHRASE}\n`,
    );
    const recoveryFile = join(target.directory, 'recovery-uncertain.kit');
    const originalWrite = keyFiles.writeRecoveryKitFile;
    vi.spyOn(keyFiles, 'writeRecoveryKitFile').mockImplementationOnce(
      async (...arguments_) => {
        await originalWrite(...arguments_);
        throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
      },
    );

    const failure = runWithStdin(
      [
        'recovery',
        'create',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--recovery-file',
        recoveryFile,
        '--passphrase-stdin',
        '--recovery-passphrase-stdin',
      ],
      `${PASSPHRASE}\n${RECOVERY_PASSPHRASE}\n`,
    );
    await expect(failure).rejects.toMatchObject({
      name: 'LocalVaultPublicationError',
    });
    expect((await readFile(recoveryFile)).byteLength).toBeGreaterThan(0);
  });

  it('preserves recovery-use outputs after a later datastore update rejection', async () => {
    const target = await paths();
    await runWithStdin(
      initArgs(target.data, target.key),
      `${PASSPHRASE}\n${PASSPHRASE}\n`,
    );
    const recoveryFile = join(target.directory, 'recovery.kit');
    await runWithStdin(
      [
        'recovery',
        'create',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--recovery-file',
        recoveryFile,
        '--passphrase-stdin',
        '--recovery-passphrase-stdin',
      ],
      `${PASSPHRASE}\n${RECOVERY_PASSPHRASE}\n`,
    );
    const outputRecoveryFile = join(target.directory, 'recovery-next.kit');
    const outputKeyFile = join(target.directory, 'recovered.key');
    const [beforeData, beforeKey, beforeAnchor, beforeRecovery] = await Promise.all([
      readFile(target.data),
      readFile(target.key),
      readFile(target.anchor),
      readFile(recoveryFile),
    ]);
    vi.spyOn(FileLocalVaultStore.prototype, 'update').mockRejectedValueOnce(
      new EncryptedVaultStoreError('conflict', 'update rejected'),
    );

    const failure = runWithStdin(
      [
        'recovery',
        'use',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--recovery-file',
        recoveryFile,
        '--output-recovery-file',
        outputRecoveryFile,
        '--output-key-file',
        outputKeyFile,
        '--recovery-passphrase-stdin',
        '--new-passphrase-stdin',
      ],
      `${RECOVERY_PASSPHRASE}\n${NEW_PASSPHRASE}\n${NEW_PASSPHRASE}\n`,
    );
    await expect(failure).rejects.toMatchObject({
      name: 'LocalVaultPublicationError',
    });
    expect((await readFile(outputRecoveryFile)).byteLength).toBeGreaterThan(0);
    expect((await readFile(outputKeyFile)).byteLength).toBeGreaterThan(0);
    await expect(access(`${outputKeyFile}.anchor`)).rejects.toMatchObject({
      code: 'ENOENT',
    });
    const [afterData, afterKey, afterAnchor, afterRecovery] = await Promise.all([
      readFile(target.data),
      readFile(target.key),
      readFile(target.anchor),
      readFile(recoveryFile),
    ]);
    expect(afterData.equals(beforeData)).toBe(true);
    expect(afterKey.equals(beforeKey)).toBe(true);
    expect(afterAnchor.equals(beforeAnchor)).toBe(true);
    expect(afterRecovery.equals(beforeRecovery)).toBe(true);
  });

  it('preserves a newly-created key when a later anchor copy fails', async () => {
    const target = await paths();
    await runWithStdin(
      initArgs(target.data, target.key),
      `${PASSPHRASE}\n${PASSPHRASE}\n`,
    );
    const destination = join(target.directory, 'copy.key');
    const beforeSource = await readFile(target.key);
    vi.spyOn(keyFiles, 'copyRevisionAnchor').mockRejectedValueOnce(
      new PortableKeyFileError('KEY_FILE_ALREADY_EXISTS'),
    );

    const failure = runWithStdin(
      [
        'key',
        'copy',
        '--source',
        target.key,
        '--destination',
        destination,
        '--passphrase-stdin',
        '--new-passphrase-stdin',
      ],
      `${PASSPHRASE}\n${NEW_PASSPHRASE}\n${NEW_PASSPHRASE}\n`,
    );
    await expect(failure).rejects.toMatchObject({
      name: 'LocalVaultPublicationError',
    });
    expect((await readFile(destination)).byteLength).toBeGreaterThan(0);
    await expect(access(`${destination}.anchor`)).rejects.toMatchObject({
      code: 'ENOENT',
    });
    const afterSource = await readFile(target.key);
    expect(afterSource.equals(beforeSource)).toBe(true);
    expect(keyFiles.copyRevisionAnchor).toHaveBeenCalledTimes(1);
  });

  it('preserves an overwritten key when a later anchor copy is ambiguous', async () => {
    const target = await paths();
    await runWithStdin(
      initArgs(target.data, target.key),
      `${PASSPHRASE}\n${PASSPHRASE}\n`,
    );
    const destination = join(target.directory, 'copy.key');
    await runWithStdin(
      [
        'key',
        'copy',
        '--source',
        target.key,
        '--destination',
        destination,
        '--passphrase-stdin',
        '--new-passphrase-stdin',
      ],
      `${PASSPHRASE}\n${RECOVERY_PASSPHRASE}\n${RECOVERY_PASSPHRASE}\n`,
    );
    const beforeSource = await readFile(target.key);
    const beforeDestination = await readFile(destination);
    const beforeAnchor = await readFile(`${destination}.anchor`);
    vi.spyOn(keyFiles, 'copyRevisionAnchor').mockRejectedValueOnce(
      new PortableKeyFileError('KEY_FILE_ALREADY_EXISTS'),
    );

    const failure = runWithStdin(
      [
        'key',
        'copy',
        '--source',
        target.key,
        '--destination',
        destination,
        '--overwrite',
        '--passphrase-stdin',
        '--new-passphrase-stdin',
      ],
      `${PASSPHRASE}\n${NEW_PASSPHRASE}\n${NEW_PASSPHRASE}\n`,
    );
    await expect(failure).rejects.toMatchObject({ name: 'LocalVaultPublicationError' });
    await expect(failure).rejects.toThrow(
      'The vault operation may have committed; protected local artifacts were retained.',
    );
    const [afterSource, afterDestination, afterAnchor] = await Promise.all([
      readFile(target.key),
      readFile(destination),
      readFile(`${destination}.anchor`),
    ]);
    expect(afterSource.equals(beforeSource)).toBe(true);
    expect(afterDestination.equals(beforeDestination)).toBe(false);
    expect(afterDestination.byteLength).toBeGreaterThan(0);
    expect(afterAnchor.equals(beforeAnchor)).toBe(true);
    expect(keyFiles.copyRevisionAnchor).toHaveBeenCalledTimes(1);
  });

  it('sanitizes hostile strings in JSON output without changing ordinary Unicode', async () => {
    const target = await paths();
    await runWithStdin(
      initArgs(target.data, target.key),
      `${PASSPHRASE}\n${PASSPHRASE}\n`,
    );
    // Control-character names are refused at input by validateCredentialName;
    // hostile-but-valid spellings must still round-trip byte-exact, and the
    // [CONTROL] rewrite itself is covered by the sanitizeJsonValue unit test.
    const name = 'hostile-name-"quoted"-Δ-日本語';
    await runWithStdin(
      [
        'put',
        name,
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
        '--value-stdin',
      ],
      `${PASSPHRASE}\nsecret\n`,
    );
    const output: string[] = [];
    const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      return true;
    });
    try {
      await runWithStdin(
        [
          'list',
          '--json',
          '--datastore',
          'file',
          '--data-file',
          target.data,
          '--key-file',
          target.key,
          '--passphrase-stdin',
        ],
        `${PASSPHRASE}\n`,
      );
    } finally {
      write.mockRestore();
    }
    const serialized = output.join('');
    expect(serialized).not.toContain('\u001b');
    expect(JSON.parse(serialized)).toEqual({
      names: ['hostile-name-"quoted"-Δ-日本語'],
      revision: 1,
    });
  });

  it('fails closed instead of dropping colliding sanitized object keys', () => {
    expect(() =>
      sanitizeJsonValue({
        'hostile\u001b': 'first',
        'hostile[CONTROL]': 'second',
      }),
    ).toThrow('JSON output contains colliding sanitized keys.');
    expect(sanitizeJsonValue({ nested: { 'inner\u0000': '\u001b[31mΔ' } })).toEqual({
      nested: { 'inner[CONTROL]': '[CONTROL][31mΔ' },
    });
  });
});
