import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  passphraseFrame,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

const PASSPHRASE = `${EXEC_PASSPHRASE}\n`;
const BACKUP_PASSPHRASE = 'backup-passphrase-16b';
const BACKUP_FRAMES = `${BACKUP_PASSPHRASE}\n${BACKUP_PASSPHRASE}\n`;

let container: ExecutionFixture;
let backupDirectory: string;

beforeAll(async () => {
  container = await createExecutionFixture({
    'github/token': 'backup-canary-secret-value',
  });
  backupDirectory = await mkdtemp(join(tmpdir(), 'kavrix-backup-'));
});

afterAll(async () => {
  await destroyFixture(container);
  await rm(backupDirectory, { force: true, recursive: true });
});

describe('kavrix backup (file datastore, database container)', () => {
  it('create refuses a MongoDB-only surface and an unbound profile', async () => {
    const noProfile = await runCli(
      [
        'backup',
        'create',
        '--file',
        join(backupDirectory, 'x.json'),
        '--passphrase-stdin',
      ],
      '',
    );
    // No registry exists under the process default config directory.
    expect(noProfile.exitCode).toBe(14);

    const unbound = await mkdtemp(join(tmpdir(), 'kavrix-backup-unbound-'));
    try {
      const add = await runCli(
        [
          'db',
          'profile',
          'add',
          'unbound',
          '--datastore',
          'file',
          '--data-file',
          join(unbound, 'db.kavrix'),
          '--key-file',
          join(unbound, 'owner.key'),
          '--profile-config-dir',
          unbound,
          '--json',
        ],
        '',
      );
      expect(add.exitCode).toBe(0);
      const created = await runCli(
        [
          'backup',
          'create',
          '--file',
          join(unbound, 'x.json'),
          '--profile',
          'unbound',
          '--profile-config-dir',
          unbound,
          '--passphrase-stdin',
        ],
        BACKUP_FRAMES,
      );
      expect(created.exitCode).toBe(14);
      expect(created.stderr).toContain('not bound to a database');
    } finally {
      await rm(unbound, { force: true, recursive: true });
    }
  });

  it('create → verify → restore round-trips a working database', async () => {
    const archivePath = join(backupDirectory, 'database.backup.json');
    const restoredDataFile = join(backupDirectory, 'restored.kavrix');

    const create = await runCli(
      [
        'backup',
        'create',
        '--file',
        archivePath,
        ...container.routingArgs,
        '--passphrase-stdin',
        '--json',
      ],
      BACKUP_FRAMES,
    );
    expect(create.exitCode).toBe(0);
    const createdEnvelope = JSON.parse(create.stdout) as {
      created: boolean;
      databaseId: string;
      plaintextBytes: number;
    };
    expect(createdEnvelope.created).toBe(true);
    expect(typeof createdEnvelope.databaseId).toBe('string');
    expect(createdEnvelope.databaseId).toContain('db_');
    expect(createdEnvelope.plaintextBytes).toBeGreaterThan(0);

    // Refuses to clobber without --overwrite.
    const clobber = await runCli(
      [
        'backup',
        'create',
        '--file',
        archivePath,
        ...container.routingArgs,
        '--passphrase-stdin',
      ],
      BACKUP_FRAMES,
    );
    expect(clobber.exitCode).toBe(1);
    expect(clobber.stderr).toContain('--overwrite');

    const verify = await runCli(
      ['backup', 'verify', '--file', archivePath, '--passphrase-stdin', '--json'],
      `${BACKUP_PASSPHRASE}\n`,
    );
    expect(verify.exitCode).toBe(0);
    const verifiedEnvelope = JSON.parse(verify.stdout) as {
      valid: boolean;
      databaseId: string;
    };
    expect(verifiedEnvelope.valid).toBe(true);
    expect(verifiedEnvelope.databaseId).toBe(createdEnvelope.databaseId);

    const wrongPassphrase = await runCli(
      ['backup', 'verify', '--file', archivePath, '--passphrase-stdin', '--json'],
      'wrong-passphrase-16b\n',
    );
    expect(wrongPassphrase.exitCode).toBe(10);
    // --json failures keep the machine envelope on stdout with no human
    // stderr duplicate.
    const wrongEnvelope = JSON.parse(wrongPassphrase.stdout) as {
      error: { code: string; message: string };
    };
    expect(wrongEnvelope.error.code).toBe('AUTHENTICATION_FAILED');
    expect(wrongEnvelope.error.message).toContain('Backup authentication failed');
    expect(wrongPassphrase.stderr).toBe('');

    const restore = await runCli(
      [
        'backup',
        'restore',
        '--file',
        archivePath,
        '--data-file',
        restoredDataFile,
        '--passphrase-stdin',
        '--json',
      ],
      `${BACKUP_PASSPHRASE}\n`,
    );
    expect(restore.exitCode).toBe(0);
    const restoredEnvelope = JSON.parse(restore.stdout) as {
      restored: boolean;
      databaseId: string;
    };
    expect(restoredEnvelope.restored).toBe(true);
    expect(restoredEnvelope.databaseId).toBe(createdEnvelope.databaseId);

    // The restored file is the same database: a profile bound to it
    // authenticates against the original owner key.
    const add = await runCli(
      [
        'db',
        'profile',
        'add',
        'restored',
        '--datastore',
        'file',
        '--data-file',
        restoredDataFile,
        '--key-file',
        container.keyFile,
        '--profile-config-dir',
        join(backupDirectory, 'restored-profiles'),
        '--json',
      ],
      '',
    );
    expect(add.exitCode).toBe(0);
    const status = await runCli(
      [
        'db',
        'status',
        '--profile',
        'restored',
        '--profile-config-dir',
        join(backupDirectory, 'restored-profiles'),
        '--passphrase-stdin',
        '--json',
      ],
      PASSPHRASE,
    );
    expect(status.exitCode).toBe(0);
    const statusEnvelope = JSON.parse(status.stdout) as {
      databaseId?: string;
      database?: { databaseId?: string };
    };
    expect(statusEnvelope.databaseId ?? statusEnvelope.database?.databaseId ?? '').toBe(
      createdEnvelope.databaseId,
    );
  });

  it('verify fails closed on a tampered archive body', async () => {
    const archivePath = join(backupDirectory, 'tampered.backup.json');
    const create = await runCli(
      [
        'backup',
        'create',
        '--file',
        archivePath,
        ...container.routingArgs,
        '--passphrase-stdin',
      ],
      BACKUP_FRAMES,
    );
    expect(create.exitCode).toBe(0);

    const { readFile, writeFile } = await import('node:fs/promises');
    const raw = await readFile(archivePath, 'utf8');
    const parsed = JSON.parse(raw) as { ciphertext: string };
    const bytes = Buffer.from(parsed.ciphertext, 'base64url');
    bytes[0] = (bytes[0] ?? 0) ^ 0x20;
    parsed.ciphertext = bytes.toString('base64url');
    await writeFile(archivePath, JSON.stringify(parsed), 'utf8');

    const verify = await runCli(
      ['backup', 'verify', '--file', archivePath, '--passphrase-stdin'],
      `${BACKUP_PASSPHRASE}\n`,
    );
    expect(verify.exitCode).toBe(10);
    expect(verify.stderr).toContain('Backup authentication failed');
  });

  it('rejects non-backup files as integrity failures before any key work', async () => {
    // Written through the protected writer so the file passes platform
    // permission checks; only its content is hostile.
    const junkPath = join(backupDirectory, 'junk.backup.json');
    await rm(junkPath, { force: true });
    const { writeSecureStreamFile } = await import('@kavrix/key-files');
    const junk = new TextEncoder().encode('{"hello":"world"}');
    await writeSecureStreamFile(
      junkPath,
      (async function* () {
        yield junk;
      })(),
      junk.byteLength + 1,
    );
    const verify = await runCli(
      ['backup', 'verify', '--file', junkPath, '--passphrase-stdin'],
      passphraseFrame(),
    );
    expect(verify.exitCode).toBe(16);
    expect(verify.stderr).toContain('not a valid Kavrix database backup');
  });
});
