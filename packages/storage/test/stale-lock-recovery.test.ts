import { lstat, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { databaseIdSchema } from '@kavrix/schemas';

const aclMocks = vi.hoisted(() => ({
  set: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
  verifyDirectory: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
  verify: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
}));

vi.mock('@kavrix/key-files/windows-acl', () => ({
  setWindowsUserOnlyAcl: aclMocks.set,
  verifyWindowsDirectoryAcl: aclMocks.verifyDirectory,
  verifyWindowsUserOnlyAcl: aclMocks.verify,
}));

import {
  FileEncryptedDatabaseStore,
  FileLocalVaultError,
  FileLocalVaultStore,
} from '../src/index.js';

const temporaryDirectories: string[] = [];

async function scratch(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-stale-lock-'));
  temporaryDirectories.push(directory);
  return directory;
}

/** A PID that no live process uses; negative values are never addressable. */
function deadPid(): number {
  // pid 0 addresses the process group; -1 is never a valid owner.
  return -1;
}

function localLockPayload(pid: number): string {
  return JSON.stringify({ format: 'kavrix-local-vault-lock', version: 1, pid });
}

function databaseLockPayload(pid: number): string {
  return JSON.stringify({ format: 'kavrix-database-lock', version: 1, pid });
}

afterEach(async () => {
  vi.clearAllMocks();
  const directories = temporaryDirectories.splice(0);
  for (const directory of directories) {
    await rm(directory, { force: true, recursive: true });
  }
});

describe('stale lock recovery', () => {
  it('reclaims a local vault lock left by a provably dead process', async () => {
    const target = join(await scratch(), 'vault.data');
    const first = await FileLocalVaultStore.open(target);
    await first.close();

    await writeFile(`${target}.lock`, localLockPayload(deadPid()), 'utf8');
    const reopened = await FileLocalVaultStore.open(target);
    await expect(reopened.ping()).resolves.toBeUndefined();
    await reopened.close();
    await expect(lstat(`${target}.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('keeps refusing while a local vault lock records a live owner', async () => {
    const target = join(await scratch(), 'vault.data');
    const holder = await FileLocalVaultStore.open(target);
    await expect(FileLocalVaultStore.open(target)).rejects.toMatchObject({
      code: 'busy',
    });
    await holder.close();
  });

  it('never reclaims a hostile local vault lock shape', async () => {
    const target = join(await scratch(), 'vault.data');
    const first = await FileLocalVaultStore.open(target);
    await first.close();
    // Correct metadata but a live PID (this process) must remain busy.
    await writeFile(`${target}.lock`, localLockPayload(process.pid), 'utf8');
    await expect(FileLocalVaultStore.open(target)).rejects.toBeInstanceOf(
      FileLocalVaultError,
    );
    await expect(FileLocalVaultStore.open(target)).rejects.toMatchObject({
      code: 'busy',
    });
  });

  it('reclaims an encrypted-database lock left by a provably dead process', async () => {
    const target = join(await scratch(), 'database.kavrix-db');
    const first = await FileEncryptedDatabaseStore.open(target);
    await first.close();

    await writeFile(`${target}.lock`, databaseLockPayload(deadPid()), 'utf8');
    const reopened = await FileEncryptedDatabaseStore.open(target);
    await expect(
      reopened.listVaults(databaseIdSchema.parse('db_any')),
    ).resolves.toEqual([]);
    await reopened.close();
    await expect(lstat(`${target}.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('keeps refusing while an encrypted-database lock records a live owner', async () => {
    const target = join(await scratch(), 'database.kavrix-db');
    const holder = await FileEncryptedDatabaseStore.open(target);
    await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
      code: 'busy',
    });
    await holder.close();
  });

  it('refuses oversized or malformed lock metadata instead of reclaiming', async () => {
    const target = join(await scratch(), 'vault.data');
    const first = await FileLocalVaultStore.open(target);
    await first.close();
    await writeFile(
      `${target}.lock`,
      `{"pid":${String(deadPid())},${'x'.repeat(400)}}`,
    );
    await expect(FileLocalVaultStore.open(target)).rejects.toMatchObject({
      code: 'busy',
    });
  });
});
