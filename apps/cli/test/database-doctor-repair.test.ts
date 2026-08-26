import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { FileEncryptedDatabaseStore } from '@kavrix/storage';

import { DatabaseSession } from '../src/database-session.js';
import { createSecureTestDirectory as scratch } from '../../../packages/key-files/test/secure-temporary-directory.js';

const PASSPHRASE = Buffer.from('correct horse battery staple', 'utf8');

const directories: string[] = [];

afterEach(async () => {
  const pending = directories.splice(0);
  for (const directory of pending) {
    await rm(directory, { force: true, recursive: true });
  }
});

describe('database anchor repair', () => {
  it('refuses a restored older snapshot and heals only with explicit acceptance', async () => {
    const directory = await scratch(join(tmpdir(), 'kavrix-anchor-repair-'));
    directories.push(directory);
    const dataFile = join(directory, 'db.kavrix-db');
    const keyFile = join(directory, 'owner.kavrix-db-key');

    const first = await FileEncryptedDatabaseStore.open(dataFile);
    try {
      await DatabaseSession.initialize({
        store: first,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'repair',
      });
      const session = await DatabaseSession.open({
        store: first,
        keyFile,
        passphrase: PASSPHRASE,
      });
      try {
        await session.createVault('main');
      } finally {
        await session.close();
      }
    } finally {
      await first.close();
    }

    // Capture the one-vault snapshot, then advance the live database with a
    // second vault so the trusted anchor moves ahead of it.
    const olderSnapshot = await readFile(dataFile);
    const second = await FileEncryptedDatabaseStore.open(dataFile);
    try {
      const session = await DatabaseSession.open({
        store: second,
        keyFile,
        passphrase: PASSPHRASE,
      });
      try {
        await session.createVault('extra');
      } finally {
        await session.close();
      }
    } finally {
      await second.close();
    }

    // Restore the older snapshot behind the anchor's back.
    await writeFile(dataFile, olderSnapshot);

    const rejectStore = await FileEncryptedDatabaseStore.open(dataFile);
    try {
      await expect(
        DatabaseSession.open({ store: rejectStore, keyFile, passphrase: PASSPHRASE }),
      ).rejects.toMatchObject({ code: 'rollback' });
    } finally {
      await rejectStore.close();
    }

    // Strict opens keep refusing; the bounded repair requires explicit
    // consent and then re-anchors after fully authenticating every document.
    const repaired = await DatabaseSession.openWithSecret({
      store: await FileEncryptedDatabaseStore.open(dataFile),
      keyFile,
      passphrase: PASSPHRASE,
      readPassphrase: () => Promise.resolve(PASSPHRASE),
      acceptCurrentAnchor: true,
    });
    try {
      expect(repaired.acceptedCurrentAnchor).toBe(true);
      expect(repaired.status().vaultCount).toBe(1);
    } finally {
      await repaired.close();
    }

    const verified = await DatabaseSession.open({
      store: await FileEncryptedDatabaseStore.open(dataFile),
      keyFile,
      passphrase: PASSPHRASE,
    });
    try {
      expect(verified.listVaults().map((entry) => entry.label)).toContain('main');
    } finally {
      await verified.close();
    }
  });
});
