import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { vaultProfileSchema } from '@kavrix/client';
import {
  encryptPayload,
  generateVaultRootKey,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  openSqliteVaultProfileStore,
  type SqliteSyncLocalStore,
} from '@kavrix/local-store';
import {
  deviceIdSchema,
  secretValueSchema,
  syncCursorSchema,
  vaultIdSchema,
  type VaultId,
} from '@kavrix/schemas';
import { describe, expect, it, beforeEach, afterEach } from 'vitest';

import { openProductionEnvironment } from '../src/production/environment.js';
import {
  executeProductionAddField,
  executeProductionAddNote,
  executeProductionArchiveEntity,
  executeProductionArchiveField,
  executeProductionArchiveNote,
  executeProductionCreateCredential,
  executeProductionCreateGroup,
  executeProductionRemoveField,
  executeProductionRemoveNote,
  executeProductionRestoreEntity,
  executeProductionRestoreField,
  executeProductionRestoreNote,
  executeProductionSetField,
  executeProductionUpdateField,
  executeProductionUpdateNote,
} from '../src/production/mutations.js';
import { executeProductionShow } from '../src/production/show.js';
import { executeProductionCopy } from '../src/production/copy.js';
import { executeProductionReveal } from '../src/production/reveal.js';
import { executeProductionGet } from '../src/production/get.js';
import { executeProductionSync } from '../src/production/sync.js';
import { resolveCliDataPaths } from '../src/production/paths.js';
import { ensureDataDirectory } from '../src/production/runtime-adapters.js';
import { createSecretBackend } from '../src/production/secret-backend.js';

async function seedVaultRecordInStore(
  store: SqliteSyncLocalStore,
  vaultId: VaultId,
  rootKey: VaultRootKey,
): Promise<void> {
  const { createPortableKeySlot, generatePortableKey } = await import('@kavrix/crypto');
  const {
    associatedDataSchema,
    changeRecordSchema,
    contentHashForRecord,
    keySlotIdSchema,
    vaultRecordSchema,
  } = await import('@kavrix/schemas');

  const timestamp = '2026-08-10T00:00:00.000Z';
  const portableKey = generatePortableKey();
  const slot = await createPortableKeySlot(
    {
      vaultId,
      slotId: keySlotIdSchema.parse('slot.test001'),
      schemaVersion: 1,
      keyVersion: 1,
      createdAt: timestamp,
    },
    portableKey,
    rootKey,
  );

  const preferencesContext = associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId,
    entityType: 'vault-preferences',
    entityId: vaultId,
    purpose: 'vault-preferences',
  });

  const encryptedPreferences = await encryptPayload(
    new TextEncoder().encode(
      JSON.stringify({
        productLabel: 'Kavrix',
        executableName: 'creds',
        clipboardClearSeconds: 30,
        revealHideSeconds: 30,
        historyRetentionDays: 90,
        telemetryEnabled: false,
      }),
    ),
    rootKey,
    preferencesContext,
  );

  const vaultRecord = vaultRecordSchema.parse({
    id: vaultId,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [slot],
    currentKeyVersion: 1,
    revision: 1,
    encryptedPreferences,
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  const change = changeRecordSchema.parse({
    id: 'change.vault.001',
    vaultId,
    serverSequence: 1,
    entityType: 'vault',
    entityId: vaultId,
    recordRevision: 1,
    operation: 'upsert',
    ciphertextHash: contentHashForRecord(vaultRecord),
    createdAt: timestamp,
  });

  await store.applyPullPage({
    vaultId,
    changes: [{ change, record: vaultRecord }],
    cursor: syncCursorSchema.parse({
      vaultId,
      serverSequence: 1,
      highestSeenVaultRevision: 1,
    }),
  });
}

describe('production CLI mutation adapters', () => {
  let tempHome: string;

  beforeEach(async () => {
    tempHome = join(
      tmpdir(),
      `kavrix-prod-mutations-test-${Math.random().toString(36).slice(2)}`,
    );
    await ensureDataDirectory(tempHome);
    const paths = resolveCliDataPaths({ CREDS_HOME: tempHome });
    const profileStore = await openSqliteVaultProfileStore({
      path: paths.profileStore,
    });
    const profile = vaultProfileSchema.parse({
      version: 1,
      serverUrl: 'https://vault.example/',
      vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
      deviceId: deviceIdSchema.parse('device.test00000000000000001'),
      deviceLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        keySlotId: 'slot.device.001',
      },
      sessionLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        purpose: 'api-session',
      },
    });
    await profileStore.store(profile);
    await profileStore.close();
  });

  afterEach(async () => {
    try {
      await rm(tempHome, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on temp teardown
    }
  });

  it('creates group and credential, sets field, archives and restores entity cleanly', async () => {
    const rootKey = generateVaultRootKey();
    const vaultId = vaultIdSchema.parse('vault.test000000000000000001');

    const mockSecretsInput = {
      read: () => Promise.reject(new Error('secrets unneeded')),
      readBatch: () => Promise.reject(new Error('secrets unneeded')),
      clear: () => Promise.resolve(),
    };

    const paths = resolveCliDataPaths({ CREDS_HOME: tempHome });
    const backend = await createSecretBackend(paths, mockSecretsInput, {
      kind: 'native',
    });
    const environment = await openProductionEnvironment(paths, backend);
    const profile = vaultProfileSchema.parse({
      version: 1,
      serverUrl: 'https://vault.example/',
      vaultId,
      deviceId: deviceIdSchema.parse('device.test00000000000000001'),
      deviceLocator: {
        version: 1,
        vaultId,
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        keySlotId: 'slot.device.001',
      },
      sessionLocator: {
        version: 1,
        vaultId,
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        purpose: 'api-session',
      },
    });
    const store = await environment.openSyncStore(profile);

    await seedVaultRecordInStore(store, vaultId, rootKey);

    const mutationOptions = {
      source: store,
      queue: store,
      vaultId,
      rootKey,
    };

    try {
      // 1. Create Group
      const groupResult = await executeProductionCreateGroup(mutationOptions, {
        name: 'Infrastructure',
        description: 'Cloud and infra credentials',
      });
      expect(groupResult.name).toBe('Infrastructure');

      // 2. Create Credential
      const credResult = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: 'Infrastructure',
        title: 'AWS Production Root',
      });
      expect(credResult.title).toBe('AWS Production Root');

      // 3. Set Field
      const secretBytes = new TextEncoder().encode('super-secret-password-123');
      const setFieldResult = await executeProductionSetField(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        fieldKey: 'password',
        value: secretBytes,
      });
      expect(setFieldResult.credentialId).toBe(credResult.credentialId);
      expect(secretBytes.every((b) => b === 0)).toBe(true);

      // 4. Add Field
      await executeProductionAddField(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        fieldKey: 'api_token',
        fieldType: 'api-key',
        label: 'API Token',
        sensitive: true,
      });

      // 5. Update Field
      await executeProductionUpdateField(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        fieldKey: 'api_token',
        label: 'Production API Token',
      });

      // 6. Archive Field
      await executeProductionArchiveField(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        fieldKey: 'password',
      });

      // 7. Restore Field
      await executeProductionRestoreField(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        fieldKey: 'password',
      });

      // 8. Remove Field
      await executeProductionRemoveField(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        fieldKey: 'api_token',
      });

      // 8.5. Execute Production Show
      const showResult = await executeProductionShow(
        {
          source: store,
          vaultId: mutationOptions.vaultId,
          rootKey,
        },
        'Infrastructure',
        'AWS Production Root',
      );
      expect(showResult.item.title).toBe('AWS Production Root');
      expect(showResult.group.name).toBe('Infrastructure');

      // 8.6. Execute Production Copy
      const copyReceipt = await executeProductionCopy(
        {
          source: store,
          vaultId: mutationOptions.vaultId,
          rootKey,
          clipboard: environment.clipboard,
        },
        'Infrastructure',
        'AWS Production Root',
        'password',
      );
      expect(copyReceipt.label).toBe('Password');

      // 8.7. Execute Production Reveal
      const revealResult = await executeProductionReveal(
        {
          source: store,
          vaultId: mutationOptions.vaultId,
          rootKey,
        },
        'Infrastructure',
        'AWS Production Root',
        'password',
      );
      expect(revealResult.fieldLabel).toBe('Password');
      expect(revealResult.value).toBe('MyInitialSecret123!');

      // 8.8. Execute Production Get (redacted & revealed)
      const getRedacted = await executeProductionGet(
        {
          source: store,
          vaultId: mutationOptions.vaultId,
          rootKey,
        },
        'Infrastructure',
        'AWS Production Root',
        'password',
      );
      expect(getRedacted.value).toBe('[REDACTED]');

      const getRevealed = await executeProductionGet(
        {
          source: store,
          vaultId: mutationOptions.vaultId,
          rootKey,
        },
        'Infrastructure',
        'AWS Production Root',
        'password',
        { reveal: true },
      );
      expect(getRevealed.value).toBe('MyInitialSecret123!');

      // 8.9. Execute Production Sync
      const syncStatus: CliStatus = await executeProductionSync({
        environment: paths.env,
        secrets: {
          read: () => Promise.reject(new Error('unexpected secrets read')),
        },
        backendPolicy: { kind: 'unprotected' },
      });
      expect(syncStatus.state).toBe('unlocked');

      // 9. Add Note
      const noteAddResult = await executeProductionAddNote(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        title: 'Emergency Rotation Procedure',
        content: secretValueSchema.parse('Steps to rotate root credentials'),
        isSensitive: true,
      });
      expect(noteAddResult.title).toBe('Emergency Rotation Procedure');

      // 10. Update Note
      await executeProductionUpdateNote(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        noteQuery: 'Emergency Rotation Procedure',
        title: 'Updated Rotation SOP',
      });

      // 11. Archive Note
      await executeProductionArchiveNote(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        noteQuery: 'Updated Rotation SOP',
      });

      // 12. Restore Note
      await executeProductionRestoreNote(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        noteQuery: 'Updated Rotation SOP',
      });

      // 13. Remove Note
      await executeProductionRemoveNote(mutationOptions, {
        groupQuery: 'Infrastructure',
        credentialQuery: 'AWS Production Root',
        noteQuery: 'Updated Rotation SOP',
      });

      // 9. Archive Credential
      await expect(
        executeProductionArchiveEntity(mutationOptions, {
          groupQuery: 'Infrastructure',
          credentialQuery: 'AWS Production Root',
        }),
      ).resolves.toBeUndefined();

      // 10. Restore Credential
      await expect(
        executeProductionRestoreEntity(mutationOptions, {
          groupQuery: 'Infrastructure',
          credentialQuery: credResult.credentialId,
        }),
      ).resolves.toBeUndefined();
    } finally {
      zeroize(rootKey);
      await environment.close();
      await backend.close();
    }
  });

  it('lists, renames, and deletes credentials through catalog read/mutation paths', async () => {
    const rootKey = generateVaultRootKey();
    const vaultId = vaultIdSchema.parse('vault.test000000000000000001');

    const mockSecretsInput = {
      read: () => Promise.reject(new Error('secrets unneeded')),
      readBatch: () => Promise.reject(new Error('secrets unneeded')),
      clear: () => Promise.resolve(),
    };

    const paths = resolveCliDataPaths({ CREDS_HOME: tempHome });
    const backend = await createSecretBackend(paths, mockSecretsInput, {
      kind: 'native',
    });
    const environment = await openProductionEnvironment(paths, backend);
    const profile = vaultProfileSchema.parse({
      version: 1,
      serverUrl: 'https://vault.example/',
      vaultId,
      deviceId: deviceIdSchema.parse('device.test00000000000000001'),
      deviceLocator: {
        version: 1,
        vaultId,
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        keySlotId: 'slot.device.001',
      },
      sessionLocator: {
        version: 1,
        vaultId,
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        purpose: 'api-session',
      },
    });
    const store = await environment.openSyncStore(profile);

    await seedVaultRecordInStore(store, vaultId, rootKey);

    const mutationOptions = {
      source: store,
      queue: store,
      vaultId,
      rootKey,
    };

    const { VaultMutationService, VaultReadSession } = await import('@kavrix/client');
    const { createDefaultMutationDependencies } =
      await import('../src/production/mutations.js');
    const { recordRevisionSchema } = await import('@kavrix/schemas');

    try {
      await executeProductionCreateGroup(mutationOptions, {
        name: 'Infrastructure',
      });
      const credResult = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: 'Infrastructure',
        title: 'AWS Production Root',
      });

      const readSession = new VaultReadSession(store, vaultId);
      await readSession.unlock(rootKey);
      let listed: Awaited<ReturnType<typeof readSession.listItems>>;
      let found: Awaited<ReturnType<typeof readSession.show>>;
      try {
        listed = await readSession.listItems('Infrastructure');
        expect(listed.map((item) => item.id)).toEqual([credResult.credentialId]);
        expect(listed.map((item) => item.title)).toEqual(['AWS Production Root']);
        found = await readSession.show('Infrastructure', 'AWS Production Root');
      } finally {
        readSession.lock();
      }

      const service = new VaultMutationService(
        store,
        store,
        vaultId,
        rootKey,
        createDefaultMutationDependencies(),
      );
      await service.updateItem(found.group.id, {
        ...found.item,
        title: 'AWS Production Root (Primary)',
      });

      const renamedSession = new VaultReadSession(store, vaultId);
      await renamedSession.unlock(rootKey);
      let renamedFound: Awaited<ReturnType<typeof renamedSession.show>>;
      try {
        renamedFound = await renamedSession.show(
          'Infrastructure',
          'AWS Production Root (Primary)',
        );
      } finally {
        renamedSession.lock();
      }
      expect(renamedFound.item.title).toBe('AWS Production Root (Primary)');

      const state = await store.getCurrentItem(vaultId, credResult.credentialId);
      expect(state?.state).toBe('active');
      if (state?.state !== 'active') {
        throw new Error('Credential item is not active or found');
      }
      const deleteService = new VaultMutationService(
        store,
        store,
        vaultId,
        rootKey,
        createDefaultMutationDependencies(),
      );
      await deleteService.deleteItem(
        found.group.id,
        credResult.credentialId,
        recordRevisionSchema.parse(state.record.recordRevision),
      );

      const afterDelete = await store.getCurrentItem(vaultId, credResult.credentialId);
      expect(afterDelete?.state).toBe('deleted');
    } finally {
      zeroize(rootKey);
      await environment.close();
      await backend.close();
    }
  });
});
