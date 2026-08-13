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
import { openSqliteVaultProfileStore } from '@kavrix/local-store';
import {
  associatedDataSchema,
  changeRecordSchema,
  contentHashForRecord,
  deviceIdSchema,
  vaultIdSchema,
  vaultPreferencesSchema,
  vaultRecordSchema,
  type VaultId,
} from '@kavrix/schemas';
import { describe, expect, it, beforeEach, afterEach } from 'vitest';

import { openProductionEnvironment } from '../src/production/environment.js';
import {
  executeProductionArchiveEntity,
  executeProductionCreateCredential,
  executeProductionCreateGroup,
  executeProductionRestoreEntity,
  executeProductionSetField,
} from '../src/production/mutations.js';
import { resolveCliDataPaths } from '../src/production/paths.js';
import { ensureDataDirectory } from '../src/production/runtime-adapters.js';
import { createSecretBackend } from '../src/production/secret-backend.js';

async function seedVaultRecordInStore(
  store: any,
  vaultId: VaultId,
  rootKey: VaultRootKey,
) {
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
    cursor: {
      vaultId,
      serverSequence: 1,
      highestSeenVaultRevision: 1,
    },
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

      // 4. Archive Credential
      await expect(
        executeProductionArchiveEntity(mutationOptions, {
          groupQuery: 'Infrastructure',
          credentialQuery: 'AWS Production Root',
        }),
      ).resolves.toBeUndefined();

      // 5. Restore Credential
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
});
