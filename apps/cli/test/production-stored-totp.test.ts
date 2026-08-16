import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { vaultProfileSchema } from '@kavrix/client';
import {
  AmbiguousNameError,
  NotFoundError,
  PermissionError,
  ValidationError,
} from '@kavrix/core';
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
  syncCursorSchema,
  vaultIdSchema,
  type VaultId,
} from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openProductionEnvironment } from '../src/production/environment.js';
import {
  executeProductionCreateCredential,
  executeProductionCreateGroup,
} from '../src/production/mutations.js';
import { executeProductionStoredTotp } from '../src/production/stored-totp.js';
import { resolveCliDataPaths } from '../src/production/paths.js';
import { ensureDataDirectory } from '../src/production/runtime-adapters.js';
import { createSecretBackend } from '../src/production/secret-backend.js';

const VAULT_ID = vaultIdSchema.parse('vault.test000000000000000001');
const DEVICE_ID = deviceIdSchema.parse('device.test00000000000000001');
const TIMESTAMP = '2026-08-10T00:00:00.000Z';

/**
 * The RFC 6238 SHA-1 seed, and two further seeds that must never be usable.
 *
 * Every one of them is a canary: after any read the stored record and the queued
 * mutations are searched for all three, so a projection that leaks a seed other
 * than the one under test still fails the suite.
 */
const SEED_CANARY_PRIMARY = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const SEED_CANARY_SEALED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJA';
const SEED_CANARY_TAMPERED = SEED_CANARY_PRIMARY.toLowerCase();
const PASSWORD_CANARY = 'stored-totp-password-canary';

/** The published RFC 6238 expectation for the SHA-1 seed at Unix time 59. */
const RFC_CODE_AT_59 = '94287082';

const SHA1_POLICY = Object.freeze({
  algorithm: 'sha1',
  digits: 8,
  periodSeconds: 30,
} as const);

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

  const portableKey = generatePortableKey();
  const slot = await createPortableKeySlot(
    {
      vaultId,
      slotId: keySlotIdSchema.parse('slot.test001'),
      schemaVersion: 1,
      keyVersion: 1,
      createdAt: TIMESTAMP,
    },
    portableKey,
    rootKey,
  );

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
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType: 'vault-preferences',
      entityId: vaultId,
      purpose: 'vault-preferences',
    }),
  );

  const vaultRecord = vaultRecordSchema.parse({
    id: vaultId,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [slot],
    currentKeyVersion: 1,
    revision: 1,
    encryptedPreferences,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });

  await store.applyPullPage({
    vaultId,
    changes: [
      {
        change: changeRecordSchema.parse({
          id: 'change.vault.001',
          vaultId,
          serverSequence: 1,
          entityType: 'vault',
          entityId: vaultId,
          recordRevision: 1,
          operation: 'upsert',
          ciphertextHash: contentHashForRecord(vaultRecord),
          createdAt: TIMESTAMP,
        }),
        record: vaultRecord,
      },
    ],
    cursor: syncCursorSchema.parse({
      vaultId,
      serverSequence: 1,
      highestSeenVaultRevision: 1,
    }),
  });
}

function profileFor(vaultId: VaultId): ReturnType<typeof vaultProfileSchema.parse> {
  return vaultProfileSchema.parse({
    version: 1,
    serverUrl: 'https://vault.example/',
    vaultId,
    deviceId: DEVICE_ID,
    deviceLocator: {
      version: 1,
      vaultId,
      deviceId: DEVICE_ID,
      keySlotId: 'slot.device.001',
    },
    sessionLocator: {
      version: 1,
      vaultId,
      deviceId: DEVICE_ID,
      purpose: 'api-session',
    },
  });
}

/**
 * Assert that no seed appears anywhere in a projection.
 *
 * The API and the store are zero-knowledge layers, so a seed must only ever
 * exist inside an authenticated envelope. Searching the serialized form catches
 * both a leaked field value and a leaked queue payload.
 */
function expectNoSeedMaterial(value: unknown): void {
  const serialized = JSON.stringify(value ?? null);
  for (const canary of [
    SEED_CANARY_PRIMARY,
    SEED_CANARY_SEALED,
    SEED_CANARY_TAMPERED,
    PASSWORD_CANARY,
  ]) {
    expect(serialized).not.toContain(canary);
  }
}

describe('production stored TOTP adapter', () => {
  let tempHome: string;

  beforeEach(async () => {
    tempHome = join(
      tmpdir(),
      `kavrix-prod-stored-totp-test-${Math.random().toString(36).slice(2)}`,
    );
    await ensureDataDirectory(tempHome);
    const paths = resolveCliDataPaths({ CREDS_HOME: tempHome });
    const profileStore = await openSqliteVaultProfileStore({
      path: paths.profileStore,
    });
    await profileStore.store(profileFor(VAULT_ID));
    await profileStore.close();
  });

  afterEach(async () => {
    try {
      await rm(tempHome, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on temp teardown
    }
  });

  it('generates a published code from a stored seed and refuses every unsafe resolution', async () => {
    const rootKey = generateVaultRootKey();
    const paths = resolveCliDataPaths({ CREDS_HOME: tempHome });
    const backend = await createSecretBackend(
      paths,
      {
        read: () => Promise.reject(new Error('secrets unneeded')),
        readBatch: () => Promise.reject(new Error('secrets unneeded')),
      },
      { kind: 'native' },
    );
    const environment = await openProductionEnvironment(paths, backend);
    const store = await environment.openSyncStore(profileFor(VAULT_ID));

    await seedVaultRecordInStore(store, VAULT_ID, rootKey);

    const mutationOptions = { source: store, queue: store, vaultId: VAULT_ID, rootKey };
    const readOptions = { source: store, vaultId: VAULT_ID, rootKey };

    const { VaultMutationService, VaultReadSession } = await import('@kavrix/client');
    const { createDefaultMutationDependencies } =
      await import('../src/production/mutations.js');
    const { fieldDefinitionSchema, itemPayloadSchema } =
      await import('@kavrix/schemas');

    try {
      await executeProductionCreateGroup(mutationOptions, { name: 'Identity' });
      const shared = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: 'Identity',
        title: 'Shared Console',
      });
      const single = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: 'Identity',
        title: 'Legacy Console',
      });

      // A seed reaches a vault through import, restore, or sync rather than
      // through this command, so the fixture writes the item the way those paths
      // do: one whole-item write carrying item-scope definitions and values.
      const service = new VaultMutationService(
        store,
        store,
        VAULT_ID,
        rootKey,
        createDefaultMutationDependencies(),
      );
      type VaultAggregate = Awaited<
        ReturnType<InstanceType<typeof VaultReadSession>['show']>
      >;
      const readAggregate = async (title: string): Promise<VaultAggregate> => {
        const session = new VaultReadSession(store, VAULT_ID);
        await session.unlock(rootKey);
        try {
          return await session.show('Identity', title);
        } finally {
          session.lock();
        }
      };

      const seedDefinition = fieldDefinitionSchema.parse({
        id: 'field.totp.primary',
        stableKey: 'totp-secret',
        label: 'Authenticator seed',
        type: 'totp-secret',
        required: false,
        sensitive: true,
        repeatable: false,
        copyable: true,
        searchableLocally: false,
        showInPreview: false,
        copyPolicy: 'allowed',
        revealPolicy: 'timed',
        reauthenticationPolicy: 'after-lock',
        exportPolicy: 'guarded',
        sortOrder: 0,
        createdAt: TIMESTAMP,
        updatedAt: TIMESTAMP,
      });
      const sealedDefinition = fieldDefinitionSchema.parse({
        ...seedDefinition,
        id: 'field.totp.sealed',
        stableKey: 'totp-sealed',
        label: 'Sealed authenticator seed',
        revealPolicy: 'never',
        sortOrder: 1,
      });
      const passwordDefinition = fieldDefinitionSchema.parse({
        ...seedDefinition,
        id: 'field.password',
        stableKey: 'password',
        label: 'Password',
        type: 'secret',
        revealPolicy: 'timed',
        sortOrder: 2,
      });
      const singleSeedDefinition = fieldDefinitionSchema.parse({
        ...seedDefinition,
        id: 'field.totp.legacy',
        stableKey: 'legacy-totp',
        label: 'Legacy authenticator seed',
      });

      const storedSecret = (value: string): Readonly<Record<string, unknown>> => ({
        version: 1,
        state: 'present',
        content: { cardinality: 'single', value: { kind: 'secret', value } },
      });

      const sharedAggregate = await readAggregate('Shared Console');
      await service.updateItem(
        sharedAggregate.group.id,
        itemPayloadSchema.parse({
          ...sharedAggregate.item,
          itemFields: [seedDefinition, sealedDefinition, passwordDefinition],
          itemValues: [
            {
              fieldId: seedDefinition.id,
              stableKey: seedDefinition.stableKey,
              value: storedSecret(SEED_CANARY_PRIMARY),
              updatedAt: TIMESTAMP,
            },
            {
              fieldId: sealedDefinition.id,
              stableKey: sealedDefinition.stableKey,
              value: storedSecret(SEED_CANARY_SEALED),
              updatedAt: TIMESTAMP,
            },
            {
              fieldId: passwordDefinition.id,
              stableKey: passwordDefinition.stableKey,
              value: storedSecret(PASSWORD_CANARY),
              updatedAt: TIMESTAMP,
            },
          ],
        }),
      );

      const singleAggregate = await readAggregate('Legacy Console');
      await service.updateItem(
        singleAggregate.group.id,
        itemPayloadSchema.parse({
          ...singleAggregate.item,
          itemFields: [singleSeedDefinition],
          itemValues: [
            {
              fieldId: singleSeedDefinition.id,
              stableKey: singleSeedDefinition.stableKey,
              value: storedSecret(SEED_CANARY_TAMPERED),
              updatedAt: TIMESTAMP,
            },
          ],
        }),
      );

      const request = {
        groupQuery: 'Identity',
        credentialQuery: 'Shared Console',
        fieldQuery: 'totp-secret',
        configuration: SHA1_POLICY,
        unixTimeSeconds: 59,
      };

      // 1. The stored seed reproduces the published vector, and the receipt
      //    describes the field and the policy without carrying the seed.
      const generated = await executeProductionStoredTotp(readOptions, request);
      expect(generated).toStrictEqual({
        groupName: 'Identity',
        credentialTitle: 'Shared Console',
        fieldLabel: 'Authenticator seed',
        fieldKey: 'totp-secret',
        code: RFC_CODE_AT_59,
        remainingSeconds: 1,
        algorithm: 'sha1',
        digits: 8,
        periodSeconds: 30,
      });
      expectNoSeedMaterial(generated);

      // 2. Generating a code is a read. Repeating it produces the same code and
      //    leaves the item revision untouched, so a script that polls for a fresh
      //    code cannot silently grow the vault history.
      const beforeRepeat = await store.getCurrentItem(VAULT_ID, shared.credentialId);
      const repeated = await executeProductionStoredTotp(readOptions, request);
      const afterRepeat = await store.getCurrentItem(VAULT_ID, shared.credentialId);
      expect(repeated.code).toBe(RFC_CODE_AT_59);
      expect(afterRepeat?.state).toBe('active');
      expect(
        afterRepeat?.state === 'active' ? afterRepeat.record.recordRevision : -1,
      ).toBe(
        beforeRepeat?.state === 'active' ? beforeRepeat.record.recordRevision : -2,
      );

      // 3. Two seeds on one credential are never guessed between, and the refusal
      //    names both fields so the caller can pick one.
      let ambiguous: unknown;
      try {
        await executeProductionStoredTotp(readOptions, {
          ...request,
          fieldQuery: undefined,
        });
      } catch (error) {
        ambiguous = error;
      }
      expect(ambiguous).toBeInstanceOf(AmbiguousNameError);
      expect((ambiguous as AmbiguousNameError).candidateIds).toStrictEqual([
        'field.totp.primary',
        'field.totp.sealed',
      ]);

      // 4. An ambiguous name is refused for the same reason an omitted one is.
      await expect(
        executeProductionStoredTotp(readOptions, { ...request, fieldQuery: 'totp-' }),
      ).rejects.toBeInstanceOf(AmbiguousNameError);

      // 5. A field its own definition seals is refused even though a code is
      //    short-lived, because a code still authenticates.
      await expect(
        executeProductionStoredTotp(readOptions, {
          ...request,
          fieldQuery: 'totp-sealed',
        }),
      ).rejects.toBeInstanceOf(PermissionError);

      // 6. Naming a field that holds something else is refused as a wrong type
      //    rather than skipped and reported as a missing seed.
      await expect(
        executeProductionStoredTotp(readOptions, {
          ...request,
          fieldQuery: 'password',
        }),
      ).rejects.toThrow(/does not hold a TOTP secret/u);

      // 7. An unknown field is not found, and no seed is decoded looking for it.
      await expect(
        executeProductionStoredTotp(readOptions, { ...request, fieldQuery: 'absent' }),
      ).rejects.toBeInstanceOf(NotFoundError);

      // 8. A tampered stored seed fails closed, and the refusal describes the
      //    required encoding without echoing the stored bytes.
      let tampered: unknown;
      try {
        await executeProductionStoredTotp(readOptions, {
          ...request,
          credentialQuery: 'Legacy Console',
          fieldQuery: undefined,
        });
      } catch (error) {
        tampered = error;
      }
      expect(tampered).toBeInstanceOf(ValidationError);
      expect((tampered as ValidationError).message).not.toContain(SEED_CANARY_TAMPERED);

      // 9. Every seed stays inside its authenticated envelope: neither the stored
      //    record nor the queued mutation the API would receive carries one.
      expectNoSeedMaterial(await store.getCurrentItem(VAULT_ID, shared.credentialId));
      expectNoSeedMaterial(await store.getCurrentItem(VAULT_ID, single.credentialId));
      const pending = await store.listPendingMutations(VAULT_ID);
      expect(pending.length).toBeGreaterThan(0);
      expectNoSeedMaterial(pending);
    } finally {
      zeroize(rootKey);
      await environment.close();
      await backend.close();
    }
  });
});
