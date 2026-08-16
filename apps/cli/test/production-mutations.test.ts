import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { vaultProfileSchema } from '@kavrix/client';
import { AmbiguousNameError, PermissionError, SyncConflictError } from '@kavrix/core';
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
  executeProductionListRecoveryCodes,
  executeProductionRemoveField,
  executeProductionRemoveNote,
  executeProductionRestoreEntity,
  executeProductionRestoreField,
  executeProductionRestoreNote,
  executeProductionRevealRecoveryCode,
  executeProductionSetField,
  executeProductionUpdateField,
  executeProductionUpdateNote,
  executeProductionUseRecoveryCode,
} from '../src/production/mutations.js';
import { executeProductionShow } from '../src/production/show.js';
import { executeProductionCopy } from '../src/production/copy.js';
import { executeProductionReveal } from '../src/production/reveal.js';
import { executeProductionGet } from '../src/production/get.js';
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
        create: true,
      });
      expect(setFieldResult.credentialId).toBe(credResult.credentialId);
      expect(setFieldResult.created).toBe(true);
      expect(setFieldResult.revision).toBe(setFieldResult.previousRevision + 1);
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
      expect(revealResult.value).toBe('super-secret-password-123');

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
      // A caller reading JSON must be able to tell a withheld secret from a
      // stored value that happens to spell the placeholder.
      expect(getRedacted.redacted).toBe(true);

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
      expect(getRevealed.value).toBe('super-secret-password-123');
      expect(getRevealed.redacted).toBe(false);
      expect(getRevealed.revision).toBeGreaterThan(0);

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

  it('consumes exactly one recovery code by stable identifier and keeps the used state durable', async () => {
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

    const mutationOptions = { source: store, queue: store, vaultId, rootKey };
    const readOptions = { source: store, vaultId, rootKey };

    const { VaultMutationService, VaultReadSession } = await import('@kavrix/client');
    const { createDefaultMutationDependencies } =
      await import('../src/production/mutations.js');
    const { fieldDefinitionSchema, itemPayloadSchema } =
      await import('@kavrix/schemas');

    try {
      await executeProductionCreateGroup(mutationOptions, { name: 'Identity' });
      const credential = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: 'Identity',
        title: 'Break Glass Account',
      });

      // Recovery codes are minted by import, restore, or sync rather than by the
      // CLI, so the fixture seeds the element list the way those paths do: one
      // whole-item write carrying an item-scope definition and its stored value.
      const seedSession = new VaultReadSession(store, vaultId);
      await seedSession.unlock(rootKey);
      let seeded: Awaited<ReturnType<typeof seedSession.show>>;
      try {
        seeded = await seedSession.show('Identity', 'Break Glass Account');
      } finally {
        seedSession.lock();
      }

      const definition = fieldDefinitionSchema.parse({
        id: 'field.recovery.codes',
        stableKey: 'recovery-codes',
        label: 'Recovery codes',
        type: 'recovery-code-list',
        required: false,
        sensitive: true,
        repeatable: true,
        copyable: true,
        searchableLocally: false,
        showInPreview: false,
        copyPolicy: 'allowed',
        revealPolicy: 'timed',
        reauthenticationPolicy: 'after-lock',
        exportPolicy: 'guarded',
        sortOrder: 0,
        createdAt: '2026-08-10T00:00:00.000Z',
        updatedAt: '2026-08-10T00:00:00.000Z',
      });
      const sealedDefinition = fieldDefinitionSchema.parse({
        ...definition,
        id: 'field.recovery.sealed',
        stableKey: 'recovery-sealed',
        label: 'Sealed recovery codes',
        revealPolicy: 'never',
        sortOrder: 1,
      });

      const element = (
        id: string,
        value: string,
        usedAt?: string,
      ): Readonly<Record<string, unknown>> => ({
        id,
        value: { kind: 'secret', value },
        lifecycle:
          usedAt === undefined
            ? { version: 1, status: 'available' }
            : { version: 1, status: 'used', usedAt },
      });
      const listValue = (
        elements: readonly Readonly<Record<string, unknown>>[],
      ): Readonly<Record<string, unknown>> => ({
        version: 1,
        state: 'present',
        content: { cardinality: 'multiple', elements },
      });

      const service = new VaultMutationService(
        store,
        store,
        vaultId,
        rootKey,
        createDefaultMutationDependencies(),
      );
      await service.updateItem(
        seeded.group.id,
        itemPayloadSchema.parse({
          ...seeded.item,
          itemFields: [definition, sealedDefinition],
          itemValues: [
            {
              fieldId: definition.id,
              stableKey: definition.stableKey,
              value: listValue([
                element('code.alpha', CODE_CANARY_ALPHA),
                element('code.beta', CODE_CANARY_BETA),
                element('code.spent', CODE_CANARY_SPENT, '2026-08-01T00:00:00.000Z'),
              ]),
              updatedAt: '2026-08-10T00:00:00.000Z',
            },
            {
              fieldId: sealedDefinition.id,
              stableKey: sealedDefinition.stableKey,
              value: listValue([element('sealed.one', CODE_CANARY_SEALED)]),
              updatedAt: '2026-08-10T00:00:00.000Z',
            },
          ],
        }),
      );

      const listRequest = {
        groupQuery: 'Identity',
        credentialQuery: 'Break Glass Account',
        fieldQuery: 'recovery-codes',
      };

      // 1. Listing reports identity and lifecycle only. No projection may carry
      //    code material, in either the masked entries or the inventory.
      const listed = await executeProductionListRecoveryCodes(readOptions, listRequest);
      expect(listed.fieldLabel).toBe('Recovery codes');
      expect(listed.inventory).toStrictEqual({ total: 3, available: 2, used: 1 });
      expect(listed.codes).toStrictEqual([
        { id: 'code.alpha', status: 'available', usedAt: null },
        { id: 'code.beta', status: 'available', usedAt: null },
        { id: 'code.spent', status: 'used', usedAt: '2026-08-01T00:00:00.000Z' },
      ]);
      expectNoCodeMaterial(listed);

      // 2. An ambiguous identifier prefix is refused rather than resolved to the
      //    first match, because guessing here would consume the wrong code.
      await expect(
        executeProductionUseRecoveryCode(mutationOptions, {
          ...listRequest,
          code: 'code.',
        }),
      ).rejects.toBeInstanceOf(AmbiguousNameError);

      // 3. A stale revision expectation fails closed before any write lands.
      await expect(
        executeProductionUseRecoveryCode(mutationOptions, {
          ...listRequest,
          code: 'code.alpha',
          ifRevision: 99,
        }),
      ).rejects.toBeInstanceOf(SyncConflictError);
      const unchanged = await executeProductionListRecoveryCodes(
        readOptions,
        listRequest,
      );
      expect(unchanged.inventory.available).toBe(2);

      // 4. The consuming write marks exactly the named code used.
      const beforeUse = await store.getCurrentItem(vaultId, credential.credentialId);
      const baseRevision =
        beforeUse?.state === 'active' ? beforeUse.record.recordRevision : 0;
      const receipt = await executeProductionUseRecoveryCode(mutationOptions, {
        ...listRequest,
        code: 'code.alpha',
        ifRevision: baseRevision,
      });
      expect(receipt.codeId).toBe('code.alpha');
      expect(receipt.previousRevision).toBe(baseRevision);
      expect(receipt.revision).toBe(baseRevision + 1);
      expect(receipt.inventory).toStrictEqual({ total: 3, available: 1, used: 2 });
      expectNoCodeMaterial(receipt);

      // 5. The transition is durable and every other code keeps its identity and
      //    its own lifecycle, which is what a concurrent replica merges on.
      const afterUse = await executeProductionListRecoveryCodes(
        readOptions,
        listRequest,
      );
      expect(afterUse.codes).toStrictEqual([
        { id: 'code.alpha', status: 'used', usedAt: receipt.usedAt },
        { id: 'code.beta', status: 'available', usedAt: null },
        { id: 'code.spent', status: 'used', usedAt: '2026-08-01T00:00:00.000Z' },
      ]);

      // 6. Retrying the committed write is refused instead of restamping usedAt,
      //    so an interrupted caller that cannot tell whether its write landed can
      //    safely repeat it.
      await expect(
        executeProductionUseRecoveryCode(mutationOptions, {
          ...listRequest,
          code: 'code.alpha',
        }),
      ).rejects.toThrow(/already been used/u);
      const afterRetry = await executeProductionListRecoveryCodes(
        readOptions,
        listRequest,
      );
      expect(afterRetry.codes[0]?.usedAt).toBe(receipt.usedAt);

      // 7. A non-consuming reveal releases the value and writes nothing.
      const revealed = await executeProductionRevealRecoveryCode(mutationOptions, {
        ...listRequest,
        code: 'code.beta',
      });
      expect(revealed).toStrictEqual({
        codeId: 'code.beta',
        value: CODE_CANARY_BETA,
        receipt: null,
      });
      const afterReveal = await executeProductionListRecoveryCodes(
        readOptions,
        listRequest,
      );
      expect(afterReveal.inventory).toStrictEqual({ total: 3, available: 1, used: 2 });

      // 8. Revealing a spent code adds exposure and no use, so it is refused.
      await expect(
        executeProductionRevealRecoveryCode(mutationOptions, {
          ...listRequest,
          code: 'code.spent',
        }),
      ).rejects.toThrow(/already been used/u);

      // 9. A field whose definition forbids reveal is refused, and the refusal
      //    happens before the write so no code is spent by a denied reveal.
      const sealedRequest = { ...listRequest, fieldQuery: 'recovery-sealed' };
      await expect(
        executeProductionRevealRecoveryCode(mutationOptions, {
          ...sealedRequest,
          code: 'sealed.one',
          use: true,
        }),
      ).rejects.toBeInstanceOf(PermissionError);
      const sealedAfterDenial = await executeProductionListRecoveryCodes(
        readOptions,
        sealedRequest,
      );
      expect(sealedAfterDenial.inventory).toStrictEqual({
        total: 1,
        available: 1,
        used: 0,
      });

      // 10. A consuming reveal commits the transition before releasing the value,
      //     so an interruption cannot leave a displayed code still available.
      const consumed = await executeProductionRevealRecoveryCode(mutationOptions, {
        ...listRequest,
        code: 'code.beta',
        use: true,
      });
      expect(consumed.value).toBe(CODE_CANARY_BETA);
      expect(consumed.receipt?.codeId).toBe('code.beta');
      expectNoCodeMaterial(consumed.receipt);
      const exhausted = await executeProductionListRecoveryCodes(
        readOptions,
        listRequest,
      );
      expect(exhausted.inventory).toStrictEqual({ total: 3, available: 0, used: 3 });

      // 11. A field that cannot legally carry a `used` lifecycle is refused, so
      //     the transition can never be written onto an ordinary field.
      await executeProductionAddField(mutationOptions, {
        groupQuery: 'Identity',
        credentialQuery: 'Break Glass Account',
        fieldKey: 'console-url',
        fieldType: 'url',
        label: 'Console URL',
        sensitive: false,
      });
      await expect(
        executeProductionUseRecoveryCode(mutationOptions, {
          ...listRequest,
          fieldQuery: 'console-url',
          code: 'code.alpha',
        }),
      ).rejects.toThrow(/does not hold recovery codes/u);

      // 12. The used state lives inside the encrypted item record rather than in
      //     any plaintext column the store keeps for sync or for the queue.
      const stored = await store.getCurrentItem(vaultId, credential.credentialId);
      expect(stored?.state).toBe('active');
      expectNoCodeMaterial(stored);
      const pending = await store.listPendingMutations(vaultId);
      expect(pending.length).toBeGreaterThan(0);
      expectNoCodeMaterial(pending);
    } finally {
      zeroize(rootKey);
      await environment.close();
      await backend.close();
    }
  });
});

const CODE_CANARY_ALPHA = 'recovery-canary-alpha';
const CODE_CANARY_BETA = 'recovery-canary-beta';
const CODE_CANARY_SPENT = 'recovery-canary-spent';
const CODE_CANARY_SEALED = 'recovery-canary-sealed';

/**
 * Assert that no recovery code value appears anywhere in a projection.
 *
 * Every canary is checked against every projection, so a receipt or a stored
 * record that leaks a code other than the one under test still fails.
 */
function expectNoCodeMaterial(value: unknown): void {
  const serialized = JSON.stringify(value ?? null);
  for (const canary of [
    CODE_CANARY_ALPHA,
    CODE_CANARY_BETA,
    CODE_CANARY_SPENT,
    CODE_CANARY_SEALED,
  ]) {
    expect(serialized).not.toContain(canary);
  }
}
