import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  VaultMutationService,
  VaultReadSession,
  vaultProfileSchema,
} from '@kavrix/client';
import { NotFoundError, SyncConflictError, ValidationError } from '@kavrix/core';
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
  fieldDefinitionSchema,
  itemPayloadSchema,
  syncCursorSchema,
  vaultIdSchema,
  type ItemId,
  type VaultId,
} from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openProductionEnvironment } from '../src/production/environment.js';
import {
  createDefaultMutationDependencies,
  executeProductionCreateCredential,
  executeProductionCreateGroup,
  type ProductionMutationOptions,
} from '../src/production/mutations.js';
import { resolveCliDataPaths } from '../src/production/paths.js';
import {
  executeProductionReferenceAdd,
  executeProductionReferenceList,
  executeProductionReferenceRemove,
  type ProductionReferenceReadOptions,
} from '../src/production/references.js';
import { ensureDataDirectory } from '../src/production/runtime-adapters.js';
import { createSecretBackend } from '../src/production/secret-backend.js';

const VAULT_ID = vaultIdSchema.parse('vault.test000000000000000072');
const DEVICE_ID = deviceIdSchema.parse('device.test00000000000000072');
const TIMESTAMP = '2026-08-10T00:00:00.000Z';

const GROUP = 'Infrastructure';
const OTHER_GROUP = 'Operations';

/**
 * Plaintext that must never leave the authenticated envelope.
 *
 * In a credentials vault a title is as revealing as a secret, so both are
 * canaries: after every write the stored records and the queued mutations the
 * server would receive are searched for them.
 */
const TITLE_CANARY = 'reference-title-canary';
const PASSWORD_CANARY = 'reference-password-canary';

const ROOT_TITLE = 'Primary Database';
const TARGET_TITLE = `Bastion Host ${TITLE_CANARY}`;
const DEEP_TITLE = 'Vault Service';
const CROSS_TITLE = 'Pager Rotation';

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

type FieldDefinitionValue = ReturnType<typeof fieldDefinitionSchema.parse>;
type VaultAggregate = Awaited<
  ReturnType<InstanceType<typeof VaultReadSession>['show']>
>;
type ReferenceGraph = Awaited<
  ReturnType<typeof executeProductionReferenceList>
>['graph'];
type ReferenceGraphNode = ReferenceGraph['nodes'][number];

/**
 * An item-scope field that may hold a relation.
 *
 * A reference field is not sensitive, which the definition schema then requires
 * to carry no reveal policy, so the combination is built once here rather than
 * restated at every call site.
 */
function referenceField(
  stableKey: string,
  label: string,
  options: Readonly<{ repeatable: boolean; sortOrder: number }>,
): FieldDefinitionValue {
  return fieldDefinitionSchema.parse({
    id: `field.${stableKey}`,
    stableKey,
    label,
    type: 'item-reference',
    required: false,
    sensitive: false,
    repeatable: options.repeatable,
    copyable: false,
    searchableLocally: false,
    showInPreview: true,
    copyPolicy: 'never',
    revealPolicy: 'never',
    reauthenticationPolicy: 'never',
    exportPolicy: 'encrypted-only',
    sortOrder: options.sortOrder,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

/** A field that holds a secret, which no reference may ever be written into. */
function secretField(): FieldDefinitionValue {
  return fieldDefinitionSchema.parse({
    id: 'field.password',
    stableKey: 'password',
    label: 'Password',
    type: 'secret',
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
    sortOrder: 9,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

/** Every target ID one stored field value of the read credential names. */
function referencedIds(
  aggregate: VaultAggregate,
  stableKey: string,
): readonly string[] {
  const stored = aggregate.item.itemValues.find(
    (value) => value.stableKey === stableKey,
  );
  if (stored?.value.state !== 'present') return [];
  const content = stored.value.content;
  if (content.cardinality === 'single') {
    return content.value.kind === 'item-reference' ? [content.value.itemId] : [];
  }
  return content.elements.flatMap((element) =>
    element.value.kind === 'item-reference' ? [element.value.itemId] : [],
  );
}

/** The one graph node for a credential, so assertions never depend on position. */
function nodeFor(graph: ReferenceGraph, credentialId: string): ReferenceGraphNode {
  const found = graph.nodes.filter((node) => node.credentialId === credentialId);
  const [first] = found;
  if (first === undefined) throw new Error(`No graph node for ${credentialId}`);
  return first;
}

function expectNoPlaintext(value: unknown): void {
  const serialized = JSON.stringify(value ?? null);
  for (const canary of [TITLE_CANARY, PASSWORD_CANARY]) {
    expect(serialized).not.toContain(canary);
  }
}

type Harness = Readonly<{
  store: SqliteSyncLocalStore;
  service: VaultMutationService;
  mutationOptions: ProductionMutationOptions;
  readOptions: ProductionReferenceReadOptions;
  readAggregate: (group: string, title: string) => Promise<VaultAggregate>;
  currentRevision: (id: ItemId) => Promise<number>;
  installFields: (
    group: string,
    title: string,
    fields: readonly FieldDefinitionValue[],
    values?: readonly Readonly<Record<string, unknown>>[],
  ) => Promise<void>;
  close: () => Promise<void>;
}>;

/**
 * Opens the real composition: SQLite store, native secret backend, unlocked vault.
 *
 * Both tests drive the same production adapters, so the wiring is built once here
 * instead of being restated, and the root key is zeroized by `close` whichever way
 * the test ends.
 */
async function openHarness(tempHome: string): Promise<Harness> {
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

  const service = new VaultMutationService(
    store,
    store,
    VAULT_ID,
    rootKey,
    createDefaultMutationDependencies(),
  );
  const readAggregate = async (
    group: string,
    title: string,
  ): Promise<VaultAggregate> => {
    const session = new VaultReadSession(store, VAULT_ID);
    await session.unlock(rootKey);
    try {
      return await session.show(group, title);
    } finally {
      session.lock();
    }
  };

  return {
    store,
    service,
    mutationOptions: { source: store, queue: store, vaultId: VAULT_ID, rootKey },
    readOptions: { source: store, vaultId: VAULT_ID, rootKey },
    readAggregate,
    currentRevision: async (id: ItemId): Promise<number> => {
      const state = await store.getCurrentItem(VAULT_ID, id);
      return state?.state === 'active' ? state.record.recordRevision : -1;
    },
    // Item-scope definitions reach a credential through import, restore, or sync
    // rather than through these commands, so the fixture writes them the way
    // those paths do: one whole-item write.
    installFields: async (
      group: string,
      title: string,
      fields: readonly FieldDefinitionValue[],
      values: readonly Readonly<Record<string, unknown>>[] = [],
    ): Promise<void> => {
      const aggregate = await readAggregate(group, title);
      await service.updateItem(
        aggregate.group.id,
        itemPayloadSchema.parse({
          ...aggregate.item,
          itemFields: fields,
          itemValues: values,
        }),
      );
    },
    close: async (): Promise<void> => {
      zeroize(rootKey);
      await environment.close();
      await backend.close();
    },
  };
}

describe('production reference adapters', () => {
  let tempHome: string;

  beforeEach(async () => {
    tempHome = join(
      tmpdir(),
      `kavrix-prod-references-test-${Math.random().toString(36).slice(2)}`,
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

  it('writes a field value and its relation in one mutation and retires the relation with the last binding', async () => {
    const harness = await openHarness(tempHome);
    const { mutationOptions, store } = harness;
    try {
      await executeProductionCreateGroup(mutationOptions, { name: GROUP });
      const root = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: GROUP,
        title: ROOT_TITLE,
      });
      const target = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: GROUP,
        title: TARGET_TITLE,
      });
      const deep = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: GROUP,
        title: DEEP_TITLE,
      });

      const password = secretField();
      await harness.installFields(
        GROUP,
        ROOT_TITLE,
        [
          referenceField('depends-on', 'Depends on', {
            repeatable: true,
            sortOrder: 0,
          }),
          referenceField('owned-by', 'Owned by', { repeatable: false, sortOrder: 1 }),
          password,
        ],
        [
          {
            fieldId: password.id,
            stableKey: password.stableKey,
            value: {
              version: 1,
              state: 'present',
              content: {
                cardinality: 'single',
                value: { kind: 'secret', value: PASSWORD_CANARY },
              },
            },
            updatedAt: TIMESTAMP,
          },
        ],
      );

      const base = {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        allowCycle: false,
      } as const;

      // 1. One add writes the field value and the relation together, because a
      //    payload holding one without the other is refused by the schema.
      const added = await executeProductionReferenceAdd(mutationOptions, {
        ...base,
        fieldQuery: 'depends-on',
        targetQuery: TARGET_TITLE,
      });
      expect(added).toMatchObject({
        vaultId: VAULT_ID,
        credentialId: root.credentialId,
        title: ROOT_TITLE,
        fieldKey: 'depends-on',
        fieldLabel: 'Depends on',
        targetId: target.credentialId,
        targetTitle: TARGET_TITLE,
        targetGroupName: GROUP,
        alreadyPresent: false,
      });
      expect(added.revision).toBe(added.previousRevision + 1);
      expect(added).not.toHaveProperty('cyclePath');

      const afterAdd = await harness.readAggregate(GROUP, ROOT_TITLE);
      expect([...afterAdd.item.relatedItemIds]).toStrictEqual([target.credentialId]);
      expect(referencedIds(afterAdd, 'depends-on')).toStrictEqual([
        target.credentialId,
      ]);
      expect(afterAdd.item.revision).toBe(added.revision);

      // 2. Re-adding what is already there writes nothing at all: a byte-identical
      //    payload would consume a revision and record a change that never was.
      const beforeRepeat = await harness.currentRevision(root.credentialId);
      const repeated = await executeProductionReferenceAdd(mutationOptions, {
        ...base,
        fieldQuery: 'depends-on',
        targetQuery: TARGET_TITLE,
      });
      expect(repeated.alreadyPresent).toBe(true);
      expect(repeated.revision).toBe(repeated.previousRevision);
      expect(await harness.currentRevision(root.credentialId)).toBe(beforeRepeat);

      // 3. A repeatable field gains an element and keeps the one it had.
      const second = await executeProductionReferenceAdd(mutationOptions, {
        ...base,
        fieldQuery: 'depends-on',
        targetQuery: DEEP_TITLE,
      });
      expect(second.alreadyPresent).toBe(false);
      const afterSecond = await harness.readAggregate(GROUP, ROOT_TITLE);
      expect(referencedIds(afterSecond, 'depends-on')).toStrictEqual([
        target.credentialId,
        deep.credentialId,
      ]);
      expect([...afterSecond.item.relatedItemIds]).toStrictEqual([
        target.credentialId,
        deep.credentialId,
      ]);

      // 4. A field holding several references never guesses which one to drop.
      await expect(
        executeProductionReferenceRemove(mutationOptions, {
          groupQuery: GROUP,
          credentialQuery: ROOT_TITLE,
          fieldQuery: 'depends-on',
        }),
      ).rejects.toThrow(/several references/u);

      // 5. A second field may bind the same target, so the relation now has two.
      const alsoBound = await executeProductionReferenceAdd(mutationOptions, {
        ...base,
        fieldQuery: 'owned-by',
        targetQuery: TARGET_TITLE,
      });
      expect(alsoBound.alreadyPresent).toBe(false);
      const afterAlsoBound = await harness.readAggregate(GROUP, ROOT_TITLE);
      expect(referencedIds(afterAlsoBound, 'owned-by')).toStrictEqual([
        target.credentialId,
      ]);

      // 6. Dropping one of two bindings keeps the relation, because the value the
      //    other field still holds has to resolve through it.
      const kept = await executeProductionReferenceRemove(mutationOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        fieldQuery: 'depends-on',
        targetQuery: TARGET_TITLE,
      });
      expect(kept).toMatchObject({
        relationRemoved: false,
        targetId: target.credentialId,
        targetTitle: TARGET_TITLE,
      });
      const afterKept = await harness.readAggregate(GROUP, ROOT_TITLE);
      expect(referencedIds(afterKept, 'depends-on')).toStrictEqual([deep.credentialId]);
      expect([...afterKept.item.relatedItemIds]).toContain(target.credentialId);

      // 7. Dropping the last binding retires the relation and leaves the field
      //    holding nothing rather than an empty element list.
      const retired = await executeProductionReferenceRemove(mutationOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        fieldQuery: 'owned-by',
      });
      expect(retired.relationRemoved).toBe(true);
      const afterRetired = await harness.readAggregate(GROUP, ROOT_TITLE);
      expect(referencedIds(afterRetired, 'owned-by')).toStrictEqual([]);
      expect(
        afterRetired.item.itemValues.some((value) => value.stableKey === 'owned-by'),
      ).toBe(false);
      expect([...afterRetired.item.relatedItemIds]).toStrictEqual([deep.credentialId]);

      // 8. Every unsafe write is refused, and none of them consumes a revision.
      const settled = await harness.currentRevision(root.credentialId);
      await expect(
        executeProductionReferenceAdd(mutationOptions, {
          ...base,
          fieldQuery: 'depends-on',
          targetQuery: ROOT_TITLE,
        }),
      ).rejects.toThrow(/cannot reference itself/u);
      await expect(
        executeProductionReferenceAdd(mutationOptions, {
          ...base,
          fieldQuery: 'password',
          targetQuery: TARGET_TITLE,
        }),
      ).rejects.toThrow(/Only an item-reference field/u);
      await expect(
        executeProductionReferenceAdd(mutationOptions, {
          ...base,
          fieldQuery: 'absent',
          targetQuery: TARGET_TITLE,
        }),
      ).rejects.toBeInstanceOf(NotFoundError);
      await expect(
        executeProductionReferenceAdd(mutationOptions, {
          ...base,
          fieldQuery: 'depends-on',
          targetQuery: TARGET_TITLE,
          ifRevision: 1,
        }),
      ).rejects.toBeInstanceOf(SyncConflictError);
      await expect(
        executeProductionReferenceRemove(mutationOptions, {
          groupQuery: GROUP,
          credentialQuery: ROOT_TITLE,
          fieldQuery: 'depends-on',
          targetQuery: TARGET_TITLE,
        }),
      ).rejects.toBeInstanceOf(NotFoundError);
      expect(await harness.currentRevision(root.credentialId)).toBe(settled);

      // 9. Nothing readable left the envelope: not a title, not a secret, in the
      //    stored records or in the mutations the server would receive.
      for (const id of [root.credentialId, target.credentialId, deep.credentialId]) {
        expectNoPlaintext(await store.getCurrentItem(VAULT_ID, id));
      }
      const pending = await store.listPendingMutations(VAULT_ID);
      expect(pending.length).toBeGreaterThan(0);
      expectNoPlaintext(pending);
    } finally {
      await harness.close();
    }
  });

  it('walks references across groups and reports archived, missing, and cyclic targets', async () => {
    const harness = await openHarness(tempHome);
    const { mutationOptions, readOptions, store } = harness;
    try {
      await executeProductionCreateGroup(mutationOptions, { name: GROUP });
      await executeProductionCreateGroup(mutationOptions, { name: OTHER_GROUP });
      const root = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: GROUP,
        title: ROOT_TITLE,
      });
      const target = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: GROUP,
        title: TARGET_TITLE,
      });
      const deep = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: GROUP,
        title: DEEP_TITLE,
      });
      const cross = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: OTHER_GROUP,
        title: CROSS_TITLE,
      });

      for (const title of [ROOT_TITLE, TARGET_TITLE, DEEP_TITLE]) {
        await harness.installFields(GROUP, title, [
          referenceField('depends-on', 'Depends on', {
            repeatable: true,
            sortOrder: 0,
          }),
        ]);
      }

      const chain = async (from: string, to: string): Promise<void> => {
        await executeProductionReferenceAdd(mutationOptions, {
          groupQuery: GROUP,
          credentialQuery: from,
          fieldQuery: 'depends-on',
          targetQuery: to,
          allowCycle: false,
        });
      };
      await chain(ROOT_TITLE, TARGET_TITLE);
      await chain(TARGET_TITLE, DEEP_TITLE);

      // A target in another group is reached by naming that group, and resolves
      // there: a walk confined to the credential's own group would have reported
      // a legitimate cross-group relation as missing.
      const crossAdded = await executeProductionReferenceAdd(mutationOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        fieldQuery: 'depends-on',
        targetQuery: CROSS_TITLE,
        targetGroupQuery: OTHER_GROUP,
        allowCycle: false,
      });
      expect(crossAdded.targetGroupId).toBe(
        (await harness.readAggregate(OTHER_GROUP, CROSS_TITLE)).group.id,
      );
      expect(crossAdded.targetGroupName).toBe(OTHER_GROUP);

      const walk = (
        depth?: number,
      ): ReturnType<typeof executeProductionReferenceList> =>
        executeProductionReferenceList(readOptions, {
          groupQuery: GROUP,
          credentialQuery: ROOT_TITLE,
          ...(depth === undefined ? {} : { depth }),
        });

      // 1. The default walk is one level deep and says so rather than implying it
      //    has seen everything.
      const shallow = await walk();
      expect(shallow.requestedDepth).toBe(1);
      expect(shallow.graph.reachedDepth).toBe(1);
      expect(shallow.graph.nodes.map((node) => node.credentialId)).toStrictEqual([
        root.credentialId,
        target.credentialId,
        cross.credentialId,
      ]);
      expect(nodeFor(shallow.graph, cross.credentialId)).toMatchObject({
        depth: 1,
        state: 'active',
        groupName: OTHER_GROUP,
        title: CROSS_TITLE,
      });
      const [binding] = nodeFor(shallow.graph, target.credentialId).bindings;
      expect(binding).toMatchObject({
        fieldKey: 'depends-on',
        fieldLabel: 'Depends on',
        scope: 'item',
      });
      expect(binding?.elementId).toMatch(/^element\.[0-9a-f]{24}$/u);

      // 2. A deeper walk reaches the second level and names the parent that led
      //    there, which is what makes the path reconstructible.
      const deeper = await walk(2);
      expect(deeper.requestedDepth).toBe(2);
      expect(deeper.graph.reachedDepth).toBe(2);
      expect(nodeFor(deeper.graph, deep.credentialId)).toMatchObject({
        depth: 2,
        parentId: target.credentialId,
        state: 'active',
        groupName: GROUP,
        title: DEEP_TITLE,
      });
      expect(deeper.graph).toMatchObject({
        cycleCount: 0,
        missingCount: 0,
        truncated: false,
      });

      // 3. Closing a loop is refused with the path it would close, and recorded
      //    once the caller states the loop is deliberate.
      const closing = {
        groupQuery: GROUP,
        credentialQuery: DEEP_TITLE,
        fieldQuery: 'depends-on',
        targetQuery: ROOT_TITLE,
      };
      const refused = await executeProductionReferenceAdd(mutationOptions, {
        ...closing,
        allowCycle: false,
      }).catch((error: unknown) => error);
      expect(refused).toBeInstanceOf(ValidationError);
      expect(refused).toHaveProperty(
        'message',
        `This reference would close a cycle through ${root.credentialId} -> ${target.credentialId} -> ${deep.credentialId}. Pass --allow-cycle to record it deliberately.`,
      );

      const allowed = await executeProductionReferenceAdd(mutationOptions, {
        ...closing,
        allowCycle: true,
      });
      expect(allowed.cyclePath).toStrictEqual([root.credentialId, target.credentialId]);

      // 4. The recorded loop is disclosed as a cycle instead of being pruned, and
      //    a bounded walk still terminates.
      const looped = await walk(4);
      expect(looped.graph.cycleCount).toBe(1);
      expect(
        looped.graph.nodes.find(
          (node) => node.credentialId === root.credentialId && node.depth === 3,
        ),
      ).toMatchObject({ cycle: true, revisit: true, parentId: deep.credentialId });
      expect(looped.graph.truncated).toBe(false);

      // 5. Archiving a target retires the credential without breaking the
      //    relation, and the walk continues through it.
      const targetAggregate = await harness.readAggregate(GROUP, TARGET_TITLE);
      await harness.service.updateItem(
        targetAggregate.group.id,
        itemPayloadSchema.parse({ ...targetAggregate.item, archivedAt: TIMESTAMP }),
      );
      const archived = await walk(2);
      expect(nodeFor(archived.graph, target.credentialId)).toMatchObject({
        state: 'archived',
        title: TARGET_TITLE,
      });
      expect(nodeFor(archived.graph, deep.credentialId).depth).toBe(2);

      // 6. A tombstoned target is excluded from every read, so its relation
      //    survives with nothing behind it and is reported as missing rather than
      //    silently dropped from the list.
      const deepAggregate = await harness.readAggregate(GROUP, DEEP_TITLE);
      await harness.service.deleteItem(
        deepAggregate.group.id,
        deepAggregate.item.id,
        deepAggregate.item.revision,
      );
      const missing = await walk(3);
      const missingNode = nodeFor(missing.graph, deep.credentialId);
      expect(missingNode).toMatchObject({ state: 'missing', depth: 2 });
      expect(missingNode).not.toHaveProperty('groupName');
      expect(missingNode).not.toHaveProperty('title');
      expect(missing.graph.missingCount).toBe(1);
      // The loop went with the credential that closed it, and nothing claims
      // otherwise.
      expect(missing.graph.cycleCount).toBe(0);

      // 7. None of it leaked: no title and no secret in the stored records or in
      //    the queued mutations.
      for (const id of [
        root.credentialId,
        target.credentialId,
        deep.credentialId,
        cross.credentialId,
      ]) {
        expectNoPlaintext(await store.getCurrentItem(VAULT_ID, id));
      }
      expectNoPlaintext(await store.listPendingMutations(VAULT_ID));
    } finally {
      await harness.close();
    }
  });
});
