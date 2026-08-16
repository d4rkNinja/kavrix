import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  VaultMutationService,
  VaultReadSession,
  vaultProfileSchema,
} from '@kavrix/client';
import { NotFoundError, SyncConflictError } from '@kavrix/core';
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
  archivedFieldValueSchema,
  attachmentIdSchema,
  deviceIdSchema,
  fieldDefinitionSchema,
  groupPayloadSchema,
  itemPayloadSchema,
  noteIdSchema,
  noteSchema,
  syncCursorSchema,
  vaultIdSchema,
  type ItemId,
  type TemplateId,
  type TemplateVersion,
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
  executeProductionPurgeFields,
  executeProductionPurgeNotes,
  executeProductionPurgePreview,
  type ProductionPurgeReadOptions,
} from '../src/production/purge.js';
import { ensureDataDirectory } from '../src/production/runtime-adapters.js';
import { createSecretBackend } from '../src/production/secret-backend.js';

const VAULT_ID = vaultIdSchema.parse('vault.test000000000000000073');
const DEVICE_ID = deviceIdSchema.parse('device.test00000000000000073');
const TIMESTAMP = '2026-08-10T00:00:00.000Z';

const GROUP = 'Infrastructure';

/**
 * Plaintext that must never leave the authenticated envelope.
 *
 * A purge decides whether to destroy a value and never needs to read one, so the
 * archived secret and the archived note body are canaries alongside the title:
 * after every write the stored records and the mutations the server would receive
 * are searched for all three.
 */
const TITLE_CANARY = 'purge-title-canary';
const SECRET_CANARY = 'purge-secret-canary';
const NOTE_CANARY = 'purge-note-canary';

const ROOT_TITLE = `Primary Database ${TITLE_CANARY}`;
const TARGET_TITLE = 'Bastion Host';
const DOOMED_TITLE = 'Retired Runner';

const ATTACHMENT_ID = attachmentIdSchema.parse('attachment.purge.001');

/** An instant a whole number of days before the run, for ageing a retirable unit. */
function daysAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}

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
type ArchivedFieldValueValue = ReturnType<typeof archivedFieldValueSchema.parse>;
type NoteValue = ReturnType<typeof noteSchema.parse>;
type VaultAggregate = Awaited<
  ReturnType<InstanceType<typeof VaultReadSession>['show']>
>;
type PurgePlanValue = Awaited<ReturnType<typeof executeProductionPurgePreview>>['plan'];

/** The definition an archived value carries, which is by construction not an active field. */
function archivedDefinition(
  stableKey: string,
  label: string,
  options: Readonly<{
    type: 'secret' | 'item-reference' | 'attachment';
    sortOrder: number;
  }>,
): FieldDefinitionValue {
  const sensitive = options.type === 'secret';
  return fieldDefinitionSchema.parse({
    id: `field.${stableKey}`,
    stableKey,
    label,
    type: options.type,
    required: false,
    sensitive,
    repeatable: false,
    copyable: sensitive,
    searchableLocally: false,
    showInPreview: false,
    copyPolicy: sensitive ? 'allowed' : 'never',
    revealPolicy: sensitive ? 'timed' : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    exportPolicy: sensitive ? 'guarded' : 'encrypted-only',
    sortOrder: options.sortOrder,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

/**
 * One archived value, aged and holding the scalar its definition requires.
 *
 * Archiving stores the value in the orphaned state around the value it had while
 * active, which is what the payload schema validates the definition against, so
 * the fixture is built the same way rather than approximated.
 */
function archived(
  definition: FieldDefinitionValue,
  scalar: Readonly<Record<string, unknown>>,
  options: Readonly<{
    reason: ArchivedFieldValueValue['reason'];
    ageDays: number;
    templateId: TemplateId;
    templateVersion: TemplateVersion;
  }>,
): ArchivedFieldValueValue {
  return archivedFieldValueSchema.parse({
    definition,
    value: {
      version: 1,
      state: 'orphaned',
      originalValue: {
        version: 1,
        state: 'present',
        content: { cardinality: 'single', value: scalar },
      },
    },
    sourceTemplateId: options.templateId,
    sourceTemplateVersion: options.templateVersion,
    archivedAt: daysAgo(options.ageDays),
    reason: options.reason,
  });
}

/** One note, archived when an age is given and active when it is not. */
function note(
  id: string,
  title: string,
  options: Readonly<{ sortOrder: number; ageDays?: number }>,
): NoteValue {
  return noteSchema.parse({
    id: noteIdSchema.parse(id),
    title,
    content: `${NOTE_CANARY} ${title}`,
    isSensitive: true,
    isPinned: false,
    tags: [],
    sortOrder: options.sortOrder,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
    ...(options.ageDays === undefined ? {} : { archivedAt: daysAgo(options.ageDays) }),
  });
}

/** Every unit of one category the plan reported, so assertions never depend on order. */
function unitsOf(plan: PurgePlanValue, unitId: string): PurgePlanValue['units'] {
  return plan.units.filter((unit) => unit.unitId === unitId);
}

/** The one reported unit for an identity, which a plan must never duplicate. */
function unitFor(
  plan: PurgePlanValue,
  unitId: string,
): PurgePlanValue['units'][number] {
  const found = unitsOf(plan, unitId);
  const [first] = found;
  if (first === undefined) throw new Error(`No purge unit for ${unitId}`);
  expect(found).toHaveLength(1);
  return first;
}

function totalFor(
  plan: PurgePlanValue,
  category: PurgePlanValue['categories'][number],
): PurgePlanValue['totals'][number] {
  const found = plan.totals.find((total) => total.category === category);
  if (found === undefined) throw new Error(`No totals row for ${category}`);
  return found;
}

function expectNoPlaintext(value: unknown): void {
  const serialized = JSON.stringify(value ?? null);
  for (const canary of [TITLE_CANARY, SECRET_CANARY, NOTE_CANARY]) {
    expect(serialized).not.toContain(canary);
  }
}

type Harness = Readonly<{
  store: SqliteSyncLocalStore;
  service: VaultMutationService;
  mutationOptions: ProductionMutationOptions;
  readOptions: ProductionPurgeReadOptions;
  readAggregate: (group: string, title: string) => Promise<VaultAggregate>;
  currentRevision: (id: ItemId) => Promise<number>;
  installItem: (
    group: string,
    title: string,
    overrides: Readonly<Record<string, unknown>>,
  ) => Promise<void>;
  installGroupNotes: (
    group: string,
    title: string,
    notes: readonly NoteValue[],
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
    // Archived values and aged notes reach a credential through archiving, import,
    // or sync rather than through these commands, and none of those can be asked
    // for a past timestamp, so the fixture writes them the way a sync page would:
    // one whole-record write.
    installItem: async (
      group: string,
      title: string,
      overrides: Readonly<Record<string, unknown>>,
    ): Promise<void> => {
      const aggregate = await readAggregate(group, title);
      await service.updateItem(
        aggregate.group.id,
        itemPayloadSchema.parse({ ...aggregate.item, ...overrides }),
      );
    },
    installGroupNotes: async (
      group: string,
      title: string,
      notes: readonly NoteValue[],
    ): Promise<void> => {
      const aggregate = await readAggregate(group, title);
      await service.updateGroup(
        groupPayloadSchema.parse({ ...aggregate.group, notes: [...notes] }),
      );
    },
    close: async (): Promise<void> => {
      zeroize(rootKey);
      await environment.close();
      await backend.close();
    },
  };
}

describe('production purge adapters', () => {
  let tempHome: string;

  beforeEach(async () => {
    tempHome = join(
      tmpdir(),
      `kavrix-prod-purge-test-${Math.random().toString(36).slice(2)}`,
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

  it('destroys archived field values as one revision-bound mutation and reports what it unbinds', async () => {
    const harness = await openHarness(tempHome);
    const { mutationOptions, readOptions, store } = harness;
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

      const seeded = await harness.readAggregate(GROUP, ROOT_TITLE);
      const templateContext = {
        templateId: seeded.item.templateId,
        templateVersion: seeded.item.templateVersion,
      } as const;
      const token = archivedDefinition('legacy-token', 'Legacy Token', {
        type: 'secret',
        sortOrder: 0,
      });
      const owner = archivedDefinition('legacy-owner', 'Legacy Owner', {
        type: 'item-reference',
        sortOrder: 1,
      });
      const document = archivedDefinition('legacy-doc', 'Legacy Document', {
        type: 'attachment',
        sortOrder: 2,
      });
      const tokenArchived = archived(
        token,
        { kind: 'secret', value: SECRET_CANARY },
        {
          reason: 'user-archived',
          ageDays: 40,
          ...templateContext,
        },
      );
      await harness.installItem(GROUP, ROOT_TITLE, {
        archivedFieldValues: [
          tokenArchived,
          // Retired two days ago, so a thirty-day window must keep it, and it is
          // the only surviving binding of the relation while it does.
          archived(
            owner,
            { kind: 'item-reference', itemId: target.credentialId },
            {
              reason: 'template-field-removed',
              ageDays: 2,
              ...templateContext,
            },
          ),
          archived(
            document,
            { kind: 'attachment-reference', attachmentId: ATTACHMENT_ID },
            {
              reason: 'type-conversion',
              ageDays: 40,
              ...templateContext,
            },
          ),
        ],
        relatedItemIds: [target.credentialId],
        attachmentIds: [ATTACHMENT_ID],
      });

      // 1. The preview states a fate for every unit and writes nothing: the two
      //    aged values are purgeable, the young one is retained by the window, and
      //    the attachment has no local destruction path at all.
      const installedRevision = await harness.currentRevision(root.credentialId);
      const preview = await executeProductionPurgePreview(readOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        olderThanDays: 30,
      });
      expect(preview.vaultId).toBe(VAULT_ID);
      expect(unitFor(preview.plan, 'legacy-token')).toMatchObject({
        category: 'archived-field',
        disposition: 'purgeable',
        credentialId: root.credentialId,
        label: 'Legacy Token',
        ageDays: 40,
      });
      expect(unitFor(preview.plan, 'legacy-doc')).toMatchObject({
        category: 'archived-field',
        disposition: 'purgeable',
      });
      // A removed template field is reported as an orphan rather than as an
      // ordinary archived field, because the two are cleaned up for different
      // reasons.
      expect(unitFor(preview.plan, 'legacy-owner')).toMatchObject({
        category: 'orphan-value',
        disposition: 'retained',
        ageDays: 2,
      });
      expect(unitFor(preview.plan, 'legacy-owner').reason).toContain('30-day');
      expect(unitFor(preview.plan, ATTACHMENT_ID)).toMatchObject({
        category: 'attachment',
        disposition: 'unsupported',
      });
      expect(preview.plan.olderThanDays).toBe(30);
      expect(preview.plan.truncated).toBe(false);
      expect(preview.plan.unreferencedAttachments).toStrictEqual([
        { credentialId: root.credentialId, attachmentId: ATTACHMENT_ID },
      ]);
      // Nothing is unbound by a purge the window would stop.
      expect(preview.plan.retiredRelations).toStrictEqual([]);
      expect(await harness.currentRevision(root.credentialId)).toBe(installedRevision);

      // 2. `--field` resolves against the archived definitions, which are absent
      //    from both the item's fields and its template's, and destroys only that
      //    one value.
      const byField = await executeProductionPurgeFields(mutationOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        fieldKey: 'Legacy Token',
      });
      expect(byField).toMatchObject({
        vaultId: VAULT_ID,
        credentialId: root.credentialId,
        title: ROOT_TITLE,
        retiredRelations: [],
        unreferencedAttachments: [],
      });
      expect(byField.purged).toStrictEqual([
        {
          fieldKey: 'legacy-token',
          fieldLabel: 'Legacy Token',
          reason: 'user-archived',
          archivedAt: tokenArchived.archivedAt,
          ageDays: 40,
        },
      ]);
      expect(byField.revision).toBe(byField.previousRevision + 1);

      // 3. A windowed purge destroys the aged value and leaves the young one, and
      //    the attachment it strands is reported instead of unlinked: the ID is the
      //    operator's only handle on a blob this client cannot read.
      const windowed = await executeProductionPurgeFields(mutationOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        olderThanDays: 30,
      });
      expect(windowed.purged.map(({ fieldKey }) => fieldKey)).toStrictEqual([
        'legacy-doc',
      ]);
      expect(windowed.unreferencedAttachments).toStrictEqual([ATTACHMENT_ID]);
      expect(windowed.retiredRelations).toStrictEqual([]);
      expect(windowed.revision).toBe(windowed.previousRevision + 1);

      const afterWindowed = await harness.readAggregate(GROUP, ROOT_TITLE);
      expect(
        afterWindowed.item.archivedFieldValues.map(
          ({ definition }) => definition.stableKey,
        ),
      ).toStrictEqual(['legacy-owner']);
      // Reported, never unlinked.
      expect([...afterWindowed.item.attachmentIds]).toStrictEqual([ATTACHMENT_ID]);
      // Still bound by the surviving archived value.
      expect([...afterWindowed.item.relatedItemIds]).toStrictEqual([
        target.credentialId,
      ]);

      // 4. Retrying an interrupted purge is idempotent: the values are already
      //    gone, so nothing is selected and no second revision is consumed.
      const retried = await executeProductionPurgeFields(mutationOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        olderThanDays: 30,
      });
      expect(retried.purged).toStrictEqual([]);
      expect(retried.retiredRelations).toStrictEqual([]);
      expect(retried.unreferencedAttachments).toStrictEqual([]);
      expect(retried.revision).toBe(retried.previousRevision);
      expect(await harness.currentRevision(root.credentialId)).toBe(windowed.revision);

      // 5. A revision the caller did not name is refused before anything is
      //    destroyed, and the refusal consumes no revision.
      await expect(
        executeProductionPurgeFields(mutationOptions, {
          groupQuery: GROUP,
          credentialQuery: ROOT_TITLE,
          ifRevision: windowed.revision + 5,
        }),
      ).rejects.toThrow(SyncConflictError);
      expect(await harness.currentRevision(root.credentialId)).toBe(windowed.revision);

      // 6. Purging the last binding retires the relation in the same mutation,
      //    because the payload requires every field reference to resolve through
      //    the relation list and nothing else would ever clear it.
      const unbound = await executeProductionPurgeFields(mutationOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        ifRevision: windowed.revision,
      });
      expect(unbound.purged.map(({ fieldKey }) => fieldKey)).toStrictEqual([
        'legacy-owner',
      ]);
      expect(unbound.retiredRelations).toStrictEqual([target.credentialId]);
      const afterUnbound = await harness.readAggregate(GROUP, ROOT_TITLE);
      expect([...afterUnbound.item.archivedFieldValues]).toStrictEqual([]);
      expect([...afterUnbound.item.relatedItemIds]).toStrictEqual([]);
      expect(afterUnbound.item.revision).toBe(unbound.revision);

      // 7. A purge with nothing left to reach reports an empty vault as examined
      //    rather than as unexaminable.
      const emptied = await executeProductionPurgePreview(readOptions, {
        groupQuery: GROUP,
        categories: ['archived-field', 'orphan-value'],
      });
      expect(emptied.plan.purgeableCount).toBe(0);
      expect(totalFor(emptied.plan, 'archived-field')).toMatchObject({
        purgeable: 0,
        retained: 0,
        serverRetained: 0,
        unsupported: 0,
      });

      // 8. None of it leaked: no title, no archived secret, and no note body in
      //    the stored records or in the queued mutations.
      for (const id of [root.credentialId, target.credentialId]) {
        expectNoPlaintext(await store.getCurrentItem(VAULT_ID, id));
      }
      expectNoPlaintext(await store.listPendingMutations(VAULT_ID));
    } finally {
      await harness.close();
    }
  });

  it('purges archived notes per record and names the categories it cannot destroy', async () => {
    const harness = await openHarness(tempHome);
    const { mutationOptions, readOptions, store } = harness;
    try {
      await executeProductionCreateGroup(mutationOptions, { name: GROUP });
      const root = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: GROUP,
        title: ROOT_TITLE,
      });
      const doomed = await executeProductionCreateCredential(mutationOptions, {
        groupQuery: GROUP,
        title: DOOMED_TITLE,
      });

      const activeNote = note('note.active.001', 'Runbook', { sortOrder: 0 });
      const agedNote = note('note.aged.001', 'Old Runbook', {
        sortOrder: 1,
        ageDays: 40,
      });
      const youngNote = note('note.young.001', 'Recent Runbook', {
        sortOrder: 2,
        ageDays: 2,
      });
      await harness.installItem(GROUP, ROOT_TITLE, {
        notes: [activeNote, agedNote, youngNote],
      });
      const groupActiveNote = note('note.group.active', 'Group Runbook', {
        sortOrder: 0,
      });
      const groupAgedNote = note('note.group.aged', 'Old Group Runbook', {
        sortOrder: 1,
        ageDays: 40,
      });
      await harness.installGroupNotes(GROUP, ROOT_TITLE, [
        groupActiveNote,
        groupAgedNote,
      ]);

      // A tombstoned credential is the category a client must not destroy early.
      const doomedAggregate = await harness.readAggregate(GROUP, DOOMED_TITLE);
      await harness.service.deleteItem(
        doomedAggregate.group.id,
        doomedAggregate.item.id,
        doomedAggregate.item.revision,
      );

      // 1. The whole-vault preview separates what this client can destroy from what
      //    it may not and from what it cannot even enumerate.
      const preview = await executeProductionPurgePreview(readOptions, {});
      expect(unitFor(preview.plan, agedNote.id)).toMatchObject({
        category: 'note',
        disposition: 'purgeable',
        credentialId: root.credentialId,
        label: 'Old Runbook',
        ageDays: 40,
      });
      expect(unitFor(preview.plan, groupAgedNote.id)).toMatchObject({
        category: 'note',
        disposition: 'purgeable',
        label: 'Old Group Runbook',
      });
      expect(unitFor(preview.plan, groupAgedNote.id)).not.toHaveProperty(
        'credentialId',
      );
      // An active note is not a retirable unit at all, so it is absent rather than
      // reported as retained.
      expect(unitsOf(preview.plan, activeNote.id)).toStrictEqual([]);
      expect(unitsOf(preview.plan, groupActiveNote.id)).toStrictEqual([]);
      const tombstoned = unitFor(preview.plan, doomed.credentialId);
      expect(tombstoned).toMatchObject({
        category: 'credential',
        disposition: 'server-retained',
      });
      expect(typeof tombstoned.tombstone?.deletedAt).toBe('string');
      // A deleted record carries no readable title, so it is named by ID.
      expect(tombstoned.label).toBe(doomed.credentialId);
      expect(unitFor(preview.plan, 'history')).toMatchObject({
        category: 'history',
        disposition: 'unsupported',
      });
      expect(preview.undiscoverableCategories).toHaveLength(1);
      expect(preview.undiscoverableCategories[0]?.category).toBe('group');
      expect(preview.undiscoverableCategories[0]?.reason).toContain('deleted group');
      // Every category is present in the totals, so an absent one reads as zero
      // rather than as unexamined.
      expect(preview.plan.totals.map(({ category }) => category)).toStrictEqual([
        ...preview.plan.categories,
      ]);
      // No window was requested and none is assumed, so every archived note is
      // purgeable — including the one a thirty-day window would hold back.
      expect(preview.plan.olderThanDays).toBeUndefined();
      expect(unitFor(preview.plan, youngNote.id)).toMatchObject({
        category: 'note',
        disposition: 'purgeable',
        ageDays: 2,
      });
      expect(totalFor(preview.plan, 'note').purgeable).toBe(3);
      expect(totalFor(preview.plan, 'note').retained).toBe(0);

      // 2. A category filter narrows the inventory without silently hiding the
      //    warning about what is unenumerable.
      const filtered = await executeProductionPurgePreview(readOptions, {
        categories: ['note'],
      });
      expect(filtered.plan.units.every((unit) => unit.category === 'note')).toBe(true);
      expect(filtered.undiscoverableCategories).toStrictEqual([]);

      // 3. Purging a credential's notes destroys the aged one, keeps the note the
      //    window still covers, and never reaches the active note.
      const credentialPurge = await executeProductionPurgeNotes(mutationOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        olderThanDays: 30,
      });
      expect(credentialPurge).toMatchObject({
        vaultId: VAULT_ID,
        credentialId: root.credentialId,
        credentialTitle: ROOT_TITLE,
      });
      expect(credentialPurge.purged).toStrictEqual([
        {
          noteId: agedNote.id,
          title: 'Old Runbook',
          archivedAt: agedNote.archivedAt,
          ageDays: 40,
        },
      ]);
      expect(credentialPurge.revision).toBe(credentialPurge.previousRevision + 1);
      const afterCredential = await harness.readAggregate(GROUP, ROOT_TITLE);
      expect(afterCredential.item.notes.map(({ id }) => id)).toStrictEqual([
        activeNote.id,
        youngNote.id,
      ]);
      // The group holds its own notes, and a credential purge did not move them.
      expect(afterCredential.group.notes.map(({ id }) => id)).toStrictEqual([
        groupActiveNote.id,
        groupAgedNote.id,
      ]);

      // 4. `--note` refuses an active note by ID, so a purge can never be confused
      //    with `note archive`.
      await expect(
        executeProductionPurgeNotes(mutationOptions, {
          groupQuery: GROUP,
          credentialQuery: ROOT_TITLE,
          noteId: activeNote.id,
        }),
      ).rejects.toThrow(NotFoundError);
      expect(await harness.currentRevision(root.credentialId)).toBe(
        credentialPurge.revision,
      );

      // 5. A window that covers nothing consumes no revision.
      const untouched = await executeProductionPurgeNotes(mutationOptions, {
        groupQuery: GROUP,
        credentialQuery: ROOT_TITLE,
        olderThanDays: 30,
      });
      expect(untouched.purged).toStrictEqual([]);
      expect(untouched.revision).toBe(untouched.previousRevision);

      // 6. A stale expected revision is refused for a group exactly as for a
      //    credential.
      const groupAggregate = await harness.readAggregate(GROUP, ROOT_TITLE);
      await expect(
        executeProductionPurgeNotes(mutationOptions, {
          groupQuery: GROUP,
          ifRevision: groupAggregate.group.revision + 5,
        }),
      ).rejects.toThrow(SyncConflictError);

      // 7. The group's own notes purge against the group's revision, and only the
      //    archived one goes.
      const groupPurge = await executeProductionPurgeNotes(mutationOptions, {
        groupQuery: GROUP,
        noteId: groupAgedNote.id,
        ifRevision: groupAggregate.group.revision,
      });
      expect(groupPurge).not.toHaveProperty('credentialId');
      expect(groupPurge.purged.map(({ noteId }) => noteId)).toStrictEqual([
        groupAgedNote.id,
      ]);
      expect(groupPurge.revision).toBe(groupPurge.previousRevision + 1);
      const afterGroup = await harness.readAggregate(GROUP, ROOT_TITLE);
      expect(afterGroup.group.notes.map(({ id }) => id)).toStrictEqual([
        groupActiveNote.id,
      ]);
      expect(afterGroup.group.revision).toBe(groupPurge.revision);

      // 8. None of it leaked: no title, no archived secret, and no note body in the
      //    stored records or in the queued mutations.
      for (const id of [root.credentialId, doomed.credentialId]) {
        expectNoPlaintext(await store.getCurrentItem(VAULT_ID, id));
      }
      expectNoPlaintext(await store.getCurrentGroup(VAULT_ID, afterGroup.group.id));
      expectNoPlaintext(await store.listPendingMutations(VAULT_ID));
    } finally {
      await harness.close();
    }
  });
});
