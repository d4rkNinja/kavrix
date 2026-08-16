import {
  attachmentIdSchema,
  fieldDefinitionSchema,
  groupPayloadSchema,
  itemPayloadSchema,
  noteSchema,
  type ArchivedFieldValue,
  type AttachmentId,
  type FieldDefinition,
  type GroupPayload,
  type ItemId,
  type ItemPayload,
  type Note,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import { ValidationError } from '../src/errors.js';
import {
  MAX_PURGE_PLAN_UNITS,
  MAX_PURGE_RETENTION_DAYS,
  PURGE_CATEGORIES,
  planRetentionPurge,
  purgeAgeDays,
  retiredRelationIds,
  selectArchivedFieldValues,
  selectArchivedNotes,
  unreferencedAttachmentIds,
  type PurgeCategory,
  type PurgePlan,
  type PurgeScope,
  type PurgeUnit,
} from '../src/policies/retention-purge.js';

const NOW = '2026-08-16T00:00:00.000Z';

/**
 * The values a purge plan must never carry.
 *
 * A plan names what would be destroyed. It reports labels a listing command
 * already shows and nothing else, so a stored secret or a note body appearing
 * anywhere in the serialized plan fails on these exact strings.
 */
const SECRET_CANARY = 'canary-secret-value';
const NOTE_CANARY = 'canary-note-content';

function id(index: number): ItemId {
  return `item.${String(index)}` as ItemId;
}

function attachmentId(index: number): AttachmentId {
  return attachmentIdSchema.parse(`attachment.${String(index)}`);
}

/** An ISO instant a whole number of days before `NOW`. */
function daysAgo(days: number): string {
  return new Date(Date.parse(NOW) - days * 86_400_000).toISOString();
}

interface FieldOverrides {
  readonly type?: FieldDefinition['type'];
  readonly label?: string;
  readonly sensitive?: boolean;
  readonly sortOrder?: number;
}

function field(key: string, overrides: FieldOverrides = {}): FieldDefinition {
  const sensitive = overrides.sensitive ?? false;
  return fieldDefinitionSchema.parse({
    id: `field.${key}`,
    stableKey: key,
    label: overrides.label ?? key,
    type: overrides.type ?? (sensitive ? 'secret' : 'text'),
    required: false,
    sensitive,
    repeatable: false,
    copyable: true,
    searchableLocally: false,
    showInPreview: false,
    copyPolicy: 'allowed',
    revealPolicy: sensitive ? 'timed' : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    exportPolicy: 'guarded',
    sortOrder: overrides.sortOrder ?? 0,
    createdAt: daysAgo(400),
    updatedAt: daysAgo(400),
  });
}

function group(index: number, notes: readonly Note[] = []): GroupPayload {
  return groupPayloadSchema.parse({
    id: `group.${String(index)}`,
    vaultId: 'vault.1',
    name: `Group ${String(index)}`,
    slug: `group-${String(index)}`,
    aliases: [],
    tags: [],
    notes,
    template: {
      id: `template.${String(index)}`,
      name: 'Custom',
      version: 1,
      fields: [],
      createdAt: daysAgo(400),
      updatedAt: daysAgo(400),
    },
    sortOrder: index,
    revision: 1,
    createdAt: daysAgo(400),
    updatedAt: daysAgo(400),
  });
}

interface ArchivedOverrides {
  readonly reason?: ArchivedFieldValue['reason'];
  readonly archivedAt?: string;
  readonly value?: unknown;
}

/**
 * The value an archived field kept, which must still be valid for its definition.
 *
 * A secret field keeps the canary precisely so that a plan leaking an archived
 * value fails loudly rather than subtly.
 */
function originalFor(definition: FieldDefinition): unknown {
  const scalar =
    definition.type === 'secret'
      ? { kind: 'secret', value: SECRET_CANARY }
      : { kind: 'text', value: 'retired-plain-text' };
  return {
    version: 1,
    state: 'present',
    content: { cardinality: 'single', value: scalar },
  };
}

/** An archived field value, which is the shape a purge is asked to destroy. */
function archived(
  definition: FieldDefinition,
  overrides: ArchivedOverrides = {},
): unknown {
  return {
    definition,
    value: {
      version: 1,
      state: 'orphaned',
      originalValue: overrides.value ?? originalFor(definition),
    },
    sourceTemplateId: 'template.1',
    sourceTemplateVersion: 1,
    archivedAt: overrides.archivedAt ?? daysAgo(120),
    reason: overrides.reason ?? 'user-archived',
  };
}

/** An archived value that keeps a relation alive with no active field behind it. */
function archivedReference(definition: FieldDefinition, targetId: ItemId): unknown {
  return archived(definition, {
    value: {
      version: 1,
      state: 'present',
      content: {
        cardinality: 'single',
        value: { kind: 'item-reference', itemId: targetId },
      },
    },
  });
}

/** An archived value that keeps an attachment reference alive. */
function archivedAttachment(
  definition: FieldDefinition,
  target: AttachmentId,
): unknown {
  return archived(definition, {
    value: {
      version: 1,
      state: 'present',
      content: {
        cardinality: 'single',
        value: { kind: 'attachment-reference', attachmentId: target },
      },
    },
  });
}

function secretValue(definition: FieldDefinition, value: string): unknown {
  return {
    fieldId: definition.id,
    stableKey: definition.stableKey,
    value: {
      version: 1,
      state: 'present',
      content: { cardinality: 'single', value: { kind: 'secret', value } },
    },
    updatedAt: daysAgo(400),
  };
}

function referenceValue(definition: FieldDefinition, targetId: ItemId): unknown {
  return {
    fieldId: definition.id,
    stableKey: definition.stableKey,
    value: {
      version: 1,
      state: 'present',
      content: {
        cardinality: 'single',
        value: { kind: 'item-reference', itemId: targetId },
      },
    },
    updatedAt: daysAgo(400),
  };
}

function note(index: number, archivedAt?: string): Note {
  return noteSchema.parse({
    id: `note.${String(index)}`,
    title: `Note ${String(index)}`,
    content: NOTE_CANARY,
    isSensitive: true,
    isPinned: false,
    tags: [],
    sortOrder: index,
    createdAt: daysAgo(400),
    updatedAt: daysAgo(400),
    ...(archivedAt === undefined ? {} : { archivedAt }),
  });
}

interface ItemOverrides {
  readonly title?: string;
  readonly itemFields?: readonly FieldDefinition[];
  readonly itemValues?: readonly unknown[];
  readonly archivedFieldValues?: readonly unknown[];
  readonly relatedItemIds?: readonly ItemId[];
  readonly attachmentIds?: readonly AttachmentId[];
  readonly notes?: readonly Note[];
}

function item(
  owner: GroupPayload,
  index: number,
  overrides: ItemOverrides = {},
): ItemPayload {
  return itemPayloadSchema.parse({
    version: 1,
    id: id(index),
    vaultId: owner.vaultId,
    groupId: owner.id,
    templateId: owner.template.id,
    title: overrides.title ?? `Credential ${String(index)}`,
    slug: `credential-${String(index)}`,
    aliases: [],
    templateVersion: owner.template.version,
    templateValues: [],
    itemFields: overrides.itemFields ?? [],
    itemValues: overrides.itemValues ?? [],
    archivedFieldValues: overrides.archivedFieldValues ?? [],
    notes: overrides.notes ?? [],
    tags: [],
    favorite: false,
    productionSensitive: false,
    relatedItemIds: overrides.relatedItemIds ?? [],
    attachmentIds: overrides.attachmentIds ?? [],
    copySequences: [],
    revision: 1,
    createdAt: daysAgo(400),
    updatedAt: daysAgo(400),
  });
}

function unitsOf(plan: PurgePlan, category: PurgeCategory): readonly PurgeUnit[] {
  return plan.units.filter((unit) => unit.category === category);
}

function totalOf(plan: PurgePlan, category: PurgeCategory): number {
  const total = plan.totals.find((candidate) => candidate.category === category);
  if (total === undefined) throw new Error(`missing total for ${category}`);
  return total.purgeable;
}

const RETIRED_FIELD = field('legacy_token', { sensitive: true, label: 'Legacy token' });
const ORPHANED_FIELD = field('dropped_note', { label: 'Dropped note', sortOrder: 1 });
const REFERENCE_FIELD = field('depends_on', {
  type: 'item-reference',
  label: 'Depends on',
  sortOrder: 2,
});
const ATTACHMENT_FIELD = field('evidence', {
  type: 'attachment',
  label: 'Evidence',
  sortOrder: 3,
});
const ACTIVE_FIELD = field('active_token', { sensitive: true, sortOrder: 4 });
// An archived definition may never collide with an active one, so a field that is
// only ever archived gets its own key rather than shadowing the active field above.
const RETIRED_REFERENCE_FIELD = field('former_dependency', {
  type: 'item-reference',
  label: 'Former dependency',
  sortOrder: 5,
});
const SECOND_RETIRED_REFERENCE_FIELD = field('former_upstream', {
  type: 'item-reference',
  label: 'Former upstream',
  sortOrder: 6,
});
const RETIRED_ATTACHMENT_FIELD = field('old_evidence', {
  type: 'attachment',
  label: 'Old evidence',
  sortOrder: 7,
});

describe('retention purge plan', () => {
  it('reports archived field values as purgeable without disclosing their content', () => {
    const owner = group(1);
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [
        {
          group: owner,
          credentials: [
            item(owner, 1, { archivedFieldValues: [archived(RETIRED_FIELD)] }),
          ],
        },
      ],
    });

    const units = unitsOf(plan, 'archived-field');
    expect(units).toHaveLength(1);
    expect(units[0]).toMatchObject({
      category: 'archived-field',
      disposition: 'purgeable',
      groupId: owner.id,
      groupName: owner.name,
      credentialId: id(1),
      credentialTitle: 'Credential 1',
      unitId: RETIRED_FIELD.stableKey,
      label: 'Legacy token',
      retiredAt: daysAgo(120),
      ageDays: 120,
    });
    expect(units[0]?.reason).toBeUndefined();
    expect(JSON.stringify(plan)).not.toContain(SECRET_CANARY);
  });

  it('separates a template-removed orphan value from an operator-archived field', () => {
    const owner = group(1);
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [
        {
          group: owner,
          credentials: [
            item(owner, 1, {
              archivedFieldValues: [
                archived(RETIRED_FIELD, { reason: 'type-conversion' }),
                archived(ORPHANED_FIELD, { reason: 'template-field-removed' }),
              ],
            }),
          ],
        },
      ],
    });

    expect(unitsOf(plan, 'archived-field').map((unit) => unit.unitId)).toEqual([
      RETIRED_FIELD.stableKey,
    ]);
    expect(unitsOf(plan, 'orphan-value').map((unit) => unit.unitId)).toEqual([
      ORPHANED_FIELD.stableKey,
    ]);
    expect(totalOf(plan, 'archived-field')).toBe(1);
    expect(totalOf(plan, 'orphan-value')).toBe(1);
    expect(plan.purgeableCount).toBe(2);
  });

  it('retains a unit younger than the requested window and states why', () => {
    const owner = group(1);
    const plan = planRetentionPurge({
      now: NOW,
      olderThanDays: 90,
      scopes: [
        {
          group: owner,
          credentials: [
            item(owner, 1, {
              archivedFieldValues: [
                archived(RETIRED_FIELD, { archivedAt: daysAgo(120) }),
                archived(ORPHANED_FIELD, { archivedAt: daysAgo(10) }),
              ],
            }),
          ],
        },
      ],
    });

    const retained = plan.units.find(
      (unit) => unit.unitId === ORPHANED_FIELD.stableKey,
    );
    expect(retained?.disposition).toBe('retained');
    expect(retained?.reason).toContain('90');
    expect(retained?.ageDays).toBe(10);
    expect(plan.olderThanDays).toBe(90);
    expect(plan.purgeableCount).toBe(1);
  });

  it('reports an archived note and never an active one', () => {
    const owner = group(1, [note(1, daysAgo(200)), note(2)]);
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [
        {
          group: owner,
          credentials: [item(owner, 1, { notes: [note(3, daysAgo(5))] })],
        },
      ],
    });

    const units = unitsOf(plan, 'note');
    expect(units.map((unit) => unit.unitId)).toEqual(['note.1', 'note.3']);
    expect(units[0]).toMatchObject({
      disposition: 'purgeable',
      groupId: owner.id,
      label: 'Note 1',
      ageDays: 200,
    });
    expect(units[0]?.credentialId).toBeUndefined();
    expect(units[1]?.credentialId).toBe(id(1));
    expect(JSON.stringify(plan)).not.toContain(NOTE_CANARY);
  });

  it('never offers a tombstoned credential or group for local purge', () => {
    const owner = group(1);
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [
        {
          group: owner,
          credentials: [],
          groupTombstone: { deletedAt: daysAgo(30), purgeAfter: daysAgo(-60) },
          deletedCredentials: [
            { credentialId: id(9), tombstone: { deletedAt: daysAgo(30) } },
          ],
        },
      ],
    });

    const credential = unitsOf(plan, 'credential');
    const deletedGroup = unitsOf(plan, 'group');
    expect(credential).toHaveLength(1);
    expect(deletedGroup).toHaveLength(1);
    for (const unit of [...credential, ...deletedGroup]) {
      expect(unit.disposition).toBe('server-retained');
      expect(unit.reason).toContain('retention');
      expect(unit.tombstone?.deletedAt).toBe(daysAgo(30));
    }
    expect(deletedGroup[0]?.tombstone?.purgeAfter).toBe(daysAgo(-60));
    expect(plan.purgeableCount).toBe(0);
  });

  it('reports an unreferenced attachment as unsupported and names the real command', () => {
    const owner = group(1);
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [
        {
          group: owner,
          credentials: [
            item(owner, 1, {
              attachmentIds: [attachmentId(1), attachmentId(2)],
              archivedFieldValues: [
                archivedAttachment(RETIRED_ATTACHMENT_FIELD, attachmentId(2)),
              ],
            }),
          ],
        },
      ],
    });

    const units = unitsOf(plan, 'attachment');
    expect(units.map((unit) => unit.unitId)).toEqual([
      attachmentId(1),
      attachmentId(2),
    ]);
    for (const unit of units) {
      expect(unit.disposition).toBe('unsupported');
      expect(unit.reason).toContain('attachment delete');
    }
    expect(totalOf(plan, 'attachment')).toBe(0);
  });

  it('reports revision history once, as a limitation rather than as work', () => {
    const owner = group(1);
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [
        { group: owner, credentials: [item(owner, 1), item(owner, 2)] },
        { group: group(2), credentials: [] },
      ],
    });

    const units = unitsOf(plan, 'history');
    expect(units).toHaveLength(1);
    expect(units[0]).toMatchObject({ disposition: 'unsupported', unitId: 'history' });
    expect(units[0]?.reason).toContain('no revision history');
    expect(units[0]?.groupId).toBeUndefined();
  });

  it('retires only the relations no surviving value would bind', () => {
    const owner = group(1);
    const holder = item(owner, 1, {
      itemFields: [REFERENCE_FIELD],
      itemValues: [referenceValue(REFERENCE_FIELD, id(2))],
      archivedFieldValues: [
        archivedReference(RETIRED_REFERENCE_FIELD, id(3)),
        archivedReference(SECOND_RETIRED_REFERENCE_FIELD, id(2)),
      ],
      relatedItemIds: [id(2), id(3)],
    });
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [{ group: owner, credentials: [holder, item(owner, 2), item(owner, 3)] }],
    });

    expect(plan.retiredRelations).toEqual([{ credentialId: id(1), targetId: id(3) }]);
  });

  it('keeps a relation that a retained archived value still binds', () => {
    const owner = group(1);
    const holder = item(owner, 1, {
      archivedFieldValues: [
        archivedReference(RETIRED_REFERENCE_FIELD, id(2)),
        archived(ORPHANED_FIELD, { archivedAt: daysAgo(1) }),
      ],
      relatedItemIds: [id(2)],
    });
    const purgeable = selectArchivedFieldValues(holder, {
      now: NOW,
      olderThanDays: 30,
    });
    expect(purgeable.map(({ definition }) => definition.stableKey)).toEqual([
      RETIRED_REFERENCE_FIELD.stableKey,
    ]);
    expect(retiredRelationIds(holder, purgeable)).toEqual([id(2)]);
    expect(retiredRelationIds(holder, [])).toEqual([]);
  });

  it('reports the attachments a purge would leave unreferenced', () => {
    const owner = group(1);
    const holder = item(owner, 1, {
      attachmentIds: [attachmentId(1)],
      archivedFieldValues: [
        archivedAttachment(RETIRED_ATTACHMENT_FIELD, attachmentId(1)),
      ],
    });
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [{ group: owner, credentials: [holder] }],
    });

    expect(plan.unreferencedAttachments).toEqual([
      { credentialId: id(1), attachmentId: attachmentId(1) },
    ]);
    expect(
      unreferencedAttachmentIds(
        holder,
        selectArchivedFieldValues(holder, { now: NOW }),
      ),
    ).toEqual([attachmentId(1)]);
  });

  it('does not report an attachment an active value still names', () => {
    const owner = group(1);
    const holder = item(owner, 1, {
      itemFields: [ATTACHMENT_FIELD],
      itemValues: [
        {
          fieldId: ATTACHMENT_FIELD.id,
          stableKey: ATTACHMENT_FIELD.stableKey,
          value: {
            version: 1,
            state: 'present',
            content: {
              cardinality: 'single',
              value: { kind: 'attachment-reference', attachmentId: attachmentId(1) },
            },
          },
          updatedAt: daysAgo(400),
        },
      ],
      attachmentIds: [attachmentId(1)],
      archivedFieldValues: [archived(RETIRED_FIELD)],
    });
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [{ group: owner, credentials: [holder] }],
    });

    expect(plan.unreferencedAttachments).toEqual([]);
    expect(unitsOf(plan, 'attachment')).toEqual([]);
  });

  it('restricts the plan to the requested categories', () => {
    const owner = group(1, [note(1, daysAgo(200))]);
    const plan = planRetentionPurge({
      now: NOW,
      categories: ['note'],
      scopes: [
        {
          group: owner,
          credentials: [
            item(owner, 1, { archivedFieldValues: [archived(RETIRED_FIELD)] }),
          ],
        },
      ],
    });

    expect(plan.units.map((unit) => unit.category)).toEqual(['note']);
    expect(plan.purgeableCount).toBe(1);
    expect(plan.totals.map((total) => total.category)).toEqual([...PURGE_CATEGORIES]);
  });

  it('caps the reported units and says so', () => {
    const owner = group(1);
    const notes = Array.from({ length: MAX_PURGE_PLAN_UNITS + 20 }, (_value, index) =>
      note(index + 1, daysAgo(200)),
    );
    const plan = planRetentionPurge({
      now: NOW,
      scopes: [{ group: group(1, notes), credentials: [item(owner, 1)] }],
    });

    expect(plan.units).toHaveLength(MAX_PURGE_PLAN_UNITS);
    expect(plan.truncated).toBe(true);
  });

  it.each([[0], [-1], [1.5], [Number.NaN], [MAX_PURGE_RETENTION_DAYS + 1]])(
    'rejects an out-of-range retention window of %s',
    (days) => {
      const owner = group(1);
      expect(() =>
        planRetentionPurge({
          now: NOW,
          olderThanDays: days,
          scopes: [{ group: owner, credentials: [item(owner, 1)] }],
        }),
      ).toThrow(ValidationError);
    },
  );

  it('measures age in whole elapsed days and never negatively', () => {
    expect(purgeAgeDays(daysAgo(90), NOW)).toBe(90);
    expect(purgeAgeDays(NOW, NOW)).toBe(0);
    expect(purgeAgeDays(daysAgo(-5), NOW)).toBe(0);
  });

  it('selects archived notes by the same window the plan reports', () => {
    const notes = [note(1, daysAgo(200)), note(2, daysAgo(3)), note(3)];
    expect(
      selectArchivedNotes(notes, { now: NOW, olderThanDays: 30 }).map(
        ({ id: noteId }) => noteId,
      ),
    ).toEqual(['note.1']);
    expect(
      selectArchivedNotes(notes, { now: NOW }).map(({ id: noteId }) => noteId),
    ).toEqual(['note.1', 'note.2']);
  });

  it('selects archived field values by reason as well as by age', () => {
    const owner = group(1);
    const holder = item(owner, 1, {
      archivedFieldValues: [
        archived(RETIRED_FIELD, { reason: 'user-archived' }),
        archived(ORPHANED_FIELD, { reason: 'template-field-removed' }),
      ],
    });

    expect(
      selectArchivedFieldValues(holder, {
        now: NOW,
        reasons: ['template-field-removed'],
      }).map(({ definition }) => definition.stableKey),
    ).toEqual([ORPHANED_FIELD.stableKey]);
  });

  it('never selects a value the plan reports as retained', () => {
    const owner = group(1);
    const holder = item(owner, 1, {
      itemFields: [ACTIVE_FIELD],
      itemValues: [secretValue(ACTIVE_FIELD, SECRET_CANARY)],
      archivedFieldValues: [archived(RETIRED_FIELD, { archivedAt: daysAgo(2) })],
    });
    const scopes: readonly PurgeScope[] = [{ group: owner, credentials: [holder] }];
    const plan = planRetentionPurge({ now: NOW, olderThanDays: 30, scopes });

    expect(plan.units.every((unit) => unit.disposition !== 'purgeable')).toBe(true);
    expect(
      selectArchivedFieldValues(holder, { now: NOW, olderThanDays: 30 }),
    ).toHaveLength(0);
    expect(JSON.stringify(plan)).not.toContain(SECRET_CANARY);
  });
});
