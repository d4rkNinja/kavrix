import type {
  ArchivedFieldValue,
  AttachmentId,
  FieldValue,
  GroupId,
  GroupPayload,
  ItemId,
  ItemPayload,
  Note,
  NoteId,
} from '@kavrix/schemas';

import { ValidationError } from '../errors.js';
import { referencesInFieldValue } from './reference-graph.js';

/**
 * Everything a permanent purge can be asked about.
 *
 * The list is deliberately wider than what a client can actually destroy, because
 * the categories a purge cannot reach are the ones an operator most needs told:
 * an inventory that silently omitted deleted records or attachments would read as
 * "nothing left to remove" when the truth is "this client is not where that is
 * removed".
 */
export const PURGE_CATEGORIES = [
  'archived-field',
  'orphan-value',
  'note',
  'credential',
  'group',
  'attachment',
  'history',
] as const;

export type PurgeCategory = (typeof PURGE_CATEGORIES)[number];

/**
 * What can be done with one retirable unit right now.
 *
 * `purgeable` is the only disposition a purge command acts on. The other three
 * exist so that a unit is never simply missing from the report: `retained` is
 * inside the requested retention window, `server-retained` is owned by a
 * tombstone's own clock and must not be destroyed locally ahead of it, and
 * `unsupported` has no local destruction path at all.
 */
export type PurgeDisposition =
  'purgeable' | 'retained' | 'server-retained' | 'unsupported';

/** Hard ceiling on reported units, so a large vault cannot turn a preview into unbounded work. */
export const MAX_PURGE_PLAN_UNITS = 2_000;
/** Widest retention window a caller may request, matching the vault's own retention bounds. */
export const MAX_PURGE_RETENTION_DAYS = 36_500;

/** The server-side retention clock of a deleted record, as the client sees it. */
export type PurgeTombstone = Readonly<{
  deletedAt: string;
  /** Instant after which the server may destroy the record; absent when it states none. */
  purgeAfter?: string;
}>;

/** One tombstoned credential, named by ID because a deleted record carries no readable title. */
export type DeletedCredential = Readonly<{
  credentialId: ItemId;
  tombstone: PurgeTombstone;
}>;

/**
 * One group, its readable credentials, and the deletions the caller could observe.
 *
 * Tombstones are supplied rather than derived: they live in the mutation state and
 * not in a decrypted payload, so a pure policy cannot discover them and must be
 * told about the ones the caller actually enumerated.
 */
export type PurgeScope = Readonly<{
  group: GroupPayload;
  credentials: readonly ItemPayload[];
  deletedCredentials?: readonly DeletedCredential[];
  groupTombstone?: PurgeTombstone;
}>;

/**
 * One thing a purge could be asked to destroy, and what would actually happen.
 *
 * Only identities a listing command already discloses are reported — a field
 * label, a note title, a credential title, an opaque ID. The archived value
 * itself never appears, because a purge decides whether to destroy a value and
 * never needs to show it.
 */
export type PurgeUnit = Readonly<{
  category: PurgeCategory;
  disposition: PurgeDisposition;
  /** Why this unit is not purgeable; absent only when it is. */
  reason?: string;
  /** Absent for a vault-wide unit that belongs to no single group. */
  groupId?: GroupId;
  groupName?: string;
  /** Absent for a unit held by the group rather than by a credential. */
  credentialId?: ItemId;
  credentialTitle?: string;
  /** Identity inside its record: a field stable key, note ID, attachment ID, or record ID. */
  unitId: string;
  /** Operator-facing name, already visible from the matching listing command. */
  label: string;
  /** When the unit entered its retirable state; absent when nothing records it. */
  retiredAt?: string;
  ageDays?: number;
  /** The server retention clock, for a unit this client may not destroy. */
  tombstone?: PurgeTombstone;
}>;

export type PurgeCategoryTotal = Readonly<{
  category: PurgeCategory;
  purgeable: number;
  retained: number;
  serverRetained: number;
  unsupported: number;
}>;

/** A relation this plan would retire, because nothing surviving would bind it. */
export type RetiredRelation = Readonly<{ credentialId: ItemId; targetId: ItemId }>;

/** An attachment this plan would leave unreferenced. The reference itself is never unlinked here. */
export type UnreferencedAttachment = Readonly<{
  credentialId: ItemId;
  attachmentId: AttachmentId;
}>;

export type PurgePlan = Readonly<{
  /** The instant the plan was evaluated against, so ages are reproducible. */
  evaluatedAt: string;
  olderThanDays?: number;
  categories: readonly PurgeCategory[];
  units: readonly PurgeUnit[];
  /** Every category, always, so an absent one reads as zero rather than as unexamined. */
  totals: readonly PurgeCategoryTotal[];
  purgeableCount: number;
  retiredRelations: readonly RetiredRelation[];
  unreferencedAttachments: readonly UnreferencedAttachment[];
  /** The unit ceiling stopped the inventory before the vault was exhausted. */
  truncated: boolean;
}>;

/**
 * Which retirable units a purge is about.
 *
 * The same selection drives the preview and the write, so a plan cannot describe
 * one set of units while the command destroys another.
 */
export type PurgeSelection = Readonly<{
  now: string;
  /** Only units retired at least this many whole days ago. */
  olderThanDays?: number;
  /** Only archived values retired for these reasons. */
  reasons?: readonly ArchivedFieldValue['reason'][];
  /** Only the archived value of this field, by stable key. */
  fieldKey?: string;
  /** Only this note. */
  noteId?: NoteId;
}>;

export type RetentionPurgeInput = Readonly<{
  scopes: readonly PurgeScope[];
  now: string;
  olderThanDays?: number;
  /** Restrict the inventory; every category is examined when absent. */
  categories?: readonly PurgeCategory[];
}>;

/**
 * Whole elapsed days between two instants, never negative.
 *
 * A clock that has moved backwards, or a record stamped slightly in the future by
 * another device, would otherwise produce a negative age that compares as younger
 * than every retention window and quietly makes the unit unpurgeable forever.
 */
export function purgeAgeDays(retiredAt: string, now: string): number {
  const retired = Date.parse(retiredAt);
  const evaluated = Date.parse(now);
  if (Number.isNaN(retired) || Number.isNaN(evaluated)) {
    throw new ValidationError('A retention age needs two valid timestamps.');
  }
  return Math.max(0, Math.floor((evaluated - retired) / 86_400_000));
}

/** Refuses a retention window that is not a usable whole number of days. */
function assertRetentionWindow(days: number | undefined): void {
  if (days === undefined) return;
  if (!Number.isInteger(days) || days < 1 || days > MAX_PURGE_RETENTION_DAYS) {
    throw new ValidationError(
      `A retention window must be a whole number of days between 1 and ${String(MAX_PURGE_RETENTION_DAYS)}.`,
    );
  }
}

function withinWindow(retiredAt: string, selection: PurgeSelection): boolean {
  if (selection.olderThanDays === undefined) return true;
  return purgeAgeDays(retiredAt, selection.now) >= selection.olderThanDays;
}

/**
 * The archived field values a purge would destroy.
 *
 * Archived values are the one category a client owns outright: they live inside
 * the item payload, so removing them is an ordinary revision-bound update rather
 * than anything the server has to agree to.
 */
export function selectArchivedFieldValues(
  item: ItemPayload,
  selection: PurgeSelection,
): readonly ArchivedFieldValue[] {
  assertRetentionWindow(selection.olderThanDays);
  return item.archivedFieldValues.filter((archived) => {
    if (
      selection.fieldKey !== undefined &&
      archived.definition.stableKey !== selection.fieldKey
    ) {
      return false;
    }
    if (
      selection.reasons !== undefined &&
      !selection.reasons.includes(archived.reason)
    ) {
      return false;
    }
    return withinWindow(archived.archivedAt, selection);
  });
}

/**
 * The archived notes a purge would destroy.
 *
 * An active note is never selected. Archiving is the reversible step and purging
 * is not, so a purge that could reach an active note would make the two
 * indistinguishable from the operator's side.
 */
export function selectArchivedNotes(
  notes: readonly Note[],
  selection: PurgeSelection,
): readonly Note[] {
  assertRetentionWindow(selection.olderThanDays);
  return notes.filter((note) => {
    const { archivedAt } = note;
    if (archivedAt === undefined) return false;
    if (selection.noteId !== undefined && note.id !== selection.noteId) return false;
    return withinWindow(archivedAt, selection);
  });
}

/** Every entity ID the given stored or archived values name, split by kind. */
function boundEntities(
  values: readonly Readonly<{ value: FieldValue }>[],
): Readonly<{ items: ReadonlySet<string>; attachments: ReadonlySet<string> }> {
  const items = new Set<string>();
  const attachments = new Set<string>();
  for (const { value } of values) {
    for (const reference of referencesInFieldValue(value)) {
      if (reference.kind === 'item-reference') items.add(reference.itemId);
      else attachments.add(reference.attachmentId);
    }
  }
  return { items, attachments };
}

/** The archived values of an item that a purge of `purged` would leave behind. */
function survivors(
  item: ItemPayload,
  purged: readonly ArchivedFieldValue[],
): readonly ArchivedFieldValue[] {
  const removed = new Set(purged.map(({ definition }) => definition.stableKey));
  return item.archivedFieldValues.filter(
    (archived) => !removed.has(archived.definition.stableKey),
  );
}

/**
 * The relations a purge would retire, because the purged values were the last to
 * bind them.
 *
 * A relation that nothing binds today is left alone: `relatedItemIds` is the
 * authoritative relation list and a field reference is required to appear in it
 * rather than the other way round, so an unbound relation is a valid state and
 * not debris for a purge to collect. Only a relation this purge actually
 * unbinds is retired, which is the same last-binding rule a reference removal
 * follows.
 */
export function retiredRelationIds(
  item: ItemPayload,
  purged: readonly ArchivedFieldValue[],
): readonly ItemId[] {
  if (purged.length === 0) return [];
  const purgedBound = boundEntities(purged.map(({ value }) => ({ value }))).items;
  const surviving = boundEntities([
    ...item.templateValues,
    ...item.itemValues,
    ...survivors(item, purged),
  ]).items;
  return item.relatedItemIds.filter(
    (targetId) => purgedBound.has(targetId) && !surviving.has(targetId),
  );
}

/**
 * The attachments a purge would leave unreferenced.
 *
 * These are reported and never unlinked. An attachment ID is reachable through
 * `attachment list` and removable through `attachment delete`, and silently
 * dropping the reference here would destroy the operator's only handle on a blob
 * this client cannot see.
 */
export function unreferencedAttachmentIds(
  item: ItemPayload,
  purged: readonly ArchivedFieldValue[],
): readonly AttachmentId[] {
  if (purged.length === 0) return [];
  const purgedBound = boundEntities(purged.map(({ value }) => ({ value }))).attachments;
  const surviving = boundEntities([
    ...item.templateValues,
    ...item.itemValues,
    ...survivors(item, purged),
  ]).attachments;
  return item.attachmentIds.filter(
    (attachmentId) => purgedBound.has(attachmentId) && !surviving.has(attachmentId),
  );
}

const CATEGORY_OF_REASON: Readonly<
  Record<ArchivedFieldValue['reason'], PurgeCategory>
> = Object.freeze({
  'template-field-removed': 'orphan-value',
  'type-conversion': 'archived-field',
  'user-archived': 'archived-field',
});

const TOMBSTONE_REASON =
  "A deleted record is destroyed by the vault's own retention schedule, so this client reports its clock instead of purging it early.";
const ATTACHMENT_REASON =
  'No attachment content is stored locally, so there is nothing here to destroy; use `attachment delete --force` to unlink the reference itself.';
const HISTORY_REASON =
  'There is no revision history stored locally, so nothing is retained for a purge to reclaim.';

/**
 * Inventories everything a purge could reach, and states what each unit's fate
 * would actually be.
 *
 * The plan is pure and read-only: the caller has already decrypted every scope, so
 * no title, note title, or relation leaves the process, and nothing is written by
 * producing it. Its purpose is that a purge is never confused with an archive or a
 * delete — every unit carries the disposition that says which of the three it is
 * subject to, and the two categories a client can genuinely destroy are the only
 * ones ever marked `purgeable`.
 */
export function planRetentionPurge(input: RetentionPurgeInput): PurgePlan {
  assertRetentionWindow(input.olderThanDays);
  const categories = input.categories ?? PURGE_CATEGORIES;
  const wanted = new Set<PurgeCategory>(categories);
  const selection: PurgeSelection = {
    now: input.now,
    ...(input.olderThanDays === undefined
      ? {}
      : { olderThanDays: input.olderThanDays }),
  };

  const units: PurgeUnit[] = [];
  const retiredRelations: RetiredRelation[] = [];
  const unreferencedAttachments: UnreferencedAttachment[] = [];
  let truncated = false;

  const add = (unit: PurgeUnit): void => {
    if (!wanted.has(unit.category)) return;
    if (units.length >= MAX_PURGE_PLAN_UNITS) {
      truncated = true;
      return;
    }
    units.push(Object.freeze(unit));
  };

  for (const scope of input.scopes) {
    const owner = {
      groupId: scope.group.id,
      groupName: scope.group.name,
    } as const;

    for (const note of scope.group.notes) {
      if (note.archivedAt === undefined) continue;
      add(
        retirableUnit('note', owner, note.id, note.title, note.archivedAt, selection),
      );
    }

    for (const credential of scope.credentials) {
      const held = {
        ...owner,
        credentialId: credential.id,
        credentialTitle: credential.title,
      } as const;

      for (const archived of credential.archivedFieldValues) {
        add(
          retirableUnit(
            CATEGORY_OF_REASON[archived.reason],
            held,
            archived.definition.stableKey,
            archived.definition.label,
            archived.archivedAt,
            selection,
          ),
        );
      }

      for (const note of credential.notes) {
        if (note.archivedAt === undefined) continue;
        add(
          retirableUnit('note', held, note.id, note.title, note.archivedAt, selection),
        );
      }

      const activeBound = boundEntities([
        ...credential.templateValues,
        ...credential.itemValues,
      ]).attachments;
      for (const attachmentId of credential.attachmentIds) {
        if (activeBound.has(attachmentId)) continue;
        add({
          category: 'attachment',
          disposition: 'unsupported',
          reason: ATTACHMENT_REASON,
          ...held,
          unitId: attachmentId,
          label: attachmentId,
        });
      }

      const purgeable = selectArchivedFieldValues(credential, selection);
      for (const targetId of retiredRelationIds(credential, purgeable)) {
        retiredRelations.push(Object.freeze({ credentialId: credential.id, targetId }));
      }
      for (const attachmentId of unreferencedAttachmentIds(credential, purgeable)) {
        unreferencedAttachments.push(
          Object.freeze({ credentialId: credential.id, attachmentId }),
        );
      }
    }

    for (const deleted of scope.deletedCredentials ?? []) {
      add(
        tombstoneUnit(
          'credential',
          owner,
          deleted.credentialId,
          deleted.credentialId,
          deleted.tombstone,
          input.now,
        ),
      );
    }
    const { groupTombstone } = scope;
    if (groupTombstone !== undefined) {
      add(
        tombstoneUnit(
          'group',
          owner,
          scope.group.id,
          scope.group.name,
          groupTombstone,
          input.now,
        ),
      );
    }
  }

  add({
    category: 'history',
    disposition: 'unsupported',
    reason: HISTORY_REASON,
    unitId: 'history',
    label: 'Revision history',
  });

  return Object.freeze({
    evaluatedAt: input.now,
    ...(input.olderThanDays === undefined
      ? {}
      : { olderThanDays: input.olderThanDays }),
    categories: Object.freeze([...categories]),
    units: Object.freeze(units),
    totals: totalsOf(units),
    purgeableCount: units.filter((unit) => unit.disposition === 'purgeable').length,
    retiredRelations: Object.freeze(retiredRelations),
    unreferencedAttachments: Object.freeze(unreferencedAttachments),
    truncated,
  });
}

type UnitOwner = Readonly<{
  groupId: GroupId;
  groupName: string;
  credentialId?: ItemId;
  credentialTitle?: string;
}>;

/** A unit this client can destroy, once it is older than the requested window. */
function retirableUnit(
  category: PurgeCategory,
  owner: UnitOwner,
  unitId: string,
  label: string,
  retiredAt: string,
  selection: PurgeSelection,
): PurgeUnit {
  const ageDays = purgeAgeDays(retiredAt, selection.now);
  const inside =
    selection.olderThanDays !== undefined && ageDays < selection.olderThanDays;
  return {
    category,
    disposition: inside ? 'retained' : 'purgeable',
    ...(inside
      ? {
          reason: `Retired ${String(ageDays)} days ago, inside the requested ${String(selection.olderThanDays)}-day retention window.`,
        }
      : {}),
    ...owner,
    unitId,
    label,
    retiredAt,
    ageDays,
  };
}

/** A deleted record, whose destruction belongs to the retention schedule and not to this client. */
function tombstoneUnit(
  category: PurgeCategory,
  owner: UnitOwner,
  unitId: string,
  label: string,
  tombstone: PurgeTombstone,
  now: string,
): PurgeUnit {
  return {
    category,
    disposition: 'server-retained',
    reason: TOMBSTONE_REASON,
    ...owner,
    unitId,
    label,
    retiredAt: tombstone.deletedAt,
    ageDays: purgeAgeDays(tombstone.deletedAt, now),
    tombstone,
  };
}

function totalsOf(units: readonly PurgeUnit[]): readonly PurgeCategoryTotal[] {
  return Object.freeze(
    PURGE_CATEGORIES.map((category) => {
      const own = units.filter((unit) => unit.category === category);
      const count = (disposition: PurgeDisposition): number =>
        own.filter((unit) => unit.disposition === disposition).length;
      return Object.freeze({
        category,
        purgeable: count('purgeable'),
        retained: count('retained'),
        serverRetained: count('server-retained'),
        unsupported: count('unsupported'),
      });
    }),
  );
}
