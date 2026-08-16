import {
  VaultMutationService,
  VaultReadSession,
  type VaultMutationStatePort,
  type VaultReadSourcePort,
} from '@kavrix/client';
import {
  NotFoundError,
  PURGE_CATEGORIES,
  deleteNote,
  planRetentionPurge,
  purgeAgeDays,
  resolveNamedEntity,
  retiredRelationIds,
  selectArchivedFieldValues,
  selectArchivedNotes,
  unreferencedAttachmentIds,
  type DeletedCredential,
  type PurgeScope,
  type PurgeSelection,
} from '@kavrix/core';
import type { VaultRootKey } from '@kavrix/crypto';
import type {
  ArchivedFieldValue,
  GroupPayload,
  ItemPayload,
  Note,
  VaultId,
} from '@kavrix/schemas';

import type {
  CliPurgeFieldsResult,
  CliPurgeNotesResult,
  CliPurgePreviewResult,
  CliPurgedField,
  CliPurgedNote,
  CliUndiscoverablePurgeCategory,
} from '../contracts.js';
import type {
  CliPurgeFieldsRequest,
  CliPurgeNotesRequest,
  CliPurgePreviewRequest,
} from '../mutation-contracts.js';
import {
  assertExpectedGroupRevision,
  assertExpectedItemRevision,
  createDefaultMutationDependencies,
  type ProductionMutationOptions,
} from './mutations.js';

/**
 * What a purge inventory needs, which is read access plus the mutation state.
 *
 * The mutation state is where tombstones live, and a preview that could not read
 * them would report a vault with deleted records in it as having nothing retired at
 * all. It still asks for no mutation queue: the inventory is the command an operator
 * runs *before* deciding, so it must not be able to reach the write path.
 */
export type ProductionPurgeReadOptions = Readonly<{
  source: VaultMutationStatePort & VaultReadSourcePort;
  vaultId: VaultId;
  rootKey: VaultRootKey;
}>;

/**
 * Categories this client cannot enumerate at all, as opposed to categories it
 * enumerated and found empty.
 *
 * A group tombstone is only reachable by asking for a group ID that is already
 * known, and a deleted group is excluded from every vault listing, so there is no
 * way to discover one. Saying so is the difference between "nothing is left" and
 * "this client cannot see what is left", and only the first would be a lie.
 */
const UNDISCOVERABLE: readonly CliUndiscoverablePurgeCategory[] = Object.freeze([
  Object.freeze({
    category: 'group' as const,
    reason:
      'A deleted group is absent from every vault listing, so this client cannot enumerate group tombstones; the server retention schedule destroys them.',
  }),
]);

/** One credential located in the unlocked vault together with its owning group. */
type LocatedCredential = Readonly<{ group: GroupPayload; item: ItemPayload }>;

/**
 * Reports what a purge would destroy without destroying anything.
 *
 * Every group is opened in one pass, because the question is what the *vault*
 * retains and a preview restricted to one group would answer a narrower question
 * than the one that decides whether to purge at all. Deleted credentials are read
 * from the mutation state per group, so their tombstone clocks appear beside the
 * units this client could actually destroy and the two are never confused.
 * Decryption stays local and the read session is locked before returning.
 */
export async function executeProductionPurgePreview(
  options: ProductionPurgeReadOptions,
  request: CliPurgePreviewRequest,
): Promise<CliPurgePreviewResult> {
  const scopes = await readPurgeScopes(options, request);
  const plan = planRetentionPurge({
    scopes,
    now: new Date().toISOString(),
    ...(request.olderThanDays === undefined
      ? {}
      : { olderThanDays: request.olderThanDays }),
    ...(request.categories === undefined ? {} : { categories: request.categories }),
  });
  const examined = new Set(request.categories ?? PURGE_CATEGORIES);
  return {
    vaultId: options.vaultId,
    plan,
    undiscoverableCategories: UNDISCOVERABLE.filter((entry) =>
      examined.has(entry.category),
    ),
  };
}

/**
 * Permanently destroys a credential's archived field values.
 *
 * The purge is one revision-bound item update, so it either lands whole or not at
 * all: a retry after an interrupted publish re-reads the current revision and finds
 * the values already gone rather than destroying a second, different set. Relations
 * the purge unbinds are retired in the same mutation, because the item payload
 * requires every field reference to resolve through `relatedItemIds` and a payload
 * that kept a relation no value binds is one the schema still accepts but nothing
 * would ever clear. Attachment references are reported and never unlinked: the ID is
 * the operator's only handle on a blob this client cannot see.
 */
export async function executeProductionPurgeFields(
  options: ProductionMutationOptions,
  request: CliPurgeFieldsRequest,
): Promise<CliPurgeFieldsResult> {
  const scopes = await readVaultScopes(options);
  const source = locateCredential(scopes, request.groupQuery, request.credentialQuery);
  const now = new Date().toISOString();
  const selection: PurgeSelection = {
    now,
    ...(request.olderThanDays === undefined
      ? {}
      : { olderThanDays: request.olderThanDays }),
    ...(request.reasons === undefined ? {} : { reasons: request.reasons }),
    ...(request.fieldKey === undefined
      ? {}
      : { fieldKey: resolveArchivedFieldKey(source.item, request.fieldKey) }),
  };

  const state = await options.source.getCurrentItem(options.vaultId, source.item.id);
  if (state?.state !== 'active') throw new NotFoundError();
  assertExpectedItemRevision(source.item, request.ifRevision);

  const purged = selectArchivedFieldValues(source.item, selection);
  const located = {
    vaultId: options.vaultId,
    groupId: source.group.id,
    groupName: source.group.name,
    credentialId: source.item.id,
    title: source.item.title,
  } as const;
  if (purged.length === 0) {
    return {
      ...located,
      purged: [],
      retiredRelations: [],
      unreferencedAttachments: [],
      previousRevision: source.item.revision,
      revision: source.item.revision,
    };
  }

  const retired = new Set<string>(retiredRelationIds(source.item, purged));
  const unreferenced = unreferencedAttachmentIds(source.item, purged);
  const destroyed = new Set(purged.map(({ definition }) => definition.stableKey));
  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );
  await service.updateItem(source.group.id, {
    ...source.item,
    archivedFieldValues: source.item.archivedFieldValues.filter(
      (archived) => !destroyed.has(archived.definition.stableKey),
    ),
    relatedItemIds: source.item.relatedItemIds.filter((id) => !retired.has(id)),
  });

  return {
    ...located,
    purged: purged.map((archived) => purgedField(archived, now)),
    retiredRelations: [...retired],
    unreferencedAttachments: [...unreferenced],
    previousRevision: source.item.revision,
    revision: source.item.revision + 1,
  };
}

/**
 * Permanently destroys the archived notes of a group or of one credential.
 *
 * Which record holds the notes is stated by the caller rather than guessed: a group
 * and its credentials both carry notes, and resolving the wrong one would move a
 * revision the operator never named. Removal goes through the notes policy so the
 * remaining collection is validated as a collection, which is what keeps a purge
 * from writing a note list the schema would refuse on the next read.
 */
export async function executeProductionPurgeNotes(
  options: ProductionMutationOptions,
  request: CliPurgeNotesRequest,
): Promise<CliPurgeNotesResult> {
  const now = new Date().toISOString();
  const selection: PurgeSelection = {
    now,
    ...(request.olderThanDays === undefined
      ? {}
      : { olderThanDays: request.olderThanDays }),
    ...(request.noteId === undefined ? {} : { noteId: request.noteId }),
  };
  const service = (): VaultMutationService =>
    new VaultMutationService(
      options.source,
      options.queue,
      options.vaultId,
      options.rootKey,
      createDefaultMutationDependencies(),
    );

  const scopes = await readVaultScopes(options);
  if (request.credentialQuery !== undefined) {
    const source = locateCredential(
      scopes,
      request.groupQuery,
      request.credentialQuery,
    );
    const state = await options.source.getCurrentItem(options.vaultId, source.item.id);
    if (state?.state !== 'active') throw new NotFoundError();
    assertExpectedItemRevision(source.item, request.ifRevision);

    const purged = selectArchivedNotes(source.item.notes, selection);
    if (request.noteId !== undefined && purged.length === 0) throw new NotFoundError();
    const located = {
      vaultId: options.vaultId,
      groupId: source.group.id,
      groupName: source.group.name,
      credentialId: source.item.id,
      credentialTitle: source.item.title,
    } as const;
    if (purged.length === 0) {
      return {
        ...located,
        purged: [],
        previousRevision: source.item.revision,
        revision: source.item.revision,
      };
    }
    await service().updateItem(source.group.id, {
      ...source.item,
      notes: [...withoutNotes(source.item.notes, purged)],
    });
    return {
      ...located,
      purged: purged.map((note) => purgedNote(note, now)),
      previousRevision: source.item.revision,
      revision: source.item.revision + 1,
    };
  }

  const group = locateGroup(scopes, request.groupQuery);
  const groupState = await options.source.getCurrentGroup(options.vaultId, group.id);
  if (groupState?.state !== 'active') throw new NotFoundError();
  assertExpectedGroupRevision(group, request.ifRevision);

  const purged = selectArchivedNotes(group.notes, selection);
  if (request.noteId !== undefined && purged.length === 0) throw new NotFoundError();
  const located = {
    vaultId: options.vaultId,
    groupId: group.id,
    groupName: group.name,
  } as const;
  if (purged.length === 0) {
    return {
      ...located,
      purged: [],
      previousRevision: group.revision,
      revision: group.revision,
    };
  }
  await service().updateGroup({
    ...group,
    notes: [...withoutNotes(group.notes, purged)],
  });
  return {
    ...located,
    purged: purged.map((note) => purgedNote(note, now)),
    previousRevision: group.revision,
    revision: group.revision + 1,
  };
}

/**
 * Removes every selected note, one policy call at a time.
 *
 * The policy validates the surviving collection on each removal, so a purge cannot
 * assemble an invalid note list by filtering the whole set in one pass and only
 * discovering the problem when the payload is next read.
 */
function withoutNotes(
  notes: readonly Note[],
  purged: readonly Note[],
): readonly Note[] {
  let remaining = notes;
  for (const note of purged) remaining = deleteNote(remaining, note.id);
  return remaining;
}

/** The archived-value identity a purge reports, never the value itself. */
function purgedField(archived: ArchivedFieldValue, now: string): CliPurgedField {
  return {
    fieldKey: archived.definition.stableKey,
    fieldLabel: archived.definition.label,
    reason: archived.reason,
    archivedAt: archived.archivedAt,
    ageDays: purgeAgeDays(archived.archivedAt, now),
  };
}

/** The archived-note identity a purge reports, never the note body. */
function purgedNote(note: Note, now: string): CliPurgedNote {
  const archivedAt = note.archivedAt ?? now;
  return {
    noteId: note.id,
    title: note.title,
    archivedAt,
    ageDays: purgeAgeDays(archivedAt, now),
  };
}

/**
 * Resolves `--field` against the archived definitions rather than the active ones.
 *
 * An archived value's definition is by construction absent from both the item's own
 * fields and its template's, so resolving through the ordinary writable-field lookup
 * would report every archived field as missing. Resolution is still explicit and
 * never guesses: an ambiguous query fails rather than picking one of the values a
 * purge would then destroy.
 */
function resolveArchivedFieldKey(item: ItemPayload, fieldQuery: string): string {
  const resolved = resolveNamedEntity(
    fieldQuery,
    item.archivedFieldValues.map((archived) => ({
      id: archived.definition.id,
      name: archived.definition.label,
      slug: archived.definition.stableKey,
      aliases: [],
      stableKey: archived.definition.stableKey,
    })),
  );
  return resolved.stableKey;
}

/**
 * Reads the scopes a preview covers, with the deletions each one can disclose.
 *
 * `listCurrentItems` is the only enumeration of tombstoned records a client has, and
 * it is per group, so it is asked once per scope. A tombstone without a `purgeAfter`
 * is carried as such: inventing a schedule the server never stated would present a
 * guess as the retention clock.
 */
async function readPurgeScopes(
  options: ProductionPurgeReadOptions,
  request: CliPurgePreviewRequest,
): Promise<readonly PurgeScope[]> {
  const scopes = await readVaultScopes(options, request.groupQuery);
  const { credentialQuery } = request;
  const filtered =
    credentialQuery === undefined
      ? scopes
      : scopes.map((scope) => ({
          ...scope,
          credentials: [locateCredential(scopes, scope.group.id, credentialQuery).item],
        }));
  const withDeletions: PurgeScope[] = [];
  for (const scope of filtered) {
    const deletedCredentials = await deletedIn(options, scope.group.id);
    withDeletions.push({
      ...scope,
      ...(deletedCredentials.length === 0 ? {} : { deletedCredentials }),
    });
  }
  return withDeletions;
}

/** Every tombstoned credential one group still holds, with its retention clock. */
async function deletedIn(
  options: ProductionPurgeReadOptions,
  groupId: GroupPayload['id'],
): Promise<readonly DeletedCredential[]> {
  const deleted: DeletedCredential[] = [];
  for await (const state of options.source.listCurrentItems(options.vaultId, groupId)) {
    if (state.state !== 'deleted') continue;
    deleted.push({
      credentialId: state.tombstone.entityId,
      tombstone: {
        deletedAt: state.tombstone.deletedAt,
        ...(state.tombstone.purgeAfter === undefined
          ? {}
          : { purgeAfter: state.tombstone.purgeAfter }),
      },
    });
  }
  return deleted;
}

/** Opens the vault, reads every scope it holds, and locks the session again. */
async function readVaultScopes(
  options: Readonly<{
    source: VaultReadSourcePort;
    vaultId: VaultId;
    rootKey: VaultRootKey;
  }>,
  groupQuery?: string,
): Promise<
  readonly Readonly<{ group: GroupPayload; credentials: readonly ItemPayload[] }>[]
> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    const scopes = await readSession.listScopes(groupQuery);
    return scopes.map(({ group, items }) => ({ group, credentials: items }));
  } finally {
    readSession.lock();
  }
}

/** Resolves a group without guessing which one was meant. */
function locateGroup(
  scopes: readonly Readonly<{ group: GroupPayload }>[],
  groupQuery: string,
): GroupPayload {
  return resolveNamedEntity(
    groupQuery,
    scopes.map(({ group }) => group),
  );
}

/** Resolves a group and then a credential inside it, without guessing either. */
function locateCredential(
  scopes: readonly Readonly<{
    group: GroupPayload;
    credentials: readonly ItemPayload[];
  }>[],
  groupQuery: string,
  credentialQuery: string,
): LocatedCredential {
  const group = locateGroup(scopes, groupQuery);
  const scope = scopes.find(({ group: candidate }) => candidate.id === group.id);
  if (scope === undefined) throw new NotFoundError();
  const resolved = resolveNamedEntity(
    credentialQuery,
    scope.credentials.map((candidate) => ({
      id: candidate.id,
      name: candidate.title,
      slug: candidate.slug,
      aliases: candidate.aliases,
      item: candidate,
    })),
  );
  return { group, item: resolved.item };
}
