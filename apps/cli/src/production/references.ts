import {
  VaultMutationService,
  VaultReadSession,
  type VaultReadSourcePort,
} from '@kavrix/client';
import {
  NotFoundError,
  ValidationError,
  findReferencePath,
  isItemReferenceField,
  resolveNamedEntity,
  traverseReferenceGraph,
  type ReferenceScope,
} from '@kavrix/core';
import type { VaultRootKey } from '@kavrix/crypto';
import {
  fieldExpectsMultipleValues,
  fieldValueElementIdSchema,
  recordRevisionSchema,
  type ActiveFieldValue,
  type FieldValue,
  type GroupPayload,
  type ItemId,
  type ItemPayload,
  type StoredFieldValue,
  type VaultId,
} from '@kavrix/schemas';
import { randomBytes } from 'node:crypto';

import type {
  CliReferenceListResult,
  CliReferenceRemoveResult,
  CliReferenceWriteResult,
} from '../contracts.js';
import type {
  CliReferenceListRequest,
  CliReferenceRemoveRequest,
  CliReferenceWriteRequest,
} from '../mutation-contracts.js';
import {
  assertExpectedItemRevision,
  createDefaultMutationDependencies,
  resolveWritableField,
  storedFieldValue,
  type ProductionMutationOptions,
  type ResolvableField,
} from './mutations.js';

/**
 * What a reference walk needs, which is read access and nothing more.
 *
 * Listing references never writes, so it asks for no mutation queue: a read-only
 * command that cannot reach the write path cannot accidentally take it.
 */
export type ProductionReferenceReadOptions = Readonly<{
  source: VaultReadSourcePort;
  vaultId: VaultId;
  rootKey: VaultRootKey;
}>;

/** One credential located in the unlocked vault together with its owning group. */
type LocatedCredential = Readonly<{ group: GroupPayload; item: ItemPayload }>;

/**
 * Walks a credential's references without writing anything.
 *
 * The whole vault is opened in one pass because a reference may cross groups: a
 * walk restricted to the credential's own group would report a legitimate
 * cross-group target as missing, which is the one answer this command must never
 * give wrongly. Decryption, name resolution, and traversal all happen locally and
 * the session is locked before the call returns, so no target name and no relation
 * ever reaches the server.
 */
export async function executeProductionReferenceList(
  options: ProductionReferenceReadOptions,
  request: CliReferenceListRequest,
): Promise<CliReferenceListResult> {
  const scopes = await readVaultScopes(options);
  const source = locateCredential(scopes, request.groupQuery, request.credentialQuery);
  const graph = traverseReferenceGraph(scopes, source.item.id, {
    ...(request.depth === undefined ? {} : { maxDepth: request.depth }),
  });
  return {
    vaultId: options.vaultId,
    requestedDepth: request.depth ?? graph.reachedDepth,
    graph,
  };
}

/**
 * Points a reference field at a credential.
 *
 * The relation list and the field value are written in the same mutation because
 * the item payload requires every field-level reference to resolve through
 * `relatedItemIds`: writing one without the other would produce a payload the
 * schema refuses, so they are never separable steps.
 *
 * A cycle is disclosed rather than forbidden. Mutual references are a legitimate
 * shape, but closing a loop unannounced is how a reference set stops being
 * navigable, so the write refuses until `--allow-cycle` records that the loop is
 * intended, and the path is named so the decision is made against the actual
 * credentials involved.
 */
export async function executeProductionReferenceAdd(
  options: ProductionMutationOptions,
  request: CliReferenceWriteRequest,
): Promise<CliReferenceWriteResult> {
  const scopes = await readVaultScopes(options);
  const source = locateCredential(scopes, request.groupQuery, request.credentialQuery);
  const target = locateCredential(
    scopes,
    request.targetGroupQuery ?? request.groupQuery,
    request.targetQuery,
  );
  if (target.item.id === source.item.id) {
    throw new ValidationError('A credential cannot reference itself.');
  }

  const field = resolveReferenceField(source, request.fieldQuery);
  await assertWritableCredential(options, source, request.ifRevision);

  // The search reports the path inclusive of both ends, and the far end is this
  // credential. Trimming it leaves the loop closed exactly once, by the caller
  // naming the source after the path, so a mutual reference is disclosed as
  // "through the target" rather than naming the source twice.
  const cyclePath = findReferencePath(scopes, target.item.id, source.item.id)?.slice(
    0,
    -1,
  );
  if (cyclePath !== undefined && !request.allowCycle) {
    throw new ValidationError(
      `This reference would close a cycle through ${cyclePath.join(' -> ')} -> ${source.item.id}. Pass --allow-cycle to record it deliberately.`,
    );
  }

  const existing = storedFieldValue(source.item, field);
  const alreadyPresent = referencesTarget(existing, target.item.id);
  // An add that changes nothing writes nothing. Publishing a byte-identical
  // payload would consume a revision and land a history entry describing a
  // change that never happened, which is worse than doing nothing at all.
  if (!alreadyPresent) {
    await publish(options, source, {
      relatedItemIds: source.item.relatedItemIds.some((id) => id === target.item.id)
        ? source.item.relatedItemIds
        : [...source.item.relatedItemIds, target.item.id],
      ...placeValue(source.item, field, withReference(field, existing, target.item.id)),
    });
  }

  return {
    vaultId: options.vaultId,
    groupId: source.group.id,
    credentialId: source.item.id,
    title: source.item.title,
    fieldKey: field.definition.stableKey,
    fieldLabel: field.definition.label,
    targetId: target.item.id,
    targetTitle: target.item.title,
    targetGroupId: target.group.id,
    targetGroupName: target.group.name,
    alreadyPresent,
    ...(cyclePath === undefined ? {} : { cyclePath }),
    previousRevision: source.item.revision,
    revision: alreadyPresent
      ? source.item.revision
      : recordRevisionSchema.parse(source.item.revision + 1),
  };
}

/**
 * Drops a reference from a field, and the relation with it when nothing else binds
 * the target.
 *
 * The relation is retired only once no remaining field value names the target,
 * because `relatedItemIds` is what every other field-level reference resolves
 * through: removing it while a second field still pointed at the same credential
 * would leave a payload the schema refuses.
 *
 * A target that no longer resolves is still removable. A relation can outlive the
 * credential it named, and refusing to clean that up would leave the reference set
 * permanently holding an unresolvable edge.
 */
export async function executeProductionReferenceRemove(
  options: ProductionMutationOptions,
  request: CliReferenceRemoveRequest,
): Promise<CliReferenceRemoveResult> {
  const scopes = await readVaultScopes(options);
  const source = locateCredential(scopes, request.groupQuery, request.credentialQuery);
  const field = resolveReferenceField(source, request.fieldQuery);
  await assertWritableCredential(options, source, request.ifRevision);

  const existing = storedFieldValue(source.item, field);
  const targetId = removalTarget(scopes, existing, request);
  const nextValue = withoutReference(existing, targetId);
  const remainingValues = placeValue(source.item, field, nextValue);
  const stillBound = boundTargets({
    ...source.item,
    ...remainingValues,
  }).has(targetId);
  const relatedItemIds = stillBound
    ? source.item.relatedItemIds
    : source.item.relatedItemIds.filter((id) => id !== targetId);

  await publish(options, source, { relatedItemIds, ...remainingValues });

  const target = scopes
    .flatMap(({ credentials }) => credentials)
    .find((credential) => credential.id === targetId);
  return {
    vaultId: options.vaultId,
    groupId: source.group.id,
    credentialId: source.item.id,
    title: source.item.title,
    fieldKey: field.definition.stableKey,
    fieldLabel: field.definition.label,
    targetId,
    ...(target === undefined ? {} : { targetTitle: target.title }),
    relationRemoved: !stillBound,
    previousRevision: source.item.revision,
    revision: recordRevisionSchema.parse(source.item.revision + 1),
  };
}

/**
 * Opens every group and its credentials in one pass.
 *
 * References cross groups, so the traversal needs the whole vault to tell an
 * unresolvable target from one that simply lives elsewhere.
 */
async function readVaultScopes(
  options: ProductionReferenceReadOptions,
): Promise<readonly ReferenceScope[]> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    const scopes = await readSession.listScopes();
    return scopes.map(({ group, items }) => ({ group, credentials: items }));
  } finally {
    readSession.lock();
  }
}

/** Resolves a group and then a credential inside it, without guessing either. */
function locateCredential(
  scopes: readonly ReferenceScope[],
  groupQuery: string,
  credentialQuery: string,
): LocatedCredential {
  const group = resolveNamedEntity(
    groupQuery,
    scopes.map(({ group: candidate }) => candidate),
  );
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

/**
 * Resolves the field a reference write targets and refuses any other field type.
 *
 * A text field can hold an item ID as characters, but that is a string and not a
 * relation: the schema would not register it, no traversal would follow it, and
 * deleting the target would leave it silently stale. Refusing here keeps the two
 * from being confused.
 */
function resolveReferenceField(
  source: LocatedCredential,
  fieldQuery: string,
): ResolvableField {
  const field = resolveWritableField(
    { item: source.item, template: source.group.template },
    fieldQuery,
  );
  if (field === undefined) throw new NotFoundError();
  if (!isItemReferenceField(field.definition)) {
    throw new ValidationError(
      'Only an item-reference field can hold a credential reference.',
    );
  }
  return field;
}

/** Refuses a write against a record that is not active or has already moved on. */
async function assertWritableCredential(
  options: ProductionMutationOptions,
  source: LocatedCredential,
  ifRevision: number | undefined,
): Promise<void> {
  const state = await options.source.getCurrentItem(options.vaultId, source.item.id);
  if (state?.state !== 'active') throw new NotFoundError();
  assertExpectedItemRevision(source.item, ifRevision);
}

/** Every target ID any stored field value of the credential currently names. */
function boundTargets(item: ItemPayload): ReadonlySet<string> {
  const bound = new Set<string>();
  for (const stored of [...item.templateValues, ...item.itemValues]) {
    for (const targetId of referencedTargets(stored.value)) bound.add(targetId);
  }
  return bound;
}

function referencedTargets(value: FieldValue | undefined): readonly string[] {
  if (value?.state !== 'present') return [];
  if (value.content.cardinality === 'single') {
    const scalar = value.content.value;
    return scalar.kind === 'item-reference' ? [scalar.itemId] : [];
  }
  return value.content.elements.flatMap((element) =>
    element.value.kind === 'item-reference' ? [element.value.itemId] : [],
  );
}

function referencesTarget(value: FieldValue | undefined, targetId: ItemId): boolean {
  return referencedTargets(value).includes(targetId);
}

/**
 * Produces the field value that adds one reference.
 *
 * A repeatable field gains an element and keeps the ones it already had; a
 * single-valued field is replaced, which is what "point this field at that
 * credential" means when only one target fits. The result is an active value by
 * construction, because a stored value may never hold an orphaned one.
 */
function withReference(
  field: ResolvableField,
  existing: FieldValue | undefined,
  targetId: ItemId,
): ActiveFieldValue {
  const scalar = { kind: 'item-reference' as const, itemId: targetId };
  if (!fieldExpectsMultipleValues(field.definition)) {
    return {
      version: 1,
      state: 'present',
      content: { cardinality: 'single', value: scalar },
    };
  }
  const element = {
    id: fieldValueElementIdSchema.parse(`element.${randomBytes(12).toString('hex')}`),
    value: scalar,
    lifecycle: { version: 1 as const, status: 'available' as const },
  };
  const kept =
    existing?.state === 'present' && existing.content.cardinality === 'multiple'
      ? existing.content.elements
      : [];
  return {
    version: 1,
    state: 'present',
    content: { cardinality: 'multiple', elements: [...kept, element] },
  };
}

/**
 * Produces the field value that drops one reference, or `undefined` when the
 * field is left holding nothing.
 *
 * A repeatable value cannot legally be an empty element list, so removing the
 * last element clears the stored value entirely instead of writing a payload the
 * schema would refuse.
 */
function withoutReference(
  existing: FieldValue | undefined,
  targetId: string,
): ActiveFieldValue | undefined {
  if (existing?.state !== 'present') return undefined;
  if (existing.content.cardinality === 'single') return undefined;
  const remaining = existing.content.elements.filter(
    (element) =>
      !(element.value.kind === 'item-reference' && element.value.itemId === targetId),
  );
  const [first, ...rest] = remaining;
  if (first === undefined) return undefined;
  return {
    version: 1,
    state: 'present',
    content: { cardinality: 'multiple', elements: [first, ...rest] },
  };
}

/**
 * Decides which target a removal is about.
 *
 * A field holding exactly one reference needs no target restated. A field holding
 * several does need one, because dropping every element is a different intent from
 * dropping one and guessing between them would silently discard references the
 * operator never named.
 */
function removalTarget(
  scopes: readonly ReferenceScope[],
  existing: FieldValue | undefined,
  request: CliReferenceRemoveRequest,
): string {
  const held = referencedTargets(existing);
  const [first, ...rest] = held;
  if (first === undefined) throw new NotFoundError();
  if (request.targetQuery === undefined) {
    if (rest.length > 0) {
      throw new ValidationError(
        'This field holds several references, so name the one to remove with --target.',
      );
    }
    return first;
  }
  return resolveHeldTarget(scopes, request, held);
}

/**
 * Resolves a named removal target to one of the IDs the field actually holds.
 *
 * The query is matched against the held IDs first, because a relation can outlive
 * the credential it named: refusing an ID that no longer resolves anywhere would
 * leave an unresolvable edge permanently unremovable. Otherwise the name is
 * resolved against the credentials the vault still holds, and the result must be
 * one this field binds — removing a target the field never referenced is a mistake
 * worth reporting rather than a silent success.
 */
function resolveHeldTarget(
  scopes: readonly ReferenceScope[],
  request: CliReferenceRemoveRequest,
  held: readonly string[],
): string {
  const query = request.targetQuery?.trim() ?? '';
  if (held.includes(query)) return query;
  const target = locateCredential(
    scopes,
    request.targetGroupQuery ?? request.groupQuery,
    query,
  );
  if (!held.includes(target.item.id)) throw new NotFoundError();
  return target.item.id;
}

/** Places a field value back into the collection its scope belongs to. */
function placeValue(
  item: ItemPayload,
  field: ResolvableField,
  value: ActiveFieldValue | undefined,
): Readonly<{ templateValues: StoredFieldValue[]; itemValues: StoredFieldValue[] }> {
  const stored: StoredFieldValue[] =
    value === undefined
      ? []
      : [
          {
            fieldId: field.definition.id,
            stableKey: field.definition.stableKey,
            value,
            updatedAt: new Date().toISOString(),
          },
        ];
  const withoutField = (values: readonly StoredFieldValue[]): StoredFieldValue[] =>
    values.filter((candidate) => candidate.fieldId !== field.definition.id);
  return field.scope === 'template'
    ? {
        templateValues: [...withoutField(item.templateValues), ...stored],
        itemValues: item.itemValues,
      }
    : {
        templateValues: item.templateValues,
        itemValues: [...withoutField(item.itemValues), ...stored],
      };
}

/** Publishes one revision-bound item mutation through the mutation service. */
async function publish(
  options: ProductionMutationOptions,
  source: LocatedCredential,
  changes: Readonly<{
    relatedItemIds: ItemId[];
    templateValues: StoredFieldValue[];
    itemValues: StoredFieldValue[];
  }>,
): Promise<void> {
  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );
  await service.updateItem(source.group.id, { ...source.item, ...changes });
}
