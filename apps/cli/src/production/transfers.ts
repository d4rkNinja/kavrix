import {
  VaultMutationService,
  VaultReadSession,
  type CreateGroupInput,
  type CreateItemInput,
  type OpaqueMutationQueuePort,
  type VaultMutationStatePort,
  type VaultReadSourcePort,
} from '@kavrix/client';
import { zeroize, type VaultRootKey } from '@kavrix/crypto';
import {
  BackupError,
  createEncryptedTransfer,
  readEncryptedTransfer,
  resolveTransferLimits,
  type TransferDocument,
  type TransferItemDocument,
} from '@kavrix/import-export';
import {
  MAX_SECURE_STREAM_FILE_BYTES,
  PortableKeyFileError,
  readSecureFile,
  validateSecureFileDestination,
  validateSecureFileSource,
  writeSecureStreamFile,
} from '@kavrix/key-files';
import type {
  GroupId,
  GroupPayload,
  ItemPayload,
  TransferCollisionStrategy,
  VaultId,
} from '@kavrix/schemas';

import type { CliTransferExportResult, CliTransferImportResult } from '../contracts.js';
import {
  CliTransferExportError,
  CliTransferImportError,
  CliUsageError,
} from '../errors.js';
import { createDefaultMutationDependencies } from './mutations.js';

export const MAX_CLI_TRANSFER_BYTES = MAX_SECURE_STREAM_FILE_BYTES;
export const MAX_CLI_TRANSFER_DOCUMENTS = 20_000;

const TRANSFER_LIMITS = Object.freeze({
  maximumBytes: MAX_CLI_TRANSFER_BYTES,
  maximumDocuments: MAX_CLI_TRANSFER_DOCUMENTS,
});

/**
 * How many suffixed candidates a colliding group name is offered before the
 * import gives up. A bounded search keeps `rename` from scanning without end.
 */
const MAX_RENAME_ATTEMPTS = 1_000;

type TransferSource = VaultMutationStatePort & VaultReadSourcePort;

export interface ProductionTransferExportOptions {
  readonly source: TransferSource;
  readonly vaultId: VaultId;
  readonly rootKey: VaultRootKey;
}

export interface ProductionTransferImportOptions {
  readonly source: TransferSource;
  readonly queue: OpaqueMutationQueuePort;
  readonly vaultId: VaultId;
  readonly rootKey: VaultRootKey;
}

export type ProductionTransferExportRequest = Readonly<{
  destination: string;
  /** Transfer passphrase bytes. Owned by the caller, which must zeroize them. */
  passphrase: Uint8Array;
  groupQuery?: string;
}>;

export type ProductionTransferImportRequest = Readonly<{
  source: string;
  /** Transfer passphrase bytes. Owned by the caller, which must zeroize them. */
  passphrase: Uint8Array;
  onCollision: TransferCollisionStrategy;
}>;

export interface ProductionTransferExportDependencies {
  readonly validateDestination: typeof validateSecureFileDestination;
  readonly writeDestination: typeof writeSecureStreamFile;
}

export interface ProductionTransferImportDependencies {
  readonly validateSource: typeof validateSecureFileSource;
  readonly readSource: typeof readSecureFile;
}

/** One planned group creation, or a deliberate skip. */
export type TransferGroupPlan = Readonly<{
  group: GroupPayload;
  /** The name to create the group under, or `undefined` to skip the group. */
  name: string | undefined;
}>;

const DEFAULT_EXPORT_DEPENDENCIES: ProductionTransferExportDependencies = {
  validateDestination: validateSecureFileDestination,
  writeDestination: writeSecureStreamFile,
};

const DEFAULT_IMPORT_DEPENDENCIES: ProductionTransferImportDependencies = {
  validateSource: validateSecureFileSource,
  readSource: readSecureFile,
};

/**
 * Write one policy-filtered encrypted transfer protected by its own passphrase.
 *
 * The destination is validated before any plaintext document is decrypted, and
 * the file is published atomically only after the whole stream succeeds.
 */
export async function executeProductionTransferExport(
  options: ProductionTransferExportOptions,
  request: ProductionTransferExportRequest,
  overrides: Partial<ProductionTransferExportDependencies> = {},
): Promise<CliTransferExportResult> {
  const dependencies = { ...DEFAULT_EXPORT_DEPENDENCIES, ...overrides };
  const destination = validateTransferPath(request.destination);
  await guardExport(() => dependencies.validateDestination(destination));

  const vault = await options.source.getVault(options.vaultId);
  if (vault === null) throw new CliTransferExportError();

  const session = new VaultReadSession(options.source, options.vaultId);
  await session.unlock(options.rootKey);
  const counts = { groups: 0, items: 0, withheld: 0 };
  try {
    const groups =
      request.groupQuery === undefined
        ? await session.listGroups()
        : [await session.showGroup(request.groupQuery)];
    if (groups.length === 0) {
      throw new CliUsageError('The vault has no active group to transfer.');
    }

    const limits = resolveTransferLimits(TRANSFER_LIMITS);
    const written = await guardExport(() =>
      dependencies.writeDestination(
        destination,
        createEncryptedTransfer(
          {
            vaultId: options.vaultId,
            schemaVersion: vault.schemaVersion,
            documents: projectTransferDocuments(session, groups, counts),
            limits,
          },
          request.passphrase,
        ),
        limits.maximumBytes,
      ),
    );

    return {
      action: 'exported',
      vaultId: options.vaultId,
      groupCount: counts.groups,
      itemCount: counts.items,
      withheldValues: counts.withheld,
      bytes: written.bytes,
    };
  } finally {
    session.lock();
  }
}

/**
 * Apply one authenticated encrypted transfer to the unlocked vault.
 *
 * The whole file is authenticated, and the whole application is planned, before
 * the first group is created: a malformed, truncated, oversized, tampered, or
 * colliding transfer therefore fails before any mutation is enqueued.
 */
export async function executeProductionTransferImport(
  options: ProductionTransferImportOptions,
  request: ProductionTransferImportRequest,
  overrides: Partial<ProductionTransferImportDependencies> = {},
): Promise<CliTransferImportResult> {
  const dependencies = { ...DEFAULT_IMPORT_DEPENDENCIES, ...overrides };
  const source = validateTransferPath(request.source);
  await guardImport(() =>
    dependencies.validateSource(source, TRANSFER_LIMITS.maximumBytes),
  );
  const contents = await guardImport(() =>
    dependencies.readSource(source, TRANSFER_LIMITS.maximumBytes),
  );

  let transfer;
  try {
    transfer = await readEncryptedTransfer(
      singleChunk(contents),
      request.passphrase,
      TRANSFER_LIMITS,
    );
  } catch (error) {
    throw asImportError(error);
  } finally {
    zeroize(contents);
  }

  const itemsByGroup = groupTransferItems(transfer.items, transfer.groups);
  await assertTransferItemsMatchTemplates(transfer.items, transfer.groups);
  const session = new VaultReadSession(options.source, options.vaultId);
  await session.unlock(options.rootKey);
  let plan: readonly TransferGroupPlan[];
  try {
    plan = planTransferGroupNames(
      transfer.groups,
      (await session.listGroups()).map((group) => group.name),
      request.onCollision,
    );
  } finally {
    session.lock();
  }

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  let groupsCreated = 0;
  let groupsSkipped = 0;
  let itemsCreated = 0;
  let withheldValues = 0;
  let referencesDropped = 0;

  for (const entry of plan) {
    if (entry.name === undefined) {
      groupsSkipped += 1;
      continue;
    }
    const createdGroupId = await service.createGroup(
      groupCreateInput(entry.group, entry.name),
    );
    groupsCreated += 1;

    for (const document of itemsByGroup.get(entry.group.id) ?? []) {
      withheldValues += document.withheld.length;
      const reduced = itemCreateInput(document.item);
      referencesDropped += reduced.referencesDropped;
      await service.createItem(createdGroupId, reduced.input);
      itemsCreated += 1;
    }
  }

  return {
    action: 'imported',
    vaultId: options.vaultId,
    createdAt: transfer.header.createdAt,
    groupsCreated,
    groupsSkipped,
    itemsCreated,
    withheldValues,
    referencesDropped,
  };
}

/**
 * Decide, before anything is written, the name every transferred group will be
 * created under. `fail` refuses the whole transfer, `skip` drops the colliding
 * group and its items, and `rename` finds the first free suffixed candidate.
 *
 * Names chosen for earlier groups count as taken, so two identically named
 * groups inside one transfer cannot silently collapse into one.
 */
export function planTransferGroupNames(
  groups: readonly GroupPayload[],
  existingNames: readonly string[],
  strategy: TransferCollisionStrategy,
): readonly TransferGroupPlan[] {
  const taken = new Set(existingNames);
  const plan: TransferGroupPlan[] = [];
  for (const group of groups) {
    if (!taken.has(group.name)) {
      taken.add(group.name);
      plan.push({ group, name: group.name });
      continue;
    }
    if (strategy === 'fail') {
      throw new CliUsageError(
        'The transfer names a group that already exists. Re-run with --on-collision skip or --on-collision rename.',
      );
    }
    if (strategy === 'skip') {
      plan.push({ group, name: undefined });
      continue;
    }
    plan.push({ group, name: renamedGroup(group.name, taken) });
  }
  return plan;
}

/**
 * Bucket item documents by their source group, refusing a transfer that carries
 * an item whose group never arrived. Rejecting here keeps a structurally broken
 * transfer from silently losing items during application.
 */
export function groupTransferItems(
  items: readonly TransferItemDocument[],
  groups: readonly GroupPayload[],
): ReadonlyMap<string, readonly TransferItemDocument[]> {
  const known = new Set(groups.map((group) => group.id));
  const grouped = new Map<string, TransferItemDocument[]>();
  for (const document of items) {
    if (!known.has(document.item.groupId)) {
      throw new CliTransferImportError('BACKUP_INVALID');
    }
    const existing = grouped.get(document.item.groupId);
    if (existing === undefined) grouped.set(document.item.groupId, [document]);
    else existing.push(document);
  }
  return grouped;
}

/**
 * Prove, before the first mutation, that every transferred item still satisfies
 * the template it travels with.
 *
 * A transfer this CLI wrote is already projected to satisfy its own template, but
 * a file from another producer need not be. Re-checking here turns what would
 * otherwise surface mid-import — with groups already created — into a refusal
 * that leaves the destination vault untouched. The specific mismatch is folded
 * into one uniform error so the message never describes the rejected document.
 */
export async function assertTransferItemsMatchTemplates(
  items: readonly TransferItemDocument[],
  groups: readonly GroupPayload[],
): Promise<void> {
  const templates = new Map(groups.map((group) => [group.id, group.template]));
  const core = await import('@kavrix/core');
  for (const document of items) {
    const template = templates.get(document.item.groupId);
    if (template === undefined) throw new CliTransferImportError('BACKUP_INVALID');
    try {
      core.validateItemAgainstTemplate(document.item, template);
    } catch (error) {
      if (error instanceof CliTransferImportError) throw error;
      throw new CliTransferImportError('BACKUP_INVALID');
    }
  }
}

/**
 * Reduce a transferred item to a creation input.
 *
 * Every carried field is named explicitly rather than spread from the source
 * document. A payload field added later must therefore be considered before it
 * can ride into a destination vault, and an unknown field arriving in a foreign
 * transfer is dropped instead of applied.
 *
 * Source identity, revision bookkeeping, and the source slug are dropped so the
 * destination mints its own. Item-to-item references cannot survive re-minted
 * identities, so they are dropped and counted rather than left dangling, and
 * attachment identifiers are dropped because a transfer never carries the
 * attachment content they would name.
 */
export function itemCreateInput(
  item: ItemPayload,
): Readonly<{ input: CreateItemInput; referencesDropped: number }> {
  const input: CreateItemInput = {
    version: item.version,
    title: item.title,
    aliases: item.aliases,
    ...(item.subtitle === undefined ? {} : { subtitle: item.subtitle }),
    templateValues: item.templateValues,
    itemFields: item.itemFields,
    itemValues: item.itemValues,
    archivedFieldValues: item.archivedFieldValues,
    notes: item.notes,
    tags: item.tags,
    favorite: item.favorite,
    ...(item.environment === undefined ? {} : { environment: item.environment }),
    ...(item.owner === undefined ? {} : { owner: item.owner }),
    ...(item.purpose === undefined ? {} : { purpose: item.purpose }),
    productionSensitive: item.productionSensitive,
    ...(item.expiresAt === undefined ? {} : { expiresAt: item.expiresAt }),
    ...(item.rotationIntervalDays === undefined
      ? {}
      : { rotationIntervalDays: item.rotationIntervalDays }),
    ...(item.lastRotatedAt === undefined ? {} : { lastRotatedAt: item.lastRotatedAt }),
    ...(item.lastVerifiedAt === undefined
      ? {}
      : { lastVerifiedAt: item.lastVerifiedAt }),
    relatedItemIds: [],
    attachmentIds: [],
    copySequences: item.copySequences,
    ...(item.archivedAt === undefined ? {} : { archivedAt: item.archivedAt }),
  };
  return { input, referencesDropped: item.relatedItemIds.length };
}

/**
 * Reduce a transferred group to a creation input under its planned name.
 *
 * Fields are named explicitly for the same reason they are on an item. The
 * source slug is dropped because a slug is unique per vault and a renamed group
 * must not carry the original one across.
 */
export function groupCreateInput(group: GroupPayload, name: string): CreateGroupInput {
  return {
    name,
    aliases: group.aliases,
    ...(group.description === undefined ? {} : { description: group.description }),
    ...(group.icon === undefined ? {} : { icon: group.icon }),
    ...(group.colorToken === undefined ? {} : { colorToken: group.colorToken }),
    tags: group.tags,
    notes: group.notes,
    template: group.template,
    sortOrder: group.sortOrder,
    ...(group.archivedAt === undefined ? {} : { archivedAt: group.archivedAt }),
  };
}

/**
 * Stream every selected group followed by its policy-filtered items.
 *
 * The exported item set is deliberately empty. The reader mints new identities,
 * so no source item identifier is resolvable on the far side; declaring each
 * reference as withheld at export time is honest, and it keeps only one item's
 * plaintext resident at a time instead of buffering the whole vault.
 */
async function* projectTransferDocuments(
  session: VaultReadSession,
  groups: readonly GroupPayload[],
  counts: { groups: number; items: number; withheld: number },
): AsyncGenerator<TransferDocument> {
  const core = await import('@kavrix/core');
  const unresolvable: ReadonlySet<string> = new Set<string>();
  for (const group of groups) {
    counts.groups += 1;
    yield { kind: 'group', group };
    for (const item of await session.listItems(group.id)) {
      const projection = core.projectItemForTransfer(item, group.template, {
        exportedItemIds: unresolvable,
      });
      counts.items += 1;
      counts.withheld += projection.withheld.length;
      yield { kind: 'item', item: projection.item, withheld: projection.withheld };
    }
  }
}

function renamedGroup(name: string, taken: ReadonlySet<string>): string {
  for (let attempt = 2; attempt <= MAX_RENAME_ATTEMPTS; attempt += 1) {
    const candidate = `${name} (${String(attempt)})`;
    if (!taken.has(candidate)) return candidate;
  }
  throw new CliUsageError('The transferred group name could not be made unique.');
}

/**
 * Collapse every filesystem, format, and policy failure into one uniform export
 * error so the message never reveals which document or policy stopped the run.
 */
async function guardExport<Output>(operation: () => Promise<Output>): Promise<Output> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof CliUsageError) throw error;
    if (error instanceof PortableKeyFileError || error instanceof BackupError) {
      throw new CliTransferExportError();
    }
    throw error;
  }
}

async function guardImport<Output>(operation: () => Promise<Output>): Promise<Output> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof CliUsageError) throw error;
    throw asImportError(error);
  }
}

function asImportError(error: unknown): unknown {
  if (error instanceof CliTransferImportError) return error;
  if (error instanceof BackupError) return new CliTransferImportError(error.code);
  if (error instanceof PortableKeyFileError) {
    return new CliTransferImportError('BACKUP_INVALID');
  }
  return error;
}

function singleChunk(value: Uint8Array): AsyncIterable<Uint8Array> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      let sent = false;
      return {
        next: (): Promise<IteratorResult<Uint8Array>> => {
          if (sent) return Promise.resolve({ done: true, value: undefined });
          sent = true;
          return Promise.resolve({ done: false, value });
        },
      };
    },
  };
}

function validateTransferPath(input: string): string {
  if (
    input.length === 0 ||
    input.length > 4_096 ||
    Array.from(input).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 31 || codePoint === 127;
    })
  ) {
    throw new CliUsageError('The transfer file path is invalid.');
  }
  return input;
}

/** Kept so a caller can name the branded group type without re-deriving it. */
export type TransferGroupId = GroupId;
