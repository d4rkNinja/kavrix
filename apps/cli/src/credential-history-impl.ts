/**
 * History metadata and guarded restoration. Legacy isolated envelopes remain
 * read-only. New snapshots are authenticated by the version 2 vault envelope;
 * no snapshot values are printed by these commands.
 */
import type { Command } from 'commander';
import { timestampSchema } from '@kavrix/schemas';
import { restoreItemSnapshot } from './item-snapshots.js';

import {
  encryptedHistoryRecordSchema,
  type StructuredVaultPayload,
} from '@kavrix/schemas';

import {
  readDatabaseFlatSecrets,
  withDatabaseFlatVault,
  type DatabaseFlatCommandOptions,
} from './database-flat-commands.js';
import { LocalCliError } from './cli-error.js';
import { credentialMissing, securityIntegrityFailure } from './execution/exit-codes.js';
import { sanitizeJsonValue } from './local-vault-cli.js';
import { resolveProfileConfigDirectory } from './profile-config-directory.js';
import {
  resolveItem,
  resolveProjectContext,
  resolveService,
  structuredRoutingOverrides,
  type StructuredRoutingInput,
} from './structured-vault-impl.js';

/** Default number of history entries reported by one list. */
export const CREDENTIAL_HISTORY_DEFAULT_LIST_LIMIT = 50;

/** Hard ceiling for one list so a large history cannot flood stdout. */
export const CREDENTIAL_HISTORY_MAX_LIST_LIMIT = 500;

/**
 * Non-sensitive metadata for one history record. Deliberately free of anything
 * derived from `encryptedPayload`: only identities, revisions, versions, and
 * digests that `structuredVaultPayloadSchema` already authenticates.
 */
export type CredentialHistoryEntry = Readonly<{
  /** Opaque history record identity; the exact `<version>` argument of `show`. */
  version: string;
  /** Item revision this snapshot captured, not a per-record sequence number. */
  itemRevision: number;
  createdAt: string;
  /** Schema version of the encrypted record envelope. */
  schemaVersion: number;
  /** Key version the snapshot envelope was sealed under. */
  keyVersion?: number;
  ciphertextHash?: string;
  restorable?: boolean;
}>;

export type CredentialHistoryProjection = Readonly<{
  context: string;
  service: string;
  item: string;
  history: readonly CredentialHistoryEntry[];
  truncated: boolean;
}>;

/**
 * A history command option failure is a local CLI error so reviewed messages
 * reach the user unchanged. The stable machine-readable classes (not found,
 * integrity) are raised as coded errors from `./execution/exit-codes.js`.
 */
export class CredentialHistoryCommandError extends LocalCliError {
  public constructor(message: string) {
    super(message);
    this.name = 'CredentialHistoryCommandError';
  }
}

/**
 * Projects one item's history records into non-sensitive metadata.
 *
 * Resolution and ordering are deterministic: names resolve exactly, records are
 * ordered by creation timestamp then identity, and the list is bounded. A record
 * that is present but malformed, or that is not bound to the resolved vault,
 * group, and item, fails the whole projection closed instead of being skipped —
 * a partially listed history would misrepresent what the vault holds.
 */
export function projectCredentialHistory(
  payload: StructuredVaultPayload,
  request: Readonly<{
    context: string;
    service: string;
    item: string;
    limit: number;
  }>,
): CredentialHistoryProjection {
  const base = projectItemHistory(payload, request);
  const limit = normalizeListLimit(request.limit);
  return {
    context: base.context,
    service: base.service,
    item: base.item,
    history: base.entries.slice(0, limit),
    truncated: base.entries.length > limit,
  };
}

/**
 * Full projection for exact entry resolution. The list ceiling bounds display
 * output only: `credential history show <version>` must resolve the requested
 * entry against every collected record, so a version beyond the 500-record
 * list limit still resolves instead of reporting a missing credential.
 */
export function projectCredentialHistoryForResolve(
  payload: StructuredVaultPayload,
  request: Readonly<{
    context: string;
    service: string;
    item: string;
  }>,
): CredentialHistoryProjection {
  const base = projectItemHistory(payload, request);
  return {
    context: base.context,
    service: base.service,
    item: base.item,
    history: base.entries,
    truncated: false,
  };
}

function projectItemHistory(
  payload: StructuredVaultPayload,
  request: Readonly<{
    context: string;
    service: string;
    item: string;
  }>,
): Readonly<{
  context: string;
  service: string;
  item: string;
  entries: readonly CredentialHistoryEntry[];
}> {
  const context = resolveContextOrMissing(payload, request.context);
  const group = resolveServiceOrMissing(payload, context.id, request.service);
  const item = resolveItemOrMissing(payload, group.id, request.item);
  return {
    context: context.name,
    service: group.name,
    item: item.title,
    entries: collectHistoryEntries(payload, item.id, group.id, payload.vaultId),
  };
}

/** Selects exactly one history entry by its opaque record identity. */
export function resolveCredentialHistoryEntry(
  entries: readonly CredentialHistoryEntry[],
  version: string,
): CredentialHistoryEntry {
  const requested = version.trim();
  const matches = entries.filter((entry) => entry.version === requested);
  if (matches.length !== 1) throw credentialMissing();
  const match = matches[0];
  if (match === undefined) throw credentialMissing();
  return match;
}

/** Parses and bounds the `--limit` option. */
export function parseCredentialHistoryListLimit(value: unknown): number {
  if (value === undefined) return CREDENTIAL_HISTORY_DEFAULT_LIST_LIMIT;
  if (typeof value !== 'string') {
    throw new CredentialHistoryCommandError('--limit must be an integer.');
  }
  const parsed = Number(value.trim());
  if (
    !Number.isSafeInteger(parsed) ||
    parsed < 1 ||
    parsed > CREDENTIAL_HISTORY_MAX_LIST_LIMIT
  ) {
    throw new CredentialHistoryCommandError(
      `--limit must be an integer between 1 and ${String(CREDENTIAL_HISTORY_MAX_LIST_LIMIT)}.`,
    );
  }
  return parsed;
}

/** Handler for `credential history list <title>`. */
export async function credentialHistoryList(
  title: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
  const flat = commandOptions(command);
  const contextName = requiredOption(options, 'context');
  const serviceName = requiredOption(options, 'service');
  const limit = parseCredentialHistoryListLimit(options['limit']);
  const values = await readDatabaseFlatSecrets(flat, []);
  await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
    let projection: CredentialHistoryProjection | undefined;
    const document = await session.inspectStructuredVault(vaultId, (payload) => {
      projection = projectCredentialHistory(payload, {
        context: contextName,
        service: serviceName,
        item: title,
        limit,
      });
    });
    if (projection === undefined) {
      throw new CredentialHistoryCommandError('Credential history was not projected.');
    }
    writeJsonResult({ ...projection, revision: document.revision });
  });
}

/** Handler for `credential history show <title> <version>`. */
export async function credentialHistoryShow(
  title: string,
  version: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
  const flat = commandOptions(command);
  const contextName = requiredOption(options, 'context');
  const serviceName = requiredOption(options, 'service');
  const values = await readDatabaseFlatSecrets(flat, []);
  await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
    let result: Record<string, unknown> | undefined;
    const document = await session.inspectStructuredVault(vaultId, (payload) => {
      // Resolution uses the full collected entry set: the list ceiling bounds
      // display only, so an entry beyond it still resolves with `show`.
      const projection = projectCredentialHistoryForResolve(payload, {
        context: contextName,
        service: serviceName,
        item: title,
      });
      const entry = resolveCredentialHistoryEntry(projection.history, version);
      result = {
        context: projection.context,
        service: projection.service,
        item: projection.item,
        ...entry,
        // Show never prints values. New vault snapshots are restored through
        // the mutation command; legacy isolated envelopes remain metadata-only.
        revealable: false,
      };
    });
    if (result === undefined) {
      throw new CredentialHistoryCommandError('Credential history was not projected.');
    }
    writeJsonResult({ ...result, revision: document.revision });
  });
}

/**
 * Collects and validates the history entries bound to one item.
 *
 * The record-level re-validation is defense in depth behind
 * `structuredVaultPayloadSchema`: a payload that reaches this function through
 * the session was already authenticated and fully parsed, but the projection is
 * also a public contract, so a malformed record must fail closed here instead of
 * being reported as an ordinary entry.
 */
function collectHistoryEntries(
  payload: StructuredVaultPayload,
  itemId: string,
  groupId: string,
  vaultId: string,
): readonly CredentialHistoryEntry[] {
  const entries: CredentialHistoryEntry[] = [];
  for (const snapshot of payload.snapshots ?? []) {
    if (
      snapshot.item.id !== itemId ||
      snapshot.item.groupId !== groupId ||
      snapshot.item.vaultId !== vaultId
    )
      continue;
    entries.push({
      version: snapshot.id,
      itemRevision: snapshot.item.revision,
      createdAt: snapshot.createdAt,
      schemaVersion: 2,
      restorable: true,
    });
  }
  for (const record of payload.history) {
    if (
      record.vaultId !== vaultId ||
      record.groupId !== groupId ||
      record.itemId !== itemId
    ) {
      continue;
    }
    if (!encryptedHistoryRecordSchema.safeParse(record).success) {
      throw securityIntegrityFailure('Credential history record failed validation.');
    }
    entries.push({
      version: record.id,
      itemRevision: record.itemRecordRevision,
      createdAt: record.createdAt,
      schemaVersion: record.schemaVersion,
      keyVersion: record.encryptedPayload.keyVersion,
      ciphertextHash: record.ciphertextHash,
    });
  }
  return entries.sort(compareHistoryEntries);
}

function compareHistoryEntries(
  left: CredentialHistoryEntry,
  right: CredentialHistoryEntry,
): number {
  if (left.createdAt !== right.createdAt) {
    return left.createdAt < right.createdAt ? -1 : 1;
  }
  return left.version.localeCompare(right.version);
}

function resolveContextOrMissing(
  payload: StructuredVaultPayload,
  name: string,
): Readonly<{ id: string; name: string }> {
  try {
    const context = resolveProjectContext(payload, name);
    return { id: context.id, name: context.name };
  } catch (error) {
    throw asCredentialMissing(error);
  }
}

function resolveServiceOrMissing(
  payload: StructuredVaultPayload,
  projectContextId: string,
  name: string,
): Readonly<{ id: string; name: string }> {
  try {
    const group = resolveService(payload, projectContextId, name);
    return { id: group.id, name: group.name };
  } catch (error) {
    throw asCredentialMissing(error);
  }
}

function resolveItemOrMissing(
  payload: StructuredVaultPayload,
  groupId: string,
  title: string,
): Readonly<{ id: string; title: string }> {
  try {
    const item = resolveItem(payload, groupId, title);
    return { id: item.id, title: item.title };
  } catch (error) {
    throw asCredentialMissing(error);
  }
}

/**
 * Name resolution in this family reports the stable `CREDENTIAL_MISSING` class
 * so automation reads exit 11 instead of the sibling family's generic local
 * error. The canonical resolvers already keep their messages free of record
 * content, and the coded message carries no identifier at all.
 */
function asCredentialMissing(error: unknown): unknown {
  return error instanceof LocalCliError ? credentialMissing() : error;
}

function normalizeListLimit(limit: number): number {
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new CredentialHistoryCommandError('--limit must be a positive integer.');
  }
  return limit;
}

function commandOptions(command: Command): DatabaseFlatCommandOptions {
  const options = command.opts<Record<string, unknown>>();
  const vault = options['vault'];
  if (typeof vault !== 'string') {
    throw new CredentialHistoryCommandError('A vault is required.');
  }
  const vaultSource = command.getOptionValueSource('vault');
  const profile = stringOption(options, 'profile');
  const profileConfigDir = resolveProfileConfigDirectory(
    stringOption(options, 'profileConfigDir'),
    stringOption(options, 'configDir'),
  );
  const datastore = stringOption(options, 'datastore');
  const dataFile = stringOption(options, 'dataFile');
  const database = stringOption(options, 'database');
  const collection = stringOption(options, 'collection');
  const keyFile = stringOption(options, 'keyFile');
  const routing: StructuredRoutingInput = {
    ...(datastore === undefined ? {} : { datastore }),
    ...(dataFile === undefined ? {} : { dataFile }),
    ...(database === undefined ? {} : { database }),
    ...(collection === undefined ? {} : { collection }),
    ...(keyFile === undefined ? {} : { keyFile }),
  };
  return {
    vault,
    ...(vaultSource === undefined || vaultSource === 'default'
      ? { vaultWasDefaulted: true }
      : {}),
    ...(profile === undefined ? {} : { profile }),
    ...(profileConfigDir === undefined ? {} : { profileConfigDir }),
    ...(datastore === undefined ? {} : { datastore }),
    ...(dataFile === undefined ? {} : { dataFile }),
    ...(database === undefined ? {} : { database }),
    ...(collection === undefined ? {} : { collection }),
    ...(keyFile === undefined ? {} : { keyFile }),
    routingOverrides: structuredRoutingOverrides(routing),
    ...(options['databaseUrlStdin'] === true ? { databaseUrlStdin: true } : {}),
    ...(options['passphraseStdin'] === true ? { passphraseStdin: true } : {}),
    ...(options['allowInsecureTransport'] === true
      ? { allowInsecureTransport: true }
      : {}),
  };
}

function stringOption(
  options: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = options[key];
  return typeof value === 'string' ? value : undefined;
}

function requiredOption(options: Record<string, unknown>, key: string): string {
  const value = options[key];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new CredentialHistoryCommandError(`Missing required option --${key}.`);
  }
  return value;
}

function writeJsonResult(value: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(sanitizeJsonValue(value)) + '\n');
}

export async function credentialHistoryRestore(
  title: string,
  version: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
  const flat = commandOptions(command);
  const context = requiredOption(options, 'context');
  const service = requiredOption(options, 'service');
  const values = await readDatabaseFlatSecrets(flat, []);
  await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
    const document = await session.updateStructuredVault(vaultId, (payload) =>
      restoreItemSnapshot(
        payload,
        context,
        service,
        title,
        version,
        timestampSchema.parse(new Date().toISOString()),
      ),
    );
    writeJsonResult({ restored: true, version, revision: document.revision });
  });
}
