import { createHmac, hkdfSync } from 'node:crypto';

import {
  constantTimeEqual,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from '@kavrix/crypto';
import {
  MAX_DATABASE_VAULTS,
  canonicalJson,
  databaseIdSchema,
  databaseRevisionSchema,
  sha256DigestSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type DatabaseId,
  type DatabaseRevision,
  type Sha256Digest,
  type VaultId,
  type VaultRevision,
} from '@kavrix/schemas';
import { z } from 'zod';

import { PortableKeyFileError } from './errors.js';
import {
  readSecureFile,
  readSecureFileWhileExclusive,
  replaceSecureFileWhileExclusive,
  withExclusiveSecureFile,
  writeSecureFile,
} from './filesystem.js';

const FORMAT = 'kavrix-database-revision-anchor';
const VERSION = 1;
const DOMAIN = 'kavrix/database-revision-anchor/v1';
const DRK_BYTES = 32;
const TAG_BYTES = 32;
const MAX_FILE_BYTES = 128 * 1024;
const KDF_SALT = new Uint8Array(32);
const KDF_INFO = Buffer.from(DOMAIN, 'ascii');

export const databaseVaultRevisionAnchorSchema = z
  .object({
    revision: vaultRevisionSchema,
    metadataDigest: sha256DigestSchema,
  })
  .strict();

const vaultHeadsSchema = z
  .record(vaultIdSchema, databaseVaultRevisionAnchorSchema)
  .superRefine((heads, context) => {
    const keys = Object.keys(heads);
    if (keys.length > MAX_DATABASE_VAULTS) {
      context.addIssue({
        code: 'custom',
        message: 'Database anchors may contain at most 1,000 vault heads',
      });
    }
    if (!isSorted(keys)) {
      context.addIssue({
        code: 'custom',
        message: 'Database anchor vault heads must use canonical key ordering',
      });
    }
  });

export const databaseRevisionAnchorSchema = z
  .object({
    format: z.literal(FORMAT),
    version: z.literal(VERSION),
    databaseId: databaseIdSchema,
    databaseRevision: databaseRevisionSchema,
    catalogMetadataDigest: sha256DigestSchema,
    vaultHeads: vaultHeadsSchema,
    authenticationTag: z.string().min(1),
  })
  .strict();

export type DatabaseVaultRevisionAnchor = Readonly<{
  revision: VaultRevision;
  metadataDigest: Sha256Digest;
}>;

export type DatabaseRevisionAnchor = Readonly<{
  databaseId: DatabaseId;
  databaseRevision: DatabaseRevision;
  catalogMetadataDigest: Sha256Digest;
  vaultHeads: Readonly<Record<VaultId, DatabaseVaultRevisionAnchor>>;
}>;

export type DatabaseRevisionAnchorVerificationOptions = Readonly<{
  requireExactVaultSet?: boolean;
}>;

export type DatabaseRevisionAnchorTransitionResult<Result> = Readonly<{
  nextAnchor: DatabaseRevisionAnchor;
  result: Result;
}>;

export function databaseRevisionAnchorPath(databaseKeyFilePath: string): string {
  if (typeof databaseKeyFilePath !== 'string' || databaseKeyFilePath.length === 0) {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
  return `${databaseKeyFilePath}.database-anchor`;
}

export async function writeDatabaseRevisionAnchor(
  path: string,
  databaseRootKey: Uint8Array,
  anchor: DatabaseRevisionAnchor,
  mode: 'create' | 'replace',
): Promise<void> {
  requireByteLength(databaseRootKey, DRK_BYTES, 'database root key');
  let normalized: DatabaseRevisionAnchor;
  try {
    normalized = normalizeAnchor(anchor);
  } catch {
    throw invalid();
  }
  let serialized: Uint8Array | undefined;
  try {
    serialized = serializeAnchor(databaseRootKey, normalized);
    await writeSecureFile(path, serialized, mode, MAX_FILE_BYTES);
  } finally {
    zeroize(serialized);
  }
}

/**
 * Authenticates the stored anchor. When an observed database state is supplied,
 * it additionally rejects rollback and equal-revision digest forks before the
 * caller accepts the state or advances the anchor.
 */
export async function readDatabaseRevisionAnchor(
  path: string,
  databaseRootKey: Uint8Array,
  observed?: DatabaseRevisionAnchor,
  options: DatabaseRevisionAnchorVerificationOptions = {},
): Promise<DatabaseRevisionAnchor> {
  requireByteLength(databaseRootKey, DRK_BYTES, 'database root key');
  let file: Uint8Array | undefined;
  try {
    file = await readSecureFile(path, MAX_FILE_BYTES);
    return parseAuthenticatedAnchor(file, databaseRootKey, observed, options);
  } catch {
    throw invalid();
  } finally {
    zeroize(file);
  }
}

/**
 * Runs the whole trusted anchor transition under one private protected-file
 * lock. The caller receives only the authenticated current state, returns its
 * accepted next state, and cannot publish through an unguarded filesystem API.
 */
export async function transitionDatabaseRevisionAnchor<Result>(
  path: string,
  databaseRootKey: Uint8Array,
  observed: DatabaseRevisionAnchor,
  callback: (
    trusted: DatabaseRevisionAnchor,
  ) => Promise<DatabaseRevisionAnchorTransitionResult<Result>>,
  options: DatabaseRevisionAnchorVerificationOptions = {},
): Promise<Result> {
  requireByteLength(databaseRootKey, DRK_BYTES, 'database root key');
  return withExclusiveSecureFile(path, MAX_FILE_BYTES, async (lock) => {
    let file: Uint8Array | undefined;
    let serialized: Uint8Array | undefined;
    try {
      file = await readSecureFileWhileExclusive(lock);
      const trusted = parseAuthenticatedAnchor(
        file,
        databaseRootKey,
        observed,
        options,
      );
      const transition = await callback(trusted);
      const next = normalizeAnchor(transition.nextAnchor);
      verifyDatabaseRevisionAnchor(trusted, next);
      verifyDatabaseRevisionAnchor(observed, next);
      serialized = serializeAnchor(databaseRootKey, next);
      await replaceSecureFileWhileExclusive(lock, serialized);
      return transition.result;
    } finally {
      zeroize(serialized);
      zeroize(file);
    }
  });
}

/**
 * Compares a trusted local anchor with an authenticated datastore observation.
 * The default permits a newer state so callers can atomically advance their
 * anchor after acceptance; exact vault-set mode is for stable read snapshots.
 */
export function verifyDatabaseRevisionAnchor(
  trusted: DatabaseRevisionAnchor,
  observed: DatabaseRevisionAnchor,
  options: DatabaseRevisionAnchorVerificationOptions = {},
): void {
  const prior = normalizeAnchor(trusted);
  const current = normalizeAnchor(observed);
  if (prior.databaseId !== current.databaseId) throw invalid();
  if (current.databaseRevision < prior.databaseRevision) throw invalid();
  if (
    current.databaseRevision === prior.databaseRevision &&
    current.catalogMetadataDigest !== prior.catalogMetadataDigest
  )
    throw invalid();
  const priorIds = Object.keys(prior.vaultHeads);
  const currentIds = Object.keys(current.vaultHeads);
  if (options.requireExactVaultSet === true && !sameSet(priorIds, currentIds))
    throw invalid();
  for (const id of priorIds) {
    const before = prior.vaultHeads[id as VaultId];
    const after = current.vaultHeads[id as VaultId];
    if (before === undefined || after === undefined) throw invalid();
    if (after.revision < before.revision) throw invalid();
    if (
      after.revision === before.revision &&
      after.metadataDigest !== before.metadataDigest
    )
      throw invalid();
  }
  if (options.requireExactVaultSet === true) {
    for (const id of currentIds) {
      if (prior.vaultHeads[id as VaultId] === undefined) throw invalid();
    }
  }
}

function serializeAnchor(
  databaseRootKey: Uint8Array,
  anchor: DatabaseRevisionAnchor,
): Uint8Array {
  let message: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  try {
    message = anchorMessage(anchor);
    tag = hmac(databaseRootKey, message);
    const envelope = databaseRevisionAnchorSchema.parse({
      format: FORMAT,
      version: VERSION,
      ...anchor,
      authenticationTag: encodeBase64Url(tag),
    });
    const serialized = Buffer.from(`${canonicalJson(envelope)}\n`, 'utf8');
    if (serialized.byteLength > MAX_FILE_BYTES) {
      zeroize(serialized);
      throw invalid();
    }
    return serialized;
  } finally {
    zeroize(tag);
    zeroize(message);
  }
}

function parseAuthenticatedAnchor(
  file: Uint8Array,
  databaseRootKey: Uint8Array,
  observed?: DatabaseRevisionAnchor,
  options: DatabaseRevisionAnchorVerificationOptions = {},
): DatabaseRevisionAnchor {
  let suppliedTag: Uint8Array | undefined;
  let expectedTag: Uint8Array | undefined;
  let message: Uint8Array | undefined;
  try {
    const envelope = parseEnvelope(file);
    const trusted = toAnchor(envelope);
    message = anchorMessage(trusted);
    suppliedTag = decodeBase64Url(envelope.authenticationTag, {
      exactBytes: TAG_BYTES,
    });
    expectedTag = hmac(databaseRootKey, message);
    if (!constantTimeEqual(suppliedTag, expectedTag)) throw invalid();
    if (observed !== undefined)
      verifyDatabaseRevisionAnchor(trusted, observed, options);
    return trusted;
  } finally {
    zeroize(message);
    zeroize(expectedTag);
    zeroize(suppliedTag);
  }
}

function parseEnvelope(file: Uint8Array): z.infer<typeof databaseRevisionAnchorSchema> {
  try {
    const text = Buffer.from(file).toString('utf8');
    if (!text.endsWith('\n') || text.endsWith('\n\n')) throw invalid();
    const value: unknown = JSON.parse(text);
    if (canonicalJson(value) + '\n' !== text) throw invalid();
    return databaseRevisionAnchorSchema.parse(value);
  } catch {
    throw invalid();
  }
}

function normalizeAnchor(anchor: DatabaseRevisionAnchor): DatabaseRevisionAnchor {
  const heads: Record<VaultId, DatabaseVaultRevisionAnchor> = {};
  for (const vaultId of Object.keys(anchor.vaultHeads).sort()) {
    const parsedId = vaultIdSchema.parse(vaultId);
    const head = anchor.vaultHeads[parsedId];
    if (head === undefined) throw invalid();
    heads[parsedId] = databaseVaultRevisionAnchorSchema.parse(head);
  }
  const parsed = databaseRevisionAnchorSchema
    .pick({
      databaseId: true,
      databaseRevision: true,
      catalogMetadataDigest: true,
      vaultHeads: true,
    })
    .parse({
      databaseId: anchor.databaseId,
      databaseRevision: anchor.databaseRevision,
      catalogMetadataDigest: anchor.catalogMetadataDigest,
      vaultHeads: heads,
    });
  return {
    databaseId: parsed.databaseId,
    databaseRevision: parsed.databaseRevision,
    catalogMetadataDigest: parsed.catalogMetadataDigest,
    vaultHeads: parsed.vaultHeads,
  };
}

function toAnchor(
  envelope: z.infer<typeof databaseRevisionAnchorSchema>,
): DatabaseRevisionAnchor {
  return {
    databaseId: envelope.databaseId,
    databaseRevision: envelope.databaseRevision,
    catalogMetadataDigest: envelope.catalogMetadataDigest,
    vaultHeads: envelope.vaultHeads,
  };
}

function anchorMessage(anchor: DatabaseRevisionAnchor): Uint8Array {
  return Buffer.from(
    canonicalJson({ domain: DOMAIN, format: FORMAT, version: VERSION, ...anchor }),
    'utf8',
  );
}

function hmac(databaseRootKey: Uint8Array, message: Uint8Array): Uint8Array {
  const anchorKey = new Uint8Array(
    hkdfSync('sha256', databaseRootKey, KDF_SALT, KDF_INFO, DRK_BYTES),
  );
  try {
    return Uint8Array.from(createHmac('sha256', anchorKey).update(message).digest());
  } finally {
    zeroize(anchorKey);
  }
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length && left.every((entry, index) => entry === right[index])
  );
}

function isSorted(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index += 1) {
    const previous = values[index - 1];
    const current = values[index];
    if (previous === undefined || current === undefined || previous > current)
      return false;
  }
  return true;
}

function invalid(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}
