import { createHash, createHmac, hkdfSync } from 'node:crypto';

import {
  MAX_COLLABORATIVE_AUTHORIZATION_WITNESS_BYTES,
  MAX_COLLABORATIVE_IDENTITY_BYTES,
  MAX_COLLABORATIVE_OPERATION_BYTES,
  MAX_COLLABORATIVE_ROLLBACK_ANCHOR_BYTES,
  MAX_COLLABORATIVE_VAULT_DOCUMENT_BYTES,
  canonicalJson,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationMutationProofEntrySchema,
  collaborationOperationIdSchema,
  collaborativeVaultDocumentSchema,
  durableOperationOutcomeSchema,
  publicIdentityExportSchema,
  recipientRollbackAnchorSchema,
  sha256DigestSchema,
  timestampSchema,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationMigrationActiveMarker,
  type CollaborationMigrationPreparedMarker,
  type CollaborationMigrationRequest,
  type CollaborationOperationId,
  type CollaborativeVaultDocument,
  type DatabaseId,
  type DeviceId,
  type DurableOperationOutcome,
  type PrincipalId,
  type PublicIdentityExport,
  type RecipientRollbackAnchor,
  type Sha256Digest,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';
import {
  constantTimeEqual,
  computeLegacySourceDigest,
  computeMigrationRequestDigest,
  computeDiscoveryTag,
  computePublicKeyFingerprint,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from '@kavrix/crypto';
import { z } from 'zod';

import {
  ProtectedJsonDocumentError,
  readProtectedJsonDocument,
  transitionProtectedJsonDocument,
  writeProtectedJsonDocument,
  type CanonicalJsonDocumentSchema,
} from './canonical-json-document.js';
import {
  collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument,
  readCollaborationAuthorityRollbackAnchor,
  type CollaborationAuthorityRollbackAnchorScope,
} from './collaboration-authority-anchor.js';
import {
  computeFinalizedMutationLinkDigest,
  readRecipientRollbackAnchor,
  type RecipientRollbackAnchorScope,
} from './collaboration-anchor.js';
import { PortableKeyFileError } from './errors.js';

export const COLLABORATION_MIGRATION_JOURNAL_SUFFIX =
  '.collaboration-migration-journal';
export const COLLABORATION_MIGRATION_JOURNAL_FORMAT =
  'kavrix-collaboration-migration-journal';
export const COLLABORATION_MIGRATION_JOURNAL_VERSION = 1;

const FORMAT = COLLABORATION_MIGRATION_JOURNAL_FORMAT;
const VERSION = COLLABORATION_MIGRATION_JOURNAL_VERSION;
const DOMAIN = 'kavrix/collaboration-migration-journal/v1';
const KDF_DOMAIN = 'kavrix/collaboration-migration-journal/hmac-key/v1';
const KDF_SALT_DOMAIN = 'kavrix/collaboration-migration-journal/hkdf-salt/v1';
const SECRET_BYTES = 32;
const TAG_BYTES = 32;
const ENVELOPE_OVERHEAD_BYTES = 64 * 1024;

/**
 * Sum of the canonical component bounds plus fixed journal overhead. The
 * secure-file reader enforces this before allocating or parsing JSON.
 */
export const MAX_COLLABORATION_MIGRATION_JOURNAL_BYTES =
  2 * MAX_COLLABORATIVE_VAULT_DOCUMENT_BYTES +
  MAX_COLLABORATIVE_IDENTITY_BYTES +
  MAX_COLLABORATIVE_AUTHORIZATION_WITNESS_BYTES +
  3 * MAX_COLLABORATIVE_OPERATION_BYTES +
  MAX_COLLABORATIVE_ROLLBACK_ANCHOR_BYTES +
  ENVELOPE_OVERHEAD_BYTES;

const KDF_SALT = createHash('sha256').update(KDF_SALT_DOMAIN, 'ascii').digest();
const authenticationTagSchema = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/u);

export const collaborationMigrationJournalStateSchema = z.enum([
  'prepared',
  'published',
  'anchored',
  'active',
  'failed',
]);

export type CollaborationMigrationJournalState = z.infer<
  typeof collaborationMigrationJournalStateSchema
>;

export type CollaborationMigrationJournalScope = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  principalId: PrincipalId;
  deviceId: DeviceId;
  operationId: CollaborationOperationId;
  requestDigest: Sha256Digest;
}>;

export const collaborationMigrationRestartRecipientSchema = z
  .object({
    principalId: recipientRollbackAnchorSchema.shape.principalId,
    deviceId: recipientRollbackAnchorSchema.shape.deviceId,
  })
  .strict();

export type CollaborationMigrationRestartRecipient = z.infer<
  typeof collaborationMigrationRestartRecipientSchema
>;

type CollaborationMutationProofEntry = z.infer<
  typeof collaborationMutationProofEntrySchema
>;

export const collaborationMigrationJournalCreateInputSchema = z
  .object({
    request: collaborationMigrationRequestSchema,
    registryCandidate: collaborationDatabaseDeviceRegistrySchema,
    preparedMarker: collaborationMigrationPreparedMarkerSchema,
    activeMarker: collaborationMigrationActiveMarkerSchema,
    collaborativeCandidate: collaborativeVaultDocumentSchema,
    proofEntry: collaborationMutationProofEntrySchema,
    proposedOutcome: durableOperationOutcomeSchema,
    initialRecipientAnchor: recipientRollbackAnchorSchema,
    initialOwnerIdentity: publicIdentityExportSchema,
    restartRecipient: collaborationMigrationRestartRecipientSchema,
  })
  .strict()
  .superRefine((input, context) => {
    try {
      assertPreparedBundle(input);
    } catch {
      addIssue(context, 'Migration journal bundle has an invalid binding');
    }
  });

export type CollaborationMigrationJournalCreateInput = z.infer<
  typeof collaborationMigrationJournalCreateInputSchema
>;

type JournalIdentity = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  principalId: PrincipalId;
  deviceId: DeviceId;
  operationId: CollaborationOperationId;
  requestDigest: Sha256Digest;
}>;

type JournalBundle = Readonly<{
  request: CollaborationMigrationRequest;
  registryCandidate: CollaborationDatabaseDeviceRegistry;
  preparedMarker: CollaborationMigrationPreparedMarker;
  activeMarker: CollaborationMigrationActiveMarker;
  collaborativeCandidate: CollaborativeVaultDocument;
  proofEntry: CollaborationMutationProofEntry;
  proposedOutcome: DurableOperationOutcome;
  initialRecipientAnchor: RecipientRollbackAnchor;
  initialOwnerIdentity: PublicIdentityExport;
  restartRecipient: CollaborationMigrationRestartRecipient;
}>;

const journalBaseSchema = z
  .object({
    format: z.literal(FORMAT),
    version: z.literal(VERSION),
    databaseId: recipientRollbackAnchorSchema.shape.databaseId,
    vaultId: recipientRollbackAnchorSchema.shape.vaultId,
    principalId: recipientRollbackAnchorSchema.shape.principalId,
    deviceId: recipientRollbackAnchorSchema.shape.deviceId,
    operationId: collaborationOperationIdSchema,
    requestDigest: sha256DigestSchema,
    request: collaborationMigrationRequestSchema,
    registryCandidate: collaborationDatabaseDeviceRegistrySchema,
    preparedMarker: collaborationMigrationPreparedMarkerSchema,
    activeMarker: collaborationMigrationActiveMarkerSchema,
    collaborativeCandidate: collaborativeVaultDocumentSchema,
    proofEntry: collaborationMutationProofEntrySchema,
    proposedOutcome: durableOperationOutcomeSchema,
    initialRecipientAnchor: recipientRollbackAnchorSchema,
    initialOwnerIdentity: publicIdentityExportSchema,
    restartRecipient: collaborationMigrationRestartRecipientSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    authenticationTag: authenticationTagSchema,
  })
  .strict();

const progressingJournalSchema = journalBaseSchema
  .extend({
    state: z.enum(['prepared', 'published', 'anchored', 'active']),
  })
  .strict()
  .superRefine((record, context) => {
    assertJournalSchemaBinding(record, context);
  });

const failedJournalSchema = journalBaseSchema
  .extend({
    state: z.literal('failed'),
    authoritativeOutcome: durableOperationOutcomeSchema,
  })
  .strict()
  .superRefine((record, context) => {
    assertJournalSchemaBinding(record, context);
    try {
      assertAuthoritativeOutcomeIdentity(record, record.authoritativeOutcome);
      if (sameCanonical(record.proposedOutcome, record.authoritativeOutcome)) {
        addIssue(context, 'A matching committed outcome cannot terminalize as failed');
      }
    } catch {
      addIssue(context, 'Failed migration journal has invalid authoritative evidence');
    }
  });

export const collaborationMigrationJournalRecordSchema = z.discriminatedUnion('state', [
  progressingJournalSchema,
  failedJournalSchema,
]);

type JournalEnvelope = z.infer<typeof collaborationMigrationJournalRecordSchema>;
type WithoutAuthenticationTag<T> = T extends unknown
  ? Omit<T, 'authenticationTag'>
  : never;

export type CollaborationMigrationJournalRecord =
  WithoutAuthenticationTag<JournalEnvelope>;

const journalDocumentSchema: CanonicalJsonDocumentSchema<JournalEnvelope> =
  collaborationMigrationJournalRecordSchema;

export type CollaborationMigrationJournalReadOptions = Readonly<{
  expectedScope: CollaborationMigrationJournalScope;
}>;

export function collaborationMigrationJournalPath(
  basePath: string,
  databaseId: DatabaseId,
  vaultId: VaultId,
  operationId: CollaborationOperationId,
): string {
  assertPath(basePath);
  const database = parsePathDatabaseId(databaseId);
  const vault = parsePathVaultId(vaultId);
  const operation = parsePathOperationId(operationId);
  return `${basePath}${COLLABORATION_MIGRATION_JOURNAL_SUFFIX}.${database}.${vault}.${operation}`;
}

/** Creates the immutable migration bundle before any remote publication. */
export async function createCollaborationMigrationJournal(
  path: string,
  deviceProtectionSecret: Uint8Array,
  input: CollaborationMigrationJournalCreateInput,
): Promise<void> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const prepared = buildPreparedRecord(input);
  const envelope = serializeJournal(deviceProtectionSecret, prepared);
  try {
    await writeProtectedJsonDocument(path, envelope, 'create', documentOptions());
    return;
  } catch (error) {
    if (
      !(error instanceof PortableKeyFileError) ||
      error.code !== 'KEY_FILE_ALREADY_EXISTS'
    ) {
      throw mapJournalError(error);
    }
  }

  const existing = await readJournalWithoutScope(path, deviceProtectionSecret);
  if (existing === null || !sameImmutableBundle(existing, prepared)) {
    throw invalidJournal();
  }
}

/** Reads an authenticated journal; absence is the only null result. */
export async function readCollaborationMigrationJournal(
  path: string,
  deviceProtectionSecret: Uint8Array,
  options: CollaborationMigrationJournalReadOptions,
): Promise<CollaborationMigrationJournalRecord | null> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const scope = parseScope(options);
  const record = await readJournalWithoutScope(path, deviceProtectionSecret);
  if (record === null) return null;
  assertScope(record, scope);
  return record;
}

/** Reads one authenticated journal when its scope must be recovered after restart. */
export async function readCollaborationMigrationJournalForResume(
  path: string,
  deviceProtectionSecret: Uint8Array,
): Promise<CollaborationMigrationJournalRecord | null> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  return await readJournalWithoutScope(path, deviceProtectionSecret);
}

/**
 * Records the authoritative publication outcome. Exact committed bytes move
 * prepared -> published. A same-operation/same-request incompatible outcome
 * is the only path to terminal failed state.
 */
export async function reconcileCollaborationMigrationPublication(
  path: string,
  deviceProtectionSecret: Uint8Array,
  authoritativeOutcome: DurableOperationOutcome,
): Promise<'published' | 'failed'> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const outcome = parseOutcome(authoritativeOutcome);
  // Opaque conflict/rejection responses are not proof that the prepared
  // genesis was rejected. Keep the protected bundle retryable until a
  // committed outcome carrying its writer-signed receipt and finalized-link
  // digest is available.
  if (outcome.state !== 'committed') {
    throw invalidJournal();
  }
  try {
    return await transitionProtectedJsonDocument(
      path,
      documentOptions(),
      (currentEnvelope) => {
        const current = parseAuthenticatedJournal(
          deviceProtectionSecret,
          currentEnvelope,
        );
        if (current.state === 'failed') {
          if (!sameCanonical(current.authoritativeOutcome, outcome)) {
            throw invalidJournal();
          }
          return { document: currentEnvelope, result: 'failed' as const };
        }
        if (current.state === 'published') {
          if (!sameCanonical(current.proposedOutcome, outcome)) {
            throw invalidJournal();
          }
          return { document: currentEnvelope, result: 'published' as const };
        }
        if (current.state !== 'prepared') throw invalidJournal();
        assertAuthoritativeOutcomeIdentity(current, outcome);
        if (sameCanonical(current.proposedOutcome, outcome)) {
          const next = withProgressState(current, 'published');
          return {
            document: serializeJournal(deviceProtectionSecret, next),
            result: 'published' as const,
          };
        }
        const failed = withFailure(current, outcome);
        return {
          document: serializeJournal(deviceProtectionSecret, failed),
          result: 'failed' as const,
        };
      },
    );
  } catch (error) {
    throw mapJournalError(error);
  }
}

/** Records that both exact genesis freshness anchors were durably persisted. */
export async function markCollaborationMigrationAnchored(
  path: string,
  deviceProtectionSecret: Uint8Array,
  persistedRecipientAnchorPath: string,
  expectedRecipientAnchorScope: RecipientRollbackAnchorScope,
  persistedAuthorityAnchorPath: string,
  databaseRootKey: Uint8Array,
  expectedAuthorityAnchorScope: CollaborationAuthorityRollbackAnchorScope,
): Promise<void> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  assertPath(persistedRecipientAnchorPath);
  assertPath(persistedAuthorityAnchorPath);
  const recipientScope = parseAnchorScope(expectedRecipientAnchorScope);
  await advanceProgressState(
    path,
    deviceProtectionSecret,
    'published',
    'anchored',
    async (current) => {
      try {
        const recipientAnchor = await readRecipientRollbackAnchor(
          persistedRecipientAnchorPath,
          deviceProtectionSecret,
          { expectedScope: recipientScope },
        );
        const authorityAnchor = await readCollaborationAuthorityRollbackAnchor(
          persistedAuthorityAnchorPath,
          databaseRootKey,
          { expectedScope: expectedAuthorityAnchorScope },
        );
        const expectedAuthorityAnchor =
          collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
            current.collaborativeCandidate,
            {
              membershipDigest: current.initialRecipientAnchor.membershipDigest,
              policyDigest: current.initialRecipientAnchor.policyDigest,
            },
          );
        return (
          sameCanonical(current.initialRecipientAnchor, recipientAnchor) &&
          sameCanonical(expectedAuthorityAnchor, authorityAnchor)
        );
      } catch {
        // The migration must never advance based on absent, malformed, or
        // cross-scope anchor paths. Keep the public failure deliberately generic.
        return false;
      }
    },
  );
}

/** Records that the exact precomputed active marker is authoritative. */
export async function markCollaborationMigrationActive(
  path: string,
  deviceProtectionSecret: Uint8Array,
  observedActiveMarker: CollaborationMigrationActiveMarker,
): Promise<void> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const marker = parseActiveMarker(observedActiveMarker);
  await advanceProgressState(
    path,
    deviceProtectionSecret,
    'anchored',
    'active',
    (current) => sameCanonical(current.activeMarker, marker),
  );
}

async function advanceProgressState(
  path: string,
  secret: Uint8Array,
  expectedState: 'published' | 'anchored',
  nextState: 'anchored' | 'active',
  evidenceMatches: (current: JournalEnvelope) => boolean | Promise<boolean>,
): Promise<void> {
  try {
    await transitionProtectedJsonDocument(
      path,
      documentOptions(),
      async (currentEnvelope) => {
        const current = parseAuthenticatedJournal(secret, currentEnvelope);
        if (!(await evidenceMatches(current))) throw invalidJournal();
        if (current.state === nextState) {
          return { document: currentEnvelope, result: undefined };
        }
        if (current.state !== expectedState) {
          throw invalidJournal();
        }
        const next = withProgressState(current, nextState);
        return {
          document: serializeJournal(secret, next),
          result: undefined,
        };
      },
    );
  } catch (error) {
    throw mapJournalError(error);
  }
}

function buildPreparedRecord(
  input: CollaborationMigrationJournalCreateInput,
): CollaborationMigrationJournalRecord {
  try {
    const bundle = collaborationMigrationJournalCreateInputSchema.parse(
      structuredClone(input),
    );
    const identity = identityFromBundle(bundle);
    return {
      format: FORMAT,
      version: VERSION,
      ...identity,
      state: 'prepared',
      ...bundle,
      createdAt: bundle.preparedMarker.preparedAt,
      updatedAt: bundle.preparedMarker.preparedAt,
    };
  } catch {
    throw invalidJournal();
  }
}

function identityFromBundle(bundle: JournalBundle): JournalIdentity {
  return {
    databaseId: bundle.request.databaseId,
    vaultId: bundle.request.vaultId,
    principalId: bundle.request.initialOwnerPrincipalId,
    deviceId: bundle.request.initialOwnerDeviceId,
    operationId: bundle.request.operationId,
    requestDigest: bundle.request.requestDigest,
  };
}

function withProgressState(
  current: Exclude<JournalEnvelope, { state: 'failed' }>,
  state: 'published' | 'anchored' | 'active',
): CollaborationMigrationJournalRecord {
  return {
    ...withoutAuthenticationTag(current),
    state,
    updatedAt: now(),
  };
}

function withFailure(
  current: Exclude<JournalEnvelope, { state: 'failed' }>,
  authoritativeOutcome: DurableOperationOutcome,
): CollaborationMigrationJournalRecord {
  return {
    ...withoutAuthenticationTag(current),
    state: 'failed',
    authoritativeOutcome,
    updatedAt: now(),
  };
}

function serializeJournal(
  secret: Uint8Array,
  record: CollaborationMigrationJournalRecord | JournalEnvelope,
): JournalEnvelope {
  const value = { ...record } as Record<string, unknown>;
  delete value['authenticationTag'];
  const parsed = collaborationMigrationJournalRecordSchema.parse({
    ...value,
    authenticationTag: 'A'.repeat(43),
  });
  let message: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  try {
    message = journalMessage(parsed);
    tag = authenticate(secret, parsed, message);
    return collaborationMigrationJournalRecordSchema.parse({
      ...parsed,
      authenticationTag: encodeBase64Url(tag),
    });
  } finally {
    zeroize(message);
    zeroize(tag);
  }
}

function parseAuthenticatedJournal(
  secret: Uint8Array,
  envelope: JournalEnvelope,
): JournalEnvelope {
  const parsed = collaborationMigrationJournalRecordSchema.parse(envelope);
  let message: Uint8Array | undefined;
  let supplied: Uint8Array | undefined;
  let expected: Uint8Array | undefined;
  try {
    message = journalMessage(parsed);
    supplied = decodeBase64Url(parsed.authenticationTag, { exactBytes: TAG_BYTES });
    expected = authenticate(secret, parsed, message);
    if (!constantTimeEqual(supplied, expected)) throw invalidJournal();
    return parsed;
  } finally {
    zeroize(message);
    zeroize(supplied);
    zeroize(expected);
  }
}

function journalMessage(record: JournalEnvelope): Uint8Array {
  const value = { ...record } as Record<string, unknown>;
  delete value['authenticationTag'];
  return Buffer.from(
    canonicalJson({ domain: DOMAIN, format: FORMAT, version: VERSION, ...value }),
    'utf8',
  );
}

function authenticate(
  secret: Uint8Array,
  record: JournalEnvelope,
  message: Uint8Array,
): Uint8Array {
  const key = deriveAuthenticationKey(secret, record);
  try {
    return Uint8Array.from(createHmac('sha256', key).update(message).digest());
  } finally {
    zeroize(key);
  }
}

function deriveAuthenticationKey(
  secret: Uint8Array,
  record: JournalEnvelope,
): Uint8Array {
  const info = Buffer.from(
    canonicalJson({
      domain: KDF_DOMAIN,
      version: VERSION,
      databaseId: record.databaseId,
      vaultId: record.vaultId,
      principalId: record.principalId,
      deviceId: record.deviceId,
      operationId: record.operationId,
      requestDigest: record.requestDigest,
    }),
    'ascii',
  );
  try {
    return new Uint8Array(hkdfSync('sha256', secret, KDF_SALT, info, SECRET_BYTES));
  } finally {
    info.fill(0);
  }
}

function assertPreparedBundle(bundle: JournalBundle): void {
  const request = bundle.request;
  const registry = bundle.registryCandidate;
  const prepared = bundle.preparedMarker;
  const active = bundle.activeMarker;
  const candidate = bundle.collaborativeCandidate;
  const proofEntry = bundle.proofEntry;
  const commitment = candidate.currentMutationLink.commitment;
  const outcome = bundle.proposedOutcome;
  const anchor = bundle.initialRecipientAnchor;
  const priorTuple = priorTupleFromCandidate(candidate);
  const committedTuple = currentTupleFromCandidate(candidate);
  const finalizedLinkDigest = computeFinalizedMutationLinkDigest(
    candidate.currentMutationLink,
  );
  assertRestartMaterialBinding(
    request,
    candidate,
    bundle.initialOwnerIdentity,
    bundle.restartRecipient,
  );

  // These digests are claims about canonical source/request bytes, not merely
  // caller-provided fields. Recompute them before accepting or persisting the
  // bundle so a stale or substituted projection cannot enter the journal.
  if (
    request.legacySourceDigest !== computeLegacySourceDigest(prepared.legacySource) ||
    request.requestDigest !== computeMigrationRequestDigest(request)
  ) {
    throw invalidJournal();
  }

  if (
    request.databaseId !== prepared.databaseId ||
    request.databaseId !== active.databaseId ||
    request.databaseId !== registry.databaseId ||
    request.databaseId !== candidate.databaseId ||
    request.databaseId !== outcome.databaseId ||
    request.databaseId !== anchor.databaseId ||
    request.vaultId !== prepared.vaultId ||
    request.vaultId !== active.vaultId ||
    request.vaultId !== candidate.vaultId ||
    request.vaultId !== outcome.vaultId ||
    request.vaultId !== anchor.vaultId ||
    request.operationId !== prepared.operationId ||
    request.operationId !== active.operationId ||
    request.operationId !== commitment.operationId ||
    request.operationId !== outcome.operationId ||
    request.requestDigest !== prepared.requestDigest ||
    request.requestDigest !== active.requestDigest ||
    request.requestDigest !== commitment.requestDigest ||
    request.requestDigest !== outcome.requestDigest ||
    proofEntry.link.commitment.operationId !== request.operationId ||
    proofEntry.link.commitment.operationType !== 'genesis-migration' ||
    proofEntry.link.commitment.requestDigest !== request.requestDigest ||
    proofEntry.link.commitment.writerPrincipalId !== request.initialOwnerPrincipalId ||
    proofEntry.link.commitment.writerDeviceId !== request.initialOwnerDeviceId ||
    !sameCanonical(proofEntry.link, candidate.currentMutationLink) ||
    proofEntry.link.resultingHeadDigest !== candidate.headDigest ||
    computeFinalizedMutationLinkDigest(proofEntry.link) !== finalizedLinkDigest ||
    proofEntry.authorizationWitness?.finalizedMutationLinkDigest !==
      finalizedLinkDigest ||
    Number(request.legacyVaultRevision) !== Number(prepared.legacySource.revision) ||
    request.legacySourceDigest !== prepared.legacySourceDigest ||
    !sameCanonical(registry, prepared.registryCandidate)
  ) {
    throw invalidJournal();
  }

  const sameAuthority =
    request.authorityEpoch === registry.authorityEpoch &&
    request.authorityEpoch === prepared.authorityEpoch &&
    request.authorityEpoch === active.authorityEpoch &&
    request.authorityEpoch === candidate.authorityEpoch &&
    request.authorityEpoch === anchor.authorityEpoch &&
    request.authorityFingerprint === registry.authorityFingerprint &&
    request.authorityFingerprint === prepared.authorityFingerprint &&
    request.authorityFingerprint === active.authorityFingerprint &&
    request.authorityFingerprint ===
      candidate.authorityDelegation.authoritySigningKeyFingerprint &&
    anchor.authorityDelegationDigest === candidate.authorityDelegationDigest;
  const sameRegistryFence =
    request.databaseDeviceGeneration === registry.generation &&
    request.databaseDeviceGeneration === prepared.databaseDeviceGeneration &&
    request.databaseDeviceGeneration === active.databaseDeviceGeneration &&
    request.databaseDeviceGeneration === candidate.databaseDeviceGeneration &&
    request.databaseDeviceGeneration === anchor.databaseDeviceGeneration &&
    request.databaseDeviceRegistryDigest === registry.registryDigest &&
    request.databaseDeviceRegistryDigest === prepared.databaseDeviceRegistryDigest &&
    request.databaseDeviceRegistryDigest === active.databaseDeviceRegistryDigest &&
    request.databaseDeviceRegistryDigest === candidate.databaseDeviceRegistryDigest &&
    request.databaseDeviceRegistryDigest === anchor.databaseDeviceRegistryDigest;
  if (!sameAuthority || !sameRegistryFence) throw invalidJournal();

  if (
    !sameMarkerBase(prepared, active) ||
    prepared.candidateHeadDigest !== candidate.headDigest ||
    active.candidateHeadDigest !== candidate.headDigest ||
    active.outcomeDigest !== outcome.outcomeDigest ||
    commitment.operationType !== 'genesis-migration' ||
    commitment.writerPrincipalId !== request.initialOwnerPrincipalId ||
    commitment.writerDeviceId !== request.initialOwnerDeviceId ||
    candidate.currentMutationLink.writerSignature.writerPrincipalId !==
      request.initialOwnerPrincipalId ||
    candidate.currentMutationLink.writerSignature.writerDeviceId !==
      request.initialOwnerDeviceId ||
    candidate.previousHeadDigest !== commitment.previousHeadDigest ||
    commitment.previousDocumentRevision !== 0 ||
    commitment.previousMembershipRevision !== 0 ||
    commitment.previousPolicyRevision !== 0 ||
    commitment.previousKeyEpoch !== 1 ||
    commitment.previousAuthorityEpoch !== request.authorityEpoch ||
    commitment.previousDatabaseDeviceGeneration !== request.databaseDeviceGeneration ||
    commitment.previousDatabaseDeviceRegistryDigest !==
      request.databaseDeviceRegistryDigest ||
    candidate.previousHeadDigest !== COLLABORATION_GENESIS_HEAD_DIGEST ||
    candidate.documentRevision !== 1 ||
    candidate.membershipRevision !== 1 ||
    candidate.policyRevision !== 1 ||
    candidate.keyEpoch !== 1 ||
    candidate.authorizationStateDigest !==
      candidate.authorityDelegation.initialAuthorizationStateDigest ||
    candidate.currentMutationLink.authorizationTransition === undefined
  ) {
    throw invalidJournal();
  }

  if (
    outcome.state !== 'committed' ||
    outcome.operationType !== 'genesis-migration' ||
    outcome.actorPrincipalId !== request.initialOwnerPrincipalId ||
    outcome.actorDeviceId !== request.initialOwnerDeviceId ||
    outcome.priorHeadDigest !== candidate.previousHeadDigest ||
    !sameCanonical(outcome.priorTuple, priorTuple) ||
    outcome.committedTuple === undefined ||
    !sameCanonical(outcome.committedTuple, committedTuple) ||
    outcome.committedHeadDigest !== candidate.headDigest ||
    outcome.signedMutationReceipt === undefined ||
    outcome.finalizedMutationLinkDigest !== finalizedLinkDigest ||
    outcome.signedMutationReceipt.finalizedMutationLinkDigest !==
      outcome.finalizedMutationLinkDigest
  ) {
    throw invalidJournal();
  }

  if (
    anchor.principalId !== request.initialOwnerPrincipalId ||
    anchor.deviceId !== request.initialOwnerDeviceId ||
    anchor.membershipRevision !== candidate.membershipRevision ||
    anchor.policyRevision !== candidate.policyRevision ||
    anchor.keyEpoch !== candidate.keyEpoch ||
    anchor.documentRevision !== candidate.documentRevision ||
    anchor.encryptedPayloadDigest !== candidate.encryptedPayloadDigest ||
    anchor.headDigest !== candidate.headDigest ||
    anchor.authorityDelegationDigest !== candidate.authorityDelegationDigest ||
    anchor.authorizationStateDigest !== candidate.authorizationStateDigest ||
    anchor.finalizedMutationLinkDigest !== finalizedLinkDigest ||
    anchor.updatedAt !== candidate.updatedAt ||
    candidate.authorityDelegation.initialOwnerPrincipalId !==
      request.initialOwnerPrincipalId ||
    candidate.authorityDelegation.initialOwnerDeviceId !== request.initialOwnerDeviceId
  ) {
    throw invalidJournal();
  }

  // The logical membership/policy anchor digests require the opened genesis
  // manifest, which this non-secret journal deliberately never retains. Exact
  // candidate/anchor bytes and the candidate authorization digest remain bound
  // by the protected journal and are reverified by the client before use.
}

function assertJournalSchemaBinding(
  record: JournalEnvelope,
  context: z.RefinementCtx,
): void {
  try {
    assertCanonicalBytes(record, context);
    assertPreparedBundle(record);
    const identity = identityFromBundle(record);
    if (
      record.databaseId !== identity.databaseId ||
      record.vaultId !== identity.vaultId ||
      record.principalId !== identity.principalId ||
      record.deviceId !== identity.deviceId ||
      record.operationId !== identity.operationId ||
      record.requestDigest !== identity.requestDigest ||
      Date.parse(record.updatedAt) < Date.parse(record.createdAt)
    ) {
      throw invalidJournal();
    }
  } catch {
    addIssue(context, 'Migration journal record has an invalid binding');
  }
}

function assertAuthoritativeOutcomeIdentity(
  record: JournalBundle & JournalIdentity,
  outcome: DurableOperationOutcome,
): void {
  if (
    outcome.state !== 'committed' ||
    outcome.databaseId !== record.databaseId ||
    outcome.vaultId !== record.vaultId ||
    outcome.operationId !== record.operationId ||
    outcome.operationType !== 'genesis-migration' ||
    outcome.requestDigest !== record.requestDigest ||
    outcome.actorPrincipalId !== record.principalId ||
    outcome.actorDeviceId !== record.deviceId ||
    outcome.priorHeadDigest !== record.proposedOutcome.priorHeadDigest ||
    !sameCanonical(outcome.priorTuple, record.proposedOutcome.priorTuple) ||
    outcome.signedMutationReceipt === undefined ||
    outcome.finalizedMutationLinkDigest === undefined ||
    outcome.signedMutationReceipt.finalizedMutationLinkDigest !==
      outcome.finalizedMutationLinkDigest
  ) {
    throw invalidJournal();
  }
}

function sameMarkerBase(
  prepared: CollaborationMigrationPreparedMarker,
  active: CollaborationMigrationActiveMarker,
): boolean {
  return (
    prepared.databaseId === active.databaseId &&
    prepared.vaultId === active.vaultId &&
    prepared.operationId === active.operationId &&
    prepared.requestDigest === active.requestDigest &&
    prepared.legacySourceDigest === active.legacySourceDigest &&
    prepared.authorityEpoch === active.authorityEpoch &&
    prepared.authorityFingerprint === active.authorityFingerprint &&
    prepared.databaseDeviceGeneration === active.databaseDeviceGeneration &&
    prepared.databaseDeviceRegistryDigest === active.databaseDeviceRegistryDigest &&
    prepared.candidateHeadDigest === active.candidateHeadDigest &&
    prepared.preparedAt === active.preparedAt
  );
}

function priorTupleFromCandidate(
  candidate: CollaborativeVaultDocument,
): DurableOperationOutcome['priorTuple'] {
  const commitment = candidate.currentMutationLink.commitment;
  return {
    authorityEpoch: commitment.previousAuthorityEpoch,
    documentRevision: commitment.previousDocumentRevision,
    membershipRevision: commitment.previousMembershipRevision,
    policyRevision: commitment.previousPolicyRevision,
    keyEpoch: commitment.previousKeyEpoch,
    databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
    databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
    authorizationStateDigest: commitment.previousAuthorizationStateDigest,
  };
}

function currentTupleFromCandidate(
  candidate: CollaborativeVaultDocument,
): NonNullable<DurableOperationOutcome['committedTuple']> {
  return {
    authorityEpoch: candidate.authorityEpoch,
    documentRevision: candidate.documentRevision,
    membershipRevision: candidate.membershipRevision,
    policyRevision: candidate.policyRevision,
    keyEpoch: candidate.keyEpoch,
    databaseDeviceGeneration: candidate.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
    authorizationStateDigest: candidate.authorizationStateDigest,
  };
}

function sameImmutableBundle(
  existing: CollaborationMigrationJournalRecord,
  prepared: CollaborationMigrationJournalRecord,
): boolean {
  const immutableKeys = [
    'databaseId',
    'vaultId',
    'principalId',
    'deviceId',
    'operationId',
    'requestDigest',
    'request',
    'registryCandidate',
    'preparedMarker',
    'activeMarker',
    'collaborativeCandidate',
    'proofEntry',
    'proposedOutcome',
    'initialRecipientAnchor',
    'createdAt',
  ] as const;
  return (
    immutableKeys.every((key) => sameCanonical(existing[key], prepared[key])) &&
    sameCanonical(existing.initialOwnerIdentity, prepared.initialOwnerIdentity) &&
    sameCanonical(existing.restartRecipient, prepared.restartRecipient)
  );
}

function assertRestartMaterialBinding(
  request: CollaborationMigrationRequest,
  candidate: CollaborativeVaultDocument,
  identity: PublicIdentityExport,
  recipient: CollaborationMigrationRestartRecipient,
): void {
  const delegation = candidate.authorityDelegation;
  const rootFingerprint = computePublicKeyFingerprint(
    identity.rootSigningPublicKey,
    'ed25519',
  );
  const writerMatches = identity.devices.filter(
    (device) => device.deviceId === request.initialOwnerDeviceId,
  );
  const recipientMatches = identity.devices.filter(
    (device) => device.deviceId === recipient.deviceId,
  );
  const writer = writerMatches[0];
  const recipientDevice = recipientMatches[0];
  if (
    identity.principalId !== request.initialOwnerPrincipalId ||
    recipient.principalId !== request.initialOwnerPrincipalId ||
    writerMatches.length !== 1 ||
    recipientMatches.length !== 1 ||
    writer === undefined ||
    recipientDevice === undefined ||
    writer.state !== 'active' ||
    recipientDevice.state !== 'active' ||
    delegation.initialOwnerRootKeyFingerprint !== rootFingerprint ||
    delegation.initialOwnerDeviceSigningKeyFingerprint !==
      computePublicKeyFingerprint(writer.signingPublicKey, 'ed25519') ||
    delegation.initialOwnerDeviceEncryptionKeyFingerprint !==
      computePublicKeyFingerprint(writer.encryptionPublicKey, 'x25519')
  ) {
    throw invalidJournal();
  }

  const discoveryTag = computeDiscoveryTag(candidate.databaseId, rootFingerprint);
  const records = candidate.discoveryRecords.filter(
    (record) =>
      record.discoveryTag === discoveryTag &&
      record.encryptedMemberKeyEnvelope.principalId === recipient.principalId &&
      record.encryptedMemberKeyEnvelope.deviceId === recipient.deviceId,
  );
  const record = records[0];
  if (
    records.length !== 1 ||
    record?.membershipState !== 'active' ||
    record.membershipId !== request.initialMembershipId ||
    record.encryptedMemberKeyEnvelope.recipientEncryptionKeyFingerprint !==
      computePublicKeyFingerprint(recipientDevice.encryptionPublicKey, 'x25519')
  ) {
    throw invalidJournal();
  }
}

async function readJournalWithoutScope(
  path: string,
  secret: Uint8Array,
): Promise<CollaborationMigrationJournalRecord | null> {
  let envelope: JournalEnvelope;
  try {
    envelope = await readProtectedJsonDocument(path, documentOptions());
  } catch (error) {
    if (error instanceof PortableKeyFileError && error.code === 'KEY_FILE_NOT_FOUND') {
      return null;
    }
    throw mapJournalError(error);
  }
  try {
    return withoutAuthenticationTag(parseAuthenticatedJournal(secret, envelope));
  } catch (error) {
    throw mapJournalError(error);
  }
}

function parseScope(
  options: CollaborationMigrationJournalReadOptions,
): CollaborationMigrationJournalScope {
  try {
    return z
      .object({
        expectedScope: z
          .object({
            databaseId: recipientRollbackAnchorSchema.shape.databaseId,
            vaultId: recipientRollbackAnchorSchema.shape.vaultId,
            principalId: recipientRollbackAnchorSchema.shape.principalId,
            deviceId: recipientRollbackAnchorSchema.shape.deviceId,
            operationId: collaborationOperationIdSchema,
            requestDigest: sha256DigestSchema,
          })
          .strict(),
      })
      .strict()
      .parse(structuredClone(options)).expectedScope;
  } catch {
    throw invalidJournal();
  }
}

function assertScope(
  record: CollaborationMigrationJournalRecord,
  scope: CollaborationMigrationJournalScope,
): void {
  if (
    record.databaseId !== scope.databaseId ||
    record.vaultId !== scope.vaultId ||
    record.principalId !== scope.principalId ||
    record.deviceId !== scope.deviceId ||
    record.operationId !== scope.operationId ||
    record.requestDigest !== scope.requestDigest
  ) {
    throw invalidJournal();
  }
}

function parseOutcome(value: unknown): DurableOperationOutcome {
  try {
    return durableOperationOutcomeSchema.parse(structuredClone(value));
  } catch {
    throw invalidJournal();
  }
}

function parseAnchorScope(value: unknown): RecipientRollbackAnchorScope {
  try {
    return z
      .object({
        databaseId: recipientRollbackAnchorSchema.shape.databaseId,
        vaultId: recipientRollbackAnchorSchema.shape.vaultId,
        principalId: recipientRollbackAnchorSchema.shape.principalId,
        deviceId: recipientRollbackAnchorSchema.shape.deviceId,
      })
      .strict()
      .parse(structuredClone(value));
  } catch {
    throw invalidJournal();
  }
}

function parseActiveMarker(value: unknown): CollaborationMigrationActiveMarker {
  try {
    return collaborationMigrationActiveMarkerSchema.parse(structuredClone(value));
  } catch {
    throw invalidJournal();
  }
}

function withoutAuthenticationTag<T extends JournalEnvelope>(
  envelope: T,
): WithoutAuthenticationTag<T> {
  const record = { ...envelope };
  Reflect.deleteProperty(record, 'authenticationTag');
  return record as unknown as WithoutAuthenticationTag<T>;
}

function documentOptions(): Readonly<{
  schema: CanonicalJsonDocumentSchema<JournalEnvelope>;
  maximumBytes: number;
}> {
  return {
    schema: journalDocumentSchema,
    maximumBytes: MAX_COLLABORATION_MIGRATION_JOURNAL_BYTES,
  } as const;
}

function assertCanonicalBytes(value: unknown, context: z.RefinementCtx): void {
  try {
    if (
      Buffer.byteLength(canonicalJson(value), 'utf8') >
      MAX_COLLABORATION_MIGRATION_JOURNAL_BYTES
    ) {
      addIssue(context, 'Migration journal exceeds its canonical size bound');
    }
  } catch {
    addIssue(context, 'Migration journal is not canonically encodable');
  }
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function addIssue(
  context: z.RefinementCtx,
  message: string,
  path: (string | number)[] = [],
): void {
  context.addIssue({ code: 'custom', message, path });
}

function requireDeviceProtectionSecret(secret: Uint8Array): void {
  requireByteLength(secret, SECRET_BYTES, 'device protection secret');
}

function parsePathDatabaseId(value: unknown): DatabaseId {
  try {
    return recipientRollbackAnchorSchema.shape.databaseId.parse(value);
  } catch {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function parsePathVaultId(value: unknown): VaultId {
  try {
    return recipientRollbackAnchorSchema.shape.vaultId.parse(value);
  } catch {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function parsePathOperationId(value: unknown): CollaborationOperationId {
  try {
    return collaborationOperationIdSchema.parse(value);
  } catch {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function assertPath(path: string): void {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\u0000')) {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function now(): Timestamp {
  return timestampSchema.parse(new Date().toISOString());
}

function mapJournalError(error: unknown): PortableKeyFileError {
  if (error instanceof PortableKeyFileError) return error;
  if (error instanceof ProtectedJsonDocumentError) return invalidJournal();
  return invalidJournal();
}

function invalidJournal(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}
