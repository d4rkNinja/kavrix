import { createHash, createHmac, hkdfSync } from 'node:crypto';

import {
  MAX_COLLABORATIVE_AUTHORIZATION_WITNESS_BYTES,
  MAX_COLLABORATIVE_OPERATION_BYTES,
  MAX_COLLABORATIVE_ROLLBACK_ANCHOR_BYTES,
  MAX_COLLABORATIVE_VAULT_DOCUMENT_BYTES,
  canonicalJson,
  collaborationAuthorizationCheckpointSchema,
  collaborationMutationProofEntrySchema,
  collaborationOperationIdSchema,
  collaborationRevisionTupleSchema,
  collaborativeVaultDocumentSchema,
  durableOperationOutcomeSchema,
  recipientRollbackAnchorSchema,
  sha256DigestSchema,
  timestampSchema,
  type CollaborativeVaultDocument,
  type CollaborationAuthorizationCheckpoint,
  type CollaborationOperationId,
  type CollaborationRevisionTuple,
  type DatabaseId,
  type DeviceId,
  type DurableOperationOutcome,
  type PrincipalId,
  type RecipientRollbackAnchor,
  type Sha256Digest,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';
import {
  computeAuthorizationCheckpointDigest,
  constantTimeEqual,
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
import { computeFinalizedMutationLinkDigest } from './collaboration-anchor.js';
import { PortableKeyFileError } from './errors.js';

/** Stable suffix for the local ambiguous-commit journal sidecar. */
export const COLLABORATIVE_OPERATION_JOURNAL_SUFFIX =
  '.collaboration-operation-journal';

export const COLLABORATIVE_OPERATION_JOURNAL_FORMAT =
  'kavrix-collaborative-operation-journal';
export const COLLABORATIVE_OPERATION_JOURNAL_VERSION = 1;

const FORMAT = COLLABORATIVE_OPERATION_JOURNAL_FORMAT;
const VERSION = COLLABORATIVE_OPERATION_JOURNAL_VERSION;
const DOMAIN = 'kavrix/collaborative-operation-journal/v1';
const KDF_DOMAIN = 'kavrix/collaborative-operation-journal/hmac-key/v1';
const CANDIDATE_DIGEST_DOMAIN = Buffer.from(
  'kavrix/collaborative-operation-journal/candidate/v1',
  'ascii',
);
const OUTCOME_DIGEST_DOMAIN = Buffer.from(
  'kavrix/collaborative-operation-journal/proposed-outcome/v1',
  'ascii',
);
const SECRET_BYTES = 32;
const TAG_BYTES = 32;
const ENVELOPE_OVERHEAD_BYTES = 64 * 1024;
export const MAX_COLLABORATION_OPERATION_JOURNAL_BYTES =
  MAX_COLLABORATIVE_VAULT_DOCUMENT_BYTES +
  MAX_COLLABORATIVE_AUTHORIZATION_WITNESS_BYTES +
  3 * MAX_COLLABORATIVE_OPERATION_BYTES +
  MAX_COLLABORATIVE_ROLLBACK_ANCHOR_BYTES +
  ENVELOPE_OVERHEAD_BYTES;
const MAX_FILE_BYTES = MAX_COLLABORATION_OPERATION_JOURNAL_BYTES;
const KDF_SALT = new Uint8Array(32);

const authenticationTagSchema = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/u);

const accessModeSchema = z.enum(['recipient', 'database-authority-recovery']);

const recoveryRestartEvidenceSchema = z
  .object({
    priorTuple: collaborationRevisionTupleSchema,
    priorHeadDigest: sha256DigestSchema,
    priorDatabaseAuthorityRecoveryEnvelopeDigest: sha256DigestSchema,
  })
  .strict();

export type CollaborationOperationJournalScope = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  principalId: PrincipalId;
  deviceId: DeviceId;
}>;

export type CollaborationOperationJournalAccessMode =
  'recipient' | 'database-authority-recovery';

export type CollaborationRecoveryRestartEvidence = Readonly<{
  priorTuple: CollaborationRevisionTuple;
  priorHeadDigest: Sha256Digest;
  priorDatabaseAuthorityRecoveryEnvelopeDigest: Sha256Digest;
}>;

export type CollaborationOperationJournalCreateInput = Readonly<{
  accessMode: CollaborationOperationJournalAccessMode;
  recoveryRestartEvidence?: CollaborationRecoveryRestartEvidence;
  candidate: CollaborativeVaultDocument;
  /** The non-secret recipient rollback anchor prepared for this candidate. */
  candidateAnchor: RecipientRollbackAnchor;
  /** The exact writer-signed finalized mutation proof retained for replay. */
  proofEntry: CollaborationMutationProofEntry;
  /** Exact owner-signed checkpoint retained for fail-closed publication replay. */
  authorizationCheckpoint?: CollaborationAuthorizationCheckpoint;
  /** The complete immutable committed outcome proposed for publication. */
  proposedOutcome: DurableOperationOutcome;
  createdAt?: Timestamp;
}>;

type JournalIdentity = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  operationId: CollaborationOperationId;
  operationType: DurableOperationOutcome['operationType'];
  requestDigest: Sha256Digest;
  actorPrincipalId: PrincipalId;
  actorDeviceId: DeviceId;
  accessMode: CollaborationOperationJournalAccessMode;
  recoveryRestartEvidence?: CollaborationRecoveryRestartEvidence | undefined;
}>;

type CollaborationMutationProofEntry = z.infer<
  typeof collaborationMutationProofEntrySchema
>;

type JournalActiveEnvelope = JournalIdentity &
  Readonly<{
    format: typeof FORMAT;
    version: typeof VERSION;
    state: 'prepared';
    candidateDigest: Sha256Digest;
    proposedOutcomeDigest: Sha256Digest;
    candidate: CollaborativeVaultDocument;
    candidateAnchor: RecipientRollbackAnchor;
    proofEntry: CollaborationMutationProofEntry;
    authorizationCheckpoint?: CollaborationAuthorizationCheckpoint | undefined;
    proposedOutcome: DurableOperationOutcome;
    createdAt: Timestamp;
    updatedAt: Timestamp;
    authenticationTag: string;
  }>;

type JournalTerminalEnvelope = JournalIdentity &
  Readonly<{
    format: typeof FORMAT;
    version: typeof VERSION;
    state: 'committed';
    candidateDigest: Sha256Digest;
    proposedOutcomeDigest: Sha256Digest;
    candidate: CollaborativeVaultDocument;
    candidateAnchor: RecipientRollbackAnchor;
    proofEntry: CollaborationMutationProofEntry;
    authorizationCheckpoint?: CollaborationAuthorizationCheckpoint | undefined;
    outcome: DurableOperationOutcome;
    createdAt: Timestamp;
    updatedAt: Timestamp;
    authenticationTag: string;
  }>;

export const collaborativeOperationJournalActiveSchema = z
  .object({
    format: z.literal(FORMAT),
    version: z.literal(VERSION),
    databaseId: recipientRollbackAnchorSchema.shape.databaseId,
    vaultId: recipientRollbackAnchorSchema.shape.vaultId,
    operationId: collaborationOperationIdSchema,
    operationType: durableOperationOutcomeSchema.shape.operationType,
    requestDigest: sha256DigestSchema,
    actorPrincipalId: recipientRollbackAnchorSchema.shape.principalId,
    actorDeviceId: recipientRollbackAnchorSchema.shape.deviceId,
    accessMode: accessModeSchema,
    recoveryRestartEvidence: recoveryRestartEvidenceSchema.optional(),
    state: z.literal('prepared'),
    candidateDigest: sha256DigestSchema,
    proposedOutcomeDigest: sha256DigestSchema,
    candidate: collaborativeVaultDocumentSchema,
    candidateAnchor: recipientRollbackAnchorSchema,
    proofEntry: collaborationMutationProofEntrySchema,
    authorizationCheckpoint: collaborationAuthorizationCheckpointSchema.optional(),
    proposedOutcome: durableOperationOutcomeSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    authenticationTag: authenticationTagSchema,
  })
  .strict()
  .superRefine((record, context) => {
    assertCanonicalBytes(record, MAX_FILE_BYTES, context);
    try {
      assertActiveBinding(record);
      if (record.proposedOutcome.state !== 'committed') {
        addIssue(
          context,
          'Prepared collaboration journals require a committed proposal',
        );
      }
      if (record.candidateDigest !== digestCandidate(record.candidate)) {
        addIssue(
          context,
          'Prepared journal candidate digest does not match its bytes',
          ['candidateDigest'],
        );
      }
      if (record.proposedOutcomeDigest !== digestOutcome(record.proposedOutcome)) {
        addIssue(context, 'Prepared journal outcome digest does not match its bytes', [
          'proposedOutcomeDigest',
        ]);
      }
    } catch {
      addIssue(context, 'Prepared journal binding is invalid');
    }
  });

export const collaborativeOperationJournalTerminalSchema = z
  .object({
    format: z.literal(FORMAT),
    version: z.literal(VERSION),
    databaseId: recipientRollbackAnchorSchema.shape.databaseId,
    vaultId: recipientRollbackAnchorSchema.shape.vaultId,
    operationId: collaborationOperationIdSchema,
    operationType: durableOperationOutcomeSchema.shape.operationType,
    requestDigest: sha256DigestSchema,
    actorPrincipalId: recipientRollbackAnchorSchema.shape.principalId,
    actorDeviceId: recipientRollbackAnchorSchema.shape.deviceId,
    accessMode: accessModeSchema,
    recoveryRestartEvidence: recoveryRestartEvidenceSchema.optional(),
    state: z.literal('committed'),
    candidateDigest: sha256DigestSchema,
    proposedOutcomeDigest: sha256DigestSchema,
    candidate: collaborativeVaultDocumentSchema,
    candidateAnchor: recipientRollbackAnchorSchema,
    proofEntry: collaborationMutationProofEntrySchema,
    authorizationCheckpoint: collaborationAuthorizationCheckpointSchema.optional(),
    outcome: durableOperationOutcomeSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    authenticationTag: authenticationTagSchema,
  })
  .strict()
  .superRefine((record, context) => {
    assertCanonicalBytes(record, MAX_FILE_BYTES, context);
    try {
      assertTerminalBinding(record);
    } catch {
      addIssue(context, 'Terminal journal binding is invalid');
    }
  });

export const collaborativeOperationJournalRecordSchema = z.union([
  collaborativeOperationJournalActiveSchema,
  collaborativeOperationJournalTerminalSchema,
]);

export type CollaborativeOperationJournalActiveRecord = Omit<
  z.infer<typeof collaborativeOperationJournalActiveSchema>,
  'authenticationTag'
>;
export type CollaborativeOperationJournalTerminalRecord = Omit<
  z.infer<typeof collaborativeOperationJournalTerminalSchema>,
  'authenticationTag'
>;
export type CollaborativeOperationJournalRecord =
  | CollaborativeOperationJournalActiveRecord
  | CollaborativeOperationJournalTerminalRecord;

const journalDocumentSchema: CanonicalJsonDocumentSchema<
  JournalActiveEnvelope | JournalTerminalEnvelope
> = collaborativeOperationJournalRecordSchema;

/**
 * Derives the operation sidecar name. The identity intentionally stops at
 * database/vault/operation ID: request digest is authenticated in the file,
 * allowing incompatible reuse of one operation ID to be detected as
 * corruption instead of silently creating a second sidecar.
 */
export function collaborativeOperationJournalPath(
  basePath: string,
  databaseId: DatabaseId,
  vaultId: VaultId,
  operationId: CollaborationOperationId,
): string {
  assertPath(basePath);
  const database = parseDatabaseId(databaseId);
  const vault = parseVaultId(vaultId);
  const operation = parseOperationId(operationId);
  return `${basePath}${COLLABORATIVE_OPERATION_JOURNAL_SUFFIX}.${database}.${vault}.${operation}`;
}

/**
 * Creates the immutable candidate/outcome pair before a remote publication.
 * A same-ID/same-digest retry is an authenticated no-op; a same-ID/different-
 * digest retry is corruption and fails closed.
 */
export async function createCollaborativeOperationJournal(
  path: string,
  deviceProtectionSecret: Uint8Array,
  input: CollaborationOperationJournalCreateInput,
): Promise<void> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const active = buildActiveRecord(input);
  const envelope = serializeJournal(deviceProtectionSecret, active);
  try {
    await writeProtectedJsonDocument(path, envelope, 'create', {
      schema: journalDocumentSchema,
      maximumBytes: MAX_FILE_BYTES,
    });
    return;
  } catch (error) {
    if (
      !(error instanceof PortableKeyFileError) ||
      error.code !== 'KEY_FILE_ALREADY_EXISTS'
    ) {
      throw mapJournalError(error);
    }
  }

  // The create race has a single authoritative readback. It also verifies the
  // HMAC before comparing the identity, so a forged collision cannot win.
  const existing = await readCollaborativeOperationJournal(
    path,
    deviceProtectionSecret,
  );
  if (existing === null || !sameJournalRequest(existing, active)) {
    throw invalidJournal();
  }
}

/** Reads an authenticated journal, returning null only when it is absent. */
export async function readCollaborativeOperationJournal(
  path: string,
  deviceProtectionSecret: Uint8Array,
  options?: CollaborationOperationJournalReadOptions,
): Promise<CollaborativeOperationJournalRecord | null> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const parsedOptions = parseReadOptions(options);
  let envelope: JournalActiveEnvelope | JournalTerminalEnvelope;
  try {
    envelope = await readProtectedJsonDocument(path, {
      schema: journalDocumentSchema,
      maximumBytes: MAX_FILE_BYTES,
    });
  } catch (error) {
    if (error instanceof PortableKeyFileError && error.code === 'KEY_FILE_NOT_FOUND') {
      return null;
    }
    throw mapJournalError(error);
  }
  try {
    const trusted = parseAuthenticatedJournal(deviceProtectionSecret, envelope);
    if (parsedOptions.expectedScope !== undefined) {
      assertJournalScope(trusted, parsedOptions.expectedScope);
    }
    return withoutAuthenticationTag(trusted);
  } catch (error) {
    throw mapJournalError(error);
  }
}

export type CollaborationOperationJournalReadOptions = Readonly<{
  expectedScope?: CollaborationOperationJournalScope;
}>;

/**
 * Reconciles one authoritative datastore outcome and atomically terminalizes
 * the local journal. A committed remote outcome must be byte-for-byte equal to
 * the proposed outcome. Conflict/rejection responses remain retryable hints and
 * never discard the prepared candidate bytes.
 */
export async function reconcileCollaborativeOperationJournal(
  path: string,
  deviceProtectionSecret: Uint8Array,
  outcome: DurableOperationOutcome,
): Promise<void> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const remoteOutcome = parseOutcome(outcome);
  // A conflict or rejection returned by an opaque store is only an
  // availability hint. It is not sufficient evidence to discard the exact
  // prepared candidate, so keep the active journal intact and let the caller
  // retry or obtain a signed committed outcome.
  if (remoteOutcome.state !== 'committed') {
    throw invalidJournal();
  }
  try {
    await transitionProtectedJsonDocument(
      path,
      { schema: journalDocumentSchema, maximumBytes: MAX_FILE_BYTES },
      (currentEnvelope) => {
        const current = parseAuthenticatedJournal(
          deviceProtectionSecret,
          currentEnvelope,
        );
        if (current.state !== 'prepared') {
          assertTerminalOutcome(current, remoteOutcome);
          return {
            document: currentEnvelope,
            result: undefined,
          };
        }
        assertOutcomeMatchesJournal(current, remoteOutcome);
        const terminal = buildTerminalRecord(current, remoteOutcome);
        return {
          document: serializeJournal(deviceProtectionSecret, terminal),
          result: undefined,
        };
      },
    );
  } catch (error) {
    throw mapJournalError(error);
  }
}

function buildActiveRecord(
  input: CollaborationOperationJournalCreateInput,
): CollaborativeOperationJournalActiveRecord {
  let candidate: CollaborativeVaultDocument;
  let createdAt: Timestamp | undefined;
  try {
    const accessMode = accessModeSchema.parse(input.accessMode);
    const recoveryRestartEvidence =
      input.recoveryRestartEvidence === undefined
        ? undefined
        : recoveryRestartEvidenceSchema.parse(
            structuredClone(input.recoveryRestartEvidence),
          );
    candidate = collaborativeVaultDocumentSchema.parse(
      structuredClone(input.candidate),
    );
    const candidateAnchor = recipientRollbackAnchorSchema.parse(
      structuredClone(input.candidateAnchor),
    );
    const proofEntry = collaborationMutationProofEntrySchema.parse(
      structuredClone(input.proofEntry),
    );
    const authorizationCheckpoint =
      input.authorizationCheckpoint === undefined
        ? undefined
        : collaborationAuthorizationCheckpointSchema.parse(
            structuredClone(input.authorizationCheckpoint),
          );
    const outcome = durableOperationOutcomeSchema.parse(
      structuredClone(input.proposedOutcome),
    );
    createdAt =
      input.createdAt === undefined
        ? undefined
        : timestampSchema.parse(input.createdAt);
    const commitment = candidate.currentMutationLink.commitment;
    const identity: JournalIdentity = {
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      operationId: parseOperationId(commitment.operationId),
      operationType: commitment.operationType,
      requestDigest: sha256DigestSchema.parse(commitment.requestDigest),
      actorPrincipalId: parsePrincipalId(commitment.writerPrincipalId),
      actorDeviceId: parseDeviceId(commitment.writerDeviceId),
      accessMode,
      ...(recoveryRestartEvidence === undefined ? {} : { recoveryRestartEvidence }),
    };
    const prepared: CollaborativeOperationJournalActiveRecord = {
      format: FORMAT,
      version: VERSION,
      ...identity,
      state: 'prepared',
      candidateDigest: digestCandidate(candidate),
      proposedOutcomeDigest: digestOutcome(outcome),
      candidate,
      candidateAnchor,
      proofEntry,
      ...(authorizationCheckpoint === undefined ? {} : { authorizationCheckpoint }),
      proposedOutcome: outcome,
      createdAt: createdAt ?? now(),
      updatedAt: createdAt ?? now(),
    };
    assertActiveBinding(prepared);
    // Public records omit the tag; this internal value is replaced during
    // serialization and is stripped again on read.
    return prepared;
  } catch (error) {
    throw mapJournalError(error);
  }
}

function buildTerminalRecord(
  current: JournalActiveEnvelope,
  outcome: DurableOperationOutcome,
): CollaborativeOperationJournalTerminalRecord {
  return {
    format: FORMAT,
    version: VERSION,
    databaseId: current.databaseId,
    vaultId: current.vaultId,
    operationId: current.operationId,
    operationType: current.operationType,
    requestDigest: current.requestDigest,
    actorPrincipalId: current.actorPrincipalId,
    actorDeviceId: current.actorDeviceId,
    accessMode: current.accessMode,
    ...(current.recoveryRestartEvidence === undefined
      ? {}
      : { recoveryRestartEvidence: current.recoveryRestartEvidence }),
    state: 'committed',
    candidateDigest: current.candidateDigest,
    proposedOutcomeDigest: current.proposedOutcomeDigest,
    candidate: current.candidate,
    candidateAnchor: current.candidateAnchor,
    proofEntry: current.proofEntry,
    ...(current.authorizationCheckpoint === undefined
      ? {}
      : { authorizationCheckpoint: current.authorizationCheckpoint }),
    outcome,
    createdAt: current.createdAt,
    updatedAt: now(),
  };
}

function serializeJournal(
  secret: Uint8Array,
  record:
    | JournalActiveEnvelope
    | JournalTerminalEnvelope
    | CollaborativeOperationJournalRecord,
): JournalActiveEnvelope | JournalTerminalEnvelope {
  const withoutTag = { ...record } as Record<string, unknown>;
  delete withoutTag['authenticationTag'];
  const parsed = collaborativeOperationJournalRecordSchema.parse({
    ...withoutTag,
    authenticationTag: 'A'.repeat(43),
  });
  let message: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  try {
    message = journalMessage(parsed);
    tag = hmac(secret, parsed, message);
    return {
      ...parsed,
      authenticationTag: encodeBase64Url(tag),
    };
  } finally {
    zeroize(message);
    zeroize(tag);
  }
}

function parseAuthenticatedJournal(
  secret: Uint8Array,
  envelope: JournalActiveEnvelope | JournalTerminalEnvelope,
): JournalActiveEnvelope | JournalTerminalEnvelope {
  const parsed = collaborativeOperationJournalRecordSchema.parse(envelope);
  let message: Uint8Array | undefined;
  let supplied: Uint8Array | undefined;
  let expected: Uint8Array | undefined;
  try {
    message = journalMessage(parsed);
    supplied = decodeBase64Url(parsed.authenticationTag, { exactBytes: TAG_BYTES });
    expected = hmac(secret, parsed, message);
    if (!constantTimeEqual(supplied, expected)) throw invalidJournal();
    return parsed;
  } finally {
    zeroize(message);
    zeroize(supplied);
    zeroize(expected);
  }
}

function journalMessage(
  record:
    | JournalActiveEnvelope
    | JournalTerminalEnvelope
    | CollaborativeOperationJournalRecord,
): Uint8Array {
  const value = { ...record } as Record<string, unknown>;
  delete value['authenticationTag'];
  return Buffer.from(
    canonicalJson({ domain: DOMAIN, format: FORMAT, version: VERSION, ...value }),
    'utf8',
  );
}

function hmac(
  secret: Uint8Array,
  record:
    | JournalActiveEnvelope
    | JournalTerminalEnvelope
    | CollaborativeOperationJournalRecord,
  message: Uint8Array,
): Uint8Array {
  const key = deriveJournalKey(secret, record);
  try {
    return Uint8Array.from(createHmac('sha256', key).update(message).digest());
  } finally {
    zeroize(key);
  }
}

function deriveJournalKey(
  secret: Uint8Array,
  record:
    | JournalActiveEnvelope
    | JournalTerminalEnvelope
    | CollaborativeOperationJournalRecord,
): Uint8Array {
  const info = Buffer.from(
    canonicalJson({
      domain: KDF_DOMAIN,
      version: VERSION,
      databaseId: record.databaseId,
      vaultId: record.vaultId,
      principalId: record.actorPrincipalId,
      deviceId: record.actorDeviceId,
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

function digestCandidate(candidate: CollaborativeVaultDocument): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256')
      .update(CANDIDATE_DIGEST_DOMAIN)
      .update(canonicalJson(candidate), 'utf8')
      .digest('base64url'),
  );
}

function digestOutcome(outcome: DurableOperationOutcome): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256')
      .update(OUTCOME_DIGEST_DOMAIN)
      .update(canonicalJson(outcome), 'utf8')
      .digest('base64url'),
  );
}

function assertActiveBinding(
  record: Pick<
    JournalActiveEnvelope,
    | 'databaseId'
    | 'vaultId'
    | 'operationId'
    | 'operationType'
    | 'requestDigest'
    | 'actorPrincipalId'
    | 'actorDeviceId'
    | 'accessMode'
    | 'recoveryRestartEvidence'
    | 'candidate'
    | 'candidateAnchor'
    | 'proofEntry'
    | 'authorizationCheckpoint'
    | 'proposedOutcome'
  >,
): void {
  const commitment = record.candidate.currentMutationLink.commitment;
  const priorTuple = {
    authorityEpoch: commitment.previousAuthorityEpoch,
    databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
    databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
    documentRevision: commitment.previousDocumentRevision,
    membershipRevision: commitment.previousMembershipRevision,
    policyRevision: commitment.previousPolicyRevision,
    keyEpoch: commitment.previousKeyEpoch,
    authorizationStateDigest: commitment.previousAuthorizationStateDigest,
  };
  const committedTuple = {
    authorityEpoch: record.candidate.authorityEpoch,
    databaseDeviceGeneration: record.candidate.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: record.candidate.databaseDeviceRegistryDigest,
    documentRevision: record.candidate.documentRevision,
    membershipRevision: record.candidate.membershipRevision,
    policyRevision: record.candidate.policyRevision,
    keyEpoch: record.candidate.keyEpoch,
    authorizationStateDigest: record.candidate.authorizationStateDigest,
  };
  const outcome = record.proposedOutcome;
  const proofEntry = record.proofEntry;
  const linkDigest = computeFinalizedMutationLinkDigest(
    record.candidate.currentMutationLink,
  );
  const receipt = outcome.signedMutationReceipt;
  assertAccessBinding(record, priorTuple, commitment.previousHeadDigest);
  assertCandidateAnchorBinding(record.candidate, record.candidateAnchor);
  assertAuthorizationCheckpointBinding(
    record.authorizationCheckpoint,
    record.candidate,
  );
  if (
    record.databaseId !== record.candidate.databaseId ||
    record.vaultId !== record.candidate.vaultId ||
    record.operationId !== commitment.operationId ||
    record.operationType !== commitment.operationType ||
    record.requestDigest !== commitment.requestDigest ||
    record.actorPrincipalId !== commitment.writerPrincipalId ||
    record.actorDeviceId !== commitment.writerDeviceId ||
    canonicalJson(proofEntry.link) !==
      canonicalJson(record.candidate.currentMutationLink) ||
    proofEntry.link.commitment.operationId !== record.operationId ||
    proofEntry.link.commitment.operationType !== record.operationType ||
    proofEntry.link.commitment.requestDigest !== record.requestDigest ||
    proofEntry.link.commitment.writerPrincipalId !== record.actorPrincipalId ||
    proofEntry.link.commitment.writerDeviceId !== record.actorDeviceId ||
    proofEntry.link.resultingHeadDigest !== record.candidate.headDigest ||
    computeFinalizedMutationLinkDigest(proofEntry.link) !== linkDigest ||
    (proofEntry.authorizationWitness !== undefined &&
      proofEntry.authorizationWitness.finalizedMutationLinkDigest !== linkDigest) ||
    outcome.databaseId !== record.databaseId ||
    outcome.vaultId !== record.vaultId ||
    outcome.operationId !== record.operationId ||
    outcome.operationType !== record.operationType ||
    outcome.requestDigest !== record.requestDigest ||
    outcome.actorPrincipalId !== record.actorPrincipalId ||
    outcome.actorDeviceId !== record.actorDeviceId ||
    outcome.state !== 'committed' ||
    outcome.priorHeadDigest !== record.candidate.previousHeadDigest ||
    !tuplesEqual(outcome.priorTuple, priorTuple) ||
    outcome.committedTuple === undefined ||
    !tuplesEqual(outcome.committedTuple, committedTuple) ||
    outcome.committedHeadDigest !== record.candidate.headDigest ||
    outcome.finalizedMutationLinkDigest !== linkDigest ||
    record.candidateAnchor.finalizedMutationLinkDigest !== linkDigest ||
    receipt?.finalizedMutationLinkDigest !== linkDigest ||
    receipt.committedHeadDigest !== record.candidate.headDigest
  ) {
    throw invalidJournal();
  }
}

function assertCandidateAnchorBinding(
  candidate: CollaborativeVaultDocument,
  candidateAnchor: RecipientRollbackAnchor,
): void {
  const commitment = candidate.currentMutationLink.commitment;
  if (
    candidateAnchor.databaseId !== candidate.databaseId ||
    candidateAnchor.vaultId !== candidate.vaultId ||
    candidateAnchor.principalId !== commitment.writerPrincipalId ||
    candidateAnchor.deviceId !== commitment.writerDeviceId ||
    candidateAnchor.authorityEpoch !== candidate.authorityEpoch ||
    candidateAnchor.authorityDelegationDigest !== candidate.authorityDelegationDigest ||
    candidateAnchor.databaseDeviceGeneration !== candidate.databaseDeviceGeneration ||
    candidateAnchor.databaseDeviceRegistryDigest !==
      candidate.databaseDeviceRegistryDigest ||
    candidateAnchor.membershipRevision !== candidate.membershipRevision ||
    candidateAnchor.policyRevision !== candidate.policyRevision ||
    candidateAnchor.keyEpoch !== candidate.keyEpoch ||
    candidateAnchor.documentRevision !== candidate.documentRevision ||
    candidateAnchor.encryptedPayloadDigest !== candidate.encryptedPayloadDigest ||
    candidateAnchor.headDigest !== candidate.headDigest ||
    candidateAnchor.authorizationStateDigest !== candidate.authorizationStateDigest ||
    candidateAnchor.finalizedMutationLinkDigest !==
      computeFinalizedMutationLinkDigest(candidate.currentMutationLink) ||
    candidateAnchor.updatedAt !== candidate.updatedAt
  ) {
    throw invalidJournal();
  }

  // Logical membership/policy anchor digests are computed only after opening
  // the encrypted manifest. This non-secret journal never stores that plaintext;
  // it instead binds the exact supplied anchor, candidate authorization digest,
  // revisions, head, link, and outcome under its device-protected MAC.
}

function assertAccessBinding(
  record: Pick<
    JournalActiveEnvelope,
    'accessMode' | 'recoveryRestartEvidence' | 'operationType'
  >,
  priorTupleInput: CollaborationRevisionTuple,
  priorHeadDigest: Sha256Digest,
): void {
  const priorTuple = collaborationRevisionTupleSchema.parse(priorTupleInput);
  if (record.accessMode === 'recipient') {
    if (record.recoveryRestartEvidence !== undefined) throw invalidJournal();
    return;
  }
  const evidence = record.recoveryRestartEvidence;
  if (
    record.operationType !== 'recover-owner' ||
    evidence === undefined ||
    canonicalJson(evidence.priorTuple) !== canonicalJson(priorTuple) ||
    evidence.priorHeadDigest !== priorHeadDigest
  ) {
    throw invalidJournal();
  }
}

function assertTerminalBinding(record: JournalTerminalEnvelope): void {
  assertActiveBinding({
    ...record,
    proposedOutcome: record.outcome,
  });
  if (
    record.state !== record.outcome.state ||
    record.databaseId !== record.outcome.databaseId ||
    record.vaultId !== record.outcome.vaultId ||
    record.operationId !== record.outcome.operationId ||
    record.operationType !== record.outcome.operationType ||
    record.requestDigest !== record.outcome.requestDigest ||
    record.actorPrincipalId !== record.outcome.actorPrincipalId ||
    record.actorDeviceId !== record.outcome.actorDeviceId ||
    record.candidateAnchor.databaseId !== record.databaseId ||
    record.candidateAnchor.vaultId !== record.vaultId ||
    record.candidateAnchor.principalId !== record.actorPrincipalId ||
    record.candidateAnchor.deviceId !== record.actorDeviceId ||
    record.proofEntry.link.databaseId !== record.databaseId ||
    record.proofEntry.link.vaultId !== record.vaultId ||
    record.proofEntry.link.authorityDelegationDigest !==
      record.candidateAnchor.authorityDelegationDigest ||
    record.proofEntry.link.commitment.operationId !== record.operationId ||
    record.proofEntry.link.commitment.operationType !== record.operationType ||
    record.proofEntry.link.commitment.requestDigest !== record.requestDigest ||
    record.proofEntry.link.commitment.writerPrincipalId !== record.actorPrincipalId ||
    record.proofEntry.link.commitment.writerDeviceId !== record.actorDeviceId ||
    record.proofEntry.link.resultingHeadDigest !== record.outcome.committedHeadDigest ||
    computeFinalizedMutationLinkDigest(record.proofEntry.link) !==
      record.outcome.finalizedMutationLinkDigest ||
    (record.proofEntry.authorizationWitness !== undefined &&
      record.proofEntry.authorizationWitness.finalizedMutationLinkDigest !==
        record.outcome.finalizedMutationLinkDigest)
  ) {
    throw invalidJournal();
  }
  if (record.proposedOutcomeDigest !== digestOutcome(record.outcome)) {
    throw invalidJournal();
  }
  if (record.candidateDigest !== digestCandidate(record.candidate)) {
    throw invalidJournal();
  }
  const committedTuple = record.outcome.committedTuple;
  if (committedTuple === undefined) throw invalidJournal();
  assertTerminalAuthorizationCheckpointBinding(
    record.authorizationCheckpoint,
    record,
    committedTuple,
  );
  if (
    record.candidateAnchor.authorityEpoch !== committedTuple.authorityEpoch ||
    record.candidateAnchor.databaseDeviceGeneration !==
      committedTuple.databaseDeviceGeneration ||
    record.candidateAnchor.databaseDeviceRegistryDigest !==
      committedTuple.databaseDeviceRegistryDigest ||
    record.candidateAnchor.membershipRevision !== committedTuple.membershipRevision ||
    record.candidateAnchor.policyRevision !== committedTuple.policyRevision ||
    record.candidateAnchor.keyEpoch !== committedTuple.keyEpoch ||
    record.candidateAnchor.documentRevision !== committedTuple.documentRevision ||
    record.candidateAnchor.authorizationStateDigest !==
      committedTuple.authorizationStateDigest ||
    record.candidateAnchor.headDigest !== record.outcome.committedHeadDigest ||
    record.candidateAnchor.finalizedMutationLinkDigest !==
      record.outcome.finalizedMutationLinkDigest ||
    record.outcome.signedMutationReceipt?.finalizedMutationLinkDigest !==
      record.outcome.finalizedMutationLinkDigest
  ) {
    throw invalidJournal();
  }
}

function assertOutcomeMatchesJournal(
  journal: JournalActiveEnvelope,
  outcome: DurableOperationOutcome,
): void {
  if (
    journal.databaseId !== outcome.databaseId ||
    journal.vaultId !== outcome.vaultId ||
    journal.operationId !== outcome.operationId ||
    journal.operationType !== outcome.operationType ||
    journal.requestDigest !== outcome.requestDigest ||
    journal.actorPrincipalId !== outcome.actorPrincipalId ||
    journal.actorDeviceId !== outcome.actorDeviceId ||
    !tuplesEqual(journal.proposedOutcome.priorTuple, outcome.priorTuple) ||
    journal.proposedOutcome.priorHeadDigest !== outcome.priorHeadDigest
  ) {
    throw invalidJournal();
  }
  if (
    outcome.state === 'committed' &&
    canonicalJson(journal.proposedOutcome) !== canonicalJson(outcome)
  ) {
    throw invalidJournal();
  }
}

function assertTerminalOutcome(
  journal: JournalTerminalEnvelope,
  outcome: DurableOperationOutcome,
): void {
  if (
    journal.databaseId !== outcome.databaseId ||
    journal.vaultId !== outcome.vaultId ||
    journal.operationId !== outcome.operationId ||
    journal.requestDigest !== outcome.requestDigest ||
    canonicalJson(journal.outcome) !== canonicalJson(outcome)
  ) {
    throw invalidJournal();
  }
}

function sameJournalRequest(
  existing: CollaborativeOperationJournalRecord,
  active: CollaborativeOperationJournalActiveRecord,
): boolean {
  if (
    existing.databaseId !== active.databaseId ||
    existing.vaultId !== active.vaultId ||
    existing.operationId !== active.operationId ||
    existing.operationType !== active.operationType ||
    existing.requestDigest !== active.requestDigest ||
    existing.actorPrincipalId !== active.actorPrincipalId ||
    existing.actorDeviceId !== active.actorDeviceId ||
    existing.accessMode !== active.accessMode ||
    !sameOptionalCanonical(
      existing.recoveryRestartEvidence,
      active.recoveryRestartEvidence,
    )
  ) {
    return false;
  }
  if (existing.candidateDigest !== active.candidateDigest) return false;
  if (existing.proposedOutcomeDigest !== active.proposedOutcomeDigest) return false;
  if (
    canonicalJson(existing.candidateAnchor) !== canonicalJson(active.candidateAnchor)
  ) {
    return false;
  }
  if (canonicalJson(existing.proofEntry) !== canonicalJson(active.proofEntry)) {
    return false;
  }
  if (
    !sameOptionalCanonical(
      existing.authorizationCheckpoint,
      active.authorizationCheckpoint,
    )
  ) {
    return false;
  }
  if (canonicalJson(existing.candidate) !== canonicalJson(active.candidate))
    return false;
  if (existing.state === 'prepared') {
    return (
      canonicalJson(existing.proposedOutcome) === canonicalJson(active.proposedOutcome)
    );
  }
  return true;
}

function assertAuthorizationCheckpointBinding(
  checkpoint: CollaborationAuthorizationCheckpoint | undefined,
  candidate: CollaborativeVaultDocument,
): void {
  if (checkpoint === undefined) return;
  const linkDigest = computeFinalizedMutationLinkDigest(candidate.currentMutationLink);
  const tuple = {
    authorityEpoch: candidate.authorityEpoch,
    databaseDeviceGeneration: candidate.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
    documentRevision: candidate.documentRevision,
    membershipRevision: candidate.membershipRevision,
    policyRevision: candidate.policyRevision,
    keyEpoch: candidate.keyEpoch,
    authorizationStateDigest: candidate.authorizationStateDigest,
  };
  if (
    checkpoint.databaseId !== candidate.databaseId ||
    checkpoint.vaultId !== candidate.vaultId ||
    checkpoint.authorityDelegationDigest !== candidate.authorityDelegationDigest ||
    canonicalJson(checkpoint.tuple) !== canonicalJson(tuple) ||
    checkpoint.headDigest !== candidate.headDigest ||
    checkpoint.authorizationStateDigest !== candidate.authorizationStateDigest ||
    checkpoint.finalizedMutationLinkDigest !== linkDigest ||
    checkpoint.checkpointDigest !== computeAuthorizationCheckpointDigest(checkpoint)
  ) {
    throw invalidJournal();
  }
}

function assertTerminalAuthorizationCheckpointBinding(
  checkpoint: CollaborationAuthorizationCheckpoint | undefined,
  record: JournalTerminalEnvelope,
  committedTuple: NonNullable<DurableOperationOutcome['committedTuple']>,
): void {
  if (checkpoint === undefined) return;
  if (
    checkpoint.databaseId !== record.databaseId ||
    checkpoint.vaultId !== record.vaultId ||
    checkpoint.authorityDelegationDigest !==
      record.candidateAnchor.authorityDelegationDigest ||
    canonicalJson(checkpoint.tuple) !== canonicalJson(committedTuple) ||
    checkpoint.headDigest !== record.outcome.committedHeadDigest ||
    checkpoint.authorizationStateDigest !== committedTuple.authorizationStateDigest ||
    checkpoint.finalizedMutationLinkDigest !==
      record.outcome.finalizedMutationLinkDigest ||
    checkpoint.checkpointDigest !== computeAuthorizationCheckpointDigest(checkpoint)
  ) {
    throw invalidJournal();
  }
}

function sameOptionalCanonical(left: unknown, right: unknown): boolean {
  if (left === undefined || right === undefined) return left === right;
  return canonicalJson(left) === canonicalJson(right);
}

function withoutAuthenticationTag(
  envelope: JournalActiveEnvelope | JournalTerminalEnvelope,
): CollaborativeOperationJournalRecord {
  const record = { ...envelope };
  Reflect.deleteProperty(record, 'authenticationTag');
  return record;
}

function parseReadOptions(
  value: CollaborationOperationJournalReadOptions | undefined,
): CollaborationOperationJournalReadOptions {
  if (value === undefined) return {};
  try {
    const parsed = z
      .object({
        expectedScope: z
          .object({
            databaseId: recipientRollbackAnchorSchema.shape.databaseId,
            vaultId: recipientRollbackAnchorSchema.shape.vaultId,
            principalId: recipientRollbackAnchorSchema.shape.principalId,
            deviceId: recipientRollbackAnchorSchema.shape.deviceId,
          })
          .strict()
          .optional(),
      })
      .strict()
      .parse(structuredClone(value));
    return {
      ...(parsed.expectedScope === undefined
        ? {}
        : { expectedScope: parseScope(parsed.expectedScope) }),
    };
  } catch {
    throw invalidJournal();
  }
}

function parseScope(
  input: CollaborationOperationJournalScope,
): CollaborationOperationJournalScope {
  try {
    return z
      .object({
        databaseId: recipientRollbackAnchorSchema.shape.databaseId,
        vaultId: recipientRollbackAnchorSchema.shape.vaultId,
        principalId: recipientRollbackAnchorSchema.shape.principalId,
        deviceId: recipientRollbackAnchorSchema.shape.deviceId,
      })
      .strict()
      .parse(structuredClone(input));
  } catch {
    throw invalidJournal();
  }
}

function assertJournalScope(
  journal: JournalActiveEnvelope | JournalTerminalEnvelope,
  expected: CollaborationOperationJournalScope,
): void {
  const scope = parseScope(expected);
  if (
    journal.databaseId !== scope.databaseId ||
    journal.vaultId !== scope.vaultId ||
    journal.actorPrincipalId !== scope.principalId ||
    journal.actorDeviceId !== scope.deviceId
  ) {
    throw invalidJournal();
  }
}

function parseDatabaseId(value: unknown): DatabaseId {
  try {
    return recipientRollbackAnchorSchema.shape.databaseId.parse(value);
  } catch {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function parseVaultId(value: unknown): VaultId {
  try {
    return recipientRollbackAnchorSchema.shape.vaultId.parse(value);
  } catch {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function parseOperationId(value: unknown): CollaborationOperationId {
  try {
    return collaborationOperationIdSchema.parse(value);
  } catch {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function parsePrincipalId(value: unknown): PrincipalId {
  return recipientRollbackAnchorSchema.shape.principalId.parse(value);
}

function parseDeviceId(value: unknown): DeviceId {
  return recipientRollbackAnchorSchema.shape.deviceId.parse(value);
}

function parseOutcome(value: unknown): DurableOperationOutcome {
  try {
    return durableOperationOutcomeSchema.parse(structuredClone(value));
  } catch {
    throw invalidJournal();
  }
}

function tuplesEqual(
  left: DurableOperationOutcome['priorTuple'],
  right: DurableOperationOutcome['priorTuple'],
): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function assertCanonicalBytes(
  value: unknown,
  maximumBytes: number,
  context: z.RefinementCtx,
): void {
  try {
    if (Buffer.byteLength(canonicalJson(value), 'utf8') > maximumBytes) {
      addIssue(context, 'Collaboration operation journal exceeds its size bound');
    }
  } catch {
    addIssue(context, 'Collaboration operation journal is not canonically encodable');
  }
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
