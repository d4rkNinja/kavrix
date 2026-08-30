import {
  COLLABORATION_DOMAINS,
  computeAadMetadataDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeDeviceCertificateFingerprint,
  computeDeviceRegistryDigest,
  computeDiscoveryRecordDigest,
  computeDiscoveryTag,
  computeEncryptedMembershipDigest,
  computeEncryptedPayloadDigest,
  computeFinalizedMutationLinkDigest,
  computeKeyEnvelopeSetDigest,
  computeKeyEnvelopeDigest,
  computeLegacySourceDigest,
  computeMembershipHistoryDigest,
  computeMembershipManifestDigest,
  computeMembershipStateDigest,
  computeMigrationRequestDigest,
  computeMutationHead,
  computeOperationOutcomeDigest,
  computePolicyDigest,
  computePolicyStateDigest,
  computePublicKeyFingerprint,
  decryptCollaborationEnvelope,
  openVaultRootKeyForDevice,
  verifyAuthorityDelegation,
  verifyAuthorizationTransitionOwner,
  verifyCollaborationRecord,
  verifyCommittedOperationOutcome,
  verifyDiscoveryRecord,
  verifyFinalizedMutationLink,
  verifyMigrationActiveMarker,
  verifyMigrationPreparedMarker,
  verifyMigrationRequestAuthority,
  verifyMigrationRequestOwner,
  verifyOperationTombstone,
  zeroize,
  type DatabaseRootKey,
} from '@kavrix/crypto';
import {
  collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument,
  collaborationMigrationJournalCreateInputSchema,
  createCollaborationAuthorityRollbackAnchor,
  createCollaborationMigrationJournal,
  createRecipientRollbackAnchor,
  markCollaborationMigrationActive,
  markCollaborationMigrationAnchored,
  readCollaborationAuthorityRollbackAnchor,
  readCollaborationMigrationJournal,
  readCollaborationMigrationJournalForResume,
  readDatabaseRevisionAnchor,
  readRecipientRollbackAnchor,
  reconcileCollaborationMigrationPublication,
  transitionDatabaseRevisionAnchor,
  type CollaborationAuthorityRollbackAnchor,
  type CollaborationAuthorityRollbackAnchorScope,
  type CollaborationMigrationJournalCreateInput,
  type CollaborationMigrationJournalRecord,
  type CollaborationMigrationJournalScope,
  type CollaborationMigrationRestartRecipient,
  type DatabaseRevisionAnchor,
  type RecipientRollbackAnchorScope,
} from '@kavrix/key-files';
import {
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationKeyEnvelopeSchema,
  collaborationPolicyStateSchema,
  collaborativeMembershipManifestSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  durableOperationOutcomeSchema,
  membershipHistoryEventSchema,
  operationDeduplicationTombstoneSchema,
  publicIdentityExportSchema,
  type CollaborativeMembershipManifest,
  type DeviceCertificate,
  type DurableOperationOutcome,
  type OperationDeduplicationTombstone,
  type PublicIdentityExport,
  type RecipientRollbackAnchor,
} from '@kavrix/schemas';

import { requireExactDatabaseAuthorityRecoveryEnvelope } from './collaboration-recovery-envelope-binding.js';
import {
  EncryptedDatabaseStoreError,
  type CollaborativeVaultStore,
} from '@kavrix/storage';

import type { PreparedCollaborativeGenesis } from './collaboration-genesis-builder.js';

const SAFE_MESSAGE = 'Collaborative vault migration failed.';
const DEVICE_PROTECTION_SECRET_BYTES = 32;

export type CollaborationMigrationOrchestrationFailureKind = 'invalid-input';

/** A stable redacted error safe for logs and terminal boundaries. */
export class CollaborationMigrationOrchestrationError extends Error {
  readonly safe = true;
  readonly kind: CollaborationMigrationOrchestrationFailureKind;

  constructor(kind: CollaborationMigrationOrchestrationFailureKind) {
    super(SAFE_MESSAGE);
    this.name = 'CollaborationMigrationOrchestrationError';
    this.kind = kind;
  }
}

export type CollaborationMigrationOrchestrationResult =
  | Readonly<{
      status: 'active';
      disposition: 'activated' | 'already-active';
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone;
    }>
  | Readonly<{ status: 'retryable'; reason: 'conflict' | 'rejected' }>
  | Readonly<{
      status: 'unknown';
      reason:
        | 'outcome-unavailable'
        | 'migration-ambiguous'
        | 'readback-unavailable'
        | 'journal-persistence-failed'
        | 'anchor-persistence-failed';
    }>
  | Readonly<{
      status: 'terminal';
      reason:
        | 'journal-failed'
        | 'journal-mismatch'
        | 'anchor-mismatch'
        | 'operation-id-reused'
        | 'remote-outcome-invalid'
        | 'remote-state-mismatch';
    }>;

export type OrchestrateCollaborativeGenesisMigrationInput = Readonly<{
  store: CollaborativeVaultStore;
  prepared: PreparedCollaborativeGenesis;
  databaseRootKey: DatabaseRootKey | Uint8Array;
  deviceProtectionSecret: Uint8Array;
  migrationJournalPath: string;
  legacyDatabaseRevisionAnchorPath: string;
  authorityRollbackAnchorPath: string;
  rollbackAnchorPath: string;
  /** Optional exact override plus device key for immediate cryptographic readback. */
  restart?: CollaborationGenesisMigrationRestartInput;
}>;

export type CollaborationGenesisMigrationRestartInput = Readonly<{
  initialOwnerIdentity: PublicIdentityExport;
  recipient: CollaborationMigrationRestartRecipient;
  recipientEncryptionPrivateKey: Uint8Array;
}>;

export type StageCollaborativeGenesisMigrationInput = Readonly<{
  prepared: PreparedCollaborativeGenesis;
  initialOwnerIdentity: PublicIdentityExport;
  restartRecipient: CollaborationMigrationRestartRecipient;
  recipientEncryptionPrivateKey: Uint8Array;
  deviceProtectionSecret: Uint8Array;
  migrationJournalPath: string;
}>;

export type ResumeCollaborativeGenesisMigrationInput = Readonly<{
  store: CollaborativeVaultStore;
  recipientEncryptionPrivateKey: Uint8Array;
  databaseRootKey: DatabaseRootKey | Uint8Array;
  deviceProtectionSecret: Uint8Array;
  migrationJournalPath: string;
  legacyDatabaseRevisionAnchorPath: string;
  authorityRollbackAnchorPath: string;
  rollbackAnchorPath: string;
}>;

export type CollaborationGenesisMigrationStageResult =
  | Readonly<{ status: 'staged' }>
  | Readonly<{ status: 'unknown'; reason: 'journal-persistence-failed' }>
  | Readonly<{ status: 'terminal'; reason: 'journal-mismatch' }>;

type ParsedMigration = Readonly<{
  journalInput: CollaborationMigrationJournalCreateInput;
  writerSigningPublicKey: string;
  scope: CollaborationMigrationJournalScope;
  anchorScope: RecipientRollbackAnchorScope;
  authorityAnchor: CollaborationAuthorityRollbackAnchor;
  authorityAnchorScope: CollaborationAuthorityRollbackAnchorScope;
}>;

type OutcomeClassification =
  | Readonly<{
      kind: 'matching';
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone;
    }>
  | Readonly<{
      kind: 'incompatible-committed';
      outcome: DurableOperationOutcome;
    }>
  | Readonly<{ kind: 'retryable'; reason: 'conflict' | 'rejected' }>
  | Readonly<{ kind: 'operation-id-reused' }>
  | Readonly<{ kind: 'invalid' }>;

type RemoteOutcomeRead =
  | Readonly<{
      kind: 'available';
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone | null;
    }>
  | Readonly<{ kind: 'unavailable' }>;

type RemoteEvidence =
  | Readonly<{
      kind: 'matching';
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone;
    }>
  | Readonly<{
      kind: 'incompatible-committed';
      outcome: DurableOperationOutcome;
    }>
  | Readonly<{ kind: 'absent' }>
  | Readonly<{ kind: 'retryable'; reason: 'conflict' | 'rejected' }>
  | Readonly<{ kind: 'operation-id-reused' }>
  | Readonly<{ kind: 'outcome-invalid' }>
  | Readonly<{ kind: 'state-mismatch' }>
  | Readonly<{ kind: 'outcome-unavailable' }>
  | Readonly<{ kind: 'readback-unavailable' }>;

type StepResult =
  | Readonly<{ kind: 'advanced' }>
  | Readonly<{ kind: 'result'; result: CollaborationMigrationOrchestrationResult }>;

/**
 * Resumes one immutable genesis migration until it is durably anchored and
 * locally marked active, or returns a redacted retry/terminal classification.
 * The prepared plaintext manifest and disposable vault root key are never
 * passed to a journal, store, or error; required digest checks remain in memory.
 */
export async function orchestrateCollaborativeGenesisMigration(
  input: OrchestrateCollaborativeGenesisMigrationInput,
): Promise<CollaborationMigrationOrchestrationResult> {
  let databaseRootKey: Uint8Array | undefined;
  let protectionSecret: Uint8Array | undefined;
  let recipientPrivateKey: Uint8Array | undefined;
  try {
    assertPath(input.migrationJournalPath);
    assertPath(input.legacyDatabaseRevisionAnchorPath);
    assertPath(input.authorityRollbackAnchorPath);
    assertPath(input.rollbackAnchorPath);
    databaseRootKey = copySecret(input.databaseRootKey, 32);
    protectionSecret = copySecret(
      input.deviceProtectionSecret,
      DEVICE_PROTECTION_SECRET_BYTES,
    );
    recipientPrivateKey =
      input.restart === undefined
        ? undefined
        : copySecret(input.restart.recipientEncryptionPrivateKey, 32);
    const parsed = await parsePrepared(input.prepared, input.restart);
    if (recipientPrivateKey !== undefined) {
      await recoverAndVerifyRestartBundle(
        parsed.journalInput,
        recipientPrivateKey,
        input.prepared.initialManifest,
      );
    }
    const journalReady = await ensureJournal(
      input.migrationJournalPath,
      protectionSecret,
      parsed,
    );
    if (journalReady.kind === 'result') return journalReady.result;

    return await driveMigration(
      input.store,
      input.migrationJournalPath,
      input.legacyDatabaseRevisionAnchorPath,
      input.authorityRollbackAnchorPath,
      input.rollbackAnchorPath,
      databaseRootKey,
      protectionSecret,
      parsed,
    );
  } catch (error) {
    if (error instanceof CollaborationMigrationOrchestrationError) throw error;
    throw failure('invalid-input');
  } finally {
    zeroize(recipientPrivateKey);
    zeroize(protectionSecret);
    zeroize(databaseRootKey);
  }
}

/** Durably stages exact public restart material without mutating the store. */
export async function stageCollaborativeGenesisMigration(
  input: StageCollaborativeGenesisMigrationInput,
): Promise<CollaborationGenesisMigrationStageResult> {
  let protectionSecret: Uint8Array | undefined;
  let recipientPrivateKey: Uint8Array | undefined;
  try {
    assertPath(input.migrationJournalPath);
    protectionSecret = copySecret(
      input.deviceProtectionSecret,
      DEVICE_PROTECTION_SECRET_BYTES,
    );
    recipientPrivateKey = copySecret(input.recipientEncryptionPrivateKey, 32);
    const parsed = await parsePrepared(input.prepared, {
      initialOwnerIdentity: input.initialOwnerIdentity,
      restartRecipient: input.restartRecipient,
    });
    await recoverAndVerifyRestartBundle(
      parsed.journalInput,
      recipientPrivateKey,
      input.prepared.initialManifest,
    );
    const staged = await ensureJournal(
      input.migrationJournalPath,
      protectionSecret,
      parsed,
    );
    if (staged.kind === 'advanced') return { status: 'staged' };
    return staged.result.status === 'terminal'
      ? { status: 'terminal', reason: 'journal-mismatch' }
      : { status: 'unknown', reason: 'journal-persistence-failed' };
  } catch (error) {
    if (error instanceof CollaborationMigrationOrchestrationError) throw error;
    throw failure('invalid-input');
  } finally {
    zeroize(recipientPrivateKey);
    zeroize(protectionSecret);
  }
}

/** Resumes solely from authenticated files, public journal material, and one device key. */
export async function resumeCollaborativeGenesisMigration(
  input: ResumeCollaborativeGenesisMigrationInput,
): Promise<CollaborationMigrationOrchestrationResult> {
  let databaseRootKey: Uint8Array | undefined;
  let protectionSecret: Uint8Array | undefined;
  let recipientPrivateKey: Uint8Array | undefined;
  try {
    assertPath(input.migrationJournalPath);
    assertPath(input.legacyDatabaseRevisionAnchorPath);
    assertPath(input.authorityRollbackAnchorPath);
    assertPath(input.rollbackAnchorPath);
    databaseRootKey = copySecret(input.databaseRootKey, 32);
    protectionSecret = copySecret(
      input.deviceProtectionSecret,
      DEVICE_PROTECTION_SECRET_BYTES,
    );
    recipientPrivateKey = copySecret(input.recipientEncryptionPrivateKey, 32);
    const record = await readCollaborationMigrationJournalForResume(
      input.migrationJournalPath,
      protectionSecret,
    );
    if (record === null) {
      return { status: 'unknown', reason: 'journal-persistence-failed' };
    }
    const journalInput = journalInputFromRecord(record);
    const parsed = await recoverAndVerifyRestartBundle(
      journalInput,
      recipientPrivateKey,
    );
    if (!journalMatches(record, parsed)) {
      return { status: 'terminal', reason: 'journal-mismatch' };
    }
    return await driveMigration(
      input.store,
      input.migrationJournalPath,
      input.legacyDatabaseRevisionAnchorPath,
      input.authorityRollbackAnchorPath,
      input.rollbackAnchorPath,
      databaseRootKey,
      protectionSecret,
      parsed,
    );
  } catch (error) {
    if (error instanceof CollaborationMigrationOrchestrationError) throw error;
    throw failure('invalid-input');
  } finally {
    zeroize(recipientPrivateKey);
    zeroize(protectionSecret);
    zeroize(databaseRootKey);
  }
}

async function driveMigration(
  store: CollaborativeVaultStore,
  migrationJournalPath: string,
  legacyDatabaseRevisionAnchorPath: string,
  authorityRollbackAnchorPath: string,
  rollbackAnchorPath: string,
  databaseRootKey: Uint8Array,
  protectionSecret: Uint8Array,
  parsed: ParsedMigration,
): Promise<CollaborationMigrationOrchestrationResult> {
  const initial = await readJournal(
    migrationJournalPath,
    protectionSecret,
    parsed.scope,
  );
  if (initial.kind === 'unavailable') {
    return { status: 'unknown', reason: 'journal-persistence-failed' };
  }
  if (initial.record === null || !journalMatches(initial.record, parsed)) {
    return { status: 'terminal', reason: 'journal-mismatch' };
  }
  const startedActive = initial.record.state === 'active';

  // Each successful pass advances exactly one durable local state. The
  // fixed bound prevents malformed/custom stores from creating a busy loop.
  for (let step = 0; step < 5; step += 1) {
    const current = await readJournal(
      migrationJournalPath,
      protectionSecret,
      parsed.scope,
    );
    if (current.kind === 'unavailable') {
      return { status: 'unknown', reason: 'journal-persistence-failed' };
    }
    if (current.record === null || !journalMatches(current.record, parsed)) {
      return { status: 'terminal', reason: 'journal-mismatch' };
    }

    switch (current.record.state) {
      case 'failed':
        return { status: 'terminal', reason: 'journal-failed' };
      case 'prepared': {
        const result = await publishGenesis(
          store,
          migrationJournalPath,
          legacyDatabaseRevisionAnchorPath,
          databaseRootKey,
          protectionSecret,
          parsed,
        );
        if (result.kind === 'result') return result.result;
        break;
      }
      case 'published': {
        const result = await persistAnchor(
          authorityRollbackAnchorPath,
          rollbackAnchorPath,
          migrationJournalPath,
          databaseRootKey,
          protectionSecret,
          parsed,
        );
        if (result.kind === 'result') return result.result;
        break;
      }
      case 'anchored': {
        const result = await proveActiveAndMarkJournal(
          store,
          migrationJournalPath,
          protectionSecret,
          parsed,
        );
        if (result.kind === 'result') return result.result;
        break;
      }
      case 'active':
        return await verifyActiveState(
          store,
          authorityRollbackAnchorPath,
          rollbackAnchorPath,
          databaseRootKey,
          protectionSecret,
          parsed,
          startedActive,
        );
    }
  }
  return { status: 'unknown', reason: 'migration-ambiguous' };
}

async function parsePrepared(
  prepared: PreparedCollaborativeGenesis,
  restart:
    | CollaborationGenesisMigrationRestartInput
    | Readonly<{
        initialOwnerIdentity: PublicIdentityExport;
        restartRecipient: CollaborationMigrationRestartRecipient;
      }>
    | undefined,
): Promise<ParsedMigration> {
  try {
    const derivedIdentity = publicIdentityExportSchema.parse(
      structuredClone(prepared.initialOwnerIdentity),
    );
    const derivedRecipient: CollaborationMigrationRestartRecipient = {
      principalId: prepared.candidateAnchor.principalId,
      deviceId: prepared.candidateAnchor.deviceId,
    };
    const overrideIdentity = restart?.initialOwnerIdentity;
    const overrideRecipient =
      restart === undefined
        ? undefined
        : 'recipient' in restart
          ? restart.recipient
          : restart.restartRecipient;
    if (
      (overrideIdentity !== undefined &&
        !sameCanonical(overrideIdentity, derivedIdentity)) ||
      (overrideRecipient !== undefined &&
        !sameCanonical(overrideRecipient, derivedRecipient))
    ) {
      throw failure('invalid-input');
    }
    // Select the exact persistent projection. In particular, do not clone or
    // canonically encode the full PreparedCollaborativeGenesis object.
    const journalInput = collaborationMigrationJournalCreateInputSchema.parse({
      request: prepared.request,
      registryCandidate: prepared.registryCandidate,
      preparedMarker: prepared.preparedMarker,
      activeMarker: prepared.activeMarker,
      collaborativeCandidate: prepared.candidate,
      proofEntry: prepared.proofEntry,
      proposedOutcome: prepared.proposedOutcome,
      initialRecipientAnchor: prepared.candidateAnchor,
      initialOwnerIdentity: derivedIdentity,
      restartRecipient: derivedRecipient,
    });
    const manifest = collaborativeMembershipManifestSchema.parse(
      structuredClone(prepared.initialManifest),
    );
    const { writer, recipientDevice } = await verifyRestartIdentity(
      journalInput,
      derivedIdentity,
      derivedRecipient,
    );
    const discovery = selectRestartDiscovery(
      journalInput,
      derivedIdentity,
      derivedRecipient,
      recipientDevice,
    );
    await verifyRestartDiscoveryAndEnvelope(journalInput, discovery, writer);
    await verifyRestartManifest(
      journalInput,
      manifest,
      derivedIdentity,
      writer,
      discovery.encryptedMemberKeyEnvelope,
    );
    await verifyLocalBundle(journalInput, manifest, writer);
    return parsedMigration(journalInput, writer.signingPublicKey);
  } catch (error) {
    if (error instanceof CollaborationMigrationOrchestrationError) throw error;
    throw failure('invalid-input');
  }
}

function journalInputFromRecord(
  record: CollaborationMigrationJournalRecord,
): CollaborationMigrationJournalCreateInput {
  try {
    return collaborationMigrationJournalCreateInputSchema.parse({
      request: record.request,
      registryCandidate: record.registryCandidate,
      preparedMarker: record.preparedMarker,
      activeMarker: record.activeMarker,
      collaborativeCandidate: record.collaborativeCandidate,
      proofEntry: record.proofEntry,
      proposedOutcome: record.proposedOutcome,
      initialRecipientAnchor: record.initialRecipientAnchor,
      initialOwnerIdentity: record.initialOwnerIdentity,
      restartRecipient: record.restartRecipient,
    });
  } catch {
    throw failure('invalid-input');
  }
}

function parsedMigration(
  journalInput: CollaborationMigrationJournalCreateInput,
  writerSigningPublicKey: string,
): ParsedMigration {
  const scope: CollaborationMigrationJournalScope = {
    databaseId: journalInput.request.databaseId,
    vaultId: journalInput.request.vaultId,
    principalId: journalInput.request.initialOwnerPrincipalId,
    deviceId: journalInput.request.initialOwnerDeviceId,
    operationId: journalInput.request.operationId,
    requestDigest: journalInput.request.requestDigest,
  };
  const authorityAnchor =
    collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
      journalInput.collaborativeCandidate,
      {
        membershipDigest: journalInput.initialRecipientAnchor.membershipDigest,
        policyDigest: journalInput.initialRecipientAnchor.policyDigest,
      },
    );
  return {
    journalInput,
    writerSigningPublicKey,
    scope,
    anchorScope: {
      databaseId: scope.databaseId,
      vaultId: scope.vaultId,
      principalId: scope.principalId,
      deviceId: scope.deviceId,
    },
    authorityAnchor,
    authorityAnchorScope: {
      databaseId: authorityAnchor.databaseId,
      vaultId: authorityAnchor.vaultId,
      authorityEpoch: authorityAnchor.authorityEpoch,
      authorityDelegationDigest: authorityAnchor.authorityDelegationDigest,
    },
  };
}

async function recoverAndVerifyRestartBundle(
  bundle: CollaborationMigrationJournalCreateInput,
  recipientPrivateKey: Uint8Array,
  expectedManifest?: CollaborativeMembershipManifest,
): Promise<ParsedMigration> {
  const identity = bundle.initialOwnerIdentity;
  const recipient = bundle.restartRecipient;
  const verifiedIdentity = publicIdentityExportSchema.parse(identity);
  const { writer, recipientDevice } = await verifyRestartIdentity(
    bundle,
    verifiedIdentity,
    recipient,
  );
  const discovery = selectRestartDiscovery(
    bundle,
    verifiedIdentity,
    recipient,
    recipientDevice,
  );
  await verifyRestartDiscoveryAndEnvelope(bundle, discovery, writer);

  let vaultRootKey: Uint8Array | undefined;
  let manifestPlaintext: Uint8Array | undefined;
  let payloadPlaintext: Uint8Array | undefined;
  try {
    vaultRootKey = await openVaultRootKeyForDevice(
      discovery.encryptedMemberKeyEnvelope.sealedVaultRootKey,
      recipientDevice.encryptionPublicKey,
      recipientPrivateKey,
    );
    manifestPlaintext = await decryptCollaborationEnvelope(
      bundle.collaborativeCandidate.encryptedMembershipManifest,
      vaultRootKey,
      expectedCandidateAad(bundle.collaborativeCandidate, 'membership-manifest'),
    );
    payloadPlaintext = await decryptCollaborationEnvelope(
      bundle.collaborativeCandidate.encryptedPayload,
      vaultRootKey,
      expectedCandidateAad(bundle.collaborativeCandidate, 'vault-payload'),
    );
    const manifest = parseManifestPlaintext(manifestPlaintext);
    if (expectedManifest !== undefined && !sameCanonical(manifest, expectedManifest)) {
      throw failure('invalid-input');
    }
    await verifyRestartManifest(
      bundle,
      manifest,
      verifiedIdentity,
      writer,
      discovery.encryptedMemberKeyEnvelope,
    );
    await verifyLocalBundle(bundle, manifest, writer);
    return parsedMigration(bundle, writer.signingPublicKey);
  } catch (error) {
    if (error instanceof CollaborationMigrationOrchestrationError) throw error;
    throw failure('invalid-input');
  } finally {
    zeroize(vaultRootKey);
    zeroize(manifestPlaintext);
    zeroize(payloadPlaintext);
  }
}

async function verifyRestartIdentity(
  bundle: CollaborationMigrationJournalCreateInput,
  identity: PublicIdentityExport,
  recipient: CollaborationMigrationRestartRecipient,
): Promise<
  Readonly<{ writer: DeviceCertificate; recipientDevice: DeviceCertificate }>
> {
  const request = bundle.request;
  if (
    identity.principalId !== request.initialOwnerPrincipalId ||
    recipient.principalId !== request.initialOwnerPrincipalId ||
    Date.parse(identity.createdAt) > Date.parse(request.requestedAt) ||
    (identity.expiresAt !== undefined &&
      Date.parse(identity.expiresAt) <= Date.parse(bundle.activeMarker.activatedAt)) ||
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.publicIdentitySignature,
      identity,
      publicIdentityExportSchema,
      'selfSignature',
      identity.rootSigningPublicKey,
    ))
  ) {
    throw failure('invalid-input');
  }
  for (const device of identity.devices) {
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.deviceCertificateSignature,
        device,
        deviceCertificateSchema,
        'rootSignature',
        identity.rootSigningPublicKey,
      ))
    ) {
      throw failure('invalid-input');
    }
  }
  const writers = identity.devices.filter(
    (device) => device.deviceId === request.initialOwnerDeviceId,
  );
  const recipients = identity.devices.filter(
    (device) => device.deviceId === recipient.deviceId,
  );
  const writer = writers[0];
  const recipientDevice = recipients[0];
  const delegation = bundle.collaborativeCandidate.authorityDelegation;
  if (
    writers.length !== 1 ||
    recipients.length !== 1 ||
    writer === undefined ||
    recipientDevice === undefined ||
    writer.state !== 'active' ||
    recipientDevice.state !== 'active' ||
    Date.parse(writer.createdAt) > Date.parse(request.requestedAt) ||
    Date.parse(recipientDevice.createdAt) > Date.parse(request.requestedAt) ||
    Date.parse(writer.stateChangedAt) > Date.parse(request.requestedAt) ||
    Date.parse(recipientDevice.stateChangedAt) > Date.parse(request.requestedAt) ||
    (writer.expiresAt !== undefined &&
      Date.parse(writer.expiresAt) <= Date.parse(bundle.activeMarker.activatedAt)) ||
    (recipientDevice.expiresAt !== undefined &&
      Date.parse(recipientDevice.expiresAt) <=
        Date.parse(bundle.activeMarker.activatedAt)) ||
    registryDeniesDevice(bundle.registryCandidate, writer) ||
    registryDeniesDevice(bundle.registryCandidate, recipientDevice) ||
    delegation.initialOwnerRootKeyFingerprint !==
      computePublicKeyFingerprint(identity.rootSigningPublicKey, 'ed25519') ||
    delegation.initialOwnerDeviceSigningKeyFingerprint !==
      computePublicKeyFingerprint(writer.signingPublicKey, 'ed25519') ||
    delegation.initialOwnerDeviceEncryptionKeyFingerprint !==
      computePublicKeyFingerprint(writer.encryptionPublicKey, 'x25519')
  ) {
    throw failure('invalid-input');
  }
  return { writer, recipientDevice };
}

function selectRestartDiscovery(
  bundle: CollaborationMigrationJournalCreateInput,
  identity: PublicIdentityExport,
  recipient: CollaborationMigrationRestartRecipient,
  recipientDevice: DeviceCertificate,
): CollaborationMigrationJournalCreateInput['collaborativeCandidate']['discoveryRecords'][number] {
  const candidate = bundle.collaborativeCandidate;
  const discoveryTag = computeDiscoveryTag(
    candidate.databaseId,
    computePublicKeyFingerprint(identity.rootSigningPublicKey, 'ed25519'),
  );
  const matches = candidate.discoveryRecords.filter(
    (record) =>
      record.discoveryTag === discoveryTag &&
      record.encryptedMemberKeyEnvelope.principalId === recipient.principalId &&
      record.encryptedMemberKeyEnvelope.deviceId === recipient.deviceId,
  );
  const discovery = matches[0];
  if (
    matches.length !== 1 ||
    discovery?.membershipState !== 'active' ||
    discovery.membershipId !== bundle.request.initialMembershipId ||
    discovery.encryptedMemberKeyEnvelope.recipientEncryptionKeyFingerprint !==
      computePublicKeyFingerprint(recipientDevice.encryptionPublicKey, 'x25519')
  ) {
    throw failure('invalid-input');
  }
  return discovery;
}

async function verifyRestartDiscoveryAndEnvelope(
  bundle: CollaborationMigrationJournalCreateInput,
  discovery: CollaborationMigrationJournalCreateInput['collaborativeCandidate']['discoveryRecords'][number],
  writer: DeviceCertificate,
): Promise<void> {
  const envelope = discovery.encryptedMemberKeyEnvelope;
  if (
    discovery.discoveryRecordDigest !== computeDiscoveryRecordDigest(discovery) ||
    envelope.envelopeDigest !== computeKeyEnvelopeDigest(envelope) ||
    !(await verifyDiscoveryRecord(discovery, writer.signingPublicKey)) ||
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.keyEnvelopeSignature,
      envelope,
      collaborationKeyEnvelopeSchema,
      'ownerSignature',
      writer.signingPublicKey,
    )) ||
    discovery.authorizationStateDigest !==
      bundle.collaborativeCandidate.authorizationStateDigest
  ) {
    throw failure('invalid-input');
  }
}

async function verifyRestartManifest(
  bundle: CollaborationMigrationJournalCreateInput,
  manifest: CollaborativeMembershipManifest,
  identity: PublicIdentityExport,
  writer: DeviceCertificate,
  selectedEnvelope: CollaborationMigrationJournalCreateInput['collaborativeCandidate']['discoveryRecords'][number]['encryptedMemberKeyEnvelope'],
): Promise<void> {
  const owner = manifest.memberships.find(
    (membership) =>
      membership.membershipId === bundle.request.initialMembershipId &&
      membership.principalId === bundle.request.initialOwnerPrincipalId,
  );
  const envelopeMatches = manifest.keyEnvelopes.filter(
    (envelope) =>
      'membershipId' in envelope &&
      envelope.principalId === selectedEnvelope.principalId &&
      envelope.deviceId === selectedEnvelope.deviceId,
  );
  if (
    owner?.role !== 'owner' ||
    owner.state !== 'active' ||
    owner.rootSigningPublicKey !== identity.rootSigningPublicKey ||
    owner.identityGeneration !== identity.identityGeneration ||
    owner.principalFingerprint !==
      computePublicKeyFingerprint(identity.rootSigningPublicKey, 'ed25519') ||
    !sameCanonical(owner.devices, identity.devices) ||
    envelopeMatches.length !== 1 ||
    !sameCanonical(envelopeMatches[0], selectedEnvelope)
  ) {
    throw failure('invalid-input');
  }
  for (const envelope of manifest.keyEnvelopes) {
    const memberEnvelope = 'membershipId' in envelope;
    const digest = memberEnvelope
      ? computeKeyEnvelopeDigest(envelope)
      : computeAuthorityRecoveryEnvelopeDigest(envelope);
    const signatureValid = memberEnvelope
      ? await verifyCollaborationRecord(
          COLLABORATION_DOMAINS.keyEnvelopeSignature,
          envelope,
          collaborationKeyEnvelopeSchema,
          'ownerSignature',
          writer.signingPublicKey,
        )
      : await verifyCollaborationRecord(
          COLLABORATION_DOMAINS.keyEnvelopeSignature,
          envelope,
          databaseAuthorityRecoveryEnvelopeSchema,
          'ownerSignature',
          writer.signingPublicKey,
        );
    if (envelope.envelopeDigest !== digest || !signatureValid) {
      throw failure('invalid-input');
    }
  }
  if (
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.policySignature,
      manifest.policy,
      collaborationPolicyStateSchema,
      'signature',
      writer.signingPublicKey,
    ))
  ) {
    throw failure('invalid-input');
  }
  for (const record of bundle.collaborativeCandidate.discoveryRecords) {
    if (
      record.discoveryRecordDigest !== computeDiscoveryRecordDigest(record) ||
      !(await verifyDiscoveryRecord(record, writer.signingPublicKey))
    ) {
      throw failure('invalid-input');
    }
  }
}

function parseManifestPlaintext(
  plaintext: Uint8Array,
): CollaborativeMembershipManifest {
  try {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    return collaborativeMembershipManifestSchema.parse(JSON.parse(decoded) as unknown);
  } catch {
    throw failure('invalid-input');
  }
}

function expectedCandidateAad(
  candidate: CollaborationMigrationJournalCreateInput['collaborativeCandidate'],
  entityType: 'membership-manifest' | 'vault-payload',
): ReturnType<typeof collaborationAadSchema.parse> {
  const metadata = collaborationAadMetadataSchema.parse({
    protocolVersion: candidate.protocolVersion,
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    authorityEpoch: candidate.authorityEpoch,
    entityType,
    entityId: candidate.vaultId,
    documentRevision: candidate.documentRevision,
    membershipRevision: candidate.membershipRevision,
    policyRevision: candidate.policyRevision,
    keyEpoch: candidate.keyEpoch,
    databaseDeviceGeneration: candidate.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
    authorizationStateDigest: candidate.authorizationStateDigest,
  });
  return collaborationAadSchema.parse({
    ...metadata,
    metadataDigest: computeAadMetadataDigest(metadata),
  });
}

async function verifyLocalBundle(
  bundle: CollaborationMigrationJournalCreateInput,
  manifest: CollaborativeMembershipManifest,
  writer: DeviceCertificate,
): Promise<void> {
  const { request, registryCandidate, preparedMarker, activeMarker } = bundle;
  const candidate = bundle.collaborativeCandidate;
  const link = candidate.currentMutationLink;
  const transition = link.authorizationTransition;
  const witness = bundle.proofEntry.authorizationWitness;
  const authorityPublicKey = candidate.authorityDelegation.authoritySigningPublicKey;
  requireExactDatabaseAuthorityRecoveryEnvelope(candidate, manifest);
  if (witness !== undefined) {
    requireExactDatabaseAuthorityRecoveryEnvelope(witness, manifest);
  }
  if (
    transition === undefined ||
    witness?.databaseAuthorityRecoveryEnvelope.authorityRecoveryKeyFingerprint !==
      candidate.authorityDelegation.authorityRecoveryKeyFingerprint ||
    request.requestDigest !== computeMigrationRequestDigest(request) ||
    request.legacySourceDigest !==
      computeLegacySourceDigest(preparedMarker.legacySource) ||
    registryCandidate.registryDigest !==
      computeDeviceRegistryDigest(registryCandidate) ||
    candidate.authorityDelegationDigest !==
      computeAuthorityDelegationDigest(candidate.authorityDelegation) ||
    candidate.headDigest !== computeMutationHead(link.commitment) ||
    candidate.encryptedPayloadDigest !==
      computeEncryptedPayloadDigest(candidate.encryptedPayload) ||
    candidate.encryptedMembershipDigest !==
      computeEncryptedMembershipDigest(candidate.encryptedMembershipManifest) ||
    bundle.proposedOutcome.outcomeDigest !==
      computeOperationOutcomeDigest(bundle.proposedOutcome) ||
    bundle.proposedOutcome.finalizedMutationLinkDigest !==
      computeFinalizedMutationLinkDigest(link) ||
    !sameCanonical(bundle.proofEntry.link, link) ||
    !sameCanonical(witness.databaseDeviceRegistry, registryCandidate) ||
    manifest.databaseId !== candidate.databaseId ||
    manifest.vaultId !== candidate.vaultId ||
    manifest.authorityEpoch !== candidate.authorityEpoch ||
    manifest.databaseDeviceGeneration !== candidate.databaseDeviceGeneration ||
    manifest.databaseDeviceRegistryDigest !== candidate.databaseDeviceRegistryDigest ||
    manifest.documentRevision !== candidate.documentRevision ||
    manifest.membershipRevision !== candidate.membershipRevision ||
    manifest.policyRevision !== candidate.policyRevision ||
    manifest.keyEpoch !== candidate.keyEpoch ||
    manifest.authorizationStateDigest !== candidate.authorizationStateDigest ||
    manifest.membershipDigest !== computeMembershipManifestDigest(manifest) ||
    bundle.initialRecipientAnchor.membershipDigest !==
      computeMembershipStateDigest(authorizationCoreFromManifest(manifest)) ||
    bundle.initialRecipientAnchor.policyDigest !==
      computePolicyStateDigest(manifest.policy) ||
    manifest.history.currentHistoryDigest !==
      computeMembershipHistoryDigest(manifest.history) ||
    candidate.encryptedEnvelopesDigest !==
      computeKeyEnvelopeSetDigest(manifest.keyEnvelopes) ||
    candidate.policyDigest !== computePolicyDigest(manifest.policy) ||
    !(await verifyAuthorityDelegation(
      candidate.authorityDelegation,
      authorityPublicKey,
    )) ||
    !(await verifyMigrationRequestAuthority(request, authorityPublicKey)) ||
    !(await verifyMigrationRequestOwner(request, writer.signingPublicKey)) ||
    !(await verifyMigrationPreparedMarker(preparedMarker, authorityPublicKey)) ||
    !(await verifyMigrationActiveMarker(activeMarker, authorityPublicKey)) ||
    !(await verifyAuthorizationTransitionOwner(transition, writer.signingPublicKey)) ||
    !(await verifyFinalizedMutationLink(link, writer.signingPublicKey)) ||
    !(await verifyCommittedOperationOutcome(
      bundle.proposedOutcome,
      writer.signingPublicKey,
    )) ||
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.deviceRegistrySignature,
      registryCandidate,
      collaborationDatabaseDeviceRegistrySchema,
      'authoritySignature',
      authorityPublicKey,
    )) ||
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.membershipHistorySignature,
      required(manifest.history.events),
      membershipHistoryEventSchema,
      'signature',
      writer.signingPublicKey,
    ))
  ) {
    throw failure('invalid-input');
  }
}

async function ensureJournal(
  path: string,
  secret: Uint8Array,
  parsed: ParsedMigration,
): Promise<StepResult> {
  try {
    await createCollaborationMigrationJournal(path, secret, parsed.journalInput);
    return { kind: 'advanced' };
  } catch {
    const existing = await readJournal(path, secret, parsed.scope);
    if (existing.kind === 'unavailable' || existing.record === null) {
      return {
        kind: 'result',
        result: { status: 'unknown', reason: 'journal-persistence-failed' },
      };
    }
    return journalMatches(existing.record, parsed)
      ? { kind: 'advanced' }
      : {
          kind: 'result',
          result: { status: 'terminal', reason: 'journal-mismatch' },
        };
  }
}

async function publishGenesis(
  store: CollaborativeVaultStore,
  journalPath: string,
  legacyDatabaseRevisionAnchorPath: string,
  databaseRootKey: Uint8Array,
  secret: Uint8Array,
  parsed: ParsedMigration,
): Promise<StepResult> {
  const before = await readRemoteEvidence(store, parsed, true);
  const beforeResult = await handlePrePublicationEvidence(
    before,
    journalPath,
    secret,
    parsed,
  );
  if (beforeResult !== undefined) return beforeResult;

  let beginError: unknown;
  const beginState = { invoked: false };
  try {
    const observedLegacyAnchor = await readDatabaseRevisionAnchor(
      legacyDatabaseRevisionAnchorPath,
      databaseRootKey,
    );
    const observed = await transitionDatabaseRevisionAnchor(
      legacyDatabaseRevisionAnchorPath,
      databaseRootKey,
      observedLegacyAnchor,
      async (trustedLegacyAnchor) => {
        if (!legacyAnchorMatchesSource(trustedLegacyAnchor, parsed)) {
          throw failure('invalid-input');
        }
        beginState.invoked = true;
        const marker = await store.beginCollaborativeMigration({
          request: parsed.journalInput.request,
          preparedMarker: parsed.journalInput.preparedMarker,
        });
        return { nextAnchor: trustedLegacyAnchor, result: marker };
      },
      { requireExactVaultSet: true },
    );
    if (!sameCanonical(observed, parsed.journalInput.preparedMarker)) {
      return terminal('remote-state-mismatch');
    }
  } catch (error) {
    if (!beginState.invoked) return terminal('anchor-mismatch');
    beginError = error;
    const afterBegin = await readRemoteEvidence(store, parsed, true);
    const reconciled = await handlePrePublicationEvidence(
      afterBegin,
      journalPath,
      secret,
      parsed,
    );
    if (reconciled !== undefined) return reconciled;
    // An absent outcome cannot distinguish a pre-commit failure from a lost
    // response after the prepared marker committed. Do not repeat begin here;
    // one exact activation attempt is safe in only the latter state.
  }

  try {
    const returned = await store.activateCollaborativeGenesis({
      preparedMarker: parsed.journalInput.preparedMarker,
      candidate: parsed.journalInput.collaborativeCandidate,
      outcome: parsed.journalInput.proposedOutcome,
      proofEntry: parsed.journalInput.proofEntry,
      activeMarker: parsed.journalInput.activeMarker,
    });
    const classified = await classifyOutcome(returned, parsed);
    if (classified.kind !== 'matching') {
      return await handleClassifiedOutcome(classified, journalPath, secret);
    }
  } catch (activationError) {
    const afterActivation = await readRemoteEvidence(store, parsed, true);
    const reconciled = await handlePrePublicationEvidence(
      afterActivation,
      journalPath,
      secret,
      parsed,
    );
    if (reconciled !== undefined) return reconciled;
    const decisive = classifyStoreRejection(activationError, beginError);
    return decisive === undefined
      ? unknown('migration-ambiguous')
      : { kind: 'result', result: decisive };
  }

  const committed = await readRemoteEvidence(store, parsed, true);
  return await handlePublishedEvidence(committed, journalPath, secret, parsed);
}

async function handlePrePublicationEvidence(
  evidence: RemoteEvidence,
  journalPath: string,
  secret: Uint8Array,
  parsed: ParsedMigration,
): Promise<StepResult | undefined> {
  if (evidence.kind === 'absent') return undefined;
  return await handlePublishedEvidence(evidence, journalPath, secret, parsed);
}

async function handlePublishedEvidence(
  evidence: RemoteEvidence,
  journalPath: string,
  secret: Uint8Array,
  parsed: ParsedMigration,
): Promise<StepResult> {
  switch (evidence.kind) {
    case 'matching': {
      try {
        const state = await reconcileCollaborationMigrationPublication(
          journalPath,
          secret,
          parsed.journalInput.proposedOutcome,
        );
        return state === 'published'
          ? { kind: 'advanced' }
          : terminal('journal-failed');
      } catch {
        return unknown('journal-persistence-failed');
      }
    }
    case 'incompatible-committed':
      return await terminalizeIncompatible(journalPath, secret, evidence.outcome);
    case 'retryable':
      return {
        kind: 'result',
        result: { status: 'retryable', reason: evidence.reason },
      };
    case 'operation-id-reused':
      return terminal('operation-id-reused');
    case 'outcome-invalid':
      return terminal('remote-outcome-invalid');
    case 'state-mismatch':
      return terminal('remote-state-mismatch');
    case 'outcome-unavailable':
      return unknown('outcome-unavailable');
    case 'readback-unavailable':
      return unknown('readback-unavailable');
    case 'absent':
      return unknown('migration-ambiguous');
  }
}

async function handleClassifiedOutcome(
  classified: Exclude<OutcomeClassification, { kind: 'matching' }>,
  journalPath: string,
  secret: Uint8Array,
): Promise<StepResult> {
  switch (classified.kind) {
    case 'incompatible-committed':
      return await terminalizeIncompatible(journalPath, secret, classified.outcome);
    case 'retryable':
      return {
        kind: 'result',
        result: { status: 'retryable', reason: classified.reason },
      };
    case 'operation-id-reused':
      return terminal('operation-id-reused');
    case 'invalid':
      return terminal('remote-outcome-invalid');
  }
}

async function terminalizeIncompatible(
  journalPath: string,
  secret: Uint8Array,
  outcome: DurableOperationOutcome,
): Promise<StepResult> {
  try {
    const state = await reconcileCollaborationMigrationPublication(
      journalPath,
      secret,
      outcome,
    );
    return state === 'failed'
      ? terminal('journal-failed')
      : terminal('remote-outcome-invalid');
  } catch {
    return terminal('remote-outcome-invalid');
  }
}

async function persistAnchor(
  authorityAnchorPath: string,
  recipientAnchorPath: string,
  journalPath: string,
  databaseRootKey: Uint8Array,
  secret: Uint8Array,
  parsed: ParsedMigration,
): Promise<StepResult> {
  try {
    await createCollaborationAuthorityRollbackAnchor(
      authorityAnchorPath,
      databaseRootKey,
      parsed.authorityAnchor,
    );
  } catch {
    const existing = await readAuthorityAnchor(
      authorityAnchorPath,
      databaseRootKey,
      parsed.authorityAnchorScope,
    );
    if (existing.kind === 'unavailable') {
      return unknown('anchor-persistence-failed');
    }
    if (!sameCanonical(existing.anchor, parsed.authorityAnchor)) {
      return terminal('anchor-mismatch');
    }
  }

  const observedAuthorityAnchor = await readAuthorityAnchor(
    authorityAnchorPath,
    databaseRootKey,
    parsed.authorityAnchorScope,
  );
  if (observedAuthorityAnchor.kind === 'unavailable') {
    return unknown('anchor-persistence-failed');
  }
  if (!sameCanonical(observedAuthorityAnchor.anchor, parsed.authorityAnchor)) {
    return terminal('anchor-mismatch');
  }

  const expectedRecipientAnchor = parsed.journalInput.initialRecipientAnchor;
  try {
    await createRecipientRollbackAnchor(
      recipientAnchorPath,
      secret,
      expectedRecipientAnchor,
    );
  } catch {
    const existing = await readAnchor(recipientAnchorPath, secret, parsed.anchorScope);
    if (existing.kind === 'unavailable') {
      return unknown('anchor-persistence-failed');
    }
    if (!sameCanonical(existing.anchor, expectedRecipientAnchor)) {
      return terminal('anchor-mismatch');
    }
  }

  const observed = await readAnchor(recipientAnchorPath, secret, parsed.anchorScope);
  if (observed.kind === 'unavailable') {
    return unknown('anchor-persistence-failed');
  }
  if (!sameCanonical(observed.anchor, expectedRecipientAnchor)) {
    return terminal('anchor-mismatch');
  }
  try {
    await markCollaborationMigrationAnchored(
      journalPath,
      secret,
      recipientAnchorPath,
      parsed.anchorScope,
      authorityAnchorPath,
      databaseRootKey,
      parsed.authorityAnchorScope,
    );
    return { kind: 'advanced' };
  } catch {
    return unknown('anchor-persistence-failed');
  }
}

async function proveActiveAndMarkJournal(
  store: CollaborativeVaultStore,
  journalPath: string,
  secret: Uint8Array,
  parsed: ParsedMigration,
): Promise<StepResult> {
  try {
    const replayed = await store.activateCollaborativeGenesis({
      preparedMarker: parsed.journalInput.preparedMarker,
      candidate: parsed.journalInput.collaborativeCandidate,
      outcome: parsed.journalInput.proposedOutcome,
      proofEntry: parsed.journalInput.proofEntry,
      activeMarker: parsed.journalInput.activeMarker,
    });
    const classified = await classifyOutcome(replayed, parsed);
    if (classified.kind !== 'matching') {
      return await handleClassifiedOutcome(classified, journalPath, secret);
    }
  } catch (error) {
    const evidence = await readRemoteEvidence(store, parsed, true);
    if (evidence.kind === 'incompatible-committed') {
      return await terminalizeIncompatible(journalPath, secret, evidence.outcome);
    }
    if (evidence.kind === 'operation-id-reused') {
      return terminal('operation-id-reused');
    }
    if (evidence.kind === 'outcome-invalid') {
      return terminal('remote-outcome-invalid');
    }
    if (evidence.kind === 'state-mismatch') {
      return terminal('remote-state-mismatch');
    }
    if (evidence.kind === 'outcome-unavailable') {
      return unknown('outcome-unavailable');
    }
    if (evidence.kind === 'readback-unavailable') {
      return unknown('readback-unavailable');
    }
    const retryable = classifyStoreRejection(error);
    return retryable === undefined
      ? unknown('migration-ambiguous')
      : { kind: 'result', result: retryable };
  }

  const evidence = await readRemoteEvidence(store, parsed, true);
  if (evidence.kind !== 'matching') {
    return await handlePublishedEvidence(evidence, journalPath, secret, parsed);
  }
  try {
    await markCollaborationMigrationActive(
      journalPath,
      secret,
      parsed.journalInput.activeMarker,
    );
    return { kind: 'advanced' };
  } catch {
    return unknown('journal-persistence-failed');
  }
}

async function verifyActiveState(
  store: CollaborativeVaultStore,
  authorityAnchorPath: string,
  recipientAnchorPath: string,
  databaseRootKey: Uint8Array,
  secret: Uint8Array,
  parsed: ParsedMigration,
  startedActive: boolean,
): Promise<CollaborationMigrationOrchestrationResult> {
  const authorityAnchor = await readAuthorityAnchor(
    authorityAnchorPath,
    databaseRootKey,
    parsed.authorityAnchorScope,
  );
  if (authorityAnchor.kind === 'unavailable') {
    return { status: 'unknown', reason: 'anchor-persistence-failed' };
  }
  if (!sameCanonical(authorityAnchor.anchor, parsed.authorityAnchor)) {
    return { status: 'terminal', reason: 'anchor-mismatch' };
  }
  const anchor = await readAnchor(recipientAnchorPath, secret, parsed.anchorScope);
  if (anchor.kind === 'unavailable') {
    return { status: 'unknown', reason: 'anchor-persistence-failed' };
  }
  if (!sameCanonical(anchor.anchor, parsed.journalInput.initialRecipientAnchor)) {
    return { status: 'terminal', reason: 'anchor-mismatch' };
  }
  const evidence = await readRemoteEvidence(store, parsed, true);
  switch (evidence.kind) {
    case 'matching':
      return {
        status: 'active',
        disposition: startedActive ? 'already-active' : 'activated',
        outcome: evidence.outcome,
      };
    case 'incompatible-committed':
    case 'outcome-invalid':
      return { status: 'terminal', reason: 'remote-outcome-invalid' };
    case 'operation-id-reused':
      return { status: 'terminal', reason: 'operation-id-reused' };
    case 'state-mismatch':
    case 'absent':
    case 'retryable':
      return { status: 'terminal', reason: 'remote-state-mismatch' };
    case 'outcome-unavailable':
      return { status: 'unknown', reason: 'outcome-unavailable' };
    case 'readback-unavailable':
      return { status: 'unknown', reason: 'readback-unavailable' };
  }
}

async function readRemoteEvidence(
  store: CollaborativeVaultStore,
  parsed: ParsedMigration,
  requireReadback: boolean,
): Promise<RemoteEvidence> {
  const outcomeRead = await readRemoteOutcome(store, parsed);
  if (outcomeRead.kind === 'unavailable') return { kind: 'outcome-unavailable' };
  if (outcomeRead.outcome === null) return { kind: 'absent' };
  const classified = await classifyOutcome(outcomeRead.outcome, parsed);
  switch (classified.kind) {
    case 'matching':
      if (!requireReadback) {
        return { kind: 'matching', outcome: classified.outcome };
      }
      return await verifyRemoteReadback(store, parsed, classified.outcome);
    case 'incompatible-committed':
      return classified;
    case 'retryable':
      return classified;
    case 'operation-id-reused':
      return classified;
    case 'invalid':
      return { kind: 'outcome-invalid' };
  }
}

async function classifyOutcome(
  remote: DurableOperationOutcome | OperationDeduplicationTombstone,
  parsed: ParsedMigration,
): Promise<OutcomeClassification> {
  try {
    if (remote.format === 'kavrix-collaborative-operation-tombstone') {
      const tombstone = operationDeduplicationTombstoneSchema.parse(remote);
      if (!sameOutcomeIdentity(tombstone, parsed)) return { kind: 'invalid' };
      if (tombstone.requestDigest !== parsed.scope.requestDigest) {
        return { kind: 'operation-id-reused' };
      }
      if (!(await verifyOperationTombstone(tombstone, parsed.writerSigningPublicKey))) {
        return { kind: 'invalid' };
      }
      if (
        tombstone.outcomeDigest !== parsed.journalInput.proposedOutcome.outcomeDigest ||
        !sameCanonical(
          tombstone.signedMutationReceipt,
          parsed.journalInput.proposedOutcome.signedMutationReceipt,
        )
      ) {
        return { kind: 'invalid' };
      }
      return { kind: 'matching', outcome: tombstone };
    }

    const outcome = durableOperationOutcomeSchema.parse(remote);
    if (!sameOutcomeIdentity(outcome, parsed)) return { kind: 'invalid' };
    if (outcome.state !== 'committed') {
      return {
        kind: 'retryable',
        reason: outcome.state === 'conflicted' ? 'conflict' : 'rejected',
      };
    }
    if (
      !(await verifyCommittedOperationOutcome(outcome, parsed.writerSigningPublicKey))
    ) {
      return { kind: 'invalid' };
    }
    if (outcome.requestDigest !== parsed.scope.requestDigest) {
      return { kind: 'operation-id-reused' };
    }
    if (sameCanonical(outcome, parsed.journalInput.proposedOutcome)) {
      return { kind: 'matching', outcome };
    }
    return canTerminalize(outcome, parsed)
      ? { kind: 'incompatible-committed', outcome }
      : { kind: 'invalid' };
  } catch {
    return { kind: 'invalid' };
  }
}

async function verifyRemoteReadback(
  store: CollaborativeVaultStore,
  parsed: ParsedMigration,
  outcome: DurableOperationOutcome | OperationDeduplicationTombstone,
): Promise<RemoteEvidence> {
  const candidate = parsed.journalInput.collaborativeCandidate;
  const expectedLink = parsed.journalInput.proofEntry.link;
  try {
    const observedCandidate = await store.getCollaborativeVault(
      candidate.databaseId,
      candidate.vaultId,
    );
    const observedRegistry = await store.getDatabaseDeviceRegistry(
      candidate.databaseId,
    );
    const observedByOperation =
      await store.getCollaborativeFinalizedMutationLinkByOperation(
        candidate.databaseId,
        candidate.vaultId,
        parsed.scope.operationId,
      );
    const observedByHead = await store.getCollaborativeFinalizedMutationLinkByHead(
      candidate.databaseId,
      candidate.vaultId,
      candidate.headDigest,
    );
    if (
      observedCandidate === null ||
      observedRegistry === null ||
      observedByOperation === null ||
      observedByHead === null ||
      !sameCanonical(observedCandidate, candidate) ||
      !sameCanonical(observedRegistry, parsed.journalInput.registryCandidate) ||
      !sameCanonical(observedByOperation, expectedLink) ||
      !sameCanonical(observedByHead, expectedLink)
    ) {
      return { kind: 'state-mismatch' };
    }
    return { kind: 'matching', outcome };
  } catch {
    return { kind: 'readback-unavailable' };
  }
}

async function readRemoteOutcome(
  store: CollaborativeVaultStore,
  parsed: ParsedMigration,
): Promise<RemoteOutcomeRead> {
  try {
    return {
      kind: 'available',
      outcome: await store.getCollaborativeOperationOutcome(
        parsed.scope.databaseId,
        parsed.scope.vaultId,
        parsed.scope.operationId,
      ),
    };
  } catch {
    return { kind: 'unavailable' };
  }
}

async function readJournal(
  path: string,
  secret: Uint8Array,
  scope: CollaborationMigrationJournalScope,
): Promise<
  | Readonly<{
      kind: 'available';
      record: CollaborationMigrationJournalRecord | null;
    }>
  | Readonly<{ kind: 'unavailable' }>
> {
  try {
    return {
      kind: 'available',
      record: await readCollaborationMigrationJournal(path, secret, {
        expectedScope: scope,
      }),
    };
  } catch {
    return { kind: 'unavailable' };
  }
}

async function readAnchor(
  path: string,
  secret: Uint8Array,
  scope: RecipientRollbackAnchorScope,
): Promise<
  | Readonly<{ kind: 'available'; anchor: RecipientRollbackAnchor }>
  | Readonly<{ kind: 'unavailable' }>
> {
  try {
    return {
      kind: 'available',
      anchor: await readRecipientRollbackAnchor(path, secret, {
        expectedScope: scope,
      }),
    };
  } catch {
    return { kind: 'unavailable' };
  }
}

async function readAuthorityAnchor(
  path: string,
  databaseRootKey: Uint8Array,
  scope: CollaborationAuthorityRollbackAnchorScope,
): Promise<
  | Readonly<{
      kind: 'available';
      anchor: CollaborationAuthorityRollbackAnchor;
    }>
  | Readonly<{ kind: 'unavailable' }>
> {
  try {
    return {
      kind: 'available',
      anchor: await readCollaborationAuthorityRollbackAnchor(path, databaseRootKey, {
        expectedScope: scope,
      }),
    };
  } catch {
    return { kind: 'unavailable' };
  }
}

function legacyAnchorMatchesSource(
  anchor: DatabaseRevisionAnchor,
  parsed: ParsedMigration,
): boolean {
  const source = parsed.journalInput.preparedMarker.legacySource;
  const vaultHead = Object.entries(anchor.vaultHeads).find(
    ([vaultId]) => vaultId === source.id,
  )?.[1];
  if (vaultHead === undefined) return false;
  return (
    anchor.databaseId === source.databaseId &&
    anchor.databaseRevision === source.databaseRevision &&
    vaultHead.revision === source.revision &&
    vaultHead.metadataDigest === source.payloadMetadataDigest
  );
}

function journalMatches(
  record: CollaborationMigrationJournalRecord,
  parsed: ParsedMigration,
): boolean {
  const expected = parsed.journalInput;
  return (
    record.databaseId === parsed.scope.databaseId &&
    record.vaultId === parsed.scope.vaultId &&
    record.principalId === parsed.scope.principalId &&
    record.deviceId === parsed.scope.deviceId &&
    record.operationId === parsed.scope.operationId &&
    record.requestDigest === parsed.scope.requestDigest &&
    sameCanonical(record.request, expected.request) &&
    sameCanonical(record.registryCandidate, expected.registryCandidate) &&
    sameCanonical(record.preparedMarker, expected.preparedMarker) &&
    sameCanonical(record.activeMarker, expected.activeMarker) &&
    sameCanonical(record.collaborativeCandidate, expected.collaborativeCandidate) &&
    sameCanonical(record.proofEntry, expected.proofEntry) &&
    sameCanonical(record.proposedOutcome, expected.proposedOutcome) &&
    sameCanonical(record.initialRecipientAnchor, expected.initialRecipientAnchor) &&
    sameCanonical(record.initialOwnerIdentity, expected.initialOwnerIdentity) &&
    sameCanonical(record.restartRecipient, expected.restartRecipient)
  );
}

function sameOutcomeIdentity(
  outcome: Readonly<{
    databaseId: string;
    vaultId: string;
    operationId: string;
    operationType: string;
  }>,
  parsed: ParsedMigration,
): boolean {
  return (
    outcome.databaseId === parsed.scope.databaseId &&
    outcome.vaultId === parsed.scope.vaultId &&
    outcome.operationId === parsed.scope.operationId &&
    outcome.operationType === 'genesis-migration'
  );
}

function canTerminalize(
  outcome: DurableOperationOutcome,
  parsed: ParsedMigration,
): boolean {
  const proposed = parsed.journalInput.proposedOutcome;
  return (
    outcome.state === 'committed' &&
    outcome.requestDigest === proposed.requestDigest &&
    outcome.actorPrincipalId === proposed.actorPrincipalId &&
    outcome.actorDeviceId === proposed.actorDeviceId &&
    outcome.priorHeadDigest === proposed.priorHeadDigest &&
    sameCanonical(outcome.priorTuple, proposed.priorTuple)
  );
}

function authorizationCoreFromManifest(
  manifest: CollaborativeMembershipManifest,
): ReturnType<typeof collaborationAuthorizationStateCoreSchema.parse> {
  return collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: manifest.protocolVersion,
    databaseId: manifest.databaseId,
    vaultId: manifest.vaultId,
    authorityEpoch: manifest.authorityEpoch,
    databaseDeviceGeneration: manifest.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: manifest.databaseDeviceRegistryDigest,
    membershipRevision: manifest.membershipRevision,
    policyRevision: manifest.policyRevision,
    keyEpoch: manifest.keyEpoch,
    memberships: manifest.memberships.map((membership) => ({
      membershipId: membership.membershipId,
      principalId: membership.principalId,
      principalFingerprint: membership.principalFingerprint,
      rootSigningPublicKey: membership.rootSigningPublicKey,
      identityGeneration: membership.identityGeneration,
      role: membership.role,
      state: membership.state,
      devices: membership.devices.map(deviceAuthorizationCore),
      createdAt: membership.createdAt,
      updatedAt: membership.updatedAt,
      ...(membership.removedAt === undefined
        ? {}
        : { removedAt: membership.removedAt }),
    })),
    ownerPrincipalIds: manifest.ownerPrincipalIds,
    keyEnvelopes: manifest.keyEnvelopes.map(envelopeAuthorizationCore),
    approvalPolicy: manifest.approvalPolicy,
  });
}

function deviceAuthorizationCore(device: DeviceCertificate): Record<string, unknown> {
  const core: Record<string, unknown> = { ...device };
  Reflect.deleteProperty(core, 'rootSignature');
  return core;
}

function envelopeAuthorizationCore(
  envelope: CollaborativeMembershipManifest['keyEnvelopes'][number],
): Record<string, unknown> {
  const core: Record<string, unknown> = { ...envelope };
  Reflect.deleteProperty(core, 'envelopeDigest');
  Reflect.deleteProperty(core, 'createdAt');
  Reflect.deleteProperty(core, 'ownerSignature');
  return core;
}

function classifyStoreRejection(
  primary: unknown,
  secondary?: unknown,
): CollaborationMigrationOrchestrationResult | undefined {
  for (const error of [primary, secondary]) {
    if (!(error instanceof EncryptedDatabaseStoreError)) continue;
    if (error.code === 'conflict' || error.code === 'exists') {
      return { status: 'retryable', reason: 'conflict' };
    }
    if (error.code === 'invalid') {
      return { status: 'retryable', reason: 'rejected' };
    }
  }
  return undefined;
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function required<T>(values: readonly T[]): T {
  if (values.length !== 1 || values[0] === undefined) {
    throw failure('invalid-input');
  }
  return values[0];
}

function copySecret(value: Uint8Array, exactBytes: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== exactBytes) {
    throw failure('invalid-input');
  }
  return Uint8Array.from(value);
}

function registryDeniesDevice(
  registry: CollaborationMigrationJournalCreateInput['registryCandidate'],
  device: DeviceCertificate,
): boolean {
  const signingFingerprint = computePublicKeyFingerprint(
    device.signingPublicKey,
    'ed25519',
  );
  const certificateFingerprint = computeDeviceCertificateFingerprint(device);
  return registry.deniedDevices.some(
    (denial) =>
      denial.deviceId === device.deviceId ||
      denial.signingKeyFingerprint === signingFingerprint ||
      denial.signingKeyFingerprint === certificateFingerprint,
  );
}

function assertPath(path: string): void {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\u0000')) {
    throw failure('invalid-input');
  }
}

function terminal(
  reason: Extract<
    CollaborationMigrationOrchestrationResult,
    { status: 'terminal' }
  >['reason'],
): StepResult {
  return { kind: 'result', result: { status: 'terminal', reason } };
}

function unknown(
  reason: Extract<
    CollaborationMigrationOrchestrationResult,
    { status: 'unknown' }
  >['reason'],
): StepResult {
  return { kind: 'result', result: { status: 'unknown', reason } };
}

function failure(
  kind: CollaborationMigrationOrchestrationFailureKind,
): CollaborationMigrationOrchestrationError {
  return new CollaborationMigrationOrchestrationError(kind);
}
