import { validateRevisionTransition } from '@kavrix/core';
import {
  COLLABORATION_DOMAINS,
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
  computeAadMetadataDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeAuthorizationStateDigest,
  computeDatabaseVaultPayloadMetadataDigest,
  computeAuthorizationTransitionDigest,
  computeDeviceCertificateFingerprint,
  computeDeviceRegistryDigest,
  computeDiscoveryRecordDigest,
  computeDiscoveryTag,
  computeEncryptedMembershipDigest,
  computeEncryptedPayloadDigest,
  computeFinalizedMutationLinkDigest,
  computeKeyEnvelopeDigest,
  computeKeyEnvelopeSetDigest,
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
  constantTimeEqual,
  decryptCollaborationEnvelope,
  decryptPayload,
  encryptCollaborationEnvelope,
  generateVaultRootKey,
  sealCollaborationVaultRootForDatabaseAuthority,
  sealVaultRootKeyForDevice,
  signAuthorityDelegation,
  signAuthorizationTransitionOwner,
  signCollaborationRecord,
  signDiscoveryRecord,
  signFinalizedMutationLink,
  signMigrationActiveMarker,
  signMigrationPreparedMarker,
  signMigrationRequestAuthority,
  signMigrationRequestOwner,
  signMutationReceipt,
  unwrapVaultRootForDatabase,
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
  zeroize,
  type DatabaseAuthoritySigningPrivateKey,
  type DatabaseRootKey,
  type DeviceSigningPrivateKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  readDatabaseRevisionAnchor,
  recipientRollbackAnchorFromCollaborativeVaultDocument,
  type RecipientRollbackAnchorScope,
} from '@kavrix/key-files';
import {
  COLLABORATION_PROTOCOL_VERSION,
  COLLABORATIVE_AUTHORIZATION_TRANSITION_FORMAT,
  COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
  COLLABORATIVE_AUTHORITY_DELEGATION_FORMAT,
  COLLABORATIVE_DISCOVERY_RECORD_FORMAT,
  COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
  COLLABORATIVE_KEY_ENVELOPE_FORMAT,
  COLLABORATIVE_MEMBERSHIP_MANIFEST_FORMAT,
  COLLABORATIVE_MIGRATION_MARKER_FORMAT,
  COLLABORATIVE_MUTATION_RECEIPT_FORMAT,
  COLLABORATIVE_OPERATION_OUTCOME_FORMAT,
  COLLABORATIVE_VAULT_FORMAT,
  MAX_CIPHERTEXT_CHARS,
  associatedDataSchema,
  MAX_COLLABORATIVE_OPERATION_EXPIRY_SECONDS,
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationAuthorityDelegationSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMembershipSchema,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationMutationCommitmentSchema,
  collaborationMutationProofEntrySchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAssociatedDataSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  databaseVaultPayloadSchema,
  databaseVaultDocumentSchema,
  deviceCertificateSchema,
  durableOperationOutcomeSchema,
  membershipHistoryEventSchema,
  membershipHistorySchema,
  publicIdentityExportSchema,
  recipientRollbackAnchorSchema,
  timestampSchema,
  type CollaborationAuthorizationStateCore,
  type CollaborationAuthorizationTransition,
  type CollaborationAuthorityDelegation,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationDiscoveryRecord,
  type CollaborationFinalizedMutationLink,
  type CollaborationKeyEnvelope,
  type CollaborationMembership,
  type CollaborationMigrationActiveMarker,
  type CollaborationMigrationPreparedMarker,
  type CollaborationMigrationRequest,
  type CollaborationMutationCommitment,
  type CollaborationMutationProof,
  type CollaborationPolicyState,
  type CollaborationRevisionTuple,
  type CollaborationAeadEnvelope,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DatabaseAuthorityRecoveryEnvelope,
  type DatabaseVaultDocument,
  type DeviceCertificate,
  type DurableOperationOutcome,
  type PublicIdentityExport,
  type RecipientRollbackAnchor,
  type Sha256Digest,
  type Timestamp,
} from '@kavrix/schemas';

import {
  requireDatabaseAuthorityRecoveryEnvelope,
  requireExactDatabaseAuthorityRecoveryEnvelope,
} from './collaboration-recovery-envelope-binding.js';

const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');
const SAFE_MESSAGE = 'Collaborative genesis preparation failed.';
const MAX_DATABASE_VAULT_PAYLOAD_BYTES = Math.floor((MAX_CIPHERTEXT_CHARS * 3) / 4);

export type CollaborationGenesisRandomness = Readonly<{
  /** Test seam only. Production callers must omit this provider. */
  generateVaultRootKey(): Uint8Array;
}>;

export type BuildCollaborativeGenesisInput = Readonly<{
  legacySource: DatabaseVaultDocument;
  legacyDatabaseRevisionAnchorPath: string;
  databaseRootKey: DatabaseRootKey | Uint8Array;
  registryCandidate: CollaborationDatabaseDeviceRegistry;
  initialOwnerIdentity: PublicIdentityExport;
  initialOwnerDeviceId: DeviceCertificate['deviceId'];
  initialMembershipId: CollaborationMembership['membershipId'];
  ownerDeviceSigningPrivateKey: DeviceSigningPrivateKey | Uint8Array;
  authoritySigningPrivateKey: DatabaseAuthoritySigningPrivateKey | Uint8Array;
  authoritySigningPublicKey: string;
  authoritySigningKeyFingerprint: Sha256Digest;
  authorityRecoveryPublicKey: string;
  authorityRecoveryKeyFingerprint: Sha256Digest;
  authorityEpoch: CollaborationRevisionTuple['authorityEpoch'];
  operationId: CollaborationMutationCommitment['operationId'];
  requestedAt: Timestamp;
  preparedAt: Timestamp;
  activatedAt: Timestamp;
  transitionExpiresAt: Timestamp;
  anchorScope: RecipientRollbackAnchorScope;
  randomness?: CollaborationGenesisRandomness;
}>;

export type PreparedCollaborativeGenesis = Readonly<{
  request: CollaborationMigrationRequest;
  preparedMarker: CollaborationMigrationPreparedMarker;
  registryCandidate: CollaborationDatabaseDeviceRegistry;
  candidate: CollaborativeVaultDocument;
  initialManifest: CollaborativeMembershipManifest;
  /** Authenticated public trust root retained for crash-safe migration resume. */
  initialOwnerIdentity: PublicIdentityExport;
  proofEntry: CollaborationMutationProof['entries'][number];
  proposedOutcome: DurableOperationOutcome;
  candidateAnchor: RecipientRollbackAnchor;
  activeMarker: CollaborationMigrationActiveMarker;
  /** A disposable copy owned exclusively by the caller. */
  vaultRootKey: VaultRootKey;
}>;

export class CollaborationGenesisPreparationError extends Error {
  readonly safe = true;

  constructor() {
    super(SAFE_MESSAGE);
    this.name = 'CollaborationGenesisPreparationError';
  }
}

type ParsedInput = Readonly<{
  legacySource: DatabaseVaultDocument;
  payload: Uint8Array;
  registry: CollaborationDatabaseDeviceRegistry;
  identity: PublicIdentityExport;
  writer: DeviceCertificate;
  ownerPrivateKey: Uint8Array;
  authorityPrivateKey: Uint8Array;
  authoritySigningPublicKey: string;
  authoritySigningFingerprint: Sha256Digest;
  authorityRecoveryPublicKey: string;
  authorityRecoveryFingerprint: Sha256Digest;
  authorityEpoch: CollaborationRevisionTuple['authorityEpoch'];
  operationId: CollaborationMutationCommitment['operationId'];
  membershipId: CollaborationMembership['membershipId'];
  requestedAt: Timestamp;
  preparedAt: Timestamp;
  activatedAt: Timestamp;
  expiresAt: Timestamp;
  anchorScope: RecipientRollbackAnchorScope;
  randomness?: CollaborationGenesisRandomness;
}>;

type EncryptedGenesisState = Readonly<{
  encryptedPayload: CollaborationAeadEnvelope;
  encryptedMembershipManifest: CollaborationAeadEnvelope;
  encryptedPayloadDigest: Sha256Digest;
  encryptedMembershipDigest: Sha256Digest;
}>;

type MigrationMarkerBase = Omit<
  CollaborationMigrationActiveMarker,
  'state' | 'outcomeDigest' | 'activatedAt'
>;

/** Build one complete immutable genesis bundle without file or store access. */
export async function buildCollaborativeGenesis(
  input: BuildCollaborativeGenesisInput,
): Promise<PreparedCollaborativeGenesis> {
  let parsed: ParsedInput | undefined;
  let generatedKey: Uint8Array | undefined;
  let vaultRootKey: Uint8Array | undefined;
  let returnedVaultRootKey: VaultRootKey | undefined;
  try {
    parsed = await parseAndAuthenticateInput(input);
    const request = await buildMigrationRequest(parsed);

    generatedKey = parsed.randomness?.generateVaultRootKey() ?? generateVaultRootKey();
    vaultRootKey = copySecret(generatedKey, 32);
    zeroize(generatedKey);
    generatedKey = undefined;

    const owner = buildOwnerMembership(parsed);
    const tupleBase = genesisTupleBase({
      authorityEpoch: parsed.authorityEpoch,
      databaseDeviceGeneration: parsed.registry.generation,
      databaseDeviceRegistryDigest: parsed.registry.registryDigest,
    });
    const keyEnvelopes = await buildGenesisKeyEnvelopes(
      parsed,
      owner,
      tupleBase,
      vaultRootKey,
    );
    const authorizationCore = authorizationCoreOf(
      parsed,
      owner,
      tupleBase,
      keyEnvelopes,
    );
    const authorizationStateDigest = computeAuthorizationStateDigest(authorizationCore);
    const tuple = collaborationRevisionTupleSchema.parse({
      ...tupleBase,
      authorizationStateDigest,
    });
    const priorTuple = genesisPriorTuple(parsed);
    const policy = await buildGenesisPolicy(parsed, tuple);
    const history = await buildGenesisHistory(parsed, priorTuple, tuple);
    const manifest = buildGenesisManifest(
      parsed,
      owner,
      tuple,
      keyEnvelopes,
      policy,
      history,
    );
    const encrypted = await encryptGenesisState(parsed, tuple, manifest, vaultRootKey);
    const discoveryRecords = await buildGenesisDiscoveryRecords(
      parsed,
      owner,
      encrypted.encryptedMembershipDigest,
      keyEnvelopes,
    );
    const transition = await buildGenesisTransition(parsed, priorTuple, tuple);
    const revision = validateRevisionTransition({
      operationType: 'genesis-migration',
      prior: priorTuple,
      next: tuple,
      authorizationTransitionDigest: transition.transitionDigest,
    });
    if (!revision.valid) fail();
    const commitment = collaborationMutationCommitmentSchema.parse({
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: parsed.legacySource.databaseId,
      vaultId: parsed.legacySource.id,
      operationId: parsed.operationId,
      operationType: 'genesis-migration',
      requestDigest: request.requestDigest,
      previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
      previousAuthorizationStateDigest:
        COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
      authorizationStateDigest,
      authorizationTransitionDigest: transition.transitionDigest,
      previousAuthorityEpoch: parsed.authorityEpoch,
      previousDocumentRevision: 0,
      previousMembershipRevision: 0,
      previousPolicyRevision: 0,
      previousKeyEpoch: 1,
      previousDatabaseDeviceGeneration: parsed.registry.generation,
      previousDatabaseDeviceRegistryDigest: parsed.registry.registryDigest,
      authorityEpoch: tuple.authorityEpoch,
      documentRevision: tuple.documentRevision,
      membershipRevision: tuple.membershipRevision,
      policyRevision: tuple.policyRevision,
      keyEpoch: tuple.keyEpoch,
      databaseDeviceGeneration: tuple.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
      encryptedPayloadDigest: encrypted.encryptedPayloadDigest,
      encryptedMembershipDigest: encrypted.encryptedMembershipDigest,
      encryptedEnvelopesDigest: computeKeyEnvelopeSetDigest(keyEnvelopes),
      policyDigest: policy.policyDigest,
      writerPrincipalId: owner.principalId,
      writerDeviceId: parsed.writer.deviceId,
      timestamp: parsed.preparedAt,
      expiresAt: parsed.expiresAt,
    });
    const headDigest = computeMutationHead(commitment);
    const delegation = await buildGenesisDelegation(parsed, owner, tuple, headDigest);
    const authorityDelegationDigest = computeAuthorityDelegationDigest(delegation);
    const link = await buildGenesisLink(
      parsed,
      commitment,
      transition,
      headDigest,
      authorityDelegationDigest,
    );
    const finalizedMutationLinkDigest = computeFinalizedMutationLinkDigest(link);
    const candidate = collaborativeVaultDocumentSchema.parse({
      format: COLLABORATIVE_VAULT_FORMAT,
      documentVersion: 1,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: parsed.legacySource.databaseId,
      vaultId: parsed.legacySource.id,
      authorityEpoch: tuple.authorityEpoch,
      databaseDeviceGeneration: tuple.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
      documentRevision: tuple.documentRevision,
      membershipRevision: tuple.membershipRevision,
      policyRevision: tuple.policyRevision,
      keyEpoch: tuple.keyEpoch,
      previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
      headDigest,
      authorityDelegation: delegation,
      authorityDelegationDigest,
      authorizationStateDigest,
      encryptedPayloadDigest: encrypted.encryptedPayloadDigest,
      encryptedMembershipDigest: encrypted.encryptedMembershipDigest,
      encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
      policyDigest: policy.policyDigest,
      databaseAuthorityRecoveryEnvelope:
        requireDatabaseAuthorityRecoveryEnvelope(manifest),
      encryptedPayload: encrypted.encryptedPayload,
      encryptedMembershipManifest: encrypted.encryptedMembershipManifest,
      discoveryRecords,
      currentMutationLink: link,
      createdAt: parsed.requestedAt,
      updatedAt: parsed.preparedAt,
    });
    const proofEntry = collaborationMutationProofEntrySchema.parse({
      link,
      authorizationWitness: {
        format: COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
        protocolVersion: COLLABORATION_PROTOCOL_VERSION,
        databaseId: candidate.databaseId,
        vaultId: candidate.vaultId,
        authorityDelegationDigest,
        tuple,
        previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
        headDigest,
        encryptedMembershipDigest: encrypted.encryptedMembershipDigest,
        encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
        policyDigest: policy.policyDigest,
        databaseDeviceRegistry: parsed.registry,
        databaseAuthorityRecoveryEnvelope:
          requireDatabaseAuthorityRecoveryEnvelope(manifest),
        encryptedMembershipManifest: encrypted.encryptedMembershipManifest,
        discoveryRecords,
        finalizedMutationLinkDigest,
      },
    });
    const outcome = await buildGenesisOutcome(
      parsed,
      request.requestDigest,
      priorTuple,
      tuple,
      headDigest,
      finalizedMutationLinkDigest,
    );
    const candidateAnchor = recipientRollbackAnchorSchema.parse(
      recipientRollbackAnchorFromCollaborativeVaultDocument(
        candidate,
        parsed.anchorScope,
        {
          membershipDigest: computeMembershipStateDigest(authorizationCore),
          policyDigest: computePolicyStateDigest(policy),
          finalizedMutationLinkDigest,
          updatedAt: candidate.updatedAt,
        },
      ),
    );
    const preparedMarker = await buildPreparedMarker(
      parsed,
      request.requestDigest,
      headDigest,
    );
    const activeMarker = await buildActiveMarker(
      parsed,
      request.requestDigest,
      headDigest,
      outcome.outcomeDigest,
    );

    await verifyCompleteBundle({
      parsed,
      request,
      candidate,
      manifest,
      proofEntry,
      outcome,
      candidateAnchor,
      preparedMarker,
      activeMarker,
      vaultRootKey,
    });

    returnedVaultRootKey = copySecret(vaultRootKey, 32) as VaultRootKey;
    return freezePrepared({
      request,
      preparedMarker,
      registryCandidate: parsed.registry,
      candidate,
      initialManifest: manifest,
      initialOwnerIdentity: parsed.identity,
      proofEntry,
      proposedOutcome: outcome,
      candidateAnchor,
      activeMarker,
      vaultRootKey: returnedVaultRootKey,
    });
  } catch {
    zeroize(returnedVaultRootKey);
    throw new CollaborationGenesisPreparationError();
  } finally {
    zeroize(generatedKey);
    zeroize(vaultRootKey);
    wipeParsed(parsed);
  }
}

async function parseAndAuthenticateInput(
  input: BuildCollaborativeGenesisInput,
): Promise<ParsedInput> {
  let databaseRootKey: DatabaseRootKey | undefined;
  let legacyVaultRootKey: Uint8Array | undefined;
  let payload: Uint8Array | undefined;
  let ownerPrivateKey: Uint8Array | undefined;
  let authorityPrivateKey: Uint8Array | undefined;
  try {
    const legacySource = databaseVaultDocumentSchema.parse(input.legacySource);
    const registry = collaborationDatabaseDeviceRegistrySchema.parse(
      input.registryCandidate,
    );
    const identity = publicIdentityExportSchema.parse(input.initialOwnerIdentity);
    const requestedAt = timestampSchema.parse(input.requestedAt);
    const preparedAt = timestampSchema.parse(input.preparedAt);
    const activatedAt = timestampSchema.parse(input.activatedAt);
    const expiresAt = timestampSchema.parse(input.transitionExpiresAt);
    ownerPrivateKey = copySecret(input.ownerDeviceSigningPrivateKey, 64);
    authorityPrivateKey = copySecret(input.authoritySigningPrivateKey, 64);
    const operationId = collaborationMutationCommitmentSchema.shape.operationId.parse(
      input.operationId,
    );
    const membershipId = collaborationMembershipSchema.shape.membershipId.parse(
      input.initialMembershipId,
    );
    const authorityEpoch = collaborationRevisionTupleSchema.shape.authorityEpoch.parse(
      input.authorityEpoch,
    );
    const signingPublicKey =
      collaborationAuthorityDelegationSchema.shape.authoritySigningPublicKey.parse(
        input.authoritySigningPublicKey,
      );
    const recoveryPublicKey =
      collaborationAuthorityDelegationSchema.shape.authorityRecoveryPublicKey.parse(
        input.authorityRecoveryPublicKey,
      );
    const signingFingerprint =
      collaborationAuthorityDelegationSchema.shape.authoritySigningKeyFingerprint.parse(
        input.authoritySigningKeyFingerprint,
      );
    const recoveryFingerprint =
      collaborationAuthorityDelegationSchema.shape.authorityRecoveryKeyFingerprint.parse(
        input.authorityRecoveryKeyFingerprint,
      );
    const anchorScope = parseAnchorScope(input.anchorScope);
    const writer = requireUnique(
      identity.devices.filter(
        (device) => device.deviceId === input.initialOwnerDeviceId,
      ),
    );
    const requested = Date.parse(requestedAt);
    const prepared = Date.parse(preparedAt);
    const activated = Date.parse(activatedAt);
    const expiry = Date.parse(expiresAt);
    if (
      Date.parse(legacySource.createdAt) > Date.parse(legacySource.updatedAt) ||
      Date.parse(legacySource.updatedAt) > requested ||
      requested > prepared ||
      prepared > activated ||
      activated >= expiry ||
      (expiry - prepared) / 1_000 > MAX_COLLABORATIVE_OPERATION_EXPIRY_SECONDS ||
      Date.parse(identity.createdAt) > requested ||
      (identity.expiresAt !== undefined &&
        activated >= Date.parse(identity.expiresAt)) ||
      Date.parse(registry.updatedAt) > requested ||
      registry.databaseId !== legacySource.databaseId ||
      registry.authorityEpoch !== authorityEpoch ||
      registry.authorityFingerprint !== signingFingerprint ||
      signingPublicKey === recoveryPublicKey ||
      computePublicKeyFingerprint(signingPublicKey, 'ed25519') !== signingFingerprint ||
      computePublicKeyFingerprint(recoveryPublicKey, 'x25519') !==
        recoveryFingerprint ||
      computeDeviceRegistryDigest(registry) !== registry.registryDigest ||
      anchorScope.databaseId !== legacySource.databaseId ||
      anchorScope.vaultId !== legacySource.id ||
      anchorScope.principalId !== identity.principalId ||
      anchorScope.deviceId !== writer.deviceId
    ) {
      fail();
    }
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.deviceRegistrySignature,
        registry,
        collaborationDatabaseDeviceRegistrySchema,
        'authoritySignature',
        signingPublicKey,
      )) ||
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.publicIdentitySignature,
        identity,
        publicIdentityExportSchema,
        'selfSignature',
        identity.rootSigningPublicKey,
      ))
    ) {
      fail();
    }
    for (const device of identity.devices) {
      if (
        !(await verifyCollaborationRecord(
          COLLABORATION_DOMAINS.deviceCertificateSignature,
          device,
          deviceCertificateSchema,
          'rootSignature',
          identity.rootSigningPublicKey,
        )) ||
        (device.state === 'active' &&
          !deviceUsableThrough(device, requestedAt, activatedAt))
      ) {
        fail();
      }
      if (device.state === 'active' && registryDeniesDevice(registry, device)) fail();
    }
    if (
      writer.state !== 'active' ||
      !deviceUsableThrough(writer, requestedAt, activatedAt)
    ) {
      fail();
    }
    computeLegacySourceDigest(legacySource);
    try {
      if (
        typeof input.legacyDatabaseRevisionAnchorPath !== 'string' ||
        input.legacyDatabaseRevisionAnchorPath.length === 0
      ) {
        fail();
      }
      databaseRootKey = copySecret(input.databaseRootKey, 32) as DatabaseRootKey;
      const trustedLegacyAnchor = await readDatabaseRevisionAnchor(
        input.legacyDatabaseRevisionAnchorPath,
        databaseRootKey,
      );
      const trustedVaultHead = trustedLegacyAnchor.vaultHeads[legacySource.id];
      if (
        trustedLegacyAnchor.databaseId !== legacySource.databaseId ||
        trustedLegacyAnchor.databaseRevision !== legacySource.databaseRevision ||
        trustedVaultHead?.revision !== legacySource.revision ||
        trustedVaultHead.metadataDigest !== legacySource.payloadMetadataDigest
      ) {
        fail();
      }
      legacyVaultRootKey = await unwrapVaultRootForDatabase(
        legacySource.wrappedVaultRoot,
        databaseRootKey,
        databaseAssociatedDataSchema.parse({
          version: 1,
          databaseId: legacySource.databaseId,
          vaultId: legacySource.id,
          entityType: 'wrapped-vault-root',
          entityId: legacySource.id,
          purpose: 'vault-root',
          schemaVersion: legacySource.schemaVersion,
          keyVersion: legacySource.currentKeyVersion,
          revision: legacySource.databaseRevision,
          metadataDigest: legacySource.payloadMetadataDigest,
        }),
      );
      payload = await decryptPayload(
        legacySource.encryptedPayload,
        legacyVaultRootKey,
        associatedDataSchema.parse({
          version: 1,
          vaultId: legacySource.id,
          entityType: 'vault-preferences',
          entityId: legacySource.id,
          purpose: 'vault-preferences',
          schemaVersion: legacySource.schemaVersion,
          keyVersion: legacySource.currentKeyVersion,
          revision: legacySource.revision,
          metadataDigest: legacySource.payloadMetadataDigest,
        }),
      );
      if (payload.byteLength > MAX_DATABASE_VAULT_PAYLOAD_BYTES) fail();
      const parsedPayload = databaseVaultPayloadSchema.parse(
        JSON.parse(
          new TextDecoder('utf-8', { fatal: true }).decode(payload),
        ) as unknown,
      );
      if ('vaultId' in parsedPayload && parsedPayload.vaultId !== legacySource.id) {
        fail();
      }
      if (
        computeDatabaseVaultPayloadMetadataDigest(
          legacySource,
          legacyVaultRootKey,
          payload,
        ) !== legacySource.payloadMetadataDigest
      ) {
        fail();
      }
    } finally {
      zeroize(databaseRootKey);
      databaseRootKey = undefined;
      zeroize(legacyVaultRootKey);
      legacyVaultRootKey = undefined;
    }
    return {
      legacySource,
      payload,
      registry,
      identity,
      writer,
      ownerPrivateKey,
      authorityPrivateKey,
      authoritySigningPublicKey: signingPublicKey,
      authoritySigningFingerprint: signingFingerprint,
      authorityRecoveryPublicKey: recoveryPublicKey,
      authorityRecoveryFingerprint: recoveryFingerprint,
      authorityEpoch,
      operationId,
      membershipId,
      requestedAt,
      preparedAt,
      activatedAt,
      expiresAt,
      anchorScope,
      ...(input.randomness === undefined ? {} : { randomness: input.randomness }),
    };
  } catch {
    zeroize(payload);
    zeroize(ownerPrivateKey);
    zeroize(authorityPrivateKey);
    fail();
  } finally {
    zeroize(databaseRootKey);
    zeroize(legacyVaultRootKey);
  }
}

async function buildMigrationRequest(
  parsed: ParsedInput,
): Promise<CollaborationMigrationRequest> {
  const base = collaborationMigrationRequestSchema.parse({
    format: 'kavrix-collaborative-migration-request',
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    operationType: 'genesis-migration',
    operationId: parsed.operationId,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    legacyVaultRevision: parsed.legacySource.revision,
    legacySourceDigest: computeLegacySourceDigest(parsed.legacySource),
    authorityEpoch: parsed.authorityEpoch,
    authorityFingerprint: parsed.authoritySigningFingerprint,
    databaseDeviceGeneration: parsed.registry.generation,
    databaseDeviceRegistryDigest: parsed.registry.registryDigest,
    initialOwnerPrincipalId: parsed.identity.principalId,
    initialOwnerDeviceId: parsed.writer.deviceId,
    initialMembershipId: parsed.membershipId,
    requestedAt: parsed.requestedAt,
    requestDigest: PLACEHOLDER_DIGEST,
    authoritySignature: PLACEHOLDER_SIGNATURE,
    ownerSignature: PLACEHOLDER_SIGNATURE,
  });
  const withDigest = collaborationMigrationRequestSchema.parse({
    ...base,
    requestDigest: computeMigrationRequestDigest(base),
  });
  const authoritySignature = await signMigrationRequestAuthority(
    withDigest,
    parsed.authorityPrivateKey,
  );
  const ownerSignature = await signMigrationRequestOwner(
    withDigest,
    parsed.ownerPrivateKey,
  );
  const request = collaborationMigrationRequestSchema.parse({
    ...withDigest,
    authoritySignature,
    ownerSignature,
  });
  if (
    !(await verifyMigrationRequestAuthority(
      request,
      parsed.authoritySigningPublicKey,
    )) ||
    !(await verifyMigrationRequestOwner(request, parsed.writer.signingPublicKey))
  ) {
    fail();
  }
  return request;
}

function buildOwnerMembership(parsed: ParsedInput): CollaborationMembership {
  return collaborationMembershipSchema.parse({
    membershipId: parsed.membershipId,
    principalId: parsed.identity.principalId,
    principalFingerprint: computePublicKeyFingerprint(
      parsed.identity.rootSigningPublicKey,
      'ed25519',
    ),
    rootSigningPublicKey: parsed.identity.rootSigningPublicKey,
    identityGeneration: parsed.identity.identityGeneration,
    role: 'owner',
    state: 'active',
    devices: parsed.identity.devices,
    createdAt: parsed.requestedAt,
    updatedAt: parsed.preparedAt,
  });
}

async function buildGenesisKeyEnvelopes(
  parsed: ParsedInput,
  owner: CollaborationMembership,
  tuple: Omit<CollaborationRevisionTuple, 'authorizationStateDigest'>,
  vaultRootKey: Uint8Array,
): Promise<readonly (CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope)[]> {
  const envelopes: (CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope)[] =
    [];
  for (const device of owner.devices) {
    if (device.state !== 'active') continue;
    const unsigned = collaborationKeyEnvelopeSchema.parse({
      format: COLLABORATIVE_KEY_ENVELOPE_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      algorithm: 'x25519-sealed-box',
      databaseId: parsed.legacySource.databaseId,
      vaultId: parsed.legacySource.id,
      authorityEpoch: tuple.authorityEpoch,
      membershipId: owner.membershipId,
      principalId: owner.principalId,
      deviceId: device.deviceId,
      recipientEncryptionKeyFingerprint: computePublicKeyFingerprint(
        device.encryptionPublicKey,
        'x25519',
      ),
      keyEpoch: tuple.keyEpoch,
      membershipRevision: tuple.membershipRevision,
      databaseDeviceGeneration: tuple.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
      sealedVaultRootKey: await sealVaultRootKeyForDevice(
        vaultRootKey,
        device.encryptionPublicKey,
      ),
      envelopeDigest: PLACEHOLDER_DIGEST,
      createdAt: parsed.preparedAt,
      ownerSignature: PLACEHOLDER_SIGNATURE,
    });
    const withDigest = collaborationKeyEnvelopeSchema.parse({
      ...unsigned,
      envelopeDigest: computeKeyEnvelopeDigest(unsigned),
    });
    const envelope = collaborationKeyEnvelopeSchema.parse({
      ...withDigest,
      ownerSignature: await signCollaborationRecord(
        COLLABORATION_DOMAINS.keyEnvelopeSignature,
        withDigest,
        collaborationKeyEnvelopeSchema,
        'ownerSignature',
        parsed.ownerPrivateKey,
      ),
    });
    envelopes.push(envelope);
  }
  const recoveryUnsigned = databaseAuthorityRecoveryEnvelopeSchema.parse({
    format: 'kavrix-collaborative-authority-recovery-envelope',
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    algorithm: 'x25519-sealed-box',
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    authorityEpoch: tuple.authorityEpoch,
    authorityRecoveryKeyFingerprint: parsed.authorityRecoveryFingerprint,
    keyEpoch: tuple.keyEpoch,
    membershipRevision: tuple.membershipRevision,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    sealedVaultRootKey: await sealCollaborationVaultRootForDatabaseAuthority(
      vaultRootKey,
      parsed.authorityRecoveryPublicKey,
    ),
    envelopeDigest: PLACEHOLDER_DIGEST,
    sealedByPrincipalId: owner.principalId,
    sealedByDeviceId: parsed.writer.deviceId,
    createdAt: parsed.preparedAt,
    ownerSignature: PLACEHOLDER_SIGNATURE,
  });
  const recoveryWithDigest = databaseAuthorityRecoveryEnvelopeSchema.parse({
    ...recoveryUnsigned,
    envelopeDigest: computeAuthorityRecoveryEnvelopeDigest(recoveryUnsigned),
  });
  envelopes.push(
    databaseAuthorityRecoveryEnvelopeSchema.parse({
      ...recoveryWithDigest,
      ownerSignature: await signCollaborationRecord(
        COLLABORATION_DOMAINS.keyEnvelopeSignature,
        recoveryWithDigest,
        databaseAuthorityRecoveryEnvelopeSchema,
        'ownerSignature',
        parsed.ownerPrivateKey,
      ),
    }),
  );
  return envelopes;
}

function authorizationCoreOf(
  parsed: ParsedInput,
  owner: CollaborationMembership,
  tuple: Omit<CollaborationRevisionTuple, 'authorizationStateDigest'>,
  keyEnvelopes: readonly (
    CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope
  )[],
): CollaborationAuthorizationStateCore {
  return collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    memberships: [
      {
        membershipId: owner.membershipId,
        principalId: owner.principalId,
        principalFingerprint: owner.principalFingerprint,
        rootSigningPublicKey: owner.rootSigningPublicKey,
        identityGeneration: owner.identityGeneration,
        role: owner.role,
        state: owner.state,
        devices: owner.devices.map(deviceAuthorizationCore),
        createdAt: owner.createdAt,
        updatedAt: owner.updatedAt,
      },
    ],
    ownerPrincipalIds: [owner.principalId],
    keyEnvelopes: keyEnvelopes.map(envelopeAuthorizationCore),
    approvalPolicy: 'none',
  });
}

async function buildGenesisPolicy(
  parsed: ParsedInput,
  tuple: CollaborationRevisionTuple,
): Promise<CollaborationPolicyState> {
  const unsigned = collaborationPolicyStateSchema.parse({
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    authorityEpoch: tuple.authorityEpoch,
    policyRevision: tuple.policyRevision,
    approvalPolicy: 'none',
    policyDigest: PLACEHOLDER_DIGEST,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    changedByPrincipalId: parsed.identity.principalId,
    changedByDeviceId: parsed.writer.deviceId,
    changedAt: parsed.preparedAt,
    signature: PLACEHOLDER_SIGNATURE,
  });
  const withDigest = collaborationPolicyStateSchema.parse({
    ...unsigned,
    policyDigest: computePolicyDigest(unsigned),
  });
  return collaborationPolicyStateSchema.parse({
    ...withDigest,
    signature: await signCollaborationRecord(
      COLLABORATION_DOMAINS.policySignature,
      withDigest,
      collaborationPolicyStateSchema,
      'signature',
      parsed.ownerPrivateKey,
    ),
  });
}

async function buildGenesisHistory(
  parsed: ParsedInput,
  priorTuple: CollaborationRevisionTuple,
  tuple: CollaborationRevisionTuple,
): Promise<CollaborativeMembershipManifest['history']> {
  const eventInput = membershipHistoryEventSchema.parse({
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    operationId: parsed.operationId,
    eventType: 'genesis-created',
    actorPrincipalId: parsed.identity.principalId,
    actorDeviceId: parsed.writer.deviceId,
    previousDocumentRevision: priorTuple.documentRevision,
    newDocumentRevision: tuple.documentRevision,
    previousMembershipRevision: priorTuple.membershipRevision,
    newMembershipRevision: tuple.membershipRevision,
    previousPolicyRevision: priorTuple.policyRevision,
    newPolicyRevision: tuple.policyRevision,
    previousKeyEpoch: priorTuple.keyEpoch,
    newKeyEpoch: tuple.keyEpoch,
    previousAuthorityEpoch: priorTuple.authorityEpoch,
    newAuthorityEpoch: tuple.authorityEpoch,
    previousDatabaseDeviceGeneration: priorTuple.databaseDeviceGeneration,
    newDatabaseDeviceGeneration: tuple.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: priorTuple.databaseDeviceRegistryDigest,
    newDatabaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    previousAuthorizationStateDigest: priorTuple.authorizationStateDigest,
    newAuthorizationStateDigest: tuple.authorizationStateDigest,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    timestamp: parsed.preparedAt,
    signature: PLACEHOLDER_SIGNATURE,
  });
  const event = membershipHistoryEventSchema.parse({
    ...eventInput,
    signature: await signCollaborationRecord(
      COLLABORATION_DOMAINS.membershipHistorySignature,
      eventInput,
      membershipHistoryEventSchema,
      'signature',
      parsed.ownerPrivateKey,
    ),
  });
  const historyInput = {
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    events: [event],
    checkpoints: [],
    compactedThroughRevision: 0,
    compactedHistoryDigest: COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousHistoryDigest: COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
    currentHistoryDigest: PLACEHOLDER_DIGEST,
  } as const;
  return membershipHistorySchema.parse({
    ...historyInput,
    currentHistoryDigest: computeMembershipHistoryDigest(historyInput),
  });
}

function buildGenesisManifest(
  parsed: ParsedInput,
  owner: CollaborationMembership,
  tuple: CollaborationRevisionTuple,
  keyEnvelopes: readonly (
    CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope
  )[],
  policy: CollaborationPolicyState,
  history: CollaborativeMembershipManifest['history'],
): CollaborativeMembershipManifest {
  const input = collaborativeMembershipManifestSchema.parse({
    format: COLLABORATIVE_MEMBERSHIP_MANIFEST_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    authorizationStateDigest: tuple.authorizationStateDigest,
    memberships: [owner],
    ownerPrincipalIds: [owner.principalId],
    keyEnvelopes,
    approvalPolicy: 'none',
    policy,
    pendingApprovals: [],
    pendingTransfers: [],
    history,
    previousMembershipDigest: COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
    membershipDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    createdAt: parsed.requestedAt,
    updatedAt: parsed.preparedAt,
  });
  return collaborativeMembershipManifestSchema.parse({
    ...input,
    membershipDigest: computeMembershipManifestDigest(input),
  });
}

async function encryptGenesisState(
  parsed: ParsedInput,
  tuple: CollaborationRevisionTuple,
  manifest: CollaborativeMembershipManifest,
  vaultRootKey: Uint8Array,
): Promise<EncryptedGenesisState> {
  let manifestBytes: Uint8Array | undefined;
  try {
    const encryptedPayload = await encryptCollaborationEnvelope(
      parsed.payload,
      vaultRootKey,
      aadFor(parsed, tuple, 'vault-payload'),
    );
    manifestBytes = Buffer.from(canonicalJson(manifest), 'utf8');
    const encryptedMembershipManifest = await encryptCollaborationEnvelope(
      manifestBytes,
      vaultRootKey,
      aadFor(parsed, tuple, 'membership-manifest'),
    );
    return {
      encryptedPayload,
      encryptedMembershipManifest,
      encryptedPayloadDigest: computeEncryptedPayloadDigest(encryptedPayload),
      encryptedMembershipDigest: computeEncryptedMembershipDigest(
        encryptedMembershipManifest,
      ),
    };
  } finally {
    zeroize(manifestBytes);
  }
}

async function buildGenesisDiscoveryRecords(
  parsed: ParsedInput,
  owner: CollaborationMembership,
  encryptedMembershipDigest: Sha256Digest,
  keyEnvelopes: readonly (
    CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope
  )[],
): Promise<readonly CollaborationDiscoveryRecord[]> {
  const records: CollaborationDiscoveryRecord[] = [];
  for (const envelope of keyEnvelopes) {
    if (!('membershipId' in envelope)) continue;
    const unsigned = collaborationDiscoveryRecordSchema.parse({
      format: COLLABORATIVE_DISCOVERY_RECORD_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: parsed.legacySource.databaseId,
      vaultId: parsed.legacySource.id,
      authorityEpoch: parsed.authorityEpoch,
      databaseDeviceGeneration: parsed.registry.generation,
      databaseDeviceRegistryDigest: parsed.registry.registryDigest,
      discoveryTag: computeDiscoveryTag(
        parsed.legacySource.databaseId,
        owner.principalFingerprint,
      ),
      membershipId: owner.membershipId,
      membershipState: 'active',
      keyEpoch: 1,
      membershipRevision: 1,
      authorizationStateDigest: computeAuthorizationStateDigest(
        authorizationCoreFromOwner(parsed, owner, keyEnvelopes),
      ),
      encryptedMemberKeyEnvelope: envelope,
      encryptedMembershipMetadataDigest: encryptedMembershipDigest,
      discoveryRecordDigest: PLACEHOLDER_DIGEST,
      signerPrincipalId: owner.principalId,
      signerDeviceId: parsed.writer.deviceId,
      writerSignature: PLACEHOLDER_SIGNATURE,
      createdAt: parsed.preparedAt,
      updatedAt: parsed.preparedAt,
    });
    const withDigest = collaborationDiscoveryRecordSchema.parse({
      ...unsigned,
      discoveryRecordDigest: computeDiscoveryRecordDigest(unsigned),
    });
    records.push(
      collaborationDiscoveryRecordSchema.parse({
        ...withDigest,
        writerSignature: await signDiscoveryRecord(withDigest, parsed.ownerPrivateKey),
      }),
    );
  }
  return records;
}

function authorizationCoreFromOwner(
  parsed: ParsedInput,
  owner: CollaborationMembership,
  keyEnvelopes: readonly (
    CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope
  )[],
): CollaborationAuthorizationStateCore {
  return authorizationCoreOf(
    parsed,
    owner,
    genesisTupleBase({
      authorityEpoch: parsed.authorityEpoch,
      databaseDeviceGeneration: parsed.registry.generation,
      databaseDeviceRegistryDigest: parsed.registry.registryDigest,
    }),
    keyEnvelopes,
  );
}

async function buildGenesisTransition(
  parsed: ParsedInput,
  priorTuple: CollaborationRevisionTuple,
  tuple: CollaborationRevisionTuple,
): Promise<CollaborationAuthorizationTransition> {
  const unsigned = collaborationAuthorizationTransitionSchema.parse({
    format: COLLABORATIVE_AUTHORIZATION_TRANSITION_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    operationId: parsed.operationId,
    operationType: 'genesis-migration',
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousAuthorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
    authorizationStateDigest: tuple.authorizationStateDigest,
    previousTuple: priorTuple,
    nextTuple: tuple,
    evidence: { kind: 'none' },
    issuedAt: parsed.preparedAt,
    expiresAt: parsed.expiresAt,
    transitionDigest: PLACEHOLDER_DIGEST,
    transitionSignature: {
      signerKind: 'owner-device',
      signerPrincipalId: parsed.identity.principalId,
      signerDeviceId: parsed.writer.deviceId,
      signature: PLACEHOLDER_SIGNATURE,
    },
  });
  const withDigest = collaborationAuthorizationTransitionSchema.parse({
    ...unsigned,
    transitionDigest: computeAuthorizationTransitionDigest(unsigned),
  });
  return collaborationAuthorizationTransitionSchema.parse({
    ...withDigest,
    transitionSignature: {
      ...withDigest.transitionSignature,
      signature: await signAuthorizationTransitionOwner(
        withDigest,
        parsed.ownerPrivateKey,
      ),
    },
  });
}

async function buildGenesisDelegation(
  parsed: ParsedInput,
  owner: CollaborationMembership,
  tuple: CollaborationRevisionTuple,
  headDigest: Sha256Digest,
): Promise<CollaborationAuthorityDelegation> {
  const unsigned = collaborationAuthorityDelegationSchema.parse({
    format: COLLABORATIVE_AUTHORITY_DELEGATION_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    authorityEpoch: parsed.authorityEpoch,
    authoritySigningPublicKey: parsed.authoritySigningPublicKey,
    authoritySigningKeyFingerprint: parsed.authoritySigningFingerprint,
    authorityRecoveryPublicKey: parsed.authorityRecoveryPublicKey,
    authorityRecoveryKeyFingerprint: parsed.authorityRecoveryFingerprint,
    genesisOperationId: parsed.operationId,
    genesisTuple: tuple,
    genesisHeadDigest: headDigest,
    initialAuthorizationStateDigest: tuple.authorizationStateDigest,
    initialOwnerPrincipalId: owner.principalId,
    initialOwnerRootKeyFingerprint: owner.principalFingerprint,
    initialOwnerDeviceId: parsed.writer.deviceId,
    initialOwnerDeviceSigningKeyFingerprint: computePublicKeyFingerprint(
      parsed.writer.signingPublicKey,
      'ed25519',
    ),
    initialOwnerDeviceEncryptionKeyFingerprint: computePublicKeyFingerprint(
      parsed.writer.encryptionPublicKey,
      'x25519',
    ),
    issuedAt: parsed.requestedAt,
    authoritySignature: PLACEHOLDER_SIGNATURE,
  });
  return collaborationAuthorityDelegationSchema.parse({
    ...unsigned,
    authoritySignature: await signAuthorityDelegation(
      unsigned,
      parsed.authorityPrivateKey,
    ),
  });
}

async function buildGenesisLink(
  parsed: ParsedInput,
  commitment: CollaborationMutationCommitment,
  transition: ReturnType<typeof collaborationAuthorizationTransitionSchema.parse>,
  headDigest: Sha256Digest,
  authorityDelegationDigest: Sha256Digest,
): Promise<CollaborationFinalizedMutationLink> {
  const unsigned = collaborationFinalizedMutationLinkSchema.parse({
    format: COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    authorityDelegationDigest,
    commitment,
    authorizationTransition: transition,
    resultingHeadDigest: headDigest,
    writerSignature: {
      algorithm: 'ed25519',
      writerPrincipalId: parsed.identity.principalId,
      writerDeviceId: parsed.writer.deviceId,
      commitmentDigest: headDigest,
      signature: PLACEHOLDER_SIGNATURE,
    },
    finalizedAt: parsed.preparedAt,
  });
  return collaborationFinalizedMutationLinkSchema.parse({
    ...unsigned,
    writerSignature: {
      ...unsigned.writerSignature,
      signature: await signFinalizedMutationLink(unsigned, parsed.ownerPrivateKey),
    },
  });
}

async function buildGenesisOutcome(
  parsed: ParsedInput,
  requestDigest: Sha256Digest,
  priorTuple: CollaborationRevisionTuple,
  tuple: CollaborationRevisionTuple,
  headDigest: Sha256Digest,
  finalizedMutationLinkDigest: Sha256Digest,
): Promise<DurableOperationOutcome> {
  const unsigned = {
    format: COLLABORATIVE_OPERATION_OUTCOME_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    operationId: parsed.operationId,
    operationType: 'genesis-migration' as const,
    requestDigest,
    actorPrincipalId: parsed.identity.principalId,
    actorDeviceId: parsed.writer.deviceId,
    priorTuple,
    priorHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    state: 'committed' as const,
    committedTuple: tuple,
    committedHeadDigest: headDigest,
    finalizedMutationLinkDigest,
    committedAt: parsed.activatedAt,
    outcomeDigest: PLACEHOLDER_DIGEST,
    signedMutationReceipt: {
      format: COLLABORATIVE_MUTATION_RECEIPT_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: parsed.legacySource.databaseId,
      vaultId: parsed.legacySource.id,
      operationId: parsed.operationId,
      operationType: 'genesis-migration' as const,
      requestDigest,
      actorPrincipalId: parsed.identity.principalId,
      actorDeviceId: parsed.writer.deviceId,
      priorTuple,
      priorHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
      committedTuple: tuple,
      committedHeadDigest: headDigest,
      finalizedMutationLinkDigest,
      outcomeDigest: PLACEHOLDER_DIGEST,
      committedAt: parsed.activatedAt,
      receiptSignature: PLACEHOLDER_SIGNATURE,
    },
    createdAt: parsed.requestedAt,
    resolvedAt: parsed.activatedAt,
    detailsRetainedUntil: parsed.expiresAt,
  };
  const outcomeDigest = computeOperationOutcomeDigest(unsigned);
  const receipt = {
    ...unsigned.signedMutationReceipt,
    outcomeDigest,
  };
  const receiptSignature = await signMutationReceipt(receipt, parsed.ownerPrivateKey);
  return durableOperationOutcomeSchema.parse({
    ...unsigned,
    outcomeDigest,
    signedMutationReceipt: { ...receipt, receiptSignature },
  });
}

async function buildPreparedMarker(
  parsed: ParsedInput,
  requestDigest: Sha256Digest,
  headDigest: Sha256Digest,
): Promise<CollaborationMigrationPreparedMarker> {
  const unsigned = collaborationMigrationPreparedMarkerSchema.parse({
    ...migrationMarkerBase(parsed, requestDigest, headDigest),
    state: 'prepared',
    legacySource: parsed.legacySource,
    registryCandidate: parsed.registry,
  });
  return collaborationMigrationPreparedMarkerSchema.parse({
    ...unsigned,
    authoritySignature: await signMigrationPreparedMarker(
      unsigned,
      parsed.authorityPrivateKey,
    ),
  });
}

async function buildActiveMarker(
  parsed: ParsedInput,
  requestDigest: Sha256Digest,
  headDigest: Sha256Digest,
  outcomeDigest: Sha256Digest,
): Promise<CollaborationMigrationActiveMarker> {
  const unsigned = collaborationMigrationActiveMarkerSchema.parse({
    ...migrationMarkerBase(parsed, requestDigest, headDigest),
    state: 'active',
    outcomeDigest,
    activatedAt: parsed.activatedAt,
  });
  return collaborationMigrationActiveMarkerSchema.parse({
    ...unsigned,
    authoritySignature: await signMigrationActiveMarker(
      unsigned,
      parsed.authorityPrivateKey,
    ),
  });
}

function migrationMarkerBase(
  parsed: ParsedInput,
  requestDigest: Sha256Digest,
  headDigest: Sha256Digest,
): MigrationMarkerBase {
  return {
    format: COLLABORATIVE_MIGRATION_MARKER_FORMAT,
    markerVersion: 1 as const,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    operationId: parsed.operationId,
    requestDigest,
    legacySourceDigest: computeLegacySourceDigest(parsed.legacySource),
    authorityEpoch: parsed.authorityEpoch,
    authorityFingerprint: parsed.authoritySigningFingerprint,
    databaseDeviceGeneration: parsed.registry.generation,
    databaseDeviceRegistryDigest: parsed.registry.registryDigest,
    candidateHeadDigest: headDigest,
    preparedAt: parsed.preparedAt,
    authoritySignature: PLACEHOLDER_SIGNATURE,
  };
}

async function verifyCompleteBundle(
  input: Readonly<{
    parsed: ParsedInput;
    request: CollaborationMigrationRequest;
    candidate: CollaborativeVaultDocument;
    manifest: CollaborativeMembershipManifest;
    proofEntry: CollaborationMutationProof['entries'][number];
    outcome: DurableOperationOutcome;
    candidateAnchor: RecipientRollbackAnchor;
    preparedMarker: CollaborationMigrationPreparedMarker;
    activeMarker: CollaborationMigrationActiveMarker;
    vaultRootKey: Uint8Array;
  }>,
): Promise<void> {
  const { parsed, candidate, manifest } = input;
  const link = candidate.currentMutationLink;
  const witness = input.proofEntry.authorizationWitness;
  let openedPayload: Uint8Array | undefined;
  let openedManifest: Uint8Array | undefined;
  let expectedManifest: Uint8Array | undefined;
  try {
    requireExactDatabaseAuthorityRecoveryEnvelope(candidate, manifest);
    if (
      witness === undefined ||
      computeMigrationRequestDigest(input.request) !== input.request.requestDigest ||
      computeLegacySourceDigest(parsed.legacySource) !==
        input.request.legacySourceDigest ||
      computeDeviceRegistryDigest(parsed.registry) !== parsed.registry.registryDigest ||
      computeMutationHead(link.commitment) !== candidate.headDigest ||
      computeAuthorityDelegationDigest(candidate.authorityDelegation) !==
        candidate.authorityDelegationDigest ||
      computeFinalizedMutationLinkDigest(link) !==
        witness.finalizedMutationLinkDigest ||
      computeEncryptedPayloadDigest(candidate.encryptedPayload) !==
        candidate.encryptedPayloadDigest ||
      computeEncryptedMembershipDigest(candidate.encryptedMembershipManifest) !==
        candidate.encryptedMembershipDigest ||
      computeKeyEnvelopeSetDigest(manifest.keyEnvelopes) !==
        candidate.encryptedEnvelopesDigest ||
      computePolicyDigest(manifest.policy) !== candidate.policyDigest ||
      computeMembershipHistoryDigest(manifest.history) !==
        manifest.history.currentHistoryDigest ||
      computeMembershipManifestDigest(manifest) !== manifest.membershipDigest ||
      computeAuthorizationStateDigest(
        authorizationCoreFromOwner(
          parsed,
          requireUnique(manifest.memberships),
          manifest.keyEnvelopes,
        ),
      ) !== candidate.authorizationStateDigest ||
      computeOperationOutcomeDigest(input.outcome) !== input.outcome.outcomeDigest ||
      canonicalJson(input.proofEntry.link) !== canonicalJson(link) ||
      canonicalJson(witness.databaseDeviceRegistry) !==
        canonicalJson(parsed.registry) ||
      input.candidateAnchor.headDigest !== candidate.headDigest ||
      input.preparedMarker.candidateHeadDigest !== candidate.headDigest ||
      input.activeMarker.candidateHeadDigest !== candidate.headDigest ||
      input.activeMarker.outcomeDigest !== input.outcome.outcomeDigest ||
      !(await verifyAuthorityDelegation(
        candidate.authorityDelegation,
        parsed.authoritySigningPublicKey,
      )) ||
      !(await verifyAuthorizationTransitionOwner(
        link.authorizationTransition,
        parsed.writer.signingPublicKey,
      )) ||
      !(await verifyFinalizedMutationLink(link, parsed.writer.signingPublicKey)) ||
      !(await verifyCommittedOperationOutcome(
        input.outcome,
        parsed.writer.signingPublicKey,
      )) ||
      !(await verifyMigrationPreparedMarker(
        input.preparedMarker,
        parsed.authoritySigningPublicKey,
      )) ||
      !(await verifyMigrationActiveMarker(
        input.activeMarker,
        parsed.authoritySigningPublicKey,
      ))
    ) {
      fail();
    }
    for (const envelope of manifest.keyEnvelopes) {
      const envelopeDigest =
        'membershipId' in envelope
          ? computeKeyEnvelopeDigest(envelope)
          : computeAuthorityRecoveryEnvelopeDigest(envelope);
      const verified =
        'membershipId' in envelope
          ? await verifyCollaborationRecord(
              COLLABORATION_DOMAINS.keyEnvelopeSignature,
              envelope,
              collaborationKeyEnvelopeSchema,
              'ownerSignature',
              parsed.writer.signingPublicKey,
            )
          : await verifyCollaborationRecord(
              COLLABORATION_DOMAINS.keyEnvelopeSignature,
              envelope,
              databaseAuthorityRecoveryEnvelopeSchema,
              'ownerSignature',
              parsed.writer.signingPublicKey,
            );
      if (envelopeDigest !== envelope.envelopeDigest || !verified) {
        fail();
      }
    }
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.policySignature,
        manifest.policy,
        collaborationPolicyStateSchema,
        'signature',
        parsed.writer.signingPublicKey,
      )) ||
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        requireUnique(manifest.history.events),
        membershipHistoryEventSchema,
        'signature',
        parsed.writer.signingPublicKey,
      ))
    ) {
      fail();
    }
    for (const record of candidate.discoveryRecords) {
      if (
        computeDiscoveryRecordDigest(record) !== record.discoveryRecordDigest ||
        !(await verifyDiscoveryRecord(record, parsed.writer.signingPublicKey))
      )
        fail();
    }
    openedPayload = await decryptCollaborationEnvelope(
      candidate.encryptedPayload,
      input.vaultRootKey,
      candidate.encryptedPayload.aad,
    );
    openedManifest = await decryptCollaborationEnvelope(
      candidate.encryptedMembershipManifest,
      input.vaultRootKey,
      candidate.encryptedMembershipManifest.aad,
    );
    expectedManifest = Buffer.from(canonicalJson(manifest), 'utf8');
    if (
      !constantTimeEqual(openedPayload, parsed.payload) ||
      !constantTimeEqual(openedManifest, expectedManifest)
    ) {
      fail();
    }
  } finally {
    zeroize(openedPayload);
    zeroize(openedManifest);
    zeroize(expectedManifest);
  }
}

function genesisPriorTuple(parsed: ParsedInput): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: parsed.authorityEpoch,
    documentRevision: 0,
    membershipRevision: 0,
    policyRevision: 0,
    keyEpoch: 1,
    databaseDeviceGeneration: parsed.registry.generation,
    databaseDeviceRegistryDigest: parsed.registry.registryDigest,
    authorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  });
}

function genesisTupleBase(
  input: Readonly<{
    authorityEpoch: CollaborationRevisionTuple['authorityEpoch'];
    databaseDeviceGeneration: CollaborationRevisionTuple['databaseDeviceGeneration'];
    databaseDeviceRegistryDigest: Sha256Digest;
  }>,
): Omit<CollaborationRevisionTuple, 'authorizationStateDigest'> {
  const parsed = collaborationRevisionTupleSchema.parse({
    ...input,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    authorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  });
  const base: Record<string, unknown> = { ...parsed };
  Reflect.deleteProperty(base, 'authorizationStateDigest');
  return base as Omit<CollaborationRevisionTuple, 'authorizationStateDigest'>;
}

function aadFor(
  parsed: ParsedInput,
  tuple: CollaborationRevisionTuple,
  entityType: 'vault-payload' | 'membership-manifest',
): ReturnType<typeof collaborationAadSchema.parse> {
  const metadata = collaborationAadMetadataSchema.parse({
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: parsed.legacySource.databaseId,
    vaultId: parsed.legacySource.id,
    authorityEpoch: tuple.authorityEpoch,
    entityType,
    entityId: parsed.legacySource.id,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    authorizationStateDigest: tuple.authorizationStateDigest,
  });
  return collaborationAadSchema.parse({
    ...metadata,
    metadataDigest: computeAadMetadataDigest(metadata),
  });
}

function registryDeniesDevice(
  registry: CollaborationDatabaseDeviceRegistry,
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

function deviceUsableThrough(
  device: DeviceCertificate,
  start: Timestamp,
  end: Timestamp,
): boolean {
  return (
    device.state === 'active' &&
    Date.parse(device.createdAt) <= Date.parse(start) &&
    Date.parse(device.stateChangedAt) <= Date.parse(start) &&
    (device.expiresAt === undefined || Date.parse(end) < Date.parse(device.expiresAt))
  );
}

function parseAnchorScope(
  scope: RecipientRollbackAnchorScope,
): RecipientRollbackAnchorScope {
  return {
    databaseId: recipientRollbackAnchorSchema.shape.databaseId.parse(scope.databaseId),
    vaultId: recipientRollbackAnchorSchema.shape.vaultId.parse(scope.vaultId),
    principalId: recipientRollbackAnchorSchema.shape.principalId.parse(
      scope.principalId,
    ),
    deviceId: recipientRollbackAnchorSchema.shape.deviceId.parse(scope.deviceId),
  };
}

function deviceAuthorizationCore(device: DeviceCertificate): Record<string, unknown> {
  const core: Record<string, unknown> = { ...device };
  Reflect.deleteProperty(core, 'rootSignature');
  return core;
}

function envelopeAuthorizationCore(
  envelope: CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope,
): Record<string, unknown> {
  const core: Record<string, unknown> = { ...envelope };
  Reflect.deleteProperty(core, 'envelopeDigest');
  Reflect.deleteProperty(core, 'createdAt');
  Reflect.deleteProperty(core, 'ownerSignature');
  return core;
}

function copySecret(value: Uint8Array, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) fail();
  return Uint8Array.from(value);
}

function requireUnique<T>(values: readonly T[]): T {
  if (values.length !== 1 || values[0] === undefined) fail();
  return values[0];
}

function wipeParsed(parsed: ParsedInput | undefined): void {
  zeroize(parsed?.payload);
  zeroize(parsed?.ownerPrivateKey);
  zeroize(parsed?.authorityPrivateKey);
}

function fail(): never {
  throw new CollaborationGenesisPreparationError();
}

function freezePrepared(
  value: PreparedCollaborativeGenesis,
): PreparedCollaborativeGenesis {
  deepFreeze(value.request);
  deepFreeze(value.preparedMarker);
  deepFreeze(value.registryCandidate);
  deepFreeze(value.candidate);
  deepFreeze(value.initialManifest);
  deepFreeze(value.initialOwnerIdentity);
  deepFreeze(value.proofEntry);
  deepFreeze(value.proposedOutcome);
  deepFreeze(value.candidateAnchor);
  deepFreeze(value.activeMarker);
  return Object.freeze(value);
}

function deepFreeze(value: unknown): void {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
}
