import type {
  CollaborationAuthorizationCheckpoint,
  CollaborationAuthorizationWitness,
  CollaborationDatabaseDeviceRegistry,
  CollaborationDiscoveryRecord,
  CollaborationFinalizedMutationLink,
  CollaborationMigrationActiveMarker,
  CollaborationMigrationPreparedMarker,
  CollaborationMigrationRequest,
  CollaborationMutationProof,
  CollaborationVaultDestructionTombstone,
  CollaborativeVaultDocument,
  DatabaseId,
  DurableOperationOutcome,
  OperationDeduplicationTombstone,
  Sha256Digest,
  VaultId,
} from '@kavrix/schemas';

/**
 * The opaque persistence port for the Mongo-only collaboration protocol.
 *
 * Callers prepare every protocol value before entering this adapter. The
 * adapter validates and atomically stores those values, but never creates
 * protocol identifiers, timestamps, nonces, signatures, or ciphertext.
 */
export interface CollaborativeVaultStore {
  getCollaborativeVault(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<CollaborativeVaultDocument | null>;
  discoverCollaborativeMemberships(
    databaseId: DatabaseId,
    discoveryTags: readonly Sha256Digest[] | Sha256Digest,
    limit?: number,
  ): Promise<readonly CollaborationDiscoveryRecord[]>;
  getDatabaseDeviceRegistry(
    databaseId: DatabaseId,
  ): Promise<CollaborationDatabaseDeviceRegistry | null>;
  publishDatabaseDeviceRegistry(
    candidate: CollaborationDatabaseDeviceRegistry,
  ): Promise<void>;
  publishCollaborativeVault(
    input: PublishCollaborativeVaultInput,
  ): Promise<DurableOperationOutcome | OperationDeduplicationTombstone>;
  destroyCollaborativeVault(
    input: DestroyCollaborativeVaultInput,
  ): Promise<DurableOperationOutcome | OperationDeduplicationTombstone>;
  getCollaborativeVaultDestructionTombstone(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<CollaborationVaultDestructionTombstone | null>;
  getCollaborativeFinalizedMutationLinkByHead(
    databaseId: DatabaseId,
    vaultId: VaultId,
    resultingHeadDigest: Sha256Digest,
  ): Promise<CollaborationFinalizedMutationLink | null>;
  getCollaborativeFinalizedMutationLinkByOperation(
    databaseId: DatabaseId,
    vaultId: VaultId,
    operationId: string,
  ): Promise<CollaborationFinalizedMutationLink | null>;
  getCollaborativeMutationProofRange(
    input: GetCollaborativeMutationProofRangeInput,
  ): Promise<CollaborationMutationProof>;
  getCollaborationAuthorizationWitness(
    databaseId: DatabaseId,
    vaultId: VaultId,
    authorizationStateDigest: Sha256Digest,
    atOrBeforeDocumentRevision: number,
  ): Promise<CollaborationAuthorizationWitness | null>;
  appendCollaborationAuthorizationCheckpoint(
    checkpoint: CollaborationAuthorizationCheckpoint,
  ): Promise<void>;
  getCollaborationAuthorizationCheckpoint(
    databaseId: DatabaseId,
    vaultId: VaultId,
    checkpointDigest: Sha256Digest,
  ): Promise<CollaborationAuthorizationCheckpoint | null>;
  beginCollaborativeMigration(
    input: BeginCollaborativeMigrationInput,
  ): Promise<CollaborationMigrationPreparedMarker>;
  activateCollaborativeGenesis(
    input: ActivateCollaborativeGenesisInput,
  ): Promise<DurableOperationOutcome>;
  getCollaborativeOperationOutcome(
    databaseId: DatabaseId,
    vaultId: VaultId,
    operationId: string,
  ): Promise<DurableOperationOutcome | OperationDeduplicationTombstone | null>;
  compactCollaborativeOperationOutcome(
    input: CompactCollaborativeOperationOutcomeInput,
  ): Promise<OperationDeduplicationTombstone>;
}

export type PublishCollaborativeVaultInput = Readonly<{
  /** Complete next state; persisted unchanged apart from the internal _id. */
  candidate: CollaborativeVaultDocument;
  /** Complete signed durable result for the exact operation. */
  outcome: DurableOperationOutcome;
  /** Exact immutable proof entry persisted beside the candidate and outcome. */
  proofEntry: CollaborationMutationProof['entries'][number];
}>;

export type DestroyCollaborativeVaultInput = Readonly<{
  /** Permanent terminal identity fence carrying the exact final proof entry. */
  tombstone: CollaborationVaultDestructionTombstone;
  /** Complete committed result for the exact irreversible destruction. */
  outcome: DurableOperationOutcome;
}>;

export type CollaborativeProofPosition = Readonly<{
  documentRevision: number;
  headDigest: Sha256Digest;
}>;

export type GetCollaborativeMutationProofRangeInput = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  fromExclusive: CollaborativeProofPosition;
  toInclusive: CollaborativeProofPosition;
  /** Upper bound supplied by the caller; protocol maximum is 256 links. */
  limit?: number;
}>;

export type CompactCollaborativeOperationOutcomeInput = Readonly<{
  /** Immutable tombstone prepared by the caller from the full outcome. */
  tombstone: OperationDeduplicationTombstone;
}>;

export type BeginCollaborativeMigrationInput = Readonly<{
  request: CollaborationMigrationRequest;
  preparedMarker: CollaborationMigrationPreparedMarker;
}>;

export type ActivateCollaborativeGenesisInput = Readonly<{
  preparedMarker: CollaborationMigrationPreparedMarker;
  candidate: CollaborativeVaultDocument;
  outcome: DurableOperationOutcome;
  proofEntry: CollaborationMutationProof['entries'][number];
  activeMarker: CollaborationMigrationActiveMarker;
}>;
