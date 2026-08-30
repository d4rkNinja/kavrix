import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  COLLABORATION_DOMAINS,
  computeDatabaseVaultPayloadMetadataDigest,
  computeDeviceRegistryDigest,
  computeFinalizedMutationLinkDigest,
  computeLegacySourceDigest,
  computeMigrationRequestDigest,
  computeOperationOutcomeDigest,
  computePublicKeyFingerprint,
  encryptPayload,
  generateDatabaseRootKey,
  generateDeviceEncryptionKeyPair,
  generateDeviceSigningKeyPair,
  generatePrincipalSigningKeyPair,
  generateVaultRootKey,
  signCollaborationRecord,
  signMutationReceipt,
  wrapVaultRootForDatabase,
  zeroize,
  type CollaborationEncryptionKeyPair,
  type DatabaseRootKey,
  type DeviceSigningKeyPair,
  type PrincipalSigningKeyPair,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument,
  createCollaborationAuthorityRollbackAnchor,
  createCollaborationMigrationJournal,
  createRecipientRollbackAnchor,
  collaborationMigrationJournalRecordSchema,
  markCollaborationMigrationAnchored,
  readCollaborationAuthorityRollbackAnchor,
  readCollaborationMigrationJournal,
  readRecipientRollbackAnchor,
  reconcileCollaborationMigrationPublication,
  writeDatabaseRevisionAnchor,
  type CollaborationAuthorityRollbackAnchor,
  type CollaborationAuthorityRollbackAnchorScope,
  type RecipientRollbackAnchorScope,
} from '@kavrix/key-files';
import {
  associatedDataSchema,
  canonicalJson,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationMigrationRequestSchema,
  collaborationMutationReceiptSchema,
  databaseAssociatedDataSchema,
  databaseVaultDocumentSchema,
  deviceCertificateSchema,
  durableOperationOutcomeSchema,
  publicIdentityExportSchema,
  sha256DigestSchema,
  timestampSchema,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationFinalizedMutationLink,
  type CollaborationMigrationPreparedMarker,
  type CollaborativeVaultDocument,
  type DatabaseVaultDocument,
  type DeviceCertificate,
  type DurableOperationOutcome,
  type OperationDeduplicationTombstone,
  type PublicIdentityExport,
  type Sha256Digest,
} from '@kavrix/schemas';
import {
  EncryptedDatabaseStoreError,
  type CollaborativeVaultStore,
} from '@kavrix/storage';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../key-files/dist/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(() => Promise.resolve()),
  verifyWindowsDirectoryAcl: vi.fn(() => Promise.resolve()),
  verifyWindowsUserOnlyAcl: vi.fn(() => Promise.resolve()),
}));

import {
  buildCollaborativeGenesis,
  type BuildCollaborativeGenesisInput,
  type PreparedCollaborativeGenesis,
} from '../src/collaboration-genesis-builder.js';
import {
  CollaborationMigrationOrchestrationError,
  orchestrateCollaborativeGenesisMigration,
  resumeCollaborativeGenesisMigration,
  stageCollaborativeGenesisMigration,
  type CollaborationMigrationOrchestrationResult,
} from '../src/collaboration-migration-orchestrator.js';

const DATABASE_ID = 'database-migration-orchestrator';
const VAULT_ID = 'vault-migration-orchestrator';
const PRINCIPAL_ID = 'principal-migration-owner';
const DEVICE_ID = 'device-migration-owner';
const MEMBERSHIP_ID = 'membership-migration-owner';
const OPERATION_ID = 'operation-migration-orchestrator';
const LEGACY_AT = timestampSchema.parse('2026-08-29T00:00:00.000Z');
const REQUESTED_AT = timestampSchema.parse('2026-08-29T00:01:00.000Z');
const PREPARED_AT = timestampSchema.parse('2026-08-29T00:02:00.000Z');
const ACTIVATED_AT = timestampSchema.parse('2026-08-29T00:03:00.000Z');
const EXPIRES_AT = timestampSchema.parse('2026-08-29T00:12:00.000Z');
const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');
const PLAINTEXT_CANARY = 'migration-plaintext-payload-canary';
const PROTECTION_CANARY = 'migration-device-protection-canary';
const ROOT_KEY_CANARY = Buffer.from('vrk-canary-0123456789abcdefghijk', 'utf8');

type FixtureSecrets = Readonly<{
  root: PrincipalSigningKeyPair;
  writerSigning: DeviceSigningKeyPair;
  writerEncryption: CollaborationEncryptionKeyPair;
  authoritySigning: PrincipalSigningKeyPair;
  authorityRecovery: CollaborationEncryptionKeyPair;
  databaseRootKey: DatabaseRootKey;
  legacyVaultRootKey: VaultRootKey;
}>;

type Fixture = Readonly<{
  prepared: PreparedCollaborativeGenesis;
  initialOwnerIdentity: PublicIdentityExport;
  secrets: FixtureSecrets;
  protectionSecret: Uint8Array;
  legacyDatabaseRevisionAnchorPath: string;
  authorityRollbackAnchorPath: string;
}>;

type JournalEnvelope = ReturnType<
  typeof collaborationMigrationJournalRecordSchema.parse
>;

const cleanup: (PreparedCollaborativeGenesis | FixtureSecrets | Uint8Array)[] = [];
let directory = '';
let fixtureCounter = 0;

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-migration-orchestrator-'));
  fixtureCounter = 0;
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
  for (const value of cleanup.splice(0)) {
    if (value instanceof Uint8Array) {
      zeroize(value);
      continue;
    }
    if ('vaultRootKey' in value) {
      zeroize(value.vaultRootKey);
      continue;
    }
    zeroize(value.root.privateKey);
    zeroize(value.writerSigning.privateKey);
    zeroize(value.writerEncryption.privateKey);
    zeroize(value.authoritySigning.privateKey);
    zeroize(value.authorityRecovery.privateKey);
    zeroize(value.databaseRootKey);
    zeroize(value.legacyVaultRootKey);
  }
});

function journalPath(): string {
  return join(directory, 'migration.journal');
}

function anchorPath(): string {
  return join(directory, 'recipient.anchor');
}

function digest(fill: number): Sha256Digest {
  return sha256DigestSchema.parse(Buffer.alloc(32, fill).toString('base64url'));
}

function mutateBase64(value: string): string {
  return `${value.startsWith('A') ? 'B' : 'A'}${value.slice(1)}`;
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

async function signedRecord<T>(
  domain: (typeof COLLABORATION_DOMAINS)[keyof typeof COLLABORATION_DOMAINS],
  value: Record<string, unknown>,
  schema: { parse(input: unknown): T },
  field: 'rootSignature' | 'selfSignature' | 'authoritySignature',
  privateKey: Uint8Array,
): Promise<T> {
  return schema.parse({
    ...value,
    [field]: await signCollaborationRecord(domain, value, schema, field, privateKey),
  });
}

async function makeFixture(): Promise<Fixture> {
  const root = await generatePrincipalSigningKeyPair();
  const writerSigning = await generateDeviceSigningKeyPair();
  const writerEncryption = await generateDeviceEncryptionKeyPair();
  const authoritySigning = await generatePrincipalSigningKeyPair();
  const authorityRecovery = await generateDeviceEncryptionKeyPair();
  const databaseRootKey = generateDatabaseRootKey();
  const legacyVaultRootKey = generateVaultRootKey();
  const secrets = {
    root,
    writerSigning,
    writerEncryption,
    authoritySigning,
    authorityRecovery,
    databaseRootKey,
    legacyVaultRootKey,
  };
  cleanup.push(secrets);

  const certificate = await makeCertificate(root, writerSigning, writerEncryption);
  const identityBase = {
    format: 'kavrix-collaborative-public-identity' as const,
    protocolVersion: 1 as const,
    principalId: PRINCIPAL_ID,
    identityGeneration: 1,
    rootSigningPublicKey: root.publicKeyBase64,
    devices: [certificate],
    createdAt: LEGACY_AT,
    selfSignature: PLACEHOLDER_SIGNATURE,
  };
  const identity = await signedRecord(
    COLLABORATION_DOMAINS.publicIdentitySignature,
    identityBase,
    publicIdentityExportSchema,
    'selfSignature',
    root.privateKey,
  );
  const authorityFingerprint = computePublicKeyFingerprint(
    authoritySigning.publicKeyBase64,
    'ed25519',
  );
  const registry = await makeRegistry(authoritySigning, authorityFingerprint);
  const legacyPlaintext = Buffer.from(
    canonicalJson({
      records: {
        migration: { updatedAt: LEGACY_AT, value: PLAINTEXT_CANARY },
      },
    }),
    'utf8',
  );
  let legacySource: DatabaseVaultDocument;
  try {
    legacySource = await legacyVault(
      databaseRootKey,
      legacyVaultRootKey,
      legacyPlaintext,
    );
  } finally {
    zeroize(legacyPlaintext);
  }
  const protectionSecret = Uint8Array.from(
    createHash('sha256').update(PROTECTION_CANARY, 'utf8').digest(),
  );
  cleanup.push(protectionSecret);
  expect(ROOT_KEY_CANARY).toHaveLength(32);
  const fixtureId = fixtureCounter++;
  const legacyDatabaseRevisionAnchorPath = join(
    directory,
    `legacy-${String(fixtureId)}.database-anchor`,
  );
  const authorityRollbackAnchorPath = join(
    directory,
    `authority-${String(fixtureId)}.anchor`,
  );
  await writeDatabaseRevisionAnchor(
    legacyDatabaseRevisionAnchorPath,
    databaseRootKey,
    {
      databaseId: legacySource.databaseId,
      databaseRevision: legacySource.databaseRevision,
      catalogMetadataDigest: digest(63),
      vaultHeads: {
        [legacySource.id]: {
          revision: legacySource.revision,
          metadataDigest: legacySource.payloadMetadataDigest,
        },
      },
    },
    'create',
  );
  const input: BuildCollaborativeGenesisInput = {
    legacySource,
    legacyDatabaseRevisionAnchorPath,
    databaseRootKey,
    registryCandidate: registry,
    initialOwnerIdentity: identity,
    initialOwnerDeviceId: certificate.deviceId,
    initialMembershipId:
      collaborationMigrationRequestSchema.shape.initialMembershipId.parse(
        MEMBERSHIP_ID,
      ),
    ownerDeviceSigningPrivateKey: writerSigning.privateKey,
    authoritySigningPrivateKey: authoritySigning.privateKey,
    authoritySigningPublicKey: authoritySigning.publicKeyBase64,
    authoritySigningKeyFingerprint: authorityFingerprint,
    authorityRecoveryPublicKey: authorityRecovery.publicKeyBase64,
    authorityRecoveryKeyFingerprint: computePublicKeyFingerprint(
      authorityRecovery.publicKeyBase64,
      'x25519',
    ),
    authorityEpoch: 1 as BuildCollaborativeGenesisInput['authorityEpoch'],
    operationId:
      collaborationMigrationRequestSchema.shape.operationId.parse(OPERATION_ID),
    requestedAt: REQUESTED_AT,
    preparedAt: PREPARED_AT,
    activatedAt: ACTIVATED_AT,
    transitionExpiresAt: EXPIRES_AT,
    anchorScope: {
      databaseId:
        DATABASE_ID as BuildCollaborativeGenesisInput['anchorScope']['databaseId'],
      vaultId: VAULT_ID as BuildCollaborativeGenesisInput['anchorScope']['vaultId'],
      principalId:
        PRINCIPAL_ID as BuildCollaborativeGenesisInput['anchorScope']['principalId'],
      deviceId: DEVICE_ID as BuildCollaborativeGenesisInput['anchorScope']['deviceId'],
    },
    randomness: {
      generateVaultRootKey: () => Uint8Array.from(ROOT_KEY_CANARY),
    },
  };
  const prepared = await buildCollaborativeGenesis(input);
  cleanup.push(prepared);
  return {
    prepared,
    initialOwnerIdentity: identity,
    secrets,
    protectionSecret,
    legacyDatabaseRevisionAnchorPath,
    authorityRollbackAnchorPath,
  };
}

async function makeCertificate(
  root: PrincipalSigningKeyPair,
  signing: DeviceSigningKeyPair,
  encryption: CollaborationEncryptionKeyPair,
): Promise<DeviceCertificate> {
  return await signedRecord(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    {
      protocolVersion: 1,
      principalId: PRINCIPAL_ID,
      deviceId: DEVICE_ID,
      deviceGeneration: 1,
      signingPublicKey: signing.publicKeyBase64,
      encryptionPublicKey: encryption.publicKeyBase64,
      state: 'active',
      createdAt: LEGACY_AT,
      stateChangedAt: LEGACY_AT,
      rootSignature: PLACEHOLDER_SIGNATURE,
    },
    deviceCertificateSchema,
    'rootSignature',
    root.privateKey,
  );
}

async function makeRegistry(
  authority: PrincipalSigningKeyPair,
  authorityFingerprint: Sha256Digest,
): Promise<CollaborationDatabaseDeviceRegistry> {
  const base = collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    authorityEpoch: 1,
    authorityFingerprint,
    generation: 1,
    previousRegistryDigest: digest(7),
    registryDigest: PLACEHOLDER_DIGEST,
    deniedDevices: [],
    updatedAt: REQUESTED_AT,
    authoritySignature: PLACEHOLDER_SIGNATURE,
  });
  const withDigest = collaborationDatabaseDeviceRegistrySchema.parse({
    ...base,
    registryDigest: computeDeviceRegistryDigest(base),
  });
  return await signedRecord(
    COLLABORATION_DOMAINS.deviceRegistrySignature,
    withDigest,
    collaborationDatabaseDeviceRegistrySchema,
    'authoritySignature',
    authority.privateKey,
  );
}

async function legacyVault(
  databaseRootKey: DatabaseRootKey,
  legacyVaultRootKey: VaultRootKey,
  plaintext: Uint8Array,
): Promise<DatabaseVaultDocument> {
  const metadata = {
    databaseId: DATABASE_ID,
    id: VAULT_ID,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    databaseRevision: 9,
    revision: 9,
    createdAt: LEGACY_AT,
    updatedAt: LEGACY_AT,
  } as const;
  const payloadMetadataDigest = computeDatabaseVaultPayloadMetadataDigest(
    metadata as DatabaseVaultDocument,
    legacyVaultRootKey,
    plaintext,
  );
  const encryptedPayload = await encryptPayload(
    plaintext,
    legacyVaultRootKey,
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType: 'vault-preferences',
      entityId: VAULT_ID,
      purpose: 'vault-preferences',
      revision: 9,
      metadataDigest: payloadMetadataDigest,
    }),
  );
  const wrappedVaultRoot = await wrapVaultRootForDatabase(
    legacyVaultRootKey,
    databaseRootKey,
    databaseAssociatedDataSchema.parse({
      version: 1,
      databaseId: DATABASE_ID,
      entityType: 'wrapped-vault-root',
      entityId: VAULT_ID,
      purpose: 'vault-root',
      schemaVersion: 1,
      keyVersion: 1,
      revision: 9,
      vaultId: VAULT_ID,
      metadataDigest: payloadMetadataDigest,
    }),
  );
  return databaseVaultDocumentSchema.parse({
    ...metadata,
    wrappedVaultRoot,
    encryptedPayload,
    payloadMetadataDigest,
  });
}

class FakeMigrationStore implements CollaborativeVaultStore {
  readonly events: string[] = [];
  readonly serializedMutationCalls: string[] = [];
  state: 'legacy' | 'prepared' | 'active' = 'legacy';
  beginBehavior: 'normal' | 'commit-then-throw' = 'normal';
  activateBehavior: 'normal' | 'commit-then-throw' = 'normal';
  beforeBegin: (() => Promise<void>) | undefined;
  candidate: CollaborativeVaultDocument | null = null;
  registry: CollaborationDatabaseDeviceRegistry | null = null;
  outcome: DurableOperationOutcome | OperationDeduplicationTombstone | null = null;
  proofLink: CollaborationFinalizedMutationLink | null = null;
  preparedMarker: CollaborationMigrationPreparedMarker | null = null;
  activeMarker: PreparedCollaborativeGenesis['activeMarker'] | null = null;

  readonly getCollaborativeVault: CollaborativeVaultStore['getCollaborativeVault'] =
    async () => {
      await Promise.resolve();
      this.events.push('read-candidate');
      return this.candidate === null ? null : structuredClone(this.candidate);
    };

  readonly discoverCollaborativeMemberships: CollaborativeVaultStore['discoverCollaborativeMemberships'] =
    async () => {
      await Promise.resolve();
      return [];
    };

  readonly getDatabaseDeviceRegistry: CollaborativeVaultStore['getDatabaseDeviceRegistry'] =
    async () => {
      await Promise.resolve();
      this.events.push('read-registry');
      return this.registry === null ? null : structuredClone(this.registry);
    };

  readonly publishDatabaseDeviceRegistry: CollaborativeVaultStore['publishDatabaseDeviceRegistry'] =
    async () => {
      await Promise.resolve();
      throw new EncryptedDatabaseStoreError('unsupported');
    };

  readonly publishCollaborativeVault: CollaborativeVaultStore['publishCollaborativeVault'] =
    async () => {
      await Promise.resolve();
      throw new EncryptedDatabaseStoreError('unsupported');
    };

  readonly destroyCollaborativeVault: CollaborativeVaultStore['destroyCollaborativeVault'] =
    async () => {
      await Promise.resolve();
      throw new EncryptedDatabaseStoreError('unsupported');
    };

  readonly getCollaborativeVaultDestructionTombstone: CollaborativeVaultStore['getCollaborativeVaultDestructionTombstone'] =
    async () => {
      await Promise.resolve();
      return null;
    };

  readonly getCollaborativeFinalizedMutationLinkByHead: CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByHead'] =
    async () => {
      await Promise.resolve();
      this.events.push('read-link-head');
      return this.proofLink === null ? null : structuredClone(this.proofLink);
    };

  readonly getCollaborativeFinalizedMutationLinkByOperation: CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByOperation'] =
    async () => {
      await Promise.resolve();
      this.events.push('read-link-operation');
      return this.proofLink === null ? null : structuredClone(this.proofLink);
    };

  readonly getCollaborativeMutationProofRange: CollaborativeVaultStore['getCollaborativeMutationProofRange'] =
    async () => {
      await Promise.resolve();
      throw new EncryptedDatabaseStoreError('unsupported');
    };

  readonly getCollaborationAuthorizationWitness: CollaborativeVaultStore['getCollaborationAuthorizationWitness'] =
    async () => {
      await Promise.resolve();
      return null;
    };

  readonly appendCollaborationAuthorizationCheckpoint: CollaborativeVaultStore['appendCollaborationAuthorizationCheckpoint'] =
    async () => {
      await Promise.resolve();
      throw new EncryptedDatabaseStoreError('unsupported');
    };

  readonly getCollaborationAuthorizationCheckpoint: CollaborativeVaultStore['getCollaborationAuthorizationCheckpoint'] =
    async () => {
      await Promise.resolve();
      return null;
    };

  readonly beginCollaborativeMigration: CollaborativeVaultStore['beginCollaborativeMigration'] =
    async (input) => {
      this.events.push('begin');
      await this.beforeBegin?.();
      this.serializedMutationCalls.push(canonicalJson(input));
      if (this.state === 'active') throw new EncryptedDatabaseStoreError('conflict');
      if (this.state === 'prepared') {
        if (!sameCanonical(this.preparedMarker, input.preparedMarker)) {
          throw new EncryptedDatabaseStoreError('invalid');
        }
        return structuredClone(input.preparedMarker);
      }
      this.state = 'prepared';
      this.preparedMarker = structuredClone(input.preparedMarker);
      if (this.beginBehavior === 'commit-then-throw') {
        this.beginBehavior = 'normal';
        throw new Error('lost response');
      }
      return structuredClone(input.preparedMarker);
    };

  readonly activateCollaborativeGenesis: CollaborativeVaultStore['activateCollaborativeGenesis'] =
    async (input) => {
      await Promise.resolve();
      this.events.push('activate');
      this.serializedMutationCalls.push(canonicalJson(input));
      if (this.state === 'active') {
        if (!this.matchesActive(input)) {
          throw new EncryptedDatabaseStoreError('invalid');
        }
        return structuredClone(input.outcome);
      }
      if (
        this.state !== 'prepared' ||
        !sameCanonical(this.preparedMarker, input.preparedMarker)
      ) {
        throw new EncryptedDatabaseStoreError('conflict');
      }
      this.installActiveInput(input);
      if (this.activateBehavior === 'commit-then-throw') {
        this.activateBehavior = 'normal';
        throw new Error('lost response');
      }
      return structuredClone(input.outcome);
    };

  readonly getCollaborativeOperationOutcome: CollaborativeVaultStore['getCollaborativeOperationOutcome'] =
    async () => {
      await Promise.resolve();
      this.events.push('read-outcome');
      return this.outcome === null ? null : structuredClone(this.outcome);
    };

  readonly compactCollaborativeOperationOutcome: CollaborativeVaultStore['compactCollaborativeOperationOutcome'] =
    async () => {
      await Promise.resolve();
      throw new EncryptedDatabaseStoreError('unsupported');
    };

  installActive(prepared: PreparedCollaborativeGenesis): void {
    this.installActiveInput({
      preparedMarker: prepared.preparedMarker,
      candidate: prepared.candidate,
      outcome: prepared.proposedOutcome,
      proofEntry: prepared.proofEntry,
      activeMarker: prepared.activeMarker,
    });
  }

  private installActiveInput(
    input: Parameters<CollaborativeVaultStore['activateCollaborativeGenesis']>[0],
  ): void {
    this.state = 'active';
    this.preparedMarker = structuredClone(input.preparedMarker);
    this.activeMarker = structuredClone(input.activeMarker);
    this.candidate = structuredClone(input.candidate);
    this.registry = structuredClone(input.preparedMarker.registryCandidate);
    this.outcome = structuredClone(input.outcome);
    this.proofLink = structuredClone(input.proofEntry.link);
  }

  private matchesActive(
    input: Parameters<CollaborativeVaultStore['activateCollaborativeGenesis']>[0],
  ): boolean {
    return (
      sameCanonical(this.preparedMarker, input.preparedMarker) &&
      sameCanonical(this.activeMarker, input.activeMarker) &&
      sameCanonical(this.candidate, input.candidate) &&
      sameCanonical(this.registry, input.preparedMarker.registryCandidate) &&
      sameCanonical(this.outcome, input.outcome) &&
      sameCanonical(this.proofLink, input.proofEntry.link)
    );
  }
}

function journalInput(
  prepared: PreparedCollaborativeGenesis,
): Parameters<typeof createCollaborationMigrationJournal>[2] {
  return {
    request: prepared.request,
    registryCandidate: prepared.registryCandidate,
    preparedMarker: prepared.preparedMarker,
    activeMarker: prepared.activeMarker,
    collaborativeCandidate: prepared.candidate,
    proofEntry: prepared.proofEntry,
    proposedOutcome: prepared.proposedOutcome,
    initialRecipientAnchor: prepared.candidateAnchor,
    initialOwnerIdentity: prepared.initialOwnerIdentity,
    restartRecipient: {
      principalId: prepared.candidateAnchor.principalId,
      deviceId: prepared.candidateAnchor.deviceId,
    },
  };
}

function journalScope(
  prepared: PreparedCollaborativeGenesis,
): Parameters<typeof readCollaborationMigrationJournal>[2]['expectedScope'] {
  return {
    databaseId: prepared.request.databaseId,
    vaultId: prepared.request.vaultId,
    principalId: prepared.request.initialOwnerPrincipalId,
    deviceId: prepared.request.initialOwnerDeviceId,
    operationId: prepared.request.operationId,
    requestDigest: prepared.request.requestDigest,
  };
}

function anchorScope(
  prepared: PreparedCollaborativeGenesis,
): RecipientRollbackAnchorScope {
  return {
    databaseId: prepared.request.databaseId,
    vaultId: prepared.request.vaultId,
    principalId: prepared.request.initialOwnerPrincipalId,
    deviceId: prepared.request.initialOwnerDeviceId,
  };
}

function authorityAnchor(
  prepared: PreparedCollaborativeGenesis,
): CollaborationAuthorityRollbackAnchor {
  return collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
    prepared.candidate,
    {
      membershipDigest: prepared.candidateAnchor.membershipDigest,
      policyDigest: prepared.candidateAnchor.policyDigest,
    },
  );
}

function authorityAnchorScope(
  prepared: PreparedCollaborativeGenesis,
): CollaborationAuthorityRollbackAnchorScope {
  const anchor = authorityAnchor(prepared);
  return {
    databaseId: anchor.databaseId,
    vaultId: anchor.vaultId,
    authorityEpoch: anchor.authorityEpoch,
    authorityDelegationDigest: anchor.authorityDelegationDigest,
  };
}

async function run(
  fixture: Fixture,
  store: FakeMigrationStore,
): Promise<CollaborationMigrationOrchestrationResult> {
  return await orchestrateCollaborativeGenesisMigration({
    store,
    prepared: fixture.prepared,
    databaseRootKey: fixture.secrets.databaseRootKey,
    deviceProtectionSecret: fixture.protectionSecret,
    migrationJournalPath: journalPath(),
    legacyDatabaseRevisionAnchorPath: fixture.legacyDatabaseRevisionAnchorPath,
    authorityRollbackAnchorPath: fixture.authorityRollbackAnchorPath,
    rollbackAnchorPath: anchorPath(),
  });
}

async function stage(
  fixture: Fixture,
  path = journalPath(),
): Promise<Awaited<ReturnType<typeof stageCollaborativeGenesisMigration>>> {
  return await stageCollaborativeGenesisMigration({
    prepared: fixture.prepared,
    initialOwnerIdentity: fixture.prepared.initialOwnerIdentity,
    restartRecipient: {
      principalId: fixture.prepared.candidateAnchor.principalId,
      deviceId: fixture.prepared.candidateAnchor.deviceId,
    },
    recipientEncryptionPrivateKey: fixture.secrets.writerEncryption.privateKey,
    deviceProtectionSecret: fixture.protectionSecret,
    migrationJournalPath: path,
  });
}

async function resume(
  fixture: Fixture,
  store: FakeMigrationStore,
  migrationPath = journalPath(),
  recipientAnchorPath = anchorPath(),
): Promise<CollaborationMigrationOrchestrationResult> {
  return await resumeCollaborativeGenesisMigration({
    store,
    recipientEncryptionPrivateKey: fixture.secrets.writerEncryption.privateKey,
    databaseRootKey: fixture.secrets.databaseRootKey,
    deviceProtectionSecret: fixture.protectionSecret,
    migrationJournalPath: migrationPath,
    legacyDatabaseRevisionAnchorPath: fixture.legacyDatabaseRevisionAnchorPath,
    authorityRollbackAnchorPath: fixture.authorityRollbackAnchorPath,
    rollbackAnchorPath: recipientAnchorPath,
  });
}

function tamperedRestartRecords(record: JournalEnvelope): readonly unknown[] {
  const candidate = record.collaborativeCandidate;
  const discovery = candidate.discoveryRecords[0];
  if (discovery === undefined) throw new Error('fixture discovery is missing');
  return [
    {
      ...record,
      authenticationTag: mutateBase64(record.authenticationTag),
    },
    {
      ...record,
      initialOwnerIdentity: {
        ...record.initialOwnerIdentity,
        selfSignature: mutateBase64(record.initialOwnerIdentity.selfSignature),
      },
    },
    {
      ...record,
      restartRecipient: {
        ...record.restartRecipient,
        deviceId: 'substituted-restart-device',
      },
    },
    {
      ...record,
      collaborativeCandidate: {
        ...candidate,
        encryptedPayload: {
          ...candidate.encryptedPayload,
          ciphertext: mutateBase64(candidate.encryptedPayload.ciphertext),
        },
      },
    },
    {
      ...record,
      collaborativeCandidate: {
        ...candidate,
        discoveryRecords: [
          {
            ...discovery,
            encryptedMemberKeyEnvelope: {
              ...discovery.encryptedMemberKeyEnvelope,
              sealedVaultRootKey: mutateBase64(
                discovery.encryptedMemberKeyEnvelope.sealedVaultRootKey,
              ),
            },
          },
          ...candidate.discoveryRecords.slice(1),
        ],
      },
    },
    {
      ...record,
      collaborativeCandidate: {
        ...candidate,
        encryptedMembershipManifest: {
          ...candidate.encryptedMembershipManifest,
          aad: {
            ...candidate.encryptedMembershipManifest.aad,
            metadataDigest: mutateBase64(
              candidate.encryptedMembershipManifest.aad.metadataDigest,
            ),
          },
        },
      },
    },
  ];
}

async function incompatibleCommittedOutcome(
  prepared: PreparedCollaborativeGenesis,
  writerPrivateKey: Uint8Array,
): Promise<DurableOperationOutcome> {
  const proposed = prepared.proposedOutcome;
  const unsigned = durableOperationOutcomeSchema.parse({
    ...proposed,
    detailsRetainedUntil: timestampSchema.parse('2026-10-29T00:03:00.000Z'),
    outcomeDigest: PLACEHOLDER_DIGEST,
    signedMutationReceipt: {
      ...proposed.signedMutationReceipt,
      outcomeDigest: PLACEHOLDER_DIGEST,
      receiptSignature: PLACEHOLDER_SIGNATURE,
    },
  });
  const outcomeDigest = computeOperationOutcomeDigest(unsigned);
  const receipt = collaborationMutationReceiptSchema.parse({
    ...unsigned.signedMutationReceipt,
    outcomeDigest,
    receiptSignature: PLACEHOLDER_SIGNATURE,
  });
  const signedReceipt = collaborationMutationReceiptSchema.parse({
    ...receipt,
    receiptSignature: await signMutationReceipt(receipt, writerPrivateKey),
  });
  return durableOperationOutcomeSchema.parse({
    ...unsigned,
    outcomeDigest,
    signedMutationReceipt: signedReceipt,
  });
}

describe('collaboration migration orchestrator', () => {
  it('journals before mutation, activates, anchors, and replays exact success', async () => {
    const fixture = await makeFixture();
    const store = new FakeMigrationStore();
    const prepared = fixture.prepared;
    const linkDigest = computeFinalizedMutationLinkDigest(
      prepared.candidate.currentMutationLink,
    );
    const diagnosticBindings = {
      requestDigest:
        prepared.request.requestDigest ===
        computeMigrationRequestDigest(prepared.request),
      legacyDigest:
        prepared.request.legacySourceDigest ===
        computeLegacySourceDigest(prepared.preparedMarker.legacySource),
      registry: sameCanonical(
        prepared.registryCandidate,
        prepared.preparedMarker.registryCandidate,
      ),
      proofLink: sameCanonical(
        prepared.proofEntry.link,
        prepared.candidate.currentMutationLink,
      ),
      witnessDigest:
        prepared.proofEntry.authorizationWitness?.finalizedMutationLinkDigest ===
        linkDigest,
      outcomeDigest:
        prepared.proposedOutcome.finalizedMutationLinkDigest === linkDigest,
      receiptDigest:
        prepared.proposedOutcome.signedMutationReceipt?.finalizedMutationLinkDigest ===
        linkDigest,
      markerOutcome:
        prepared.activeMarker.outcomeDigest === prepared.proposedOutcome.outcomeDigest,
      anchorLink: prepared.candidateAnchor.finalizedMutationLinkDigest === linkDigest,
    };
    expect(
      Object.entries(diagnosticBindings)
        .filter(([, matches]) => !matches)
        .map(([name]) => name),
    ).toEqual([]);
    store.beforeBegin = async () => {
      const record = await readCollaborationMigrationJournal(
        journalPath(),
        fixture.protectionSecret,
        { expectedScope: journalScope(fixture.prepared) },
      );
      expect(record?.state).toBe('prepared');
    };

    await expect(run(fixture, store)).resolves.toMatchObject({
      status: 'active',
      disposition: 'activated',
    });
    const anchor = await readRecipientRollbackAnchor(
      anchorPath(),
      fixture.protectionSecret,
      { expectedScope: anchorScope(fixture.prepared) },
    );
    expect(anchor).toEqual(fixture.prepared.candidateAnchor);
    expect(
      await readCollaborationAuthorityRollbackAnchor(
        fixture.authorityRollbackAnchorPath,
        fixture.secrets.databaseRootKey,
        { expectedScope: authorityAnchorScope(fixture.prepared) },
      ),
    ).toEqual(authorityAnchor(fixture.prepared));
    expect(
      (
        await readCollaborationMigrationJournal(
          journalPath(),
          fixture.protectionSecret,
          { expectedScope: journalScope(fixture.prepared) },
        )
      )?.state,
    ).toBe('active');

    await expect(run(fixture, store)).resolves.toMatchObject({
      status: 'active',
      disposition: 'already-active',
    });
  });

  it('rejects a bundle whose protected legacy head advanced after preparation', async () => {
    const fixture = await makeFixture();
    const store = new FakeMigrationStore();
    const source = fixture.prepared.preparedMarker.legacySource;
    await writeDatabaseRevisionAnchor(
      fixture.legacyDatabaseRevisionAnchorPath,
      fixture.secrets.databaseRootKey,
      {
        databaseId: source.databaseId,
        databaseRevision: (source.databaseRevision +
          1) as typeof source.databaseRevision,
        catalogMetadataDigest: digest(96),
        vaultHeads: {
          [source.id]: {
            revision: (source.revision + 1) as typeof source.revision,
            metadataDigest: digest(97),
          },
        },
      },
      'replace',
    );

    await expect(run(fixture, store)).resolves.toEqual({
      status: 'terminal',
      reason: 'anchor-mismatch',
    });
    expect(store.events).not.toContain('begin');
    expect(store.events).not.toContain('activate');
  });

  it('restarts in a new invocation after discarding the prepared root key', async () => {
    const fixture = await makeFixture();
    const store = new FakeMigrationStore();
    const privateKeySnapshot = Uint8Array.from(
      fixture.secrets.writerEncryption.privateKey,
    );
    cleanup.push(privateKeySnapshot);

    await expect(stage(fixture)).resolves.toEqual({ status: 'staged' });
    expect(store.events).toEqual([]);
    const staged = await readCollaborationMigrationJournal(
      journalPath(),
      fixture.protectionSecret,
      { expectedScope: journalScope(fixture.prepared) },
    );
    expect(staged).toMatchObject({
      state: 'prepared',
      initialOwnerIdentity: fixture.prepared.initialOwnerIdentity,
      restartRecipient: {
        principalId: fixture.prepared.candidateAnchor.principalId,
        deviceId: fixture.prepared.candidateAnchor.deviceId,
      },
    });

    zeroize(fixture.prepared.vaultRootKey);
    const processB = {
      store,
      recipientEncryptionPrivateKey: fixture.secrets.writerEncryption.privateKey,
      databaseRootKey: fixture.secrets.databaseRootKey,
      deviceProtectionSecret: fixture.protectionSecret,
      migrationJournalPath: journalPath(),
      legacyDatabaseRevisionAnchorPath: fixture.legacyDatabaseRevisionAnchorPath,
      authorityRollbackAnchorPath: fixture.authorityRollbackAnchorPath,
      rollbackAnchorPath: anchorPath(),
    } satisfies Parameters<typeof resumeCollaborativeGenesisMigration>[0];
    await expect(resumeCollaborativeGenesisMigration(processB)).resolves.toMatchObject({
      status: 'active',
      disposition: 'activated',
    });
    await expect(resumeCollaborativeGenesisMigration(processB)).resolves.toMatchObject({
      status: 'active',
      disposition: 'already-active',
    });
    expect(fixture.secrets.writerEncryption.privateKey).toEqual(privateKeySnapshot);
    expect(
      await readRecipientRollbackAnchor(anchorPath(), fixture.protectionSecret, {
        expectedScope: anchorScope(fixture.prepared),
      }),
    ).toEqual(fixture.prepared.candidateAnchor);
  });

  it('fails closed before store mutation for wrong keys and substituted stage trust', async () => {
    const fixture = await makeFixture();
    const store = new FakeMigrationStore();
    await expect(stage(fixture)).resolves.toEqual({ status: 'staged' });
    const wrongKey = await generateDeviceEncryptionKeyPair();
    cleanup.push(wrongKey.privateKey);
    await expect(
      resumeCollaborativeGenesisMigration({
        store,
        recipientEncryptionPrivateKey: wrongKey.privateKey,
        databaseRootKey: fixture.secrets.databaseRootKey,
        deviceProtectionSecret: fixture.protectionSecret,
        migrationJournalPath: journalPath(),
        legacyDatabaseRevisionAnchorPath: fixture.legacyDatabaseRevisionAnchorPath,
        authorityRollbackAnchorPath: fixture.authorityRollbackAnchorPath,
        rollbackAnchorPath: anchorPath(),
      }),
    ).rejects.toMatchObject({
      name: 'CollaborationMigrationOrchestrationError',
      kind: 'invalid-input',
      safe: true,
      message: 'Collaborative vault migration failed.',
    });
    expect(store.events).toEqual([]);

    const substitutedIdentity = {
      ...fixture.prepared.initialOwnerIdentity,
      selfSignature: mutateBase64(fixture.prepared.initialOwnerIdentity.selfSignature),
    };
    await expect(
      stageCollaborativeGenesisMigration({
        prepared: fixture.prepared,
        initialOwnerIdentity: substitutedIdentity,
        restartRecipient: {
          principalId: fixture.prepared.candidateAnchor.principalId,
          deviceId: fixture.prepared.candidateAnchor.deviceId,
        },
        recipientEncryptionPrivateKey: fixture.secrets.writerEncryption.privateKey,
        deviceProtectionSecret: fixture.protectionSecret,
        migrationJournalPath: join(directory, 'substituted-identity.journal'),
      }),
    ).rejects.toBeInstanceOf(CollaborationMigrationOrchestrationError);
    await expect(
      stageCollaborativeGenesisMigration({
        prepared: fixture.prepared,
        initialOwnerIdentity: fixture.prepared.initialOwnerIdentity,
        restartRecipient: {
          principalId: fixture.prepared.candidateAnchor.principalId,
          deviceId: deviceCertificateSchema.shape.deviceId.parse('different-device'),
        },
        recipientEncryptionPrivateKey: fixture.secrets.writerEncryption.privateKey,
        deviceProtectionSecret: fixture.protectionSecret,
        migrationJournalPath: join(directory, 'substituted-selector.journal'),
      }),
    ).rejects.toBeInstanceOf(CollaborationMigrationOrchestrationError);

    const discovery = fixture.prepared.candidate.discoveryRecords[0];
    if (discovery === undefined) throw new Error('fixture discovery is missing');
    const invalidCandidates: PreparedCollaborativeGenesis[] = [
      {
        ...fixture.prepared,
        candidate: {
          ...fixture.prepared.candidate,
          discoveryRecords: fixture.prepared.candidate.discoveryRecords.map(
            (record, index) =>
              index === 0 ? { ...record, membershipState: 'revoked' as const } : record,
          ),
        },
      },
      {
        ...fixture.prepared,
        candidate: {
          ...fixture.prepared.candidate,
          discoveryRecords: [
            ...fixture.prepared.candidate.discoveryRecords,
            structuredClone(discovery),
          ],
        },
      },
    ];
    for (const [index, prepared] of invalidCandidates.entries()) {
      await expect(
        stageCollaborativeGenesisMigration({
          prepared,
          initialOwnerIdentity: prepared.initialOwnerIdentity,
          restartRecipient: {
            principalId: prepared.candidateAnchor.principalId,
            deviceId: prepared.candidateAnchor.deviceId,
          },
          recipientEncryptionPrivateKey: fixture.secrets.writerEncryption.privateKey,
          deviceProtectionSecret: fixture.protectionSecret,
          migrationJournalPath: join(
            directory,
            `invalid-recipient-${String(index)}.journal`,
          ),
        }),
      ).rejects.toBeInstanceOf(CollaborationMigrationOrchestrationError);
    }
  });

  it('rejects authenticated-journal, candidate, envelope, and AAD byte tampering', async () => {
    const fixture = await makeFixture();
    await expect(stage(fixture)).resolves.toEqual({ status: 'staged' });
    const original = await readFile(journalPath(), 'utf8');
    const record = collaborationMigrationJournalRecordSchema.parse(
      JSON.parse(original),
    );
    const mutations = tamperedRestartRecords(record);

    for (const tampered of mutations) {
      await writeFile(journalPath(), canonicalJson(tampered), { mode: 0o600 });
      const store = new FakeMigrationStore();
      await expect(resume(fixture, store)).rejects.toMatchObject({
        name: 'CollaborationMigrationOrchestrationError',
        kind: 'invalid-input',
        safe: true,
        message: 'Collaborative vault migration failed.',
      });
      expect(store.events).toEqual([]);
      await writeFile(journalPath(), original, { mode: 0o600 });
    }
  });

  it('resumes after journal creation and an exact prepared-marker commit', async () => {
    const fixture = await makeFixture();
    const store = new FakeMigrationStore();
    await expect(stage(fixture)).resolves.toEqual({ status: 'staged' });
    await store.beginCollaborativeMigration({
      request: fixture.prepared.request,
      preparedMarker: fixture.prepared.preparedMarker,
    });
    store.events.length = 0;

    await expect(resume(fixture, store)).resolves.toMatchObject({ status: 'active' });
    expect(store.events).toContain('begin');
    expect(store.events).toContain('activate');
  });

  it('reconciles lost responses after begin and remote activation', async () => {
    const beginFixture = await makeFixture();
    const beginStore = new FakeMigrationStore();
    await expect(stage(beginFixture)).resolves.toEqual({ status: 'staged' });
    beginStore.beginBehavior = 'commit-then-throw';
    await expect(resume(beginFixture, beginStore)).resolves.toMatchObject({
      status: 'active',
    });

    const activationFixture = await makeFixture();
    const activationStore = new FakeMigrationStore();
    activationStore.activateBehavior = 'commit-then-throw';
    const secondJournal = join(directory, 'second.journal');
    const secondAnchor = join(directory, 'second.anchor');
    await expect(stage(activationFixture, secondJournal)).resolves.toEqual({
      status: 'staged',
    });
    const activationResult = await resume(
      activationFixture,
      activationStore,
      secondJournal,
      secondAnchor,
    );
    expect(activationResult).toMatchObject({ status: 'active' });
  });

  it('resumes after publication reconciliation, anchor persistence, and active marking', async () => {
    const publishedFixture = await makeFixture();
    const publishedStore = new FakeMigrationStore();
    publishedStore.installActive(publishedFixture.prepared);
    await expect(stage(publishedFixture)).resolves.toEqual({ status: 'staged' });
    await expect(resume(publishedFixture, publishedStore)).resolves.toMatchObject({
      status: 'active',
    });

    const anchoredFixture = await makeFixture();
    const anchoredStore = new FakeMigrationStore();
    anchoredStore.installActive(anchoredFixture.prepared);
    const anchoredJournal = join(directory, 'anchored.journal');
    const anchoredAnchor = join(directory, 'anchored.anchor');
    await expect(stage(anchoredFixture, anchoredJournal)).resolves.toEqual({
      status: 'staged',
    });
    await reconcileCollaborationMigrationPublication(
      anchoredJournal,
      anchoredFixture.protectionSecret,
      anchoredFixture.prepared.proposedOutcome,
    );
    await createRecipientRollbackAnchor(
      anchoredAnchor,
      anchoredFixture.protectionSecret,
      anchoredFixture.prepared.candidateAnchor,
    );
    await expect(
      resume(anchoredFixture, anchoredStore, anchoredJournal, anchoredAnchor),
    ).resolves.toMatchObject({ status: 'active' });

    const authorityOnlyFixture = await makeFixture();
    const authorityOnlyStore = new FakeMigrationStore();
    authorityOnlyStore.installActive(authorityOnlyFixture.prepared);
    const authorityOnlyJournal = join(directory, 'authority-only.journal');
    const authorityOnlyRecipientAnchor = join(
      directory,
      'authority-only-recipient.anchor',
    );
    await expect(stage(authorityOnlyFixture, authorityOnlyJournal)).resolves.toEqual({
      status: 'staged',
    });
    await reconcileCollaborationMigrationPublication(
      authorityOnlyJournal,
      authorityOnlyFixture.protectionSecret,
      authorityOnlyFixture.prepared.proposedOutcome,
    );
    await createCollaborationAuthorityRollbackAnchor(
      authorityOnlyFixture.authorityRollbackAnchorPath,
      authorityOnlyFixture.secrets.databaseRootKey,
      authorityAnchor(authorityOnlyFixture.prepared),
    );
    await expect(
      resume(
        authorityOnlyFixture,
        authorityOnlyStore,
        authorityOnlyJournal,
        authorityOnlyRecipientAnchor,
      ),
    ).resolves.toMatchObject({ status: 'active' });
    expect(
      await readRecipientRollbackAnchor(
        authorityOnlyRecipientAnchor,
        authorityOnlyFixture.protectionSecret,
        { expectedScope: anchorScope(authorityOnlyFixture.prepared) },
      ),
    ).toEqual(authorityOnlyFixture.prepared.candidateAnchor);

    const activeFixture = await makeFixture();
    const activeStore = new FakeMigrationStore();
    activeStore.installActive(activeFixture.prepared);
    const activeJournal = join(directory, 'active.journal');
    const activeAnchor = join(directory, 'active.anchor');
    await expect(stage(activeFixture, activeJournal)).resolves.toEqual({
      status: 'staged',
    });
    await reconcileCollaborationMigrationPublication(
      activeJournal,
      activeFixture.protectionSecret,
      activeFixture.prepared.proposedOutcome,
    );
    await createRecipientRollbackAnchor(
      activeAnchor,
      activeFixture.protectionSecret,
      activeFixture.prepared.candidateAnchor,
    );
    await createCollaborationAuthorityRollbackAnchor(
      activeFixture.authorityRollbackAnchorPath,
      activeFixture.secrets.databaseRootKey,
      authorityAnchor(activeFixture.prepared),
    );
    await markCollaborationMigrationAnchored(
      activeJournal,
      activeFixture.protectionSecret,
      activeAnchor,
      anchorScope(activeFixture.prepared),
      activeFixture.authorityRollbackAnchorPath,
      activeFixture.secrets.databaseRootKey,
      authorityAnchorScope(activeFixture.prepared),
    );
    await expect(
      resume(activeFixture, activeStore, activeJournal, activeAnchor),
    ).resolves.toMatchObject({ status: 'active' });
    expect(activeStore.events).toContain('activate');
  });

  it('fails closed for changed immutable bundle components and anchor bytes', async () => {
    const fixture = await makeFixture();
    const receipt = fixture.prepared.proposedOutcome.signedMutationReceipt;
    if (receipt === undefined) throw new Error('fixture outcome is not committed');
    const changedValues: PreparedCollaborativeGenesis[] = [
      {
        ...fixture.prepared,
        request: {
          ...fixture.prepared.request,
          ownerSignature: mutateBase64(fixture.prepared.request.ownerSignature),
        },
      },
      {
        ...fixture.prepared,
        candidate: {
          ...fixture.prepared.candidate,
          encryptedPayload: {
            ...fixture.prepared.candidate.encryptedPayload,
            ciphertext: mutateBase64(
              fixture.prepared.candidate.encryptedPayload.ciphertext,
            ),
          },
        },
      },
      {
        ...fixture.prepared,
        proofEntry: {
          ...fixture.prepared.proofEntry,
          link: {
            ...fixture.prepared.proofEntry.link,
            writerSignature: {
              ...fixture.prepared.proofEntry.link.writerSignature,
              signature: mutateBase64(
                fixture.prepared.proofEntry.link.writerSignature.signature,
              ),
            },
          },
        },
      },
      {
        ...fixture.prepared,
        proposedOutcome: {
          ...fixture.prepared.proposedOutcome,
          signedMutationReceipt: {
            ...receipt,
            receiptSignature: mutateBase64(receipt.receiptSignature),
          },
        },
      },
      {
        ...fixture.prepared,
        initialOwnerIdentity: {
          ...fixture.prepared.initialOwnerIdentity,
          selfSignature: mutateBase64(
            fixture.prepared.initialOwnerIdentity.selfSignature,
          ),
        },
      },
      {
        ...fixture.prepared,
        candidateAnchor: {
          ...fixture.prepared.candidateAnchor,
          membershipDigest: digest(91),
        },
      },
    ];
    for (const [index, changed] of changedValues.entries()) {
      await expect(
        orchestrateCollaborativeGenesisMigration({
          store: new FakeMigrationStore(),
          prepared: changed,
          databaseRootKey: fixture.secrets.databaseRootKey,
          deviceProtectionSecret: fixture.protectionSecret,
          migrationJournalPath: join(directory, `changed-${String(index)}.journal`),
          legacyDatabaseRevisionAnchorPath: fixture.legacyDatabaseRevisionAnchorPath,
          authorityRollbackAnchorPath: join(
            directory,
            `changed-${String(index)}.authority-anchor`,
          ),
          rollbackAnchorPath: join(directory, `changed-${String(index)}.anchor`),
        }),
      ).rejects.toBeInstanceOf(CollaborationMigrationOrchestrationError);
    }

    const anchorStore = new FakeMigrationStore();
    anchorStore.installActive(fixture.prepared);
    const mismatchedAnchor = {
      ...fixture.prepared.candidateAnchor,
      membershipDigest: digest(92),
    };
    await createCollaborationMigrationJournal(
      journalPath(),
      fixture.protectionSecret,
      journalInput(fixture.prepared),
    );
    await reconcileCollaborationMigrationPublication(
      journalPath(),
      fixture.protectionSecret,
      fixture.prepared.proposedOutcome,
    );
    await createRecipientRollbackAnchor(
      anchorPath(),
      fixture.protectionSecret,
      mismatchedAnchor,
    );
    await expect(run(fixture, anchorStore)).resolves.toEqual({
      status: 'terminal',
      reason: 'anchor-mismatch',
    });
  });

  it('rejects a substituted logical-policy anchor before journaling or store mutation', async () => {
    const fixture = await makeFixture();
    const store = new FakeMigrationStore();
    const changed: PreparedCollaborativeGenesis = {
      ...fixture.prepared,
      candidateAnchor: {
        ...fixture.prepared.candidateAnchor,
        policyDigest: digest(94),
      },
    };

    await expect(
      orchestrateCollaborativeGenesisMigration({
        store,
        prepared: changed,
        databaseRootKey: fixture.secrets.databaseRootKey,
        deviceProtectionSecret: fixture.protectionSecret,
        migrationJournalPath: journalPath(),
        legacyDatabaseRevisionAnchorPath: fixture.legacyDatabaseRevisionAnchorPath,
        authorityRollbackAnchorPath: fixture.authorityRollbackAnchorPath,
        rollbackAnchorPath: anchorPath(),
      }),
    ).rejects.toMatchObject({
      name: 'CollaborationMigrationOrchestrationError',
      kind: 'invalid-input',
      safe: true,
      message: 'Collaborative vault migration failed.',
    });
    expect(store.events).toEqual([]);
    await expect(readFile(journalPath(), 'utf8')).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('rejects substituted remote candidate, proof link, and committed outcome', async () => {
    const fixture = await makeFixture();
    const candidateStore = new FakeMigrationStore();
    candidateStore.installActive(fixture.prepared);
    candidateStore.candidate = {
      ...fixture.prepared.candidate,
      encryptedPayload: {
        ...fixture.prepared.candidate.encryptedPayload,
        ciphertext: mutateBase64(
          fixture.prepared.candidate.encryptedPayload.ciphertext,
        ),
      },
    };
    await expect(
      orchestrateCollaborativeGenesisMigration({
        store: candidateStore,
        prepared: fixture.prepared,
        databaseRootKey: fixture.secrets.databaseRootKey,
        deviceProtectionSecret: fixture.protectionSecret,
        migrationJournalPath: join(directory, 'remote-candidate.journal'),
        legacyDatabaseRevisionAnchorPath: fixture.legacyDatabaseRevisionAnchorPath,
        authorityRollbackAnchorPath: join(
          directory,
          'remote-candidate.authority-anchor',
        ),
        rollbackAnchorPath: join(directory, 'remote-candidate.anchor'),
      }),
    ).resolves.toEqual({
      status: 'terminal',
      reason: 'remote-state-mismatch',
    });

    const proofStore = new FakeMigrationStore();
    proofStore.installActive(fixture.prepared);
    proofStore.proofLink = {
      ...fixture.prepared.proofEntry.link,
      writerSignature: {
        ...fixture.prepared.proofEntry.link.writerSignature,
        signature: mutateBase64(
          fixture.prepared.proofEntry.link.writerSignature.signature,
        ),
      },
    };
    await expect(
      orchestrateCollaborativeGenesisMigration({
        store: proofStore,
        prepared: fixture.prepared,
        databaseRootKey: fixture.secrets.databaseRootKey,
        deviceProtectionSecret: fixture.protectionSecret,
        migrationJournalPath: join(directory, 'remote-proof.journal'),
        legacyDatabaseRevisionAnchorPath: fixture.legacyDatabaseRevisionAnchorPath,
        authorityRollbackAnchorPath: join(directory, 'remote-proof.authority-anchor'),
        rollbackAnchorPath: join(directory, 'remote-proof.anchor'),
      }),
    ).resolves.toEqual({
      status: 'terminal',
      reason: 'remote-state-mismatch',
    });

    const receipt = fixture.prepared.proposedOutcome.signedMutationReceipt;
    if (receipt === undefined) throw new Error('fixture outcome is not committed');
    const outcomeStore = new FakeMigrationStore();
    outcomeStore.installActive(fixture.prepared);
    outcomeStore.outcome = {
      ...fixture.prepared.proposedOutcome,
      signedMutationReceipt: {
        ...receipt,
        receiptSignature: mutateBase64(receipt.receiptSignature),
      },
    };
    await expect(
      orchestrateCollaborativeGenesisMigration({
        store: outcomeStore,
        prepared: fixture.prepared,
        databaseRootKey: fixture.secrets.databaseRootKey,
        deviceProtectionSecret: fixture.protectionSecret,
        migrationJournalPath: join(directory, 'remote-outcome.journal'),
        legacyDatabaseRevisionAnchorPath: fixture.legacyDatabaseRevisionAnchorPath,
        authorityRollbackAnchorPath: join(directory, 'remote-outcome.authority-anchor'),
        rollbackAnchorPath: join(directory, 'remote-outcome.anchor'),
      }),
    ).resolves.toEqual({
      status: 'terminal',
      reason: 'remote-outcome-invalid',
    });
  });

  it('terminalizes only an authenticated incompatible committed outcome', async () => {
    const fixture = await makeFixture();
    const store = new FakeMigrationStore();
    store.outcome = await incompatibleCommittedOutcome(
      fixture.prepared,
      fixture.secrets.writerSigning.privateKey,
    );

    await expect(stage(fixture)).resolves.toEqual({ status: 'staged' });
    await expect(resume(fixture, store)).resolves.toEqual({
      status: 'terminal',
      reason: 'journal-failed',
    });
    expect(
      (
        await readCollaborationMigrationJournal(
          journalPath(),
          fixture.protectionSecret,
          { expectedScope: journalScope(fixture.prepared) },
        )
      )?.state,
    ).toBe('failed');

    const retryFixture = await makeFixture();
    const retryStore = new FakeMigrationStore();
    retryStore.outcome = durableOperationOutcomeSchema.parse({
      ...retryFixture.prepared.proposedOutcome,
      state: 'conflicted',
      committedTuple: undefined,
      committedHeadDigest: undefined,
      finalizedMutationLinkDigest: undefined,
      committedAt: undefined,
      signedMutationReceipt: undefined,
      outcomeDigest: digest(93),
    });
    const retryJournal = join(directory, 'retry.journal');
    const retryAnchor = join(directory, 'retry.anchor');
    await expect(stage(retryFixture, retryJournal)).resolves.toEqual({
      status: 'staged',
    });
    await expect(
      resume(retryFixture, retryStore, retryJournal, retryAnchor),
    ).resolves.toEqual({ status: 'retryable', reason: 'conflict' });
    expect(
      (
        await readCollaborationMigrationJournal(
          retryJournal,
          retryFixture.protectionSecret,
          { expectedScope: journalScope(retryFixture.prepared) },
        )
      )?.state,
    ).toBe('prepared');
  });

  it('never persists plaintext, the manifest, the VRK, or the protection secret', async () => {
    const fixture = await makeFixture();
    const store = new FakeMigrationStore();
    const privateKeyCanary = Buffer.from(
      fixture.secrets.writerEncryption.privateKey,
    ).toString('base64url');
    await expect(stage(fixture)).resolves.toEqual({ status: 'staged' });
    zeroize(fixture.prepared.vaultRootKey);
    const result = await resume(fixture, store);
    expect(result).toMatchObject({ status: 'active' });

    const journalBytes = await readFile(journalPath(), 'utf8');
    const serializedCalls = store.serializedMutationCalls.join('\n');
    const forbidden = [
      PLAINTEXT_CANARY,
      canonicalJson(fixture.prepared.initialManifest),
      ROOT_KEY_CANARY.toString('utf8'),
      ROOT_KEY_CANARY.toString('base64url'),
      PROTECTION_CANARY,
      Buffer.from(fixture.protectionSecret).toString('base64url'),
      privateKeyCanary,
    ];
    for (const canary of forbidden) {
      expect(journalBytes).not.toContain(canary);
      expect(serializedCalls).not.toContain(canary);
    }
  });
});
