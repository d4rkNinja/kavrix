import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  COLLABORATION_DOMAINS,
  computeCollaborativeVaultDestructionActionDigest,
  computeDatabaseVaultPayloadMetadataDigest,
  computeDeviceRegistryDigest,
  computeEncryptedMembershipDigest,
  computeFinalizedMutationLinkDigest,
  computeMembershipHistoryCompactionDigest,
  computeMembershipHistoryDigest,
  computeMembershipManifestDigest,
  computeMutationRequestDigest,
  computePublicKeyFingerprint,
  decryptCollaborationEnvelope,
  deriveDatabaseAuthorityRecoveryKeyPair,
  encryptPayload,
  generateDatabaseRootKey,
  generateDeviceEncryptionKeyPair,
  generateDeviceSigningKeyPair,
  generatePrincipalSigningKeyPair,
  generateVaultRootKey,
  signCollaborationRecord,
  verifyCollaborationRecord,
  verifyCommittedOperationOutcome,
  verifyDiscoveryRecord,
  verifyFinalizedMutationLink,
  wrapVaultRootForDatabase,
  zeroize,
  type CollaborationEncryptionKeyPair,
  type DatabaseAuthorityRecoveryKeyPair,
  type DatabaseRootKey,
  type DeviceSigningKeyPair,
  type PrincipalSigningKeyPair,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  readCollaborativeVaultDestructionJournal,
  readRecipientVaultDestructionAnchor,
  writeDatabaseRevisionAnchor,
} from '@kavrix/key-files';
import {
  associatedDataSchema,
  canonicalJson,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationMigrationRequestSchema,
  collaborationVaultDestructionActionSchema,
  collaborativeMembershipManifestSchema,
  databaseAssociatedDataSchema,
  databaseVaultDocumentSchema,
  deviceCertificateSchema,
  MAX_COLLABORATIVE_HISTORY_EVENTS,
  membershipHistoryCheckpointSchema,
  membershipHistoryEventSchema,
  membershipHistorySchema,
  publicIdentityExportSchema,
  sha256DigestSchema,
  timestampSchema,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationVaultDestructionTombstone,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DatabaseVaultDocument,
  type DeviceCertificate,
  type DurableOperationOutcome,
  type PublicIdentityExport,
  type Sha256Digest,
} from '@kavrix/schemas';
import type { CollaborativeVaultStore } from '@kavrix/storage';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as KeyFilesModule from '@kavrix/key-files';
import type * as StateVerifierModule from '../src/collaboration-state-verifier.js';
import {
  buildCollaborativeGenesis,
  type BuildCollaborativeGenesisInput,
} from '../src/collaboration-genesis-builder.js';

const verifier = vi.hoisted(() => ({ open: vi.fn() }));
const protectedState = vi.hoisted(() => ({
  journals: new Map<string, Record<string, unknown>>(),
  anchors: new Map<string, unknown>(),
  databaseAnchors: new Map<
    string,
    Readonly<{ key: string; anchor: Record<string, unknown> }>
  >(),
  moduleExports: undefined as Record<string, unknown> | undefined,
}));

function exact(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

vi.mock('@kavrix/key-files', async (importOriginal) => {
  const actual = await importOriginal<typeof KeyFilesModule>();
  const mocked = {
    ...actual,
    createCollaborativeVaultDestructionJournal: vi.fn(
      (
        path: string,
        _secret: Uint8Array,
        input: Readonly<{
          tombstone: CollaborationVaultDestructionTombstone;
          proposedOutcome: DurableOperationOutcome;
          recipientAnchor: unknown;
          createdAt?: string;
        }>,
      ) => {
        const existing = protectedState.journals.get(path);
        const commitment = input.tombstone.proofEntry.link.commitment;
        const createdAt = input.createdAt ?? input.tombstone.core.destroyedAt;
        const prepared = {
          format: 'kavrix-collaborative-vault-destruction-journal',
          version: 1,
          state: 'prepared',
          databaseId: input.tombstone.databaseId,
          vaultId: input.tombstone.vaultId,
          operationId: input.tombstone.core.operationId,
          requestDigest: commitment.requestDigest,
          actorPrincipalId: input.tombstone.core.actorPrincipalId,
          actorDeviceId: input.tombstone.core.actorDeviceId,
          actionParametersDigest: input.tombstone.core.actionParametersDigest,
          tombstone: structuredClone(input.tombstone),
          proposedOutcome: structuredClone(input.proposedOutcome),
          recipientAnchor: structuredClone(input.recipientAnchor),
          createdAt,
          updatedAt: createdAt,
        };
        if (existing !== undefined && !exact(existing, prepared)) {
          return Promise.reject(new Error('foreign destruction journal'));
        }
        protectedState.journals.set(path, prepared);
        return Promise.resolve();
      },
    ),
    readCollaborativeVaultDestructionJournal: vi.fn((path: string) => {
      const record = protectedState.journals.get(path);
      return Promise.resolve(record === undefined ? null : structuredClone(record));
    }),
    reconcileCollaborativeVaultDestructionJournal: vi.fn(
      (
        path: string,
        _secret: Uint8Array,
        evidence: Readonly<{
          tombstone: CollaborationVaultDestructionTombstone;
          outcome: DurableOperationOutcome;
        }>,
      ) => {
        const current = protectedState.journals.get(path);
        if (
          current === undefined ||
          !exact(current['tombstone'], evidence.tombstone) ||
          !exact(current['proposedOutcome'], evidence.outcome)
        ) {
          return Promise.reject(new Error('invalid committed evidence'));
        }
        protectedState.journals.set(path, {
          ...current,
          state: 'committed',
          updatedAt: evidence.tombstone.core.destroyedAt,
        });
        return Promise.resolve();
      },
    ),
    verifyCommittedCollaborativeVaultDestructionJournal: vi.fn((path: string) => {
      const current = protectedState.journals.get(path);
      return current?.['state'] === 'committed'
        ? Promise.resolve(structuredClone(current))
        : Promise.reject(new Error('journal is not committed'));
    }),
    createOrVerifyRecipientVaultDestructionAnchor: vi.fn(
      (path: string, _secret: Uint8Array, anchor: unknown) => {
        const current = protectedState.anchors.get(path);
        if (current !== undefined && !exact(current, anchor)) {
          return Promise.reject(new Error('foreign destruction anchor'));
        }
        protectedState.anchors.set(path, structuredClone(anchor));
        return Promise.resolve();
      },
    ),
    readRecipientVaultDestructionAnchor: vi.fn((path: string) => {
      const anchor = protectedState.anchors.get(path);
      return anchor === undefined
        ? Promise.reject(new Error('missing destruction anchor'))
        : Promise.resolve(structuredClone(anchor));
    }),
    writeDatabaseRevisionAnchor: vi.fn(
      (
        path: string,
        databaseRootKey: Uint8Array,
        anchor: Record<string, unknown>,
        mode: 'create' | 'replace',
      ) => {
        if (mode === 'create' && protectedState.databaseAnchors.has(path)) {
          return Promise.reject(new Error('database anchor already exists'));
        }
        protectedState.databaseAnchors.set(path, {
          key: Buffer.from(databaseRootKey).toString('base64url'),
          anchor: structuredClone(anchor),
        });
        return Promise.resolve();
      },
    ),
    readDatabaseRevisionAnchor: vi.fn((path: string, databaseRootKey: Uint8Array) => {
      const stored = protectedState.databaseAnchors.get(path);
      if (stored?.key !== Buffer.from(databaseRootKey).toString('base64url')) {
        return Promise.reject(new Error('database anchor unavailable'));
      }
      return Promise.resolve(structuredClone(stored.anchor));
    }),
  };
  protectedState.moduleExports = mocked;
  return mocked;
});

vi.mock('../src/collaboration-state-verifier.js', async (importOriginal) => ({
  ...(await importOriginal<typeof StateVerifierModule>()),
  openCollaborativeVaultWithPinnedTrust: verifier.open,
}));

import {
  CollaborationVaultDestructionError,
  destroyCollaborativeVaultWithPinnedTrust,
  type DestroyCollaborativeVaultWithPinnedTrustInput,
} from '../src/collaboration-destruction-service.js';

const DATABASE_ID = 'database-destruction-service';
const VAULT_ID = 'vault-destruction-service';
const OWNER_ID = 'principal-destruction-owner';
const OWNER_DEVICE_ID = 'device-destruction-owner';
const OWNER_MEMBERSHIP_ID = 'membership-destruction-owner';
const LEGACY_AT = timestampSchema.parse('2026-08-29T00:00:00.000Z');
const REQUESTED_AT = timestampSchema.parse('2026-08-29T00:01:00.000Z');
const PREPARED_AT = timestampSchema.parse('2026-08-29T00:02:00.000Z');
const ACTIVATED_AT = timestampSchema.parse('2026-08-29T00:03:00.000Z');
const DESTROYED_AT = timestampSchema.parse('2026-08-29T00:20:00.000Z');
const EXPIRES_AT = timestampSchema.parse('2026-08-29T00:30:00.000Z');
const RETAINED_UNTIL = timestampSchema.parse('2026-09-29T00:20:00.000Z');
const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');
const PAYLOAD = Buffer.from(
  canonicalJson({
    records: {
      destruction: {
        updatedAt: LEGACY_AT,
        value: 'destruction-plaintext-payload-canary',
      },
    },
  }),
  'utf8',
);
const PROTECTION_SECRET = Uint8Array.from({ length: 32 }, (_, index) => 201 - index);
const RUN_PROTECTED_COMPOSITION =
  process.env['KAVRIX_RUN_PROTECTED_DESTRUCTION_COMPOSITION'] === 'true';

type OwnedSecrets = Readonly<{
  ownerRoot: PrincipalSigningKeyPair;
  ownerSigning: DeviceSigningKeyPair;
  ownerEncryption: CollaborationEncryptionKeyPair;
  authoritySigning: PrincipalSigningKeyPair;
  authorityRecovery: DatabaseAuthorityRecoveryKeyPair;
  databaseRootKey: DatabaseRootKey;
  legacyVaultRootKey: VaultRootKey;
}>;

type Fixture = Readonly<{
  document: CollaborativeVaultDocument;
  manifest: CollaborativeMembershipManifest;
  registry: CollaborationDatabaseDeviceRegistry;
  actorMembership: CollaborativeMembershipManifest['memberships'][number];
  actorDevice: DeviceCertificate;
  vaultRootKey: VaultRootKey;
  secrets: OwnedSecrets;
}>;

type PublishedArtifacts = Readonly<{
  tombstone: CollaborationVaultDestructionTombstone;
  outcome: DurableOperationOutcome;
}>;

const fixtures: Fixture[] = [];
const exposedSecrets: Uint8Array[] = [];
let pathCounter = 0;
let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-destruction-service-'));
  verifier.open.mockReset();
  protectedState.journals.clear();
  protectedState.anchors.clear();
  protectedState.databaseAnchors.clear();
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
  for (const secret of exposedSecrets.splice(0)) zeroize(secret);
  for (const fixture of fixtures.splice(0)) {
    zeroize(fixture.vaultRootKey);
    zeroize(fixture.secrets.ownerRoot.privateKey);
    zeroize(fixture.secrets.ownerSigning.privateKey);
    zeroize(fixture.secrets.ownerEncryption.privateKey);
    zeroize(fixture.secrets.authoritySigning.privateKey);
    zeroize(fixture.secrets.authorityRecovery.privateKey);
    zeroize(fixture.secrets.databaseRootKey);
    zeroize(fixture.secrets.legacyVaultRootKey);
  }
});

class MemoryDestructionStore {
  live: CollaborativeVaultDocument | null;
  tombstone: CollaborationVaultDestructionTombstone | null = null;
  outcome: DurableOperationOutcome | null = null;
  destroyCalls = 0;
  captured: PublishedArtifacts | undefined;
  commitThenThrow = false;
  throwWithoutCommit = false;
  beforePublish: ((artifacts: PublishedArtifacts) => Promise<void>) | undefined;

  constructor(document: CollaborativeVaultDocument) {
    this.live = document;
  }

  async destroyCollaborativeVault(artifacts: PublishedArtifacts): Promise<unknown> {
    this.destroyCalls += 1;
    this.captured = structuredClone(artifacts);
    await this.beforePublish?.(artifacts);
    if (this.throwWithoutCommit) throw new Error('ambiguous publication');
    this.live = null;
    this.tombstone = structuredClone(artifacts.tombstone);
    this.outcome = structuredClone(artifacts.outcome);
    if (this.commitThenThrow) throw new Error('ambiguous committed publication');
    return artifacts.outcome;
  }

  getCollaborativeVault(): Promise<CollaborativeVaultDocument | null> {
    return Promise.resolve(this.live === null ? null : structuredClone(this.live));
  }

  getCollaborativeVaultDestructionTombstone(): Promise<CollaborationVaultDestructionTombstone | null> {
    return Promise.resolve(
      this.tombstone === null ? null : structuredClone(this.tombstone),
    );
  }

  getCollaborativeOperationOutcome(): Promise<DurableOperationOutcome | null> {
    return Promise.resolve(
      this.outcome === null ? null : structuredClone(this.outcome),
    );
  }
}

function digest(fill: number): Sha256Digest {
  return sha256DigestSchema.parse(Buffer.alloc(32, fill).toString('base64url'));
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('Incomplete destruction test fixture');
  return value;
}

function manifestAtHistoryCapacity(fixture: Fixture): CollaborativeMembershipManifest {
  const initialEvent = required(fixture.manifest.history.events[0]);
  const events = Array.from({ length: MAX_COLLABORATIVE_HISTORY_EVENTS }, (_, index) =>
    index === 0
      ? initialEvent
      : membershipHistoryEventSchema.parse({
          ...initialEvent,
          operationId: collaborationMigrationRequestSchema.shape.operationId.parse(
            `capacity-history-${String(index).padStart(3, '0')}`,
          ),
        }),
  );
  const historyInput = {
    ...fixture.manifest.history,
    events,
    currentHistoryDigest: PLACEHOLDER_DIGEST,
  };
  const history = membershipHistorySchema.parse({
    ...historyInput,
    currentHistoryDigest: computeMembershipHistoryDigest(historyInput),
  });
  const manifestInput = {
    ...fixture.manifest,
    history,
    membershipDigest: PLACEHOLDER_DIGEST,
  };
  return collaborativeMembershipManifestSchema.parse({
    ...manifestInput,
    membershipDigest: computeMembershipManifestDigest(manifestInput),
  });
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

async function makeCertificate(
  root: PrincipalSigningKeyPair,
  signing: DeviceSigningKeyPair,
  encryption: CollaborationEncryptionKeyPair,
): Promise<DeviceCertificate> {
  return signedRecord(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    {
      protocolVersion: 1,
      principalId: OWNER_ID,
      deviceId: OWNER_DEVICE_ID,
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

async function legacyVault(
  databaseRootKey: DatabaseRootKey,
  legacyVaultRootKey: VaultRootKey,
): Promise<ReturnType<typeof databaseVaultDocumentSchema.parse>> {
  const metadata = {
    databaseId: DATABASE_ID,
    id: VAULT_ID,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    databaseRevision: 9,
    revision: 4,
    createdAt: LEGACY_AT,
    updatedAt: LEGACY_AT,
  } as const;
  const payloadMetadataDigest = computeDatabaseVaultPayloadMetadataDigest(
    metadata as DatabaseVaultDocument,
    legacyVaultRootKey,
    PAYLOAD,
  );
  const wrappedVaultRoot = await wrapVaultRootForDatabase(
    legacyVaultRootKey,
    databaseRootKey,
    databaseAssociatedDataSchema.parse({
      version: 1,
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      entityType: 'wrapped-vault-root',
      entityId: VAULT_ID,
      purpose: 'vault-root',
      schemaVersion: 1,
      keyVersion: 1,
      revision: 9,
      metadataDigest: payloadMetadataDigest,
    }),
  );
  const encryptedPayload = await encryptPayload(
    PAYLOAD,
    legacyVaultRootKey,
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType: 'vault-preferences',
      entityId: VAULT_ID,
      purpose: 'vault-preferences',
      revision: 4,
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

async function buildFixture(): Promise<Fixture> {
  const ownerRoot = await generatePrincipalSigningKeyPair();
  const ownerSigning = await generateDeviceSigningKeyPair();
  const ownerEncryption = await generateDeviceEncryptionKeyPair();
  const authoritySigning = await generatePrincipalSigningKeyPair();
  const databaseRootKey = generateDatabaseRootKey();
  const authorityRecovery = await deriveDatabaseAuthorityRecoveryKeyPair(
    databaseRootKey,
    DATABASE_ID,
    1,
  );
  const legacyVaultRootKey = generateVaultRootKey();
  const secrets = {
    ownerRoot,
    ownerSigning,
    ownerEncryption,
    authoritySigning,
    authorityRecovery,
    databaseRootKey,
    legacyVaultRootKey,
  };
  const actorDevice = await makeCertificate(ownerRoot, ownerSigning, ownerEncryption);
  const identityBase = {
    format: 'kavrix-collaborative-public-identity' as const,
    protocolVersion: 1 as const,
    principalId: OWNER_ID,
    identityGeneration: 1,
    rootSigningPublicKey: ownerRoot.publicKeyBase64,
    devices: [actorDevice],
    createdAt: LEGACY_AT,
    selfSignature: PLACEHOLDER_SIGNATURE,
  };
  const identity: PublicIdentityExport = await signedRecord(
    COLLABORATION_DOMAINS.publicIdentitySignature,
    identityBase,
    publicIdentityExportSchema,
    'selfSignature',
    ownerRoot.privateKey,
  );
  const authorityFingerprint = computePublicKeyFingerprint(
    authoritySigning.publicKeyBase64,
    'ed25519',
  );
  const registryBase = collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    authorityEpoch: 1,
    authorityFingerprint,
    generation: 3,
    previousRegistryDigest: digest(12),
    registryDigest: PLACEHOLDER_DIGEST,
    deniedDevices: [],
    updatedAt: REQUESTED_AT,
    authoritySignature: PLACEHOLDER_SIGNATURE,
  });
  const registryWithDigest = collaborationDatabaseDeviceRegistrySchema.parse({
    ...registryBase,
    registryDigest: computeDeviceRegistryDigest(registryBase),
  });
  const registry = await signedRecord(
    COLLABORATION_DOMAINS.deviceRegistrySignature,
    registryWithDigest,
    collaborationDatabaseDeviceRegistrySchema,
    'authoritySignature',
    authoritySigning.privateKey,
  );
  const legacySource = await legacyVault(databaseRootKey, legacyVaultRootKey);
  const legacyDatabaseRevisionAnchorPath = join(directory, 'legacy.database-anchor');
  await writeDatabaseRevisionAnchor(
    legacyDatabaseRevisionAnchorPath,
    databaseRootKey,
    {
      databaseId: legacySource.databaseId,
      databaseRevision: legacySource.databaseRevision,
      catalogMetadataDigest: digest(44),
      vaultHeads: {
        [legacySource.id]: {
          revision: legacySource.revision,
          metadataDigest: legacySource.payloadMetadataDigest,
        },
      },
    },
    'create',
  );
  const prepared = await buildCollaborativeGenesis({
    legacySource,
    legacyDatabaseRevisionAnchorPath,
    databaseRootKey,
    registryCandidate: registry,
    initialOwnerIdentity: identity,
    initialOwnerDeviceId: deviceCertificateSchema.shape.deviceId.parse(OWNER_DEVICE_ID),
    initialMembershipId:
      collaborativeMembershipManifestSchema.shape.memberships.element.shape.membershipId.parse(
        OWNER_MEMBERSHIP_ID,
      ),
    ownerDeviceSigningPrivateKey: ownerSigning.privateKey,
    authoritySigningPrivateKey: authoritySigning.privateKey,
    authoritySigningPublicKey: authoritySigning.publicKeyBase64,
    authoritySigningKeyFingerprint: authorityFingerprint,
    authorityRecoveryPublicKey: authorityRecovery.publicKeyBase64,
    authorityRecoveryKeyFingerprint: computePublicKeyFingerprint(
      authorityRecovery.publicKeyBase64,
      'x25519',
    ),
    authorityEpoch: 1 as BuildCollaborativeGenesisInput['authorityEpoch'],
    operationId: collaborationMigrationRequestSchema.shape.operationId.parse(
      'operation-destruction-genesis',
    ),
    requestedAt: REQUESTED_AT,
    preparedAt: PREPARED_AT,
    activatedAt: ACTIVATED_AT,
    transitionExpiresAt: EXPIRES_AT,
    anchorScope: {
      databaseId: legacySource.databaseId,
      vaultId: legacySource.id,
      principalId: identity.principalId,
      deviceId: actorDevice.deviceId,
    },
  });
  const fixture = {
    document: prepared.candidate,
    manifest: prepared.initialManifest,
    registry,
    actorMembership: required(prepared.initialManifest.memberships[0]),
    actorDevice,
    vaultRootKey: prepared.vaultRootKey,
    secrets,
  };
  fixtures.push(fixture);
  return fixture;
}

function makePaths(): {
  rollback: string;
  journal: string;
  anchor: string;
} {
  pathCounter += 1;
  return {
    rollback: `rollback-anchor-${String(pathCounter)}.json`,
    journal: `destruction-journal-${String(pathCounter)}.json`,
    anchor: `destruction-anchor-${String(pathCounter)}.json`,
  };
}

function exposeAuthenticatedPrior(
  fixture: Fixture,
  manifest: CollaborativeMembershipManifest = fixture.manifest,
): void {
  verifier.open.mockImplementation(() => {
    const vaultRootKey = Uint8Array.from(fixture.vaultRootKey);
    const decryptedPayload = Uint8Array.from(PAYLOAD);
    exposedSecrets.push(vaultRootKey, decryptedPayload);
    return Promise.resolve({
      document: fixture.document,
      manifest,
      recipientMembership: fixture.actorMembership,
      recipientDevice: fixture.actorDevice,
      vaultRootKey,
      decryptedPayload,
    });
  });
}

function destructionInput(
  fixture: Fixture,
  store: MemoryDestructionStore,
  paths: ReturnType<typeof makePaths>,
  overrides: Partial<DestroyCollaborativeVaultWithPinnedTrustInput> = {},
): DestroyCollaborativeVaultWithPinnedTrustInput {
  return {
    store: store as unknown as CollaborativeVaultStore,
    document: fixture.document,
    authoritativeDeviceRegistry: fixture.registry,
    trusted: {} as DestroyCollaborativeVaultWithPinnedTrustInput['trusted'],
    scope: {
      databaseId: fixture.document.databaseId,
      vaultId: fixture.document.vaultId,
      principalId: fixture.actorMembership.principalId,
      deviceId: fixture.actorDevice.deviceId,
    },
    recipientEncryptionPrivateKey: fixture.secrets.ownerEncryption.privateKey,
    deviceSigningPrivateKey: fixture.secrets.ownerSigning.privateKey,
    deviceProtectionSecret: PROTECTION_SECRET,
    rollbackAnchorPath: paths.rollback,
    destructionJournalPath: paths.journal,
    destructionAnchorPath: paths.anchor,
    operationId: collaborationMigrationRequestSchema.shape.operationId.parse(
      'operation-destroy-vault',
    ),
    destroyedAt: DESTROYED_AT,
    expiresAt: EXPIRES_AT,
    detailsRetainedUntil: RETAINED_UNTIL,
    ...overrides,
  };
}

describe('collaborative vault destruction service', () => {
  it('authenticates, journals before publication, builds exact terminal evidence, then anchors', async () => {
    const fixture = await buildFixture();
    const paths = makePaths();
    const store = new MemoryDestructionStore(fixture.document);
    exposeAuthenticatedPrior(fixture);
    store.beforePublish = async (artifacts) => {
      const prepared = await readCollaborativeVaultDestructionJournal(
        paths.journal,
        PROTECTION_SECRET,
      );
      expect(prepared?.state).toBe('prepared');
      expect(prepared?.tombstone).toStrictEqual(artifacts.tombstone);
      expect(protectedState.anchors.has(paths.anchor)).toBe(false);
    };
    const recipientKeyBefore = Uint8Array.from(
      fixture.secrets.ownerEncryption.privateKey,
    );
    const signerBefore = Uint8Array.from(fixture.secrets.ownerSigning.privateKey);
    const protectionBefore = Uint8Array.from(PROTECTION_SECRET);

    const result = await destroyCollaborativeVaultWithPinnedTrust(
      destructionInput(fixture, store, paths),
    );

    expect(store.destroyCalls, JSON.stringify(result)).toBe(1);
    expect(result.status).toBe('committed');
    if (result.status !== 'committed') throw new Error('Expected committed result');
    expect(result.disposition).toBe('published');
    expect(store.destroyCalls).toBe(1);
    expect(store.live).toBeNull();
    expect(result.tombstone).toStrictEqual(store.tombstone);
    expect(result.outcome).toStrictEqual(store.outcome);
    const action = collaborationVaultDestructionActionSchema.parse({
      protocolVersion: 1,
      operationType: 'destroy-vault',
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      destructionMode: 'irreversible',
    });
    const actionDigest = computeCollaborativeVaultDestructionActionDigest(action);
    expect(result.tombstone.core.actionParametersDigest).toBe(actionDigest);
    expect(result.outcome.requestDigest).toBe(
      result.tombstone.proofEntry.link.commitment.requestDigest,
    );
    expect(result.tombstone.core.terminalTuple.documentRevision).toBe(
      fixture.document.documentRevision + 1,
    );
    expect(result.tombstone.core.terminalTuple.membershipRevision).toBe(
      fixture.document.membershipRevision,
    );
    expect(result.tombstone.core.terminalTuple.authorizationStateDigest).toBe(
      fixture.document.authorizationStateDigest,
    );
    expect(
      await verifyFinalizedMutationLink(
        result.tombstone.proofEntry.link,
        fixture.actorDevice.signingPublicKey,
      ),
    ).toBe(true);
    expect(
      await verifyCommittedOperationOutcome(
        result.outcome,
        fixture.actorDevice.signingPublicKey,
      ),
    ).toBe(true);
    expect(result.tombstone.proofEntry.link.commitment.requestDigest).toBe(
      computeMutationRequestDigest(result.tombstone.proofEntry.link.commitment),
    );
    const witness = required(result.tombstone.proofEntry.authorizationWitness);
    expect(witness.finalizedMutationLinkDigest).toBe(
      computeFinalizedMutationLinkDigest(result.tombstone.proofEntry.link),
    );
    expect(witness.encryptedMembershipManifest.aad.documentRevision).toBe(
      fixture.document.documentRevision + 1,
    );
    expect(witness.encryptedMembershipManifest.aad.authorizationStateDigest).toBe(
      fixture.document.authorizationStateDigest,
    );
    expect(witness.encryptedMembershipDigest).toBe(
      computeEncryptedMembershipDigest(witness.encryptedMembershipManifest),
    );
    const manifestBytes = await decryptCollaborationEnvelope(
      witness.encryptedMembershipManifest,
      fixture.vaultRootKey,
      witness.encryptedMembershipManifest.aad,
    );
    const manifest = collaborativeMembershipManifestSchema.parse(
      JSON.parse(Buffer.from(manifestBytes).toString('utf8')),
    );
    zeroize(manifestBytes);
    expect(manifest.history.events.at(-1)?.eventType).toBe('vault-destroyed');
    expect(manifest.history.events.at(-1)?.operationId).toBe(
      result.tombstone.core.operationId,
    );
    for (const record of witness.discoveryRecords) {
      expect(
        await verifyDiscoveryRecord(record, fixture.actorDevice.signingPublicKey),
      ).toBe(true);
      expect(record.encryptedMembershipMetadataDigest).toBe(
        witness.encryptedMembershipDigest,
      );
    }
    const journal = await readCollaborativeVaultDestructionJournal(
      paths.journal,
      PROTECTION_SECRET,
    );
    expect(journal?.state).toBe('committed');
    const anchor = await readRecipientVaultDestructionAnchor(
      paths.anchor,
      PROTECTION_SECRET,
      destructionInput(fixture, store, paths).scope,
    );
    expect(anchor.outcomeDigest).toBe(result.tombstone.outcomeDigest);
    expect(anchor.terminalHeadDigest).toBe(result.tombstone.terminalHeadDigest);
    expect(fixture.secrets.ownerEncryption.privateKey).toEqual(recipientKeyBefore);
    expect(fixture.secrets.ownerSigning.privateKey).toEqual(signerBefore);
    expect(PROTECTION_SECRET).toEqual(protectionBefore);
    expect(exposedSecrets.every((secret) => secret.every((byte) => byte === 0))).toBe(
      true,
    );
    expect(canonicalJson(result)).not.toContain(PAYLOAD.toString('utf8'));
    expect(canonicalJson(journal)).not.toContain(PAYLOAD.toString('utf8'));
    expect(canonicalJson(anchor)).not.toContain(PAYLOAD.toString('utf8'));
  });

  it('reconciles an ambiguous committed publication and replays exact journal bytes', async () => {
    const fixture = await buildFixture();
    const paths = makePaths();
    const store = new MemoryDestructionStore(fixture.document);
    store.commitThenThrow = true;
    exposeAuthenticatedPrior(fixture);

    const first = await destroyCollaborativeVaultWithPinnedTrust(
      destructionInput(fixture, store, paths),
    );
    expect(store.destroyCalls, JSON.stringify(first)).toBe(1);
    expect(first).toStrictEqual(
      expect.objectContaining({
        status: 'committed',
        disposition: 'already-committed',
      }),
    );
    const exactTombstone = structuredClone(store.tombstone);
    const exactOutcome = structuredClone(store.outcome);

    const second = await destroyCollaborativeVaultWithPinnedTrust(
      destructionInput(fixture, store, paths),
    );

    expect(second).toStrictEqual(
      expect.objectContaining({
        status: 'committed',
        disposition: 'already-committed',
      }),
    );
    expect(store.destroyCalls).toBe(1);
    expect(store.tombstone).toStrictEqual(exactTombstone);
    expect(store.outcome).toStrictEqual(exactOutcome);
    expect(
      await readCollaborativeVaultDestructionJournal(paths.journal, PROTECTION_SECRET),
    ).toStrictEqual(
      expect.objectContaining({ state: 'committed', tombstone: exactTombstone }),
    );
  });

  it('compacts a capacity-bound authenticated history and replays its exact terminal checkpoint', async () => {
    const fixture = await buildFixture();
    const priorManifest = manifestAtHistoryCapacity(fixture);
    const paths = makePaths();
    const store = new MemoryDestructionStore(fixture.document);
    exposeAuthenticatedPrior(fixture, priorManifest);

    const first = await destroyCollaborativeVaultWithPinnedTrust(
      destructionInput(fixture, store, paths),
    );

    expect(first.status).toBe('committed');
    if (first.status !== 'committed') {
      throw new Error('Expected capacity-bound destruction commitment');
    }
    const witness = required(first.tombstone.proofEntry.authorizationWitness);
    const manifestBytes = await decryptCollaborationEnvelope(
      witness.encryptedMembershipManifest,
      fixture.vaultRootKey,
      witness.encryptedMembershipManifest.aad,
    );
    const terminalManifest = collaborativeMembershipManifestSchema.parse(
      JSON.parse(Buffer.from(manifestBytes).toString('utf8')),
    );
    zeroize(manifestBytes);
    expect(terminalManifest.history.events).toHaveLength(1);
    expect(terminalManifest.history.checkpoints).toHaveLength(1);
    const terminalEvent = required(terminalManifest.history.events[0]);
    const checkpoint = required(terminalManifest.history.checkpoints[0]);
    expect(terminalEvent.eventType).toBe('vault-destroyed');
    expect(terminalEvent.operationId).toBe(first.tombstone.core.operationId);
    expect(terminalEvent.previousDocumentRevision).toBe(
      fixture.document.documentRevision,
    );
    expect(terminalEvent.newDocumentRevision).toBe(
      fixture.document.documentRevision + 1,
    );
    expect(checkpoint.previousHeadDigest).toBe(fixture.document.headDigest);
    expect(checkpoint.compactedThroughRevision).toBe(
      fixture.document.membershipRevision,
    );
    expect(checkpoint.documentRevision).toBe(
      first.tombstone.core.terminalTuple.documentRevision,
    );
    expect(checkpoint.compactedHistoryDigest).toBe(
      computeMembershipHistoryCompactionDigest({
        protocolVersion: 1,
        databaseId: fixture.document.databaseId,
        vaultId: fixture.document.vaultId,
        authorityEpoch: fixture.document.authorityEpoch,
        compactingOperationId: first.tombstone.core.operationId,
        previousHeadDigest: fixture.document.headDigest,
        previousTuple: first.tombstone.core.priorTuple,
        priorHistory: priorManifest.history,
      }),
    );
    expect(terminalManifest.history.previousHistoryDigest).toBe(
      priorManifest.history.currentHistoryDigest,
    );
    expect(terminalManifest.history.currentHistoryDigest).toBe(
      computeMembershipHistoryDigest(terminalManifest.history),
    );
    expect(
      await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        terminalEvent,
        membershipHistoryEventSchema,
        'signature',
        fixture.actorDevice.signingPublicKey,
      ),
    ).toBe(true);
    expect(
      await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        fixture.actorDevice.signingPublicKey,
      ),
    ).toBe(true);

    const second = await destroyCollaborativeVaultWithPinnedTrust(
      destructionInput(fixture, store, paths),
    );
    expect(second).toStrictEqual(
      expect.objectContaining({
        status: 'committed',
        disposition: 'already-committed',
        tombstone: first.tombstone,
      }),
    );
    expect(store.destroyCalls).toBe(1);
  });

  it('rejects an inactive actor and a device-fenced actor before journaling', async () => {
    const fixture = await buildFixture();
    const paths = makePaths();
    const store = new MemoryDestructionStore(fixture.document);
    const inactiveDevice = deviceCertificateSchema.parse({
      ...fixture.actorDevice,
      state: 'revoked',
      stateChangedAt: ACTIVATED_AT,
      revokedAt: ACTIVATED_AT,
    });
    verifier.open.mockResolvedValue({
      document: fixture.document,
      manifest: fixture.manifest,
      recipientMembership: fixture.actorMembership,
      recipientDevice: inactiveDevice,
      vaultRootKey: Uint8Array.from(fixture.vaultRootKey),
      decryptedPayload: Uint8Array.from(PAYLOAD),
    });
    await expect(
      destroyCollaborativeVaultWithPinnedTrust(destructionInput(fixture, store, paths)),
    ).rejects.toStrictEqual(
      expect.objectContaining({
        name: 'CollaborationVaultDestructionError',
        kind: 'current-state-invalid',
      }),
    );
    expect(store.destroyCalls).toBe(0);
    expect(protectedState.journals.has(paths.journal)).toBe(false);

    const deniedRegistry = collaborationDatabaseDeviceRegistrySchema.parse({
      ...fixture.registry,
      deniedDevices: [
        {
          principalId: OWNER_ID,
          deviceId: OWNER_DEVICE_ID,
          deviceGeneration: fixture.actorDevice.deviceGeneration,
          signingKeyFingerprint: computePublicKeyFingerprint(
            fixture.actorDevice.signingPublicKey,
            'ed25519',
          ),
          reason: 'authority-fence',
          deniedAt: ACTIVATED_AT,
        },
      ],
    });
    exposeAuthenticatedPrior(fixture);
    await expect(
      destroyCollaborativeVaultWithPinnedTrust(
        destructionInput(fixture, store, paths, {
          authoritativeDeviceRegistry: deniedRegistry,
        }),
      ),
    ).rejects.toBeInstanceOf(CollaborationVaultDestructionError);
    expect(store.destroyCalls).toBe(0);
  });

  it.runIf(RUN_PROTECTED_COMPOSITION)(
    'composes real protected journal commitment and create-only destruction anchoring',
    async () => {
      const fixture = await buildFixture();
      const directory = await mkdtemp(
        join(tmpdir(), 'kavrix-real-destruction-service-'),
      );
      const realKeyFiles =
        await vi.importActual<typeof KeyFilesModule>('@kavrix/key-files');
      try {
        if (process.platform === 'win32') {
          await realKeyFiles.setWindowsUserOnlyAcl(directory);
        }
        const paths = {
          rollback: join(directory, 'rollback-anchor.json'),
          journal: join(directory, 'destruction-journal.json'),
          anchor: join(directory, 'destruction-anchor.json'),
        };
        const store = new MemoryDestructionStore(fixture.document);
        exposeAuthenticatedPrior(fixture);
        store.beforePublish = async (artifacts) => {
          const prepared = await realKeyFiles.readCollaborativeVaultDestructionJournal(
            paths.journal,
            PROTECTION_SECRET,
          );
          expect(prepared?.state).toBe('prepared');
          expect(prepared?.tombstone).toStrictEqual(artifacts.tombstone);
          await expect(
            realKeyFiles.readRecipientVaultDestructionAnchor(
              paths.anchor,
              PROTECTION_SECRET,
            ),
          ).rejects.toBeDefined();
        };

        vi.doUnmock('@kavrix/key-files');
        vi.resetModules();
        const realService = await import('../src/collaboration-destruction-service.js');
        const result = await realService.destroyCollaborativeVaultWithPinnedTrust(
          destructionInput(fixture, store, paths),
        );

        expect(result).toStrictEqual(
          expect.objectContaining({ status: 'committed', disposition: 'published' }),
        );
        if (result.status !== 'committed') {
          throw new Error('Expected real protected-boundary commitment');
        }
        const journal = await realKeyFiles.readCollaborativeVaultDestructionJournal(
          paths.journal,
          PROTECTION_SECRET,
        );
        expect(journal?.state).toBe('committed');
        expect(journal?.tombstone).toStrictEqual(result.tombstone);
        const anchor = await realKeyFiles.readRecipientVaultDestructionAnchor(
          paths.anchor,
          PROTECTION_SECRET,
          destructionInput(fixture, store, paths).scope,
        );
        expect(anchor).toStrictEqual(
          realKeyFiles.recipientVaultDestructionAnchorFromTombstone(
            result.tombstone,
            destructionInput(fixture, store, paths).scope,
          ),
        );
      } finally {
        const mockedExports = protectedState.moduleExports;
        if (mockedExports !== undefined) {
          vi.doMock('@kavrix/key-files', () => mockedExports);
        }
        vi.resetModules();
        await rm(directory, { recursive: true, force: true });
      }
    },
  );
});
