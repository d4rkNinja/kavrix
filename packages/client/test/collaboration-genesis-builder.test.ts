import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  COLLABORATION_DOMAINS,
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
  computeAuthorityDelegationDigest,
  computeDatabaseVaultPayloadMetadataDigest,
  computeDeviceRegistryDigest,
  computeFinalizedMutationLinkDigest,
  computeLegacySourceDigest,
  computeMembershipStateDigest,
  computeMigrationRequestDigest,
  computeMutationHead,
  computePolicyDigest,
  computePolicyStateDigest,
  computePublicKeyFingerprint,
  decryptCollaborationEnvelope,
  deriveDatabaseAuthorityRecoveryKeyPair,
  encryptPayload,
  generateDatabaseRootKey,
  generateDeviceEncryptionKeyPair,
  generateDeviceSigningKeyPair,
  generatePrincipalSigningKeyPair,
  generateVaultRootKey,
  openCollaborationVaultRootForDatabaseAuthority,
  signCollaborationRecord,
  verifyAuthorityDelegation,
  verifyCommittedOperationOutcome,
  verifyDiscoveryRecord,
  verifyFinalizedMutationLink,
  verifyMigrationActiveMarker,
  verifyMigrationPreparedMarker,
  verifyMigrationRequestAuthority,
  verifyMigrationRequestOwner,
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
  collaborationMigrationJournalCreateInputSchema,
  writeDatabaseRevisionAnchor,
  type DatabaseRevisionAnchor,
} from '@kavrix/key-files';
import {
  associatedDataSchema,
  canonicalJson,
  collaborationAuthorizationStateCoreSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationMutationProofEntrySchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAssociatedDataSchema,
  databaseIdSchema,
  databaseRevisionSchema,
  databaseVaultPayloadSchema,
  databaseVaultDocumentSchema,
  deviceCertificateSchema,
  durableOperationOutcomeSchema,
  publicIdentityExportSchema,
  recipientRollbackAnchorSchema,
  sha256DigestSchema,
  timestampSchema,
  vaultRevisionSchema,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborativeMembershipManifest,
  type DatabaseVaultDocument,
  type DeviceCertificate,
  type PublicIdentityExport,
  type Sha256Digest,
} from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../key-files/dist/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(() => Promise.resolve()),
  verifyWindowsDirectoryAcl: vi.fn(() => Promise.resolve()),
  verifyWindowsUserOnlyAcl: vi.fn(() => Promise.resolve()),
}));

import {
  CollaborationGenesisPreparationError,
  buildCollaborativeGenesis,
  type BuildCollaborativeGenesisInput,
  type PreparedCollaborativeGenesis,
} from '../src/collaboration-genesis-builder.js';
import { requireExactDatabaseAuthorityRecoveryEnvelope } from '../src/collaboration-recovery-envelope-binding.js';

const DATABASE_ID = 'database-genesis-builder';
const VAULT_ID = 'vault-genesis-builder';
const PRINCIPAL_ID = 'principal-genesis-owner';
const WRITER_DEVICE_ID = 'device-genesis-writer';
const SECOND_DEVICE_ID = 'device-genesis-second';
const MEMBERSHIP_ID = 'membership-genesis-owner';
const LEGACY_AT = timestampSchema.parse('2026-08-29T00:00:00.000Z');
const REQUESTED_AT = timestampSchema.parse('2026-08-29T00:01:00.000Z');
const PREPARED_AT = timestampSchema.parse('2026-08-29T00:02:00.000Z');
const ACTIVATED_AT = timestampSchema.parse('2026-08-29T00:03:00.000Z');
const EXPIRES_AT = timestampSchema.parse('2026-08-29T00:12:00.000Z');
const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');
const PAYLOAD_CANARY = 'genesis-private-payload-canary';
const PAYLOAD = Buffer.from(
  canonicalJson({
    records: {
      genesis: { updatedAt: LEGACY_AT, value: PAYLOAD_CANARY },
    },
  }),
  'utf8',
);

type OwnedSecrets = Readonly<{
  root: PrincipalSigningKeyPair;
  writerSigning: DeviceSigningKeyPair;
  writerEncryption: CollaborationEncryptionKeyPair;
  secondSigning: DeviceSigningKeyPair;
  secondEncryption: CollaborationEncryptionKeyPair;
  authoritySigning: PrincipalSigningKeyPair;
  authorityRecovery: DatabaseAuthorityRecoveryKeyPair;
  databaseRootKey: DatabaseRootKey;
  legacyVaultRootKey: VaultRootKey;
}>;

type Fixture = Readonly<{
  input: BuildCollaborativeGenesisInput;
  identity: PublicIdentityExport;
  registry: CollaborationDatabaseDeviceRegistry;
  secrets: OwnedSecrets;
  generatedKey: Uint8Array;
  randomnessCalls: { count: number };
  legacyAnchorPath: string;
}>;

const cleanup: (OwnedSecrets | PreparedCollaborativeGenesis | Uint8Array)[] = [];
let directory = '';
let fixtureCounter = 0;

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-genesis-builder-'));
  fixtureCounter = 0;
});

afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
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
    zeroize(value.secondSigning.privateKey);
    zeroize(value.secondEncryption.privateKey);
    zeroize(value.authoritySigning.privateKey);
    zeroize(value.authorityRecovery.privateKey);
    zeroize(value.databaseRootKey);
    zeroize(value.legacyVaultRootKey);
  }
});

function digest(fill: number): Sha256Digest {
  return sha256DigestSchema.parse(Buffer.alloc(32, fill).toString('base64url'));
}

function mutateBase64(value: string): string {
  return `${value.startsWith('A') ? 'B' : 'A'}${value.slice(1)}`;
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
  deviceId: string,
): Promise<DeviceCertificate> {
  return signedRecord(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    {
      protocolVersion: 1,
      principalId: PRINCIPAL_ID,
      deviceId,
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

async function makeFixture(): Promise<Fixture> {
  const root = await generatePrincipalSigningKeyPair();
  const writerSigning = await generateDeviceSigningKeyPair();
  const writerEncryption = await generateDeviceEncryptionKeyPair();
  const secondSigning = await generateDeviceSigningKeyPair();
  const secondEncryption = await generateDeviceEncryptionKeyPair();
  const authoritySigning = await generatePrincipalSigningKeyPair();
  const databaseRootKey = generateDatabaseRootKey();
  const authorityRecovery = await deriveDatabaseAuthorityRecoveryKeyPair(
    databaseRootKey,
    DATABASE_ID,
    1,
  );
  const legacyVaultRootKey = generateVaultRootKey();
  const secrets = {
    root,
    writerSigning,
    writerEncryption,
    secondSigning,
    secondEncryption,
    authoritySigning,
    authorityRecovery,
    databaseRootKey,
    legacyVaultRootKey,
  };
  cleanup.push(secrets);
  const devices = [
    await makeCertificate(root, writerSigning, writerEncryption, WRITER_DEVICE_ID),
    await makeCertificate(root, secondSigning, secondEncryption, SECOND_DEVICE_ID),
  ];
  const identityBase = {
    format: 'kavrix-collaborative-public-identity' as const,
    protocolVersion: 1 as const,
    principalId: PRINCIPAL_ID,
    identityGeneration: 1,
    rootSigningPublicKey: root.publicKeyBase64,
    devices,
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
  const legacySource = await legacyVault(databaseRootKey, legacyVaultRootKey, PAYLOAD);
  const legacyAnchorPath = join(
    directory,
    `legacy-${String(fixtureCounter++)}.database-anchor`,
  );
  await writeDatabaseRevisionAnchor(
    legacyAnchorPath,
    databaseRootKey,
    legacyAnchor(legacySource),
    'create',
  );
  const generatedKey = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const randomnessCalls = { count: 0 };
  const input: BuildCollaborativeGenesisInput = {
    legacySource,
    legacyDatabaseRevisionAnchorPath: legacyAnchorPath,
    databaseRootKey,
    registryCandidate: registry,
    initialOwnerIdentity: identity,
    initialOwnerDeviceId:
      deviceCertificateSchema.shape.deviceId.parse(WRITER_DEVICE_ID),
    initialMembershipId:
      collaborativeMembershipManifestSchema.shape.memberships.element.shape.membershipId.parse(
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
    operationId: collaborationMigrationRequestSchema.shape.operationId.parse(
      'operation-genesis-builder',
    ),
    requestedAt: REQUESTED_AT,
    preparedAt: PREPARED_AT,
    activatedAt: ACTIVATED_AT,
    transitionExpiresAt: EXPIRES_AT,
    anchorScope: {
      databaseId: legacySource.databaseId,
      vaultId: legacySource.id,
      principalId: identity.principalId,
      deviceId: required(devices[0]).deviceId,
    },
    randomness: {
      generateVaultRootKey: () => {
        randomnessCalls.count += 1;
        return generatedKey;
      },
    },
  };
  return {
    input,
    identity,
    registry,
    secrets,
    generatedKey,
    randomnessCalls,
    legacyAnchorPath,
  };
}

async function legacyVault(
  databaseRootKey: DatabaseRootKey,
  legacyVaultRootKey: VaultRootKey,
  plaintext: Uint8Array,
  options: Readonly<{
    declaredPayloadMetadataDigest?: Sha256Digest;
    wrappedRootMetadataDigest?: Sha256Digest;
  }> = {},
): Promise<DatabaseVaultDocument> {
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
  const payloadMetadataDigest =
    options.declaredPayloadMetadataDigest ??
    computeDatabaseVaultPayloadMetadataDigest(
      metadata as DatabaseVaultDocument,
      legacyVaultRootKey,
      plaintext,
    );
  const wrappedVaultRoot = await wrapVaultRootForDatabase(
    legacyVaultRootKey,
    databaseRootKey,
    databaseAssociatedDataSchema.parse({
      version: 1,
      databaseId: DATABASE_ID,
      entityType: 'wrapped-vault-root' as const,
      entityId: VAULT_ID,
      purpose: 'vault-root' as const,
      schemaVersion: 1,
      keyVersion: 1,
      revision: 9,
      vaultId: VAULT_ID,
      metadataDigest: options.wrappedRootMetadataDigest ?? payloadMetadataDigest,
    }),
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

function legacyAnchor(source: DatabaseVaultDocument): DatabaseRevisionAnchor {
  return {
    databaseId: source.databaseId,
    databaseRevision: source.databaseRevision,
    catalogMetadataDigest: digest(63),
    vaultHeads: {
      [source.id]: {
        revision: source.revision,
        metadataDigest: source.payloadMetadataDigest,
      },
    },
  };
}

async function expectRejected(input: BuildCollaborativeGenesisInput): Promise<void> {
  await expect(buildCollaborativeGenesis(input)).rejects.toStrictEqual(
    expect.objectContaining({
      name: 'CollaborationGenesisPreparationError',
      message: 'Collaborative genesis preparation failed.',
      safe: true,
    }),
  );
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('Incomplete genesis test fixture');
  return value;
}

describe('collaboration genesis builder', () => {
  it('builds one complete exact genesis bundle and wipes generated randomness', async () => {
    const fixture = await makeFixture();
    const ownerKeyBefore = Uint8Array.from(fixture.secrets.writerSigning.privateKey);
    const authorityKeyBefore = Uint8Array.from(
      fixture.secrets.authoritySigning.privateKey,
    );
    const legacyVaultRootKeyBefore = Uint8Array.from(
      fixture.secrets.legacyVaultRootKey,
    );
    const databaseRootKeyBefore = Uint8Array.from(fixture.secrets.databaseRootKey);
    const prepared = await buildCollaborativeGenesis(fixture.input);
    cleanup.push(prepared);

    expect(fixture.randomnessCalls.count).toBe(1);
    expect(fixture.generatedKey.every((value) => value === 0)).toBe(true);
    expect([...prepared.vaultRootKey]).toStrictEqual(
      Array.from({ length: 32 }, (_, index) => index + 1),
    );
    expect(fixture.secrets.writerSigning.privateKey).toEqual(ownerKeyBefore);
    expect(fixture.secrets.authoritySigning.privateKey).toEqual(authorityKeyBefore);
    expect(fixture.secrets.legacyVaultRootKey).toEqual(legacyVaultRootKeyBefore);
    expect(fixture.secrets.databaseRootKey).toEqual(databaseRootKeyBefore);

    expect(collaborationMigrationRequestSchema.parse(prepared.request)).toStrictEqual(
      prepared.request,
    );
    expect(
      collaborationMigrationPreparedMarkerSchema.parse(prepared.preparedMarker),
    ).toStrictEqual(prepared.preparedMarker);
    expect(collaborativeVaultDocumentSchema.parse(prepared.candidate)).toStrictEqual(
      prepared.candidate,
    );
    expect(
      collaborativeMembershipManifestSchema.parse(prepared.initialManifest),
    ).toStrictEqual(prepared.initialManifest);
    expect(prepared.initialOwnerIdentity).toStrictEqual(fixture.identity);
    expect(
      collaborationMutationProofEntrySchema.parse(prepared.proofEntry),
    ).toStrictEqual(prepared.proofEntry);
    expect(durableOperationOutcomeSchema.parse(prepared.proposedOutcome)).toStrictEqual(
      prepared.proposedOutcome,
    );
    expect(recipientRollbackAnchorSchema.parse(prepared.candidateAnchor)).toStrictEqual(
      prepared.candidateAnchor,
    );
    expect(
      collaborationMigrationActiveMarkerSchema.parse(prepared.activeMarker),
    ).toStrictEqual(prepared.activeMarker);
    expect(
      collaborationMigrationJournalCreateInputSchema.parse(
        migrationJournalBundle(prepared),
      ),
    ).toStrictEqual(migrationJournalBundle(prepared));

    expect(prepared.request.requestDigest).toBe(
      computeMigrationRequestDigest(prepared.request),
    );
    expect(prepared.request.legacySourceDigest).toBe(
      computeLegacySourceDigest(fixture.input.legacySource),
    );
    expect(prepared.candidate.previousHeadDigest).toBe(
      COLLABORATION_GENESIS_HEAD_DIGEST,
    );
    expect(
      prepared.candidate.currentMutationLink.commitment
        .previousAuthorizationStateDigest,
    ).toBe(COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST);
    expect(prepared.initialManifest.previousMembershipDigest).toBe(
      COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
    );
    expect(prepared.initialManifest.history.previousHistoryDigest).toBe(
      COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
    );
    expect(prepared.initialManifest.history.compactedHistoryDigest).toBe(
      COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
    );
    const authorizationCore = authorizationCoreFromManifest(prepared.initialManifest);
    expect(prepared.candidateAnchor.membershipDigest).toBe(
      computeMembershipStateDigest(authorizationCore),
    );
    const substitutedMembershipCore = collaborationAuthorizationStateCoreSchema.parse({
      ...authorizationCore,
      memberships: authorizationCore.memberships.map((membership, index) =>
        index === 0
          ? { ...membership, identityGeneration: membership.identityGeneration + 1 }
          : membership,
      ),
    });
    expect(computeMembershipStateDigest(substitutedMembershipCore)).not.toBe(
      prepared.candidateAnchor.membershipDigest,
    );
    expect(prepared.initialManifest.policy.policyDigest).toBe(
      computePolicyDigest(prepared.initialManifest.policy),
    );
    expect(prepared.candidate.policyDigest).toBe(
      prepared.initialManifest.policy.policyDigest,
    );
    expect(prepared.candidateAnchor.policyDigest).toBe(
      computePolicyStateDigest(prepared.initialManifest.policy),
    );
    expect(prepared.initialManifest.keyEnvelopes).toHaveLength(3);
    expect(prepared.candidate.discoveryRecords).toHaveLength(2);
    expect(prepared.proofEntry.authorizationWitness?.databaseDeviceRegistry).toEqual(
      fixture.registry,
    );
    expect(computeMutationHead(prepared.candidate.currentMutationLink.commitment)).toBe(
      prepared.candidate.headDigest,
    );
    expect(
      computeAuthorityDelegationDigest(prepared.candidate.authorityDelegation),
    ).toBe(prepared.candidate.authorityDelegationDigest);
    expect(
      computeFinalizedMutationLinkDigest(prepared.candidate.currentMutationLink),
    ).toBe(prepared.proofEntry.authorizationWitness?.finalizedMutationLinkDigest);

    expect(
      await verifyMigrationRequestAuthority(
        prepared.request,
        fixture.secrets.authoritySigning.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyMigrationRequestOwner(
        prepared.request,
        fixture.secrets.writerSigning.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyAuthorityDelegation(
        prepared.candidate.authorityDelegation,
        fixture.secrets.authoritySigning.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyFinalizedMutationLink(
        prepared.candidate.currentMutationLink,
        fixture.secrets.writerSigning.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyCommittedOperationOutcome(
        prepared.proposedOutcome,
        fixture.secrets.writerSigning.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyMigrationPreparedMarker(
        prepared.preparedMarker,
        fixture.secrets.authoritySigning.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyMigrationActiveMarker(
        prepared.activeMarker,
        fixture.secrets.authoritySigning.publicKeyBase64,
      ),
    ).toBe(true);
    for (const record of prepared.candidate.discoveryRecords) {
      expect(
        await verifyDiscoveryRecord(
          record,
          fixture.secrets.writerSigning.publicKeyBase64,
        ),
      ).toBe(true);
    }

    const openedPayload = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedPayload,
      prepared.vaultRootKey,
      prepared.candidate.encryptedPayload.aad,
    );
    const openedManifest = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedMembershipManifest,
      prepared.vaultRootKey,
      prepared.candidate.encryptedMembershipManifest.aad,
    );
    expect(Buffer.from(openedPayload)).toEqual(PAYLOAD);
    expect(Buffer.from(openedManifest).toString('utf8')).toBe(
      canonicalJson(prepared.initialManifest),
    );
    zeroize(openedPayload);
    zeroize(openedManifest);

    const nonsecret = canonicalJson({
      request: prepared.request,
      preparedMarker: prepared.preparedMarker,
      registryCandidate: prepared.registryCandidate,
      candidate: prepared.candidate,
      initialManifest: prepared.initialManifest,
      initialOwnerIdentity: prepared.initialOwnerIdentity,
      proofEntry: prepared.proofEntry,
      proposedOutcome: prepared.proposedOutcome,
      candidateAnchor: prepared.candidateAnchor,
      activeMarker: prepared.activeMarker,
    });
    expect(nonsecret).not.toContain(PAYLOAD.toString('utf8'));
    expect(nonsecret).not.toContain(
      Buffer.from(fixture.secrets.writerSigning.privateKey).toString('base64url'),
    );
    expect(nonsecret).not.toContain(
      Buffer.from(fixture.secrets.authoritySigning.privateKey).toString('base64url'),
    );
    expect(nonsecret).not.toContain(
      Buffer.from(fixture.secrets.databaseRootKey).toString('base64url'),
    );
    expect(nonsecret).not.toContain(
      Buffer.from(fixture.secrets.authorityRecovery.privateKey).toString('base64url'),
    );
    expect(nonsecret).not.toContain(
      Buffer.from(prepared.vaultRootKey).toString('base64url'),
    );
    expect(Object.isFrozen(prepared)).toBe(true);
    expect(Object.isFrozen(prepared.candidate.currentMutationLink)).toBe(true);
    expect(Object.isFrozen(prepared.initialManifest.history)).toBe(true);
    expect(Object.isFrozen(prepared.initialOwnerIdentity)).toBe(true);
  });

  it('opens current and historical VRKs from outer authority envelopes and rejects substitutions', async () => {
    const fixture = await makeFixture();
    const prepared = await buildCollaborativeGenesis(fixture.input);
    cleanup.push(prepared);
    const outer = prepared.candidate.databaseAuthorityRecoveryEnvelope;
    const inner = prepared.initialManifest.keyEnvelopes.find(
      (envelope) => !('membershipId' in envelope),
    );
    expect(canonicalJson(outer)).toBe(canonicalJson(inner));

    const opened = await openCollaborationVaultRootForDatabaseAuthority(
      outer.sealedVaultRootKey,
      fixture.secrets.databaseRootKey,
      prepared.candidate.databaseId,
      prepared.candidate.authorityEpoch,
      prepared.candidate.authorityDelegation.authorityRecoveryPublicKey,
    );
    const manifestPlaintext = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedMembershipManifest,
      opened,
      prepared.candidate.encryptedMembershipManifest.aad,
    );
    try {
      const authenticatedManifest = collaborativeMembershipManifestSchema.parse(
        JSON.parse(Buffer.from(manifestPlaintext).toString('utf8')),
      );
      expect(() =>
        requireExactDatabaseAuthorityRecoveryEnvelope(
          prepared.candidate,
          authenticatedManifest,
        ),
      ).not.toThrow();

      const substitutedOuter = {
        ...prepared.candidate,
        databaseAuthorityRecoveryEnvelope: {
          ...outer,
          ownerSignature: mutateBase64(outer.ownerSignature),
        },
      };
      expect(() =>
        requireExactDatabaseAuthorityRecoveryEnvelope(
          substitutedOuter,
          authenticatedManifest,
        ),
      ).toThrow('Collaborative recovery-envelope verification failed.');
    } finally {
      zeroize(opened);
      zeroize(manifestPlaintext);
    }

    const witness = required(prepared.proofEntry.authorizationWitness);
    const witnessOuter = witness.databaseAuthorityRecoveryEnvelope;
    expect(canonicalJson(witnessOuter)).toBe(canonicalJson(inner));
    const historicalOpened = await openCollaborationVaultRootForDatabaseAuthority(
      witnessOuter.sealedVaultRootKey,
      fixture.secrets.databaseRootKey,
      witness.databaseId,
      witness.tuple.authorityEpoch,
      prepared.candidate.authorityDelegation.authorityRecoveryPublicKey,
    );
    const historicalManifestPlaintext = await decryptCollaborationEnvelope(
      witness.encryptedMembershipManifest,
      historicalOpened,
      witness.encryptedMembershipManifest.aad,
    );
    try {
      const authenticatedHistoricalManifest =
        collaborativeMembershipManifestSchema.parse(
          JSON.parse(Buffer.from(historicalManifestPlaintext).toString('utf8')),
        );
      expect(() =>
        requireExactDatabaseAuthorityRecoveryEnvelope(
          witness,
          authenticatedHistoricalManifest,
        ),
      ).not.toThrow();
    } finally {
      zeroize(historicalOpened);
      zeroize(historicalManifestPlaintext);
    }

    const wrongDatabaseRootKey = generateDatabaseRootKey();
    cleanup.push(wrongDatabaseRootKey);
    await expect(
      openCollaborationVaultRootForDatabaseAuthority(
        witnessOuter.sealedVaultRootKey,
        wrongDatabaseRootKey,
        prepared.candidate.databaseId,
        prepared.candidate.authorityEpoch,
        prepared.candidate.authorityDelegation.authorityRecoveryPublicKey,
      ),
    ).rejects.toThrow('Authentication failed');
    await expect(
      openCollaborationVaultRootForDatabaseAuthority(
        mutateBase64(witnessOuter.sealedVaultRootKey),
        fixture.secrets.databaseRootKey,
        prepared.candidate.databaseId,
        prepared.candidate.authorityEpoch,
        prepared.candidate.authorityDelegation.authorityRecoveryPublicKey,
      ),
    ).rejects.toThrow('Authentication failed');
  });

  it('rejects source scope, authority, registry, and timestamp substitution', async () => {
    const fixture = await makeFixture();
    await expectRejected({
      ...fixture.input,
      anchorScope: { ...fixture.input.anchorScope, vaultId: 'other-vault' as never },
    });
    await expectRejected({
      ...fixture.input,
      authoritySigningKeyFingerprint: digest(99),
    });
    await expectRejected({
      ...fixture.input,
      registryCandidate: {
        ...fixture.registry,
        registryDigest: sha256DigestSchema.parse(
          mutateBase64(fixture.registry.registryDigest),
        ),
      },
    });
    await expectRejected({
      ...fixture.input,
      activatedAt: EXPIRES_AT,
    });
    const substitutedSource = {
      ...fixture.input.legacySource,
      id: 'other-vault',
      wrappedVaultRoot: {
        ...fixture.input.legacySource.wrappedVaultRoot,
        aad: {
          ...fixture.input.legacySource.wrappedVaultRoot.aad,
          vaultId: 'other-vault',
          entityId: 'other-vault',
        },
      },
      encryptedPayload: {
        ...fixture.input.legacySource.encryptedPayload,
        aad: {
          ...fixture.input.legacySource.encryptedPayload.aad,
          vaultId: 'other-vault',
          entityId: 'other-vault',
        },
      },
    } as BuildCollaborativeGenesisInput['legacySource'];
    await expectRejected({ ...fixture.input, legacySource: substitutedSource });
  });

  it('rejects missing, malformed, wrong-key, foreign, and newer protected legacy anchors before randomness', async () => {
    const missing = await makeFixture();
    await rm(missing.legacyAnchorPath, { force: true });
    await expectRejected(missing.input);
    expect(missing.randomnessCalls.count).toBe(0);

    const malformed = await makeFixture();
    await writeFile(malformed.legacyAnchorPath, '{"format":"foreign"}\n', {
      mode: 0o600,
    });
    await expectRejected(malformed.input);
    expect(malformed.randomnessCalls.count).toBe(0);

    const wrongKey = await makeFixture();
    const wrongDatabaseRootKey = generateDatabaseRootKey();
    cleanup.push(wrongDatabaseRootKey);
    const wrongDatabaseRootKeyBefore = Uint8Array.from(wrongDatabaseRootKey);
    await expectRejected({
      ...wrongKey.input,
      databaseRootKey: wrongDatabaseRootKey,
    });
    expect(wrongDatabaseRootKey).toEqual(wrongDatabaseRootKeyBefore);
    expect(wrongKey.randomnessCalls.count).toBe(0);

    const foreign = await makeFixture();
    await writeDatabaseRevisionAnchor(
      foreign.legacyAnchorPath,
      foreign.secrets.databaseRootKey,
      {
        ...legacyAnchor(foreign.input.legacySource),
        databaseId: databaseIdSchema.parse('foreign-database'),
      },
      'replace',
    );
    await expectRejected(foreign.input);
    expect(foreign.randomnessCalls.count).toBe(0);

    const stale = await makeFixture();
    const trusted = legacyAnchor(stale.input.legacySource);
    await writeDatabaseRevisionAnchor(
      stale.legacyAnchorPath,
      stale.secrets.databaseRootKey,
      {
        ...trusted,
        vaultHeads: {
          ...trusted.vaultHeads,
          [stale.input.legacySource.id]: {
            revision: vaultRevisionSchema.parse(stale.input.legacySource.revision + 1),
            metadataDigest: digest(91),
          },
        },
      },
      'replace',
    );
    await expectRejected(stale.input);
    expect(stale.randomnessCalls.count).toBe(0);

    const newerDatabase = await makeFixture();
    const databaseAnchor = legacyAnchor(newerDatabase.input.legacySource);
    await writeDatabaseRevisionAnchor(
      newerDatabase.legacyAnchorPath,
      newerDatabase.secrets.databaseRootKey,
      {
        ...databaseAnchor,
        databaseRevision: databaseRevisionSchema.parse(
          newerDatabase.input.legacySource.databaseRevision + 1,
        ),
      },
      'replace',
    );
    await expectRejected(newerDatabase.input);
    expect(newerDatabase.randomnessCalls.count).toBe(0);
  });

  it('rejects wrong keyed payload metadata, invalid payloads, and structured vault substitution before randomness', async () => {
    const wrongDigest = await makeFixture();
    const wrongDigestSource = await legacyVault(
      wrongDigest.secrets.databaseRootKey,
      wrongDigest.secrets.legacyVaultRootKey,
      PAYLOAD,
      { declaredPayloadMetadataDigest: digest(92) },
    );
    await writeDatabaseRevisionAnchor(
      wrongDigest.legacyAnchorPath,
      wrongDigest.secrets.databaseRootKey,
      legacyAnchor(wrongDigestSource),
      'replace',
    );
    await expectRejected({ ...wrongDigest.input, legacySource: wrongDigestSource });
    expect(wrongDigest.randomnessCalls.count).toBe(0);

    for (const plaintext of [
      Buffer.from('{', 'utf8'),
      Buffer.from(
        canonicalJson({ records: { invalid: { value: PAYLOAD_CANARY } } }),
        'utf8',
      ),
      Buffer.from(
        canonicalJson(
          databaseVaultPayloadSchema.parse({
            version: 1,
            vaultId: 'substituted-vault',
            projectContexts: [],
            groups: [],
            items: [],
            attachments: [],
            history: [],
          }),
        ),
        'utf8',
      ),
    ]) {
      const fixture = await makeFixture();
      cleanup.push(plaintext);
      const source = await legacyVault(
        fixture.secrets.databaseRootKey,
        fixture.secrets.legacyVaultRootKey,
        plaintext,
      );
      await writeDatabaseRevisionAnchor(
        fixture.legacyAnchorPath,
        fixture.secrets.databaseRootKey,
        legacyAnchor(source),
        'replace',
      );
      await expectRejected({ ...fixture.input, legacySource: source });
      expect(fixture.randomnessCalls.count).toBe(0);
    }
  });

  it('accepts an exact authenticated structured legacy payload and retains its original bytes', async () => {
    const fixture = await makeFixture();
    const plaintext = Buffer.from(
      canonicalJson(
        databaseVaultPayloadSchema.parse({
          version: 1,
          vaultId: VAULT_ID,
          projectContexts: [],
          groups: [],
          items: [],
          attachments: [],
          history: [],
        }),
      ),
      'utf8',
    );
    cleanup.push(plaintext);
    const source = await legacyVault(
      fixture.secrets.databaseRootKey,
      fixture.secrets.legacyVaultRootKey,
      plaintext,
    );
    await writeDatabaseRevisionAnchor(
      fixture.legacyAnchorPath,
      fixture.secrets.databaseRootKey,
      legacyAnchor(source),
      'replace',
    );
    const prepared = await buildCollaborativeGenesis({
      ...fixture.input,
      legacySource: source,
    });
    cleanup.push(prepared);
    const opened = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedPayload,
      prepared.vaultRootKey,
      prepared.candidate.encryptedPayload.aad,
    );
    try {
      expect(Buffer.from(opened)).toEqual(plaintext);
      expect(fixture.randomnessCalls.count).toBe(1);
    } finally {
      zeroize(opened);
    }
  });

  it('rejects a wrong database root, independently reconstructed AAD, and authenticated legacy envelope tampering', async () => {
    const fixture = await makeFixture();
    const wrongDatabaseRootKey = generateDatabaseRootKey();
    cleanup.push(wrongDatabaseRootKey);
    const wrongDatabaseRootKeyBefore = Uint8Array.from(wrongDatabaseRootKey);
    await expectRejected({
      ...fixture.input,
      databaseRootKey: wrongDatabaseRootKey,
    });
    expect(wrongDatabaseRootKey).toEqual(wrongDatabaseRootKeyBefore);

    const substitutedWrappedRootSource = await legacyVault(
      fixture.secrets.databaseRootKey,
      fixture.secrets.legacyVaultRootKey,
      PAYLOAD,
      { wrappedRootMetadataDigest: digest(93) },
    );
    await expectRejected({
      ...fixture.input,
      legacySource: substitutedWrappedRootSource,
    });

    await expectRejected({
      ...fixture.input,
      legacySource: {
        ...fixture.input.legacySource,
        encryptedPayload: {
          ...fixture.input.legacySource.encryptedPayload,
          ciphertext: mutateBase64(
            fixture.input.legacySource.encryptedPayload.ciphertext,
          ),
        },
      },
    });

    await expectRejected({
      ...fixture.input,
      legacySource: databaseVaultDocumentSchema.parse({
        ...fixture.input.legacySource,
        currentKeyVersion: 2,
        wrappedVaultRoot: {
          ...fixture.input.legacySource.wrappedVaultRoot,
          aad: {
            ...fixture.input.legacySource.wrappedVaultRoot.aad,
            keyVersion: 2,
          },
          keyVersion: 2,
        },
        encryptedPayload: {
          ...fixture.input.legacySource.encryptedPayload,
          aad: {
            ...fixture.input.legacySource.encryptedPayload.aad,
            keyVersion: 2,
          },
          keyVersion: 2,
        },
      }),
    });
    expect(fixture.randomnessCalls.count).toBe(0);
  });

  it('rejects malformed legacy encrypted payload envelopes', async () => {
    const fixture = await makeFixture();
    await expectRejected({
      ...fixture.input,
      legacySource: {
        ...fixture.input.legacySource,
        encryptedPayload: {
          ...fixture.input.legacySource.encryptedPayload,
          nonce: 'AA',
        },
      },
    });
    expect(fixture.randomnessCalls.count).toBe(0);
  });

  it('rejects bad identity/certificate/private keys and a missing active writer', async () => {
    const fixture = await makeFixture();
    await expectRejected({
      ...fixture.input,
      initialOwnerIdentity: {
        ...fixture.identity,
        selfSignature: mutateBase64(fixture.identity.selfSignature),
      },
    });
    const invalidCertificate = {
      ...required(fixture.identity.devices[0]),
      rootSignature: mutateBase64(required(fixture.identity.devices[0]).rootSignature),
    };
    const invalidCertificateIdentity = await signedRecord(
      COLLABORATION_DOMAINS.publicIdentitySignature,
      {
        ...fixture.identity,
        devices: [invalidCertificate, required(fixture.identity.devices[1])],
        selfSignature: PLACEHOLDER_SIGNATURE,
      },
      publicIdentityExportSchema,
      'selfSignature',
      fixture.secrets.root.privateKey,
    );
    await expectRejected({
      ...fixture.input,
      initialOwnerIdentity: invalidCertificateIdentity,
    });
    await expectRejected({
      ...fixture.input,
      ownerDeviceSigningPrivateKey: fixture.secrets.secondSigning.privateKey,
    });
    await expectRejected({
      ...fixture.input,
      authoritySigningPrivateKey: fixture.secrets.root.privateKey,
    });
    await expectRejected({
      ...fixture.input,
      initialOwnerDeviceId:
        deviceCertificateSchema.shape.deviceId.parse('missing-device'),
      anchorScope: {
        ...fixture.input.anchorScope,
        deviceId: deviceCertificateSchema.shape.deviceId.parse('missing-device'),
      },
    });
  });

  it('rejects tampered output relationships and a noncanonical predecessor', async () => {
    const fixture = await makeFixture();
    const prepared = await buildCollaborativeGenesis(fixture.input);
    cleanup.push(prepared);
    expect(
      await verifyMigrationRequestAuthority(
        {
          ...prepared.request,
          legacySourceDigest: mutateBase64(prepared.request.legacySourceDigest),
        },
        fixture.secrets.authoritySigning.publicKeyBase64,
      ),
    ).toBe(false);
    expect(
      collaborationMigrationJournalCreateInputSchema.safeParse({
        ...migrationJournalBundle(prepared),
        collaborativeCandidate: {
          ...prepared.candidate,
          previousHeadDigest: digest(77),
        },
      }).success,
    ).toBe(false);
    const witness = required(prepared.proofEntry.authorizationWitness);
    const tamperedProof = collaborationMutationProofEntrySchema.parse({
      ...prepared.proofEntry,
      authorizationWitness: {
        ...witness,
        finalizedMutationLinkDigest: digest(78),
      },
    });
    expect(
      collaborationMigrationJournalCreateInputSchema.safeParse({
        ...migrationJournalBundle(prepared),
        proofEntry: tamperedProof,
      }).success,
    ).toBe(false);
    expect(
      collaborationMigrationJournalCreateInputSchema.safeParse({
        ...migrationJournalBundle(prepared),
        proposedOutcome: {
          ...prepared.proposedOutcome,
          committedHeadDigest: digest(79),
        },
      }).success,
    ).toBe(false);
  });

  it('zeroizes injected randomness when construction fails after generation', async () => {
    const fixture = await makeFixture();
    const shortGeneratedKey = Buffer.alloc(31, 7);
    let calls = 0;
    const input = {
      ...fixture.input,
      randomness: {
        generateVaultRootKey: () => {
          calls += 1;
          return shortGeneratedKey;
        },
      },
    };
    await expectRejected(input);
    expect(calls).toBe(1);
    expect(shortGeneratedKey.every((value) => value === 0)).toBe(true);
  });

  it('exports only one redacted safe error surface', () => {
    const error = new CollaborationGenesisPreparationError();
    expect(error.safe).toBe(true);
    expect(error.message).toBe('Collaborative genesis preparation failed.');
    expect(error.message).not.toMatch(/key|payload|signature|identity/i);
  });
});

function migrationJournalBundle(
  prepared: PreparedCollaborativeGenesis,
): ReturnType<typeof collaborationMigrationJournalCreateInputSchema.parse> {
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
