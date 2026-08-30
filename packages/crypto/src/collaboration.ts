import { createHash, hkdfSync, randomBytes } from 'node:crypto';

import {
  base64UrlSchema,
  canonicalJson,
  collaborationAadSchema,
  collaborationAadMetadataSchema,
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST as SCHEMA_COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST as SCHEMA_COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST as SCHEMA_COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST as SCHEMA_COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST as SCHEMA_COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
  collaborationAuthorityDelegationSchema,
  collaborationAuthorizationCheckpointSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationPolicyStateSchema,
  approvalRequestSchema,
  collaborativeMembershipManifestSchema,
  collaborativeAeadEnvelopeSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMutationReceiptSchema,
  collaborationMutationCommitmentSchema,
  collaborationVaultDestructionActionSchema,
  collaborationVaultDestructionCoreSchema,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationPublicKeySchema,
  collaborationSignatureSchema,
  collaborationKeyEpochSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  databaseVaultDocumentSchema,
  deviceCertificateSchema,
  databaseIdSchema,
  enrollmentReceiptSchema,
  MAX_COLLABORATIVE_OPERATION_BYTES,
  MAX_COLLABORATIVE_KEY_ENVELOPES,
  durableOperationOutcomeSchema,
  membershipHistoryCompactionInputSchema,
  membershipHistorySchema,
  operationDeduplicationTombstoneSchema,
  approvalEvidenceSchema,
  ownershipTransferAcceptanceSchema,
  transferIntentSchema,
  sha256DigestSchema,
  type CollaborationAeadEnvelope,
  type CollaborationAadMetadata,
  type Sha256Digest,
  type DatabaseId,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import {
  constantTimeEqual,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from './bytes.js';
import { AuthenticationError, CryptoInputError } from './errors.js';
import type { DatabaseRootKey, VaultRootKey } from './keys.js';

const COLLABORATION_KEY_BYTES = 32;
const ED25519_SEED_BYTES = 32;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_PRIVATE_KEY_BYTES = 64;
const ED25519_SIGNATURE_BYTES = 64;
const X25519_SEED_BYTES = 32;
const X25519_PRIVATE_KEY_BYTES = 32;
const SEALED_BOX_OVERHEAD_BYTES = 48;
const COLLABORATION_NONCE_BYTES = 24;
const COLLABORATION_TAG_BYTES = 16;
const MAX_COLLABORATION_PLAINTEXT_BYTES = 8 * 1024 * 1024;

const AUTHORITY_DERIVATION_SALT = Buffer.from(
  'kavrix/collaboration/authority-key-salt/v1',
  'ascii',
);
const AUTHORITY_RECOVERY_DERIVATION_SALT = Buffer.from(
  'kavrix/collaboration/authority-recovery-key-salt/v1',
  'ascii',
);
const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');

/** Every collaboration domain is explicit and independently versioned. */
export const COLLABORATION_DOMAINS = Object.freeze({
  authorityKeyDerivation: 'kavrix/collaboration/authority-key-derivation/v1',
  principalRootSignature: 'kavrix/collaboration/principal-root-signature/v1',
  deviceCertificateSignature: 'kavrix/collaboration/device-certificate/v1',
  principalIdentitySignature: 'kavrix/collaboration/principal-identity/v1',
  publicIdentitySignature: 'kavrix/collaboration/public-identity/v1',
  enrollmentReceiptSignature: 'kavrix/collaboration/enrollment-receipt/v1',
  authorityDelegationDigest: 'kavrix/collaboration/authority-delegation-digest/v1',
  authorityDelegationSignature:
    'kavrix/collaboration/authority-delegation-signature/v1',
  authorizationStateDigest: 'kavrix/collaboration/authorization-state-digest/v1',
  membershipStateDigest: 'kavrix/collaboration/membership-state-digest/v1',
  authorizationTransitionDigest:
    'kavrix/collaboration/authorization-transition-digest/v1',
  authorizationTransitionOwnerSignature:
    'kavrix/collaboration/authorization-transition-owner-signature/v1',
  authorizationTransitionAuthoritySignature:
    'kavrix/collaboration/authorization-transition-authority-signature/v1',
  finalizedMutationLinkDigest: 'kavrix/collaboration/finalized-mutation-link-digest/v1',
  finalizedMutationLinkSignature:
    'kavrix/collaboration/finalized-mutation-link-signature/v1',
  authorizationCheckpointDigest:
    'kavrix/collaboration/authorization-checkpoint-digest/v1',
  authorizationCheckpointSignature:
    'kavrix/collaboration/authorization-checkpoint-signature/v1',
  discoveryRecordSignature: 'kavrix/collaboration/discovery-record/v1',
  keyEnvelopeSignature: 'kavrix/collaboration/key-envelope-signature/v1',
  mutationRequestDigest: 'kavrix/collaboration/mutation-request-digest/v1',
  mutationCommitmentSignature: 'kavrix/collaboration/mutation-commitment/v1',
  mutationHead: 'kavrix/collaboration/mutation-head/v1',
  keyEnvelopeDigest: 'kavrix/collaboration/key-envelope-digest/v1',
  keyEnvelopeSetDigest: 'kavrix/collaboration/key-envelope-set-digest/v1',
  discoveryTag: 'kavrix/collaboration/discovery-tag/v1',
  genesisHead: 'kavrix/collaboration/genesis-head/v1',
  genesisAuthorizationState: 'kavrix/collaboration/genesis-authorization-state/v1',
  genesisMembershipState: 'kavrix/collaboration/genesis-membership-state/v1',
  genesisMembershipHistory: 'kavrix/collaboration/genesis-membership-history/v1',
  genesisCompactedHistory: 'kavrix/collaboration/genesis-compacted-history/v1',
  aadMetadataDigest: 'kavrix/collaboration/aad-metadata-digest/v1',
  encryptedPayloadDigest: 'kavrix/collaboration/encrypted-payload-digest/v1',
  encryptedMembershipDigest: 'kavrix/collaboration/encrypted-membership-digest/v1',
  membershipManifestDigest: 'kavrix/collaboration/membership-manifest-digest/v1',
  membershipHistoryDigest: 'kavrix/collaboration/membership-history-digest/v1',
  membershipHistoryCompactionDigest:
    'kavrix/collaboration/membership-history-compaction-digest/v1',
  collaborativeVaultDestroyedPayloadDigest:
    'kavrix/collaboration/vault-destroyed-payload-digest/v1',
  collaborativeVaultDestructionActionDigest:
    'kavrix/collaboration/vault-destruction-action-digest/v1',
  policyDigest: 'kavrix/collaboration/policy-digest/v1',
  policyStateDigest: 'kavrix/collaboration/policy-state-digest/v1',
  policySignature: 'kavrix/collaboration/policy-signature/v1',
  deviceRegistryDigest: 'kavrix/collaboration/device-registry-digest/v1',
  discoveryRecordDigest: 'kavrix/collaboration/discovery-record-digest/v1',
  deviceCertificateFingerprint:
    'kavrix/collaboration/device-certificate-fingerprint/v1',
  operationOutcomeDigest: 'kavrix/collaboration/operation-outcome-digest/v1',
  operationTombstoneDigest: 'kavrix/collaboration/operation-tombstone-digest/v1',
  authorityRecoveryEnvelopeDigest:
    'kavrix/collaboration/authority-recovery-envelope-digest/v1',
  authorityRecoveryKeyDerivation:
    'kavrix/collaboration/authority-recovery-key-derivation/v1',
  legacySourceDigest: 'kavrix/collaboration/legacy-source-digest/v1',
  migrationRequestDigest: 'kavrix/collaboration/migration-request-digest/v1',
  migrationRequestAuthoritySignature:
    'kavrix/collaboration/migration-request-authority-signature/v1',
  migrationRequestOwnerSignature:
    'kavrix/collaboration/migration-request-owner-signature/v1',
  migrationPreparedMarkerSignature:
    'kavrix/collaboration/migration-prepared-marker-signature/v1',
  migrationActiveMarkerSignature:
    'kavrix/collaboration/migration-active-marker-signature/v1',
  approvalRequestSignature: 'kavrix/collaboration/approval-request/v1',
  approvalRequestDigest: 'kavrix/collaboration/approval-request-digest/v1',
  administrativeActionParametersDigest:
    'kavrix/collaboration/administrative-action-parameters-digest/v1',
  transferIntentSignature: 'kavrix/collaboration/transfer-intent/v1',
  transferIntentDigest: 'kavrix/collaboration/transfer-intent-digest/v1',
  transferAcceptanceSignature: 'kavrix/collaboration/transfer-acceptance-signature/v1',
  approvalEvidenceSignature: 'kavrix/collaboration/approval-evidence-signature/v1',
  membershipHistorySignature: 'kavrix/collaboration/membership-history/v1',
  membershipHistoryCheckpointSignature:
    'kavrix/collaboration/membership-history-checkpoint/v1',
  deviceRegistrySignature: 'kavrix/collaboration/device-registry/v1',
  mutationReceiptSignature: 'kavrix/collaboration/mutation-receipt/v1',
  publicKeyFingerprint: 'kavrix/collaboration/public-key-fingerprint/v1',
  collaborationAad: 'kavrix/collaboration/aad/v1',
} as const);

/** Fixed prior head for the protocol's genesis migration operation. */
export const COLLABORATION_GENESIS_HEAD_DIGEST: Sha256Digest =
  SCHEMA_COLLABORATION_GENESIS_HEAD_DIGEST;

/** Fixed prior authorization state for the protocol's genesis migration. */
export const COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST: Sha256Digest =
  SCHEMA_COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST;

/** Fixed prior membership state for the protocol's genesis migration. */
export const COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST: Sha256Digest =
  SCHEMA_COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST;

/** Fixed prior membership-history state for the protocol's genesis migration. */
export const COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST: Sha256Digest =
  SCHEMA_COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST;

/** Fixed empty compacted-history prefix for the protocol's genesis migration. */
export const COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST: Sha256Digest =
  SCHEMA_COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST;

export type CollaborationDomain =
  (typeof COLLABORATION_DOMAINS)[keyof typeof COLLABORATION_DOMAINS];

/** Direct signature fields that may be omitted for a self-signature. */
export type CollaborationSignatureField =
  | 'signature'
  | 'selfSignature'
  | 'rootSignature'
  | 'ownerSignature'
  | 'writerSignature'
  | 'authoritySignature'
  | 'initiatorSignature'
  | 'requesterSignature'
  | 'receiptSignature';

declare const principalSigningPrivateKeyBrand: unique symbol;
declare const deviceSigningPrivateKeyBrand: unique symbol;
declare const deviceEncryptionPrivateKeyBrand: unique symbol;
declare const authoritySigningPrivateKeyBrand: unique symbol;
declare const authorityRecoveryPrivateKeyBrand: unique symbol;
declare const ed25519PublicKeyBrand: unique symbol;
declare const x25519PublicKeyBrand: unique symbol;

/** An Ed25519 private key owned by a principal root identity (64 bytes). */
export type PrincipalSigningPrivateKey = Uint8Array & {
  readonly [principalSigningPrivateKeyBrand]: 'principal-signing';
};

/** An Ed25519 private key owned by a device identity (64 bytes). */
export type DeviceSigningPrivateKey = Uint8Array & {
  readonly [deviceSigningPrivateKeyBrand]: 'device-signing';
};

/** An X25519 private key owned by a device identity (32 bytes). */
export type DeviceEncryptionPrivateKey = Uint8Array & {
  readonly [deviceEncryptionPrivateKeyBrand]: 'device-encryption';
};

/** The deterministic Ed25519 private key derived from a database DRK (64 bytes). */
export type DatabaseAuthoritySigningPrivateKey = Uint8Array & {
  readonly [authoritySigningPrivateKeyBrand]: 'database-authority-signing';
};

/** The deterministic X25519 private key derived from a database DRK (32 bytes). */
export type DatabaseAuthorityRecoveryPrivateKey = Uint8Array & {
  readonly [authorityRecoveryPrivateKeyBrand]: 'database-authority-recovery';
};

/** Raw Ed25519 public key bytes (32 bytes). */
export type CollaborationEd25519PublicKey = Uint8Array & {
  readonly [ed25519PublicKeyBrand]: 'ed25519';
};

/** Raw X25519 public key bytes (32 bytes). */
export type CollaborationX25519PublicKey = Uint8Array & {
  readonly [x25519PublicKeyBrand]: 'x25519';
};

export interface CollaborationSigningKeyPair<PrivateKey extends Uint8Array> {
  readonly algorithm: 'ed25519';
  readonly publicKey: CollaborationEd25519PublicKey;
  /** Canonical base64url form for schema/wire fields. */
  readonly publicKeyBase64: string;
  readonly privateKey: PrivateKey;
}

export interface CollaborationEncryptionKeyPair {
  readonly algorithm: 'x25519';
  readonly publicKey: CollaborationX25519PublicKey;
  /** Canonical base64url form for schema/wire fields. */
  readonly publicKeyBase64: string;
  readonly privateKey: DeviceEncryptionPrivateKey;
}

export type PrincipalSigningKeyPair =
  CollaborationSigningKeyPair<PrincipalSigningPrivateKey>;
export type DeviceSigningKeyPair = CollaborationSigningKeyPair<DeviceSigningPrivateKey>;
export type DatabaseAuthoritySigningKeyPair =
  CollaborationSigningKeyPair<DatabaseAuthoritySigningPrivateKey>;

export interface DatabaseAuthorityRecoveryKeyPair {
  readonly algorithm: 'x25519';
  readonly publicKey: CollaborationX25519PublicKey;
  /** Canonical base64url form for the immutable authority delegation. */
  readonly publicKeyBase64: string;
  readonly privateKey: DatabaseAuthorityRecoveryPrivateKey;
}

type Ed25519PrivateKey =
  | PrincipalSigningPrivateKey
  | DeviceSigningPrivateKey
  | DatabaseAuthoritySigningPrivateKey;

interface SchemaLike<T> {
  readonly parse: (value: unknown) => T;
}

type CollaborationAad = ReturnType<typeof collaborationAadSchema.parse>;

/** Generate the protected Ed25519 root signing pair for one principal. */
export async function generatePrincipalSigningKeyPair(): Promise<PrincipalSigningKeyPair> {
  return generateSigningKeyPair<'principal-signing'>();
}

/** Generate one device's Ed25519 signing pair. */
export async function generateDeviceSigningKeyPair(): Promise<DeviceSigningKeyPair> {
  return generateSigningKeyPair<'device-signing'>();
}

/** Generate one device's independent X25519 encryption pair. */
export async function generateDeviceEncryptionKeyPair(): Promise<CollaborationEncryptionKeyPair> {
  const seed = randomBytes(X25519_SEED_BYTES);
  let generated:
    { readonly publicKey: Uint8Array; readonly privateKey: Uint8Array } | undefined;
  try {
    await sodium.ready;
    generated = sodium.crypto_box_seed_keypair(seed);
    const publicKey = copyPublicKey(
      generated.publicKey,
      'X25519 public key',
    ) as CollaborationX25519PublicKey;
    const privateKey = copyPrivateKey(
      generated.privateKey,
      X25519_PRIVATE_KEY_BYTES,
      'X25519 private key',
    ) as DeviceEncryptionPrivateKey;
    return {
      algorithm: 'x25519',
      publicKey,
      publicKeyBase64: encodePublicKey(publicKey),
      privateKey,
    };
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to generate collaboration encryption keys');
  } finally {
    zeroize(generated?.publicKey);
    zeroize(generated?.privateKey);
    zeroize(seed);
  }
}

/** Generate both independent device key pairs in one operation. */
export async function generateDeviceKeyPairs(): Promise<{
  readonly signing: DeviceSigningKeyPair;
  readonly encryption: CollaborationEncryptionKeyPair;
}> {
  const signing = await generateDeviceSigningKeyPair();
  try {
    const encryption = await generateDeviceEncryptionKeyPair();
    return { signing, encryption };
  } catch (error) {
    zeroize(signing.privateKey);
    throw error;
  }
}

/**
 * Derive the database authority Ed25519 key deterministically from the DRK.
 * The protocol version, database ID, and authority epoch are all in the HKDF
 * info, so the same DRK cannot silently authenticate another database/epoch.
 */
export async function deriveDatabaseAuthoritySigningKeyPair(
  databaseRootKey: DatabaseRootKey | Uint8Array,
  databaseId: DatabaseId | string,
  authorityEpoch: number,
): Promise<DatabaseAuthoritySigningKeyPair> {
  let seed: Uint8Array | undefined;
  let info: Uint8Array | undefined;
  let generated:
    { readonly publicKey: Uint8Array; readonly privateKey: Uint8Array } | undefined;
  try {
    requireByteLength(databaseRootKey, COLLABORATION_KEY_BYTES, 'database root key');
    const parsedDatabaseId = databaseIdSchema.parse(databaseId);
    const parsedEpoch = collaborationKeyEpochSchema.parse(authorityEpoch);
    info = canonicalJsonBytes(COLLABORATION_DOMAINS.authorityKeyDerivation, {
      protocolVersion: 1,
      databaseId: parsedDatabaseId,
      authorityEpoch: parsedEpoch,
    });
    seed = new Uint8Array(
      hkdfSync(
        'sha256',
        databaseRootKey,
        AUTHORITY_DERIVATION_SALT,
        info,
        ED25519_SEED_BYTES,
      ),
    );
    await sodium.ready;
    generated = sodium.crypto_sign_seed_keypair(seed);
    const publicKey = copyPublicKey(
      generated.publicKey,
      'authority public key',
    ) as CollaborationEd25519PublicKey;
    const privateKey = copyPrivateKey(
      generated.privateKey,
      ED25519_PRIVATE_KEY_BYTES,
      'authority private key',
    ) as DatabaseAuthoritySigningPrivateKey;
    return {
      algorithm: 'ed25519',
      publicKey,
      publicKeyBase64: encodePublicKey(publicKey),
      privateKey,
    };
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to derive database authority keys');
  } finally {
    zeroize(generated?.publicKey);
    zeroize(generated?.privateKey);
    zeroize(seed);
    zeroize(info);
  }
}

/**
 * Derive the database authority X25519 recovery pair independently from the
 * signing pair. Database scope and authority epoch are part of the HKDF info,
 * so a recovery wrapper cannot be transplanted to another database or epoch.
 */
export async function deriveDatabaseAuthorityRecoveryKeyPair(
  databaseRootKey: DatabaseRootKey | Uint8Array,
  databaseId: DatabaseId | string,
  authorityEpoch: number,
): Promise<DatabaseAuthorityRecoveryKeyPair> {
  let seed: Uint8Array | undefined;
  let info: Uint8Array | undefined;
  let generated:
    { readonly publicKey: Uint8Array; readonly privateKey: Uint8Array } | undefined;
  try {
    requireByteLength(databaseRootKey, COLLABORATION_KEY_BYTES, 'database root key');
    const parsedDatabaseId = databaseIdSchema.parse(databaseId);
    const parsedEpoch = collaborationKeyEpochSchema.parse(authorityEpoch);
    info = canonicalJsonBytes(COLLABORATION_DOMAINS.authorityRecoveryKeyDerivation, {
      protocolVersion: 1,
      databaseId: parsedDatabaseId,
      authorityEpoch: parsedEpoch,
    });
    seed = new Uint8Array(
      hkdfSync(
        'sha256',
        databaseRootKey,
        AUTHORITY_RECOVERY_DERIVATION_SALT,
        info,
        X25519_SEED_BYTES,
      ),
    );
    await sodium.ready;
    generated = sodium.crypto_box_seed_keypair(seed);
    const publicKey = copyPublicKey(
      generated.publicKey,
      'authority recovery public key',
    ) as CollaborationX25519PublicKey;
    const privateKey = copyPrivateKey(
      generated.privateKey,
      X25519_PRIVATE_KEY_BYTES,
      'authority recovery private key',
    ) as DatabaseAuthorityRecoveryPrivateKey;
    return {
      algorithm: 'x25519',
      publicKey,
      publicKeyBase64: encodePublicKey(publicKey),
      privateKey,
    };
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to derive database authority recovery keys');
  } finally {
    zeroize(generated?.publicKey);
    zeroize(generated?.privateKey);
    zeroize(seed);
    zeroize(info);
  }
}

/** Encode raw public key bytes through the strict collaboration key schema. */
export function encodeCollaborationPublicKey(publicKey: Uint8Array): string {
  return encodePublicKey(publicKey);
}

/** Decode a canonical wire public key, returning owned bytes. */
export function decodeCollaborationPublicKey(publicKey: string): Uint8Array {
  const parsed = collaborationPublicKeySchema.parse(publicKey);
  return decodeBase64Url(parsed, { exactBytes: ED25519_PUBLIC_KEY_BYTES });
}

/**
 * Compute the canonical fingerprint carried by public enrollment material.
 * The algorithm label is included so an Ed25519 key and an X25519 key cannot
 * accidentally share a fingerprint even though both are 32 bytes.
 */
export function computePublicKeyFingerprint(
  publicKey: string | Uint8Array,
  algorithm: 'ed25519' | 'x25519',
): Sha256Digest {
  const algorithmValue: string = algorithm;
  if (algorithmValue !== 'ed25519' && algorithmValue !== 'x25519') {
    throw new CryptoInputError('Invalid collaboration public-key algorithm');
  }
  let keyBytes: Uint8Array | undefined;
  try {
    keyBytes = decodePublicKey(publicKey);
    const encoded = encodePublicKey(keyBytes);
    return digestCanonicalValue(COLLABORATION_DOMAINS.publicKeyFingerprint, {
      algorithm,
      publicKey: collaborationPublicKeySchema.parse(encoded),
    });
  } finally {
    zeroize(keyBytes);
  }
}

/** Sign a parsed collaboration value with a versioned, domain-separated Ed25519 signature. */
export async function signCanonicalCollaborationValue<T>(
  domain: CollaborationDomain,
  value: unknown,
  schema: SchemaLike<T>,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  let message: Uint8Array | undefined;
  let signature: Uint8Array | undefined;
  try {
    requireEd25519PrivateKey(privateKey);
    message = canonicalSchemaBytes(domain, value, schema);
    await sodium.ready;
    signature = sodium.crypto_sign_detached(message, privateKey);
    if (signature.byteLength !== ED25519_SIGNATURE_BYTES) {
      throw new CryptoInputError('Invalid collaboration signature length');
    }
    return collaborationSignatureSchema.parse(encodeBase64Url(signature));
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to create collaboration signature');
  } finally {
    zeroize(message);
    zeroize(signature);
  }
}

/** Verify a parsed collaboration value; malformed or mismatched input fails closed as false. */
export async function verifyCanonicalCollaborationValue<T>(
  domain: CollaborationDomain,
  value: unknown,
  schema: SchemaLike<T>,
  signatureValue: string,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  let message: Uint8Array | undefined;
  let signature: Uint8Array | undefined;
  let publicKey: Uint8Array | undefined;
  try {
    message = canonicalSchemaBytes(domain, value, schema);
    signature = decodeSignature(signatureValue);
    publicKey = decodeEd25519PublicKey(publicKeyValue);
    await sodium.ready;
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  } finally {
    zeroize(message);
    zeroize(signature);
    zeroize(publicKey);
  }
}

async function signCanonicalProjection(
  domain: CollaborationDomain,
  value: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  let message: Uint8Array | undefined;
  let signature: Uint8Array | undefined;
  try {
    requireEd25519PrivateKey(privateKey);
    message = canonicalJsonBytes(domain, value);
    await sodium.ready;
    signature = sodium.crypto_sign_detached(message, privateKey);
    if (signature.byteLength !== ED25519_SIGNATURE_BYTES) {
      throw new CryptoInputError('Invalid collaboration signature length');
    }
    return collaborationSignatureSchema.parse(encodeBase64Url(signature));
  } finally {
    zeroize(message);
    zeroize(signature);
  }
}

async function verifyCanonicalProjection(
  domain: CollaborationDomain,
  value: unknown,
  signatureValue: string,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  let message: Uint8Array | undefined;
  let signature: Uint8Array | undefined;
  let publicKey: Uint8Array | undefined;
  try {
    message = canonicalJsonBytes(domain, value);
    signature = decodeSignature(signatureValue);
    publicKey = decodeEd25519PublicKey(publicKeyValue);
    await sodium.ready;
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  } finally {
    zeroize(message);
    zeroize(signature);
    zeroize(publicKey);
  }
}

/**
 * Sign a record while omitting exactly one audited direct signature field.
 * The field name is a closed union so callers cannot accidentally omit a
 * digest, identity, or other security-relevant field from the signed bytes.
 */
export async function signCollaborationRecord<T>(
  domain: CollaborationDomain,
  value: unknown,
  schema: SchemaLike<T>,
  signatureField: CollaborationSignatureField,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  let message: Uint8Array | undefined;
  let signature: Uint8Array | undefined;
  try {
    assertSignatureField(signatureField);
    const unsigned = parseUnsignedSignatureRecord(value, schema, signatureField);
    requireEd25519PrivateKey(privateKey);
    message = canonicalJsonBytes(domain, unsigned);
    await sodium.ready;
    signature = sodium.crypto_sign_detached(message, privateKey);
    if (signature.byteLength !== ED25519_SIGNATURE_BYTES) {
      throw new CryptoInputError('Invalid collaboration signature length');
    }
    return collaborationSignatureSchema.parse(encodeBase64Url(signature));
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to create collaboration record signature');
  } finally {
    zeroize(message);
    zeroize(signature);
  }
}

/** Verify a record signature over a strictly parsed record minus one field. */
export async function verifyCollaborationRecord<T>(
  domain: CollaborationDomain,
  value: unknown,
  schema: SchemaLike<T>,
  signatureField: CollaborationSignatureField,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  let message: Uint8Array | undefined;
  let signature: Uint8Array | undefined;
  let publicKey: Uint8Array | undefined;
  try {
    assertSignatureField(signatureField);
    const parsed = parseSchema(value, schema) as Record<string, unknown>;
    const signatureValue = parsed[signatureField];
    if (typeof signatureValue !== 'string') return false;
    const unsigned = parseUnsignedSignatureRecord(parsed, schema, signatureField);
    message = canonicalJsonBytes(domain, unsigned);
    signature = decodeSignature(signatureValue);
    publicKey = decodeEd25519PublicKey(publicKeyValue);
    await sodium.ready;
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  } finally {
    zeroize(message);
    zeroize(signature);
    zeroize(publicKey);
  }
}

/** Digest a complete, authority-signed immutable vault delegation. */
export function computeAuthorityDelegationDigest(delegation: unknown): Sha256Digest {
  const parsed = parseAndValidateAuthorityDelegation(delegation);
  return digestCanonicalValue(COLLABORATION_DOMAINS.authorityDelegationDigest, parsed);
}

/** Sign the immutable genesis delegation, omitting only its signature bytes. */
export function signAuthorityDelegation(
  delegation: unknown,
  privateKey: DatabaseAuthoritySigningPrivateKey | Uint8Array,
): Promise<string> {
  const parsed = parseAndValidateAuthorityDelegation(delegation);
  return signCollaborationRecord(
    COLLABORATION_DOMAINS.authorityDelegationSignature,
    parsed,
    collaborationAuthorityDelegationSchema,
    'authoritySignature',
    privateKey,
  );
}

/** Verify the one database-authority signature on an immutable delegation. */
export function verifyAuthorityDelegation(
  delegation: unknown,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  return (async () => {
    try {
      const parsed = parseAndValidateAuthorityDelegation(delegation);
      if (!publicKeysEqual(parsed.authoritySigningPublicKey, publicKey)) {
        return false;
      }
      return await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.authorityDelegationSignature,
        parsed,
        collaborationAuthorityDelegationSchema,
        'authoritySignature',
        publicKey,
      );
    } catch {
      return false;
    }
  })();
}

/** Hash exactly the strict, signature-free authorization-state projection. */
export function computeAuthorizationStateDigest(
  authorizationState: unknown,
): Sha256Digest {
  return digestCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.authorizationStateDigest,
    authorizationState,
    collaborationAuthorizationStateCoreSchema,
  );
}

/**
 * Hash only the logical membership/owner projection used by rollback anchors.
 * Unlike the encrypted manifest digest, this remains stable across ordinary
 * document writes, policy-only changes, and key-envelope rotation.
 */
export function computeMembershipStateDigest(
  authorizationState: unknown,
): Sha256Digest {
  const parsed = parseSchema(
    authorizationState,
    collaborationAuthorizationStateCoreSchema,
  );
  return digestCanonicalValue(COLLABORATION_DOMAINS.membershipStateDigest, {
    protocolVersion: parsed.protocolVersion,
    databaseId: parsed.databaseId,
    vaultId: parsed.vaultId,
    authorityEpoch: parsed.authorityEpoch,
    membershipRevision: parsed.membershipRevision,
    memberships: parsed.memberships,
    ownerPrincipalIds: parsed.ownerPrincipalIds,
  });
}

/**
 * Hash an administrative transition without its self-digest or signature
 * bytes. Signer identity/kind remain part of the immutable projection.
 */
export function computeAuthorizationTransitionDigest(
  transition: unknown,
): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.authorizationTransitionDigest,
    authorizationTransitionUnsignedCore(transition),
  );
}

/** Sign a non-recovery administrative transition as its prior-state owner. */
export function signAuthorizationTransitionOwner(
  transition: unknown,
  privateKey: DeviceSigningPrivateKey | Uint8Array,
): Promise<string> {
  return signAuthorizationTransitionInternal(transition, privateKey, 'owner-device');
}

/** Verify a prior-state owner's authorization-transition signature. */
export function verifyAuthorizationTransitionOwner(
  transition: unknown,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  return verifyAuthorizationTransitionInternal(transition, publicKey, 'owner-device');
}

/** Sign the exceptional `recover-owner` transition as database authority. */
export function signAuthorizationTransitionAuthority(
  transition: unknown,
  privateKey: DatabaseAuthoritySigningPrivateKey | Uint8Array,
): Promise<string> {
  return signAuthorizationTransitionInternal(
    transition,
    privateKey,
    'database-authority',
  );
}

/** Verify the database authority's exceptional owner-recovery transition. */
export function verifyAuthorizationTransitionAuthority(
  transition: unknown,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  return verifyAuthorizationTransitionInternal(
    transition,
    publicKey,
    'database-authority',
  );
}

/**
 * Compute a non-genesis mutation's replay identity from every strict,
 * nonsecret commitment field while omitting only requestDigest itself.
 */
export function computeMutationRequestDigest(commitment: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.mutationRequestDigest,
    parseMutationRequestProjection(commitment),
  );
}

/** Sign a mutation commitment after strict parsing. */
export function signMutationCommitment(
  commitment: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  return signCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.mutationCommitmentSignature,
    commitment,
    collaborationMutationCommitmentSchema,
    privateKey,
  );
}

/** Verify a mutation commitment signature after strict parsing. */
export function verifyMutationCommitment(
  commitment: unknown,
  signature: string,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  return verifyCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.mutationCommitmentSignature,
    commitment,
    collaborationMutationCommitmentSchema,
    signature,
    publicKey,
  );
}

/** Compute the new mutation head from the acyclic parsed commitment only. */
export function computeMutationHead(commitment: unknown): Sha256Digest {
  return digestCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.mutationHead,
    commitment,
    collaborationMutationCommitmentSchema,
  );
}

/** Sign a finalized link after checking its derived head and transition digest. */
export async function signFinalizedMutationLink(
  link: unknown,
  privateKey: DeviceSigningPrivateKey | Uint8Array,
): Promise<string> {
  try {
    const parsed = parseAndValidateFinalizedMutationLink(link);
    return await signCanonicalProjection(
      COLLABORATION_DOMAINS.finalizedMutationLinkSignature,
      finalizedMutationLinkSignaturePayload(parsed),
      privateKey,
    );
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to sign finalized collaboration mutation');
  }
}

/** Verify a writer signature plus all acyclic finalized-link bindings. */
export async function verifyFinalizedMutationLink(
  link: unknown,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  try {
    const parsed = parseAndValidateFinalizedMutationLink(link);
    return await verifyCanonicalProjection(
      COLLABORATION_DOMAINS.finalizedMutationLinkSignature,
      finalizedMutationLinkSignaturePayload(parsed),
      parsed.writerSignature.signature,
      publicKey,
    );
  } catch {
    return false;
  }
}

/** Digest one complete, writer-signed finalized mutation link. */
export function computeFinalizedMutationLinkDigest(link: unknown): Sha256Digest {
  const parsed = parseAndValidateFinalizedMutationLink(link);
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.finalizedMutationLinkDigest,
    parsed,
  );
}

/** Compute a checkpoint digest without its self-digest or owner signature. */
export function computeAuthorizationCheckpointDigest(
  checkpoint: unknown,
): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.authorizationCheckpointDigest,
    authorizationCheckpointUnsignedCore(checkpoint),
  );
}

/** Sign a checkpoint after confirming its stored digest. */
export function signAuthorizationCheckpoint(
  checkpoint: unknown,
  privateKey: DeviceSigningPrivateKey | Uint8Array,
): Promise<string> {
  const parsed = parseSchema(checkpoint, collaborationAuthorizationCheckpointSchema);
  assertStoredDigest(
    parsed.checkpointDigest,
    computeAuthorizationCheckpointDigest(parsed),
    'authorization checkpoint',
  );
  return signCanonicalProjection(
    COLLABORATION_DOMAINS.authorizationCheckpointSignature,
    authorizationCheckpointSignaturePayload(parsed),
    privateKey,
  );
}

/** Verify a checkpoint's self-digest and prior-state owner signature. */
export async function verifyAuthorizationCheckpoint(
  checkpoint: unknown,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  try {
    const parsed = parseSchema(checkpoint, collaborationAuthorizationCheckpointSchema);
    if (parsed.checkpointDigest !== computeAuthorizationCheckpointDigest(parsed)) {
      return false;
    }
    return await verifyCanonicalProjection(
      COLLABORATION_DOMAINS.authorizationCheckpointSignature,
      authorizationCheckpointSignaturePayload(parsed),
      parsed.ownerSignature,
      publicKey,
    );
  } catch {
    return false;
  }
}

/** Sign an out-of-band enrollment receipt as the authenticated current owner. */
export function signEnrollmentReceipt(
  receipt: unknown,
  privateKey: DeviceSigningPrivateKey | Uint8Array,
): Promise<string> {
  const parsed = parseAndValidateEnrollmentReceipt(receipt);
  return signCollaborationRecord(
    COLLABORATION_DOMAINS.enrollmentReceiptSignature,
    parsed,
    enrollmentReceiptSchema,
    'ownerSignature',
    privateKey,
  );
}

/** Verify an owner-signed enrollment receipt and its delegation digest. */
export async function verifyEnrollmentReceipt(
  receipt: unknown,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  try {
    const parsed = parseAndValidateEnrollmentReceipt(receipt);
    return await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.enrollmentReceiptSignature,
      parsed,
      enrollmentReceiptSchema,
      'ownerSignature',
      publicKey,
    );
  } catch {
    return false;
  }
}

/** Compute a database-scoped pseudonymous discovery tag. */
export function computeDiscoveryTag(
  databaseId: DatabaseId | string,
  principalFingerprint: Sha256Digest | string,
): Sha256Digest {
  const parsedDatabaseId = databaseIdSchema.parse(databaseId);
  const parsedFingerprint = sha256DigestSchema.parse(principalFingerprint);
  return digestCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.discoveryTag,
    { databaseId: parsedDatabaseId, principalFingerprint: parsedFingerprint },
    discoveryTagInputSchema,
  );
}

/** Compute the AAD metadata digest without binding the digest field itself. */
export function computeAadMetadataDigest(aadMetadata: unknown): Sha256Digest {
  const parsedMetadata = parseAadMetadataInput(aadMetadata);
  return digestCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.aadMetadataDigest,
    parsedMetadata,
    collaborationAadMetadataSchema,
  );
}

/** Compute the digest of a completed payload AEAD envelope. */
export function computeEncryptedPayloadDigest(envelope: unknown): Sha256Digest {
  return computeCompletedEncryptedDigest(
    COLLABORATION_DOMAINS.encryptedPayloadDigest,
    'vault-payload',
    envelope,
  );
}

/** Compute the digest of a completed encrypted membership-manifest envelope. */
export function computeEncryptedMembershipDigest(envelope: unknown): Sha256Digest {
  return computeCompletedEncryptedDigest(
    COLLABORATION_DOMAINS.encryptedMembershipDigest,
    'membership-manifest',
    envelope,
  );
}

/** Hash a complete key envelope without its self-referential digest/signature fields. */
export function computeKeyEnvelopeDigest(envelope: unknown): Sha256Digest {
  const unsigned = parseUnsignedKeyEnvelope(envelope);
  return digestCanonicalValue(COLLABORATION_DOMAINS.keyEnvelopeDigest, unsigned);
}

/** Compute the canonical digest of a completed, order-independent envelope set. */
export function computeKeyEnvelopeSetDigest(envelopes: unknown): Sha256Digest {
  const parsed = parseKeyEnvelopeSet(envelopes);
  const ordered = parsed
    .map((envelope) => ({
      envelope,
      orderingBytes: canonicalJson(envelope),
    }))
    .sort((left, right) => {
      if (left.orderingBytes < right.orderingBytes) return -1;
      if (left.orderingBytes > right.orderingBytes) return 1;
      return 0;
    })
    .map(({ envelope }) => envelope);
  return digestCanonicalValue(COLLABORATION_DOMAINS.keyEnvelopeSetDigest, ordered);
}

/** Compute a policy digest omitting only policyDigest and its signature. */
export function computePolicyDigest(policy: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.policyDigest,
    parseUnsignedPolicy(policy),
  );
}

/**
 * Hash the logical approval-policy projection used by rollback anchors. The
 * separately anchored registry tuple and the full signed policy artifact may
 * advance without changing policyRevision or this digest.
 */
export function computePolicyStateDigest(policy: unknown): Sha256Digest {
  const parsed = parseSchema(policy, collaborationPolicyStateSchema);
  return digestCanonicalValue(COLLABORATION_DOMAINS.policyStateDigest, {
    protocolVersion: parsed.protocolVersion,
    databaseId: parsed.databaseId,
    vaultId: parsed.vaultId,
    authorityEpoch: parsed.authorityEpoch,
    policyRevision: parsed.policyRevision,
    approvalPolicy: parsed.approvalPolicy,
  });
}

/** Compute a device-registry digest omitting only registryDigest and its authority signature. */
export function computeDeviceRegistryDigest(registry: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.deviceRegistryDigest,
    parseUnsignedDeviceRegistry(registry),
  );
}

/** Compute a discovery-record digest omitting only its digest and writer signature. */
export function computeDiscoveryRecordDigest(record: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.discoveryRecordDigest,
    parseUnsignedDiscoveryRecord(record),
  );
}

/** Sign the exact current discovery record as the finalized-mutation writer. */
export function signDiscoveryRecord(
  record: unknown,
  privateKey: DeviceSigningPrivateKey | Uint8Array,
): Promise<string> {
  return signCollaborationRecord(
    COLLABORATION_DOMAINS.discoveryRecordSignature,
    record,
    collaborationDiscoveryRecordSchema,
    'writerSignature',
    privateKey,
  );
}

/** Verify an exact discovery record against its declared mutation writer. */
export function verifyDiscoveryRecord(
  record: unknown,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  return verifyCollaborationRecord(
    COLLABORATION_DOMAINS.discoveryRecordSignature,
    record,
    collaborationDiscoveryRecordSchema,
    'writerSignature',
    publicKey,
  );
}

/** Fingerprint a complete root-signed device certificate. */
export function computeDeviceCertificateFingerprint(
  certificate: unknown,
): Sha256Digest {
  const parsed = parseSchema(certificate, deviceCertificateSchema);
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.deviceCertificateFingerprint,
    parsed,
  );
}

/** Compute a membership-manifest digest omitting only membershipDigest. */
export function computeMembershipManifestDigest(manifest: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.membershipManifestDigest,
    parseUnsignedMembershipManifest(manifest),
  );
}

/** Compute a membership-history digest omitting only currentHistoryDigest. */
export function computeMembershipHistoryDigest(history: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.membershipHistoryDigest,
    parseUnsignedMembershipHistory(history),
  );
}

/** Hash the exact authenticated prior history and its reachable prior position. */
export function computeMembershipHistoryCompactionDigest(input: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.membershipHistoryCompactionDigest,
    parseSchema(input, membershipHistoryCompactionInputSchema),
  );
}

/** Hash the exact non-secret irreversible-destruction core committed by the link. */
export function computeCollaborativeVaultDestroyedPayloadDigest(
  core: unknown,
): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.collaborativeVaultDestroyedPayloadDigest,
    parseSchema(core, collaborationVaultDestructionCoreSchema),
  );
}

/** Hash the exact non-secret irreversible-destruction action projection. */
export function computeCollaborativeVaultDestructionActionDigest(
  action: unknown,
): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.collaborativeVaultDestructionActionDigest,
    parseSchema(action, collaborationVaultDestructionActionSchema),
  );
}

/** Compute an operation outcome digest without its digest or signed receipt. */
export function computeOperationOutcomeDigest(outcome: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.operationOutcomeDigest,
    parseUnsignedOperationOutcome(outcome),
  );
}

/** Sign the exact committed operation receipt as the writer device. */
export function signMutationReceipt(
  receipt: unknown,
  privateKey: DeviceSigningPrivateKey | Uint8Array,
): Promise<string> {
  return signCollaborationRecord(
    COLLABORATION_DOMAINS.mutationReceiptSignature,
    receipt,
    collaborationMutationReceiptSchema,
    'receiptSignature',
    privateKey,
  );
}

/** Verify the writer-device signature on one committed operation receipt. */
export function verifyMutationReceipt(
  receipt: unknown,
  publicKey: string | Uint8Array,
): Promise<boolean> {
  return verifyCollaborationRecord(
    COLLABORATION_DOMAINS.mutationReceiptSignature,
    receipt,
    collaborationMutationReceiptSchema,
    'receiptSignature',
    publicKey,
  );
}

/**
 * Verify a committed outcome's self-digest and exact writer-signed receipt.
 * Rejected/conflicted outcomes intentionally have no member signature.
 */
export async function verifyCommittedOperationOutcome(
  outcome: unknown,
  writerPublicKey: string | Uint8Array,
): Promise<boolean> {
  try {
    const parsed = parseSchema(outcome, durableOperationOutcomeSchema);
    if (
      parsed.state !== 'committed' ||
      parsed.signedMutationReceipt === undefined ||
      parsed.outcomeDigest !== computeOperationOutcomeDigest(parsed)
    ) {
      return false;
    }
    return await verifyMutationReceipt(parsed.signedMutationReceipt, writerPublicKey);
  } catch {
    return false;
  }
}

/** Compute the complete canonical operation tombstone digest. */
export function computeOperationTombstoneDigest(tombstone: unknown): Sha256Digest {
  const parsed = parseSchema(tombstone, operationDeduplicationTombstoneSchema);
  return digestCanonicalValue(COLLABORATION_DOMAINS.operationTombstoneDigest, parsed);
}

/** Authenticate a compact tombstone through its exact embedded signed receipt. */
export async function verifyOperationTombstone(
  tombstone: unknown,
  writerPublicKey: string | Uint8Array,
): Promise<boolean> {
  try {
    const parsed = parseSchema(tombstone, operationDeduplicationTombstoneSchema);
    return await verifyMutationReceipt(parsed.signedMutationReceipt, writerPublicKey);
  } catch {
    return false;
  }
}

/** Hash a database-authority recovery envelope without its self-reference. */
export function computeAuthorityRecoveryEnvelopeDigest(
  envelope: unknown,
): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.authorityRecoveryEnvelopeDigest,
    parseUnsignedAuthorityRecoveryEnvelope(envelope),
  );
}

/** Compute the complete strict legacy vault-document source digest. */
export function computeLegacySourceDigest(legacySource: unknown): Sha256Digest {
  const parsed = parseSchema(legacySource, databaseVaultDocumentSchema);
  return digestCanonicalValue(COLLABORATION_DOMAINS.legacySourceDigest, parsed);
}

/** Compute the immutable migration-request digest, excluding only its digest and two signatures. */
export function computeMigrationRequestDigest(request: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.migrationRequestDigest,
    parseUnsignedMigrationRequest(request),
  );
}

/** Sign a migration request with the database authority signature domain. */
export function signMigrationRequestAuthority(
  request: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  return signMigrationRequestInternal(
    request,
    privateKey,
    COLLABORATION_DOMAINS.migrationRequestAuthoritySignature,
  );
}

/** Verify the database authority signature on a migration request. */
export function verifyMigrationRequestAuthority(
  request: unknown,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  return verifyMigrationRequestInternal(
    request,
    publicKeyValue,
    COLLABORATION_DOMAINS.migrationRequestAuthoritySignature,
    'authoritySignature',
  );
}

/** Sign a migration request with the initial-owner signature domain. */
export function signMigrationRequestOwner(
  request: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  return signMigrationRequestInternal(
    request,
    privateKey,
    COLLABORATION_DOMAINS.migrationRequestOwnerSignature,
  );
}

/** Verify the initial-owner signature on a migration request. */
export function verifyMigrationRequestOwner(
  request: unknown,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  return verifyMigrationRequestInternal(
    request,
    publicKeyValue,
    COLLABORATION_DOMAINS.migrationRequestOwnerSignature,
    'ownerSignature',
  );
}

/** Sign a prepared migration marker, omitting only its authority signature. */
export function signMigrationPreparedMarker(
  marker: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  parseSchema(marker, collaborationMigrationPreparedMarkerSchema);
  return signCollaborationRecord(
    COLLABORATION_DOMAINS.migrationPreparedMarkerSignature,
    marker,
    collaborationMigrationPreparedMarkerSchema,
    'authoritySignature',
    privateKey,
  );
}

/** Verify a prepared migration marker authority signature. */
export function verifyMigrationPreparedMarker(
  marker: unknown,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  return verifyCollaborationRecord(
    COLLABORATION_DOMAINS.migrationPreparedMarkerSignature,
    marker,
    collaborationMigrationPreparedMarkerSchema,
    'authoritySignature',
    publicKeyValue,
  );
}

/** Sign an active migration marker, omitting only its authority signature. */
export function signMigrationActiveMarker(
  marker: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  parseSchema(marker, collaborationMigrationActiveMarkerSchema);
  return signCollaborationRecord(
    COLLABORATION_DOMAINS.migrationActiveMarkerSignature,
    marker,
    collaborationMigrationActiveMarkerSchema,
    'authoritySignature',
    privateKey,
  );
}

/** Verify an active migration marker authority signature. */
export function verifyMigrationActiveMarker(
  marker: unknown,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  return verifyCollaborationRecord(
    COLLABORATION_DOMAINS.migrationActiveMarkerSignature,
    marker,
    collaborationMigrationActiveMarkerSchema,
    'authoritySignature',
    publicKeyValue,
  );
}

/** Seal exactly one VRK to the immutable delegation's X25519 recovery key. */
export async function sealCollaborationVaultRootForDatabaseAuthority(
  vaultRootKey: VaultRootKey | Uint8Array,
  authorityRecoveryPublicKey: string | Uint8Array,
): Promise<string> {
  let recoveryPublicKey: Uint8Array | undefined;
  let sealed: Uint8Array | undefined;
  try {
    requireByteLength(vaultRootKey, COLLABORATION_KEY_BYTES, 'vault root key');
    recoveryPublicKey = decodeX25519PublicKey(authorityRecoveryPublicKey);
    await sodium.ready;
    sealed = sodium.crypto_box_seal(vaultRootKey, recoveryPublicKey);
    if (sealed.byteLength !== COLLABORATION_KEY_BYTES + SEALED_BOX_OVERHEAD_BYTES) {
      throw new CryptoInputError('Invalid authority recovery envelope length');
    }
    return base64UrlSchema.parse(encodeBase64Url(sealed));
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError(
      'Unable to seal the vault root key for authority recovery',
    );
  } finally {
    zeroize(recoveryPublicKey);
    zeroize(sealed);
  }
}

/**
 * Open an authority recovery wrapper only after re-deriving and matching the
 * delegation's public key. Wrong DRKs, database IDs, epochs, or delegations
 * are deliberately indistinguishable authentication failures.
 */
export async function openCollaborationVaultRootForDatabaseAuthority(
  sealedVaultRootKey: string,
  databaseRootKey: DatabaseRootKey | Uint8Array,
  databaseId: DatabaseId | string,
  authorityEpoch: number,
  expectedAuthorityRecoveryPublicKey: string | Uint8Array,
): Promise<VaultRootKey> {
  let recoveryKeyPair: DatabaseAuthorityRecoveryKeyPair | undefined;
  let expectedPublicKey: Uint8Array | undefined;
  let sealed: Uint8Array | undefined;
  let opened: Uint8Array | undefined;
  try {
    recoveryKeyPair = await deriveDatabaseAuthorityRecoveryKeyPair(
      databaseRootKey,
      databaseId,
      authorityEpoch,
    );
    expectedPublicKey = decodeX25519PublicKey(expectedAuthorityRecoveryPublicKey);
    if (!constantTimeEqual(recoveryKeyPair.publicKey, expectedPublicKey)) {
      throw new AuthenticationError();
    }
    const parsedSealed = base64UrlSchema.parse(sealedVaultRootKey);
    sealed = decodeBase64Url(parsedSealed, {
      exactBytes: COLLABORATION_KEY_BYTES + SEALED_BOX_OVERHEAD_BYTES,
      maximumBytes: COLLABORATION_KEY_BYTES + SEALED_BOX_OVERHEAD_BYTES,
    });
    await sodium.ready;
    opened = sodium.crypto_box_seal_open(
      sealed,
      recoveryKeyPair.publicKey,
      recoveryKeyPair.privateKey,
    );
    requireByteLength(opened, COLLABORATION_KEY_BYTES, 'vault root key');
    return opened as VaultRootKey;
  } catch {
    zeroize(opened);
    throw new AuthenticationError();
  } finally {
    zeroize(recoveryKeyPair?.publicKey);
    zeroize(recoveryKeyPair?.privateKey);
    zeroize(expectedPublicKey);
    zeroize(sealed);
  }
}

/** Compute the immutable request-core digest used by approval evidence. */
export function computeApprovalRequestDigest(request: unknown): Sha256Digest {
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.approvalRequestDigest,
    approvalRequestCore(parseApprovalRequestForDigest(request)),
  );
}

/**
 * Hash the caller's complete, non-secret administrative action projection.
 * The candidate builder recomputes this digest from the exact proposed state,
 * so an approval cannot authorize a different action projection.
 */
export function computeAdministrativeActionParametersDigest(
  actionParameters: unknown,
): Sha256Digest {
  const parsed = copyRecord(actionParameters);
  let canonical: string;
  try {
    canonical = canonicalJson(parsed);
  } catch {
    throw new CryptoInputError('Invalid collaboration action parameters');
  }
  if (Buffer.byteLength(canonical, 'utf8') > MAX_COLLABORATIVE_OPERATION_BYTES) {
    throw new CryptoInputError('Collaboration action parameters exceed their limit');
  }
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.administrativeActionParametersDigest,
    parsed,
  );
}

/** Sign the immutable approval request core plus its computed request digest. */
export function signApprovalRequest(
  request: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  return signApprovalRequestInternal(request, privateKey);
}

/** Verify an approval requester signature over the fixed request projection. */
export function verifyApprovalRequest(
  request: unknown,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  return verifyApprovalRequestInternal(request, publicKeyValue);
}

/** Compute the immutable transfer-intent core digest, excluding lifecycle fields. */
export function computeTransferIntentDigest(intent: unknown): Sha256Digest {
  const parsed = parseSchema(intent, transferIntentSchema) as Record<string, unknown>;
  return digestCanonicalValue(
    COLLABORATION_DOMAINS.transferIntentDigest,
    transferIntentCore(parsed),
  );
}

/** Sign the immutable transfer-intent core plus its stored digest. */
export async function signTransferIntent(
  intent: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  try {
    const parsed = parseSchema(intent, transferIntentSchema) as Record<string, unknown>;
    const computedDigest = computeTransferIntentDigest(parsed);
    if (parsed['intentDigest'] !== computedDigest) {
      throw new CryptoInputError('Invalid transfer intent digest');
    }
    return await signCanonicalProjection(
      COLLABORATION_DOMAINS.transferIntentSignature,
      transferIntentSignaturePayload(parsed),
      privateKey,
    );
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to create transfer intent signature');
  }
}

/** Verify an initiator signature over a complete transfer intent. */
export async function verifyTransferIntent(
  intent: unknown,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  try {
    const parsed = parseSchema(intent, transferIntentSchema) as Record<string, unknown>;
    if (parsed['intentDigest'] !== computeTransferIntentDigest(parsed)) {
      return false;
    }
    const signature = parsed['initiatorSignature'];
    if (typeof signature !== 'string') return false;
    return await verifyCanonicalProjection(
      COLLABORATION_DOMAINS.transferIntentSignature,
      transferIntentSignaturePayload(parsed),
      signature,
      publicKeyValue,
    );
  } catch {
    return false;
  }
}

/** Sign an ownership-transfer acceptance record, omitting only its signature. */
export function signOwnershipTransferAcceptance(
  acceptance: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  parseSchema(acceptance, ownershipTransferAcceptanceSchema);
  return signCollaborationRecord(
    COLLABORATION_DOMAINS.transferAcceptanceSignature,
    acceptance,
    ownershipTransferAcceptanceSchema,
    'signature',
    privateKey,
  );
}

/** Verify an ownership-transfer acceptance signature. */
export function verifyOwnershipTransferAcceptance(
  acceptance: unknown,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  return verifyCollaborationRecord(
    COLLABORATION_DOMAINS.transferAcceptanceSignature,
    acceptance,
    ownershipTransferAcceptanceSchema,
    'signature',
    publicKeyValue,
  );
}

/** Sign approval evidence, omitting only its signature. */
export function signApprovalEvidence(
  evidence: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  parseSchema(evidence, approvalEvidenceSchema);
  return signCollaborationRecord(
    COLLABORATION_DOMAINS.approvalEvidenceSignature,
    evidence,
    approvalEvidenceSchema,
    'signature',
    privateKey,
  );
}

/** Verify an approval-evidence signature. */
export function verifyApprovalEvidence(
  evidence: unknown,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  return verifyCollaborationRecord(
    COLLABORATION_DOMAINS.approvalEvidenceSignature,
    evidence,
    approvalEvidenceSchema,
    'signature',
    publicKeyValue,
  );
}

/** Seal exactly one 32-byte VRK to one X25519 device public key. */
export async function sealVaultRootKeyForDevice(
  vaultRootKey: VaultRootKey | Uint8Array,
  recipientEncryptionPublicKey: string | Uint8Array,
): Promise<string> {
  let recipientPublicKey: Uint8Array | undefined;
  let sealed: Uint8Array | undefined;
  try {
    requireByteLength(vaultRootKey, COLLABORATION_KEY_BYTES, 'vault root key');
    recipientPublicKey = decodeX25519PublicKey(recipientEncryptionPublicKey);
    await sodium.ready;
    sealed = sodium.crypto_box_seal(vaultRootKey, recipientPublicKey);
    if (sealed.byteLength !== COLLABORATION_KEY_BYTES + SEALED_BOX_OVERHEAD_BYTES) {
      throw new CryptoInputError('Invalid sealed vault root key length');
    }
    return base64UrlSchema.parse(encodeBase64Url(sealed));
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to seal the vault root key');
  } finally {
    zeroize(recipientPublicKey);
    zeroize(sealed);
  }
}

/** Open one sealed 32-byte VRK with the matching X25519 device pair. */
export async function openVaultRootKeyForDevice(
  sealedVaultRootKey: string,
  recipientEncryptionPublicKey: string | Uint8Array,
  recipientEncryptionPrivateKey: DeviceEncryptionPrivateKey | Uint8Array,
): Promise<VaultRootKey> {
  let sealed: Uint8Array | undefined;
  let recipientPublicKey: Uint8Array | undefined;
  let recipientPrivateKey: Uint8Array | undefined;
  let opened: Uint8Array | undefined;
  try {
    const parsedSealed = base64UrlSchema.parse(sealedVaultRootKey);
    sealed = decodeBase64Url(parsedSealed, {
      exactBytes: COLLABORATION_KEY_BYTES + SEALED_BOX_OVERHEAD_BYTES,
      maximumBytes: COLLABORATION_KEY_BYTES + SEALED_BOX_OVERHEAD_BYTES,
    });
    recipientPublicKey = decodeX25519PublicKey(recipientEncryptionPublicKey);
    recipientPrivateKey = copyPrivateKey(
      recipientEncryptionPrivateKey,
      X25519_PRIVATE_KEY_BYTES,
      'X25519 private key',
    );
    await sodium.ready;
    opened = sodium.crypto_box_seal_open(
      sealed,
      recipientPublicKey,
      recipientPrivateKey,
    );
    requireByteLength(opened, COLLABORATION_KEY_BYTES, 'vault root key');
    return opened as VaultRootKey;
  } catch {
    zeroize(opened);
    throw new AuthenticationError();
  } finally {
    zeroize(sealed);
    zeroize(recipientPublicKey);
    zeroize(recipientPrivateKey);
  }
}

/** Encrypt collaboration payload bytes with strict, authenticated collaboration AAD. */
export async function encryptCollaborationEnvelope(
  plaintext: Uint8Array,
  key: Uint8Array,
  associatedData: CollaborationAad,
): Promise<CollaborationAeadEnvelope> {
  let aadBytes: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  try {
    requireCollaborationKey(key);
    requirePlaintext(plaintext);
    const aad = collaborationAadSchema.parse(associatedData);
    assertAadMetadataDigest(aad);
    aadBytes = canonicalJsonBytes(COLLABORATION_DOMAINS.collaborationAad, aad);
    nonce = randomBytes(COLLABORATION_NONCE_BYTES);
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      plaintext,
      aadBytes,
      null,
      nonce,
      key,
    );
    ciphertext = encrypted.ciphertext;
    authenticationTag = encrypted.mac;
    return collaborativeAeadEnvelopeSchema.parse({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
      authenticationTag: encodeBase64Url(authenticationTag),
      aad,
    });
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to encrypt collaboration data');
  } finally {
    zeroize(aadBytes);
    zeroize(nonce);
    zeroize(ciphertext);
    zeroize(authenticationTag);
  }
}

/** Decrypt a collaboration envelope only when its complete AAD tuple matches. */
export async function decryptCollaborationEnvelope(
  envelope: CollaborationAeadEnvelope,
  key: Uint8Array,
  expectedAssociatedData: CollaborationAad,
): Promise<Uint8Array> {
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  let storedAadBytes: Uint8Array | undefined;
  let expectedAadBytes: Uint8Array | undefined;
  try {
    requireCollaborationKey(key);
    const parsedEnvelope = collaborativeAeadEnvelopeSchema.parse(envelope);
    const expected = collaborationAadSchema.parse(expectedAssociatedData);
    assertAadMetadataDigest(parsedEnvelope.aad);
    assertAadMetadataDigest(expected);
    storedAadBytes = canonicalJsonBytes(
      COLLABORATION_DOMAINS.collaborationAad,
      parsedEnvelope.aad,
    );
    expectedAadBytes = canonicalJsonBytes(
      COLLABORATION_DOMAINS.collaborationAad,
      expected,
    );
    if (!constantTimeEqual(storedAadBytes, expectedAadBytes)) {
      throw new AuthenticationError();
    }
    nonce = decodeBase64Url(parsedEnvelope.nonce, {
      exactBytes: COLLABORATION_NONCE_BYTES,
    });
    ciphertext = decodeBase64Url(parsedEnvelope.ciphertext, {
      maximumBytes: MAX_COLLABORATION_PLAINTEXT_BYTES,
    });
    authenticationTag = decodeBase64Url(parsedEnvelope.authenticationTag, {
      exactBytes: COLLABORATION_TAG_BYTES,
    });
    await sodium.ready;
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
      null,
      ciphertext,
      authenticationTag,
      expectedAadBytes,
      nonce,
      key,
    );
  } catch {
    throw new AuthenticationError();
  } finally {
    zeroize(nonce);
    zeroize(ciphertext);
    zeroize(authenticationTag);
    zeroize(storedAadBytes);
    zeroize(expectedAadBytes);
  }
}

/** Digest one strictly parsed collaboration value using a versioned domain. */
export function digestCanonicalCollaborationValue<T>(
  domain: CollaborationDomain,
  value: unknown,
  schema: SchemaLike<T>,
): Sha256Digest {
  const parsed = parseSchema(value, schema);
  return digestCanonicalValue(domain, parsed);
}

const discoveryTagInputSchema: SchemaLike<{
  readonly databaseId: DatabaseId;
  readonly principalFingerprint: Sha256Digest;
}> = {
  parse(value: unknown): {
    readonly databaseId: DatabaseId;
    readonly principalFingerprint: Sha256Digest;
  } {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new CryptoInputError('Invalid discovery tag input');
    }
    const candidate = value as Record<string, unknown>;
    const keys = Object.keys(candidate).sort();
    if (
      keys.length !== 2 ||
      keys[0] !== 'databaseId' ||
      keys[1] !== 'principalFingerprint'
    ) {
      throw new CryptoInputError('Invalid discovery tag input');
    }
    return {
      databaseId: databaseIdSchema.parse(candidate['databaseId']),
      principalFingerprint: sha256DigestSchema.parse(candidate['principalFingerprint']),
    };
  },
};

function generateSigningKeyPair<
  Kind extends 'principal-signing' | 'device-signing',
>(): Promise<
  Kind extends 'principal-signing' ? PrincipalSigningKeyPair : DeviceSigningKeyPair
> {
  return (async () => {
    const seed = randomBytes(ED25519_SEED_BYTES);
    let generated:
      { readonly publicKey: Uint8Array; readonly privateKey: Uint8Array } | undefined;
    try {
      await sodium.ready;
      generated = sodium.crypto_sign_seed_keypair(seed);
      const publicKey = copyPublicKey(
        generated.publicKey,
        'Ed25519 public key',
      ) as CollaborationEd25519PublicKey;
      const privateKey = copyPrivateKey(
        generated.privateKey,
        ED25519_PRIVATE_KEY_BYTES,
        'Ed25519 private key',
      ) as Kind extends 'principal-signing'
        ? PrincipalSigningPrivateKey
        : DeviceSigningPrivateKey;
      return {
        algorithm: 'ed25519',
        publicKey,
        publicKeyBase64: encodePublicKey(publicKey),
        privateKey,
      } as Kind extends 'principal-signing'
        ? PrincipalSigningKeyPair
        : DeviceSigningKeyPair;
    } catch (error) {
      if (error instanceof CryptoInputError) throw error;
      throw new CryptoInputError('Unable to generate collaboration signing keys');
    } finally {
      zeroize(generated?.publicKey);
      zeroize(generated?.privateKey);
      zeroize(seed);
    }
  })();
}

function canonicalSchemaBytes<T>(
  domain: CollaborationDomain,
  value: unknown,
  schema: SchemaLike<T>,
): Uint8Array {
  const parsed = parseSchema(value, schema);
  return canonicalJsonBytes(domain, parsed);
}

function parseSchema<T>(value: unknown, schema: SchemaLike<T>): T {
  try {
    return schema.parse(value);
  } catch {
    throw new CryptoInputError('Invalid collaboration record');
  }
}

function canonicalJsonBytes(domain: CollaborationDomain, value: unknown): Uint8Array {
  assertVersionedDomain(domain);
  const canonical = canonicalJson(value);
  const domainBytes = Buffer.from(domain, 'ascii');
  const valueBytes = Buffer.from(canonical, 'utf8');
  const domainLength = Buffer.allocUnsafe(4);
  const valueLength = Buffer.allocUnsafe(4);
  domainLength.writeUInt32BE(domainBytes.byteLength);
  valueLength.writeUInt32BE(valueBytes.byteLength);
  try {
    return Buffer.concat([domainLength, domainBytes, valueLength, valueBytes]);
  } finally {
    zeroize(domainLength);
    zeroize(valueLength);
    zeroize(domainBytes);
    zeroize(valueBytes);
  }
}

function digestCanonicalValue(
  domain: CollaborationDomain,
  value: unknown,
): Sha256Digest {
  let bytes: Uint8Array | undefined;
  let digest: Uint8Array | undefined;
  try {
    bytes = canonicalJsonBytes(domain, value);
    digest = createHash('sha256').update(bytes).digest();
    return sha256DigestSchema.parse(encodeBase64Url(digest));
  } finally {
    zeroize(bytes);
    zeroize(digest);
  }
}

function parseAadMetadataInput(value: unknown): CollaborationAadMetadata {
  const candidate = copyRecord(value);
  if (Object.prototype.hasOwnProperty.call(candidate, 'metadataDigest')) {
    const parsed = parseSchema(candidate, collaborationAadSchema) as Record<
      string,
      unknown
    >;
    delete parsed['metadataDigest'];
    return parseSchema(parsed, collaborationAadMetadataSchema);
  }
  return parseSchema(candidate, collaborationAadMetadataSchema);
}

function assertAadMetadataDigest(aad: unknown): void {
  const parsed = parseSchema(aad, collaborationAadSchema);
  const computed = computeAadMetadataDigest(parsed);
  let actualBytes: Uint8Array | undefined;
  let computedBytes: Uint8Array | undefined;
  try {
    actualBytes = decodeBase64Url(parsed.metadataDigest, {
      exactBytes: COLLABORATION_KEY_BYTES,
    });
    computedBytes = decodeBase64Url(computed, {
      exactBytes: COLLABORATION_KEY_BYTES,
    });
    if (!constantTimeEqual(actualBytes, computedBytes)) {
      throw new CryptoInputError('Invalid collaboration AAD metadata digest');
    }
  } finally {
    zeroize(actualBytes);
    zeroize(computedBytes);
  }
}

function computeCompletedEncryptedDigest(
  domain: CollaborationDomain,
  entityType: 'vault-payload' | 'membership-manifest',
  envelope: unknown,
): Sha256Digest {
  const parsed = parseSchema(envelope, collaborativeAeadEnvelopeSchema);
  if (parsed.aad.entityType !== entityType) {
    throw new CryptoInputError('Collaboration envelope entity type mismatch');
  }
  assertAadMetadataDigest(parsed.aad);
  return digestCanonicalValue(domain, parsed);
}

function parseUnsignedKeyEnvelope(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  candidate['envelopeDigest'] = PLACEHOLDER_DIGEST;
  candidate['ownerSignature'] = PLACEHOLDER_SIGNATURE;
  const parsed = parseSchema(candidate, collaborationKeyEnvelopeSchema) as Record<
    string,
    unknown
  >;
  delete parsed['envelopeDigest'];
  delete parsed['ownerSignature'];
  return parsed;
}

function parseMutationRequestProjection(value: unknown): Record<string, unknown> {
  const parsed = parseSchema(value, collaborationMutationCommitmentSchema) as Record<
    string,
    unknown
  >;
  if (parsed['operationType'] === 'genesis-migration') {
    throw new CryptoInputError(
      'Genesis migration requires its specialized signed request digest',
    );
  }
  delete parsed['requestDigest'];
  return parsed;
}

function parseKeyEnvelopeSet(
  value: unknown,
): (
  | ReturnType<typeof collaborationKeyEnvelopeSchema.parse>
  | ReturnType<typeof databaseAuthorityRecoveryEnvelopeSchema.parse>
)[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > MAX_COLLABORATIVE_KEY_ENVELOPES
  ) {
    throw new CryptoInputError('Invalid collaboration key-envelope set');
  }
  return value.map((entry) => {
    try {
      return parseSchema(entry, collaborationKeyEnvelopeSchema);
    } catch {
      return parseSchema(entry, databaseAuthorityRecoveryEnvelopeSchema);
    }
  });
}

function parseUnsignedPolicy(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  candidate['policyDigest'] = PLACEHOLDER_DIGEST;
  candidate['signature'] = PLACEHOLDER_SIGNATURE;
  const parsed = parseSchema(candidate, collaborationPolicyStateSchema) as Record<
    string,
    unknown
  >;
  delete parsed['policyDigest'];
  delete parsed['signature'];
  return parsed;
}

function parseUnsignedDeviceRegistry(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  candidate['registryDigest'] = PLACEHOLDER_DIGEST;
  candidate['authoritySignature'] = PLACEHOLDER_SIGNATURE;
  const parsed = parseSchema(
    candidate,
    collaborationDatabaseDeviceRegistrySchema,
  ) as Record<string, unknown>;
  delete parsed['registryDigest'];
  delete parsed['authoritySignature'];
  return parsed;
}

function parseUnsignedDiscoveryRecord(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  candidate['discoveryRecordDigest'] = PLACEHOLDER_DIGEST;
  candidate['writerSignature'] = PLACEHOLDER_SIGNATURE;
  const parsed = parseSchema(candidate, collaborationDiscoveryRecordSchema) as Record<
    string,
    unknown
  >;
  delete parsed['discoveryRecordDigest'];
  delete parsed['writerSignature'];
  return parsed;
}

function parseUnsignedMembershipManifest(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  candidate['membershipDigest'] = PLACEHOLDER_DIGEST;
  const parsed = parseSchema(
    candidate,
    collaborativeMembershipManifestSchema,
  ) as Record<string, unknown>;
  delete parsed['membershipDigest'];
  return parsed;
}

function parseUnsignedMembershipHistory(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  candidate['currentHistoryDigest'] = PLACEHOLDER_DIGEST;
  const parsed = parseSchema(candidate, membershipHistorySchema) as Record<
    string,
    unknown
  >;
  delete parsed['currentHistoryDigest'];
  return parsed;
}

function parseApprovalRequestForDigest(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  const suppliedRequestDigest = candidate['requestDigest'];
  if (suppliedRequestDigest !== undefined) {
    try {
      sha256DigestSchema.parse(suppliedRequestDigest);
    } catch {
      throw new CryptoInputError('Invalid approval request digest');
    }
  }
  const suppliedRequesterSignature = candidate['requesterSignature'];
  if (suppliedRequesterSignature !== undefined) {
    try {
      collaborationSignatureSchema.parse(suppliedRequesterSignature);
    } catch {
      throw new CryptoInputError('Invalid approval requester signature');
    }
  }
  candidate['requestDigest'] = PLACEHOLDER_DIGEST;
  candidate['requesterSignature'] = PLACEHOLDER_SIGNATURE;
  candidate['state'] = 'pending';
  candidate['approvals'] = [];
  delete candidate['resolvedAt'];
  return parseSchema(candidate, approvalRequestSchema);
}

function approvalRequestCore(
  request: Record<string, unknown>,
): Record<string, unknown> {
  return {
    format: request['format'],
    protocolVersion: request['protocolVersion'],
    approvalRequestId: request['approvalRequestId'],
    operationId: request['operationId'],
    operationType: request['operationType'],
    databaseId: request['databaseId'],
    vaultId: request['vaultId'],
    actionParametersDigest: request['actionParametersDigest'],
    authorityEpoch: request['authorityEpoch'],
    databaseDeviceGeneration: request['databaseDeviceGeneration'],
    databaseDeviceRegistryDigest: request['databaseDeviceRegistryDigest'],
    documentRevision: request['documentRevision'],
    membershipRevision: request['membershipRevision'],
    policyRevision: request['policyRevision'],
    keyEpoch: request['keyEpoch'],
    priorHeadDigest: request['priorHeadDigest'],
    authorizationStateDigest: request['authorizationStateDigest'],
    requestingPrincipalId: request['requestingPrincipalId'],
    requestingDeviceId: request['requestingDeviceId'],
    requiredApprovalPolicy: request['requiredApprovalPolicy'],
    createdAt: request['createdAt'],
    expiresAt: request['expiresAt'],
    nonce: request['nonce'],
  };
}

function approvalRequestSignaturePayload(
  request: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...approvalRequestCore(request),
    requestDigest: request['requestDigest'],
  };
}

function transferIntentCore(intent: Record<string, unknown>): Record<string, unknown> {
  const core: Record<string, unknown> = {
    format: intent['format'],
    protocolVersion: intent['protocolVersion'],
    transferIntentId: intent['transferIntentId'],
    operationId: intent['operationId'],
    databaseId: intent['databaseId'],
    vaultId: intent['vaultId'],
    initiatorPrincipalId: intent['initiatorPrincipalId'],
    initiatorDeviceId: intent['initiatorDeviceId'],
    recipientPrincipalId: intent['recipientPrincipalId'],
    recipientDeviceId: intent['recipientDeviceId'],
    targetRole: intent['targetRole'],
    originalOwnerDisposition: intent['originalOwnerDisposition'],
    authorityEpoch: intent['authorityEpoch'],
    databaseDeviceGeneration: intent['databaseDeviceGeneration'],
    databaseDeviceRegistryDigest: intent['databaseDeviceRegistryDigest'],
    documentRevision: intent['documentRevision'],
    membershipRevision: intent['membershipRevision'],
    policyRevision: intent['policyRevision'],
    keyEpoch: intent['keyEpoch'],
    currentHeadDigest: intent['currentHeadDigest'],
    authorizationStateDigest: intent['authorizationStateDigest'],
    createdAt: intent['createdAt'],
    expiresAt: intent['expiresAt'],
  };
  if (intent['approvalRequestId'] !== undefined) {
    core['approvalRequestId'] = intent['approvalRequestId'];
  }
  return core;
}

function transferIntentSignaturePayload(
  intent: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...transferIntentCore(intent),
    intentDigest: intent['intentDigest'],
  };
}

async function signApprovalRequestInternal(
  value: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
): Promise<string> {
  try {
    const request = parseSchema(value, approvalRequestSchema) as Record<
      string,
      unknown
    >;
    const requestDigest = computeApprovalRequestDigest(request);
    if (request['requestDigest'] !== requestDigest) {
      throw new CryptoInputError('Invalid approval request digest');
    }
    return await signCanonicalProjection(
      COLLABORATION_DOMAINS.approvalRequestSignature,
      approvalRequestSignaturePayload(request),
      privateKey,
    );
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to create approval request signature');
  }
}

async function verifyApprovalRequestInternal(
  value: unknown,
  publicKeyValue: string | Uint8Array,
): Promise<boolean> {
  try {
    const request = parseSchema(value, approvalRequestSchema) as Record<
      string,
      unknown
    >;
    const requestDigest = computeApprovalRequestDigest(request);
    if (request['requestDigest'] !== requestDigest) return false;
    const signatureValue = request['requesterSignature'];
    if (typeof signatureValue !== 'string') return false;
    return await verifyCanonicalProjection(
      COLLABORATION_DOMAINS.approvalRequestSignature,
      approvalRequestSignaturePayload(request),
      signatureValue,
      publicKeyValue,
    );
  } catch {
    return false;
  }
}

function authorizationTransitionUnsignedCore(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  if (candidate['transitionDigest'] !== undefined) {
    parseSchema(candidate['transitionDigest'], sha256DigestSchema);
  }
  const signatureCandidate = copyRecord(candidate['transitionSignature']);
  if (signatureCandidate['signature'] !== undefined) {
    parseSchema(signatureCandidate['signature'], collaborationSignatureSchema);
  }
  candidate['transitionDigest'] = PLACEHOLDER_DIGEST;
  candidate['transitionSignature'] = {
    ...signatureCandidate,
    signature: PLACEHOLDER_SIGNATURE,
  };
  const parsed = parseSchema(
    candidate,
    collaborationAuthorizationTransitionSchema,
  ) as Record<string, unknown>;
  const signature = copyRecord(parsed['transitionSignature']);
  delete signature['signature'];
  delete parsed['transitionDigest'];
  parsed['transitionSignature'] = signature;
  return parsed;
}

function authorizationTransitionSignaturePayload(
  transition: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...authorizationTransitionUnsignedCore(transition),
    transitionDigest: transition['transitionDigest'],
  };
}

async function signAuthorizationTransitionInternal(
  value: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
  signerKind: 'owner-device' | 'database-authority',
): Promise<string> {
  let authorityPublicKey: Uint8Array | undefined;
  try {
    const transition = parseSchema(value, collaborationAuthorizationTransitionSchema);
    if (transition.transitionSignature.signerKind !== signerKind) {
      throw new CryptoInputError('Invalid authorization-transition signer kind');
    }
    if (signerKind === 'database-authority') {
      authorityPublicKey = await deriveEd25519PublicKey(privateKey);
      if (!authorityTransitionAuthorityBindingsMatch(transition, authorityPublicKey)) {
        throw new CryptoInputError(
          'Invalid authorization-transition authority binding',
        );
      }
    }
    assertStoredDigest(
      transition.transitionDigest,
      computeAuthorizationTransitionDigest(transition),
      'authorization transition',
    );
    const domain =
      signerKind === 'owner-device'
        ? COLLABORATION_DOMAINS.authorizationTransitionOwnerSignature
        : COLLABORATION_DOMAINS.authorizationTransitionAuthoritySignature;
    return await signCanonicalProjection(
      domain,
      authorizationTransitionSignaturePayload(transition),
      privateKey,
    );
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to sign authorization transition');
  } finally {
    zeroize(authorityPublicKey);
  }
}

async function verifyAuthorizationTransitionInternal(
  value: unknown,
  publicKey: string | Uint8Array,
  signerKind: 'owner-device' | 'database-authority',
): Promise<boolean> {
  try {
    const transition = parseSchema(value, collaborationAuthorizationTransitionSchema);
    const signature = transition.transitionSignature;
    if (
      signature.signerKind !== signerKind ||
      transition.transitionDigest !==
        computeAuthorizationTransitionDigest(transition) ||
      (signerKind === 'database-authority' &&
        !authorityTransitionAuthorityBindingsMatch(transition, publicKey))
    ) {
      return false;
    }
    const domain =
      signerKind === 'owner-device'
        ? COLLABORATION_DOMAINS.authorizationTransitionOwnerSignature
        : COLLABORATION_DOMAINS.authorizationTransitionAuthoritySignature;
    return await verifyCanonicalProjection(
      domain,
      authorizationTransitionSignaturePayload(transition),
      signature.signature,
      publicKey,
    );
  } catch {
    return false;
  }
}

function authorityTransitionAuthorityBindingsMatch(
  transition: ReturnType<typeof collaborationAuthorizationTransitionSchema.parse>,
  publicKey: string | Uint8Array,
): boolean {
  const signature = transition.transitionSignature;
  return (
    signature.signerKind === 'database-authority' &&
    signature.authorityEpoch === transition.previousTuple.authorityEpoch &&
    signature.authorityEpoch === transition.nextTuple.authorityEpoch &&
    signature.authoritySigningKeyFingerprint ===
      computePublicKeyFingerprint(publicKey, 'ed25519')
  );
}

function parseAndValidateFinalizedMutationLink(
  value: unknown,
): ReturnType<typeof collaborationFinalizedMutationLinkSchema.parse> {
  const link = parseSchema(value, collaborationFinalizedMutationLinkSchema);
  if (link.resultingHeadDigest !== computeMutationHead(link.commitment)) {
    throw new CryptoInputError('Invalid finalized mutation head');
  }
  if (
    link.authorizationTransition !== undefined &&
    link.authorizationTransition.transitionDigest !==
      computeAuthorizationTransitionDigest(link.authorizationTransition)
  ) {
    throw new CryptoInputError('Invalid finalized authorization transition');
  }
  return link;
}

function finalizedMutationLinkSignaturePayload(
  link: ReturnType<typeof collaborationFinalizedMutationLinkSchema.parse>,
): Record<string, unknown> {
  const writerSignature = { ...link.writerSignature };
  delete (writerSignature as { signature?: string }).signature;
  return { ...link, writerSignature };
}

function authorizationCheckpointUnsignedCore(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  if (candidate['checkpointDigest'] !== undefined) {
    parseSchema(candidate['checkpointDigest'], sha256DigestSchema);
  }
  if (candidate['ownerSignature'] !== undefined) {
    parseSchema(candidate['ownerSignature'], collaborationSignatureSchema);
  }
  candidate['checkpointDigest'] = PLACEHOLDER_DIGEST;
  candidate['ownerSignature'] = PLACEHOLDER_SIGNATURE;
  const parsed = parseSchema(
    candidate,
    collaborationAuthorizationCheckpointSchema,
  ) as Record<string, unknown>;
  delete parsed['checkpointDigest'];
  delete parsed['ownerSignature'];
  return parsed;
}

function authorizationCheckpointSignaturePayload(
  checkpoint: ReturnType<typeof collaborationAuthorizationCheckpointSchema.parse>,
): Record<string, unknown> {
  return {
    ...authorizationCheckpointUnsignedCore(checkpoint),
    checkpointDigest: checkpoint.checkpointDigest,
  };
}

function parseAndValidateAuthorityDelegation(
  value: unknown,
): ReturnType<typeof collaborationAuthorityDelegationSchema.parse> {
  const delegation = parseSchema(value, collaborationAuthorityDelegationSchema);
  if (
    delegation.authoritySigningKeyFingerprint !==
      computePublicKeyFingerprint(delegation.authoritySigningPublicKey, 'ed25519') ||
    delegation.authorityRecoveryKeyFingerprint !==
      computePublicKeyFingerprint(delegation.authorityRecoveryPublicKey, 'x25519')
  ) {
    throw new CryptoInputError('Invalid authority delegation key fingerprint');
  }
  return delegation;
}

function parseAndValidateEnrollmentReceipt(
  value: unknown,
): ReturnType<typeof enrollmentReceiptSchema.parse> {
  const receipt = parseSchema(value, enrollmentReceiptSchema);
  if (
    receipt.authorityDelegationDigest !==
    computeAuthorityDelegationDigest(receipt.authorityDelegation)
  ) {
    throw new CryptoInputError('Invalid enrollment authority delegation digest');
  }
  return receipt;
}

function parseUnsignedOperationOutcome(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  candidate['outcomeDigest'] = PLACEHOLDER_DIGEST;
  if (candidate['state'] === 'committed') {
    candidate['signedMutationReceipt'] = placeholderMutationReceipt(candidate);
  } else {
    delete candidate['signedMutationReceipt'];
  }
  const parsed = parseSchema(candidate, durableOperationOutcomeSchema) as Record<
    string,
    unknown
  >;
  delete parsed['outcomeDigest'];
  delete parsed['signedMutationReceipt'];
  return parsed;
}

function placeholderMutationReceipt(
  outcome: Record<string, unknown>,
): Record<string, unknown> {
  return {
    format: 'kavrix-collaborative-mutation-receipt',
    protocolVersion: outcome['protocolVersion'],
    databaseId: outcome['databaseId'],
    vaultId: outcome['vaultId'],
    operationId: outcome['operationId'],
    operationType: outcome['operationType'],
    requestDigest: outcome['requestDigest'],
    actorPrincipalId: outcome['actorPrincipalId'],
    actorDeviceId: outcome['actorDeviceId'],
    priorTuple: outcome['priorTuple'],
    priorHeadDigest: outcome['priorHeadDigest'],
    committedTuple: outcome['committedTuple'],
    committedHeadDigest: outcome['committedHeadDigest'],
    finalizedMutationLinkDigest: outcome['finalizedMutationLinkDigest'],
    outcomeDigest: PLACEHOLDER_DIGEST,
    committedAt: outcome['committedAt'],
    receiptSignature: PLACEHOLDER_SIGNATURE,
  };
}

function parseUnsignedAuthorityRecoveryEnvelope(
  value: unknown,
): Record<string, unknown> {
  const candidate = copyRecord(value);
  candidate['envelopeDigest'] = PLACEHOLDER_DIGEST;
  candidate['ownerSignature'] = PLACEHOLDER_SIGNATURE;
  const parsed = parseSchema(
    candidate,
    databaseAuthorityRecoveryEnvelopeSchema,
  ) as Record<string, unknown>;
  delete parsed['envelopeDigest'];
  delete parsed['ownerSignature'];
  return parsed;
}

function parseUnsignedMigrationRequest(value: unknown): Record<string, unknown> {
  const candidate = copyRecord(value);
  if (candidate['requestDigest'] !== undefined) {
    parseSchema(candidate['requestDigest'], sha256DigestSchema);
  }
  if (candidate['authoritySignature'] !== undefined) {
    parseSchema(candidate['authoritySignature'], collaborationSignatureSchema);
  }
  if (candidate['ownerSignature'] !== undefined) {
    parseSchema(candidate['ownerSignature'], collaborationSignatureSchema);
  }
  candidate['requestDigest'] = PLACEHOLDER_DIGEST;
  candidate['authoritySignature'] = PLACEHOLDER_SIGNATURE;
  candidate['ownerSignature'] = PLACEHOLDER_SIGNATURE;
  const parsed = parseSchema(candidate, collaborationMigrationRequestSchema) as Record<
    string,
    unknown
  >;
  delete parsed['requestDigest'];
  delete parsed['authoritySignature'];
  delete parsed['ownerSignature'];
  return parsed;
}

function migrationRequestSignaturePayload(
  request: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...parseUnsignedMigrationRequest(request),
    requestDigest: request['requestDigest'],
  };
}

async function signMigrationRequestInternal(
  value: unknown,
  privateKey: Ed25519PrivateKey | Uint8Array,
  domain: CollaborationDomain,
): Promise<string> {
  try {
    const request = parseSchema(value, collaborationMigrationRequestSchema) as Record<
      string,
      unknown
    >;
    const requestDigest = computeMigrationRequestDigest(request);
    if (request['requestDigest'] !== requestDigest) {
      throw new CryptoInputError('Invalid migration request digest');
    }
    return await signCanonicalProjection(
      domain,
      migrationRequestSignaturePayload(request),
      privateKey,
    );
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new CryptoInputError('Unable to create migration request signature');
  }
}

async function verifyMigrationRequestInternal(
  value: unknown,
  publicKeyValue: string | Uint8Array,
  domain: CollaborationDomain,
  signatureField: 'authoritySignature' | 'ownerSignature',
): Promise<boolean> {
  try {
    const request = parseSchema(value, collaborationMigrationRequestSchema) as Record<
      string,
      unknown
    >;
    if (request['requestDigest'] !== computeMigrationRequestDigest(request)) {
      return false;
    }
    const signature = request[signatureField];
    if (typeof signature !== 'string') return false;
    return await verifyCanonicalProjection(
      domain,
      migrationRequestSignaturePayload(request),
      signature,
      publicKeyValue,
    );
  } catch {
    return false;
  }
}

function parseUnsignedSignatureRecord<T>(
  value: unknown,
  schema: SchemaLike<T>,
  signatureField: CollaborationSignatureField,
): Record<string, unknown> {
  assertSignatureField(signatureField);
  const candidate = copyRecord(value);
  candidate[signatureField] = PLACEHOLDER_SIGNATURE;
  const parsed = parseSchema(candidate, schema) as Record<string, unknown>;
  return Object.fromEntries(
    Object.entries(parsed).filter(([key]) => key !== signatureField),
  );
}

function copyRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new CryptoInputError('Invalid collaboration record');
  }
  return { ...(value as Record<string, unknown>) };
}

function assertStoredDigest(
  stored: unknown,
  computed: Sha256Digest,
  label: string,
): void {
  if (sha256DigestSchema.parse(stored) !== computed) {
    throw new CryptoInputError(`Invalid ${label} digest`);
  }
}

function assertSignatureField(
  field: string,
): asserts field is CollaborationSignatureField {
  if (
    field !== 'signature' &&
    field !== 'selfSignature' &&
    field !== 'rootSignature' &&
    field !== 'ownerSignature' &&
    field !== 'writerSignature' &&
    field !== 'authoritySignature' &&
    field !== 'initiatorSignature' &&
    field !== 'requesterSignature' &&
    field !== 'receiptSignature'
  ) {
    throw new CryptoInputError('Invalid collaboration signature field');
  }
}

function requireCollaborationKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.byteLength !== COLLABORATION_KEY_BYTES) {
    throw new CryptoInputError('Collaboration keys must encode exactly 32 bytes');
  }
}

function requirePlaintext(plaintext: Uint8Array): void {
  if (
    !(plaintext instanceof Uint8Array) ||
    plaintext.byteLength === 0 ||
    plaintext.byteLength > MAX_COLLABORATION_PLAINTEXT_BYTES
  ) {
    throw new CryptoInputError(
      'Collaboration plaintext is empty or outside the supported range',
    );
  }
}

function requireEd25519PrivateKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.byteLength !== ED25519_PRIVATE_KEY_BYTES) {
    throw new CryptoInputError('Ed25519 private keys must encode exactly 64 bytes');
  }
}

function copyPrivateKey(
  key: Uint8Array,
  expectedBytes: number,
  label: string,
): Uint8Array {
  requireByteLength(key, expectedBytes, label);
  return Uint8Array.from(key);
}

function copyPublicKey(key: Uint8Array, label: string): Uint8Array {
  requireByteLength(key, 32, label);
  return Uint8Array.from(key);
}

function encodePublicKey(publicKey: Uint8Array): string {
  requireByteLength(publicKey, 32, 'collaboration public key');
  return collaborationPublicKeySchema.parse(encodeBase64Url(publicKey));
}

function decodeEd25519PublicKey(publicKey: string | Uint8Array): Uint8Array {
  return decodePublicKey(publicKey);
}

async function deriveEd25519PublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  let seed: Uint8Array | undefined;
  let generated:
    { readonly publicKey: Uint8Array; readonly privateKey: Uint8Array } | undefined;
  try {
    requireEd25519PrivateKey(privateKey);
    seed = Uint8Array.from(privateKey.subarray(0, ED25519_SEED_BYTES));
    await sodium.ready;
    generated = sodium.crypto_sign_seed_keypair(seed);
    if (!constantTimeEqual(generated.privateKey, privateKey)) {
      throw new CryptoInputError('Invalid Ed25519 private key');
    }
    return copyPublicKey(generated.publicKey, 'Ed25519 public key');
  } finally {
    zeroize(seed);
    zeroize(generated?.publicKey);
    zeroize(generated?.privateKey);
  }
}

function decodeX25519PublicKey(publicKey: string | Uint8Array): Uint8Array {
  return decodePublicKey(publicKey);
}

function decodePublicKey(publicKey: string | Uint8Array): Uint8Array {
  if (typeof publicKey === 'string') {
    const parsed = collaborationPublicKeySchema.parse(publicKey);
    return decodeBase64Url(parsed, { exactBytes: 32 });
  }
  const encoded = encodePublicKey(publicKey);
  const parsed = collaborationPublicKeySchema.parse(encoded);
  return decodeBase64Url(parsed, { exactBytes: 32 });
}

function publicKeysEqual(
  left: string | Uint8Array,
  right: string | Uint8Array,
): boolean {
  let leftBytes: Uint8Array | undefined;
  let rightBytes: Uint8Array | undefined;
  try {
    leftBytes = decodePublicKey(left);
    rightBytes = decodePublicKey(right);
    return constantTimeEqual(leftBytes, rightBytes);
  } finally {
    zeroize(leftBytes);
    zeroize(rightBytes);
  }
}

function decodeSignature(signature: string): Uint8Array {
  const parsed = collaborationSignatureSchema.parse(signature);
  return decodeBase64Url(parsed, { exactBytes: ED25519_SIGNATURE_BYTES });
}

function assertVersionedDomain(domain: string): void {
  if (
    typeof domain !== 'string' ||
    !/^[\x21-\x7e]+$/.test(domain) ||
    !/\/v[1-9][0-9]*$/.test(domain)
  ) {
    throw new CryptoInputError(
      'Collaboration domains must be explicit versioned ASCII',
    );
  }
}
