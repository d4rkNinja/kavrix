import { z } from 'zod';

import { canonicalJson } from './content-hash.js';
import { databaseVaultDocumentSchema } from './database-container.js';
import {
  approvalRequestIdSchema,
  collaborationOperationIdSchema,
  databaseIdSchema,
  deviceIdSchema,
  historyIdSchema,
  membershipIdSchema,
  principalIdSchema,
  transferIntentIdSchema,
  vaultIdSchema,
} from './identifiers.js';
import {
  base64UrlSchema,
  revisionSchema,
  sha256DigestSchema,
  timestampSchema,
  utf8ByteLength,
} from './primitives.js';

/** The independently versioned Mongo-only collaboration wire protocol. */
export const COLLABORATIVE_VAULT_FORMAT = 'kavrix-collaborative-vault';
export const COLLABORATIVE_PUBLIC_IDENTITY_FORMAT =
  'kavrix-collaborative-public-identity';
export const COLLABORATIVE_ENROLLMENT_RECEIPT_FORMAT =
  'kavrix-collaborative-enrollment-receipt';
export const COLLABORATIVE_MEMBERSHIP_MANIFEST_FORMAT =
  'kavrix-collaborative-membership-manifest';
export const COLLABORATIVE_DISCOVERY_RECORD_FORMAT =
  'kavrix-collaborative-discovery-record';
export const COLLABORATIVE_DEVICE_REGISTRY_FORMAT =
  'kavrix-collaborative-device-registry';
export const COLLABORATIVE_KEY_ENVELOPE_FORMAT =
  'kavrix-collaborative-member-key-envelope';
export const COLLABORATIVE_OPERATION_OUTCOME_FORMAT =
  'kavrix-collaborative-operation-outcome';
export const COLLABORATIVE_MUTATION_RECEIPT_FORMAT =
  'kavrix-collaborative-mutation-receipt';
export const COLLABORATIVE_OPERATION_TOMBSTONE_FORMAT =
  'kavrix-collaborative-operation-tombstone';
export const COLLABORATIVE_TRANSFER_INTENT_FORMAT =
  'kavrix-collaborative-transfer-intent';
export const COLLABORATIVE_ROLLBACK_ANCHOR_FORMAT =
  'kavrix-collaborative-recipient-rollback-anchor';
export const COLLABORATIVE_MIGRATION_MARKER_FORMAT =
  'kavrix-collaborative-migration-marker';
export const COLLABORATIVE_AUTHORITY_DELEGATION_FORMAT =
  'kavrix-collaborative-authority-delegation';
export const COLLABORATIVE_AUTHORIZATION_TRANSITION_FORMAT =
  'kavrix-collaborative-authorization-transition';
export const COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT =
  'kavrix-collaborative-finalized-mutation-link';
export const COLLABORATIVE_AUTHORIZATION_CHECKPOINT_FORMAT =
  'kavrix-collaborative-authorization-checkpoint';
export const COLLABORATIVE_MUTATION_PROOF_FORMAT =
  'kavrix-collaborative-mutation-proof';
export const COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT =
  'kavrix-collaborative-authorization-witness';
export const COLLABORATIVE_VAULT_DESTRUCTION_CORE_FORMAT =
  'kavrix-collaborative-vault-destruction-core';
export const COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_FORMAT =
  'kavrix-collaborative-vault-destruction-tombstone';
export const COLLABORATIVE_RECIPIENT_VAULT_DESTRUCTION_ANCHOR_FORMAT =
  'kavrix-collaborative-recipient-vault-destruction-anchor';

export const COLLABORATION_PROTOCOL_VERSION = 1;
export const COLLABORATIVE_DOCUMENT_VERSION = 1;
export const CURRENT_COLLABORATION_PROTOCOL_VERSION = COLLABORATION_PROTOCOL_VERSION;
export const CURRENT_COLLABORATIVE_DOCUMENT_VERSION = COLLABORATIVE_DOCUMENT_VERSION;
/** Fixed predecessor head for the first collaborative document revision. */
export const COLLABORATION_GENESIS_HEAD_DIGEST = sha256DigestSchema.parse(
  'RiTK4FdPLkENRfqO-EKfcCdvB7wllEvCOOOdXS_6yAA',
);
/** Fixed predecessor authorization state for the first collaborative revision. */
export const COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST =
  sha256DigestSchema.parse('PZF17edxefLzSDCRJPU0Evstf6KOYz6V6iR28UOjluM');
/** Fixed predecessor membership state for the first collaborative revision. */
export const COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST = sha256DigestSchema.parse(
  'AFG_PkcMlhK5uv3armnbGflrgLM6cM_Z1YJENKpM27Q',
);
/** Fixed predecessor membership-history state for the first collaborative revision. */
export const COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST = sha256DigestSchema.parse(
  'Ukec1BsTbLSA1DJWShxd1XPoZ6IiF25bGKmYJfFcvKU',
);
/** Fixed empty compacted-history prefix for the first collaborative revision. */
export const COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST = sha256DigestSchema.parse(
  'sxqHtMWDuIqXgNV9u2DesTYAWSjeK9pXF3i8f2O_KEw',
);

/*
 * These limits are wire-contract limits, rather than guidance for callers.
 * Keeping them in one module makes it possible for every parser and transport
 * to enforce the same allocation ceiling before any decryption or signature
 * work occurs.
 */
export const MAX_COLLABORATIVE_MEMBERS = 128;
export const MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL = 16;
export const MAX_COLLABORATIVE_DATABASE_DEVICES = 2_048;
export const MAX_COLLABORATIVE_OWNERS = 8;
export const MAX_COLLABORATIVE_KEY_ENVELOPES = 256;
export const MAX_COLLABORATIVE_DISCOVERY_RECORDS = 256;
export const MAX_COLLABORATIVE_HISTORY_EVENTS = 256;
export const MAX_COLLABORATIVE_HISTORY_CHECKPOINTS = 32;
export const MAX_COLLABORATIVE_PROOF_LINKS = 256;
export const MAX_COLLABORATIVE_PENDING_APPROVALS = 32;
export const MAX_COLLABORATIVE_PENDING_TRANSFERS = 8;
export const MAX_COLLABORATIVE_APPROVAL_EVIDENCE = 1;
export const MAX_COLLABORATIVE_IDENTITY_BYTES = 64 * 1024;
export const MAX_COLLABORATIVE_ENROLLMENT_RECEIPT_BYTES = 128 * 1024;
export const MAX_COLLABORATIVE_MANIFEST_BYTES = 2 * 1024 * 1024;
export const MAX_COLLABORATIVE_HISTORY_BYTES = 2 * 1024 * 1024;
export const MAX_COLLABORATIVE_OPERATION_BYTES = 128 * 1024;
export const MAX_COLLABORATIVE_HISTORY_COMPACTION_INPUT_BYTES =
  MAX_COLLABORATIVE_HISTORY_BYTES + MAX_COLLABORATIVE_OPERATION_BYTES;
export const MAX_COLLABORATIVE_AUTHORIZATION_WITNESS_BYTES = 14 * 1024 * 1024;
export const MAX_COLLABORATIVE_PROOF_BYTES = 15 * 1024 * 1024;
export const MAX_COLLABORATIVE_ROLLBACK_ANCHOR_BYTES = 16 * 1024;
export const MAX_COLLABORATIVE_VAULT_DESTRUCTION_CORE_BYTES = 128 * 1024;
export const MAX_COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_BYTES = 15 * 1024 * 1024;
export const MAX_COLLABORATIVE_VAULT_DESTRUCTION_ANCHOR_BYTES = 16 * 1024;
// Keep a material margin below MongoDB's 16 MiB BSON document ceiling for
// envelope metadata, indexes, and future protocol fields.
export const MAX_COLLABORATIVE_VAULT_DOCUMENT_BYTES = 12 * 1024 * 1024;
export const MAX_COLLABORATIVE_ENCRYPTED_PAYLOAD_BYTES = 8 * 1024 * 1024;
export const MAX_COLLABORATIVE_ENCRYPTED_MANIFEST_BYTES = 2 * 1024 * 1024;
export const MAX_COLLABORATIVE_ENCRYPTED_METADATA_BYTES = 256 * 1024;
export const MAX_COLLABORATIVE_SEALED_KEY_BYTES = 256;
export const MAX_COLLABORATIVE_NONCE_BYTES = 24;
export const MAX_COLLABORATIVE_AUTHENTICATION_TAG_BYTES = 16;
export const MAX_COLLABORATIVE_PUBLIC_KEY_BYTES = 32;
export const MAX_COLLABORATIVE_SIGNATURE_BYTES = 64;
export const MAX_COLLABORATIVE_NONCE_CHARS = 32;
export const MAX_COLLABORATIVE_AUTHENTICATION_TAG_CHARS = 22;
export const MAX_COLLABORATIVE_PUBLIC_KEY_CHARS = 43;
export const MAX_COLLABORATIVE_SIGNATURE_CHARS = 86;
export const MAX_COLLABORATIVE_SEALED_KEY_CHARS = 342;
export const MAX_COLLABORATIVE_DISCOVERY_TAG_CHARS = 43;
export const MAX_COLLABORATIVE_TEXT_CHARS = 256;
export const MAX_COLLABORATIVE_CLOCK_SKEW_SECONDS = 300;
export const MAX_COLLABORATIVE_APPROVAL_LIFETIME_SECONDS = 24 * 60 * 60;
export const MAX_COLLABORATIVE_TRANSFER_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
export const MAX_COLLABORATIVE_ENROLLMENT_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
export const MAX_COLLABORATIVE_OPERATION_EXPIRY_SECONDS = 7 * 24 * 60 * 60;
export const MAX_COLLABORATIVE_NONCE_SIZE_BYTES = 16;
export const MAX_COLLABORATIVE_NONCE_SIZE_CHARS = 22;

const protocolVersionSchema = z.literal(COLLABORATION_PROTOCOL_VERSION);
const documentVersionSchema = z.literal(COLLABORATIVE_DOCUMENT_VERSION);

/** Public Ed25519/X25519 keys are canonical unpadded base64url byte strings. */
export const collaborationPublicKeySchema = base64UrlSchema
  .length(MAX_COLLABORATIVE_PUBLIC_KEY_CHARS)
  .refine(
    (value) =>
      Buffer.from(value, 'base64url').byteLength === MAX_COLLABORATIVE_PUBLIC_KEY_BYTES,
    { error: 'Public keys must encode exactly 32 bytes' },
  );

/** Ed25519 signatures are represented as opaque canonical base64url bytes. */
export const collaborationSignatureSchema = base64UrlSchema
  .length(MAX_COLLABORATIVE_SIGNATURE_CHARS)
  .refine(
    (value) =>
      Buffer.from(value, 'base64url').byteLength === MAX_COLLABORATIVE_SIGNATURE_BYTES,
    { error: 'Signatures must encode exactly 64 bytes' },
  );

const collaborationNonceSchema = base64UrlSchema
  .length(MAX_COLLABORATIVE_NONCE_CHARS)
  .refine(
    (value) =>
      Buffer.from(value, 'base64url').byteLength === MAX_COLLABORATIVE_NONCE_BYTES,
    { error: 'AEAD nonces must encode exactly 24 bytes' },
  );

const collaborationAuthenticationTagSchema = base64UrlSchema
  .length(MAX_COLLABORATIVE_AUTHENTICATION_TAG_CHARS)
  .refine(
    (value) =>
      Buffer.from(value, 'base64url').byteLength ===
      MAX_COLLABORATIVE_AUTHENTICATION_TAG_BYTES,
    { error: 'AEAD authentication tags must encode exactly 16 bytes' },
  );

const collaborationBlobSchema = (
  maximumBytes: number,
  maximumChars: number,
): z.ZodType<string> =>
  base64UrlSchema
    .max(maximumChars)
    .refine((value) => Buffer.from(value, 'base64url').byteLength <= maximumBytes, {
      error: 'Encrypted data exceeds the collaboration bound',
    });

const collaborationNonceValueSchema = base64UrlSchema
  .length(MAX_COLLABORATIVE_NONCE_SIZE_CHARS)
  .refine(
    (value) =>
      Buffer.from(value, 'base64url').byteLength === MAX_COLLABORATIVE_NONCE_SIZE_BYTES,
    { error: 'Nonces must encode exactly 16 bytes' },
  );

const boundedSignatureSchema = collaborationSignatureSchema;
const boundedPublicKeySchema = collaborationPublicKeySchema;
const boundedBlobMaximumChars = (maximumBytes: number): number =>
  Math.ceil((maximumBytes * 4) / 3);

const addIssue = (
  context: z.RefinementCtx,
  message: string,
  path: (string | number)[] = [],
): void => {
  context.addIssue({ code: 'custom', message, path });
};

function assertCanonicalBytes(
  value: unknown,
  maximumBytes: number,
  context: z.RefinementCtx,
  path: (string | number)[] = [],
): void {
  try {
    if (utf8ByteLength(canonicalJson(value)) > maximumBytes) {
      addIssue(context, 'Canonical collaboration record exceeds its size bound', path);
    }
  } catch {
    addIssue(context, 'Collaboration record is not canonically encodable', path);
  }
}

function isAtOrAfter(left: string, right: string): boolean {
  return Date.parse(left) >= Date.parse(right);
}

function isAfter(left: string, right: string): boolean {
  return Date.parse(left) > Date.parse(right);
}

function lifetimeSeconds(start: string, end: string): number {
  return (Date.parse(end) - Date.parse(start)) / 1_000;
}

function assertUnique(
  values: readonly string[],
  context: z.RefinementCtx,
  message: string,
  path: (string | number)[],
): void {
  const seen = new Set<string>();
  for (const [index, value] of values.entries()) {
    if (seen.has(value)) addIssue(context, message, [...path, index]);
    seen.add(value);
  }
}

export const collaborationRoleSchema = z.enum(['reader', 'editor', 'owner']);
export const membershipRoleSchema = collaborationRoleSchema;

export const collaborationKeyEpochSchema = z
  .number()
  .int()
  .positive()
  .max(Number.MAX_SAFE_INTEGER)
  .brand<'CollaborationKeyEpoch'>();

export const collaborationRevisionTupleSchema = z
  .object({
    authorityEpoch: collaborationKeyEpochSchema,
    documentRevision: revisionSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
  })
  .strict();

export type CollaborationRevisionTuple = z.infer<
  typeof collaborationRevisionTupleSchema
>;

function isExactVaultDestructionTuple(
  prior: CollaborationRevisionTuple,
  terminal: CollaborationRevisionTuple,
): boolean {
  return (
    terminal.authorityEpoch === prior.authorityEpoch &&
    terminal.documentRevision === prior.documentRevision + 1 &&
    terminal.membershipRevision === prior.membershipRevision &&
    terminal.policyRevision === prior.policyRevision &&
    terminal.keyEpoch === prior.keyEpoch &&
    terminal.databaseDeviceGeneration === prior.databaseDeviceGeneration &&
    terminal.databaseDeviceRegistryDigest === prior.databaseDeviceRegistryDigest &&
    terminal.authorizationStateDigest === prior.authorizationStateDigest
  );
}

function assertExactVaultDestructionTuple(
  prior: CollaborationRevisionTuple,
  terminal: CollaborationRevisionTuple,
  context: z.RefinementCtx,
  path: (string | number)[],
): void {
  if (!isExactVaultDestructionTuple(prior, terminal)) {
    addIssue(
      context,
      'Vault destruction must advance only the document revision by exactly one',
      path,
    );
  }
}

/**
 * Immutable database-authority trust root for one collaborative vault.
 *
 * The delegation is issued once at genesis. Routine mutations reuse its digest
 * and never require a fresh database-authority signature.
 */
export const collaborationAuthorityDelegationSchema = z
  .object({
    format: z.literal(COLLABORATIVE_AUTHORITY_DELEGATION_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    authoritySigningPublicKey: boundedPublicKeySchema,
    authoritySigningKeyFingerprint: sha256DigestSchema,
    authorityRecoveryPublicKey: boundedPublicKeySchema,
    authorityRecoveryKeyFingerprint: sha256DigestSchema,
    genesisOperationId: collaborationOperationIdSchema,
    genesisTuple: collaborationRevisionTupleSchema,
    genesisHeadDigest: sha256DigestSchema,
    initialAuthorizationStateDigest: sha256DigestSchema,
    initialOwnerPrincipalId: principalIdSchema,
    initialOwnerRootKeyFingerprint: sha256DigestSchema,
    initialOwnerDeviceId: deviceIdSchema,
    initialOwnerDeviceSigningKeyFingerprint: sha256DigestSchema,
    initialOwnerDeviceEncryptionKeyFingerprint: sha256DigestSchema,
    issuedAt: timestampSchema,
    authoritySignature: boundedSignatureSchema,
  })
  .strict()
  .superRefine((delegation, context) => {
    assertCanonicalBytes(delegation, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    if (
      delegation.authoritySigningPublicKey === delegation.authorityRecoveryPublicKey
    ) {
      addIssue(context, 'Authority signing and recovery public keys must be distinct', [
        'authorityRecoveryPublicKey',
      ]);
    }
    if (
      delegation.genesisTuple.authorityEpoch !== delegation.authorityEpoch ||
      delegation.genesisTuple.authorizationStateDigest !==
        delegation.initialAuthorizationStateDigest ||
      delegation.genesisTuple.documentRevision !== 1 ||
      delegation.genesisTuple.membershipRevision !== 1 ||
      delegation.genesisTuple.policyRevision !== 1 ||
      delegation.genesisTuple.keyEpoch !== 1
    ) {
      addIssue(
        context,
        'Authority delegation must bind the exact revision-one genesis tuple',
        ['genesisTuple'],
      );
    }
  });

export type CollaborationAuthorityDelegation = z.infer<
  typeof collaborationAuthorityDelegationSchema
>;

export const deviceLifecycleStateSchema = z.enum([
  'created',
  'verified',
  'active',
  'rotating',
  'replaced',
  'compromised',
  'revoked',
  'lost',
]);

const deviceCertificateObjectSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    principalId: principalIdSchema,
    deviceId: deviceIdSchema,
    deviceGeneration: revisionSchema,
    signingPublicKey: boundedPublicKeySchema,
    encryptionPublicKey: boundedPublicKeySchema,
    state: deviceLifecycleStateSchema,
    createdAt: timestampSchema,
    stateChangedAt: timestampSchema,
    expiresAt: timestampSchema.optional(),
    revokedAt: timestampSchema.optional(),
    rootSignature: boundedSignatureSchema,
  })
  .strict();

export const deviceCertificateSchema = deviceCertificateObjectSchema.superRefine(
  (certificate, context) => {
    if (certificate.signingPublicKey === certificate.encryptionPublicKey) {
      addIssue(context, 'Device signing and encryption public keys must be distinct', [
        'encryptionPublicKey',
      ]);
    }
    if (!isAtOrAfter(certificate.stateChangedAt, certificate.createdAt)) {
      addIssue(context, 'Device state transition cannot precede creation', [
        'stateChangedAt',
      ]);
    }
    if (
      certificate.expiresAt !== undefined &&
      !isAfter(certificate.expiresAt, certificate.createdAt)
    ) {
      addIssue(context, 'Device expiry must follow creation', ['expiresAt']);
    }
    const terminal = new Set(['replaced', 'compromised', 'revoked', 'lost']);
    if (terminal.has(certificate.state) && certificate.revokedAt === undefined) {
      addIssue(context, 'Terminal devices require a retirement timestamp', [
        'revokedAt',
      ]);
    }
    if (!terminal.has(certificate.state) && certificate.revokedAt !== undefined) {
      addIssue(context, 'Non-terminal devices cannot have a retirement timestamp', [
        'revokedAt',
      ]);
    }
    if (
      certificate.revokedAt !== undefined &&
      !isAtOrAfter(certificate.revokedAt, certificate.stateChangedAt)
    ) {
      addIssue(context, 'Device retirement cannot precede its state transition', [
        'revokedAt',
      ]);
    }
  },
);

export type DeviceCertificate = z.infer<typeof deviceCertificateSchema>;

export const collaborationDatabaseDeviceDenialReasonSchema = z.enum([
  'compromised',
  'revoked',
  'lost',
  'authority-fence',
]);

export const collaborationDatabaseDeviceDenialSchema = z
  .object({
    principalId: principalIdSchema,
    deviceId: deviceIdSchema,
    deviceGeneration: revisionSchema,
    signingKeyFingerprint: sha256DigestSchema,
    reason: collaborationDatabaseDeviceDenialReasonSchema,
    deniedAt: timestampSchema,
  })
  .strict();

/** Exceptional authority-signed deny/recovery fence, never a positive allowlist. */
export const collaborationDatabaseDeviceRegistrySchema = z
  .object({
    format: z.literal(COLLABORATIVE_DEVICE_REGISTRY_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    authorityFingerprint: sha256DigestSchema,
    generation: revisionSchema,
    previousRegistryDigest: sha256DigestSchema,
    registryDigest: sha256DigestSchema,
    deniedDevices: z
      .array(collaborationDatabaseDeviceDenialSchema)
      .max(MAX_COLLABORATIVE_DATABASE_DEVICES),
    updatedAt: timestampSchema,
    authoritySignature: boundedSignatureSchema,
  })
  .strict()
  .superRefine((registry, context) => {
    assertUnique(
      registry.deniedDevices.map((device) => device.deviceId),
      context,
      'Denied database device IDs must be globally unique',
      ['deniedDevices'],
    );
    assertCanonicalBytes(registry, MAX_COLLABORATIVE_MANIFEST_BYTES, context);
  });

export type CollaborationDatabaseDeviceRegistry = z.infer<
  typeof collaborationDatabaseDeviceRegistrySchema
>;

export const principalLifecycleStateSchema = z.enum([
  'active',
  'revoked',
  'replaced',
  'compromised',
]);

const principalIdentityObjectSchema = z
  .object({
    format: z.literal('kavrix-collaborative-principal-identity'),
    protocolVersion: protocolVersionSchema,
    principalId: principalIdSchema,
    identityGeneration: revisionSchema,
    rootSigningPublicKey: boundedPublicKeySchema,
    state: principalLifecycleStateSchema,
    devices: z
      .array(deviceCertificateSchema)
      .min(1)
      .max(MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL),
    createdAt: timestampSchema,
    expiresAt: timestampSchema.optional(),
    revokedAt: timestampSchema.optional(),
    selfSignature: boundedSignatureSchema,
  })
  .strict();

export const principalIdentitySchema = principalIdentityObjectSchema.superRefine(
  (identity, context) => {
    assertCanonicalBytes(identity, MAX_COLLABORATIVE_IDENTITY_BYTES, context);
    assertUnique(
      identity.devices.map((device) => device.deviceId),
      context,
      'Principal device IDs must be unique',
      ['devices'],
    );
    assertUnique(
      identity.devices.map((device) => device.signingPublicKey),
      context,
      'Principal device signing keys must be unique',
      ['devices'],
    );
    assertUnique(
      identity.devices.map((device) => device.encryptionPublicKey),
      context,
      'Principal device encryption keys must be unique',
      ['devices'],
    );
    for (const [index, device] of identity.devices.entries()) {
      if (device.principalId !== identity.principalId) {
        addIssue(context, 'Device certificate belongs to another principal', [
          'devices',
          index,
          'principalId',
        ]);
      }
      if (identity.state !== 'active' && device.state === 'active') {
        addIssue(context, 'Inactive principals cannot retain active devices', [
          'devices',
          index,
          'state',
        ]);
      }
      if (
        device.signingPublicKey === identity.rootSigningPublicKey ||
        device.encryptionPublicKey === identity.rootSigningPublicKey
      ) {
        addIssue(context, 'Principal root and device keys must be distinct', [
          'devices',
          index,
        ]);
      }
    }
    if (
      identity.expiresAt !== undefined &&
      !isAfter(identity.expiresAt, identity.createdAt)
    ) {
      addIssue(context, 'Principal expiry must follow creation', ['expiresAt']);
    }
    if (identity.state === 'active' && identity.revokedAt !== undefined) {
      addIssue(context, 'Active principals cannot have a revocation timestamp', [
        'revokedAt',
      ]);
    }
    if (identity.state !== 'active' && identity.revokedAt === undefined) {
      addIssue(context, 'Inactive principals require a revocation timestamp', [
        'revokedAt',
      ]);
    }
  },
);

export type PrincipalIdentity = z.infer<typeof principalIdentitySchema>;

const publicIdentityExportObjectSchema = z
  .object({
    format: z.literal(COLLABORATIVE_PUBLIC_IDENTITY_FORMAT),
    protocolVersion: protocolVersionSchema,
    principalId: principalIdSchema,
    identityGeneration: revisionSchema,
    rootSigningPublicKey: boundedPublicKeySchema,
    devices: z
      .array(deviceCertificateSchema)
      .min(1)
      .max(MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL),
    createdAt: timestampSchema,
    expiresAt: timestampSchema.optional(),
    selfSignature: boundedSignatureSchema,
  })
  .strict();

export const publicIdentityExportSchema = publicIdentityExportObjectSchema.superRefine(
  (identity, context) => {
    assertCanonicalBytes(identity, MAX_COLLABORATIVE_IDENTITY_BYTES, context);
    assertUnique(
      identity.devices.map((device) => device.deviceId),
      context,
      'Public identity device IDs must be unique',
      ['devices'],
    );
    for (const [index, device] of identity.devices.entries()) {
      if (device.principalId !== identity.principalId) {
        addIssue(context, 'Public device certificate belongs to another principal', [
          'devices',
          index,
          'principalId',
        ]);
      }
      if (
        device.state === 'replaced' ||
        device.state === 'compromised' ||
        device.state === 'revoked' ||
        device.state === 'lost'
      ) {
        addIssue(context, 'Public identity exports cannot contain retired devices', [
          'devices',
          index,
          'state',
        ]);
      }
      if (
        device.signingPublicKey === identity.rootSigningPublicKey ||
        device.encryptionPublicKey === identity.rootSigningPublicKey
      ) {
        addIssue(context, 'Public root and device keys must be distinct', [
          'devices',
          index,
        ]);
      }
    }
    if (
      identity.expiresAt !== undefined &&
      !isAfter(identity.expiresAt, identity.createdAt)
    ) {
      addIssue(context, 'Public identity expiry must follow creation', ['expiresAt']);
    }
  },
);

export const publicIdentityDocumentSchema = publicIdentityExportSchema;
export const principalPublicIdentitySchema = publicIdentityExportSchema;

export type PublicIdentityExport = z.infer<typeof publicIdentityExportSchema>;
export type PublicIdentityDocument = PublicIdentityExport;

export const collaborationMembershipStateSchema = z.enum([
  'active',
  'removal-prepared',
  'revoked',
  'superseded',
]);

const membershipObjectSchema = z
  .object({
    membershipId: membershipIdSchema,
    principalId: principalIdSchema,
    principalFingerprint: sha256DigestSchema,
    rootSigningPublicKey: boundedPublicKeySchema,
    identityGeneration: revisionSchema,
    role: collaborationRoleSchema,
    state: collaborationMembershipStateSchema,
    devices: z
      .array(deviceCertificateSchema)
      .min(1)
      .max(MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    removedAt: timestampSchema.optional(),
  })
  .strict();

export const collaborationMembershipSchema = membershipObjectSchema.superRefine(
  (membership, context) => {
    assertCanonicalBytes(membership, MAX_COLLABORATIVE_MANIFEST_BYTES, context);
    assertUnique(
      membership.devices.map((device) => device.deviceId),
      context,
      'Membership device IDs must be unique',
      ['devices'],
    );
    for (const [index, device] of membership.devices.entries()) {
      if (device.principalId !== membership.principalId) {
        addIssue(context, 'Membership device belongs to another principal', [
          'devices',
          index,
          'principalId',
        ]);
      }
      if (
        device.signingPublicKey === membership.rootSigningPublicKey ||
        device.encryptionPublicKey === membership.rootSigningPublicKey
      ) {
        addIssue(context, 'Membership root and device keys must be distinct', [
          'devices',
          index,
        ]);
      }
    }
    if (membership.state === 'active') {
      if (membership.removedAt !== undefined) {
        addIssue(context, 'Active memberships cannot have a removal timestamp', [
          'removedAt',
        ]);
      }
      if (!membership.devices.some((device) => device.state === 'active')) {
        addIssue(context, 'Active memberships require an active device', ['devices']);
      }
    } else if (membership.removedAt === undefined) {
      addIssue(context, 'Non-active memberships require a removal timestamp', [
        'removedAt',
      ]);
    }
  },
);

export const membershipRecordSchema = collaborationMembershipSchema;
export const vaultMembershipSchema = collaborationMembershipSchema;
export type CollaborationMembership = z.infer<typeof collaborationMembershipSchema>;
export type MembershipRecord = CollaborationMembership;

export const collaborationAadEntityTypeSchema = z.enum([
  'vault-payload',
  'membership-manifest',
  'member-key-envelope',
  'policy',
  'membership-history',
]);

const collaborationAadObjectSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    entityType: collaborationAadEntityTypeSchema,
    entityId: z.union([vaultIdSchema, membershipIdSchema, historyIdSchema]),
    documentRevision: revisionSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    metadataDigest: sha256DigestSchema,
  })
  .strict();

/** The acyclic AAD context whose digest becomes `metadataDigest`. */
export const collaborationAadMetadataSchema = collaborationAadObjectSchema.omit({
  metadataDigest: true,
});

export type CollaborationAadMetadata = z.infer<typeof collaborationAadMetadataSchema>;

export const collaborationAadSchema = collaborationAadObjectSchema.superRefine(
  (aad, context) => {
    const vaultEntity =
      aad.entityType === 'vault-payload' ||
      aad.entityType === 'membership-manifest' ||
      aad.entityType === 'policy';
    if (vaultEntity && aad.entityId !== aad.vaultId) {
      addIssue(context, 'Vault collaboration envelopes must be bound to their vault', [
        'entityId',
      ]);
    }
    if (
      aad.entityType === 'member-key-envelope' &&
      !membershipIdSchema.safeParse(aad.entityId).success
    ) {
      addIssue(context, 'Member-key envelopes must be bound to a membership', [
        'entityId',
      ]);
    }
    if (
      aad.entityType === 'membership-history' &&
      !historyIdSchema.safeParse(aad.entityId).success
    ) {
      addIssue(
        context,
        'Membership history envelopes must be bound to a history record',
        ['entityId'],
      );
    }
  },
);

export const collaborativeAeadEnvelopeSchema = z
  .object({
    version: z.literal(1),
    algorithm: z.literal('xchacha20-poly1305-ietf'),
    nonce: collaborationNonceSchema,
    ciphertext: collaborationBlobSchema(
      MAX_COLLABORATIVE_ENCRYPTED_PAYLOAD_BYTES,
      boundedBlobMaximumChars(MAX_COLLABORATIVE_ENCRYPTED_PAYLOAD_BYTES),
    ),
    authenticationTag: collaborationAuthenticationTagSchema,
    aad: collaborationAadSchema,
  })
  .strict()
  .superRefine((envelope, context) => {
    const maximumCiphertext =
      envelope.aad.entityType === 'membership-manifest'
        ? MAX_COLLABORATIVE_ENCRYPTED_MANIFEST_BYTES
        : envelope.aad.entityType === 'policy'
          ? MAX_COLLABORATIVE_ENCRYPTED_METADATA_BYTES
          : MAX_COLLABORATIVE_ENCRYPTED_PAYLOAD_BYTES;
    if (Buffer.from(envelope.ciphertext, 'base64url').byteLength > maximumCiphertext) {
      addIssue(context, 'Encrypted collaboration ciphertext exceeds its entity bound', [
        'ciphertext',
      ]);
    }
  });

export const collaborationEnvelopeSchema = collaborativeAeadEnvelopeSchema;
export type CollaborationAeadEnvelope = z.infer<typeof collaborativeAeadEnvelopeSchema>;

const collaborationKeyEnvelopeObjectSchema = z
  .object({
    format: z.literal(COLLABORATIVE_KEY_ENVELOPE_FORMAT),
    protocolVersion: protocolVersionSchema,
    algorithm: z.literal('x25519-sealed-box'),
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    membershipId: membershipIdSchema,
    principalId: principalIdSchema,
    deviceId: deviceIdSchema,
    recipientEncryptionKeyFingerprint: sha256DigestSchema,
    keyEpoch: collaborationKeyEpochSchema,
    membershipRevision: revisionSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    sealedVaultRootKey: collaborationBlobSchema(
      MAX_COLLABORATIVE_SEALED_KEY_BYTES,
      MAX_COLLABORATIVE_SEALED_KEY_CHARS,
    ),
    envelopeDigest: sha256DigestSchema,
    createdAt: timestampSchema,
    ownerSignature: boundedSignatureSchema,
  })
  .strict();

export const collaborationKeyEnvelopeSchema =
  collaborationKeyEnvelopeObjectSchema.superRefine((envelope, context) => {
    if (envelope.sealedVaultRootKey.length > MAX_COLLABORATIVE_SEALED_KEY_CHARS) {
      addIssue(context, 'Sealed vault keys exceed the canonical bound', [
        'sealedVaultRootKey',
      ]);
    }
    assertCanonicalBytes(envelope, MAX_COLLABORATIVE_OPERATION_BYTES, context);
  });

export const memberKeyEnvelopeSchema = collaborationKeyEnvelopeSchema;
export const encryptedMemberKeyEnvelopeSchema = collaborationKeyEnvelopeSchema;
export type CollaborationKeyEnvelope = z.infer<typeof collaborationKeyEnvelopeSchema>;
export type MemberKeyEnvelope = CollaborationKeyEnvelope;

/**
 * A recovery wrapper is not a membership grant.  The database authority holds
 * the DRK and may need to recover an owner-less vault, so its envelope is
 * represented separately instead of pretending the authority is an active
 * member device.
 */
const databaseAuthorityRecoveryEnvelopeObjectSchema = z
  .object({
    format: z.literal('kavrix-collaborative-authority-recovery-envelope'),
    protocolVersion: protocolVersionSchema,
    algorithm: z.literal('x25519-sealed-box'),
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    authorityRecoveryKeyFingerprint: sha256DigestSchema,
    keyEpoch: collaborationKeyEpochSchema,
    membershipRevision: revisionSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    sealedVaultRootKey: collaborationBlobSchema(
      MAX_COLLABORATIVE_SEALED_KEY_BYTES,
      MAX_COLLABORATIVE_SEALED_KEY_CHARS,
    ),
    envelopeDigest: sha256DigestSchema,
    sealedByPrincipalId: principalIdSchema,
    sealedByDeviceId: deviceIdSchema,
    createdAt: timestampSchema,
    ownerSignature: boundedSignatureSchema,
  })
  .strict();

export const databaseAuthorityRecoveryEnvelopeSchema =
  databaseAuthorityRecoveryEnvelopeObjectSchema.superRefine((envelope, context) => {
    assertCanonicalBytes(envelope, MAX_COLLABORATIVE_OPERATION_BYTES, context);
  });

export type DatabaseAuthorityRecoveryEnvelope = z.infer<
  typeof databaseAuthorityRecoveryEnvelopeSchema
>;

export const manifestKeyEnvelopeSchema = z.union([
  collaborationKeyEnvelopeSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
]);

const collaborationAuthorizationDeviceCoreSchema = deviceCertificateObjectSchema.omit({
  rootSignature: true,
});

const collaborationAuthorizationMembershipCoreSchema = membershipObjectSchema
  .omit({ devices: true })
  .extend({
    devices: z
      .array(collaborationAuthorizationDeviceCoreSchema)
      .min(1)
      .max(MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL),
  })
  .strict();

const collaborationAuthorizationMemberKeyEnvelopeCoreSchema =
  collaborationKeyEnvelopeObjectSchema.omit({
    envelopeDigest: true,
    createdAt: true,
    ownerSignature: true,
  });

const collaborationAuthorizationRecoveryEnvelopeCoreSchema =
  databaseAuthorityRecoveryEnvelopeObjectSchema.omit({
    envelopeDigest: true,
    createdAt: true,
    ownerSignature: true,
  });

export const collaborationAuthorizationKeyEnvelopeCoreSchema = z.union([
  collaborationAuthorizationMemberKeyEnvelopeCoreSchema,
  collaborationAuthorizationRecoveryEnvelopeCoreSchema,
]);

export const approvalPolicySchema = z.enum(['none', 'one-additional-owner']);
export const collaborationApprovalPolicySchema = approvalPolicySchema;

export const collaborationPolicyStateSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    policyRevision: revisionSchema,
    approvalPolicy: approvalPolicySchema,
    policyDigest: sha256DigestSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    changedByPrincipalId: principalIdSchema,
    changedByDeviceId: deviceIdSchema,
    changedAt: timestampSchema,
    signature: boundedSignatureSchema,
  })
  .strict()
  .superRefine((policy, context) => {
    assertCanonicalBytes(policy, MAX_COLLABORATIVE_ENCRYPTED_METADATA_BYTES, context);
  });

export const membershipPolicySchema = collaborationPolicyStateSchema;
export type CollaborationPolicyState = z.infer<typeof collaborationPolicyStateSchema>;

/**
 * Canonical authorization projection. History, signatures, document revision,
 * current head, and this projection's resulting digest are deliberately absent.
 */
export const collaborationAuthorizationStateCoreSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    memberships: z
      .array(collaborationAuthorizationMembershipCoreSchema)
      .min(1)
      .max(MAX_COLLABORATIVE_MEMBERS),
    ownerPrincipalIds: z.array(principalIdSchema).min(1).max(MAX_COLLABORATIVE_OWNERS),
    keyEnvelopes: z
      .array(collaborationAuthorizationKeyEnvelopeCoreSchema)
      .min(2)
      .max(MAX_COLLABORATIVE_KEY_ENVELOPES),
    approvalPolicy: approvalPolicySchema,
  })
  .strict()
  .superRefine((state, context) => {
    assertCanonicalBytes(state, MAX_COLLABORATIVE_MANIFEST_BYTES, context);
    assertUnique(
      state.memberships.map((membership) => membership.membershipId),
      context,
      'Authorization-state membership IDs must be unique',
      ['memberships'],
    );
    assertUnique(
      state.memberships.map((membership) => membership.principalId),
      context,
      'Authorization-state principal IDs must be unique',
      ['memberships'],
    );
    assertUnique(
      state.ownerPrincipalIds,
      context,
      'Authorization-state owner IDs must be unique',
      ['ownerPrincipalIds'],
    );
    assertUnique(
      state.keyEnvelopes.map((envelope) =>
        'membershipId' in envelope
          ? `${envelope.membershipId}:${envelope.deviceId}`
          : `authority:${String(envelope.authorityEpoch)}:${String(envelope.keyEpoch)}`,
      ),
      context,
      'Authorization-state key envelopes must be unique per recipient',
      ['keyEnvelopes'],
    );
    const activeOwners = new Set(
      state.memberships
        .filter(
          (membership) => membership.state === 'active' && membership.role === 'owner',
        )
        .map((membership) => membership.principalId),
    );
    if (
      activeOwners.size !== state.ownerPrincipalIds.length ||
      state.ownerPrincipalIds.some((principalId) => !activeOwners.has(principalId))
    ) {
      addIssue(
        context,
        'Authorization-state owner index must enumerate every active owner exactly once',
        ['ownerPrincipalIds'],
      );
    }
    const recoveryEnvelopes = state.keyEnvelopes.filter(
      (envelope) => !('membershipId' in envelope),
    );
    if (recoveryEnvelopes.length !== 1) {
      addIssue(
        context,
        'Authorization state requires exactly one current authority recovery envelope',
        ['keyEnvelopes'],
      );
    }
    for (const [envelopeIndex, envelope] of state.keyEnvelopes.entries()) {
      if (
        envelope.databaseId !== state.databaseId ||
        envelope.vaultId !== state.vaultId ||
        envelope.authorityEpoch !== state.authorityEpoch ||
        envelope.keyEpoch !== state.keyEpoch ||
        envelope.membershipRevision !== state.membershipRevision ||
        envelope.databaseDeviceGeneration !== state.databaseDeviceGeneration ||
        envelope.databaseDeviceRegistryDigest !== state.databaseDeviceRegistryDigest
      ) {
        addIssue(context, 'Authorization-state envelope has the wrong state tuple', [
          'keyEnvelopes',
          envelopeIndex,
        ]);
      }
      if (!('membershipId' in envelope)) {
        const sealingOwner = state.memberships.find(
          (membership) =>
            membership.principalId === envelope.sealedByPrincipalId &&
            membership.state === 'active' &&
            membership.role === 'owner',
        );
        if (
          !sealingOwner?.devices.some(
            (device) =>
              device.deviceId === envelope.sealedByDeviceId &&
              device.state === 'active',
          )
        ) {
          addIssue(
            context,
            'Authority recovery envelope must be sealed by an active owner device',
            ['keyEnvelopes', envelopeIndex],
          );
        }
      }
    }
    for (const [membershipIndex, membership] of state.memberships.entries()) {
      for (const [deviceIndex, device] of membership.devices.entries()) {
        const envelopeCount = state.keyEnvelopes.filter(
          (envelope) =>
            'membershipId' in envelope &&
            envelope.membershipId === membership.membershipId &&
            envelope.principalId === membership.principalId &&
            envelope.deviceId === device.deviceId,
        ).length;
        const mustDecrypt = membership.state === 'active' && device.state === 'active';
        if (mustDecrypt ? envelopeCount !== 1 : envelopeCount !== 0) {
          addIssue(
            context,
            'Only active member devices receive exactly one current key envelope',
            ['memberships', membershipIndex, 'devices', deviceIndex],
          );
        }
      }
    }
  });

export type CollaborationAuthorizationStateCore = z.infer<
  typeof collaborationAuthorizationStateCoreSchema
>;

export const mutationOperationTypeSchema = z.enum([
  'genesis-migration',
  'ordinary-write',
  'add-member',
  'add-device',
  'remove-member',
  'revoke-device',
  'change-role',
  'rotate-key',
  'change-policy',
  'transfer-owner',
  'destroy-vault',
  'recover-owner',
  'emergency-rekey',
]);
export const collaborationOperationTypeSchema = mutationOperationTypeSchema;

export const collaborationAuthorizationEvidenceSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('none') }).strict(),
  z
    .object({
      kind: z.literal('approval'),
      evidenceDigest: sha256DigestSchema,
    })
    .strict(),
  z
    .object({
      kind: z.literal('ownership-transfer'),
      evidenceDigest: sha256DigestSchema,
    })
    .strict(),
  z
    .object({
      kind: z.literal('authority-recovery'),
      evidenceDigest: sha256DigestSchema,
    })
    .strict(),
]);

const ownerAuthorizationTransitionSignatureSchema = z
  .object({
    signerKind: z.literal('owner-device'),
    signerPrincipalId: principalIdSchema,
    signerDeviceId: deviceIdSchema,
    signature: boundedSignatureSchema,
  })
  .strict();

const authorityAuthorizationTransitionSignatureSchema = z
  .object({
    signerKind: z.literal('database-authority'),
    authorityEpoch: collaborationKeyEpochSchema,
    authoritySigningKeyFingerprint: sha256DigestSchema,
    signature: boundedSignatureSchema,
  })
  .strict();

export const collaborationAuthorizationTransitionSignatureSchema = z.discriminatedUnion(
  'signerKind',
  [
    ownerAuthorizationTransitionSignatureSchema,
    authorityAuthorizationTransitionSignatureSchema,
  ],
);

export const collaborationAuthorizationTransitionSchema = z
  .object({
    format: z.literal(COLLABORATIVE_AUTHORIZATION_TRANSITION_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    operationId: collaborationOperationIdSchema,
    operationType: mutationOperationTypeSchema,
    previousHeadDigest: sha256DigestSchema,
    previousAuthorizationStateDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    previousTuple: collaborationRevisionTupleSchema,
    nextTuple: collaborationRevisionTupleSchema,
    evidence: collaborationAuthorizationEvidenceSchema,
    issuedAt: timestampSchema,
    expiresAt: timestampSchema,
    transitionDigest: sha256DigestSchema,
    transitionSignature: collaborationAuthorizationTransitionSignatureSchema,
  })
  .strict()
  .superRefine((transition, context) => {
    assertCanonicalBytes(transition, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    if (!isAfter(transition.expiresAt, transition.issuedAt)) {
      addIssue(context, 'Authorization transition expiry must follow issuance', [
        'expiresAt',
      ]);
    } else if (
      lifetimeSeconds(transition.issuedAt, transition.expiresAt) >
      MAX_COLLABORATIVE_OPERATION_EXPIRY_SECONDS
    ) {
      addIssue(context, 'Authorization transition exceeds its maximum lifetime', [
        'expiresAt',
      ]);
    }
    if (transition.operationType === 'ordinary-write') {
      addIssue(context, 'Ordinary writes cannot carry authorization transitions', [
        'operationType',
      ]);
    }
    if (
      transition.transitionSignature.signerKind === 'database-authority' &&
      transition.operationType !== 'recover-owner'
    ) {
      addIssue(
        context,
        'Database authority may sign only an explicit owner-recovery transition',
        ['transitionSignature', 'signerKind'],
      );
    }
    if (
      transition.operationType === 'destroy-vault' &&
      transition.previousAuthorizationStateDigest !==
        transition.authorizationStateDigest
    ) {
      addIssue(
        context,
        'Vault destruction must retain the authorization-state digest',
        ['authorizationStateDigest'],
      );
    } else if (
      transition.operationType !== 'destroy-vault' &&
      transition.previousAuthorizationStateDigest ===
        transition.authorizationStateDigest
    ) {
      addIssue(
        context,
        'Authorization transitions must change the authorization-state digest',
        ['authorizationStateDigest'],
      );
    }
    if (
      transition.previousTuple.authorizationStateDigest !==
      transition.previousAuthorizationStateDigest
    ) {
      addIssue(
        context,
        'Previous tuple must bind the previous authorization-state digest',
        ['previousTuple', 'authorizationStateDigest'],
      );
    }
    if (
      transition.nextTuple.authorizationStateDigest !==
      transition.authorizationStateDigest
    ) {
      addIssue(context, 'Next tuple must bind the next authorization-state digest', [
        'nextTuple',
        'authorizationStateDigest',
      ]);
    }
    if (
      transition.operationType === 'transfer-owner' &&
      transition.evidence.kind !== 'ownership-transfer'
    ) {
      addIssue(context, 'Ownership transfer requires exact transfer evidence', [
        'evidence',
      ]);
    }
    if (
      transition.operationType !== 'transfer-owner' &&
      transition.evidence.kind === 'ownership-transfer'
    ) {
      addIssue(context, 'Ownership-transfer evidence is exclusive to owner transfer', [
        'evidence',
      ]);
    }
    if (
      transition.operationType === 'genesis-migration' &&
      (transition.transitionSignature.signerKind !== 'owner-device' ||
        transition.evidence.kind !== 'none')
    ) {
      addIssue(
        context,
        'Genesis transition requires the initial owner and no approval',
        ['transitionSignature'],
      );
    }
    if (
      transition.operationType === 'recover-owner' &&
      (transition.transitionSignature.signerKind !== 'database-authority' ||
        transition.evidence.kind !== 'authority-recovery')
    ) {
      addIssue(
        context,
        'Owner recovery requires authority signature and authority-recovery evidence',
      );
    }
    if (
      transition.operationType !== 'recover-owner' &&
      transition.evidence.kind === 'authority-recovery'
    ) {
      addIssue(context, 'Authority-recovery evidence is exclusive to owner recovery', [
        'evidence',
      ]);
    }
  });

export type CollaborationAuthorizationTransition = z.infer<
  typeof collaborationAuthorizationTransitionSchema
>;

export const collaborationMutationCommitmentSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    operationId: collaborationOperationIdSchema,
    operationType: mutationOperationTypeSchema,
    requestDigest: sha256DigestSchema,
    previousHeadDigest: sha256DigestSchema,
    previousAuthorizationStateDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    authorizationTransitionDigest: sha256DigestSchema.optional(),
    previousAuthorityEpoch: collaborationKeyEpochSchema,
    previousDocumentRevision: revisionSchema,
    previousMembershipRevision: revisionSchema,
    previousPolicyRevision: revisionSchema,
    previousKeyEpoch: collaborationKeyEpochSchema,
    previousDatabaseDeviceGeneration: revisionSchema,
    previousDatabaseDeviceRegistryDigest: sha256DigestSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    documentRevision: revisionSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    encryptedPayloadDigest: sha256DigestSchema,
    encryptedMembershipDigest: sha256DigestSchema,
    encryptedEnvelopesDigest: sha256DigestSchema,
    policyDigest: sha256DigestSchema,
    writerPrincipalId: principalIdSchema,
    writerDeviceId: deviceIdSchema,
    timestamp: timestampSchema,
    expiresAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((commitment, context) => {
    assertCanonicalBytes(commitment, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    if (
      commitment.expiresAt !== undefined &&
      !isAfter(commitment.expiresAt, commitment.timestamp)
    ) {
      addIssue(context, 'Mutation expiry must follow its timestamp', ['expiresAt']);
    } else if (
      commitment.expiresAt !== undefined &&
      lifetimeSeconds(commitment.timestamp, commitment.expiresAt) >
        MAX_COLLABORATIVE_OPERATION_EXPIRY_SECONDS
    ) {
      addIssue(context, 'Mutation expiry exceeds its maximum lifetime', ['expiresAt']);
    }
    if (
      commitment.previousAuthorityEpoch > commitment.authorityEpoch ||
      commitment.previousDocumentRevision > commitment.documentRevision ||
      commitment.previousMembershipRevision > commitment.membershipRevision ||
      commitment.previousPolicyRevision > commitment.policyRevision ||
      commitment.previousKeyEpoch > commitment.keyEpoch ||
      commitment.previousDatabaseDeviceGeneration > commitment.databaseDeviceGeneration
    ) {
      addIssue(context, 'Mutation revisions cannot move backwards');
    }
    if (
      commitment.previousDatabaseDeviceGeneration ===
        commitment.databaseDeviceGeneration &&
      commitment.previousDatabaseDeviceRegistryDigest !==
        commitment.databaseDeviceRegistryDigest
    ) {
      addIssue(
        context,
        'An unchanged database device generation must retain its registry digest',
        ['databaseDeviceRegistryDigest'],
      );
    }
    if (commitment.operationType === 'ordinary-write') {
      if (commitment.authorizationTransitionDigest !== undefined) {
        addIssue(
          context,
          'Ordinary writes cannot carry an authorization-transition digest',
          ['authorizationTransitionDigest'],
        );
      }
      if (
        commitment.previousAuthorizationStateDigest !==
        commitment.authorizationStateDigest
      ) {
        addIssue(
          context,
          'Ordinary writes cannot change the authorization-state digest',
          ['authorizationStateDigest'],
        );
      }
    } else {
      if (commitment.authorizationTransitionDigest === undefined) {
        addIssue(
          context,
          'Administrative and genesis mutations require an authorization transition',
          ['authorizationTransitionDigest'],
        );
      }
      if (
        commitment.operationType === 'destroy-vault' &&
        commitment.previousAuthorizationStateDigest !==
          commitment.authorizationStateDigest
      ) {
        addIssue(
          context,
          'Vault destruction must retain the authorization-state digest',
          ['authorizationStateDigest'],
        );
      } else if (
        commitment.operationType !== 'destroy-vault' &&
        commitment.previousAuthorizationStateDigest ===
          commitment.authorizationStateDigest
      ) {
        addIssue(
          context,
          'Administrative and genesis mutations must change authorization state',
          ['authorizationStateDigest'],
        );
      }
    }
  });

export const mutationCommitmentSchema = collaborationMutationCommitmentSchema;
export const signedMutationCommitmentSchema = collaborationMutationCommitmentSchema;
export type CollaborationMutationCommitment = z.infer<
  typeof collaborationMutationCommitmentSchema
>;
export type MutationCommitment = CollaborationMutationCommitment;

export const collaborationHistoryEventTypeSchema = z.enum([
  'genesis-created',
  'member-added',
  'member-removed',
  'role-changed',
  'device-added',
  'device-revoked',
  'key-rotated',
  'policy-changed',
  'owner-transfer',
  'owner-recovery',
  'emergency-rekey',
  'vault-destroyed',
]);

const membershipHistoryEventObjectSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    operationId: collaborationOperationIdSchema,
    eventType: collaborationHistoryEventTypeSchema,
    actorPrincipalId: principalIdSchema,
    actorDeviceId: deviceIdSchema,
    targetPrincipalId: principalIdSchema.optional(),
    targetDeviceId: deviceIdSchema.optional(),
    previousRole: collaborationRoleSchema.optional(),
    newRole: collaborationRoleSchema.optional(),
    previousState: collaborationMembershipStateSchema.optional(),
    newState: collaborationMembershipStateSchema.optional(),
    previousDocumentRevision: revisionSchema,
    newDocumentRevision: revisionSchema,
    previousMembershipRevision: revisionSchema,
    newMembershipRevision: revisionSchema,
    previousPolicyRevision: revisionSchema,
    newPolicyRevision: revisionSchema,
    previousKeyEpoch: collaborationKeyEpochSchema,
    newKeyEpoch: collaborationKeyEpochSchema,
    previousAuthorityEpoch: collaborationKeyEpochSchema,
    newAuthorityEpoch: collaborationKeyEpochSchema,
    previousDatabaseDeviceGeneration: revisionSchema,
    newDatabaseDeviceGeneration: revisionSchema,
    previousDatabaseDeviceRegistryDigest: sha256DigestSchema,
    newDatabaseDeviceRegistryDigest: sha256DigestSchema,
    previousAuthorizationStateDigest: sha256DigestSchema,
    newAuthorizationStateDigest: sha256DigestSchema,
    // Membership history is encrypted before the outer head is calculated.
    // It may authenticate the prior head, but must not create a cycle by
    // carrying the resulting outer head.
    previousHeadDigest: sha256DigestSchema,
    approvalRequestId: approvalRequestIdSchema.optional(),
    approvalRequestDigest: sha256DigestSchema.optional(),
    timestamp: timestampSchema,
    expiresAt: timestampSchema.optional(),
    signature: boundedSignatureSchema,
  })
  .strict();

export const membershipHistoryEventSchema =
  membershipHistoryEventObjectSchema.superRefine((event, context) => {
    if (event.targetDeviceId !== undefined && event.targetPrincipalId === undefined) {
      addIssue(context, 'A target device must be scoped to a target principal', [
        'targetPrincipalId',
      ]);
    }
    if (
      event.newDocumentRevision < event.previousDocumentRevision ||
      event.newMembershipRevision < event.previousMembershipRevision ||
      event.newPolicyRevision < event.previousPolicyRevision ||
      event.newKeyEpoch < event.previousKeyEpoch ||
      event.newAuthorityEpoch < event.previousAuthorityEpoch ||
      event.newDatabaseDeviceGeneration < event.previousDatabaseDeviceGeneration
    ) {
      addIssue(context, 'History revisions cannot move backwards');
    }
    if (
      event.newDocumentRevision === event.previousDocumentRevision &&
      event.newMembershipRevision === event.previousMembershipRevision &&
      event.newPolicyRevision === event.previousPolicyRevision &&
      event.newKeyEpoch === event.previousKeyEpoch &&
      event.newAuthorityEpoch === event.previousAuthorityEpoch &&
      event.newDatabaseDeviceGeneration === event.previousDatabaseDeviceGeneration
    ) {
      addIssue(context, 'History events must advance at least one revision');
    }
    if (
      event.newDatabaseDeviceGeneration === event.previousDatabaseDeviceGeneration &&
      event.newDatabaseDeviceRegistryDigest !==
        event.previousDatabaseDeviceRegistryDigest
    ) {
      addIssue(
        context,
        'Unchanged device generations must retain their registry digest',
        ['newDatabaseDeviceRegistryDigest'],
      );
    }
    if (
      (event.approvalRequestId === undefined) !==
      (event.approvalRequestDigest === undefined)
    ) {
      addIssue(context, 'Approval request ID and digest must be supplied together');
    }
    if (event.expiresAt !== undefined && !isAfter(event.expiresAt, event.timestamp)) {
      addIssue(context, 'History event expiry must follow its timestamp', [
        'expiresAt',
      ]);
    }
  });

export type MembershipHistoryEvent = z.infer<typeof membershipHistoryEventSchema>;

export const membershipHistoryCheckpointSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    checkpointId: historyIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    membershipRevision: revisionSchema,
    documentRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    previousHeadDigest: sha256DigestSchema,
    compactedThroughRevision: revisionSchema,
    compactedHistoryDigest: sha256DigestSchema,
    signerPrincipalId: principalIdSchema,
    signerDeviceId: deviceIdSchema,
    createdAt: timestampSchema,
    signature: boundedSignatureSchema,
  })
  .strict()
  .superRefine((checkpoint, context) => {
    if (checkpoint.compactedThroughRevision > checkpoint.membershipRevision) {
      addIssue(
        context,
        'A history checkpoint cannot compact beyond the manifest revision',
        ['compactedThroughRevision'],
      );
    }
  });

export type MembershipHistoryCheckpoint = z.infer<
  typeof membershipHistoryCheckpointSchema
>;

export const membershipHistorySchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    events: z.array(membershipHistoryEventSchema).max(MAX_COLLABORATIVE_HISTORY_EVENTS),
    checkpoints: z
      .array(membershipHistoryCheckpointSchema)
      .max(MAX_COLLABORATIVE_HISTORY_CHECKPOINTS),
    compactedThroughRevision: revisionSchema,
    compactedHistoryDigest: sha256DigestSchema,
    previousHeadDigest: sha256DigestSchema,
    previousHistoryDigest: sha256DigestSchema,
    currentHistoryDigest: sha256DigestSchema,
  })
  .strict()
  .superRefine((history, context) => {
    assertCanonicalBytes(history, MAX_COLLABORATIVE_HISTORY_BYTES, context);
    assertUnique(
      history.events.map((event) => event.operationId),
      context,
      'Membership history operation IDs must be unique',
      ['events'],
    );
    const previousCheckpointRevision = -1;
    let lastCheckpointRevision = previousCheckpointRevision;
    for (const [index, checkpoint] of history.checkpoints.entries()) {
      if (checkpoint.membershipRevision < lastCheckpointRevision) {
        addIssue(
          context,
          'History checkpoints must be ordered by membership revision',
          ['checkpoints', index, 'membershipRevision'],
        );
      }
      lastCheckpointRevision = checkpoint.membershipRevision;
    }
    if (
      history.compactedThroughRevision > 0 &&
      history.compactedHistoryDigest.length === 0
    ) {
      addIssue(context, 'Compacted history requires a detectable digest', [
        'compactedHistoryDigest',
      ]);
    }
    for (const [index, event] of history.events.entries()) {
      if (event.previousMembershipRevision < history.compactedThroughRevision) {
        addIssue(
          context,
          'History events cannot predate the compacted-history boundary',
          ['events', index, 'previousMembershipRevision'],
        );
      }
    }
  });

export type MembershipHistory = z.infer<typeof membershipHistorySchema>;
export const collaborationHistorySchema = membershipHistorySchema;

/**
 * Exact authenticated predecessor committed by one rolling history checkpoint.
 * The nested history includes its existing currentHistoryDigest: it is prior
 * state, so hashing it cannot create a new-state digest cycle.
 */
export const membershipHistoryCompactionInputSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    compactingOperationId: collaborationOperationIdSchema,
    previousHeadDigest: sha256DigestSchema,
    previousTuple: collaborationRevisionTupleSchema,
    priorHistory: membershipHistorySchema,
  })
  .strict()
  .superRefine((input, context) => {
    assertCanonicalBytes(
      input,
      MAX_COLLABORATIVE_HISTORY_COMPACTION_INPUT_BYTES,
      context,
    );
    const { previousTuple, priorHistory } = input;
    if (
      input.databaseId !== priorHistory.databaseId ||
      input.vaultId !== priorHistory.vaultId
    ) {
      addIssue(context, 'History compaction scope must match its exact prior history');
    }
    if (
      input.authorityEpoch !== previousTuple.authorityEpoch ||
      input.authorityEpoch !== priorHistory.authorityEpoch
    ) {
      addIssue(
        context,
        'History compaction authority epoch must match its prior state',
        ['authorityEpoch'],
      );
    }
    if (
      previousTuple.databaseDeviceGeneration !==
        priorHistory.databaseDeviceGeneration ||
      previousTuple.databaseDeviceRegistryDigest !==
        priorHistory.databaseDeviceRegistryDigest
    ) {
      addIssue(
        context,
        'History compaction tuple must bind the prior history registry fence',
        ['previousTuple'],
      );
    }
    for (const [index, event] of priorHistory.events.entries()) {
      if (
        event.newAuthorityEpoch !== previousTuple.authorityEpoch ||
        event.newDocumentRevision > previousTuple.documentRevision ||
        event.newMembershipRevision > previousTuple.membershipRevision ||
        event.newPolicyRevision > previousTuple.policyRevision ||
        event.newKeyEpoch > previousTuple.keyEpoch ||
        event.newDatabaseDeviceGeneration > previousTuple.databaseDeviceGeneration ||
        (event.newDatabaseDeviceGeneration === previousTuple.databaseDeviceGeneration &&
          event.newDatabaseDeviceRegistryDigest !==
            previousTuple.databaseDeviceRegistryDigest)
      ) {
        addIssue(context, 'Compacted history event cannot exceed its prior tuple', [
          'priorHistory',
          'events',
          index,
        ]);
      }
    }
    for (const [index, checkpoint] of priorHistory.checkpoints.entries()) {
      if (
        checkpoint.authorityEpoch !== previousTuple.authorityEpoch ||
        checkpoint.documentRevision > previousTuple.documentRevision ||
        checkpoint.membershipRevision > previousTuple.membershipRevision ||
        checkpoint.policyRevision > previousTuple.policyRevision ||
        checkpoint.keyEpoch > previousTuple.keyEpoch ||
        checkpoint.databaseDeviceGeneration > previousTuple.databaseDeviceGeneration ||
        (checkpoint.databaseDeviceGeneration ===
          previousTuple.databaseDeviceGeneration &&
          checkpoint.databaseDeviceRegistryDigest !==
            previousTuple.databaseDeviceRegistryDigest)
      ) {
        addIssue(
          context,
          'Compacted history checkpoint cannot exceed its prior tuple',
          ['priorHistory', 'checkpoints', index],
        );
      }
    }
  });

export type MembershipHistoryCompactionInput = z.infer<
  typeof membershipHistoryCompactionInputSchema
>;

export const discoveryMembershipStateSchema = z.enum([
  'active',
  'revoked',
  'superseded',
]);

export const collaborationDiscoveryRecordSchema = z
  .object({
    format: z.literal(COLLABORATIVE_DISCOVERY_RECORD_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    discoveryTag: sha256DigestSchema,
    membershipId: membershipIdSchema,
    membershipState: discoveryMembershipStateSchema,
    keyEpoch: collaborationKeyEpochSchema,
    membershipRevision: revisionSchema,
    authorizationStateDigest: sha256DigestSchema,
    encryptedMemberKeyEnvelope: collaborationKeyEnvelopeSchema,
    encryptedMembershipMetadataDigest: sha256DigestSchema,
    discoveryRecordDigest: sha256DigestSchema,
    signerPrincipalId: principalIdSchema,
    signerDeviceId: deviceIdSchema,
    writerSignature: boundedSignatureSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((record, context) => {
    assertCanonicalBytes(record, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    const envelope = record.encryptedMemberKeyEnvelope;
    if (
      envelope.databaseId !== record.databaseId ||
      envelope.vaultId !== record.vaultId ||
      envelope.membershipId !== record.membershipId ||
      envelope.authorityEpoch !== record.authorityEpoch ||
      envelope.keyEpoch !== record.keyEpoch ||
      envelope.membershipRevision !== record.membershipRevision ||
      envelope.databaseDeviceGeneration !== record.databaseDeviceGeneration ||
      envelope.databaseDeviceRegistryDigest !== record.databaseDeviceRegistryDigest
    ) {
      addIssue(
        context,
        'Discovery key envelope is bound to a different collaboration state',
        ['encryptedMemberKeyEnvelope'],
      );
    }
    if (
      record.membershipState === 'active' &&
      envelope.sealedVaultRootKey.length === 0
    ) {
      addIssue(context, 'Active discovery records require a sealed member key', [
        'encryptedMemberKeyEnvelope',
        'sealedVaultRootKey',
      ]);
    }
  });

export const discoveryRecordSchema = collaborationDiscoveryRecordSchema;
export const recipientDiscoveryRecordSchema = collaborationDiscoveryRecordSchema;
export type CollaborationDiscoveryRecord = z.infer<
  typeof collaborationDiscoveryRecordSchema
>;

export const enrollmentReceiptSchema = z
  .object({
    format: z.literal(COLLABORATIVE_ENROLLMENT_RECEIPT_FORMAT),
    protocolVersion: protocolVersionSchema,
    operationType: z.enum(['add-member', 'add-device']),
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    authorityDelegation: collaborationAuthorityDelegationSchema,
    authorityDelegationDigest: sha256DigestSchema,
    ownerPrincipalId: principalIdSchema,
    ownerPrincipalFingerprint: sha256DigestSchema,
    ownerRootSigningPublicKey: boundedPublicKeySchema,
    ownerDeviceCertificate: deviceCertificateSchema,
    recipientPrincipalId: principalIdSchema,
    recipientPrincipalFingerprint: sha256DigestSchema,
    recipientPublicIdentity: publicIdentityExportSchema,
    recipientDeviceId: deviceIdSchema,
    recipientDeviceFingerprints: z
      .array(sha256DigestSchema)
      .min(1)
      .max(MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL),
    membershipId: membershipIdSchema,
    role: collaborationRoleSchema,
    discoveryTag: sha256DigestSchema,
    discoveryRecordDigest: sha256DigestSchema,
    memberKeyEnvelopeDigest: sha256DigestSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    documentRevision: revisionSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    headDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    finalizedMutationLinkDigest: sha256DigestSchema,
    authorizationCheckpointDigest: sha256DigestSchema,
    issuedAt: timestampSchema,
    expiresAt: timestampSchema,
    ownerSignature: boundedSignatureSchema,
  })
  .strict()
  .superRefine((receipt, context) => {
    assertCanonicalBytes(receipt, MAX_COLLABORATIVE_ENROLLMENT_RECEIPT_BYTES, context);
    assertUnique(
      receipt.recipientDeviceFingerprints,
      context,
      'Enrollment recipient device fingerprints must be unique',
      ['recipientDeviceFingerprints'],
    );
    if (!isAfter(receipt.expiresAt, receipt.issuedAt)) {
      addIssue(context, 'Enrollment receipt expiry must follow issuance', [
        'expiresAt',
      ]);
    } else if (
      lifetimeSeconds(receipt.issuedAt, receipt.expiresAt) >
      MAX_COLLABORATIVE_ENROLLMENT_LIFETIME_SECONDS
    ) {
      addIssue(context, 'Enrollment receipt exceeds its maximum lifetime', [
        'expiresAt',
      ]);
    }
    if (
      receipt.operationType === 'add-member' &&
      (receipt.ownerPrincipalId === receipt.recipientPrincipalId ||
        receipt.ownerPrincipalFingerprint === receipt.recipientPrincipalFingerprint)
    ) {
      addIssue(context, 'An enrollment receipt cannot enroll its issuing owner', [
        'recipientPrincipalFingerprint',
      ]);
    }
    if (
      receipt.ownerPrincipalId === receipt.recipientPrincipalId &&
      receipt.ownerPrincipalFingerprint !== receipt.recipientPrincipalFingerprint
    ) {
      addIssue(context, 'One principal cannot have conflicting root fingerprints', [
        'recipientPrincipalFingerprint',
      ]);
    }
    if (receipt.ownerDeviceCertificate.principalId !== receipt.ownerPrincipalId) {
      addIssue(
        context,
        'Enrollment receipt owner device belongs to another principal',
        ['ownerDeviceCertificate'],
      );
    }
    if (
      receipt.recipientPublicIdentity.principalId !== receipt.recipientPrincipalId ||
      !receipt.recipientPublicIdentity.devices.some(
        (device) => device.deviceId === receipt.recipientDeviceId,
      )
    ) {
      addIssue(context, 'Enrollment receipt must name a certified recipient device', [
        'recipientDeviceId',
      ]);
    }
    if (
      receipt.authorityDelegation.databaseId !== receipt.databaseId ||
      receipt.authorityDelegation.vaultId !== receipt.vaultId ||
      receipt.authorityDelegation.authorityEpoch !== receipt.authorityEpoch
    ) {
      addIssue(
        context,
        'Enrollment authority delegation belongs to another vault or epoch',
        ['authorityDelegation'],
      );
    }
  });

export const collaborationEnrollmentReceiptSchema = enrollmentReceiptSchema;
export type EnrollmentReceipt = z.infer<typeof enrollmentReceiptSchema>;

export const approvalStateSchema = z.enum([
  'pending',
  'quorum-reached',
  'consumed',
  'expired',
  'cancelled',
  'conflicted',
]);

export const approvalEvidenceSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    approvalRequestId: approvalRequestIdSchema,
    operationId: collaborationOperationIdSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    requestDigest: sha256DigestSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    documentRevision: revisionSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    priorHeadDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    requestingPrincipalId: principalIdSchema,
    approverPrincipalId: principalIdSchema,
    approverDeviceId: deviceIdSchema,
    approvedAt: timestampSchema,
    signature: boundedSignatureSchema,
  })
  .strict()
  .superRefine((evidence, context) => {
    if (evidence.requestingPrincipalId === evidence.approverPrincipalId) {
      addIssue(context, 'An approval requester cannot approve its own request', [
        'approverPrincipalId',
      ]);
    }
  });

export type ApprovalEvidence = z.infer<typeof approvalEvidenceSchema>;

export const approvalRequestSchema = z
  .object({
    format: z.literal('kavrix-collaborative-approval-request'),
    protocolVersion: protocolVersionSchema,
    approvalRequestId: approvalRequestIdSchema,
    operationId: collaborationOperationIdSchema,
    operationType: mutationOperationTypeSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    requestDigest: sha256DigestSchema,
    actionParametersDigest: sha256DigestSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    documentRevision: revisionSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    priorHeadDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    requestingPrincipalId: principalIdSchema,
    requestingDeviceId: deviceIdSchema,
    requiredApprovalPolicy: approvalPolicySchema,
    state: approvalStateSchema,
    createdAt: timestampSchema,
    expiresAt: timestampSchema,
    nonce: collaborationNonceValueSchema,
    requesterSignature: boundedSignatureSchema,
    approvals: z.array(approvalEvidenceSchema).max(MAX_COLLABORATIVE_APPROVAL_EVIDENCE),
    resolvedAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((request, context) => {
    assertCanonicalBytes(request, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    if (!isAfter(request.expiresAt, request.createdAt)) {
      addIssue(context, 'Approval request expiry must follow creation', ['expiresAt']);
    } else if (
      lifetimeSeconds(request.createdAt, request.expiresAt) >
      MAX_COLLABORATIVE_APPROVAL_LIFETIME_SECONDS
    ) {
      addIssue(context, 'Approval request exceeds its maximum lifetime', ['expiresAt']);
    }
    assertUnique(
      request.approvals.map((approval) => approval.approverDeviceId),
      context,
      'Approval devices must be unique',
      ['approvals'],
    );
    for (const [index, approval] of request.approvals.entries()) {
      if (
        approval.approvalRequestId !== request.approvalRequestId ||
        approval.operationId !== request.operationId ||
        approval.databaseId !== request.databaseId ||
        approval.vaultId !== request.vaultId ||
        approval.requestDigest !== request.requestDigest ||
        approval.authorityEpoch !== request.authorityEpoch ||
        approval.databaseDeviceGeneration !== request.databaseDeviceGeneration ||
        approval.databaseDeviceRegistryDigest !==
          request.databaseDeviceRegistryDigest ||
        approval.documentRevision !== request.documentRevision ||
        approval.membershipRevision !== request.membershipRevision ||
        approval.policyRevision !== request.policyRevision ||
        approval.keyEpoch !== request.keyEpoch ||
        approval.priorHeadDigest !== request.priorHeadDigest ||
        approval.authorizationStateDigest !== request.authorizationStateDigest ||
        approval.requestingPrincipalId !== request.requestingPrincipalId
      ) {
        addIssue(context, 'Approval evidence must bind the exact request tuple', [
          'approvals',
          index,
        ]);
      }
    }
    if (request.requiredApprovalPolicy === 'none' && request.approvals.length > 0) {
      addIssue(context, 'An approval-free policy cannot carry approval evidence', [
        'approvals',
      ]);
    }
    if (
      request.requiredApprovalPolicy === 'one-additional-owner' &&
      (request.state === 'quorum-reached' || request.state === 'consumed') &&
      request.approvals.length !== 1
    ) {
      addIssue(
        context,
        'One-additional-owner requests require one approval at quorum',
        ['approvals'],
      );
    }
    const terminal = new Set(['consumed', 'expired', 'cancelled', 'conflicted']);
    if (terminal.has(request.state) && request.resolvedAt === undefined) {
      addIssue(context, 'Terminal approval requests require a resolution timestamp', [
        'resolvedAt',
      ]);
    }
    if (!terminal.has(request.state) && request.resolvedAt !== undefined) {
      addIssue(context, 'Open approval requests cannot have a resolution timestamp', [
        'resolvedAt',
      ]);
    }
    if (
      request.state === 'expired' &&
      request.resolvedAt !== undefined &&
      !isAtOrAfter(request.resolvedAt, request.expiresAt)
    ) {
      addIssue(context, 'Expired approval requests resolve at or after expiry', [
        'resolvedAt',
      ]);
    }
  });

export const collaborationApprovalRequestSchema = approvalRequestSchema;
export type ApprovalRequest = z.infer<typeof approvalRequestSchema>;

export const transferIntentStateSchema = z.enum([
  'intent-created',
  'initiator-signed',
  'recipient-accepted',
  'published',
  'expired',
  'cancelled',
  'conflicted',
]);

export const transferOwnerDispositionSchema = z.enum([
  'remain-owner',
  'editor',
  'reader',
  'removed',
]);

export const ownershipTransferAcceptanceSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    transferIntentId: transferIntentIdSchema,
    operationId: collaborationOperationIdSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    intentDigest: sha256DigestSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    recipientPrincipalId: principalIdSchema,
    recipientDeviceId: deviceIdSchema,
    acceptedAt: timestampSchema,
    signature: boundedSignatureSchema,
  })
  .strict();

export const transferAcceptanceSchema = ownershipTransferAcceptanceSchema;
export type OwnershipTransferAcceptance = z.infer<
  typeof ownershipTransferAcceptanceSchema
>;

export const transferIntentSchema = z
  .object({
    format: z.literal(COLLABORATIVE_TRANSFER_INTENT_FORMAT),
    protocolVersion: protocolVersionSchema,
    transferIntentId: transferIntentIdSchema,
    operationId: collaborationOperationIdSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    initiatorPrincipalId: principalIdSchema,
    initiatorDeviceId: deviceIdSchema,
    recipientPrincipalId: principalIdSchema,
    recipientDeviceId: deviceIdSchema,
    targetRole: z.literal('owner'),
    originalOwnerDisposition: transferOwnerDispositionSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    documentRevision: revisionSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    currentHeadDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    intentDigest: sha256DigestSchema,
    approvalRequestId: approvalRequestIdSchema.optional(),
    state: transferIntentStateSchema,
    createdAt: timestampSchema,
    expiresAt: timestampSchema,
    initiatorSignedAt: timestampSchema.optional(),
    initiatorSignature: boundedSignatureSchema.optional(),
    recipientAcceptance: ownershipTransferAcceptanceSchema.optional(),
    publishedAt: timestampSchema.optional(),
    terminalAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((intent, context) => {
    assertCanonicalBytes(intent, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    if (intent.initiatorPrincipalId === intent.recipientPrincipalId) {
      addIssue(context, 'Ownership transfer cannot target its initiating principal', [
        'recipientPrincipalId',
      ]);
    }
    if (intent.initiatorDeviceId === intent.recipientDeviceId) {
      addIssue(
        context,
        'Ownership transfer requires distinct initiator and recipient devices',
        ['recipientDeviceId'],
      );
    }
    if (!isAfter(intent.expiresAt, intent.createdAt)) {
      addIssue(context, 'Transfer expiry must follow creation', ['expiresAt']);
    } else if (
      lifetimeSeconds(intent.createdAt, intent.expiresAt) >
      MAX_COLLABORATIVE_TRANSFER_LIFETIME_SECONDS
    ) {
      addIssue(context, 'Transfer intent exceeds its maximum lifetime', ['expiresAt']);
    }
    const signed = intent.initiatorSignature !== undefined;
    if (intent.initiatorSignedAt !== undefined && !signed) {
      addIssue(context, 'Initiator signing time requires an initiator signature', [
        'initiatorSignature',
      ]);
    }
    if (signed && intent.initiatorSignedAt === undefined) {
      addIssue(context, 'Initiator signature requires a signing time', [
        'initiatorSignedAt',
      ]);
    }
    const acceptance = intent.recipientAcceptance;
    if (acceptance !== undefined) {
      if (
        acceptance.transferIntentId !== intent.transferIntentId ||
        acceptance.operationId !== intent.operationId ||
        acceptance.databaseId !== intent.databaseId ||
        acceptance.vaultId !== intent.vaultId ||
        acceptance.intentDigest !== intent.intentDigest ||
        acceptance.authorityEpoch !== intent.authorityEpoch ||
        acceptance.databaseDeviceGeneration !== intent.databaseDeviceGeneration ||
        acceptance.databaseDeviceRegistryDigest !==
          intent.databaseDeviceRegistryDigest ||
        acceptance.authorizationStateDigest !== intent.authorizationStateDigest ||
        acceptance.recipientPrincipalId !== intent.recipientPrincipalId ||
        acceptance.recipientDeviceId !== intent.recipientDeviceId
      ) {
        addIssue(context, 'Transfer acceptance must bind the exact intent', [
          'recipientAcceptance',
        ]);
      }
      if (
        !isAtOrAfter(acceptance.acceptedAt, intent.createdAt) ||
        !isAtOrAfter(intent.expiresAt, acceptance.acceptedAt)
      ) {
        addIssue(context, 'Transfer acceptance must occur inside the intent lifetime', [
          'recipientAcceptance',
          'acceptedAt',
        ]);
      }
    }
    const terminal = new Set(['expired', 'cancelled', 'conflicted']);
    if (terminal.has(intent.state) && intent.terminalAt === undefined) {
      addIssue(context, 'Terminal transfer intents require a terminal timestamp', [
        'terminalAt',
      ]);
    }
    if (!terminal.has(intent.state) && intent.terminalAt !== undefined) {
      addIssue(context, 'Live transfer intents cannot have a terminal timestamp', [
        'terminalAt',
      ]);
    }
    if (intent.state === 'intent-created' && signed) {
      addIssue(context, 'Intent-created transfers cannot carry initiator signatures', [
        'initiatorSignature',
      ]);
    }
    if (intent.state === 'intent-created' && acceptance !== undefined) {
      addIssue(context, 'Intent-created transfers cannot carry recipient acceptance', [
        'recipientAcceptance',
      ]);
    }
    if (
      (intent.state === 'initiator-signed' ||
        intent.state === 'recipient-accepted' ||
        intent.state === 'published') &&
      !signed
    ) {
      addIssue(context, 'This transfer state requires an initiator signature', [
        'initiatorSignature',
      ]);
    }
    if (
      (intent.state === 'recipient-accepted' || intent.state === 'published') &&
      acceptance === undefined
    ) {
      addIssue(context, 'This transfer state requires recipient acceptance', [
        'recipientAcceptance',
      ]);
    }
    if (intent.state === 'published' && intent.publishedAt === undefined) {
      addIssue(context, 'Published transfers require a publication timestamp', [
        'publishedAt',
      ]);
    }
    if (intent.state !== 'published' && intent.publishedAt !== undefined) {
      addIssue(context, 'Only published transfers may have a publication timestamp', [
        'publishedAt',
      ]);
    }
    if (
      intent.state === 'expired' &&
      intent.terminalAt !== undefined &&
      !isAtOrAfter(intent.terminalAt, intent.expiresAt)
    ) {
      addIssue(context, 'Expired transfers terminate at or after expiry', [
        'terminalAt',
      ]);
    }
  });

export const ownershipTransferIntentSchema = transferIntentSchema;
export type TransferIntent = z.infer<typeof transferIntentSchema>;

export const recipientRollbackAnchorSchema = z
  .object({
    format: z.literal(COLLABORATIVE_ROLLBACK_ANCHOR_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    principalId: principalIdSchema,
    deviceId: deviceIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    authorityDelegationDigest: sha256DigestSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    membershipRevision: revisionSchema,
    membershipDigest: sha256DigestSchema,
    policyRevision: revisionSchema,
    policyDigest: sha256DigestSchema,
    keyEpoch: collaborationKeyEpochSchema,
    documentRevision: revisionSchema,
    encryptedPayloadDigest: sha256DigestSchema,
    headDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    finalizedMutationLinkDigest: sha256DigestSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((anchor, context) => {
    assertCanonicalBytes(anchor, MAX_COLLABORATIVE_ROLLBACK_ANCHOR_BYTES, context);
  });

export const protectedRecipientRollbackAnchorSchema = recipientRollbackAnchorSchema;
export const collaborationRollbackAnchorSchema = recipientRollbackAnchorSchema;
export type RecipientRollbackAnchor = z.infer<typeof recipientRollbackAnchorSchema>;

export const collaborativeMembershipManifestSchema = z
  .object({
    format: z.literal(COLLABORATIVE_MEMBERSHIP_MANIFEST_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    documentRevision: revisionSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    authorizationStateDigest: sha256DigestSchema,
    memberships: z
      .array(collaborationMembershipSchema)
      .min(1)
      .max(MAX_COLLABORATIVE_MEMBERS),
    ownerPrincipalIds: z.array(principalIdSchema).min(1).max(MAX_COLLABORATIVE_OWNERS),
    keyEnvelopes: z
      .array(manifestKeyEnvelopeSchema)
      .min(1)
      .max(MAX_COLLABORATIVE_KEY_ENVELOPES),
    approvalPolicy: approvalPolicySchema,
    policy: collaborationPolicyStateSchema,
    pendingApprovals: z
      .array(approvalRequestSchema)
      .max(MAX_COLLABORATIVE_PENDING_APPROVALS),
    pendingTransfers: z
      .array(transferIntentSchema)
      .max(MAX_COLLABORATIVE_PENDING_TRANSFERS),
    history: membershipHistorySchema,
    previousMembershipDigest: sha256DigestSchema,
    membershipDigest: sha256DigestSchema,
    previousHeadDigest: sha256DigestSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((manifest, context) => {
    assertCanonicalBytes(manifest, MAX_COLLABORATIVE_MANIFEST_BYTES, context);
    assertUnique(
      manifest.memberships.map((membership) => membership.membershipId),
      context,
      'Membership IDs must be unique',
      ['memberships'],
    );
    assertUnique(
      manifest.memberships.map((membership) => membership.principalId),
      context,
      'Principal IDs must be unique in a manifest',
      ['memberships'],
    );
    assertUnique(
      manifest.ownerPrincipalIds,
      context,
      'Owner principal IDs must be unique',
      ['ownerPrincipalIds'],
    );
    assertUnique(
      manifest.keyEnvelopes.map((envelope) =>
        'membershipId' in envelope
          ? `${envelope.membershipId}:${envelope.deviceId}`
          : `authority:${String(envelope.authorityEpoch)}:${String(envelope.keyEpoch)}`,
      ),
      context,
      'Member key envelopes must be unique per device',
      ['keyEnvelopes'],
    );
    const activeOwners = manifest.memberships.filter(
      (membership) => membership.state === 'active' && membership.role === 'owner',
    );
    if (activeOwners.length === 0) {
      addIssue(context, 'A membership manifest must retain an active owner', [
        'memberships',
      ]);
    }
    const activeOwnerIds = new Set(
      activeOwners.map((membership) => membership.principalId),
    );
    for (const [index, ownerId] of manifest.ownerPrincipalIds.entries()) {
      if (!activeOwnerIds.has(ownerId)) {
        addIssue(context, 'Owner index must contain only active owner memberships', [
          'ownerPrincipalIds',
          index,
        ]);
      }
    }
    if (manifest.ownerPrincipalIds.length !== activeOwners.length) {
      addIssue(context, 'Owner index must enumerate every active owner exactly once', [
        'ownerPrincipalIds',
      ]);
    }
    if (
      manifest.policy.databaseId !== manifest.databaseId ||
      manifest.policy.vaultId !== manifest.vaultId ||
      manifest.policy.authorityEpoch !== manifest.authorityEpoch ||
      manifest.policy.databaseDeviceGeneration !== manifest.databaseDeviceGeneration ||
      manifest.policy.databaseDeviceRegistryDigest !==
        manifest.databaseDeviceRegistryDigest ||
      manifest.policy.policyRevision !== manifest.policyRevision ||
      manifest.policy.approvalPolicy !== manifest.approvalPolicy
    ) {
      addIssue(context, 'Manifest policy must bind the exact current policy tuple', [
        'policy',
      ]);
    }
    if (
      manifest.history.databaseId !== manifest.databaseId ||
      manifest.history.vaultId !== manifest.vaultId ||
      manifest.history.authorityEpoch !== manifest.authorityEpoch ||
      manifest.history.databaseDeviceGeneration !== manifest.databaseDeviceGeneration ||
      manifest.history.databaseDeviceRegistryDigest !==
        manifest.databaseDeviceRegistryDigest ||
      manifest.history.previousHeadDigest !== manifest.previousHeadDigest
    ) {
      addIssue(
        context,
        'Manifest history must belong to the manifest database and vault',
        ['history'],
      );
    }
    if (
      manifest.documentRevision === 1 &&
      (manifest.membershipRevision !== 1 ||
        manifest.previousHeadDigest !== COLLABORATION_GENESIS_HEAD_DIGEST ||
        manifest.previousMembershipDigest !==
          COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST ||
        manifest.history.compactedThroughRevision !== 0 ||
        manifest.history.compactedHistoryDigest !==
          COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST ||
        manifest.history.previousHistoryDigest !==
          COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST)
    ) {
      addIssue(
        context,
        'Genesis manifest must use the canonical predecessor state digests',
      );
    }
    for (const [membershipIndex, membership] of manifest.memberships.entries()) {
      for (const [deviceIndex, device] of membership.devices.entries()) {
        const envelopeCount = manifest.keyEnvelopes.filter(
          (envelope) =>
            'membershipId' in envelope &&
            envelope.membershipId === membership.membershipId &&
            envelope.principalId === membership.principalId &&
            envelope.deviceId === device.deviceId &&
            envelope.authorityEpoch === manifest.authorityEpoch &&
            envelope.keyEpoch === manifest.keyEpoch &&
            envelope.membershipRevision === manifest.membershipRevision &&
            envelope.databaseDeviceGeneration === manifest.databaseDeviceGeneration &&
            envelope.databaseDeviceRegistryDigest ===
              manifest.databaseDeviceRegistryDigest,
        ).length;
        const mustDecrypt = membership.state === 'active' && device.state === 'active';
        if (mustDecrypt ? envelopeCount !== 1 : envelopeCount !== 0) {
          addIssue(
            context,
            'Only active member devices receive exactly one current key envelope',
            ['memberships', membershipIndex, 'devices', deviceIndex],
          );
        }
      }
    }
    let authorityRecoveryEnvelopeCount = 0;
    for (const [index, envelope] of manifest.keyEnvelopes.entries()) {
      if (!('membershipId' in envelope)) {
        authorityRecoveryEnvelopeCount += 1;
        const sealingOwner = manifest.memberships.find(
          (membership) => membership.principalId === envelope.sealedByPrincipalId,
        );
        if (
          envelope.databaseId !== manifest.databaseId ||
          envelope.vaultId !== manifest.vaultId ||
          envelope.authorityEpoch !== manifest.authorityEpoch ||
          envelope.keyEpoch !== manifest.keyEpoch ||
          envelope.databaseDeviceGeneration !== manifest.databaseDeviceGeneration ||
          envelope.databaseDeviceRegistryDigest !==
            manifest.databaseDeviceRegistryDigest ||
          !activeOwnerIds.has(envelope.sealedByPrincipalId) ||
          !sealingOwner?.devices.some(
            (device) =>
              device.deviceId === envelope.sealedByDeviceId &&
              device.state === 'active',
          )
        ) {
          addIssue(
            context,
            'Authority recovery envelopes must bind the current vault state',
            ['keyEnvelopes', index],
          );
        }
        continue;
      }
      if (
        envelope.databaseId !== manifest.databaseId ||
        envelope.vaultId !== manifest.vaultId ||
        envelope.authorityEpoch !== manifest.authorityEpoch ||
        envelope.keyEpoch !== manifest.keyEpoch ||
        envelope.membershipRevision !== manifest.membershipRevision ||
        envelope.databaseDeviceGeneration !== manifest.databaseDeviceGeneration ||
        envelope.databaseDeviceRegistryDigest !== manifest.databaseDeviceRegistryDigest
      ) {
        addIssue(context, 'Manifest key envelopes must bind the current state', [
          'keyEnvelopes',
          index,
        ]);
      }
      const membership = manifest.memberships.find(
        (candidate) => candidate.membershipId === envelope.membershipId,
      );
      if (
        membership?.state !== 'active' ||
        membership.principalId !== envelope.principalId ||
        !membership.devices.some(
          (device) =>
            device.deviceId === envelope.deviceId && device.state === 'active',
        )
      ) {
        addIssue(context, 'Key envelopes cannot be issued to inactive members', [
          'keyEnvelopes',
          index,
        ]);
      }
    }
    if (authorityRecoveryEnvelopeCount !== 1) {
      addIssue(
        context,
        'Membership manifest requires exactly one current authority recovery envelope',
        ['keyEnvelopes'],
      );
    }
  });

export const membershipManifestSchema = collaborativeMembershipManifestSchema;
export const collaborationMembershipManifestSchema =
  collaborativeMembershipManifestSchema;
export type CollaborativeMembershipManifest = z.infer<
  typeof collaborativeMembershipManifestSchema
>;
export type MembershipManifest = CollaborativeMembershipManifest;

export const collaborationWriterSignatureSchema = z
  .object({
    algorithm: z.literal('ed25519'),
    writerPrincipalId: principalIdSchema,
    writerDeviceId: deviceIdSchema,
    commitmentDigest: sha256DigestSchema,
    signature: boundedSignatureSchema,
  })
  .strict();

export type CollaborationWriterSignature = z.infer<
  typeof collaborationWriterSignatureSchema
>;

export const collaborationFinalizedMutationLinkSchema = z
  .object({
    format: z.literal(COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityDelegationDigest: sha256DigestSchema,
    commitment: collaborationMutationCommitmentSchema,
    authorizationTransition: collaborationAuthorizationTransitionSchema.optional(),
    resultingHeadDigest: sha256DigestSchema,
    writerSignature: collaborationWriterSignatureSchema,
    finalizedAt: timestampSchema,
  })
  .strict()
  .superRefine((link, context) => {
    assertCanonicalBytes(link, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    const commitment = link.commitment;
    if (
      commitment.databaseId !== link.databaseId ||
      commitment.vaultId !== link.vaultId
    ) {
      addIssue(context, 'Finalized mutation link and commitment scope must match', [
        'commitment',
      ]);
    }
    if (
      link.writerSignature.writerPrincipalId !== commitment.writerPrincipalId ||
      link.writerSignature.writerDeviceId !== commitment.writerDeviceId ||
      link.writerSignature.commitmentDigest !== link.resultingHeadDigest
    ) {
      addIssue(context, 'Finalized mutation link writer must sign its resulting head', [
        'writerSignature',
      ]);
    }
    const transition = link.authorizationTransition;
    if (commitment.operationType === 'ordinary-write' && transition !== undefined) {
      addIssue(
        context,
        'Ordinary mutation links cannot carry authorization transitions',
        ['authorizationTransition'],
      );
    }
    if (commitment.operationType !== 'ordinary-write' && transition === undefined) {
      addIssue(
        context,
        'Administrative mutation links require authorization transitions',
        ['authorizationTransition'],
      );
    }
    if (
      transition !== undefined &&
      (transition.databaseId !== link.databaseId ||
        transition.vaultId !== link.vaultId ||
        transition.operationId !== commitment.operationId ||
        transition.operationType !== commitment.operationType ||
        transition.previousHeadDigest !== commitment.previousHeadDigest ||
        transition.previousAuthorizationStateDigest !==
          commitment.previousAuthorizationStateDigest ||
        transition.authorizationStateDigest !== commitment.authorizationStateDigest ||
        transition.transitionDigest !== commitment.authorizationTransitionDigest ||
        canonicalJson(transition.previousTuple) !==
          canonicalJson({
            authorityEpoch: commitment.previousAuthorityEpoch,
            documentRevision: commitment.previousDocumentRevision,
            membershipRevision: commitment.previousMembershipRevision,
            policyRevision: commitment.previousPolicyRevision,
            keyEpoch: commitment.previousKeyEpoch,
            databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
            databaseDeviceRegistryDigest:
              commitment.previousDatabaseDeviceRegistryDigest,
            authorizationStateDigest: commitment.previousAuthorizationStateDigest,
          }) ||
        canonicalJson(transition.nextTuple) !==
          canonicalJson({
            authorityEpoch: commitment.authorityEpoch,
            documentRevision: commitment.documentRevision,
            membershipRevision: commitment.membershipRevision,
            policyRevision: commitment.policyRevision,
            keyEpoch: commitment.keyEpoch,
            databaseDeviceGeneration: commitment.databaseDeviceGeneration,
            databaseDeviceRegistryDigest: commitment.databaseDeviceRegistryDigest,
            authorizationStateDigest: commitment.authorizationStateDigest,
          }))
    ) {
      addIssue(
        context,
        'Authorization transition must bind the exact mutation commitment',
        ['authorizationTransition'],
      );
    }
  });

export type CollaborationFinalizedMutationLink = z.infer<
  typeof collaborationFinalizedMutationLinkSchema
>;

export const collaborationAuthorizationWitnessSchema = z
  .object({
    format: z.literal(COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityDelegationDigest: sha256DigestSchema,
    tuple: collaborationRevisionTupleSchema,
    previousHeadDigest: sha256DigestSchema,
    headDigest: sha256DigestSchema,
    encryptedMembershipDigest: sha256DigestSchema,
    encryptedEnvelopesDigest: sha256DigestSchema,
    policyDigest: sha256DigestSchema,
    databaseDeviceRegistry: collaborationDatabaseDeviceRegistrySchema,
    databaseAuthorityRecoveryEnvelope: databaseAuthorityRecoveryEnvelopeSchema,
    encryptedMembershipManifest: collaborativeAeadEnvelopeSchema,
    discoveryRecords: z
      .array(collaborationDiscoveryRecordSchema)
      .max(MAX_COLLABORATIVE_DISCOVERY_RECORDS),
    finalizedMutationLinkDigest: sha256DigestSchema,
  })
  .strict()
  .superRefine((witness, context) => {
    assertCanonicalBytes(
      witness,
      MAX_COLLABORATIVE_AUTHORIZATION_WITNESS_BYTES,
      context,
    );
    const registry = witness.databaseDeviceRegistry;
    const recoveryEnvelope = witness.databaseAuthorityRecoveryEnvelope;
    if (
      registry.databaseId !== witness.databaseId ||
      registry.authorityEpoch !== witness.tuple.authorityEpoch ||
      registry.generation !== witness.tuple.databaseDeviceGeneration ||
      registry.registryDigest !== witness.tuple.databaseDeviceRegistryDigest
    ) {
      addIssue(
        context,
        'Authorization witness device registry must bind its exact tuple',
        ['databaseDeviceRegistry'],
      );
    }
    if (
      recoveryEnvelope.databaseId !== witness.databaseId ||
      recoveryEnvelope.vaultId !== witness.vaultId ||
      recoveryEnvelope.authorityEpoch !== witness.tuple.authorityEpoch ||
      recoveryEnvelope.keyEpoch !== witness.tuple.keyEpoch ||
      recoveryEnvelope.membershipRevision !== witness.tuple.membershipRevision ||
      recoveryEnvelope.databaseDeviceGeneration !==
        witness.tuple.databaseDeviceGeneration ||
      recoveryEnvelope.databaseDeviceRegistryDigest !==
        witness.tuple.databaseDeviceRegistryDigest
    ) {
      addIssue(
        context,
        'Authorization witness recovery envelope must bind its exact scope and tuple',
        ['databaseAuthorityRecoveryEnvelope'],
      );
    }
    const aad = witness.encryptedMembershipManifest.aad;
    if (
      aad.databaseId !== witness.databaseId ||
      aad.vaultId !== witness.vaultId ||
      aad.entityType !== 'membership-manifest' ||
      aad.entityId !== witness.vaultId ||
      canonicalJson({
        authorityEpoch: aad.authorityEpoch,
        documentRevision: aad.documentRevision,
        membershipRevision: aad.membershipRevision,
        policyRevision: aad.policyRevision,
        keyEpoch: aad.keyEpoch,
        databaseDeviceGeneration: aad.databaseDeviceGeneration,
        databaseDeviceRegistryDigest: aad.databaseDeviceRegistryDigest,
        authorizationStateDigest: aad.authorizationStateDigest,
      }) !== canonicalJson(witness.tuple)
    ) {
      addIssue(
        context,
        'Authorization witness manifest AAD must bind its exact tuple',
        ['encryptedMembershipManifest', 'aad'],
      );
    }
    assertUnique(
      witness.discoveryRecords.map(
        (record) =>
          `${record.discoveryTag}:${record.membershipId}:${record.encryptedMemberKeyEnvelope.deviceId}`,
      ),
      context,
      'Authorization witness discovery records must be unique per member device',
      ['discoveryRecords'],
    );
    for (const [index, record] of witness.discoveryRecords.entries()) {
      if (
        record.databaseId !== witness.databaseId ||
        record.vaultId !== witness.vaultId ||
        record.authorityEpoch !== witness.tuple.authorityEpoch ||
        record.databaseDeviceGeneration !== witness.tuple.databaseDeviceGeneration ||
        record.databaseDeviceRegistryDigest !==
          witness.tuple.databaseDeviceRegistryDigest ||
        record.membershipRevision !== witness.tuple.membershipRevision ||
        record.keyEpoch !== witness.tuple.keyEpoch ||
        record.authorizationStateDigest !== witness.tuple.authorizationStateDigest ||
        record.encryptedMembershipMetadataDigest !== witness.encryptedMembershipDigest
      ) {
        addIssue(context, 'Authorization witness discovery record has wrong state', [
          'discoveryRecords',
          index,
        ]);
      }
    }
  });

export type CollaborationAuthorizationWitness = z.infer<
  typeof collaborationAuthorizationWitnessSchema
>;

export const collaborationMutationProofEntrySchema = z
  .object({
    link: collaborationFinalizedMutationLinkSchema,
    authorizationWitness: collaborationAuthorizationWitnessSchema.optional(),
  })
  .strict()
  .superRefine((entry, context) => {
    const commitment = entry.link.commitment;
    const witness = entry.authorizationWitness;
    if (commitment.operationType === 'ordinary-write') {
      if (witness !== undefined) {
        addIssue(
          context,
          'Ordinary proof entries cannot carry authorization witnesses',
          ['authorizationWitness'],
        );
      }
      return;
    }
    if (witness === undefined) {
      addIssue(
        context,
        'Administrative proof entries require authorization witnesses',
        ['authorizationWitness'],
      );
      return;
    }
    if (
      witness.databaseId !== entry.link.databaseId ||
      witness.vaultId !== entry.link.vaultId ||
      witness.authorityDelegationDigest !== entry.link.authorityDelegationDigest ||
      witness.previousHeadDigest !== commitment.previousHeadDigest ||
      witness.headDigest !== entry.link.resultingHeadDigest ||
      witness.tuple.authorizationStateDigest !== commitment.authorizationStateDigest ||
      witness.encryptedMembershipDigest !== commitment.encryptedMembershipDigest ||
      witness.encryptedEnvelopesDigest !== commitment.encryptedEnvelopesDigest ||
      witness.policyDigest !== commitment.policyDigest ||
      canonicalJson(witness.tuple) !==
        canonicalJson({
          authorityEpoch: commitment.authorityEpoch,
          documentRevision: commitment.documentRevision,
          membershipRevision: commitment.membershipRevision,
          policyRevision: commitment.policyRevision,
          keyEpoch: commitment.keyEpoch,
          databaseDeviceGeneration: commitment.databaseDeviceGeneration,
          databaseDeviceRegistryDigest: commitment.databaseDeviceRegistryDigest,
          authorizationStateDigest: commitment.authorizationStateDigest,
        })
    ) {
      addIssue(
        context,
        'Authorization witness must bind the exact administrative link',
        ['authorizationWitness'],
      );
    }
    for (const [index, record] of witness.discoveryRecords.entries()) {
      if (
        record.signerPrincipalId !== entry.link.writerSignature.writerPrincipalId ||
        record.signerDeviceId !== entry.link.writerSignature.writerDeviceId
      ) {
        addIssue(
          context,
          'Authorization-witness discovery records must be signed by the finalized-link writer',
          ['authorizationWitness', 'discoveryRecords', index],
        );
      }
    }
  });

export const collaborationMutationProofSchema = z
  .object({
    format: z.literal(COLLABORATIVE_MUTATION_PROOF_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityDelegationDigest: sha256DigestSchema,
    fromDocumentRevision: revisionSchema,
    fromHeadDigest: sha256DigestSchema,
    toDocumentRevision: revisionSchema,
    toHeadDigest: sha256DigestSchema,
    startingAuthorizationWitness: collaborationAuthorizationWitnessSchema,
    entries: z
      .array(collaborationMutationProofEntrySchema)
      .min(1)
      .max(MAX_COLLABORATIVE_PROOF_LINKS),
  })
  .strict()
  .superRefine((proof, context) => {
    assertCanonicalBytes(proof, MAX_COLLABORATIVE_PROOF_BYTES, context);
    const startingWitness = proof.startingAuthorizationWitness;
    const firstEntry = proof.entries[0];
    if (
      firstEntry === undefined ||
      startingWitness.databaseId !== proof.databaseId ||
      startingWitness.vaultId !== proof.vaultId ||
      startingWitness.authorityDelegationDigest !== proof.authorityDelegationDigest ||
      startingWitness.tuple.documentRevision > proof.fromDocumentRevision ||
      startingWitness.tuple.authorizationStateDigest !==
        firstEntry.link.commitment.previousAuthorizationStateDigest
    ) {
      addIssue(
        context,
        'Mutation proof must carry the exact prior authorization-state witness',
        ['startingAuthorizationWitness'],
      );
    }
    let expectedPreviousRevision = proof.fromDocumentRevision;
    let expectedPreviousHead = proof.fromHeadDigest;
    for (const [index, entry] of proof.entries.entries()) {
      const link = entry.link;
      const commitment = link.commitment;
      if (
        link.databaseId !== proof.databaseId ||
        link.vaultId !== proof.vaultId ||
        link.authorityDelegationDigest !== proof.authorityDelegationDigest ||
        commitment.previousDocumentRevision !== expectedPreviousRevision ||
        commitment.documentRevision !== expectedPreviousRevision + 1 ||
        commitment.previousHeadDigest !== expectedPreviousHead
      ) {
        addIssue(context, 'Mutation proof links must form one exact contiguous chain', [
          'entries',
          index,
        ]);
      }
      expectedPreviousRevision = commitment.documentRevision;
      expectedPreviousHead = link.resultingHeadDigest;
    }
    if (
      expectedPreviousRevision !== proof.toDocumentRevision ||
      expectedPreviousHead !== proof.toHeadDigest
    ) {
      addIssue(context, 'Mutation proof tip does not match its declared destination');
    }
  });

export type CollaborationMutationProof = z.infer<
  typeof collaborationMutationProofSchema
>;

export const collaborationAuthorizationCheckpointSchema = z
  .object({
    format: z.literal(COLLABORATIVE_AUTHORIZATION_CHECKPOINT_FORMAT),
    protocolVersion: protocolVersionSchema,
    checkpointId: historyIdSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityDelegationDigest: sha256DigestSchema,
    tuple: collaborationRevisionTupleSchema,
    headDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    finalizedMutationLinkDigest: sha256DigestSchema,
    previousCheckpointDigest: sha256DigestSchema.optional(),
    compactedThroughDocumentRevision: revisionSchema,
    checkpointDigest: sha256DigestSchema,
    signerPrincipalId: principalIdSchema,
    signerDeviceId: deviceIdSchema,
    createdAt: timestampSchema,
    ownerSignature: boundedSignatureSchema,
  })
  .strict()
  .superRefine((checkpoint, context) => {
    assertCanonicalBytes(checkpoint, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    if (
      checkpoint.tuple.authorizationStateDigest !== checkpoint.authorizationStateDigest
    ) {
      addIssue(context, 'Checkpoint tuple must bind its authorization-state digest', [
        'tuple',
        'authorizationStateDigest',
      ]);
    }
    if (
      checkpoint.compactedThroughDocumentRevision > checkpoint.tuple.documentRevision
    ) {
      addIssue(context, 'Checkpoint cannot compact beyond its bound tuple', [
        'compactedThroughDocumentRevision',
      ]);
    }
  });

export type CollaborationAuthorizationCheckpoint = z.infer<
  typeof collaborationAuthorizationCheckpointSchema
>;

export const collaborativeVaultDocumentSchema = z
  .object({
    format: z.literal(COLLABORATIVE_VAULT_FORMAT),
    documentVersion: documentVersionSchema,
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    documentRevision: revisionSchema,
    membershipRevision: revisionSchema,
    policyRevision: revisionSchema,
    keyEpoch: collaborationKeyEpochSchema,
    previousHeadDigest: sha256DigestSchema,
    headDigest: sha256DigestSchema,
    authorityDelegation: collaborationAuthorityDelegationSchema,
    authorityDelegationDigest: sha256DigestSchema,
    authorizationStateDigest: sha256DigestSchema,
    encryptedPayloadDigest: sha256DigestSchema,
    encryptedMembershipDigest: sha256DigestSchema,
    encryptedEnvelopesDigest: sha256DigestSchema,
    policyDigest: sha256DigestSchema,
    databaseAuthorityRecoveryEnvelope: databaseAuthorityRecoveryEnvelopeSchema,
    encryptedPayload: collaborativeAeadEnvelopeSchema,
    encryptedMembershipManifest: collaborativeAeadEnvelopeSchema,
    discoveryRecords: z
      .array(collaborationDiscoveryRecordSchema)
      .max(MAX_COLLABORATIVE_DISCOVERY_RECORDS),
    currentMutationLink: collaborationFinalizedMutationLinkSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((document, context) => {
    assertCanonicalBytes(document, MAX_COLLABORATIVE_VAULT_DOCUMENT_BYTES, context);
    const payloadAad = document.encryptedPayload.aad;
    const membershipAad = document.encryptedMembershipManifest.aad;
    const recoveryEnvelope = document.databaseAuthorityRecoveryEnvelope;
    const tupleMatches = (value: CollaborationRevisionTuple): boolean =>
      value.authorityEpoch === document.authorityEpoch &&
      value.databaseDeviceGeneration === document.databaseDeviceGeneration &&
      value.databaseDeviceRegistryDigest === document.databaseDeviceRegistryDigest &&
      value.authorizationStateDigest === document.authorizationStateDigest &&
      value.documentRevision === document.documentRevision &&
      value.membershipRevision === document.membershipRevision &&
      value.policyRevision === document.policyRevision &&
      value.keyEpoch === document.keyEpoch;
    if (
      recoveryEnvelope.databaseId !== document.databaseId ||
      recoveryEnvelope.vaultId !== document.vaultId ||
      recoveryEnvelope.authorityEpoch !== document.authorityEpoch ||
      recoveryEnvelope.authorityRecoveryKeyFingerprint !==
        document.authorityDelegation.authorityRecoveryKeyFingerprint ||
      recoveryEnvelope.keyEpoch !== document.keyEpoch ||
      recoveryEnvelope.membershipRevision !== document.membershipRevision ||
      recoveryEnvelope.databaseDeviceGeneration !== document.databaseDeviceGeneration ||
      recoveryEnvelope.databaseDeviceRegistryDigest !==
        document.databaseDeviceRegistryDigest
    ) {
      addIssue(
        context,
        'Authority recovery envelope must bind the exact current document scope',
        ['databaseAuthorityRecoveryEnvelope'],
      );
    }
    if (
      payloadAad.databaseId !== document.databaseId ||
      payloadAad.vaultId !== document.vaultId ||
      payloadAad.entityType !== 'vault-payload' ||
      payloadAad.entityId !== document.vaultId ||
      !tupleMatches(payloadAad)
    ) {
      addIssue(
        context,
        'Encrypted payload has invalid database, vault, tuple, or digest binding',
        ['encryptedPayload', 'aad'],
      );
    }
    if (
      membershipAad.databaseId !== document.databaseId ||
      membershipAad.vaultId !== document.vaultId ||
      membershipAad.entityType !== 'membership-manifest' ||
      membershipAad.entityId !== document.vaultId ||
      !tupleMatches(membershipAad)
    ) {
      addIssue(context, 'Encrypted membership manifest has an invalid binding', [
        'encryptedMembershipManifest',
        'aad',
      ]);
    }
    const link = document.currentMutationLink;
    const commitment = link.commitment;
    if (
      commitment.databaseId !== document.databaseId ||
      commitment.vaultId !== document.vaultId ||
      commitment.authorityEpoch !== document.authorityEpoch ||
      commitment.databaseDeviceGeneration !== document.databaseDeviceGeneration ||
      commitment.databaseDeviceRegistryDigest !==
        document.databaseDeviceRegistryDigest ||
      commitment.documentRevision !== document.documentRevision ||
      commitment.membershipRevision !== document.membershipRevision ||
      commitment.policyRevision !== document.policyRevision ||
      commitment.keyEpoch !== document.keyEpoch ||
      commitment.previousHeadDigest !== document.previousHeadDigest ||
      commitment.authorizationStateDigest !== document.authorizationStateDigest ||
      commitment.encryptedPayloadDigest !== document.encryptedPayloadDigest ||
      commitment.encryptedMembershipDigest !== document.encryptedMembershipDigest ||
      commitment.encryptedEnvelopesDigest !== document.encryptedEnvelopesDigest ||
      commitment.policyDigest !== document.policyDigest
    ) {
      addIssue(
        context,
        'Mutation commitment does not bind the complete document state',
        ['currentMutationLink', 'commitment'],
      );
    }
    if (
      link.databaseId !== document.databaseId ||
      link.vaultId !== document.vaultId ||
      link.authorityDelegationDigest !== document.authorityDelegationDigest ||
      link.resultingHeadDigest !== document.headDigest
    ) {
      addIssue(
        context,
        'Current mutation link must bind the document scope, delegation, and head',
        ['currentMutationLink'],
      );
    }
    if (
      document.authorityDelegation.databaseId !== document.databaseId ||
      document.authorityDelegation.vaultId !== document.vaultId ||
      document.authorityDelegation.authorityEpoch !== document.authorityEpoch
    ) {
      addIssue(
        context,
        'Authority delegation must bind the document database, vault, and epoch',
        ['authorityDelegation'],
      );
    }
    if (document.documentRevision === 1) {
      const delegation = document.authorityDelegation;
      if (
        commitment.operationType !== 'genesis-migration' ||
        commitment.operationId !== delegation.genesisOperationId ||
        document.previousHeadDigest !== COLLABORATION_GENESIS_HEAD_DIGEST ||
        commitment.previousDocumentRevision !== 0 ||
        commitment.previousMembershipRevision !== 0 ||
        commitment.previousPolicyRevision !== 0 ||
        commitment.previousAuthorityEpoch !== document.authorityEpoch ||
        commitment.previousKeyEpoch !== document.keyEpoch ||
        commitment.previousDatabaseDeviceGeneration !==
          document.databaseDeviceGeneration ||
        commitment.previousDatabaseDeviceRegistryDigest !==
          document.databaseDeviceRegistryDigest ||
        commitment.previousAuthorizationStateDigest !==
          COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST ||
        document.headDigest !== delegation.genesisHeadDigest ||
        document.authorizationStateDigest !==
          delegation.initialAuthorizationStateDigest ||
        canonicalJson(delegation.genesisTuple) !==
          canonicalJson({
            authorityEpoch: document.authorityEpoch,
            documentRevision: document.documentRevision,
            membershipRevision: document.membershipRevision,
            policyRevision: document.policyRevision,
            keyEpoch: document.keyEpoch,
            databaseDeviceGeneration: document.databaseDeviceGeneration,
            databaseDeviceRegistryDigest: document.databaseDeviceRegistryDigest,
            authorizationStateDigest: document.authorizationStateDigest,
          })
      ) {
        addIssue(
          context,
          'Genesis document must match the immutable authority delegation exactly',
          ['authorityDelegation'],
        );
      }
    } else if (commitment.operationType === 'genesis-migration') {
      addIssue(context, 'Genesis migration is valid only at document revision one', [
        'currentMutationLink',
        'commitment',
        'operationType',
      ]);
    }
    assertUnique(
      document.discoveryRecords.map(
        (record) =>
          `${record.discoveryTag}:${record.membershipId}:${record.encryptedMemberKeyEnvelope.deviceId}`,
      ),
      context,
      'Discovery records must be unique per member device in a vault document',
      ['discoveryRecords'],
    );
    for (const [index, record] of document.discoveryRecords.entries()) {
      if (
        record.databaseId !== document.databaseId ||
        record.vaultId !== document.vaultId ||
        record.authorityEpoch !== document.authorityEpoch ||
        record.databaseDeviceGeneration !== document.databaseDeviceGeneration ||
        record.databaseDeviceRegistryDigest !== document.databaseDeviceRegistryDigest ||
        record.keyEpoch !== document.keyEpoch ||
        record.membershipRevision !== document.membershipRevision ||
        record.authorizationStateDigest !== document.authorizationStateDigest ||
        record.encryptedMembershipMetadataDigest !==
          document.encryptedMembershipDigest ||
        record.signerPrincipalId !== link.writerSignature.writerPrincipalId ||
        record.signerDeviceId !== link.writerSignature.writerDeviceId
      ) {
        addIssue(context, 'Discovery records must bind the current document tuple', [
          'discoveryRecords',
          index,
        ]);
      }
    }
  });

export const collaborativeVaultDocumentFormatSchema = z.literal(
  COLLABORATIVE_VAULT_FORMAT,
);
export const collaborativeDocumentSchema = collaborativeVaultDocumentSchema;
export const collaborativeVaultSchema = collaborativeVaultDocumentSchema;
export type CollaborativeVaultDocument = z.infer<
  typeof collaborativeVaultDocumentSchema
>;
export type CollaborativeDocument = CollaborativeVaultDocument;

export const collaborationMigrationRequestSchema = z
  .object({
    format: z.literal('kavrix-collaborative-migration-request'),
    protocolVersion: protocolVersionSchema,
    operationType: z.literal('genesis-migration'),
    operationId: collaborationOperationIdSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    legacyVaultRevision: revisionSchema,
    legacySourceDigest: sha256DigestSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    authorityFingerprint: sha256DigestSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    initialOwnerPrincipalId: principalIdSchema,
    initialOwnerDeviceId: deviceIdSchema,
    initialMembershipId: membershipIdSchema,
    requestedAt: timestampSchema,
    requestDigest: sha256DigestSchema,
    authoritySignature: boundedSignatureSchema,
    ownerSignature: boundedSignatureSchema,
  })
  .strict()
  .superRefine((request, context) => {
    assertCanonicalBytes(request, MAX_COLLABORATIVE_OPERATION_BYTES, context);
  });

export type CollaborationMigrationRequest = z.infer<
  typeof collaborationMigrationRequestSchema
>;

const collaborationMigrationMarkerBaseSchema = z
  .object({
    format: z.literal(COLLABORATIVE_MIGRATION_MARKER_FORMAT),
    markerVersion: z.literal(1),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    operationId: collaborationOperationIdSchema,
    requestDigest: sha256DigestSchema,
    legacySourceDigest: sha256DigestSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    authorityFingerprint: sha256DigestSchema,
    databaseDeviceGeneration: revisionSchema,
    databaseDeviceRegistryDigest: sha256DigestSchema,
    candidateHeadDigest: sha256DigestSchema,
    preparedAt: timestampSchema,
    authoritySignature: boundedSignatureSchema,
  })
  .strict();

export const collaborationMigrationPreparedMarkerSchema =
  collaborationMigrationMarkerBaseSchema
    .extend({
      state: z.literal('prepared'),
      legacySource: databaseVaultDocumentSchema,
      registryCandidate: collaborationDatabaseDeviceRegistrySchema,
    })
    .strict()
    .superRefine((marker, context) => {
      assertCanonicalBytes(marker, MAX_COLLABORATIVE_VAULT_DOCUMENT_BYTES, context);
      if (
        marker.legacySource.databaseId !== marker.databaseId ||
        marker.legacySource.id !== marker.vaultId
      ) {
        addIssue(context, 'Migration source belongs to another database or vault', [
          'legacySource',
        ]);
      }
      if (
        marker.registryCandidate.databaseId !== marker.databaseId ||
        marker.registryCandidate.authorityEpoch !== marker.authorityEpoch ||
        marker.registryCandidate.authorityFingerprint !== marker.authorityFingerprint ||
        marker.registryCandidate.generation !== marker.databaseDeviceGeneration ||
        marker.registryCandidate.registryDigest !== marker.databaseDeviceRegistryDigest
      ) {
        addIssue(context, 'Migration registry candidate does not bind the marker', [
          'registryCandidate',
        ]);
      }
    });

export const collaborationMigrationActiveMarkerSchema =
  collaborationMigrationMarkerBaseSchema
    .extend({
      state: z.literal('active'),
      outcomeDigest: sha256DigestSchema,
      activatedAt: timestampSchema,
    })
    .strict()
    .superRefine((marker, context) => {
      assertCanonicalBytes(marker, MAX_COLLABORATIVE_OPERATION_BYTES, context);
      if (!isAtOrAfter(marker.activatedAt, marker.preparedAt)) {
        addIssue(context, 'Migration activation cannot precede preparation', [
          'activatedAt',
        ]);
      }
    });

export const collaborationMigrationMarkerSchema = z.discriminatedUnion('state', [
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationActiveMarkerSchema,
]);

export type CollaborationMigrationPreparedMarker = z.infer<
  typeof collaborationMigrationPreparedMarkerSchema
>;
export type CollaborationMigrationActiveMarker = z.infer<
  typeof collaborationMigrationActiveMarkerSchema
>;
export type CollaborationMigrationMarker = z.infer<
  typeof collaborationMigrationMarkerSchema
>;

/** Exact non-secret action projection approved for irreversible vault destruction. */
export const collaborationVaultDestructionActionSchema = z
  .object({
    protocolVersion: protocolVersionSchema,
    operationType: z.literal('destroy-vault'),
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    destructionMode: z.literal('irreversible'),
  })
  .strict();

export type CollaborationVaultDestructionAction = z.infer<
  typeof collaborationVaultDestructionActionSchema
>;

export const operationOutcomeStateSchema = z.enum([
  'committed',
  'conflicted',
  'rejected',
]);

export const collaborationMutationReceiptSchema = z
  .object({
    format: z.literal(COLLABORATIVE_MUTATION_RECEIPT_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    operationId: collaborationOperationIdSchema,
    operationType: mutationOperationTypeSchema,
    requestDigest: sha256DigestSchema,
    actorPrincipalId: principalIdSchema,
    actorDeviceId: deviceIdSchema,
    priorTuple: collaborationRevisionTupleSchema,
    priorHeadDigest: sha256DigestSchema,
    committedTuple: collaborationRevisionTupleSchema,
    committedHeadDigest: sha256DigestSchema,
    finalizedMutationLinkDigest: sha256DigestSchema,
    outcomeDigest: sha256DigestSchema,
    committedAt: timestampSchema,
    receiptSignature: boundedSignatureSchema,
  })
  .strict()
  .superRefine((receipt, context) => {
    assertCanonicalBytes(receipt, MAX_COLLABORATIVE_OPERATION_BYTES, context);
  });

export type CollaborationMutationReceipt = z.infer<
  typeof collaborationMutationReceiptSchema
>;

export const durableOperationOutcomeSchema = z
  .object({
    format: z.literal(COLLABORATIVE_OPERATION_OUTCOME_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    operationId: collaborationOperationIdSchema,
    operationType: mutationOperationTypeSchema,
    requestDigest: sha256DigestSchema,
    actorPrincipalId: principalIdSchema,
    actorDeviceId: deviceIdSchema,
    priorTuple: collaborationRevisionTupleSchema,
    priorHeadDigest: sha256DigestSchema,
    state: operationOutcomeStateSchema,
    committedTuple: collaborationRevisionTupleSchema.optional(),
    committedHeadDigest: sha256DigestSchema.optional(),
    finalizedMutationLinkDigest: sha256DigestSchema.optional(),
    committedAt: timestampSchema.optional(),
    outcomeDigest: sha256DigestSchema,
    signedMutationReceipt: collaborationMutationReceiptSchema.optional(),
    createdAt: timestampSchema,
    resolvedAt: timestampSchema,
    detailsRetainedUntil: timestampSchema,
  })
  .strict()
  .superRefine((outcome, context) => {
    assertCanonicalBytes(outcome, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    if (!isAtOrAfter(outcome.resolvedAt, outcome.createdAt)) {
      addIssue(context, 'Operation outcome cannot resolve before creation', [
        'resolvedAt',
      ]);
    }
    if (!isAfter(outcome.detailsRetainedUntil, outcome.resolvedAt)) {
      addIssue(context, 'Full outcome retention must extend beyond resolution', [
        'detailsRetainedUntil',
      ]);
    }
    const committedFields = [
      outcome.committedTuple,
      outcome.committedHeadDigest,
      outcome.finalizedMutationLinkDigest,
      outcome.committedAt,
      outcome.signedMutationReceipt,
    ];
    const hasAllCommittedFields = committedFields.every((field) => field !== undefined);
    const hasAnyCommittedFields = committedFields.some((field) => field !== undefined);
    if (outcome.state === 'committed' && !hasAllCommittedFields) {
      addIssue(
        context,
        'Committed operation outcomes require the complete committed tuple and head',
      );
    }
    if (outcome.state !== 'committed' && hasAnyCommittedFields) {
      addIssue(context, 'Only committed operation outcomes may carry committed state', [
        'state',
      ]);
    }
    if (outcome.signedMutationReceipt !== undefined) {
      const receipt = outcome.signedMutationReceipt;
      if (
        receipt.databaseId !== outcome.databaseId ||
        receipt.vaultId !== outcome.vaultId ||
        receipt.operationId !== outcome.operationId ||
        receipt.operationType !== outcome.operationType ||
        receipt.requestDigest !== outcome.requestDigest ||
        receipt.actorPrincipalId !== outcome.actorPrincipalId ||
        receipt.actorDeviceId !== outcome.actorDeviceId ||
        receipt.priorHeadDigest !== outcome.priorHeadDigest ||
        receipt.committedHeadDigest !== outcome.committedHeadDigest ||
        receipt.finalizedMutationLinkDigest !== outcome.finalizedMutationLinkDigest ||
        receipt.outcomeDigest !== outcome.outcomeDigest ||
        canonicalJson(receipt.priorTuple) !== canonicalJson(outcome.priorTuple) ||
        canonicalJson(receipt.committedTuple) !== canonicalJson(outcome.committedTuple)
      ) {
        addIssue(
          context,
          'Signed mutation receipt must bind the exact durable outcome',
          ['signedMutationReceipt'],
        );
      }
    }
  });

export const operationDeduplicationTombstoneSchema = z
  .object({
    format: z.literal(COLLABORATIVE_OPERATION_TOMBSTONE_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    operationId: collaborationOperationIdSchema,
    operationType: mutationOperationTypeSchema,
    requestDigest: sha256DigestSchema,
    outcomeDigest: sha256DigestSchema,
    signedMutationReceipt: collaborationMutationReceiptSchema,
    createdAt: timestampSchema,
    retainedUntilVaultDestruction: z.literal(true),
  })
  .strict()
  .superRefine((tombstone, context) => {
    assertCanonicalBytes(tombstone, MAX_COLLABORATIVE_OPERATION_BYTES, context);
    const receipt = tombstone.signedMutationReceipt;
    if (
      receipt.databaseId !== tombstone.databaseId ||
      receipt.vaultId !== tombstone.vaultId ||
      receipt.operationId !== tombstone.operationId ||
      receipt.operationType !== tombstone.operationType ||
      receipt.requestDigest !== tombstone.requestDigest ||
      receipt.outcomeDigest !== tombstone.outcomeDigest
    ) {
      addIssue(context, 'Operation tombstone must retain the exact signed receipt', [
        'signedMutationReceipt',
      ]);
    }
  });

/**
 * Non-secret terminal payload committed by a destroy-vault mutation.
 *
 * The resulting terminal head is deliberately excluded: the digest of this
 * core is placed in the mutation commitment before that head is calculated.
 */
export const collaborationVaultDestructionCoreSchema = z
  .object({
    format: z.literal(COLLABORATIVE_VAULT_DESTRUCTION_CORE_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    operationId: collaborationOperationIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    authorityDelegationDigest: sha256DigestSchema,
    priorTuple: collaborationRevisionTupleSchema,
    priorHeadDigest: sha256DigestSchema,
    terminalTuple: collaborationRevisionTupleSchema,
    actionParametersDigest: sha256DigestSchema,
    actorPrincipalId: principalIdSchema,
    actorDeviceId: deviceIdSchema,
    destructionMode: z.literal('irreversible'),
    destroyedAt: timestampSchema,
  })
  .strict()
  .superRefine((core, context) => {
    assertCanonicalBytes(core, MAX_COLLABORATIVE_VAULT_DESTRUCTION_CORE_BYTES, context);
    if (
      core.priorTuple.authorityEpoch !== core.authorityEpoch ||
      core.terminalTuple.authorityEpoch !== core.authorityEpoch
    ) {
      addIssue(context, 'Vault destruction tuples must bind the authority epoch', [
        'authorityEpoch',
      ]);
    }
    assertExactVaultDestructionTuple(core.priorTuple, core.terminalTuple, context, [
      'terminalTuple',
    ]);
  });

export type CollaborationVaultDestructionCore = z.infer<
  typeof collaborationVaultDestructionCoreSchema
>;

/** Permanent terminal evidence that replaces one live collaborative vault. */
export const collaborationVaultDestructionTombstoneSchema = z
  .object({
    format: z.literal(COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    core: collaborationVaultDestructionCoreSchema,
    destroyedPayloadDigest: sha256DigestSchema,
    terminalHeadDigest: sha256DigestSchema,
    proofEntry: collaborationMutationProofEntrySchema,
    outcomeDigest: sha256DigestSchema,
    signedMutationReceipt: collaborationMutationReceiptSchema,
  })
  .strict()
  .superRefine((tombstone, context) => {
    assertCanonicalBytes(
      tombstone,
      MAX_COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_BYTES,
      context,
    );
    const { core, proofEntry, signedMutationReceipt: receipt } = tombstone;
    const { link } = proofEntry;
    const { commitment } = link;
    const transition = link.authorizationTransition;
    const transitionSigner = transition?.transitionSignature;
    const witness = proofEntry.authorizationWitness;
    const commitmentPriorTuple = {
      authorityEpoch: commitment.previousAuthorityEpoch,
      documentRevision: commitment.previousDocumentRevision,
      membershipRevision: commitment.previousMembershipRevision,
      policyRevision: commitment.previousPolicyRevision,
      keyEpoch: commitment.previousKeyEpoch,
      databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
      databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
      authorizationStateDigest: commitment.previousAuthorizationStateDigest,
    };
    const commitmentTerminalTuple = {
      authorityEpoch: commitment.authorityEpoch,
      documentRevision: commitment.documentRevision,
      membershipRevision: commitment.membershipRevision,
      policyRevision: commitment.policyRevision,
      keyEpoch: commitment.keyEpoch,
      databaseDeviceGeneration: commitment.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: commitment.databaseDeviceRegistryDigest,
      authorizationStateDigest: commitment.authorizationStateDigest,
    };

    if (
      tombstone.databaseId !== core.databaseId ||
      tombstone.vaultId !== core.vaultId ||
      link.databaseId !== core.databaseId ||
      link.vaultId !== core.vaultId ||
      link.authorityDelegationDigest !== core.authorityDelegationDigest
    ) {
      addIssue(context, 'Vault destruction tombstone scope is inconsistent', ['core']);
    }
    if (
      commitment.operationType !== 'destroy-vault' ||
      commitment.operationId !== core.operationId ||
      commitment.previousHeadDigest !== core.priorHeadDigest ||
      commitment.encryptedPayloadDigest !== tombstone.destroyedPayloadDigest ||
      commitment.writerPrincipalId !== core.actorPrincipalId ||
      commitment.writerDeviceId !== core.actorDeviceId ||
      commitment.timestamp !== core.destroyedAt ||
      canonicalJson(commitmentPriorTuple) !== canonicalJson(core.priorTuple) ||
      canonicalJson(commitmentTerminalTuple) !== canonicalJson(core.terminalTuple)
    ) {
      addIssue(
        context,
        'Vault destruction core must bind the exact terminal mutation commitment',
        ['proofEntry', 'link', 'commitment'],
      );
    }
    if (
      link.resultingHeadDigest !== tombstone.terminalHeadDigest ||
      link.writerSignature.writerPrincipalId !== core.actorPrincipalId ||
      link.writerSignature.writerDeviceId !== core.actorDeviceId ||
      !isAtOrAfter(link.finalizedAt, core.destroyedAt)
    ) {
      addIssue(context, 'Vault destruction terminal link is inconsistent', [
        'proofEntry',
        'link',
      ]);
    }
    if (
      transitionSigner?.signerKind !== 'owner-device' ||
      transitionSigner.signerPrincipalId !== core.actorPrincipalId ||
      transitionSigner.signerDeviceId !== core.actorDeviceId
    ) {
      addIssue(
        context,
        'Vault destruction requires the actor owner-device authorization transition',
        ['proofEntry', 'link', 'authorizationTransition'],
      );
    }
    if (receipt.finalizedMutationLinkDigest !== witness?.finalizedMutationLinkDigest) {
      addIssue(
        context,
        'Vault destruction receipt must bind the retained administrative proof link',
        ['signedMutationReceipt', 'finalizedMutationLinkDigest'],
      );
    }
    if (
      receipt.databaseId !== core.databaseId ||
      receipt.vaultId !== core.vaultId ||
      receipt.operationId !== core.operationId ||
      receipt.operationType !== 'destroy-vault' ||
      receipt.requestDigest !== commitment.requestDigest ||
      receipt.actorPrincipalId !== core.actorPrincipalId ||
      receipt.actorDeviceId !== core.actorDeviceId ||
      receipt.priorHeadDigest !== core.priorHeadDigest ||
      receipt.committedHeadDigest !== tombstone.terminalHeadDigest ||
      receipt.outcomeDigest !== tombstone.outcomeDigest ||
      canonicalJson(receipt.priorTuple) !== canonicalJson(core.priorTuple) ||
      canonicalJson(receipt.committedTuple) !== canonicalJson(core.terminalTuple) ||
      !isAtOrAfter(receipt.committedAt, link.finalizedAt)
    ) {
      addIssue(
        context,
        'Vault destruction tombstone must retain the exact committed signed receipt',
        ['signedMutationReceipt'],
      );
    }
  });

export type CollaborationVaultDestructionTombstone = z.infer<
  typeof collaborationVaultDestructionTombstoneSchema
>;

/** Minimal terminal rollback evidence stored in a recipient's protected file. */
export const recipientVaultDestructionAnchorSchema = z
  .object({
    format: z.literal(COLLABORATIVE_RECIPIENT_VAULT_DESTRUCTION_ANCHOR_FORMAT),
    protocolVersion: protocolVersionSchema,
    databaseId: databaseIdSchema,
    vaultId: vaultIdSchema,
    principalId: principalIdSchema,
    deviceId: deviceIdSchema,
    authorityEpoch: collaborationKeyEpochSchema,
    authorityDelegationDigest: sha256DigestSchema,
    operationId: collaborationOperationIdSchema,
    priorTuple: collaborationRevisionTupleSchema,
    priorHeadDigest: sha256DigestSchema,
    terminalTuple: collaborationRevisionTupleSchema,
    terminalHeadDigest: sha256DigestSchema,
    destroyedPayloadDigest: sha256DigestSchema,
    finalizedMutationLinkDigest: sha256DigestSchema,
    outcomeDigest: sha256DigestSchema,
    destroyedAt: timestampSchema,
  })
  .strict()
  .superRefine((anchor, context) => {
    assertCanonicalBytes(
      anchor,
      MAX_COLLABORATIVE_VAULT_DESTRUCTION_ANCHOR_BYTES,
      context,
    );
    if (
      anchor.priorTuple.authorityEpoch !== anchor.authorityEpoch ||
      anchor.terminalTuple.authorityEpoch !== anchor.authorityEpoch
    ) {
      addIssue(
        context,
        'Recipient destruction anchor tuples must bind the authority epoch',
        ['authorityEpoch'],
      );
    }
    assertExactVaultDestructionTuple(anchor.priorTuple, anchor.terminalTuple, context, [
      'terminalTuple',
    ]);
  });

export type RecipientVaultDestructionAnchor = z.infer<
  typeof recipientVaultDestructionAnchorSchema
>;

export const operationOutcomeSchema = durableOperationOutcomeSchema;
export const collaborationOperationOutcomeSchema = durableOperationOutcomeSchema;
export type DurableOperationOutcome = z.infer<typeof durableOperationOutcomeSchema>;
export type OperationOutcome = DurableOperationOutcome;
export type OperationDeduplicationTombstone = z.infer<
  typeof operationDeduplicationTombstoneSchema
>;
