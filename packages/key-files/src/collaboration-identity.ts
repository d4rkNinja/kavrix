import { randomBytes } from 'node:crypto';

import {
  COLLABORATION_DOMAINS,
  constantTimeEqual,
  createPassphraseDerivation,
  decodeBase64Url,
  derivePassphraseKek,
  encodeBase64Url,
  generateDeviceKeyPairs,
  generatePrincipalSigningKeyPair,
  openVaultRootKeyForDevice,
  requireByteLength,
  sealVaultRootKeyForDevice,
  signCanonicalCollaborationValue,
  verifyCanonicalCollaborationValue,
  zeroize,
  type DeviceEncryptionPrivateKey,
  type DeviceSigningPrivateKey,
  type PrincipalSigningPrivateKey,
} from '@kavrix/crypto';
import {
  COLLABORATION_PROTOCOL_VERSION,
  MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL,
  MAX_COLLABORATIVE_IDENTITY_BYTES,
  base64UrlSchema,
  canonicalJson,
  collaborationPublicKeySchema,
  deviceCertificateSchema,
  deviceIdSchema,
  passphraseDerivationSchema,
  principalIdSchema,
  principalLifecycleStateSchema,
  publicIdentityExportSchema,
  revisionSchema,
  timestampSchema,
  type DeviceCertificate,
  type DeviceId,
  type PrincipalId,
  type PublicIdentityExport,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';
import { z } from 'zod';

import {
  readProtectedJsonDocument,
  writeProtectedJsonDocument,
  type CanonicalJsonDocumentSchema,
} from './canonical-json-document.js';
import { PortableKeyFileError } from './errors.js';
import {
  readSecureFileWhileExclusive,
  replaceSecureFileWhileExclusive,
  withExclusiveSecureFile,
} from './filesystem.js';

const PROTECTED_IDENTITY_FORMAT = 'kavrix-collaboration-protected-identity';
const PRINCIPAL_ROOT_METADATA_FORMAT = 'kavrix-collaboration-principal-root-metadata';
const DEVICE_IDENTITY_METADATA_FORMAT = 'kavrix-collaboration-device-identity-metadata';
const FILE_VERSION = 1;
const PROTECTION = 'argon2id+xchacha20-poly1305-ietf';
const AAD_VERSION = 1;
const ROOT_FILE_AAD_DOMAIN = 'kavrix/collaboration/principal-root-identity-file/v1';
const DEVICE_FILE_AAD_DOMAIN = 'kavrix/collaboration/device-identity-file/v1';
const PRIVATE_KEY_PROOF_BYTES = 32;
const ED25519_PRIVATE_KEY_BYTES = 64;
const X25519_PRIVATE_KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const MAX_PASSPHRASE_BYTES = 1024;
const MAX_PRIVATE_PAYLOAD_BYTES = MAX_COLLABORATIVE_IDENTITY_BYTES + 1024;
const MAX_IDENTITY_FILE_BYTES = 128 * 1024;
const METADATA_LENGTH_BYTES = 4;
const TERMINAL_DEVICE_STATES = new Set([
  'replaced',
  'compromised',
  'revoked',
  'lost',
] as const);
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');

const nonceSchema = base64UrlSchema
  .length(32)
  .refine((value) => Buffer.from(value, 'base64url').byteLength === NONCE_BYTES, {
    error: 'Invalid protected identity nonce',
  });
const authenticationTagSchema = base64UrlSchema
  .length(22)
  .refine((value) => Buffer.from(value, 'base64url').byteLength === TAG_BYTES, {
    error: 'Invalid protected identity authentication tag',
  });
const ciphertextSchema = base64UrlSchema
  .max(Math.ceil((MAX_PRIVATE_PAYLOAD_BYTES * 4) / 3))
  .refine(
    (value) =>
      Buffer.from(value, 'base64url').byteLength > METADATA_LENGTH_BYTES &&
      Buffer.from(value, 'base64url').byteLength <= MAX_PRIVATE_PAYLOAD_BYTES,
    { error: 'Invalid protected identity ciphertext length' },
  );

const protectedPrincipalRootEnvelopeSchema = z
  .object({
    format: z.literal(PROTECTED_IDENTITY_FORMAT),
    version: z.literal(FILE_VERSION),
    kind: z.literal('principal-root'),
    principalId: principalIdSchema,
    rootSigningPublicKey: collaborationPublicKeySchema,
    protection: z.literal(PROTECTION),
    derivation: passphraseDerivationSchema,
    nonce: nonceSchema,
    aadVersion: z.literal(AAD_VERSION),
    ciphertext: ciphertextSchema,
    authenticationTag: authenticationTagSchema,
  })
  .strict();

const protectedDeviceEnvelopeSchema = z
  .object({
    format: z.literal(PROTECTED_IDENTITY_FORMAT),
    version: z.literal(FILE_VERSION),
    kind: z.literal('device'),
    principalId: principalIdSchema,
    deviceId: deviceIdSchema,
    signingPublicKey: collaborationPublicKeySchema,
    encryptionPublicKey: collaborationPublicKeySchema,
    protection: z.literal(PROTECTION),
    derivation: passphraseDerivationSchema,
    nonce: nonceSchema,
    aadVersion: z.literal(AAD_VERSION),
    ciphertext: ciphertextSchema,
    authenticationTag: authenticationTagSchema,
  })
  .strict();

const protectedIdentityEnvelopeSchema = z.discriminatedUnion('kind', [
  protectedPrincipalRootEnvelopeSchema,
  protectedDeviceEnvelopeSchema,
]);
type ProtectedIdentityEnvelope = z.infer<typeof protectedIdentityEnvelopeSchema>;
type ProtectedPrincipalRootEnvelope = z.infer<
  typeof protectedPrincipalRootEnvelopeSchema
>;
type ProtectedDeviceEnvelope = z.infer<typeof protectedDeviceEnvelopeSchema>;

const principalRootMetadataObjectSchema = z
  .object({
    format: z.literal(PRINCIPAL_ROOT_METADATA_FORMAT),
    version: z.literal(FILE_VERSION),
    protocolVersion: z.literal(COLLABORATION_PROTOCOL_VERSION),
    principalId: principalIdSchema,
    identityGeneration: revisionSchema,
    rootSigningPublicKey: collaborationPublicKeySchema,
    state: principalLifecycleStateSchema,
    devices: z
      .array(deviceCertificateSchema)
      .max(MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL),
    createdAt: timestampSchema,
    expiresAt: timestampSchema.optional(),
    revokedAt: timestampSchema.optional(),
  })
  .strict();

const principalRootMetadataSchema = principalRootMetadataObjectSchema.superRefine(
  (metadata, context) => {
    const deviceIds = new Set<string>();
    const signingKeys = new Set<string>();
    const encryptionKeys = new Set<string>();
    for (const [index, device] of metadata.devices.entries()) {
      if (deviceIds.has(device.deviceId)) {
        context.addIssue({
          code: 'custom',
          message: 'Duplicate device identity',
          path: ['devices', index, 'deviceId'],
        });
      }
      if (signingKeys.has(device.signingPublicKey)) {
        context.addIssue({
          code: 'custom',
          message: 'Duplicate device signing key',
          path: ['devices', index, 'signingPublicKey'],
        });
      }
      if (encryptionKeys.has(device.encryptionPublicKey)) {
        context.addIssue({
          code: 'custom',
          message: 'Duplicate device encryption key',
          path: ['devices', index, 'encryptionPublicKey'],
        });
      }
      deviceIds.add(device.deviceId);
      signingKeys.add(device.signingPublicKey);
      encryptionKeys.add(device.encryptionPublicKey);
      if (device.principalId !== metadata.principalId) {
        context.addIssue({
          code: 'custom',
          message: 'Device belongs to another principal',
          path: ['devices', index, 'principalId'],
        });
      }
      if (metadata.state !== 'active' && device.state === 'active') {
        context.addIssue({
          code: 'custom',
          message: 'Inactive principal has an active device',
          path: ['devices', index, 'state'],
        });
      }
    }
    if (
      metadata.expiresAt !== undefined &&
      Date.parse(metadata.expiresAt) <= Date.parse(metadata.createdAt)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Principal expiry must follow creation',
        path: ['expiresAt'],
      });
    }
    if (metadata.state === 'active' && metadata.revokedAt !== undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Active principal has a revocation timestamp',
        path: ['revokedAt'],
      });
    }
    if (metadata.state !== 'active' && metadata.revokedAt === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Inactive principal lacks a revocation timestamp',
        path: ['revokedAt'],
      });
    }
    if (
      Buffer.byteLength(canonicalJson(metadata), 'utf8') >
      MAX_COLLABORATIVE_IDENTITY_BYTES
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Principal root metadata exceeds its bound',
      });
    }
  },
);
type PrincipalRootMetadata = z.infer<typeof principalRootMetadataSchema>;

const deviceIdentityMetadataSchema = z
  .object({
    format: z.literal(DEVICE_IDENTITY_METADATA_FORMAT),
    version: z.literal(FILE_VERSION),
    certificate: deviceCertificateSchema,
  })
  .strict();
type DeviceIdentityMetadata = z.infer<typeof deviceIdentityMetadataSchema>;

const identityEnvelopeDocumentSchema: CanonicalJsonDocumentSchema<ProtectedIdentityEnvelope> =
  protectedIdentityEnvelopeSchema;
const publicIdentityDocumentSchema: CanonicalJsonDocumentSchema<PublicIdentityExport> =
  publicIdentityExportSchema;

type UnsignedDeviceCertificate = Omit<DeviceCertificate, 'rootSignature'>;
type UnsignedPublicIdentity = Omit<PublicIdentityExport, 'selfSignature'>;

/**
 * Audited self-reference projection: accept no signature field, restore one
 * fixed canonical placeholder, parse the complete canonical certificate, and
 * omit exactly rootSignature from the bytes covered by both sign and verify.
 */
const unsignedDeviceCertificateSchema = {
  parse(value: unknown): UnsignedDeviceCertificate {
    if (!isRecord(value) || 'rootSignature' in value) throw invalid();
    const parsed = deviceCertificateSchema.parse({
      ...value,
      rootSignature: PLACEHOLDER_SIGNATURE,
    });
    return omitDeviceRootSignature(parsed);
  },
};

/** Equivalent audited projection for a public identity's self-signature. */
const unsignedPublicIdentitySchema = {
  parse(value: unknown): UnsignedPublicIdentity {
    if (!isRecord(value) || 'selfSignature' in value) throw invalid();
    const parsed = publicIdentityExportSchema.parse({
      ...value,
      selfSignature: PLACEHOLDER_SIGNATURE,
    });
    return omitPublicIdentitySignature(parsed);
  },
};

export type PrincipalIdentityExpectation = Readonly<{
  principalId: PrincipalId;
  rootSigningPublicKey: string;
}>;

export type CreatedPrincipalRootIdentity = PrincipalIdentityExpectation &
  Readonly<{
    identityGeneration: ReturnType<typeof revisionSchema.parse>;
    createdAt: ReturnType<typeof timestampSchema.parse>;
    expiresAt?: ReturnType<typeof timestampSchema.parse>;
  }>;

export type OpenedPrincipalRootIdentity = PrincipalIdentityExpectation &
  Readonly<{
    identityGeneration: ReturnType<typeof revisionSchema.parse>;
    state: ReturnType<typeof principalLifecycleStateSchema.parse>;
    devices: readonly DeviceCertificate[];
    createdAt: ReturnType<typeof timestampSchema.parse>;
    expiresAt?: ReturnType<typeof timestampSchema.parse>;
    revokedAt?: ReturnType<typeof timestampSchema.parse>;
    /** Caller-owned secret bytes; zeroize immediately after the operation. */
    rootSigningPrivateKey: PrincipalSigningPrivateKey;
  }>;

export type OpenedDeviceIdentity = Readonly<{
  certificate: DeviceCertificate;
  /** Caller-owned secret bytes; zeroize immediately after the operation. */
  signingPrivateKey: DeviceSigningPrivateKey;
  /** Caller-owned secret bytes; zeroize immediately after the operation. */
  encryptionPrivateKey: DeviceEncryptionPrivateKey;
}>;

export type IdentityTimeOptions = Readonly<{
  at?: string;
  /**
   * Caller-pinned monotonic floor. Supplying it rejects an otherwise authentic
   * older protected root or public identity snapshot.
   */
  minimumIdentityGeneration?: ReturnType<typeof revisionSchema.parse>;
}>;

export type CreatePrincipalRootIdentityOptions = Readonly<{
  principalId: PrincipalId;
  passphrase: Uint8Array;
  createdAt?: string;
  expiresAt?: string;
}>;

export type CreateCertifiedDeviceIdentityOptions = Readonly<{
  expectedPrincipal: PrincipalIdentityExpectation;
  principalRootPassphrase: Uint8Array;
  devicePassphrase: Uint8Array;
  deviceId: DeviceId;
  createdAt?: string;
  expiresAt?: string;
  minimumIdentityGeneration?: ReturnType<typeof revisionSchema.parse>;
}>;

export type CreatedCertifiedDeviceIdentity = Readonly<{
  certificate: DeviceCertificate;
  publicIdentity: PublicIdentityExport;
}>;

export type DeviceRevocationState = Extract<
  DeviceCertificate['state'],
  'replaced' | 'compromised' | 'revoked' | 'lost'
>;

export type RevokeDeviceCredentialOptions = Readonly<{
  expectedPrincipal: PrincipalIdentityExpectation;
  passphrase: Uint8Array;
  deviceId: DeviceId;
  revokedAt?: string;
  state?: DeviceRevocationState;
  minimumIdentityGeneration?: ReturnType<typeof revisionSchema.parse>;
}>;

export type RevokedDeviceCredential = Readonly<{
  certificate: DeviceCertificate;
  identityGeneration: ReturnType<typeof revisionSchema.parse>;
  publicIdentity?: PublicIdentityExport;
}>;

export type VerifyDeviceCertificateOptions = Readonly<{ at?: string }>;

export type ExportPublicIdentityFileOptions = IdentityTimeOptions &
  Readonly<{ mode?: 'create' | 'replace' }>;

/** Creates a protected root-only identity file with no reusable device key. */
export async function createPrincipalRootIdentityFile(
  path: string,
  options: CreatePrincipalRootIdentityOptions,
): Promise<CreatedPrincipalRootIdentity> {
  const createdAt = parseTimestamp(options.createdAt ?? nowTimestamp());
  const principalId = principalIdSchema.parse(options.principalId);
  const expiresAt =
    options.expiresAt === undefined ? undefined : parseTimestamp(options.expiresAt);
  const passphrase = copyPassphrase(options.passphrase);
  let keyPair: Awaited<ReturnType<typeof generatePrincipalSigningKeyPair>> | undefined;
  let privatePayload: Uint8Array | undefined;
  try {
    keyPair = await generatePrincipalSigningKeyPair();
    const metadata = principalRootMetadataSchema.parse({
      format: PRINCIPAL_ROOT_METADATA_FORMAT,
      version: FILE_VERSION,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      principalId,
      identityGeneration: revisionSchema.parse(1),
      rootSigningPublicKey: keyPair.publicKeyBase64,
      state: 'active',
      devices: [],
      createdAt,
      ...(expiresAt === undefined ? {} : { expiresAt }),
    });
    await assertPrincipalRootKeyPair(metadata, keyPair.privateKey);
    privatePayload = serializePrivatePayload(metadata, [keyPair.privateKey]);
    const envelope = await protectPrincipalRootPayload(
      metadata,
      privatePayload,
      passphrase,
    );
    await writeProtectedJsonDocument(path, envelope, 'create', {
      schema: identityEnvelopeDocumentSchema,
      maximumBytes: MAX_IDENTITY_FILE_BYTES,
    });
    return {
      principalId: metadata.principalId,
      rootSigningPublicKey: metadata.rootSigningPublicKey,
      identityGeneration: metadata.identityGeneration,
      createdAt: metadata.createdAt,
      ...(metadata.expiresAt === undefined ? {} : { expiresAt: metadata.expiresAt }),
    };
  } catch (error) {
    throw mapCreateError(error);
  } finally {
    zeroize(privatePayload);
    zeroize(keyPair?.privateKey);
    zeroize(keyPair?.publicKey);
    zeroize(passphrase);
  }
}

/** Opens and verifies a root identity against an explicit pinned expectation. */
export async function openPrincipalRootIdentityFile(
  path: string,
  passphraseInput: Uint8Array,
  expectedInput: PrincipalIdentityExpectation,
  options: IdentityTimeOptions = {},
): Promise<OpenedPrincipalRootIdentity> {
  const passphrase = copyPassphrase(passphraseInput);
  try {
    const envelope = await readIdentityEnvelope(path);
    return await openPrincipalRootEnvelope(
      envelope,
      passphrase,
      parseExpectation(expectedInput),
      parseEvaluationTime(options.at),
      parseMinimumIdentityGeneration(options.minimumIdentityGeneration),
    );
  } catch {
    throw invalid();
  } finally {
    zeroize(passphrase);
  }
}

/** Reprotects the unchanged root metadata and private key with a new passphrase. */
export async function rewrapPrincipalRootIdentityFile(
  path: string,
  oldPassphraseInput: Uint8Array,
  newPassphraseInput: Uint8Array,
  expectedInput: PrincipalIdentityExpectation,
  options: IdentityTimeOptions = {},
): Promise<void> {
  validatePassphraseInput(oldPassphraseInput);
  validatePassphraseInput(newPassphraseInput);
  const oldPassphrase = copyPassphrase(oldPassphraseInput);
  const newPassphrase = copyPassphrase(newPassphraseInput);
  const expected = parseExpectation(expectedInput);
  const evaluationTime = parseEvaluationTime(options.at);
  const minimumIdentityGeneration = parseMinimumIdentityGeneration(
    options.minimumIdentityGeneration,
  );
  let opened: OpenedPrincipalRootIdentity | undefined;
  let privatePayload: Uint8Array | undefined;
  try {
    await withExclusiveSecureFile(path, MAX_IDENTITY_FILE_BYTES, async (lock) => {
      const bytes = await readSecureFileWhileExclusive(lock);
      try {
        const envelope = parseCanonicalEnvelopeBytes(bytes);
        opened = await openPrincipalRootEnvelope(
          envelope,
          oldPassphrase,
          expected,
          evaluationTime,
          minimumIdentityGeneration,
        );
        const metadata = rootMetadataFromOpened(opened);
        privatePayload = serializePrivatePayload(metadata, [
          opened.rootSigningPrivateKey,
        ]);
        const replacement = await protectPrincipalRootPayload(
          metadata,
          privatePayload,
          newPassphrase,
        );
        const serialized = serializeCanonicalEnvelope(replacement);
        try {
          await replaceSecureFileWhileExclusive(lock, serialized);
        } finally {
          zeroize(serialized);
        }
      } finally {
        zeroize(bytes);
      }
    });
  } catch {
    throw invalid();
  } finally {
    zeroize(privatePayload);
    zeroize(opened?.rootSigningPrivateKey);
    zeroize(oldPassphrase);
    zeroize(newPassphrase);
  }
}

/**
 * Generates one independently protected device key, root-certifies it, then
 * records the certificate in the protected root identity.
 */
export async function createCertifiedDeviceIdentityFile(
  principalRootPath: string,
  deviceIdentityPath: string,
  options: CreateCertifiedDeviceIdentityOptions,
): Promise<CreatedCertifiedDeviceIdentity> {
  const expected = parseExpectation(options.expectedPrincipal);
  const requestedCreatedAt =
    options.createdAt === undefined ? undefined : parseTimestamp(options.createdAt);
  const evaluationTime = requestedCreatedAt ?? parseTimestamp(nowTimestamp());
  const deviceId = deviceIdSchema.parse(options.deviceId);
  const expiresAt =
    options.expiresAt === undefined ? undefined : parseTimestamp(options.expiresAt);
  const minimumIdentityGeneration = parseMinimumIdentityGeneration(
    options.minimumIdentityGeneration,
  );
  validatePassphraseInput(options.principalRootPassphrase);
  validatePassphraseInput(options.devicePassphrase);
  const rootPassphrase = copyPassphrase(options.principalRootPassphrase);
  const devicePassphrase = copyPassphrase(options.devicePassphrase);
  let root: OpenedPrincipalRootIdentity | undefined;
  let deviceKeys: Awaited<ReturnType<typeof generateDeviceKeyPairs>> | undefined;
  let devicePayload: Uint8Array | undefined;
  let rootPayload: Uint8Array | undefined;
  try {
    return await withExclusiveSecureFile(
      principalRootPath,
      MAX_IDENTITY_FILE_BYTES,
      async (lock) => {
        const rootBytes = await readSecureFileWhileExclusive(lock);
        try {
          const rootEnvelope = parseCanonicalEnvelopeBytes(rootBytes);
          root = await openPrincipalRootEnvelope(
            rootEnvelope,
            rootPassphrase,
            expected,
            evaluationTime,
            minimumIdentityGeneration,
          );
        } finally {
          zeroize(rootBytes);
        }
        const currentCertificate = root.devices.find(
          (device) => device.deviceId === deviceId,
        );
        let existingEnvelope = await readIdentityEnvelopeIfPresent(deviceIdentityPath);
        let certificate: DeviceCertificate;
        if (existingEnvelope !== null) {
          certificate = await recoverPublishedDeviceCertificate(
            existingEnvelope,
            devicePassphrase,
            expected,
            deviceId,
            requestedCreatedAt,
            expiresAt,
            evaluationTime,
          );
        } else {
          if (currentCertificate !== undefined) throw invalid();
          if (root.devices.length >= MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL) {
            throw invalid();
          }

          deviceKeys = await generateDeviceKeyPairs();
          certificate = await createDeviceCertificate(root, {
            deviceId,
            signingPublicKey: deviceKeys.signing.publicKeyBase64,
            encryptionPublicKey: deviceKeys.encryption.publicKeyBase64,
            createdAt: evaluationTime,
            ...(expiresAt === undefined ? {} : { expiresAt }),
          });
          const deviceMetadata = deviceIdentityMetadataSchema.parse({
            format: DEVICE_IDENTITY_METADATA_FORMAT,
            version: FILE_VERSION,
            certificate,
          });
          devicePayload = serializePrivatePayload(deviceMetadata, [
            deviceKeys.signing.privateKey,
            deviceKeys.encryption.privateKey,
          ]);
          const deviceEnvelope = await protectDevicePayload(
            deviceMetadata,
            devicePayload,
            devicePassphrase,
          );
          try {
            await writeProtectedJsonDocument(
              deviceIdentityPath,
              deviceEnvelope,
              'create',
              {
                schema: identityEnvelopeDocumentSchema,
                maximumBytes: MAX_IDENTITY_FILE_BYTES,
              },
            );
          } catch (error) {
            if (
              !(error instanceof PortableKeyFileError) ||
              error.code !== 'KEY_FILE_ALREADY_EXISTS'
            ) {
              throw error;
            }
            existingEnvelope = await readIdentityEnvelope(deviceIdentityPath);
            certificate = await recoverPublishedDeviceCertificate(
              existingEnvelope,
              devicePassphrase,
              expected,
              deviceId,
              requestedCreatedAt,
              expiresAt,
              evaluationTime,
            );
          }
        }

        if (currentCertificate !== undefined) {
          if (canonicalJson(currentCertificate) !== canonicalJson(certificate)) {
            throw invalid();
          }
          const currentMetadata = rootMetadataFromOpened(root);
          return {
            certificate,
            publicIdentity: await createPublicIdentity(
              currentMetadata,
              root.rootSigningPrivateKey,
              evaluationTime,
            ),
          };
        }
        if (root.devices.length >= MAX_COLLABORATIVE_DEVICES_PER_PRINCIPAL) {
          throw invalid();
        }

        const nextMetadata = principalRootMetadataSchema.parse({
          ...rootMetadataFromOpened(root),
          identityGeneration: incrementRevision(root.identityGeneration),
          devices: [...root.devices, certificate],
        });
        rootPayload = serializePrivatePayload(nextMetadata, [
          root.rootSigningPrivateKey,
        ]);
        const nextRootEnvelope = await protectPrincipalRootPayload(
          nextMetadata,
          rootPayload,
          rootPassphrase,
        );
        const serializedRoot = serializeCanonicalEnvelope(nextRootEnvelope);
        try {
          await replaceSecureFileWhileExclusive(lock, serializedRoot);
        } finally {
          zeroize(serializedRoot);
        }
        const publicIdentity = await createPublicIdentity(
          nextMetadata,
          root.rootSigningPrivateKey,
          evaluationTime,
        );
        return { certificate, publicIdentity };
      },
    );
  } catch (error) {
    throw mapCreateError(error);
  } finally {
    zeroize(rootPayload);
    zeroize(devicePayload);
    zeroize(deviceKeys?.signing.privateKey);
    zeroize(deviceKeys?.signing.publicKey);
    zeroize(deviceKeys?.encryption.privateKey);
    zeroize(deviceKeys?.encryption.publicKey);
    zeroize(root?.rootSigningPrivateKey);
    zeroize(rootPassphrase);
    zeroize(devicePassphrase);
  }
}

/** Opens a device only when it remains active in the current trusted identity. */
export async function openDeviceIdentityFile(
  path: string,
  passphraseInput: Uint8Array,
  currentIdentityInput: PublicIdentityExport,
  expectedPrincipalInput: PrincipalIdentityExpectation,
  options: IdentityTimeOptions = {},
): Promise<OpenedDeviceIdentity> {
  const passphrase = copyPassphrase(passphraseInput);
  try {
    const evaluationTime = parseEvaluationTime(options.at);
    const minimumIdentityGeneration = parseMinimumIdentityGeneration(
      options.minimumIdentityGeneration,
    );
    const expected = parseExpectation(expectedPrincipalInput);
    const currentIdentity = await verifyPublicIdentityExport(
      currentIdentityInput,
      expected,
      {
        at: evaluationTime,
        ...(minimumIdentityGeneration === undefined
          ? {}
          : { minimumIdentityGeneration }),
      },
    );
    const envelope = await readIdentityEnvelope(path);
    if (envelope.kind !== 'device') throw invalid();
    const currentCertificate = currentIdentity.devices.find(
      (device) => device.deviceId === envelope.deviceId,
    );
    if (currentCertificate === undefined) throw invalid();
    return await openDeviceEnvelope(
      envelope,
      passphrase,
      currentCertificate,
      expected,
      evaluationTime,
    );
  } catch {
    throw invalid();
  } finally {
    zeroize(passphrase);
  }
}

/** Reprotects unchanged device private keys after verifying current authorization. */
export async function rewrapDeviceIdentityFile(
  path: string,
  oldPassphraseInput: Uint8Array,
  newPassphraseInput: Uint8Array,
  currentIdentityInput: PublicIdentityExport,
  expectedPrincipalInput: PrincipalIdentityExpectation,
  options: IdentityTimeOptions = {},
): Promise<void> {
  validatePassphraseInput(oldPassphraseInput);
  validatePassphraseInput(newPassphraseInput);
  const oldPassphrase = copyPassphrase(oldPassphraseInput);
  const newPassphrase = copyPassphrase(newPassphraseInput);
  const expected = parseExpectation(expectedPrincipalInput);
  const evaluationTime = parseEvaluationTime(options.at);
  const minimumIdentityGeneration = parseMinimumIdentityGeneration(
    options.minimumIdentityGeneration,
  );
  let opened: OpenedDeviceIdentity | undefined;
  let privatePayload: Uint8Array | undefined;
  try {
    const currentIdentity = await verifyPublicIdentityExport(
      currentIdentityInput,
      expected,
      {
        at: evaluationTime,
        ...(minimumIdentityGeneration === undefined
          ? {}
          : { minimumIdentityGeneration }),
      },
    );
    await withExclusiveSecureFile(path, MAX_IDENTITY_FILE_BYTES, async (lock) => {
      const bytes = await readSecureFileWhileExclusive(lock);
      try {
        const envelope = parseCanonicalEnvelopeBytes(bytes);
        if (envelope.kind !== 'device') throw invalid();
        const currentCertificate = currentIdentity.devices.find(
          (device) => device.deviceId === envelope.deviceId,
        );
        if (currentCertificate === undefined) throw invalid();
        opened = await openDeviceEnvelope(
          envelope,
          oldPassphrase,
          currentCertificate,
          expected,
          evaluationTime,
        );
        const metadata = deviceIdentityMetadataSchema.parse({
          format: DEVICE_IDENTITY_METADATA_FORMAT,
          version: FILE_VERSION,
          certificate: opened.certificate,
        });
        privatePayload = serializePrivatePayload(metadata, [
          opened.signingPrivateKey,
          opened.encryptionPrivateKey,
        ]);
        const replacement = await protectDevicePayload(
          metadata,
          privatePayload,
          newPassphrase,
        );
        const serialized = serializeCanonicalEnvelope(replacement);
        try {
          await replaceSecureFileWhileExclusive(lock, serialized);
        } finally {
          zeroize(serialized);
        }
      } finally {
        zeroize(bytes);
      }
    });
  } catch {
    throw invalid();
  } finally {
    zeroize(privatePayload);
    zeroize(opened?.signingPrivateKey);
    zeroize(opened?.encryptionPrivateKey);
    zeroize(oldPassphrase);
    zeroize(newPassphrase);
  }
}

/** Creates the bounded public-only identity from the current protected root. */
export async function exportPrincipalPublicIdentity(
  principalRootPath: string,
  passphraseInput: Uint8Array,
  expectedPrincipalInput: PrincipalIdentityExpectation,
  options: IdentityTimeOptions = {},
): Promise<PublicIdentityExport> {
  const root = await openPrincipalRootIdentityFile(
    principalRootPath,
    passphraseInput,
    expectedPrincipalInput,
    options,
  );
  try {
    return await createPublicIdentity(
      rootMetadataFromOpened(root),
      root.rootSigningPrivateKey,
      parseEvaluationTime(options.at),
    );
  } catch {
    throw invalid();
  } finally {
    zeroize(root.rootSigningPrivateKey);
  }
}

/** Writes only the canonical public identity; no private field is representable. */
export async function exportPrincipalPublicIdentityFile(
  principalRootPath: string,
  publicIdentityPath: string,
  passphraseInput: Uint8Array,
  expectedPrincipalInput: PrincipalIdentityExpectation,
  options: ExportPublicIdentityFileOptions = {},
): Promise<PublicIdentityExport> {
  const identity = await exportPrincipalPublicIdentity(
    principalRootPath,
    passphraseInput,
    expectedPrincipalInput,
    options,
  );
  try {
    await writeProtectedJsonDocument(
      publicIdentityPath,
      identity,
      options.mode ?? 'create',
      {
        schema: publicIdentityDocumentSchema,
        maximumBytes: MAX_COLLABORATIVE_IDENTITY_BYTES,
      },
    );
    return identity;
  } catch (error) {
    throw mapCreateError(error);
  }
}

/** Reads a canonical public identity and validates its complete trust chain. */
export async function readAndVerifyPublicIdentityFile(
  path: string,
  expectedPrincipalInput: PrincipalIdentityExpectation,
  options: IdentityTimeOptions = {},
): Promise<PublicIdentityExport> {
  try {
    const identity = await readProtectedJsonDocument(path, {
      schema: publicIdentityDocumentSchema,
      maximumBytes: MAX_COLLABORATIVE_IDENTITY_BYTES,
    });
    return await verifyPublicIdentityExport(identity, expectedPrincipalInput, options);
  } catch {
    throw invalid();
  }
}

/** Verifies the public identity against a separately supplied principal/root pin. */
export async function verifyPublicIdentityExport(
  identityInput: PublicIdentityExport,
  expectedPrincipalInput: PrincipalIdentityExpectation,
  options: IdentityTimeOptions = {},
): Promise<PublicIdentityExport> {
  try {
    const identity = publicIdentityExportSchema.parse(identityInput);
    const expected = parseExpectation(expectedPrincipalInput);
    const evaluationTime = parseEvaluationTime(options.at);
    const minimumIdentityGeneration = parseMinimumIdentityGeneration(
      options.minimumIdentityGeneration,
    );
    assertIdentityExpectation(identity, expected);
    assertUsableInterval(identity.createdAt, identity.expiresAt, evaluationTime);
    const verified = await verifyCanonicalCollaborationValue(
      COLLABORATION_DOMAINS.publicIdentitySignature,
      omitPublicIdentitySignature(identity),
      unsignedPublicIdentitySchema,
      identity.selfSignature,
      expected.rootSigningPublicKey,
    );
    if (!verified) throw invalid();
    for (const certificate of identity.devices) {
      await verifyDeviceCertificate(certificate, expected, {
        at: evaluationTime,
      });
    }
    assertMinimumIdentityGeneration(
      identity.identityGeneration,
      minimumIdentityGeneration,
    );
    return publicIdentityExportSchema.parse(identity);
  } catch {
    throw invalid();
  }
}

/** Verifies a root-signed certificate against the expected principal and root. */
export async function verifyDeviceCertificate(
  certificateInput: DeviceCertificate,
  expectedPrincipalInput: PrincipalIdentityExpectation,
  options: VerifyDeviceCertificateOptions = {},
): Promise<DeviceCertificate> {
  try {
    const expected = parseExpectation(expectedPrincipalInput);
    const certificate = await verifyDeviceCertificateSignature(
      certificateInput,
      expected,
    );
    const evaluationTime = parseEvaluationTime(options.at);
    if (certificate.state !== 'active' || certificate.revokedAt !== undefined) {
      throw invalid();
    }
    assertUsableInterval(certificate.createdAt, certificate.expiresAt, evaluationTime);
    if (Date.parse(certificate.stateChangedAt) > Date.parse(evaluationTime)) {
      throw invalid();
    }
    return deviceCertificateSchema.parse(certificate);
  } catch {
    throw invalid();
  }
}

async function verifyDeviceCertificateSignature(
  certificateInput: DeviceCertificate,
  expected: PrincipalIdentityExpectation,
): Promise<DeviceCertificate> {
  const certificate = deviceCertificateSchema.parse(certificateInput);
  if (certificate.principalId !== expected.principalId) throw invalid();
  const verified = await verifyCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    omitDeviceRootSignature(certificate),
    unsignedDeviceCertificateSchema,
    certificate.rootSignature,
    expected.rootSigningPublicKey,
  );
  if (!verified) throw invalid();
  return certificate;
}

/** Root-signs a terminal certificate and removes the device from future exports. */
export async function revokeDeviceCredential(
  principalRootPath: string,
  options: RevokeDeviceCredentialOptions,
): Promise<RevokedDeviceCredential> {
  const expected = parseExpectation(options.expectedPrincipal);
  const revokedAt = parseTimestamp(options.revokedAt ?? nowTimestamp());
  const deviceId = deviceIdSchema.parse(options.deviceId);
  const terminalState = options.state ?? 'revoked';
  if (!TERMINAL_DEVICE_STATES.has(terminalState)) throw invalid();
  const passphrase = copyPassphrase(options.passphrase);
  const minimumIdentityGeneration = parseMinimumIdentityGeneration(
    options.minimumIdentityGeneration,
  );
  let root: OpenedPrincipalRootIdentity | undefined;
  let rootPayload: Uint8Array | undefined;
  try {
    return await withExclusiveSecureFile(
      principalRootPath,
      MAX_IDENTITY_FILE_BYTES,
      async (lock) => {
        const rootBytes = await readSecureFileWhileExclusive(lock);
        try {
          root = await openPrincipalRootEnvelope(
            parseCanonicalEnvelopeBytes(rootBytes),
            passphrase,
            expected,
            revokedAt,
            minimumIdentityGeneration,
          );
        } finally {
          zeroize(rootBytes);
        }
        const currentIndex = root.devices.findIndex(
          (certificate) => certificate.deviceId === deviceId,
        );
        const current = root.devices[currentIndex];
        if (current?.state !== 'active') throw invalid();
        if (Date.parse(revokedAt) < Date.parse(current.stateChangedAt)) throw invalid();
        const certificate = await signDeviceCertificate(
          {
            ...omitDeviceRootSignature(current),
            deviceGeneration: incrementRevision(current.deviceGeneration),
            state: terminalState,
            stateChangedAt: revokedAt,
            revokedAt,
          },
          root.rootSigningPrivateKey,
        );
        const devices = [...root.devices];
        devices[currentIndex] = certificate;
        const nextMetadata = principalRootMetadataSchema.parse({
          ...rootMetadataFromOpened(root),
          identityGeneration: incrementRevision(root.identityGeneration),
          devices,
        });
        rootPayload = serializePrivatePayload(nextMetadata, [
          root.rootSigningPrivateKey,
        ]);
        const replacement = await protectPrincipalRootPayload(
          nextMetadata,
          rootPayload,
          passphrase,
        );
        const serialized = serializeCanonicalEnvelope(replacement);
        try {
          await replaceSecureFileWhileExclusive(lock, serialized);
        } finally {
          zeroize(serialized);
        }
        const publicIdentity = await createPublicIdentityIfPossible(
          nextMetadata,
          root.rootSigningPrivateKey,
          revokedAt,
        );
        return {
          certificate,
          identityGeneration: nextMetadata.identityGeneration,
          ...(publicIdentity === undefined ? {} : { publicIdentity }),
        };
      },
    );
  } catch {
    throw invalid();
  } finally {
    zeroize(rootPayload);
    zeroize(root?.rootSigningPrivateKey);
    zeroize(passphrase);
  }
}

async function readIdentityEnvelope(path: string): Promise<ProtectedIdentityEnvelope> {
  return readProtectedJsonDocument(path, {
    schema: identityEnvelopeDocumentSchema,
    maximumBytes: MAX_IDENTITY_FILE_BYTES,
  });
}

async function readIdentityEnvelopeIfPresent(
  path: string,
): Promise<ProtectedIdentityEnvelope | null> {
  try {
    return await readIdentityEnvelope(path);
  } catch (error) {
    if (error instanceof PortableKeyFileError && error.code === 'KEY_FILE_NOT_FOUND') {
      return null;
    }
    throw invalid();
  }
}

async function openPrincipalRootEnvelope(
  envelopeInput: ProtectedIdentityEnvelope,
  passphrase: Uint8Array,
  expected: PrincipalIdentityExpectation,
  evaluationTime: string,
  minimumIdentityGeneration?: ReturnType<typeof revisionSchema.parse>,
): Promise<OpenedPrincipalRootIdentity> {
  if (envelopeInput.kind !== 'principal-root') throw invalid();
  const envelope = protectedPrincipalRootEnvelopeSchema.parse(envelopeInput);
  assertIdentityExpectation(envelope, expected);
  let plaintext: Uint8Array | undefined;
  let privateKey: Uint8Array | undefined;
  try {
    plaintext = await decryptProtectedPayload(envelope, passphrase);
    const parsed = parsePrivatePayload(plaintext, principalRootMetadataSchema, [
      ED25519_PRIVATE_KEY_BYTES,
    ]);
    privateKey = parsed.privateParts[0];
    if (privateKey === undefined) throw invalid();
    const metadata = parsed.metadata;
    assertIdentityExpectation(metadata, expected);
    if (
      metadata.principalId !== envelope.principalId ||
      metadata.rootSigningPublicKey !== envelope.rootSigningPublicKey
    ) {
      throw invalid();
    }
    assertPrincipalUsable(metadata, evaluationTime);
    await assertPrincipalRootKeyPair(metadata, privateKey);
    for (const certificate of metadata.devices) {
      await verifyDeviceCertificateSignature(certificate, expected);
    }
    assertMinimumIdentityGeneration(
      metadata.identityGeneration,
      minimumIdentityGeneration,
    );
    const result: OpenedPrincipalRootIdentity = {
      principalId: metadata.principalId,
      rootSigningPublicKey: metadata.rootSigningPublicKey,
      identityGeneration: metadata.identityGeneration,
      state: metadata.state,
      devices: metadata.devices,
      createdAt: metadata.createdAt,
      ...(metadata.expiresAt === undefined ? {} : { expiresAt: metadata.expiresAt }),
      ...(metadata.revokedAt === undefined ? {} : { revokedAt: metadata.revokedAt }),
      rootSigningPrivateKey: privateKey as PrincipalSigningPrivateKey,
    };
    privateKey = undefined;
    return result;
  } finally {
    zeroize(privateKey);
    zeroize(plaintext);
  }
}

async function openDeviceEnvelope(
  envelope: ProtectedDeviceEnvelope,
  passphrase: Uint8Array,
  currentCertificateInput: DeviceCertificate,
  expected: PrincipalIdentityExpectation,
  evaluationTime: string,
): Promise<OpenedDeviceIdentity> {
  const currentCertificate = await verifyDeviceCertificate(
    currentCertificateInput,
    expected,
    { at: evaluationTime },
  );
  const opened = await openEmbeddedDeviceEnvelope(
    envelope,
    passphrase,
    expected,
    evaluationTime,
  );
  if (canonicalJson(opened.certificate) !== canonicalJson(currentCertificate)) {
    zeroize(opened.signingPrivateKey);
    zeroize(opened.encryptionPrivateKey);
    throw invalid();
  }
  return opened;
}

async function openEmbeddedDeviceEnvelope(
  envelope: ProtectedDeviceEnvelope,
  passphrase: Uint8Array,
  expected: PrincipalIdentityExpectation,
  evaluationTime: string,
): Promise<OpenedDeviceIdentity> {
  let plaintext: Uint8Array | undefined;
  let signingPrivateKey: Uint8Array | undefined;
  let encryptionPrivateKey: Uint8Array | undefined;
  try {
    plaintext = await decryptProtectedPayload(envelope, passphrase);
    const parsed = parsePrivatePayload(plaintext, deviceIdentityMetadataSchema, [
      ED25519_PRIVATE_KEY_BYTES,
      X25519_PRIVATE_KEY_BYTES,
    ]);
    signingPrivateKey = parsed.privateParts[0];
    encryptionPrivateKey = parsed.privateParts[1];
    if (signingPrivateKey === undefined || encryptionPrivateKey === undefined) {
      throw invalid();
    }
    const certificate = await verifyDeviceCertificate(
      parsed.metadata.certificate,
      expected,
      { at: evaluationTime },
    );
    if (
      envelope.principalId !== certificate.principalId ||
      envelope.deviceId !== certificate.deviceId ||
      envelope.signingPublicKey !== certificate.signingPublicKey ||
      envelope.encryptionPublicKey !== certificate.encryptionPublicKey
    ) {
      throw invalid();
    }
    await assertDeviceSigningKeyPair(certificate, signingPrivateKey);
    await assertDeviceEncryptionKeyPair(certificate, encryptionPrivateKey);
    const result: OpenedDeviceIdentity = {
      certificate,
      signingPrivateKey: signingPrivateKey as DeviceSigningPrivateKey,
      encryptionPrivateKey: encryptionPrivateKey as DeviceEncryptionPrivateKey,
    };
    signingPrivateKey = undefined;
    encryptionPrivateKey = undefined;
    return result;
  } finally {
    zeroize(signingPrivateKey);
    zeroize(encryptionPrivateKey);
    zeroize(plaintext);
  }
}

async function recoverPublishedDeviceCertificate(
  envelopeInput: ProtectedIdentityEnvelope,
  passphrase: Uint8Array,
  expected: PrincipalIdentityExpectation,
  expectedDeviceId: DeviceId,
  expectedCreatedAt: string | undefined,
  expectedExpiresAt: string | undefined,
  evaluationTime: string,
): Promise<DeviceCertificate> {
  if (envelopeInput.kind !== 'device') throw invalid();
  let opened: OpenedDeviceIdentity | undefined;
  try {
    opened = await openEmbeddedDeviceEnvelope(
      envelopeInput,
      passphrase,
      expected,
      evaluationTime,
    );
    const certificate = opened.certificate;
    if (
      certificate.principalId !== expected.principalId ||
      certificate.deviceId !== expectedDeviceId ||
      certificate.deviceGeneration !== 1 ||
      certificate.state !== 'active' ||
      certificate.revokedAt !== undefined ||
      (expectedCreatedAt !== undefined &&
        certificate.createdAt !== expectedCreatedAt) ||
      certificate.stateChangedAt !== certificate.createdAt ||
      certificate.expiresAt !== expectedExpiresAt
    ) {
      throw invalid();
    }
    return deviceCertificateSchema.parse(certificate);
  } finally {
    zeroize(opened?.signingPrivateKey);
    zeroize(opened?.encryptionPrivateKey);
  }
}

async function createDeviceCertificate(
  root: OpenedPrincipalRootIdentity,
  input: Readonly<{
    deviceId: DeviceId;
    signingPublicKey: string;
    encryptionPublicKey: string;
    createdAt: string;
    expiresAt?: string;
  }>,
): Promise<DeviceCertificate> {
  return signDeviceCertificate(
    {
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      principalId: root.principalId,
      deviceId: input.deviceId,
      deviceGeneration: revisionSchema.parse(1),
      signingPublicKey: collaborationPublicKeySchema.parse(input.signingPublicKey),
      encryptionPublicKey: collaborationPublicKeySchema.parse(
        input.encryptionPublicKey,
      ),
      state: 'active',
      createdAt: parseTimestamp(input.createdAt),
      stateChangedAt: parseTimestamp(input.createdAt),
      ...(input.expiresAt === undefined
        ? {}
        : { expiresAt: parseTimestamp(input.expiresAt) }),
    },
    root.rootSigningPrivateKey,
  );
}

async function signDeviceCertificate(
  unsignedInput: UnsignedDeviceCertificate,
  rootPrivateKey: PrincipalSigningPrivateKey,
): Promise<DeviceCertificate> {
  const unsigned = unsignedDeviceCertificateSchema.parse(unsignedInput);
  const signature = await signCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    unsigned,
    unsignedDeviceCertificateSchema,
    rootPrivateKey,
  );
  return deviceCertificateSchema.parse({ ...unsigned, rootSignature: signature });
}

async function createPublicIdentity(
  metadata: PrincipalRootMetadata,
  rootPrivateKey: PrincipalSigningPrivateKey,
  evaluationTime: string,
): Promise<PublicIdentityExport> {
  assertPrincipalUsable(metadata, evaluationTime);
  const evaluated = Date.parse(evaluationTime);
  const activeDevices = metadata.devices.filter(
    (device) =>
      device.state === 'active' &&
      Date.parse(device.createdAt) <= evaluated &&
      Date.parse(device.stateChangedAt) <= evaluated &&
      (device.expiresAt === undefined || evaluated < Date.parse(device.expiresAt)),
  );
  if (activeDevices.length === 0) throw invalid();
  const unsigned = unsignedPublicIdentitySchema.parse({
    format: 'kavrix-collaborative-public-identity',
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    principalId: metadata.principalId,
    identityGeneration: metadata.identityGeneration,
    rootSigningPublicKey: metadata.rootSigningPublicKey,
    devices: activeDevices,
    createdAt: metadata.createdAt,
    ...(metadata.expiresAt === undefined ? {} : { expiresAt: metadata.expiresAt }),
  });
  const selfSignature = await signCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.publicIdentitySignature,
    unsigned,
    unsignedPublicIdentitySchema,
    rootPrivateKey,
  );
  const identity = publicIdentityExportSchema.parse({
    ...unsigned,
    selfSignature,
  });
  await verifyPublicIdentityExport(
    identity,
    {
      principalId: metadata.principalId,
      rootSigningPublicKey: metadata.rootSigningPublicKey,
    },
    { at: evaluationTime },
  );
  return identity;
}

async function createPublicIdentityIfPossible(
  metadata: PrincipalRootMetadata,
  rootPrivateKey: PrincipalSigningPrivateKey,
  evaluationTime: string,
): Promise<PublicIdentityExport | undefined> {
  const evaluated = Date.parse(evaluationTime);
  return metadata.devices.some(
    (device) =>
      device.state === 'active' &&
      Date.parse(device.createdAt) <= evaluated &&
      Date.parse(device.stateChangedAt) <= evaluated &&
      (device.expiresAt === undefined || evaluated < Date.parse(device.expiresAt)),
  )
    ? createPublicIdentity(metadata, rootPrivateKey, evaluationTime)
    : undefined;
}

async function assertPrincipalRootKeyPair(
  metadata: PrincipalRootMetadata,
  privateKey: Uint8Array,
): Promise<void> {
  requireByteLength(privateKey, ED25519_PRIVATE_KEY_BYTES, 'principal root key');
  const proof = await signCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.principalRootSignature,
    metadata,
    principalRootMetadataSchema,
    privateKey,
  );
  const verified = await verifyCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.principalRootSignature,
    metadata,
    principalRootMetadataSchema,
    proof,
    metadata.rootSigningPublicKey,
  );
  if (!verified) throw invalid();
}

async function assertDeviceSigningKeyPair(
  certificate: DeviceCertificate,
  privateKey: Uint8Array,
): Promise<void> {
  requireByteLength(privateKey, ED25519_PRIVATE_KEY_BYTES, 'device signing key');
  const unsigned = omitDeviceRootSignature(certificate);
  const proof = await signCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    unsigned,
    unsignedDeviceCertificateSchema,
    privateKey,
  );
  const verified = await verifyCanonicalCollaborationValue(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    unsigned,
    unsignedDeviceCertificateSchema,
    proof,
    certificate.signingPublicKey,
  );
  if (!verified) throw invalid();
}

async function assertDeviceEncryptionKeyPair(
  certificate: DeviceCertificate,
  privateKey: Uint8Array,
): Promise<void> {
  requireByteLength(privateKey, X25519_PRIVATE_KEY_BYTES, 'device encryption key');
  const challenge = randomBytes(PRIVATE_KEY_PROOF_BYTES);
  let opened: Uint8Array | undefined;
  try {
    const sealed = await sealVaultRootKeyForDevice(
      challenge,
      certificate.encryptionPublicKey,
    );
    opened = await openVaultRootKeyForDevice(
      sealed,
      certificate.encryptionPublicKey,
      privateKey,
    );
    if (!constantTimeEqual(challenge, opened)) throw invalid();
  } finally {
    zeroize(opened);
    zeroize(challenge);
  }
}

async function protectPrincipalRootPayload(
  metadata: PrincipalRootMetadata,
  privatePayload: Uint8Array,
  passphrase: Uint8Array,
): Promise<ProtectedPrincipalRootEnvelope> {
  return protectPayload(
    {
      kind: 'principal-root',
      principalId: metadata.principalId,
      rootSigningPublicKey: metadata.rootSigningPublicKey,
    },
    privatePayload,
    passphrase,
  );
}

async function protectDevicePayload(
  metadata: DeviceIdentityMetadata,
  privatePayload: Uint8Array,
  passphrase: Uint8Array,
): Promise<ProtectedDeviceEnvelope> {
  const certificate = metadata.certificate;
  return protectPayload(
    {
      kind: 'device',
      principalId: certificate.principalId,
      deviceId: certificate.deviceId,
      signingPublicKey: certificate.signingPublicKey,
      encryptionPublicKey: certificate.encryptionPublicKey,
    },
    privatePayload,
    passphrase,
  );
}

type PrincipalRootBinding = Readonly<{
  kind: 'principal-root';
  principalId: PrincipalId;
  rootSigningPublicKey: string;
}>;
type DeviceBinding = Readonly<{
  kind: 'device';
  principalId: PrincipalId;
  deviceId: DeviceId;
  signingPublicKey: string;
  encryptionPublicKey: string;
}>;

async function protectPayload(
  binding: PrincipalRootBinding,
  plaintext: Uint8Array,
  passphrase: Uint8Array,
): Promise<ProtectedPrincipalRootEnvelope>;
async function protectPayload(
  binding: DeviceBinding,
  plaintext: Uint8Array,
  passphrase: Uint8Array,
): Promise<ProtectedDeviceEnvelope>;
async function protectPayload(
  binding: PrincipalRootBinding | DeviceBinding,
  plaintext: Uint8Array,
  passphrase: Uint8Array,
): Promise<ProtectedPrincipalRootEnvelope | ProtectedDeviceEnvelope> {
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_PRIVATE_PAYLOAD_BYTES) {
    throw invalid();
  }
  const derivation = createPassphraseDerivation();
  let kek: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  try {
    kek = await derivePassphraseKek(passphrase, derivation);
    nonce = randomBytes(NONCE_BYTES);
    const header = protectedHeader(binding, derivation);
    aad = protectedAssociatedData(header);
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      plaintext,
      aad,
      null,
      nonce,
      kek,
    );
    ciphertext = encrypted.ciphertext;
    tag = encrypted.mac;
    return protectedIdentityEnvelopeSchema.parse({
      ...header,
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
      authenticationTag: encodeBase64Url(tag),
    });
  } finally {
    zeroize(tag);
    zeroize(ciphertext);
    zeroize(aad);
    zeroize(nonce);
    zeroize(kek);
  }
}

async function decryptProtectedPayload(
  envelope: ProtectedIdentityEnvelope,
  passphrase: Uint8Array,
): Promise<Uint8Array> {
  let kek: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    const parsed = protectedIdentityEnvelopeSchema.parse(envelope);
    kek = await derivePassphraseKek(passphrase, parsed.derivation);
    nonce = decodeBase64Url(parsed.nonce, { exactBytes: NONCE_BYTES });
    ciphertext = decodeBase64Url(parsed.ciphertext, {
      maximumBytes: MAX_PRIVATE_PAYLOAD_BYTES,
    });
    tag = decodeBase64Url(parsed.authenticationTag, { exactBytes: TAG_BYTES });
    aad = protectedAssociatedData(protectedHeaderFromEnvelope(parsed));
    await sodium.ready;
    plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
      null,
      ciphertext,
      tag,
      aad,
      nonce,
      kek,
    );
    if (
      plaintext.byteLength <= METADATA_LENGTH_BYTES ||
      plaintext.byteLength > MAX_PRIVATE_PAYLOAD_BYTES
    ) {
      throw invalid();
    }
    const result = plaintext;
    plaintext = undefined;
    return result;
  } catch {
    throw invalid();
  } finally {
    zeroize(plaintext);
    zeroize(tag);
    zeroize(ciphertext);
    zeroize(aad);
    zeroize(nonce);
    zeroize(kek);
  }
}

type ProtectedPrincipalRootHeader = Omit<
  ProtectedPrincipalRootEnvelope,
  'nonce' | 'ciphertext' | 'authenticationTag'
>;
type ProtectedDeviceHeader = Omit<
  ProtectedDeviceEnvelope,
  'nonce' | 'ciphertext' | 'authenticationTag'
>;
type ProtectedHeader = ProtectedPrincipalRootHeader | ProtectedDeviceHeader;

function protectedHeader(
  binding: PrincipalRootBinding | DeviceBinding,
  derivation: ReturnType<typeof passphraseDerivationSchema.parse>,
): ProtectedHeader {
  const common = {
    format: PROTECTED_IDENTITY_FORMAT,
    version: FILE_VERSION,
    protection: PROTECTION,
    derivation: passphraseDerivationSchema.parse(derivation),
    aadVersion: AAD_VERSION,
  } as const;
  return binding.kind === 'principal-root'
    ? {
        ...common,
        kind: binding.kind,
        principalId: principalIdSchema.parse(binding.principalId),
        rootSigningPublicKey: collaborationPublicKeySchema.parse(
          binding.rootSigningPublicKey,
        ),
      }
    : {
        ...common,
        kind: binding.kind,
        principalId: principalIdSchema.parse(binding.principalId),
        deviceId: deviceIdSchema.parse(binding.deviceId),
        signingPublicKey: collaborationPublicKeySchema.parse(binding.signingPublicKey),
        encryptionPublicKey: collaborationPublicKeySchema.parse(
          binding.encryptionPublicKey,
        ),
      };
}

function protectedHeaderFromEnvelope(
  envelope: ProtectedIdentityEnvelope,
): ProtectedHeader {
  return envelope.kind === 'principal-root'
    ? protectedHeader(
        {
          kind: envelope.kind,
          principalId: envelope.principalId,
          rootSigningPublicKey: envelope.rootSigningPublicKey,
        },
        envelope.derivation,
      )
    : protectedHeader(
        {
          kind: envelope.kind,
          principalId: envelope.principalId,
          deviceId: envelope.deviceId,
          signingPublicKey: envelope.signingPublicKey,
          encryptionPublicKey: envelope.encryptionPublicKey,
        },
        envelope.derivation,
      );
}

function protectedAssociatedData(header: ProtectedHeader): Uint8Array {
  return Buffer.from(
    canonicalJson({
      domain:
        header.kind === 'principal-root'
          ? ROOT_FILE_AAD_DOMAIN
          : DEVICE_FILE_AAD_DOMAIN,
      ...header,
    }),
    'utf8',
  );
}

function serializePrivatePayload(
  metadataInput: unknown,
  privateParts: readonly Uint8Array[],
): Uint8Array {
  const metadataBytes = Buffer.from(canonicalJson(metadataInput), 'utf8');
  const privateBytes = privateParts.reduce((total, part) => total + part.byteLength, 0);
  const payload = Buffer.alloc(
    METADATA_LENGTH_BYTES + metadataBytes.byteLength + privateBytes,
  );
  try {
    payload.writeUInt32BE(metadataBytes.byteLength, 0);
    payload.set(metadataBytes, METADATA_LENGTH_BYTES);
    let offset = METADATA_LENGTH_BYTES + metadataBytes.byteLength;
    for (const part of privateParts) {
      payload.set(part, offset);
      offset += part.byteLength;
    }
    if (payload.byteLength > MAX_PRIVATE_PAYLOAD_BYTES) throw invalid();
    return payload;
  } catch (error) {
    zeroize(payload);
    throw error;
  } finally {
    zeroize(metadataBytes);
  }
}

function parsePrivatePayload<T>(
  payload: Uint8Array,
  schema: CanonicalJsonDocumentSchema<T>,
  privatePartLengths: readonly number[],
): Readonly<{ metadata: T; privateParts: Uint8Array[] }> {
  const privateParts: Uint8Array[] = [];
  try {
    if (payload.byteLength < METADATA_LENGTH_BYTES) throw invalid();
    const view = Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
    const metadataLength = view.readUInt32BE(0);
    const privateLength = privatePartLengths.reduce(
      (total, length) => total + length,
      0,
    );
    if (
      metadataLength === 0 ||
      metadataLength > MAX_COLLABORATIVE_IDENTITY_BYTES ||
      payload.byteLength !== METADATA_LENGTH_BYTES + metadataLength + privateLength
    ) {
      throw invalid();
    }
    const metadataBytes = payload.subarray(
      METADATA_LENGTH_BYTES,
      METADATA_LENGTH_BYTES + metadataLength,
    );
    const metadataText = new TextDecoder('utf-8', { fatal: true }).decode(
      metadataBytes,
    );
    const metadata = schema.parse(JSON.parse(metadataText) as unknown);
    if (canonicalJson(metadata) !== metadataText) throw invalid();
    let offset = METADATA_LENGTH_BYTES + metadataLength;
    for (const length of privatePartLengths) {
      const next = Uint8Array.from(payload.subarray(offset, offset + length));
      requireByteLength(next, length, 'identity private key');
      privateParts.push(next);
      offset += length;
    }
    return { metadata, privateParts };
  } catch (error) {
    for (const part of privateParts) zeroize(part);
    throw error;
  }
}

function rootMetadataFromOpened(
  root: OpenedPrincipalRootIdentity,
): PrincipalRootMetadata {
  return principalRootMetadataSchema.parse({
    format: PRINCIPAL_ROOT_METADATA_FORMAT,
    version: FILE_VERSION,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    principalId: root.principalId,
    identityGeneration: root.identityGeneration,
    rootSigningPublicKey: root.rootSigningPublicKey,
    state: root.state,
    devices: root.devices,
    createdAt: root.createdAt,
    ...(root.expiresAt === undefined ? {} : { expiresAt: root.expiresAt }),
    ...(root.revokedAt === undefined ? {} : { revokedAt: root.revokedAt }),
  });
}

function omitDeviceRootSignature(
  certificateInput: DeviceCertificate,
): UnsignedDeviceCertificate {
  const certificate = deviceCertificateSchema.parse(certificateInput);
  const { rootSignature: _rootSignature, ...unsigned } = certificate;
  void _rootSignature;
  return unsigned;
}

function omitPublicIdentitySignature(
  identityInput: PublicIdentityExport,
): UnsignedPublicIdentity {
  const identity = publicIdentityExportSchema.parse(identityInput);
  const { selfSignature: _selfSignature, ...unsigned } = identity;
  void _selfSignature;
  return unsigned;
}

function parseCanonicalEnvelopeBytes(bytes: Uint8Array): ProtectedIdentityEnvelope {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const envelope = protectedIdentityEnvelopeSchema.parse(JSON.parse(text) as unknown);
    if (canonicalJson(envelope) !== text) throw invalid();
    return envelope;
  } catch {
    throw invalid();
  }
}

function serializeCanonicalEnvelope(envelope: ProtectedIdentityEnvelope): Uint8Array {
  const parsed = protectedIdentityEnvelopeSchema.parse(envelope);
  const bytes = Buffer.from(canonicalJson(parsed), 'utf8');
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_IDENTITY_FILE_BYTES) {
    zeroize(bytes);
    throw invalid();
  }
  return bytes;
}

function parseExpectation(
  expectation: PrincipalIdentityExpectation,
): PrincipalIdentityExpectation {
  try {
    return {
      principalId: principalIdSchema.parse(expectation.principalId),
      rootSigningPublicKey: collaborationPublicKeySchema.parse(
        expectation.rootSigningPublicKey,
      ),
    };
  } catch {
    throw invalid();
  }
}

function assertIdentityExpectation(
  value: Readonly<{ principalId: PrincipalId; rootSigningPublicKey: string }>,
  expected: PrincipalIdentityExpectation,
): void {
  if (
    value.principalId !== expected.principalId ||
    value.rootSigningPublicKey !== expected.rootSigningPublicKey
  ) {
    throw invalid();
  }
}

function assertPrincipalUsable(
  metadata: PrincipalRootMetadata,
  evaluationTime: string,
): void {
  if (metadata.state !== 'active' || metadata.revokedAt !== undefined) throw invalid();
  assertUsableInterval(metadata.createdAt, metadata.expiresAt, evaluationTime);
}

function assertUsableInterval(
  createdAt: string,
  expiresAt: string | undefined,
  evaluationTime: string,
): void {
  const evaluated = Date.parse(evaluationTime);
  if (evaluated < Date.parse(createdAt)) throw invalid();
  if (expiresAt !== undefined && evaluated >= Date.parse(expiresAt)) throw invalid();
}

function incrementRevision(
  revision: ReturnType<typeof revisionSchema.parse>,
): ReturnType<typeof revisionSchema.parse> {
  if (revision >= Number.MAX_SAFE_INTEGER) throw invalid();
  return revisionSchema.parse(revision + 1);
}

function parseMinimumIdentityGeneration(
  value: number | undefined,
): ReturnType<typeof revisionSchema.parse> | undefined {
  if (value === undefined) return undefined;
  try {
    return revisionSchema.parse(value);
  } catch {
    throw invalid();
  }
}

function assertMinimumIdentityGeneration(
  actual: ReturnType<typeof revisionSchema.parse>,
  minimum: ReturnType<typeof revisionSchema.parse> | undefined,
): void {
  if (minimum !== undefined && actual < minimum) throw invalid();
}

function parseEvaluationTime(value: string | undefined): string {
  return parseTimestamp(value ?? nowTimestamp());
}

function parseTimestamp(value: string): ReturnType<typeof timestampSchema.parse> {
  try {
    return timestampSchema.parse(value);
  } catch {
    throw invalid();
  }
}

function nowTimestamp(): string {
  return new Date().toISOString();
}

function copyPassphrase(value: Uint8Array): Uint8Array {
  validatePassphraseInput(value);
  return Uint8Array.from(value);
}

function validatePassphraseInput(value: Uint8Array): void {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength === 0 ||
    value.byteLength > MAX_PASSPHRASE_BYTES
  ) {
    throw invalid();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function mapCreateError(error: unknown): PortableKeyFileError {
  if (
    error instanceof PortableKeyFileError &&
    (error.code === 'KEY_FILE_ALREADY_EXISTS' || error.code === 'KEY_FILE_BUSY')
  ) {
    return error;
  }
  return invalid();
}

function invalid(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}
