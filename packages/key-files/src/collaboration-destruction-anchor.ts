import { createHmac, hkdfSync } from 'node:crypto';

import {
  COLLABORATIVE_RECIPIENT_VAULT_DESTRUCTION_ANCHOR_FORMAT,
  MAX_COLLABORATIVE_VAULT_DESTRUCTION_ANCHOR_BYTES,
  canonicalJson,
  collaborationVaultDestructionTombstoneSchema,
  recipientVaultDestructionAnchorSchema,
  type CollaborationVaultDestructionTombstone,
  type DatabaseId,
  type DeviceId,
  type PrincipalId,
  type RecipientVaultDestructionAnchor,
  type VaultId,
} from '@kavrix/schemas';
import {
  constantTimeEqual,
  computeFinalizedMutationLinkDigest,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from '@kavrix/crypto';
import { z } from 'zod';

import {
  ProtectedJsonDocumentError,
  readProtectedJsonDocument,
  writeProtectedJsonDocument,
  type CanonicalJsonDocumentSchema,
} from './canonical-json-document.js';
import { PortableKeyFileError } from './errors.js';

/** Stable suffix for a protected per-device terminal destruction sidecar. */
export const RECIPIENT_VAULT_DESTRUCTION_ANCHOR_SUFFIX =
  '.recipient-vault-destruction-anchor';

const VERSION = 1;
const DOMAIN = 'kavrix/collaborative-recipient-vault-destruction-anchor/v1';
const KDF_DOMAIN =
  'kavrix/collaborative-recipient-vault-destruction-anchor/hmac-key/v1';
const SECRET_BYTES = 32;
const TAG_BYTES = 32;
const KDF_SALT = new Uint8Array(32);
const MAX_FILE_BYTES = MAX_COLLABORATIVE_VAULT_DESTRUCTION_ANCHOR_BYTES + 1024;

const authenticationTagSchema = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/u);

const destructionAnchorEnvelopeSchema = recipientVaultDestructionAnchorSchema
  .extend({ authenticationTag: authenticationTagSchema })
  .strict();
type DestructionAnchorEnvelope = z.infer<typeof destructionAnchorEnvelopeSchema>;

const destructionAnchorDocumentSchema: CanonicalJsonDocumentSchema<DestructionAnchorEnvelope> =
  destructionAnchorEnvelopeSchema;

export type RecipientVaultDestructionAnchorScope = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  principalId: PrincipalId;
  deviceId: DeviceId;
}>;

/** Derives a deterministic non-secret sidecar path for one recipient device. */
export function recipientVaultDestructionAnchorPath(
  basePath: string,
  scope: RecipientVaultDestructionAnchorScope,
): string {
  assertPath(basePath);
  const parsed = parseScope(scope);
  return `${basePath}${RECIPIENT_VAULT_DESTRUCTION_ANCHOR_SUFFIX}.${parsed.databaseId}.${parsed.vaultId}.${parsed.principalId}.${parsed.deviceId}`;
}

/** Maps exact authenticated terminal evidence to a recipient-scoped anchor. */
export function recipientVaultDestructionAnchorFromTombstone(
  tombstoneInput: CollaborationVaultDestructionTombstone,
  scopeInput: RecipientVaultDestructionAnchorScope,
): RecipientVaultDestructionAnchor {
  try {
    const tombstone = collaborationVaultDestructionTombstoneSchema.parse(
      structuredClone(tombstoneInput),
    );
    const scope = parseScope(scopeInput);
    const core = tombstone.core;
    return normalizeAnchor({
      format: COLLABORATIVE_RECIPIENT_VAULT_DESTRUCTION_ANCHOR_FORMAT,
      protocolVersion: tombstone.protocolVersion,
      ...scope,
      authorityEpoch: core.authorityEpoch,
      authorityDelegationDigest: core.authorityDelegationDigest,
      operationId: core.operationId,
      priorTuple: core.priorTuple,
      priorHeadDigest: core.priorHeadDigest,
      terminalTuple: core.terminalTuple,
      terminalHeadDigest: tombstone.terminalHeadDigest,
      destroyedPayloadDigest: tombstone.destroyedPayloadDigest,
      finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
        tombstone.proofEntry.link,
      ),
      outcomeDigest: tombstone.outcomeDigest,
      destroyedAt: core.destroyedAt,
    });
  } catch (error) {
    throw mapAnchorError(error);
  }
}

/** Creates the terminal anchor without ever replacing an existing sidecar. */
export async function createRecipientVaultDestructionAnchor(
  path: string,
  deviceProtectionSecret: Uint8Array,
  anchorInput: RecipientVaultDestructionAnchor,
): Promise<void> {
  try {
    assertPath(path);
    requireDeviceProtectionSecret(deviceProtectionSecret);
    const anchor = normalizeAnchor(anchorInput);
    await writeProtectedJsonDocument(
      path,
      serializeAnchor(deviceProtectionSecret, anchor),
      'create',
      {
        schema: destructionAnchorDocumentSchema,
        maximumBytes: MAX_FILE_BYTES,
      },
    );
  } catch (error) {
    throw mapAnchorError(error);
  }
}

/**
 * Create-only replay helper. An existing sidecar is accepted only when its
 * authenticated canonical bytes describe the exact same terminal evidence.
 */
export async function createOrVerifyRecipientVaultDestructionAnchor(
  path: string,
  deviceProtectionSecret: Uint8Array,
  anchorInput: RecipientVaultDestructionAnchor,
): Promise<void> {
  const anchor = normalizeAnchor(anchorInput);
  try {
    await createRecipientVaultDestructionAnchor(path, deviceProtectionSecret, anchor);
    return;
  } catch {
    const observed = await readRecipientVaultDestructionAnchor(
      path,
      deviceProtectionSecret,
      scopeOf(anchor),
    );
    if (canonicalJson(observed) !== canonicalJson(anchor)) throw invalidAnchor();
  }
}

/** Reads and authenticates one terminal recipient anchor. */
export async function readRecipientVaultDestructionAnchor(
  path: string,
  deviceProtectionSecret: Uint8Array,
  expectedScope?: RecipientVaultDestructionAnchorScope,
): Promise<RecipientVaultDestructionAnchor> {
  let envelope: DestructionAnchorEnvelope;
  try {
    assertPath(path);
    requireDeviceProtectionSecret(deviceProtectionSecret);
    envelope = await readProtectedJsonDocument(path, {
      schema: destructionAnchorDocumentSchema,
      maximumBytes: MAX_FILE_BYTES,
    });
  } catch (error) {
    throw mapAnchorError(error);
  }
  try {
    const anchor = parseAuthenticatedEnvelope(deviceProtectionSecret, envelope);
    if (expectedScope !== undefined) assertScope(anchor, expectedScope);
    return anchor;
  } catch (error) {
    throw mapAnchorError(error);
  }
}

function serializeAnchor(
  secret: Uint8Array,
  anchor: RecipientVaultDestructionAnchor,
): DestructionAnchorEnvelope {
  let message: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  try {
    message = anchorMessage(anchor);
    tag = hmac(secret, anchor, message);
    return destructionAnchorEnvelopeSchema.parse({
      ...anchor,
      authenticationTag: encodeBase64Url(tag),
    });
  } finally {
    zeroize(message);
    zeroize(tag);
  }
}

function parseAuthenticatedEnvelope(
  secret: Uint8Array,
  envelopeInput: DestructionAnchorEnvelope,
): RecipientVaultDestructionAnchor {
  const envelope = destructionAnchorEnvelopeSchema.parse(envelopeInput);
  const { authenticationTag, ...anchorInput } = envelope;
  const anchor = normalizeAnchor(anchorInput);
  let message: Uint8Array | undefined;
  let supplied: Uint8Array | undefined;
  let expected: Uint8Array | undefined;
  try {
    message = anchorMessage(anchor);
    supplied = decodeBase64Url(authenticationTag, { exactBytes: TAG_BYTES });
    expected = hmac(secret, anchor, message);
    if (!constantTimeEqual(supplied, expected)) throw invalidAnchor();
    return anchor;
  } finally {
    zeroize(message);
    zeroize(supplied);
    zeroize(expected);
  }
}

function hmac(
  secret: Uint8Array,
  anchor: RecipientVaultDestructionAnchor,
  message: Uint8Array,
): Uint8Array {
  const key = deriveKey(secret, scopeOf(anchor));
  try {
    return Uint8Array.from(createHmac('sha256', key).update(message).digest());
  } finally {
    zeroize(key);
  }
}

function deriveKey(
  secret: Uint8Array,
  scope: RecipientVaultDestructionAnchorScope,
): Uint8Array {
  const info = Buffer.from(
    canonicalJson({ domain: KDF_DOMAIN, version: VERSION, ...scope }),
    'utf8',
  );
  try {
    return new Uint8Array(hkdfSync('sha256', secret, KDF_SALT, info, SECRET_BYTES));
  } finally {
    info.fill(0);
  }
}

function anchorMessage(anchor: RecipientVaultDestructionAnchor): Uint8Array {
  return Buffer.from(
    canonicalJson({ domain: DOMAIN, version: VERSION, ...anchor }),
    'utf8',
  );
}

function normalizeAnchor(
  input: RecipientVaultDestructionAnchor,
): RecipientVaultDestructionAnchor {
  try {
    return recipientVaultDestructionAnchorSchema.parse(structuredClone(input));
  } catch (error) {
    throw mapAnchorError(error);
  }
}

function parseScope(
  input: RecipientVaultDestructionAnchorScope,
): RecipientVaultDestructionAnchorScope {
  try {
    return z
      .object({
        databaseId: recipientVaultDestructionAnchorSchema.shape.databaseId,
        vaultId: recipientVaultDestructionAnchorSchema.shape.vaultId,
        principalId: recipientVaultDestructionAnchorSchema.shape.principalId,
        deviceId: recipientVaultDestructionAnchorSchema.shape.deviceId,
      })
      .strict()
      .parse(structuredClone(input));
  } catch {
    throw invalidAnchor();
  }
}

function scopeOf(
  anchor: RecipientVaultDestructionAnchor,
): RecipientVaultDestructionAnchorScope {
  return {
    databaseId: anchor.databaseId,
    vaultId: anchor.vaultId,
    principalId: anchor.principalId,
    deviceId: anchor.deviceId,
  };
}

function assertScope(
  anchor: RecipientVaultDestructionAnchor,
  expectedInput: RecipientVaultDestructionAnchorScope,
): void {
  const expected = parseScope(expectedInput);
  if (
    anchor.databaseId !== expected.databaseId ||
    anchor.vaultId !== expected.vaultId ||
    anchor.principalId !== expected.principalId ||
    anchor.deviceId !== expected.deviceId
  ) {
    throw invalidAnchor();
  }
}

function requireDeviceProtectionSecret(secret: Uint8Array): void {
  requireByteLength(secret, SECRET_BYTES, 'device protection secret');
}

function assertPath(path: string): void {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\u0000')) {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function mapAnchorError(error: unknown): PortableKeyFileError {
  if (error instanceof PortableKeyFileError) return error;
  if (error instanceof ProtectedJsonDocumentError) return invalidAnchor();
  return invalidAnchor();
}

function invalidAnchor(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}

export type { RecipientVaultDestructionAnchor } from '@kavrix/schemas';
