import { createHmac, hkdfSync } from 'node:crypto';

import {
  canonicalJson,
  collaborativeVaultDocumentSchema,
  recipientRollbackAnchorSchema,
  sha256DigestSchema,
  timestampSchema,
  type CollaborativeVaultDocument,
  type DatabaseId,
  type DeviceId,
  type PrincipalId,
  type RecipientRollbackAnchor,
  type Sha256Digest,
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
  transitionProtectedJsonDocument,
  writeProtectedJsonDocument,
  type CanonicalJsonDocumentSchema,
} from './canonical-json-document.js';
import { PortableKeyFileError } from './errors.js';

/** Stable suffix for the protected per-device recipient anchor sidecar. */
export const RECIPIENT_ROLLBACK_ANCHOR_SUFFIX = '.recipient-rollback-anchor';

const FORMAT = 'kavrix-collaborative-recipient-rollback-anchor';
const VERSION = 1;
const DOMAIN = 'kavrix/collaborative-recipient-rollback-anchor/v1';
const KDF_DOMAIN = 'kavrix/collaborative-recipient-rollback-anchor/hmac-key/v1';
const SECRET_BYTES = 32;
const TAG_BYTES = 32;
const MAX_FILE_BYTES = 16 * 1024;
const KDF_SALT = new Uint8Array(32);

const authenticationTagSchema = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/u);

const recipientRollbackAnchorEnvelopeSchema = recipientRollbackAnchorSchema
  .extend({ authenticationTag: authenticationTagSchema })
  .strict();
type RecipientRollbackAnchorEnvelope = z.infer<
  typeof recipientRollbackAnchorEnvelopeSchema
>;

const anchorDocumentSchema: CanonicalJsonDocumentSchema<
  z.infer<typeof recipientRollbackAnchorEnvelopeSchema>
> = recipientRollbackAnchorEnvelopeSchema;

export type RecipientRollbackAnchorScope = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  principalId: PrincipalId;
  deviceId: DeviceId;
}>;

export type RecipientRollbackAnchorVerificationOptions = Readonly<{
  /** Require this exact database/vault/principal/device binding. */
  expectedScope?: RecipientRollbackAnchorScope;
  /** Compare the authenticated anchor against an observed remote state. */
  observed?: RecipientRollbackAnchor;
  /**
   * A proof-chain result produced by the collaboration verifier. This is an
   * assertion boundary, not a verifier: callers must validate every signed
   * mutation link and authorization transition before passing this value.
   */
  chainVerification?: RecipientRollbackAnchorChainVerification;
}>;

/**
 * Exact endpoints of a proof chain that was verified by the caller. The
 * anchor module intentionally does not inspect remote links or signatures;
 * it only binds the caller's already-verified result to the two anchors.
 */
export type RecipientRollbackAnchorChainVerification = Readonly<{
  kind: 'verified-chain';
  from: RecipientRollbackAnchor;
  to: RecipientRollbackAnchor;
}>;

export type RecipientRollbackAnchorTransitionResult<Result> = Readonly<{
  nextAnchor: RecipientRollbackAnchor;
  result: Result;
}>;

/**
 * Derives the deterministic sidecar path. Supplying a scope appends the
 * canonical scope to make one base device file safe for multiple vaults.
 * The operation never includes secret material.
 */
export function recipientRollbackAnchorPath(
  basePath: string,
  scope: RecipientRollbackAnchorScope,
): string {
  assertPath(basePath);
  const parsedScope = parseScope(scope);
  return `${basePath}${RECIPIENT_ROLLBACK_ANCHOR_SUFFIX}.${parsedScope.databaseId}.${parsedScope.vaultId}.${parsedScope.principalId}.${parsedScope.deviceId}`;
}

/** Writes a canonical authenticated anchor through the secure-file boundary. */
async function writeRecipientRollbackAnchor(
  path: string,
  deviceProtectionSecret: Uint8Array,
  anchor: RecipientRollbackAnchor,
  mode: 'create' | 'replace',
): Promise<void> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const normalized = normalizeAnchor(anchor);
  try {
    const envelope = serializeAnchor(deviceProtectionSecret, normalized);
    await writeProtectedJsonDocument(path, envelope, mode, {
      schema: anchorDocumentSchema,
      maximumBytes: MAX_FILE_BYTES,
    });
  } catch (error) {
    throw mapAnchorError(error);
  }
}

/** Create-only convenience API for a first-use recipient anchor. */
export async function createRecipientRollbackAnchor(
  path: string,
  deviceProtectionSecret: Uint8Array,
  anchor: RecipientRollbackAnchor,
): Promise<void> {
  await writeRecipientRollbackAnchor(path, deviceProtectionSecret, anchor, 'create');
}

/** Reads and authenticates a protected recipient anchor. Missing is not a valid state. */
export async function readRecipientRollbackAnchor(
  path: string,
  deviceProtectionSecret: Uint8Array,
  options?: RecipientRollbackAnchorVerificationOptions,
): Promise<RecipientRollbackAnchor> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const parsedOptions = readOptions(options);
  let envelope: RecipientRollbackAnchorEnvelope;
  try {
    envelope = await readProtectedJsonDocument(path, {
      schema: anchorDocumentSchema,
      maximumBytes: MAX_FILE_BYTES,
    });
  } catch (error) {
    throw mapAnchorError(error);
  }

  try {
    const trusted = parseAuthenticatedEnvelope(deviceProtectionSecret, envelope);
    if (parsedOptions.expectedScope !== undefined) {
      assertScope(trusted, parsedOptions.expectedScope);
    }
    if (parsedOptions.observed !== undefined) {
      verifyRecipientRollbackAnchor(
        trusted,
        parsedOptions.observed,
        parsedOptions.expectedScope,
        parsedOptions.chainVerification,
      );
    }
    return trusted;
  } catch (error) {
    throw mapAnchorError(error);
  }
}

/**
 * Compares an authenticated local anchor with a newly observed state. Every
 * monotonic scalar is checked independently; when a scalar is unchanged, its
 * associated digest must be unchanged as well. `updatedAt` is intentionally
 * ignored and is never a rollback authority.
 */
export function verifyRecipientRollbackAnchor(
  trustedInput: RecipientRollbackAnchor,
  observedInput: RecipientRollbackAnchor,
  expectedScope?: RecipientRollbackAnchorScope,
  chainVerification?: RecipientRollbackAnchorChainVerification,
): void {
  try {
    const trusted = normalizeAnchor(trustedInput);
    const observed = normalizeAnchor(observedInput);
    if (expectedScope !== undefined) {
      assertScope(trusted, expectedScope);
      assertScope(observed, expectedScope);
    }
    assertScopeEqual(trusted, observed);

    // The authority delegation is immutable for this anchor scope. An epoch
    // or delegation change requires a new migration/anchor, never an
    // in-place remote update.
    assertExactPair(
      trusted.authorityEpoch,
      observed.authorityEpoch,
      trusted.authorityDelegationDigest,
      observed.authorityDelegationDigest,
    );
    assertMonotonic(
      trusted.databaseDeviceGeneration,
      observed.databaseDeviceGeneration,
      trusted.databaseDeviceRegistryDigest,
      observed.databaseDeviceRegistryDigest,
    );
    assertMonotonic(
      trusted.membershipRevision,
      observed.membershipRevision,
      trusted.membershipDigest,
      observed.membershipDigest,
    );
    assertMonotonic(
      trusted.policyRevision,
      observed.policyRevision,
      trusted.policyDigest,
      observed.policyDigest,
    );
    assertMonotonic(trusted.keyEpoch, observed.keyEpoch, undefined, undefined);
    assertMonotonic(
      trusted.documentRevision,
      observed.documentRevision,
      trusted.encryptedPayloadDigest,
      observed.encryptedPayloadDigest,
    );
    const authorizationStateAdvanced =
      observed.databaseDeviceGeneration > trusted.databaseDeviceGeneration ||
      observed.membershipRevision > trusted.membershipRevision ||
      observed.policyRevision > trusted.policyRevision ||
      observed.keyEpoch > trusted.keyEpoch;
    if (
      authorizationStateAdvanced &&
      observed.authorizationStateDigest === trusted.authorizationStateDigest
    ) {
      throw invalidAnchor();
    }
    if (
      !authorizationStateAdvanced &&
      observed.authorizationStateDigest !== trusted.authorizationStateDigest
    ) {
      throw invalidAnchor();
    }
    if (
      observed.documentRevision === trusted.documentRevision &&
      observed.finalizedMutationLinkDigest !== trusted.finalizedMutationLinkDigest
    ) {
      throw invalidAnchor();
    }
    if (
      observed.documentRevision === trusted.documentRevision &&
      observed.headDigest !== trusted.headDigest
    ) {
      throw invalidAnchor();
    }
    if (
      observed.documentRevision > trusted.documentRevision &&
      observed.headDigest === trusted.headDigest
    ) {
      throw invalidAnchor();
    }
    if (
      observed.documentRevision > trusted.documentRevision &&
      observed.finalizedMutationLinkDigest === trusted.finalizedMutationLinkDigest
    ) {
      throw invalidAnchor();
    }

    const databaseGenerationDelta =
      observed.databaseDeviceGeneration - trusted.databaseDeviceGeneration;
    const membershipDelta = observed.membershipRevision - trusted.membershipRevision;
    const policyDelta = observed.policyRevision - trusted.policyRevision;
    const keyDelta = observed.keyEpoch - trusted.keyEpoch;
    const documentDelta = observed.documentRevision - trusted.documentRevision;
    const hasUnprovedGap =
      databaseGenerationDelta > 1 ||
      membershipDelta > 1 ||
      policyDelta > 1 ||
      keyDelta > 1 ||
      documentDelta > 1;
    if (hasUnprovedGap && chainVerification === undefined) {
      throw invalidAnchor();
    }
    if (chainVerification !== undefined) {
      assertVerifiedChain(chainVerification, trusted, observed);
    }
  } catch (error) {
    throw mapAnchorError(error);
  }
}

/**
 * Runs verification, caller policy, and publication under the protected-file
 * lock. A stale concurrent writer cannot interleave between those steps.
 */
export async function transitionRecipientRollbackAnchor<Result>(
  path: string,
  deviceProtectionSecret: Uint8Array,
  observed: RecipientRollbackAnchor,
  callback: (
    trusted: RecipientRollbackAnchor,
  ) =>
    | RecipientRollbackAnchorTransitionResult<Result>
    | Promise<RecipientRollbackAnchorTransitionResult<Result>>,
  options: RecipientRollbackAnchorVerificationOptions = {},
): Promise<Result> {
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const normalizedObserved = normalizeAnchor(observed);
  const expectedScope = options.expectedScope ?? scopeOf(normalizedObserved);
  if (options.observed !== undefined) {
    verifyRecipientRollbackAnchor(
      normalizedObserved,
      options.observed,
      expectedScope,
      options.chainVerification,
    );
  }

  try {
    return await transitionProtectedJsonDocument(
      path,
      { schema: anchorDocumentSchema, maximumBytes: MAX_FILE_BYTES },
      async (currentEnvelope) => {
        const trusted = parseAuthenticatedEnvelope(
          deviceProtectionSecret,
          currentEnvelope,
        );
        assertScope(trusted, expectedScope);
        verifyRecipientRollbackAnchor(
          trusted,
          normalizedObserved,
          expectedScope,
          options.chainVerification,
        );
        const transition = await callback(trusted);
        const nextAnchor = normalizeAnchor(transition.nextAnchor);
        assertScope(nextAnchor, expectedScope);
        verifyRecipientRollbackAnchor(normalizedObserved, nextAnchor, expectedScope);
        return {
          document: serializeAnchor(deviceProtectionSecret, nextAnchor),
          result: transition.result,
        };
      },
    );
  } catch (error) {
    throw mapAnchorError(error);
  }
}

/**
 * Maps a complete authenticated collaborative document to anchor material.
 * Membership and policy digests may be supplied from the separately opened
 * manifest/policy; the document's encrypted payload digest is the default
 * document digest and remains opaque to this package.
 */
export function recipientRollbackAnchorFromCollaborativeVaultDocument(
  documentInput: CollaborativeVaultDocument,
  scope: RecipientRollbackAnchorScope,
  options: Readonly<{
    /** Logical membership-state digest computed after opening the manifest. */
    membershipDigest: Sha256Digest;
    /** Logical policy-state digest computed from the authenticated policy. */
    policyDigest: Sha256Digest;
    encryptedPayloadDigest?: Sha256Digest;
    finalizedMutationLinkDigest?: Sha256Digest;
    updatedAt?: string;
  }>,
): RecipientRollbackAnchor {
  const document = collaborativeVaultDocumentSchema.parse(documentInput);
  const parsedScope = parseScope(scope);
  const membershipDigest = sha256DigestSchema.parse(options.membershipDigest);
  const policyDigest = sha256DigestSchema.parse(options.policyDigest);
  const encryptedPayloadDigest = sha256DigestSchema.parse(
    options.encryptedPayloadDigest ?? document.encryptedPayloadDigest,
  );
  const finalizedMutationLinkDigest = sha256DigestSchema.parse(
    options.finalizedMutationLinkDigest ??
      computeFinalizedMutationLinkDigest(document.currentMutationLink),
  );
  const updatedAt = timestampSchema.parse(options.updatedAt ?? document.updatedAt);
  return normalizeAnchor({
    format: FORMAT,
    protocolVersion: document.protocolVersion,
    ...parsedScope,
    authorityEpoch: document.authorityEpoch,
    authorityDelegationDigest: document.authorityDelegationDigest,
    databaseDeviceGeneration: document.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: document.databaseDeviceRegistryDigest,
    membershipRevision: document.membershipRevision,
    membershipDigest,
    policyRevision: document.policyRevision,
    policyDigest,
    keyEpoch: document.keyEpoch,
    documentRevision: document.documentRevision,
    encryptedPayloadDigest,
    headDigest: document.headDigest,
    authorizationStateDigest: document.authorizationStateDigest,
    finalizedMutationLinkDigest,
    updatedAt,
  });
}

// Re-export the canonical digest implementation so journals and callers share
// the crypto package's schema validation and domain separation.
export { computeFinalizedMutationLinkDigest } from '@kavrix/crypto';

function serializeAnchor(
  secret: Uint8Array,
  anchor: RecipientRollbackAnchor,
): RecipientRollbackAnchorEnvelope {
  let message: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  try {
    message = anchorMessage(anchor);
    tag = hmac(secret, anchor, message);
    return recipientRollbackAnchorEnvelopeSchema.parse({
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
  envelope: RecipientRollbackAnchorEnvelope,
): RecipientRollbackAnchor {
  const parsed = recipientRollbackAnchorEnvelopeSchema.parse(envelope);
  const { authenticationTag, ...anchorInput } = parsed;
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
  anchor: RecipientRollbackAnchor,
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
  scope: RecipientRollbackAnchorScope,
): Uint8Array {
  const info = Buffer.from(
    canonicalJson({ domain: KDF_DOMAIN, version: VERSION, ...scope }),
    'utf8',
  );
  let derived: Uint8Array | undefined;
  try {
    derived = new Uint8Array(hkdfSync('sha256', secret, KDF_SALT, info, SECRET_BYTES));
    return derived;
  } finally {
    info.fill(0);
    // The returned key is deliberately not zeroized here; its caller owns it.
  }
}

function anchorMessage(anchor: RecipientRollbackAnchor): Uint8Array {
  return Buffer.from(
    canonicalJson({
      domain: DOMAIN,
      format: FORMAT,
      protocolVersion: anchor.protocolVersion,
      databaseId: anchor.databaseId,
      vaultId: anchor.vaultId,
      principalId: anchor.principalId,
      deviceId: anchor.deviceId,
      authorityEpoch: anchor.authorityEpoch,
      authorityDelegationDigest: anchor.authorityDelegationDigest,
      databaseDeviceGeneration: anchor.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: anchor.databaseDeviceRegistryDigest,
      membershipRevision: anchor.membershipRevision,
      membershipDigest: anchor.membershipDigest,
      policyRevision: anchor.policyRevision,
      policyDigest: anchor.policyDigest,
      keyEpoch: anchor.keyEpoch,
      documentRevision: anchor.documentRevision,
      encryptedPayloadDigest: anchor.encryptedPayloadDigest,
      headDigest: anchor.headDigest,
      authorizationStateDigest: anchor.authorizationStateDigest,
      finalizedMutationLinkDigest: anchor.finalizedMutationLinkDigest,
      updatedAt: anchor.updatedAt,
    }),
    'utf8',
  );
}

function normalizeAnchor(input: RecipientRollbackAnchor): RecipientRollbackAnchor {
  try {
    const parsed = recipientRollbackAnchorSchema.parse(structuredClone(input));
    return parsed;
  } catch (error) {
    throw mapAnchorError(error);
  }
}

function parseScope(input: RecipientRollbackAnchorScope): RecipientRollbackAnchorScope {
  try {
    const parsed = z
      .object({
        databaseId: recipientRollbackAnchorSchema.shape.databaseId,
        vaultId: recipientRollbackAnchorSchema.shape.vaultId,
        principalId: recipientRollbackAnchorSchema.shape.principalId,
        deviceId: recipientRollbackAnchorSchema.shape.deviceId,
      })
      .strict()
      .parse(structuredClone(input));
    return parsed;
  } catch {
    throw invalidAnchor();
  }
}

function scopeOf(anchor: RecipientRollbackAnchor): RecipientRollbackAnchorScope {
  return {
    databaseId: anchor.databaseId,
    vaultId: anchor.vaultId,
    principalId: anchor.principalId,
    deviceId: anchor.deviceId,
  };
}

function assertScope(
  anchor: RecipientRollbackAnchor,
  expected: RecipientRollbackAnchorScope,
): void {
  const scope = parseScope(expected);
  if (
    anchor.databaseId !== scope.databaseId ||
    anchor.vaultId !== scope.vaultId ||
    anchor.principalId !== scope.principalId ||
    anchor.deviceId !== scope.deviceId
  ) {
    throw invalidAnchor();
  }
}

function assertScopeEqual(
  left: RecipientRollbackAnchor,
  right: RecipientRollbackAnchor,
): void {
  if (
    left.databaseId !== right.databaseId ||
    left.vaultId !== right.vaultId ||
    left.principalId !== right.principalId ||
    left.deviceId !== right.deviceId
  ) {
    throw invalidAnchor();
  }
}

function assertMonotonic(
  prior: number,
  current: number,
  priorDigest: Sha256Digest | undefined,
  currentDigest: Sha256Digest | undefined,
): void {
  if (current < prior) throw invalidAnchor();
  if ((priorDigest === undefined) !== (currentDigest === undefined)) {
    throw invalidAnchor();
  }
  if (
    current === prior &&
    priorDigest !== undefined &&
    currentDigest !== undefined &&
    priorDigest !== currentDigest
  ) {
    throw invalidAnchor();
  }
}

function assertExactPair(
  prior: number,
  current: number,
  priorDigest: Sha256Digest,
  currentDigest: Sha256Digest,
): void {
  if (prior !== current || priorDigest !== currentDigest) throw invalidAnchor();
}

function assertVerifiedChain(
  proof: RecipientRollbackAnchorChainVerification,
  trusted: RecipientRollbackAnchor,
  observed: RecipientRollbackAnchor,
): void {
  try {
    const parsed = z
      .object({
        kind: z.literal('verified-chain'),
        from: recipientRollbackAnchorSchema,
        to: recipientRollbackAnchorSchema,
      })
      .strict()
      .parse(structuredClone(proof));
    const from = normalizeAnchor(parsed.from);
    const to = normalizeAnchor(parsed.to);
    if (!sameAnchorState(from, trusted) || !sameAnchorState(to, observed)) {
      throw invalidAnchor();
    }
    if (to.documentRevision < from.documentRevision) throw invalidAnchor();
  } catch (error) {
    if (error instanceof PortableKeyFileError) throw error;
    throw invalidAnchor();
  }
}

/** Equality for proof endpoints. `updatedAt` is authenticated metadata, not
 * a rollback authority, so a verifier may carry the observation's timestamp. */
function sameAnchorState(
  left: RecipientRollbackAnchor,
  right: RecipientRollbackAnchor,
): boolean {
  const leftState = { ...left } as Record<string, unknown>;
  const rightState = { ...right } as Record<string, unknown>;
  Reflect.deleteProperty(leftState, 'updatedAt');
  Reflect.deleteProperty(rightState, 'updatedAt');
  return canonicalJson(leftState) === canonicalJson(rightState);
}

function readOptions(
  value: RecipientRollbackAnchorVerificationOptions | undefined,
): RecipientRollbackAnchorVerificationOptions {
  if (value === undefined) return {};
  try {
    const parsed = z
      .object({
        expectedScope: z
          .object({
            databaseId: recipientRollbackAnchorSchema.shape.databaseId,
            vaultId: recipientRollbackAnchorSchema.shape.vaultId,
            principalId: recipientRollbackAnchorSchema.shape.principalId,
            deviceId: recipientRollbackAnchorSchema.shape.deviceId,
          })
          .strict()
          .optional(),
        observed: recipientRollbackAnchorSchema.optional(),
        chainVerification: z
          .object({
            kind: z.literal('verified-chain'),
            from: recipientRollbackAnchorSchema,
            to: recipientRollbackAnchorSchema,
          })
          .strict()
          .optional(),
      })
      .strict()
      .parse(structuredClone(value));
    return {
      ...(parsed.expectedScope === undefined
        ? {}
        : { expectedScope: parseScope(parsed.expectedScope) }),
      ...(parsed.observed === undefined ? {} : { observed: parsed.observed }),
      ...(parsed.chainVerification === undefined
        ? {}
        : {
            chainVerification: {
              kind: 'verified-chain' as const,
              from: parsed.chainVerification.from,
              to: parsed.chainVerification.to,
            },
          }),
    };
  } catch {
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

export type { RecipientRollbackAnchor } from '@kavrix/schemas';
