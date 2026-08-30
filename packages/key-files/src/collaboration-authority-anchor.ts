import { createHmac, hkdfSync } from 'node:crypto';

import {
  canonicalJson,
  collaborativeVaultDocumentSchema,
  recipientRollbackAnchorSchema,
  sha256DigestSchema,
  timestampSchema,
  type CollaborativeVaultDocument,
  type DatabaseId,
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

export const COLLABORATION_AUTHORITY_ROLLBACK_ANCHOR_SUFFIX =
  '.authority-rollback-anchor';
export const COLLABORATION_AUTHORITY_ROLLBACK_ANCHOR_FORMAT =
  'kavrix-collaborative-authority-rollback-anchor';
export const COLLABORATION_AUTHORITY_ROLLBACK_ANCHOR_VERSION = 1;

const DOMAIN = 'kavrix/collaborative-authority-rollback-anchor/v1';
const KDF_DOMAIN = 'kavrix/collaborative-authority-rollback-anchor/hmac-key/v1';
const SECRET_BYTES = 32;
const TAG_BYTES = 32;
const MAX_FILE_BYTES = 16 * 1024;
const KDF_SALT = new Uint8Array(32);

export const collaborationAuthorityRollbackAnchorSchema = z
  .object({
    format: z.literal(COLLABORATION_AUTHORITY_ROLLBACK_ANCHOR_FORMAT),
    protocolVersion: recipientRollbackAnchorSchema.shape.protocolVersion,
    databaseId: recipientRollbackAnchorSchema.shape.databaseId,
    vaultId: recipientRollbackAnchorSchema.shape.vaultId,
    authorityEpoch: recipientRollbackAnchorSchema.shape.authorityEpoch,
    authorityDelegationDigest:
      recipientRollbackAnchorSchema.shape.authorityDelegationDigest,
    databaseDeviceGeneration:
      recipientRollbackAnchorSchema.shape.databaseDeviceGeneration,
    databaseDeviceRegistryDigest:
      recipientRollbackAnchorSchema.shape.databaseDeviceRegistryDigest,
    membershipRevision: recipientRollbackAnchorSchema.shape.membershipRevision,
    membershipDigest: recipientRollbackAnchorSchema.shape.membershipDigest,
    policyRevision: recipientRollbackAnchorSchema.shape.policyRevision,
    policyDigest: recipientRollbackAnchorSchema.shape.policyDigest,
    keyEpoch: recipientRollbackAnchorSchema.shape.keyEpoch,
    documentRevision: recipientRollbackAnchorSchema.shape.documentRevision,
    encryptedPayloadDigest: recipientRollbackAnchorSchema.shape.encryptedPayloadDigest,
    headDigest: recipientRollbackAnchorSchema.shape.headDigest,
    authorizationStateDigest:
      recipientRollbackAnchorSchema.shape.authorizationStateDigest,
    finalizedMutationLinkDigest:
      recipientRollbackAnchorSchema.shape.finalizedMutationLinkDigest,
    updatedAt: recipientRollbackAnchorSchema.shape.updatedAt,
  })
  .strict();

export type CollaborationAuthorityRollbackAnchor = z.infer<
  typeof collaborationAuthorityRollbackAnchorSchema
>;

const authenticationTagSchema = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/u);
const authorityAnchorEnvelopeSchema = collaborationAuthorityRollbackAnchorSchema
  .extend({ authenticationTag: authenticationTagSchema })
  .strict();
type AuthorityAnchorEnvelope = z.infer<typeof authorityAnchorEnvelopeSchema>;
const authorityAnchorDocumentSchema: CanonicalJsonDocumentSchema<AuthorityAnchorEnvelope> =
  authorityAnchorEnvelopeSchema;

export type CollaborationAuthorityRollbackAnchorScope = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  authorityEpoch: number;
  authorityDelegationDigest: Sha256Digest;
}>;

export type CollaborationAuthorityRollbackAnchorChainVerification = Readonly<{
  kind: 'verified-chain';
  from: CollaborationAuthorityRollbackAnchor;
  to: CollaborationAuthorityRollbackAnchor;
}>;

export type CollaborationAuthorityRollbackAnchorVerificationOptions = Readonly<{
  expectedScope?: CollaborationAuthorityRollbackAnchorScope;
  observed?: CollaborationAuthorityRollbackAnchor;
  chainVerification?: CollaborationAuthorityRollbackAnchorChainVerification;
}>;

export type CollaborationAuthorityRollbackAnchorTransitionResult<Result> = Readonly<{
  nextAnchor: CollaborationAuthorityRollbackAnchor;
  result: Result;
}>;

export function collaborationAuthorityRollbackAnchorPath(
  basePath: string,
  scope: CollaborationAuthorityRollbackAnchorScope,
): string {
  assertPath(basePath);
  const parsed = parseScope(scope);
  return `${basePath}${COLLABORATION_AUTHORITY_ROLLBACK_ANCHOR_SUFFIX}.${parsed.databaseId}.${parsed.vaultId}.${String(parsed.authorityEpoch)}`;
}

export async function createCollaborationAuthorityRollbackAnchor(
  path: string,
  databaseRootKey: Uint8Array,
  anchor: CollaborationAuthorityRollbackAnchor,
): Promise<void> {
  requireDatabaseRootKey(databaseRootKey);
  const normalized = normalizeAnchor(anchor);
  try {
    const envelope = serializeAnchor(databaseRootKey, normalized);
    await writeProtectedJsonDocument(path, envelope, 'create', {
      schema: authorityAnchorDocumentSchema,
      maximumBytes: MAX_FILE_BYTES,
    });
  } catch (error) {
    throw mapAnchorError(error);
  }
}

export async function readCollaborationAuthorityRollbackAnchor(
  path: string,
  databaseRootKey: Uint8Array,
  options?: CollaborationAuthorityRollbackAnchorVerificationOptions,
): Promise<CollaborationAuthorityRollbackAnchor> {
  requireDatabaseRootKey(databaseRootKey);
  const parsedOptions = readOptions(options);
  let envelope: AuthorityAnchorEnvelope;
  try {
    envelope = await readProtectedJsonDocument(path, {
      schema: authorityAnchorDocumentSchema,
      maximumBytes: MAX_FILE_BYTES,
    });
  } catch (error) {
    throw mapAnchorError(error);
  }
  try {
    const trusted = parseAuthenticatedEnvelope(databaseRootKey, envelope);
    if (parsedOptions.expectedScope !== undefined) {
      assertScope(trusted, parsedOptions.expectedScope);
    }
    if (parsedOptions.observed !== undefined) {
      verifyCollaborationAuthorityRollbackAnchor(
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

export function verifyCollaborationAuthorityRollbackAnchor(
  trustedInput: CollaborationAuthorityRollbackAnchor,
  observedInput: CollaborationAuthorityRollbackAnchor,
  expectedScope?: CollaborationAuthorityRollbackAnchorScope,
  chainVerification?: CollaborationAuthorityRollbackAnchorChainVerification,
): void {
  try {
    const trusted = normalizeAnchor(trustedInput);
    const observed = normalizeAnchor(observedInput);
    if (expectedScope !== undefined) {
      assertScope(trusted, expectedScope);
      assertScope(observed, expectedScope);
    }
    assertScopeEqual(trusted, observed);
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
    assertMonotonic(trusted.keyEpoch, observed.keyEpoch);
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
      (authorizationStateAdvanced &&
        observed.authorizationStateDigest === trusted.authorizationStateDigest) ||
      (!authorizationStateAdvanced &&
        observed.authorizationStateDigest !== trusted.authorizationStateDigest)
    ) {
      throw invalidAnchor();
    }
    if (
      observed.documentRevision === trusted.documentRevision &&
      (observed.finalizedMutationLinkDigest !== trusted.finalizedMutationLinkDigest ||
        observed.headDigest !== trusted.headDigest)
    ) {
      throw invalidAnchor();
    }
    if (
      observed.documentRevision > trusted.documentRevision &&
      (observed.headDigest === trusted.headDigest ||
        observed.finalizedMutationLinkDigest === trusted.finalizedMutationLinkDigest)
    ) {
      throw invalidAnchor();
    }

    const hasUnprovedGap =
      observed.databaseDeviceGeneration - trusted.databaseDeviceGeneration > 1 ||
      observed.membershipRevision - trusted.membershipRevision > 1 ||
      observed.policyRevision - trusted.policyRevision > 1 ||
      observed.keyEpoch - trusted.keyEpoch > 1 ||
      observed.documentRevision - trusted.documentRevision > 1;
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

export async function transitionCollaborationAuthorityRollbackAnchor<Result>(
  path: string,
  databaseRootKey: Uint8Array,
  observed: CollaborationAuthorityRollbackAnchor,
  callback: (
    trusted: CollaborationAuthorityRollbackAnchor,
  ) =>
    | CollaborationAuthorityRollbackAnchorTransitionResult<Result>
    | Promise<CollaborationAuthorityRollbackAnchorTransitionResult<Result>>,
  options: CollaborationAuthorityRollbackAnchorVerificationOptions = {},
): Promise<Result> {
  requireDatabaseRootKey(databaseRootKey);
  const normalizedObserved = normalizeAnchor(observed);
  const expectedScope = options.expectedScope ?? scopeOf(normalizedObserved);
  if (options.observed !== undefined) {
    verifyCollaborationAuthorityRollbackAnchor(
      normalizedObserved,
      options.observed,
      expectedScope,
      options.chainVerification,
    );
  }
  try {
    return await transitionProtectedJsonDocument(
      path,
      { schema: authorityAnchorDocumentSchema, maximumBytes: MAX_FILE_BYTES },
      async (currentEnvelope) => {
        const trusted = parseAuthenticatedEnvelope(databaseRootKey, currentEnvelope);
        assertScope(trusted, expectedScope);
        verifyCollaborationAuthorityRollbackAnchor(
          trusted,
          normalizedObserved,
          expectedScope,
          options.chainVerification,
        );
        const transition = await callback(trusted);
        const nextAnchor = normalizeAnchor(transition.nextAnchor);
        assertScope(nextAnchor, expectedScope);
        verifyCollaborationAuthorityRollbackAnchor(
          normalizedObserved,
          nextAnchor,
          expectedScope,
        );
        return {
          document: serializeAnchor(databaseRootKey, nextAnchor),
          result: transition.result,
        };
      },
    );
  } catch (error) {
    throw mapAnchorError(error);
  }
}

export function collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
  documentInput: CollaborativeVaultDocument,
  options: Readonly<{
    membershipDigest: Sha256Digest;
    policyDigest: Sha256Digest;
  }>,
): CollaborationAuthorityRollbackAnchor {
  const document = collaborativeVaultDocumentSchema.parse(documentInput);
  return normalizeAnchor({
    format: COLLABORATION_AUTHORITY_ROLLBACK_ANCHOR_FORMAT,
    protocolVersion: document.protocolVersion,
    databaseId: document.databaseId,
    vaultId: document.vaultId,
    authorityEpoch: document.authorityEpoch,
    authorityDelegationDigest: document.authorityDelegationDigest,
    databaseDeviceGeneration: document.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: document.databaseDeviceRegistryDigest,
    membershipRevision: document.membershipRevision,
    membershipDigest: sha256DigestSchema.parse(options.membershipDigest),
    policyRevision: document.policyRevision,
    policyDigest: sha256DigestSchema.parse(options.policyDigest),
    keyEpoch: document.keyEpoch,
    documentRevision: document.documentRevision,
    encryptedPayloadDigest: document.encryptedPayloadDigest,
    headDigest: document.headDigest,
    authorizationStateDigest: document.authorizationStateDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
      document.currentMutationLink,
    ),
    updatedAt: timestampSchema.parse(document.updatedAt),
  });
}

function serializeAnchor(
  databaseRootKey: Uint8Array,
  anchor: CollaborationAuthorityRollbackAnchor,
): AuthorityAnchorEnvelope {
  let message: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  try {
    message = anchorMessage(anchor);
    tag = hmac(databaseRootKey, anchor, message);
    return authorityAnchorEnvelopeSchema.parse({
      ...anchor,
      authenticationTag: encodeBase64Url(tag),
    });
  } finally {
    zeroize(message);
    zeroize(tag);
  }
}

function parseAuthenticatedEnvelope(
  databaseRootKey: Uint8Array,
  envelope: AuthorityAnchorEnvelope,
): CollaborationAuthorityRollbackAnchor {
  const parsed = authorityAnchorEnvelopeSchema.parse(envelope);
  const { authenticationTag, ...anchorInput } = parsed;
  const anchor = normalizeAnchor(anchorInput);
  let message: Uint8Array | undefined;
  let supplied: Uint8Array | undefined;
  let expected: Uint8Array | undefined;
  try {
    message = anchorMessage(anchor);
    supplied = decodeBase64Url(authenticationTag, { exactBytes: TAG_BYTES });
    expected = hmac(databaseRootKey, anchor, message);
    if (!constantTimeEqual(supplied, expected)) throw invalidAnchor();
    return anchor;
  } finally {
    zeroize(message);
    zeroize(supplied);
    zeroize(expected);
  }
}

function hmac(
  databaseRootKey: Uint8Array,
  anchor: CollaborationAuthorityRollbackAnchor,
  message: Uint8Array,
): Uint8Array {
  const key = deriveKey(databaseRootKey, scopeOf(anchor));
  try {
    return Uint8Array.from(createHmac('sha256', key).update(message).digest());
  } finally {
    zeroize(key);
  }
}

function deriveKey(
  databaseRootKey: Uint8Array,
  scope: CollaborationAuthorityRollbackAnchorScope,
): Uint8Array {
  const info = Buffer.from(
    canonicalJson({ domain: KDF_DOMAIN, version: 1, ...scope }),
    'utf8',
  );
  try {
    return new Uint8Array(
      hkdfSync('sha256', databaseRootKey, KDF_SALT, info, SECRET_BYTES),
    );
  } finally {
    info.fill(0);
  }
}

function anchorMessage(anchor: CollaborationAuthorityRollbackAnchor): Uint8Array {
  return Buffer.from(canonicalJson({ domain: DOMAIN, ...anchor }), 'utf8');
}

function normalizeAnchor(
  input: CollaborationAuthorityRollbackAnchor,
): CollaborationAuthorityRollbackAnchor {
  try {
    return collaborationAuthorityRollbackAnchorSchema.parse(structuredClone(input));
  } catch (error) {
    throw mapAnchorError(error);
  }
}

function parseScope(
  input: CollaborationAuthorityRollbackAnchorScope,
): CollaborationAuthorityRollbackAnchorScope {
  try {
    return z
      .object({
        databaseId: collaborationAuthorityRollbackAnchorSchema.shape.databaseId,
        vaultId: collaborationAuthorityRollbackAnchorSchema.shape.vaultId,
        authorityEpoch: collaborationAuthorityRollbackAnchorSchema.shape.authorityEpoch,
        authorityDelegationDigest:
          collaborationAuthorityRollbackAnchorSchema.shape.authorityDelegationDigest,
      })
      .strict()
      .parse(structuredClone(input));
  } catch {
    throw invalidAnchor();
  }
}

function scopeOf(
  anchor: CollaborationAuthorityRollbackAnchor,
): CollaborationAuthorityRollbackAnchorScope {
  return {
    databaseId: anchor.databaseId,
    vaultId: anchor.vaultId,
    authorityEpoch: anchor.authorityEpoch,
    authorityDelegationDigest: anchor.authorityDelegationDigest,
  };
}

function assertScope(
  anchor: CollaborationAuthorityRollbackAnchor,
  expected: CollaborationAuthorityRollbackAnchorScope,
): void {
  const scope = parseScope(expected);
  if (canonicalJson(scopeOf(anchor)) !== canonicalJson(scope)) {
    throw invalidAnchor();
  }
}

function assertScopeEqual(
  left: CollaborationAuthorityRollbackAnchor,
  right: CollaborationAuthorityRollbackAnchor,
): void {
  if (canonicalJson(scopeOf(left)) !== canonicalJson(scopeOf(right))) {
    throw invalidAnchor();
  }
}

function assertMonotonic(
  prior: number,
  current: number,
  priorDigest?: Sha256Digest,
  currentDigest?: Sha256Digest,
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
  proof: CollaborationAuthorityRollbackAnchorChainVerification,
  trusted: CollaborationAuthorityRollbackAnchor,
  observed: CollaborationAuthorityRollbackAnchor,
): void {
  try {
    const parsed = z
      .object({
        kind: z.literal('verified-chain'),
        from: collaborationAuthorityRollbackAnchorSchema,
        to: collaborationAuthorityRollbackAnchorSchema,
      })
      .strict()
      .parse(structuredClone(proof));
    if (
      !sameAnchorState(parsed.from, trusted) ||
      !sameAnchorState(parsed.to, observed) ||
      parsed.to.documentRevision < parsed.from.documentRevision
    ) {
      throw invalidAnchor();
    }
  } catch (error) {
    if (error instanceof PortableKeyFileError) throw error;
    throw invalidAnchor();
  }
}

function sameAnchorState(
  left: CollaborationAuthorityRollbackAnchor,
  right: CollaborationAuthorityRollbackAnchor,
): boolean {
  const leftState = { ...left } as Record<string, unknown>;
  const rightState = { ...right } as Record<string, unknown>;
  Reflect.deleteProperty(leftState, 'updatedAt');
  Reflect.deleteProperty(rightState, 'updatedAt');
  return canonicalJson(leftState) === canonicalJson(rightState);
}

function readOptions(
  value: CollaborationAuthorityRollbackAnchorVerificationOptions | undefined,
): CollaborationAuthorityRollbackAnchorVerificationOptions {
  if (value === undefined) return {};
  try {
    const parsed = z
      .object({
        expectedScope: z
          .object({
            databaseId: collaborationAuthorityRollbackAnchorSchema.shape.databaseId,
            vaultId: collaborationAuthorityRollbackAnchorSchema.shape.vaultId,
            authorityEpoch:
              collaborationAuthorityRollbackAnchorSchema.shape.authorityEpoch,
            authorityDelegationDigest:
              collaborationAuthorityRollbackAnchorSchema.shape
                .authorityDelegationDigest,
          })
          .strict()
          .optional(),
        observed: collaborationAuthorityRollbackAnchorSchema.optional(),
        chainVerification: z
          .object({
            kind: z.literal('verified-chain'),
            from: collaborationAuthorityRollbackAnchorSchema,
            to: collaborationAuthorityRollbackAnchorSchema,
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
        : { chainVerification: parsed.chainVerification }),
    };
  } catch {
    throw invalidAnchor();
  }
}

function requireDatabaseRootKey(databaseRootKey: Uint8Array): void {
  requireByteLength(databaseRootKey, SECRET_BYTES, 'database root key');
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
