import { createHmac, hkdfSync } from 'node:crypto';

import {
  MAX_COLLABORATIVE_OPERATION_BYTES,
  MAX_COLLABORATIVE_VAULT_DESTRUCTION_ANCHOR_BYTES,
  MAX_COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_BYTES,
  canonicalJson,
  collaborationOperationIdSchema,
  collaborationVaultDestructionTombstoneSchema,
  durableOperationOutcomeSchema,
  recipientVaultDestructionAnchorSchema,
  sha256DigestSchema,
  timestampSchema,
  type CollaborationOperationId,
  type CollaborationVaultDestructionTombstone,
  type DatabaseId,
  type DeviceId,
  type DurableOperationOutcome,
  type PrincipalId,
  type RecipientVaultDestructionAnchor,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';
import {
  computeCollaborativeVaultDestroyedPayloadDigest,
  computeCollaborativeVaultDestructionActionDigest,
  computeFinalizedMutationLinkDigest,
  computeOperationOutcomeDigest,
  constantTimeEqual,
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

/** Stable suffix for an irreversible collaborative-vault destruction journal. */
export const COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_SUFFIX =
  '.collaboration-vault-destruction-journal';
export const COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_FORMAT =
  'kavrix-collaborative-vault-destruction-journal';
export const COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_VERSION = 1;

const FORMAT = COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_FORMAT;
const VERSION = COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_VERSION;
const DOMAIN = 'kavrix/collaborative-vault-destruction-journal/v1';
const KDF_DOMAIN = 'kavrix/collaborative-vault-destruction-journal/hmac-key/v1';
const SECRET_BYTES = 32;
const TAG_BYTES = 32;
const KDF_SALT = new Uint8Array(32);
const ENVELOPE_OVERHEAD_BYTES = 64 * 1024;

export const MAX_COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_BYTES =
  MAX_COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_BYTES +
  MAX_COLLABORATIVE_OPERATION_BYTES +
  MAX_COLLABORATIVE_VAULT_DESTRUCTION_ANCHOR_BYTES +
  ENVELOPE_OVERHEAD_BYTES;

const authenticationTagSchema = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/u);

export type CollaborationVaultDestructionJournalScope = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  principalId: PrincipalId;
  deviceId: DeviceId;
}>;

export type CollaborationVaultDestructionJournalCreateInput = Readonly<{
  tombstone: CollaborationVaultDestructionTombstone;
  proposedOutcome: DurableOperationOutcome;
  recipientAnchor: RecipientVaultDestructionAnchor;
  createdAt?: Timestamp;
}>;

export type CollaborationVaultDestructionJournalCommittedEvidence = Readonly<{
  tombstone: CollaborationVaultDestructionTombstone;
  outcome: DurableOperationOutcome;
}>;

export type CollaborationVaultDestructionJournalReadOptions = Readonly<{
  expectedScope?: CollaborationVaultDestructionJournalScope;
}>;

const journalIdentityShape = {
  databaseId: recipientVaultDestructionAnchorSchema.shape.databaseId,
  vaultId: recipientVaultDestructionAnchorSchema.shape.vaultId,
  operationId: collaborationOperationIdSchema,
  requestDigest: sha256DigestSchema,
  actorPrincipalId: recipientVaultDestructionAnchorSchema.shape.principalId,
  actorDeviceId: recipientVaultDestructionAnchorSchema.shape.deviceId,
  actionParametersDigest: sha256DigestSchema,
} as const;

const journalArtifactShape = {
  tombstone: collaborationVaultDestructionTombstoneSchema,
  proposedOutcome: durableOperationOutcomeSchema,
  recipientAnchor: recipientVaultDestructionAnchorSchema,
} as const;

const journalCommonShape = {
  format: z.literal(FORMAT),
  version: z.literal(VERSION),
  ...journalIdentityShape,
  ...journalArtifactShape,
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
  authenticationTag: authenticationTagSchema,
} as const;

export const collaborativeVaultDestructionJournalPreparedSchema = z
  .object({ ...journalCommonShape, state: z.literal('prepared') })
  .strict()
  .superRefine(assertJournalRecord);

export const collaborativeVaultDestructionJournalCommittedSchema = z
  .object({ ...journalCommonShape, state: z.literal('committed') })
  .strict()
  .superRefine(assertJournalRecord);

export const collaborativeVaultDestructionJournalRecordSchema = z.union([
  collaborativeVaultDestructionJournalPreparedSchema,
  collaborativeVaultDestructionJournalCommittedSchema,
]);

type JournalPreparedEnvelope = z.infer<
  typeof collaborativeVaultDestructionJournalPreparedSchema
>;
type JournalCommittedEnvelope = z.infer<
  typeof collaborativeVaultDestructionJournalCommittedSchema
>;
type JournalEnvelope = JournalPreparedEnvelope | JournalCommittedEnvelope;

export type CollaborativeVaultDestructionJournalPreparedRecord = Omit<
  JournalPreparedEnvelope,
  'authenticationTag'
>;
export type CollaborativeVaultDestructionJournalCommittedRecord = Omit<
  JournalCommittedEnvelope,
  'authenticationTag'
>;
export type CollaborativeVaultDestructionJournalRecord =
  | CollaborativeVaultDestructionJournalPreparedRecord
  | CollaborativeVaultDestructionJournalCommittedRecord;

const journalDocumentSchema: CanonicalJsonDocumentSchema<JournalEnvelope> =
  collaborativeVaultDestructionJournalRecordSchema;

const createInputSchema = z
  .object({
    ...journalArtifactShape,
    createdAt: timestampSchema.optional(),
  })
  .strict();

const committedEvidenceSchema = z
  .object({
    tombstone: collaborationVaultDestructionTombstoneSchema,
    outcome: durableOperationOutcomeSchema,
  })
  .strict();

/** Derives one deterministic sidecar path for a destruction operation. */
export function collaborativeVaultDestructionJournalPath(
  basePath: string,
  databaseId: DatabaseId,
  vaultId: VaultId,
  operationId: CollaborationOperationId,
): string {
  assertPath(basePath);
  const database = parseDatabaseId(databaseId);
  const vault = parseVaultId(vaultId);
  const operation = parseOperationId(operationId);
  return `${basePath}${COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_SUFFIX}.${database}.${vault}.${operation}`;
}

/**
 * Durably prepares exact non-secret destruction artifacts before publication.
 * Exact same-operation replay is an authenticated no-op; every substitution
 * fails closed without replacing the existing journal.
 */
export async function createCollaborativeVaultDestructionJournal(
  path: string,
  deviceProtectionSecret: Uint8Array,
  input: CollaborationVaultDestructionJournalCreateInput,
): Promise<void> {
  assertPath(path);
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const prepared = buildPreparedRecord(input);
  const envelope = serializeJournal(deviceProtectionSecret, prepared);
  try {
    await writeProtectedJsonDocument(path, envelope, 'create', {
      schema: journalDocumentSchema,
      maximumBytes: MAX_COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_BYTES,
    });
    return;
  } catch (error) {
    if (
      !(error instanceof PortableKeyFileError) ||
      error.code !== 'KEY_FILE_ALREADY_EXISTS'
    ) {
      throw mapJournalError(error);
    }
  }

  const existing = await readCollaborativeVaultDestructionJournal(
    path,
    deviceProtectionSecret,
  );
  if (existing === null || !samePreparedArtifacts(existing, prepared)) {
    throw invalidJournal();
  }
}

/** Reads and authenticates one destruction journal; absence is the only null result. */
export async function readCollaborativeVaultDestructionJournal(
  path: string,
  deviceProtectionSecret: Uint8Array,
  options?: CollaborationVaultDestructionJournalReadOptions,
): Promise<CollaborativeVaultDestructionJournalRecord | null> {
  assertPath(path);
  requireDeviceProtectionSecret(deviceProtectionSecret);
  let envelope: JournalEnvelope;
  try {
    envelope = await readProtectedJsonDocument(path, {
      schema: journalDocumentSchema,
      maximumBytes: MAX_COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_BYTES,
    });
  } catch (error) {
    if (error instanceof PortableKeyFileError && error.code === 'KEY_FILE_NOT_FOUND') {
      return null;
    }
    throw mapJournalError(error);
  }

  try {
    const trusted = parseAuthenticatedJournal(deviceProtectionSecret, envelope);
    const expectedScope = parseReadOptions(options).expectedScope;
    if (expectedScope !== undefined) assertJournalScope(trusted, expectedScope);
    return withoutAuthenticationTag(trusted);
  } catch (error) {
    throw mapJournalError(error);
  }
}

/**
 * Reconciles authoritative permanent evidence and atomically marks a prepared
 * journal committed. Only an exact committed tombstone/outcome pair is terminal.
 */
export async function reconcileCollaborativeVaultDestructionJournal(
  path: string,
  deviceProtectionSecret: Uint8Array,
  evidenceInput: CollaborationVaultDestructionJournalCommittedEvidence,
): Promise<void> {
  assertPath(path);
  requireDeviceProtectionSecret(deviceProtectionSecret);
  const evidence = parseCommittedEvidence(evidenceInput);
  try {
    await transitionProtectedJsonDocument(
      path,
      {
        schema: journalDocumentSchema,
        maximumBytes: MAX_COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_BYTES,
      },
      (currentEnvelope) => {
        const current = parseAuthenticatedJournal(
          deviceProtectionSecret,
          currentEnvelope,
        );
        assertCommittedEvidenceMatches(current, evidence);
        if (current.state === 'committed') {
          return { document: currentEnvelope, result: undefined };
        }
        const committed: CollaborativeVaultDestructionJournalCommittedRecord = {
          ...withoutAuthenticationTag(current),
          state: 'committed',
          updatedAt: now(),
        };
        return {
          document: serializeJournal(deviceProtectionSecret, committed),
          result: undefined,
        };
      },
    );
  } catch (error) {
    throw mapJournalError(error);
  }
}

/** Verifies exact committed replay without changing journal bytes. */
export async function verifyCommittedCollaborativeVaultDestructionJournal(
  path: string,
  deviceProtectionSecret: Uint8Array,
  evidenceInput: CollaborationVaultDestructionJournalCommittedEvidence,
): Promise<CollaborativeVaultDestructionJournalCommittedRecord> {
  const evidence = parseCommittedEvidence(evidenceInput);
  const record = await readCollaborativeVaultDestructionJournal(
    path,
    deviceProtectionSecret,
  );
  if (record?.state !== 'committed') throw invalidJournal();
  assertCommittedEvidenceMatches(record, evidence);
  return record;
}

function buildPreparedRecord(
  input: CollaborationVaultDestructionJournalCreateInput,
): CollaborativeVaultDestructionJournalPreparedRecord {
  try {
    const parsed = createInputSchema.parse(structuredClone(input));
    const commitment = parsed.tombstone.proofEntry.link.commitment;
    const createdAt = parsed.createdAt ?? now();
    const record: CollaborativeVaultDestructionJournalPreparedRecord = {
      format: FORMAT,
      version: VERSION,
      state: 'prepared',
      databaseId: parsed.tombstone.databaseId,
      vaultId: parsed.tombstone.vaultId,
      operationId: parsed.tombstone.core.operationId,
      requestDigest: commitment.requestDigest,
      actorPrincipalId: parsed.tombstone.core.actorPrincipalId,
      actorDeviceId: parsed.tombstone.core.actorDeviceId,
      actionParametersDigest: parsed.tombstone.core.actionParametersDigest,
      tombstone: parsed.tombstone,
      proposedOutcome: parsed.proposedOutcome,
      recipientAnchor: parsed.recipientAnchor,
      createdAt,
      updatedAt: createdAt,
    };
    assertArtifactBindings(record);
    return record;
  } catch (error) {
    throw mapJournalError(error);
  }
}

function serializeJournal(
  secret: Uint8Array,
  record: JournalEnvelope | CollaborativeVaultDestructionJournalRecord,
): JournalEnvelope {
  const untagged = { ...record } as Record<string, unknown>;
  delete untagged['authenticationTag'];
  const parsed = collaborativeVaultDestructionJournalRecordSchema.parse({
    ...untagged,
    authenticationTag: 'A'.repeat(43),
  });
  let message: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  try {
    message = journalMessage(parsed);
    tag = hmac(secret, parsed, message);
    return { ...parsed, authenticationTag: encodeBase64Url(tag) };
  } finally {
    zeroize(message);
    zeroize(tag);
  }
}

function parseAuthenticatedJournal(
  secret: Uint8Array,
  envelopeInput: JournalEnvelope,
): JournalEnvelope {
  const envelope =
    collaborativeVaultDestructionJournalRecordSchema.parse(envelopeInput);
  let message: Uint8Array | undefined;
  let supplied: Uint8Array | undefined;
  let expected: Uint8Array | undefined;
  try {
    message = journalMessage(envelope);
    supplied = decodeBase64Url(envelope.authenticationTag, {
      exactBytes: TAG_BYTES,
    });
    expected = hmac(secret, envelope, message);
    if (!constantTimeEqual(supplied, expected)) throw invalidJournal();
    return envelope;
  } finally {
    zeroize(message);
    zeroize(supplied);
    zeroize(expected);
  }
}

function journalMessage(
  record: JournalEnvelope | CollaborativeVaultDestructionJournalRecord,
): Uint8Array {
  const value = { ...record } as Record<string, unknown>;
  delete value['authenticationTag'];
  return Buffer.from(
    canonicalJson({ domain: DOMAIN, format: FORMAT, version: VERSION, ...value }),
    'utf8',
  );
}

function hmac(
  secret: Uint8Array,
  record: JournalEnvelope | CollaborativeVaultDestructionJournalRecord,
  message: Uint8Array,
): Uint8Array {
  const key = deriveJournalKey(secret, record);
  try {
    return Uint8Array.from(createHmac('sha256', key).update(message).digest());
  } finally {
    zeroize(key);
  }
}

function deriveJournalKey(
  secret: Uint8Array,
  record: JournalEnvelope | CollaborativeVaultDestructionJournalRecord,
): Uint8Array {
  const info = Buffer.from(
    canonicalJson({
      domain: KDF_DOMAIN,
      version: VERSION,
      databaseId: record.databaseId,
      vaultId: record.vaultId,
      principalId: record.actorPrincipalId,
      deviceId: record.actorDeviceId,
      operationId: record.operationId,
      requestDigest: record.requestDigest,
      actionParametersDigest: record.actionParametersDigest,
    }),
    'utf8',
  );
  try {
    return new Uint8Array(hkdfSync('sha256', secret, KDF_SALT, info, SECRET_BYTES));
  } finally {
    info.fill(0);
  }
}

function assertJournalRecord(record: JournalEnvelope, context: z.RefinementCtx): void {
  assertCanonicalBytes(record, context);
  try {
    assertArtifactBindings(record);
    if (record.updatedAt < record.createdAt) throw invalidJournal();
  } catch {
    addIssue(context, 'Vault destruction journal has an invalid binding');
  }
}

function assertArtifactBindings(
  record: Pick<
    JournalEnvelope,
    | 'databaseId'
    | 'vaultId'
    | 'operationId'
    | 'requestDigest'
    | 'actorPrincipalId'
    | 'actorDeviceId'
    | 'actionParametersDigest'
    | 'tombstone'
    | 'proposedOutcome'
    | 'recipientAnchor'
  >,
): void {
  const tombstone = collaborationVaultDestructionTombstoneSchema.parse(
    record.tombstone,
  );
  const outcome = durableOperationOutcomeSchema.parse(record.proposedOutcome);
  const anchor = recipientVaultDestructionAnchorSchema.parse(record.recipientAnchor);
  const core = tombstone.core;
  const commitment = tombstone.proofEntry.link.commitment;
  const linkDigest = computeFinalizedMutationLinkDigest(tombstone.proofEntry.link);
  const actionDigest = computeCollaborativeVaultDestructionActionDigest({
    protocolVersion: core.protocolVersion,
    operationType: 'destroy-vault',
    databaseId: core.databaseId,
    vaultId: core.vaultId,
    destructionMode: core.destructionMode,
  });

  if (
    record.databaseId !== core.databaseId ||
    record.vaultId !== core.vaultId ||
    record.operationId !== core.operationId ||
    record.requestDigest !== commitment.requestDigest ||
    record.actorPrincipalId !== core.actorPrincipalId ||
    record.actorDeviceId !== core.actorDeviceId ||
    record.actionParametersDigest !== core.actionParametersDigest ||
    core.actionParametersDigest !== actionDigest ||
    tombstone.destroyedPayloadDigest !==
      computeCollaborativeVaultDestroyedPayloadDigest(core) ||
    tombstone.signedMutationReceipt.finalizedMutationLinkDigest !== linkDigest ||
    tombstone.outcomeDigest !== computeOperationOutcomeDigest(outcome) ||
    outcome.state !== 'committed' ||
    outcome.databaseId !== core.databaseId ||
    outcome.vaultId !== core.vaultId ||
    outcome.operationId !== core.operationId ||
    outcome.operationType !== 'destroy-vault' ||
    outcome.requestDigest !== commitment.requestDigest ||
    outcome.actorPrincipalId !== core.actorPrincipalId ||
    outcome.actorDeviceId !== core.actorDeviceId ||
    outcome.priorHeadDigest !== core.priorHeadDigest ||
    canonicalJson(outcome.priorTuple) !== canonicalJson(core.priorTuple) ||
    canonicalJson(outcome.committedTuple) !== canonicalJson(core.terminalTuple) ||
    outcome.committedHeadDigest !== tombstone.terminalHeadDigest ||
    outcome.finalizedMutationLinkDigest !== linkDigest ||
    outcome.outcomeDigest !== tombstone.outcomeDigest ||
    canonicalJson(outcome.signedMutationReceipt) !==
      canonicalJson(tombstone.signedMutationReceipt) ||
    anchor.databaseId !== core.databaseId ||
    anchor.vaultId !== core.vaultId ||
    anchor.principalId !== core.actorPrincipalId ||
    anchor.deviceId !== core.actorDeviceId ||
    anchor.authorityEpoch !== core.authorityEpoch ||
    anchor.authorityDelegationDigest !== core.authorityDelegationDigest ||
    anchor.operationId !== core.operationId ||
    canonicalJson(anchor.priorTuple) !== canonicalJson(core.priorTuple) ||
    anchor.priorHeadDigest !== core.priorHeadDigest ||
    canonicalJson(anchor.terminalTuple) !== canonicalJson(core.terminalTuple) ||
    anchor.terminalHeadDigest !== tombstone.terminalHeadDigest ||
    anchor.destroyedPayloadDigest !== tombstone.destroyedPayloadDigest ||
    anchor.finalizedMutationLinkDigest !== linkDigest ||
    anchor.outcomeDigest !== tombstone.outcomeDigest ||
    anchor.destroyedAt !== core.destroyedAt
  ) {
    throw invalidJournal();
  }
}

function assertCommittedEvidenceMatches(
  record: CollaborativeVaultDestructionJournalRecord | JournalEnvelope,
  evidence: CollaborationVaultDestructionJournalCommittedEvidence,
): void {
  assertArtifactBindings({
    ...record,
    tombstone: evidence.tombstone,
    proposedOutcome: evidence.outcome,
  });
  if (
    canonicalJson(record.tombstone) !== canonicalJson(evidence.tombstone) ||
    canonicalJson(record.proposedOutcome) !== canonicalJson(evidence.outcome)
  ) {
    throw invalidJournal();
  }
}

function samePreparedArtifacts(
  existing: CollaborativeVaultDestructionJournalRecord,
  prepared: CollaborativeVaultDestructionJournalPreparedRecord,
): boolean {
  return (
    existing.databaseId === prepared.databaseId &&
    existing.vaultId === prepared.vaultId &&
    existing.operationId === prepared.operationId &&
    existing.requestDigest === prepared.requestDigest &&
    existing.actorPrincipalId === prepared.actorPrincipalId &&
    existing.actorDeviceId === prepared.actorDeviceId &&
    existing.actionParametersDigest === prepared.actionParametersDigest &&
    canonicalJson(existing.tombstone) === canonicalJson(prepared.tombstone) &&
    canonicalJson(existing.proposedOutcome) ===
      canonicalJson(prepared.proposedOutcome) &&
    canonicalJson(existing.recipientAnchor) === canonicalJson(prepared.recipientAnchor)
  );
}

function parseCommittedEvidence(
  input: CollaborationVaultDestructionJournalCommittedEvidence,
): CollaborationVaultDestructionJournalCommittedEvidence {
  try {
    const parsed = committedEvidenceSchema.parse(structuredClone(input));
    if (parsed.outcome.state !== 'committed') throw invalidJournal();
    return parsed;
  } catch (error) {
    throw mapJournalError(error);
  }
}

function parseReadOptions(
  input: CollaborationVaultDestructionJournalReadOptions | undefined,
): CollaborationVaultDestructionJournalReadOptions {
  if (input === undefined) return {};
  try {
    const parsed = z
      .object({
        expectedScope: z
          .object({
            databaseId: recipientVaultDestructionAnchorSchema.shape.databaseId,
            vaultId: recipientVaultDestructionAnchorSchema.shape.vaultId,
            principalId: recipientVaultDestructionAnchorSchema.shape.principalId,
            deviceId: recipientVaultDestructionAnchorSchema.shape.deviceId,
          })
          .strict()
          .optional(),
      })
      .strict()
      .parse(structuredClone(input));
    return parsed.expectedScope === undefined
      ? {}
      : { expectedScope: parsed.expectedScope };
  } catch {
    throw invalidJournal();
  }
}

function assertJournalScope(
  record: JournalEnvelope,
  expectedInput: CollaborationVaultDestructionJournalScope,
): void {
  const expected = parseReadOptions({ expectedScope: expectedInput }).expectedScope;
  if (
    record.databaseId !== expected?.databaseId ||
    record.vaultId !== expected.vaultId ||
    record.actorPrincipalId !== expected.principalId ||
    record.actorDeviceId !== expected.deviceId
  ) {
    throw invalidJournal();
  }
}

function withoutAuthenticationTag(
  envelope: JournalEnvelope,
): CollaborativeVaultDestructionJournalRecord {
  const record = { ...envelope };
  Reflect.deleteProperty(record, 'authenticationTag');
  return record;
}

function parseDatabaseId(value: unknown): DatabaseId {
  try {
    return recipientVaultDestructionAnchorSchema.shape.databaseId.parse(value);
  } catch {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function parseVaultId(value: unknown): VaultId {
  try {
    return recipientVaultDestructionAnchorSchema.shape.vaultId.parse(value);
  } catch {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function parseOperationId(value: unknown): CollaborationOperationId {
  try {
    return collaborationOperationIdSchema.parse(value);
  } catch {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function assertCanonicalBytes(value: unknown, context: z.RefinementCtx): void {
  try {
    if (
      Buffer.byteLength(canonicalJson(value), 'utf8') >
      MAX_COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_BYTES
    ) {
      addIssue(context, 'Vault destruction journal exceeds its size bound');
    }
  } catch {
    addIssue(context, 'Vault destruction journal is not canonically encodable');
  }
}

function addIssue(
  context: z.RefinementCtx,
  message: string,
  path: (string | number)[] = [],
): void {
  context.addIssue({ code: 'custom', message, path });
}

function requireDeviceProtectionSecret(secret: Uint8Array): void {
  try {
    requireByteLength(secret, SECRET_BYTES, 'device protection secret');
  } catch {
    throw invalidJournal();
  }
}

function assertPath(path: string): void {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\u0000')) {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

function now(): Timestamp {
  return timestampSchema.parse(new Date().toISOString());
}

function mapJournalError(error: unknown): PortableKeyFileError {
  if (error instanceof PortableKeyFileError) return error;
  if (error instanceof ProtectedJsonDocumentError) return invalidJournal();
  return invalidJournal();
}

function invalidJournal(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}

export type {
  CollaborationVaultDestructionTombstone,
  DurableOperationOutcome,
  RecipientVaultDestructionAnchor,
};
