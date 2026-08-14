import {
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

import {
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  DEFAULT_MAX_BACKUP_RECORDS,
  MAX_SUPPORTED_BACKUP_BYTES,
  attachmentRecordHashMatchesCanonicalContent,
  backupRestoreStatusSchema,
  backupVerificationSchema,
  canonicalJson,
  contentHashForRecord,
  createBackupStagedEntryCommitment,
  restoreKnownRecordsVerificationV1Schema,
  sha256DigestSchema,
  vaultIdSchema,
  type BackupLimits,
  type BackupRestoreStager,
  type BackupRestoreStore,
  type BackupRestoreStatus,
  type BackupVerification,
  type ResolvedBackupLimits,
  type RestoreKnownRecordsVerificationV1,
  type Sha256Digest,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';

import {
  encryptedBackupEntrySchema,
  encryptedBackupFooterSchema,
  encryptedBackupHeaderSchema,
  type EncryptedBackupEntry,
  type EncryptedBackupFooter,
  type EncryptedBackupHeader,
} from './backup-format.js';
import { BackupError } from './errors.js';
import {
  DEFAULT_MAX_BACKUP_BYTES,
  MAX_BACKUP_LINE_BYTES,
  splitBackupLines,
} from './line-framing.js';

const BACKUP_AUTH_INFO = Buffer.from('credvault/backup-authentication/v1', 'ascii');
const RESTORE_SESSION_DOMAIN = Buffer.from(
  'credvault/backup-restore-session/v1\0',
  'ascii',
);
const AUTH_KEY_BYTES = 32;

export {
  DEFAULT_MAX_BACKUP_RECORDS,
  MAX_SUPPORTED_BACKUP_BYTES,
} from '@kavrix/schemas';
export type {
  BackupLimits,
  BackupRestoreStager,
  BackupRestoreStore,
  BackupRestoreStatus,
  BackupVerification,
  ResolvedBackupLimits,
} from '@kavrix/schemas';

export type CreateEncryptedBackupInput = Readonly<{
  vault: VaultRecord;
  records: AsyncIterable<EncryptedBackupEntry>;
  createdAt?: string;
  limits?: BackupLimits;
}>;

export type VerifyEncryptedBackupOptions = Readonly<{
  /** Observes parsed graph entries; the summary returns only after final auth. */
  onEntry?: (entry: EncryptedBackupEntry) => void | Promise<void>;
}>;

export type RestoreVerificationSession = Readonly<{
  readonly vaultRootKey: VaultRootKey;
  readonly selectedSlot: RestoreKnownRecordsVerificationV1['selectedSlot'];
  verify(
    entries: AsyncIterable<EncryptedBackupEntry>,
    summary: BackupVerification,
  ): Promise<RestoreKnownRecordsVerificationV1>;
  close(): void;
}>;

export type RestoreVerificationSessionFactory = (
  vault: VaultRecord,
) => Promise<RestoreVerificationSession>;

export type RestoreEncryptedBackupResult =
  | Readonly<{
      disposition: 'verified-and-committed';
      backup: BackupVerification;
      verification: RestoreKnownRecordsVerificationV1;
    }>
  | Readonly<{
      disposition: 'previously-committed';
      backup: BackupVerification;
    }>;

type Transcript = Readonly<{
  update(line: Uint8Array): void;
  finish(): Readonly<{ digest: Uint8Array; authenticationTag: Uint8Array }>;
}>;

type ProcessSetup = Readonly<{
  vaultRootKey: VaultRootKey;
  onEntry?: (entry: EncryptedBackupEntry) => Promise<void>;
}>;

type ProcessSetupFactory = (input: {
  readonly header: EncryptedBackupHeader;
  readonly vault: VaultRecord;
  readonly restoreSessionId: Sha256Digest;
  readonly limits: ResolvedBackupLimits;
}) => Promise<ProcessSetup>;

interface RestoreRecoveryContext {
  initialState?: BackupRestoreStatus['state'];
  publicationMayHaveStarted: boolean;
}

export async function* createEncryptedBackup(
  input: CreateEncryptedBackupInput,
  vaultRootKey: VaultRootKey,
): AsyncGenerator<Uint8Array> {
  requireByteLength(vaultRootKey, AUTH_KEY_BYTES, 'vault root key');
  const limits = resolveBackupLimits(input.limits);
  const salt = randomBytes(AUTH_KEY_BYTES);
  const authenticationKey = deriveAuthenticationKey(vaultRootKey, salt);
  const header = parseSchema(encryptedBackupHeaderSchema, {
    type: 'header',
    format: 'kavrix-encrypted-backup',
    version: 1,
    vaultId: input.vault.id,
    schemaVersion: input.vault.schemaVersion,
    createdAt: input.createdAt ?? new Date().toISOString(),
    authentication: {
      algorithm: 'hkdf-sha256+hmac-sha256',
      salt: encodeBase64Url(salt),
    },
  });
  const transcript = createTranscript(authenticationKey);
  const recordSet = new BackupRecordSet(header.vaultId, limits.maximumRecords);
  let emittedBytes = 0;

  try {
    const headerLine = encodeTranscriptLine(header, transcript);
    emittedBytes = accountOutputBytes(emittedBytes, headerLine, limits.maximumBytes);
    yield headerLine;

    const vaultEntry = parseSchema(encryptedBackupEntrySchema, {
      kind: 'vault',
      record: input.vault,
    });
    recordSet.accept(vaultEntry);
    const vaultLine = encodeTranscriptLine(vaultEntry, transcript);
    emittedBytes = accountOutputBytes(emittedBytes, vaultLine, limits.maximumBytes);
    yield vaultLine;

    for await (const candidate of input.records) {
      const entry = parseSchema(encryptedBackupEntrySchema, candidate);
      recordSet.accept(entry);
      const line = encodeTranscriptLine(entry, transcript);
      emittedBytes = accountOutputBytes(emittedBytes, line, limits.maximumBytes);
      yield line;
    }

    recordSet.finish();
    const finished = transcript.finish();
    try {
      const footer = parseSchema(encryptedBackupFooterSchema, {
        type: 'footer',
        version: 1,
        recordCount: recordSet.recordCount,
        transcriptSha256: encodeBase64Url(finished.digest),
        authenticationTag: encodeBase64Url(finished.authenticationTag),
      });
      const footerLine = encodeJsonLine(footer);
      accountOutputBytes(emittedBytes, footerLine, limits.maximumBytes);
      yield footerLine;
    } finally {
      zeroize(finished.digest);
      zeroize(finished.authenticationTag);
    }
  } finally {
    zeroize(authenticationKey);
    zeroize(salt);
  }
}

export async function verifyEncryptedBackup(
  source: AsyncIterable<Uint8Array>,
  vaultRootKey: VaultRootKey,
  expectedVaultId: VaultId,
  limits?: BackupLimits,
  options?: VerifyEncryptedBackupOptions,
): Promise<BackupVerification> {
  return processEncryptedBackup(
    source,
    expectedVaultId,
    resolveBackupLimits(limits),
    () =>
      Promise.resolve({
        vaultRootKey,
        ...(options?.onEntry === undefined
          ? {}
          : {
              onEntry: async (entry: EncryptedBackupEntry): Promise<void> => {
                await options.onEntry?.(entry);
              },
            }),
      }),
  );
}

export async function restoreEncryptedBackup(
  source: AsyncIterable<Uint8Array>,
  expectedVaultId: VaultId,
  store: BackupRestoreStore,
  openVerification: RestoreVerificationSessionFactory,
  limitsInput?: BackupLimits,
): Promise<RestoreEncryptedBackupResult> {
  const limits = resolveBackupLimits(limitsInput);
  let stager: BackupRestoreStager | undefined;
  let initialStatus: BackupRestoreStatus | undefined;
  let session: RestoreVerificationSession | undefined;
  let capturedVaultRootKey: VaultRootKey | undefined;
  let summary: BackupVerification | undefined;
  let result: RestoreEncryptedBackupResult | undefined;
  let failure: unknown;
  const recovery: RestoreRecoveryContext = {
    publicationMayHaveStarted: false,
  };

  try {
    summary = await processEncryptedBackup(
      source,
      expectedVaultId,
      limits,
      async ({ vault, restoreSessionId }) => {
        try {
          session = await openVerification(vault);
          capturedVaultRootKey = session.vaultRootKey;
          requireByteLength(capturedVaultRootKey, AUTH_KEY_BYTES, 'vault root key');
        } catch {
          throw authenticationFailure();
        }
        let statusCandidate: unknown;
        try {
          stager = await store.open(restoreSessionId, limits);
          statusCandidate = await stager.status();
        } catch {
          throw commitUncertain();
        }
        initialStatus = parseRestoreStatus(statusCandidate);
        recovery.initialState = initialStatus.state;
        assertInitialStatus(initialStatus, restoreSessionId, vault.id, limits);
        return {
          vaultRootKey: capturedVaultRootKey,
          ...(initialStatus.state === 'staging'
            ? {
                async onEntry(entry: EncryptedBackupEntry): Promise<void> {
                  try {
                    await requireDefined(stager).write(entry);
                  } catch {
                    throw authenticationFailure();
                  }
                },
              }
            : {}),
        };
      },
    );
    const readyStager = requireDefined(stager);
    const readyStatus = requireDefined(initialStatus);
    const readySession = requireDefined(session);
    assertFrozenSummary(readyStatus, summary);
    result = await coordinateRestore(
      readyStager,
      readySession,
      readyStatus,
      summary,
      recovery,
    );
  } catch (error) {
    failure = await reconcileFailure(stager, initialStatus, summary, error, recovery);
  } finally {
    let cleanupFailed = false;
    try {
      session?.close();
    } catch {
      cleanupFailed = true;
    } finally {
      try {
        zeroize(capturedVaultRootKey);
      } catch {
        cleanupFailed = true;
      }
    }
    if (cleanupFailed && !isCommitUncertain(failure)) {
      failure = authenticationFailure();
    }
  }
  if (failure !== undefined) {
    throw failure instanceof Error ? failure : authenticationFailure();
  }
  return requireDefined(result);
}

async function processEncryptedBackup(
  source: AsyncIterable<Uint8Array>,
  expectedVaultId: VaultId,
  limits: ResolvedBackupLimits,
  setupFactory: ProcessSetupFactory,
): Promise<BackupVerification> {
  const expectedId = vaultIdSchema.parse(expectedVaultId);
  const iterator = splitBackupLines(sanitizeSource(source), limits.maximumBytes)[
    Symbol.asyncIterator
  ]();
  let header: EncryptedBackupHeader | undefined;
  let footer: EncryptedBackupFooter | undefined;
  let transcript: Transcript | undefined;
  let authenticationKey: Uint8Array | undefined;
  let restoreSessionId: Sha256Digest | undefined;
  let headerLine: Uint8Array | undefined;
  let vaultLine: Uint8Array | undefined;
  let eof = false;
  const recordSet = new BackupRecordSet(expectedId, limits.maximumRecords);
  const commitment = createBackupStagedEntryCommitment();

  try {
    const first = await iterator.next();
    if (first.done) {
      eof = true;
      throw incompleteBackup();
    }
    headerLine = first.value;
    header = parseSchema(encryptedBackupHeaderSchema, parseJsonLine(headerLine));
    if (header.vaultId !== expectedId) {
      throw new BackupError(
        'BACKUP_WRONG_VAULT',
        'The encrypted backup belongs to a different vault.',
      );
    }
    restoreSessionId = restoreSessionIdForHeader(headerLine);

    const second = await iterator.next();
    if (second.done) {
      eof = true;
      throw incompleteBackup();
    }
    vaultLine = second.value;
    const vaultEntry = parseSchema(
      encryptedBackupEntrySchema,
      parseJsonLine(vaultLine),
    );
    if (
      vaultEntry.kind !== 'vault' ||
      vaultEntry.record.id !== header.vaultId ||
      vaultEntry.record.schemaVersion !== header.schemaVersion
    ) {
      throw new BackupError(
        'BACKUP_INVALID',
        'The encrypted backup leading vault does not match its header.',
      );
    }

    const setup = await setupFactory({
      header,
      vault: vaultEntry.record,
      restoreSessionId,
      limits,
    });
    requireByteLength(setup.vaultRootKey, AUTH_KEY_BYTES, 'vault root key');
    const salt = decodeBackupBytes(header.authentication.salt);
    try {
      authenticationKey = deriveAuthenticationKey(setup.vaultRootKey, salt);
    } finally {
      zeroize(salt);
    }
    transcript = createTranscript(authenticationKey);
    transcript.update(headerLine);
    transcript.update(vaultLine);
    recordSet.accept(vaultEntry);
    commitment.update(vaultEntry);
    await setup.onEntry?.(vaultEntry);
    zeroize(headerLine);
    headerLine = undefined;
    zeroize(vaultLine);
    vaultLine = undefined;

    for (;;) {
      const next = await iterator.next();
      if (next.done) {
        eof = true;
        break;
      }
      const line = next.value;
      try {
        if (footer !== undefined) {
          throw new BackupError(
            'BACKUP_INVALID',
            'The encrypted backup contains data after its footer.',
          );
        }
        const value = parseJsonLine(line);
        if (isFooterCandidate(value)) {
          footer = parseSchema(encryptedBackupFooterSchema, value);
          continue;
        }
        const entry = parseSchema(encryptedBackupEntrySchema, value);
        recordSet.accept(entry);
        transcript.update(line);
        commitment.update(entry);
        await setup.onEntry?.(entry);
      } finally {
        zeroize(line);
      }
    }

    if (footer === undefined) throw incompleteBackup();
    recordSet.finish();
    if (recordSet.recordCount !== footer.recordCount) {
      throw new BackupError(
        'BACKUP_INVALID',
        'The encrypted backup record count is inconsistent.',
      );
    }

    const finished = transcript.finish();
    const suppliedDigest = decodeBackupBytes(footer.transcriptSha256);
    const suppliedTag = decodeBackupBytes(footer.authenticationTag);
    try {
      if (
        !timingSafeEqual(finished.digest, suppliedDigest) ||
        !timingSafeEqual(finished.authenticationTag, suppliedTag)
      ) {
        throw new BackupError(
          'BACKUP_AUTHENTICATION_FAILED',
          'The encrypted backup could not be authenticated.',
        );
      }
      return parseSchema(backupVerificationSchema, {
        header,
        restoreSessionId,
        recordCount: recordSet.recordCount,
        transcriptSha256: footer.transcriptSha256,
        canonicalEntriesSha256: commitment.finalize(),
      });
    } finally {
      zeroize(finished.digest);
      zeroize(finished.authenticationTag);
      zeroize(suppliedDigest);
      zeroize(suppliedTag);
    }
  } finally {
    if (!eof) {
      try {
        await iterator.return(undefined);
      } catch {
        // The public failure remains sanitized by the owning API.
      }
    }
    zeroize(headerLine);
    zeroize(vaultLine);
    zeroize(authenticationKey);
  }
}

async function coordinateRestore(
  stager: BackupRestoreStager,
  session: RestoreVerificationSession,
  initialStatus: BackupRestoreStatus,
  summary: BackupVerification,
  recovery: RestoreRecoveryContext,
): Promise<RestoreEncryptedBackupResult> {
  if (initialStatus.state === 'aborted') throw authenticationFailure();
  if (initialStatus.state === 'committed') {
    return { disposition: 'previously-committed', backup: summary };
  }

  let state = initialStatus;
  if (state.state === 'staging') {
    state = await sealAndReconcile(stager, summary, state);
  }

  let receipt = await verifySealed(stager, session, summary);
  if (state.state === 'sealed') {
    const publication = await publishAndReconcile(
      stager,
      session,
      summary,
      receipt,
      recovery,
    );
    receipt = publication.receipt;
    if (publication.status.state === 'committed') {
      return verifiedResult(summary, receipt);
    }
  }
  recovery.publicationMayHaveStarted = true;
  await finalizeAndReconcile(stager, summary, receipt);
  return verifiedResult(summary, receipt);
}

async function sealAndReconcile(
  stager: BackupRestoreStager,
  summary: BackupVerification,
  initialStatus: Extract<BackupRestoreStatus, { state: 'staging' }>,
): Promise<Extract<BackupRestoreStatus, { state: 'sealed' }>> {
  let failed = false;
  try {
    await stager.seal(summary);
  } catch {
    failed = true;
  }
  const status = await readExactStatusOrUncertain(stager, summary, initialStatus);
  if (status.state === 'sealed') return status;
  if (status.state === 'staging') {
    await abortDefiniteHiddenState(stager, status, commitUncertain());
  }
  if (failed) throw commitUncertain();
  throw commitUncertain();
}

async function publishAndReconcile(
  stager: BackupRestoreStager,
  session: RestoreVerificationSession,
  summary: BackupVerification,
  initialReceipt: RestoreKnownRecordsVerificationV1,
  recovery: RestoreRecoveryContext,
): Promise<{
  readonly receipt: RestoreKnownRecordsVerificationV1;
  readonly status: Extract<BackupRestoreStatus, { state: 'published' | 'committed' }>;
}> {
  let receipt = initialReceipt;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let failed = false;
    try {
      recovery.publicationMayHaveStarted = true;
      await stager.publish(summary, receipt);
    } catch {
      failed = true;
    }
    const status = await readExactStatusOrUncertain(stager, summary, undefined);
    if (status.state === 'published' || status.state === 'committed') {
      return { receipt, status };
    }
    if (status.state === 'sealed' && failed && attempt === 0) {
      receipt = await verifySealed(stager, session, summary);
      continue;
    }
    if (status.state === 'sealed') {
      await abortDefiniteHiddenState(stager, status, commitUncertain());
    }
    throw commitUncertain();
  }
  throw commitUncertain();
}

async function finalizeAndReconcile(
  stager: BackupRestoreStager,
  summary: BackupVerification,
  receipt: RestoreKnownRecordsVerificationV1,
): Promise<void> {
  try {
    await stager.finalize(summary, receipt);
  } catch {
    // The exact durable state below is authoritative.
  }
  const status = await readExactStatusOrUncertain(stager, summary, undefined);
  if (status.state === 'committed') return;
  throw commitUncertain();
}

async function verifySealed(
  stager: BackupRestoreStager,
  session: RestoreVerificationSession,
  summary: BackupVerification,
): Promise<RestoreKnownRecordsVerificationV1> {
  let iterator: AsyncIterator<EncryptedBackupEntry> | undefined;
  const readback = { eof: false };
  let claimed = false;
  let cleanupFailed = false;
  let candidate: unknown;
  let verificationFailure: unknown;
  try {
    iterator = stager.readSealed(summary)[Symbol.asyncIterator]();
    const guarded: AsyncIterable<EncryptedBackupEntry> = {
      [Symbol.asyncIterator](): AsyncIterator<EncryptedBackupEntry> {
        if (claimed) throw authenticationFailure();
        claimed = true;
        return {
          async next(): Promise<IteratorResult<EncryptedBackupEntry>> {
            const next = await requireDefined(iterator).next();
            if (next.done) readback.eof = true;
            return next;
          },
          async return(): Promise<IteratorResult<EncryptedBackupEntry>> {
            const active = requireDefined(iterator);
            if (active.return === undefined) {
              return { done: true, value: undefined };
            }
            return active.return();
          },
        };
      },
    };
    candidate = await session.verify(guarded, summary);
    if (!readback.eof) verificationFailure = authenticationFailure();
  } catch (error) {
    verificationFailure = mapVerificationFailure(error);
  } finally {
    if (!readback.eof && iterator?.return !== undefined) {
      try {
        await iterator.return();
      } catch {
        cleanupFailed = true;
      }
    }
  }
  if (verificationFailure !== undefined) {
    throw verificationFailure instanceof Error
      ? verificationFailure
      : authenticationFailure();
  }
  if (cleanupFailed) throw authenticationFailure();
  const receipt = parseReceipt(candidate);
  assertReceiptBinding(receipt, summary, session.selectedSlot);
  return receipt;
}

function assertReceiptBinding(
  receipt: RestoreKnownRecordsVerificationV1,
  summary: BackupVerification,
  selectedSlot: RestoreKnownRecordsVerificationV1['selectedSlot'],
): void {
  if (
    receipt.vaultId !== summary.header.vaultId ||
    receipt.restoreSessionId !== summary.restoreSessionId ||
    receipt.transcriptSha256 !== summary.transcriptSha256 ||
    receipt.canonicalEntriesSha256 !== summary.canonicalEntriesSha256 ||
    receipt.recordCount !== summary.recordCount ||
    receipt.selectedSlot.id !== selectedSlot.id ||
    receipt.selectedSlot.type !== selectedSlot.type ||
    receipt.selectedSlot.keyVersion !== selectedSlot.keyVersion
  ) {
    throw authenticationFailure();
  }
}

function parseReceipt(candidate: unknown): RestoreKnownRecordsVerificationV1 {
  const parsed = restoreKnownRecordsVerificationV1Schema.safeParse(candidate);
  if (!parsed.success) throw authenticationFailure();
  return parsed.data;
}

function parseRestoreStatus(candidate: unknown): BackupRestoreStatus {
  const parsed = backupRestoreStatusSchema.safeParse(candidate);
  if (!parsed.success) throw authenticationFailure();
  return parsed.data;
}

async function readStatusOrUncertain(
  stager: BackupRestoreStager,
): Promise<BackupRestoreStatus> {
  try {
    return parseRestoreStatus(await stager.status());
  } catch {
    throw commitUncertain();
  }
}

async function readExactStatusOrUncertain(
  stager: BackupRestoreStager,
  summary: BackupVerification,
  expectedHidden: BackupRestoreStatus | undefined,
): Promise<BackupRestoreStatus> {
  const status = await readStatusOrUncertain(stager);
  try {
    assertFrozenSummary(status, summary);
    if (
      status.state === 'staging' &&
      (!isExactAbortableHiddenStatus(status, expectedHidden, summary) ||
        status.stagedRecords !== summary.recordCount ||
        status.vaultId !== summary.header.vaultId)
    ) {
      throw commitUncertain();
    }
    return status;
  } catch {
    throw commitUncertain();
  }
}

function assertInitialStatus(
  status: BackupRestoreStatus,
  restoreSessionId: Sha256Digest,
  vaultId: VaultId,
  limits: ResolvedBackupLimits,
): void {
  if (status.restoreSessionId !== restoreSessionId) throw authenticationFailure();
  if ('maximumBytes' in status) {
    if (
      status.maximumBytes !== limits.maximumBytes ||
      status.maximumRecords !== limits.maximumRecords ||
      (status.stagedRecords > 0 && status.vaultId !== vaultId)
    ) {
      throw authenticationFailure();
    }
  }
}

function assertFrozenSummary(
  status: BackupRestoreStatus,
  summary: BackupVerification,
): void {
  if (
    status.state !== 'staging' &&
    status.state !== 'aborted' &&
    canonicalJson(status.summary) !== canonicalJson(summary)
  ) {
    throw authenticationFailure();
  }
}

async function reconcileFailure(
  stager: BackupRestoreStager | undefined,
  initialStatus: BackupRestoreStatus | undefined,
  summary: BackupVerification | undefined,
  error: unknown,
  recovery: RestoreRecoveryContext,
): Promise<unknown> {
  const safe = mapCoordinatorFailure(error);
  if (stager === undefined || isCommitUncertain(safe)) return safe;
  if (initialStatus === undefined) return safe;
  if (
    recovery.initialState === 'committed' ||
    (recovery.initialState === 'published' && !recovery.publicationMayHaveStarted)
  ) {
    return safe;
  }
  let status: BackupRestoreStatus;
  try {
    status = parseRestoreStatus(await stager.status());
  } catch {
    return commitUncertain();
  }
  if (status.state === 'published' || status.state === 'committed') {
    return commitUncertain();
  }
  if (status.state !== 'staging' && status.state !== 'sealed') {
    return safe;
  }
  if (!isExactAbortableHiddenStatus(status, initialStatus, summary)) {
    return commitUncertain();
  }
  try {
    await abortDefiniteHiddenState(stager, status, safe);
    return safe;
  } catch (abortFailure) {
    return abortFailure;
  }
}

function isExactAbortableHiddenStatus(
  status: Extract<BackupRestoreStatus, { state: 'staging' | 'sealed' }>,
  initialStatus: BackupRestoreStatus | undefined,
  summary: BackupVerification | undefined,
): boolean {
  if (status.state === 'sealed') {
    if (
      initialStatus?.state === 'sealed' &&
      canonicalJson(status) === canonicalJson(initialStatus)
    ) {
      return true;
    }
    if (summary !== undefined) {
      return canonicalJson(status.summary) === canonicalJson(summary);
    }
    return false;
  }
  if (initialStatus?.state !== 'staging') return false;
  return (
    status.restoreSessionId === initialStatus.restoreSessionId &&
    status.maximumBytes === initialStatus.maximumBytes &&
    status.maximumRecords === initialStatus.maximumRecords &&
    (status.vaultId === undefined ||
      summary === undefined ||
      status.vaultId === summary.header.vaultId)
  );
}

async function abortDefiniteHiddenState(
  stager: BackupRestoreStager,
  expectedHidden: Extract<BackupRestoreStatus, { state: 'staging' | 'sealed' }>,
  originalFailure: unknown,
): Promise<never> {
  try {
    await stager.abort();
  } catch {
    // Reconcile below without retaining the unsafe operational exception.
  }
  let status: BackupRestoreStatus;
  try {
    status = parseRestoreStatus(await stager.status());
  } catch {
    throw commitUncertain();
  }
  if (
    status.state === 'aborted' &&
    status.restoreSessionId === expectedHidden.restoreSessionId
  ) {
    throw mapCoordinatorFailure(originalFailure);
  }
  if (status.state === 'staging' || status.state === 'sealed') {
    if (!isSameHiddenStatus(status, expectedHidden)) throw commitUncertain();
    throw new AggregateError(
      [
        mapCoordinatorFailure(originalFailure),
        new Error('Backup hidden staging cleanup failed.'),
      ],
      'Backup restore failed and its hidden staging area could not be aborted.',
    );
  }
  throw commitUncertain();
}

function isSameHiddenStatus(
  status: Extract<BackupRestoreStatus, { state: 'staging' | 'sealed' }>,
  expected: Extract<BackupRestoreStatus, { state: 'staging' | 'sealed' }>,
): boolean {
  return canonicalJson(status) === canonicalJson(expected);
}

function mapVerificationFailure(error: unknown): BackupError {
  if (isSafeVerifierFailure(error)) {
    return error.kind === 'unsupported'
      ? new BackupError(
          'BACKUP_DECRYPTABILITY_UNSUPPORTED',
          'Encrypted backup decryptability verification is unsupported.',
        )
      : authenticationFailure();
  }
  return authenticationFailure();
}

function mapCoordinatorFailure(error: unknown): BackupError {
  if (error instanceof BackupError) {
    return new BackupError(error.code, error.message);
  }
  return mapVerificationFailure(error);
}

function isSafeVerifierFailure(error: unknown): error is Error & {
  readonly safe: true;
  readonly kind: 'invalid' | 'unsupported';
} {
  return (
    error instanceof Error &&
    error.name === 'RestoreKnownRecordsVerificationError' &&
    error.message === 'Encrypted backup decryptability verification failed.' &&
    'safe' in error &&
    error.safe === true &&
    'kind' in error &&
    (error.kind === 'invalid' || error.kind === 'unsupported')
  );
}

function authenticationFailure(): BackupError {
  return new BackupError(
    'BACKUP_AUTHENTICATION_FAILED',
    'The encrypted backup could not be authenticated.',
  );
}

function commitUncertain(): BackupError {
  return new BackupError(
    'BACKUP_COMMIT_UNCERTAIN',
    'The authenticated backup state could not be reconciled; retry the same restore session.',
  );
}

function isCommitUncertain(error: unknown): boolean {
  return error instanceof BackupError && error.code === 'BACKUP_COMMIT_UNCERTAIN';
}

function incompleteBackup(): BackupError {
  return new BackupError(
    'BACKUP_INCOMPLETE',
    'The encrypted backup header or footer is missing.',
  );
}

function sanitizeSource(source: AsyncIterable<Uint8Array>): AsyncIterable<Uint8Array> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      let iterator: AsyncIterator<Uint8Array>;
      try {
        iterator = source[Symbol.asyncIterator]();
      } catch {
        throw authenticationFailure();
      }
      return {
        async next(): Promise<IteratorResult<Uint8Array>> {
          try {
            return await iterator.next();
          } catch {
            throw authenticationFailure();
          }
        },
        async return(): Promise<IteratorResult<Uint8Array>> {
          if (iterator.return === undefined) {
            return { done: true, value: undefined };
          }
          try {
            return await iterator.return();
          } catch {
            throw authenticationFailure();
          }
        },
      };
    },
  };
}

function verifiedResult(
  backup: BackupVerification,
  verification: RestoreKnownRecordsVerificationV1,
): RestoreEncryptedBackupResult {
  return { disposition: 'verified-and-committed', backup, verification };
}

function requireDefined<Value>(value: Value | undefined): Value {
  if (value === undefined) throw authenticationFailure();
  return value;
}

class BackupRecordSet {
  readonly #vaultId: VaultId;
  readonly #maximumRecords: number;
  readonly #identities = new Set<string>();
  readonly #groups = new Set<string>();
  readonly #items = new Map<string, string>();
  readonly #attachments = new Map<string, AttachmentState>();
  readonly #tombstonePredecessors = new Map<string, TombstonePredecessor>();
  readonly #tombstones: Readonly<{
    type: string;
    id: string;
    state: 'deleted' | 'restored';
  }>[] = [];
  #sawVault = false;
  recordCount = 0;

  constructor(vaultId: VaultId, maximumRecords: number) {
    this.#vaultId = vaultId;
    this.#maximumRecords = maximumRecords;
  }

  accept(entry: EncryptedBackupEntry): void {
    if (this.recordCount >= this.#maximumRecords) {
      throw new BackupError(
        'BACKUP_TOO_LARGE',
        'The encrypted backup contains too many records.',
      );
    }
    assertCanonicalAttachmentHash(entry);
    if (!this.#sawVault && entry.kind !== 'vault') {
      throw new BackupError(
        'BACKUP_INVALID',
        'The first encrypted backup record must be its vault record.',
      );
    }
    assertEntryVault(entry, this.#vaultId);

    switch (entry.kind) {
      case 'vault':
        this.#unique('vault', entry.record.id);
        if (this.#sawVault) {
          throw new BackupError(
            'BACKUP_INVALID',
            'The encrypted backup contains duplicate vault records.',
          );
        }
        this.#sawVault = true;
        break;
      case 'group':
        this.#unique('group', entry.record.id);
        this.#groups.add(entry.record.id);
        break;
      case 'item':
        this.#requireGroup(entry.record.groupId);
        this.#unique('item', entry.record.id);
        this.#items.set(entry.record.id, entry.record.groupId);
        break;
      case 'attachment': {
        this.#requireItem(entry.record.itemId, entry.record.groupId);
        this.#unique('attachment', entry.record.id);
        this.#attachments.set(entry.record.id, {
          groupId: entry.record.groupId,
          itemId: entry.record.itemId,
          schemaVersion: entry.record.schemaVersion,
          keyVersion: entry.record.encryptedManifest.aad.keyVersion,
          recordRevision: entry.record.recordRevision,
          chunkCount: entry.record.chunkCount,
          headerSeen: false,
          nextChunkIndex: 0,
          finalSeen: false,
        });
        break;
      }
      case 'attachment-header': {
        const identity = entry.record.record;
        const attachment = this.#requireAttachment(
          identity.attachmentId,
          identity.groupId,
          identity.itemId,
          identity.schemaVersion,
          identity.keyVersion,
          entry.record.recordRevision,
        );
        this.#unique('attachment-header', identity.attachmentId);
        if (attachment.headerSeen) {
          throw new BackupError('BACKUP_INVALID', 'Duplicate attachment header.');
        }
        attachment.headerSeen = true;
        break;
      }
      case 'attachment-chunk': {
        const identity = entry.record.record;
        const attachment = this.#requireAttachment(
          identity.attachmentId,
          identity.groupId,
          identity.itemId,
          identity.schemaVersion,
          identity.keyVersion,
          entry.record.recordRevision,
        );
        if (!attachment.headerSeen || identity.index !== attachment.nextChunkIndex) {
          throw new BackupError(
            'BACKUP_INVALID',
            'Attachment chunks must follow one header in contiguous order.',
          );
        }
        this.#unique(
          'attachment-chunk',
          `${identity.attachmentId}:${String(identity.index)}`,
        );
        const isLast = identity.index === attachment.chunkCount - 1;
        if (
          (isLast && identity.tag !== 'final') ||
          (!isLast && identity.tag !== 'message')
        ) {
          throw new BackupError(
            'BACKUP_INVALID',
            'Attachment final-tag position does not match its chunk count.',
          );
        }
        attachment.nextChunkIndex += 1;
        attachment.finalSeen = isLast;
        break;
      }
      case 'audit':
        this.#unique('audit', entry.record.id);
        break;
      case 'history':
        this.#requireItem(entry.record.itemId, entry.record.groupId);
        this.#unique('history', entry.record.id);
        break;
      case 'tombstone-predecessor': {
        const key = `${entry.entityType}:${entry.record.id}`;
        if (!this.#identities.has(key)) {
          throw new BackupError(
            'BACKUP_INCOMPLETE',
            'A tombstone predecessor is missing its current opaque record.',
          );
        }
        this.#unique(`tombstone-predecessor:${entry.entityType}`, entry.record.id);
        this.#tombstonePredecessors.set(key, entry.record);
        break;
      }
      case 'tombstone': {
        this.#unique(`tombstone:${entry.record.entityType}`, entry.record.entityId);
        const key = `${entry.record.entityType}:${entry.record.entityId}`;
        const predecessor = this.#tombstonePredecessors.get(key);
        if (entry.record.state === 'deleted' && entry.record.entityType !== 'vault') {
          if (predecessor === undefined) {
            throw new BackupError(
              'BACKUP_INCOMPLETE',
              'A deleted record is missing its authenticated tombstone predecessor.',
            );
          }
          if (
            predecessor.recordRevision !== entry.record.lastRecordRevision ||
            contentHashForRecord(predecessor) !== entry.record.lastCiphertextHash
          ) {
            throw new BackupError(
              'BACKUP_INVALID',
              'A deleted tombstone does not authenticate its predecessor.',
            );
          }
        }
        this.#tombstones.push({
          type: entry.record.entityType,
          id: entry.record.entityId,
          state: entry.record.state,
        });
        break;
      }
    }
    this.recordCount += 1;
  }

  finish(): void {
    if (!this.#sawVault) {
      throw new BackupError('BACKUP_INCOMPLETE', 'The vault record is missing.');
    }
    for (const attachment of this.#attachments.values()) {
      if (
        !attachment.headerSeen ||
        !attachment.finalSeen ||
        attachment.nextChunkIndex !== attachment.chunkCount
      ) {
        throw new BackupError(
          'BACKUP_INCOMPLETE',
          'An attachment header or contiguous chunk set is incomplete.',
        );
      }
    }
    for (const tombstone of this.#tombstones) {
      if (!this.#identities.has(`${tombstone.type}:${tombstone.id}`)) {
        throw new BackupError(
          'BACKUP_INCOMPLETE',
          'A tombstone is missing its corresponding opaque record.',
        );
      }
      if (
        tombstone.state === 'deleted' &&
        tombstone.type !== 'vault' &&
        !this.#tombstonePredecessors.has(`${tombstone.type}:${tombstone.id}`)
      ) {
        throw new BackupError(
          'BACKUP_INCOMPLETE',
          'A deleted record is missing its authenticated tombstone predecessor.',
        );
      }
    }
  }

  #unique(type: string, id: string): void {
    const key = `${type}:${id}`;
    if (this.#identities.has(key)) {
      throw new BackupError(
        'BACKUP_INVALID',
        'The encrypted backup contains a duplicate record identity.',
      );
    }
    this.#identities.add(key);
  }

  #requireGroup(groupId: string): void {
    if (!this.#groups.has(groupId)) {
      throw new BackupError(
        'BACKUP_INCOMPLETE',
        'An encrypted backup item is missing its parent group.',
      );
    }
  }

  #requireItem(itemId: string, groupId: string): void {
    if (this.#items.get(itemId) !== groupId) {
      throw new BackupError(
        'BACKUP_INCOMPLETE',
        'An encrypted backup record is missing its parent item.',
      );
    }
  }

  #requireAttachment(
    attachmentId: string,
    groupId: string,
    itemId: string,
    schemaVersion: number,
    keyVersion: number,
    recordRevision: number,
  ): AttachmentState {
    const attachment = this.#attachments.get(attachmentId);
    if (
      attachment?.groupId !== groupId ||
      attachment.itemId !== itemId ||
      attachment.schemaVersion !== schemaVersion ||
      attachment.keyVersion !== keyVersion ||
      attachment.recordRevision !== recordRevision
    ) {
      throw new BackupError(
        'BACKUP_INCOMPLETE',
        'Attachment stream records do not match their encrypted metadata.',
      );
    }
    return attachment;
  }
}

function assertCanonicalAttachmentHash(entry: EncryptedBackupEntry): void {
  const matches =
    entry.kind === 'attachment-header' || entry.kind === 'attachment-chunk'
      ? attachmentRecordHashMatchesCanonicalContent(entry.record)
      : true;
  if (!matches) {
    throw new BackupError(
      'BACKUP_INVALID',
      'An attachment backup record has a noncanonical content hash.',
    );
  }
}

interface AttachmentState {
  readonly groupId: string;
  readonly itemId: string;
  readonly schemaVersion: number;
  readonly keyVersion: number;
  readonly recordRevision: number;
  readonly chunkCount: number;
  headerSeen: boolean;
  nextChunkIndex: number;
  finalSeen: boolean;
}

type TombstonePredecessor = Extract<
  EncryptedBackupEntry,
  { kind: 'tombstone-predecessor' }
>['record'];

function assertEntryVault(entry: EncryptedBackupEntry, vaultId: VaultId): void {
  const entryVaultId =
    entry.kind === 'vault'
      ? entry.record.id
      : entry.kind === 'attachment-header' || entry.kind === 'attachment-chunk'
        ? entry.record.record.vaultId
        : entry.record.vaultId;
  if (entryVaultId !== vaultId) {
    throw new BackupError(
      'BACKUP_WRONG_VAULT',
      'An encrypted backup record belongs to a different vault.',
    );
  }
}

function createTranscript(authenticationKey: Uint8Array): Transcript {
  const digest = createHash('sha256');
  const authentication = createHmac('sha256', authenticationKey);
  let finished = false;
  return {
    update(line): void {
      if (finished || line.byteLength > MAX_BACKUP_LINE_BYTES) {
        throw new BackupError('BACKUP_INVALID', 'Invalid backup transcript state.');
      }
      const length = Buffer.allocUnsafe(4);
      length.writeUInt32BE(line.byteLength);
      digest.update(length).update(line);
      authentication.update(length).update(line);
      length.fill(0);
    },
    finish() {
      if (finished) {
        throw new BackupError('BACKUP_INVALID', 'Backup transcript already finalized.');
      }
      finished = true;
      return {
        digest: Uint8Array.from(digest.digest()),
        authenticationTag: Uint8Array.from(authentication.digest()),
      };
    },
  };
}

function deriveAuthenticationKey(
  vaultRootKey: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  const result = hkdfSync(
    'sha256',
    vaultRootKey,
    salt,
    BACKUP_AUTH_INFO,
    AUTH_KEY_BYTES,
  );
  const bytes = new Uint8Array(result);
  try {
    return Uint8Array.from(bytes);
  } finally {
    zeroize(bytes);
  }
}

function restoreSessionIdForHeader(headerLine: Uint8Array): Sha256Digest {
  return parseSchema(
    sha256DigestSchema,
    createHash('sha256')
      .update(RESTORE_SESSION_DOMAIN)
      .update(headerLine)
      .digest('base64url'),
  );
}

function encodeTranscriptLine(value: unknown, transcript: Transcript): Uint8Array {
  const line = encodeJson(value);
  transcript.update(line);
  const framed = Buffer.allocUnsafe(line.byteLength + 1);
  framed.set(line);
  framed[line.byteLength] = 0x0a;
  zeroize(line);
  return framed;
}

function encodeJsonLine(value: unknown): Uint8Array {
  const line = encodeJson(value);
  const framed = Buffer.allocUnsafe(line.byteLength + 1);
  framed.set(line);
  framed[line.byteLength] = 0x0a;
  zeroize(line);
  return framed;
}

function encodeJson(value: unknown): Uint8Array {
  const encoded = Buffer.from(JSON.stringify(value), 'utf8');
  if (encoded.byteLength === 0 || encoded.byteLength > MAX_BACKUP_LINE_BYTES) {
    zeroize(encoded);
    throw new BackupError(
      'BACKUP_TOO_LARGE',
      'A backup record exceeds the size limit.',
    );
  }
  return encoded;
}

function parseJsonLine(line: Uint8Array): unknown {
  try {
    return JSON.parse(Buffer.from(line).toString('utf8')) as unknown;
  } catch (error) {
    throw new BackupError('BACKUP_INVALID', 'The encrypted backup is malformed.', {
      cause: error,
    });
  }
}

function isFooterCandidate(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    'type' in value &&
    value.type === 'footer'
  );
}

function parseSchema<Output>(
  schema: {
    safeParse(
      value: unknown,
    ): { success: true; data: Output } | { success: false; error?: unknown };
  },
  value: unknown,
): Output {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new BackupError('BACKUP_INVALID', 'The encrypted backup is malformed.', {
      ...(parsed.error === undefined ? {} : { cause: parsed.error }),
    });
  }
  return parsed.data;
}

function decodeBackupBytes(value: string): Uint8Array {
  try {
    return decodeBase64Url(value, { exactBytes: AUTH_KEY_BYTES });
  } catch (error) {
    throw new BackupError('BACKUP_INVALID', 'The encrypted backup is malformed.', {
      cause: error,
    });
  }
}

function accountOutputBytes(
  current: number,
  line: Uint8Array,
  maximum: number,
): number {
  const next = current + line.byteLength;
  if (!Number.isSafeInteger(next) || next > maximum) {
    zeroize(line);
    throw new BackupError(
      'BACKUP_TOO_LARGE',
      'The encrypted backup exceeds the aggregate byte limit.',
    );
  }
  return next;
}

export function resolveBackupLimits(
  limits: BackupLimits | undefined,
): ResolvedBackupLimits {
  const maximumBytes = limits?.maximumBytes ?? DEFAULT_MAX_BACKUP_BYTES;
  const maximumRecords = limits?.maximumRecords ?? DEFAULT_MAX_BACKUP_RECORDS;
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAX_SUPPORTED_BACKUP_BYTES ||
    !Number.isSafeInteger(maximumRecords) ||
    maximumRecords < 1 ||
    maximumRecords > DEFAULT_MAX_BACKUP_RECORDS
  ) {
    throw new RangeError('Backup limits are outside the supported range.');
  }
  return { maximumBytes, maximumRecords };
}
