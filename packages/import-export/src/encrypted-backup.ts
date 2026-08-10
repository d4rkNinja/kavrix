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
  contentHashForRecord,
  sha256DigestSchema,
  vaultIdSchema,
  type BackupLimits,
  type BackupRestoreStager,
  type BackupRestoreStore,
  type BackupStagingStatus,
  type BackupVerification,
  type ResolvedBackupLimits,
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
  BackupStagingStatus,
  BackupVerification,
  ResolvedBackupLimits,
} from '@kavrix/schemas';

export type CreateEncryptedBackupInput = Readonly<{
  vault: VaultRecord;
  records: AsyncIterable<EncryptedBackupEntry>;
  createdAt?: string;
  limits?: BackupLimits;
}>;

type Transcript = Readonly<{
  update(line: Uint8Array): void;
  finish(): Readonly<{ digest: Uint8Array; authenticationTag: Uint8Array }>;
}>;

type ProcessCallbacks = Readonly<{
  onHeader?: (
    restoreSessionId: Sha256Digest,
    limits: ResolvedBackupLimits,
  ) => Promise<void>;
  onEntry?: (entry: EncryptedBackupEntry) => Promise<void>;
}>;

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
): Promise<BackupVerification> {
  return processEncryptedBackup(
    source,
    vaultRootKey,
    expectedVaultId,
    resolveBackupLimits(limits),
  );
}

export async function restoreEncryptedBackup(
  source: AsyncIterable<Uint8Array>,
  vaultRootKey: VaultRootKey,
  expectedVaultId: VaultId,
  store: BackupRestoreStore,
  limitsInput?: BackupLimits,
): Promise<BackupVerification> {
  const limits = resolveBackupLimits(limitsInput);
  let stager: BackupRestoreStager | undefined;
  let commitStarted = false;
  let summary: BackupVerification | undefined;

  try {
    summary = await processEncryptedBackup(
      source,
      vaultRootKey,
      expectedVaultId,
      limits,
      {
        async onHeader(restoreSessionId): Promise<void> {
          stager = await store.open(restoreSessionId, limits);
        },
        async onEntry(entry): Promise<void> {
          if (stager === undefined) {
            throw new BackupError(
              'BACKUP_INCOMPLETE',
              'Backup staging was not initialized.',
            );
          }
          await stager.write(entry);
        },
      },
    );
    if (stager === undefined) {
      throw new BackupError('BACKUP_INCOMPLETE', 'Backup staging was not initialized.');
    }

    commitStarted = true;
    try {
      await stager.commit(summary);
      return summary;
    } catch (commitError) {
      let status: BackupStagingStatus;
      try {
        status = await stager.status();
      } catch (statusError) {
        throw new AggregateError(
          [commitError, statusError],
          'Backup commit failed and its durable status could not be reconciled.',
          { cause: statusError },
        );
      }
      if (status === 'committed') {
        return summary;
      }
      throw new BackupError(
        'BACKUP_COMMIT_UNCERTAIN',
        'The authenticated backup remains staged; retry the same restore session.',
        { cause: commitError },
      );
    }
  } catch (error) {
    if (commitStarted || stager === undefined) {
      throw error;
    }
    try {
      await stager.abort();
    } catch (abortError) {
      throw new AggregateError(
        [error, abortError],
        'Backup restore failed and its hidden staging area could not be aborted.',
        { cause: abortError },
      );
    }
    throw error;
  }
}

async function processEncryptedBackup(
  source: AsyncIterable<Uint8Array>,
  vaultRootKey: VaultRootKey,
  expectedVaultId: VaultId,
  limits: ResolvedBackupLimits,
  callbacks: ProcessCallbacks = {},
): Promise<BackupVerification> {
  requireByteLength(vaultRootKey, AUTH_KEY_BYTES, 'vault root key');
  const expectedId = vaultIdSchema.parse(expectedVaultId);
  let header: EncryptedBackupHeader | undefined;
  let footer: EncryptedBackupFooter | undefined;
  let transcript: Transcript | undefined;
  let authenticationKey: Uint8Array | undefined;
  let restoreSessionId: Sha256Digest | undefined;
  const recordSet = new BackupRecordSet(expectedId, limits.maximumRecords);

  try {
    for await (const line of splitBackupLines(source, limits.maximumBytes)) {
      if (footer !== undefined) {
        throw new BackupError(
          'BACKUP_INVALID',
          'The encrypted backup contains data after its footer.',
        );
      }

      const value = parseJsonLine(line);
      if (header === undefined) {
        header = parseSchema(encryptedBackupHeaderSchema, value);
        if (header.vaultId !== expectedId) {
          throw new BackupError(
            'BACKUP_WRONG_VAULT',
            'The encrypted backup belongs to a different vault.',
          );
        }
        const salt = decodeBackupBytes(header.authentication.salt);
        try {
          authenticationKey = deriveAuthenticationKey(vaultRootKey, salt);
        } finally {
          zeroize(salt);
        }
        transcript = createTranscript(authenticationKey);
        transcript.update(line);
        restoreSessionId = restoreSessionIdForHeader(line);
        await callbacks.onHeader?.(restoreSessionId, limits);
        continue;
      }

      if (isFooterCandidate(value)) {
        footer = parseSchema(encryptedBackupFooterSchema, value);
        continue;
      }
      if (transcript === undefined) {
        throw new BackupError('BACKUP_INVALID', 'Invalid backup transcript state.');
      }

      const entry = parseSchema(encryptedBackupEntrySchema, value);
      recordSet.accept(entry);
      transcript.update(line);
      await callbacks.onEntry?.(entry);
    }

    if (
      header === undefined ||
      footer === undefined ||
      transcript === undefined ||
      restoreSessionId === undefined
    ) {
      throw new BackupError(
        'BACKUP_INCOMPLETE',
        'The encrypted backup header or footer is missing.',
      );
    }
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
      return {
        header,
        restoreSessionId,
        recordCount: recordSet.recordCount,
        transcriptSha256: footer.transcriptSha256,
      };
    } finally {
      zeroize(finished.digest);
      zeroize(finished.authenticationTag);
      zeroize(suppliedDigest);
      zeroize(suppliedTag);
    }
  } finally {
    zeroize(authenticationKey);
  }
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
