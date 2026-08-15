import {
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

import {
  createPassphraseDerivation,
  decodeBase64Url,
  derivePassphraseKek,
  encodeBase64Url,
  encryptPayload,
  decryptPayload,
  zeroize,
} from '@kavrix/crypto';
import {
  DEFAULT_MAX_TRANSFER_DOCUMENTS,
  MAX_SUPPORTED_TRANSFER_BYTES,
  associatedDataSchema,
  encryptedTransferEntrySchema,
  encryptedTransferFooterSchema,
  encryptedTransferHeaderSchema,
  groupPayloadSchema,
  itemPayloadSchema,
  vaultIdSchema,
  type AssociatedData,
  type EncryptedTransferEntry,
  type EncryptedTransferFooter,
  type EncryptedTransferHeader,
  type GroupPayload,
  type ItemPayload,
  type ResolvedTransferLimits,
  type SchemaVersion,
  type TransferLimits,
  type TransferPassphraseDerivation,
  type TransferWithholding,
  type VaultId,
} from '@kavrix/schemas';

import { BackupError } from './errors.js';
import { MAX_BACKUP_LINE_BYTES, splitBackupLines } from './line-framing.js';

/**
 * Distinct HKDF info strings keep the sealing key and the transcript key
 * independent, so recovering one cannot reveal the other.
 */
const TRANSFER_PAYLOAD_INFO = Buffer.from('credvault/transfer-payload/v1', 'ascii');
const TRANSFER_AUTH_INFO = Buffer.from('credvault/transfer-authentication/v1', 'ascii');
const TRANSFER_KEY_BYTES = 32;

/** Transfers carry logical documents, so the writer is given them, not records. */
export type TransferDocument =
  | Readonly<{ kind: 'group'; group: GroupPayload }>
  | Readonly<{
      kind: 'item';
      item: ItemPayload;
      withheld: readonly TransferWithholding[];
    }>;

export type TransferItemDocument = Readonly<{
  item: ItemPayload;
  withheld: readonly TransferWithholding[];
}>;

export type CreateEncryptedTransferInput = Readonly<{
  vaultId: VaultId;
  schemaVersion: SchemaVersion;
  documents: AsyncIterable<TransferDocument>;
  createdAt?: string;
  limits?: TransferLimits;
  /**
   * Argon2id parameters for the transfer passphrase. Callers normally omit this
   * so the canonical vault minimums apply; a caller that supplies one must have
   * produced it through `createPassphraseDerivation`.
   */
  derivation?: TransferPassphraseDerivation;
}>;

export type ReadEncryptedTransferResult = Readonly<{
  header: EncryptedTransferHeader;
  groups: readonly GroupPayload[];
  items: readonly TransferItemDocument[];
}>;

type TransferKeys = Readonly<{ payloadKey: Uint8Array; authenticationKey: Uint8Array }>;

type Transcript = Readonly<{
  update: (line: Uint8Array) => void;
  finish: () => Readonly<{ digest: Uint8Array; authenticationTag: Uint8Array }>;
}>;

/**
 * Write an encrypted transfer as newline-framed JSON.
 *
 * Every document is sealed under a key derived only from the transfer
 * passphrase, so the file is readable by whoever holds that passphrase and by
 * nobody else — importantly, not by the API or by a holder of the source vault's
 * root key. The trailing footer authenticates the exact transcript of lines, so
 * truncation, reordering, or substitution is detected before a reader acts.
 */
export async function* createEncryptedTransfer(
  input: CreateEncryptedTransferInput,
  passphrase: Uint8Array,
): AsyncGenerator<Uint8Array> {
  const limits = resolveTransferLimits(input.limits);
  const expansionSalt = randomBytes(TRANSFER_KEY_BYTES);
  const header = parseSchema(encryptedTransferHeaderSchema, {
    type: 'header',
    format: 'kavrix-encrypted-transfer',
    version: 1,
    vaultId: input.vaultId,
    schemaVersion: input.schemaVersion,
    createdAt: input.createdAt ?? new Date().toISOString(),
    protection: {
      algorithm: 'argon2id+hkdf-sha256+xchacha20-poly1305-ietf',
      derivation: input.derivation ?? createTransferDerivation(),
      expansionSalt: encodeBase64Url(expansionSalt),
    },
  });

  let keys: TransferKeys | undefined;
  let transcript: Transcript | undefined;
  try {
    keys = await deriveTransferKeys(passphrase, header, expansionSalt);
    transcript = createTranscript(keys.authenticationKey);
    let emittedBytes = 0;
    let groupCount = 0;
    let itemCount = 0;

    const headerLine = encodeTranscriptLine(header, transcript);
    emittedBytes = accountOutputBytes(emittedBytes, headerLine, limits.maximumBytes);
    yield headerLine;

    for await (const document of input.documents) {
      const entry = await sealDocument(document, header, keys.payloadKey);
      if (entry.kind === 'group') groupCount += 1;
      else itemCount += 1;
      if (groupCount + itemCount > limits.maximumDocuments) {
        throw new BackupError(
          'BACKUP_TOO_LARGE',
          'The encrypted transfer exceeds the document limit.',
        );
      }
      const line = encodeTranscriptLine(entry, transcript);
      emittedBytes = accountOutputBytes(emittedBytes, line, limits.maximumBytes);
      yield line;
    }

    const finished = transcript.finish();
    try {
      const footer = parseSchema(encryptedTransferFooterSchema, {
        type: 'footer',
        version: 1,
        groupCount,
        itemCount,
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
    zeroize(expansionSalt);
    if (keys !== undefined) {
      zeroize(keys.payloadKey);
      zeroize(keys.authenticationKey);
    }
  }
}

/**
 * Read an encrypted transfer in full and authenticate it before returning.
 *
 * Nothing is handed back until the footer tag verifies, which is what lets a
 * caller treat the result as safe to apply: a malformed, truncated, oversized,
 * or tampered file raises before any document reaches a mutation path.
 */
export async function readEncryptedTransfer(
  source: AsyncIterable<Uint8Array>,
  passphrase: Uint8Array,
  limits?: TransferLimits,
): Promise<ReadEncryptedTransferResult> {
  const resolved = resolveTransferLimits(limits);
  const iterator = splitBackupLines(sanitizeSource(source), resolved.maximumBytes)[
    Symbol.asyncIterator
  ]();
  const groups: GroupPayload[] = [];
  const items: TransferItemDocument[] = [];
  let header: EncryptedTransferHeader | undefined;
  let footer: EncryptedTransferFooter | undefined;
  let keys: TransferKeys | undefined;
  let transcript: Transcript | undefined;
  let headerLine: Uint8Array | undefined;
  let eof = false;

  try {
    const first = await iterator.next();
    if (first.done === true) {
      eof = true;
      throw incompleteTransfer();
    }
    headerLine = first.value;
    header = parseSchema(encryptedTransferHeaderSchema, parseJsonLine(headerLine));
    const expansionSalt = decodeTransferBytes(header.protection.expansionSalt);
    try {
      keys = await deriveTransferKeys(passphrase, header, expansionSalt);
    } finally {
      zeroize(expansionSalt);
    }
    transcript = createTranscript(keys.authenticationKey);
    transcript.update(headerLine);
    zeroize(headerLine);
    headerLine = undefined;

    for (;;) {
      const next = await iterator.next();
      if (next.done === true) {
        eof = true;
        break;
      }
      const line = next.value;
      try {
        if (footer !== undefined) {
          throw new BackupError(
            'BACKUP_INVALID',
            'The encrypted transfer contains data after its footer.',
          );
        }
        const value = parseJsonLine(line);
        if (isFooterCandidate(value)) {
          footer = parseSchema(encryptedTransferFooterSchema, value);
          continue;
        }
        if (groups.length + items.length >= resolved.maximumDocuments) {
          throw new BackupError(
            'BACKUP_TOO_LARGE',
            'The encrypted transfer exceeds the document limit.',
          );
        }
        const entry = parseSchema(encryptedTransferEntrySchema, value);
        transcript.update(line);
        const opened = await openDocument(entry, header, keys.payloadKey);
        if (opened.kind === 'group') groups.push(opened.group);
        else items.push({ item: opened.item, withheld: opened.withheld });
      } finally {
        zeroize(line);
      }
    }

    if (footer === undefined) throw incompleteTransfer();
    if (footer.groupCount !== groups.length || footer.itemCount !== items.length) {
      throw new BackupError(
        'BACKUP_INVALID',
        'The encrypted transfer document count is inconsistent.',
      );
    }

    const finished = transcript.finish();
    const suppliedDigest = decodeTransferBytes(footer.transcriptSha256);
    const suppliedTag = decodeTransferBytes(footer.authenticationTag);
    try {
      if (
        !timingSafeEqual(finished.digest, suppliedDigest) ||
        !timingSafeEqual(finished.authenticationTag, suppliedTag)
      ) {
        throw authenticationFailure();
      }
    } finally {
      zeroize(finished.digest);
      zeroize(finished.authenticationTag);
      zeroize(suppliedDigest);
      zeroize(suppliedTag);
    }
    return { header, groups, items };
  } finally {
    if (!eof) {
      try {
        await iterator.return(undefined);
      } catch {
        // The public failure stays sanitized by the caller-facing error above.
      }
    }
    zeroize(headerLine);
    if (keys !== undefined) {
      zeroize(keys.payloadKey);
      zeroize(keys.authenticationKey);
    }
  }
}

export function resolveTransferLimits(
  limits: TransferLimits | undefined,
): ResolvedTransferLimits {
  const maximumBytes = limits?.maximumBytes ?? MAX_SUPPORTED_TRANSFER_BYTES;
  const maximumDocuments = limits?.maximumDocuments ?? DEFAULT_MAX_TRANSFER_DOCUMENTS;
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAX_SUPPORTED_TRANSFER_BYTES ||
    !Number.isSafeInteger(maximumDocuments) ||
    maximumDocuments < 1 ||
    maximumDocuments > DEFAULT_MAX_TRANSFER_DOCUMENTS
  ) {
    throw new RangeError('Transfer limits are outside the supported range.');
  }
  return { maximumBytes, maximumDocuments };
}

function createTransferDerivation(): TransferPassphraseDerivation {
  return createPassphraseDerivation();
}

async function sealDocument(
  document: TransferDocument,
  header: EncryptedTransferHeader,
  payloadKey: Uint8Array,
): Promise<EncryptedTransferEntry> {
  if (document.kind === 'group') {
    const group = parseSchema(groupPayloadSchema, document.group);
    assertSameVault(group.vaultId, header.vaultId);
    const envelope = await encryptPayload(
      encodeJson(group),
      payloadKey,
      groupAssociatedData(header, group.id),
    );
    return parseSchema(encryptedTransferEntrySchema, {
      kind: 'group',
      groupId: group.id,
      envelope,
    });
  }
  const item = parseSchema(itemPayloadSchema, document.item);
  assertSameVault(item.vaultId, header.vaultId);
  const envelope = await encryptPayload(
    encodeJson(item),
    payloadKey,
    itemAssociatedData(header, item.groupId, item.id),
  );
  return parseSchema(encryptedTransferEntrySchema, {
    kind: 'item',
    groupId: item.groupId,
    itemId: item.id,
    envelope,
    withheld: document.withheld,
  });
}

async function openDocument(
  entry: EncryptedTransferEntry,
  header: EncryptedTransferHeader,
  payloadKey: Uint8Array,
): Promise<
  | Readonly<{ kind: 'group'; group: GroupPayload }>
  | Readonly<{
      kind: 'item';
      item: ItemPayload;
      withheld: readonly TransferWithholding[];
    }>
> {
  const context =
    entry.kind === 'group'
      ? groupAssociatedData(header, entry.groupId)
      : itemAssociatedData(header, entry.groupId, entry.itemId);
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = await decryptPayload(entry.envelope, payloadKey, context);
  } catch (error) {
    throw new BackupError(
      'BACKUP_AUTHENTICATION_FAILED',
      'The encrypted transfer could not be authenticated.',
      { cause: error },
    );
  }
  try {
    const value = parseJsonLine(plaintext);
    if (entry.kind === 'group') {
      const group = parseSchema(groupPayloadSchema, value);
      if (group.id !== entry.groupId) throw mislabelledDocument();
      assertSameVault(group.vaultId, header.vaultId);
      return { kind: 'group', group };
    }
    const item = parseSchema(itemPayloadSchema, value);
    if (item.id !== entry.itemId || item.groupId !== entry.groupId) {
      throw mislabelledDocument();
    }
    assertSameVault(item.vaultId, header.vaultId);
    return { kind: 'item', item, withheld: entry.withheld };
  } finally {
    zeroize(plaintext);
  }
}

function groupAssociatedData(
  header: EncryptedTransferHeader,
  groupId: GroupPayload['id'],
): AssociatedData {
  return parseSchema(associatedDataSchema, {
    version: 1,
    schemaVersion: header.schemaVersion,
    keyVersion: 1,
    vaultId: header.vaultId,
    entityType: 'group',
    entityId: groupId,
    purpose: 'group-payload',
  });
}

function itemAssociatedData(
  header: EncryptedTransferHeader,
  groupId: ItemPayload['groupId'],
  itemId: ItemPayload['id'],
): AssociatedData {
  return parseSchema(associatedDataSchema, {
    version: 1,
    schemaVersion: header.schemaVersion,
    keyVersion: 1,
    vaultId: header.vaultId,
    entityType: 'item',
    entityId: itemId,
    purpose: 'item-payload',
    groupId,
  });
}

async function deriveTransferKeys(
  passphrase: Uint8Array,
  header: EncryptedTransferHeader,
  expansionSalt: Uint8Array,
): Promise<TransferKeys> {
  const kek = await derivePassphraseKek(passphrase, header.protection.derivation);
  try {
    return {
      payloadKey: expand(kek, expansionSalt, TRANSFER_PAYLOAD_INFO),
      authenticationKey: expand(kek, expansionSalt, TRANSFER_AUTH_INFO),
    };
  } finally {
    zeroize(kek);
  }
}

function expand(key: Uint8Array, salt: Uint8Array, info: Uint8Array): Uint8Array {
  const derived = new Uint8Array(
    hkdfSync('sha256', key, salt, info, TRANSFER_KEY_BYTES),
  );
  try {
    return Uint8Array.from(derived);
  } finally {
    zeroize(derived);
  }
}

function createTranscript(authenticationKey: Uint8Array): Transcript {
  const digest = createHash('sha256');
  const authentication = createHmac('sha256', authenticationKey);
  let finished = false;
  return {
    update(line): void {
      if (finished || line.byteLength > MAX_BACKUP_LINE_BYTES) {
        throw new BackupError('BACKUP_INVALID', 'Invalid transfer transcript state.');
      }
      const length = Buffer.allocUnsafe(4);
      length.writeUInt32BE(line.byteLength);
      digest.update(length).update(line);
      authentication.update(length).update(line);
      length.fill(0);
    },
    finish() {
      if (finished) {
        throw new BackupError(
          'BACKUP_INVALID',
          'Transfer transcript already finalized.',
        );
      }
      finished = true;
      return {
        digest: Uint8Array.from(digest.digest()),
        authenticationTag: Uint8Array.from(authentication.digest()),
      };
    },
  };
}

function assertSameVault(actual: VaultId, expected: VaultId): void {
  if (vaultIdSchema.parse(actual) !== expected) {
    throw new BackupError(
      'BACKUP_WRONG_VAULT',
      'The encrypted transfer document belongs to a different vault.',
    );
  }
}

function mislabelledDocument(): BackupError {
  return new BackupError(
    'BACKUP_INVALID',
    'An encrypted transfer document does not match its declared identity.',
  );
}

function incompleteTransfer(): BackupError {
  return new BackupError('BACKUP_INCOMPLETE', 'The encrypted transfer is incomplete.');
}

function authenticationFailure(): BackupError {
  return new BackupError(
    'BACKUP_AUTHENTICATION_FAILED',
    'The encrypted transfer could not be authenticated.',
  );
}

function encodeTranscriptLine(value: unknown, transcript: Transcript): Uint8Array {
  const line = encodeJson(value);
  transcript.update(line);
  return frame(line);
}

function encodeJsonLine(value: unknown): Uint8Array {
  return frame(encodeJson(value));
}

function frame(line: Uint8Array): Uint8Array {
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
      'An encrypted transfer document exceeds the size limit.',
    );
  }
  return encoded;
}

function parseJsonLine(line: Uint8Array): unknown {
  try {
    return JSON.parse(Buffer.from(line).toString('utf8')) as unknown;
  } catch (error) {
    throw new BackupError('BACKUP_INVALID', 'The encrypted transfer is malformed.', {
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
    throw new BackupError('BACKUP_INVALID', 'The encrypted transfer is malformed.', {
      ...(parsed.error === undefined ? {} : { cause: parsed.error }),
    });
  }
  return parsed.data;
}

function decodeTransferBytes(value: string): Uint8Array {
  try {
    return decodeBase64Url(value, { exactBytes: TRANSFER_KEY_BYTES });
  } catch (error) {
    throw new BackupError('BACKUP_INVALID', 'The encrypted transfer is malformed.', {
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
      'The encrypted transfer exceeds the aggregate byte limit.',
    );
  }
  return next;
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
