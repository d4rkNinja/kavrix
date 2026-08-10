import {
  JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES,
  joinJournalRecordSchema,
  lifecycleOperationIdSchema,
  type JoinActiveJournalRecord,
  type LifecycleOperationId,
} from '@kavrix/client';

import { KeychainError } from './errors.js';
import {
  assertSafeService,
  classifyNativeFailure,
  DEFAULT_KEYCHAIN_SERVICE,
  loadNativeEntryFactory,
  nativeErrorCode,
  toOwnedNativeBytes,
  type NativeEntryFactory,
} from './native-keychain.js';

const MAGIC = Uint8Array.of(0x4b, 0x4a, 0x4a, 0x52);
const FORMAT_VERSION = 1;
const HEADER_BYTES = 8;
const BEARER_BYTES = 32;
const BEARER_COUNT = 3;
const WINDOWS_CREDENTIAL_MANAGER_HARD_MAX_BYTES = 2_560;
const STATE_CODES = {
  prepared: 1,
  'redeem-attempted': 2,
  'completion-attempted': 3,
} as const;

type ActiveState = JoinActiveJournalRecord['state'];

/** Native-only bearer storage used by the SQLite join recovery state machine. */
export class NativeJoinJournalSecrets {
  readonly #createEntry: NativeEntryFactory;
  readonly #service: string;

  public constructor(
    createEntry: NativeEntryFactory,
    service = DEFAULT_KEYCHAIN_SERVICE,
  ) {
    assertSafeService(service);
    this.#createEntry = createEntry;
    this.#service = service;
  }

  public async store(recordInput: JoinActiveJournalRecord): Promise<void> {
    const record = parseActive(recordInput);
    const encoded = encode(record);
    try {
      await this.#createEntry(this.#service, accountFor(record.operationId)).setSecret(
        encoded,
      );
    } catch (error) {
      throw classifyNativeFailure(error);
    } finally {
      encoded.fill(0);
    }
  }

  public async load(
    operationIdInput: LifecycleOperationId,
  ): Promise<JoinActiveJournalRecord | null> {
    const operationId = parseOperationId(operationIdInput);
    let nativeValue: unknown;
    try {
      nativeValue = await this.#createEntry(
        this.#service,
        accountFor(operationId),
      ).getSecret();
    } catch (error) {
      throw classifyNativeFailure(error);
    }
    const encoded = toOwnedNativeBytes(nativeValue);
    if (encoded === null) return null;
    try {
      return decode(encoded, operationId);
    } finally {
      encoded.fill(0);
    }
  }

  public async delete(operationIdInput: LifecycleOperationId): Promise<void> {
    const operationId = parseOperationId(operationIdInput);
    try {
      await this.#createEntry(
        this.#service,
        accountFor(operationId),
      ).deleteCredential();
    } catch (error) {
      const code = nativeErrorCode(error);
      if (code.includes('noentry') || code.includes('notfound')) return;
      throw classifyNativeFailure(error);
    }
  }
}

export async function createNativeJoinJournalSecrets(
  service = DEFAULT_KEYCHAIN_SERVICE,
): Promise<NativeJoinJournalSecrets> {
  assertSafeService(service);
  return new NativeJoinJournalSecrets(await loadNativeEntryFactory(), service);
}

function accountFor(operationIdInput: LifecycleOperationId): string {
  return `v1:vault-join-operation:${parseOperationId(operationIdInput)}`;
}

function parseOperationId(input: LifecycleOperationId): LifecycleOperationId {
  const parsed = lifecycleOperationIdSchema.safeParse(input);
  if (!parsed.success) throw failed();
  return parsed.data;
}

function parseActive(input: JoinActiveJournalRecord): JoinActiveJournalRecord {
  const parsed = joinJournalRecordSchema.safeParse(input);
  if (!parsed.success || parsed.data.state === 'committed') throw failed();
  return parsed.data;
}

function publicRecord(
  record: JoinActiveJournalRecord,
): Omit<
  JoinActiveJournalRecord,
  'state' | 'inviteBearer' | 'enrollmentSuccessor' | 'sessionSuccessor'
> {
  return {
    version: 1,
    kind: 'vault-join',
    operationId: record.operationId,
    expectedVaultId: record.expectedVaultId,
    deviceId: record.deviceId,
    completionRequest: record.completionRequest,
    sessionLocator: record.sessionLocator,
  };
}

function encode(record: JoinActiveJournalRecord): Uint8Array {
  const publicBytes = new TextEncoder().encode(JSON.stringify(publicRecord(record)));
  const totalBytes =
    HEADER_BYTES + publicBytes.byteLength + BEARER_BYTES * BEARER_COUNT;
  if (
    publicBytes.byteLength > 0xffff ||
    totalBytes > JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES ||
    totalBytes > WINDOWS_CREDENTIAL_MANAGER_HARD_MAX_BYTES
  ) {
    publicBytes.fill(0);
    throw failed();
  }
  const encoded = new Uint8Array(totalBytes);
  try {
    encoded.set(MAGIC, 0);
    encoded[4] = FORMAT_VERSION;
    encoded[5] = STATE_CODES[record.state];
    new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength).setUint16(
      6,
      publicBytes.byteLength,
      false,
    );
    encoded.set(publicBytes, HEADER_BYTES);
    let offset = HEADER_BYTES + publicBytes.byteLength;
    for (const bearer of [
      record.inviteBearer,
      record.enrollmentSuccessor,
      record.sessionSuccessor,
    ]) {
      if (bearer.byteLength !== BEARER_BYTES) throw failed();
      encoded.set(bearer, offset);
      offset += BEARER_BYTES;
    }
    return encoded;
  } catch (error) {
    encoded.fill(0);
    if (error instanceof KeychainError) throw error;
    throw failed();
  } finally {
    publicBytes.fill(0);
  }
}

function decode(
  encoded: Uint8Array,
  expectedOperationId: LifecycleOperationId,
): JoinActiveJournalRecord {
  try {
    if (
      encoded.byteLength < HEADER_BYTES + BEARER_BYTES * BEARER_COUNT ||
      encoded.byteLength > JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES ||
      !MAGIC.every((value, index) => encoded[index] === value) ||
      encoded[4] !== FORMAT_VERSION
    ) {
      throw corrupted();
    }
    const state = stateFromCode(encoded[5]);
    const publicLength = new DataView(
      encoded.buffer,
      encoded.byteOffset,
      encoded.byteLength,
    ).getUint16(6, false);
    if (
      HEADER_BYTES + publicLength + BEARER_BYTES * BEARER_COUNT !==
      encoded.byteLength
    ) {
      throw corrupted();
    }
    const publicJson = new TextDecoder('utf-8', { fatal: true }).decode(
      encoded.subarray(HEADER_BYTES, HEADER_BYTES + publicLength),
    );
    const publicValue = parseJson(publicJson);
    let offset = HEADER_BYTES + publicLength;
    const inviteBearer = Uint8Array.from(
      encoded.subarray(offset, offset + BEARER_BYTES),
    );
    offset += BEARER_BYTES;
    const enrollmentSuccessor = Uint8Array.from(
      encoded.subarray(offset, offset + BEARER_BYTES),
    );
    offset += BEARER_BYTES;
    const sessionSuccessor = Uint8Array.from(
      encoded.subarray(offset, offset + BEARER_BYTES),
    );
    try {
      const parsed = joinJournalRecordSchema.safeParse({
        ...(publicValue as object),
        state,
        inviteBearer,
        enrollmentSuccessor,
        sessionSuccessor,
      });
      if (
        !parsed.success ||
        parsed.data.state === 'committed' ||
        parsed.data.operationId !== expectedOperationId ||
        JSON.stringify(publicRecord(parsed.data)) !== publicJson
      ) {
        throw corrupted();
      }
      return parsed.data;
    } catch (error) {
      inviteBearer.fill(0);
      enrollmentSuccessor.fill(0);
      sessionSuccessor.fill(0);
      throw error;
    }
  } catch (error) {
    if (error instanceof KeychainError) throw error;
    throw corrupted();
  }
}

function stateFromCode(value: number | undefined): ActiveState {
  if (value === 1) return 'prepared';
  if (value === 2) return 'redeem-attempted';
  if (value === 3) return 'completion-attempted';
  throw corrupted();
}

function parseJson(value: string): unknown {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw corrupted();
    }
    return parsed;
  } catch (error) {
    if (error instanceof KeychainError) throw error;
    throw corrupted();
  }
}

function failed(): KeychainError {
  return new KeychainError(
    'KEYCHAIN_OPERATION_FAILED',
    'The protected lifecycle journal operation failed.',
  );
}

function corrupted(): KeychainError {
  return new KeychainError(
    'KEYCHAIN_CORRUPTED',
    'The protected lifecycle journal entry is invalid.',
  );
}
