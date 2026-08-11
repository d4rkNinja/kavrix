import { createRequire } from 'node:module';

import type { KeychainPort, SessionCredentialPort } from '@kavrix/core';
import type { AsyncEntry as AsyncEntryInstance } from '@napi-rs/keyring';
import {
  deviceIdSchema,
  deviceUnlockSecretSchema,
  keychainLocatorSchema,
  protectedLocalDeviceStateSchema,
  sha256DigestSchema,
  sessionCredentialLocatorSchema,
  sessionCredentialSecretSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type DeviceId,
  type DeviceUnlockSecret,
  type KeychainLocator,
  type ProtectedLocalDeviceState,
  type Sha256Digest,
  type SessionCredentialLocator,
  type SessionCredentialSecret,
  type VaultId,
} from '@kavrix/schemas';
import {
  SyncLocalStateError,
  validateOutboundObservationBinding,
  type ProtectedSyncStatePort,
} from '@kavrix/sync';

import { KeychainError } from './errors.js';
import { withProtectedStateQueue } from './protected-state-queue.js';

export const DEFAULT_KEYCHAIN_SERVICE = 'dev.kavrix.credentials';
const SAFE_SERVICE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const PROTECTED_STATE_MAGIC = Uint8Array.of(0x4b, 0x53, 0x53, 0x54);
const PROTECTED_STATE_VERSION_V1 = 1;
const PROTECTED_STATE_VERSION_V2 = 2;
const PROTECTED_STATE_V1_TRAILER_BYTES = 16;
const PROTECTED_STATE_MAX_BYTES = 1_024;
const PROTECTED_STATE_FLAG_OBSERVATION = 1 << 0;
const PROTECTED_STATE_FLAG_LAST_COMPLETED = 1 << 1;
const PROTECTED_STATE_KNOWN_FLAGS =
  PROTECTED_STATE_FLAG_OBSERVATION | PROTECTED_STATE_FLAG_LAST_COMPLETED;

type NativeEntry = Readonly<{
  setSecret(secret: Uint8Array, signal?: AbortSignal): Promise<unknown>;
  getSecret(signal?: AbortSignal): Promise<unknown>;
  deleteCredential(signal?: AbortSignal): Promise<unknown>;
}>;

export type NativeEntryFactory = (service: string, account: string) => NativeEntry;
type AsyncEntryConstructor = new (
  service: string,
  account: string,
) => AsyncEntryInstance;

export function assertSafeService(value: string): void {
  if (!SAFE_SERVICE.test(value)) {
    throw new KeychainError(
      'KEYCHAIN_OPERATION_FAILED',
      'Invalid service name for secure storage.',
    );
  }
}

function accountFor(locatorInput: KeychainLocator): string {
  const parsed = keychainLocatorSchema.safeParse(locatorInput);
  if (!parsed.success) {
    throw new KeychainError(
      'KEYCHAIN_OPERATION_FAILED',
      'Invalid secure-storage locator.',
    );
  }
  const locator = parsed.data;
  return `v1:device-unlock:${locator.vaultId}:${locator.deviceId}:${locator.keySlotId}`;
}

function sessionAccountFor(locatorInput: SessionCredentialLocator): string {
  const parsed = sessionCredentialLocatorSchema.safeParse(locatorInput);
  if (!parsed.success) {
    throw new KeychainError(
      'KEYCHAIN_OPERATION_FAILED',
      'Invalid secure-storage locator.',
    );
  }
  const locator = parsed.data;
  return `v1:api-session:${locator.vaultId}:${locator.deviceId}`;
}

function protectedStateAccountFor(
  vaultIdInput: VaultId,
  deviceIdInput: DeviceId,
): string {
  const vaultId = vaultIdSchema.safeParse(vaultIdInput);
  const deviceId = deviceIdSchema.safeParse(deviceIdInput);
  if (!vaultId.success || !deviceId.success) throw new SyncLocalStateError();
  return `v1:protected-sync-state:${vaultId.data}:${deviceId.data}`;
}

function parseDeviceSecret(secret: Uint8Array): DeviceUnlockSecret {
  const parsed = deviceUnlockSecretSchema.safeParse(secret);
  if (!parsed.success) {
    throw new KeychainError(
      'KEYCHAIN_OPERATION_FAILED',
      'Remembered device material must contain exactly 32 bytes.',
    );
  }
  return parsed.data;
}

function parseStoredDeviceSecret(secret: Uint8Array): DeviceUnlockSecret {
  const parsed = deviceUnlockSecretSchema.safeParse(secret);
  if (!parsed.success) {
    secret.fill(0);
    throw new KeychainError(
      'KEYCHAIN_CORRUPTED',
      'The native credential store returned invalid remembered material.',
    );
  }
  return parsed.data;
}

function parseSessionSecret(secret: Uint8Array): SessionCredentialSecret {
  const parsed = sessionCredentialSecretSchema.safeParse(secret);
  if (!parsed.success) {
    throw new KeychainError(
      'KEYCHAIN_OPERATION_FAILED',
      'Session credentials must contain exactly 32 bytes.',
    );
  }
  return parsed.data;
}

function parseStoredSessionSecret(secret: Uint8Array): SessionCredentialSecret {
  const parsed = sessionCredentialSecretSchema.safeParse(secret);
  if (!parsed.success) {
    secret.fill(0);
    throw new KeychainError(
      'KEYCHAIN_CORRUPTED',
      'The native credential store returned an invalid session credential.',
    );
  }
  return parsed.data;
}

function toSecretBytes<TSecret extends Uint8Array>(
  value: unknown,
  parseStored: (secret: Uint8Array) => TSecret,
): TSecret | null {
  if (value === null || value === undefined) {
    return null;
  }

  if (value instanceof Uint8Array) {
    try {
      return parseStored(Uint8Array.from(value));
    } finally {
      value.fill(0);
    }
  }

  if (
    Array.isArray(value) &&
    value.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)
  ) {
    try {
      return parseStored(Uint8Array.from(value as number[]));
    } finally {
      value.fill(0);
    }
  }

  throw new KeychainError(
    'KEYCHAIN_CORRUPTED',
    'The native credential store returned invalid remembered material.',
  );
}

export function toOwnedNativeBytes(value: unknown): Uint8Array | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Uint8Array) {
    try {
      return Uint8Array.from(value);
    } finally {
      value.fill(0);
    }
  }
  if (Array.isArray(value)) {
    try {
      if (
        !value.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)
      ) {
        throw new KeychainError(
          'KEYCHAIN_CORRUPTED',
          'The native credential store returned invalid protected state.',
        );
      }
      return Uint8Array.from(value as number[]);
    } finally {
      value.fill(0);
    }
  }
  throw new KeychainError(
    'KEYCHAIN_CORRUPTED',
    'The native credential store returned invalid protected state.',
  );
}

export function nativeErrorCode(error: unknown): string {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String(error.code).toLowerCase()
    : '';
}

export function classifyNativeFailure(error: unknown): KeychainError {
  if (error instanceof KeychainError) {
    return error;
  }

  const code = nativeErrorCode(error);
  if (
    code.includes('abort') ||
    (error instanceof DOMException && error.name === 'AbortError')
  ) {
    return new KeychainError(
      'KEYCHAIN_ABORTED',
      'The operating-system credential store operation was cancelled.',
    );
  }

  if (code.includes('denied') || code.includes('locked') || code.includes('cancel')) {
    return new KeychainError(
      'KEYCHAIN_ACCESS_DENIED',
      'The operating-system credential store denied access.',
    );
  }

  return new KeychainError(
    'KEYCHAIN_OPERATION_FAILED',
    'The operating-system credential store operation failed.',
  );
}

class NativeSecretStore<TLocator, TSecret extends Uint8Array> {
  public constructor(
    private readonly createEntry: NativeEntryFactory,
    private readonly service: string,
    private readonly account: (locator: TLocator) => string,
    private readonly parseInput: (secret: Uint8Array) => TSecret,
    private readonly parseStored: (secret: Uint8Array) => TSecret,
  ) {}

  public async store(
    locator: TLocator,
    secret: TSecret,
    signal?: AbortSignal,
  ): Promise<void> {
    const parsedSecret = this.parseInput(secret);
    const ownedSecret = Uint8Array.from(parsedSecret);
    try {
      await this.createEntry(this.service, this.account(locator)).setSecret(
        ownedSecret,
        signal,
      );
    } catch (error) {
      throw classifyNativeFailure(error);
    } finally {
      ownedSecret.fill(0);
    }
  }

  public async load(locator: TLocator, signal?: AbortSignal): Promise<TSecret | null> {
    try {
      const value = await this.createEntry(
        this.service,
        this.account(locator),
      ).getSecret(signal);
      return toSecretBytes(value, this.parseStored);
    } catch (error) {
      throw classifyNativeFailure(error);
    }
  }

  public async delete(locator: TLocator, signal?: AbortSignal): Promise<void> {
    try {
      await this.createEntry(this.service, this.account(locator)).deleteCredential(
        signal,
      );
    } catch (error) {
      const code = nativeErrorCode(error);
      if (code.includes('noentry') || code.includes('notfound')) return;
      throw classifyNativeFailure(error);
    }
  }
}

export class NativeKeychain implements KeychainPort {
  readonly #store: NativeSecretStore<KeychainLocator, DeviceUnlockSecret>;

  public constructor(
    createEntry: NativeEntryFactory,
    service = DEFAULT_KEYCHAIN_SERVICE,
  ) {
    assertSafeService(service);
    this.#store = new NativeSecretStore(
      createEntry,
      service,
      accountFor,
      parseDeviceSecret,
      parseStoredDeviceSecret,
    );
  }

  public async store(
    locator: KeychainLocator,
    secret: DeviceUnlockSecret,
    signal?: AbortSignal,
  ): Promise<void> {
    return this.#store.store(locator, secret, signal);
  }

  public async load(
    locator: KeychainLocator,
    signal?: AbortSignal,
  ): Promise<DeviceUnlockSecret | null> {
    return this.#store.load(locator, signal);
  }

  public async delete(locator: KeychainLocator, signal?: AbortSignal): Promise<void> {
    return this.#store.delete(locator, signal);
  }
}

/** Native-only API session credential storage; there is intentionally no file fallback. */
export class NativeSessionCredentials implements SessionCredentialPort {
  readonly #store: NativeSecretStore<SessionCredentialLocator, SessionCredentialSecret>;

  public constructor(
    createEntry: NativeEntryFactory,
    service = DEFAULT_KEYCHAIN_SERVICE,
  ) {
    assertSafeService(service);
    this.#store = new NativeSecretStore(
      createEntry,
      service,
      sessionAccountFor,
      parseSessionSecret,
      parseStoredSessionSecret,
    );
  }

  public async store(
    locator: SessionCredentialLocator,
    secret: SessionCredentialSecret,
    signal?: AbortSignal,
  ): Promise<void> {
    return this.#store.store(locator, secret, signal);
  }

  public async load(
    locator: SessionCredentialLocator,
    signal?: AbortSignal,
  ): Promise<SessionCredentialSecret | null> {
    return this.#store.load(locator, signal);
  }

  public async delete(
    locator: SessionCredentialLocator,
    signal?: AbortSignal,
  ): Promise<void> {
    return this.#store.delete(locator, signal);
  }
}

/** Native-only rollback anchor storage; there is intentionally no file fallback. */
export class NativeProtectedSyncState implements ProtectedSyncStatePort {
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

  public async load(
    vaultId: VaultId,
    deviceId: DeviceId,
  ): Promise<ProtectedLocalDeviceState | null> {
    const account = protectedStateAccountFor(vaultId, deviceId);
    return withProtectedStateQueue(this.#service, account, () =>
      this.#load(account, vaultId, deviceId),
    );
  }

  public async save(stateInput: ProtectedLocalDeviceState): Promise<void> {
    const state = parseProtectedState(stateInput);
    const account = protectedStateAccountFor(state.vaultId, state.deviceId);
    return withProtectedStateQueue(this.#service, account, async () => {
      const existing = await this.#load(account, state.vaultId, state.deviceId);
      const transition = transitionForSave(existing, state);
      if (transition === null) return;
      await this.#write(account, transition);
    });
  }

  public async completeObservation(
    vaultId: VaultId,
    deviceId: DeviceId,
    expectedObservationId: Sha256Digest,
    candidateRevision: ProtectedLocalDeviceState['highestSeenVaultRevision'],
    updatedAt: ProtectedLocalDeviceState['updatedAt'],
  ): Promise<void> {
    const account = protectedStateAccountFor(vaultId, deviceId);
    const observationId = sha256DigestSchema.safeParse(expectedObservationId);
    const parsedRevision = vaultRevisionSchema.safeParse(candidateRevision);
    const parsedTimestamp = canonicalTimestamp(updatedAt);
    if (!observationId.success || !parsedRevision.success || parsedTimestamp === null) {
      throw new SyncLocalStateError();
    }
    return withProtectedStateQueue(this.#service, account, async () => {
      const existing = await this.#load(account, vaultId, deviceId);
      if (
        existing === null ||
        parsedRevision.data < existing.highestSeenVaultRevision
      ) {
        throw new SyncLocalStateError();
      }
      const pending = existing.outboundObservation;
      if (pending === undefined) {
        if (existing.lastCompletedObservationId !== observationId.data) {
          throw new SyncLocalStateError();
        }
        const higherRevision = parsedRevision.data > existing.highestSeenVaultRevision;
        const newerTimestamp = parsedTimestamp > Date.parse(existing.updatedAt);
        if (!higherRevision && !newerTimestamp) return;
        await this.#write(
          account,
          parseProtectedState({
            ...existing,
            highestSeenVaultRevision: parsedRevision.data,
            updatedAt: maximumTimestamp(existing.updatedAt, updatedAt),
          }),
        );
        return;
      } else if (pending.observationId !== observationId.data) {
        throw new SyncLocalStateError();
      }
      const completed = parseProtectedState({
        version: 2,
        vaultId,
        deviceId,
        highestSeenVaultRevision: parsedRevision.data,
        updatedAt: maximumTimestamp(existing.updatedAt, updatedAt),
        lastCompletedObservationId: observationId.data,
      });
      await this.#write(account, completed);
    });
  }

  public async delete(vaultId: VaultId, deviceId: DeviceId): Promise<void> {
    const account = protectedStateAccountFor(vaultId, deviceId);
    return withProtectedStateQueue(this.#service, account, async () => {
      const existing = await this.#load(account, vaultId, deviceId);
      if (existing?.outboundObservation !== undefined) {
        throw new SyncLocalStateError();
      }
      try {
        await this.#createEntry(this.#service, account).deleteCredential();
      } catch (error) {
        const code = nativeErrorCode(error);
        if (code.includes('noentry') || code.includes('notfound')) return;
        throw classifyNativeFailure(error);
      }
    });
  }

  async #load(
    account: string,
    vaultIdInput: VaultId,
    deviceIdInput: DeviceId,
  ): Promise<ProtectedLocalDeviceState | null> {
    let nativeValue: unknown;
    try {
      nativeValue = await this.#createEntry(this.#service, account).getSecret();
    } catch (error) {
      throw classifyNativeFailure(error);
    }
    const encoded = toOwnedNativeBytes(nativeValue);
    if (encoded === null) return null;
    try {
      return decodeProtectedState(encoded, vaultIdInput, deviceIdInput);
    } finally {
      encoded.fill(0);
    }
  }

  async #write(account: string, state: ProtectedLocalDeviceState): Promise<void> {
    const encoded = encodeProtectedState(state);
    try {
      await this.#createEntry(this.#service, account).setSecret(encoded);
    } catch (error) {
      throw classifyNativeFailure(error);
    } finally {
      encoded.fill(0);
    }
  }
}

export async function createNativeKeychain(
  service = DEFAULT_KEYCHAIN_SERVICE,
): Promise<NativeKeychain> {
  assertSafeService(service);
  return new NativeKeychain(await loadNativeEntryFactory(), service);
}

export async function createNativeSessionCredentials(
  service = DEFAULT_KEYCHAIN_SERVICE,
): Promise<NativeSessionCredentials> {
  assertSafeService(service);
  return new NativeSessionCredentials(await loadNativeEntryFactory(), service);
}

export async function createNativeProtectedSyncState(
  service = DEFAULT_KEYCHAIN_SERVICE,
): Promise<NativeProtectedSyncState> {
  assertSafeService(service);
  return new NativeProtectedSyncState(await loadNativeEntryFactory(), service);
}

function parseProtectedState(
  input: ProtectedLocalDeviceState,
): ProtectedLocalDeviceState {
  let parsed: ProtectedLocalDeviceState;
  try {
    parsed = validateOutboundObservationBinding(input);
  } catch {
    throw new SyncLocalStateError();
  }
  if (canonicalTimestamp(parsed.updatedAt) === null) throw new SyncLocalStateError();
  return parsed;
}

function encodeProtectedState(state: ProtectedLocalDeviceState): Uint8Array {
  const vault = new TextEncoder().encode(state.vaultId);
  const device = new TextEncoder().encode(state.deviceId);
  const batch =
    state.outboundObservation === undefined
      ? new Uint8Array()
      : new TextEncoder().encode(state.outboundObservation.batchIdempotencyKey);
  const digests = [
    ...(state.outboundObservation === undefined
      ? []
      : [
          decodeDigest(state.outboundObservation.requestHash),
          decodeDigest(state.outboundObservation.responseHash),
          decodeDigest(state.outboundObservation.observationId),
        ]),
    ...(state.lastCompletedObservationId === undefined
      ? []
      : [decodeDigest(state.lastCompletedObservationId)]),
  ];
  const updatedAt = canonicalTimestamp(state.updatedAt);
  if (
    vault.byteLength < 1 ||
    vault.byteLength > 0xffff ||
    device.byteLength < 1 ||
    device.byteLength > 0xffff ||
    batch.byteLength > 0xffff ||
    updatedAt === null
  ) {
    wipeAll(vault, device, batch, ...digests);
    throw new SyncLocalStateError();
  }
  const observationBytes =
    state.outboundObservation === undefined ? 0 : 1 + 1 + 2 + batch.byteLength + 120;
  const completedBytes = state.lastCompletedObservationId === undefined ? 0 : 32;
  const encodedLength =
    PROTECTED_STATE_MAGIC.byteLength +
    1 +
    1 +
    2 +
    vault.byteLength +
    2 +
    device.byteLength +
    16 +
    observationBytes +
    completedBytes;
  if (encodedLength > PROTECTED_STATE_MAX_BYTES) {
    wipeAll(vault, device, batch, ...digests);
    throw new SyncLocalStateError();
  }
  const encoded = new Uint8Array(encodedLength);
  try {
    let offset = 0;
    encoded.set(PROTECTED_STATE_MAGIC, offset);
    offset += PROTECTED_STATE_MAGIC.byteLength;
    encoded[offset] = PROTECTED_STATE_VERSION_V2;
    offset += 1;
    let flags = 0;
    if (state.outboundObservation !== undefined) {
      flags |= PROTECTED_STATE_FLAG_OBSERVATION;
    }
    if (state.lastCompletedObservationId !== undefined) {
      flags |= PROTECTED_STATE_FLAG_LAST_COMPLETED;
    }
    encoded[offset] = flags;
    offset += 1;
    const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
    view.setUint16(offset, vault.byteLength, false);
    offset += 2;
    encoded.set(vault, offset);
    offset += vault.byteLength;
    view.setUint16(offset, device.byteLength, false);
    offset += 2;
    encoded.set(device, offset);
    offset += device.byteLength;
    view.setBigUint64(offset, BigInt(state.highestSeenVaultRevision), false);
    offset += 8;
    view.setBigInt64(offset, BigInt(updatedAt), false);
    offset += 8;
    if (state.outboundObservation !== undefined) {
      encoded[offset] = state.outboundObservation.version;
      offset += 1;
      encoded[offset] = state.outboundObservation.kind === 'generic-push' ? 1 : 2;
      offset += 1;
      view.setUint16(offset, batch.byteLength, false);
      offset += 2;
      encoded.set(batch, offset);
      offset += batch.byteLength;
      for (const digest of digests.slice(0, 2)) {
        encoded.set(digest, offset);
        offset += digest.byteLength;
      }
      view.setBigUint64(
        offset,
        BigInt(state.outboundObservation.responseVaultRevision),
        false,
      );
      offset += 8;
      view.setBigUint64(
        offset,
        BigInt(state.outboundObservation.replayFromServerSequence),
        false,
      );
      offset += 8;
      view.setBigUint64(
        offset,
        BigInt(state.outboundObservation.requiredThroughServerSequence),
        false,
      );
      offset += 8;
      const observationId = digests[2];
      if (observationId === undefined) throw new SyncLocalStateError();
      encoded.set(observationId, offset);
      offset += observationId.byteLength;
    }
    if (state.lastCompletedObservationId !== undefined) {
      const digest = digests.at(-1);
      if (digest === undefined) throw new SyncLocalStateError();
      encoded.set(digest, offset);
      offset += digest.byteLength;
    }
    if (offset !== encoded.byteLength) throw new SyncLocalStateError();
    return encoded;
  } catch (error) {
    encoded.fill(0);
    if (error instanceof SyncLocalStateError) throw error;
    throw new SyncLocalStateError();
  } finally {
    wipeAll(vault, device, batch, ...digests);
  }
}

function decodeProtectedState(
  encoded: Uint8Array,
  expectedVaultId: VaultId,
  expectedDeviceId: DeviceId,
): ProtectedLocalDeviceState {
  try {
    if (encoded.byteLength > PROTECTED_STATE_MAX_BYTES) {
      throw corruptedProtectedState();
    }
    let offset = 0;
    if (
      encoded.byteLength <
        PROTECTED_STATE_MAGIC.byteLength +
          1 +
          1 +
          1 +
          PROTECTED_STATE_V1_TRAILER_BYTES ||
      !PROTECTED_STATE_MAGIC.every((value, index) => encoded[index] === value)
    ) {
      throw new KeychainError(
        'KEYCHAIN_CORRUPTED',
        'The native credential store returned invalid protected state.',
      );
    }
    offset += PROTECTED_STATE_MAGIC.byteLength;
    const version = encoded[offset];
    offset += 1;
    if (version === PROTECTED_STATE_VERSION_V1) {
      return decodeProtectedStateV1(encoded, offset, expectedVaultId, expectedDeviceId);
    }
    if (version !== PROTECTED_STATE_VERSION_V2) throw corruptedProtectedState();
    return decodeProtectedStateV2(encoded, offset, expectedVaultId, expectedDeviceId);
  } catch (error) {
    if (error instanceof KeychainError) throw error;
    throw corruptedProtectedState();
  }
}

function decodeProtectedStateV1(
  encoded: Uint8Array,
  initialOffset: number,
  expectedVaultId: VaultId,
  expectedDeviceId: DeviceId,
): ProtectedLocalDeviceState {
  let offset = initialOffset;
  try {
    const vaultLength = encoded[offset];
    if (vaultLength === undefined || vaultLength < 1 || vaultLength > 128) {
      throw corruptedProtectedState();
    }
    offset += 1;
    const vaultEnd = offset + vaultLength;
    if (vaultEnd > encoded.byteLength) throw corruptedProtectedState();
    const vaultId = new TextDecoder('utf-8', { fatal: true }).decode(
      encoded.subarray(offset, vaultEnd),
    );
    offset = vaultEnd;
    const deviceLength = encoded[offset];
    if (deviceLength === undefined || deviceLength < 1 || deviceLength > 128) {
      throw corruptedProtectedState();
    }
    offset += 1;
    const deviceEnd = offset + deviceLength;
    if (deviceEnd + PROTECTED_STATE_V1_TRAILER_BYTES !== encoded.byteLength) {
      throw corruptedProtectedState();
    }
    const deviceId = new TextDecoder('utf-8', { fatal: true }).decode(
      encoded.subarray(offset, deviceEnd),
    );
    offset = deviceEnd;
    const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
    const revision = view.getBigUint64(offset, false);
    offset += 8;
    const updatedAtMilliseconds = view.getBigInt64(offset, false);
    if (
      revision > BigInt(Number.MAX_SAFE_INTEGER) ||
      updatedAtMilliseconds < BigInt(Number.MIN_SAFE_INTEGER) ||
      updatedAtMilliseconds > BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      throw corruptedProtectedState();
    }
    const updatedAt = new Date(Number(updatedAtMilliseconds)).toISOString();
    const parsed = protectedLocalDeviceStateSchema.safeParse({
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: Number(revision),
      updatedAt,
    });
    if (
      !parsed.success ||
      parsed.data.vaultId !== expectedVaultId ||
      parsed.data.deviceId !== expectedDeviceId
    ) {
      throw corruptedProtectedState();
    }
    return parsed.data;
  } catch {
    throw corruptedProtectedState();
  }
}

function decodeProtectedStateV2(
  encoded: Uint8Array,
  initialOffset: number,
  expectedVaultId: VaultId,
  expectedDeviceId: DeviceId,
): ProtectedLocalDeviceState {
  let offset = initialOffset;
  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  const flags = readUint8(encoded, offset);
  offset += 1;
  if ((flags & ~PROTECTED_STATE_KNOWN_FLAGS) !== 0) throw corruptedProtectedState();
  const vault = readText16(encoded, view, offset);
  offset = vault.offset;
  const device = readText16(encoded, view, offset);
  offset = device.offset;
  const highestSeenVaultRevision = readSafeUint64(view, offset);
  offset += 8;
  const updatedAtMilliseconds = readSafeInt64(view, offset);
  offset += 8;
  let outboundObservation: ProtectedLocalDeviceState['outboundObservation'];
  if ((flags & PROTECTED_STATE_FLAG_OBSERVATION) !== 0) {
    if (readUint8(encoded, offset) !== 1) throw corruptedProtectedState();
    offset += 1;
    const kindByte = readUint8(encoded, offset);
    offset += 1;
    if (kindByte !== 1 && kindByte !== 2) throw corruptedProtectedState();
    const batch = readText16(encoded, view, offset);
    offset = batch.offset;
    const requestHash = readDigest(encoded, offset);
    offset += 32;
    const responseHash = readDigest(encoded, offset);
    offset += 32;
    const responseVaultRevision = readSafeUint64(view, offset);
    offset += 8;
    const replayFromServerSequence = readSafeUint64(view, offset);
    offset += 8;
    const requiredThroughServerSequence = readSafeUint64(view, offset);
    offset += 8;
    const observationId = readDigest(encoded, offset);
    offset += 32;
    outboundObservation = {
      version: 1,
      observationId,
      kind: kindByte === 1 ? 'generic-push' : 'template-publication',
      batchIdempotencyKey: batch.value,
      requestHash,
      responseHash,
      responseVaultRevision,
      replayFromServerSequence,
      requiredThroughServerSequence,
    } as ProtectedLocalDeviceState['outboundObservation'];
  }
  let lastCompletedObservationId: Sha256Digest | undefined;
  if ((flags & PROTECTED_STATE_FLAG_LAST_COMPLETED) !== 0) {
    lastCompletedObservationId = readDigest(encoded, offset);
    offset += 32;
  }
  if (offset !== encoded.byteLength) throw corruptedProtectedState();
  const parsed = protectedLocalDeviceStateSchema.safeParse({
    version: 2,
    vaultId: vault.value,
    deviceId: device.value,
    highestSeenVaultRevision,
    updatedAt: new Date(updatedAtMilliseconds).toISOString(),
    ...(outboundObservation === undefined ? {} : { outboundObservation }),
    ...(lastCompletedObservationId === undefined ? {} : { lastCompletedObservationId }),
  });
  if (
    !parsed.success ||
    parsed.data.vaultId !== expectedVaultId ||
    parsed.data.deviceId !== expectedDeviceId
  ) {
    throw corruptedProtectedState();
  }
  try {
    return validateOutboundObservationBinding(parsed.data);
  } catch {
    throw corruptedProtectedState();
  }
}

function transitionForSave(
  existing: ProtectedLocalDeviceState | null,
  candidate: ProtectedLocalDeviceState,
): ProtectedLocalDeviceState | null {
  if (existing === null) {
    if (candidate.lastCompletedObservationId !== undefined) {
      throw new SyncLocalStateError();
    }
    return candidate;
  }
  if (candidate.highestSeenVaultRevision < existing.highestSeenVaultRevision) {
    throw new SyncLocalStateError();
  }
  if (candidate.lastCompletedObservationId !== existing.lastCompletedObservationId) {
    throw new SyncLocalStateError();
  }
  const existingObservation = existing.outboundObservation;
  const candidateObservation = candidate.outboundObservation;
  if (existingObservation !== undefined) {
    if (
      candidateObservation === undefined ||
      !observationsEqual(existingObservation, candidateObservation)
    ) {
      throw new SyncLocalStateError();
    }
  }
  const semanticBegin =
    existingObservation === undefined && candidateObservation !== undefined;
  if (
    semanticBegin &&
    candidateObservation.responseVaultRevision < existing.highestSeenVaultRevision
  ) {
    throw new SyncLocalStateError();
  }
  const higherRevision =
    candidate.highestSeenVaultRevision > existing.highestSeenVaultRevision;
  const newerTimestamp =
    Date.parse(candidate.updatedAt) > Date.parse(existing.updatedAt);
  if (!semanticBegin && !higherRevision && !newerTimestamp) return null;
  return parseProtectedState({
    ...candidate,
    updatedAt: maximumTimestamp(existing.updatedAt, candidate.updatedAt),
  });
}

function observationsEqual(
  left: NonNullable<ProtectedLocalDeviceState['outboundObservation']>,
  right: NonNullable<ProtectedLocalDeviceState['outboundObservation']>,
): boolean {
  return (
    left.observationId === right.observationId &&
    left.kind === right.kind &&
    left.batchIdempotencyKey === right.batchIdempotencyKey &&
    left.requestHash === right.requestHash &&
    left.responseHash === right.responseHash &&
    left.responseVaultRevision === right.responseVaultRevision &&
    left.replayFromServerSequence === right.replayFromServerSequence &&
    left.requiredThroughServerSequence === right.requiredThroughServerSequence
  );
}

function maximumTimestamp(left: string, right: string): string {
  return Date.parse(left) >= Date.parse(right) ? left : right;
}

function decodeDigest(value: Sha256Digest): Uint8Array {
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.byteLength !== 32) {
    decoded.fill(0);
    throw new SyncLocalStateError();
  }
  return decoded;
}

function readUint8(encoded: Uint8Array, offset: number): number {
  const value = encoded[offset];
  if (value === undefined) throw corruptedProtectedState();
  return value;
}

function readText16(
  encoded: Uint8Array,
  view: DataView,
  offset: number,
): { value: string; offset: number } {
  const length = view.getUint16(offset, false);
  offset += 2;
  if (length < 1 || offset + length > encoded.byteLength) {
    throw corruptedProtectedState();
  }
  const end = offset + length;
  return {
    value: new TextDecoder('utf-8', { fatal: true }).decode(
      encoded.subarray(offset, end),
    ),
    offset: end,
  };
}

function readSafeUint64(view: DataView, offset: number): number {
  const value = view.getBigUint64(offset, false);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw corruptedProtectedState();
  return Number(value);
}

function readSafeInt64(view: DataView, offset: number): number {
  const value = view.getBigInt64(offset, false);
  if (
    value < BigInt(Number.MIN_SAFE_INTEGER) ||
    value > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw corruptedProtectedState();
  }
  return Number(value);
}

function readDigest(encoded: Uint8Array, offset: number): Sha256Digest {
  const end = offset + 32;
  if (end > encoded.byteLength) throw corruptedProtectedState();
  const owned = Buffer.from(encoded.subarray(offset, end));
  try {
    const parsed = sha256DigestSchema.safeParse(owned.toString('base64url'));
    if (!parsed.success) throw corruptedProtectedState();
    return parsed.data;
  } finally {
    owned.fill(0);
  }
}

function wipeAll(...values: Uint8Array[]): void {
  for (const value of values) value.fill(0);
}

function canonicalTimestamp(value: string): number | null {
  const milliseconds = Date.parse(value);
  if (
    !Number.isSafeInteger(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    return null;
  }
  return milliseconds;
}

function corruptedProtectedState(): KeychainError {
  return new KeychainError(
    'KEYCHAIN_CORRUPTED',
    'The native credential store returned invalid protected state.',
  );
}

/**
 * Assembled at runtime so a bundler cannot statically follow it. The published
 * package is dependency-free and must not inline the adapter's `.node` binary,
 * but the adapter must still load when a host installation provides it.
 */
const NATIVE_KEYRING_SPECIFIER = ['@napi-rs', 'keyring'].join('/');

type NativeKeyringModule = Readonly<{ AsyncEntry: AsyncEntryConstructor }>;

/**
 * Resolution is synchronous, but the published contract stays promise-based so
 * every caller has a single failure channel: an unavailable or malformed
 * adapter rejects instead of throwing while the call is being evaluated.
 */
export function loadNativeEntryFactory(): Promise<NativeEntryFactory> {
  return Promise.resolve().then(() => {
    let AsyncEntry: AsyncEntryConstructor;
    try {
      // Anchored to this module, never the working directory, so an untrusted CWD
      // cannot substitute the native library that unlocks the vault.
      const resolveFromHere = createRequire(import.meta.url);
      ({ AsyncEntry } = resolveFromHere(
        NATIVE_KEYRING_SPECIFIER,
      ) as NativeKeyringModule);
    } catch {
      throw new KeychainError(
        'KEYCHAIN_UNAVAILABLE',
        'No supported native operating-system credential store is available.',
      );
    }
    if (typeof AsyncEntry !== 'function') {
      throw new KeychainError(
        'KEYCHAIN_UNAVAILABLE',
        'No supported native operating-system credential store is available.',
      );
    }
    return (service, account) => new AsyncEntry(service, account);
  });
}

export async function tryLoadNativeEntryFactory(): Promise<NativeEntryFactory | null> {
  try {
    return await loadNativeEntryFactory();
  } catch (error) {
    if (error instanceof KeychainError && error.code === 'KEYCHAIN_UNAVAILABLE') {
      return null;
    }
    throw error;
  }
}
