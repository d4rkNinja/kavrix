import type { KeychainPort, SessionCredentialPort } from '@kavrix/core';
import type { AsyncEntry as AsyncEntryInstance } from '@napi-rs/keyring';
import {
  deviceIdSchema,
  deviceUnlockSecretSchema,
  keychainLocatorSchema,
  protectedLocalDeviceStateSchema,
  sessionCredentialLocatorSchema,
  sessionCredentialSecretSchema,
  vaultIdSchema,
  type DeviceId,
  type DeviceUnlockSecret,
  type KeychainLocator,
  type ProtectedLocalDeviceState,
  type SessionCredentialLocator,
  type SessionCredentialSecret,
  type VaultId,
} from '@kavrix/schemas';
import { SyncLocalStateError, type ProtectedSyncStatePort } from '@kavrix/sync';

import { KeychainError } from './errors.js';

export const DEFAULT_KEYCHAIN_SERVICE = 'dev.kavrix.credentials';
const SAFE_SERVICE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const PROTECTED_STATE_MAGIC = Uint8Array.of(0x4b, 0x53, 0x53, 0x54);
const PROTECTED_STATE_VERSION = 1;
const PROTECTED_STATE_TRAILER_BYTES = 16;

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
  #tail: Promise<void> = Promise.resolve();

  public constructor(
    createEntry: NativeEntryFactory,
    service = DEFAULT_KEYCHAIN_SERVICE,
  ) {
    assertSafeService(service);
    this.#createEntry = createEntry;
    this.#service = service;
  }

  public load(
    vaultId: VaultId,
    deviceId: DeviceId,
  ): Promise<ProtectedLocalDeviceState | null> {
    return this.#exclusive(() => this.#load(vaultId, deviceId));
  }

  public save(stateInput: ProtectedLocalDeviceState): Promise<void> {
    return this.#exclusive(async () => {
      const state = parseProtectedState(stateInput);
      const existing = await this.#load(state.vaultId, state.deviceId);
      if (
        existing !== null &&
        (state.highestSeenVaultRevision < existing.highestSeenVaultRevision ||
          (state.highestSeenVaultRevision === existing.highestSeenVaultRevision &&
            Date.parse(state.updatedAt) < Date.parse(existing.updatedAt)))
      ) {
        throw new SyncLocalStateError();
      }
      const encoded = encodeProtectedState(state);
      try {
        await this.#createEntry(
          this.#service,
          protectedStateAccountFor(state.vaultId, state.deviceId),
        ).setSecret(encoded);
      } catch (error) {
        throw classifyNativeFailure(error);
      } finally {
        encoded.fill(0);
      }
    });
  }

  public delete(vaultId: VaultId, deviceId: DeviceId): Promise<void> {
    return this.#exclusive(async () => {
      try {
        await this.#createEntry(
          this.#service,
          protectedStateAccountFor(vaultId, deviceId),
        ).deleteCredential();
      } catch (error) {
        const code = nativeErrorCode(error);
        if (code.includes('noentry') || code.includes('notfound')) return;
        throw classifyNativeFailure(error);
      }
    });
  }

  async #load(
    vaultIdInput: VaultId,
    deviceIdInput: DeviceId,
  ): Promise<ProtectedLocalDeviceState | null> {
    const account = protectedStateAccountFor(vaultIdInput, deviceIdInput);
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

  #exclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
    const predecessor = this.#tail;
    let release: (() => void) | undefined;
    this.#tail = new Promise((resolve) => {
      release = resolve;
    });
    return predecessor.then(operation).finally(() => release?.());
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
  const parsed = protectedLocalDeviceStateSchema.safeParse(input);
  if (!parsed.success || canonicalTimestamp(parsed.data.updatedAt) === null) {
    throw new SyncLocalStateError();
  }
  return parsed.data;
}

function encodeProtectedState(state: ProtectedLocalDeviceState): Uint8Array {
  const vault = new TextEncoder().encode(state.vaultId);
  const device = new TextEncoder().encode(state.deviceId);
  const updatedAt = canonicalTimestamp(state.updatedAt);
  if (
    vault.byteLength < 1 ||
    vault.byteLength > 128 ||
    device.byteLength < 1 ||
    device.byteLength > 128 ||
    updatedAt === null
  ) {
    vault.fill(0);
    device.fill(0);
    throw new SyncLocalStateError();
  }
  const encoded = new Uint8Array(
    PROTECTED_STATE_MAGIC.byteLength +
      1 +
      1 +
      vault.byteLength +
      1 +
      device.byteLength +
      PROTECTED_STATE_TRAILER_BYTES,
  );
  try {
    let offset = 0;
    encoded.set(PROTECTED_STATE_MAGIC, offset);
    offset += PROTECTED_STATE_MAGIC.byteLength;
    encoded[offset] = PROTECTED_STATE_VERSION;
    offset += 1;
    encoded[offset] = vault.byteLength;
    offset += 1;
    encoded.set(vault, offset);
    offset += vault.byteLength;
    encoded[offset] = device.byteLength;
    offset += 1;
    encoded.set(device, offset);
    offset += device.byteLength;
    const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
    view.setBigUint64(offset, BigInt(state.highestSeenVaultRevision), false);
    offset += 8;
    view.setBigInt64(offset, BigInt(updatedAt), false);
    return encoded;
  } catch (error) {
    encoded.fill(0);
    if (error instanceof SyncLocalStateError) throw error;
    throw new SyncLocalStateError();
  } finally {
    vault.fill(0);
    device.fill(0);
  }
}

function decodeProtectedState(
  encoded: Uint8Array,
  expectedVaultId: VaultId,
  expectedDeviceId: DeviceId,
): ProtectedLocalDeviceState {
  try {
    let offset = 0;
    if (
      encoded.byteLength <
        PROTECTED_STATE_MAGIC.byteLength + 1 + 1 + 1 + PROTECTED_STATE_TRAILER_BYTES ||
      !PROTECTED_STATE_MAGIC.every((value, index) => encoded[index] === value)
    ) {
      throw new KeychainError(
        'KEYCHAIN_CORRUPTED',
        'The native credential store returned invalid protected state.',
      );
    }
    offset += PROTECTED_STATE_MAGIC.byteLength;
    if (encoded[offset] !== PROTECTED_STATE_VERSION) throw corruptedProtectedState();
    offset += 1;
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
    if (deviceEnd + PROTECTED_STATE_TRAILER_BYTES !== encoded.byteLength) {
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
  } catch (error) {
    if (error instanceof KeychainError) throw error;
    throw corruptedProtectedState();
  }
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

export async function loadNativeEntryFactory(): Promise<NativeEntryFactory> {
  let AsyncEntry: AsyncEntryConstructor;
  try {
    ({ AsyncEntry } = await import('@napi-rs/keyring'));
  } catch {
    throw new KeychainError(
      'KEYCHAIN_UNAVAILABLE',
      'No supported native operating-system credential store is available.',
    );
  }
  return (service, account) => new AsyncEntry(service, account);
}
