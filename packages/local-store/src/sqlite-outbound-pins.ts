import type { DatabaseSync } from 'node:sqlite';

import {
  deviceIdSchema,
  MAX_IDEMPOTENCY_KEY_CHARS,
  MIN_IDEMPOTENCY_KEY_CHARS,
  sha256DigestSchema,
  vaultIdSchema,
  type DeviceId,
  type OutboundObservation,
  type Sha256Digest,
  type VaultId,
} from '@kavrix/schemas';

import { invalidState } from './sqlite-local-errors.js';
import type {
  PersistedOutboundObservationPinRow,
  VaultStateLimits,
} from './sqlite-vault-schema.js';

export type OutboundObservationPin = Readonly<{
  vaultId: VaultId;
  deviceId: DeviceId;
  observationId: Sha256Digest;
  kind: OutboundObservation['kind'];
  state: 'pinned' | 'released';
  acceptedKeys: readonly string[];
}>;

export class SqliteOutboundPins {
  readonly #database: DatabaseSync;
  readonly #limits: VaultStateLimits;

  constructor(database: DatabaseSync, limits: VaultStateLimits) {
    this.#database = database;
    this.#limits = limits;
  }

  load(vaultIdInput: VaultId): OutboundObservationPin | null {
    const vaultId = parseVaultId(vaultIdInput);
    const row = this.#database
      .prepare(
        `SELECT vault_id, device_id, observation_id, kind, state,
                accepted_keys_json, serialized_bytes
           FROM outbound_observation_pins WHERE vault_id = ?`,
      )
      .get(vaultId) as PersistedOutboundObservationPinRow | undefined;
    return row === undefined ? null : parsePinRow(row, vaultId, this.#limits);
  }

  pin(
    vaultIdInput: VaultId,
    deviceIdInput: DeviceId,
    observation: OutboundObservation,
    acceptedKeysInput: readonly string[],
  ): void {
    const vaultId = parseVaultId(vaultIdInput);
    const deviceId = parseDeviceId(deviceIdInput);
    const observationId = parseObservationId(observation.observationId);
    const acceptedKeys = parseAcceptedKeys(acceptedKeysInput);
    const acceptedKeysJson = JSON.stringify(acceptedKeys);
    if (Buffer.byteLength(acceptedKeysJson) > this.#limits.maxSerializedRowBytes) {
      throw invalidState();
    }
    const expected: OutboundObservationPin = {
      vaultId,
      deviceId,
      observationId,
      kind: observation.kind,
      state: 'pinned',
      acceptedKeys,
    };
    const existing = this.load(vaultId);
    if (existing?.state === 'pinned') {
      if (!samePin(existing, expected)) throw invalidState();
      return;
    }
    if (existing === null) {
      this.#database
        .prepare(
          `INSERT INTO outbound_observation_pins
             (vault_id, device_id, observation_id, kind, state,
              accepted_keys_json, serialized_bytes)
           VALUES (?, ?, ?, ?, 'pinned', ?, ?)`,
        )
        .run(
          vaultId,
          deviceId,
          observationId,
          observation.kind,
          acceptedKeysJson,
          Buffer.byteLength(acceptedKeysJson),
        );
    } else {
      const changed = this.#database
        .prepare(
          `UPDATE outbound_observation_pins
              SET device_id = ?, observation_id = ?, kind = ?, state = 'pinned',
                  accepted_keys_json = ?, serialized_bytes = ?
            WHERE vault_id = ? AND state = 'released'
              AND observation_id = ? AND device_id = ?`,
        )
        .run(
          deviceId,
          observationId,
          observation.kind,
          acceptedKeysJson,
          Buffer.byteLength(acceptedKeysJson),
          vaultId,
          existing.observationId,
          existing.deviceId,
        );
      if (changed.changes !== 1) throw invalidState();
    }
    this.assertBounds();
  }

  requirePinned(
    vaultId: VaultId,
    deviceIdInput: DeviceId,
    observation: OutboundObservation,
    acceptedKeysInput: readonly string[],
  ): void {
    const pin = this.load(vaultId);
    const expected: OutboundObservationPin = {
      vaultId: parseVaultId(vaultId),
      deviceId: parseDeviceId(deviceIdInput),
      observationId: parseObservationId(observation.observationId),
      kind: observation.kind,
      state: 'pinned',
      acceptedKeys: parseAcceptedKeys(acceptedKeysInput),
    };
    if (pin === null || !samePin(pin, expected)) throw invalidState();
  }

  release(
    vaultIdInput: VaultId,
    deviceIdInput: DeviceId,
    observationIdInput: Sha256Digest,
  ): void {
    const vaultId = parseVaultId(vaultIdInput);
    const deviceId = parseDeviceId(deviceIdInput);
    const observationId = parseObservationId(observationIdInput);
    const existing = this.load(vaultId);
    if (existing?.deviceId !== deviceId || existing.observationId !== observationId) {
      throw invalidState();
    }
    if (existing.state === 'released') return;
    const changed = this.#database
      .prepare(
        `UPDATE outbound_observation_pins SET state = 'released'
          WHERE vault_id = ? AND device_id = ? AND observation_id = ?
            AND state = 'pinned'`,
      )
      .run(vaultId, deviceId, observationId);
    if (changed.changes !== 1) throw invalidState();
  }

  pinnedObservationIds(kind: OutboundObservation['kind']): ReadonlySet<string> {
    const result = new Set<string>();
    for (const pin of this.#all()) {
      if (pin.state === 'pinned' && pin.kind === kind) {
        result.add(pin.observationId);
      }
    }
    return result;
  }

  pinnedMutationKeys(): ReadonlySet<string> {
    const result = new Set<string>();
    for (const pin of this.#all()) {
      if (pin.state !== 'pinned') continue;
      for (const key of pin.acceptedKeys) result.add(key);
    }
    return result;
  }

  assertCanonicalRows(): void {
    this.#all();
    this.assertBounds();
  }

  assertBounds(): void {
    const row = this.#database
      .prepare(`SELECT COUNT(*) AS value FROM outbound_observation_pins`)
      .get() as { value?: unknown } | undefined;
    if (
      row === undefined ||
      !Number.isSafeInteger(row.value) ||
      (row.value as number) < 0 ||
      (row.value as number) > this.#limits.maxVaults
    ) {
      throw invalidState();
    }
  }

  #all(): readonly OutboundObservationPin[] {
    const rows = this.#database
      .prepare(
        `SELECT vault_id, device_id, observation_id, kind, state,
                accepted_keys_json, serialized_bytes
           FROM outbound_observation_pins ORDER BY vault_id ASC`,
      )
      .all() as unknown as PersistedOutboundObservationPinRow[];
    return rows.map((row) => parsePinRow(row, undefined, this.#limits));
  }
}

function parsePinRow(
  row: PersistedOutboundObservationPinRow,
  expectedVaultId: VaultId | undefined,
  limits: VaultStateLimits,
): OutboundObservationPin {
  const vaultId = parseVaultId(row.vault_id);
  const deviceId = parseDeviceId(row.device_id);
  const observationId = parseObservationId(row.observation_id);
  if (
    (expectedVaultId !== undefined && vaultId !== expectedVaultId) ||
    (row.kind !== 'generic-push' && row.kind !== 'template-publication') ||
    (row.state !== 'pinned' && row.state !== 'released') ||
    typeof row.accepted_keys_json !== 'string'
  ) {
    throw invalidState();
  }
  const acceptedKeys = parseAcceptedKeysJson(row.accepted_keys_json);
  const bytes = Buffer.byteLength(row.accepted_keys_json);
  if (bytes > limits.maxSerializedRowBytes || row.serialized_bytes !== bytes) {
    throw invalidState();
  }
  return {
    vaultId,
    deviceId,
    observationId,
    kind: row.kind,
    state: row.state,
    acceptedKeys,
  };
}

function parseAcceptedKeysJson(value: string): readonly string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw invalidState();
  }
  const keys = parseAcceptedKeys(parsed);
  if (JSON.stringify(keys) !== value) throw invalidState();
  return keys;
}

function parseAcceptedKeys(value: unknown): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.length > 100 ||
    value.some(
      (key) =>
        typeof key !== 'string' ||
        key.length < MIN_IDEMPOTENCY_KEY_CHARS ||
        key.length > MAX_IDEMPOTENCY_KEY_CHARS,
    ) ||
    new Set(value).size !== value.length
  ) {
    throw invalidState();
  }
  return value as readonly string[];
}

function parseVaultId(value: unknown): VaultId {
  const parsed = vaultIdSchema.safeParse(value);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

function parseDeviceId(value: unknown): DeviceId {
  const parsed = deviceIdSchema.safeParse(value);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

function parseObservationId(value: unknown): Sha256Digest {
  const parsed = sha256DigestSchema.safeParse(value);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

function samePin(
  actual: OutboundObservationPin,
  expected: OutboundObservationPin,
): boolean {
  return (
    actual.vaultId === expected.vaultId &&
    actual.deviceId === expected.deviceId &&
    actual.observationId === expected.observationId &&
    actual.kind === expected.kind &&
    actual.state === expected.state &&
    JSON.stringify(actual.acceptedKeys) === JSON.stringify(expected.acceptedKeys)
  );
}
