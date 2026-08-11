import type { DatabaseSync } from 'node:sqlite';

import {
  vaultProfileSchema,
  type VaultProfile,
  type VaultProfileStorePort,
} from '@kavrix/client';
import {
  deviceIdSchema,
  vaultIdSchema,
  type DeviceId,
  type VaultId,
} from '@kavrix/schemas';

import {
  SqliteLifecycleJournalBase,
  VAULT_PROFILE_APPLICATION_ID,
  invalidState,
  openLifecycleDatabase,
  parseLifecycleOptions,
  withTransaction,
  type LifecycleJournalLimits,
  type SqliteLifecycleJournalOptions,
} from './lifecycle-journal-db.js';
import type { LocalWriterLease } from './local-writer-lease.js';

const MAX_PROFILE_LIMIT = 256;

const VAULT_PROFILE_SCHEMA = {
  lifecycle_metadata: `CREATE TABLE lifecycle_metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
  vault_profiles: `CREATE TABLE vault_profiles (
    vault_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2),
    device_locator_json TEXT NOT NULL UNIQUE,
    session_locator_json TEXT NOT NULL UNIQUE,
    PRIMARY KEY(vault_id, device_id)
  ) STRICT, WITHOUT ROWID`,
} as const;

export interface SqliteVaultProfileStoreOptions {
  readonly path: string;
  readonly leasePath?: string;
  readonly maxProfiles?: number;
  readonly maxSerializedBytes?: number;
  readonly maxDatabaseBytes?: number;
}

type VaultProfileRow = Readonly<{
  vault_id: unknown;
  device_id: unknown;
  profile_json: unknown;
  serialized_bytes: unknown;
  device_locator_json: unknown;
  session_locator_json: unknown;
}>;

export class SqliteVaultProfileStore
  extends SqliteLifecycleJournalBase
  implements VaultProfileStorePort
{
  private constructor(
    database: DatabaseSync,
    databasePath: string,
    limits: LifecycleJournalLimits,
    lease: LocalWriterLease,
  ) {
    super(database, databasePath, limits, lease);
  }

  public static async open(
    options: SqliteVaultProfileStoreOptions,
  ): Promise<SqliteVaultProfileStore> {
    const limits = parseProfileOptions(options);
    const opened = await openLifecycleDatabase(
      {
        path: options.path,
        ...(options.leasePath === undefined ? {} : { leasePath: options.leasePath }),
        maxOperations: limits.maxOperations,
        maxSerializedBytes: limits.maxSerializedBytes,
        maxDatabaseBytes: limits.maxDatabaseBytes,
      },
      limits,
      VAULT_PROFILE_APPLICATION_ID,
      'kavrix-vault-profile-store-v1',
      VAULT_PROFILE_SCHEMA,
      verifyProfileRows,
    );
    return new SqliteVaultProfileStore(
      opened.database,
      opened.path,
      limits,
      opened.lease,
    );
  }

  public load(
    vaultIdInput: VaultId,
    deviceIdInput: DeviceId,
  ): Promise<VaultProfile | null> {
    return this.exclusive(() => {
      const vaultId = parseVaultId(vaultIdInput);
      const deviceId = parseDeviceId(deviceIdInput);
      const row = this.database
        .prepare(
          `SELECT vault_id, device_id, profile_json, serialized_bytes,
                  device_locator_json, session_locator_json
             FROM vault_profiles WHERE vault_id = ? AND device_id = ?`,
        )
        .get(vaultId, deviceId) as VaultProfileRow | undefined;
      return Promise.resolve(
        row === undefined ? null : parseProfileRow(row, this.limits.maxSerializedBytes),
      );
    });
  }

  /**
   * Full-table read mirroring the open-time row verification, so a caller can
   * resolve which vault this installation is enrolled in without being told.
   */
  public listProfiles(): Promise<readonly VaultProfile[]> {
    return this.exclusive(() => {
      const rows = this.database
        .prepare(
          `SELECT vault_id, device_id, profile_json, serialized_bytes,
                  device_locator_json, session_locator_json
             FROM vault_profiles ORDER BY vault_id ASC, device_id ASC`,
        )
        .all() as unknown as VaultProfileRow[];
      return Promise.resolve(
        rows.map((row) => parseProfileRow(row, this.limits.maxSerializedBytes)),
      );
    });
  }

  public store(profileInput: VaultProfile): Promise<void> {
    return this.exclusive(async () => {
      const profile = parseProfile(profileInput);
      const encoded = encodeProfile(profile, this.limits.maxSerializedBytes);
      const deviceLocator = JSON.stringify(profile.deviceLocator);
      const sessionLocator = JSON.stringify(profile.sessionLocator);
      withTransaction(this.database, () => {
        const existing = this.database
          .prepare(
            `SELECT vault_id, device_id, profile_json, serialized_bytes,
                    device_locator_json, session_locator_json
               FROM vault_profiles WHERE vault_id = ? AND device_id = ?`,
          )
          .get(profile.vaultId, profile.deviceId) as VaultProfileRow | undefined;
        if (existing !== undefined) {
          const parsed = parseProfileRow(existing, this.limits.maxSerializedBytes);
          if (JSON.stringify(parsed) === encoded.json) return;
          throw invalidState();
        }
        this.database
          .prepare(
            `INSERT INTO vault_profiles
               (vault_id, device_id, profile_json, serialized_bytes,
                device_locator_json, session_locator_json)
             VALUES (?, ?, ?, ?, ?, ?)`,
          )
          .run(
            profile.vaultId,
            profile.deviceId,
            encoded.json,
            encoded.bytes,
            deviceLocator,
            sessionLocator,
          );
        verifyProfileCapacity(this.database, this.limits);
      });
      await this.durableFlush();
    });
  }
}

export async function openSqliteVaultProfileStore(
  options: SqliteVaultProfileStoreOptions,
): Promise<SqliteVaultProfileStore> {
  return SqliteVaultProfileStore.open(options);
}

function parseProfileOptions(input: unknown): LifecycleJournalLimits {
  const permitted = [
    'path',
    'leasePath',
    'maxProfiles',
    'maxSerializedBytes',
    'maxDatabaseBytes',
  ];
  if (typeof input !== 'object' || input === null) throw invalidState();
  const options = input as SqliteVaultProfileStoreOptions;
  if (
    Object.keys(options).some((key) => !permitted.includes(key)) ||
    (options.maxProfiles !== undefined &&
      (!Number.isSafeInteger(options.maxProfiles) ||
        options.maxProfiles < 1 ||
        options.maxProfiles > MAX_PROFILE_LIMIT))
  ) {
    throw invalidState();
  }
  const lifecycleOptions: SqliteLifecycleJournalOptions = {
    path: options.path,
    ...(options.leasePath === undefined ? {} : { leasePath: options.leasePath }),
    maxOperations: options.maxProfiles ?? MAX_PROFILE_LIMIT,
    ...(options.maxSerializedBytes === undefined
      ? {}
      : { maxSerializedBytes: options.maxSerializedBytes }),
    ...(options.maxDatabaseBytes === undefined
      ? {}
      : { maxDatabaseBytes: options.maxDatabaseBytes }),
  };
  return parseLifecycleOptions(lifecycleOptions);
}

function verifyProfileRows(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
): void {
  verifyProfileCapacity(database, limits);
  const rows = database
    .prepare(
      `SELECT vault_id, device_id, profile_json, serialized_bytes,
              device_locator_json, session_locator_json FROM vault_profiles`,
    )
    .all() as unknown as VaultProfileRow[];
  for (const row of rows) parseProfileRow(row, limits.maxSerializedBytes);
}

function verifyProfileCapacity(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
): void {
  const row = database
    .prepare(
      `SELECT COUNT(*) AS row_count,
              COALESCE(SUM(serialized_bytes), 0) AS total_bytes FROM vault_profiles`,
    )
    .get() as { row_count?: unknown; total_bytes?: unknown } | undefined;
  if (
    row === undefined ||
    requireInteger(row.row_count) > limits.maxOperations ||
    requireInteger(row.total_bytes) > limits.maxSerializedBytes
  ) {
    throw invalidState();
  }
}

function parseProfileRow(
  row: VaultProfileRow,
  maxSerializedBytes: number,
): VaultProfile {
  if (
    typeof row.vault_id !== 'string' ||
    typeof row.device_id !== 'string' ||
    typeof row.profile_json !== 'string' ||
    typeof row.device_locator_json !== 'string' ||
    typeof row.session_locator_json !== 'string' ||
    requireInteger(row.serialized_bytes) !== Buffer.byteLength(row.profile_json) ||
    Buffer.byteLength(row.profile_json) > maxSerializedBytes
  ) {
    throw invalidState();
  }
  const profile = parseProfile(parseJson(row.profile_json));
  if (
    profile.vaultId !== row.vault_id ||
    profile.deviceId !== row.device_id ||
    JSON.stringify(profile) !== row.profile_json ||
    JSON.stringify(profile.deviceLocator) !== row.device_locator_json ||
    JSON.stringify(profile.sessionLocator) !== row.session_locator_json
  ) {
    throw invalidState();
  }
  return profile;
}

function parseProfile(input: unknown): VaultProfile {
  const parsed = vaultProfileSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

function encodeProfile(
  profile: VaultProfile,
  maxSerializedBytes: number,
): Readonly<{ json: string; bytes: number }> {
  const json = JSON.stringify(profile);
  const bytes = Buffer.byteLength(json);
  if (bytes < 2 || bytes > maxSerializedBytes) throw invalidState();
  return { json, bytes };
}

function parseVaultId(input: unknown): VaultId {
  const parsed = vaultIdSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

function parseDeviceId(input: unknown): DeviceId {
  const parsed = deviceIdSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

function parseJson(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw invalidState();
  }
}

function requireInteger(input: unknown): number {
  if (!Number.isSafeInteger(input) || (input as number) < 0) throw invalidState();
  return input as number;
}
