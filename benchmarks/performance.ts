import { createHash, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { arch, cpus, platform, release, tmpdir, totalmem } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { spawn } from 'node:child_process';

import {
  OpaqueVaultSnapshot,
  VaultReadSession,
  type VaultReadSourcePort,
} from '../packages/client/dist/index.js';
import { AmbiguousNameError, resolveNamedEntity } from '../packages/core/dist/index.js';
import {
  ARGON2ID_MINIMUM_MEMORY_KIB,
  ARGON2ID_MINIMUM_PARALLELISM,
  ARGON2ID_MINIMUM_PASSES,
  createPassphraseKeySlot,
  createPortableKeySlot,
  encryptPayload,
  formatPortableKey,
  generateGroupKey,
  generateItemKey,
  generatePortableKey,
  generateVaultRootKey,
  wrapGroupKey,
  wrapItemKey,
  unlockPassphraseKeySlot,
  unlockPortableKeySlot,
  zeroize,
  type VaultRootKey,
} from '../packages/crypto/dist/index.js';
import {
  createEncryptedBackup,
  verifyEncryptedBackup,
  type EncryptedBackupEntry,
} from '../packages/import-export/dist/index.js';
import {
  associatedDataSchema,
  contentHashForRecord,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  groupIdSchema,
  groupPayloadSchema,
  itemIdSchema,
  itemPayloadSchema,
  keySlotIdSchema,
  sha256DigestSchema,
  syncPullResponseSchema,
  templateIdSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type GroupId,
  type ItemId,
  type SyncPullResponse,
  type VaultId,
  type VaultRecord,
} from '../packages/schemas/dist/index.js';

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXED_TIMESTAMP = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const GROUP_RECORD_COUNT = 128;
const ITEMS_IN_SELECTED_GROUP = 32;
const SELECTED_GROUP_INDEX = Math.floor(GROUP_RECORD_COUNT / 2);
const SELECTED_ITEM_INDEX = Math.floor(ITEMS_IN_SELECTED_GROUP / 2);
const NAME_GROUP_COUNT = 500;
const NAME_ITEM_COUNT = 5_000;
const MAX_CHILD_OUTPUT_BYTES = 2 * 1024 * 1024;
const BACKUP_CHUNK_BYTES = 64 * 1024;
const BACKUP_MAXIMUM_BYTES = 32 * 1024 * 1024;

type MetricId =
  | 'packed_cli_version_cold'
  | 'packed_cli_completion_fish_cold'
  | 'argon2id_minimum_policy_unlock'
  | 'portable_slot_authenticated_unwrap'
  | 'group_name_resolution_500'
  | 'item_name_resolution_5000'
  | 'ambiguous_item_name_rejection_5000'
  | 'exact_id_item_show_one_group_one_item'
  | 'named_item_show_128_groups_32_items'
  | 'opaque_sync_page_apply_161_records'
  | 'encrypted_backup_create_stream'
  | 'encrypted_backup_verify_stream';

type Budget = Readonly<{
  medianMs: number;
  p95Ms: number;
}>;

const EVALUATION_BUDGETS: Readonly<Record<MetricId, Budget>> = {
  packed_cli_version_cold: { medianMs: 350, p95Ms: 750 },
  packed_cli_completion_fish_cold: { medianMs: 350, p95Ms: 750 },
  argon2id_minimum_policy_unlock: { medianMs: 1_500, p95Ms: 2_500 },
  portable_slot_authenticated_unwrap: { medianMs: 10, p95Ms: 25 },
  group_name_resolution_500: { medianMs: 2, p95Ms: 5 },
  item_name_resolution_5000: { medianMs: 20, p95Ms: 40 },
  ambiguous_item_name_rejection_5000: { medianMs: 20, p95Ms: 40 },
  exact_id_item_show_one_group_one_item: { medianMs: 25, p95Ms: 50 },
  named_item_show_128_groups_32_items: {
    medianMs: 250,
    p95Ms: 500,
  },
  opaque_sync_page_apply_161_records: { medianMs: 80, p95Ms: 160 },
  encrypted_backup_create_stream: { medianMs: 100, p95Ms: 200 },
  encrypted_backup_verify_stream: { medianMs: 100, p95Ms: 200 },
};

type MetricReport = Readonly<{
  id: MetricId;
  label: string;
  unit: 'milliseconds';
  warmups: number;
  samples: number;
  operationsPerSample: number;
  medianMs: number;
  p95Ms: number;
  minimumMs: number;
  maximumMs: number;
  budget: Budget & Readonly<{ informationalOnly: true }>;
  withinInformationalBudget: boolean;
  medianMiBPerSecond?: number;
}>;

type EncryptedFixture = Readonly<{
  vaultId: VaultId;
  rootKey: VaultRootKey;
  vault: VaultRecord;
  groups: readonly EncryptedGroupRecord[];
  items: readonly EncryptedItemRecord[];
  syncPage: SyncPullResponse;
  backupEntries: readonly EncryptedBackupEntry[];
  selectedGroupId: GroupId;
  selectedItemId: ReturnType<typeof itemIdSchema.parse>;
  selectedGroupName: string;
  selectedItemTitle: string;
  passphrase: Uint8Array;
  passphraseSlot: Extract<
    VaultRecord['keySlots'][number],
    { readonly type: 'passphrase' }
  >;
  portableSlot: Extract<
    VaultRecord['keySlots'][number],
    { readonly type: 'portable-key' }
  >;
  formattedPortableKey: string;
}>;

type CliInvocation = Readonly<{
  stdout: string;
  stderr: string;
  exitCode: number;
}>;

type PreparedPackedCli = Readonly<{
  binPath: string;
  packageVersion: string;
  cleanup(): Promise<void>;
}>;

type ProcessResult = Readonly<{
  stdout: Buffer;
  stderr: Buffer;
  exitCode: number;
}>;

type ReadObservation = Readonly<{
  getVaultCalls: number;
  getGroupCalls: number;
  listGroupsCalls: number;
  yieldedGroups: number;
  getItemCalls: number;
  listItemsCalls: number;
  yieldedItems: number;
}>;

/** Transparent benchmark instrumentation around a real production read source. */
class ObservedReadSource implements VaultReadSourcePort {
  readonly #source: VaultReadSourcePort;
  #getVaultCalls = 0;
  #getGroupCalls = 0;
  #listGroupsCalls = 0;
  #yieldedGroups = 0;
  #getItemCalls = 0;
  #listItemsCalls = 0;
  #yieldedItems = 0;

  constructor(source: VaultReadSourcePort) {
    this.#source = source;
  }

  get observation(): ReadObservation {
    return {
      getVaultCalls: this.#getVaultCalls,
      getGroupCalls: this.#getGroupCalls,
      listGroupsCalls: this.#listGroupsCalls,
      yieldedGroups: this.#yieldedGroups,
      getItemCalls: this.#getItemCalls,
      listItemsCalls: this.#listItemsCalls,
      yieldedItems: this.#yieldedItems,
    };
  }

  getVault(vaultId: VaultId): Promise<VaultRecord | null> {
    this.#getVaultCalls += 1;
    return this.#source.getVault(vaultId);
  }

  getGroup(vaultId: VaultId, groupId: GroupId): Promise<EncryptedGroupRecord | null> {
    this.#getGroupCalls += 1;
    return this.#source.getGroup(vaultId, groupId);
  }

  listGroups(vaultId: VaultId): AsyncIterable<EncryptedGroupRecord> {
    this.#listGroupsCalls += 1;
    return observedValues(this.#source.listGroups(vaultId), () => {
      this.#yieldedGroups += 1;
    });
  }

  getItem(vaultId: VaultId, itemId: ItemId): Promise<EncryptedItemRecord | null> {
    this.#getItemCalls += 1;
    return this.#source.getItem(vaultId, itemId);
  }

  listItems(vaultId: VaultId, groupId: GroupId): AsyncIterable<EncryptedItemRecord> {
    this.#listItemsCalls += 1;
    return observedValues(this.#source.listItems(vaultId, groupId), () => {
      this.#yieldedItems += 1;
    });
  }
}

class BenchmarkFailure extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BenchmarkFailure';
  }
}

async function main(): Promise<void> {
  assertSupportedNode();
  const outputPath = parseOutputPath(process.argv.slice(2));
  const cli = await preparePackedCli();
  let ownedFixture: EncryptedFixture | undefined;

  try {
    const fixture = await createEncryptedFixture();
    ownedFixture = fixture;
    const snapshot = new OpaqueVaultSnapshot(fixture.vaultId, {
      maximumRecords: 1 + GROUP_RECORD_COUNT + ITEMS_IN_SELECTED_GROUP,
      maximumBytes: 32 * 1024 * 1024,
    });
    snapshot.applyPullPage(fixture.syncPage);
    assert(
      snapshot.recordCount === 1 + GROUP_RECORD_COUNT + ITEMS_IN_SELECTED_GROUP,
      'Opaque sync fixture validation failed.',
    );

    const backupBytes = await collectBackup(fixture);
    const initialVerification = await verifyEncryptedBackup(
      bufferChunks(backupBytes),
      fixture.rootKey,
      fixture.vaultId,
      backupLimits(fixture),
    );
    assert(
      initialVerification.recordCount === fixture.backupEntries.length + 1,
      'Encrypted backup fixture validation failed.',
    );

    const nameFixture = createNameResolutionFixture();
    validateNameResolutionFixture(nameFixture);
    validateKdfPolicy(fixture);

    const metrics: MetricReport[] = [];
    metrics.push(
      await measure(
        {
          id: 'packed_cli_version_cold',
          label: 'Packed public CLI: cold --version process',
          warmups: 3,
          samples: 15,
        },
        () => invokePackedCli(cli.binPath, ['--version']),
        (result) => {
          assertCleanCliResult(result);
          assert(
            result.stdout.trim() === cli.packageVersion,
            'Packed CLI version output validation failed.',
          );
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'packed_cli_completion_fish_cold',
          label: 'Packed public CLI: cold static Fish completion process',
          warmups: 3,
          samples: 15,
        },
        () => invokePackedCli(cli.binPath, ['completion', 'fish']),
        (result) => {
          assertCleanCliResult(result);
          assert(
            result.stdout.includes('complete -c creds'),
            'Packed CLI Fish completion validation failed.',
          );
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'argon2id_minimum_policy_unlock',
          label: 'Argon2id minimum-policy passphrase slot unlock',
          warmups: 1,
          samples: 7,
        },
        () =>
          unlockPassphraseKeySlot(fixture.passphraseSlot, fixture.passphrase, {
            vaultId: fixture.vaultId,
            slotId: fixture.passphraseSlot.id,
            schemaVersion: fixture.vault.schemaVersion,
            keyVersion: fixture.vault.currentKeyVersion,
          }),
        (candidate) => {
          try {
            assertBytesEqual(
              candidate,
              fixture.rootKey,
              'Passphrase slot unlock validation failed.',
            );
          } finally {
            zeroize(candidate);
          }
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'portable_slot_authenticated_unwrap',
          label: 'Portable slot authenticated unwrap',
          warmups: 3,
          samples: 21,
        },
        () =>
          unlockPortableKeySlot(fixture.portableSlot, fixture.formattedPortableKey, {
            vaultId: fixture.vaultId,
            slotId: fixture.portableSlot.id,
            schemaVersion: fixture.vault.schemaVersion,
            keyVersion: fixture.vault.currentKeyVersion,
          }),
        (candidate) => {
          try {
            assertBytesEqual(
              candidate,
              fixture.rootKey,
              'Portable slot unwrap validation failed.',
            );
          } finally {
            zeroize(candidate);
          }
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'group_name_resolution_500',
          label: 'Direct group name resolution over 500 groups',
          warmups: 5,
          samples: 31,
          operationsPerSample: 25,
        },
        () => {
          let selected = nameFixture.groups[0];
          for (let index = 0; index < 25; index += 1) {
            selected = resolveNamedEntity(
              nameFixture.uniqueGroupQuery,
              nameFixture.groups,
            );
          }
          return selected;
        },
        (selected) => {
          assert(
            selected?.id === nameFixture.uniqueGroupId,
            'Group name resolution validation failed.',
          );
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'item_name_resolution_5000',
          label: 'Direct item name resolution over 5,000 items',
          warmups: 5,
          samples: 31,
          operationsPerSample: 10,
        },
        () => {
          let selected = nameFixture.items[0];
          for (let index = 0; index < 10; index += 1) {
            selected = resolveNamedEntity(
              nameFixture.uniqueItemQuery,
              nameFixture.items,
            );
          }
          return selected;
        },
        (selected) => {
          assert(
            selected?.id === nameFixture.uniqueItemId,
            'Item name resolution validation failed.',
          );
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'ambiguous_item_name_rejection_5000',
          label: 'Ambiguous item name rejection over 5,000 items',
          warmups: 5,
          samples: 31,
          operationsPerSample: 10,
        },
        () => {
          let rejected = 0;
          for (let index = 0; index < 10; index += 1) {
            try {
              resolveNamedEntity(nameFixture.ambiguousQuery, nameFixture.items);
            } catch (error) {
              if (error instanceof AmbiguousNameError) rejected += 1;
              else throw error;
            }
          }
          return rejected;
        },
        (rejected) => {
          assert(rejected === 10, 'Ambiguous name validation failed.');
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'exact_id_item_show_one_group_one_item',
          label: 'Exact-ID item show: one group and one item lookup/decrypt',
          warmups: 3,
          samples: 21,
        },
        async () => {
          const source = new ObservedReadSource(snapshot);
          const session = new VaultReadSession(source, fixture.vaultId);
          await session.unlock(fixture.rootKey);
          try {
            const result = await session.show(
              fixture.selectedGroupId,
              fixture.selectedItemId,
            );
            return { result, observation: source.observation };
          } finally {
            session.lock();
          }
        },
        ({ result, observation }) => {
          assert(
            result.item.id === fixture.selectedItemId &&
              result.item.groupId === fixture.selectedGroupId,
            'Exact-ID authenticated item read validation failed.',
          );
          assertReadObservation(
            observation,
            {
              getVaultCalls: 1,
              getGroupCalls: 1,
              listGroupsCalls: 0,
              yieldedGroups: 0,
              getItemCalls: 1,
              listItemsCalls: 0,
              yieldedItems: 0,
            },
            'Exact-ID item read used an unexpected storage path.',
          );
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'named_item_show_128_groups_32_items',
          label: 'Named item show: decrypt 128 groups and 32 selected-group items',
          warmups: 2,
          samples: 11,
        },
        async () => {
          const source = new ObservedReadSource(snapshot);
          const session = new VaultReadSession(source, fixture.vaultId);
          await session.unlock(fixture.rootKey);
          try {
            const result = await session.show(
              fixture.selectedGroupName,
              fixture.selectedItemTitle,
            );
            return { result, observation: source.observation };
          } finally {
            session.lock();
          }
        },
        ({ result, observation }) => {
          assert(
            result.item.id === fixture.selectedItemId &&
              result.item.groupId === fixture.selectedGroupId,
            'Named authenticated item read validation failed.',
          );
          assertReadObservation(
            observation,
            {
              getVaultCalls: 1,
              getGroupCalls: 0,
              listGroupsCalls: 1,
              yieldedGroups: GROUP_RECORD_COUNT,
              getItemCalls: 0,
              listItemsCalls: 1,
              yieldedItems: ITEMS_IN_SELECTED_GROUP,
            },
            'Named item read used an unexpected storage path.',
          );
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'opaque_sync_page_apply_161_records',
          label: 'Opaque sync page validation and application: 161 records',
          warmups: 3,
          samples: 15,
        },
        () => {
          const candidate = new OpaqueVaultSnapshot(fixture.vaultId, {
            maximumRecords: 1 + GROUP_RECORD_COUNT + ITEMS_IN_SELECTED_GROUP,
            maximumBytes: 32 * 1024 * 1024,
          });
          candidate.applyPullPage(fixture.syncPage);
          return candidate;
        },
        (candidate) => {
          assert(
            candidate.recordCount ===
              1 + GROUP_RECORD_COUNT + ITEMS_IN_SELECTED_GROUP &&
              candidate.cursor.serverSequence ===
                1 + GROUP_RECORD_COUNT + ITEMS_IN_SELECTED_GROUP,
            'Opaque sync application validation failed.',
          );
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'encrypted_backup_create_stream',
          label: `Encrypted backup create stream: ${String(
            fixture.backupEntries.length + 1,
          )} records`,
          warmups: 2,
          samples: 11,
          throughputBytes: backupBytes.byteLength,
        },
        () => collectBackup(fixture),
        async (candidate) => {
          assert(
            candidate.byteLength === backupBytes.byteLength,
            'Encrypted backup create size validation failed.',
          );
          const verified = await verifyEncryptedBackup(
            bufferChunks(candidate),
            fixture.rootKey,
            fixture.vaultId,
            backupLimits(fixture),
          );
          assert(
            verified.recordCount === fixture.backupEntries.length + 1,
            'Encrypted backup create authentication validation failed.',
          );
        },
      ),
    );
    metrics.push(
      await measure(
        {
          id: 'encrypted_backup_verify_stream',
          label: `Encrypted backup verify stream: ${formatMiB(
            backupBytes.byteLength,
          )} MiB`,
          warmups: 3,
          samples: 15,
          throughputBytes: backupBytes.byteLength,
        },
        () =>
          verifyEncryptedBackup(
            bufferChunks(backupBytes),
            fixture.rootKey,
            fixture.vaultId,
            backupLimits(fixture),
          ),
        (verified) => {
          assert(
            verified.recordCount === fixture.backupEntries.length + 1,
            'Encrypted backup verification validation failed.',
          );
        },
      ),
    );

    const report = {
      format: 'kavrix-performance-report',
      version: 1,
      generatedAt: new Date().toISOString(),
      scope: 'machine-specific working-tree measurement; not a release claim',
      runtime: runtimeMetadata(),
      methodology: {
        timer: 'node:perf_hooks performance.now',
        childProcess: 'node:child_process spawn with shell=false',
        percentile: 'nearest-rank p95',
        validation: 'every warmup and sample is validated before timing is recorded',
        budgets: 'informational evaluation objectives; not a CI gate',
        readObservation:
          'a transparent counter delegates every call to the production opaque snapshot',
      },
      fixtures: {
        encryptedData: 'generated benchmark-only data using production crypto APIs',
        syncRecords: 1 + GROUP_RECORD_COUNT + ITEMS_IN_SELECTED_GROUP,
        encryptedGroups: GROUP_RECORD_COUNT,
        itemsInSelectedGroup: ITEMS_IN_SELECTED_GROUP,
        exactIdReadGroupMetadataDecryptions: 1,
        exactIdReadItemMetadataDecryptions: 1,
        namedReadGroupMetadataDecryptions: GROUP_RECORD_COUNT,
        namedReadItemMetadataDecryptions: ITEMS_IN_SELECTED_GROUP,
        nameResolutionGroups: NAME_GROUP_COUNT,
        nameResolutionItems: NAME_ITEM_COUNT,
        backupRecords: fixture.backupEntries.length + 1,
        backupBytes: backupBytes.byteLength,
        backupMiB: Number(formatMiB(backupBytes.byteLength)),
        argon2id: {
          memoryKiB: ARGON2ID_MINIMUM_MEMORY_KIB,
          passes: ARGON2ID_MINIMUM_PASSES,
          parallelism: ARGON2ID_MINIMUM_PARALLELISM,
        },
      },
      knownGap: {
        namedReadFanOut:
          'The exact-ID path reads one group and one item, but a name/slug/alias/prefix query still decrypts every group metadata record and every item metadata record in the selected group before resolving a target.',
      },
      metrics,
    } as const;

    await publishReport(report, outputPath);
  } finally {
    zeroize(ownedFixture?.passphrase);
    zeroize(ownedFixture?.rootKey);
    await cli.cleanup();
  }
}

function assertSupportedNode(): void {
  const parts = process.versions.node.split('.').map(Number);
  const major = parts[0];
  const minor = parts[1];
  const patch = parts[2];
  if (
    major !== 24 ||
    minor === undefined ||
    patch === undefined ||
    !Number.isSafeInteger(minor) ||
    minor < 19 ||
    !Number.isSafeInteger(patch) ||
    patch < 0
  ) {
    throw new BenchmarkFailure('Unsupported Node runtime. Use Node >=24.19.0 and <25.');
  }
}

function parseOutputPath(arguments_: readonly string[]): string | undefined {
  if (arguments_.length === 0) return undefined;
  if (arguments_.length !== 2 || arguments_[0] !== '--output') {
    throw new BenchmarkFailure('Usage: performance.ts [--output <new-file>]');
  }
  const candidate = arguments_[1];
  if (candidate === undefined || candidate.trim().length === 0) {
    throw new BenchmarkFailure('The output file must be non-empty.');
  }
  return resolve(candidate);
}

async function preparePackedCli(): Promise<PreparedPackedCli> {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'kavrix-performance-'));
  assertTemporaryRoot(temporaryRoot);
  const npmCli = join(
    dirname(process.execPath),
    'node_modules',
    'npm',
    'bin',
    'npm-cli.js',
  );
  const packageDirectory = join(REPOSITORY_ROOT, 'apps', 'cli');
  const packDirectory = join(temporaryRoot, 'pack');
  const installDirectory = join(temporaryRoot, 'install');
  await mkdir(packDirectory);
  await mkdir(installDirectory);
  await writeFile(join(temporaryRoot, 'npmrc'), '', { flag: 'wx', mode: 0o600 });
  await writeFile(
    join(installDirectory, 'package.json'),
    '{"name":"kavrix-performance-install","private":true}',
    { flag: 'wx', mode: 0o600 },
  );

  try {
    const packageJson = JSON.parse(
      await readFile(join(packageDirectory, 'package.json'), 'utf8'),
    ) as unknown;
    const packageVersion = readStringProperty(packageJson, 'version');
    const pack = await runProcess(
      process.execPath,
      [
        npmCli,
        'pack',
        packageDirectory,
        '--ignore-scripts',
        '--json',
        '--pack-destination',
        packDirectory,
      ],
      REPOSITORY_ROOT,
      npmEnvironment(temporaryRoot),
      60_000,
    );
    assert(pack.exitCode === 0, 'Packed CLI setup failed.');
    const packed = JSON.parse(pack.stdout.toString('utf8')) as unknown;
    const filename = readPackedFilename(packed);
    const archive = resolve(packDirectory, basename(filename));
    assert(
      dirname(archive) === resolve(packDirectory),
      'Packed CLI archive validation failed.',
    );
    const install = await runProcess(
      process.execPath,
      [
        npmCli,
        'install',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--package-lock=false',
        archive,
      ],
      installDirectory,
      npmEnvironment(temporaryRoot),
      60_000,
    );
    assert(install.exitCode === 0, 'Packed CLI installation failed.');
    const binPath = join(installDirectory, 'node_modules', 'kavrix', 'dist', 'bin.js');
    const smoke = await invokePackedCli(binPath, ['--version']);
    assertCleanCliResult(smoke);
    assert(
      smoke.stdout.trim() === packageVersion,
      'Packed CLI smoke validation failed.',
    );
    return {
      binPath,
      packageVersion,
      async cleanup(): Promise<void> {
        assertTemporaryRoot(temporaryRoot);
        await rm(temporaryRoot, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await rm(temporaryRoot, { recursive: true, force: true });
    if (error instanceof BenchmarkFailure) throw error;
    throw new BenchmarkFailure('Packed CLI setup failed.');
  }
}

function assertTemporaryRoot(path: string): void {
  const temporaryDirectory = resolve(tmpdir());
  const candidate = resolve(path);
  assert(
    candidate.startsWith(`${temporaryDirectory}${sep}`) &&
      basename(candidate).startsWith('kavrix-performance-'),
    'Temporary benchmark directory validation failed.',
  );
}

function readPackedFilename(value: unknown): string {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new BenchmarkFailure('Packed CLI manifest validation failed.');
  }
  return readStringProperty(value[0], 'filename');
}

function readStringProperty(value: unknown, property: string): string {
  if (
    typeof value !== 'object' ||
    value === null ||
    !(property in value) ||
    typeof value[property as keyof typeof value] !== 'string'
  ) {
    throw new BenchmarkFailure('Package metadata validation failed.');
  }
  return value[property as keyof typeof value];
}

function npmEnvironment(temporaryRoot: string): NodeJS.ProcessEnv {
  const environment = childEnvironment();
  environment['npm_config_cache'] = join(temporaryRoot, 'npm-cache');
  environment['npm_config_userconfig'] = join(temporaryRoot, 'npmrc');
  environment['npm_config_update_notifier'] = 'false';
  return environment;
}

function childEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {
    FORCE_COLOR: '0',
    NO_COLOR: '1',
    LANG: 'C',
    LC_ALL: 'C',
  };
  for (const key of [
    'PATH',
    'Path',
    'SystemRoot',
    'SYSTEMROOT',
    'WINDIR',
    'ComSpec',
    'PATHEXT',
    'TEMP',
    'TMP',
  ]) {
    const value = process.env[key];
    if (value !== undefined) environment[key] = value;
  }
  return environment;
}

async function invokePackedCli(
  binPath: string,
  arguments_: readonly string[],
): Promise<CliInvocation> {
  const result = await runProcess(
    process.execPath,
    [binPath, ...arguments_],
    REPOSITORY_ROOT,
    childEnvironment(),
    10_000,
  );
  return {
    stdout: result.stdout.toString('utf8'),
    stderr: result.stderr.toString('utf8'),
    exitCode: result.exitCode,
  };
}

function assertCleanCliResult(result: CliInvocation): void {
  assert(
    result.exitCode === 0,
    `Packed CLI process failed with exit code ${String(result.exitCode)}.`,
  );
  assert(result.stderr.length === 0, 'Packed CLI emitted stderr.');
  assert(!result.stdout.includes('\u001b'), 'Packed CLI emitted ANSI output.');
}

function runProcess(
  executable: string,
  arguments_: readonly string[],
  workingDirectory: string,
  environment: NodeJS.ProcessEnv,
  timeoutMs: number,
): Promise<ProcessResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(executable, arguments_, {
      cwd: workingDirectory,
      env: environment,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let failure: BenchmarkFailure | undefined;
    let settled = false;

    const timeout = setTimeout(() => {
      failure = new BenchmarkFailure('Child process timed out.');
      child.kill();
    }, timeoutMs);

    const collect = (target: Buffer[], chunk: Uint8Array): void => {
      outputBytes += chunk.byteLength;
      if (outputBytes > MAX_CHILD_OUTPUT_BYTES) {
        failure = new BenchmarkFailure('Child process output exceeded its bound.');
        child.kill();
        return;
      }
      target.push(Buffer.from(chunk));
    };
    child.stdout.on('data', (chunk: Uint8Array) => {
      collect(stdout, chunk);
    });
    child.stderr.on('data', (chunk: Uint8Array) => {
      collect(stderr, chunk);
    });
    child.once('error', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      rejectPromise(new BenchmarkFailure('Child process could not start.'));
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (failure !== undefined) {
        rejectPromise(failure);
        return;
      }
      if (signal !== null || code === null) {
        rejectPromise(new BenchmarkFailure('Child process ended unexpectedly.'));
        return;
      }
      resolvePromise({
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        exitCode: code,
      });
    });
  });
}

async function createEncryptedFixture(): Promise<EncryptedFixture> {
  const vaultId = vaultIdSchema.parse('vault.benchmark-only');
  const rootKey = generateVaultRootKey();
  const portableKey = generatePortableKey();
  const formattedPortableKey = formatPortableKey(portableKey);
  const passphrase = Uint8Array.from(randomBytes(32));
  const schemaVersion = 1;
  const keyVersion = 1;

  try {
    const portableSlot = await createPortableKeySlot(
      {
        vaultId,
        slotId: keySlotIdSchema.parse('slot.benchmark.portable'),
        schemaVersion,
        keyVersion,
        createdAt: FIXED_TIMESTAMP,
      },
      portableKey,
      rootKey,
    );
    const passphraseSlot = await createPassphraseKeySlot(
      {
        vaultId,
        slotId: keySlotIdSchema.parse('slot.benchmark.passphrase'),
        schemaVersion,
        keyVersion,
        createdAt: FIXED_TIMESTAMP,
      },
      passphrase,
      rootKey,
    );
    const preferencesContext = associatedDataSchema.parse({
      version: 1,
      schemaVersion,
      keyVersion,
      vaultId,
      entityType: 'vault-preferences',
      entityId: vaultId,
      purpose: 'vault-preferences',
    });
    const preferences = Buffer.from('{"fixture":"benchmark-only"}', 'utf8');
    let encryptedPreferences;
    try {
      encryptedPreferences = await encryptPayload(
        preferences,
        rootKey,
        preferencesContext,
      );
    } finally {
      zeroize(preferences);
    }
    const vault = vaultRecordSchema.parse({
      id: vaultId,
      schemaVersion,
      cryptographicVersion: 1,
      keySlots: [portableSlot, passphraseSlot],
      currentKeyVersion: keyVersion,
      revision: 1,
      encryptedPreferences,
      createdAt: FIXED_TIMESTAMP,
      updatedAt: FIXED_TIMESTAMP,
    });

    const groups: EncryptedGroupRecord[] = [];
    const items: EncryptedItemRecord[] = [];
    let selectedGroupId: GroupId | undefined;
    let selectedItemId: ReturnType<typeof itemIdSchema.parse> | undefined;
    let selectedGroupName: string | undefined;
    let selectedItemTitle: string | undefined;
    const largeDescription = `benchmark-only-${'x'.repeat(8_170)}`;

    for (let groupIndex = 0; groupIndex < GROUP_RECORD_COUNT; groupIndex += 1) {
      const suffix = String(groupIndex + 1).padStart(4, '0');
      const groupId = groupIdSchema.parse(`group.benchmark.${suffix}`);
      const templateId = templateIdSchema.parse(`template.benchmark.${suffix}`);
      const groupName = `Benchmark group ${suffix}`;
      const groupPayload = groupPayloadSchema.parse({
        id: groupId,
        vaultId,
        name: groupName,
        slug: `benchmark-group-${suffix}`,
        aliases: [`bg-${suffix}`],
        description: largeDescription,
        tags: [],
        notes: [],
        template: {
          id: templateId,
          name: 'Benchmark-only empty template',
          version: 1,
          fields: [],
          createdAt: FIXED_TIMESTAMP,
          updatedAt: FIXED_TIMESTAMP,
        },
        sortOrder: groupIndex,
        revision: 1,
        createdAt: FIXED_TIMESTAMP,
        updatedAt: FIXED_TIMESTAMP,
      });
      const groupKey = generateGroupKey();
      try {
        const wrappedGroupKey = await wrapGroupKey(
          groupKey,
          rootKey,
          associatedDataSchema.parse({
            version: 1,
            schemaVersion,
            keyVersion,
            vaultId,
            entityType: 'wrapped-group-key',
            entityId: groupId,
            purpose: 'group-key',
          }),
        );
        const encryptedPayload = await encryptCanonicalPayload(
          groupPayload,
          groupKey,
          associatedDataSchema.parse({
            version: 1,
            schemaVersion,
            keyVersion,
            vaultId,
            entityType: 'group',
            entityId: groupId,
            purpose: 'group-payload',
          }),
        );
        groups.push(
          encryptedGroupRecordSchema.parse({
            id: groupId,
            vaultId,
            schemaVersion,
            wrappedGroupKey,
            encryptedPayload,
            templateVersion: 1,
            recordRevision: 1,
            createdAt: FIXED_TIMESTAMP,
            updatedAt: FIXED_TIMESTAMP,
          }),
        );

        if (groupIndex === SELECTED_GROUP_INDEX) {
          selectedGroupId = groupId;
          selectedGroupName = groupName;
          for (let itemIndex = 0; itemIndex < ITEMS_IN_SELECTED_GROUP; itemIndex += 1) {
            const itemSuffix = String(itemIndex + 1).padStart(4, '0');
            const itemId = itemIdSchema.parse(`item.benchmark.${suffix}.${itemSuffix}`);
            const itemTitle = `Benchmark item ${itemSuffix}`;
            const itemPayload = itemPayloadSchema.parse({
              version: 1,
              id: itemId,
              vaultId,
              groupId,
              templateId,
              title: itemTitle,
              slug: `benchmark-item-${itemSuffix}`,
              aliases: [`bi-${itemSuffix}`],
              templateVersion: 1,
              templateValues: [],
              itemFields: [],
              itemValues: [],
              archivedFieldValues: [],
              notes: [],
              tags: [],
              favorite: false,
              productionSensitive: false,
              relatedItemIds: [],
              attachmentIds: [],
              copySequences: [],
              revision: 1,
              createdAt: FIXED_TIMESTAMP,
              updatedAt: FIXED_TIMESTAMP,
            });
            const itemKey = generateItemKey();
            try {
              const wrappedItemKey = await wrapItemKey(
                itemKey,
                groupKey,
                associatedDataSchema.parse({
                  version: 1,
                  schemaVersion,
                  keyVersion,
                  vaultId,
                  entityType: 'wrapped-item-key',
                  entityId: itemId,
                  groupId,
                  purpose: 'item-key',
                }),
              );
              const itemEnvelope = await encryptCanonicalPayload(
                itemPayload,
                itemKey,
                associatedDataSchema.parse({
                  version: 1,
                  schemaVersion,
                  keyVersion,
                  vaultId,
                  entityType: 'item',
                  entityId: itemId,
                  groupId,
                  purpose: 'item-payload',
                }),
              );
              const ciphertextHash = sha256DigestSchema.parse(
                createHash('sha256')
                  .update(Buffer.from(itemEnvelope.ciphertext, 'base64url'))
                  .digest('base64url'),
              );
              items.push(
                encryptedItemRecordSchema.parse({
                  id: itemId,
                  vaultId,
                  groupId,
                  schemaVersion,
                  wrappedItemKey,
                  encryptedPayload: itemEnvelope,
                  recordRevision: 1,
                  ciphertextHash,
                  createdAt: FIXED_TIMESTAMP,
                  updatedAt: FIXED_TIMESTAMP,
                }),
              );
              if (itemIndex === SELECTED_ITEM_INDEX) {
                selectedItemId = itemId;
                selectedItemTitle = itemTitle;
              }
            } finally {
              zeroize(itemKey);
            }
          }
        }
      } finally {
        zeroize(groupKey);
      }
    }

    assert(
      selectedGroupId !== undefined &&
        selectedItemId !== undefined &&
        selectedGroupName !== undefined &&
        selectedItemTitle !== undefined,
      'Encrypted read fixture validation failed.',
    );
    const backupEntries: EncryptedBackupEntry[] = [
      ...groups.map((record) => ({ kind: 'group' as const, record })),
      ...items.map((record) => ({ kind: 'item' as const, record })),
    ];
    const syncPage = createSyncPage(vault, groups, items);
    return {
      vaultId,
      rootKey,
      vault,
      groups,
      items,
      syncPage,
      backupEntries,
      selectedGroupId,
      selectedItemId,
      selectedGroupName,
      selectedItemTitle,
      passphrase,
      passphraseSlot,
      portableSlot,
      formattedPortableKey,
    };
  } catch (error) {
    zeroize(passphrase);
    zeroize(rootKey);
    throw error;
  } finally {
    zeroize(portableKey);
  }
}

async function encryptCanonicalPayload(
  value: unknown,
  key: Uint8Array,
  context: ReturnType<typeof associatedDataSchema.parse>,
): Promise<ReturnType<typeof encryptedGroupRecordSchema.parse>['encryptedPayload']> {
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');
  try {
    return await encryptPayload(plaintext, key, context);
  } finally {
    zeroize(plaintext);
  }
}

function createSyncPage(
  vault: VaultRecord,
  groups: readonly EncryptedGroupRecord[],
  items: readonly EncryptedItemRecord[],
): SyncPullResponse {
  const records = [vault, ...groups, ...items] as const;
  const changes = records.map((record, index) => {
    const entityType =
      'revision' in record ? 'vault' : 'groupId' in record ? 'item' : 'group';
    const recordRevision =
      'revision' in record ? record.revision : record.recordRevision;
    return {
      change: {
        id: `change.benchmark.${String(index + 1)}`,
        vaultId: vault.id,
        serverSequence: index + 1,
        recordRevision,
        operation: 'upsert',
        ciphertextHash: contentHashForRecord(record),
        createdAt: FIXED_TIMESTAMP,
        entityType,
        entityId: record.id,
      },
      record,
    };
  });
  return syncPullResponseSchema.parse({
    vaultId: vault.id,
    serverVaultRevision: vault.revision,
    changes,
    nextCursor: {
      vaultId: vault.id,
      serverSequence: changes.length,
      highestSeenVaultRevision: vault.revision,
    },
    hasMore: false,
  });
}

function validateKdfPolicy(fixture: EncryptedFixture): void {
  const derivation = fixture.passphraseSlot.derivation;
  assert(
    derivation.memoryKiB === ARGON2ID_MINIMUM_MEMORY_KIB &&
      derivation.passes === ARGON2ID_MINIMUM_PASSES &&
      derivation.parallelism === ARGON2ID_MINIMUM_PARALLELISM,
    'Argon2id fixture is not using the production minimum policy.',
  );
}

type NameEntity = Readonly<{
  id: string;
  name: string;
  slug: string;
  aliases: readonly string[];
}>;

type NameResolutionFixture = Readonly<{
  groups: readonly NameEntity[];
  items: readonly NameEntity[];
  uniqueGroupQuery: string;
  uniqueGroupId: string;
  uniqueItemQuery: string;
  uniqueItemId: string;
  ambiguousQuery: string;
}>;

function createNameResolutionFixture(): NameResolutionFixture {
  const groups = Array.from({ length: NAME_GROUP_COUNT }, (_, index) => {
    const suffix = String(index + 1).padStart(4, '0');
    return {
      id: `group.name-benchmark.${suffix}`,
      name: `Benchmark group lookup ${suffix}`,
      slug: `benchmark-group-lookup-${suffix}`,
      aliases: [`bgl-${suffix}`],
    };
  });
  const items = Array.from({ length: NAME_ITEM_COUNT }, (_, index) => {
    const suffix = String(index + 1).padStart(5, '0');
    return {
      id: `item.name-benchmark.${suffix}`,
      name: `Benchmark item lookup ${suffix}`,
      slug: `benchmark-item-lookup-${suffix}`,
      aliases:
        index === NAME_ITEM_COUNT - 1 || index === NAME_ITEM_COUNT - 2
          ? [`bil-${suffix}`, 'benchmark-shared-ambiguity']
          : [`bil-${suffix}`],
    };
  });
  const uniqueGroup = required(groups[Math.floor(NAME_GROUP_COUNT / 2)]);
  const uniqueItem = required(items[Math.floor(NAME_ITEM_COUNT / 2)]);
  return {
    groups,
    items,
    uniqueGroupQuery: uniqueGroup.slug,
    uniqueGroupId: uniqueGroup.id,
    uniqueItemQuery: uniqueItem.slug,
    uniqueItemId: uniqueItem.id,
    ambiguousQuery: 'benchmark-shared-ambiguity',
  };
}

function validateNameResolutionFixture(fixture: NameResolutionFixture): void {
  assert(
    resolveNamedEntity(fixture.uniqueGroupQuery, fixture.groups).id ===
      fixture.uniqueGroupId,
    'Group name fixture validation failed.',
  );
  assert(
    resolveNamedEntity(fixture.uniqueItemQuery, fixture.items).id ===
      fixture.uniqueItemId,
    'Item name fixture validation failed.',
  );
  let ambiguous = false;
  try {
    resolveNamedEntity(fixture.ambiguousQuery, fixture.items);
  } catch (error) {
    if (error instanceof AmbiguousNameError) ambiguous = true;
    else throw error;
  }
  assert(ambiguous, 'Ambiguous name fixture validation failed.');
}

async function collectBackup(fixture: EncryptedFixture): Promise<Buffer> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of createEncryptedBackup(
    {
      vault: fixture.vault,
      records: asyncValues(fixture.backupEntries),
      createdAt: FIXED_TIMESTAMP,
      limits: backupLimits(fixture),
    },
    fixture.rootKey,
  )) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function backupLimits(fixture: EncryptedFixture): Readonly<{
  maximumBytes: number;
  maximumRecords: number;
}> {
  return {
    maximumBytes: BACKUP_MAXIMUM_BYTES,
    maximumRecords: fixture.backupEntries.length + 1,
  };
}

function asyncValues<Value>(values: readonly Value[]): AsyncIterable<Value> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Value> {
      let index = 0;
      return {
        next(): Promise<IteratorResult<Value>> {
          const value = values[index];
          index += 1;
          return Promise.resolve(
            value === undefined
              ? { done: true, value: undefined }
              : { done: false, value },
          );
        },
      };
    },
  };
}

function observedValues<Value>(
  source: AsyncIterable<Value>,
  onValue: () => void,
): AsyncIterable<Value> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Value> {
      const iterator = source[Symbol.asyncIterator]();
      return {
        async next(): Promise<IteratorResult<Value>> {
          const result = await iterator.next();
          if (!result.done) onValue();
          return result;
        },
      };
    },
  };
}

function bufferChunks(value: Uint8Array): AsyncIterable<Uint8Array> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      let offset = 0;
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          if (offset >= value.byteLength) {
            return Promise.resolve({ done: true, value: undefined });
          }
          const chunk = value.subarray(
            offset,
            Math.min(offset + BACKUP_CHUNK_BYTES, value.byteLength),
          );
          offset += BACKUP_CHUNK_BYTES;
          return Promise.resolve({ done: false, value: chunk });
        },
      };
    },
  };
}

async function measure<Result>(
  configuration: Readonly<{
    id: MetricId;
    label: string;
    warmups: number;
    samples: number;
    operationsPerSample?: number;
    throughputBytes?: number;
  }>,
  operation: () => Result | Promise<Result>,
  validate: (result: Result) => void | Promise<void>,
): Promise<MetricReport> {
  const operationsPerSample = configuration.operationsPerSample ?? 1;
  assert(
    configuration.warmups >= 1 &&
      configuration.samples >= 3 &&
      operationsPerSample >= 1,
    'Invalid benchmark sampling configuration.',
  );
  for (let index = 0; index < configuration.warmups; index += 1) {
    await validate(await operation());
  }

  const samples: number[] = [];
  for (let index = 0; index < configuration.samples; index += 1) {
    const started = performance.now();
    const result = await operation();
    const duration = performance.now() - started;
    await validate(result);
    samples.push(duration / operationsPerSample);
  }
  const sorted = [...samples].sort((left, right) => left - right);
  const medianMs = roundDuration(median(sorted));
  const p95Ms = roundDuration(nearestRank(sorted, 0.95));
  const budget = EVALUATION_BUDGETS[configuration.id];
  const base = {
    id: configuration.id,
    label: configuration.label,
    unit: 'milliseconds' as const,
    warmups: configuration.warmups,
    samples: configuration.samples,
    operationsPerSample,
    medianMs,
    p95Ms,
    minimumMs: roundDuration(required(sorted[0])),
    maximumMs: roundDuration(required(sorted.at(-1))),
    budget: { ...budget, informationalOnly: true as const },
    withinInformationalBudget: medianMs <= budget.medianMs && p95Ms <= budget.p95Ms,
  };
  if (configuration.throughputBytes === undefined) return base;
  return {
    ...base,
    medianMiBPerSecond: roundDuration(
      configuration.throughputBytes / (1024 * 1024) / (medianMs / 1_000),
    ),
  };
}

function median(sorted: readonly number[]): number {
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return required(sorted[middle]);
  return (required(sorted[middle - 1]) + required(sorted[middle])) / 2;
}

function nearestRank(sorted: readonly number[], percentile: number): number {
  const rank = Math.ceil(percentile * sorted.length) - 1;
  return required(sorted[Math.max(0, rank)]);
}

function roundDuration(value: number): number {
  return Number(value.toFixed(3));
}

function formatMiB(bytes: number): string {
  return (bytes / (1024 * 1024)).toFixed(3);
}

function runtimeMetadata(): Readonly<Record<string, string | number>> {
  const processors = cpus();
  const cpuModel = processors[0]?.model ?? 'unknown';
  return {
    node: process.version,
    v8: process.versions.v8,
    platform: platform(),
    osRelease: release(),
    arch: arch(),
    cpuModel: sanitizeMetadata(cpuModel),
    logicalCpuCount: processors.length,
    totalMemoryGiB: Number((totalmem() / 1024 ** 3).toFixed(1)),
  };
}

function sanitizeMetadata(value: string): string {
  return Array.from(value)
    .map((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint < 32 || codePoint === 127 ? ' ' : character;
    })
    .join('')
    .trim()
    .slice(0, 160);
}

async function publishReport(
  report: unknown,
  outputPath: string | undefined,
): Promise<void> {
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  const username = process.env['USERNAME'];
  assert(
    !serialized.includes(REPOSITORY_ROOT) &&
      !serialized.includes(tmpdir()) &&
      (username === undefined ||
        username.length === 0 ||
        !serialized.includes(username)),
    'Benchmark report metadata contains a local identity or path.',
  );
  if (outputPath === undefined) {
    process.stdout.write(serialized);
    return;
  }
  try {
    await writeFile(outputPath, serialized, { flag: 'wx', mode: 0o600 });
  } catch {
    throw new BenchmarkFailure(
      'The output file could not be created. Existing files are never overwritten.',
    );
  }
  process.stdout.write('Benchmark report written.\n');
}

function assertBytesEqual(left: Uint8Array, right: Uint8Array, message: string): void {
  assert(
    left.byteLength === right.byteLength &&
      left.every((value, index) => value === right[index]),
    message,
  );
}

function assertReadObservation(
  actual: ReadObservation,
  expected: ReadObservation,
  message: string,
): void {
  assert(
    actual.getVaultCalls === expected.getVaultCalls &&
      actual.getGroupCalls === expected.getGroupCalls &&
      actual.listGroupsCalls === expected.listGroupsCalls &&
      actual.yieldedGroups === expected.yieldedGroups &&
      actual.getItemCalls === expected.getItemCalls &&
      actual.listItemsCalls === expected.listItemsCalls &&
      actual.yieldedItems === expected.yieldedItems,
    message,
  );
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new BenchmarkFailure(message);
}

function required<Value>(value: Value | undefined): Value {
  if (value === undefined) {
    throw new BenchmarkFailure('Benchmark fixture is incomplete.');
  }
  return value;
}

void main().catch((error: unknown) => {
  const message =
    error instanceof BenchmarkFailure
      ? error.message
      : 'Performance benchmark failed unexpectedly.';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
