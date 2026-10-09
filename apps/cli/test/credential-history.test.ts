import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';

import { Command } from 'commander';
import { FileEncryptedDatabaseStore } from '@kavrix/storage';
import {
  aeadEnvelopeSchema,
  cliErrorEnvelopeSchema,
  CLI_EXIT_CODES,
  databaseIdSchema,
  encryptedHistoryRecordSchema,
  historyIdSchema,
  schemaVersionSchema,
  sha256DigestSchema,
  structuredVaultPayloadSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type DatabaseId,
  type StructuredVaultPayload,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import {
  CREDENTIAL_HISTORY_DEFAULT_LIST_LIMIT,
  CREDENTIAL_HISTORY_MAX_LIST_LIMIT,
  CredentialHistoryCommandError,
  parseCredentialHistoryListLimit,
  projectCredentialHistory,
  resolveCredentialHistoryEntry,
} from '../src/credential-history-impl.js';
import { registerStructuredVaultCommands } from '../src/structured-vault-commands.js';
import { registerCredentialHistoryCommands } from '../src/credential-history-commands.js';
import {
  createProjectContext,
  createStructuredItem,
  createStructuredService,
  setStructuredField,
} from '../src/structured-vault-impl.js';
import { createEmptyStructuredVaultPayload } from '../src/structured-vault-projection.js';
import { buildLocalCli } from '../src/local-vault-cli.js';
import { openDatabaseFlatVault } from '../src/database-flat-commands.js';
import { classifyCliFailure } from '../src/cli-errors.js';

const PASSPHRASE = 'credential-history-passphrase';
const FIELD_SECRET = 'credential-history-canary-secret-value';
const HISTORY_CIPHERTEXT = Buffer.from(
  'credential-history-ciphertext-canary',
  'utf8',
).toString('base64url');
const DIGEST = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const at = timestampSchema.parse('2026-08-29T00:00:00.000Z');
const earlier = timestampSchema.parse('2026-08-28T00:00:00.000Z');

const directories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-credential-history-${label}-`),
  );
  directories.push(directory);
  return directory;
}

function historyEnvelope(
  entityId: string,
  vaultId: string,
  itemId: string,
  groupId: string,
) {
  return aeadEnvelopeSchema.parse({
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: HISTORY_CIPHERTEXT,
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType: 'history',
      entityId,
      groupId,
      parentId: itemId,
      purpose: 'history-event',
    },
    keyVersion: 1,
  });
}

function historyRecord(
  id: string,
  vaultId: string,
  itemId: string,
  groupId: string,
  itemRevision: number,
  createdAt: string,
) {
  return encryptedHistoryRecordSchema.parse({
    id: historyIdSchema.parse(id),
    vaultId: vaultIdSchema.parse(vaultId),
    groupId,
    itemId,
    schemaVersion: 1,
    encryptedPayload: historyEnvelope(id, vaultId, itemId, groupId),
    itemRecordRevision: itemRevision,
    ciphertextHash: sha256DigestSchema.parse(DIGEST),
    createdAt,
  });
}

function payloadWithHistory(): Readonly<{
  payload: StructuredVaultPayload;
  historyIds: readonly string[];
}> {
  let payload = createEmptyStructuredVaultPayload(
    vaultIdSchema.parse('vault.history'),
    at,
  );
  payload = createProjectContext(payload, 'Payments', 'production', at);
  payload = createStructuredService(payload, 'Payments', 'postgres', at);
  payload = createStructuredItem(payload, 'Payments', 'postgres', 'primary', at);
  payload = setStructuredField(payload, 'Payments', 'postgres', 'primary', {
    name: 'password',
    type: 'password',
    rawValue: FIELD_SECRET,
    now: at,
  });
  const group = payload.groups.find((entry) => entry.name === 'postgres');
  const item = payload.items.find((entry) => entry.title === 'primary');
  if (group === undefined || item === undefined) {
    throw new Error('fixture hierarchy missing');
  }
  const first = historyRecord(
    'history.first',
    'vault.history',
    item.id,
    group.id,
    1,
    earlier,
  );
  const second = historyRecord(
    'history.second',
    'vault.history',
    item.id,
    group.id,
    2,
    at,
  );
  return {
    payload: structuredVaultPayloadSchema.parse({
      ...payload,
      history: [second, first],
    }),
    historyIds: [first.id, second.id],
  };
}

describe('credential history command model', () => {
  it('attaches to the structured item command so item and credential cannot drift', () => {
    const program = new Command();
    registerStructuredVaultCommands(program);
    registerCredentialHistoryCommands(program);

    const item = program.commands.find((command) => command.name() === 'item');
    expect(item?.aliases()).toContain('credential');
    expect(item?.commands.map((command) => command.name())).toContain('history');
    // A second top-level `credential` route would make Commander resolve the
    // alias before this family could ever be reached.
    expect(program.commands.map((command) => command.name())).not.toContain(
      'credential',
    );
  });

  it('fails closed when the structured item command is not registered', () => {
    expect(() => registerCredentialHistoryCommands(new Command())).toThrow(
      /must run after registerStructuredVaultCommands/u,
    );
  });

  it('lists revisions and timestamps without any snapshot or current value', () => {
    const { payload, historyIds } = payloadWithHistory();
    const projection = projectCredentialHistory(payload, {
      context: 'Payments',
      service: 'postgres',
      item: 'primary',
      limit: CREDENTIAL_HISTORY_DEFAULT_LIST_LIMIT,
    });

    expect(projection).toMatchObject({
      context: 'Payments',
      service: 'postgres',
      item: 'primary',
      truncated: false,
    });
    // Ordered by creation timestamp, oldest first.
    expect(projection.history.map((entry) => entry.version)).toEqual([
      historyIds[0],
      historyIds[1],
    ]);
    expect(projection.history.map((entry) => entry.itemRevision)).toEqual([1, 2]);
    expect(projection.history[0]?.createdAt).toBe(earlier);

    const serialized = JSON.stringify(projection);
    // Plaintext canary: neither the live field value nor the stored snapshot
    // ciphertext may ever reach the output.
    expect(serialized).not.toContain(FIELD_SECRET);
    expect(serialized).not.toContain(HISTORY_CIPHERTEXT);
    expect(serialized).not.toContain('itemValues');
    expect(serialized).not.toContain('encryptedPayload');
  });

  it('bounds one list and reports truncation', () => {
    const { payload } = payloadWithHistory();
    const projection = projectCredentialHistory(payload, {
      context: 'Payments',
      service: 'postgres',
      item: 'primary',
      limit: 1,
    });
    expect(projection.history).toHaveLength(1);
    expect(projection.truncated).toBe(true);
    expect(projection.history[0]?.version).toBe('history.first');
  });

  it('reports only the records bound to the requested item', () => {
    const base = payloadWithHistory();
    const other = createStructuredItem(
      base.payload,
      'Payments',
      'postgres',
      'replica',
      at,
    );
    const otherItem = other.items.find((entry) => entry.title === 'replica');
    if (otherItem === undefined) throw new Error('fixture item missing');
    const group = other.groups.find((entry) => entry.name === 'postgres');
    if (group === undefined) throw new Error('fixture group missing');
    const foreign = historyRecord(
      'history.replica',
      'vault.history',
      otherItem.id,
      group.id,
      1,
      at,
    );
    const payload = structuredVaultPayloadSchema.parse({
      ...other,
      history: [...base.payload.history, foreign],
    });

    const primary = projectCredentialHistory(payload, {
      context: 'Payments',
      service: 'postgres',
      item: 'primary',
      limit: CREDENTIAL_HISTORY_DEFAULT_LIST_LIMIT,
    });
    const replica = projectCredentialHistory(payload, {
      context: 'Payments',
      service: 'postgres',
      item: 'replica',
      limit: CREDENTIAL_HISTORY_DEFAULT_LIST_LIMIT,
    });
    expect(primary.history.map((entry) => entry.version)).toEqual([
      'history.first',
      'history.second',
    ]);
    expect(replica.history.map((entry) => entry.version)).toEqual(['history.replica']);
  });

  it('resolves one version by its opaque identity and nothing else', () => {
    const { payload, historyIds } = payloadWithHistory();
    const entries = projectCredentialHistory(payload, {
      context: 'Payments',
      service: 'postgres',
      item: 'primary',
      limit: CREDENTIAL_HISTORY_MAX_LIST_LIMIT,
    }).history;

    expect(resolveCredentialHistoryEntry(entries, historyIds[0] ?? '')?.version).toBe(
      historyIds[0],
    );
    expect(() => resolveCredentialHistoryEntry(entries, 'history.absent')).toThrow(
      'Credential was not found.',
    );
    expect(() => resolveCredentialHistoryEntry(entries, '  ')).toThrow(
      'Credential was not found.',
    );
  });

  it('fails closed on a history record the schema cannot authenticate', () => {
    const { payload } = payloadWithHistory();
    const first = payload.history[0];
    if (first === undefined) throw new Error('fixture history record missing');
    const unsupported = { ...first, schemaVersion: schemaVersionSchema.parse(2) };
    expect(encryptedHistoryRecordSchema.safeParse(unsupported).success).toBe(false);
    // The authenticated payload schema rejects it before anything is persisted.
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...payload,
        history: [...payload.history, unsupported],
      }).success,
    ).toBe(false);

    // The projection is a public contract, so it refuses rather than listing it.
    const tampered: StructuredVaultPayload = {
      ...payload,
      history: [...payload.history, unsupported],
    };
    let thrown: unknown;
    try {
      projectCredentialHistory(tampered, {
        context: 'Payments',
        service: 'postgres',
        item: 'primary',
        limit: CREDENTIAL_HISTORY_DEFAULT_LIST_LIMIT,
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({
      name: 'CodedCliError',
      errorCode: 'SECURITY_INTEGRITY_FAILURE',
      exitCode: CLI_EXIT_CODES.securityIntegrityFailure,
    });
  });

  it('parses the bounded --limit option', () => {
    expect(parseCredentialHistoryListLimit(undefined)).toBe(
      CREDENTIAL_HISTORY_DEFAULT_LIST_LIMIT,
    );
    expect(parseCredentialHistoryListLimit('1')).toBe(1);
    expect(
      parseCredentialHistoryListLimit(String(CREDENTIAL_HISTORY_MAX_LIST_LIMIT)),
    ).toBe(CREDENTIAL_HISTORY_MAX_LIST_LIMIT);
    for (const invalid of ['0', '-1', 'abc', '1.5', String(Number.MAX_SAFE_INTEGER)]) {
      expect(() => parseCredentialHistoryListLimit(invalid)).toThrow(
        CredentialHistoryCommandError,
      );
    }
    expect(() => parseCredentialHistoryListLimit('501')).toThrow(/between 1 and 500/u);
  });
});

/**
 * The shipping CLI, which registers this family through `cli-registration.ts`.
 *
 * This previously composed the registration itself. Now that the family is wired
 * into the real CLI, doing that here as well registers `item history` twice and
 * Commander refuses the duplicate route, so the helper is a direct call. That is
 * the stronger assertion anyway: it proves the family works through the same
 * registration order the executable uses.
 */
function buildTestCli(): Command {
  return buildLocalCli();
}

type CapturedRun = Readonly<{
  exitCode: number;
  stdout: string;
  stderr: string;
}>;

async function runCli(args: readonly string[], input = ''): Promise<CapturedRun> {
  const originalStdin = process.stdin;
  const originalExitCode = process.exitCode;
  const stdout: string[] = [];
  const stderr: string[] = [];
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: Readable.from([input]),
  });
  const writeOut = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    stdout.push(String(chunk));
    return true;
  });
  const writeErr = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    stderr.push(String(chunk));
    return true;
  });
  process.exitCode = undefined;
  try {
    try {
      await buildTestCli().parseAsync(['node', 'kavrix', ...args]);
    } catch (error) {
      if (args.includes('--json')) {
        const { reportJsonFailure } = await import('../src/execution/commands.js');
        reportJsonFailure(error);
      }
      const { message, exitCode } = classifyCliFailure(error);
      if (message.length > 0) process.stderr.write(`${message}\n`);
      process.exitCode = exitCode;
    }
    return {
      exitCode: process.exitCode ?? 0,
      stdout: stdout.join(''),
      stderr: stderr.join(''),
    };
  } finally {
    writeOut.mockRestore();
    writeErr.mockRestore();
    Object.defineProperty(process, 'stdin', {
      configurable: true,
      value: originalStdin,
    });
    process.exitCode = originalExitCode;
  }
}

type InitializedVault = Readonly<{
  configDir: string;
  dataFile: string;
  vaultId: string;
  route: readonly string[];
}>;

async function initializeVault(label: string): Promise<InitializedVault> {
  const directory = await scratch(label);
  const dataFile = join(directory, 'history.kavrix');
  const keyFile = join(directory, 'owner.key');
  const configDir = join(directory, 'config');
  const init = await runCli(
    [
      'init',
      '--json',
      '--datastore',
      'file',
      '--data-file',
      dataFile,
      '--key-file',
      keyFile,
      '--profile-config-dir',
      configDir,
      '--passphrase-stdin',
    ],
    `${PASSPHRASE}\n${PASSPHRASE}\n`,
  );
  expect(init.exitCode, init.stderr || init.stdout).toBe(0);
  const initialized = JSON.parse(init.stdout) as Record<string, unknown>;
  const vaultId = initialized['vaultId'];
  const profileId = initialized['profileId'];
  if (typeof vaultId !== 'string' || typeof profileId !== 'string') {
    throw new Error('init did not report the vault/profile identifiers');
  }
  return {
    configDir,
    dataFile,
    vaultId,
    route: [
      '--profile',
      profileId,
      '--profile-config-dir',
      configDir,
      '--passphrase-stdin',
    ],
  };
}

function historyRoute(vault: InitializedVault): readonly string[] {
  return ['--context', 'Payments', '--service', 'postgres', ...vault.route];
}

async function seedCredentialWithSecrets(vault: InitializedVault): Promise<void> {
  const created = await runCli(
    ['context', 'create', 'Payments', '--environment', 'production', ...vault.route],
    `${PASSPHRASE}\n`,
  );
  expect(created.exitCode, created.stderr || created.stdout).toBe(0);
  const service = await runCli(
    ['service', 'create', 'postgres', '--context', 'Payments', ...vault.route],
    `${PASSPHRASE}\n`,
  );
  expect(service.exitCode, service.stderr || service.stdout).toBe(0);
  const item = await runCli(
    [
      'item',
      'create',
      'primary',
      '--context',
      'Payments',
      '--service',
      'postgres',
      ...vault.route,
    ],
    `${PASSPHRASE}\n`,
  );
  expect(item.exitCode, item.stderr || item.stdout).toBe(0);
  const field = await runCli(
    [
      'field',
      'set',
      'password',
      '--type',
      'password',
      '--context',
      'Payments',
      '--service',
      'postgres',
      '--item',
      'primary',
      ...vault.route,
      '--value-stdin',
    ],
    `${PASSPHRASE}\n${FIELD_SECRET}\n`,
  );
  expect(field.exitCode, field.stderr || field.stdout).toBe(0);
}

/**
 * Appends history records through the production write port. Nothing in the
 * shipping CLI writes these records, so the open vault handle is the only
 * supported way to place a schema-valid record into an encrypted payload.
 */
async function appendHistoryRecords(
  vault: InitializedVault,
  records: readonly unknown[],
): Promise<void> {
  const handle = await openDatabaseFlatVault(
    { vault: vault.vaultId, profileConfigDir: vault.configDir },
    { passphrase: PASSPHRASE, extras: [] },
  );
  try {
    await handle.session.updateStructuredVault(handle.vaultId, (payload) =>
      structuredVaultPayloadSchema.parse({ ...payload, history: records }),
    );
  } finally {
    await handle.session.close();
  }
}

async function readStoredPayload(
  vault: InitializedVault,
): Promise<StructuredVaultPayload> {
  const handle = await openDatabaseFlatVault(
    { vault: vault.vaultId, profileConfigDir: vault.configDir },
    { passphrase: PASSPHRASE, extras: [] },
  );
  try {
    let observed: StructuredVaultPayload | undefined;
    await handle.session.inspectStructuredVault(handle.vaultId, (payload) => {
      observed = payload;
    });
    if (observed === undefined) throw new Error('payload was not observed');
    return observed;
  } finally {
    await handle.session.close();
  }
}

async function resolveItemCoordinates(
  vault: InitializedVault,
): Promise<Readonly<{ databaseId: DatabaseId; groupId: string; itemId: string }>> {
  const handle = await openDatabaseFlatVault(
    { vault: vault.vaultId, profileConfigDir: vault.configDir },
    { passphrase: PASSPHRASE, extras: [] },
  );
  try {
    const databaseId = handle.profile.databaseId;
    if (databaseId === undefined) throw new Error('profile is not bound to a database');
    let coordinates:
      | Readonly<{
          databaseId: DatabaseId;
          groupId: string;
          itemId: string;
        }>
      | undefined;
    await handle.session.inspectStructuredVault(handle.vaultId, (payload) => {
      const group = payload.groups.find((entry) => entry.name === 'postgres');
      const item = payload.items.find(
        (entry) => entry.groupId === group?.id && entry.title === 'primary',
      );
      if (group === undefined || item === undefined) {
        throw new Error('seeded hierarchy missing');
      }
      coordinates = {
        databaseId: databaseIdSchema.parse(databaseId),
        groupId: group.id,
        itemId: item.id,
      };
    });
    if (coordinates === undefined) throw new Error('seeded hierarchy missing');
    return coordinates;
  } finally {
    await handle.session.close();
  }
}

function swapAdjacentCharacters(value: string): string {
  const characters = Array.from(value);
  const first = characters[1];
  const second = characters[2];
  if (first === undefined || second === undefined || first === second) {
    throw new Error('fixture ciphertext is too short to tamper');
  }
  characters[1] = second;
  characters[2] = first;
  return characters.join('');
}

describe('credential history commands against the real encrypted datastore', () => {
  it('lists and shows history metadata without revealing any value', async () => {
    const vault = await initializeVault('read');
    await seedCredentialWithSecrets(vault);
    const { groupId, itemId } = await resolveItemCoordinates(vault);
    await appendHistoryRecords(vault, [
      historyRecord('history.later', vault.vaultId, itemId, groupId, 2, at),
      historyRecord('history.earlier', vault.vaultId, itemId, groupId, 1, earlier),
    ]);

    const list = await runCli(
      ['credential', 'history', 'list', 'primary', '--json', ...historyRoute(vault)],
      `${PASSPHRASE}\n`,
    );
    expect(list.exitCode, list.stderr || list.stdout).toBe(0);
    const listed = JSON.parse(list.stdout) as Record<string, unknown>;
    expect(listed).toMatchObject({
      context: 'Payments',
      service: 'postgres',
      item: 'primary',
      truncated: false,
    });
    expect(listed['history']).toEqual([
      expect.objectContaining({
        version: 'history.earlier',
        itemRevision: 1,
        createdAt: earlier,
        schemaVersion: 1,
        keyVersion: 1,
        ciphertextHash: DIGEST,
      }),
      expect.objectContaining({ version: 'history.later', itemRevision: 2 }),
    ]);
    // Plaintext canary across the whole command surface.
    expect(list.stdout).not.toContain(FIELD_SECRET);
    expect(list.stdout).not.toContain(HISTORY_CIPHERTEXT);

    const show = await runCli(
      [
        'credential',
        'history',
        'show',
        'primary',
        'history.earlier',
        '--json',
        ...historyRoute(vault),
      ],
      `${PASSPHRASE}\n`,
    );
    expect(show.exitCode, show.stderr || show.stdout).toBe(0);
    expect(JSON.parse(show.stdout)).toEqual({
      context: 'Payments',
      service: 'postgres',
      item: 'primary',
      version: 'history.earlier',
      itemRevision: 1,
      createdAt: earlier,
      schemaVersion: 1,
      keyVersion: 1,
      ciphertextHash: DIGEST,
      revealable: false,
      revision: expect.any(Number),
    });
    expect(show.stdout).not.toContain(FIELD_SECRET);
    expect(show.stdout).not.toContain(HISTORY_CIPHERTEXT);

    // The alias route resolves the same command object.
    const aliased = await runCli(
      ['item', 'history', 'list', 'primary', '--json', ...historyRoute(vault)],
      `${PASSPHRASE}\n`,
    );
    expect(aliased.exitCode, aliased.stderr || aliased.stdout).toBe(0);
    expect(JSON.parse(aliased.stdout)).toEqual(listed);
  });

  it('renders ANSI-free help for every credential history route', async () => {
    for (const args of [
      ['credential', 'history', '--help'],
      ['item', 'history', '--help'],
      ['credential', 'history', 'list', '--help'],
      ['credential', 'history', 'show', '--help'],
    ]) {
      const help = await runCli(args);
      expect(help.exitCode, args.join(' ')).toBe(0);
      expect(help.stderr, args.join(' ')).toBe('');
      expect(help.stdout, args.join(' ')).toContain('Usage:');
      expect(help.stdout, args.join(' ')).not.toMatch(/\u001b|\u009b/u);
      expect(help.stdout, args.join(' ')).not.toContain('field value');
    }
  });

  it('rejects an unknown option instead of inventing a reveal guard', async () => {
    const vault = await initializeVault('reveal');
    await seedCredentialWithSecrets(vault);
    const reveal = await runCli(
      [
        'credential',
        'history',
        'show',
        'primary',
        'history.any',
        '--reveal',
        ...historyRoute(vault),
      ],
      `${PASSPHRASE}\n`,
    );
    expect(reveal.exitCode).toBe(CLI_EXIT_CODES.usageError);
    expect(reveal.stdout).toBe('');
  });

  it('fails closed with the stable exit code for unknown items and versions', async () => {
    const vault = await initializeVault('missing');
    await seedCredentialWithSecrets(vault);
    const { groupId, itemId } = await resolveItemCoordinates(vault);
    await appendHistoryRecords(vault, [
      historyRecord('history.only', vault.vaultId, itemId, groupId, 1, at),
    ]);

    const unknownItem = await runCli(
      ['credential', 'history', 'list', 'absent', '--json', ...historyRoute(vault)],
      `${PASSPHRASE}\n`,
    );
    expect(unknownItem.exitCode).toBe(CLI_EXIT_CODES.credentialMissing);
    const envelope = cliErrorEnvelopeSchema.parse(
      JSON.parse(unknownItem.stdout) as unknown,
    );
    expect(envelope).toEqual({
      error: {
        code: 'CREDENTIAL_MISSING',
        exitCode: CLI_EXIT_CODES.credentialMissing,
        message: 'Credential was not found.',
      },
    });

    const unknownVersion = await runCli(
      [
        'credential',
        'history',
        'show',
        'primary',
        'history.absent',
        '--json',
        ...historyRoute(vault),
      ],
      `${PASSPHRASE}\n`,
    );
    expect(unknownVersion.exitCode).toBe(CLI_EXIT_CODES.credentialMissing);

    // The same failure without --json keeps the reviewed message on stderr.
    const plain = await runCli(
      [
        'credential',
        'history',
        'show',
        'primary',
        'history.absent',
        ...historyRoute(vault),
      ],
      `${PASSPHRASE}\n`,
    );
    expect(plain.exitCode).toBe(CLI_EXIT_CODES.credentialMissing);
    expect(plain.stderr).toContain('Credential was not found.');
    expect(plain.stdout).toBe('');
  });

  it('rejects a tampered vault payload instead of reporting history metadata', async () => {
    const vault = await initializeVault('tamper');
    await seedCredentialWithSecrets(vault);
    const { databaseId, groupId, itemId } = await resolveItemCoordinates(vault);
    await appendHistoryRecords(vault, [
      historyRecord('history.intact', vault.vaultId, itemId, groupId, 1, at),
    ]);

    const store = await FileEncryptedDatabaseStore.open(vault.dataFile);
    try {
      const [document] = await store.listVaults(databaseId);
      if (document === undefined) throw new Error('vault document missing');
      await store.updateVault({
        vault: {
          ...document,
          revision: vaultRevisionSchema.parse(document.revision + 1),
          encryptedPayload: {
            ...document.encryptedPayload,
            aad: {
              ...document.encryptedPayload.aad,
              revision: vaultRevisionSchema.parse(document.revision + 1),
            },
            ciphertext: swapAdjacentCharacters(document.encryptedPayload.ciphertext),
          },
        },
        expectedVaultRevision: document.revision,
      });
    } finally {
      await store.close();
    }

    const tampered = await runCli(
      ['credential', 'history', 'list', 'primary', '--json', ...historyRoute(vault)],
      `${PASSPHRASE}\n`,
    );
    expect(tampered.exitCode).toBe(CLI_EXIT_CODES.authenticationFailed);
    expect(tampered.stdout).not.toContain(FIELD_SECRET);
    expect(tampered.stdout).not.toContain(HISTORY_CIPHERTEXT);
  });

  it('refuses to persist a malformed history record and keeps the stored set intact', async () => {
    const vault = await initializeVault('corrupt');
    await seedCredentialWithSecrets(vault);
    const { groupId, itemId } = await resolveItemCoordinates(vault);
    await appendHistoryRecords(vault, [
      historyRecord('history.good', vault.vaultId, itemId, groupId, 1, at),
    ]);

    const malformed = {
      ...historyRecord('history.bad', vault.vaultId, itemId, groupId, 2, at),
      schemaVersion: schemaVersionSchema.parse(2),
    };
    const stored = await readStoredPayload(vault);
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...stored,
        history: [...stored.history, malformed],
      }).success,
    ).toBe(false);
    await expect(appendHistoryRecords(vault, [malformed])).rejects.toThrow();

    const after = await runCli(
      ['credential', 'history', 'list', 'primary', '--json', ...historyRoute(vault)],
      `${PASSPHRASE}\n`,
    );
    expect(after.exitCode, after.stderr || after.stdout).toBe(0);
    expect(JSON.parse(after.stdout)).toMatchObject({
      history: [expect.objectContaining({ version: 'history.good' })],
    });
  });
});
