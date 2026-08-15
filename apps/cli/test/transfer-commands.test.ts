import { Readable, Writable } from 'node:stream';

import {
  groupIdSchema,
  groupPayloadSchema,
  itemPayloadSchema,
  timestampSchema,
  vaultIdSchema,
  type GroupPayload,
  type ItemPayload,
  type TransferWithholding,
} from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  acquiredSecretSchema,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
  type SecretInputPort,
} from '../src/index.js';
import {
  cliTransferExportResultSchema,
  cliTransferImportResultSchema,
  type CliTransferExportResult,
  type CliTransferImportResult,
} from '../src/contracts.js';
import { CliTransferExportError, CliTransferImportError } from '../src/errors.js';
import {
  assertTransferItemsMatchTemplates,
  groupCreateInput,
  groupTransferItems,
  itemCreateInput,
  planTransferGroupNames,
} from '../src/production/transfers.js';

const TIMESTAMP = timestampSchema.parse('2026-08-12T09:30:00.000Z');
const VAULT_ID = vaultIdSchema.parse('vault.primary');
const GROUP_ID = groupIdSchema.parse('group.databases');
// A path is never echoed back by a receipt, so a clearly fake one is enough.
const TRANSFER_PATH = 'C:\\transfers.invalid\\databases.cvtx';
const PASSPHRASE = acquiredSecretSchema.parse('correct horse battery staple');

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;

function writable(): MemoryWritable {
  let content = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      content += Buffer.from(chunk).toString('utf8');
      callback();
    },
  });
  return { stream, value: () => content };
}

function useCases(overrides: Partial<CliUseCasePorts>): CliUseCasePorts {
  const unexpected = (): Promise<never> => Promise.reject(new Error('Unexpected call'));
  return {
    status: unexpected,
    lock: unexpected,
    show: unexpected,
    copy: unexpected,
    listInvitePage: unexpected,
    revokeInvite: unexpected,
    joinInvite: unexpected,
    ...overrides,
  };
}

async function execute(
  arguments_: readonly string[],
  portsOverrides: Partial<CliUseCasePorts> = {},
  secrets?: SecretInputPort,
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const stdout = writable();
  const stderr = writable();
  const dependencies: CliDependencies = {
    ports: useCases(portsOverrides),
    secrets: secrets ?? {
      read: () => Promise.reject(new Error('secrets unneeded')),
      readBatch: () => Promise.reject(new Error('secrets unneeded')),
    },
    runtime: {
      stdin: Readable.from([]),
      stdout: stdout.stream,
      stderr: stderr.stream,
    },
  };
  const exitCode = await runCli(arguments_, dependencies);
  return { exitCode, stdout: stdout.value(), stderr: stderr.value() };
}

function exportResult(): CliTransferExportResult {
  return cliTransferExportResultSchema.parse({
    action: 'exported',
    vaultId: VAULT_ID,
    groupCount: 1,
    itemCount: 2,
    withheldValues: 3,
    bytes: 4_096,
  });
}

function importResult(): CliTransferImportResult {
  return cliTransferImportResultSchema.parse({
    action: 'imported',
    vaultId: VAULT_ID,
    createdAt: TIMESTAMP,
    groupsCreated: 1,
    groupsSkipped: 1,
    itemsCreated: 2,
    withheldValues: 3,
    referencesDropped: 0,
  });
}

describe('CLI transfer commands', () => {
  it('exports a transfer through the injected port with a bounded receipt', async () => {
    const exportTransfer = vi.fn(() => Promise.resolve(exportResult()));

    const text = await execute(['transfer', 'export', '--file', TRANSFER_PATH], {
      exportTransfer,
    });

    expect(text).toEqual({
      exitCode: CLI_EXIT_CODES.success,
      stdout:
        'Encrypted transfer exported from vault vault.primary (1 groups, 2 credentials, 3 withheld values, 4096 bytes).\n',
      stderr: '',
    });
    expect(exportTransfer).toHaveBeenCalledWith({ destination: TRANSFER_PATH });

    const json = await execute(
      ['transfer', 'export', '--file', TRANSFER_PATH, '--json'],
      { exportTransfer },
    );
    expect(JSON.parse(json.stdout)).toEqual({
      action: 'exported',
      vaultId: 'vault.primary',
      groupCount: 1,
      itemCount: 2,
      withheldValues: 3,
      bytes: 4_096,
    });
    // A receipt must not disclose where the operator keeps the file.
    expect(json.stdout).not.toContain('transfers.invalid');
  });

  it('carries an explicit group selection and vault into the export request', async () => {
    const exportTransfer = vi.fn(() => Promise.resolve(exportResult()));

    const result = await execute(
      [
        'transfer',
        'export',
        '--file',
        TRANSFER_PATH,
        '--group',
        'Databases',
        '--vault',
        'vault.primary',
      ],
      { exportTransfer },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(exportTransfer).toHaveBeenCalledWith({
      destination: TRANSFER_PATH,
      groupQuery: 'Databases',
      vaultId: 'vault.primary',
    });
  });

  it('refuses an export without a destination before reaching the use case', async () => {
    const exportTransfer = vi.fn(() => Promise.resolve(exportResult()));

    const result = await execute(['transfer', 'export'], { exportTransfer });

    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.usage,
      stdout: '',
      stderr: 'Error [CLI_USAGE]: A transfer destination is required.\n',
    });
    expect(exportTransfer).not.toHaveBeenCalled();
  });

  it('reports a refused export without naming what stopped it', async () => {
    const exportTransfer = vi.fn(() => Promise.reject(new CliTransferExportError()));

    const result = await execute(['transfer', 'export', '--file', TRANSFER_PATH], {
      exportTransfer,
    });

    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.failure,
      stdout: '',
      stderr:
        'Error [TRANSFER_EXPORT_FAILED]: The encrypted transfer could not be exported.\n',
    });
  });

  it('imports a transfer through the injected port and defaults to failing on collisions', async () => {
    const importTransfer = vi.fn(() => Promise.resolve(importResult()));

    const text = await execute(['transfer', 'import', '--file', TRANSFER_PATH], {
      importTransfer,
    });

    expect(text).toEqual({
      exitCode: CLI_EXIT_CODES.success,
      stdout:
        'Encrypted transfer imported into vault vault.primary (1 groups created, 1 skipped, 2 credentials created, 3 withheld values, 0 references dropped).\n',
      stderr: '',
    });
    expect(importTransfer).toHaveBeenCalledWith({
      source: TRANSFER_PATH,
      onCollision: 'fail',
    });

    const json = await execute(
      ['transfer', 'import', '--file', TRANSFER_PATH, '--json'],
      { importTransfer },
    );
    expect(JSON.parse(json.stdout)).toEqual({
      action: 'imported',
      vaultId: 'vault.primary',
      createdAt: '2026-08-12T09:30:00.000Z',
      groupsCreated: 1,
      groupsSkipped: 1,
      itemsCreated: 2,
      withheldValues: 3,
      referencesDropped: 0,
    });
    expect(json.stdout).not.toContain('transfers.invalid');
  });

  it('passes each supported collision strategy through unchanged', async () => {
    for (const strategy of ['fail', 'skip', 'rename'] as const) {
      const importTransfer = vi.fn(() => Promise.resolve(importResult()));
      const result = await execute(
        ['transfer', 'import', '--file', TRANSFER_PATH, '--on-collision', strategy],
        { importTransfer },
      );

      expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
      expect(importTransfer).toHaveBeenCalledWith({
        source: TRANSFER_PATH,
        onCollision: strategy,
      });
    }
  });

  it('rejects an unsupported collision strategy before reaching the use case', async () => {
    const importTransfer = vi.fn(() => Promise.resolve(importResult()));

    const result = await execute(
      ['transfer', 'import', '--file', TRANSFER_PATH, '--on-collision', 'overwrite'],
      { importTransfer },
    );

    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.usage,
      stdout: '',
      stderr: 'Error [CLI_USAGE]: The collision strategy is invalid.\n',
    });
    expect(importTransfer).not.toHaveBeenCalled();
  });

  it('reports an unauthenticated transfer without revealing why it failed', async () => {
    const importTransfer = vi.fn(() =>
      Promise.reject(new CliTransferImportError('BACKUP_AUTHENTICATION_FAILED')),
    );

    const result = await execute(['transfer', 'import', '--file', TRANSFER_PATH], {
      importTransfer,
    });

    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.failure,
      stdout: '',
      stderr:
        'Error [BACKUP_AUTHENTICATION_FAILED]: The encrypted transfer could not be imported.\n',
    });
  });

  it('tells the operator when an import outcome is uncertain', async () => {
    const importTransfer = vi.fn(() =>
      Promise.reject(new CliTransferImportError('BACKUP_COMMIT_UNCERTAIN')),
    );

    const result = await execute(['transfer', 'import', '--file', TRANSFER_PATH], {
      importTransfer,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(result.stderr).toContain('[BACKUP_COMMIT_UNCERTAIN]');
    expect(result.stderr).toContain('uncertain');
  });

  it('confirms a new transfer passphrase twice and refuses a mismatch', async () => {
    const readBatch = vi.fn(() =>
      Promise.resolve([
        PASSPHRASE,
        acquiredSecretSchema.parse('correct horse battery stapler'),
      ]),
    );
    const secrets: SecretInputPort = {
      read: () => Promise.reject(new Error('Unexpected single secret read')),
      readBatch,
    };

    const result = await execute(
      ['transfer', 'export', '--file', TRANSFER_PATH, '--transfer-passphrase-stdin'],
      {},
      secrets,
    );

    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.usage,
      stdout: '',
      stderr: 'Error [CLI_USAGE]: Passphrase confirmation did not match.\n',
    });
    expect(readBatch).toHaveBeenCalledWith({
      kinds: ['passphrase', 'passphrase'],
      fromStdin: true,
      requireEnd: true,
    });
  });

  it('acquires one passphrase for import and two for export, then reports no adapter', async () => {
    const readBatch = vi.fn(() => Promise.resolve([PASSPHRASE, PASSPHRASE]));
    const read = vi.fn(() => Promise.resolve(PASSPHRASE));
    const secrets: SecretInputPort = { read, readBatch };

    const exported = await execute(
      ['transfer', 'export', '--file', TRANSFER_PATH],
      {},
      secrets,
    );
    expect(exported.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(exported.stderr).toContain('transfer export is unavailable');
    expect(readBatch).toHaveBeenCalledWith({
      kinds: ['passphrase', 'passphrase'],
      fromStdin: false,
      requireEnd: false,
    });
    expect(read).not.toHaveBeenCalled();

    const imported = await execute(
      ['transfer', 'import', '--file', TRANSFER_PATH],
      {},
      secrets,
    );
    expect(imported.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(imported.stderr).toContain('transfer import is unavailable');
    expect(read).toHaveBeenCalledWith({ kind: 'passphrase', fromStdin: false });
  });
});

describe('transfer import planning', () => {
  it('keeps every non-colliding group under its own name', () => {
    const plan = planTransferGroupNames(
      [group(), group({ id: 'group.cache', name: 'Cache' })],
      ['Secrets'],
      'fail',
    );

    expect(plan.map((entry) => entry.name)).toEqual(['Databases', 'Cache']);
  });

  it('refuses the whole transfer when a name collides and the strategy is fail', () => {
    expect(() => planTransferGroupNames([group()], ['Databases'], 'fail')).toThrow(
      /already exists/u,
    );
  });

  it('marks a colliding group as skipped without touching the others', () => {
    const plan = planTransferGroupNames(
      [group(), group({ id: 'group.cache', name: 'Cache' })],
      ['Databases'],
      'skip',
    );

    expect(plan[0]?.name).toBeUndefined();
    expect(plan[1]?.name).toBe('Cache');
  });

  it('renames a colliding group to the first free suffixed candidate', () => {
    const plan = planTransferGroupNames(
      [group()],
      ['Databases', 'Databases (2)'],
      'rename',
    );

    expect(plan[0]?.name).toBe('Databases (3)');
  });

  it('does not collapse two identically named groups inside one transfer', () => {
    const plan = planTransferGroupNames(
      [group(), group({ id: 'group.databases-2' })],
      [],
      'rename',
    );

    expect(plan.map((entry) => entry.name)).toEqual(['Databases', 'Databases (2)']);
  });

  it('buckets item documents by the group they were exported from', () => {
    const first = { item: item(), withheld: [] };
    const second = { item: item({ id: 'item.replica' }), withheld: [] };

    const grouped = groupTransferItems([first, second], [group()]);

    expect(grouped.get(GROUP_ID)).toStrictEqual([first, second]);
  });

  it('refuses a transfer carrying an item whose group never arrived', () => {
    expect(() =>
      groupTransferItems(
        [{ item: item(), withheld: [] }],
        [group({ id: 'group.cache', name: 'Cache' })],
      ),
    ).toThrow(CliTransferImportError);
  });

  it('carries a withholding manifest through untouched', () => {
    const withheld: readonly TransferWithholding[] = [
      { stableKey: 'master_key', scope: 'template', reason: 'export-policy' },
    ];

    const grouped = groupTransferItems([{ item: item(), withheld }], [group()]);

    expect(grouped.get(GROUP_ID)?.[0]?.withheld).toStrictEqual(withheld);
  });

  it('accepts an item that satisfies the template it travels with', async () => {
    await expect(
      assertTransferItemsMatchTemplates([{ item: item(), withheld: [] }], [group()]),
    ).resolves.toBeUndefined();
  });

  it('refuses an item bound to a template version its group never carried', async () => {
    await expect(
      assertTransferItemsMatchTemplates(
        [{ item: item({ templateVersion: 2 }), withheld: [] }],
        [group()],
      ),
    ).rejects.toThrow(CliTransferImportError);
  });

  it('refuses an item carrying a value with no definition in its template', async () => {
    const orphaned = item({
      templateValues: [
        {
          fieldId: 'field.ghost',
          stableKey: 'ghost',
          value: {
            version: 1,
            state: 'present',
            content: { cardinality: 'single', value: { kind: 'text', value: 'x' } },
          },
          updatedAt: TIMESTAMP,
        },
      ],
    });

    await expect(
      assertTransferItemsMatchTemplates([{ item: orphaned, withheld: [] }], [group()]),
    ).rejects.toThrow(CliTransferImportError);
  });

  it('strips source identity from a group so the destination mints its own', () => {
    const input = groupCreateInput(group({ slug: 'databases' }), 'Databases (2)');

    expect(input.name).toBe('Databases (2)');
    expect(input).not.toHaveProperty('id');
    expect(input).not.toHaveProperty('vaultId');
    expect(input).not.toHaveProperty('revision');
    expect(input).not.toHaveProperty('slug');
    expect(input.template.id).toBe('template.database');
  });

  it('strips source identity from an item and reports every dropped reference', () => {
    const reduced = itemCreateInput(
      item({ slug: 'primary-db', relatedItemIds: ['item.replica', 'item.audit'] }),
    );

    expect(reduced.referencesDropped).toBe(2);
    expect(reduced.input.relatedItemIds).toEqual([]);
    expect(reduced.input.title).toBe('Primary DB');
    expect(reduced.input).not.toHaveProperty('id');
    expect(reduced.input).not.toHaveProperty('groupId');
    expect(reduced.input).not.toHaveProperty('templateVersion');
    expect(reduced.input).not.toHaveProperty('slug');
  });

  it('drops attachment identifiers because a transfer never carries attachments', () => {
    const reduced = itemCreateInput(item({ attachmentIds: ['attachment.tls-bundle'] }));

    expect(reduced.input.attachmentIds).toEqual([]);
  });

  it('reports no dropped references for an item that had none', () => {
    expect(itemCreateInput(item()).referencesDropped).toBe(0);
  });
});

function group(overrides: Record<string, unknown> = {}): GroupPayload {
  return groupPayloadSchema.parse({
    id: GROUP_ID,
    vaultId: VAULT_ID,
    name: 'Databases',
    aliases: [],
    tags: [],
    notes: [],
    template: {
      id: 'template.database',
      name: 'Database',
      version: 1,
      fields: [
        {
          id: 'field.hostname',
          stableKey: 'hostname',
          label: 'Hostname',
          type: 'text',
          required: false,
          sensitive: false,
          repeatable: false,
          copyable: true,
          searchableLocally: true,
          showInPreview: true,
          copyPolicy: 'allowed',
          revealPolicy: 'never',
          reauthenticationPolicy: 'never',
          exportPolicy: 'encrypted-only',
          sortOrder: 0,
          createdAt: TIMESTAMP,
          updatedAt: TIMESTAMP,
        },
      ],
      createdAt: TIMESTAMP,
      updatedAt: TIMESTAMP,
    },
    sortOrder: 0,
    revision: 1,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
    ...overrides,
  });
}

function item(overrides: Record<string, unknown> = {}): ItemPayload {
  return itemPayloadSchema.parse({
    version: 1,
    id: 'item.primary-db',
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    templateId: 'template.database',
    templateVersion: 1,
    title: 'Primary DB',
    aliases: [],
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
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
    ...overrides,
  });
}
