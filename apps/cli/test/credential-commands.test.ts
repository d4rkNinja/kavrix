import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';
import {
  groupIdSchema,
  itemIdSchema,
  itemPayloadSchema,
  vaultIdSchema,
} from '@kavrix/schemas';

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

function memoryOutput(): Readonly<{
  stdout: MemoryWritable;
  stderr: MemoryWritable;
}> {
  return { stdout: writable(), stderr: writable() };
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
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const output = memoryOutput();
  const dependencies: CliDependencies = {
    ports: useCases(portsOverrides),
    secrets: {
      read: () => Promise.reject(new Error('secrets unneeded')),
      readBatch: () => Promise.reject(new Error('secrets unneeded')),
    },
    runtime: {
      stdin: Readable.from([]),
      stdout: output.stdout.stream,
      stderr: output.stderr.stream,
    },
  };
  const exitCode = await runCli(arguments_, dependencies);
  return { exitCode, stdout: output.stdout.value(), stderr: output.stderr.value() };
}

function itemFixture(
  id: string,
  title: string,
  subtitle?: string,
): ReturnType<typeof itemPayloadSchema.parse> {
  return itemPayloadSchema.parse({
    version: 1,
    id: itemIdSchema.parse(id),
    vaultId: vaultIdSchema.parse('vault.1'),
    groupId: 'group.1',
    templateId: 'template.default000000000000001',
    templateVersion: 1,
    title,
    subtitle,
    aliases: [],
    tags: [],
    favorite: false,
    productionSensitive: false,
    templateValues: [],
    itemFields: [],
    itemValues: [],
    archivedFieldValues: [],
    notes: [],
    relatedItemIds: [],
    attachmentIds: [],
    copySequences: [],
    revision: 1,
    createdAt: '2026-08-10T00:00:00.000Z',
    updatedAt: '2026-08-10T00:00:00.000Z',
  });
}

describe('CLI credential commands', () => {
  it('executes credential create using ports and outputs formatted text', async () => {
    const createCredential = vi.fn((request: { title: string; groupQuery: string }) =>
      Promise.resolve({
        vaultId: vaultIdSchema.parse('vault.1'),
        groupId: groupIdSchema.parse('group.1'),
        credentialId: itemIdSchema.parse('item.101'),
        title: request.title,
      }),
    );

    const result = await execute(
      ['credential', 'create', 'Engineering', 'Database Admin'],
      { createCredential },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(createCredential).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      title: 'Database Admin',
    });
    expect(result.stdout).toBe('Credential "Database Admin" created (item.101).\n');
  });

  it('executes credential list and renders text list or JSON', async () => {
    const items = [
      itemFixture('item.1', 'Primary DB', 'Production primary'),
      itemFixture('item.2', 'Staging DB'),
    ];
    const listCredentials = vi.fn(() => Promise.resolve(items));

    const resultText = await execute(['credential', 'list', 'Engineering'], {
      listCredentials,
    });
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(listCredentials).toHaveBeenCalledWith('Engineering');
    expect(resultText.stdout).toContain('Credentials (2):');
    expect(resultText.stdout).toContain('- Primary DB (item.1): Production primary');
    expect(resultText.stdout).toContain('- Staging DB (item.2)');

    const resultJson = await execute(['credential', 'list', 'Engineering', '--json'], {
      listCredentials,
    });
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(JSON.parse(resultJson.stdout)).toEqual([
      {
        id: 'item.1',
        title: 'Primary DB',
        subtitle: 'Production primary',
        favorite: false,
      },
      { id: 'item.2', title: 'Staging DB', favorite: false },
    ]);
  });

  it('executes credential rename and updates the credential title', async () => {
    const renameCredential = vi.fn(() => Promise.resolve());

    const result = await execute(
      ['credential', 'rename', 'Engineering', 'Primary DB', 'Primary Database'],
      { renameCredential },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(renameCredential).toHaveBeenCalledWith(
      'Engineering',
      'Primary DB',
      'Primary Database',
    );
    expect(result.stdout).toBe('Credential renamed to "Primary Database".\n');
  });

  it('executes credential archive and credential restore', async () => {
    const archiveEntity = vi.fn(() => Promise.resolve());
    const restoreEntity = vi.fn(() => Promise.resolve());

    const resultArchive = await execute(
      ['credential', 'archive', 'Engineering', 'Primary DB'],
      { archiveEntity },
    );
    expect(resultArchive.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(archiveEntity).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
    });
    expect(resultArchive.stdout).toBe('Credential "Primary DB" archived.\n');

    const resultRestore = await execute(
      ['credential', 'restore', 'Engineering', 'item.1'],
      { restoreEntity },
    );
    expect(resultRestore.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(restoreEntity).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'item.1',
    });
    expect(resultRestore.stdout).toBe('Credential "item.1" restored.\n');
  });

  it('requires --force flag for credential delete', async () => {
    const deleteCredential = vi.fn(() => Promise.resolve());

    const resultNoForce = await execute(
      ['credential', 'delete', 'Engineering', 'Primary DB'],
      { deleteCredential },
    );
    expect(resultNoForce.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultNoForce.stderr).toContain(
      'The --force flag is required for permanent credential deletion.',
    );
    expect(deleteCredential).not.toHaveBeenCalled();

    const resultForce = await execute(
      ['credential', 'delete', 'Engineering', 'Primary DB', '--force'],
      {
        deleteCredential,
      },
    );
    expect(resultForce.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(deleteCredential).toHaveBeenCalledWith('Engineering', 'Primary DB');
    expect(resultForce.stdout).toBe('Credential "Primary DB" deleted.\n');
  });

  it('fails closed when required arguments are missing', async () => {
    const result = await execute(['credential', 'create']);
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('Invalid command usage');
  });

  it('sanitizes hostile terminal text in credential list output', async () => {
    const canary = 'credential-echo-canary';
    const items = [
      itemFixture(
        'item.1',
        `Primary\u001b]2;${canary}\u0007\u001b[2J login`,
        'Production\u202e primary',
      ),
    ];
    const listCredentials = vi.fn(() => Promise.resolve(items));

    const result = await execute(['credential', 'list', 'Engineering'], {
      listCredentials,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).not.toContain('\u001b');
    expect(result.stdout).not.toContain('\u0007');
    expect(result.stdout).not.toContain(canary);
    expect(result.stdout).not.toContain('\u202e');
    expect(result.stdout).toContain('Primary\uFFFD\uFFFD login');
    expect(result.stdout).toContain('Production\uFFFD primary');
  });
});
