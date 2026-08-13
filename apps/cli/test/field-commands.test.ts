import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';
import { groupIdSchema, itemIdSchema, vaultIdSchema } from '@kavrix/schemas';

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
  stdinInput: string[] = [],
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const output = memoryOutput();
  const dependencies: CliDependencies = {
    ports: useCases(portsOverrides),
    secrets: {
      read: ({ fromStdin }) => {
        if (!fromStdin || stdinInput.length === 0) {
          return Promise.reject(new Error('secrets unneeded'));
        }
        const val = stdinInput.shift()!;
        return Promise.resolve(val as any);
      },
      readBatch: () => Promise.reject(new Error('secrets unneeded')),
    },
    runtime: {
      stdin: Readable.from(stdinInput.map((s) => `${s}\n`)),
      stdout: output.stdout.stream,
      stderr: output.stderr.stream,
    },
  };
  const exitCode = await runCli(arguments_, dependencies);
  return { exitCode, stdout: output.stdout.value(), stderr: output.stderr.value() };
}

describe('CLI field commands', () => {
  it('executes field add using ports and outputs formatted text', async () => {
    const addField = vi.fn((request: any) =>
      Promise.resolve({
        vaultId: vaultIdSchema.parse('vault.1'),
        groupId: groupIdSchema.parse('group.1'),
        credentialId: itemIdSchema.parse('item.101'),
        title: 'Primary DB',
      }),
    );

    const result = await execute(
      [
        'field',
        'add',
        'Engineering',
        'Primary DB',
        'api_key',
        '--type',
        'api-key',
        '--label',
        'API Key',
        '--sensitive',
        '--value-stdin',
      ],
      { addField },
      ['secret-key-12345'],
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(addField).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'api_key',
      fieldType: 'api-key',
      label: 'API Key',
      sensitive: true,
      value: expect.any(Uint8Array),
    });
    expect(result.stdout).toBe('Field "api_key" added to credential "Primary DB".\n');
  });

  it('executes field set with positional value or stdin', async () => {
    const setField = vi.fn((request: any) =>
      Promise.resolve({
        vaultId: vaultIdSchema.parse('vault.1'),
        groupId: groupIdSchema.parse('group.1'),
        credentialId: itemIdSchema.parse('item.101'),
        title: 'Primary DB',
      }),
    );

    const resultPositional = await execute(
      ['field', 'set', 'Engineering', 'Primary DB', 'hostname', 'db.internal.net'],
      { setField },
    );
    expect(resultPositional.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(setField).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'hostname',
      value: expect.any(Uint8Array),
    });
    expect(resultPositional.stdout).toBe(
      'Field "hostname" set for credential "Primary DB".\n',
    );

    const resultStdin = await execute(
      ['field', 'set', 'Engineering', 'Primary DB', 'password', '--value-stdin'],
      { setField },
      ['super-secret-pass'],
    );
    expect(resultStdin.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(resultStdin.stdout).toBe(
      'Field "password" set for credential "Primary DB".\n',
    );
  });

  it('executes field update to modify field label, type, or sensitivity', async () => {
    const updateField = vi.fn(() => Promise.resolve());

    const result = await execute(
      [
        'field',
        'update',
        'Engineering',
        'Primary DB',
        'hostname',
        '--label',
        'Database Hostname',
      ],
      { updateField },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(updateField).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'hostname',
      label: 'Database Hostname',
    });
    expect(result.stdout).toBe(
      'Field "hostname" updated for credential "Primary DB".\n',
    );
  });

  it('executes field archive and field restore', async () => {
    const archiveField = vi.fn(() => Promise.resolve());
    const restoreField = vi.fn(() => Promise.resolve());

    const resultArchive = await execute(
      ['field', 'archive', 'Engineering', 'Primary DB', 'hostname'],
      { archiveField },
    );
    expect(resultArchive.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(archiveField).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'hostname',
    });
    expect(resultArchive.stdout).toBe(
      'Field "hostname" archived for credential "Primary DB".\n',
    );

    const resultRestore = await execute(
      ['field', 'restore', 'Engineering', 'Primary DB', 'hostname'],
      { restoreField },
    );
    expect(resultRestore.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(restoreField).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'hostname',
    });
    expect(resultRestore.stdout).toBe(
      'Field "hostname" restored for credential "Primary DB".\n',
    );
  });

  it('requires --force flag for field remove', async () => {
    const removeField = vi.fn(() => Promise.resolve());

    const resultNoForce = await execute(
      ['field', 'remove', 'Engineering', 'Primary DB', 'custom_key'],
      { removeField },
    );
    expect(resultNoForce.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultNoForce.stderr).toContain(
      'The --force flag is required for permanent field removal.',
    );
    expect(removeField).not.toHaveBeenCalled();

    const resultForce = await execute(
      ['field', 'remove', 'Engineering', 'Primary DB', 'custom_key', '--force'],
      { removeField },
    );
    expect(resultForce.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(removeField).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'custom_key',
    });
    expect(resultForce.stdout).toBe(
      'Field "custom_key" removed from credential "Primary DB".\n',
    );
  });

  it('fails closed when required positional arguments are missing', async () => {
    const result = await execute(['field', 'add', 'Engineering']);
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('Invalid command usage');
  });

  it('fails closed when field set is missing both positional value and --value-stdin', async () => {
    const result = await execute([
      'field',
      'set',
      'Engineering',
      'Primary DB',
      'secret_key',
    ]);
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain(
      'Provide a value argument or use --value-stdin to supply secret input.',
    );
  });
});
