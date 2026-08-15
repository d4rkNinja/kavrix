import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  CliUsageError,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';
import { groupIdSchema, itemIdSchema, vaultIdSchema } from '@kavrix/schemas';

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;

type SetFieldPort = NonNullable<CliUseCasePorts['setField']>;
type UpdateFieldPort = NonNullable<CliUseCasePorts['updateField']>;

/** A field write receipt every set/update assertion can start from. */
function mutationReceipt(): Awaited<ReturnType<SetFieldPort>> {
  return {
    vaultId: vaultIdSchema.parse('vault.1'),
    groupId: groupIdSchema.parse('group.1'),
    credentialId: itemIdSchema.parse('item.101'),
    title: 'Primary DB',
    fieldKey: 'hostname',
    fieldLabel: 'Hostname',
    fieldType: 'text',
    sensitive: false,
    created: false,
    previousRevision: 4,
    revision: 5,
  };
}

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
        // A script has no terminal, so the production port fails closed exactly
        // this way when a command is given no explicit standard-input flag.
        if (!fromStdin) {
          return Promise.reject(
            new CliUsageError(
              'A masked field value prompt requires a terminal; use --value-stdin explicitly.',
            ),
          );
        }
        const val = stdinInput.shift();
        if (val === undefined) {
          return Promise.reject(new Error('secrets unneeded'));
        }
        return Promise.resolve(
          val as unknown as Awaited<ReturnType<CliDependencies['secrets']['read']>>,
        );
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
    const addField = vi.fn(() =>
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
      value: expect.any(Uint8Array) as unknown,
    });
    expect(result.stdout).toBe('Field "api_key" added to credential "Primary DB".\n');
  });

  it('executes field set from standard input and reports the written revision', async () => {
    const setField = vi.fn<SetFieldPort>(() => Promise.resolve(mutationReceipt()));

    const result = await execute(
      [
        'field',
        'set',
        'Engineering',
        'Primary DB',
        'hostname',
        '--value-stdin',
        '--if-revision',
        '4',
      ],
      { setField },
      ['db.internal.invalid'],
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(setField).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'hostname',
      value: expect.any(Uint8Array) as unknown,
      ifRevision: 4,
    });
    expect(result.stdout).toBe(
      [
        'Field "hostname" set for credential "Primary DB".',
        '  Label: Hostname',
        '  Type: text',
        '  Sensitive: no',
        '  Created: no',
        '  Revision: 4 -> 5',
        '',
      ].join('\n'),
    );
  });

  it('rejects a positional field value so a secret never reaches process arguments', async () => {
    const setField = vi.fn<SetFieldPort>(() => Promise.resolve(mutationReceipt()));

    const result = await execute(
      ['field', 'set', 'Engineering', 'Primary DB', 'hostname', 'db.internal.invalid'],
      { setField },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('Invalid command usage');
    expect(setField).not.toHaveBeenCalled();
  });

  it('forwards --create so a typo cannot silently define a new field', async () => {
    const setField = vi.fn<SetFieldPort>(() =>
      Promise.resolve({ ...mutationReceipt(), created: true }),
    );

    const withoutCreate = await execute(
      ['field', 'set', 'Engineering', 'Primary DB', 'hostname', '--value-stdin'],
      { setField },
      ['db.internal.invalid'],
    );
    expect(withoutCreate.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(setField).toHaveBeenLastCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'hostname',
      value: expect.any(Uint8Array) as unknown,
    });

    const withCreate = await execute(
      [
        'field',
        'set',
        'Engineering',
        'Primary DB',
        'hostname',
        '--value-stdin',
        '--create',
      ],
      { setField },
      ['db.internal.invalid'],
    );
    expect(withCreate.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(setField).toHaveBeenLastCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'hostname',
      value: expect.any(Uint8Array) as unknown,
      create: true,
    });
    expect(withCreate.stdout).toContain('  Created: yes');
  });

  it('rejects an --if-revision value that cannot identify a stored record', async () => {
    const setField = vi.fn<SetFieldPort>(() => Promise.resolve(mutationReceipt()));

    const result = await execute(
      [
        'field',
        'set',
        'Engineering',
        'Primary DB',
        'hostname',
        '--value-stdin',
        '--if-revision',
        '0',
      ],
      { setField },
      ['db.internal.invalid'],
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('The expected revision is invalid.');
    expect(setField).not.toHaveBeenCalled();
  });

  it('executes field update to modify field label, type, or sensitivity', async () => {
    const updateField = vi.fn<UpdateFieldPort>(() =>
      Promise.resolve({ ...mutationReceipt(), fieldLabel: 'Database Hostname' }),
    );

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
      [
        'Field "hostname" updated for credential "Primary DB".',
        '  Label: Database Hostname',
        '  Type: text',
        '  Sensitive: no',
        '  Created: no',
        '  Revision: 4 -> 5',
        '',
      ].join('\n'),
    );
  });

  it('rejects a field update that changes nothing', async () => {
    const updateField = vi.fn<UpdateFieldPort>(() =>
      Promise.resolve(mutationReceipt()),
    );

    const result = await execute(
      ['field', 'update', 'Engineering', 'Primary DB', 'hostname'],
      { updateField },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain(
      'Provide at least one of --label, --type, --sensitive, or --no-sensitive.',
    );
    expect(updateField).not.toHaveBeenCalled();
  });

  it('shares one handler between the field family and the top-level commands', async () => {
    const setField = vi.fn<SetFieldPort>(() => Promise.resolve(mutationReceipt()));
    const updateField = vi.fn<UpdateFieldPort>(() =>
      Promise.resolve(mutationReceipt()),
    );

    const setResult = await execute(
      ['set', 'Engineering', 'Primary DB', 'hostname', '--value-stdin', '--json'],
      { setField },
      ['db.internal.invalid'],
    );
    expect(setResult.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(setField).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'hostname',
      value: expect.any(Uint8Array) as unknown,
    });
    expect(JSON.parse(setResult.stdout)).toMatchObject({
      action: 'set',
      fieldKey: 'hostname',
      previousRevision: 4,
      revision: 5,
    });

    const updateResult = await execute(
      ['update', 'Engineering', 'Primary DB', 'hostname', '--no-sensitive', '--json'],
      { updateField },
    );
    expect(updateResult.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(updateField).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      fieldKey: 'hostname',
      sensitive: false,
    });
    expect(JSON.parse(updateResult.stdout)).toMatchObject({ action: 'update' });
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

  it('fails closed when field set has no value source at all', async () => {
    const setField = vi.fn<SetFieldPort>(() => Promise.resolve(mutationReceipt()));

    const result = await execute(
      ['field', 'set', 'Engineering', 'Primary DB', 'secret_key'],
      { setField },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('requires a terminal; use --value-stdin');
    expect(setField).not.toHaveBeenCalled();
  });
});
