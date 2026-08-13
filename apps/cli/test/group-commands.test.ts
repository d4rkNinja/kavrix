import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';
import { groupFixture } from './fixtures.js';
import { groupIdSchema, vaultIdSchema } from '@kavrix/schemas';

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

describe('CLI group commands', () => {
  it('executes group create using ports and outputs formatted text', async () => {
    const createGroup = vi.fn((request: { name: string; description?: string }) =>
      Promise.resolve({
        vaultId: vaultIdSchema.parse('vault.1'),
        groupId: groupIdSchema.parse('group.101'),
        name: request.name,
      }),
    );

    const result = await execute(
      ['group', 'create', 'Engineering', '--description', 'Engineering team group'],
      { createGroup },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(createGroup).toHaveBeenCalledWith({
      name: 'Engineering',
      description: 'Engineering team group',
    });
    expect(result.stdout).toBe('Group "Engineering" created.\n');
  });

  it('executes group list and renders text list or JSON', async () => {
    const groups = [
      groupFixture('group.1', 'Infrastructure', 'Cloud servers'),
      groupFixture('group.2', 'Finance', 'Banking'),
    ];
    const listGroups = vi.fn(() => Promise.resolve(groups));

    const resultText = await execute(['group', 'list'], { listGroups });
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(resultText.stdout).toContain('Groups (2):');
    expect(resultText.stdout).toContain('- Infrastructure (group.1): Cloud servers');
    expect(resultText.stdout).toContain('- Finance (group.2): Banking');

    const resultJson = await execute(['group', 'list', '--json'], { listGroups });
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(JSON.parse(resultJson.stdout)).toEqual([
      { id: 'group.1', name: 'Infrastructure', description: 'Cloud servers' },
      { id: 'group.2', name: 'Finance', description: 'Banking' },
    ]);
  });

  it('executes group rename and updates group name', async () => {
    const renameGroup = vi.fn(() => Promise.resolve());

    const result = await execute(
      ['group', 'rename', 'Infrastructure', 'Cloud Infrastructure'],
      { renameGroup },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(renameGroup).toHaveBeenCalledWith('Infrastructure', 'Cloud Infrastructure');
    expect(result.stdout).toBe('Group renamed to "Cloud Infrastructure".\n');
  });

  it('executes group archive and group restore', async () => {
    const archiveEntity = vi.fn(() => Promise.resolve());
    const restoreEntity = vi.fn(() => Promise.resolve());

    const resultArchive = await execute(['group', 'archive', 'Infrastructure'], {
      archiveEntity,
    });
    expect(resultArchive.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(archiveEntity).toHaveBeenCalledWith({ groupQuery: 'Infrastructure' });
    expect(resultArchive.stdout).toBe('Group "Infrastructure" archived.\n');

    const resultRestore = await execute(['group', 'restore', 'group.1'], {
      restoreEntity,
    });
    expect(resultRestore.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(restoreEntity).toHaveBeenCalledWith({ groupQuery: 'group.1' });
    expect(resultRestore.stdout).toBe('Group "group.1" restored.\n');
  });

  it('requires --force flag for group delete', async () => {
    const deleteGroup = vi.fn(() => Promise.resolve());

    const resultNoForce = await execute(['group', 'delete', 'Infrastructure'], {
      deleteGroup,
    });
    expect(resultNoForce.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultNoForce.stderr).toContain('The --force flag is required');
    expect(deleteGroup).not.toHaveBeenCalled();

    const resultForce = await execute(
      ['group', 'delete', 'Infrastructure', '--force'],
      {
        deleteGroup,
      },
    );
    expect(resultForce.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(deleteGroup).toHaveBeenCalledWith('Infrastructure');
    expect(resultForce.stdout).toBe('Group "Infrastructure" deleted.\n');
  });

  it('fails closed when required arguments are missing', async () => {
    const result = await execute(['group', 'create']);
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('Invalid command usage');
  });
});
