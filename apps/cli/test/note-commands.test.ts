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
  noteIdSchema,
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

describe('CLI note commands', () => {
  it('executes note add for group and credential', async () => {
    const addNote = vi.fn(() =>
      Promise.resolve({
        vaultId: vaultIdSchema.parse('vault.1'),
        groupId: groupIdSchema.parse('group.1'),
        credentialId: itemIdSchema.parse('item.101'),
        noteId: noteIdSchema.parse('note.1000000000000001'),
        title: 'Recovery Note',
      }),
    );

    const resultGroup = await execute(
      [
        'note',
        'add',
        'Engineering',
        'Architecture Overview',
        '--content',
        'High level architecture overview text',
      ],
      { addNote },
    );
    expect(resultGroup.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(addNote).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      title: 'Architecture Overview',
      content: 'High level architecture overview text',
    });
    expect(resultGroup.stdout).toBe(
      'Note "Architecture Overview" added to group "Engineering".\n',
    );

    const resultCred = await execute(
      [
        'note',
        'add',
        'Engineering',
        'Primary DB',
        '--title',
        'Recovery Note',
        '--content-stdin',
        '--sensitive',
        '--pinned',
      ],
      { addNote },
      ['Secret recovery material'],
    );
    expect(resultCred.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(addNote).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      title: 'Recovery Note',
      content: 'Secret recovery material',
      isSensitive: true,
      isPinned: true,
    });
    expect(resultCred.stdout).toBe(
      'Note "Recovery Note" added to credential "Primary DB".\n',
    );
  });

  it('executes note update', async () => {
    const updateNote = vi.fn(() =>
      Promise.resolve({
        vaultId: vaultIdSchema.parse('vault.1'),
        groupId: groupIdSchema.parse('group.1'),
        noteId: noteIdSchema.parse('note.1000000000000001'),
        title: 'Updated Note',
      }),
    );

    const result = await execute(
      [
        'note',
        'update',
        'Engineering',
        'Primary DB',
        'Recovery Note',
        '--title',
        'Updated Note',
      ],
      { updateNote },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(updateNote).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      noteQuery: 'Recovery Note',
      title: 'Updated Note',
    });
    expect(result.stdout).toBe('Note "Recovery Note" updated.\n');
  });

  it('executes note archive and note restore', async () => {
    const archiveNote = vi.fn(() => Promise.resolve());
    const restoreNote = vi.fn(() => Promise.resolve());

    const resultArchive = await execute(
      ['note', 'archive', 'Engineering', 'Primary DB', 'Recovery Note'],
      { archiveNote },
    );
    expect(resultArchive.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(archiveNote).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      noteQuery: 'Recovery Note',
    });
    expect(resultArchive.stdout).toBe('Note "Recovery Note" archived.\n');

    const resultRestore = await execute(
      ['note', 'restore', 'Engineering', 'Primary DB', 'Recovery Note'],
      { restoreNote },
    );
    expect(resultRestore.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(restoreNote).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      noteQuery: 'Recovery Note',
    });
    expect(resultRestore.stdout).toBe('Note "Recovery Note" restored.\n');
  });

  it('requires --force flag for note remove', async () => {
    const removeNote = vi.fn(() => Promise.resolve());

    const resultNoForce = await execute(
      ['note', 'remove', 'Engineering', 'Primary DB', 'Recovery Note'],
      { removeNote },
    );
    expect(resultNoForce.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resultNoForce.stderr).toContain(
      'The --force flag is required for permanent note removal.',
    );
    expect(removeNote).not.toHaveBeenCalled();

    const resultForce = await execute(
      ['note', 'remove', 'Engineering', 'Primary DB', 'Recovery Note', '--force'],
      { removeNote },
    );
    expect(resultForce.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(removeNote).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Primary DB',
      noteQuery: 'Recovery Note',
    });
    expect(resultForce.stdout).toBe('Note "Recovery Note" removed.\n');
  });

  it('fails closed when required arguments are missing', async () => {
    const result = await execute(['note', 'add']);
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('Invalid command usage');
  });
});
