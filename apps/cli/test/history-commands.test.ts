import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';
import { groupIdSchema, itemIdSchema } from '@kavrix/schemas';
import { PermissionError } from '@kavrix/core';

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
  return {
    exitCode,
    stdout: output.stdout.value(),
    stderr: output.stderr.value(),
  };
}

describe('CLI history commands', () => {
  const sampleGroupId = groupIdSchema.parse('group.team-a');
  const sampleItemId = itemIdSchema.parse('item.db-creds');

  it('lists historical revisions for a credential item in text and JSON format', async () => {
    const listHistory = vi.fn(() =>
      Promise.resolve([
        {
          revision: 1,
          historyId: 'history.item.db-creds.v1',
          groupId: sampleGroupId,
          itemId: sampleItemId,
          schemaVersion: 1,
          createdAt: '2026-08-01T00:00:00.000Z',
          fieldCount: 3,
        },
        {
          revision: 2,
          historyId: 'history.item.db-creds.v2',
          groupId: sampleGroupId,
          itemId: sampleItemId,
          schemaVersion: 1,
          createdAt: '2026-08-05T00:00:00.000Z',
          fieldCount: 4,
        },
      ]),
    );

    const resultText = await execute(['history', 'list', 'Engineering', 'Database'], {
      listHistory,
    });
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(listHistory).toHaveBeenCalledWith('Engineering', 'Database');
    expect(resultText.stdout).toContain('Credential History (2 revision(s)):');
    expect(resultText.stdout).toContain('Revision 1');
    expect(resultText.stdout).toContain('history.item.db-creds.v1');
    expect(resultText.stdout).toContain('Revision 2');

    const resultJson = await execute(
      ['history', 'list', 'Engineering', 'Database', '--json'],
      { listHistory },
    );
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as readonly {
      revision: number;
      historyId: string;
    }[];
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0]?.revision).toBe(1);
    expect(parsed[1]?.revision).toBe(2);
  });

  it('renders an empty history message when no revisions exist', async () => {
    const listHistory = vi.fn(() => Promise.resolve([]));
    const result = await execute(['history', 'list', 'Engineering', 'Database'], {
      listHistory,
    });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('No history revisions found');
  });

  it('inspects a historical revision projection with masked secret values', async () => {
    const showHistory = vi.fn(() =>
      Promise.resolve({
        revision: 1,
        historyId: 'history.item.db-creds.v1',
        groupId: sampleGroupId,
        itemId: sampleItemId,
        title: 'Production Database',
        createdAt: '2026-08-01T00:00:00.000Z',
        fields: [
          {
            stableKey: 'username',
            label: 'Username',
            type: 'text',
            maskedValue: '••••••••',
          },
          {
            stableKey: 'password',
            label: 'Password',
            type: 'password',
            maskedValue: '••••••••',
          },
        ],
        notes: [
          {
            id: 'note-1',
            title: 'Cluster Info',
            body: 'Primary cluster endpoint',
          },
        ],
      }),
    );

    const resultText = await execute(
      ['history', 'show', 'Engineering', 'Database', '1'],
      { showHistory },
    );
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(showHistory).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Database',
      revision: 1,
    });
    expect(resultText.stdout).toContain('Credential History Revision 1:');
    expect(resultText.stdout).toContain('Title: Production Database');
    expect(resultText.stdout).toContain('Username (text): ••••••••');
    expect(resultText.stdout).toContain('Cluster Info: Primary cluster endpoint');

    const resultJson = await execute(
      ['history', 'show', 'Engineering', 'Database', '1', '--json'],
      { showHistory },
    );
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as {
      revision: number;
      title: string;
      fields: readonly { label: string }[];
    };
    expect(parsed.revision).toBe(1);
    expect(parsed.title).toBe('Production Database');
    expect(parsed.fields.length).toBe(2);
  });

  it('compares changed fields between revisions with diff', async () => {
    const diffHistory = vi.fn(() =>
      Promise.resolve({
        groupId: sampleGroupId,
        itemId: sampleItemId,
        baseRevision: 1,
        targetRevision: 2,
        addedFields: [{ stableKey: 'port', label: 'Port', type: 'text' }],
        removedFields: [],
        modifiedFields: [
          { stableKey: 'password', label: 'Password', type: 'password' },
        ],
        unchangedFieldCount: 2,
        notesChanged: true,
      }),
    );

    const resultText = await execute(
      ['history', 'diff', 'Engineering', 'Database', '1', '2'],
      { diffHistory },
    );
    expect(resultText.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(diffHistory).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Database',
      revision: 1,
      compareRevision: 2,
    });
    expect(resultText.stdout).toContain('History Diff (Revision 1 -> Revision 2):');
    expect(resultText.stdout).toContain('+ Port [port] (text)');
    expect(resultText.stdout).toContain('~ Password [password] (password)');
    expect(resultText.stdout).toContain('Unchanged fields: 2');
    expect(resultText.stdout).toContain('Notes changed: yes');

    const resultJson = await execute(
      ['history', 'diff', 'Engineering', 'Database', '1', '2', '--json'],
      { diffHistory },
    );
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as {
      baseRevision: number;
      targetRevision: number;
      notesChanged: boolean;
    };
    expect(parsed.baseRevision).toBe(1);
    expect(parsed.targetRevision).toBe(2);
    expect(parsed.notesChanged).toBe(true);
  });

  it('restores an exact prior revision with explicit --force', async () => {
    const restoreHistory = vi.fn((request: { force?: boolean | undefined }) => {
      if (!request.force) {
        throw new PermissionError();
      }
      return Promise.resolve({
        groupId: sampleGroupId,
        itemId: sampleItemId,
        restoredFromRevision: 1,
        newRevision: 3,
        updatedAt: '2026-08-15T00:00:00.000Z',
      });
    });

    const resultWithoutForce = await execute(
      ['history', 'restore', 'Engineering', 'Database', '1'],
      { restoreHistory },
    );
    expect(resultWithoutForce.exitCode).toBe(CLI_EXIT_CODES.failure);

    const resultWithForce = await execute(
      ['history', 'restore', 'Engineering', 'Database', '1', '--force'],
      { restoreHistory },
    );
    expect(resultWithForce.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(restoreHistory).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Database',
      revision: 1,
      force: true,
    });
    expect(resultWithForce.stdout).toContain('Credential restored from revision 1.');
    expect(resultWithForce.stdout).toContain('New Revision: 3');

    const resultJson = await execute(
      ['history', 'restore', 'Engineering', 'Database', '1', '--force', '--json'],
      { restoreHistory },
    );
    expect(resultJson.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(resultJson.stdout) as {
      restoredFromRevision: number;
      newRevision: number;
    };
    expect(parsed.restoredFromRevision).toBe(1);
    expect(parsed.newRevision).toBe(3);
  });

  it('sanitizes terminal ANSI sequences in history output', async () => {
    const listHistory = vi.fn(() =>
      Promise.resolve([
        {
          revision: 1,
          historyId: 'history.\u001b[31mhostile\u001b[0m.v1',
          groupId: sampleGroupId,
          itemId: sampleItemId,
          schemaVersion: 1,
          createdAt: '2026-08-01T00:00:00.000Z',
          fieldCount: 1,
        },
      ]),
    );

    const result = await execute(['history', 'list', 'Engineering', 'Database'], {
      listHistory,
    });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).not.toContain('\u001b[');
    // Each ANSI escape sequence is replaced with the U+FFFD replacement character.
    expect(result.stdout).toContain('history.\uFFFDhostile\uFFFD.v1');
  });

  it('fails closed when required arguments are missing', async () => {
    const resList = await execute(['history', 'list']);
    expect(resList.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resList.stderr).toContain('Invalid command usage');

    const resShow = await execute(['history', 'show', 'Engineering', 'Database']);
    expect(resShow.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resShow.stderr).toContain('Invalid command usage');

    const resDiff = await execute(['history', 'diff', 'Engineering', 'Database']);
    expect(resDiff.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resDiff.stderr).toContain('Invalid command usage');

    const resRestore = await execute(['history', 'restore', 'Engineering', 'Database']);
    expect(resRestore.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(resRestore.stderr).toContain('Invalid command usage');
  });
});
