import { afterEach, describe, expect, it, vi } from 'vitest';

import { LocalCliError } from '../src/cli-error.js';
import { buildLocalCli, runLocalCli } from '../src/local-vault-cli.js';
import {
  DEFAULT_ROOT_DATASTORE,
  INVALID_ROOT_DATASTORE_MESSAGE,
  addRootDatastoreOption,
  parseRootDatastore,
  resolveRootDatastore,
} from '../src/root-datastore.js';

describe('root datastore default policy', () => {
  it('locks the unified product default to file (aligned with init)', () => {
    expect(DEFAULT_ROOT_DATASTORE).toBe('file');
    expect(resolveRootDatastore(undefined)).toBe('file');
    expect(resolveRootDatastore('file')).toBe('file');
    expect(resolveRootDatastore('mongodb')).toBe('mongodb');
  });

  it('rejects invalid datastore values with LocalCliError', () => {
    expect(() => parseRootDatastore('unsupported')).toThrow(LocalCliError);
    expect(() => parseRootDatastore('unsupported')).toThrow(
      INVALID_ROOT_DATASTORE_MESSAGE,
    );
    expect(() => resolveRootDatastore('redis')).toThrow(INVALID_ROOT_DATASTORE_MESSAGE);
  });

  it('attaches Commander --datastore with the shared default', async () => {
    const { Command } = await import('commander');
    const command = addRootDatastoreOption(new Command('probe'));
    expect(command.opts().datastore).toBe(DEFAULT_ROOT_DATASTORE);
    expect(command.getOptionValueSource('datastore')).toBe('default');
  });

  it('publishes the same file default on init and root CRUD help', () => {
    const program = buildLocalCli();
    for (const name of ['init', 'put', 'get', 'list', 'doctor'] as const) {
      const command = program.commands.find((candidate) => candidate.name() === name);
      expect(command, name).toBeDefined();
      // Collapse help wrapping so "(default: file)" matches across line breaks.
      const help = command!.helpInformation().replace(/\s+/gu, ' ');
      expect(help, name).toMatch(/--datastore <type>/u);
      expect(help, name).toMatch(/\(default: "?file"?\)/u);
      expect(help, name).not.toMatch(/\(default: "?mongodb"?\)/u);
      expect(command!.opts().datastore, name).toBe(DEFAULT_ROOT_DATASTORE);
      expect(command!.getOptionValueSource('datastore'), name).toBe('default');
    }
  });
});

describe('root datastore resolution error exits', () => {
  const originalExitCode = process.exitCode;

  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = originalExitCode;
  });

  async function captureExit(args: readonly string[]): Promise<{
    exitCode: number;
    stderr: string;
  }> {
    const stderr: string[] = [];
    const writeErr = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderr.push(String(chunk));
      return true;
    });
    const writeOut = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    process.exitCode = undefined;
    try {
      await runLocalCli(['node', 'kavrix', ...args]);
      return { exitCode: process.exitCode ?? 0, stderr: stderr.join('') };
    } finally {
      writeErr.mockRestore();
      writeOut.mockRestore();
    }
  }

  it('exits non-zero for an invalid --datastore on list', async () => {
    const result = await captureExit([
      'list',
      '--datastore',
      'unsupported',
      '--data-file',
      './missing.vault',
      '--key-file',
      './missing.key',
    ]);
    expect(result.exitCode).not.toBe(0);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain(INVALID_ROOT_DATASTORE_MESSAGE);
  });

  it('exits non-zero for an invalid --datastore on doctor', async () => {
    const result = await captureExit([
      'doctor',
      '--datastore',
      'bogus',
      '--data-file',
      './missing.vault',
      '--key-file',
      './missing.key',
    ]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain(INVALID_ROOT_DATASTORE_MESSAGE);
  });

  it('exits non-zero for an invalid --datastore on put', async () => {
    const result = await captureExit([
      'put',
      'demo/token',
      '--datastore',
      'other',
      '--data-file',
      './missing.vault',
      '--key-file',
      './missing.key',
      '--passphrase-stdin',
    ]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain(INVALID_ROOT_DATASTORE_MESSAGE);
  });

  it('exits non-zero when db ping inherits the file default without an explicit mongodb datastore', async () => {
    const result = await captureExit(['db', 'ping', '--database-url-stdin']);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain('db ping requires --datastore mongodb');
  });
});
