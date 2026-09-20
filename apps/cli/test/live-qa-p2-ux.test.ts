import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { PortableKeyFileError } from '@kavrix/key-files';
import { EncryptedDatabaseStoreError } from '@kavrix/storage';

import { classifyCliFailure } from '../src/cli-errors.js';
import { executeAgentExec } from '../src/execution/agent-command.js';
import { assembleEntry } from '../src/execution/policy-command.js';

const basePolicy = {
  id: 'demo',
  vault: 'default',
  secret: 'demo/api',
} as const;

describe('live-qa P2 UX fixes (0.2.20)', () => {
  it('policy create rejects absolute command paths with basename guidance', () => {
    expect(() =>
      assembleEntry({
        ...basePolicy,
        commands: ['/bin/echo'],
      }),
    ).toThrow(/basename-only/);
    expect(
      assembleEntry({
        ...basePolicy,
        commands: ['echo'],
      }).commands,
    ).toEqual(['echo']);
  });

  it('agent exec --dry-run fails closed for unknown permissions', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kavrix-p2-agent-'));
    const previous = process.cwd();
    try {
      await writeFile(
        join(root, 'kavrix.yaml'),
        [
          'version: 1',
          'agents:',
          '  coder:',
          '    permissions:',
          '      ping:',
          '        secret: demo/api',
          '        commands: [echo]',
          '',
        ].join('\n'),
        'utf8',
      );
      process.chdir(root);
      await expect(
        executeAgentExec({
          permission: 'nonexistent',
          dryRun: true,
          executableAndArgs: [],
        }),
      ).rejects.toThrow(/Unknown agent permission|refuses unknown|fail closed/i);
      await expect(
        executeAgentExec({
          permission: 'ping',
          dryRun: true,
          executableAndArgs: [],
        }),
      ).resolves.toMatchObject({ dryRun: true, ok: true, permission: 'ping' });
    } finally {
      process.chdir(previous);
      await rm(root, { recursive: true, force: true });
    }
  });

  it('agent exec --dry-run without project config fails closed', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kavrix-p2-noconfig-'));
    const previous = process.cwd();
    try {
      process.chdir(root);
      await expect(
        executeAgentExec({
          permission: 'anything',
          dryRun: true,
          executableAndArgs: [],
        }),
      ).rejects.toThrow(/project config|kavrix\.yaml/i);
    } finally {
      process.chdir(previous);
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('classifyCliFailure P2 message branches', () => {
  it('maps EncryptedDatabaseStoreError unsafe to exit 15 with heal guidance', () => {
    const classified = classifyCliFailure(new EncryptedDatabaseStoreError('unsafe'));
    expect(classified.exitCode).toBe(15);
    expect(classified.message).toMatch(/unsafe|mode 700|doctor health --heal/i);
  });

  it('rewrites portable key-file not-found and unsafe messages', () => {
    const missing = classifyCliFailure(new PortableKeyFileError('KEY_FILE_NOT_FOUND'));
    expect(missing).toEqual({
      message: 'The portable key file was not found.',
      exitCode: 11,
    });

    const unsafe = classifyCliFailure(new PortableKeyFileError('KEY_FILE_UNSAFE'));
    expect(unsafe.exitCode).toBe(14);
    expect(unsafe.message).toMatch(/not safe to use|mode 700|doctor health --heal/i);
  });

  it('keeps other portable key-file messages and maps busy/operation to exit 15', () => {
    const busy = classifyCliFailure(new PortableKeyFileError('KEY_FILE_BUSY'));
    expect(busy.exitCode).toBe(15);
    expect(busy.message.length).toBeGreaterThan(0);

    const exists = classifyCliFailure(
      new PortableKeyFileError('KEY_FILE_ALREADY_EXISTS'),
    );
    expect(exists.exitCode).toBe(14);
  });
});
