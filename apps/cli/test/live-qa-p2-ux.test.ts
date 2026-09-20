import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

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
