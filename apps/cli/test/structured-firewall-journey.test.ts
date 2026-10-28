import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { executionReference } from '@kavrix/schemas';
import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  runCli,
} from './execution-helpers.js';

describe('structured firewall command journey', () => {
  it('executes fields, requires policies, restores history, and imports structured data with inert policies', async () => {
    const source = await createExecutionFixture({});
    const target = await createExecutionFixture({});
    const frames = (...values: string[]) => values.join('\n') + '\n';
    const route = [...source.routingArgs, '--passphrase-stdin', '--json'];
    const hierarchy = ['--context', 'project/prod', '--service', 'api'];
    const itemRoute = [...hierarchy, '--item', 'deploy'];
    const first = 'structured-journey-canary-first';
    const second = 'structured-journey-canary-second';
    const reference = executionReference({
      context: 'project/prod',
      service: 'api',
      item: 'deploy',
      field: 'token',
    });
    const digest = createHash('sha256').update(first).digest('hex');
    const args = [
      '-e',
      `process.exit(require('node:crypto').createHash('sha256').update(process.env.TARGET_TOKEN ?? '').digest('hex') === '${digest}' ? 0 : 3)`,
    ];
    async function ok(args: string[], values = [EXEC_PASSPHRASE]) {
      const result = await runCli(args, frames(...values));
      expect(result.exitCode, result.stderr || result.stdout).toBe(0);
      expect(result.stdout + result.stderr).not.toContain(first);
      expect(result.stdout + result.stderr).not.toContain(second);
      return JSON.parse(result.stdout) as Record<string, unknown>;
    }
    try {
      await ok(['context', 'create', 'project/prod', ...route]);
      await ok(['service', 'create', 'api', '--context', 'project/prod', ...route]);
      await ok(['item', 'create', 'deploy', ...hierarchy, ...route]);
      await ok(
        [
          'field',
          'set',
          'token',
          ...itemRoute,
          '--type',
          'api-key',
          '--value-stdin',
          ...route,
        ],
        [EXEC_PASSPHRASE, first],
      );
      await ok(
        [
          'note',
          'add',
          'deploy',
          'runbook',
          ...hierarchy,
          '--content-stdin',
          '--sensitive',
          ...route,
        ],
        [EXEC_PASSPHRASE, 'private-note-canary'],
      );
      await ok([
        'run',
        '--secret',
        `TARGET_TOKEN=${reference}`,
        ...route,
        '--',
        process.execPath,
        ...args,
      ]);
      await ok(['policy', 'mode', 'required', ...route]);
      const unguarded = await runCli(
        [
          'run',
          '--no-config',
          '--secret',
          `TARGET_TOKEN=${reference}`,
          ...route,
          '--',
          process.execPath,
          ...args,
        ],
        frames(EXEC_PASSPHRASE),
      );
      expect(unguarded.exitCode).toBe(12);
      expect(unguarded.stdout + unguarded.stderr).toContain('policy');
      await ok([
        'policy',
        'create',
        'structured-use',
        '--secret',
        reference,
        '--command',
        'node',
        '--operation',
        JSON.stringify({ command: 'node', args }),
        ...route,
      ]);
      await ok([
        'run',
        '--policy',
        'structured-use',
        '--secret',
        `TARGET_TOKEN=${reference}`,
        ...route,
        '--',
        process.execPath,
        ...args,
      ]);
      const denied = await runCli(
        [
          'policy',
          'check',
          'structured-use',
          ...route,
          '--',
          process.execPath,
          ...args,
          'extra',
        ],
        frames(EXEC_PASSPHRASE),
      );
      expect(denied.exitCode).toBe(12);
      expect(denied.stdout).toContain('operation-not-allowed');
      const reveal = await runCli(
        ['field', 'get', 'token', ...itemRoute, '--reveal', ...route],
        frames(EXEC_PASSPHRASE),
      );
      expect(reveal.exitCode).toBe(12);
      expect(reveal.stdout + reveal.stderr).not.toContain(first);
      await ok(
        [
          'field',
          'set',
          'token',
          ...itemRoute,
          '--type',
          'api-key',
          '--value-stdin',
          ...route,
        ],
        [EXEC_PASSPHRASE, second],
      );
      const history = await ok([
        'item',
        'history',
        'list',
        'deploy',
        ...hierarchy,
        ...route,
      ]);
      const latest = (history.history as { version: string; restorable?: boolean }[])
        .filter((entry) => entry.restorable)
        .at(-1)!;
      await ok([
        'item',
        'history',
        'restore',
        'deploy',
        latest.version,
        ...hierarchy,
        ...route,
      ]);
      await ok([
        'run',
        '--policy',
        'structured-use',
        '--secret',
        `TARGET_TOKEN=${reference}`,
        ...route,
        '--',
        process.execPath,
        ...args,
      ]);
      expect(await readFile(source.dataFile, 'utf8')).not.toContain(first);
      expect(await readFile(source.dataFile, 'utf8')).not.toContain(second);
      const file = join(source.directory, 'structured.export');
      const archivePassphrase = 'structured-transfer-archive-passphrase';
      await ok(
        ['export', '--structured', '--include-policies', '--file', file, ...route],
        [EXEC_PASSPHRASE, archivePassphrase, archivePassphrase],
      );
      expect(await readFile(file, 'utf8')).not.toContain('private-note-canary');
      const targetRoute = [...target.routingArgs, '--passphrase-stdin', '--json'];
      await ok(
        ['import', 'archive', '--file', file, ...targetRoute],
        [EXEC_PASSPHRASE, archivePassphrase],
      );
      const candidates = await ok(['policy', 'candidates', ...targetRoute]);
      expect(candidates.candidates).toHaveProperty('structured-use');
      const noPolicy = await runCli(
        [
          'run',
          '--secret',
          `TARGET_TOKEN=${reference}`,
          ...targetRoute,
          '--',
          process.execPath,
          ...args,
        ],
        frames(EXEC_PASSPHRASE),
      );
      expect(noPolicy.exitCode).toBe(12);
      await ok(['policy', 'import', 'structured-use', ...targetRoute]);
      await ok([
        'run',
        '--policy',
        'structured-use',
        '--secret',
        `TARGET_TOKEN=${reference}`,
        ...targetRoute,
        '--',
        process.execPath,
        ...args,
      ]);
      const note = await ok(['note', 'list', 'deploy', ...hierarchy, ...targetRoute]);
      expect((note.notes as unknown[]).length).toBe(1);
      expect(await readFile(target.dataFile, 'utf8')).not.toContain(first);
      // Wrong archive credentials cannot replace the imported vault.
      const before = await readFile(target.dataFile);
      const wrong = await runCli(
        ['import', 'archive', '--file', file, '--overwrite', ...targetRoute],
        frames(EXEC_PASSPHRASE, 'incorrect-archive-passphrase'),
      );
      expect(wrong.exitCode).toBe(10);
      expect(await readFile(target.dataFile)).toEqual(before);
    } finally {
      await destroyFixture(source);
      await destroyFixture(target);
    }
  });
});
