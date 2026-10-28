import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import {
  openDatabaseBackupArchive,
  parseDatabaseBackupArchive,
  sealDatabaseBackupArchive,
} from '@kavrix/crypto';
import { publishProtectedFile } from '../src/backup-command-impl.js';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  runCli,
} from './execution-helpers.js';

describe('firewall recovery bundle', () => {
  it('recovers policies and audit while permanently discarding archived grants', async () => {
    const fixture = await createExecutionFixture({
      'github/token': 'firewall-recovery-canary',
    });
    const frames = (...values: string[]) => values.join('\n') + '\n';
    try {
      const policy = await runCli(
        [
          'policy',
          'create',
          'block',
          '--secret',
          'github/token',
          '--deny',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--json',
        ],
        frames(EXEC_PASSPHRASE),
      );
      expect(policy.exitCode, policy.stderr).toBe(0);
      const grant = await runCli(
        [
          'grant',
          'create',
          'github/token',
          '--command',
          'node',
          '--ttl',
          '15m',
          '--max-uses',
          '1',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--json',
        ],
        frames(EXEC_PASSPHRASE),
      );
      expect(grant.exitCode, grant.stderr).toBe(0);
      const file = join(fixture.directory, 'firewall.backup');
      const archivePassphrase = 'firewall-recovery-archive-passphrase';
      const created = await runCli(
        [
          'backup',
          'create',
          '--file',
          file,
          '--include-firewall',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--json',
        ],
        frames(archivePassphrase, archivePassphrase),
      );
      expect(created.exitCode, created.stderr).toBe(0);
      const bytes = await readFile(file, 'utf8');
      expect(bytes).not.toContain('firewall-recovery-canary');
      expect(bytes).not.toContain(EXEC_PASSPHRASE);
      const restoredFile = join(fixture.directory, 'restored.database');
      const restored = await runCli(
        [
          'backup',
          'restore',
          '--file',
          file,
          '--data-file',
          restoredFile,
          '--passphrase-stdin',
          '--json',
        ],
        frames(archivePassphrase),
      );
      expect(restored.exitCode, restored.stderr).toBe(0);
      expect(JSON.parse(restored.stdout)).toMatchObject({ firewallPending: true });
      expect(await readFile(restoredFile, 'utf8')).toBe(
        await readFile(fixture.dataFile, 'utf8'),
      );
      const rejected = await runCli(
        [
          'backup',
          'restore-firewall',
          '--file',
          file,
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--json',
        ],
        frames(EXEC_PASSPHRASE, archivePassphrase),
      );
      expect(rejected.exitCode).not.toBe(0);
      const applied = await runCli(
        [
          'backup',
          'restore-firewall',
          '--file',
          file,
          '--overwrite',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--json',
        ],
        frames(EXEC_PASSPHRASE, archivePassphrase),
      );
      expect(applied.exitCode, applied.stderr).toBe(0);
      expect(JSON.parse(applied.stdout)).toMatchObject({
        firewallRestored: true,
        discardedGrants: 1,
      });
      const snapshot = await runCli(
        ['policy', 'snapshot', ...fixture.routingArgs, '--passphrase-stdin', '--json'],
        frames(EXEC_PASSPHRASE),
      );
      const decoded = JSON.parse(snapshot.stdout);
      expect(decoded.policies.block.definition.deny).toBe(true);
      expect(decoded.grants).toEqual({});
      expect(decoded.audit.length).toBeGreaterThan(0);
      const sidecarBefore = await readFile(fixture.keyFile + '.authorization');
      const wrongPassphrase = await runCli(
        [
          'backup',
          'restore-firewall',
          '--file',
          file,
          '--overwrite',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--json',
        ],
        frames(EXEC_PASSPHRASE, 'incorrect-archive-passphrase'),
      );
      expect(wrongPassphrase.exitCode).toBe(10);
      expect(await readFile(fixture.keyFile + '.authorization')).toEqual(sidecarBefore);
      const foreign = await createExecutionFixture({});
      try {
        const wrongScope = await runCli(
          [
            'backup',
            'restore-firewall',
            '--file',
            file,
            ...foreign.routingArgs,
            '--passphrase-stdin',
            '--json',
          ],
          frames(EXEC_PASSPHRASE, archivePassphrase),
        );
        expect(wrongScope.exitCode).toBe(16);
        expect(existsSync(foreign.keyFile + '.authorization')).toBe(false);
      } finally {
        await destroyFixture(foreign);
      }
      const archive = parseDatabaseBackupArchive(await readFile(file));
      const archiveKey = new TextEncoder().encode(archivePassphrase);
      const opened = await openDatabaseBackupArchive(archive, archiveKey);
      const inner = JSON.parse(Buffer.from(opened.plaintext).toString('utf8'));
      inner.authorization.authenticationTag =
        (inner.authorization.authenticationTag[0] === 'A' ? 'B' : 'A') +
        inner.authorization.authenticationTag.slice(1);
      const resealed = await sealDatabaseBackupArchive(
        new TextEncoder().encode(JSON.stringify(inner)),
        archiveKey,
        { ...opened.header, version: 2 },
      );
      opened.plaintext.fill(0);
      archiveKey.fill(0);
      const tamperedFile = join(fixture.directory, 'tampered-firewall.backup');
      await publishProtectedFile(
        tamperedFile,
        new TextEncoder().encode(JSON.stringify(resealed)),
        false,
        'Test archive',
        128 * 1024 * 1024,
      );
      const badSidecar = await runCli(
        [
          'backup',
          'restore-firewall',
          '--file',
          tamperedFile,
          '--overwrite',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--json',
        ],
        frames(EXEC_PASSPHRASE, archivePassphrase),
      );
      expect(badSidecar.exitCode).toBe(16);
      expect(await readFile(fixture.keyFile + '.authorization')).toEqual(sidecarBefore);
    } finally {
      await destroyFixture(fixture);
    }
  });
});
