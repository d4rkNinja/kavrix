import { chmod, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { deleteSecureFile, writeProtectedJsonDocument } from '@kavrix/key-files';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import {
  DatastoreProfileRegistry,
  resolveProfilePath,
  type DatastoreProfile,
} from '../src/datastore-profiles.js';
import { doctorHealModeFromOptions, runDoctorHeal } from '../src/doctor-heal.js';
import { runCli } from './execution-helpers.js';

const directories: string[] = [];

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-heal-${label}-`),
  );
  directories.push(directory);
  return directory;
}

describe('doctor --heal', () => {
  it('removes incomplete unbound profiles so init can retry', async () => {
    const directory = await scratch('unbound');
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    const profile: DatastoreProfile = {
      id: 'default' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'missing.db'),
      keyFile: join(directory, 'missing.key'),
    };
    await registry.add(profile);
    await registry.use(profile.id);

    const dryRun = await runCli(
      [
        'doctor',
        'health',
        '--heal',
        '--dry-run',
        '--json',
        '--profile-config-dir',
        configDir,
      ],
      '',
    );
    expect(dryRun.exitCode).toBe(0);
    const planned = JSON.parse(dryRun.stdout) as {
      planned: string[];
      healActions: Array<{ id: string; status: string }>;
    };
    expect(planned.planned).toContain('incomplete-unbound-profile');
    expect((await registry.list()).map((entry) => entry.id)).toContain('default');

    const healed = await runCli(
      ['doctor', 'health', '--heal', '--json', '--profile-config-dir', configDir],
      '',
    );
    expect(healed.exitCode).toBe(0);
    const report = JSON.parse(healed.stdout) as {
      healthy: boolean;
      autoHealed: string[];
    };
    expect(report.healthy).toBe(true);
    expect(report.autoHealed).toContain('incomplete-unbound-profile');
    expect(await registry.list()).toEqual([]);
  });

  it('hardens unsafe key-file parent directory modes with --heal', async () => {
    const directory = await scratch('acl');
    const parent = join(directory, 'keys');
    await mkdir(parent, { mode: 0o755 });
    await chmod(parent, 0o755);
    const keyFile = join(parent, 'owner.key');
    // Placeholder non-secret file so the path exists for ACL heal.
    await writeFile(keyFile, 'not-a-real-key', { mode: 0o644 });
    await chmod(keyFile, 0o644);

    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    const profile: DatastoreProfile = {
      id: 'aclfix' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'data.db'),
      keyFile,
    };
    await registry.add(profile);

    const result = await runCli(
      [
        'db',
        'doctor',
        'health',
        '--heal',
        '--json',
        '--profile',
        'aclfix',
        '--profile-config-dir',
        configDir,
      ],
      '',
    );
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as {
      autoHealed: string[];
      healthy: boolean;
    };
    expect(report.autoHealed).toEqual(
      expect.arrayContaining(['incomplete-unbound-profile']),
    );
    expect(report.autoHealed).toEqual(
      expect.arrayContaining(['key-parent-acl', 'key-file-acl']),
    );

    if (process.platform !== 'win32') {
      const { stat } = await import('node:fs/promises');
      const parentMode = (await stat(parent)).mode & 0o777;
      const fileMode = (await stat(keyFile)).mode & 0o777;
      expect(parentMode).toBe(0o700);
      expect(fileMode).toBe(0o600);
    }
  });

  it('does not invent passphrase recovery for corrupt vault state', async () => {
    const directory = await scratch('corrupt');
    const fixture = await createBoundFixture(directory);
    await writeFile(fixture.dataFile, Buffer.from('corrupt-not-a-vault'));

    const result = await runCli(
      ['doctor', 'health', '--heal', '--json', ...fixture.routingArgs],
      `${fixture.passphrase}\n`,
    );
    expect(result.exitCode).not.toBe(0);
    const report = JSON.parse(result.stdout) as {
      healthy: boolean;
      manualRecoveryRequired: string[];
    };
    expect(report.healthy).toBe(false);
    expect(report.manualRecoveryRequired.join(' ').toLowerCase()).not.toMatch(
      /passphrase.*recover|recover.*passphrase/i,
    );
  });


  it('does not chmod CWD for unused default ./kavrix.key when profile key lives elsewhere', async () => {
    if (process.platform === 'win32') return;
    const directory = await scratch('no-cwd-chmod');
    const workdir = join(directory, 'workdir');
    await mkdir(workdir, { mode: 0o755 });
    await chmod(workdir, 0o755);
    const keyParent = join(directory, 'profile-keys');
    await mkdir(keyParent, { mode: 0o700 });
    const keyFile = join(keyParent, 'kavrix.key');
    await writeFile(keyFile, 'placeholder', { mode: 0o600 });
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    // Unbound profile whose real key parent is not CWD — mimics ~/.kavrix after init
    // while Commander still defaults --key-file to ./kavrix.key.
    await registry.add({
      id: 'homeish' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'vault.db'),
      keyFile,
    });

    const previousCwd = process.cwd();
    try {
      process.chdir(workdir);
      const dryRun = await runCli(
        [
          'doctor',
          'health',
          '--heal',
          '--dry-run',
          '--json',
          '--profile-config-dir',
          configDir,
        ],
        '',
      );
      expect(dryRun.exitCode).toBe(0);
      const planned = JSON.parse(dryRun.stdout) as {
        planned: string[];
        healActions: Array<{ id: string; path?: string }>;
      };
      expect(
        planned.healActions.some(
          (action) =>
            action.id === 'key-parent-acl' && action.path === workdir,
        ),
      ).toBe(false);

      const healed = await runCli(
        ['doctor', 'health', '--heal', '--json', '--profile-config-dir', configDir],
        '',
      );
      expect(healed.exitCode).toBe(0);
      const { stat } = await import('node:fs/promises');
      expect((await stat(workdir)).mode & 0o777).toBe(0o755);
      const report = JSON.parse(healed.stdout) as {
        autoHealed: string[];
        healActions: Array<{ id: string; path?: string }>;
      };
      expect(
        report.healActions.some(
          (action) =>
            action.id === 'key-parent-acl' && action.path === workdir,
        ),
      ).toBe(false);
      expect(
        report.healActions.filter((action) => action.id === 'key-parent-acl'),
      ).toEqual([]);
    } finally {
      process.chdir(previousCwd);
    }
  });

  it('does not plan/apply ACL on a workspace-like parent of a nested empty workdir', async () => {
    if (process.platform === 'win32') return;
    // Mimic /workspace (755) with a nested empty CWD and profile key under a private dir.
    const workspaceLike = await scratch('workspace-like');
    await chmod(workspaceLike, 0o755);
    const workdir = join(workspaceLike, 'nested-cwd');
    await mkdir(workdir, { mode: 0o755 });
    await chmod(workdir, 0o755);
    const keyParent = join(workspaceLike, 'home', '.kavrix');
    await mkdir(keyParent, { recursive: true, mode: 0o700 });
    await chmod(keyParent, 0o700);
    const keyFile = join(keyParent, 'kavrix.key');
    await writeFile(keyFile, 'placeholder', { mode: 0o600 });
    const configDir = join(workspaceLike, 'home', '.config', 'kavrix');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    await registry.add({
      id: 'default' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(keyParent, 'kavrix.vault'),
      keyFile,
    });

    const previousCwd = process.cwd();
    try {
      process.chdir(workdir);
      const dryRun = await runCli(
        [
          'doctor',
          'health',
          '--heal',
          '--dry-run',
          '--json',
          '--profile-config-dir',
          configDir,
        ],
        '',
      );
      expect(dryRun.exitCode).toBe(0);
      const planned = JSON.parse(dryRun.stdout) as {
        healActions: Array<{ id: string; path?: string; status: string }>;
      };
      const aclPaths = planned.healActions
        .filter((action) => action.id === 'key-parent-acl')
        .map((action) => action.path);
      expect(aclPaths).not.toContain(workdir);
      expect(aclPaths).not.toContain(workspaceLike);

      const healed = await runCli(
        ['doctor', 'health', '--heal', '--json', '--profile-config-dir', configDir],
        '',
      );
      expect(healed.exitCode).toBe(0);
      const { stat } = await import('node:fs/promises');
      expect((await stat(workdir)).mode & 0o777).toBe(0o755);
      expect((await stat(workspaceLike)).mode & 0o777).toBe(0o755);
      const report = JSON.parse(healed.stdout) as {
        healActions: Array<{ id: string; path?: string }>;
      };
      const appliedAcl = report.healActions
        .filter((action) => action.id === 'key-parent-acl')
        .map((action) => action.path);
      expect(appliedAcl).not.toContain(workdir);
      expect(appliedAcl).not.toContain(workspaceLike);
    } finally {
      process.chdir(previousCwd);
    }
  });

  it('reports help for --heal on doctor health and db doctor health', async () => {
    const root = await runCli(['doctor', 'health', '--help'], '');
    expect(root.stdout).toMatch(/--heal/);
    expect(root.stdout).toMatch(/--dry-run/);
    const db = await runCli(['db', 'doctor', 'health', '--help'], '');
    expect(db.stdout).toMatch(/--heal/);
  });
});

describe('runDoctorHeal unit', () => {
  it('applies unbound removal and ACL harden in heal mode', async () => {
    const directory = await scratch('unit-heal');
    const parent = join(directory, 'keys');
    await mkdir(parent, { mode: 0o755 });
    await chmod(parent, 0o755);
    const keyFile = join(parent, 'owner.key');
    await writeFile(keyFile, 'placeholder', { mode: 0o644 });
    await chmod(keyFile, 0o644);
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    await registry.add({
      id: 'stuck' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'a.db'),
      keyFile,
    });
    const report = await runDoctorHeal({
      mode: 'heal',
      profileConfigDir: configDir,
    });
    expect(report.healed).toContain('incomplete-unbound-profile');
    expect(report.healed).toEqual(
      expect.arrayContaining(['key-parent-acl', 'key-file-acl']),
    );
    expect(report.manualRecoveryRequired).toEqual([]);
    expect((await registry.list()).length).toBe(0);
  });

  it('plans unbound removal in dry-run without mutating', async () => {
    const directory = await scratch('unit-dry');
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    await registry.add({
      id: 'stuck' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'a.db'),
      keyFile: join(directory, 'a.key'),
    });
    const report = await runDoctorHeal({
      mode: 'dry-run',
      profileConfigDir: configDir,
    });
    expect(report.planned).toContain('incomplete-unbound-profile');
    expect((await registry.list()).length).toBe(1);
  });

  it('clears a dangling current pointer with --heal', async () => {
    const directory = await scratch('dangling');
    const configDir = join(directory, 'config');
    // Ensure the secure config directory exists, then plant a dangling pointer.
    await DatastoreProfileRegistry.open({ configDirectory: configDir });
    const seeded = await DatastoreProfileRegistry.open({ configDirectory: configDir });
    await seeded.add({
      id: 'alive' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'a.db'),
      keyFile: join(directory, 'a.key'),
    });
    const registryPath = resolveProfilePath(configDir);
    await deleteSecureFile(registryPath);
    await writeProtectedJsonDocument(
      registryPath,
      {
        version: 2 as const,
        current: 'ghost',
        profiles: [],
      },
      'create',
      {
        maximumBytes: 128 * 1024,
        schema: {
          parse: (value: unknown) =>
            value as {
              version: 2;
              current: string | null;
              profiles: DatastoreProfile[];
            },
        },
      },
    );

    const reportMode = await runDoctorHeal({
      mode: 'report',
      profileConfigDir: configDir,
    });
    expect(reportMode.manualRecoveryRequired.join(' ')).toMatch(/dangling/i);

    const dry = await runDoctorHeal({
      mode: 'dry-run',
      profileConfigDir: configDir,
    });
    expect(dry.planned).toContain('dangling-current-pointer');

    const healed = await runDoctorHeal({
      mode: 'heal',
      profileConfigDir: configDir,
    });
    expect(healed.healed).toContain('dangling-current-pointer');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    expect(await registry.current()).toBeNull();
    expect(await registry.list()).toEqual([]);
  });


  it('refuses to harden broad filesystem roots even if named as a key parent', async () => {
    if (process.platform === 'win32') return;
    const report = await runDoctorHeal({
      mode: 'dry-run',
      // Simulate a pathological key whose immediate parent is /tmp (top-level root).
      keyFile: '/tmp/kavrix-heal-broad-root-sentinel.key',
    });
    // Missing artifact → no ACL plan. Plant the file then ensure /tmp is skipped.
    const { writeFile, unlink, chmod: chmodFile } = await import('node:fs/promises');
    await writeFile('/tmp/kavrix-heal-broad-root-sentinel.key', 'x', { mode: 0o600 });
    try {
      const withFile = await runDoctorHeal({
        mode: 'dry-run',
        keyFile: '/tmp/kavrix-heal-broad-root-sentinel.key',
      });
      const tmpActions = withFile.actions.filter(
        (action) => action.id === 'key-parent-acl' && action.path === resolve('/tmp'),
      );
      expect(tmpActions.length).toBe(1);
      expect(tmpActions[0]?.status).toBe('skipped');
      expect(withFile.planned).not.toContain('key-parent-acl');
    } finally {
      await unlink('/tmp/kavrix-heal-broad-root-sentinel.key').catch(() => undefined);
      void chmodFile;
    }
  });

  it('skips unused nonexistent standalone key-file so CWD is not hardened', async () => {
    if (process.platform === 'win32') return;
    const directory = await scratch('unused-default-key');
    const workdir = join(directory, 'workdir');
    await mkdir(workdir, { mode: 0o755 });
    await chmod(workdir, 0o755);
    const keyParent = join(directory, 'real-keys');
    await mkdir(keyParent, { mode: 0o700 });
    const keyFile = join(keyParent, 'owner.key');
    await writeFile(keyFile, 'placeholder', { mode: 0o600 });
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    await registry.add({
      id: 'real' as DatastoreProfile['id'],
      datastore: 'file',
      databaseId: '11111111-1111-4111-8111-111111111111' as never,
      dataFile: join(directory, 'vault.db'),
      keyFile,
    });

    const previousCwd = process.cwd();
    try {
      process.chdir(workdir);
      const report = await runDoctorHeal({
        mode: 'dry-run',
        profileConfigDir: configDir,
        // Simulate Commander default pointing at missing ./kavrix.key under CWD.
        keyFile: './kavrix.key',
      });
      expect(
        report.actions.some(
          (action) =>
            action.id === 'key-parent-acl' && action.path === workdir,
        ),
      ).toBe(false);
      const { stat } = await import('node:fs/promises');
      expect((await stat(workdir)).mode & 0o777).toBe(0o755);
    } finally {
      process.chdir(previousCwd);
    }
  });

  it('still hardens an explicit standalone key-file parent when the key exists', async () => {
    if (process.platform === 'win32') return;
    const directory = await scratch('explicit-cwd-key');
    const workdir = join(directory, 'workdir');
    await mkdir(workdir, { mode: 0o755 });
    await chmod(workdir, 0o755);
    const keyFile = join(workdir, 'kavrix.key');
    await writeFile(keyFile, 'placeholder', { mode: 0o644 });
    await chmod(keyFile, 0o644);

    const previousCwd = process.cwd();
    try {
      process.chdir(workdir);
      const report = await runDoctorHeal({
        mode: 'heal',
        keyFile: './kavrix.key',
      });
      expect(report.healed).toEqual(
        expect.arrayContaining(['key-parent-acl', 'key-file-acl']),
      );
      const { stat } = await import('node:fs/promises');
      expect((await stat(workdir)).mode & 0o777).toBe(0o700);
      expect((await stat(keyFile)).mode & 0o777).toBe(0o600);
    } finally {
      process.chdir(previousCwd);
    }
  });

  it('maps doctorHealModeFromOptions correctly', () => {
    expect(doctorHealModeFromOptions({})).toBe('report');
    expect(doctorHealModeFromOptions({ heal: true })).toBe('heal');
    expect(doctorHealModeFromOptions({ heal: true, dryRun: true })).toBe('dry-run');
  });

  it('treats a symlink key parent as a manual ACL issue', async () => {
    if (process.platform === 'win32') return;
    const directory = await scratch('symlink-acl');
    const realParent = join(directory, 'real-keys');
    await mkdir(realParent, { mode: 0o700 });
    const linkParent = join(directory, 'link-keys');
    const { symlink } = await import('node:fs/promises');
    await symlink(realParent, linkParent);
    const keyFile = join(linkParent, 'owner.key');
    await writeFile(join(realParent, 'owner.key'), 'x', { mode: 0o600 });
    const report = await runDoctorHeal({
      mode: 'report',
      keyFile,
    });
    expect(report.actions.some((action) => action.id === 'key-parent-acl')).toBe(true);
  });

  it('reports missing bound artifacts as manual recovery', async () => {
    const directory = await scratch('missing-bound');
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    // Bound id without files on disk.
    await registry.add({
      id: 'boundish' as DatastoreProfile['id'],
      datastore: 'file',
      databaseId: '11111111-1111-4111-8111-111111111111' as never,
      dataFile: join(directory, 'gone.db'),
      keyFile: join(directory, 'gone.key'),
    });
    const report = await runDoctorHeal({
      mode: 'heal',
      profileConfigDir: configDir,
      profileId: 'boundish',
    });
    expect(report.manualRecoveryRequired.join(' ')).toMatch(/missing/i);
    expect(
      report.actions.some((action) => action.id === 'missing-bound-artifacts'),
    ).toBe(true);
  });

  it('dry-runs key ACL repairs without applying them', async () => {
    if (process.platform === 'win32') return;
    const directory = await scratch('dry-acl');
    const parent = join(directory, 'keys');
    await mkdir(parent, { mode: 0o755 });
    await chmod(parent, 0o755);
    const keyFile = join(parent, 'owner.key');
    await writeFile(keyFile, 'placeholder', { mode: 0o644 });
    await chmod(keyFile, 0o644);
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    await registry.add({
      id: 'acl' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'a.db'),
      keyFile,
    });
    const report = await runDoctorHeal({
      mode: 'dry-run',
      profileConfigDir: configDir,
    });
    expect(report.planned).toEqual(
      expect.arrayContaining([
        'incomplete-unbound-profile',
        'key-parent-acl',
        'key-file-acl',
      ]),
    );
    const { stat } = await import('node:fs/promises');
    expect((await stat(parent)).mode & 0o777).toBe(0o755);
    expect((await stat(keyFile)).mode & 0o777).toBe(0o644);
  });

  it('reports unbound profiles without --heal as manual', async () => {
    const directory = await scratch('report-unbound');
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    await registry.add({
      id: 'leftover' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'x.db'),
      keyFile: join(directory, 'x.key'),
    });
    const report = await runDoctorHeal({
      mode: 'report',
      profileConfigDir: configDir,
    });
    expect(report.manualRecoveryRequired.join(' ')).toMatch(/Incomplete unbound/);
    expect(report.healed).toEqual([]);
  });

  it('hardens explicit --data-file parents in heal mode', async () => {
    if (process.platform === 'win32') return;
    const directory = await scratch('data-parent');
    const parent = join(directory, 'data');
    await mkdir(parent, { mode: 0o755 });
    await chmod(parent, 0o755);
    const dataFile = join(parent, 'vault.db');
    await writeFile(dataFile, 'x', { mode: 0o600 });
    const report = await runDoctorHeal({
      mode: 'heal',
      dataFile,
    });
    expect(report.healed).toContain('key-parent-acl');
    const { stat } = await import('node:fs/promises');
    expect((await stat(parent)).mode & 0o777).toBe(0o700);
  });
});

async function createBoundFixture(directory: string): Promise<{
  dataFile: string;
  keyFile: string;
  passphrase: string;
  routingArgs: string[];
}> {
  const configDir = join(directory, 'config');
  const dataFile = join(directory, 'vault.db');
  const keyFile = join(directory, 'owner.key');
  const passphrase = 'correct horse battery staple';
  const init = await runCli(
    [
      'init',
      '--json',
      '--passphrase-stdin',
      '--data-file',
      dataFile,
      '--key-file',
      keyFile,
      '--profile-config-dir',
      configDir,
    ],
    `${passphrase}\n${passphrase}\n`,
  );
  expect(init.exitCode).toBe(0);
  return {
    dataFile,
    keyFile,
    passphrase,
    routingArgs: ['--profile-config-dir', configDir, '--passphrase-stdin'],
  };
}
