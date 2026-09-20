import { execFile } from 'node:child_process';
import { chmod, mkdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';

import { databaseIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { afterEach, describe, expect, it } from 'vitest';

import {
  deleteSecureFile,
  verifyWindowsUserOnlyAcl,
  writeProtectedJsonDocument,
} from '@kavrix/key-files';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import {
  DatastoreProfileRegistry,
  resolveProfilePath,
  type DatastoreProfile,
} from '../src/datastore-profiles.js';
import {
  collectOwnedSecretParentDirectories,
  doctorHealModeFromOptions,
  runDoctorHeal,
} from '../src/doctor-heal.js';
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
    // Select so binding is unbound (not missing). P1 dry-run no longer
    // short-circuits missing binding before vault unlock.
    await registry.use('homeish' as DatastoreProfile['id']);

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
          (action) => action.id === 'key-parent-acl' && action.path === workdir,
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
          (action) => action.id === 'key-parent-acl' && action.path === workdir,
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
    await registry.use('default' as DatastoreProfile['id']);

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

  it('does not chmod --config-dir when key/data files live elsewhere', async () => {
    // Project root used only as a profile registry home (also holds src/).
    // Same family as the unused-CWD chmod bug; 0.2.17 did not cover config-dir.
    const directory = await scratch('no-config-dir-chmod');
    const projectRoot = join(directory, 'project');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: projectRoot,
    });
    await mkdir(join(projectRoot, 'src'));
    await writeFile(join(projectRoot, 'src', 'index.ts'), 'export {};\n');
    const keyParent = join(directory, 'owned-keys');
    await mkdir(keyParent);
    const keyFile = join(keyParent, 'kavrix.key');
    await writeFile(keyFile, 'placeholder');
    const dataParent = join(directory, 'owned-data');
    await mkdir(dataParent);
    const dataFile = join(dataParent, 'kavrix.vault');
    await writeFile(dataFile, 'placeholder');
    await registry.add({
      id: 'elsewhere' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile,
      keyFile,
    });
    await registry.use('elsewhere' as DatastoreProfile['id']);
    await markAsProjectRootLike(projectRoot);
    await markOwnedSecretParentUnsafe(keyParent);
    await markOwnedSecretFileUnsafe(keyFile);
    const beforeConfig = await captureAccessFingerprint(projectRoot);
    const beforeSrc = await captureAccessFingerprint(join(projectRoot, 'src'));

    const dryRun = await runCli(
      [
        'doctor',
        'health',
        '--heal',
        '--dry-run',
        '--json',
        '--config-dir',
        projectRoot,
      ],
      '',
    );
    expect(dryRun.exitCode).toBe(0);
    const planned = JSON.parse(dryRun.stdout) as {
      healActions: Array<{ id: string; path?: string }>;
    };
    expect(
      await actionTargetsDirectory(planned.healActions, projectRoot, [
        'key-parent-acl',
        'config-directory-acl',
      ]),
    ).toBe(false);

    const healed = await runCli(
      ['doctor', 'health', '--heal', '--json', '--config-dir', projectRoot],
      '',
    );
    expect(healed.exitCode).toBe(0);
    const report = JSON.parse(healed.stdout) as {
      autoHealed: string[];
      healActions: Array<{ id: string; path?: string }>;
    };
    expect(
      await actionTargetsDirectory(report.healActions, projectRoot, [
        'key-parent-acl',
        'config-directory-acl',
      ]),
    ).toBe(false);
    expect(report.autoHealed).toEqual(
      expect.arrayContaining(['key-parent-acl', 'key-file-acl']),
    );
    expect(await captureAccessFingerprint(projectRoot)).toBe(beforeConfig);
    expect(await captureAccessFingerprint(join(projectRoot, 'src'))).toBe(beforeSrc);
    await expectOwnerOnlyDirectory(keyParent);
    await expectOwnerOnlyFile(keyFile);
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
    const alive: DatastoreProfile = {
      id: 'alive' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'a.db'),
      keyFile: join(directory, 'a.key'),
      databaseId: databaseIdSchema.parse('db_alive'),
      defaultVaultId: vaultIdSchema.parse('vault_alive'),
    };
    await seeded.add(alive);
    const registryPath = resolveProfilePath(configDir);
    const onDisk = {
      version: 2 as const,
      current: 'does-not-exist',
      profiles: [alive],
    };
    await deleteSecureFile(registryPath);
    await writeProtectedJsonDocument(registryPath, onDisk, 'create', {
      maximumBytes: 128 * 1024,
      schema: {
        parse: (value: unknown) =>
          value as {
            version: 2;
            current: string | null;
            profiles: DatastoreProfile[];
          },
      },
    });

    // Soft-read must keep list/recovery usable before heal clears the pointer.
    const listed = await runCli(
      ['db', 'profile', 'list', '--json', '--profile-config-dir', configDir],
      '',
    );
    expect(listed.exitCode).toBe(0);
    expect(JSON.parse(listed.stdout).profiles.map((p: { id: string }) => p.id)).toEqual(
      ['alive'],
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
    expect((await registry.list()).map((profile) => profile.id)).toEqual(['alive']);

    const use = await runCli(
      ['db', 'profile', 'use', 'alive', '--profile-config-dir', configDir],
      '',
    );
    expect(use.exitCode).toBe(0);
  });

  it('refuses to harden broad filesystem roots even if named as a key parent', async () => {
    const tmp = await realpath(tmpdir());
    const fsRoot = await canonPath('/');
    const tmpParent = dirname(tmp);
    // Only when $TMPDIR is a top-level root (typical Linux /tmp). Nested
    // macOS/Windows temp dirs are not broad roots and must not be used as /tmp.
    if (tmpParent !== fsRoot && tmpParent !== (await canonPath('/private'))) {
      return;
    }
    const sentinel = join(tmp, `kavrix-heal-broad-root-sentinel-${process.pid}.key`);
    await writeFile(sentinel, 'x');
    try {
      const withFile = await runDoctorHeal({
        mode: 'dry-run',
        keyFile: sentinel,
      });
      const tmpActions = withFile.actions.filter(
        (action) =>
          action.id === 'key-parent-acl' &&
          action.path !== undefined &&
          pathsEqual(action.path, tmp),
      );
      expect(tmpActions.length).toBe(1);
      expect(tmpActions[0]?.status).toBe('skipped');
      expect(withFile.planned).not.toContain('key-parent-acl');
    } finally {
      await rm(sentinel, { force: true });
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
          (action) => action.id === 'key-parent-acl' && action.path === workdir,
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

  it('collects only existing key/data parents, never a bare --config-dir', async () => {
    const directory = await scratch('collect-parents');
    const projectRoot = join(directory, 'project');
    await mkdir(join(projectRoot, 'src'), { recursive: true });
    const keyParent = join(directory, 'owned-keys');
    await mkdir(keyParent, { recursive: true });
    const keyFile = join(keyParent, 'kavrix.key');
    await writeFile(keyFile, 'placeholder');
    const dataParent = join(directory, 'owned-data');
    await mkdir(dataParent, { recursive: true });
    const dataFile = join(dataParent, 'kavrix.vault');
    await writeFile(dataFile, 'placeholder');

    const dirs = await collectOwnedSecretParentDirectories({
      profiles: [
        {
          id: 'elsewhere' as DatastoreProfile['id'],
          datastore: 'file',
          dataFile,
          keyFile,
        },
      ],
    });
    expect([...dirs].sort()).toEqual(
      [(await realpath(dataParent)), (await realpath(keyParent))].sort(),
    );
    expect(dirs.has(await canonPath(projectRoot))).toBe(false);

    const empty = await collectOwnedSecretParentDirectories({
      profiles: [
        {
          id: 'missing' as DatastoreProfile['id'],
          datastore: 'file',
          dataFile: join(projectRoot, 'absent.vault'),
          keyFile: join(projectRoot, 'absent.key'),
        },
      ],
    });
    expect([...empty]).toEqual([]);
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

  it('does not plan/apply key-parent-acl on a project-root --config-dir', async () => {
    const directory = await scratch('unit-config-dir');
    const projectRoot = join(directory, 'repo');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: projectRoot,
    });
    await mkdir(join(projectRoot, 'src'));
    const keyParent = join(directory, 'secrets');
    await mkdir(keyParent);
    const keyFile = join(keyParent, 'owner.key');
    await writeFile(keyFile, 'placeholder');
    await registry.add({
      id: 'real' as DatastoreProfile['id'],
      datastore: 'file',
      databaseId: '11111111-1111-4111-8111-111111111111' as never,
      dataFile: join(directory, 'vault.db'),
      keyFile,
    });
    await markAsProjectRootLike(projectRoot);
    const beforeConfig = await captureAccessFingerprint(projectRoot);

    const dry = await runDoctorHeal({
      mode: 'dry-run',
      profileConfigDir: projectRoot,
    });
    expect(
      await actionTargetsDirectory(dry.actions, projectRoot, [
        'key-parent-acl',
        'config-directory-acl',
      ]),
    ).toBe(false);

    const healed = await runDoctorHeal({
      mode: 'heal',
      profileConfigDir: projectRoot,
    });
    expect(
      await actionTargetsDirectory(healed.actions, projectRoot, [
        'key-parent-acl',
        'config-directory-acl',
      ]),
    ).toBe(false);
    expect(await captureAccessFingerprint(projectRoot)).toBe(beforeConfig);
  });

  it('still hardens a --config-dir that is the parent of an existing key file', async () => {
    const directory = await scratch('config-is-key-parent');
    const configDir = join(directory, 'kavrix-home');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    const keyFile = join(configDir, 'kavrix.key');
    await writeFile(keyFile, 'placeholder');
    await registry.add({
      id: 'colocated' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(configDir, 'kavrix.vault'),
      keyFile,
    });
    await markOwnedSecretParentUnsafe(configDir);
    await markOwnedSecretFileUnsafe(keyFile);

    const report = await runDoctorHeal({
      mode: 'heal',
      profileConfigDir: configDir,
      keyFile,
    });
    expect(report.healed).toEqual(
      expect.arrayContaining(['key-parent-acl', 'key-file-acl']),
    );
    expect(
      await actionTargetsDirectory(report.actions, configDir, ['key-parent-acl']),
    ).toBe(true);
    await expectOwnerOnlyDirectory(configDir);
    await expectOwnerOnlyFile(keyFile);
  });

  it('fails closed on an unsafe project-root --config-dir without chmodding it', async () => {
    const directory = await scratch('unsafe-config-dir');
    const projectRoot = join(directory, 'repo');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: projectRoot,
    });
    await mkdir(join(projectRoot, 'src'));
    const keyParent = join(directory, 'secrets');
    await mkdir(keyParent);
    const keyFile = join(keyParent, 'owner.key');
    await writeFile(keyFile, 'placeholder');
    await registry.add({
      id: 'unsafe-root' as DatastoreProfile['id'],
      datastore: 'file',
      dataFile: join(directory, 'vault.db'),
      keyFile,
    });
    await markOwnedSecretParentUnsafe(keyParent);
    await markOwnedSecretFileUnsafe(keyFile);
    await markRegistryDirectoryUnreadable(projectRoot);
    const beforeConfig = await captureAccessFingerprint(projectRoot);

    const report = await runDoctorHeal({
      mode: 'heal',
      profileConfigDir: projectRoot,
      keyFile,
    });
    expect(await captureAccessFingerprint(projectRoot)).toBe(beforeConfig);
    expect(
      await actionTargetsDirectory(report.actions, projectRoot, [
        'key-parent-acl',
        'config-directory-acl',
      ]),
    ).toBe(false);
    expect(report.manualRecoveryRequired.join(' ')).toMatch(
      /not safe to use|permissions/i,
    );
    expect(report.healed).toEqual(
      expect.arrayContaining(['key-parent-acl', 'key-file-acl']),
    );
    await expectOwnerOnlyDirectory(keyParent);
    await expectOwnerOnlyFile(keyFile);
  });

  it('hardens explicit --data-file parents in heal mode', async () => {
    const directory = await scratch('data-parent');
    const parent = join(directory, 'data');
    await mkdir(parent);
    const dataFile = join(parent, 'vault.db');
    await writeFile(dataFile, 'x');
    await markOwnedSecretParentUnsafe(parent);
    const report = await runDoctorHeal({
      mode: 'heal',
      dataFile,
    });
    expect(report.healed).toContain('key-parent-acl');
    await expectOwnerOnlyDirectory(parent);
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

const execFileAsync = promisify(execFile);
const WINDOWS_ICACLS = 'C:\\Windows\\System32\\icacls.exe';

async function canonPath(input: string): Promise<string> {
  try {
    return await realpath(input);
  } catch {
    return resolve(input);
  }
}

function pathsEqual(left: string, right: string): boolean {
  if (process.platform === 'win32') {
    return left.toLowerCase() === right.toLowerCase();
  }
  return left === right;
}

async function actionTargetsDirectory(
  actions: ReadonlyArray<{ id: string; path?: string }>,
  directory: string,
  ids: readonly string[],
): Promise<boolean> {
  const expected = await canonPath(directory);
  return actions.some(
    (action) =>
      ids.includes(action.id) &&
      action.path !== undefined &&
      pathsEqual(action.path, expected),
  );
}

async function captureAccessFingerprint(path: string): Promise<string> {
  const canonical = await canonPath(path);
  if (process.platform === 'win32') {
    const { stdout } = await execFileAsync(WINDOWS_ICACLS, [canonical], {
      env: { SystemRoot: 'C:\\Windows', WINDIR: 'C:\\Windows' },
      timeout: 15_000,
      windowsHide: true,
    });
    return String(stdout);
  }
  return String((await stat(canonical)).mode & 0o777);
}

async function grantWindowsEveryoneRead(path: string): Promise<void> {
  const canonical = await canonPath(path);
  await execFileAsync(WINDOWS_ICACLS, [canonical, '/grant', '*S-1-1-0:(R)'], {
    env: { SystemRoot: 'C:\\Windows', WINDIR: 'C:\\Windows' },
    timeout: 15_000,
    windowsHide: true,
  });
}

/** POSIX 755: registry still opens. Windows: leave the registry-hardened DACL. */
async function markAsProjectRootLike(directory: string): Promise<void> {
  if (process.platform === 'win32') return;
  await chmod(directory, 0o755);
}

/** POSIX 777 / Windows Everyone read: registry open fail-closes. */
async function markRegistryDirectoryUnreadable(directory: string): Promise<void> {
  if (process.platform === 'win32') {
    await grantWindowsEveryoneRead(directory);
    return;
  }
  await chmod(directory, 0o777);
}

async function markOwnedSecretParentUnsafe(directory: string): Promise<void> {
  if (process.platform === 'win32') {
    await grantWindowsEveryoneRead(directory);
    return;
  }
  await chmod(directory, 0o755);
}

async function markOwnedSecretFileUnsafe(filePath: string): Promise<void> {
  if (process.platform === 'win32') {
    await grantWindowsEveryoneRead(filePath);
    return;
  }
  await chmod(filePath, 0o644);
}

async function expectOwnerOnlyDirectory(directory: string): Promise<void> {
  const canonical = await canonPath(directory);
  if (process.platform === 'win32') {
    await expect(verifyWindowsUserOnlyAcl(canonical)).resolves.toBeUndefined();
    return;
  }
  expect((await stat(canonical)).mode & 0o777).toBe(0o700);
}

async function expectOwnerOnlyFile(filePath: string): Promise<void> {
  const canonical = await canonPath(filePath);
  if (process.platform === 'win32') {
    await expect(verifyWindowsUserOnlyAcl(canonical)).resolves.toBeUndefined();
    return;
  }
  expect((await stat(canonical)).mode & 0o777).toBe(0o600);
}
