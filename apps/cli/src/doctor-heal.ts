import { lstat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';

import {
  hardenExistingSecureDirectory,
  hardenExistingSecureFile,
  PortableKeyFileError,
  verifyWindowsUserOnlyAcl,
} from '@kavrix/key-files';
import {
  DatastoreProfileError,
  DatastoreProfileRegistry,
  type DatastoreProfile,
  type DatastoreProfileRegistryOptions,
} from './datastore-profiles.js';

export type DoctorHealMode = 'report' | 'heal' | 'dry-run';

export type DoctorHealAction = Readonly<{
  id: string;
  status: 'planned' | 'applied' | 'skipped' | 'manual';
  detail: string;
  profileId?: string;
  path?: string;
}>;

export type DoctorHealReport = Readonly<{
  actions: readonly DoctorHealAction[];
  healed: readonly string[];
  planned: readonly string[];
  manualRecoveryRequired: readonly string[];
}>;

export type DoctorHealOptions = Readonly<{
  mode: DoctorHealMode;
  profileConfigDir?: string;
  /** When set, only consider this profile for unbound removal / ACL checks. */
  profileId?: string;
  /** Explicit key/data paths (standalone routing without a profile registry). */
  keyFile?: string;
  dataFile?: string;
}>;

/**
 * Diagnoses and optionally repairs safe local Kavrix state:
 * incomplete unbound profiles, dangling current pointers, and owner-only
 * ACL/mode drift on key-file parents and key files. Never invents passphrase
 * recovery and never deletes vault/key data files.
 */
export async function runDoctorHeal(
  options: DoctorHealOptions,
): Promise<DoctorHealReport> {
  const actions: DoctorHealAction[] = [];
  const healed: string[] = [];
  const planned: string[] = [];
  const manualRecoveryRequired: string[] = [];
  const apply = options.mode === 'heal';
  const dryRun = options.mode === 'dry-run';

  const registryOptions: DatastoreProfileRegistryOptions =
    options.profileConfigDir === undefined
      ? {}
      : { configDirectory: options.profileConfigDir };

  let registry: DatastoreProfileRegistry | null;
  try {
    registry = await DatastoreProfileRegistry.openIfPresent(registryOptions);
  } catch (error) {
    if (error instanceof DatastoreProfileError && error.code === 'PROFILE_INVALID') {
      const detailBase = 'Profile registry has a dangling or invalid current pointer.';
      if (dryRun) {
        recordAction(
          actions,
          healed,
          planned,
          {
            id: 'dangling-current-pointer',
            status: 'planned',
            detail: `${detailBase} Would clear the selection pointer.`,
          },
          false,
          true,
        );
        // Still try to continue after a non-mutating probe is impossible; stop.
        manualRecoveryRequired.push(`${detailBase} Re-run with --heal.`);
        return { actions, healed, planned, manualRecoveryRequired };
      }
      if (!apply) {
        actions.push({
          id: 'dangling-current-pointer',
          status: 'manual',
          detail: `${detailBase} Re-run with --heal to clear it.`,
        });
        manualRecoveryRequired.push(`${detailBase} Re-run with --heal to clear it.`);
        return { actions, healed, planned, manualRecoveryRequired };
      }
      try {
        const cleared =
          await DatastoreProfileRegistry.healDanglingCurrentPointerAt(registryOptions);
        if (cleared) {
          recordAction(
            actions,
            healed,
            planned,
            {
              id: 'dangling-current-pointer',
              status: 'applied',
              detail:
                'Cleared a dangling profile selection pointer so the registry is readable again.',
            },
            true,
            false,
          );
        }
        registry = await DatastoreProfileRegistry.openIfPresent(registryOptions);
      } catch (healError) {
        const detail =
          healError instanceof Error
            ? healError.message
            : 'The datastore profile registry is invalid.';
        actions.push({ id: 'profile-registry', status: 'manual', detail });
        manualRecoveryRequired.push(detail);
        return { actions, healed, planned, manualRecoveryRequired };
      }
    } else if (
      error instanceof DatastoreProfileError &&
      error.code === 'PROFILE_UNSAFE'
    ) {
      const configDir =
        options.profileConfigDir === undefined
          ? undefined
          : resolve(options.profileConfigDir);
      if (configDir !== undefined) {
        await maybeHardenDirectory(
          configDir,
          'config-directory-acl',
          actions,
          healed,
          planned,
          manualRecoveryRequired,
          apply,
          dryRun,
          options.mode,
        );
        try {
          registry = await DatastoreProfileRegistry.openIfPresent(registryOptions);
        } catch {
          const detail =
            'The datastore profile registry directory remains unsafe after ACL inspection.';
          actions.push({
            id: 'profile-registry',
            status: 'manual',
            detail,
            path: configDir,
          });
          manualRecoveryRequired.push(detail);
          return { actions, healed, planned, manualRecoveryRequired };
        }
      } else {
        const detail =
          'The datastore profile registry is not safe to use; fix directory permissions or pass --profile-config-dir.';
        actions.push({ id: 'profile-registry', status: 'manual', detail });
        manualRecoveryRequired.push(detail);
        return { actions, healed, planned, manualRecoveryRequired };
      }
    } else {
      throw error;
    }
  }

  const profiles: DatastoreProfile[] =
    registry === null ? [] : [...(await registry.list())];
  const scoped =
    options.profileId === undefined
      ? profiles
      : profiles.filter((profile) => profile.id === options.profileId);

  const unbound = scoped.filter((profile) => profile.databaseId === undefined);
  if (unbound.length > 0) {
    for (const profile of unbound) {
      const detail = apply
        ? `Removed incomplete unbound profile \`${profile.id}\` (no database binding) so init can retry.`
        : dryRun
          ? `Would remove incomplete unbound profile \`${profile.id}\` (PROFILE_DUPLICATE leftover risk).`
          : `Incomplete unbound profile \`${profile.id}\` blocks init retry; re-run with --heal to remove the registry entry (key/data files are retained).`;
      recordAction(
        actions,
        healed,
        planned,
        {
          id: 'incomplete-unbound-profile',
          status: apply ? 'applied' : dryRun ? 'planned' : 'manual',
          detail,
          profileId: profile.id,
        },
        apply,
        dryRun,
      );
      if (!apply && !dryRun) {
        manualRecoveryRequired.push(detail);
      }
    }
    if (apply && registry !== null) {
      await registry.removeUnboundProfiles(unbound.map((profile) => profile.id));
    }
  }

  // ACL heal hardens ONLY the immediate parent of each resolved, existing
  // active key/data artifact (plus the profile config directory itself). It
  // never walks ancestors and never treats an unused Commander default
  // `./kavrix.key` as an active key.
  const pathsToHarden = new Set<string>();
  for (const profile of scoped) {
    await addImmediateParentIfArtifactExists(pathsToHarden, profile.keyFile);
    if (profile.datastore === 'file') {
      await addImmediateParentIfArtifactExists(pathsToHarden, profile.dataFile);
    }
  }
  if (options.keyFile !== undefined) {
    await addImmediateParentIfArtifactExists(pathsToHarden, options.keyFile);
  }
  if (options.dataFile !== undefined) {
    await addImmediateParentIfArtifactExists(pathsToHarden, options.dataFile);
  }
  if (options.profileConfigDir !== undefined) {
    pathsToHarden.add(resolve(options.profileConfigDir));
  }

  for (const directory of pathsToHarden) {
    await maybeHardenDirectory(
      directory,
      'key-parent-acl',
      actions,
      healed,
      planned,
      manualRecoveryRequired,
      apply,
      dryRun,
      options.mode,
    );
  }

  const filesToHarden = new Set<string>();
  for (const profile of scoped) {
    const resolvedKey = resolve(profile.keyFile);
    if (await pathExists(resolvedKey)) filesToHarden.add(resolvedKey);
  }
  if (options.keyFile !== undefined) {
    const resolvedKey = resolve(options.keyFile);
    if (await pathExists(resolvedKey)) filesToHarden.add(resolvedKey);
  }
  for (const filePath of filesToHarden) {
    await maybeHardenFile(
      filePath,
      actions,
      healed,
      planned,
      manualRecoveryRequired,
      apply,
      dryRun,
      options.mode,
    );
  }

  for (const profile of scoped) {
    if (profile.databaseId === undefined) continue;
    const missing: string[] = [];
    if (!(await pathExists(resolve(profile.keyFile)))) {
      missing.push(`key file ${profile.keyFile}`);
    }
    if (
      profile.datastore === 'file' &&
      !(await pathExists(resolve(profile.dataFile)))
    ) {
      missing.push(`data file ${profile.dataFile}`);
    }
    if (missing.length > 0) {
      const detail =
        `Bound profile \`${profile.id}\` is missing ${missing.join(' and ')}; ` +
        'restore the artifacts or remove the profile with `kavrix db profile remove` after confirming no vault data is needed. Heal will not delete vault data.';
      actions.push({
        id: 'missing-bound-artifacts',
        status: 'manual',
        detail,
        profileId: profile.id,
      });
      manualRecoveryRequired.push(detail);
    }
  }

  return { actions, healed, planned, manualRecoveryRequired };
}

function recordAction(
  actions: DoctorHealAction[],
  healed: string[],
  planned: string[],
  action: DoctorHealAction,
  apply: boolean,
  dryRun: boolean,
): void {
  actions.push(action);
  if (apply && action.status === 'applied') healed.push(action.id);
  if (dryRun && action.status === 'planned') planned.push(action.id);
}

async function maybeHardenDirectory(
  directory: string,
  actionId: string,
  actions: DoctorHealAction[],
  healed: string[],
  planned: string[],
  manualRecoveryRequired: string[],
  apply: boolean,
  dryRun: boolean,
  mode: DoctorHealMode,
): Promise<void> {
  if (isBroadFilesystemRoot(directory)) {
    const detail =
      `Refusing to change permissions on shared filesystem root ${directory}; ` +
      'heal only hardens the immediate parent of an active key/data file (for example ~/.kavrix).';
    actions.push({
      id: actionId,
      status: 'skipped',
      detail,
      path: directory,
    });
    return;
  }
  const state = await inspectDirectoryAcl(directory);
  if (state === 'missing' || state === 'ok') return;
  if (state === 'foreign-owner') {
    const detail = `Directory ${directory} is not owned by the current user; heal cannot safely change its ACL.`;
    actions.push({
      id: actionId,
      status: 'manual',
      detail,
      path: directory,
    });
    manualRecoveryRequired.push(detail);
    return;
  }
  if (dryRun || mode === 'report') {
    recordAction(
      actions,
      healed,
      planned,
      {
        id: actionId,
        status: dryRun ? 'planned' : 'manual',
        detail: dryRun
          ? `Would harden directory ${directory} to owner-only permissions.`
          : `Directory ${directory} has unsafe permissions; re-run with --heal.`,
        path: directory,
      },
      false,
      dryRun,
    );
    if (mode === 'report') {
      manualRecoveryRequired.push(
        `Directory ${directory} has unsafe permissions; re-run with --heal.`,
      );
    }
    return;
  }
  try {
    await hardenExistingSecureDirectory(directory);
    recordAction(
      actions,
      healed,
      planned,
      {
        id: actionId,
        status: 'applied',
        detail: `Hardened directory ${directory} to owner-only permissions.`,
        path: directory,
      },
      true,
      false,
    );
  } catch (error) {
    const detail =
      error instanceof PortableKeyFileError
        ? `Could not harden directory ${directory}: ${error.message}`
        : `Could not harden directory ${directory}: ${
            error instanceof Error ? error.message : String(error)
          }`;
    actions.push({
      id: actionId,
      status: 'manual',
      detail,
      path: directory,
    });
    manualRecoveryRequired.push(detail);
  }
}

async function maybeHardenFile(
  filePath: string,
  actions: DoctorHealAction[],
  healed: string[],
  planned: string[],
  manualRecoveryRequired: string[],
  apply: boolean,
  dryRun: boolean,
  mode: DoctorHealMode,
): Promise<void> {
  const state = await inspectFileAcl(filePath);
  if (state === 'missing' || state === 'ok') return;
  if (state === 'foreign-owner') {
    const detail = `Key file ${filePath} is not owned by the current user; heal cannot safely change its ACL.`;
    actions.push({
      id: 'key-file-acl',
      status: 'manual',
      detail,
      path: filePath,
    });
    manualRecoveryRequired.push(detail);
    return;
  }
  if (dryRun || mode === 'report') {
    recordAction(
      actions,
      healed,
      planned,
      {
        id: 'key-file-acl',
        status: dryRun ? 'planned' : 'manual',
        detail: dryRun
          ? `Would harden key file ${filePath} to owner-only permissions.`
          : `Key file ${filePath} has unsafe permissions; re-run with --heal.`,
        path: filePath,
      },
      false,
      dryRun,
    );
    if (mode === 'report') {
      manualRecoveryRequired.push(
        `Key file ${filePath} has unsafe permissions; re-run with --heal.`,
      );
    }
    return;
  }
  try {
    await hardenExistingSecureFile(filePath);
    recordAction(
      actions,
      healed,
      planned,
      {
        id: 'key-file-acl',
        status: 'applied',
        detail: `Hardened key file ${filePath} to owner-only permissions.`,
        path: filePath,
      },
      true,
      false,
    );
  } catch (error) {
    const detail =
      error instanceof PortableKeyFileError
        ? `Could not harden key file ${filePath}: ${error.message}`
        : `Could not harden key file ${filePath}: ${
            error instanceof Error ? error.message : String(error)
          }`;
    actions.push({
      id: 'key-file-acl',
      status: 'manual',
      detail,
      path: filePath,
    });
    manualRecoveryRequired.push(detail);
  }
}

async function addImmediateParentIfArtifactExists(
  pathsToHarden: Set<string>,
  artifactPath: string,
): Promise<void> {
  const resolved = resolve(artifactPath);
  if (!(await pathExists(resolved))) return;
  // Immediate parent only — never dirname(dirname(...)).
  pathsToHarden.add(dirname(resolved));
}

/**
 * Refuse to chmod filesystem roots and other shared directories. Heal must
 * never lock down `/`, `/tmp`, `$HOME`, `/workspace`, or other top-level roots
 * even if a mis-resolved key path named them as its parent.
 */
function isBroadFilesystemRoot(directory: string): boolean {
  const resolved = resolve(directory);
  const home = resolve(homedir());
  if (resolved === resolve('/') || resolved === home) return true;
  const parent = dirname(resolved);
  // Top-level dirs directly under `/` (and macOS `/private`): /tmp, /workspace, /home, …
  if (parent === resolve('/') || parent === resolve('/private')) return true;
  return false;
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

type AclState = 'ok' | 'unsafe' | 'missing' | 'foreign-owner';

async function inspectDirectoryAcl(path: string): Promise<AclState> {
  try {
    const metadata = await lstat(path, { bigint: true });
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) return 'unsafe';
    /* v8 ignore start -- Windows ACL probe; Linux hygiene covers POSIX modes. */
    if (process.platform === 'win32') {
      try {
        await verifyWindowsUserOnlyAcl(path);
        return 'ok';
      } catch {
        return 'unsafe';
      }
    }
    /* v8 ignore stop */
    const getuid = process.getuid;
    if (getuid === undefined) return 'unsafe';
    if (metadata.uid !== BigInt(getuid())) return 'foreign-owner';
    if ((metadata.mode & 0o777n) !== 0o700n) return 'unsafe';
    return 'ok';
  } catch {
    return 'missing';
  }
}

async function inspectFileAcl(path: string): Promise<AclState> {
  try {
    const metadata = await lstat(path, { bigint: true });
    if (metadata.isSymbolicLink() || !metadata.isFile()) return 'unsafe';
    /* v8 ignore start -- Windows ACL probe; Linux hygiene covers POSIX modes. */
    if (process.platform === 'win32') {
      try {
        await verifyWindowsUserOnlyAcl(path);
        return 'ok';
      } catch {
        return 'unsafe';
      }
    }
    /* v8 ignore stop */
    const getuid = process.getuid;
    if (getuid === undefined) return 'unsafe';
    if (metadata.uid !== BigInt(getuid())) return 'foreign-owner';
    if ((metadata.mode & 0o777n) !== 0o600n) return 'unsafe';
    return 'ok';
  } catch {
    return 'missing';
  }
}

export function doctorHealModeFromOptions(options: {
  heal?: boolean;
  dryRun?: boolean;
}): DoctorHealMode {
  if (options.heal === true && options.dryRun === true) return 'dry-run';
  if (options.heal === true) return 'heal';
  return 'report';
}
