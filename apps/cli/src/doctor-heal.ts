import { realpathSync } from 'node:fs';
import { lstat, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

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
  /**
   * Kavrix-owned artifact home (~/.kavrix). When provided, heal hardens it and
   * its config reference even when no key/data artifact exists there yet — an
   * existing home that predates strict ACLs blocks portable-key writes at
   * init. CLI handlers pass the resolved home; absent means do not touch it.
   */
  kavrixArtifactDir?: string;
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

  // Soft-read treats a dangling `current` as null, so openIfPresent no longer
  // fails closed on that case. Probe the on-disk pointer explicitly so report /
  // dry-run / heal still surface and clear it.
  let danglingCurrent = false;
  try {
    danglingCurrent =
      await DatastoreProfileRegistry.hasDanglingCurrentPointerAt(registryOptions);
  } catch (error) {
    if (!(error instanceof DatastoreProfileError && error.code === 'PROFILE_UNSAFE')) {
      throw error;
    }
    // Directory ACL issues are handled below via openIfPresent / harden paths.
  }
  if (danglingCurrent) {
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
      manualRecoveryRequired.push(`${detailBase} Re-run with --heal.`);
    } else if (!apply) {
      actions.push({
        id: 'dangling-current-pointer',
        status: 'manual',
        detail: `${detailBase} Re-run with --heal to clear it.`,
      });
      manualRecoveryRequired.push(`${detailBase} Re-run with --heal to clear it.`);
    } else {
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
      } catch (healError) {
        const detail =
          healError instanceof Error
            ? healError.message
            : 'The datastore profile registry is invalid.';
        actions.push({ id: 'profile-registry', status: 'manual', detail });
        manualRecoveryRequired.push(detail);
        return { actions, healed, planned, manualRecoveryRequired };
      }
    }
  }

  let registry: DatastoreProfileRegistry | null;
  try {
    registry = await DatastoreProfileRegistry.openIfPresent(registryOptions);
  } catch (error) {
    if (error instanceof DatastoreProfileError && error.code === 'PROFILE_INVALID') {
      const detail =
        'The datastore profile registry is invalid and cannot be repaired automatically.';
      actions.push({ id: 'profile-registry', status: 'manual', detail });
      manualRecoveryRequired.push(detail);
      return { actions, healed, planned, manualRecoveryRequired };
    } else if (
      error instanceof DatastoreProfileError &&
      error.code === 'PROFILE_UNSAFE'
    ) {
      // Fail closed on the registry. Do not chmod --config-dir: it may be a
      // project root (src/, package.json) that does not hold key/data files.
      const detail =
        'The datastore profile registry is not safe to use; fix directory permissions or pass --profile-config-dir.';
      actions.push({
        id: 'profile-registry',
        status: 'manual',
        detail,
        ...(options.profileConfigDir === undefined
          ? {}
          : { path: canonicalizeExistingPathSync(options.profileConfigDir) }),
      });
      manualRecoveryRequired.push(detail);
      registry = null;
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
  // active key/data artifact. It never walks ancestors, never treats an unused
  // Commander default `./kavrix.key` as an active key, and never chmods a
  // --config-dir / --profile-config-dir unless that directory actually holds
  // those owned files (a project-root registry home must stay untouched).
  const pathsToHarden = await collectOwnedSecretParentDirectories({
    profiles: scoped,
    ...(options.keyFile === undefined ? {} : { keyFile: options.keyFile }),
    ...(options.dataFile === undefined ? {} : { dataFile: options.dataFile }),
  });

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

  if (options.kavrixArtifactDir !== undefined) {
    const kavrixHome = resolve(options.kavrixArtifactDir);
    await maybeHardenDirectory(
      kavrixHome,
      'kavrix-dir-acl',
      actions,
      healed,
      planned,
      manualRecoveryRequired,
      apply,
      dryRun,
      options.mode,
    );
    const kavrixConfigPath = join(kavrixHome, 'config.toml');
    if (await pathExists(kavrixConfigPath)) {
      await maybeHardenFile(
        kavrixConfigPath,
        'kavrix-config-file-acl',
        'Config reference file',
        actions,
        healed,
        planned,
        manualRecoveryRequired,
        apply,
        dryRun,
        options.mode,
      );
    }
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
      'key-file-acl',
      'Key file',
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
      'heal only hardens the immediate parent of an existing key/data file that Kavrix owns.';
    actions.push({
      id: actionId,
      status: 'skipped',
      detail,
      path: directory,
    });
    return;
  }
  // Symlink directories are never chmod'd — even in --heal apply mode.
  try {
    const meta = await lstat(directory);
    if (meta.isSymbolicLink()) {
      const detail =
        `Directory ${directory} is a symbolic link; heal will not change its ACL. ` +
        'Replace the link with a real owner-only directory or harden the link target manually.';
      actions.push({
        id: actionId,
        status: 'manual',
        detail,
        path: directory,
      });
      manualRecoveryRequired.push(detail);
      return;
    }
  } catch {
    // Fall through to inspectDirectoryAcl missing/unsafe handling.
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
  actionId: string,
  label: string,
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
    const detail = `${label} ${filePath} is not owned by the current user; heal cannot safely change its ACL.`;
    actions.push({
      id: actionId,
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
        id: actionId,
        status: dryRun ? 'planned' : 'manual',
        detail: dryRun
          ? `Would harden ${label.toLowerCase()} ${filePath} to owner-only permissions.`
          : `${label} ${filePath} has unsafe permissions; re-run with --heal.`,
        path: filePath,
      },
      false,
      dryRun,
    );
    if (mode === 'report') {
      manualRecoveryRequired.push(
        `${label} ${filePath} has unsafe permissions; re-run with --heal.`,
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
        id: actionId,
        status: 'applied',
        detail: `Hardened ${label.toLowerCase()} ${filePath} to owner-only permissions.`,
        path: filePath,
      },
      true,
      false,
    );
  } catch (error) {
    const detail =
      error instanceof PortableKeyFileError
        ? `Could not harden ${label.toLowerCase()} ${filePath}: ${error.message}`
        : `Could not harden ${label.toLowerCase()} ${filePath}: ${
            error instanceof Error ? error.message : String(error)
          }`;
    actions.push({
      id: actionId,
      status: 'manual',
      detail,
      path: filePath,
    });
    manualRecoveryRequired.push(detail);
  }
}

/**
 * Immediate parents of existing Kavrix-owned key/data files. A --config-dir
 * is included only when it is that parent — never because it holds the
 * profile registry.
 */
export async function collectOwnedSecretParentDirectories(input: {
  readonly profiles?: readonly DatastoreProfile[];
  readonly keyFile?: string;
  readonly dataFile?: string;
}): Promise<Set<string>> {
  const pathsToHarden = new Set<string>();
  for (const profile of input.profiles ?? []) {
    await addImmediateParentIfArtifactExists(pathsToHarden, profile.keyFile);
    if (profile.datastore === 'file') {
      await addImmediateParentIfArtifactExists(pathsToHarden, profile.dataFile);
    }
  }
  if (input.keyFile !== undefined) {
    await addImmediateParentIfArtifactExists(pathsToHarden, input.keyFile);
  }
  if (input.dataFile !== undefined) {
    await addImmediateParentIfArtifactExists(pathsToHarden, input.dataFile);
  }
  return pathsToHarden;
}

async function addImmediateParentIfArtifactExists(
  pathsToHarden: Set<string>,
  artifactPath: string,
): Promise<void> {
  const resolved = resolve(artifactPath);
  if (!(await pathExists(resolved))) return;
  const logicalParent = dirname(resolved);
  try {
    const parentMeta = await lstat(logicalParent);
    if (parentMeta.isSymbolicLink()) {
      // Symlink parents cannot be chmod'd safely — surface them as ACL findings
      // (manual) instead of resolving through to the real directory only.
      pathsToHarden.add(logicalParent);
    }
  } catch {
    // Parent vanished between existence check and lstat; continue with realpath.
  }
  // Immediate parent only — never dirname(dirname(...)). Canonicalize so
  // Windows 8.3 / casing forms compare as the same owned directory.
  const canonicalArtifact = await realpath(resolved);
  pathsToHarden.add(await realpath(dirname(canonicalArtifact)));
}

function canonicalizeExistingPathSync(input: string): string {
  const resolved = resolve(input);
  try {
    return realpathSync(resolved);
  } catch {
    return resolved;
  }
}

/**
 * Refuse to chmod filesystem roots and other shared directories. Heal must
 * never lock down `/`, `$TMPDIR` when it is a top-level root, `$HOME`,
 * `/workspace`, or other top-level roots even if a mis-resolved key path
 * named them as its parent.
 */
function isBroadFilesystemRoot(directory: string): boolean {
  const resolved = canonicalizeExistingPathSync(directory);
  const home = canonicalizeExistingPathSync(homedir());
  const fsRoot = canonicalizeExistingPathSync('/');
  if (resolved === fsRoot || resolved === home) return true;
  const parent = dirname(resolved);
  // Top-level dirs directly under `/` (and macOS `/private`): tmp, workspace, home, …
  if (parent === fsRoot || parent === canonicalizeExistingPathSync('/private')) {
    return true;
  }
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
