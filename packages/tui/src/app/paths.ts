import { homedir } from 'node:os';
import { join, sep } from 'node:path';

/**
 * Secure default locations for a new file-datastore profile.
 * Mirrors classic guided `kavrix init` (resolves under `~/.kavrix/`) so empty
 * HOME setups do not depend on multi-level XDG trees that the portable-key
 * adapter refuses to create (`KEY_FILE_NOT_FOUND` when parents are missing).
 * Always uses `node:path.join` so `path.sep` is correct on win32.
 */
export function defaultFileProfilePaths(
  profileId: string,
  home: string = homedir(),
): Readonly<{ dataFile: string; keyFile: string }> {
  const base = join(home, '.kavrix');
  if (profileId === 'default') {
    return {
      dataFile: join(base, 'kavrix.vault'),
      keyFile: join(base, 'kavrix.key'),
    };
  }
  return {
    dataFile: join(base, `${profileId}.vault`),
    keyFile: join(base, `${profileId}.key`),
  };
}

/**
 * Default recovery-kit path under the secure `~/.kavrix` directory
 * (mirrors classic guided init resolving `./kavrix.recovery` → `~/.kavrix/...`).
 */
export function defaultRecoveryFilePath(
  profileId: string,
  home: string = homedir(),
): string {
  const fileName =
    profileId === 'default' ? 'kavrix.recovery' : `${profileId}.recovery`;
  return join(home, '.kavrix', fileName);
}

/** Exported for presentation / path.sep documentation tests. */
export function pathSeparator(): string {
  return sep;
}

/**
 * Secure default key location for a new mongodb datastore profile.
 * Connection URLs are never written to disk by the TUI.
 */
export function defaultMongoProfilePaths(
  profileId: string,
  home: string = homedir(),
): Readonly<{ keyFile: string }> {
  const base = join(home, '.kavrix');
  return {
    keyFile:
      profileId === 'default'
        ? join(base, 'kavrix.key')
        : join(base, `${profileId}.key`),
  };
}
