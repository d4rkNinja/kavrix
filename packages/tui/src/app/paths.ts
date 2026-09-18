import { homedir } from 'node:os';
import { join, sep } from 'node:path';

/**
 * Windows-safe default locations for a new file-datastore profile.
 * Always uses `node:path.join` so `path.sep` is correct on win32.
 */
export function defaultFileProfilePaths(
  profileId: string,
  home: string = homedir(),
): Readonly<{ dataFile: string; keyFile: string }> {
  const base = join(home, '.local', 'share', 'kavrix', profileId);
  return {
    dataFile: join(base, 'db.kavrix'),
    keyFile: join(base, 'owner.key'),
  };
}

/** Exported for presentation / path.sep documentation tests. */
export function pathSeparator(): string {
  return sep;
}

/**
 * Windows-safe default key location for a new mongodb datastore profile.
 * Connection URLs are never written to disk by the TUI.
 */
export function defaultMongoProfilePaths(
  profileId: string,
  home: string = homedir(),
): Readonly<{ keyFile: string }> {
  const base = join(home, '.local', 'share', 'kavrix', profileId);
  return {
    keyFile: join(base, 'owner.key'),
  };
}

