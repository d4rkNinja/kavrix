import { readFileSync } from 'node:fs';

/**
 * Resolves the CLI's own package manifest.
 *
 * The bundle evaluates this module from the dynamic main chunk under
 * `dist/chunks/`, while direct source consumers (tests, tsx) evaluate it from
 * `src/`. One directory level up covers the entry artifact and source layout;
 * two levels cover the split-chunk layout. Both resolve to the same
 * `apps/cli/package.json` in the repository and to the published package
 * manifest under `dist/`, so the manifest content is identical in every case.
 *
 * This fails closed: if neither relative location holds a parseable manifest
 * with a version string, startup aborts instead of reporting a wrong version.
 */
function readOwnManifestVersion(): string {
  for (const levelsUp of ['../package.json', '../../package.json']) {
    try {
      const manifest = JSON.parse(
        readFileSync(new URL(levelsUp, import.meta.url), 'utf8'),
      ) as { readonly version?: unknown };
      if (typeof manifest.version === 'string' && manifest.version.length > 0) {
        return manifest.version;
      }
    } catch {
      // Try the next relative location; a missing or unreadable manifest in
      // one bundled layout is expected, not an error to report.
    }
  }
  throw new Error(
    'The Kavrix installation is incomplete: the CLI package manifest (package.json) could not be located next to the executable.',
  );
}

export const CLI_VERSION = readOwnManifestVersion();
