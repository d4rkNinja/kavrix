import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

import { CliUsageError } from '../errors.js';

const APPLICATION_DIRECTORY = 'kavrix';

/**
 * Every durable artifact the CLI owns, resolved once per process. Vault stores
 * are per-vault so enrolling a second vault cannot widen the blast radius of a
 * corrupt database file.
 */
export interface CliDataPaths {
  readonly home: string;
  readonly profileStore: string;
  readonly initializationJournal: string;
  readonly joinJournal: string;
  readonly sealedSecrets: string;
  vaultStore(vaultId: string): string;
}

/**
 * `CREDS_HOME` wins so a caller can pin state to a project directory or a
 * removable volume; otherwise each platform's own convention applies. No
 * fallback silently lands in the process working directory.
 */
export function resolveCliDataPaths(
  environment: Readonly<Record<string, string | undefined>> = process.env,
  platform: NodeJS.Platform = process.platform,
): CliDataPaths {
  const home = resolveHome(environment, platform);
  return {
    home,
    profileStore: join(home, 'profiles.db'),
    initializationJournal: join(home, 'init-journal.db'),
    joinJournal: join(home, 'join-journal.db'),
    sealedSecrets: join(home, 'sealed'),
    vaultStore: (vaultId: string) =>
      join(home, `vault-${requireSafeSegment(vaultId)}.db`),
  };
}

function resolveHome(
  environment: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
): string {
  const override = readNonEmpty(environment, 'CREDS_HOME');
  if (override !== undefined) return requireAbsolute(override, 'CREDS_HOME');
  if (platform === 'win32') {
    const appData = readNonEmpty(environment, 'APPDATA');
    if (appData !== undefined) {
      return join(requireAbsolute(appData, 'APPDATA'), APPLICATION_DIRECTORY);
    }
    return join(requireUserHome(), 'AppData', 'Roaming', APPLICATION_DIRECTORY);
  }
  if (platform === 'darwin') {
    return join(
      requireUserHome(),
      'Library',
      'Application Support',
      APPLICATION_DIRECTORY,
    );
  }
  const dataHome = readNonEmpty(environment, 'XDG_DATA_HOME');
  if (dataHome !== undefined) {
    return join(requireAbsolute(dataHome, 'XDG_DATA_HOME'), APPLICATION_DIRECTORY);
  }
  return join(requireUserHome(), '.local', 'share', APPLICATION_DIRECTORY);
}

function readNonEmpty(
  environment: Readonly<Record<string, string | undefined>>,
  key: string,
): string | undefined {
  const value = environment[key];
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

function requireUserHome(): string {
  const home = homedir();
  if (typeof home !== 'string' || home.trim().length === 0 || !isAbsolute(home)) {
    throw new CliUsageError(
      'The user home directory could not be resolved. Set CREDS_HOME to an absolute path.',
    );
  }
  return resolve(home);
}

function requireAbsolute(value: string, label: string): string {
  if (!isAbsolute(value)) {
    throw new CliUsageError(`${label} must be an absolute path.`);
  }
  return resolve(value);
}

/**
 * Vault identifiers already come from a validated opaque-ID schema, but the
 * value reaches a file name here, so the traversal-safe subset is re-checked at
 * the boundary rather than trusted transitively.
 */
function requireSafeSegment(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/u.test(value)) {
    throw new CliUsageError('The vault identifier is not a valid storage name.');
  }
  return value;
}
