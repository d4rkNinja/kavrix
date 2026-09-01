/**
 * Declarative Kavrix configuration file.
 *
 * `kavrix init` now generates `~/.kavrix/config.toml` (or the platform's
 * secure Kavrix directory) instead of running the interactive wizard.
 * The file is an onboarding reference with non-secret command examples.
 * Commands do not load it automatically, and secrets (passphrases, database
 * URLs) are never stored here.
 */

import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { ensureSecureDirectory, validateSecureFileSource } from '@kavrix/key-files';

const CONFIG_FILE_NAME = 'config.toml';
const MAX_CONFIG_FILE_BYTES = 64 * 1024;

/**
 * Returns the directory that holds Kavrix's protected user data.
 * Mirrors the secure-directory logic used for key files.
 */
export function getKavrixConfigDir(): string {
  return join(homedir(), '.kavrix');
}

export function getKavrixConfigPath(): string {
  return join(getKavrixConfigDir(), CONFIG_FILE_NAME);
}

/**
 * Generates a fully-commented TOML onboarding reference. It deliberately has
 * no active settings because the current CLI does not automatically load this
 * file. Datastore profiles and their optional default vaults live in a
 * separate protected registry.
 */
export function generateDefaultConfigToml(): string {
  return `# Kavrix Onboarding Reference
# ===========================
# Location: ~/.kavrix/config.toml
#   Windows: %USERPROFILE%\\.kavrix\\config.toml
#   macOS/Linux: ~/.kavrix/config.toml
#
# This file is created by a first interactive \`kavrix init\`. It is a
# non-secret onboarding reference, not an automatically loaded settings file.
# Copy the examples you need into your terminal and keep profile selection
# explicit. All protected paths must be inside a private directory.
#
# Secrets are NEVER stored here. Passphrases and MongoDB URLs are always
# read via masked prompts or --passphrase-stdin / --database-url-stdin.
#
# See https://github.com/d4rkNinja/kavrix#readme for full documentation.

# Canonical file-datastore setup:
#   kavrix db profile add work --datastore file \\
#     --data-file ./work.kavrix --key-file ./work.kavrix.key
#   kavrix db profile use work
#   kavrix db init --profile work
#   kavrix db vault create --profile work
#   kavrix db vault use <vault-id> --profile work
#
# MongoDB is optional. Register its non-secret database and collection routing
# with \`kavrix db profile add --datastore mongodb\`; provide the URI only via
# the masked prompt or --database-url-stdin. Remote connections require
# validated TLS, and database-container writes require transaction support.
#
# After \`db vault use\`, vault-scoped commands use that profile's stored default:
#   kavrix put github/token --profile work
#   kavrix list --profile work
#   kavrix get github/token --reveal --profile work
# Pass \`--vault <vault-id>\` to override the stored default for one command.
#
# Legacy version 2 single-vault initialization remains available only when
# explicit legacy init routing options are supplied. See \`kavrix init --help\`.
`;
}

export async function ensureKavrixConfig(): Promise<string> {
  const dir = getKavrixConfigDir();
  const path = getKavrixConfigPath();

  await ensureSecureDirectory(dir);
  if (existsSync(path)) {
    await validateSecureFileSource(path, MAX_CONFIG_FILE_BYTES);
    return path;
  }

  if (!existsSync(path)) {
    const content = generateDefaultConfigToml();
    await writeFile(path, content, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    }).catch((error: unknown) => {
      if (
        error !== null &&
        typeof error === 'object' &&
        'code' in error &&
        (error as { code: string }).code === 'EEXIST'
      ) {
        return;
      }
      throw error;
    });

    // The file inherits the strict user-only boundary established by
    // ensureSecureDirectory and is created with mode 0600 on POSIX.
  }

  await validateSecureFileSource(path, MAX_CONFIG_FILE_BYTES);

  return path;
}

export function getConfigPathForDisplay(): string {
  const p = getKavrixConfigPath();
  if (process.platform === 'win32') return p;
  const home = homedir();
  if (p.startsWith(home)) return `~${p.slice(home.length)}`;
  return p;
}
