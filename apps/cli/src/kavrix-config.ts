/**
 * Declarative Kavrix configuration file.
 *
 * `kavrix init` now generates `~/.kavrix/config.toml` (or the platform's
 * secure Kavrix directory) instead of running the interactive wizard.
 * The file contains every non-secret init option with proper comments and
 * examples. Secrets (passphrases, database URLs) are never stored here.
 */

import { existsSync } from 'node:fs';
import { readFile, stat, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { z } from 'zod';

import { ensureSecureDirectory } from '@kavrix/key-files';

const CONFIG_FILE_NAME = 'config.toml';

const kavrixConfigSchema = z
  .object({
    datastore: z.enum(['file', 'mongodb']).optional(),
    dataFile: z.string().optional(),
    keyFile: z.string().optional(),
    database: z.string().optional(),
    collection: z.string().optional(),
    databaseCollection: z.string().optional(),
    vaultCollection: z.string().optional(),
    vaultLabel: z.string().optional(),
  })
  .strict();

export type KavrixConfig = z.infer<typeof kavrixConfigSchema>;

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
 * Generates a fully-commented TOML template with every init option,
 * proper descriptions, and working examples. The output is valid TOML
 * and can be parsed with `smol-toml`.
 */
export function generateDefaultConfigToml(): string {
  return `# Kavrix Configuration
# =====================
# Location: ~/.kavrix/config.toml
#   Windows: %USERPROFILE%\\.kavrix\\config.toml
#   macOS/Linux: ~/.kavrix/config.toml
#
# This file is created by \`kavrix init\`. Edit the values below, then run
# \`kavrix init\` again (or \`kavrix db init\` with --secrets-stdin) to
# initialize your encrypted vault. All paths must be inside a private
# directory that only your account can access.
#
# Secrets are NEVER stored here. Passphrases and MongoDB URLs are always
# read via masked prompts or --passphrase-stdin / --database-url-stdin.
#
# Uncomment a line to activate it. Lines starting with # are ignored.
# See https://github.com/d4rkNinja/kavrix#readme for full documentation.

# === Datastore ===
# Choose where ciphertext lives. "file" is simplest for one device;
# "mongodb" syncs opaque ciphertext through your own MongoDB deployment.
# Allowed values: "file", "mongodb"
# Example: datastore = "file"
datastore = "file"

# === Local File Datastore ===
# Only used when datastore = "file"
# Path to the encrypted vault file. Can be absolute or relative.
# The parent directory must be private (chmod 700 / icacls).
# Examples:
#   dataFile = "./kavrix.vault"
#   dataFile = "~/.kavrix/kavrix.vault"
#   dataFile = "/secure/vaults/work.vault"
dataFile = "./kavrix.vault"

# === Security ===
# Path to the protected portable key file. This file holds your
# encrypted vault key and is essential — losing it can make the vault
# permanently unrecoverable. Keep it separate from the vault file.
# On Windows, ACLs are enforced via icacls /inheritance:r.
# Examples:
#   keyFile = "./kavrix.key"
#   keyFile = "~/.kavrix/kavrix.key"
keyFile = "./kavrix.key"

# Optional: path to the database revision anchor file.
# Defaults to "<keyFile>.database-anchor" if not set.
# Example: anchorFile = "./kavrix.key.database-anchor"
# anchorFile = "./kavrix.key.database-anchor"

# === MongoDB Datastore ===
# Only used when datastore = "mongodb"
# Your MongoDB connection string is NEVER stored here.
# It is read via --database-url-stdin (masked, never in argv).
#
# Database name (1-63 chars: letters, numbers, underscore, hyphen)
# If omitted, it is inferred from the connection string.
# Example: database = "kavrix"
# database = "kavrix"

# Collection for encrypted database documents (1-64 chars)
# Default: "kavrix_databases" for databaseCollection, "kavrix_vaults" for vaultCollection
# Example: collection = "kavrix_vaults"
# collection = "kavrix_vaults"
# databaseCollection = "kavrix_databases"
# vaultCollection = "kavrix_vaults"

# === Vault ===
# Initial vault label for \`kavrix init\` (human-readable, not the ID).
# Allowed: 1-64 chars, no control characters.
# Example: vaultLabel = "personal"
# vaultLabel = "personal"

# === Profiles (optional) ===
# Datastore profiles let you manage multiple vaults/databases.
# They are stored separately in ~/.kavrix/profiles/ and managed via
# \`kavrix db profile add/list/use\`. You do not need to edit them here.
# Example:
#   [profile]
#   id = "work"
#   configDir = "~/.kavrix/profiles"

# === Advanced ===
# Allow unencrypted transport to a non-local MongoDB (isolated networks only).
# Default: false (TLS required for remote hosts)
# allowInsecureTransport = false

# End of Kavrix config.toml
# After editing, run:
#   kavrix init --secrets-stdin   # then enter label, passphrase x2 when prompted
# Or for MongoDB:
#   kavrix init --datastore mongodb --secrets-stdin
# See \`kavrix init --help\` and \`kavrix frames init\` for stdin frame contracts.
`;
}

export async function ensureKavrixConfig(): Promise<string> {
  const dir = getKavrixConfigDir();
  const path = getKavrixConfigPath();

  if (existsSync(path)) {
    const st = await stat(path).catch(() => null);
    if (st?.isFile()) return path;
  }

  await ensureSecureDirectory(dir);

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

    if (process.platform !== 'win32') {
      try {
        const { chmod } = await import('node:fs/promises');
        await chmod(path, 0o600);
      } catch {
        // best effort; file was already created with 0o600 when possible
      }
    }
    // On Windows the file inherits the ACL of the secure directory
    // created via ensureSecureDirectory, which already enforces user-only
    // access. No additional per-file ACL is required.
  }

  return path;
}

export async function loadKavrixConfig(): Promise<KavrixConfig | null> {
  const path = getKavrixConfigPath();
  if (!existsSync(path)) return null;

  const raw = await readFile(path, 'utf8');
  // Lazy import so the CLI can run without the TOML parser for other commands.
  const { parse } = (await import('smol-toml')) as unknown as {
    parse: (text: string) => unknown;
  };

  let parsed: unknown;
  try {
    parsed = parse(raw);
  } catch (error) {
    throw new Error(
      `Kavrix config.toml is not valid TOML at ${path}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }

  // Flatten possible nested tables (e.g., [datastore] type = "file") into
  // top-level keys for backwards compatibility with the flat schema.
  const flattened = flattenConfig(parsed);

  const result = kavrixConfigSchema.safeParse(flattened);
  if (!result.success) {
    throw new Error(
      `Kavrix config.toml at ${path} is invalid: ${result.error.message}`,
    );
  }

  return result.data;
}

function flattenConfig(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }

  const record = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};

  for (const [key, val] of Object.entries(record)) {
    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      const nested = val as Record<string, unknown>;
      const isTable =
        Object.keys(nested).length > 0 &&
        Object.values(nested).every(
          (v) =>
            typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean',
        );
      if (isTable) {
        for (const [k, v] of Object.entries(nested)) {
          if (!(k in out)) out[k] = v;
        }
        continue;
      }
    }
    if (!(key in out)) out[key] = val;
  }

  return out;
}

export function getConfigPathForDisplay(): string {
  const p = getKavrixConfigPath();
  if (process.platform === 'win32') return p;
  const home = homedir();
  if (p.startsWith(home)) return `~${p.slice(home.length)}`;
  return p;
}
