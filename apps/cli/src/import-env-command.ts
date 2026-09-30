import {
  closeSync,
  fstatSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeSync,
} from 'node:fs';

import type { Command } from 'commander';

import {
  type DatabaseFlatCommandOptions,
  rejectUnboundDatabaseProfile,
  usesDatabaseContainer,
  readDatabaseFlatSecrets,
  withDatabaseFlatVault,
} from './database-flat-commands.js';
import { LocalCliError } from './cli-error.js';
import { LocalSecretInput } from './local-secrets.js';

const MAX_ENV_FILE_BYTES = 1024 * 1024;
const MAX_ENV_ENTRIES = 500;
const RESERVED_CREDENTIAL_NAMES = new Set(['__proto__', 'constructor', 'prototype']);

interface ImportEnvCommandOptions {
  readonly file?: string;
  readonly prefix?: string;
  readonly deleteSource?: boolean;
  readonly overwrite?: boolean;
  readonly json?: boolean;
  readonly profile?: string;
  readonly profileConfigDir?: string;
  readonly vault?: string;
  readonly datastore?: string;
  readonly dataFile?: string;
  readonly database?: string;
  readonly collection?: string;
  readonly keyFile?: string;
  readonly databaseUrlStdin?: boolean;
  readonly passphraseStdin?: boolean;
  readonly session?: boolean;
  readonly allowInsecureTransport?: boolean;
}

export interface ParsedEnvEntry {
  readonly key: string;
  readonly value: string;
}

/** Validates one credential name with the same rules as the root put command. */
export function validateImportedName(name: string): void {
  if (RESERVED_CREDENTIAL_NAMES.has(name)) {
    throw new LocalCliError(`Credential name "${name}" is reserved.`);
  }
  if (
    name.length === 0 ||
    name.length > 256 ||
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u001f\u007f]/u.test(name) ||
    /\s/u.test(name) ||
    name.startsWith('/') ||
    name.endsWith('/') ||
    name.includes('//') ||
    name === '.' ||
    name === '..'
  ) {
    throw new LocalCliError(
      `Credential name "${name}" is invalid: names must be 1-256 characters without whitespace or control characters, must not start or end with "/", contain "//", or be a dot segment.`,
    );
  }
}

/**
 * Parses a strict `.env` document: one `KEY=value` per line, optional
 * `export ` prefixes, blank lines and `#` comments ignored. Values are the
 * literal remainder after the first `=` (trailing CR removed) — no quote
 * stripping and no escape processing, so a value is exactly what a loader
 * with the same strict rule would inject. Every failure names its line.
 */
export function parseEnvDocument(content: string): readonly ParsedEnvEntry[] {
  const lines = content.split('\n');
  const entries: ParsedEnvEntry[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const raw = lines[index] ?? '';
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;
    const withoutExport = trimmed.startsWith('export ')
      ? trimmed.slice('export '.length)
      : trimmed;
    const separator = withoutExport.indexOf('=');
    if (separator <= 0) {
      throw new LocalCliError(
        `Line ${String(lineNumber)}: expected KEY=value (missing "=" or empty key).`,
      );
    }
    const key = withoutExport.slice(0, separator).trim();
    // eslint-disable-next-line no-control-regex
    if (/[\s\u0000-\u001f\u007f]/u.test(key)) {
      throw new LocalCliError(
        `Line ${String(lineNumber)}: variable name contains whitespace or control characters.`,
      );
    }
    if (seen.has(key)) {
      throw new LocalCliError(
        `Line ${String(lineNumber)}: duplicate variable "${key}".`,
      );
    }
    seen.add(key);
    const value = withoutExport.slice(separator + 1).replace(/\r$/u, '');
    entries.push({ key, value });
  }
  if (entries.length === 0) {
    throw new LocalCliError('The file contains no KEY=value entries.');
  }
  if (entries.length > MAX_ENV_ENTRIES) {
    throw new LocalCliError(
      `The file contains more than ${String(MAX_ENV_ENTRIES)} variables; import in smaller batches.`,
    );
  }
  return entries;
}

/** Reads a bounded, regular `.env` file from disk. */
export function readEnvFile(path: string): string {
  let raw: Buffer;
  try {
    raw = readFileSync(path);
  } catch {
    throw new LocalCliError(`The .env file could not be read: ${path}`);
  }
  if (raw.byteLength === 0) {
    throw new LocalCliError('The .env file is empty.');
  }
  if (raw.byteLength > MAX_ENV_FILE_BYTES) {
    throw new LocalCliError('The .env file exceeds the supported 1 MiB size bound.');
  }
  return raw.toString('utf8');
}

/**
 * Shreds then unlinks the source file: one random overwrite pass of the
 * full length, flush, truncate, close, unlink. Best effort in JavaScript;
 * callers must treat this as hygiene, not a guarantee.
 */
export function shredAndUnlink(path: string): void {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, 'r+');
    const size = fstatSync(descriptor).size;
    if (size > 0) {
      const noise = new Uint8Array(size);
      for (let offset = 0; offset < noise.length; offset += 65536) {
        const end = Math.min(offset + 65536, noise.length);
        for (let index = offset; index < end; index += 1) {
          noise[index] = Math.floor(Math.random() * 256);
        }
        writeSync(descriptor, noise, offset, end - offset, offset);
      }
    }
    writeSync(descriptor, Buffer.alloc(0), 0, 0, 0);
    closeSync(descriptor);
    descriptor = undefined;
    unlinkSync(path);
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        /* the unlink attempt below is the remaining hygiene step */
      }
    }
    throw error;
  }
}

async function confirmSourceDeletion(path: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  process.stderr.write(`Delete the imported source file ${path}? (y/N) `);
  const input = new LocalSecretInput(process.stdin, process.stderr);
  const [answer] = await input.read(['label'], false);
  return answer?.trim().toLowerCase() === 'y';
}

function flatOptions(options: ImportEnvCommandOptions): DatabaseFlatCommandOptions {
  const vault = options.vault;
  return {
    ...(options.profile === undefined ? {} : { profile: options.profile }),
    ...(options.profileConfigDir === undefined
      ? {}
      : { profileConfigDir: options.profileConfigDir }),
    vault: vault === undefined || vault.length === 0 ? 'default' : vault,
    ...(vault === undefined || vault.length === 0
      ? { vaultWasDefaulted: true as const }
      : {}),
    ...(options.datastore === undefined ? {} : { datastore: options.datastore }),
    ...(options.dataFile === undefined ? {} : { dataFile: options.dataFile }),
    ...(options.database === undefined ? {} : { database: options.database }),
    ...(options.collection === undefined ? {} : { collection: options.collection }),
    ...(options.keyFile === undefined ? {} : { keyFile: options.keyFile }),
    ...(options.session === true ? { session: true } : {}),
    databaseUrlStdin: options.databaseUrlStdin === true,
    passphraseStdin: options.passphraseStdin === true,
    allowInsecureTransport: options.allowInsecureTransport === true,
  };
}

export async function handleImportEnv(options: ImportEnvCommandOptions): Promise<void> {
  const path = options.file;
  if (!path || path.length === 0) {
    throw new LocalCliError('Missing required --file <path>.');
  }
  const prefix = options.prefix ?? '';
  if (prefix.includes('\0') || prefix.includes('\n') || prefix.includes('\r')) {
    throw new LocalCliError('--prefix must not contain control characters.');
  }
  // Parse and validate the whole document before any unlock material is
  // requested: a malformed file fails closed without prompting.
  const entries = parseEnvDocument(readEnvFile(path));
  const names: string[] = [];
  for (const entry of entries) {
    const name = `${prefix}${entry.key}`;
    validateImportedName(name);
    names.push(name);
  }
  const flat = flatOptions(options);
  await rejectUnboundDatabaseProfile(flat, 'import env');
  if (!(await usesDatabaseContainer(flat))) {
    throw new LocalCliError(
      'import env requires a database-container profile; legacy version 2 vaults are not supported.',
    );
  }
  const secrets = await readDatabaseFlatSecrets(flat, []);
  let imported = 0;
  await withDatabaseFlatVault(flat, secrets, async (session, vaultId) => {
    await session.updateVault(vaultId, (payload) => {
      const overwrite = options.overwrite ?? false;
      const conflicts = names.filter(
        (name) => Object.hasOwn(payload.records, name) && !overwrite,
      );
      if (conflicts.length > 0) {
        throw new LocalCliError(
          `Credential already exists: ${String(conflicts[0])}${
            conflicts.length > 1 ? ` (and ${String(conflicts.length - 1)} more)` : ''
          }. Re-run with --overwrite to replace imported values.`,
        );
      }
      for (const entry of entries) {
        payload.records[`${prefix}${entry.key}`] = {
          value: entry.value,
          updatedAt: new Date().toISOString(),
        };
      }
      imported = entries.length;
      return payload;
    });
  });
  let sourceDeleted = false;
  let sourceWarning: string | undefined;
  if (imported > 0) {
    const confirmed =
      (options.deleteSource ?? false) || (await confirmSourceDeletion(path));
    if (confirmed) {
      try {
        shredAndUnlink(path);
        sourceDeleted = true;
      } catch {
        sourceWarning = 'The source file could not be deleted; remove it manually.';
      }
    }
  }
  if (options.json === true) {
    process.stdout.write(
      JSON.stringify({
        imported,
        names,
        sourceDeleted,
        ...(sourceWarning === undefined ? {} : { warning: sourceWarning }),
      }) + '\n',
    );
    return;
  }
  process.stdout.write(
    [
      `Imported ${String(imported)} credential${imported === 1 ? '' : 's'} into the selected vault.`,
      ...names.map((name) => `  ${name}`),
      sourceDeleted
        ? 'Source file shredded and deleted.'
        : (sourceWarning ?? 'Source file left in place; delete it when you are ready.'),
    ].join('\n') + '\n',
  );
}

export function registerImportCommands(program: Command): void {
  const imp = program
    .command('import')
    .description('Guarded imports into a database vault.');

  imp
    .command('env')
    .description(
      'Import a strict .env file (one KEY=value per line) as credentials in the selected database vault. Values are never echoed.',
    )
    .requiredOption('--file <path>', 'The .env file to import.')
    .option(
      '--prefix <prefix>',
      'Name every imported credential under this prefix (for example "prod/").',
    )
    .option(
      '--delete-source',
      'Shred and delete the source file after a fully successful import.',
    )
    .option('--overwrite', 'Replace credentials that already exist.')
    .option('--json', 'Machine-readable output.')
    .option('--profile <id>', 'Bound database profile.')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--vault <id>', 'Opaque vault identifier holding the imported credentials.')
    .option('--datastore <type>', 'Explicit datastore type override.')
    .option('--data-file <path>', 'Local database file override.')
    .option('--database <name>', 'MongoDB database name override.')
    .option('--collection <name>', 'MongoDB vault collection override.')
    .option('--key-file <path>', 'Protected key file path override.')
    .option('--database-url-stdin', 'Read the MongoDB URI from standard input.')
    .option('--passphrase-stdin', 'Read the key-file passphrase from standard input.')
    .option(
      '--session',
      'Unlock with the stored OS session (keychain-gated) instead of the passphrase.',
    )
    .option(
      '--allow-insecure-transport',
      'Explicitly permit unencrypted transport to a non-local MongoDB (isolated networks only).',
    )
    .action(async (...args: unknown[]) => {
      const options = args.at(-2) as ImportEnvCommandOptions;
      await handleImportEnv(options);
    });
}
