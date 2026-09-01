import type { Command } from 'commander';

import type { DatabaseFlatCommandOptions } from '../database-flat-commands.js';

/** Options shape consumed by the execution-layer command handlers. */
export type ExecutionCommandOptions = DatabaseFlatCommandOptions;

/**
 * Merges options across the full command hierarchy, preferring explicitly set
 * values over inherited defaults â€” the same contract the core CLI applies.
 */
export function extractMergedOptions(
  command: Command,
): Readonly<Record<string, unknown>> {
  const hierarchy: Command[] = [];
  let current: Command | null = command;
  while (current !== null) {
    hierarchy.unshift(current);
    current = current.parent;
  }
  const merged: Record<string, unknown> = {};
  for (const entry of hierarchy) {
    for (const [key, value] of Object.entries(entry.opts())) {
      const source = entry.getOptionValueSource(key);
      if (source !== 'default' || !Object.hasOwn(merged, key)) {
        merged[key] = value;
      }
    }
  }
  const vaultWasExplicit = hierarchy.some((entry) => {
    const source = entry.getOptionValueSource('vault');
    return source !== undefined && source !== 'default';
  });
  if (!vaultWasExplicit) merged['vaultWasDefaulted'] = true;
  return merged;
}

export function executionFlatOptions(
  merged: Readonly<Record<string, unknown>>,
): ExecutionCommandOptions {
  const vault = merged['vault'];
  return {
    ...(typeof merged['profile'] === 'string' ? { profile: merged['profile'] } : {}),
    ...(typeof merged['profileConfigDir'] === 'string'
      ? { profileConfigDir: merged['profileConfigDir'] }
      : {}),
    vault: typeof vault === 'string' && vault.length > 0 ? vault : 'default',
    ...(merged['vaultWasDefaulted'] === true ? { vaultWasDefaulted: true } : {}),
    ...(typeof merged['datastore'] === 'string'
      ? { datastore: merged['datastore'] }
      : {}),
    ...(typeof merged['dataFile'] === 'string' ? { dataFile: merged['dataFile'] } : {}),
    ...(typeof merged['database'] === 'string' ? { database: merged['database'] } : {}),
    ...(typeof merged['collection'] === 'string'
      ? { collection: merged['collection'] }
      : {}),
    ...(typeof merged['keyFile'] === 'string' ? { keyFile: merged['keyFile'] } : {}),
    databaseUrlStdin: merged['databaseUrlStdin'] === true,
    passphraseStdin: merged['passphraseStdin'] === true,
    allowInsecureTransport: merged['allowInsecureTransport'] === true,
  };
}

/** Adds the standard non-secret routing options shared by credential commands. */
export function addExecutionRoutingOptions(command: Command): Command {
  return command
    .option('--profile <id>', 'Bound database profile.')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--datastore <type>', 'Explicit datastore type override.')
    .option('--data-file <path>', 'Local database file override.')
    .option('--database <name>', 'MongoDB database name override.')
    .option('--collection <name>', 'MongoDB vault collection override.')
    .option('--key-file <path>', 'Protected key file path override.')
    .option('--database-url-stdin', 'Read the MongoDB URI from standard input.')
    .option('--passphrase-stdin', 'Read the key passphrase from standard input.')
    .option(
      '--allow-insecure-transport',
      'Explicitly permit unencrypted transport to a non-local MongoDB (isolated networks only).',
    )
    .option(
      '--vault <id>',
      'Opaque vault identifier holding the credentials.',
      'default',
    );
}
