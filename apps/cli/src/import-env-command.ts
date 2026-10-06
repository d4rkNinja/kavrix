import type { Command } from 'commander';

import type { ImportEnvCommandOptions } from './import-env-command-impl.js';

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
      const impl = await import('./import-env-command-impl.js');
      await impl.handleImportEnv(options);
    });
}
