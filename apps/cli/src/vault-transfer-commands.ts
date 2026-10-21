import type { Command } from 'commander';

import type { GenerateCommandOptions } from './generate-command-impl.js';
import type {
  ImportArchiveCommandOptions,
  VaultExportCommandOptions,
} from './vault-export-impl.js';

/**
 * Adds the database-vault routing and unlock options shared by `import env`,
 * `import archive`, `export`, and `generate`. Option text and order are part
 * of the public help surface.
 */
export function addDatabaseVaultRoutingOptions(
  command: Command,
  vaultDescription: string,
): Command {
  return command
    .option('--profile <id>', 'Bound database profile.')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--vault <id>', vaultDescription)
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
    );
}

export function registerExportCommand(program: Command): void {
  const exportCommand = program
    .command('export')
    .description(
      'Seal the credentials of the selected database vault into a passphrase-protected export archive. Values are never printed.',
    )
    .requiredOption('--file <path>', 'Export archive destination path.')
    .option(
      '--prefix <prefix>',
      'Export only credentials whose name starts with this prefix.',
    )
    .option('--overwrite', 'Replace an existing archive file.')
    .option('--json', 'Machine-readable output.');
  addDatabaseVaultRoutingOptions(
    exportCommand,
    'Opaque vault identifier holding the exported credentials.',
  ).action(async (...args: unknown[]) => {
    const options = args.at(-2) as VaultExportCommandOptions;
    const impl = await import('./vault-export-impl.js');
    await impl.handleVaultExport(options);
  });
}

export function registerImportArchiveCommand(imp: Command): void {
  const archive = imp
    .command('archive')
    .description(
      'Authenticate a Kavrix export archive and import its credentials into the selected database vault. Values are never echoed.',
    )
    .requiredOption('--file <path>', 'The export archive to import.')
    .option(
      '--prefix <prefix>',
      'Name every imported credential under this prefix (for example "staging/").',
    )
    .option('--overwrite', 'Replace credentials that already exist.')
    .option('--json', 'Machine-readable output.');
  addDatabaseVaultRoutingOptions(
    archive,
    'Opaque vault identifier holding the imported credentials.',
  ).action(async (...args: unknown[]) => {
    const options = args.at(-2) as ImportArchiveCommandOptions;
    const impl = await import('./vault-export-impl.js');
    await impl.handleImportArchive(options);
  });
}

export function registerGenerateCommand(program: Command): void {
  const generate = program
    .command('generate [name]')
    .description(
      'Generate a random secret locally. With a name, store it in the selected database vault without displaying it; without a name, --reveal prints it.',
    )
    .option('--length <count>', 'Number of characters (8-1024).', '32')
    .option('--format <format>', 'Alphabet: password, hex, or base64url.', 'password')
    .option('--no-lowercase', 'Password format: omit lowercase letters.')
    .option('--no-uppercase', 'Password format: omit uppercase letters.')
    .option('--no-digits', 'Password format: omit digits.')
    .option('--no-symbols', 'Password format: omit symbols.')
    .option(
      '--exclude-ambiguous',
      'Password format: omit look-alike characters (I l 1 O 0 o |).',
    )
    .option('--reveal', 'Print the generated value to stdout instead of storing it.')
    .option('--overwrite', 'Replace an existing credential with the generated value.')
    .option('--json', 'Machine-readable output.');
  addDatabaseVaultRoutingOptions(
    generate,
    'Opaque vault identifier that receives the generated credential.',
  ).action(async (...args: unknown[]) => {
    const name = typeof args[0] === 'string' ? args[0] : undefined;
    const options = args.at(-2) as GenerateCommandOptions;
    const impl = await import('./generate-command-impl.js');
    await impl.handleGenerate(name, options);
  });
}
