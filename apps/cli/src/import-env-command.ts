import type { Command } from 'commander';

import type { ImportEnvCommandOptions } from './import-env-command-impl.js';
import {
  addDatabaseVaultRoutingOptions,
  registerImportArchiveCommand,
} from './vault-transfer-commands.js';

export function registerImportCommands(program: Command): void {
  const imp = program
    .command('import')
    .description('Guarded imports into a database vault.');

  const env = imp
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
    .option('--json', 'Machine-readable output.');
  addDatabaseVaultRoutingOptions(
    env,
    'Opaque vault identifier holding the imported credentials.',
  ).action(async (...args: unknown[]) => {
    const options = args.at(-2) as ImportEnvCommandOptions;
    const impl = await import('./import-env-command-impl.js');
    await impl.handleImportEnv(options);
  });
  registerImportArchiveCommand(imp);
}
