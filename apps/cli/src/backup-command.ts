import type { Command } from 'commander';
import type { FirewallRestoreOptions } from './firewall-recovery.js';
import { addExecutionRoutingOptions } from './execution/cli-options.js';

import type { BackupCommandOptions } from './backup-command-impl.js';

const BACKUP_HELP = 'Passphrase-sealed backup of one local-file database container.';

export function registerBackupCommands(program: Command): void {
  const backup = program.command('backup').description(BACKUP_HELP);
  const firewall = backup
    .command('restore-firewall')
    .description(
      'Restore policies and audit from a firewall backup after owner authentication; discard all archived grants.',
    )
    .requiredOption('--file <path>', 'Firewall backup archive.')
    .option(
      '--overwrite',
      'Explicitly replace existing policies and discard active grants.',
    )
    .option('--json', 'Emit machine-readable output.');
  addExecutionRoutingOptions(firewall);
  firewall.action(async (...args: unknown[]) => {
    const options = args.at(-2) as FirewallRestoreOptions;
    const { restoreFirewallState } = await import('./firewall-recovery.js');
    process.stdout.write(JSON.stringify(await restoreFirewallState(options)) + '\n');
  });

  backup
    .command('create')
    .option(
      '--include-firewall',
      'Include the encrypted policies/grants/audit sidecar; recovery discards grants.',
    )
    .description(
      'Seal the local database file of the selected profile into a passphrase-protected backup archive.',
    )
    .requiredOption('--file <path>', 'Backup archive destination path.')
    .option('--profile <id>', 'Bound database profile.')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--config-dir <path>', 'Protected profile configuration directory.')
    .option(
      '--passphrase-stdin',
      'Read the new backup passphrase (twice) from stdin frames.',
    )
    .option('--overwrite', 'Replace an existing archive file.')
    .option('--json', 'Machine-readable output.')
    .action(async (...args: unknown[]) => {
      const options = args.at(-2) as BackupCommandOptions;
      const impl = await import('./backup-command-impl.js');
      await impl.handleBackupCreate(options);
    });

  backup
    .command('verify')
    .description(
      'Authenticate one backup archive and report its metadata without writing the database file.',
    )
    .requiredOption('--file <path>', 'Backup archive path.')
    .option('--passphrase-stdin', 'Read the backup passphrase from stdin.')
    .option('--json', 'Machine-readable output.')
    .action(async (...args: unknown[]) => {
      const options = args.at(-2) as BackupCommandOptions;
      const impl = await import('./backup-command-impl.js');
      await impl.handleBackupVerify(options);
    });

  backup
    .command('restore')
    .description(
      'Authenticate one backup archive and write its database file to a new destination path.',
    )
    .requiredOption('--file <path>', 'Backup archive path.')
    .requiredOption('--data-file <path>', 'Restored database file destination.')
    .option('--passphrase-stdin', 'Read the backup passphrase from stdin.')
    .option('--overwrite', 'Replace an existing destination file.')
    .option('--json', 'Machine-readable output.')
    .action(async (...args: unknown[]) => {
      const options = args.at(-2) as BackupCommandOptions;
      const impl = await import('./backup-command-impl.js');
      await impl.handleBackupRestore(options);
    });
}
