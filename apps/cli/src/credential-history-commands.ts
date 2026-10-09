/**
 * Light registration for the `credential history` command family.
 *
 * `credential` is the shared alias of the structured `item` command object, so
 * the history group is attached to that existing command instead of registering
 * a second top-level route. One command object means `item history` and
 * `credential history` cannot drift, and no duplicate public route appears in
 * `--help` output. This module only builds Commander shapes (names, option
 * flags, defaults, descriptions); every action dynamically imports its runtime
 * implementation from `./credential-history-impl.js` at invocation time so CLI
 * startup stays cheap.
 */
import type { Command } from 'commander';

/** Option flags shared by every database-routed structured command. */
function addDatabaseOptions(command: Command): Command {
  return command
    .option('--vault <id>', 'Opaque database vault identifier.', 'default')
    .option('--profile <id>', 'Database profile identifier.')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--config-dir <path>', 'Protected profile configuration directory.')
    .option('--datastore <type>', 'Datastore routing override.')
    .option('--data-file <path>', 'Encrypted file datastore path.')
    .option('--database <name>', 'MongoDB database name.')
    .option('--collection <name>', 'MongoDB vault collection name.')
    .option('--key-file <path>', 'Protected portable key-file path.')
    .option('--database-url-stdin', 'Read the MongoDB URL from protected stdin.')
    .option('--passphrase-stdin', 'Read the key-file passphrase from protected stdin.')
    .option(
      '--allow-insecure-transport',
      'Allow explicitly requested insecure MongoDB transport.',
    );
}

/**
 * Add the credential history command group to a Commander program.
 *
 * The structured item command (`item`, alias `credential`) must already be
 * registered; the family deliberately fails closed at startup rather than
 * silently registering a route that could never resolve.
 */
export function registerCredentialHistoryCommands(program: Command): void {
  const item = program.commands.find(
    (command) => command.name() === 'item' || command.aliases().includes('credential'),
  );
  if (item === undefined) {
    throw new Error(
      'registerCredentialHistoryCommands must run after ' +
        'registerStructuredVaultCommands: the credential history group attaches ' +
        'to the shared item/credential command.',
    );
  }
  const history = item
    .command('history')
    .description(
      'List non-sensitive metadata for prior encrypted versions of a credential item.',
    );
  addDatabaseOptions(
    history
      .command('list <title>')
      .description('List history versions with revision and timestamp only.'),
  )
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option(
      '--limit <count>',
      'Maximum versions to report (default 50, maximum 500).',
      '50',
    )
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./credential-history-impl.js');
      await impl.credentialHistoryList(
        ...(args as [string, Record<string, unknown>, Command]),
      );
    });
  addDatabaseOptions(
    history
      .command('show <title> <version>')
      .description(
        'Show metadata for one history version; snapshot values are never printed.',
      ),
  )
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./credential-history-impl.js');
      await impl.credentialHistoryShow(
        ...(args as [string, string, Record<string, unknown>, Command]),
      );
    });
}
