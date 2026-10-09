/**
 * Light registration for the structured vault command families (`context`,
 * alias `environment`; `service`, alias `group`; `item`, alias `credential`;
 * `field`; and `note`). This module only builds Commander shapes (names,
 * aliases, option flags, defaults, descriptions) so CLI startup stays cheap;
 * every action dynamically imports its runtime implementation from
 * `./structured-vault-impl.js` at invocation time.
 */
import type { Command } from 'commander';

/**
 * Add the structured command family to a Commander program. The command
 * aliases deliberately share one command object, so `service`/`group`,
 * `item`/`credential`, and `context`/`environment` cannot drift.
 */
export function registerStructuredVaultCommands(program: Command): void {
  registerContextCommands(program);
  registerServiceCommands(program);
  registerItemCommands(program);
  registerFieldCommands(program);
  registerNoteCommands(program);
}

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

function registerContextCommands(program: Command): void {
  const context = program
    .command('context')
    .alias('environment')
    .description('Manage project contexts/environments in a database vault.');
  const create = context
    .command('create <name>')
    .description('Create a project context.');
  addDatabaseOptions(create)
    .option('--environment <name>', 'Optional deployment environment label.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.contextCreate(...(args as [string, Record<string, unknown>, Command]));
    });
  const list = context.command('list').description('List project contexts.');
  addDatabaseOptions(list)
    .option('--tree', 'Include bounded service and item metadata in one snapshot.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.contextList(...(args as [Record<string, unknown>, Command]));
    });
  const rename = context
    .command('rename <from> <to>')
    .description('Rename a project context.');
  addDatabaseOptions(rename)
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.contextRename(
        ...(args as [string, string, Record<string, unknown>, Command]),
      );
    });
  const remove = context
    .command('remove <name>')
    .description('Remove an empty project context.');
  addDatabaseOptions(remove)
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.contextRemove(...(args as [string, Record<string, unknown>, Command]));
    });
}

function registerServiceCommands(program: Command): void {
  const service = program
    .command('service')
    .alias('group')
    .description('Manage services/groups inside a project context.');
  const create = service
    .command('create <name>')
    .description('Create a service/group.');
  addDatabaseOptions(create)
    .requiredOption('--context <name>', 'Project context name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.serviceCreate(...(args as [string, Record<string, unknown>, Command]));
    });
  const list = service
    .command('list')
    .description('List services/groups in a project context.');
  addDatabaseOptions(list)
    .requiredOption('--context <name>', 'Project context name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.serviceList(...(args as [Record<string, unknown>, Command]));
    });
  const rename = service
    .command('rename <from> <to>')
    .description('Rename a service/group.');
  addDatabaseOptions(rename)
    .requiredOption('--context <name>', 'Project context name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.serviceRename(
        ...(args as [string, string, Record<string, unknown>, Command]),
      );
    });
  const remove = service
    .command('remove <name>')
    .description('Remove an empty service/group.');
  addDatabaseOptions(remove)
    .requiredOption('--context <name>', 'Project context name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.serviceRemove(...(args as [string, Record<string, unknown>, Command]));
    });
}

function registerItemCommands(program: Command): void {
  const item = program
    .command('item')
    .alias('credential')
    .description('Manage credential items inside a service/group.');
  const create = item
    .command('create <title>')
    .description('Create a credential item.');
  addDatabaseOptions(create)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.itemCreate(...(args as [string, Record<string, unknown>, Command]));
    });
  const list = item
    .command('list')
    .description('List credential items in a service/group.');
  addDatabaseOptions(list)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.itemList(...(args as [Record<string, unknown>, Command]));
    });
  const show = item
    .command('show <title>')
    .description('Show item metadata and redacted field states.');
  addDatabaseOptions(show)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.itemShow(...(args as [string, Record<string, unknown>, Command]));
    });
  const rename = item
    .command('rename <from> <to>')
    .description('Rename a credential item.');
  addDatabaseOptions(rename)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.itemRename(
        ...(args as [string, string, Record<string, unknown>, Command]),
      );
    });
  const remove = item
    .command('remove <title>')
    .description('Remove an item and its owned encrypted records.');
  addDatabaseOptions(remove)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.itemRemove(...(args as [string, Record<string, unknown>, Command]));
    });
}

function registerFieldCommands(program: Command): void {
  const field = program
    .command('field')
    .description('Manage schema-driven typed item fields.');
  const base = (command: Command): Command =>
    addDatabaseOptions(command)
      .requiredOption('--context <name>', 'Project context name.')
      .requiredOption('--service <name>', 'Service/group name.')
      .requiredOption('--item <title>', 'Credential item title.');
  const set = field
    .command('set <name>')
    .description('Set a typed field value from protected input.');
  base(set)
    .option('--value-stdin', 'Read a field value from protected stdin.')
    .option(
      '--value-stdin-base64',
      'Read one base64-encoded field value frame from protected stdin.',
    )
    .requiredOption('--type <type>', 'Canonical field type or supported alias.')
    .option('--sensitive', 'Mark an otherwise public field as sensitive.')
    .option('--public', 'Explicitly make an environment-map field non-sensitive.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.fieldSet(...(args as [string, Record<string, unknown>, Command]));
    });
  const list = field
    .command('list')
    .description('List item fields and their schema policies without values.');
  base(list)
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.fieldList(...(args as [Record<string, unknown>, Command]));
    });
  const get = field
    .command('get <name>')
    .description(
      'Read one field; sensitive values are redacted unless explicitly authorized.',
    );
  base(get)
    .option('--reveal', 'Request an authorized plaintext field value.')
    .option(
      '--reveal-base64',
      'Request an authorized exact base64 field value for multiline-safe transport.',
    )
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.fieldGet(...(args as [string, Record<string, unknown>, Command]));
    });
  const remove = field
    .command('remove <name>')
    .description('Archive one active field definition and value.');
  base(remove)
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.fieldRemove(...(args as [string, Record<string, unknown>, Command]));
    });
}

function registerNoteCommands(program: Command): void {
  const note = program
    .command('note')
    .description('Manage encrypted notes attached to credential items.');
  const base = (command: Command): Command =>
    addDatabaseOptions(command)
      .requiredOption('--context <name>', 'Project context name.')
      .requiredOption('--service <name>', 'Service/group name.');
  const list = note
    .command('list <item>')
    .description('List the notes on one item, without their content.');
  base(list)
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.noteList(...(args as [string, Record<string, unknown>, Command]));
    });
  const add = note
    .command('add <item> <title>')
    .description('Add one note from protected input.');
  base(add)
    .option('--content-stdin', 'Read the note content from protected stdin.')
    .option(
      '--content-stdin-base64',
      'Read one base64-encoded note-content frame from protected stdin.',
    )
    .option('--sensitive', 'Mask the note content by default and gate every reveal.')
    .option('--pin', 'Pin the note to the top of the item listing.')
    .option('--no-pin', 'Store the note unpinned (the default).')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.noteAdd(
        ...(args as [string, string, Record<string, unknown>, Command]),
      );
    });
  const show = note
    .command('show <item> <noteId>')
    .description(
      'Read one note; a sensitive body is redacted unless explicitly authorized.',
    );
  base(show)
    .option('--reveal', 'Request an authorized plaintext note body.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.noteShow(
        ...(args as [string, string, Record<string, unknown>, Command]),
      );
    });
  const remove = note
    .command('remove <item> <noteId>')
    .description('Archive one note inside its encrypted item aggregate.');
  base(remove)
    .option('--json', 'Emit machine-readable output.')
    .action(async (...args: unknown[]) => {
      const impl = await import('./structured-vault-impl.js');
      await impl.noteRemove(
        ...(args as [string, string, Record<string, unknown>, Command]),
      );
    });
}
