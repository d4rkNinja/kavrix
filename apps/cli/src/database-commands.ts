import type { Command } from 'commander';

export function addDatabaseOwnerCommands(db: Command): void {
  const init = db
    .command('init')
    .description('Initialize one encrypted multi-vault database.');
  addRoutingOptions(init);
  addSecretOption(init);
  init.option('--json', 'Emit machine-readable output (the default for this command).');
  init.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleDatabaseInit(impl.optionsFrom(args));
  });

  const status = db
    .command('status')
    .description('Authenticate and inspect the selected database.');
  addRoutingOptions(status);
  addSecretOption(status);
  status.option('--json', 'Emit machine-readable non-secret status.');
  status.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleDatabaseStatus(impl.optionsFrom(args));
  });

  const key = db.command('key').description('Manage database-owner key files.');
  const keyStatus = key
    .command('status')
    .description('Authenticate and inspect one database-owner key binding.');
  addRoutingOptions(keyStatus);
  addSecretOption(keyStatus);
  keyStatus.option('--json', 'Emit machine-readable non-secret status.');
  keyStatus.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleDatabaseStatus(impl.optionsFrom(args));
  });
  const keyCreate = key
    .command('create')
    .description('Create a protected key for sharing one local database.');
  addRoutingOptions(keyCreate);
  addSecretOption(keyCreate);
  keyCreate.requiredOption(
    '--output-key-file <path>',
    'Fresh protected local-share database-key destination.',
  );
  keyCreate.option(
    '--json',
    'Emit machine-readable output (the default for this command).',
  );
  keyCreate.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleDatabaseKeyCreate(impl.optionsFrom(args));
  });

  const doctor = db
    .command('doctor')
    .description('Inspect and repair local trust state.');
  const doctorHealth = doctor
    .command('health')
    .description(
      'Verify the encrypted database binding, snapshot authenticity, and rollback anchor; with --heal, apply safe local-state repairs.',
    );
  addRoutingOptions(doctorHealth);
  addSecretOption(doctorHealth);
  doctorHealth
    .option(
      '--accept-current',
      'Re-anchor the local rollback guard to the observed datastore after manually verifying it (heals stale or forked anchors).',
    )
    .option(
      '--heal',
      'Apply safe, reversible local-state repairs (incomplete unbound profiles, dangling selection pointers, owner-only ACL drift).',
    )
    .option('--dry-run', 'With --heal, list planned repairs without applying them.')
    .option('--json', 'Emit machine-readable output even on a terminal.');
  doctorHealth.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleDatabaseDoctorHealth(impl.optionsFrom(args));
  });

  const recovery = db
    .command('recovery')
    .description('Manage database-root recovery kits.');
  const create = recovery
    .command('create')
    .description('Create a protected database recovery kit.');
  addRoutingOptions(create);
  addSecretOption(create);
  create.requiredOption(
    '--recovery-file <path>',
    'Protected database recovery-kit destination.',
  );
  create.option(
    '--json',
    'Emit machine-readable output (the default for this command).',
  );
  create.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleRecoveryCreate(impl.optionsFrom(args));
  });

  const verify = recovery
    .command('verify')
    .description('Verify a database recovery kit locally.');
  addRoutingOptions(verify);
  addSecretOption(verify);
  verify.requiredOption(
    '--recovery-file <path>',
    'Protected database recovery-kit source.',
  );
  verify.option(
    '--json',
    'Emit machine-readable output (the default for this command).',
  );
  verify.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleRecoveryVerify(impl.optionsFrom(args));
  });

  const recoveryStatus = recovery
    .command('status')
    .description('Show database recovery slot ids and counts (non-secret).');
  addRoutingOptions(recoveryStatus);
  addSecretOption(recoveryStatus);
  recoveryStatus.option('--json', 'Emit machine-readable output.');
  recoveryStatus.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleRecoveryStatus(impl.optionsFrom(args));
  });

  const revoke = recovery
    .command('revoke <slotId>')
    .description(
      'Revoke one non-final recovery slot (at least one other active slot must remain). Slot ids come from create output or `db recovery status`.',
    );
  addRoutingOptions(revoke);
  addSecretOption(revoke);
  revoke.action(async (slotId: string, ...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleRecoveryRevoke(slotId, impl.optionsFrom(args));
  });

  const use = recovery
    .command('use')
    .description('Recover the same database root into a fresh owner key.');
  addRoutingOptions(use, false);
  addSecretOption(use);
  use
    .requiredOption('--recovery-file <path>', 'Protected database recovery-kit source.')
    .requiredOption(
      '--output-key-file <path>',
      'Fresh protected database-owner key destination.',
    )
    .option('--anchor-file <path>', 'Fresh trusted anchor destination.');
  use.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleRecoveryUse(impl.optionsFrom(args));
  });

  addDatabaseVaultCommands(
    db.command('vault').description('Manage vaults in an encrypted database.'),
  );
}

export function addDatabaseVaultCommands(vault: Command): void {
  const create = vault
    .command('create')
    .description('Create an independently encrypted vault.');
  addRoutingOptions(create);
  addSecretOption(create);
  create.option('--json', 'Emit machine-readable output.');
  create.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleVaultCreate(impl.optionsFrom(args));
  });

  const list = vault
    .command('list')
    .description('List vault identifiers and locally decrypted labels.');
  addRoutingOptions(list);
  addSecretOption(list);
  list
    .option(
      '--show-labels',
      'Show decrypted private labels to the authenticated owner (redacted by default).',
    )
    .option('--json', 'Emit machine-readable output.');
  list.action(async (...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleVaultList(impl.optionsFrom(args));
  });

  const status = vault
    .command('status <vaultId>')
    .description('Show authenticated vault metadata.');
  addRoutingOptions(status);
  addSecretOption(status);
  status.option(
    '--show-labels',
    'Include the decrypted private label for the authenticated owner.',
  );
  status.action(async (vaultId: string, ...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleVaultStatus(vaultId, impl.optionsFrom(args));
  });

  const rename = vault
    .command('rename <vaultId>')
    .description('Rename a vault inside the encrypted catalog.');
  addRoutingOptions(rename);
  addSecretOption(rename);
  rename.action(async (vaultId: string, ...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleVaultRename(vaultId, impl.optionsFrom(args));
  });

  const use = vault
    .command('use <vaultId>')
    .description('Select the default vault for one protected datastore profile.');
  addRoutingOptions(use);
  addSecretOption(use);
  use.action(async (vaultId: string, ...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleVaultUse(vaultId, impl.optionsFrom(args));
  });

  const remove = vault
    .command('remove <vaultId>')
    .description('Remove one vault from the encrypted catalog.');
  addRoutingOptions(remove);
  addSecretOption(remove);
  remove.option('--json', 'Emit machine-readable output.');
  remove.action(async (vaultId: string, ...args: unknown[]) => {
    const impl = await import('./database-commands-impl.js');
    await impl.handleVaultRemove(vaultId, impl.optionsFrom(args));
  });
}

function addRoutingOptions(command: Command, includeKey = true): void {
  command
    .option('--profile <id>', 'Protected datastore profile alias.')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--config-dir <path>', 'Protected profile configuration directory.')
    .option('--datastore <type>', 'Encrypted datastore: file or mongodb.')
    .option('--data-file <path>', 'Encrypted local database path.')
    .option('--database <name>', 'MongoDB database routing name.')
    .option('--database-collection <name>', 'MongoDB database document collection.')
    .option('--vault-collection <name>', 'MongoDB vault document collection.')
    .option(
      '--allow-insecure-transport',
      'Explicitly permit unencrypted transport to a non-local MongoDB (isolated networks only).',
    );
  if (includeKey)
    command.option('--key-file <path>', 'Protected database-owner key file.');
}

function addSecretOption(command: Command): void {
  command
    .option('--secrets-stdin', 'Read the exact documented secret frames from stdin.')
    .option(
      '--passphrase-stdin',
      'Alias of --secrets-stdin for compatibility (reads the same frames).',
    );
}
