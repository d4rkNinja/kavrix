/**
 * Light command registration for the Kavrix CLI.
 *
 * This module is evaluated on every invocation, so it may only depend on
 * Commander, version metadata, and small string/option helpers. Every action
 * dynamically imports the implementation module (`./local-vault-cli.js`),
 * which owns the heavy graph (schemas, crypto, storage, TUI, migration,
 * execution). Command shapes here must stay byte-identical to the documented
 * CLI surface.
 */
import { Command } from 'commander';
import { addDatabaseOwnerCommands } from './database-commands.js';
import { LocalCliError } from './cli-error.js';
import { InitOnboardingCancelledError } from './init-onboarding.js';
import { registerExecutionCommands } from './execution/register.js';
import { applyStdinFrameHelp, registerFramesCommand } from './stdin-frames.js';
import { registerStructuredVaultCommands } from './structured-vault-commands.js';
import { registerCredentialHistoryCommands } from './credential-history-commands.js';
import { registerTuiCommand } from './tui-command.js';
import { registerSelfUpdateCommand } from './self-update.js';
import { registerBackupCommands } from './backup-command.js';
import { registerImportCommands } from './import-env-command.js';
import {
  addMongoPingDatastoreOption,
  addRootDatastoreOption,
  INVALID_ROOT_DATASTORE_MESSAGE,
  parseRootDatastore,
  type RootDatastore,
} from './root-datastore.js';
import { resolveProfileConfigDirectory } from './profile-config-directory.js';
import { CLI_VERSION } from './version.js';
import { terminalColorEnabled } from './terminal-presentation.js';
import type { DatastoreProfileRoutingOverrides } from './datastore-profiles.js';
// Type-only namespace import: names the implementation module's surface for the
// lazy dispatcher without adding any runtime edge to the startup graph.
import type * as CliImplementation from './local-vault-cli.js';

/**
 * Loads the implementation module for one dispatched command, starting the
 * platform ACL helper first so its interpreter start-up overlaps the
 * implementation chunk load instead of serializing before it. Best effort by
 * design: a failed prewarm changes nothing, because the first real protected
 * path verification still starts the helper and fails closed if it cannot.
 */
const loadCliImplementation = async (): Promise<typeof CliImplementation> => {
  if (process.platform === 'win32') {
    // Best-effort warm-up: a missing or mocked helper module must never
    // surface here, because the real request path re-tries and fails closed.
    void import('@kavrix/key-files')
      .then((keyFiles) => {
        keyFiles.prewarmWindowsAclHelper();
      })
      .catch(() => undefined);
  }
  return import('./local-vault-cli.js');
};

/** Bare `kavrix` needs an interactive stdin+stdout; automation keeps commands. */
function interactiveDefaultEligible(
  stdin: Readonly<{ isTTY?: boolean }> = process.stdin,
  stdout: Readonly<{ isTTY?: boolean }> = process.stdout,
): boolean {
  return stdin.isTTY === true && stdout.isTTY === true;
}

/** Mirrors `wasJsonReported` from execution/exit-codes without its imports. */
function jsonAlreadyReported(error: unknown): boolean {
  return (
    error !== null &&
    typeof error === 'object' &&
    Reflect.get(error, 'jsonReported') === true
  );
}

/**
 * Light classification for the failures the startup graph itself can raise:
 * Commander usage errors, coded CLI errors, secret-input framing, aggregate
 * failures, and local CLI errors. Everything else defers to the full
 * classifier, loaded only when such a failure actually happens, so parse
 * errors and unknown commands never load the heavy graph.
 */
function classifyLightCliFailure(
  error: unknown,
): Readonly<{ message: string; exitCode: number }> | undefined {
  if (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'CommanderError' &&
    typeof (error as { code?: unknown }).code === 'string' &&
    typeof (error as { exitCode?: unknown }).exitCode === 'number'
  ) {
    const code = (error as { code: string }).code;
    if (
      code === 'commander.help' ||
      code === 'commander.helpDisplayed' ||
      code === 'commander.version'
    ) {
      return { message: '', exitCode: 0 };
    }
    return { message: '', exitCode: 2 };
  }
  if (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'CodedCliError' &&
    typeof (error as { exitCode?: unknown }).exitCode === 'number'
  ) {
    const coded = error as Error & { exitCode: number };
    return { message: coded.message, exitCode: coded.exitCode };
  }
  if (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'LocalSecretInputError'
  ) {
    return { message: (error as Error).message, exitCode: 2 };
  }
  if (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'SessionUnlockError' &&
    typeof (error as { code?: unknown }).code === 'string'
  ) {
    const code = (error as { code: string }).code;
    const message = (error as Error).message;
    if (code === 'tampered') return { message, exitCode: 16 };
    if (code === 'keychain-unavailable') return { message, exitCode: 15 };
    return { message, exitCode: 14 };
  }
  if (error instanceof AggregateError) {
    return { message: error.message, exitCode: 1 };
  }
  if (error instanceof InitOnboardingCancelledError) {
    return { message: error.message, exitCode: 1 };
  }
  if (error instanceof LocalCliError) {
    return { message: error.message, exitCode: 1 };
  }
  if (
    error instanceof Error &&
    error.message.length > 0 &&
    error.message.length <= 200 &&
    /^(Dynamic require of |Cannot find module )/u.test(error.message)
  ) {
    return {
      message: `Kavrix command failed: ${error.message}`,
      exitCode: 1,
    };
  }
  return undefined;
}

export async function runLocalCli(argv: readonly string[]): Promise<void> {
  try {
    // Bare `kavrix` on a TTY opens the interactive default: the init
    // onboarding wizard on a fresh machine, then the TUI. Everything else —
    // flags, subcommands, unknown words, non-interactive runs — keeps the
    // classic commander behavior untouched.
    if (argv.length <= 2 && interactiveDefaultEligible()) {
      const { runDefaultInteractiveAction } = await import('./default-interactive.js');
      await runDefaultInteractiveAction();
      return;
    }
    await buildLocalCli().parseAsync(argv);
  } catch (error) {
    const light = classifyLightCliFailure(error);
    const { message, exitCode } =
      light ??
      // Heavy failure classes (storage, key files, profiles, migration) need
      // the implementation graph, which a failing command has usually already
      // loaded; this import only adds cost to the failure path.
      (await import('./cli-errors.js')).classifyCliFailure(error);
    if (argvRequestsJson(argv)) {
      const { reportJsonFailure } = await import('./execution/commands.js');
      reportJsonFailure(error);
    }
    if (
      process.env['KAVRIX_DEBUG_CONNECT'] === '1' &&
      error instanceof Error &&
      error.stack
    ) {
      process.stderr.write(error.stack + '\n');
    }
    // `--json` already wrote the machine envelope to stdout; do not duplicate
    // the same human report on stderr.
    if (message.length > 0 && !jsonAlreadyReported(error)) {
      process.stderr.write(colorizeError(message) + '\n');
    }
    process.exitCode = exitCode;
  }
}

export const DEFAULT_KEY_FILE = './kavrix.key';
export const DEFAULT_DATA_FILE = './kavrix.vault';
export const DEFAULT_RECOVERY_FILE = './kavrix.recovery';
export const DEFAULT_COLLECTION = 'kavrix_vaults';
export const DEFAULT_DATABASE_PROFILE_COLLECTION = 'kavrix_databases';
export const DEFAULT_VAULT_PROFILE_COLLECTION = 'kavrix_vaults';
export const DEFAULT_VAULT_ID = 'default';
export const MONGO_DATABASE_NAME_PATTERN = /^[A-Za-z0-9_-]{1,63}$/u;
export const MONGO_COLLECTION_NAME_PATTERN = /^[A-Za-z0-9_-]{1,64}$/u;
export const REDACTED = '[REDACTED]';
export const MAX_LOCAL_PAYLOAD_BYTES = 4 * 1024 * 1024;
export { RESERVED_CREDENTIAL_NAMES } from './credential-name.js';
export const RESERVED_VAULT_IDENTIFIERS = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);
export const ANSI_ESCAPE = String.fromCharCode(27);
export const ANSI_RESET = `${ANSI_ESCAPE}[0m`;
export const ANSI_BOLD_CYAN = `${ANSI_ESCAPE}[1;36m`;
export const ANSI_BOLD = `${ANSI_ESCAPE}[1m`;
export const ANSI_DIM = `${ANSI_ESCAPE}[2m`;
export const ANSI_GREEN = `${ANSI_ESCAPE}[32m`;
export const ANSI_MAGENTA = `${ANSI_ESCAPE}[35m`;
export const ANSI_YELLOW = `${ANSI_ESCAPE}[33m`;
export const ANSI_RED = `${ANSI_ESCAPE}[31m`;

export type LocalCliOptions = Readonly<{
  datastore?: string;
  dataFile?: string;
  database?: string;
  databaseUrlStdin?: boolean;
  profile?: string;
  profileConfigDir?: string;
  sourceProfile?: string;
  destinationProfile?: string;
  sourceVault?: string;
  secretsStdin?: boolean;
  initialize?: boolean;
  passphraseStdin?: boolean;
  newPassphraseStdin?: boolean;
  recoveryPassphraseStdin?: boolean;
  valueStdin?: boolean;
  valueStdinBase64?: boolean;
  confirmationStdin?: boolean;
  artifact?: readonly string[];
  keyFile: string;
  source?: string;
  outputKeyFile?: string;
  destination?: string;
  recoveryFile?: string;
  outputRecoveryFile?: string;
  collection: string;
  vault: string;
  vaultWasDefaulted?: true;
  routingOverrides?: DatastoreProfileRoutingOverrides;
  overwrite?: boolean;
  acceptCurrent?: boolean;
  heal?: boolean;
  dryRun?: boolean;
  reveal?: boolean;
  json?: boolean;
  /** Explicit legacy version-2 single-vault init (migrate sources only). */
  legacy?: boolean;
  /** Commander `--no-tui` sets `tui: false` (default true). */
  tui?: boolean;
  /** TUI presentation: `--ascii` / `--color` / `--no-color` / `--no-splash`. */
  ascii?: boolean;
  color?: boolean;
  splash?: boolean;
  mouse?: boolean;
  limit?: string;
  caseSensitive?: boolean;
  allowInsecureTransport?: boolean;
  /** Unlock with the stored OS session (keychain-gated) instead of prompting. */
  session?: boolean;
  /** Session lifetime in hours for `kavrix session enable`. */
  ttlHours?: string;
}>;

export function buildLocalCli(): Command {
  const program = new Command();
  program
    .name('kavrix')
    .description('Local encrypted credential vault with selectable storage.')
    .version(CLI_VERSION)
    .helpCommand(false)
    .showHelpAfterError()
    // Intercept parse failures so usage errors carry the documented exit
    // code 2 instead of commander's default process exit.
    .exitOverride()
    .configureOutput({
      writeOut: (text) =>
        process.stdout.write(colorizeHelp(text, terminalColorEnabled(process.stdout))),
      writeErr: (text) =>
        process.stderr.write(colorizeHelp(text, terminalColorEnabled(process.stderr))),
    });

  const init = program
    .command('init')
    .description(
      'Create a bound local database vault (Ink TUI on TTY by default). Scripted/--json file init creates a selected datastore profile so put/run work immediately; --no-tui uses classic guided prompts; --legacy keeps version-2 single-vault migrate sources.',
    );
  // Root init and CRUD share DEFAULT_ROOT_DATASTORE (file). MongoDB requires
  // an explicit `--datastore mongodb` choice outside the guided wizard.
  addRootDatastoreOption(init)
    .option(
      '--data-file <path>',
      'Encrypted local database (or legacy vault) file path.',
    )
    .option(
      '--allow-insecure-transport',
      'Explicitly permit unencrypted transport to a non-local MongoDB (isolated networks only).',
    )
    .option(
      '--database-url-stdin',
      'Read the MongoDB connection string from standard input (never from an argument).',
    )
    .option('--database <name>', 'MongoDB database name when it is not in the URI.')
    .option('--collection <name>', 'MongoDB collection name.', DEFAULT_COLLECTION);
  addDatastoreProfileSelectionOptions(init);
  init.option(
    '--passphrase-stdin',
    'Read the key-file passphrase from standard input (never from an argument).',
  );
  init.option(
    '--recovery-file <path>',
    'Optional recovery-kit path for scripted file init (adds recovery passphrase frames).',
  );
  init.option(
    '--legacy',
    'Create a legacy version-2 single-vault (migrate sources only); skips database-container onboarding.',
  );
  init.option(
    '--no-tui',
    'Use classic guided line prompts instead of Ink TUI onboarding (default on interactive TTY).',
  );
  init.option(
    '--json',
    'Machine-readable / non-interactive init (skips TUI and classic prompts).',
  );
  init.option('--ascii', 'Force printable ASCII borders and glyphs (TUI onboarding).');
  init.option('--color', 'Force color when the terminal supports it (TUI onboarding).');
  init.option(
    '--no-color',
    'Disable ANSI color for TUI onboarding (also honors NO_COLOR).',
  );
  init.option('--no-splash', 'Skip the animated startup splash on TUI onboarding.');
  init.option(
    '--no-mouse',
    'Use keyboard navigation and native terminal selection during setup.',
  );
  addKeyOptions(init);
  init.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleInitAction(args);
  });

  const destroy = program
    .command('destroy', { hidden: true })
    .description('Permanently destroy one authenticated vault and its active files.')
    .helpOption('-h, --help')
    .showHelpAfterError(false);
  addDatabaseOptions(destroy);
  addKeyOptions(destroy);
  destroy.option(
    '--confirmation-stdin',
    'Read exactly two destruction confirmations from the protected stdin flow.',
  );
  destroy.option(
    '--artifact <path>',
    'Additional Kavrix key, anchor, or recovery file bound to this vault.',
    collectOption,
    [],
  );
  destroy.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleDestroy(getOptions(args));
  });

  const db = program.command('db').description('Database operations.');
  addDatastoreProfileCommands(db);
  addDatabaseOwnerCommands(db);
  const ping = db
    .command('ping')
    .description(
      'Check direct MongoDB connectivity without unlocking a vault (requires --datastore mongodb).',
    );
  addMongoPingOptions(ping);
  addDatastoreProfileSelectionOptions(ping);
  ping.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handlePing(getOptions(args), profileRoutingOverrides(args));
  });

  const migrate = program
    .command('migrate')
    .description('Explicit copy-first migrations.');
  const migrateDatabase = migrate
    .command('database')
    .description(
      'Copy one legacy version 2 vault into an existing database. Prepare a legacy source profile (no databaseId; `kavrix init --legacy --passphrase-stdin` vault+key) and a bound destination (`db init`). Then: `kavrix migrate database --source-profile <legacy> --destination-profile <db> --source-vault <id> --secrets-stdin` with frames from `kavrix frames migrate database`.',
    );
  migrateDatabase
    .requiredOption('--source-profile <id>', 'Legacy version 2 datastore profile.')
    .requiredOption('--destination-profile <id>', 'Bound database profile.')
    .requiredOption('--source-vault <id>', 'Legacy source vault identifier.')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--config-dir <path>', 'Protected profile configuration directory.')
    .option(
      '--initialize',
      'Explicitly initialize an unbound file destination profile.',
    )
    .option('--secrets-stdin', 'Read every migration secret from exact stdin frames.')
    .option(
      '--allow-insecure-transport',
      'Explicitly permit unencrypted transport to a non-local MongoDB (isolated networks only).',
    );
  migrateDatabase.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleMigrateDatabase(getOptions(args));
  });

  const put = program
    .command('put <name>')
    .description('Encrypt and store one credential value.');
  addDatabaseOptions(put);
  addKeyOptions(put);
  put.option(
    '--value-stdin',
    'Read the credential value from standard input (never from an argument).',
  );
  put.option(
    '--value-stdin-base64',
    'Read one base64-encoded credential value frame from standard input; supports multi-line values (empty values store but cannot be injected by run).',
  );
  put.option('--overwrite', 'Replace an existing credential explicitly.');
  put.option('--json', 'Emit machine-readable output (the default).');
  put.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handlePut(getName(args), getOptions(args));
  });

  const get = program
    .command('get <name>')
    .description(
      'Read one credential value; use --reveal for explicit plaintext output.',
    )
    .option('--json', 'Emit masked machine-readable output (the default).');
  addDatabaseOptions(get);
  addKeyOptions(get);
  get.option('--reveal', 'Explicitly print the decrypted value to stdout.');
  get.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleGet(getName(args), getOptions(args));
  });

  const list = program
    .command('list')
    .description('List credential names without revealing values.')
    .option('--json', 'Emit machine-readable output even on a terminal.');
  addDatabaseOptions(list);
  addKeyOptions(list);
  list.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleList(getOptions(args));
  });

  const view = program
    .command('view [name]')
    .description('Show a readable vault dashboard or one credential card.');
  addDatabaseOptions(view);
  addKeyOptions(view);
  view
    .option('--reveal', 'Reveal one named credential in an interactive terminal only.')
    .option('--json', 'Emit masked machine-readable output.');
  view.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleView(getOptionalName(args), getOptions(args));
  });

  const search = program
    .command('search <pattern>')
    .description(
      'Find credential names by glob (*, ?) or substring without searching or revealing values.',
    )
    .option('--limit <count>', 'Maximum matches to display.', '50')
    .option('--json', 'Emit machine-readable output.')
    .option(
      '--ignore-case',
      'Match the pattern case-insensitively (the default).',
      true,
    )
    .option('--case-sensitive', 'Match the pattern case-sensitively.');
  addDatabaseOptions(search);
  addKeyOptions(search);
  search.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleSearch(getName(args), getOptions(args));
  });

  const stats = program
    .command('stats')
    .description('Show vault health and record statistics without revealing values.');
  addDatabaseOptions(stats);
  addKeyOptions(stats);
  stats.option('--json', 'Emit machine-readable output.');
  stats.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleStats(getOptions(args));
  });

  const remove = program
    .command('remove <name>')
    .description('Delete one credential value.')
    .option('--json', 'Emit machine-readable output (the default).');
  addDatabaseOptions(remove);
  addKeyOptions(remove);
  remove.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleRemove(getName(args), getOptions(args));
  });

  const has = program
    .command('has <name>')
    .description('Check whether a credential exists without revealing its value.')
    .option('--json', 'Emit machine-readable output even on a terminal.');
  addDatabaseOptions(has);
  addKeyOptions(has);
  has.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleHas(getName(args), getOptions(args));
  });

  const rename = program
    .command('rename <from> <to>')
    .description('Rename a credential while keeping its encrypted value.')
    .option('--json', 'Emit machine-readable output (the default).');
  addDatabaseOptions(rename);
  addKeyOptions(rename);
  rename.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    const names = getNames(args);
    await impl.handleRename(names[0], names[1], getOptions(args));
  });

  const sessionCommand = program
    .command('session')
    .description(
      'Manage OS session unlock: keychain-gated convenience sessions for the selected profile.',
    );

  const sessionEnable = sessionCommand
    .command('enable')
    .description(
      'Seal the unlock material for the selected profile behind the OS credential store.',
    );
  addDatastoreProfileSelectionOptions(sessionEnable);
  sessionEnable
    .option(
      '--ttl-hours <hours>',
      'Session lifetime in hours after enable (default 12; 1-8760).',
    )
    .option(
      '--passphrase-stdin',
      'Read the key-file passphrase from standard input (never from an argument).',
    )
    .option('--json', 'Emit machine-readable output.');
  sessionEnable.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleSessionEnableAction(args);
  });

  const sessionStatus = sessionCommand
    .command('status')
    .description('Show whether a session unlock is enabled for the selected profile.');
  addDatastoreProfileSelectionOptions(sessionStatus);
  sessionStatus.option('--json', 'Emit machine-readable output (the default).');
  sessionStatus.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleSessionStatusAction(args);
  });

  const sessionRevoke = sessionCommand
    .command('revoke')
    .description('Remove the stored session unlock for the selected profile.');
  addDatastoreProfileSelectionOptions(sessionRevoke);
  sessionRevoke.option('--json', 'Emit machine-readable output (the default).');
  sessionRevoke.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleSessionRevokeAction(args);
  });

  const doctor = program
    .command('doctor')
    .description('Decrypt and validate the local vault without revealing values.')
    .option('--json', 'Emit machine-readable output (the default).');
  addDatabaseOptions(doctor);
  addKeyOptions(doctor);
  addDoctorHealOptions(doctor);
  doctor.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleDoctorAction(args);
  });

  const doctorHealth = doctor
    .command('health')
    .description(
      'Run fail-closed health checks; with --heal, apply safe local-state repairs.',
    );
  addDatabaseOptions(doctorHealth);
  addKeyOptions(doctorHealth);
  doctorHealth.option(
    '--accept-current',
    'Initialize a missing local rollback anchor only after manually verifying the current vault.',
  );
  addDoctorHealOptions(doctorHealth);
  doctorHealth.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleDoctorHealth(getOptions(args));
  });

  const recovery = program
    .command('recovery')
    .description(
      'Legacy-vault recovery kits. For database-container profiles (modern init), use `kavrix db recovery`.',
    );
  const recoveryCreate = recovery
    .command('create')
    .description('Create an encrypted recovery kit for replacing a lost key file.');
  addDatabaseOptions(recoveryCreate);
  addKeyOptions(recoveryCreate);
  recoveryCreate
    .option('--recovery-file <path>', 'Protected recovery-kit file path.')
    .option('--json', 'Emit machine-readable output (the default for this command).')
    .option('--overwrite', 'Replace an existing recovery-kit file explicitly.')
    .option(
      '--recovery-passphrase-stdin',
      'Read the recovery-kit passphrase from standard input.',
    )
    .option(
      '--secrets-stdin',
      'Alias of --recovery-passphrase-stdin for compatibility (reads the same frames).',
    );
  recoveryCreate.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleRecoveryCreate(getOptions(args));
  });
  const recoveryVerify = recovery
    .command('verify')
    .description('Verify a protected recovery kit against the current vault.');
  addDatabaseOnlyOptions(recoveryVerify);
  addDatastoreProfileSelectionOptions(recoveryVerify);
  addVaultOption(recoveryVerify);
  recoveryVerify
    .option(
      '--key-file <path>',
      'Portable-key path whose trusted revision anchor must be present.',
      DEFAULT_KEY_FILE,
    )
    .option('--recovery-file <path>', 'Protected recovery-kit file path.')
    .option(
      '--recovery-passphrase-stdin',
      'Read the recovery-kit passphrase from standard input.',
    )
    .option(
      '--passphrase-stdin',
      'Alias of --recovery-passphrase-stdin for compatibility.',
    )
    .option('--json', 'Emit machine-readable output.');
  recoveryVerify.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleRecoveryVerify(getOptions(args));
  });
  const recoveryRevoke = recovery
    .command('revoke <slotId>')
    .description('Revoke one recovery kit while keeping another active kit available.');
  addDatabaseOptions(recoveryRevoke);
  addKeyOptions(recoveryRevoke);
  recoveryRevoke.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleRecoveryRevoke(
      getArgument(args, 'recovery slot ID'),
      getOptions(args),
    );
  });
  const recoveryStatus = recovery
    .command('status')
    .description('Show protected recovery-kit counts without revealing secrets.');
  addDatabaseOnlyOptions(recoveryStatus);
  addDatastoreProfileSelectionOptions(recoveryStatus);
  addVaultOption(recoveryStatus);
  recoveryStatus.option('--json', 'Emit machine-readable output.');
  recoveryStatus.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleRecoveryStatus(getOptions(args));
  });
  const recoveryUse = recovery
    .command('use')
    .description('Use a protected recovery kit to create and bind new keys.');
  addDatabaseOnlyOptions(recoveryUse);
  addDatastoreProfileSelectionOptions(recoveryUse);
  addVaultOption(recoveryUse);
  recoveryUse
    .option(
      '--key-file <path>',
      'Portable-key path whose trusted revision anchor must be present.',
      DEFAULT_KEY_FILE,
    )
    .option('--recovery-file <path>', 'Protected recovery-kit file path.')
    .option(
      '--output-recovery-file <path>',
      'Destination protected recovery-kit file path.',
    )
    .option(
      '--recovery-passphrase-stdin',
      'Read the recovery-kit passphrase from standard input.',
    )
    .option(
      '--new-passphrase-stdin',
      'Read the new key-file passphrase from standard input.',
    )
    .option('--output-key-file <path>', 'Destination protected key-file path.')
    .option('--destination <path>', 'Destination protected key-file path.')
    .option('--overwrite', 'Replace an existing destination key file explicitly.');
  recoveryUse.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleRecoveryUse(getOptions(args));
  });

  const vault = program
    .command('vault')
    .description('Select and inspect encrypted vaults.');
  const vaultList = vault
    .command('list')
    .description('List vault identifiers stored in the selected MongoDB collection.');
  addDatabaseOnlyOptions(vaultList);
  addDatastoreProfileSelectionOptions(vaultList);
  vaultList.option(
    '--json',
    'Emit machine-readable output (the default for this command).',
  );
  vaultList.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleVaultList(getOptions(args));
  });
  const vaultStatus = vault
    .command('status')
    .description('Show non-secret metadata for the selected vault.');
  addDatabaseOnlyOptions(vaultStatus);
  addDatastoreProfileSelectionOptions(vaultStatus);
  addVaultOption(vaultStatus);
  vaultStatus.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleVaultStatus(getOptions(args));
  });

  const key = program
    .command('key')
    .description('Protected key-file lifecycle operations.');
  addKeyOnlyOptions(
    key
      .command('status')
      .description('Verify a protected key file and show non-secret metadata.'),
  ).action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleKeyStatus(getOptions(args));
  });
  addKeyOnlyOptions(
    key.command('verify').description('Cryptographically verify a protected key file.'),
  ).action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleKeyStatus(getOptions(args));
  });
  for (const name of ['copy', 'replicate', 'assign'] as const) {
    const description =
      name === 'copy'
        ? 'Create another protected key file with the same vault binding; it is not independently revocable.'
        : `Deprecated alias of \`key copy\`; behavior and output are identical.`;
    addKeyCopyOptions(key.command(name).description(description)).action(
      async (...args: unknown[]) => {
        const impl = await loadCliImplementation();
        await impl.handleKeyCopy(getOptions(args));
      },
    );
  }
  addKeyRewrapOptions(
    key
      .command('rewrap')
      .description('Replace a key-file passphrase without changing its vault binding.'),
  ).action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleKeyRewrap(getOptions(args));
  });

  registerExecutionCommands(program);
  registerTuiCommand(program);
  registerStructuredVaultCommands(program);
  // After the structured family: the history group attaches to the shared
  // item/credential command and fails closed if that command is absent.
  registerCredentialHistoryCommands(program);
  registerBackupCommands(program);
  registerImportCommands(program);
  registerFramesCommand(program);
  registerSelfUpdateCommand(program);
  applyStdinFrameHelp(program);

  const status = program
    .command('status')
    .description(
      'Show the CLI version, selected datastore profile, and active routing mode.',
    );
  addDatastoreProfileSelectionOptions(status);
  status.option('--json', 'Emit machine-readable output even on a terminal.');
  status.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleStatus(getOptions(args));
  });

  return program;
}

export function argvRequestsJson(argv: readonly string[]): boolean {
  const separator = argv.indexOf('--');
  const flags = separator === -1 ? argv : argv.slice(0, separator);
  return flags.includes('--json');
}

export type DatastoreProfileCommandOptions = Readonly<{
  configDir?: string;
  profileConfigDir?: string;
  datastore?: string;
  databaseId?: string;
  dataFile?: string;
  database?: string;
  databaseCollection?: string;
  vaultCollection?: string;
  keyFile?: string;
}>;

export function addDatastoreProfileCommands(db: Command): void {
  const profile = db
    .command('profile')
    .description('Manage protected non-secret datastore routing profiles.');

  const add = profile
    .command('add <id>')
    .description('Add a datastore route without storing connection credentials.');
  addProfileConfigOption(add);
  add.option('--json', 'Emit machine-readable output.');
  add
    .requiredOption('--datastore <type>', 'Datastore type: mongodb or file.')
    .option(
      '--database-id <id>',
      'Expected opaque database identifier after initialization.',
    )
    .option('--database <name>', 'MongoDB database routing name.')
    .option('--database-collection <name>', 'MongoDB database document collection.')
    .option('--vault-collection <name>', 'MongoDB vault document collection.')
    .option('--data-file <path>', 'Encrypted local database file path.')
    .requiredOption('--key-file <path>', 'Protected database-owner key file path.');
  add.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleProfileAdd(
      getArgument(args, 'profile ID'),
      profileCommandOptions(args),
    );
  });

  const list = profile
    .command('list')
    .description('List registered datastore profiles.');
  addProfileConfigOption(list);
  list.option('--json', 'Emit machine-readable output.');
  list.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleProfileList(profileCommandOptions(args));
  });

  const use = profile
    .command('use <id>')
    .description('Select one datastore profile without changing its routing.');
  addProfileConfigOption(use);
  use.option('--json', 'Emit machine-readable output.');
  use.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleProfileUse(
      getArgument(args, 'profile ID'),
      profileCommandOptions(args),
    );
  });

  const status = profile
    .command('status')
    .description('Show the selected non-secret datastore profile.');
  addProfileConfigOption(status);
  status.option('--json', 'Emit machine-readable output.');
  status.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleProfileStatus(profileCommandOptions(args));
  });

  const show = profile
    .command('show')
    .description('Alias of `db profile status` for compatibility.')
    .option(
      '--config-dir <path>',
      'Protected datastore-profile configuration directory.',
    )
    .option(
      '--profile-config-dir <path>',
      'Protected datastore-profile configuration directory.',
    )
    .option('--json', 'Emit machine-readable output.');
  show.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleProfileStatus(profileCommandOptions(args));
  });

  const remove = profile
    .command('remove <id>')
    .description(
      'Remove one datastore profile; removing the current profile clears selection.',
    );
  addProfileConfigOption(remove);
  remove.option('--json', 'Emit machine-readable output.');
  remove.action(async (...args: unknown[]) => {
    const impl = await loadCliImplementation();
    await impl.handleProfileRemove(
      getArgument(args, 'profile ID'),
      profileCommandOptions(args),
    );
  });
}

export function addProfileConfigOption(command: Command): void {
  // `--config-dir` is the historical spelling for `db profile` subcommands;
  // `--profile-config-dir` is the shared standard across every other command.
  command
    .option(
      '--config-dir <path>',
      'Protected datastore-profile configuration directory.',
    )
    .option(
      '--profile-config-dir <path>',
      'Protected datastore-profile configuration directory.',
    );
}

export function profileCommandOptions(
  args: readonly unknown[],
): DatastoreProfileCommandOptions {
  return getOptions(args);
}

export function addDatastoreProfileSelectionOptions(command: Command): void {
  command
    .option('--profile <id>', 'Use one non-secret datastore profile for this command.')
    .option(
      '--config-dir <path>',
      'Protected datastore-profile configuration directory.',
    )
    .option(
      '--profile-config-dir <path>',
      'Protected datastore-profile configuration directory.',
    );
}

export function profileRoutingOverrides(
  args: readonly unknown[],
): DatastoreProfileRoutingOverrides & Readonly<{ collection?: string }> {
  const command = args.at(-1);
  if (!(command instanceof Command)) return {};
  const options = getOptions(args);
  const optionIsExplicit = (key: string): boolean => {
    const source = command.getOptionValueSource(key);
    return source !== undefined && source !== 'default';
  };
  // Unset options (no Commander default, e.g. db ping --datastore) must not be
  // treated as explicit empty values — that previously threw a generic
  // "--datastore must be mongodb or file" instead of the ping-specific hint.
  const datastore = optionIsExplicit('datastore')
    ? parseExplicitDatastore(options.datastore)
    : undefined;
  return {
    ...(datastore === undefined ? {} : { datastore }),
    ...(!optionIsExplicit('dataFile') || options.dataFile === undefined
      ? {}
      : { dataFile: options.dataFile }),
    ...(!optionIsExplicit('database') || options.database === undefined
      ? {}
      : { database: options.database }),
    ...(!optionIsExplicit('collection') ? {} : { collection: options.collection }),
  };
}

export function parseExplicitDatastore(value: string | undefined): RootDatastore {
  if (value === undefined) {
    throw new LocalCliError(INVALID_ROOT_DATASTORE_MESSAGE);
  }
  return parseRootDatastore(value);
}

export function colorizeHelp(text: string, enabled: boolean): string {
  if (!enabled) return text;
  return text
    .split('\n')
    .map((line) => {
      const trimmed = line.trimStart();
      if (/^(?:Usage:|Options:|Commands:)/u.test(trimmed)) {
        return `${ANSI_BOLD_CYAN}${line}${ANSI_RESET}`;
      }
      if (trimmed.startsWith('-')) return `${ANSI_YELLOW}${line}${ANSI_RESET}`;
      if (/^[a-z][a-z0-9-]*(?=\s+(?:\[|<|[A-Z]))/u.test(trimmed)) {
        return line.replace(
          /^(\s*)([a-z][a-z0-9-]*)/u,
          `$1${ANSI_GREEN}$2${ANSI_RESET}`,
        );
      }
      return line;
    })
    .join('\n');
}

export function colorizeError(message: string): string {
  if (!terminalColorEnabled(process.stderr)) return message;
  if (message.startsWith('error:')) {
    return `${ANSI_RED}error:${ANSI_RESET}${message.slice('error:'.length)}`;
  }
  return `${ANSI_RED}error:${ANSI_RESET} ${message}`;
}

export function addDatabaseOnlyOptions(command: Command): void {
  addRootDatastoreOption(command)
    .option('--data-file <path>', 'Encrypted local vault file path.')
    .option(
      '--allow-insecure-transport',
      'Explicitly permit unencrypted transport to a non-local MongoDB (isolated networks only).',
    )
    .option(
      '--database-url-stdin',
      'Read the MongoDB connection string from standard input (never from an argument).',
    )
    .option('--database <name>', 'MongoDB database name when it is not in the URI.')
    .option('--collection <name>', 'MongoDB collection name.', DEFAULT_COLLECTION);
}

export function addMongoPingOptions(command: Command): void {
  addMongoPingDatastoreOption(command)
    .option('--data-file <path>', 'Encrypted local vault file path.')
    .option(
      '--allow-insecure-transport',
      'Explicitly permit unencrypted transport to a non-local MongoDB (isolated networks only).',
    )
    .option(
      '--database-url-stdin',
      'Read the MongoDB connection string from standard input (never from an argument).',
    )
    .option('--database <name>', 'MongoDB database name when it is not in the URI.')
    .option('--collection <name>', 'MongoDB collection name.', DEFAULT_COLLECTION);
}

export function addDatabaseOptions(command: Command): void {
  addDatabaseOnlyOptions(command);
  addDatastoreProfileSelectionOptions(command);
  command.option(
    '--passphrase-stdin',
    'Read the key-file passphrase from standard input (never from an argument).',
  );
  command.option(
    '--session',
    'Unlock with the stored OS session (keychain-gated) instead of the passphrase.',
  );
}

export function addKeyOnlyOptions(command: Command): Command {
  return command
    .option('--key-file <path>', 'Protected portable-key file path.', DEFAULT_KEY_FILE)
    .option('--source <path>', 'Source protected key-file path.')
    .option(
      '--passphrase-stdin',
      'Read the key-file passphrase from standard input (never from an argument).',
    )
    .option('--json', 'Emit machine-readable output.');
}

export function addKeyCopyOptions(command: Command): Command {
  return addKeyOnlyOptions(command)
    .option('--output-key-file <path>', 'Destination protected key-file path.')
    .option('--destination <path>', 'Destination protected key-file path.')
    .option('--overwrite', 'Replace an existing destination key file explicitly.')
    .option(
      '--new-passphrase-stdin',
      'Read the destination key-file passphrase from standard input.',
    );
}

export function addKeyRewrapOptions(command: Command): Command {
  return addKeyOnlyOptions(command).option(
    '--new-passphrase-stdin',
    'Read the replacement key-file passphrase from standard input.',
  );
}

export function addKeyOptions(command: Command): void {
  command.option(
    '--key-file <path>',
    'Protected portable-key file path (init without --data-file/--key-file uses ~/.kavrix/; an explicit path including ./kavrix.key is honored).',
    DEFAULT_KEY_FILE,
  );
  addVaultOption(command);
}

export function addDoctorHealOptions(command: Command): void {
  command
    .option(
      '--heal',
      'Apply safe, reversible local-state repairs (incomplete unbound profiles, dangling selection pointers, owner-only ACL drift).',
    )
    .option('--dry-run', 'With --heal, list planned repairs without applying them.');
}

export function addVaultOption(command: Command): void {
  command.option('--vault <id>', 'Opaque vault identifier.', DEFAULT_VAULT_ID);
}

export function getOptions(args: readonly unknown[]): LocalCliOptions {
  const last = args.at(-1);
  if (last instanceof Command) {
    const hierarchy: Command[] = [];
    let current: Command | null = last;
    while (current !== null) {
      hierarchy.unshift(current);
      current = current.parent;
    }
    const merged: Record<string, unknown> = {};
    for (const command of hierarchy) {
      for (const [key, value] of Object.entries(command.opts())) {
        const source = command.getOptionValueSource(key);
        if (source !== 'default' || !Object.hasOwn(merged, key)) {
          merged[key] = value;
        }
      }
    }
    const profileConfigDir = resolveProfileConfigDirectory(
      typeof merged['profileConfigDir'] === 'string'
        ? merged['profileConfigDir']
        : undefined,
      typeof merged['configDir'] === 'string' ? merged['configDir'] : undefined,
    );
    if (profileConfigDir !== undefined) merged['profileConfigDir'] = profileConfigDir;
    delete merged['configDir'];
    const sourceIsExplicit = (key: string): boolean =>
      hierarchy.some((command) => {
        const source = command.getOptionValueSource(key);
        return source !== undefined && source !== 'default';
      });
    const options = merged as LocalCliOptions;
    if (!sourceIsExplicit('vault')) {
      merged['vaultWasDefaulted'] = true;
    }
    merged['routingOverrides'] = {
      ...(sourceIsExplicit('datastore')
        ? { datastore: parseExplicitDatastore(options.datastore) }
        : {}),
      ...(sourceIsExplicit('dataFile') && options.dataFile !== undefined
        ? { dataFile: options.dataFile }
        : {}),
      ...(sourceIsExplicit('database') && options.database !== undefined
        ? { database: options.database }
        : {}),
      ...(sourceIsExplicit('collection')
        ? { vaultCollection: options.collection }
        : {}),
      ...(sourceIsExplicit('keyFile') ? { keyFile: options.keyFile } : {}),
    };
    return merged as LocalCliOptions;
  }
  const candidate = args.find((value) => typeof value === 'object' && value !== null);
  if (candidate === undefined) throw new LocalCliError('Command options are invalid.');
  return candidate as LocalCliOptions;
}

export function getName(args: readonly unknown[]): string {
  return getArgument(args, 'credential name');
}

export function getArgument(args: readonly unknown[], label: string): string {
  const value = args.find((candidate) => typeof candidate === 'string');
  if (value === undefined || value.length === 0) {
    throw new LocalCliError(`A ${label} is required.`);
  }
  return value;
}

export function getOptionalName(args: readonly unknown[]): string | undefined {
  const value = args.find((candidate) => typeof candidate === 'string');
  if (value === undefined || value.length === 0) return undefined;
  return value;
}

export function getNames(args: readonly unknown[]): readonly [string, string] {
  const values = args.filter(
    (candidate): candidate is string => typeof candidate === 'string',
  );
  const from = values[0];
  const to = values[1];
  if (from === undefined || to === undefined || from.length === 0 || to.length === 0) {
    throw new LocalCliError('Two credential names are required.');
  }
  return [from, to];
}

export function collectOption(
  value: string,
  previous: readonly string[],
): readonly string[] {
  return [...previous, value];
}
