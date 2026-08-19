import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { realpath } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { Readable } from 'node:stream';

import {
  createPortableKeySlot,
  createRecoveryKeySlot,
  decryptPayload,
  encryptPayload,
  generatePortableKey,
  generateRecoveryKey,
  generateVaultRootKey,
  unlockRecoveryKeySlotBytes,
  unlockPortableKeySlotBytes,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  copyRevisionAnchor,
  deleteSecureFile,
  PortableKeyFileError,
  readPortableKeyFile,
  readRecoveryKitFile,
  readRevisionAnchor,
  readSecureFile,
  validateSecureFileDestination,
  validateRevisionAnchorFile,
  writeRecoveryKitFile,
  writeRevisionAnchor,
  writePortableKeyFile,
  type RevisionAnchor,
} from '@kavrix/key-files';
import {
  CURRENT_CRYPTOGRAPHIC_VERSION,
  CURRENT_LOCAL_VAULT_VERSION,
  CURRENT_SCHEMA_VERSION,
  associatedDataSchema,
  canonicalJson,
  databaseIdSchema,
  keySlotIdSchema,
  keyVersionSchema,
  localVaultDocumentSchema,
  localVaultPayloadSchema,
  MAX_LOCAL_RECOVERY_SLOTS,
  supportedCryptographicVersionSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
  profileIdSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  sha256DigestSchema,
  type AssociatedData,
  type DatabaseId,
  type LocalRecoveryKeySlot,
  type LocalVaultDocument,
  type LocalVaultPayload,
  type ProfileId,
  type Sha256Digest,
} from '@kavrix/schemas';
import {
  EncryptedVaultStoreError,
  FileLocalVaultStore,
  MongoLocalVaultStore,
  type EncryptedVaultStore,
} from '@kavrix/storage';
import { Command } from 'commander';

import {
  DatastoreProfileError,
  DatastoreProfileRegistry,
  resolveDatastoreProfileRouting,
  type DatastoreProfile,
  type DatastoreProfileRoutingOverrides,
} from './datastore-profiles.js';
import {
  LocalSecretInput,
  LocalSecretInputError,
  type LocalSecretKind,
} from './local-secrets.js';
import { CLI_VERSION } from './version.js';

const DEFAULT_KEY_FILE = './kavrix.key';
const DEFAULT_DATA_FILE = './kavrix.vault';
const DEFAULT_COLLECTION = 'kavrix_vaults';
const DEFAULT_DATABASE_PROFILE_COLLECTION = 'kavrix_databases';
const DEFAULT_VAULT_PROFILE_COLLECTION = 'kavrix_vaults';
const DEFAULT_VAULT_ID = 'default';
const REDACTED = '[REDACTED]';
const MAX_LOCAL_PAYLOAD_BYTES = 4 * 1024 * 1024;
const RESERVED_CREDENTIAL_NAMES = new Set(['__proto__', 'constructor', 'prototype']);
const ANSI_ESCAPE = String.fromCharCode(27);
const ANSI_RESET = `${ANSI_ESCAPE}[0m`;
const ANSI_BOLD_CYAN = `${ANSI_ESCAPE}[1;36m`;
const ANSI_BOLD = `${ANSI_ESCAPE}[1m`;
const ANSI_DIM = `${ANSI_ESCAPE}[2m`;
const ANSI_GREEN = `${ANSI_ESCAPE}[32m`;
const ANSI_MAGENTA = `${ANSI_ESCAPE}[35m`;
const ANSI_YELLOW = `${ANSI_ESCAPE}[33m`;
const ANSI_RED = `${ANSI_ESCAPE}[31m`;

export type LocalCliOptions = Readonly<{
  datastore?: string;
  dataFile?: string;
  database?: string;
  databaseUrlStdin?: boolean;
  profile?: string;
  profileConfigDir?: string;
  passphraseStdin?: boolean;
  newPassphraseStdin?: boolean;
  recoveryPassphraseStdin?: boolean;
  valueStdin?: boolean;
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
  overwrite?: boolean;
  acceptCurrent?: boolean;
  reveal?: boolean;
  json?: boolean;
  limit?: string;
}>;

export function buildLocalCli(): Command {
  const program = new Command();
  program
    .name('kavrix')
    .description('Local encrypted credential vault with selectable storage.')
    .version(CLI_VERSION)
    .helpCommand(false)
    .showHelpAfterError()
    .configureOutput({
      writeOut: (text) =>
        process.stdout.write(colorizeHelp(text, process.stdout.isTTY)),
      writeErr: (text) =>
        process.stderr.write(colorizeHelp(text, process.stderr.isTTY)),
    });

  const init = program
    .command('init')
    .description('Create a vault and a protected portable key file.');
  addDatabaseOptions(init);
  addKeyOptions(init);
  init.action(async (...args: unknown[]) => {
    await handleInit(getOptions(args));
  });

  const destroy = program
    .command('destroy', { hidden: true })
    .description('Permanently destroy one authenticated vault and its active files.')
    .helpOption(false)
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
    await handleDestroy(getOptions(args));
  });

  const db = program.command('db').description('Database operations.');
  addDatastoreProfileCommands(db);
  const ping = db
    .command('ping')
    .description('Check direct MongoDB connectivity without unlocking a vault.');
  addDatabaseOnlyOptions(ping);
  addDatastoreProfileSelectionOptions(ping);
  ping.action(async (...args: unknown[]) => {
    await handlePing(getOptions(args), profileRoutingOverrides(args));
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
  put.option('--overwrite', 'Replace an existing credential explicitly.');
  put.action(async (...args: unknown[]) => {
    await handlePut(getName(args), getOptions(args));
  });

  const get = program
    .command('get <name>')
    .description(
      'Read one credential value; use --reveal for explicit plaintext output.',
    );
  addDatabaseOptions(get);
  addKeyOptions(get);
  get.option('--reveal', 'Explicitly print the decrypted value to stdout.');
  get.action(async (...args: unknown[]) => {
    await handleGet(getName(args), getOptions(args));
  });

  const list = program
    .command('list')
    .description('List credential names without revealing values.');
  addDatabaseOptions(list);
  addKeyOptions(list);
  list.action(async (...args: unknown[]) => {
    await handleList(getOptions(args));
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
    await handleView(getOptionalName(args), getOptions(args));
  });

  const search = program
    .command('search <pattern>')
    .description('Find credential names without searching or revealing their values.');
  addDatabaseOptions(search);
  addKeyOptions(search);
  search
    .option('--limit <count>', 'Maximum matches to display.', '50')
    .option('--json', 'Emit machine-readable output.');
  search.action(async (...args: unknown[]) => {
    await handleSearch(getName(args), getOptions(args));
  });

  const stats = program
    .command('stats')
    .description('Show vault health and record statistics without revealing values.');
  addDatabaseOptions(stats);
  addKeyOptions(stats);
  stats.option('--json', 'Emit machine-readable output.');
  stats.action(async (...args: unknown[]) => {
    await handleStats(getOptions(args));
  });

  const remove = program
    .command('remove <name>')
    .description('Delete one credential value.');
  addDatabaseOptions(remove);
  addKeyOptions(remove);
  remove.action(async (...args: unknown[]) => {
    await handleRemove(getName(args), getOptions(args));
  });

  const has = program
    .command('has <name>')
    .description('Check whether a credential exists without revealing its value.');
  addDatabaseOptions(has);
  addKeyOptions(has);
  has.action(async (...args: unknown[]) => {
    await handleHas(getName(args), getOptions(args));
  });

  const rename = program
    .command('rename <from> <to>')
    .description('Rename a credential while keeping its encrypted value.');
  addDatabaseOptions(rename);
  addKeyOptions(rename);
  rename.action(async (...args: unknown[]) => {
    const names = getNames(args);
    await handleRename(names[0], names[1], getOptions(args));
  });

  const doctor = program
    .command('doctor')
    .description('Decrypt and validate the local vault without revealing values.');
  addDatabaseOptions(doctor);
  addKeyOptions(doctor);
  doctor.action(async (...args: unknown[]) => {
    await handleDoctor(getOptions(args));
  });

  const doctorHealth = doctor
    .command('health')
    .description('Run fail-closed health checks and repair only safe transient state.');
  addDatabaseOptions(doctorHealth);
  addKeyOptions(doctorHealth);
  doctorHealth.option(
    '--accept-current',
    'Initialize a missing local rollback anchor only after manually verifying the current vault.',
  );
  doctorHealth.action(async (...args: unknown[]) => {
    await handleDoctorHealth(getOptions(args));
  });

  const recovery = program
    .command('recovery')
    .description('Create protected recovery kits and replace a lost key file.');
  const recoveryCreate = recovery
    .command('create')
    .description('Create an encrypted recovery kit for replacing a lost key file.');
  addDatabaseOptions(recoveryCreate);
  addKeyOptions(recoveryCreate);
  recoveryCreate
    .option('--recovery-file <path>', 'Protected recovery-kit file path.')
    .option('--overwrite', 'Replace an existing recovery-kit file explicitly.')
    .option(
      '--recovery-passphrase-stdin',
      'Read the recovery-kit passphrase from standard input.',
    );
  recoveryCreate.action(async (...args: unknown[]) => {
    await handleRecoveryCreate(getOptions(args));
  });
  const recoveryVerify = recovery
    .command('verify')
    .description('Verify a protected recovery kit against the current vault.');
  addDatabaseOnlyOptions(recoveryVerify);
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
    .option('--json', 'Emit machine-readable output.');
  recoveryVerify.action(async (...args: unknown[]) => {
    await handleRecoveryVerify(getOptions(args));
  });
  const recoveryRevoke = recovery
    .command('revoke <slotId>')
    .description('Revoke one recovery kit while keeping another active kit available.');
  addDatabaseOptions(recoveryRevoke);
  addKeyOptions(recoveryRevoke);
  recoveryRevoke.action(async (...args: unknown[]) => {
    await handleRecoveryRevoke(getArgument(args, 'recovery slot ID'), getOptions(args));
  });
  const recoveryStatus = recovery
    .command('status')
    .description('Show protected recovery-kit counts without revealing secrets.');
  addDatabaseOnlyOptions(recoveryStatus);
  addVaultOption(recoveryStatus);
  recoveryStatus.option('--json', 'Emit machine-readable output.');
  recoveryStatus.action(async (...args: unknown[]) => {
    await handleRecoveryStatus(getOptions(args));
  });
  const recoveryUse = recovery
    .command('use')
    .description('Use a protected recovery kit to create and bind new keys.');
  addDatabaseOnlyOptions(recoveryUse);
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
    await handleRecoveryUse(getOptions(args));
  });

  const vault = program
    .command('vault')
    .description('Select and inspect encrypted vaults.');
  const vaultList = vault
    .command('list')
    .description('List vault identifiers stored in the selected MongoDB collection.');
  addDatabaseOnlyOptions(vaultList);
  vaultList.action(async (...args: unknown[]) => {
    await handleVaultList(getOptions(args));
  });
  const vaultStatus = vault
    .command('status')
    .description('Show non-secret metadata for the selected vault.');
  addDatabaseOnlyOptions(vaultStatus);
  addVaultOption(vaultStatus);
  vaultStatus.action(async (...args: unknown[]) => {
    await handleVaultStatus(getOptions(args));
  });

  const key = program
    .command('key')
    .description('Protected key-file lifecycle operations.');
  addKeyOnlyOptions(
    key
      .command('status')
      .description('Verify a protected key file and show non-secret metadata.'),
  ).action(async (...args: unknown[]) => {
    await handleKeyStatus(getOptions(args));
  });
  addKeyOnlyOptions(
    key.command('verify').description('Cryptographically verify a protected key file.'),
  ).action(async (...args: unknown[]) => {
    await handleKeyStatus(getOptions(args));
  });
  for (const name of ['copy', 'replicate', 'assign'] as const) {
    addKeyCopyOptions(
      key
        .command(name)
        .description(
          'Create another protected key file with the same vault binding; it is not independently revocable.',
        ),
    ).action(async (...args: unknown[]) => {
      await handleKeyCopy(getOptions(args));
    });
  }
  addKeyRewrapOptions(
    key
      .command('rewrap')
      .description('Replace a key-file passphrase without changing its vault binding.'),
  ).action(async (...args: unknown[]) => {
    await handleKeyRewrap(getOptions(args));
  });

  return program;
}

export async function runLocalCli(argv: readonly string[]): Promise<void> {
  try {
    await buildLocalCli().parseAsync(argv);
  } catch (error) {
    const message =
      error instanceof LocalCliError
        ? error.message
        : error instanceof LocalSecretInputError
          ? error.message
          : error instanceof EncryptedVaultStoreError
            ? error.message
            : error instanceof DatastoreProfileError
              ? error.message
              : error instanceof AggregateError
                ? error.message
                : 'Kavrix command failed.';
    process.stderr.write(colorizeError(message) + '\n');
    process.exitCode = 1;
  }
}

class LocalCliError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'LocalCliError';
  }
}

class InitializationRollbackError extends AggregateError {
  public constructor(operationError: unknown, cleanupError: unknown) {
    super(
      [asError(operationError), asError(cleanupError)],
      'Vault initialization failed and datastore rollback was incomplete.',
      { cause: asError(operationError) },
    );
    this.name = 'InitializationRollbackError';
  }
}

type DatastoreProfileCommandOptions = Readonly<{
  configDir?: string;
  datastore?: string;
  databaseId?: string;
  dataFile?: string;
  database?: string;
  databaseCollection?: string;
  vaultCollection?: string;
  keyFile?: string;
}>;

function addDatastoreProfileCommands(db: Command): void {
  const profile = db
    .command('profile')
    .description('Manage protected non-secret datastore routing profiles.');

  const add = profile
    .command('add <id>')
    .description('Add a datastore route without storing connection credentials.');
  addProfileConfigOption(add);
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
    await handleProfileAdd(
      getArgument(args, 'profile ID'),
      profileCommandOptions(args),
    );
  });

  const list = profile
    .command('list')
    .description('List registered datastore profiles.');
  addProfileConfigOption(list);
  list.action(async (...args: unknown[]) => {
    await handleProfileList(profileCommandOptions(args));
  });

  const use = profile
    .command('use <id>')
    .description('Select one datastore profile without changing its routing.');
  addProfileConfigOption(use);
  use.action(async (...args: unknown[]) => {
    await handleProfileUse(
      getArgument(args, 'profile ID'),
      profileCommandOptions(args),
    );
  });

  const status = profile
    .command('status')
    .description('Show the selected non-secret datastore profile.');
  addProfileConfigOption(status);
  status.action(async (...args: unknown[]) => {
    await handleProfileStatus(profileCommandOptions(args));
  });

  const remove = profile
    .command('remove <id>')
    .description(
      'Remove one datastore profile; removing the current profile clears selection.',
    );
  addProfileConfigOption(remove);
  remove.action(async (...args: unknown[]) => {
    await handleProfileRemove(
      getArgument(args, 'profile ID'),
      profileCommandOptions(args),
    );
  });
}

function addProfileConfigOption(command: Command): void {
  command.option(
    '--config-dir <path>',
    'Protected datastore-profile configuration directory.',
  );
}

function profileCommandOptions(
  args: readonly unknown[],
): DatastoreProfileCommandOptions {
  return getOptions(args);
}

async function handleProfileAdd(
  id: string,
  options: DatastoreProfileCommandOptions,
): Promise<void> {
  const registry = await openDatastoreProfileRegistry(options);
  const profile = await registry.add(profileFromCommand(id, options));
  writeJson({ added: true, profile: profileForOutput(profile) });
}

async function handleProfileList(
  options: DatastoreProfileCommandOptions,
): Promise<void> {
  const registry = await openDatastoreProfileRegistry(options);
  const profiles = await registry.list();
  writeJson({ profiles: profiles.map(profileForOutput) });
}

async function handleProfileUse(
  id: string,
  options: DatastoreProfileCommandOptions,
): Promise<void> {
  const registry = await openDatastoreProfileRegistry(options);
  const profile = await registry.use(parseCommandProfileId(id));
  writeJson({ selected: profileForOutput(profile) });
}

async function handleProfileStatus(
  options: DatastoreProfileCommandOptions,
): Promise<void> {
  const registry = await openDatastoreProfileRegistry(options);
  const profile = await registry.current();
  writeJson({ current: profile === null ? null : profileForOutput(profile) });
}

async function handleProfileRemove(
  id: string,
  options: DatastoreProfileCommandOptions,
): Promise<void> {
  const registry = await openDatastoreProfileRegistry(options);
  const profile = await registry.remove(parseCommandProfileId(id));
  writeJson({ removed: true, profile: profileForOutput(profile) });
}

async function openDatastoreProfileRegistry(
  options: DatastoreProfileCommandOptions,
): Promise<DatastoreProfileRegistry> {
  return DatastoreProfileRegistry.open(
    options.configDir === undefined ? {} : { configDirectory: options.configDir },
  );
}

function profileFromCommand(
  id: string,
  options: DatastoreProfileCommandOptions,
): DatastoreProfile {
  const profileId = parseCommandProfileId(id);
  const databaseId =
    options.databaseId === undefined
      ? undefined
      : parseCommandDatabaseId(options.databaseId);
  const keyFile = requiredOption(options.keyFile, '--key-file');
  if (options.datastore === 'mongodb') {
    if (options.dataFile !== undefined) {
      throw new LocalCliError('--data-file requires --datastore file.');
    }
    return {
      id: profileId,
      datastore: 'mongodb',
      database: requiredOption(options.database, '--database'),
      databaseCollection:
        options.databaseCollection ?? DEFAULT_DATABASE_PROFILE_COLLECTION,
      vaultCollection: options.vaultCollection ?? DEFAULT_VAULT_PROFILE_COLLECTION,
      keyFile,
      ...(databaseId === undefined ? {} : { databaseId }),
    };
  }
  if (options.datastore === 'file') {
    if (
      options.database !== undefined ||
      options.databaseCollection !== undefined ||
      options.vaultCollection !== undefined
    ) {
      throw new LocalCliError('MongoDB routing options require --datastore mongodb.');
    }
    return {
      id: profileId,
      datastore: 'file',
      dataFile: requiredOption(options.dataFile, '--data-file'),
      keyFile,
      ...(databaseId === undefined ? {} : { databaseId }),
    };
  }
  throw new LocalCliError('--datastore must be mongodb or file.');
}

function parseCommandProfileId(value: string): ProfileId {
  try {
    return profileIdSchema.parse(value);
  } catch {
    throw new LocalCliError('Profile ID is invalid.');
  }
}

function parseCommandDatabaseId(value: string): DatabaseId {
  try {
    return databaseIdSchema.parse(value);
  } catch {
    throw new LocalCliError('Database ID is invalid.');
  }
}

function profileForOutput(profile: DatastoreProfile): Record<string, string> {
  return profile.datastore === 'mongodb'
    ? {
        id: sanitizeTerminalText(profile.id),
        datastore: profile.datastore,
        ...(profile.databaseId === undefined
          ? {}
          : { databaseId: sanitizeTerminalText(profile.databaseId) }),
        database: sanitizeTerminalText(profile.database),
        databaseCollection: sanitizeTerminalText(profile.databaseCollection),
        vaultCollection: sanitizeTerminalText(profile.vaultCollection),
        keyFile: sanitizeTerminalText(profile.keyFile),
      }
    : {
        id: sanitizeTerminalText(profile.id),
        datastore: profile.datastore,
        ...(profile.databaseId === undefined
          ? {}
          : { databaseId: sanitizeTerminalText(profile.databaseId) }),
        dataFile: sanitizeTerminalText(profile.dataFile),
        keyFile: sanitizeTerminalText(profile.keyFile),
      };
}

function addDatastoreProfileSelectionOptions(command: Command): void {
  command
    .option('--profile <id>', 'Use one non-secret datastore profile for this command.')
    .option(
      '--profile-config-dir <path>',
      'Protected datastore-profile configuration directory.',
    );
}

function profileRoutingOverrides(
  args: readonly unknown[],
): DatastoreProfileRoutingOverrides & Readonly<{ collection?: string }> {
  const command = args.at(-1);
  if (!(command instanceof Command)) return {};
  const options = getOptions(args);
  const datastore =
    command.getOptionValueSource('datastore') === 'default'
      ? undefined
      : parseExplicitDatastore(options.datastore);
  return {
    ...(datastore === undefined ? {} : { datastore }),
    ...(command.getOptionValueSource('dataFile') === 'default' ||
    options.dataFile === undefined
      ? {}
      : { dataFile: options.dataFile }),
    ...(command.getOptionValueSource('database') === 'default' ||
    options.database === undefined
      ? {}
      : { database: options.database }),
    ...(command.getOptionValueSource('collection') === 'default'
      ? {}
      : { collection: options.collection }),
  };
}

function parseExplicitDatastore(value: string | undefined): 'mongodb' | 'file' {
  if (value === 'mongodb' || value === 'file') return value;
  throw new LocalCliError('--datastore must be mongodb or file.');
}

async function resolveProfileForPing(
  options: LocalCliOptions,
  overrides: DatastoreProfileRoutingOverrides & Readonly<{ collection?: string }>,
): Promise<Readonly<{ options: LocalCliOptions; profile: DatastoreProfile | null }>> {
  const registryOptions =
    options.profileConfigDir === undefined
      ? {}
      : { configDirectory: options.profileConfigDir };
  const registry =
    options.profile === undefined
      ? await DatastoreProfileRegistry.openIfPresent(registryOptions)
      : await DatastoreProfileRegistry.open(registryOptions);
  if (registry === null) return { options, profile: null };
  let profile: DatastoreProfile | null;
  if (options.profile === undefined) {
    profile = await registry.current();
  } else {
    profile = await registry.get(parseCommandProfileId(options.profile));
  }
  if (profile === null) return { options, profile: null };
  if (profile.databaseId !== undefined) {
    throw new LocalCliError(
      'A database-bound datastore profile requires database container commands.',
    );
  }
  const routing = resolveDatastoreProfileRouting(profile, {
    ...(overrides.datastore === undefined ? {} : { datastore: overrides.datastore }),
    ...(overrides.dataFile === undefined ? {} : { dataFile: overrides.dataFile }),
    ...(overrides.database === undefined ? {} : { database: overrides.database }),
    ...(overrides.collection === undefined
      ? {}
      : { vaultCollection: overrides.collection }),
  });
  if (routing.datastore !== 'mongodb') {
    throw new LocalCliError(
      'File datastore profiles require database container commands.',
    );
  }
  if (overrides.dataFile !== undefined) {
    throw new LocalCliError('--data-file requires --datastore file.');
  }
  const { dataFile: _dataFile, ...mongoOptions } = options;
  void _dataFile;
  return {
    options: {
      ...mongoOptions,
      datastore: 'mongodb',
      database: routing.database,
      collection: routing.vaultCollection,
    },
    profile,
  };
}

function addDatabaseOnlyOptions(command: Command): void {
  command
    .option('--datastore <type>', 'Encrypted datastore: mongodb or file.', 'mongodb')
    .option('--data-file <path>', 'Encrypted local vault file path.')
    .option(
      '--database-url-stdin',
      'Read the MongoDB connection string from standard input (never from an argument).',
    )
    .option('--database <name>', 'MongoDB database name when it is not in the URI.')
    .option('--collection <name>', 'MongoDB collection name.', DEFAULT_COLLECTION);
}

function colorizeHelp(text: string, enabled: boolean): string {
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

function colorizeError(message: string): string {
  if (!process.stderr.isTTY) return message;
  return `${ANSI_RED}error:${ANSI_RESET} ${message}`;
}

function addDatabaseOptions(command: Command): void {
  addDatabaseOnlyOptions(command);
  command.option(
    '--passphrase-stdin',
    'Read the key-file passphrase from standard input (never from an argument).',
  );
}

function addKeyOnlyOptions(command: Command): Command {
  return command
    .option('--key-file <path>', 'Protected portable-key file path.', DEFAULT_KEY_FILE)
    .option('--source <path>', 'Source protected key-file path.')
    .option(
      '--passphrase-stdin',
      'Read the key-file passphrase from standard input (never from an argument).',
    );
}

function addKeyCopyOptions(command: Command): Command {
  return addKeyOnlyOptions(command)
    .option('--output-key-file <path>', 'Destination protected key-file path.')
    .option('--destination <path>', 'Destination protected key-file path.')
    .option('--overwrite', 'Replace an existing destination key file explicitly.')
    .option(
      '--new-passphrase-stdin',
      'Read the destination key-file passphrase from standard input.',
    );
}

function addKeyRewrapOptions(command: Command): Command {
  return addKeyOnlyOptions(command).option(
    '--new-passphrase-stdin',
    'Read the replacement key-file passphrase from standard input.',
  );
}

function addKeyOptions(command: Command): void {
  command.option(
    '--key-file <path>',
    'Protected portable-key file path.',
    DEFAULT_KEY_FILE,
  );
  addVaultOption(command);
}

function addVaultOption(command: Command): void {
  command.option('--vault <id>', 'Opaque vault identifier.', DEFAULT_VAULT_ID);
}

function getOptions(args: readonly unknown[]): LocalCliOptions {
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
    return merged as LocalCliOptions;
  }
  const candidate = args.find((value) => typeof value === 'object' && value !== null);
  if (candidate === undefined) throw new LocalCliError('Command options are invalid.');
  return candidate as LocalCliOptions;
}

function getName(args: readonly unknown[]): string {
  return getArgument(args, 'credential name');
}

function getArgument(args: readonly unknown[], label: string): string {
  const value = args.find((candidate) => typeof candidate === 'string');
  if (value === undefined || value.length === 0) {
    throw new LocalCliError(`A ${label} is required.`);
  }
  return value;
}

function getOptionalName(args: readonly unknown[]): string | undefined {
  const value = args.find((candidate) => typeof candidate === 'string');
  if (value === undefined || value.length === 0) return undefined;
  return value;
}

function getNames(args: readonly unknown[]): readonly [string, string] {
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

function collectOption(value: string, previous: readonly string[]): readonly string[] {
  return [...previous, value];
}

const RECOVERY_KIT_KEYS = [
  'authenticationTag',
  'ciphertext',
  'derivation',
  'format',
  'nonce',
  'recoverySlotId',
  'vaultId',
  'version',
] as const;
const REVISION_ANCHOR_KEYS = [
  'authenticationTag',
  'format',
  'keySlotId',
  'metadataDigest',
  'revision',
  'vaultId',
  'version',
] as const;

async function handleInit(options: LocalCliOptions): Promise<void> {
  await validateSecureFileDestination(options.keyFile);
  await validateSecureFileDestination(revisionAnchorPath(options.keyFile));
  const values = await readSecrets(
    ['database-url', 'passphrase', 'passphrase'],
    options,
  );
  const databaseUrl = requiredSecret(values, 0);
  const firstPassphrase = requiredSecret(values, 1);
  const secondPassphrase = requiredSecret(values, 2);
  if (firstPassphrase !== secondPassphrase) {
    throw new LocalCliError('Passphrases do not match.');
  }
  const passphrase = Buffer.from(firstPassphrase, 'utf8');
  const portableKey = generatePortableKey();
  const rootKey = generateVaultRootKey();
  const createdFiles: string[] = [];
  let operationError: unknown;
  const cleanupFailures: Error[] = [];
  try {
    const document = await createVaultDocument(options.vault, portableKey, rootKey);
    const binding = {
      kind: 'bound' as const,
      vaultId: document.id,
      keySlotId: document.keySlot.id,
    };
    await writePortableKeyFile(options.keyFile, portableKey, binding, {
      mode: 'create',
      protection: { kind: 'passphrase', passphrase },
    });
    createdFiles.push(options.keyFile);
    await withStore(databaseUrl, options, async (store, target) => {
      await store.create(document);
      try {
        await writeRevisionAnchor(
          revisionAnchorPath(options.keyFile),
          rootKey,
          localVaultRevisionAnchor(document),
          'create',
        );
        createdFiles.push(revisionAnchorPath(options.keyFile));
        writeJson({
          vaultId: document.id,
          ...storeLocation(options, target),
          keyFile: options.keyFile,
        });
      } catch (error) {
        try {
          await store.delete(document.id, document.revision);
        } catch (cleanupError) {
          throw new InitializationRollbackError(error, cleanupError);
        }
        throw error;
      }
    });
  } catch (error) {
    operationError = error;
  } finally {
    if (
      operationError !== undefined &&
      !(operationError instanceof InitializationRollbackError)
    ) {
      for (const path of createdFiles.toReversed()) {
        try {
          await deleteSecureFile(path, 16_384);
        } catch (error) {
          cleanupFailures.push(asError(error));
        }
      }
    }
    zeroize(passphrase);
    zeroize(portableKey);
    zeroize(rootKey);
  }
  if (operationError !== undefined && cleanupFailures.length > 0) {
    throw new AggregateError(
      [asError(operationError), ...cleanupFailures],
      'Vault initialization and cleanup failed.',
    );
  }
  if (operationError !== undefined) throw asError(operationError);
  if (cleanupFailures.length > 0) {
    throw new AggregateError(
      cleanupFailures,
      'Vault initialization cleanup was incomplete.',
    );
  }
}

type DestroyInputs = Readonly<{
  databaseUrl: string;
  passphrase: string;
  confirmations?: readonly [string, string];
}>;

async function handleDestroy(options: LocalCliOptions): Promise<void> {
  const datastore = datastoreFrom(options);
  const challenge = randomUUID().replaceAll('-', '').slice(0, 12).toUpperCase();
  let inputs: DestroyInputs;
  if (options.confirmationStdin === true) {
    process.stderr.write(`Destruction challenge: ${challenge}\n`);
    inputs = await readDestroyStdin(options);
  } else {
    if (options.passphraseStdin === true || options.databaseUrlStdin === true) {
      throw new LocalCliError(
        'Destroy stdin secrets require --confirmation-stdin so every frame is read together.',
      );
    }
    const values = await readSecrets(['database-url', 'passphrase'], options);
    inputs = {
      databaseUrl: requiredSecret(values, 0),
      passphrase: requiredSecret(values, 1),
    };
  }

  await withStore(inputs.databaseUrl, options, async (store, target) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, inputs.passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      const additionalArtifacts = await resolveDestroyArtifacts(
        options.artifact ?? [],
        document.id,
        options.keyFile,
      );
      const backendTarget =
        datastore === 'file'
          ? `file ${sanitizeTerminalText(target)}`
          : `MongoDB database ${sanitizeTerminalText(target)}, collection ${sanitizeTerminalText(options.collection)}`;
      process.stderr.write(
        [
          '',
          'Permanent vault destruction requested.',
          `Vault: ${sanitizeTerminalText(document.id)}`,
          `Datastore: ${backendTarget}`,
          `Revision: ${String(document.revision)}`,
          `Encrypted records: ${String(Object.keys(payload.records).length)}`,
          `Active key: ${sanitizeTerminalText(options.keyFile)}`,
          `Revision anchor: ${sanitizeTerminalText(revisionAnchorPath(options.keyFile))}`,
          ...additionalArtifacts.map(
            (path) => `Additional artifact: ${sanitizeTerminalText(path)}`,
          ),
          'Backups, snapshots, and untracked key or recovery copies are not removed.',
          '',
        ].join('\n'),
      );

      const firstExpected = `DESTROY ${document.id}`;
      const first =
        inputs.confirmations?.[0] ??
        (await readVisibleConfirmation(`Type ${firstExpected} to continue: `));
      if (first !== firstExpected) {
        throw new LocalCliError('Vault destruction was cancelled.');
      }

      const current = await requireVault(store, document.id);
      if (
        current.revision !== document.revision ||
        localVaultMetadataDigest(current) !== localVaultMetadataDigest(document)
      ) {
        throw new LocalCliError(
          'The vault changed during destruction confirmation; nothing was deleted.',
        );
      }

      const secondExpected = `DELETE REVISION ${String(document.revision)} ${challenge}`;
      if (options.confirmationStdin !== true) {
        process.stderr.write(`Destruction challenge: ${challenge}\n`);
      }
      const second =
        inputs.confirmations?.[1] ??
        (await readVisibleConfirmation(
          `Type ${secondExpected} to permanently delete: `,
        ));
      if (second !== secondExpected) {
        throw new LocalCliError('Vault destruction was cancelled.');
      }

      await store.delete(document.id, document.revision);
      const failures: Error[] = [];
      for (const path of [
        ...additionalArtifacts,
        revisionAnchorPath(options.keyFile),
        options.keyFile,
      ]) {
        try {
          await deleteSecureFile(path, 16_384);
        } catch (error) {
          failures.push(
            error instanceof Error
              ? error
              : new LocalCliError('A protected vault file could not be deleted.'),
          );
        }
      }
      if (failures.length > 0) {
        throw new AggregateError(
          failures,
          'The encrypted datastore was deleted, but protected local-file cleanup was incomplete.',
        );
      }
      writeJson({
        destroyed: true,
        vaultId: document.id,
        datastore,
        target,
        keyFile: options.keyFile,
        anchorFile: revisionAnchorPath(options.keyFile),
      });
    } finally {
      zeroize(rootKey);
    }
  });
}

async function resolveDestroyArtifacts(
  requestedPaths: readonly string[],
  vaultId: LocalVaultDocument['id'],
  activeKeyFile: string,
): Promise<readonly string[]> {
  const activePaths = new Set([
    await realpath(activeKeyFile),
    await realpath(revisionAnchorPath(activeKeyFile)),
  ]);
  const candidates = new Set(requestedPaths);
  for (const path of requestedPaths) {
    if ((await inspectDestroyArtifact(path, vaultId)) === 'portable-key') {
      const anchorPath = revisionAnchorPath(path);
      if (existsSync(anchorPath)) candidates.add(anchorPath);
    }
  }
  const resolved: string[] = [];
  const seen = new Set<string>();
  for (const path of candidates) {
    await inspectDestroyArtifact(path, vaultId);
    const canonicalPath = await realpath(path);
    if (!activePaths.has(canonicalPath) && !seen.has(canonicalPath)) {
      seen.add(canonicalPath);
      resolved.push(canonicalPath);
    }
  }
  return resolved;
}

async function inspectDestroyArtifact(
  path: string,
  expectedVaultId: LocalVaultDocument['id'],
): Promise<'portable-key' | 'recovery-kit' | 'revision-anchor'> {
  const contents = await readSecureFile(path, 16_384);
  try {
    const text = contents.toString('utf8');
    const lines = text.endsWith('\n') ? text.slice(0, -1).split('\n') : [];
    if (lines[0] === '-----BEGIN CREDVAULT PORTABLE KEY-----') {
      const validLength = lines.length === 7 || lines.length === 17;
      const validEnd = lines.at(-1) === '-----END CREDVAULT PORTABLE KEY-----';
      const vaultLine = lines[3];
      const validHeaders =
        lines[1] === 'Version: 1' &&
        lines[2] === 'Binding: bound' &&
        lines[4]?.startsWith('Key-ID: ') === true;
      if (
        !validLength ||
        !validEnd ||
        !validHeaders ||
        vaultLine !== `Vault-ID: ${expectedVaultId}`
      ) {
        throw new LocalCliError('An additional destruction artifact is invalid.');
      }
      return 'portable-key';
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      throw new LocalCliError('An additional destruction artifact is invalid.');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new LocalCliError('An additional destruction artifact is invalid.');
    }
    const record = parsed as Record<string, unknown>;
    if (vaultIdSchema.parse(record['vaultId']) !== expectedVaultId) {
      throw new LocalCliError(
        'An additional destruction artifact belongs to another vault.',
      );
    }
    if (
      record['format'] === 'kavrix-recovery-kit' &&
      record['version'] === 1 &&
      hasExactKeys(record, RECOVERY_KIT_KEYS)
    ) {
      return 'recovery-kit';
    }
    if (
      record['format'] === 'kavrix-revision-anchor' &&
      record['version'] === 1 &&
      hasExactKeys(record, REVISION_ANCHOR_KEYS)
    ) {
      return 'revision-anchor';
    }
    throw new LocalCliError('An additional destruction artifact is invalid.');
  } catch (error) {
    if (error instanceof LocalCliError) throw error;
    throw new LocalCliError('An additional destruction artifact is invalid.');
  } finally {
    contents.fill(0);
  }
}

function hasExactKeys(
  record: Readonly<Record<string, unknown>>,
  expectedKeys: readonly string[],
): boolean {
  const actualKeys = Object.keys(record).toSorted();
  return (
    actualKeys.length === expectedKeys.length &&
    actualKeys.every((key, index) => key === expectedKeys[index])
  );
}

async function readDestroyStdin(options: LocalCliOptions): Promise<DestroyInputs> {
  const datastore = datastoreFrom(options);
  if (datastore === 'file') {
    await FileLocalVaultStore.validatePath(options.dataFile ?? DEFAULT_DATA_FILE);
  }
  if (
    options.passphraseStdin !== true ||
    (datastore === 'mongodb' && options.databaseUrlStdin !== true)
  ) {
    throw new LocalCliError(
      'Destroy with --confirmation-stdin requires stdin flags for every secret.',
    );
  }
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    for await (const chunk of process.stdin) {
      const owned = Buffer.from(chunk as Uint8Array);
      length += owned.byteLength;
      if (length > 2_100_000) {
        owned.fill(0);
        throw new LocalCliError('Destroy input exceeds the supported size.');
      }
      chunks.push(owned);
    }
    const joined = Buffer.concat(chunks, length);
    try {
      const frames = joined.toString('utf8').replace(/\r\n/gu, '\n').split('\n');
      if (frames.at(-1) === '') frames.pop();
      const secretCount = datastore === 'mongodb' ? 2 : 1;
      if (frames.length !== secretCount + 2) {
        throw new LocalCliError('Destroy input contains the wrong number of values.');
      }
      const secretKinds: LocalSecretKind[] =
        datastore === 'mongodb' ? ['database-url', 'passphrase'] : ['passphrase'];
      const secretText = frames.slice(0, secretCount).join('\n') + '\n';
      const validated = await new LocalSecretInput(
        Readable.from([secretText]),
        process.stderr,
      ).read(secretKinds, true);
      const first = frames[secretCount];
      const second = frames[secretCount + 1];
      if (first === undefined || second === undefined) {
        throw new LocalCliError('Destroy confirmations are incomplete.');
      }
      return {
        databaseUrl: datastore === 'mongodb' ? requiredSecret(validated, 0) : '',
        passphrase: requiredSecret(validated, datastore === 'mongodb' ? 1 : 0),
        confirmations: [first, second],
      };
    } finally {
      joined.fill(0);
    }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

async function readVisibleConfirmation(prompt: string): Promise<string> {
  if (!process.stdin.isTTY || !process.stderr.isTTY) {
    throw new LocalCliError(
      'Destruction confirmation requires a terminal or --confirmation-stdin.',
    );
  }
  const interface_ = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const value = await interface_.question(prompt);
    if (Buffer.byteLength(value, 'utf8') > 512 || /[\r\n\0]/u.test(value)) {
      throw new LocalCliError('Destruction confirmation is invalid.');
    }
    return value;
  } finally {
    interface_.close();
  }
}

async function handlePing(
  options: LocalCliOptions,
  overrides: DatastoreProfileRoutingOverrides & Readonly<{ collection?: string }> = {},
): Promise<void> {
  const resolved = await resolveProfileForPing(options, overrides);
  if (datastoreFrom(resolved.options) !== 'mongodb') {
    throw new LocalCliError('db ping supports only the MongoDB datastore.');
  }
  const values = await readSecrets(['database-url'], resolved.options);
  const databaseUrl = requiredSecret(values, 0);
  await withStore(databaseUrl, resolved.options, async (store, target) => {
    await store.ping();
    writeJson({
      connected: true,
      ...(resolved.profile === null
        ? {}
        : { profile: sanitizeTerminalText(resolved.profile.id) }),
      ...storeLocation(resolved.options, target),
    });
  });
}

async function handlePut(name: string, options: LocalCliOptions): Promise<void> {
  validateCredentialName(name);
  const values = await readSecrets(
    ['database-url', 'passphrase', 'field-value'],
    options,
  );
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  const value = requiredSecret(values, 2);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      if (Object.hasOwn(payload.records, name) && options.overwrite !== true) {
        throw new LocalCliError(
          'Credential already exists. Re-run with --overwrite to replace it.',
        );
      }
      payload.records[name] = {
        value,
        updatedAt: now(),
      };
      const updated = await encryptUpdatedDocument(document, payload, rootKey);
      await persistUpdatedDocument(
        store,
        updated,
        document.revision,
        options.keyFile,
        rootKey,
      );
      writeJson({ saved: true, name, revision: updated.revision });
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleGet(name: string, options: LocalCliOptions): Promise<void> {
  validateCredentialName(name);
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      const record = payload.records[name];
      if (record === undefined) throw new LocalCliError('Credential was not found.');
      if (options.reveal === true) {
        const value = process.stdout.isTTY
          ? sanitizeTerminalText(record.value)
          : record.value;
        process.stdout.write(value + '\n');
      } else {
        writeJson({ name, value: REDACTED, revision: document.revision });
      }
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleList(options: LocalCliOptions): Promise<void> {
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      writeJson({
        revision: document.revision,
        names: Object.keys(payload.records).sort((left, right) =>
          left.localeCompare(right),
        ),
      });
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleView(
  name: string | undefined,
  options: LocalCliOptions,
): Promise<void> {
  if (name !== undefined) validateCredentialName(name);
  if (options.reveal === true && name === undefined) {
    throw new LocalCliError('Choose one credential before using view --reveal.');
  }
  if (options.reveal === true && options.json === true) {
    throw new LocalCliError('view --reveal cannot be combined with --json.');
  }
  if (options.reveal === true && !process.stdout.isTTY) {
    throw new LocalCliError(
      'view --reveal requires an interactive terminal; use get --reveal for explicit scripted output.',
    );
  }
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      const entries = Object.entries(payload.records)
        .filter(([credentialName]) => name === undefined || credentialName === name)
        .sort(([left], [right]) => left.localeCompare(right));
      if (name !== undefined && entries.length === 0) {
        throw new LocalCliError('Credential was not found.');
      }
      if (options.json === true || !process.stdout.isTTY) {
        writeJson({
          vaultId: document.id,
          revision: document.revision,
          count: entries.length,
          records: entries.map(([credentialName, record]) => ({
            name: credentialName,
            updatedAt: record.updatedAt,
            value: REDACTED,
          })),
        });
        return;
      }
      process.stdout.write(renderVaultView(document, entries, options.reveal === true));
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleSearch(term: string, options: LocalCliOptions): Promise<void> {
  const normalizedTerm = term.trim().toLocaleLowerCase();
  if (normalizedTerm.length === 0)
    throw new LocalCliError('A search pattern is required.');
  if (normalizedTerm.length > 128) {
    throw new LocalCliError('Search patterns are limited to 128 characters.');
  }
  const limit = parseLimit(options.limit);
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      const matches = Object.entries(payload.records)
        .filter(([name]) => name.toLocaleLowerCase().includes(normalizedTerm))
        .sort(([left], [right]) => left.localeCompare(right));
      const result = {
        vaultId: document.id,
        revision: document.revision,
        pattern: term,
        count: matches.length,
        truncated: matches.length > limit,
        matches: matches.slice(0, limit).map(([name, record]) => ({
          name,
          updatedAt: record.updatedAt,
        })),
      };
      if (options.json === true || !process.stdout.isTTY) {
        writeJson(result);
        return;
      }
      process.stdout.write(renderSearchResult(result));
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleStats(options: LocalCliOptions): Promise<void> {
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      const timestamps = Object.values(payload.records)
        .map((record) => record.updatedAt)
        .sort();
      const result = {
        vaultId: document.id,
        revision: document.revision,
        currentKeyVersion: document.currentKeyVersion,
        credentialCount: timestamps.length,
        oldestCredentialAt: timestamps[0] ?? null,
        newestCredentialAt: timestamps.at(-1) ?? null,
        updatedAt: document.updatedAt,
      };
      if (options.json === true || !process.stdout.isTTY) {
        writeJson(result);
        return;
      }
      process.stdout.write(renderVaultStats(result));
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleRemove(name: string, options: LocalCliOptions): Promise<void> {
  validateCredentialName(name);
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      if (payload.records[name] === undefined) {
        throw new LocalCliError('Credential was not found.');
      }
      const updatedPayload = localVaultPayloadSchema.parse({
        records: Object.fromEntries(
          Object.entries(payload.records).filter(([key]) => key !== name),
        ),
      });
      const updated = await encryptUpdatedDocument(document, updatedPayload, rootKey);
      await persistUpdatedDocument(
        store,
        updated,
        document.revision,
        options.keyFile,
        rootKey,
      );
      writeJson({ removed: true, name, revision: updated.revision });
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleHas(name: string, options: LocalCliOptions): Promise<void> {
  validateCredentialName(name);
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      writeJson({
        exists: Object.hasOwn(payload.records, name),
        name,
        revision: document.revision,
      });
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleRename(
  from: string,
  to: string,
  options: LocalCliOptions,
): Promise<void> {
  validateCredentialName(from);
  validateCredentialName(to);
  if (from === to) throw new LocalCliError('Credential names must be different.');
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      const source = payload.records[from];
      if (source === undefined) throw new LocalCliError('Credential was not found.');
      if (Object.hasOwn(payload.records, to)) {
        throw new LocalCliError('The destination credential already exists.');
      }
      const records = Object.fromEntries(
        Object.entries(payload.records).flatMap(([key, record]) =>
          key === from ? [[to, record]] : [[key, record]],
        ),
      );
      const updatedPayload = localVaultPayloadSchema.parse({ records });
      const updated = await encryptUpdatedDocument(document, updatedPayload, rootKey);
      await persistUpdatedDocument(
        store,
        updated,
        document.revision,
        options.keyFile,
        rootKey,
      );
      writeJson({ renamed: true, from, to, revision: updated.revision });
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleDoctor(options: LocalCliOptions): Promise<void> {
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store, target) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const payload = await decryptVaultPayload(document, rootKey);
      writeJson({
        healthy: true,
        vaultId: document.id,
        ...storeLocation(options, target),
        revision: document.revision,
        credentialCount: Object.keys(payload.records).length,
      });
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleDoctorHealth(options: LocalCliOptions): Promise<void> {
  type HealthStatus = 'ok' | 'warning' | 'manual-recovery';
  interface HealthCheck {
    name: string;
    status: HealthStatus;
    detail: string;
    revision?: number;
    credentialCount?: number;
    activeRecoverySlots?: number;
    revokedRecoverySlots?: number;
  }

  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  const checks: HealthCheck[] = [];
  const autoHealed: string[] = [];
  const manualRecoveryRequired: string[] = [];
  let storeTarget: string | undefined;
  const datastore = datastoreFrom(options);

  const addManualRecovery = (name: string, detail: string): void => {
    checks.push({ name, status: 'manual-recovery', detail });
    manualRecoveryRequired.push(detail);
  };

  try {
    await withStore(databaseUrl, options, async (store, connectedTarget) => {
      storeTarget = connectedTarget;

      let retried = false;
      try {
        await store.ping();
      } catch {
        try {
          await store.ping();
          retried = true;
          autoHealed.push('datastore-retry');
        } catch {
          addManualRecovery(
            'database',
            'The encrypted datastore is unavailable or failed its health check.',
          );
          return;
        }
      }
      checks.push({
        name: 'database',
        status: 'ok',
        detail: retried
          ? 'The encrypted datastore recovered after one bounded retry.'
          : 'The encrypted datastore is available.',
      });

      let document: Awaited<ReturnType<typeof requireVault>>;
      try {
        document = await requireVault(store, options.vault);
      } catch {
        addManualRecovery(
          'vault-document',
          'The vault document is missing or invalid.',
        );
        return;
      }
      checks.push({
        name: 'vault-document',
        status: 'ok',
        detail:
          'The vault schema, revision, and authenticated metadata binding are valid.',
        revision: document.revision,
      });

      let rootKey: Awaited<ReturnType<typeof unlockVault>> | undefined;
      try {
        rootKey = await unlockVault(document, options.keyFile, passphrase, {
          acceptCurrent: options.acceptCurrent === true,
          onAnchorUpdated: (kind) => {
            autoHealed.push(
              kind === 'initialized'
                ? 'revision-anchor-initialized'
                : 'revision-anchor-advanced',
            );
          },
        });
      } catch (error) {
        const detail =
          error instanceof LocalCliError && error.message.includes('rollback')
            ? 'The trusted local revision anchor rejected this database snapshot as a rollback or fork.'
            : error instanceof LocalCliError &&
                error.message.includes('revision anchor')
              ? 'The trusted local revision anchor is missing or invalid.'
              : 'The portable key could not be authenticated.';
        addManualRecovery('portable-key', detail);
        return;
      }
      checks.push({
        name: 'portable-key',
        status: 'ok',
        detail: 'The protected portable key is readable and bound to this vault.',
      });
      checks.push({
        name: 'revision-anchor',
        status: 'ok',
        detail:
          'The trusted local revision anchor matches the authenticated vault snapshot.',
      });

      try {
        const payload = await decryptVaultPayload(document, rootKey);
        const activeRecoverySlots = document.recoverySlots.filter(
          (slot) => slot.state === 'active',
        ).length;
        const revokedRecoverySlots = document.recoverySlots.filter(
          (slot) => slot.state === 'revoked',
        ).length;
        checks.push({
          name: 'encrypted-payload',
          status: 'ok',
          detail:
            'The encrypted payload passed authenticated decryption and schema validation.',
          credentialCount: Object.keys(payload.records).length,
        });
        checks.push({
          name: 'recovery-slots',
          status: activeRecoverySlots > 0 ? 'ok' : 'warning',
          detail:
            activeRecoverySlots > 0
              ? 'At least one recovery slot is active.'
              : 'No active recovery slot is configured; create one manually before losing the key.',
          activeRecoverySlots,
          revokedRecoverySlots,
        });
        if (activeRecoverySlots === 0) {
          manualRecoveryRequired.push(
            'No active recovery slot is available; create a new recovery kit manually.',
          );
        }
      } catch {
        addManualRecovery(
          'encrypted-payload',
          'Authenticated payload decryption or metadata validation failed.',
        );
      } finally {
        zeroize(rootKey);
      }
    });
  } catch {
    if (!checks.some((check) => check.name === 'database')) {
      addManualRecovery(
        'database',
        'The encrypted datastore could not be opened safely.',
      );
    }
  }

  const healthy =
    manualRecoveryRequired.length === 0 &&
    checks.every((check) => check.status === 'ok');
  const result: Record<string, unknown> = {
    healthy,
    autoHealed,
    checks,
    manualRecoveryRequired,
  };
  if (storeTarget !== undefined) {
    Object.assign(result, storeLocation({ ...options, datastore }, storeTarget));
  }
  writeJson(result);
}

async function handleRecoveryCreate(options: LocalCliOptions): Promise<void> {
  const recoveryFile = requiredOption(options.recoveryFile, '--recovery-file');
  if (options.overwrite === true) {
    throw new LocalCliError(
      'Recovery kits cannot be overwritten. Choose a new --recovery-file path.',
    );
  }
  const values = await readSecrets(
    ['database-url', 'passphrase', 'recovery-passphrase'],
    options,
  );
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  const recoveryPassphrase = requiredSecret(values, 2);
  if (passphrase === recoveryPassphrase) {
    throw new LocalCliError('Use a different passphrase for the recovery kit.');
  }
  const recoveryPassphraseBytes = Buffer.from(recoveryPassphrase, 'utf8');
  let recoveryKey: ReturnType<typeof generateRecoveryKey> | undefined;
  let verifiedRecoveryKey: Awaited<ReturnType<typeof readRecoveryKitFile>> | undefined;
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      if (document.recoverySlots.length >= MAX_LOCAL_RECOVERY_SLOTS) {
        throw new LocalCliError(
          `The vault can contain at most ${String(MAX_LOCAL_RECOVERY_SLOTS)} recovery kits.`,
        );
      }
      recoveryKey = generateRecoveryKey();
      const slot = await createRecoveryKeySlot(
        {
          vaultId: document.id,
          slotId: keySlotIdSchema.parse(randomUUID()),
          schemaVersion: document.schemaVersion,
          keyVersion: document.currentKeyVersion,
          createdAt: now(),
        },
        recoveryKey,
        rootKey,
      );
      const binding = { vaultId: document.id, recoverySlotId: slot.id };
      const payload = await decryptVaultPayload(document, rootKey);
      await writeRecoveryKitFile(
        recoveryFile,
        recoveryKey,
        recoveryPassphraseBytes,
        binding,
        'create',
      );
      verifiedRecoveryKey = await readRecoveryKitFile(
        recoveryFile,
        recoveryPassphraseBytes,
        binding,
      );
      zeroize(verifiedRecoveryKey.recoveryKey);
      const updated = await encryptDocumentPayload(document, payload, rootKey, {
        version: CURRENT_LOCAL_VAULT_VERSION,
        recoverySlots: [...document.recoverySlots, slot],
      });
      await persistUpdatedDocument(
        store,
        updated,
        document.revision,
        options.keyFile,
        rootKey,
      );
      writeJson({
        recoveryKitCreated: true,
        vaultId: document.id,
        recoveryFile,
        recoverySlotId: slot.id,
        revision: updated.revision,
      });
    } finally {
      zeroize(rootKey);
      zeroize(verifiedRecoveryKey?.recoveryKey);
      zeroize(recoveryKey);
      zeroize(recoveryPassphraseBytes);
    }
  });
}

async function handleRecoveryStatus(options: LocalCliOptions): Promise<void> {
  const values = await readSecrets(['database-url'], options);
  const databaseUrl = requiredSecret(values, 0);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const result = {
      vaultId: document.id,
      revision: document.revision,
      currentKeyVersion: document.currentKeyVersion,
      totalKits: document.recoverySlots.length,
      activeKits: document.recoverySlots.filter((slot) => slot.state === 'active')
        .length,
      revokedKits: document.recoverySlots.filter((slot) => slot.state === 'revoked')
        .length,
      slots: document.recoverySlots.map((slot) => ({
        id: slot.id,
        state: slot.state,
        createdAt: slot.createdAt,
        revokedAt: slot.revokedAt ?? null,
      })),
    };
    if (options.json === true || !process.stdout.isTTY) {
      writeJson(result);
      return;
    }
    writeRecoveryStatus(result);
  });
}

async function handleRecoveryRevoke(
  slotIdValue: string,
  options: LocalCliOptions,
): Promise<void> {
  let slotId: ReturnType<typeof keySlotIdSchema.parse>;
  try {
    slotId = keySlotIdSchema.parse(slotIdValue);
  } catch {
    throw new LocalCliError('Recovery slot ID is invalid.');
  }
  const values = await readSecrets(['database-url', 'passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const passphrase = requiredSecret(values, 1);
  await withStore(databaseUrl, options, async (store) => {
    const document = await requireVault(store, options.vault);
    const rootKey = await unlockVault(document, options.keyFile, passphrase);
    try {
      const target = document.recoverySlots.find((slot) => slot.id === slotId);
      if (target?.state !== 'active') {
        throw new LocalCliError('Recovery kit was not found or is already revoked.');
      }
      const activeCount = document.recoverySlots.filter(
        (slot) => slot.state === 'active',
      ).length;
      if (activeCount <= 1) {
        throw new LocalCliError(
          'Create a replacement recovery kit before revoking the last active kit.',
        );
      }
      const payload = await decryptVaultPayload(document, rootKey);
      const updated = await encryptDocumentPayload(document, payload, rootKey, {
        recoverySlots: document.recoverySlots.map((slot) =>
          slot.id === slotId
            ? { ...slot, state: 'revoked' as const, revokedAt: now() }
            : slot,
        ),
      });
      await persistUpdatedDocument(
        store,
        updated,
        document.revision,
        options.keyFile,
        rootKey,
      );
      writeJson({
        revoked: true,
        vaultId: document.id,
        slotId,
        revision: updated.revision,
      });
    } finally {
      zeroize(rootKey);
    }
  });
}

async function handleRecoveryVerify(options: LocalCliOptions): Promise<void> {
  const recoveryFile = requiredOption(options.recoveryFile, '--recovery-file');
  const values = await readSecrets(['database-url', 'recovery-passphrase'], options);
  const databaseUrl = requiredSecret(values, 0);
  const recoveryPassphrase = requiredSecret(values, 1);
  const recoveryPassphraseBytes = Buffer.from(recoveryPassphrase, 'utf8');
  let kit: Awaited<ReturnType<typeof readRecoveryKitFile>> | undefined;
  let rootKey: VaultRootKey | undefined;
  try {
    await withStore(databaseUrl, options, async (store) => {
      const document = await requireVault(store, options.vault);
      const parsedKit = await readRecoveryKitFile(
        recoveryFile,
        recoveryPassphraseBytes,
      );
      kit = parsedKit;
      const slot = document.recoverySlots.find(
        (candidate): candidate is LocalRecoveryKeySlot =>
          candidate.state === 'active' && candidate.id === parsedKit.recoverySlotId,
      );
      if (slot === undefined || parsedKit.vaultId !== document.id) {
        zeroize(parsedKit.recoveryKey);
        throw new LocalCliError('Recovery verification failed.');
      }
      rootKey = await unlockRecoveryKeySlotBytes(slot, parsedKit.recoveryKey, {
        vaultId: document.id,
        slotId: slot.id,
        schemaVersion: document.schemaVersion,
        keyVersion: document.currentKeyVersion,
      });
      await requireCurrentRevisionAnchor(document, rootKey, options.keyFile);
      const payload = await decryptVaultPayload(document, rootKey);
      writeJson({
        valid: true,
        vaultId: document.id,
        recoverySlotId: slot.id,
        revision: document.revision,
        currentKeyVersion: document.currentKeyVersion,
        credentialCount: Object.keys(payload.records).length,
      });
    });
  } finally {
    zeroize(kit?.recoveryKey);
    zeroize(rootKey);
    zeroize(recoveryPassphraseBytes);
  }
}

async function handleRecoveryUse(options: LocalCliOptions): Promise<void> {
  const recoveryFile = requiredOption(options.recoveryFile, '--recovery-file');
  const outputRecoveryFile = requiredOption(
    options.outputRecoveryFile,
    '--output-recovery-file',
  );
  const destination = requiredOption(
    options.outputKeyFile ?? options.destination,
    '--destination',
  );
  if (options.overwrite === true) {
    throw new LocalCliError(
      'Recovery outputs cannot be overwritten. Choose new destination paths.',
    );
  }
  if (destination === recoveryFile || destination === outputRecoveryFile) {
    throw new LocalCliError('Recovery-kit and key-file paths must be different.');
  }
  if (recoveryFile === outputRecoveryFile) {
    throw new LocalCliError(
      'The source and destination recovery-kit paths must be different.',
    );
  }
  const values = await readSecrets(
    ['database-url', 'recovery-passphrase', 'new-passphrase', 'new-passphrase'],
    options,
  );
  const databaseUrl = requiredSecret(values, 0);
  const recoveryPassphrase = requiredSecret(values, 1);
  const firstPassphrase = requiredSecret(values, 2);
  const secondPassphrase = requiredSecret(values, 3);
  if (firstPassphrase !== secondPassphrase) {
    throw new LocalCliError('New passphrases do not match.');
  }
  if (recoveryPassphrase === firstPassphrase) {
    throw new LocalCliError('Use a different passphrase for the recovered key file.');
  }
  const recoveryPassphraseBytes = Buffer.from(recoveryPassphrase, 'utf8');
  const passphraseBytes = Buffer.from(firstPassphrase, 'utf8');
  let portableKey: ReturnType<typeof generatePortableKey> | undefined;
  let newRootKey: VaultRootKey | undefined;
  let recoveredRootKey: VaultRootKey | undefined;
  let verifiedKey: Awaited<ReturnType<typeof readPortableKeyFile>> | undefined;
  let verifiedRecoveryKey: Awaited<ReturnType<typeof readRecoveryKitFile>> | undefined;
  let recoveryKey: ReturnType<typeof generateRecoveryKey> | undefined;
  try {
    await withStore(databaseUrl, options, async (store) => {
      const document = await requireVault(store, options.vault);
      const kit = await readRecoveryKitFile(recoveryFile, recoveryPassphraseBytes);
      const matchedSlot = document.recoverySlots.find(
        (slot): slot is LocalRecoveryKeySlot =>
          slot.state === 'active' && slot.id === kit.recoverySlotId,
      );
      if (matchedSlot === undefined || kit.vaultId !== document.id) {
        zeroize(kit.recoveryKey);
        throw new LocalCliError('Recovery authorization failed.');
      }
      recoveredRootKey = await unlockRecoveryKeySlotBytes(
        matchedSlot,
        kit.recoveryKey,
        {
          vaultId: document.id,
          slotId: matchedSlot.id,
          schemaVersion: document.schemaVersion,
          keyVersion: document.currentKeyVersion,
        },
      );
      await requireCurrentRevisionAnchor(document, recoveredRootKey, options.keyFile);
      zeroize(kit.recoveryKey);
      const payload = await decryptVaultPayload(document, recoveredRootKey);
      newRootKey = generateVaultRootKey();
      portableKey = generatePortableKey();
      recoveryKey = generateRecoveryKey();
      const newKeyVersion = keyVersionSchema.parse(document.currentKeyVersion + 1);
      const newSlot = await createPortableKeySlot(
        {
          vaultId: document.id,
          slotId: keySlotIdSchema.parse(randomUUID()),
          schemaVersion: document.schemaVersion,
          keyVersion: newKeyVersion,
          createdAt: now(),
        },
        portableKey,
        newRootKey,
      );
      const newRecoverySlot = await createRecoveryKeySlot(
        {
          vaultId: document.id,
          slotId: keySlotIdSchema.parse(randomUUID()),
          schemaVersion: document.schemaVersion,
          keyVersion: newKeyVersion,
          createdAt: now(),
        },
        recoveryKey,
        newRootKey,
      );
      const recoveryBinding = {
        vaultId: document.id,
        recoverySlotId: newRecoverySlot.id,
      };
      await writeRecoveryKitFile(
        outputRecoveryFile,
        recoveryKey,
        recoveryPassphraseBytes,
        recoveryBinding,
        'create',
      );
      const binding = {
        kind: 'bound' as const,
        vaultId: document.id,
        keySlotId: newSlot.id,
      };
      await writePortableKeyFile(destination, portableKey, binding, {
        mode: 'create',
        protection: { kind: 'passphrase', passphrase: passphraseBytes },
      });
      verifiedKey = await readPortableKeyFile(
        destination,
        { kind: 'passphrase', passphrase: passphraseBytes },
        binding,
      );
      const verifiedPortableRootKey = await unlockPortableKeySlotBytes(
        newSlot,
        verifiedKey.key,
        {
          vaultId: document.id,
          slotId: newSlot.id,
          schemaVersion: document.schemaVersion,
          keyVersion: newKeyVersion,
        },
      );
      zeroize(verifiedPortableRootKey);
      verifiedRecoveryKey = await readRecoveryKitFile(
        outputRecoveryFile,
        recoveryPassphraseBytes,
        recoveryBinding,
      );
      const verifiedRecoveryRootKey = await unlockRecoveryKeySlotBytes(
        newRecoverySlot,
        verifiedRecoveryKey.recoveryKey,
        {
          vaultId: document.id,
          slotId: newRecoverySlot.id,
          schemaVersion: document.schemaVersion,
          keyVersion: newKeyVersion,
        },
      );
      zeroize(verifiedRecoveryRootKey);
      zeroize(verifiedRecoveryKey.recoveryKey);
      const updated = await encryptDocumentPayload(document, payload, newRootKey, {
        version: CURRENT_LOCAL_VAULT_VERSION,
        keySlot: newSlot,
        recoverySlots: [newRecoverySlot],
        currentKeyVersion: newKeyVersion,
      });
      await persistUpdatedDocument(
        store,
        updated,
        document.revision,
        destination,
        newRootKey,
        'create',
      );
      writeJson({
        recovered: true,
        vaultId: document.id,
        keyFile: destination,
        recoveryFile: outputRecoveryFile,
        keyVersion: updated.currentKeyVersion,
        revision: updated.revision,
      });
    });
  } finally {
    zeroize(verifiedRecoveryKey?.recoveryKey);
    zeroize(recoveryKey);
    zeroize(newRootKey);
    zeroize(verifiedKey?.key);
    zeroize(portableKey);
    zeroize(recoveredRootKey);
    zeroize(recoveryPassphraseBytes);
    zeroize(passphraseBytes);
  }
}

async function handleVaultList(options: LocalCliOptions): Promise<void> {
  const values = await readSecrets(['database-url'], options);
  const databaseUrl = requiredSecret(values, 0);
  await withStore(databaseUrl, options, async (store, target) => {
    const vaults = await store.listVaultIds();
    writeJson({ ...storeLocation(options, target), vaults });
  });
}

async function handleVaultStatus(options: LocalCliOptions): Promise<void> {
  const values = await readSecrets(['database-url'], options);
  const databaseUrl = requiredSecret(values, 0);
  await withStore(databaseUrl, options, async (store, target) => {
    const document = await requireVault(store, options.vault);
    writeJson({
      ...storeLocation(options, target),
      vaultId: document.id,
      revision: document.revision,
      currentKeyVersion: document.currentKeyVersion,
      keySlot: {
        id: document.keySlot.id,
        type: document.keySlot.type,
        state: document.keySlot.state,
        keyVersion: document.keySlot.keyVersion,
        createdAt: document.keySlot.createdAt,
      },
      recoverySlots: {
        total: document.recoverySlots.length,
        active: document.recoverySlots.filter((slot) => slot.state === 'active').length,
        revoked: document.recoverySlots.filter((slot) => slot.state === 'revoked')
          .length,
      },
      createdAt: document.createdAt,
      updatedAt: document.updatedAt,
    });
  });
}

async function handleKeyStatus(options: LocalCliOptions): Promise<void> {
  const keyFile = options.source ?? options.keyFile;
  const values = await readSecrets(['passphrase'], options);
  const passphrase = requiredSecret(values, 0);
  const passphraseBytes = Buffer.from(passphrase, 'utf8');
  let parsed: Awaited<ReturnType<typeof readPortableKeyFile>> | undefined;
  try {
    parsed = await readPortableKeyFile(keyFile, {
      kind: 'passphrase',
      passphrase: passphraseBytes,
    });
    writeJson({
      keyFile,
      protected: parsed.protected,
      binding:
        parsed.kind === 'bound'
          ? { kind: parsed.kind, vaultId: parsed.vaultId, keySlotId: parsed.keySlotId }
          : { kind: parsed.kind },
    });
  } finally {
    zeroize(parsed?.key);
    zeroize(passphraseBytes);
  }
}

async function handleKeyCopy(options: LocalCliOptions): Promise<void> {
  const sourceKeyFile = options.source ?? options.keyFile;
  const outputKeyFile = requiredOption(
    options.outputKeyFile ?? options.destination,
    '--destination',
  );
  const values = await readSecrets(
    ['passphrase', 'new-passphrase', 'new-passphrase'],
    options,
  );
  const sourcePassphrase = requiredSecret(values, 0);
  const newPassphrase = requiredSecret(values, 1);
  const confirmation = requiredSecret(values, 2);
  if (newPassphrase !== confirmation) {
    throw new LocalCliError('New passphrases do not match.');
  }
  const sourcePassphraseBytes = Buffer.from(sourcePassphrase, 'utf8');
  const newPassphraseBytes = Buffer.from(newPassphrase, 'utf8');
  let parsed: Awaited<ReturnType<typeof readPortableKeyFile>> | undefined;
  try {
    parsed = await readPortableKeyFile(sourceKeyFile, {
      kind: 'passphrase',
      passphrase: sourcePassphraseBytes,
    });
    const binding =
      parsed.kind === 'bound'
        ? { kind: parsed.kind, vaultId: parsed.vaultId, keySlotId: parsed.keySlotId }
        : { kind: parsed.kind };
    if (parsed.kind === 'bound') {
      await validateRevisionAnchorFile(revisionAnchorPath(sourceKeyFile));
    }
    await writePortableKeyFile(outputKeyFile, parsed.key, binding, {
      mode: options.overwrite === true ? 'replace' : 'create',
      protection: { kind: 'passphrase', passphrase: newPassphraseBytes },
    });
    if (parsed.kind === 'bound') {
      await copyRevisionAnchor(
        revisionAnchorPath(sourceKeyFile),
        revisionAnchorPath(outputKeyFile),
        options.overwrite === true ? 'replace' : 'create',
      );
    }
    const verified = await readPortableKeyFile(
      outputKeyFile,
      { kind: 'passphrase', passphrase: newPassphraseBytes },
      binding,
    );
    zeroize(verified.key);
    writeJson({ copied: true, source: sourceKeyFile, destination: outputKeyFile });
  } finally {
    zeroize(parsed?.key);
    zeroize(sourcePassphraseBytes);
    zeroize(newPassphraseBytes);
  }
}

async function handleKeyRewrap(options: LocalCliOptions): Promise<void> {
  const keyFile = options.source ?? options.keyFile;
  const values = await readSecrets(
    ['passphrase', 'new-passphrase', 'new-passphrase'],
    options,
  );
  const sourcePassphrase = requiredSecret(values, 0);
  const newPassphrase = requiredSecret(values, 1);
  const confirmation = requiredSecret(values, 2);
  if (newPassphrase !== confirmation) {
    throw new LocalCliError('New passphrases do not match.');
  }
  const sourcePassphraseBytes = Buffer.from(sourcePassphrase, 'utf8');
  const newPassphraseBytes = Buffer.from(newPassphrase, 'utf8');
  let parsed: Awaited<ReturnType<typeof readPortableKeyFile>> | undefined;
  try {
    parsed = await readPortableKeyFile(keyFile, {
      kind: 'passphrase',
      passphrase: sourcePassphraseBytes,
    });
    const binding =
      parsed.kind === 'bound'
        ? { kind: parsed.kind, vaultId: parsed.vaultId, keySlotId: parsed.keySlotId }
        : { kind: parsed.kind };
    await writePortableKeyFile(keyFile, parsed.key, binding, {
      mode: 'replace',
      protection: { kind: 'passphrase', passphrase: newPassphraseBytes },
    });
    const verified = await readPortableKeyFile(
      keyFile,
      { kind: 'passphrase', passphrase: newPassphraseBytes },
      binding,
    );
    zeroize(verified.key);
    writeJson({ rewrapped: true, keyFile });
  } finally {
    zeroize(parsed?.key);
    zeroize(sourcePassphraseBytes);
    zeroize(newPassphraseBytes);
  }
}

async function createVaultDocument(
  vaultValue: string,
  portableKey: Uint8Array,
  rootKey: VaultRootKey,
): Promise<LocalVaultDocument> {
  const id = vaultIdSchema.parse(vaultValue);
  const schemaVersion = supportedSchemaVersionSchema.parse(CURRENT_SCHEMA_VERSION);
  const cryptographicVersion = supportedCryptographicVersionSchema.parse(
    CURRENT_CRYPTOGRAPHIC_VERSION,
  );
  const keyVersion = keyVersionSchema.parse(1);
  const createdAt = now();
  const keySlot = await createPortableKeySlot(
    {
      vaultId: id,
      slotId: keySlotIdSchema.parse(randomUUID()),
      schemaVersion,
      keyVersion,
      createdAt,
    },
    portableKey,
    rootKey,
  );
  const payload = localVaultPayloadSchema.parse({ records: {} });
  const revision = vaultRevisionSchema.parse(0);
  const metadata = {
    format: 'kavrix-local-vault' as const,
    version: CURRENT_LOCAL_VAULT_VERSION as LocalVaultDocument['version'],
    id,
    schemaVersion,
    cryptographicVersion,
    currentKeyVersion: keyVersion,
    keySlot,
    recoverySlots: [],
    revision,
    createdAt,
    updatedAt: createdAt,
  };
  const metadataDigest = localVaultMetadataDigest(metadata);
  const plaintext = encodePayload(payload);
  try {
    const encryptedPayload = await encryptPayload(
      plaintext,
      rootKey,
      payloadAssociatedData(id, schemaVersion, keyVersion, revision, metadataDigest),
    );
    return localVaultDocumentSchema.parse({
      ...metadata,
      encryptedPayload,
    });
  } finally {
    zeroize(plaintext);
  }
}

async function requireVault(
  store: EncryptedVaultStore,
  vaultValue: string,
): Promise<LocalVaultDocument> {
  const document = await store.get(vaultValue);
  if (document === null) throw new LocalCliError('Vault is not initialized.');
  return document;
}

async function unlockVault(
  document: LocalVaultDocument,
  keyFile: string,
  passphrase: string,
  behavior: Readonly<{
    acceptCurrent?: boolean;
    onAnchorUpdated?: (kind: 'initialized' | 'advanced') => void;
  }> = {},
): Promise<VaultRootKey> {
  if (document.keySlot.type !== 'portable-key') {
    throw new LocalCliError('Vault unlock configuration is invalid.');
  }
  const passphraseBytes = Buffer.from(passphrase, 'utf8');
  let parsedKey: Awaited<ReturnType<typeof readPortableKeyFile>> | undefined;
  let rootKey: VaultRootKey | undefined;
  try {
    parsedKey = await readPortableKeyFile(
      keyFile,
      { kind: 'passphrase', passphrase: passphraseBytes },
      {
        kind: 'bound',
        vaultId: document.id,
        keySlotId: document.keySlot.id,
      },
    );
    rootKey = await unlockPortableKeySlotBytes(document.keySlot, parsedKey.key, {
      vaultId: document.id,
      slotId: document.keySlot.id,
      schemaVersion: document.schemaVersion,
      keyVersion: document.currentKeyVersion,
    });
    let anchor: RevisionAnchor | undefined;
    try {
      anchor = await readRevisionAnchor(revisionAnchorPath(keyFile), rootKey, {
        vaultId: document.id,
        keySlotId: document.keySlot.id,
      });
    } catch (error) {
      if (
        !(error instanceof PortableKeyFileError) ||
        error.code !== 'KEY_FILE_NOT_FOUND'
      ) {
        throw error;
      }
      if (behavior.acceptCurrent !== true) {
        throw new LocalCliError(
          'Vault revision anchor is missing. Run `kavrix doctor health --accept-current` only after verifying the current database state.',
        );
      }
    }
    const expectedAnchor = localVaultRevisionAnchor(document);
    if (
      anchor !== undefined &&
      (document.revision < anchor.revision ||
        (document.revision === anchor.revision &&
          expectedAnchor.metadataDigest !== anchor.metadataDigest))
    ) {
      throw new LocalCliError(
        'Vault rollback detected. The database snapshot is older or forked.',
      );
    }
    await decryptVaultPayload(document, rootKey);
    if (anchor === undefined || document.revision > anchor.revision) {
      await writeRevisionAnchor(
        revisionAnchorPath(keyFile),
        rootKey,
        expectedAnchor,
        anchor === undefined ? 'create' : 'replace',
      );
      behavior.onAnchorUpdated?.(anchor === undefined ? 'initialized' : 'advanced');
    }
    return rootKey;
  } catch (error) {
    zeroize(rootKey);
    if (error instanceof LocalCliError) throw error;
    throw new LocalCliError('Vault unlock failed.');
  } finally {
    zeroize(parsedKey?.key);
    zeroize(passphraseBytes);
  }
}

async function decryptVaultPayload(
  document: LocalVaultDocument,
  rootKey: VaultRootKey,
): Promise<LocalVaultPayload> {
  let plaintext: Uint8Array | undefined;
  try {
    const metadataDigest = document.encryptedPayload.aad.metadataDigest;
    if (
      metadataDigest === undefined ||
      document.encryptedPayload.aad.revision !== document.revision
    ) {
      throw new LocalCliError('Vault metadata binding is missing.');
    }
    if (metadataDigest !== localVaultMetadataDigest(document)) {
      throw new LocalCliError('Vault metadata binding is invalid.');
    }
    plaintext = await decryptPayload(
      document.encryptedPayload,
      rootKey,
      payloadAssociatedData(
        document.id,
        document.schemaVersion,
        document.currentKeyVersion,
        document.revision,
        metadataDigest,
      ),
    );
    return localVaultPayloadSchema.parse(
      JSON.parse(Buffer.from(plaintext).toString('utf8')) as unknown,
    );
  } catch {
    throw new LocalCliError('Vault decryption failed.');
  } finally {
    zeroize(plaintext);
  }
}

function revisionAnchorPath(keyFile: string): string {
  return `${keyFile}.anchor`;
}

function localVaultRevisionAnchor(document: LocalVaultDocument): RevisionAnchor {
  return {
    vaultId: document.id,
    keySlotId: document.keySlot.id,
    revision: document.revision,
    metadataDigest: localVaultMetadataDigest(document),
  };
}

async function requireCurrentRevisionAnchor(
  document: LocalVaultDocument,
  rootKey: VaultRootKey,
  keyFile: string,
): Promise<RevisionAnchor> {
  let anchor: RevisionAnchor;
  try {
    anchor = await readRevisionAnchor(revisionAnchorPath(keyFile), rootKey, {
      vaultId: document.id,
      keySlotId: document.keySlot.id,
    });
  } catch (error) {
    if (error instanceof PortableKeyFileError && error.code === 'KEY_FILE_NOT_FOUND') {
      throw new LocalCliError(
        'Vault revision anchor is missing; recovery operations require the trusted local anchor.',
      );
    }
    throw new LocalCliError('Vault revision anchor is invalid.');
  }
  const expected = localVaultRevisionAnchor(document);
  if (
    anchor.revision !== document.revision ||
    anchor.metadataDigest !== expected.metadataDigest
  ) {
    throw new LocalCliError(
      'Vault rollback detected. The database snapshot does not match the trusted local anchor.',
    );
  }
  return anchor;
}

async function persistUpdatedDocument(
  store: EncryptedVaultStore,
  updated: LocalVaultDocument,
  expectedRevision: LocalVaultDocument['revision'],
  keyFile: string,
  rootKey: VaultRootKey,
  anchorMode: 'create' | 'replace' = 'replace',
): Promise<void> {
  await store.update(updated, expectedRevision);
  await writeRevisionAnchor(
    revisionAnchorPath(keyFile),
    rootKey,
    localVaultRevisionAnchor(updated),
    anchorMode,
  );
}

async function encryptUpdatedDocument(
  document: LocalVaultDocument,
  payload: LocalVaultPayload,
  rootKey: VaultRootKey,
): Promise<LocalVaultDocument> {
  return encryptDocumentPayload(document, payload, rootKey, {});
}

type LocalVaultDocumentUpdate = Partial<
  Pick<
    LocalVaultDocument,
    'version' | 'keySlot' | 'recoverySlots' | 'currentKeyVersion'
  >
>;

async function encryptDocumentPayload(
  document: LocalVaultDocument,
  payload: LocalVaultPayload,
  rootKey: VaultRootKey,
  overrides: LocalVaultDocumentUpdate,
): Promise<LocalVaultDocument> {
  const updatedDocument = {
    ...document,
    ...overrides,
    revision: vaultRevisionSchema.parse(document.revision + 1),
    updatedAt: now(),
  };
  const metadataDigest = localVaultMetadataDigest(updatedDocument);
  const plaintext = encodePayload(payload);
  try {
    const encryptedPayload = await encryptPayload(
      plaintext,
      rootKey,
      payloadAssociatedData(
        document.id,
        document.schemaVersion,
        updatedDocument.currentKeyVersion,
        updatedDocument.revision,
        metadataDigest,
      ),
    );
    return localVaultDocumentSchema.parse({
      ...updatedDocument,
      encryptedPayload,
    });
  } finally {
    zeroize(plaintext);
  }
}

function localVaultMetadataDigest(
  document: Pick<
    LocalVaultDocument,
    | 'format'
    | 'version'
    | 'id'
    | 'schemaVersion'
    | 'cryptographicVersion'
    | 'currentKeyVersion'
    | 'keySlot'
    | 'recoverySlots'
    | 'revision'
    | 'createdAt'
    | 'updatedAt'
  >,
): Sha256Digest {
  const metadata = {
    format: document.format,
    version: document.version,
    id: document.id,
    schemaVersion: document.schemaVersion,
    cryptographicVersion: document.cryptographicVersion,
    currentKeyVersion: document.currentKeyVersion,
    keySlot: document.keySlot,
    recoverySlots: document.recoverySlots,
    revision: document.revision,
    createdAt: document.createdAt,
    updatedAt: document.updatedAt,
  };
  return sha256DigestSchema.parse(
    createHash('sha256')
      .update('kavrix/local-vault-metadata/v1\0', 'utf8')
      .update(canonicalJson(metadata), 'utf8')
      .digest('base64url'),
  );
}

function payloadAssociatedData(
  id: LocalVaultDocument['id'],
  schemaVersion: LocalVaultDocument['schemaVersion'],
  keyVersion: LocalVaultDocument['currentKeyVersion'],
  revision: LocalVaultDocument['revision'],
  metadataDigest: string,
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    vaultId: id,
    entityType: 'vault-preferences',
    entityId: id,
    purpose: 'vault-preferences',
    schemaVersion,
    keyVersion,
    revision,
    metadataDigest,
  });
}

function encodePayload(payload: LocalVaultPayload): Uint8Array {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8');
  if (encoded.byteLength > MAX_LOCAL_PAYLOAD_BYTES) {
    zeroize(encoded);
    throw new LocalCliError('Vault payload exceeds the 4 MiB safety limit.');
  }
  return encoded;
}

function validateCredentialName(name: string): void {
  if (RESERVED_CREDENTIAL_NAMES.has(name)) {
    throw new LocalCliError('That credential name is reserved.');
  }
}

function sanitizeTerminalText(value: string): string {
  let sanitized = '';
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      (codePoint < 32 || codePoint === 127 || (codePoint >= 128 && codePoint <= 159))
    ) {
      sanitized += '[CONTROL]';
    } else {
      sanitized += character;
    }
  }
  return sanitized;
}

function now(): LocalVaultDocument['createdAt'] {
  return timestampSchema.parse(new Date().toISOString());
}

async function withStore(
  databaseUrl: string,
  options: LocalCliOptions,
  operation: (store: EncryptedVaultStore, target: string) => Promise<void>,
): Promise<void> {
  const datastore = datastoreFrom(options);
  if (datastore === 'file') {
    const dataFile = options.dataFile ?? DEFAULT_DATA_FILE;
    const store = await FileLocalVaultStore.open(dataFile);
    try {
      await operation(store, dataFile);
    } finally {
      await store.close();
    }
    return;
  }
  const databaseName = databaseNameFrom(databaseUrl, options.database);
  const store = await MongoLocalVaultStore.connect(databaseUrl, databaseName, {
    collectionName: options.collection,
  });
  try {
    await operation(store, databaseName);
  } finally {
    await store.close();
  }
}

function storeLocation(
  options: LocalCliOptions,
  target: string,
): Record<string, string> {
  return datastoreFrom(options) === 'file'
    ? { datastore: 'file', dataFile: target }
    : {
        database: target,
        collection: options.collection,
      };
}

function datastoreFrom(options: LocalCliOptions): 'mongodb' | 'file' {
  const datastore = options.datastore ?? 'mongodb';
  if (datastore !== 'mongodb' && datastore !== 'file') {
    throw new LocalCliError('--datastore must be mongodb or file.');
  }
  if (datastore === 'mongodb' && options.dataFile !== undefined) {
    throw new LocalCliError('--data-file requires --datastore file.');
  }
  if (
    datastore === 'file' &&
    (options.databaseUrlStdin === true || options.database !== undefined)
  ) {
    throw new LocalCliError(
      'MongoDB connection options cannot be used with --datastore file.',
    );
  }
  return datastore;
}

function databaseNameFrom(uri: string, explicit: string | undefined): string {
  if (explicit !== undefined && /^[A-Za-z0-9_-]{1,63}$/u.test(explicit)) {
    return explicit;
  }
  if (explicit !== undefined) {
    throw new LocalCliError('MongoDB database name is invalid.');
  }
  try {
    const pathname = new URL(uri).pathname.replace(/^\/+/u, '');
    if (pathname.length > 0 && /^[A-Za-z0-9_-]{1,63}$/u.test(pathname)) {
      return pathname;
    }
  } catch {
    throw new LocalCliError('MongoDB connection string is invalid.');
  }
  throw new LocalCliError(
    'Specify --database when the MongoDB connection string has no database name.',
  );
}

async function readSecrets(
  kinds: readonly LocalSecretKind[],
  options: LocalCliOptions,
): Promise<readonly string[]> {
  const datastore = datastoreFrom(options);
  if (datastore === 'file') {
    await FileLocalVaultStore.validatePath(options.dataFile ?? DEFAULT_DATA_FILE);
  }
  const input = new LocalSecretInput(process.stdin, process.stderr);
  const requestedKinds = kinds.filter(
    (kind) => kind !== 'database-url' || datastore === 'mongodb',
  );
  const flags = requestedKinds.map((kind) => {
    if (kind === 'database-url') return options.databaseUrlStdin === true;
    if (kind === 'passphrase') return options.passphraseStdin === true;
    if (kind === 'new-passphrase') return options.newPassphraseStdin === true;
    if (kind === 'recovery-passphrase') return options.recoveryPassphraseStdin === true;
    return options.valueStdin === true;
  });
  const anyStdin = flags.some(Boolean);
  if (anyStdin && !flags.every(Boolean)) {
    throw new LocalCliError(
      'Use stdin flags for every secret in a command, or use masked prompts for all of them.',
    );
  }
  const values =
    requestedKinds.length === 0 ? [] : await input.read(requestedKinds, anyStdin);
  let index = 0;
  return kinds.map((kind) => {
    if (kind === 'database-url' && datastore === 'file') return '';
    const value = values[index];
    index += 1;
    if (value === undefined) throw new LocalCliError('Secret input is incomplete.');
    return value;
  });
}

function requiredSecret(values: readonly string[], index: number): string {
  const value = values[index];
  if (value === undefined) throw new LocalCliError('Secret input is incomplete.');
  return value;
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new LocalCliError('Kavrix operation failed.');
}

function requiredOption(value: string | undefined, name: string): string {
  if (value === undefined || value.length === 0) {
    throw new LocalCliError(`${name} is required.`);
  }
  return value;
}

function parseLimit(value: string | undefined): number {
  const raw = value ?? '50';
  if (!/^[1-9][0-9]{0,2}$/u.test(raw)) {
    throw new LocalCliError('--limit must be a whole number between 1 and 200.');
  }
  const limit = Number(raw);
  if (limit > 200) {
    throw new LocalCliError('--limit must be a whole number between 1 and 200.');
  }
  return limit;
}

type LocalRecord = Readonly<{
  value: string;
  updatedAt: string;
}>;

type SearchResult = Readonly<{
  vaultId: string;
  revision: number;
  pattern: string;
  count: number;
  truncated: boolean;
  matches: readonly Readonly<{ name: string; updatedAt: string }>[];
}>;

type StatsResult = Readonly<{
  vaultId: string;
  revision: number;
  currentKeyVersion: number;
  credentialCount: number;
  oldestCredentialAt: string | null;
  newestCredentialAt: string | null;
  updatedAt: string;
}>;

export function renderVaultView(
  document: Pick<LocalVaultDocument, 'id' | 'revision' | 'updatedAt'>,
  entries: readonly (readonly [string, LocalRecord])[],
  reveal: boolean,
): string {
  const lines = [
    paint(ANSI_BOLD_CYAN, 'KAVRIX / VAULT VIEW'),
    `  Vault ${paint(ANSI_MAGENTA, sanitizeTerminalText(document.id))}  |  Revision ${String(document.revision)}  |  Records ${String(entries.length)}`,
    `  Updated ${paint(ANSI_DIM, formatDisplayTimestamp(document.updatedAt))}`,
    '',
  ];
  const selected = entries[0];
  if (entries.length === 1 && reveal && selected !== undefined) {
    const [name, record] = selected;
    lines.push(
      paint(ANSI_BOLD, `  Credential: ${sanitizeTerminalText(name)}`),
      `  Updated:    ${formatDisplayTimestamp(record.updatedAt)}`,
      `  Value:      ${paint(ANSI_GREEN, truncateDisplay(record.value, 72))}`,
      '',
      paint(
        ANSI_DIM,
        '  Use `kavrix get <name> --reveal` when the exact value is required.',
      ),
    );
    return lines.join('\n').concat('\n');
  }
  if (entries.length === 0) {
    lines.push(paint(ANSI_YELLOW, '  No credentials stored in this vault.'));
    return lines.join('\n').concat('\n');
  }
  const nameWidth = 28;
  const updatedWidth = 24;
  const valueWidth = 48;
  const border = `  +${'-'.repeat(nameWidth + 2)}+${'-'.repeat(updatedWidth + 2)}+${'-'.repeat(valueWidth + 2)}+`;
  lines.push(
    border,
    `  | ${paint(ANSI_BOLD_CYAN, padCell('CREDENTIAL', nameWidth))} | ${paint(ANSI_BOLD_CYAN, padCell('UPDATED', updatedWidth))} | ${paint(ANSI_BOLD_CYAN, padCell('VALUE', valueWidth))} |`,
    border,
    ...entries.map(
      ([name, record]) =>
        `  | ${paint(ANSI_GREEN, padCell(truncateDisplay(name, nameWidth), nameWidth))} | ${padCell(formatDisplayTimestamp(record.updatedAt), updatedWidth)} | ${paint(ANSI_DIM, padCell(REDACTED, valueWidth))} |`,
    ),
    border,
    '',
    paint(
      ANSI_DIM,
      '  Values are masked. Select one credential and use `view <name> --reveal` to inspect it.',
    ),
  );
  return lines.join('\n').concat('\n');
}

export function renderSearchResult(result: SearchResult): string {
  const lines = [
    paint(ANSI_BOLD_CYAN, 'KAVRIX / SEARCH'),
    `  Pattern ${paint(ANSI_MAGENTA, sanitizeTerminalText(result.pattern))}  |  Matches ${String(result.count)}`,
    '',
  ];
  if (result.matches.length === 0) {
    lines.push(paint(ANSI_YELLOW, '  No credential names matched.'));
    return lines.join('\n').concat('\n');
  }
  const nameWidth = 32;
  const updatedWidth = 24;
  const border = `  +${'-'.repeat(nameWidth + 2)}+${'-'.repeat(updatedWidth + 2)}+`;
  lines.push(
    border,
    `  | ${paint(ANSI_BOLD_CYAN, padCell('CREDENTIAL', nameWidth))} | ${paint(ANSI_BOLD_CYAN, padCell('UPDATED', updatedWidth))} |`,
    border,
    ...result.matches.map(
      (match) =>
        `  | ${paint(ANSI_GREEN, padCell(truncateDisplay(match.name, nameWidth), nameWidth))} | ${padCell(formatDisplayTimestamp(match.updatedAt), updatedWidth)} |`,
    ),
    border,
  );
  if (result.truncated) {
    lines.push(
      '',
      paint(ANSI_YELLOW, '  Results were limited. Raise --limit to see more matches.'),
    );
  }
  return lines.join('\n').concat('\n');
}

export function renderVaultStats(result: StatsResult): string {
  const lines = [
    paint(ANSI_BOLD_CYAN, 'KAVRIX / VAULT STATS'),
    `  Vault:              ${paint(ANSI_MAGENTA, sanitizeTerminalText(result.vaultId))}`,
    `  Revision:           ${String(result.revision)}`,
    `  Current key version: ${String(result.currentKeyVersion)}`,
    `  Credentials:        ${paint(ANSI_GREEN, String(result.credentialCount))}`,
    `  Oldest credential:  ${result.oldestCredentialAt === null ? '(none)' : formatDisplayTimestamp(result.oldestCredentialAt)}`,
    `  Newest credential:  ${result.newestCredentialAt === null ? '(none)' : formatDisplayTimestamp(result.newestCredentialAt)}`,
    `  Vault updated:      ${formatDisplayTimestamp(result.updatedAt)}`,
  ];
  return lines.join('\n').concat('\n');
}

function paint(code: string, value: string, enabled = process.stdout.isTTY): string {
  return enabled ? `${code}${value}${ANSI_RESET}` : value;
}

function padCell(value: string, width: number): string {
  return value.padEnd(width, ' ');
}

function truncateDisplay(value: string, width: number): string {
  const sanitized = sanitizeTerminalText(value);
  if (sanitized.length <= width) return sanitized;
  if (width <= 3) return sanitized.slice(0, width);
  return `${sanitized.slice(0, width - 3)}...`;
}

function formatDisplayTimestamp(value: string): string {
  return sanitizeTerminalText(value)
    .replace(/T/u, ' ')
    .replace(/\.\d{3}Z$/u, ' UTC')
    .replace(/Z$/u, ' UTC');
}

function writeRecoveryStatus(result: {
  readonly vaultId: string;
  readonly revision: number;
  readonly currentKeyVersion: number;
  readonly totalKits: number;
  readonly activeKits: number;
  readonly revokedKits: number;
}): void {
  process.stdout.write(
    [
      paint(ANSI_BOLD_CYAN, 'KAVRIX / RECOVERY STATUS'),
      `  Vault:              ${paint(ANSI_MAGENTA, sanitizeTerminalText(result.vaultId))}`,
      `  Revision:           ${String(result.revision)}`,
      `  Current key version: ${String(result.currentKeyVersion)}`,
      `  Recovery kits:      ${String(result.totalKits)}`,
      `  Active kits:        ${paint(ANSI_GREEN, String(result.activeKits))}`,
      `  Revoked kits:       ${String(result.revokedKits)}`,
      '',
      paint(
        ANSI_DIM,
        '  Recovery kits are protected files; their secrets are never printed.',
      ),
      '',
    ].join('\n'),
  );
}

function writeJson(value: unknown): void {
  process.stdout.write(JSON.stringify(value) + '\n');
}
