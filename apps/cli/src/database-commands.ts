import type { Readable } from 'node:stream';

import { zeroize } from '@kavrix/crypto';
import {
  databaseRevisionAnchorPath,
  readDatabaseRecoveryKitFileBinding,
  validateSecureFileDestination,
  validateSecureFileSource,
} from '@kavrix/key-files';
import {
  profileIdSchema,
  vaultIdSchema,
  type DatabaseId,
  type VaultId,
} from '@kavrix/schemas';
import {
  FileEncryptedDatabaseStore,
  MongoEncryptedDatabaseStore,
  type EncryptedDatabaseStore,
} from '@kavrix/storage';
import type { Command } from 'commander';

import { DatabaseFlatCommandError } from './database-flat-commands.js';

import {
  DatastoreProfileRegistry,
  resolveDatastoreProfileRouting,
  verifyDatastoreProfileDatabaseId,
  type DatastoreProfile,
} from './datastore-profiles.js';
import { DatabaseSession, DatabaseSessionError } from './database-session.js';
import { LocalSecretInput, type LocalSecretKind } from './local-secrets.js';

const DEFAULT_KEY_FILE = './kavrix.database.key';
const DEFAULT_DATA_FILE = './kavrix.database';
const DEFAULT_DATABASE = 'kavrix';
const DEFAULT_DATABASE_COLLECTION = 'kavrix_databases';
const DEFAULT_VAULT_COLLECTION = 'kavrix_vaults';
const REDACTED_LABEL = '[REDACTED]';

type DatabaseCommandOptions = Readonly<{
  datastore?: string;
  dataFile?: string;
  database?: string;
  databaseCollection?: string;
  vaultCollection?: string;
  keyFile?: string;
  profile?: string;
  profileConfigDir?: string;
  secretsStdin?: boolean;
  passphraseStdin?: boolean;
  recoveryFile?: string;
  outputKeyFile?: string;
  anchorFile?: string;
  json?: boolean;
  acceptCurrent?: boolean;
  showLabels?: boolean;
  allowInsecureTransport?: boolean;
}>;

export function addDatabaseOwnerCommands(db: Command): void {
  const init = db
    .command('init')
    .description('Initialize one encrypted multi-vault database.');
  addRoutingOptions(init);
  addSecretOption(init);
  init.action(async (...args: unknown[]) => handleDatabaseInit(optionsFrom(args)));

  const status = db
    .command('status')
    .description('Authenticate and inspect the selected database.');
  addRoutingOptions(status);
  addSecretOption(status);
  status.option('--json', 'Emit machine-readable non-secret status.');
  status.action(async (...args: unknown[]) => handleDatabaseStatus(optionsFrom(args)));

  const key = db.command('key').description('Manage database-owner key files.');
  const keyStatus = key
    .command('status')
    .description('Authenticate and inspect one database-owner key binding.');
  addRoutingOptions(keyStatus);
  addSecretOption(keyStatus);
  keyStatus.option('--json', 'Emit machine-readable non-secret status.');
  keyStatus.action(async (...args: unknown[]) =>
    handleDatabaseStatus(optionsFrom(args)),
  );
  const keyCreate = key
    .command('create')
    .description('Create a protected key for sharing one local database.');
  addRoutingOptions(keyCreate);
  addSecretOption(keyCreate);
  keyCreate.requiredOption(
    '--output-key-file <path>',
    'Fresh protected local-share database-key destination.',
  );
  keyCreate.action(async (...args: unknown[]) =>
    handleDatabaseKeyCreate(optionsFrom(args)),
  );

  const doctor = db
    .command('doctor')
    .description('Inspect and repair local trust state.');
  const doctorHealth = doctor
    .command('health')
    .description(
      'Verify the encrypted database binding, snapshot authenticity, and rollback anchor.',
    );
  addRoutingOptions(doctorHealth);
  addSecretOption(doctorHealth);
  doctorHealth
    .option(
      '--accept-current',
      'Re-anchor the local rollback guard to the observed datastore after manually verifying it (heals stale or forked anchors).',
    )
    .option('--json', 'Emit machine-readable output even on a terminal.');
  doctorHealth.action(async (...args: unknown[]) =>
    handleDatabaseDoctorHealth(optionsFrom(args)),
  );

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
  create.action(async (...args: unknown[]) => handleRecoveryCreate(optionsFrom(args)));

  const verify = recovery
    .command('verify')
    .description('Verify a database recovery kit locally.');
  addRoutingOptions(verify);
  addSecretOption(verify);
  verify.requiredOption(
    '--recovery-file <path>',
    'Protected database recovery-kit source.',
  );
  verify.action(async (...args: unknown[]) => handleRecoveryVerify(optionsFrom(args)));

  const recoveryStatus = recovery
    .command('status')
    .description('Show database recovery slot counts.');
  addRoutingOptions(recoveryStatus);
  addSecretOption(recoveryStatus);
  recoveryStatus.option('--json', 'Emit machine-readable output.');
  recoveryStatus.action(async (...args: unknown[]) =>
    handleRecoveryStatus(optionsFrom(args)),
  );

  const revoke = recovery
    .command('revoke <slotId>')
    .description('Revoke one non-final recovery slot.');
  addRoutingOptions(revoke);
  addSecretOption(revoke);
  revoke.action(async (slotId: string, ...args: unknown[]) =>
    handleRecoveryRevoke(slotId, optionsFrom(args)),
  );

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
  use.action(async (...args: unknown[]) => handleRecoveryUse(optionsFrom(args)));

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
  create.action(async (...args: unknown[]) => handleVaultCreate(optionsFrom(args)));

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
  list.action(async (...args: unknown[]) => handleVaultList(optionsFrom(args)));

  const status = vault
    .command('status <vaultId>')
    .description('Show authenticated vault metadata.');
  addRoutingOptions(status);
  addSecretOption(status);
  status.option(
    '--show-labels',
    'Include the decrypted private label for the authenticated owner.',
  );
  status.action(async (vaultId: string, ...args: unknown[]) =>
    handleVaultStatus(vaultId, optionsFrom(args)),
  );

  const rename = vault
    .command('rename <vaultId>')
    .description('Rename a vault inside the encrypted catalog.');
  addRoutingOptions(rename);
  addSecretOption(rename);
  rename.action(async (vaultId: string, ...args: unknown[]) =>
    handleVaultRename(vaultId, optionsFrom(args)),
  );

  const use = vault
    .command('use <vaultId>')
    .description('Select the default vault for one protected datastore profile.');
  addRoutingOptions(use);
  addSecretOption(use);
  use.action(async (vaultId: string, ...args: unknown[]) =>
    handleVaultUse(vaultId, optionsFrom(args)),
  );

  const remove = vault
    .command('remove <vaultId>')
    .description(
      'Remove one vault from the encrypted catalog (requires confirmation).',
    );
  addRoutingOptions(remove);
  addSecretOption(remove);
  remove.option('--json', 'Emit machine-readable output.');
  remove.action(async (vaultId: string, ...args: unknown[]) =>
    handleVaultRemove(vaultId, optionsFrom(args)),
  );
}

async function handleDatabaseInit(options: DatabaseCommandOptions): Promise<void> {
  const route = await resolveRoute(options);
  if (route.expectedDatabaseId !== undefined) throw new DatabaseSessionError('binding');
  await DatabaseSession.validateInitializationDestinations(route.keyFile);
  if (route.datastore === 'file')
    await FileEncryptedDatabaseStore.validatePath(route.dataFile ?? DEFAULT_DATA_FILE);
  const kinds = secretKinds(route, ['label', 'new-passphrase', 'new-passphrase']);
  const values = await readCommandSecrets(kinds, options);
  const offset = route.datastore === 'mongodb' ? 1 : 0;
  const label = values[offset];
  const passphrase = values[offset + 1];
  const confirmation = values[offset + 2];
  if (label === undefined || passphrase === undefined || passphrase !== confirmation)
    throw new DatabaseSessionError('invalid');
  const passphraseBytes = Buffer.from(passphrase, 'utf8');
  const opened = await openStore(
    route,
    values[0],
    options.allowInsecureTransport === true,
  );
  const registry = route.registry;
  const profile = route.profile;
  try {
    const result = await DatabaseSession.initialize({
      store: opened.store,
      keyFile: route.keyFile,
      passphrase: passphraseBytes,
      label,
      ...(opened.rollbackDatabase === undefined
        ? {}
        : { rollbackDatabase: opened.rollbackDatabase }),
      ...(registry === null || profile === null
        ? {}
        : {
            publishBinding: (databaseId: DatabaseId) =>
              registry.bindDatabaseIdForInitialization(profile.id, databaseId),
          }),
    });
    writeOutput({ initialized: true, ...result });
  } finally {
    zeroize(passphraseBytes);
    await opened.store.close().catch(() => undefined);
  }
}

async function handleDatabaseStatus(options: DatabaseCommandOptions): Promise<void> {
  await withOwnerSession(options, [], (session) => {
    writeOutput(session.status());
  });
}

async function handleDatabaseKeyCreate(options: DatabaseCommandOptions): Promise<void> {
  if (options.outputKeyFile === undefined) throw new DatabaseSessionError('invalid');
  const route = await resolveRoute(options);
  if (route.datastore !== 'file') throw new DatabaseSessionError('invalid');
  const keyFile = options.outputKeyFile;
  await validateSecureFileDestination(keyFile);
  await withOwnerSession(
    options,
    ['new-passphrase', 'new-passphrase'],
    async (session, extras) => {
      if (extras[0] === undefined || extras[0] !== extras[1])
        throw new DatabaseSessionError('invalid');
      const passphrase = Buffer.from(extras[0], 'utf8');
      try {
        writeOutput(await session.createLocalShareKey({ keyFile, passphrase }));
        process.stderr.write(
          [
            '',
            'Share-key notice: this key authorizes the database snapshot that exists',
            'right now. Recipients who open with it see only that snapshot; later',
            'database writes are invisible to previously distributed copies. Create a',
            'fresh share key after meaningful updates so recipients stay current.',
            '',
          ].join('\n'),
        );
      } finally {
        zeroize(passphrase);
      }
    },
  );
}

type DoctorHealthReport = Readonly<{
  healthy: boolean;
  datastore: 'file' | 'mongodb';
  checks: readonly Record<string, unknown>[];
  autoHealed: readonly string[];
  manualRecoveryRequired: readonly string[];
  revision?: number;
  vaultCount?: number;
}>;

/**
 * Verifies the full local trust chain for one encrypted database container.
 * `--accept-current` performs the only bounded repair Kavrix offers for
 * containers: after the entire observed snapshot authenticates with the
 * database root key, the trusted local rollback anchor is rewritten to match,
 * healing anchors left stale or forked by a crash mid-write. Datastore content
 * is never modified.
 */
async function handleDatabaseDoctorHealth(
  options: DatabaseCommandOptions,
): Promise<void> {
  const acceptCurrent = options.acceptCurrent === true;
  const route = await resolveRoute(options);
  const checks: Record<string, unknown>[] = [];
  const autoHealed: string[] = [];
  const manualRecoveryRequired: string[] = [];
  let report: DoctorHealthReport | undefined;
  const secretReader = commandSecretReader();
  const initialKinds: LocalSecretKind[] =
    route.datastore === 'mongodb' ? ['database-url', 'passphrase'] : ['passphrase'];
  const initialValues = await readCommandSecrets(
    initialKinds,
    options,
    secretReader,
    true,
  );
  const opened = await openStore(
    route,
    route.datastore === 'mongodb' ? initialValues[0] : undefined,
    options.allowInsecureTransport === true,
  );
  let passphrase: Uint8Array | undefined;
  try {
    passphrase = Buffer.from(
      initialValues[route.datastore === 'mongodb' ? 1 : 0] ?? '',
      'utf8',
    );
    const readPassphrase = (): Promise<Uint8Array> =>
      Promise.resolve(Uint8Array.from(passphrase ?? new Uint8Array(0)));
    let session: DatabaseSession | undefined;
    try {
      session = await DatabaseSession.openWithSecret({
        store: opened.store,
        keyFile: route.keyFile,
        ...(route.expectedDatabaseId === undefined
          ? {}
          : { expectedDatabaseId: route.expectedDatabaseId }),
        readPassphrase,
        acceptCurrentAnchor: acceptCurrent,
      });
      if (session.acceptedCurrentAnchor) {
        autoHealed.push('revision-anchor-accepted-current');
      }
      const status = session.status();
      checks.push({
        name: 'database-container',
        status: 'ok',
        detail:
          'The database binding, every encrypted document, and the rollback anchor authenticated.',
        revision: status.revision,
        vaultCount: status.vaultCount,
      });
      report = {
        healthy: true,
        datastore: route.datastore,
        checks,
        autoHealed,
        manualRecoveryRequired,
        revision: status.revision,
        vaultCount: status.vaultCount,
      };
    } catch (error) {
      const failure = error instanceof Error ? error : undefined;
      const detail = describeDoctorFailure(failure);
      manualRecoveryRequired.push(detail);
      checks.push({
        name: 'database-container',
        status: 'manual-recovery',
        detail,
      });
      report = {
        healthy: false,
        datastore: route.datastore,
        checks,
        autoHealed,
        manualRecoveryRequired,
      };
    } finally {
      if (session !== undefined) await session.close().catch(() => undefined);
    }
  } finally {
    zeroize(passphrase);
    await opened.store.close().catch(() => undefined);
  }
  // Every path through the try/catch above assigns a full report.
  writeOutput(report);
  if (!report.healthy) process.exitCode = 15;
}

function describeDoctorFailure(error: Error | undefined): string {
  const message = error?.message ?? 'The encrypted database could not be opened.';
  if (message.includes('stale or forked')) {
    return (
      'The trusted rollback anchor rejected the stored snapshot as stale or forked. ' +
      'Verify the datastore contents independently, then re-run with --accept-current to re-anchor.'
    );
  }
  if (message.includes('locked by another')) {
    return `${message} Close the other Kavrix process; a dead process leaves no lock once detected.`;
  }
  return message;
}

async function handleRecoveryCreate(options: DatabaseCommandOptions): Promise<void> {
  if (options.recoveryFile === undefined) throw new DatabaseSessionError('invalid');
  const recoveryFile = options.recoveryFile;
  await DatabaseSession.validateRecoveryDestinations(recoveryFile);
  await withOwnerSession(
    options,
    ['recovery-passphrase', 'recovery-passphrase'],
    async (session, extras) => {
      if (extras[0] !== extras[1] || extras[0] === undefined)
        throw new DatabaseSessionError('invalid');
      const bytes = Buffer.from(extras[0], 'utf8');
      try {
        writeOutput(await session.createRecovery({ recoveryFile, passphrase: bytes }));
      } finally {
        zeroize(bytes);
      }
    },
  );
}

async function handleRecoveryVerify(options: DatabaseCommandOptions): Promise<void> {
  if (options.recoveryFile === undefined) throw new DatabaseSessionError('invalid');
  const recoveryFile = options.recoveryFile;
  await validateSecureFileSource(recoveryFile);
  const expectedBinding = await readDatabaseRecoveryKitFileBinding(recoveryFile);
  await withOwnerSession(options, ['recovery-passphrase'], async (session, extras) => {
    const bytes = Buffer.from(extras[0] ?? '', 'utf8');
    try {
      const slotId = await session.verifyRecovery({
        recoveryFile,
        passphrase: bytes,
        expectedBinding,
      });
      writeOutput({ valid: true, slotId });
    } finally {
      zeroize(bytes);
    }
  });
}

async function handleRecoveryStatus(options: DatabaseCommandOptions): Promise<void> {
  await withOwnerSession(options, [], (session) => {
    writeOutput(session.recoveryStatus());
  });
}

async function handleRecoveryRevoke(
  slotId: string,
  options: DatabaseCommandOptions,
): Promise<void> {
  await withOwnerSession(options, [], async (session) => {
    await session.revokeRecovery(slotId);
    writeOutput({ revoked: true, slotId: sanitize(slotId) });
  });
}

async function handleRecoveryUse(options: DatabaseCommandOptions): Promise<void> {
  if (options.recoveryFile === undefined || options.outputKeyFile === undefined)
    throw new DatabaseSessionError('invalid');
  await validateSecureFileSource(options.recoveryFile);
  await validateSecureFileSource(databaseRevisionAnchorPath(options.recoveryFile));
  if (options.anchorFile === undefined)
    await DatabaseSession.validateRecoveredOwnerDestinations(options.outputKeyFile);
  else
    await DatabaseSession.validateRecoveredOwnerDestinations(
      options.outputKeyFile,
      options.anchorFile,
    );
  const route = await resolveRoute(options);
  const binding = await readDatabaseRecoveryKitFileBinding(options.recoveryFile);
  if (
    route.expectedDatabaseId !== undefined &&
    route.expectedDatabaseId !== binding.databaseId
  )
    throw new DatabaseSessionError('binding');
  const secretReader = commandSecretReader();
  const routingSecrets =
    route.datastore === 'mongodb'
      ? await readCommandSecrets(['database-url'], options, secretReader, false)
      : [];
  const opened = await openStore(
    route,
    routingSecrets[0],
    options.allowInsecureTransport === true,
  );
  let recoveryPassphrase: Uint8Array | undefined;
  let newPassphrase: Uint8Array | undefined;
  try {
    const database = await opened.store.getDatabase(binding.databaseId);
    if (
      database?.id !== binding.databaseId ||
      (route.expectedDatabaseId !== undefined &&
        database.id !== route.expectedDatabaseId)
    )
      throw new DatabaseSessionError('binding');
    const values = await readCommandSecrets(
      ['recovery-passphrase', 'new-passphrase', 'new-passphrase'],
      options,
      secretReader,
    );
    if (values[1] !== values[2]) throw new DatabaseSessionError('invalid');
    recoveryPassphrase = Buffer.from(values[0] ?? '', 'utf8');
    newPassphrase = Buffer.from(values[1] ?? '', 'utf8');
    writeOutput(
      await DatabaseSession.useRecovery({
        store: opened.store,
        recoveryFile: options.recoveryFile,
        recoveryPassphrase,
        outputKeyFile: options.outputKeyFile,
        newPassphrase,
        ...(options.anchorFile === undefined ? {} : { anchorFile: options.anchorFile }),
        expectedBinding: binding,
      }),
    );
  } finally {
    zeroize(newPassphrase);
    zeroize(recoveryPassphrase);
    await opened.store.close().catch(() => undefined);
  }
}

async function handleVaultCreate(options: DatabaseCommandOptions): Promise<void> {
  await withOwnerSession(options, ['label'], async (session, extras) => {
    const created = await session.createVault(extras[0] ?? '');
    writeOutput({ created: { id: created.id, createdAt: created.createdAt } });
  });
}

async function handleVaultList(options: DatabaseCommandOptions): Promise<void> {
  const showLabels = options.showLabels === true;
  await withOwnerSession(options, [], (session) => {
    writeOutput({
      vaults: session.listVaults().map((entry) => ({
        id: entry.id,
        createdAt: entry.createdAt,
        label: showLabels ? sanitize(entry.label) : REDACTED_LABEL,
      })),
    });
  });
}

async function handleVaultStatus(
  vaultId: string,
  options: DatabaseCommandOptions,
): Promise<void> {
  await withOwnerSession(options, [], async (session) => {
    const id = parseVaultIdentifier(vaultId);
    await session.getVault(id);
    const document = await session.getVaultDocument(id);
    const label =
      options.showLabels === true
        ? sanitize(
            (
              session.listVaults().find((entry) => entry.id === id) ?? {
                label: REDACTED_LABEL,
              }
            ).label,
          )
        : REDACTED_LABEL;
    writeOutput({
      vaultId: id,
      label,
      revision: document.revision,
    });
  });
}

async function handleVaultRename(
  vaultId: string,
  options: DatabaseCommandOptions,
): Promise<void> {
  await withOwnerSession(options, ['label'], async (session, extras) => {
    const id = parseVaultIdentifier(vaultId);
    await session.renameVault(id, extras[0] ?? '');
    writeOutput({ renamed: true, vaultId: id });
  });
}

async function handleVaultUse(
  vaultId: string,
  options: DatabaseCommandOptions,
): Promise<void> {
  await withOwnerSession(options, [], async (session, _extras, route) => {
    const id = parseVaultIdentifier(vaultId);
    await session.getVault(id);
    if (route.registry === null || route.profile === null) {
      throw new DatabaseSessionError('binding');
    }
    const selected = await route.registry.setDefaultVaultId(
      route.profile.id,
      id,
      session.databaseId,
    );
    writeOutput({ selected: true, profile: selected.id, vaultId: id });
  });
}

async function handleVaultRemove(
  vaultId: string,
  options: DatabaseCommandOptions,
): Promise<void> {
  await withOwnerSession(options, [], async (session) => {
    const id = parseVaultIdentifier(vaultId);
    const { createDatabaseVaultDeletionAuthorization } =
      await import('./database-session.js');
    await session.deleteVault(id, createDatabaseVaultDeletionAuthorization());
    writeOutput({ removed: true, vaultId: id });
  });
}

/**
 * Validates one vault identifier with a reviewed message. Prototype-polluting
 * identifiers are refused explicitly and malformed shapes fail as input
 * errors instead of raw validation dumps.
 */
function parseVaultIdentifier(value: string): VaultId {
  if (value === '__proto__' || value === 'constructor' || value === 'prototype') {
    throw new DatabaseSessionError('invalid');
  }
  try {
    return vaultIdSchema.parse(value);
  } catch {
    throw new DatabaseFlatCommandError('Vault ID is invalid.');
  }
}

async function withOwnerSession(
  options: DatabaseCommandOptions,
  extraKinds: readonly LocalSecretKind[],
  operation: (
    session: DatabaseSession,
    extras: readonly string[],
    route: ResolvedRoute,
  ) => Promise<void> | void,
): Promise<void> {
  const route = await resolveRoute(options);
  const kinds: LocalSecretKind[] = ['passphrase', ...extraKinds];
  const secretReader = commandSecretReader();
  let values: readonly string[] = [];
  let passphrase: Uint8Array | undefined;
  let opened: Awaited<ReturnType<typeof openStore>>;
  if (route.datastore === 'file') {
    opened = await openStore(route, undefined, options.allowInsecureTransport === true);
  } else {
    values = await readCommandSecrets(['database-url'], options, secretReader, false);
    opened = await openStore(route, values[0], options.allowInsecureTransport === true);
  }
  let session: DatabaseSession | undefined;
  try {
    session = await DatabaseSession.openWithSecret({
      store: opened.store,
      keyFile: route.keyFile,
      ...(route.expectedDatabaseId === undefined
        ? {}
        : { expectedDatabaseId: route.expectedDatabaseId }),
      readPassphrase: async () => {
        const protectedValues = await readCommandSecrets(kinds, options, secretReader);
        values = [...values, ...protectedValues];
        const passphraseOffset = route.datastore === 'mongodb' ? 1 : 0;
        passphrase = Buffer.from(values[passphraseOffset] ?? '', 'utf8');
        return passphrase;
      },
    });
    if (route.profile !== null)
      verifyDatastoreProfileDatabaseId(route.profile, session.databaseId);
    const extraOffset = route.datastore === 'mongodb' ? 2 : 1;
    await operation(session, values.slice(extraOffset), route);
  } finally {
    zeroize(passphrase);
    if (session !== undefined) await session.close();
    else await opened.store.close().catch(() => undefined);
  }
}

type ResolvedRoute = Readonly<{
  datastore: 'file' | 'mongodb';
  dataFile?: string;
  database?: string;
  databaseCollection?: string;
  vaultCollection?: string;
  keyFile: string;
  expectedDatabaseId?: DatabaseId;
  registry: DatastoreProfileRegistry | null;
  profile: DatastoreProfile | null;
}>;

async function resolveRoute(options: DatabaseCommandOptions): Promise<ResolvedRoute> {
  const registryOptions =
    options.profileConfigDir === undefined
      ? {}
      : { configDirectory: options.profileConfigDir };
  const registry =
    options.profile === undefined
      ? options.datastore === undefined
        ? await DatastoreProfileRegistry.openIfPresent(registryOptions)
        : null
      : await DatastoreProfileRegistry.open(registryOptions);
  const selected =
    registry === null
      ? null
      : options.profile === undefined
        ? await registry.current()
        : await registry.get(profileIdSchema.parse(options.profile));
  const profile =
    selected === null
      ? null
      : resolveDatastoreProfileRouting(selected, {
          ...(options.datastore === undefined
            ? {}
            : { datastore: parseDatastore(options.datastore) }),
          ...(options.dataFile === undefined ? {} : { dataFile: options.dataFile }),
          ...(options.database === undefined ? {} : { database: options.database }),
          ...(options.databaseCollection === undefined
            ? {}
            : { databaseCollection: options.databaseCollection }),
          ...(options.vaultCollection === undefined
            ? {}
            : { vaultCollection: options.vaultCollection }),
          ...(options.keyFile === undefined ? {} : { keyFile: options.keyFile }),
        });
  if (profile?.datastore === 'file') {
    return {
      datastore: 'file',
      dataFile: profile.dataFile,
      keyFile: profile.keyFile,
      ...(profile.databaseId === undefined
        ? {}
        : { expectedDatabaseId: profile.databaseId }),
      registry,
      profile,
    };
  }
  if (profile?.datastore === 'mongodb') {
    return {
      datastore: 'mongodb',
      database: profile.database,
      databaseCollection: profile.databaseCollection,
      vaultCollection: profile.vaultCollection,
      keyFile: profile.keyFile,
      ...(profile.databaseId === undefined
        ? {}
        : { expectedDatabaseId: profile.databaseId }),
      registry,
      profile,
    };
  }
  const datastore = parseDatastore(options.datastore ?? 'file');
  return datastore === 'file'
    ? {
        datastore,
        dataFile: options.dataFile ?? DEFAULT_DATA_FILE,
        keyFile: options.keyFile ?? DEFAULT_KEY_FILE,
        registry,
        profile: null,
      }
    : {
        datastore,
        database: options.database ?? DEFAULT_DATABASE,
        databaseCollection: options.databaseCollection ?? DEFAULT_DATABASE_COLLECTION,
        vaultCollection: options.vaultCollection ?? DEFAULT_VAULT_COLLECTION,
        keyFile: options.keyFile ?? DEFAULT_KEY_FILE,
        registry,
        profile: null,
      };
}

async function openStore(
  route: ResolvedRoute,
  databaseUrl: string | undefined,
  allowInsecureTransport: boolean,
): Promise<
  Readonly<{
    store: EncryptedDatabaseStore;
    rollbackDatabase?: (databaseId: DatabaseId) => Promise<void>;
  }>
> {
  if (route.datastore === 'file') {
    const path = route.dataFile ?? DEFAULT_DATA_FILE;
    await FileEncryptedDatabaseStore.validatePath(path);
    const store = await FileEncryptedDatabaseStore.open(path);
    return {
      store,
      rollbackDatabase: (databaseId) => store.rollbackOwnedInitialization(databaseId),
    };
  }
  if (databaseUrl === undefined) throw new DatabaseSessionError('invalid');
  return {
    store: await MongoEncryptedDatabaseStore.connect(
      databaseUrl,
      route.database ?? DEFAULT_DATABASE,
      {
        databaseCollectionName: route.databaseCollection ?? DEFAULT_DATABASE_COLLECTION,
        vaultCollectionName: route.vaultCollection ?? DEFAULT_VAULT_COLLECTION,
        allowInsecureTransport,
      },
    ),
  };
}

function secretKinds(
  route: ResolvedRoute,
  rest: readonly LocalSecretKind[],
): LocalSecretKind[] {
  return route.datastore === 'mongodb' ? ['database-url', ...rest] : [...rest];
}

async function readCommandSecrets(
  kinds: readonly LocalSecretKind[],
  options: DatabaseCommandOptions,
  reader = commandSecretReader(),
  finalFrames = true,
): Promise<readonly string[]> {
  const useStdin = options.secretsStdin === true || options.passphraseStdin === true;
  return await reader.read(kinds, useStdin, finalFrames);
}

function commandSecretReader(): LocalSecretInput {
  const input: Readable & {
    isRaw?: boolean;
    setRawMode?: (enabled: boolean) => void;
  } = process.stdin;
  return new LocalSecretInput(input, process.stderr);
}

function addRoutingOptions(command: Command, includeKey = true): void {
  command
    .option('--profile <id>', 'Protected datastore profile alias.')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
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

function optionsFrom(args: readonly unknown[]): DatabaseCommandOptions {
  const command = args.at(-1);
  if (
    typeof command !== 'object' ||
    command === null ||
    !('optsWithGlobals' in command)
  )
    throw new DatabaseSessionError('invalid');
  return (command as Command).optsWithGlobals<DatabaseCommandOptions>();
}

function parseDatastore(value: string): 'file' | 'mongodb' {
  if (value === 'file' || value === 'mongodb') return value;
  throw new DatabaseSessionError('invalid');
}

function sanitize(value: string): string {
  return Array.from(value)
    .map((character) => {
      const point = character.codePointAt(0) ?? 0;
      return point < 32 || point === 127 || (point >= 128 && point <= 159)
        ? '[CONTROL]'
        : character;
    })
    .join('');
}

function writeOutput(value: unknown): void {
  process.stdout.write(
    JSON.stringify(value, (_key, entry: unknown) =>
      typeof entry === 'string' ? sanitize(entry) : entry,
    ) + '\n',
  );
}
