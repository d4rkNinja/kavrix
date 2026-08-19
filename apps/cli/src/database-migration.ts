import { createHash } from 'node:crypto';

import {
  decryptPayload,
  unlockPortableKeySlotBytes,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  readPortableKeyFile,
  readRevisionAnchor,
  validateSecureFileDestination,
  validateSecureFileSource,
} from '@kavrix/key-files';
import {
  associatedDataSchema,
  canonicalJson,
  localVaultDocumentSchema,
  localVaultPayloadSchema,
  sha256DigestSchema,
  type DatabaseId,
  type LocalVaultDocument,
  type LocalVaultPayload,
  type VaultId,
} from '@kavrix/schemas';
import type { EncryptedDatabaseStore } from '@kavrix/storage';

import {
  DatabaseSession,
  DatabaseSessionError,
  type MigrationInitializationOwnership,
} from './database-session.js';
import {
  validateDatastoreProfileBindingPublicationResult,
  type DatastoreProfileBindingPublicationResult,
} from './datastore-profiles.js';

const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

export type DatabaseMigrationErrorCode =
  'ambiguous-commit' | 'authentication' | 'conflict' | 'invalid' | 'verification';

export class DatabaseMigrationError extends Error {
  public constructor(public readonly code: DatabaseMigrationErrorCode) {
    super(messageFor(code));
    this.name = 'DatabaseMigrationError';
  }
}

export type LegacyMigrationSource = Readonly<{
  document: LocalVaultDocument;
  keyFile: string;
  anchorFile?: string;
  readPassphrase: () => Promise<Uint8Array>;
}>;

export type DatabaseMigrationDestination = Readonly<{
  openStore: () => Promise<EncryptedDatabaseStore>;
  keyFile: string;
  anchorFile?: string;
  expectedDatabaseId?: DatabaseId;
  vaultLabel: string;
  readPassphrase: () => Promise<Uint8Array>;
  initialize?: Readonly<{
    databaseLabel: string;
    rollbackDatabase: (databaseId: DatabaseId) => Promise<void>;
    publishBinding?: (
      databaseId: DatabaseId,
    ) => Promise<DatastoreProfileBindingPublicationResult>;
  }>;
}>;

export type LegacyDatabaseMigrationOptions = Readonly<{
  source: LegacyMigrationSource;
  destination: DatabaseMigrationDestination;
}>;

export type LegacyDatabaseMigrationResult = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  recordCount: number;
}>;

/**
 * Copies one authenticated version 2 vault into one existing encrypted database.
 * The source is read-only. Success is reported only after a fresh destination
 * session decrypts and canonically compares the complete payload.
 */
export async function migrateLegacyVaultToDatabase(
  options: LegacyDatabaseMigrationOptions,
): Promise<LegacyDatabaseMigrationResult> {
  const sourceDocument = parseSourceDocument(options.source.document);
  const sourceAnchor = options.source.anchorFile ?? `${options.source.keyFile}.anchor`;
  await validateSecureFileSource(options.source.keyFile);
  await validateSecureFileSource(sourceAnchor);
  if (options.destination.initialize === undefined) {
    await validateSecureFileSource(options.destination.keyFile);
    if (options.destination.anchorFile !== undefined) {
      await validateSecureFileSource(options.destination.anchorFile);
    }
  } else {
    await validateSecureFileDestination(options.destination.keyFile);
    await validateSecureFileDestination(
      options.destination.anchorFile ??
        `${options.destination.keyFile}.database-anchor`,
    );
  }

  let sourcePassphrase: Uint8Array | undefined;
  let destinationPassphrase: Uint8Array | undefined;
  let sourcePayload: LocalVaultPayload | undefined;
  let initializationOwnership: MigrationInitializationOwnership | undefined;
  let activeSession: DatabaseSession | undefined;
  let destinationStore: EncryptedDatabaseStore | undefined;
  let destinationDatabaseId: DatabaseId | undefined;
  let migratedVaultId: VaultId | undefined;
  let vaultPublished = false;
  let profilePublicationProvenAbsent = false;
  let failure: unknown;
  try {
    sourcePassphrase = await readSecretOnce(options.source.readPassphrase);
    destinationPassphrase = await readSecretOnce(options.destination.readPassphrase);
    sourcePayload = await openLegacyPayload(
      sourceDocument,
      options.source.keyFile,
      sourceAnchor,
      sourcePassphrase,
    );

    destinationStore = await options.destination.openStore();
    if (options.destination.initialize !== undefined) {
      const initialized = await DatabaseSession.initializeForMigration({
        store: destinationStore,
        keyFile: options.destination.keyFile,
        passphrase: destinationPassphrase,
        label: options.destination.initialize.databaseLabel,
        rollbackDatabase: options.destination.initialize.rollbackDatabase,
        ...(options.destination.anchorFile === undefined
          ? {}
          : { anchorFile: options.destination.anchorFile }),
      });
      initializationOwnership = initialized.ownership;
      destinationDatabaseId = initialized.databaseId;
      await destinationStore.close();
      destinationStore = await options.destination.openStore();
    }
    activeSession = await DatabaseSession.open({
      store: destinationStore,
      keyFile: options.destination.keyFile,
      passphrase: destinationPassphrase,
      ...(options.destination.anchorFile === undefined
        ? {}
        : { anchorFile: options.destination.anchorFile }),
      ...(options.destination.expectedDatabaseId === undefined
        ? {}
        : { expectedDatabaseId: options.destination.expectedDatabaseId }),
    });
    destinationStore = undefined;
    destinationDatabaseId = activeSession.databaseId;
    const expectedPayload = structuredClone(sourcePayload);
    const created = await activeSession.createMigrationVault(
      options.destination.vaultLabel,
      () => structuredClone(expectedPayload),
      initializationOwnership,
    );
    migratedVaultId = created.id;
    vaultPublished = true;
    await activeSession.close();
    activeSession = undefined;

    destinationStore = await options.destination.openStore();
    activeSession = await DatabaseSession.open({
      store: destinationStore,
      keyFile: options.destination.keyFile,
      passphrase: destinationPassphrase,
      expectedDatabaseId: destinationDatabaseId,
      ...(options.destination.anchorFile === undefined
        ? {}
        : { anchorFile: options.destination.anchorFile }),
    });
    destinationStore = undefined;
    const verification = { matches: false };
    await activeSession.inspectVault(migratedVaultId, (observed) => {
      verification.matches = canonicalJson(observed) === canonicalJson(expectedPayload);
    });
    if (!verification.matches) throw new DatabaseMigrationError('verification');
    if (initializationOwnership !== undefined) {
      if (options.destination.initialize?.publishBinding !== undefined) {
        let publication: unknown;
        try {
          publication =
            await options.destination.initialize.publishBinding(destinationDatabaseId);
        } catch {
          throw new DatabaseMigrationError('ambiguous-commit');
        }
        const validated = validateDatastoreProfileBindingPublicationResult(publication);
        if (validated === undefined || validated.status === 'publication-uncertain') {
          throw new DatabaseMigrationError('ambiguous-commit');
        }
        if (validated.status === 'not-published') {
          profilePublicationProvenAbsent = true;
          throw new DatabaseMigrationError('invalid');
        }
      }
      DatabaseSession.commitMigrationInitialization(initializationOwnership);
      initializationOwnership = undefined;
    }
    const result = {
      databaseId: destinationDatabaseId,
      vaultId: migratedVaultId,
      recordCount: Object.keys(expectedPayload.records).length,
    };
    await activeSession.close();
    activeSession = undefined;
    zeroize(sourcePassphrase);
    zeroize(destinationPassphrase);
    return result;
  } catch (error) {
    failure = error;
  }

  let terminalError: Error;
  if (profilePublicationProvenAbsent && initializationOwnership !== undefined) {
    const cleanupErrors: DatabaseMigrationError[] = [];
    try {
      if (activeSession !== undefined) await activeSession.close();
      else if (destinationStore !== undefined) await destinationStore.close();
    } catch {
      cleanupErrors.push(new DatabaseMigrationError('ambiguous-commit'));
    }
    activeSession = undefined;
    destinationStore = undefined;
    try {
      await DatabaseSession.rollbackMigrationInitialization(initializationOwnership);
      initializationOwnership = undefined;
    } catch {
      cleanupErrors.push(new DatabaseMigrationError('ambiguous-commit'));
    }
    terminalError =
      cleanupErrors.length === 0
        ? mapMigrationError(failure)
        : redactedMigrationAggregate(failure, cleanupErrors);
  } else if (vaultPublished || isAmbiguous(failure)) {
    await closeQuietly(activeSession, destinationStore);
    terminalError = new DatabaseMigrationError('ambiguous-commit');
  } else if (initializationOwnership !== undefined) {
    try {
      await closeQuietly(activeSession, destinationStore);
      activeSession = undefined;
      destinationStore = undefined;
      await DatabaseSession.rollbackMigrationInitialization(initializationOwnership);
      initializationOwnership = undefined;
      terminalError = mapMigrationError(failure);
    } catch {
      terminalError = new DatabaseMigrationError('ambiguous-commit');
    }
  } else {
    terminalError = mapMigrationError(failure);
  }
  await closeQuietly(activeSession, destinationStore);
  zeroize(sourcePassphrase);
  zeroize(destinationPassphrase);
  throw terminalError;
}

async function openLegacyPayload(
  document: LocalVaultDocument,
  keyFile: string,
  anchorFile: string,
  passphrase: Uint8Array,
): Promise<LocalVaultPayload> {
  let portableKey: Uint8Array | undefined;
  let rootKey: VaultRootKey | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    if (document.keySlot.type !== 'portable-key') {
      throw new DatabaseMigrationError('authentication');
    }
    const parsed = await readPortableKeyFile(
      keyFile,
      { kind: 'passphrase', passphrase },
      {
        kind: 'bound',
        vaultId: document.id,
        keySlotId: document.keySlot.id,
      },
    );
    portableKey = parsed.key;
    rootKey = await unlockPortableKeySlotBytes(document.keySlot, portableKey, {
      vaultId: document.id,
      slotId: document.keySlot.id,
      schemaVersion: document.schemaVersion,
      keyVersion: document.currentKeyVersion,
    });
    const expectedDigest = localVaultMetadataDigest(document);
    const anchor = await readRevisionAnchor(anchorFile, rootKey, {
      vaultId: document.id,
      keySlotId: document.keySlot.id,
    });
    if (
      anchor.revision !== document.revision ||
      anchor.metadataDigest !== expectedDigest ||
      document.encryptedPayload.aad.metadataDigest !== expectedDigest
    ) {
      throw new DatabaseMigrationError('authentication');
    }
    plaintext = await decryptPayload(
      document.encryptedPayload,
      rootKey,
      associatedDataSchema.parse({
        version: 1,
        vaultId: document.id,
        entityType: 'vault-preferences',
        entityId: document.id,
        purpose: 'vault-preferences',
        schemaVersion: document.schemaVersion,
        keyVersion: document.currentKeyVersion,
        revision: document.revision,
        metadataDigest: expectedDigest,
      }),
    );
    return localVaultPayloadSchema.parse(
      JSON.parse(STRICT_UTF8_DECODER.decode(plaintext)) as unknown,
    );
  } catch (error) {
    if (error instanceof DatabaseMigrationError) throw error;
    throw new DatabaseMigrationError('authentication');
  } finally {
    zeroize(plaintext);
    zeroize(rootKey);
    zeroize(portableKey);
  }
}

function localVaultMetadataDigest(
  document: LocalVaultDocument,
): ReturnType<typeof sha256DigestSchema.parse> {
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

async function readSecretOnce(read: () => Promise<Uint8Array>): Promise<Uint8Array> {
  const value = await read();
  if (!(value instanceof Uint8Array)) throw new DatabaseMigrationError('invalid');
  return value;
}

function parseSourceDocument(value: LocalVaultDocument): LocalVaultDocument {
  try {
    return localVaultDocumentSchema.parse(value);
  } catch {
    throw new DatabaseMigrationError('invalid');
  }
}

function isAmbiguous(error: unknown): boolean {
  return (
    (error instanceof DatabaseSessionError &&
      (error.code === 'ambiguous-commit' || error.code === 'close')) ||
    (error instanceof DatabaseMigrationError && error.code === 'ambiguous-commit')
  );
}

function mapMigrationError(error: unknown): DatabaseMigrationError {
  if (error instanceof DatabaseMigrationError) return error;
  if (error instanceof DatabaseSessionError) {
    if (error.code === 'duplicate' || error.code === 'conflict') {
      return new DatabaseMigrationError('conflict');
    }
    if (error.code === 'invalid' || error.code === 'binding') {
      return new DatabaseMigrationError('invalid');
    }
    if (error.code === 'ambiguous-commit') {
      return new DatabaseMigrationError('ambiguous-commit');
    }
    if (error.code === 'close') {
      return new DatabaseMigrationError('ambiguous-commit');
    }
  }
  return new DatabaseMigrationError('authentication');
}

function redactedMigrationAggregate(
  primary: unknown,
  cleanupErrors: readonly DatabaseMigrationError[],
): AggregateError {
  return new AggregateError(
    [mapMigrationError(primary), ...cleanupErrors],
    'Migration cleanup failed.',
  );
}

async function closeQuietly(
  session: DatabaseSession | undefined,
  store: EncryptedDatabaseStore | undefined,
): Promise<void> {
  if (session !== undefined) await session.close().catch(() => undefined);
  else if (store !== undefined) await store.close().catch(() => undefined);
}

function messageFor(code: DatabaseMigrationErrorCode): string {
  const messages: Record<DatabaseMigrationErrorCode, string> = {
    'ambiguous-commit':
      'Migration publication is ambiguous; recovery artifacts were retained.',
    authentication: 'Legacy vault migration authentication failed.',
    conflict: 'The migration destination changed or already exists.',
    invalid: 'The migration request is invalid.',
    verification: 'The migrated vault did not pass exact local verification.',
  };
  return messages[code];
}
