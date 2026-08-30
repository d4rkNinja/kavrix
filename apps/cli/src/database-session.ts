import { createHmac, hkdfSync, randomUUID } from 'node:crypto';

import { ZodError } from 'zod';

import {
  createDatabaseKeySlot,
  createDatabaseRecoverySlot,
  computeDatabaseVaultPayloadMetadataDigest,
  decryptDatabaseCatalog,
  decryptPayload,
  deriveAuthorizationStateKey,
  encryptDatabaseCatalog,
  encryptPayload,
  generateDatabaseRootKey,
  generatePortableKey,
  generateVaultRootKey,
  unlockDatabaseKeySlot,
  unlockDatabaseRecoverySlot,
  unwrapVaultRootForDatabase,
  wrapVaultRootForDatabase,
  zeroize,
  type DatabaseRootKey,
  type DatabaseSlotBinding,
  type DatabaseVaultPayloadDigestMetadata,
  type PortableKey,
  type RecoveryKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  databaseRevisionAnchorPath,
  cleanupOwnedDatabaseKeyFile,
  cleanupOwnedDatabaseRecoveryKitFile,
  cleanupOwnedDatabaseRevisionAnchor,
  consumeDatabaseLocalShareBootstrap,
  createOwnedDatabaseKeyFile,
  createOwnedDatabaseLocalShareKeyFile,
  createOwnedDatabaseRecoveryKitFile,
  createOwnedDatabaseRevisionAnchor,
  readDatabaseKeyFile,
  readDatabaseKeyFileBinding,
  readDatabaseRecoveryKitFile,
  readDatabaseRevisionAnchor,
  releaseOwnedDatabaseKeyFile,
  releaseOwnedDatabaseRecoveryKitFile,
  releaseOwnedDatabaseRevisionAnchor,
  transitionDatabaseRevisionAnchor,
  transitionOwnedDatabaseRevisionAnchor,
  validateSecureFileDestination,
  writeDatabaseRevisionAnchor,
  PortableKeyFileError,
  type DatabaseKeyFilePublication,
  type DatabaseKeyBinding,
  type ParsedDatabaseKeyFile,
  type DatabaseRecoveryBinding,
  type DatabaseRecoveryKitFilePublication,
  type DatabaseRevisionAnchor,
  type DatabaseRevisionAnchorPublication,
} from '@kavrix/key-files';
import {
  CURRENT_CRYPTOGRAPHIC_VERSION,
  CURRENT_SCHEMA_VERSION,
  associatedDataSchema,
  canonicalJson,
  databaseAssociatedDataSchema,
  databaseCatalogPayloadSchema,
  databaseIdSchema,
  databaseRevisionSchema,
  databaseVaultPayloadSchema,
  databaseVaultDocumentSchema,
  encryptedDatabaseDocumentSchema,
  keySlotIdSchema,
  keyVersionSchema,
  localVaultPayloadSchema,
  MAX_CIPHERTEXT_CHARS,
  sha256DigestSchema,
  structuredVaultPayloadSchema,
  supportedCryptographicVersionSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type DatabaseCatalogPayload,
  type DatabaseAssociatedData,
  type DatabaseId,
  type DatabaseRecoverySlot,
  type DatabaseRevision,
  type DatabaseVaultDocument,
  type DatabaseVaultPayload,
  type EncryptedDatabaseDocument,
  type LocalVaultPayload,
  type AssociatedData,
  type Sha256Digest,
  type StructuredVaultPayload,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';
import {
  EncryptedDatabaseStoreError,
  type EncryptedDatabaseStore,
} from '@kavrix/storage';

import { LocalCliError } from './cli-error.js';
import {
  DatastoreProfileError,
  validateDatastoreProfileBindingPublicationResult,
  type DatastoreProfileBindingPublicationResult,
} from './datastore-profiles.js';
import { LocalSecretInputError } from './local-secrets.js';
import { CodedCliError } from './execution/exit-codes.js';
import {
  applyFlatVaultPayload,
  createEmptyStructuredVaultPayload,
  isStructuredVaultPayload,
  projectFlatVaultPayload,
  upgradeLegacyVaultPayload,
} from './structured-vault-projection.js';

const MAX_LABEL_BYTES = 1_024;
// Match the already-published envelope limit exactly so no authenticated
// legacy document becomes unreadable merely because its plaintext is near
// the maximum representable ciphertext size.
const MAX_DATABASE_VAULT_PAYLOAD_BYTES = Math.floor((MAX_CIPHERTEXT_CHARS * 3) / 4);
const UTF8_ENCODER = new TextEncoder();
const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
let zeroizationObserver: ((cleared: true) => void) | undefined;
const DATABASE_VAULT_DELETION_AUTHORIZATION = Symbol(
  'database-vault-deletion-authorization',
);
type DatabaseVaultDeletionAuthorization = Readonly<{
  token: typeof DATABASE_VAULT_DELETION_AUTHORIZATION;
}>;
declare const migrationInitializationOwnershipBrand: unique symbol;
export type MigrationInitializationOwnership = Readonly<{
  readonly [migrationInitializationOwnershipBrand]: true;
}>;
type MigrationInitializationOwnershipState = Readonly<{
  databaseId: DatabaseId;
  rollbackDatabase: (databaseId: DatabaseId) => Promise<void>;
  keyPublication: DatabaseKeyFilePublication;
  anchorPublication: DatabaseRevisionAnchorPublication;
}>;
const migrationInitializationOwnerships = new WeakMap<
  object,
  MigrationInitializationOwnershipState
>();
const MIGRATION_INITIALIZATION_REQUEST = Symbol('migration-initialization-request');

export type DatabaseSessionErrorCode =
  | 'ambiguous-commit'
  | 'authentication'
  | 'binding'
  | 'busy'
  | 'close'
  | 'conflict'
  | 'duplicate'
  | 'invalid'
  | 'not-found'
  | 'operation'
  | 'rollback';

/** Stable documented exit codes for each session failure class. */
const SESSION_EXIT_CODES: Readonly<Record<DatabaseSessionErrorCode, number>> =
  Object.freeze({
    'ambiguous-commit': 15,
    authentication: 10,
    binding: 16,
    busy: 15,
    close: 15,
    conflict: 15,
    duplicate: 14,
    invalid: 14,
    'not-found': 11,
    operation: 15,
    rollback: 16,
  });

export class DatabaseSessionError extends Error {
  public constructor(public readonly code: DatabaseSessionErrorCode) {
    super(messageFor(code));
    this.name = 'DatabaseSessionError';
  }

  /** Exit code from the stable CLI contract for this failure class. */
  public get cliExitCode(): number {
    return SESSION_EXIT_CODES[this.code];
  }
}

/** @internal Test-only observation without exposing key bytes. */
export function setDatabaseSessionZeroizationObserverForTest(
  observer: ((cleared: true) => void) | undefined,
): void {
  zeroizationObserver = observer;
}

export type DatabaseVaultCatalogEntry = Readonly<{
  id: VaultId;
  label: string;
  createdAt: string;
}>;

export type DatabaseInitializationOptions = Readonly<{
  store: EncryptedDatabaseStore;
  keyFile: string;
  passphrase: Uint8Array;
  label: string;
  anchorFile?: string;
  rollbackDatabase?: (databaseId: DatabaseId) => Promise<void>;
  publishBinding?: (
    databaseId: DatabaseId,
  ) => Promise<DatastoreProfileBindingPublicationResult>;
}>;

export type DatabaseOpenOptions = Readonly<{
  store: EncryptedDatabaseStore;
  keyFile: string;
  passphrase: Uint8Array;
  expectedDatabaseId?: DatabaseId;
  anchorFile?: string;
}>;

export type DatabaseOpenWithSecretOptions = Omit<DatabaseOpenOptions, 'passphrase'> &
  Readonly<{
    readPassphrase: () => Promise<Uint8Array>;
    /**
     * Explicitly re-anchor the local rollback guard to the currently observed
     * datastore state after full authenticated verification of every encrypted
     * document. This consciously abandons rollback protection for revisions
     * at or below the observed state and must only run after a human has
     * verified the datastore contents.
     */
    acceptCurrentAnchor?: boolean;
  }>;

export type DatabaseAuthorizationStateAccess = Readonly<{
  databaseId: DatabaseId;
  authorizationStateKey: Uint8Array;
}>;

export type DatabaseRecoveryCreateOptions = Readonly<{
  recoveryFile: string;
  passphrase: Uint8Array;
}>;

export type DatabaseLocalShareKeyCreateOptions = Readonly<{
  keyFile: string;
  passphrase: Uint8Array;
}>;

export type DatabaseRecoveryVerifyOptions = DatabaseRecoveryCreateOptions &
  Readonly<{ expectedBinding?: DatabaseRecoveryBinding }>;

export type DatabaseRecoveryUseOptions = Readonly<{
  store: EncryptedDatabaseStore;
  recoveryFile: string;
  recoveryPassphrase: Uint8Array;
  outputKeyFile: string;
  newPassphrase: Uint8Array;
  anchorFile?: string;
  expectedBinding: DatabaseRecoveryBinding;
}>;

export class DatabaseSession {
  readonly #store: EncryptedDatabaseStore;
  readonly #anchorFile: string;
  readonly #databaseId: DatabaseId;
  readonly #rootKey: DatabaseRootKey;
  readonly #portableKey: PortableKey;
  #database: EncryptedDatabaseDocument;
  #catalog: DatabaseCatalogPayload;
  #closed = false;
  readonly #acceptedCurrentAnchor: boolean;

  private constructor(
    options: Readonly<{
      store: EncryptedDatabaseStore;
      anchorFile: string;
      database: EncryptedDatabaseDocument;
      catalog: DatabaseCatalogPayload;
      rootKey: DatabaseRootKey;
      portableKey: PortableKey;
      acceptedCurrentAnchor?: boolean;
    }>,
  ) {
    this.#store = options.store;
    this.#anchorFile = options.anchorFile;
    this.#databaseId = options.database.id;
    this.#database = options.database;
    this.#catalog = options.catalog;
    this.#rootKey = options.rootKey;
    this.#portableKey = options.portableKey;
    this.#acceptedCurrentAnchor = options.acceptedCurrentAnchor === true;
  }

  /** Whether this session re-anchored the local rollback guard on open. */
  public get acceptedCurrentAnchor(): boolean {
    return this.#acceptedCurrentAnchor;
  }

  public static async validateInitializationDestinations(
    keyFile: string,
    anchorFile = databaseRevisionAnchorPath(keyFile),
  ): Promise<void> {
    await validateSecureFileDestination(keyFile);
    await validateSecureFileDestination(anchorFile);
  }

  public static async validateRecoveryDestinations(
    recoveryFile: string,
  ): Promise<void> {
    await validateSecureFileDestination(recoveryFile);
    await validateSecureFileDestination(databaseRevisionAnchorPath(recoveryFile));
  }

  public static async validateRecoveredOwnerDestinations(
    keyFile: string,
    anchorFile = databaseRevisionAnchorPath(keyFile),
  ): Promise<void> {
    await this.validateInitializationDestinations(keyFile, anchorFile);
  }

  public static async initialize(
    options: DatabaseInitializationOptions,
  ): Promise<
    Readonly<{ databaseId: DatabaseId; keyFile: string; anchorFile: string }>
  > {
    const anchorFile =
      options.anchorFile ?? databaseRevisionAnchorPath(options.keyFile);
    await this.validateInitializationDestinations(options.keyFile, anchorFile);
    const label = parseLabel(options.label);
    const passphrase = Uint8Array.from(options.passphrase);
    const databaseId = databaseIdSchema.parse(`db_${randomUUID()}`);
    const slotId = keySlotIdSchema.parse(`slot_${randomUUID()}`);
    const portableKey = generatePortableKey();
    const rootKey = generateDatabaseRootKey();
    let keyPublication: DatabaseKeyFilePublication | undefined;
    let databaseMayExist = false;
    let anchorPublication: DatabaseRevisionAnchorPublication | undefined;
    let bindingPublicationUncertain = false;
    let retainPublishedArtifacts = false;
    try {
      const database = await createInitialDatabase(
        databaseId,
        slotId,
        label,
        portableKey,
        rootKey,
      );
      const createdKey = await createOwnedDatabaseKeyFile(
        options.keyFile,
        portableKey,
        { databaseId, keySlotId: slotId },
        { protection: { kind: 'passphrase', passphrase } },
      );
      if (createdKey.status !== 'not-published')
        keyPublication = createdKey.publication;
      if (createdKey.status !== 'published') throw createdKey.error;
      databaseMayExist = true;
      try {
        await options.store.createDatabase(database);
      } catch (error) {
        if (
          error instanceof EncryptedDatabaseStoreError &&
          (error.code === 'exists' ||
            error.code === 'conflict' ||
            error.code === 'invalid')
        )
          databaseMayExist = false;
        throw error;
      }
      const anchor = await observedAnchor(options.store, database);
      const createdAnchor = await createOwnedDatabaseRevisionAnchor(
        anchorFile,
        rootKey,
        anchor,
      );
      if (createdAnchor.status !== 'not-published')
        anchorPublication = createdAnchor.publication;
      if (createdAnchor.status !== 'published') throw createdAnchor.error;
      await readDatabaseRevisionAnchor(anchorFile, rootKey, anchor, {
        requireExactVaultSet: true,
      });
      if (options.publishBinding !== undefined) {
        let resolvedPublication: unknown;
        try {
          resolvedPublication = await options.publishBinding(databaseId);
        } catch {
          bindingPublicationUncertain = true;
          throw new DatabaseSessionError('ambiguous-commit');
        }
        const bindingPublication =
          validateDatastoreProfileBindingPublicationResult(resolvedPublication);
        if (bindingPublication === undefined) {
          bindingPublicationUncertain = true;
          throw new DatabaseSessionError('ambiguous-commit');
        }
        if (bindingPublication.status !== 'published') {
          if (bindingPublication.status === 'not-published') {
            throw new DatastoreProfileError(bindingPublication.errorCategory);
          }
          bindingPublicationUncertain = true;
          throw new DatabaseSessionError('ambiguous-commit');
        }
      }
      const result = { databaseId, keyFile: options.keyFile, anchorFile };
      if (
        (
          options as DatabaseInitializationOptions & {
            migrationRequest?: symbol;
          }
        ).migrationRequest === MIGRATION_INITIALIZATION_REQUEST
      ) {
        if (
          options.rollbackDatabase === undefined ||
          keyPublication === undefined ||
          anchorPublication === undefined
        ) {
          throw new DatabaseSessionError('operation');
        }
        const ownership = Object.freeze({}) as MigrationInitializationOwnership;
        migrationInitializationOwnerships.set(ownership, {
          databaseId,
          rollbackDatabase: options.rollbackDatabase,
          keyPublication,
          anchorPublication,
        });
        return { ...result, ownership } as typeof result;
      }
      retainPublishedArtifacts = true;
      await releaseOwnedPublications([
        () => releaseOwnedDatabaseRevisionAnchor(createdAnchor.publication),
        () => releaseOwnedDatabaseKeyFile(createdKey.publication),
      ]);
      return result;
    } catch (error) {
      const cleanupErrors: DatabaseSessionError[] = [];
      if (bindingPublicationUncertain || retainPublishedArtifacts) {
        await releaseOwnedPublications(
          ownerPublicationReleases(anchorPublication, keyPublication),
          false,
        );
        throw new DatabaseSessionError('ambiguous-commit');
      }
      if (databaseMayExist && options.rollbackDatabase !== undefined) {
        try {
          await options.rollbackDatabase(databaseId);
          databaseMayExist = false;
        } catch {
          cleanupErrors.push(new DatabaseSessionError('operation'));
        }
      }
      if (!databaseMayExist) {
        if (anchorPublication !== undefined) {
          const ownedAnchor = anchorPublication;
          await cleanupOwned(
            () => cleanupOwnedDatabaseRevisionAnchor(ownedAnchor),
            cleanupErrors,
          );
        }
        if (keyPublication !== undefined) {
          const ownedKey = keyPublication;
          await cleanupOwned(
            () => cleanupOwnedDatabaseKeyFile(ownedKey),
            cleanupErrors,
          );
        }
      }
      if (databaseMayExist) {
        await releaseOwnedPublications(
          ownerPublicationReleases(anchorPublication, keyPublication),
          false,
        );
        throw new DatabaseSessionError('ambiguous-commit');
      }
      if (cleanupErrors.length > 0)
        throw redactedAggregate(error, cleanupErrors, 'Database cleanup failed.');
      throw mapError(error);
    } finally {
      zeroize(rootKey);
      observeCleared(rootKey);
      zeroize(portableKey);
      zeroize(passphrase);
    }
  }

  /** Initializes a database while retaining opaque rollback ownership. */
  public static async initializeForMigration(
    options: Omit<DatabaseInitializationOptions, 'publishBinding'> &
      Readonly<{
        rollbackDatabase: (databaseId: DatabaseId) => Promise<void>;
      }>,
  ): Promise<
    Readonly<{
      databaseId: DatabaseId;
      keyFile: string;
      anchorFile: string;
      ownership: MigrationInitializationOwnership;
    }>
  > {
    return (await this.initialize({
      ...options,
      migrationRequest: MIGRATION_INITIALIZATION_REQUEST,
    } as DatabaseInitializationOptions)) as Awaited<
      ReturnType<typeof DatabaseSession.initializeForMigration>
    >;
  }

  /** Consumes initialization rollback authority after verified publication. */
  public static async commitMigrationInitialization(
    ownership: MigrationInitializationOwnership,
  ): Promise<void> {
    await this.releaseMigrationInitializationOwnership(ownership);
  }

  /** Leaves ambiguous initialization artifacts intact while closing authority. */
  public static async releaseMigrationInitializationOwnership(
    ownership: MigrationInitializationOwnership,
  ): Promise<void> {
    const state = requireMigrationInitializationOwnership(ownership);
    await releaseOwnedPublications([
      () => releaseOwnedDatabaseRevisionAnchor(state.anchorPublication),
      () => releaseOwnedDatabaseKeyFile(state.keyPublication),
    ]);
    migrationInitializationOwnerships.delete(ownership);
  }

  /** Rolls back only the exact database/key/anchor artifacts owned by migration. */
  public static async rollbackMigrationInitialization(
    ownership: MigrationInitializationOwnership,
  ): Promise<void> {
    const state = requireMigrationInitializationOwnership(ownership);
    try {
      await state.rollbackDatabase(state.databaseId);
    } catch {
      await releaseOwnedPublications(
        [
          () => releaseOwnedDatabaseRevisionAnchor(state.anchorPublication),
          () => releaseOwnedDatabaseKeyFile(state.keyPublication),
        ],
        false,
      );
      migrationInitializationOwnerships.delete(ownership);
      throw new DatabaseSessionError('ambiguous-commit');
    }
    const cleanupErrors: DatabaseSessionError[] = [];
    await cleanupOwned(
      () => cleanupOwnedDatabaseRevisionAnchor(state.anchorPublication),
      cleanupErrors,
    );
    await cleanupOwned(
      () => cleanupOwnedDatabaseKeyFile(state.keyPublication),
      cleanupErrors,
    );
    if (cleanupErrors.length > 0) {
      await releaseOwnedPublications(
        [
          () => releaseOwnedDatabaseRevisionAnchor(state.anchorPublication),
          () => releaseOwnedDatabaseKeyFile(state.keyPublication),
        ],
        false,
      );
      migrationInitializationOwnerships.delete(ownership);
      throw new DatabaseSessionError('ambiguous-commit');
    }
    migrationInitializationOwnerships.delete(ownership);
  }

  public static async open(options: DatabaseOpenOptions): Promise<DatabaseSession> {
    return this.openWithSecret({
      ...options,
      readPassphrase: () => Promise.resolve(options.passphrase),
    });
  }

  public static async openWithSecret(
    options: DatabaseOpenWithSecretOptions,
  ): Promise<DatabaseSession> {
    let passphrase: Uint8Array | undefined;
    let portableKey: PortableKey | undefined;
    let rootKey: DatabaseRootKey | undefined;
    let catalogBytes: Uint8Array | undefined;
    try {
      const publicBinding = await readDatabaseKeyFileBinding(options.keyFile);
      if (
        options.expectedDatabaseId !== undefined &&
        publicBinding.databaseId !== options.expectedDatabaseId
      ) {
        throw new DatabaseSessionError('binding');
      }
      const database = await options.store.getDatabase(publicBinding.databaseId);
      if (database?.id !== publicBinding.databaseId) {
        throw new DatabaseSessionError('binding');
      }
      if (database.keySlot.id !== publicBinding.keySlotId) {
        throw new DatabaseSessionError('binding');
      }
      passphrase = Uint8Array.from(await options.readPassphrase());
      const parsed = await readDatabaseKeyFile(
        options.keyFile,
        passphrase,
        publicBinding,
      );
      portableKey = parsed.portableKey;
      rootKey = await unlockDatabaseKeySlot(
        database.keySlot,
        portableKey,
        slotBinding(database, database.keySlot),
      );
      catalogBytes = await decryptDatabaseCatalog(
        database.encryptedCatalog,
        rootKey,
        database.encryptedCatalog.aad,
      );
      const catalog = decodeCatalog(catalogBytes);
      const anchorFile =
        options.anchorFile ?? databaseRevisionAnchorPath(options.keyFile);
      const observed = await authenticateDatabaseState(
        options.store,
        database,
        catalog,
        rootKey,
      );
      const acceptedCurrentAnchor = await reconcileOpenAnchorWithMapping({
        acceptCurrent: options.acceptCurrentAnchor === true,
        anchorFile,
        rootKey,
        observed,
        keyFile: options.keyFile,
        binding: publicBinding,
        keyFileVersion: parsed.fileVersion,
        portableKey,
        passphrase,
        ...(parsed.localShareBootstrap === undefined
          ? {}
          : { localShareBootstrap: parsed.localShareBootstrap }),
      });
      const session = new DatabaseSession({
        store: options.store,
        anchorFile,
        database,
        catalog,
        rootKey,
        portableKey,
        acceptedCurrentAnchor,
      });
      rootKey = undefined;
      portableKey = undefined;
      return session;
    } catch (error) {
      throw mapError(error);
    } finally {
      zeroize(catalogBytes);
      zeroize(rootKey);
      if (rootKey !== undefined) observeCleared(rootKey);
      zeroize(portableKey);
      zeroize(passphrase);
    }
  }

  /**
   * Unlocks only the database metadata needed to authenticate and derive the
   * sealed authorization-state key. Credential vault payloads are deliberately
   * not decrypted on this path; policy tooling must not read credential data.
   */
  public static async openAuthorizationStateAccess(
    options: DatabaseOpenOptions,
  ): Promise<DatabaseAuthorizationStateAccess> {
    let passphrase: Uint8Array | undefined;
    let portableKey: PortableKey | undefined;
    let rootKey: DatabaseRootKey | undefined;
    try {
      const publicBinding = await readDatabaseKeyFileBinding(options.keyFile);
      if (
        options.expectedDatabaseId !== undefined &&
        publicBinding.databaseId !== options.expectedDatabaseId
      ) {
        throw new DatabaseSessionError('binding');
      }
      const database = await options.store.getDatabase(publicBinding.databaseId);
      if (database?.id !== publicBinding.databaseId) {
        throw new DatabaseSessionError('binding');
      }
      if (database.keySlot.id !== publicBinding.keySlotId) {
        throw new DatabaseSessionError('binding');
      }

      passphrase = Uint8Array.from(options.passphrase);
      const parsed = await readDatabaseKeyFile(
        options.keyFile,
        passphrase,
        publicBinding,
      );
      portableKey = parsed.portableKey;
      rootKey = await unlockDatabaseKeySlot(
        database.keySlot,
        portableKey,
        slotBinding(database, database.keySlot),
      );
      const vaults = await options.store.listVaults(database.id);
      const observed = anchorFromVaults(database, vaults);
      await verifyReadOnlyOpenAnchor({
        anchorFile: options.anchorFile ?? databaseRevisionAnchorPath(options.keyFile),
        rootKey,
        observed,
      });
      return {
        databaseId: database.id,
        authorizationStateKey: deriveAuthorizationStateKey(rootKey, {
          scopeKind: 'database',
          scopeId: database.id,
        }),
      };
    } catch (error) {
      throw mapError(error);
    } finally {
      zeroize(rootKey);
      if (rootKey !== undefined) observeCleared(rootKey);
      zeroize(portableKey);
      zeroize(passphrase);
    }
  }

  public get databaseId(): DatabaseId {
    return this.#databaseId;
  }

  /**
   * Fresh purpose-bound key for the database's sealed authorization state.
   * The database root key itself never leaves the session; only the derived
   * scope-bound key is published to the caller, and each call yields new bytes
   * the caller must zeroize after use.
   */
  public authorizationStateKey(): Uint8Array {
    this.#assertOpen();
    return deriveAuthorizationStateKey(this.#rootKey, {
      scopeKind: 'database',
      scopeId: this.#databaseId,
    });
  }

  public status(): Readonly<{
    databaseId: DatabaseId;
    revision: DatabaseRevision;
    vaultCount: number;
    activeRecoverySlots: number;
  }> {
    this.#assertOpen();
    return {
      databaseId: this.#databaseId,
      revision: this.#database.revision,
      vaultCount: this.#catalog.vaults.length,
      activeRecoverySlots: this.#database.recoverySlots.filter(
        (slot) => slot.state === 'active',
      ).length,
    };
  }

  public listVaults(): readonly DatabaseVaultCatalogEntry[] {
    this.#assertOpen();
    return this.#catalog.vaults.map((entry) => ({ ...entry }));
  }

  public async getVault(id: VaultId): Promise<DatabaseVaultCatalogEntry> {
    this.#assertOpen();
    const parsed = vaultIdSchema.parse(id);
    const entry = this.#catalog.vaults.find((candidate) => candidate.id === parsed);
    if (entry === undefined) throw new DatabaseSessionError('not-found');
    const document = await this.#store.getVault(this.#databaseId, parsed);
    if (document === null) throw new DatabaseSessionError('not-found');
    return { ...entry };
  }

  public async getVaultDocument(id: VaultId): Promise<DatabaseVaultDocument> {
    this.#assertOpen();
    const document = await this.#store.getVault(
      this.#databaseId,
      vaultIdSchema.parse(id),
    );
    if (document === null) throw new DatabaseSessionError('not-found');
    return document;
  }

  public async createVault(labelInput: string): Promise<DatabaseVaultCatalogEntry> {
    return (
      await this.#createVaultWithPayload(
        labelInput,
        (id, createdAt) => createEmptyStructuredVaultPayload(id, createdAt),
        false,
      )
    ).entry;
  }

  /** Prepares and verifies the complete payload before one atomic publication. */
  public async createMigrationVault(
    labelInput: string,
    stage: (empty: LocalVaultPayload) => LocalVaultPayload | Promise<LocalVaultPayload>,
    initializationOwnership?: MigrationInitializationOwnership,
  ): Promise<DatabaseVaultCatalogEntry> {
    this.#assertOpen();
    const ownershipState =
      initializationOwnership === undefined
        ? undefined
        : requireMigrationInitializationOwnership(initializationOwnership);
    if (
      ownershipState !== undefined &&
      ownershipState.databaseId !== this.#databaseId
    ) {
      throw new DatabaseSessionError('invalid');
    }
    const payload = localVaultPayloadSchema.parse(
      await stage(structuredClone(localVaultPayloadSchema.parse({ records: {} }))),
    );
    const created = await this.#createVaultWithPayload(
      labelInput,
      (id, createdAt) => upgradeLegacyVaultPayload(payload, id, createdAt),
      true,
      ownershipState?.anchorPublication,
    );
    if (
      initializationOwnership !== undefined &&
      ownershipState !== undefined &&
      created.anchorPublication !== undefined
    ) {
      migrationInitializationOwnerships.set(initializationOwnership, {
        ...ownershipState,
        anchorPublication: created.anchorPublication,
      });
    }
    return created.entry;
  }

  async #createVaultWithPayload(
    labelInput: string,
    payloadInput:
      | DatabaseVaultPayload
      | ((id: VaultId, createdAt: Timestamp) => DatabaseVaultPayload),
    verifyBeforePublication: boolean,
    ownedAnchorPublication?: DatabaseRevisionAnchorPublication,
  ): Promise<
    Readonly<{
      entry: DatabaseVaultCatalogEntry;
      anchorPublication?: DatabaseRevisionAnchorPublication;
    }>
  > {
    this.#assertOpen();
    const label = parseLabel(labelInput);
    if (this.#catalog.vaults.some((entry) => entry.label === label)) {
      throw new DatabaseSessionError('duplicate');
    }
    const id = vaultIdSchema.parse(`vault_${randomUUID()}`);
    const createdAt = timestampSchema.parse(now());
    const payload = databaseVaultPayloadSchema.parse(
      typeof payloadInput === 'function' ? payloadInput(id, createdAt) : payloadInput,
    );
    const nextCatalog = databaseCatalogPayloadSchema.parse({
      ...this.#catalog,
      vaults: [...this.#catalog.vaults, { id, label, createdAt }],
    });
    const nextDatabase = await reencryptCatalog(
      this.#database,
      nextCatalog,
      this.#rootKey,
    );
    const root = generateVaultRootKey();
    try {
      const vault = await createVaultDocument(
        nextDatabase,
        id,
        createdAt,
        root,
        this.#rootKey,
        payload,
      );
      if (verifyBeforePublication) {
        const observed = await decryptAuthenticatedVaultPayload(vault, this.#rootKey);
        if (canonicalJson(observed) !== canonicalJson(payload)) {
          throw new DatabaseSessionError('authentication');
        }
      }
      const before = await observedAnchor(this.#store, this.#database);
      const after = anchorWithCreatedVault(before, nextDatabase, vault);
      const anchorPublication = await this.#anchoredMutation(
        before,
        after,
        async () => {
          await this.#store.createVault({
            database: nextDatabase,
            expectedDatabaseRevision: this.#database.revision,
            vault,
          });
        },
        ownedAnchorPublication,
      );
      this.#database = nextDatabase;
      this.#catalog = nextCatalog;
      return {
        entry: { id, label, createdAt },
        ...(anchorPublication === undefined ? {} : { anchorPublication }),
      };
    } catch (error) {
      throw mapError(error);
    } finally {
      zeroize(root);
    }
  }

  public async renameVault(idInput: VaultId, labelInput: string): Promise<void> {
    this.#assertOpen();
    const id = vaultIdSchema.parse(idInput);
    const label = parseLabel(labelInput);
    const current = this.#catalog.vaults.find((entry) => entry.id === id);
    if (current === undefined) throw new DatabaseSessionError('not-found');
    if (this.#catalog.vaults.some((entry) => entry.id !== id && entry.label === label))
      throw new DatabaseSessionError('duplicate');
    const nextCatalog = databaseCatalogPayloadSchema.parse({
      ...this.#catalog,
      vaults: this.#catalog.vaults.map((entry) =>
        entry.id === id ? { ...entry, label } : entry,
      ),
    });
    const nextDatabase = await reencryptCatalog(
      this.#database,
      nextCatalog,
      this.#rootKey,
    );
    await this.#databaseMutation(nextDatabase);
    this.#database = nextDatabase;
    this.#catalog = nextCatalog;
  }

  /** Updates authenticated plaintext while keeping the VRK inside the session. */
  public async updateVault(
    idInput: VaultId,
    update: (
      current: LocalVaultPayload,
    ) => LocalVaultPayload | Promise<LocalVaultPayload>,
  ): Promise<DatabaseVaultDocument> {
    return this.#updateDatabaseVaultPayload(idInput, async (current) => {
      const currentFlat = projectFlatVaultPayload(current);
      const nextFlat = localVaultPayloadSchema.parse(
        await update(structuredClone(currentFlat)),
      );
      if (!isStructuredVaultPayload(current)) return nextFlat;
      return applyFlatVaultPayload(
        current,
        currentFlat,
        nextFlat,
        timestampSchema.parse(now()),
      );
    });
  }

  /** Updates the complete encrypted hierarchy, explicitly upgrading legacy payloads. */
  public async updateStructuredVault(
    idInput: VaultId,
    update: (
      current: StructuredVaultPayload,
    ) => StructuredVaultPayload | Promise<StructuredVaultPayload>,
  ): Promise<DatabaseVaultDocument> {
    const requestedId = vaultIdSchema.parse(idInput);
    return this.#updateDatabaseVaultPayload(requestedId, async (current) => {
      const at = timestampSchema.parse(now());
      const structured = isStructuredVaultPayload(current)
        ? current
        : upgradeLegacyVaultPayload(current, requestedId, at);
      return structuredVaultPayloadSchema.parse(
        await update(structuredClone(structured)),
      );
    });
  }

  async #updateDatabaseVaultPayload(
    idInput: VaultId,
    update: (
      current: DatabaseVaultPayload,
    ) => DatabaseVaultPayload | Promise<DatabaseVaultPayload>,
  ): Promise<DatabaseVaultDocument> {
    this.#assertOpen();
    const requestedId = vaultIdSchema.parse(idInput);
    const current = await this.getVaultDocument(requestedId);
    let root: VaultRootKey | undefined;
    let plaintext: Uint8Array | undefined;
    let nextPlaintext: Uint8Array | undefined;
    try {
      root = await unwrapVaultRootForDatabase(
        current.wrappedVaultRoot,
        this.#rootKey,
        current.wrappedVaultRoot.aad,
      );
      plaintext = await decryptPayload(
        current.encryptedPayload,
        root,
        vaultPayloadContext(current, current.revision, current.payloadMetadataDigest),
      );
      assertDatabaseVaultPayloadSize(plaintext);
      if (
        vaultMetadataDigest(current, root, plaintext) !== current.payloadMetadataDigest
      )
        throw new DatabaseSessionError('authentication');
      const currentPayload = databaseVaultPayloadSchema.parse(
        JSON.parse(decodeSecretUtf8(plaintext)) as unknown,
      );
      const nextPayload = databaseVaultPayloadSchema.parse(
        await update(structuredClone(currentPayload)),
      );
      assertDatabaseVaultPayloadBinding(nextPayload, requestedId);
      nextPlaintext = UTF8_ENCODER.encode(canonicalJson(nextPayload));
      assertDatabaseVaultPayloadSize(nextPlaintext);
      const updatedAt = now();
      const revision = vaultRevisionSchema.parse(current.revision + 1);
      const metadata = {
        ...current,
        revision,
        updatedAt,
      };
      const payloadMetadataDigest = vaultMetadataDigest(metadata, root, nextPlaintext);
      const encryptedPayload = await encryptPayload(
        nextPlaintext,
        root,
        vaultPayloadContext(current, revision, payloadMetadataDigest),
      );
      const updated = databaseVaultDocumentSchema.parse({
        ...metadata,
        payloadMetadataDigest,
        encryptedPayload,
      });
      const before = await observedAnchor(this.#store, this.#database);
      const after = anchorWithUpdatedVault(before, updated);
      await this.#anchoredMutation(before, after, async () =>
        this.#store.updateVault({
          vault: updated,
          expectedVaultRevision: current.revision,
        }),
      );
      return updated;
    } catch (error) {
      throw mapError(error);
    } finally {
      zeroize(plaintext);
      zeroize(nextPlaintext);
      zeroize(root);
    }
  }

  /** Locally decrypts one vault for bounded verification without mutating it. */
  public async inspectVault(
    idInput: VaultId,
    inspect: (payload: LocalVaultPayload) => void | Promise<void>,
  ): Promise<DatabaseVaultDocument> {
    this.#assertOpen();
    const current = await this.getVaultDocument(vaultIdSchema.parse(idInput));
    try {
      const payload = await decryptAuthenticatedVaultPayload(current, this.#rootKey);
      await inspect(structuredClone(projectFlatVaultPayload(payload)));
      return current;
    } catch (error) {
      throw mapError(error);
    }
  }

  /** Locally decrypts the complete hierarchy, upgrading legacy payloads in memory only. */
  public async inspectStructuredVault(
    idInput: VaultId,
    inspect: (payload: StructuredVaultPayload) => void | Promise<void>,
  ): Promise<DatabaseVaultDocument> {
    this.#assertOpen();
    const requestedId = vaultIdSchema.parse(idInput);
    const current = await this.getVaultDocument(requestedId);
    try {
      const payload = await decryptAuthenticatedVaultPayload(current, this.#rootKey);
      const structured = isStructuredVaultPayload(payload)
        ? payload
        : upgradeLegacyVaultPayload(payload, requestedId, timestampSchema.parse(now()));
      await inspect(structuredClone(structured));
      return current;
    } catch (error) {
      throw mapError(error);
    }
  }

  /** Internal policy port; no unguarded CLI command is registered in this task. */
  public async deleteVault(
    idInput: VaultId,
    authorization?: DatabaseVaultDeletionAuthorization,
  ): Promise<void> {
    this.#assertOpen();
    if (authorization?.token !== DATABASE_VAULT_DELETION_AUTHORIZATION)
      throw new DatabaseSessionError('invalid');
    const id = vaultIdSchema.parse(idInput);
    const vault = await this.getVaultDocument(id);
    const nextCatalog = databaseCatalogPayloadSchema.parse({
      ...this.#catalog,
      vaults: this.#catalog.vaults.filter((entry) => entry.id !== id),
    });
    const nextDatabase = await reencryptCatalog(
      this.#database,
      nextCatalog,
      this.#rootKey,
    );
    const before = await observedAnchor(this.#store, this.#database);
    const after = anchorWithoutVault(before, nextDatabase, id);
    await this.#anchoredMutation(before, after, async () => {
      await this.#store.deleteVault({
        database: nextDatabase,
        expectedDatabaseRevision: this.#database.revision,
        vaultId: id,
        expectedVaultRevision: vault.revision,
      });
    });
    this.#database = nextDatabase;
    this.#catalog = nextCatalog;
  }

  public async createRecovery(
    options: DatabaseRecoveryCreateOptions,
  ): Promise<Readonly<{ slotId: string; recoveryFile: string }>> {
    this.#assertOpen();
    await DatabaseSession.validateRecoveryDestinations(options.recoveryFile);
    const recoveryAnchorFile = databaseRevisionAnchorPath(options.recoveryFile);
    const passphrase = Uint8Array.from(options.passphrase);
    const slotId = keySlotIdSchema.parse(`recovery_${randomUUID()}`);
    let recoveryKey: RecoveryKey | undefined;
    let kitPublication: DatabaseRecoveryKitFilePublication | undefined;
    let recoveryAnchorPublication: DatabaseRevisionAnchorPublication | undefined;
    const publication = { databaseAdvanced: false };
    try {
      const nextRevision = databaseRevisionSchema.parse(this.#database.revision + 1);
      const created = await createDatabaseRecoverySlot(
        {
          databaseId: this.#databaseId,
          slotId,
          schemaVersion: this.#database.schemaVersion,
          keyVersion: this.#database.currentKeyVersion,
          revision: nextRevision,
          metadataDigest: slotMetadataDigest(
            'kavrix/database-recovery-slot-metadata-digest/v1',
            this.#database,
            slotId,
            this.#rootKey,
          ),
          createdAt: now(),
        },
        this.#rootKey,
      );
      recoveryKey = created.recoveryKey;
      const createdKit = await createOwnedDatabaseRecoveryKitFile(
        options.recoveryFile,
        recoveryKey,
        { databaseId: this.#databaseId, recoverySlotId: slotId },
        { passphrase },
      );
      if (createdKit.status !== 'not-published')
        kitPublication = createdKit.publication;
      if (createdKit.status !== 'published') throw createdKit.error;
      const before = await observedAnchor(this.#store, this.#database);
      const createdAnchor = await createOwnedDatabaseRevisionAnchor(
        recoveryAnchorFile,
        this.#rootKey,
        before,
      );
      if (createdAnchor.status !== 'not-published')
        recoveryAnchorPublication = createdAnchor.publication;
      if (createdAnchor.status !== 'published') throw createdAnchor.error;
      await readDatabaseRevisionAnchor(recoveryAnchorFile, this.#rootKey, before, {
        requireExactVaultSet: true,
      });
      const next = await reencryptCatalog(
        {
          ...this.#database,
          recoverySlots: [...this.#database.recoverySlots, created.slot],
        },
        this.#catalog,
        this.#rootKey,
      );
      await this.#databaseMutation(next);
      publication.databaseAdvanced = true;
      this.#database = next;
      const recoveryAnchor = await observedAnchor(this.#store, next);
      const transitionedRecoveryAnchor = await reconcileOwnedAnchor(
        recoveryAnchorFile,
        this.#rootKey,
        recoveryAnchor,
        createdAnchor.publication,
      );
      recoveryAnchorPublication = transitionedRecoveryAnchor;
      await releaseOwnedPublications([
        () => releaseOwnedDatabaseRevisionAnchor(transitionedRecoveryAnchor),
        () => releaseOwnedDatabaseRecoveryKitFile(createdKit.publication),
      ]);
      return { slotId, recoveryFile: options.recoveryFile };
    } catch (error) {
      const ambiguous =
        error instanceof DatabaseSessionError && error.code === 'ambiguous-commit';
      const cleanupErrors: DatabaseSessionError[] = [];
      if (!publication.databaseAdvanced && !ambiguous) {
        if (recoveryAnchorPublication !== undefined) {
          const ownedAnchor = recoveryAnchorPublication;
          await cleanupOwned(
            () => cleanupOwnedDatabaseRevisionAnchor(ownedAnchor),
            cleanupErrors,
          );
        }
        if (kitPublication !== undefined) {
          const ownedKit = kitPublication;
          await cleanupOwned(
            () => cleanupOwnedDatabaseRecoveryKitFile(ownedKit),
            cleanupErrors,
          );
        }
      } else {
        await releaseOwnedPublications(
          recoveryPublicationReleases(recoveryAnchorPublication, kitPublication),
          false,
        );
      }
      if (cleanupErrors.length > 0)
        throw redactedAggregate(error, cleanupErrors, 'Recovery cleanup failed.');
      if (publication.databaseAdvanced) {
        await this.#poison();
        throw new DatabaseSessionError('ambiguous-commit');
      }
      throw mapError(error);
    } finally {
      zeroize(recoveryKey);
      zeroize(passphrase);
    }
  }

  public async createLocalShareKey(
    options: DatabaseLocalShareKeyCreateOptions,
  ): Promise<Readonly<{ keyFile: string }>> {
    this.#assertOpen();
    await validateSecureFileDestination(options.keyFile);
    const passphrase = Uint8Array.from(options.passphrase);
    try {
      const anchor = await authenticateDatabaseState(
        this.#store,
        this.#database,
        this.#catalog,
        this.#rootKey,
      );
      const created = await createOwnedDatabaseLocalShareKeyFile(
        options.keyFile,
        this.#portableKey,
        { databaseId: this.#databaseId, keySlotId: this.#database.keySlot.id },
        anchor,
        { protection: { kind: 'passphrase', passphrase } },
      );
      if (created.status !== 'published') {
        if (created.status === 'publication-uncertain') {
          await releaseOwnedDatabaseKeyFile(created.publication).catch(() => undefined);
        }
        throw created.error;
      }
      await releaseOwnedDatabaseKeyFile(created.publication);
      return { keyFile: options.keyFile };
    } catch (error) {
      throw mapError(error);
    } finally {
      zeroize(passphrase);
    }
  }

  public recoveryStatus(): Readonly<{ active: number; revoked: number }> {
    this.#assertOpen();
    return {
      active: this.#database.recoverySlots.filter((slot) => slot.state === 'active')
        .length,
      revoked: this.#database.recoverySlots.filter((slot) => slot.state === 'revoked')
        .length,
    };
  }

  public async verifyRecovery(options: DatabaseRecoveryVerifyOptions): Promise<string> {
    this.#assertOpen();
    const passphrase = Uint8Array.from(options.passphrase);
    let parsed: Awaited<ReturnType<typeof readDatabaseRecoveryKitFile>> | undefined;
    let root: DatabaseRootKey | undefined;
    let catalogBytes: Uint8Array | undefined;
    try {
      parsed = await readDatabaseRecoveryKitFile(
        options.recoveryFile,
        passphrase,
        options.expectedBinding,
      );
      if (parsed.binding.databaseId !== this.#databaseId)
        throw new DatabaseSessionError('binding');
      const slot = this.#database.recoverySlots.find(
        (candidate) => candidate.id === parsed?.binding.recoverySlotId,
      );
      if (slot?.state !== 'active') throw new DatabaseSessionError('authentication');
      root = await unlockDatabaseRecoverySlot(
        slot,
        parsed.recoveryKey,
        slotBinding(this.#database, slot),
      );
      catalogBytes = await decryptDatabaseCatalog(
        this.#database.encryptedCatalog,
        root,
        this.#database.encryptedCatalog.aad,
      );
      const catalog = decodeCatalog(catalogBytes);
      const observed = await authenticateDatabaseState(
        this.#store,
        this.#database,
        catalog,
        root,
      );
      await reconcileAnchor(
        databaseRevisionAnchorPath(options.recoveryFile),
        root,
        observed,
        true,
      );
      return slot.id;
    } catch (error) {
      throw mapError(error);
    } finally {
      zeroize(root);
      zeroize(catalogBytes);
      zeroize(parsed?.recoveryKey);
      zeroize(passphrase);
    }
  }

  public async revokeRecovery(slotIdInput: string): Promise<void> {
    this.#assertOpen();
    const slotId = keySlotIdSchema.parse(slotIdInput);
    const active = this.#database.recoverySlots.filter(
      (slot) => slot.state === 'active',
    );
    const target = active.find((slot) => slot.id === slotId);
    if (target === undefined) throw new DatabaseSessionError('not-found');
    if (active.length <= 1) throw new DatabaseSessionError('invalid');
    const recoverySlots = this.#database.recoverySlots.map((slot) =>
      slot.id === slotId
        ? { ...slot, state: 'revoked' as const, revokedAt: now() }
        : slot,
    );
    const next = await reencryptCatalog(
      { ...this.#database, recoverySlots },
      this.#catalog,
      this.#rootKey,
    );
    await this.#databaseMutation(next);
    this.#database = next;
  }

  public static async useRecovery(
    options: DatabaseRecoveryUseOptions,
  ): Promise<
    Readonly<{ databaseId: DatabaseId; keyFile: string; anchorFile: string }>
  > {
    const anchorFile =
      options.anchorFile ?? databaseRevisionAnchorPath(options.outputKeyFile);
    await this.validateRecoveredOwnerDestinations(options.outputKeyFile, anchorFile);
    const recoveryPassphrase = Uint8Array.from(options.recoveryPassphrase);
    const newPassphrase = Uint8Array.from(options.newPassphrase);
    let parsed: Awaited<ReturnType<typeof readDatabaseRecoveryKitFile>> | undefined;
    let root: DatabaseRootKey | undefined;
    let portableKey: PortableKey | undefined;
    let catalogBytes: Uint8Array | undefined;
    let destinationKeyPublication: DatabaseKeyFilePublication | undefined;
    const publication = { databaseAdvanced: false, mutationEntered: false };
    let destinationAnchorPublication: DatabaseRevisionAnchorPublication | undefined;
    try {
      parsed = await readDatabaseRecoveryKitFile(
        options.recoveryFile,
        recoveryPassphrase,
        options.expectedBinding,
      );
      if (
        parsed.binding.databaseId !== options.expectedBinding.databaseId ||
        parsed.binding.recoverySlotId !== options.expectedBinding.recoverySlotId
      )
        throw new DatabaseSessionError('binding');
      const database = await options.store.getDatabase(parsed.binding.databaseId);
      if (database === null) throw new DatabaseSessionError('binding');
      const recoverySlot = database.recoverySlots.find(
        (slot) => slot.id === parsed?.binding.recoverySlotId && slot.state === 'active',
      );
      if (recoverySlot === undefined) throw new DatabaseSessionError('authentication');
      root = await unlockDatabaseRecoverySlot(
        recoverySlot,
        parsed.recoveryKey,
        slotBinding(database, recoverySlot),
      );
      catalogBytes = await decryptDatabaseCatalog(
        database.encryptedCatalog,
        root,
        database.encryptedCatalog.aad,
      );
      const catalog = decodeCatalog(catalogBytes);
      const observed = await authenticateDatabaseState(
        options.store,
        database,
        catalog,
        root,
      );
      const sourceAnchor = databaseRevisionAnchorPath(options.recoveryFile);
      await reconcileAnchor(sourceAnchor, root, observed, true);
      portableKey = generatePortableKey();
      const slotId = keySlotIdSchema.parse(`slot_${randomUUID()}`);
      const nextRevision = databaseRevisionSchema.parse(database.revision + 1);
      const keySlot = await createDatabaseKeySlot(
        {
          databaseId: database.id,
          slotId,
          schemaVersion: database.schemaVersion,
          keyVersion: database.currentKeyVersion,
          revision: nextRevision,
          metadataDigest: slotMetadataDigest(
            'kavrix/database-owner-slot-metadata-digest/v1',
            database,
            slotId,
            root,
          ),
          createdAt: now(),
        },
        portableKey,
        root,
      );
      const next = await reencryptCatalog({ ...database, keySlot }, catalog, root);
      const createdKey = await createOwnedDatabaseKeyFile(
        options.outputKeyFile,
        portableKey,
        { databaseId: database.id, keySlotId: slotId },
        { protection: { kind: 'passphrase', passphrase: newPassphrase } },
      );
      if (createdKey.status !== 'not-published')
        destinationKeyPublication = createdKey.publication;
      if (createdKey.status !== 'published') throw createdKey.error;
      const createdAnchor = await createOwnedDatabaseRevisionAnchor(
        anchorFile,
        root,
        observed,
      );
      if (createdAnchor.status !== 'not-published')
        destinationAnchorPublication = createdAnchor.publication;
      if (createdAnchor.status !== 'published') throw createdAnchor.error;
      await readDatabaseRevisionAnchor(anchorFile, root, observed, {
        requireExactVaultSet: true,
      });
      const nextAnchor = {
        ...observed,
        databaseRevision: next.revision,
        catalogMetadataDigest: next.catalogMetadataDigest,
      };
      await transitionDatabaseRevisionAnchor(
        sourceAnchor,
        root,
        observed,
        async () => {
          publication.mutationEntered = true;
          await options.store.updateDatabase(next, database.revision);
          publication.databaseAdvanced = true;
          return { nextAnchor, result: undefined };
        },
        { requireExactVaultSet: true },
      );
      const transitionedDestinationAnchor = await reconcileOwnedAnchor(
        anchorFile,
        root,
        nextAnchor,
        createdAnchor.publication,
      );
      destinationAnchorPublication = transitionedDestinationAnchor;
      const verified = await readDatabaseKeyFile(options.outputKeyFile, newPassphrase, {
        databaseId: database.id,
        keySlotId: slotId,
      });
      zeroize(verified.portableKey);
      await readDatabaseRevisionAnchor(anchorFile, root, nextAnchor, {
        requireExactVaultSet: true,
      });
      await releaseOwnedPublications([
        () => releaseOwnedDatabaseRevisionAnchor(transitionedDestinationAnchor),
        () => releaseOwnedDatabaseKeyFile(createdKey.publication),
      ]);
      return { databaseId: database.id, keyFile: options.outputKeyFile, anchorFile };
    } catch (error) {
      const cleanupErrors: DatabaseSessionError[] = [];
      const mutationUncertain =
        publication.mutationEntered && !isProvenRejectedMutation(error);
      if (!publication.databaseAdvanced && !mutationUncertain) {
        if (destinationAnchorPublication !== undefined) {
          const ownedAnchor = destinationAnchorPublication;
          await cleanupOwned(
            () => cleanupOwnedDatabaseRevisionAnchor(ownedAnchor),
            cleanupErrors,
          );
        }
        if (destinationKeyPublication !== undefined) {
          const ownedKey = destinationKeyPublication;
          await cleanupOwned(
            () => cleanupOwnedDatabaseKeyFile(ownedKey),
            cleanupErrors,
          );
        }
      } else {
        await releaseOwnedPublications(
          ownerPublicationReleases(
            destinationAnchorPublication,
            destinationKeyPublication,
          ),
          false,
        );
      }
      if (publication.databaseAdvanced || mutationUncertain)
        throw new DatabaseSessionError('ambiguous-commit');
      if (cleanupErrors.length > 0)
        throw redactedAggregate(error, cleanupErrors, 'Recovery cleanup failed.');
      throw mapError(error);
    } finally {
      zeroize(catalogBytes);
      zeroize(portableKey);
      zeroize(root);
      zeroize(parsed?.recoveryKey);
      zeroize(newPassphrase);
      zeroize(recoveryPassphrase);
    }
  }

  public async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    zeroize(this.#portableKey);
    zeroize(this.#rootKey);
    observeCleared(this.#rootKey);
    try {
      await this.#store.close();
    } catch {
      throw new DatabaseSessionError('close');
    }
  }

  async #databaseMutation(next: EncryptedDatabaseDocument): Promise<void> {
    const before = await observedAnchor(this.#store, this.#database);
    const after: DatabaseRevisionAnchor = {
      ...before,
      databaseRevision: next.revision,
      catalogMetadataDigest: next.catalogMetadataDigest,
    };
    await this.#anchoredMutation(before, after, async () => {
      await this.#store.updateDatabase(next, this.#database.revision);
    });
  }

  async #anchoredMutation(
    before: DatabaseRevisionAnchor,
    after: DatabaseRevisionAnchor,
    mutate: () => Promise<void>,
    ownedAnchorPublication?: DatabaseRevisionAnchorPublication,
  ): Promise<DatabaseRevisionAnchorPublication | undefined> {
    const publication = { mutationEntered: false, storeAccepted: false };
    try {
      const transition = async (): Promise<
        Readonly<{ nextAnchor: DatabaseRevisionAnchor; result: undefined }>
      > => {
        publication.mutationEntered = true;
        await mutate();
        publication.storeAccepted = true;
        return { nextAnchor: after, result: undefined };
      };
      if (ownedAnchorPublication !== undefined) {
        return (
          await transitionOwnedDatabaseRevisionAnchor(
            this.#anchorFile,
            this.#rootKey,
            before,
            ownedAnchorPublication,
            transition,
            { requireExactVaultSet: true },
          )
        ).publication;
      }
      await transitionDatabaseRevisionAnchor(
        this.#anchorFile,
        this.#rootKey,
        before,
        transition,
        { requireExactVaultSet: true },
      );
      return undefined;
    } catch (error) {
      if (
        publication.storeAccepted ||
        (publication.mutationEntered && !isProvenRejectedMutation(error))
      ) {
        await this.#poison();
        throw new DatabaseSessionError('ambiguous-commit');
      }
      throw mapError(error);
    }
  }

  async #poison(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    zeroize(this.#portableKey);
    zeroize(this.#rootKey);
    observeCleared(this.#rootKey);
    await this.#store.close().catch(() => undefined);
  }

  #assertOpen(): void {
    if (this.#closed) throw new DatabaseSessionError('operation');
  }
}

async function createInitialDatabase(
  databaseId: DatabaseId,
  slotId: ReturnType<typeof keySlotIdSchema.parse>,
  label: string,
  portableKey: PortableKey,
  rootKey: DatabaseRootKey,
): Promise<EncryptedDatabaseDocument> {
  const createdAt = now();
  const schemaVersion = supportedSchemaVersionSchema.parse(CURRENT_SCHEMA_VERSION);
  const cryptographicVersion = supportedCryptographicVersionSchema.parse(
    CURRENT_CRYPTOGRAPHIC_VERSION,
  );
  const currentKeyVersion = keyVersionSchema.parse(1);
  const revision = databaseRevisionSchema.parse(0);
  const catalog = databaseCatalogPayloadSchema.parse({ label, vaults: [] });
  let catalogBytes: Uint8Array | undefined;
  try {
    catalogBytes = encodeCatalog(catalog);
    const catalogMetadataDigest = keyedDigest(
      'kavrix/database-catalog-digest/v1',
      rootKey,
      {
        databaseId,
        revision,
        currentKeyVersion,
        recoverySlotIds: [],
      },
      catalogBytes,
    );
    const keySlot = await createDatabaseKeySlot(
      {
        databaseId,
        slotId,
        schemaVersion,
        keyVersion: currentKeyVersion,
        revision,
        metadataDigest: catalogMetadataDigest,
        createdAt,
      },
      portableKey,
      rootKey,
    );
    const encryptedCatalog = await encryptDatabaseCatalog(
      catalogBytes,
      rootKey,
      catalogContext(databaseId, revision, currentKeyVersion, catalogMetadataDigest),
    );
    return encryptedDatabaseDocumentSchema.parse({
      format: 'kavrix-encrypted-database',
      version: 1,
      id: databaseId,
      schemaVersion,
      cryptographicVersion,
      currentKeyVersion,
      keySlot,
      recoverySlots: [],
      revision,
      encryptedCatalog,
      catalogMetadataDigest,
      createdAt,
      updatedAt: createdAt,
    });
  } finally {
    zeroize(catalogBytes);
  }
}

async function reencryptCatalog(
  currentInput: EncryptedDatabaseDocument,
  catalog: DatabaseCatalogPayload,
  rootKey: DatabaseRootKey,
): Promise<EncryptedDatabaseDocument> {
  const revision = databaseRevisionSchema.parse(currentInput.revision + 1);
  const updatedAt = now();
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = encodeCatalog(catalog);
    const catalogMetadataDigest = keyedDigest(
      'kavrix/database-catalog-digest/v1',
      rootKey,
      {
        databaseId: currentInput.id,
        revision,
        currentKeyVersion: currentInput.currentKeyVersion,
        recoverySlotIds: currentInput.recoverySlots.map(
          (slot) => `${slot.id}:${slot.state}`,
        ),
      },
      plaintext,
    );
    const encryptedCatalog = await encryptDatabaseCatalog(
      plaintext,
      rootKey,
      catalogContext(
        currentInput.id,
        revision,
        currentInput.currentKeyVersion,
        catalogMetadataDigest,
      ),
    );
    return encryptedDatabaseDocumentSchema.parse({
      ...currentInput,
      revision,
      updatedAt,
      catalogMetadataDigest,
      encryptedCatalog,
    });
  } finally {
    zeroize(plaintext);
  }
}

async function createVaultDocument(
  database: EncryptedDatabaseDocument,
  id: VaultId,
  createdAt: string,
  root: VaultRootKey,
  databaseRoot: DatabaseRootKey,
  payloadInput: DatabaseVaultPayload,
): Promise<DatabaseVaultDocument> {
  const revision = vaultRevisionSchema.parse(0);
  const metadataBase = {
    databaseId: database.id,
    id,
    schemaVersion: database.schemaVersion,
    cryptographicVersion: database.cryptographicVersion,
    currentKeyVersion: database.currentKeyVersion,
    databaseRevision: database.revision,
    revision,
    createdAt,
    updatedAt: createdAt,
  };
  let plaintext: Uint8Array | undefined;
  try {
    assertDatabaseVaultPayloadBinding(payloadInput, id);
    plaintext = UTF8_ENCODER.encode(
      canonicalJson(databaseVaultPayloadSchema.parse(payloadInput)),
    );
    assertDatabaseVaultPayloadSize(plaintext);
    const payloadMetadataDigest = computeDatabaseVaultPayloadMetadataDigest(
      metadataBase,
      root,
      plaintext,
    );
    const wrappedVaultRoot = await wrapVaultRootForDatabase(
      root,
      databaseRoot,
      databaseAssociatedDataSchema.parse({
        version: 1,
        databaseId: database.id,
        vaultId: id,
        entityType: 'wrapped-vault-root',
        entityId: id,
        purpose: 'vault-root',
        schemaVersion: database.schemaVersion,
        keyVersion: database.currentKeyVersion,
        revision: database.revision,
        metadataDigest: payloadMetadataDigest,
      }),
    );
    const encryptedPayload = await encryptPayload(
      plaintext,
      root,
      associatedDataSchema.parse({
        version: 1,
        vaultId: id,
        entityType: 'vault-preferences',
        entityId: id,
        purpose: 'vault-preferences',
        schemaVersion: database.schemaVersion,
        keyVersion: database.currentKeyVersion,
        revision,
        metadataDigest: payloadMetadataDigest,
      }),
    );
    return databaseVaultDocumentSchema.parse({
      ...metadataBase,
      wrappedVaultRoot,
      encryptedPayload,
      payloadMetadataDigest,
    });
  } finally {
    zeroize(plaintext);
  }
}

async function observedAnchor(
  store: EncryptedDatabaseStore,
  database: EncryptedDatabaseDocument,
): Promise<DatabaseRevisionAnchor> {
  const vaults = await store.listVaults(database.id);
  return anchorFromVaults(database, vaults);
}

async function authenticateDatabaseState(
  store: EncryptedDatabaseStore,
  database: EncryptedDatabaseDocument,
  catalog: DatabaseCatalogPayload,
  rootKey: DatabaseRootKey,
): Promise<DatabaseRevisionAnchor> {
  const vaults = await store.listVaults(database.id);
  assertCatalogVaultSet(catalog, vaults);
  for (const vault of vaults) await authenticateVault(vault, rootKey);
  return anchorFromVaults(database, vaults);
}

function assertCatalogVaultSet(
  catalog: DatabaseCatalogPayload,
  vaults: readonly DatabaseVaultDocument[],
): void {
  const catalogIds = [...catalog.vaults.map((entry) => entry.id)].sort();
  const storedIds = [...vaults.map((vault) => vault.id)].sort();
  if (
    catalogIds.length !== storedIds.length ||
    catalogIds.some((id, index) => id !== storedIds[index])
  )
    throw new DatabaseSessionError('authentication');
}

async function authenticateVault(
  vault: DatabaseVaultDocument,
  databaseRootKey: DatabaseRootKey,
): Promise<void> {
  await decryptAuthenticatedVaultPayload(vault, databaseRootKey);
}

async function decryptAuthenticatedVaultPayload(
  vault: DatabaseVaultDocument,
  databaseRootKey: DatabaseRootKey,
): Promise<DatabaseVaultPayload> {
  let root: VaultRootKey | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    root = await unwrapVaultRootForDatabase(
      vault.wrappedVaultRoot,
      databaseRootKey,
      vault.wrappedVaultRoot.aad,
    );
    plaintext = await decryptPayload(
      vault.encryptedPayload,
      root,
      vaultPayloadContext(vault, vault.revision, vault.payloadMetadataDigest),
    );
    assertDatabaseVaultPayloadSize(plaintext);
    const payload = databaseVaultPayloadSchema.parse(
      JSON.parse(decodeSecretUtf8(plaintext)) as unknown,
    );
    assertDatabaseVaultPayloadBinding(payload, vault.id);
    if (vaultMetadataDigest(vault, root, plaintext) !== vault.payloadMetadataDigest)
      throw new DatabaseSessionError('authentication');
    return payload;
  } finally {
    zeroize(plaintext);
    zeroize(root);
  }
}

function assertDatabaseVaultPayloadSize(plaintext: Uint8Array): void {
  if (plaintext.byteLength > MAX_DATABASE_VAULT_PAYLOAD_BYTES) {
    throw new DatabaseSessionError('invalid');
  }
}

function assertDatabaseVaultPayloadBinding(
  payload: DatabaseVaultPayload,
  vaultId: VaultId,
): void {
  if (isStructuredVaultPayload(payload) && payload.vaultId !== vaultId) {
    throw new DatabaseSessionError('authentication');
  }
}

function anchorFromVaults(
  database: EncryptedDatabaseDocument,
  vaults: readonly DatabaseVaultDocument[],
): DatabaseRevisionAnchor {
  const vaultHeads: Record<
    string,
    { revision: DatabaseVaultDocument['revision']; metadataDigest: Sha256Digest }
  > = {};
  for (const vault of [...vaults].sort((left, right) =>
    left.id.localeCompare(right.id),
  )) {
    vaultHeads[vault.id] = {
      revision: vault.revision,
      metadataDigest: vault.payloadMetadataDigest,
    };
  }
  return {
    databaseId: database.id,
    databaseRevision: database.revision,
    catalogMetadataDigest: database.catalogMetadataDigest,
    vaultHeads,
  };
}

async function reconcileAnchor(
  path: string,
  rootKey: DatabaseRootKey,
  observed: DatabaseRevisionAnchor,
  allowAdvance = false,
): Promise<void> {
  const trusted = await readDatabaseRevisionAnchor(path, rootKey, observed);
  if (canonicalJson(trusted) === canonicalJson(observed)) return;
  if (allowAdvance) {
    await transitionDatabaseRevisionAnchor(path, rootKey, observed, () =>
      Promise.resolve({ nextAnchor: observed, result: undefined }),
    );
    await readDatabaseRevisionAnchor(path, rootKey, observed, {
      requireExactVaultSet: true,
    });
    return;
  }
  throw new DatabaseSessionError('rollback');
}

async function verifyReadOnlyOpenAnchor(
  options: Readonly<{
    anchorFile: string;
    rootKey: DatabaseRootKey;
    observed: DatabaseRevisionAnchor;
  }>,
): Promise<void> {
  try {
    const trusted = await readDatabaseRevisionAnchor(
      options.anchorFile,
      options.rootKey,
      options.observed,
      { requireExactVaultSet: true },
    );
    if (canonicalJson(trusted) !== canonicalJson(options.observed)) {
      throw new DatabaseSessionError('rollback');
    }
  } catch (error) {
    if (error instanceof PortableKeyFileError) {
      throw new DatabaseSessionError('rollback');
    }
    throw error;
  }
}

async function reconcileOwnedAnchor(
  path: string,
  rootKey: DatabaseRootKey,
  observed: DatabaseRevisionAnchor,
  publication: DatabaseRevisionAnchorPublication,
): Promise<DatabaseRevisionAnchorPublication> {
  const trusted = await readDatabaseRevisionAnchor(path, rootKey, observed);
  if (canonicalJson(trusted) === canonicalJson(observed)) return publication;
  const transitioned = await transitionOwnedDatabaseRevisionAnchor(
    path,
    rootKey,
    observed,
    publication,
    () => Promise.resolve({ nextAnchor: observed, result: undefined }),
  );
  await readDatabaseRevisionAnchor(path, rootKey, observed, {
    requireExactVaultSet: true,
  });
  return transitioned.publication;
}

async function reconcileOpenAnchorWithMapping(
  options: Parameters<typeof reconcileOpenAnchor>[0],
): Promise<boolean> {
  try {
    return await reconcileOpenAnchor(options);
  } catch (error) {
    // Anchor verification failures mean the trusted local guard rejected the
    // stored snapshot (or is missing): a rollback/integrity condition, never
    // an authentication failure. Key-file passphrase problems are handled
    // earlier in the open sequence, so this cannot mask wrong-passphrase.
    if (error instanceof PortableKeyFileError && !options.acceptCurrent) {
      throw new DatabaseSessionError('rollback');
    }
    throw error;
  }
}

async function reconcileOpenAnchor(
  options: Readonly<{
    acceptCurrent: boolean;
    anchorFile: string;
    rootKey: DatabaseRootKey;
    observed: DatabaseRevisionAnchor;
    keyFile: string;
    binding: DatabaseKeyBinding;
    keyFileVersion: ParsedDatabaseKeyFile['fileVersion'];
    portableKey: PortableKey;
    passphrase: Uint8Array;
    localShareBootstrap?: DatabaseRevisionAnchor | null;
  }>,
): Promise<boolean> {
  if (options.localShareBootstrap === undefined) {
    if (options.acceptCurrent) {
      return await acceptCurrentAnchor(
        options.anchorFile,
        options.rootKey,
        options.observed,
      );
    }
    await reconcileAnchor(options.anchorFile, options.rootKey, options.observed);
    return false;
  }

  try {
    if (options.acceptCurrent) {
      const matched = await acceptCurrentAnchor(
        options.anchorFile,
        options.rootKey,
        options.observed,
      );
      if (options.localShareBootstrap !== null) {
        await consumeDatabaseLocalShareBootstrap(
          options.keyFile,
          options.portableKey,
          options.binding,
          options.passphrase,
          options.keyFileVersion,
        );
      }
      return matched;
    }
    await reconcileAnchor(options.anchorFile, options.rootKey, options.observed);
  } catch (error) {
    if (options.localShareBootstrap === null) throw error;
    if (canonicalJson(options.localShareBootstrap) !== canonicalJson(options.observed))
      throw error;
    const created = await createOwnedDatabaseRevisionAnchor(
      options.anchorFile,
      options.rootKey,
      options.observed,
    );
    if (created.status !== 'published') {
      if (created.status === 'publication-uncertain') {
        await releaseOwnedDatabaseRevisionAnchor(created.publication).catch(
          () => undefined,
        );
      }
      throw error;
    }
    try {
      await readDatabaseRevisionAnchor(
        options.anchorFile,
        options.rootKey,
        options.observed,
        { requireExactVaultSet: true },
      );
    } finally {
      await releaseOwnedDatabaseRevisionAnchor(created.publication);
    }
  }

  if (options.localShareBootstrap !== null) {
    await consumeDatabaseLocalShareBootstrap(
      options.keyFile,
      options.portableKey,
      options.binding,
      options.passphrase,
      options.keyFileVersion,
    );
  }
  return false;
}

/**
 * Re-anchors the trusted local rollback guard to the observed datastore state.
 * The caller must already have authenticated every encrypted document with
 * the database root key, so the accepted state provably originated from a key
 * holder; the rewrite then heals stale-or-forked anchors after a crash or a
 * verified restore. Returns whether the previous anchor already matched.
 */
async function acceptCurrentAnchor(
  path: string,
  rootKey: DatabaseRootKey,
  observed: DatabaseRevisionAnchor,
): Promise<boolean> {
  let trusted: DatabaseRevisionAnchor | undefined;
  try {
    trusted = await readDatabaseRevisionAnchor(path, rootKey);
  } catch {
    trusted = undefined;
  }
  const matchedBefore =
    trusted !== undefined && canonicalJson(trusted) === canonicalJson(observed);
  if (!matchedBefore) {
    await writeDatabaseRevisionAnchor(
      path,
      rootKey,
      observed,
      trusted === undefined ? 'create' : 'replace',
    );
  }
  await readDatabaseRevisionAnchor(path, rootKey, observed, {
    requireExactVaultSet: true,
  });
  // The caller reports whether this open performed a re-anchor.
  return !matchedBefore;
}

function anchorWithCreatedVault(
  prior: DatabaseRevisionAnchor,
  database: EncryptedDatabaseDocument,
  vault: DatabaseVaultDocument,
): DatabaseRevisionAnchor {
  return {
    databaseId: database.id,
    databaseRevision: database.revision,
    catalogMetadataDigest: database.catalogMetadataDigest,
    vaultHeads: sortedHeads({
      ...prior.vaultHeads,
      [vault.id]: {
        revision: vault.revision,
        metadataDigest: vault.payloadMetadataDigest,
      },
    }),
  };
}

function anchorWithUpdatedVault(
  prior: DatabaseRevisionAnchor,
  vault: DatabaseVaultDocument,
): DatabaseRevisionAnchor {
  return {
    ...prior,
    vaultHeads: sortedHeads({
      ...prior.vaultHeads,
      [vault.id]: {
        revision: vault.revision,
        metadataDigest: vault.payloadMetadataDigest,
      },
    }),
  };
}

function anchorWithoutVault(
  prior: DatabaseRevisionAnchor,
  database: EncryptedDatabaseDocument,
  id: VaultId,
): DatabaseRevisionAnchor {
  const heads = Object.fromEntries(
    Object.entries(prior.vaultHeads).filter(([vaultId]) => vaultId !== id),
  );
  return {
    databaseId: database.id,
    databaseRevision: database.revision,
    catalogMetadataDigest: database.catalogMetadataDigest,
    vaultHeads: sortedHeads(heads),
  };
}

function sortedHeads(
  heads: DatabaseRevisionAnchor['vaultHeads'],
): DatabaseRevisionAnchor['vaultHeads'] {
  return Object.fromEntries(
    Object.entries(heads).sort(([left], [right]) => left.localeCompare(right)),
  );
}

function slotBinding(
  database: EncryptedDatabaseDocument,
  slot: EncryptedDatabaseDocument['keySlot'] | DatabaseRecoverySlot,
): DatabaseSlotBinding {
  const aad = slot.wrappedDatabaseRoot.aad;
  return {
    databaseId: database.id,
    slotId: slot.id,
    schemaVersion: database.schemaVersion,
    keyVersion: slot.keyVersion,
    revision: aad.revision,
    metadataDigest: aad.metadataDigest,
  };
}

function catalogContext(
  databaseId: DatabaseId,
  revision: DatabaseRevision,
  keyVersion: EncryptedDatabaseDocument['currentKeyVersion'],
  metadataDigest: Sha256Digest,
): DatabaseAssociatedData {
  return databaseAssociatedDataSchema.parse({
    version: 1,
    databaseId,
    entityType: 'database-catalog',
    entityId: databaseId,
    purpose: 'catalog',
    schemaVersion: CURRENT_SCHEMA_VERSION,
    keyVersion,
    revision,
    metadataDigest,
  });
}

function vaultPayloadContext(
  current: DatabaseVaultDocument,
  revision: DatabaseVaultDocument['revision'],
  metadataDigest: Sha256Digest,
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    vaultId: current.id,
    entityType: 'vault-preferences',
    entityId: current.id,
    purpose: 'vault-preferences',
    schemaVersion: current.schemaVersion,
    keyVersion: current.currentKeyVersion,
    revision,
    metadataDigest,
  });
}

function vaultMetadataDigest(
  value: DatabaseVaultPayloadDigestMetadata,
  rootKey: VaultRootKey,
  plaintext: Uint8Array,
): Sha256Digest {
  return computeDatabaseVaultPayloadMetadataDigest(value, rootKey, plaintext);
}

function slotMetadataDigest(
  domain: string,
  database: EncryptedDatabaseDocument,
  slotId: string,
  rootKey: DatabaseRootKey,
): Sha256Digest {
  return keyedDigest(
    domain,
    rootKey,
    {
      databaseId: database.id,
      slotId,
      keyVersion: database.currentKeyVersion,
    },
    new Uint8Array(0),
  );
}

function keyedDigest(
  domain: string,
  key: Uint8Array,
  value: unknown,
  plaintext: Uint8Array,
): Sha256Digest {
  const digestKey = new Uint8Array(
    hkdfSync(
      'sha256',
      key,
      new Uint8Array(32),
      Buffer.from(`${domain}/key`, 'ascii'),
      32,
    ),
  );
  try {
    return sha256DigestSchema.parse(
      createHmac('sha256', digestKey)
        .update(domain, 'utf8')
        .update('\0')
        .update(canonicalJson(value), 'utf8')
        .update('\0')
        .update(plaintext)
        .digest('base64url'),
    );
  } finally {
    zeroize(digestKey);
  }
}

function encodeCatalog(catalog: DatabaseCatalogPayload): Uint8Array {
  return UTF8_ENCODER.encode(
    canonicalJson(databaseCatalogPayloadSchema.parse(catalog)),
  );
}

function decodeCatalog(bytes: Uint8Array): DatabaseCatalogPayload {
  try {
    return databaseCatalogPayloadSchema.parse(
      JSON.parse(decodeSecretUtf8(bytes)) as unknown,
    );
  } catch {
    throw new DatabaseSessionError('authentication');
  }
}

function decodeSecretUtf8(bytes: Uint8Array): string {
  try {
    return STRICT_UTF8_DECODER.decode(bytes);
  } catch {
    throw new DatabaseSessionError('authentication');
  }
}

function parseLabel(value: string): string {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_LABEL_BYTES) {
    throw new DatabaseSessionError('invalid');
  }
  try {
    return databaseCatalogPayloadSchema.shape.label.parse(value);
  } catch {
    throw new DatabaseSessionError('invalid');
  }
}

function now(): string {
  return timestampSchema.parse(new Date().toISOString());
}

/**
 * Normalizes one failure thrown inside a session operation.
 *
 * Deliberate command-layer failures raised inside session callbacks
 * (`LocalCliError`, secret-input framing, coded execution errors) carry their
 * own reviewed messages and exit codes and are returned unchanged so the user
 * always sees the true cause. Cryptographic failures stay redacted as
 * `authentication`; persistence failures map by store code; schema violations
 * are deterministic input problems.
 */
function mapError(error: unknown): Error {
  if (error instanceof DatabaseSessionError) return error;
  if (
    error instanceof LocalCliError ||
    error instanceof LocalSecretInputError ||
    error instanceof CodedCliError
  ) {
    return error;
  }
  if (error instanceof EncryptedDatabaseStoreError) {
    if (error.code === 'conflict' || error.code === 'exists')
      return new DatabaseSessionError('conflict');
    if (error.code === 'busy') return new DatabaseSessionError('busy');
    if (error.code === 'invalid' || error.code === 'unsupported')
      return new DatabaseSessionError('invalid');
    return new DatabaseSessionError('operation');
  }
  if (error instanceof ZodError) return new DatabaseSessionError('invalid');
  return new DatabaseSessionError('authentication');
}

function requireMigrationInitializationOwnership(
  ownership: MigrationInitializationOwnership,
): MigrationInitializationOwnershipState {
  const state = migrationInitializationOwnerships.get(ownership);
  if (state === undefined) throw new DatabaseSessionError('invalid');
  return state;
}

async function cleanupOwned(
  cleanup: () => Promise<void>,
  errors: DatabaseSessionError[],
): Promise<void> {
  try {
    await cleanup();
  } catch {
    errors.push(new DatabaseSessionError('operation'));
  }
}

async function releaseOwnedPublications(
  releases: readonly (() => Promise<void>)[],
  throwOnFailure = true,
): Promise<void> {
  const results = await Promise.allSettled(releases.map((release) => release()));
  if (throwOnFailure && results.some((result) => result.status === 'rejected')) {
    throw new DatabaseSessionError('operation');
  }
}

function ownerPublicationReleases(
  anchor: DatabaseRevisionAnchorPublication | undefined,
  key: DatabaseKeyFilePublication | undefined,
): (() => Promise<void>)[] {
  const releases: (() => Promise<void>)[] = [];
  if (anchor !== undefined) {
    releases.push(() => releaseOwnedDatabaseRevisionAnchor(anchor));
  }
  if (key !== undefined) releases.push(() => releaseOwnedDatabaseKeyFile(key));
  return releases;
}

function recoveryPublicationReleases(
  anchor: DatabaseRevisionAnchorPublication | undefined,
  kit: DatabaseRecoveryKitFilePublication | undefined,
): (() => Promise<void>)[] {
  const releases: (() => Promise<void>)[] = [];
  if (anchor !== undefined) {
    releases.push(() => releaseOwnedDatabaseRevisionAnchor(anchor));
  }
  if (kit !== undefined) {
    releases.push(() => releaseOwnedDatabaseRecoveryKitFile(kit));
  }
  return releases;
}

function isProvenRejectedMutation(error: unknown): boolean {
  return (
    error instanceof EncryptedDatabaseStoreError &&
    (error.code === 'conflict' || error.code === 'exists' || error.code === 'invalid')
  );
}

function redactedAggregate(
  primary: unknown,
  cleanupErrors: readonly DatabaseSessionError[],
  message: string,
): AggregateError {
  return new AggregateError([mapError(primary), ...cleanupErrors], message);
}

function observeCleared(key: Uint8Array): void {
  if (!key.every((byte) => byte === 0)) throw new DatabaseSessionError('operation');
  if (zeroizationObserver === undefined) return;
  try {
    zeroizationObserver(true);
  } catch {
    throw new DatabaseSessionError('operation');
  }
}

function messageFor(code: DatabaseSessionErrorCode): string {
  const messages: Record<DatabaseSessionErrorCode, string> = {
    'ambiguous-commit': 'The database may have changed; reopen it before continuing.',
    authentication: 'Database authentication failed.',
    binding: 'Database binding validation failed.',
    busy: 'The encrypted database is locked by another Kavrix process.',
    close: 'Database session cleanup failed.',
    conflict: 'The database changed while this operation was running.',
    duplicate: 'A vault with that label already exists.',
    invalid: 'The database operation is invalid.',
    'not-found': 'The requested vault was not found.',
    operation: 'The database operation failed.',
    rollback: 'The database snapshot was rejected as stale or forked.',
  };
  return messages[code];
}
