import { createHmac, hkdfSync, randomUUID } from 'node:crypto';

import {
  createDatabaseKeySlot,
  createDatabaseRecoverySlot,
  decryptDatabaseCatalog,
  decryptPayload,
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
  type PortableKey,
  type RecoveryKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  databaseRevisionAnchorPath,
  cleanupOwnedDatabaseKeyFile,
  cleanupOwnedDatabaseRecoveryKitFile,
  cleanupOwnedDatabaseRevisionAnchor,
  createOwnedDatabaseKeyFile,
  createOwnedDatabaseRecoveryKitFile,
  createOwnedDatabaseRevisionAnchor,
  readDatabaseKeyFile,
  readDatabaseKeyFileBinding,
  readDatabaseRecoveryKitFile,
  readDatabaseRevisionAnchor,
  transitionDatabaseRevisionAnchor,
  validateSecureFileDestination,
  type DatabaseKeyFilePublication,
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
  databaseVaultDocumentSchema,
  encryptedDatabaseDocumentSchema,
  keySlotIdSchema,
  keyVersionSchema,
  localVaultPayloadSchema,
  sha256DigestSchema,
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
  type EncryptedDatabaseDocument,
  type LocalVaultPayload,
  type AssociatedData,
  type Sha256Digest,
  type VaultId,
} from '@kavrix/schemas';
import {
  EncryptedDatabaseStoreError,
  type EncryptedDatabaseStore,
} from '@kavrix/storage';

import {
  DatastoreProfileError,
  validateDatastoreProfileBindingPublicationResult,
  type DatastoreProfileBindingPublicationResult,
} from './datastore-profiles.js';

const MAX_LABEL_BYTES = 1_024;
const UTF8_ENCODER = new TextEncoder();
const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
let zeroizationObserver: ((cleared: true) => void) | undefined;
const DATABASE_VAULT_DELETION_AUTHORIZATION = Symbol(
  'database-vault-deletion-authorization',
);
type DatabaseVaultDeletionAuthorization = Readonly<{
  token: typeof DATABASE_VAULT_DELETION_AUTHORIZATION;
}>;

export type DatabaseSessionErrorCode =
  | 'ambiguous-commit'
  | 'authentication'
  | 'binding'
  | 'close'
  | 'conflict'
  | 'duplicate'
  | 'invalid'
  | 'not-found'
  | 'operation'
  | 'rollback';

export class DatabaseSessionError extends Error {
  public constructor(public readonly code: DatabaseSessionErrorCode) {
    super(messageFor(code));
    this.name = 'DatabaseSessionError';
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
  Readonly<{ readPassphrase: () => Promise<Uint8Array> }>;

export type DatabaseRecoveryCreateOptions = Readonly<{
  recoveryFile: string;
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
  #database: EncryptedDatabaseDocument;
  #catalog: DatabaseCatalogPayload;
  #closed = false;

  private constructor(
    options: Readonly<{
      store: EncryptedDatabaseStore;
      anchorFile: string;
      database: EncryptedDatabaseDocument;
      catalog: DatabaseCatalogPayload;
      rootKey: DatabaseRootKey;
    }>,
  ) {
    this.#store = options.store;
    this.#anchorFile = options.anchorFile;
    this.#databaseId = options.database.id;
    this.#database = options.database;
    this.#catalog = options.catalog;
    this.#rootKey = options.rootKey;
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
      return { databaseId, keyFile: options.keyFile, anchorFile };
    } catch (error) {
      const cleanupErrors: DatabaseSessionError[] = [];
      if (bindingPublicationUncertain) {
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
      if (databaseMayExist) throw new DatabaseSessionError('ambiguous-commit');
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
      await reconcileAnchor(anchorFile, rootKey, observed);
      const session = new DatabaseSession({
        store: options.store,
        anchorFile,
        database,
        catalog,
        rootKey,
      });
      rootKey = undefined;
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

  public get databaseId(): DatabaseId {
    return this.#databaseId;
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
    this.#assertOpen();
    const label = parseLabel(labelInput);
    if (this.#catalog.vaults.some((entry) => entry.label === label)) {
      throw new DatabaseSessionError('duplicate');
    }
    const id = vaultIdSchema.parse(`vault_${randomUUID()}`);
    const createdAt = now();
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
      const vault = await createEmptyVault(
        nextDatabase,
        id,
        createdAt,
        root,
        this.#rootKey,
      );
      const before = await observedAnchor(this.#store, this.#database);
      const after = anchorWithCreatedVault(before, nextDatabase, vault);
      await this.#anchoredMutation(before, after, async () => {
        await this.#store.createVault({
          database: nextDatabase,
          expectedDatabaseRevision: this.#database.revision,
          vault,
        });
      });
      this.#database = nextDatabase;
      this.#catalog = nextCatalog;
      return { id, label, createdAt };
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
        current.encryptedPayload.aad,
      );
      const currentPayload = localVaultPayloadSchema.parse(
        JSON.parse(decodeSecretUtf8(plaintext)) as unknown,
      );
      const nextPayload = localVaultPayloadSchema.parse(
        await update(structuredClone(currentPayload)),
      );
      nextPlaintext = UTF8_ENCODER.encode(canonicalJson(nextPayload));
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
      await reconcileAnchor(recoveryAnchorFile, this.#rootKey, recoveryAnchor);
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
    const publication = { databaseAdvanced: false };
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
      await reconcileAnchor(sourceAnchor, root, observed);
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
          await options.store.updateDatabase(next, database.revision);
          publication.databaseAdvanced = true;
          return { nextAnchor, result: undefined };
        },
        { requireExactVaultSet: true },
      );
      await reconcileAnchor(anchorFile, root, nextAnchor);
      const verified = await readDatabaseKeyFile(options.outputKeyFile, newPassphrase, {
        databaseId: database.id,
        keySlotId: slotId,
      });
      zeroize(verified.portableKey);
      await readDatabaseRevisionAnchor(anchorFile, root, nextAnchor, {
        requireExactVaultSet: true,
      });
      return { databaseId: database.id, keyFile: options.outputKeyFile, anchorFile };
    } catch (error) {
      const cleanupErrors: DatabaseSessionError[] = [];
      if (!publication.databaseAdvanced) {
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
      }
      if (publication.databaseAdvanced)
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
  ): Promise<void> {
    const publication = { storeAccepted: false };
    try {
      await transitionDatabaseRevisionAnchor(
        this.#anchorFile,
        this.#rootKey,
        before,
        async () => {
          await mutate();
          publication.storeAccepted = true;
          return { nextAnchor: after, result: undefined };
        },
        { requireExactVaultSet: true },
      );
    } catch (error) {
      if (publication.storeAccepted) {
        await this.#poison();
        throw new DatabaseSessionError('ambiguous-commit');
      }
      throw mapError(error);
    }
  }

  async #poison(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
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

async function createEmptyVault(
  database: EncryptedDatabaseDocument,
  id: VaultId,
  createdAt: string,
  root: VaultRootKey,
  databaseRoot: DatabaseRootKey,
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
    plaintext = UTF8_ENCODER.encode(
      canonicalJson(localVaultPayloadSchema.parse({ records: {} })),
    );
    const payloadMetadataDigest = keyedDigest(
      'kavrix/database-vault-payload-digest/v1',
      root,
      metadataBase,
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
  const catalogIds = [...catalog.vaults.map((entry) => entry.id)].sort();
  const storedIds = [...vaults.map((vault) => vault.id)].sort();
  if (
    catalogIds.length !== storedIds.length ||
    catalogIds.some((id, index) => id !== storedIds[index])
  )
    throw new DatabaseSessionError('authentication');
  for (const vault of vaults) await authenticateVault(vault, rootKey);
  return anchorFromVaults(database, vaults);
}

async function authenticateVault(
  vault: DatabaseVaultDocument,
  databaseRootKey: DatabaseRootKey,
): Promise<void> {
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
      vault.encryptedPayload.aad,
    );
    localVaultPayloadSchema.parse(JSON.parse(decodeSecretUtf8(plaintext)) as unknown);
    if (vaultMetadataDigest(vault, root, plaintext) !== vault.payloadMetadataDigest)
      throw new DatabaseSessionError('authentication');
  } finally {
    zeroize(plaintext);
    zeroize(root);
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
): Promise<void> {
  await transitionDatabaseRevisionAnchor(path, rootKey, observed, () =>
    Promise.resolve({ nextAnchor: observed, result: undefined }),
  );
  await readDatabaseRevisionAnchor(path, rootKey, observed, {
    requireExactVaultSet: true,
  });
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
  value: unknown,
  rootKey: VaultRootKey,
  plaintext: Uint8Array,
): Sha256Digest {
  const record = value as Partial<DatabaseVaultDocument>;
  return keyedDigest(
    'kavrix/database-vault-payload-digest/v1',
    rootKey,
    {
      databaseId: record.databaseId,
      id: record.id,
      schemaVersion: record.schemaVersion,
      cryptographicVersion: record.cryptographicVersion,
      currentKeyVersion: record.currentKeyVersion,
      databaseRevision: record.databaseRevision,
      revision: record.revision,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    },
    plaintext,
  );
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

function mapError(error: unknown): DatabaseSessionError {
  if (error instanceof DatabaseSessionError) return error;
  if (error instanceof EncryptedDatabaseStoreError) {
    if (error.code === 'conflict' || error.code === 'exists')
      return new DatabaseSessionError('conflict');
    return new DatabaseSessionError('operation');
  }
  return new DatabaseSessionError('authentication');
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
