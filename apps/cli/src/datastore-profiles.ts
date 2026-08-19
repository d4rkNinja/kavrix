import { chmod, lstat, mkdir, realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, join, resolve } from 'node:path';

import {
  ProtectedJsonDocumentError,
  readProtectedJsonDocument,
  transitionProtectedJsonDocument,
  transitionProtectedJsonDocumentWithPublicationStatus,
  writeProtectedJsonDocument,
  type CanonicalJsonDocumentSchema,
  type ProtectedJsonDocumentPublication,
  type ProtectedJsonDocumentTransitionPublicationResult,
  PortableKeyFileError,
  setWindowsUserOnlyAcl,
  verifyWindowsUserOnlyAcl,
} from '@kavrix/key-files';
import {
  databaseIdSchema,
  profileIdSchema,
  type DatabaseId,
  type ProfileId,
} from '@kavrix/schemas';

const REGISTRY_VERSION = 1;
const MAX_PROFILES = 64;
const MAX_REGISTRY_BYTES = 128 * 1024;
const MAX_PATH_CHARS = 4_096;
const DEFAULT_FILE_NAME = 'datastore-profiles.json';
const SENSITIVE_KEY_PARTS = ['uri', 'password', 'token', 'secret', 'credential'];
const DATABASE_NAME = /^[A-Za-z0-9_-]{1,63}$/u;
const COLLECTION_NAME = /^[A-Za-z0-9_-]{1,64}$/u;
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

export type MongoDatastoreProfile = Readonly<{
  id: ProfileId;
  datastore: 'mongodb';
  databaseId?: DatabaseId;
  database: string;
  databaseCollection: string;
  vaultCollection: string;
  keyFile: string;
}>;

export type FileDatastoreProfile = Readonly<{
  id: ProfileId;
  datastore: 'file';
  databaseId?: DatabaseId;
  dataFile: string;
  keyFile: string;
}>;

export type DatastoreProfile = MongoDatastoreProfile | FileDatastoreProfile;

export type DatastoreProfileRoutingOverrides = Readonly<{
  datastore?: 'mongodb' | 'file';
  dataFile?: string;
  database?: string;
  databaseCollection?: string;
  vaultCollection?: string;
  keyFile?: string;
}>;

type DatastoreProfileRegistryDocument = Readonly<{
  version: 1;
  current: ProfileId | null;
  profiles: readonly DatastoreProfile[];
}>;

const profileRegistryDocumentSchema: CanonicalJsonDocumentSchema<DatastoreProfileRegistryDocument> =
  { parse: parseDocument };

const profileRegistryDocumentOptions = {
  schema: profileRegistryDocumentSchema,
  maximumBytes: MAX_REGISTRY_BYTES,
};

export type DatastoreProfileRegistryOptions = Readonly<{
  configDirectory?: string;
  fileName?: string;
}>;

const datastoreProfileBindingPublicationBrand = Symbol(
  'datastoreProfileBindingPublication',
);

/**
 * Opaque evidence that an initialization binding replacement started. It has
 * no registry path, bytes, lock state, or cleanup authority.
 */
export type DatastoreProfileBindingPublication = Readonly<{
  readonly [datastoreProfileBindingPublicationBrand]: true;
}>;

export type DatastoreProfileBindingPublicationResult =
  | Readonly<{
      status: 'not-published';
      error: DatastoreProfileError;
    }>
  | Readonly<{
      status: 'published';
      publication: DatastoreProfileBindingPublication;
    }>
  | Readonly<{
      status: 'publication-uncertain';
      publication: DatastoreProfileBindingPublication;
      error: DatastoreProfileError;
    }>;

const datastoreProfileBindingPublications = new WeakMap<
  object,
  ProtectedJsonDocumentPublication
>();

/** Validates an opaque binding-publication capability without exposing it. */
export function isDatastoreProfileBindingPublication(
  value: unknown,
): value is DatastoreProfileBindingPublication {
  return (
    typeof value === 'object' &&
    value !== null &&
    datastoreProfileBindingPublications.has(value)
  );
}

export class DatastoreProfileError extends Error {
  public constructor(
    public readonly code:
      | 'PROFILE_DUPLICATE'
      | 'PROFILE_INVALID'
      | 'PROFILE_LIMIT'
      | 'PROFILE_NOT_FOUND'
      | 'PROFILE_OPERATION_FAILED'
      | 'PROFILE_UNSAFE',
  ) {
    super(profileErrorMessage(code));
    this.name = 'DatastoreProfileError';
  }
}

/** Returns the fixed, non-secret registry name below a caller-owned config directory. */
export function resolveProfilePath(
  configDirectory: string,
  fileName = DEFAULT_FILE_NAME,
): string {
  if (typeof configDirectory !== 'string' || configDirectory.length === 0) {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
  if (
    typeof fileName !== 'string' ||
    !FILE_NAME.test(fileName) ||
    basename(fileName) !== fileName
  ) {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
  return join(resolve(configDirectory), fileName);
}

/**
 * Applies only public routing overrides while preserving a selected profile's
 * expected database ID. Session composition must verify that binding before it
 * unlocks or accepts a database.
 */
export function resolveDatastoreProfileRouting(
  profile: DatastoreProfile,
  overrides: DatastoreProfileRoutingOverrides,
): DatastoreProfile {
  const datastore = overrides.datastore ?? profile.datastore;
  const databaseId = profile.databaseId;
  if (datastore === 'mongodb') {
    const mongo = profile.datastore === 'mongodb' ? profile : undefined;
    return parseProfile({
      id: profile.id,
      datastore,
      ...(databaseId === undefined ? {} : { databaseId }),
      database: overrides.database ?? mongo?.database,
      databaseCollection: overrides.databaseCollection ?? mongo?.databaseCollection,
      vaultCollection: overrides.vaultCollection ?? mongo?.vaultCollection,
      keyFile: overrides.keyFile ?? profile.keyFile,
    });
  }
  const file = profile.datastore === 'file' ? profile : undefined;
  return parseProfile({
    id: profile.id,
    datastore,
    ...(databaseId === undefined ? {} : { databaseId }),
    dataFile: overrides.dataFile ?? file?.dataFile,
    keyFile: overrides.keyFile ?? profile.keyFile,
  });
}

/** Fails closed when an observed database document is not the profile binding. */
export function verifyDatastoreProfileDatabaseId(
  profile: DatastoreProfile,
  observedDatabaseId: DatabaseId,
): void {
  const observed = parseOptionalDatabaseId(observedDatabaseId);
  if (
    observed === undefined ||
    (profile.databaseId !== undefined && profile.databaseId !== observed)
  ) {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
}

/**
 * A versioned local registry for public datastore routing only. It is protected
 * like a key file because switching a profile must not be silently redirected.
 */
export class DatastoreProfileRegistry {
  readonly #path: string;

  private constructor(path: string) {
    this.#path = path;
  }

  static async open(
    options: DatastoreProfileRegistryOptions = {},
  ): Promise<DatastoreProfileRegistry> {
    const directory = await secureConfigDirectory(
      options.configDirectory ?? defaultConfigDirectory(),
    );
    const registry = new DatastoreProfileRegistry(
      resolveProfilePath(directory, options.fileName),
    );
    await registry.#readOrEmpty();
    return registry;
  }

  /** Opens an existing registry without creating configuration state for callers. */
  static async openIfPresent(
    options: DatastoreProfileRegistryOptions = {},
  ): Promise<DatastoreProfileRegistry | null> {
    const inputDirectory = options.configDirectory ?? defaultConfigDirectory();
    try {
      await lstat(resolve(inputDirectory));
    } catch (error) {
      if (errorCode(error) === 'ENOENT') return null;
      throw new DatastoreProfileError('PROFILE_UNSAFE');
    }
    const directory = await secureConfigDirectory(inputDirectory);
    const registry = new DatastoreProfileRegistry(
      resolveProfilePath(directory, options.fileName),
    );
    if (!(await registryExists(registry.#path))) return null;
    await registry.#readOrEmpty();
    return registry;
  }

  async add(profile: DatastoreProfile): Promise<DatastoreProfile> {
    const parsed = parseProfile(profile);
    return this.#mutate((document) => {
      if (document.profiles.some((candidate) => candidate.id === parsed.id)) {
        throw new DatastoreProfileError('PROFILE_DUPLICATE');
      }
      if (document.profiles.length >= MAX_PROFILES) {
        throw new DatastoreProfileError('PROFILE_LIMIT');
      }
      const profiles = sortProfiles([...document.profiles, parsed]);
      return {
        document: { ...document, profiles },
        result: cloneProfile(parsed),
      };
    });
  }

  async list(): Promise<readonly DatastoreProfile[]> {
    const document = await this.#readOrEmpty();
    return document.profiles.map(cloneProfile);
  }

  async get(id: ProfileId): Promise<DatastoreProfile> {
    const parsedId = parseProfileId(id);
    const document = await this.#readOrEmpty();
    const profile = document.profiles.find((candidate) => candidate.id === parsedId);
    if (profile === undefined) throw new DatastoreProfileError('PROFILE_NOT_FOUND');
    return cloneProfile(profile);
  }

  async use(id: ProfileId): Promise<DatastoreProfile> {
    const parsedId = parseProfileId(id);
    return this.#mutate((document) => {
      const profile = document.profiles.find((candidate) => candidate.id === parsedId);
      if (profile === undefined) throw new DatastoreProfileError('PROFILE_NOT_FOUND');
      return {
        document: { ...document, current: parsedId },
        result: cloneProfile(profile),
      };
    });
  }

  /** Binds an initialized database once; a profile cannot be rebound silently. */
  async bindDatabaseId(
    id: ProfileId,
    databaseId: DatabaseId,
  ): Promise<DatastoreProfile> {
    const parsedId = parseProfileId(id);
    const parsedDatabaseId = parseOptionalDatabaseId(databaseId);
    if (parsedDatabaseId === undefined)
      throw new DatastoreProfileError('PROFILE_INVALID');
    return this.#mutate((document) => {
      const profile = document.profiles.find((candidate) => candidate.id === parsedId);
      if (profile === undefined) throw new DatastoreProfileError('PROFILE_NOT_FOUND');
      if (profile.databaseId !== undefined && profile.databaseId !== parsedDatabaseId) {
        throw new DatastoreProfileError('PROFILE_INVALID');
      }
      const bound = parseProfile({ ...profile, databaseId: parsedDatabaseId });
      return {
        document: {
          ...document,
          profiles: document.profiles.map((candidate) =>
            candidate.id === parsedId ? bound : candidate,
          ),
        },
        result: cloneProfile(bound),
      };
    });
  }

  /**
   * Binds an uninitialized profile and reports whether registry publication is
   * proven absent, complete, or ambiguous. Initialization callers may roll
   * back database/key/anchor artifacts only for `not-published`; the other two
   * states must retain recovery-capable artifacts and surface ambiguity.
   */
  async bindDatabaseIdForInitialization(
    id: ProfileId,
    databaseId: DatabaseId,
  ): Promise<DatastoreProfileBindingPublicationResult> {
    let parsedId: ProfileId;
    let parsedDatabaseId: DatabaseId | undefined;
    try {
      parsedId = parseProfileId(id);
      parsedDatabaseId = parseOptionalDatabaseId(databaseId);
    } catch (error) {
      return {
        status: 'not-published',
        error: profileFilesystemError(error),
      };
    }
    if (parsedDatabaseId === undefined)
      return {
        status: 'not-published',
        error: new DatastoreProfileError('PROFILE_INVALID'),
      };
    const publication = await this.#mutateWithPublicationStatus((document) => {
      const profile = document.profiles.find((candidate) => candidate.id === parsedId);
      if (profile === undefined) throw new DatastoreProfileError('PROFILE_NOT_FOUND');
      if (profile.databaseId !== undefined) {
        throw new DatastoreProfileError('PROFILE_INVALID');
      }
      const bound = parseProfile({ ...profile, databaseId: parsedDatabaseId });
      return {
        document: {
          ...document,
          profiles: document.profiles.map((candidate) =>
            candidate.id === parsedId ? bound : candidate,
          ),
        },
        result: cloneProfile(bound),
      };
    });
    if (publication.status === 'not-published') {
      return {
        status: 'not-published',
        error: profileFilesystemError(publication.error),
      };
    }
    const capability = newDatastoreProfileBindingPublication(publication.publication);
    if (publication.status === 'publication-uncertain') {
      return {
        status: 'publication-uncertain',
        publication: capability,
        error: profileFilesystemError(publication.error),
      };
    }
    return {
      status: 'published',
      publication: capability,
    };
  }

  async current(): Promise<DatastoreProfile | null> {
    const document = await this.#readOrEmpty();
    if (document.current === null) return null;
    const profile = document.profiles.find(
      (candidate) => candidate.id === document.current,
    );
    if (profile === undefined) throw new DatastoreProfileError('PROFILE_INVALID');
    return cloneProfile(profile);
  }

  async remove(id: ProfileId): Promise<DatastoreProfile> {
    const parsedId = parseProfileId(id);
    return this.#mutate((document) => {
      const profile = document.profiles.find((candidate) => candidate.id === parsedId);
      if (profile === undefined) throw new DatastoreProfileError('PROFILE_NOT_FOUND');
      return {
        document: {
          ...document,
          current: document.current === parsedId ? null : document.current,
          profiles: document.profiles.filter((candidate) => candidate.id !== parsedId),
        },
        result: cloneProfile(profile),
      };
    });
  }

  async #readOrEmpty(): Promise<DatastoreProfileRegistryDocument> {
    if (!(await registryExists(this.#path))) return emptyDocument();
    try {
      return await readProtectedJsonDocument(
        this.#path,
        profileRegistryDocumentOptions,
      );
    } catch (error) {
      throw profileFilesystemError(error);
    }
  }

  async #mutate<T>(
    mutate: (
      document: DatastoreProfileRegistryDocument,
    ) => Readonly<{ document: DatastoreProfileRegistryDocument; result: T }>,
  ): Promise<T> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      if (!(await registryExists(this.#path))) {
        const transition = mutate(emptyDocument());
        try {
          await writeProtectedJsonDocument(
            this.#path,
            transition.document,
            'create',
            profileRegistryDocumentOptions,
          );
          return transition.result;
        } catch (error) {
          if (isKeyFileError(error, 'KEY_FILE_ALREADY_EXISTS')) {
            await yieldRegistryMutation();
            continue;
          }
          throw profileFilesystemError(error);
        }
      }

      try {
        return await transitionProtectedJsonDocument(
          this.#path,
          profileRegistryDocumentOptions,
          (document) => {
            const transition = mutate(document);
            return transition;
          },
        );
      } catch (error) {
        if (
          isKeyFileError(error, 'KEY_FILE_NOT_FOUND') ||
          isKeyFileError(error, 'KEY_FILE_BUSY')
        ) {
          await yieldRegistryMutation();
          continue;
        }
        throw profileFilesystemError(error);
      }
    }
    throw new DatastoreProfileError('PROFILE_OPERATION_FAILED');
  }

  async #mutateWithPublicationStatus<T>(
    mutate: (
      document: DatastoreProfileRegistryDocument,
    ) => Readonly<{ document: DatastoreProfileRegistryDocument; result: T }>,
  ): Promise<ProtectedJsonDocumentTransitionPublicationResult<T>> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        if (!(await registryExists(this.#path))) {
          return {
            status: 'not-published',
            error: new DatastoreProfileError('PROFILE_NOT_FOUND'),
          };
        }
      } catch (error) {
        return {
          status: 'not-published',
          error: profileFilesystemError(error),
        };
      }

      const publication = await transitionProtectedJsonDocumentWithPublicationStatus(
        this.#path,
        profileRegistryDocumentOptions,
        mutate,
      );
      if (
        publication.status === 'not-published' &&
        (isKeyFileError(publication.error, 'KEY_FILE_NOT_FOUND') ||
          isKeyFileError(publication.error, 'KEY_FILE_BUSY'))
      ) {
        await yieldRegistryMutation();
        continue;
      }
      return publication;
    }
    return {
      status: 'not-published',
      error: new DatastoreProfileError('PROFILE_OPERATION_FAILED'),
    };
  }
}

function newDatastoreProfileBindingPublication(
  publication: ProtectedJsonDocumentPublication,
): DatastoreProfileBindingPublication {
  const capability = Object.freeze({});
  datastoreProfileBindingPublications.set(capability, publication);
  return capability as DatastoreProfileBindingPublication;
}

async function yieldRegistryMutation(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

function defaultConfigDirectory(): string {
  return join(homedir(), '.config', 'kavrix');
}

async function secureConfigDirectory(input: string): Promise<string> {
  if (typeof input !== 'string' || input.length === 0 || hasControlCharacters(input)) {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
  const directory = resolve(input);
  let existed = true;
  try {
    await lstat(directory);
  } catch (error) {
    if (errorCode(error) !== 'ENOENT')
      throw new DatastoreProfileError('PROFILE_UNSAFE');
    existed = false;
  }
  try {
    await mkdir(directory, { mode: 0o700, recursive: true });
    if (!existed) {
      if (process.platform === 'win32') {
        await setWindowsUserOnlyAcl(directory);
      } else {
        await chmodOwnerOnly(directory);
      }
    }
    const direct = await lstat(directory, { bigint: true });
    if (direct.isSymbolicLink() || !direct.isDirectory()) {
      throw new DatastoreProfileError('PROFILE_UNSAFE');
    }
    const canonical = await realpath(directory);
    const metadata = await stat(canonical, { bigint: true });
    if (!metadata.isDirectory()) throw new DatastoreProfileError('PROFILE_UNSAFE');
    if (process.platform === 'win32') {
      await verifyWindowsUserOnlyAcl(canonical);
    } else {
      const getuid = process.getuid;
      if (
        getuid === undefined ||
        metadata.uid !== BigInt(getuid()) ||
        (metadata.mode & 0o022n) !== 0n
      ) {
        throw new DatastoreProfileError('PROFILE_UNSAFE');
      }
    }
    return canonical;
  } catch (error) {
    if (error instanceof DatastoreProfileError) throw error;
    throw new DatastoreProfileError('PROFILE_UNSAFE');
  }
}

async function chmodOwnerOnly(path: string): Promise<void> {
  await chmod(path, 0o700);
}

async function registryExists(path: string): Promise<boolean> {
  try {
    const metadata = await lstat(path, { bigint: true });
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1n) {
      throw new DatastoreProfileError('PROFILE_UNSAFE');
    }
    return true;
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return false;
    if (error instanceof DatastoreProfileError) throw error;
    throw new DatastoreProfileError('PROFILE_UNSAFE');
  }
}

function emptyDocument(): DatastoreProfileRegistryDocument {
  return { version: REGISTRY_VERSION, current: null, profiles: [] };
}

function parseDocument(value: unknown): DatastoreProfileRegistryDocument {
  assertNoSensitiveKeys(value);
  const record = plainRecord(value);
  assertExactKeys(record, ['current', 'profiles', 'version']);
  if (record['version'] !== REGISTRY_VERSION || !Array.isArray(record['profiles'])) {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
  if (record['profiles'].length > MAX_PROFILES) {
    throw new DatastoreProfileError('PROFILE_LIMIT');
  }
  const profiles = record['profiles'].map(parseProfile);
  const ids = new Set<string>();
  for (const profile of profiles) {
    if (ids.has(profile.id)) throw new DatastoreProfileError('PROFILE_INVALID');
    ids.add(profile.id);
  }
  const sorted = sortProfiles(profiles);
  if (!sameProfiles(profiles, sorted))
    throw new DatastoreProfileError('PROFILE_INVALID');
  const current = record['current'] === null ? null : parseProfileId(record['current']);
  if (current !== null && !ids.has(current))
    throw new DatastoreProfileError('PROFILE_INVALID');
  return { version: REGISTRY_VERSION, current, profiles: sorted };
}

function parseProfile(value: unknown): DatastoreProfile {
  assertNoSensitiveKeys(value);
  const record = plainRecord(value);
  const id = parseProfileId(record['id']);
  const databaseId = parseOptionalDatabaseId(record['databaseId']);
  if (record['datastore'] === 'mongodb') {
    assertExactKeys(
      record,
      [
        'database',
        'databaseCollection',
        'databaseId',
        'datastore',
        'id',
        'keyFile',
        'vaultCollection',
      ],
      databaseId === undefined ? ['databaseId'] : [],
    );
    const profile: MongoDatastoreProfile = {
      id,
      datastore: 'mongodb',
      database: parseRoutingName(record['database'], DATABASE_NAME),
      databaseCollection: parseRoutingName(
        record['databaseCollection'],
        COLLECTION_NAME,
      ),
      vaultCollection: parseRoutingName(record['vaultCollection'], COLLECTION_NAME),
      keyFile: parsePath(record['keyFile']),
      ...(databaseId === undefined ? {} : { databaseId }),
    };
    return profile;
  }
  if (record['datastore'] === 'file') {
    assertExactKeys(
      record,
      ['dataFile', 'databaseId', 'datastore', 'id', 'keyFile'],
      databaseId === undefined ? ['databaseId'] : [],
    );
    const profile: FileDatastoreProfile = {
      id,
      datastore: 'file',
      dataFile: parsePath(record['dataFile']),
      keyFile: parsePath(record['keyFile']),
      ...(databaseId === undefined ? {} : { databaseId }),
    };
    return profile;
  }
  throw new DatastoreProfileError('PROFILE_INVALID');
}

function parseProfileId(value: unknown): ProfileId {
  try {
    return profileIdSchema.parse(value);
  } catch {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
}

function parseOptionalDatabaseId(value: unknown): DatabaseId | undefined {
  if (value === undefined) return undefined;
  try {
    return databaseIdSchema.parse(value);
  } catch {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
}

function parseRoutingName(value: unknown, pattern: RegExp): string {
  if (
    typeof value !== 'string' ||
    !pattern.test(value) ||
    hasControlCharacters(value)
  ) {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
  return value;
}

function parsePath(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_PATH_CHARS ||
    hasControlCharacters(value)
  ) {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
  return value;
}

function assertNoSensitiveKeys(value: unknown): void {
  if (Array.isArray(value)) {
    for (const entry of value) assertNoSensitiveKeys(entry);
    return;
  }
  if (value === null || typeof value !== 'object') return;
  const record = plainRecord(value);
  for (const [key, entry] of Object.entries(record)) {
    const lowered = key.toLocaleLowerCase('en-US');
    if (SENSITIVE_KEY_PARTS.some((part) => lowered.includes(part))) {
      throw new DatastoreProfileError('PROFILE_INVALID');
    }
    assertNoSensitiveKeys(entry);
  }
}

function plainRecord(value: unknown): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new DatastoreProfileError('PROFILE_INVALID');
  }
  return value as Readonly<Record<string, unknown>>;
}

function assertExactKeys(
  record: Readonly<Record<string, unknown>>,
  expected: readonly string[],
  optional: readonly string[] = [],
): void {
  const expectedSet = new Set(expected);
  const optionalSet = new Set(optional);
  for (const key of Object.keys(record)) {
    if (!expectedSet.has(key)) throw new DatastoreProfileError('PROFILE_INVALID');
  }
  for (const key of expected) {
    if (!optionalSet.has(key) && !Object.hasOwn(record, key)) {
      throw new DatastoreProfileError('PROFILE_INVALID');
    }
  }
}

function sortProfiles(
  profiles: readonly DatastoreProfile[],
): readonly DatastoreProfile[] {
  return [...profiles].sort((left, right) =>
    left.id < right.id ? -1 : left.id > right.id ? 1 : 0,
  );
}

function sameProfiles(
  left: readonly DatastoreProfile[],
  right: readonly DatastoreProfile[],
): boolean {
  return (
    left.length === right.length &&
    left.every((profile, index) => profile === right[index])
  );
}

function cloneProfile(profile: DatastoreProfile): DatastoreProfile {
  return profile.datastore === 'mongodb'
    ? {
        id: profile.id,
        datastore: 'mongodb',
        database: profile.database,
        databaseCollection: profile.databaseCollection,
        vaultCollection: profile.vaultCollection,
        keyFile: profile.keyFile,
        ...(profile.databaseId === undefined ? {} : { databaseId: profile.databaseId }),
      }
    : {
        id: profile.id,
        datastore: 'file',
        dataFile: profile.dataFile,
        keyFile: profile.keyFile,
        ...(profile.databaseId === undefined ? {} : { databaseId: profile.databaseId }),
      };
}

function hasControlCharacters(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0);
    return (
      codePoint === undefined ||
      codePoint < 32 ||
      codePoint === 127 ||
      (codePoint >= 128 && codePoint <= 159)
    );
  });
}

function errorCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String(error.code)
    : undefined;
}

function isKeyFileError(error: unknown, code: string): boolean {
  return error instanceof PortableKeyFileError && error.code === code;
}

function profileFilesystemError(error: unknown): DatastoreProfileError {
  if (error instanceof DatastoreProfileError) return error;
  if (error instanceof ProtectedJsonDocumentError) {
    return new DatastoreProfileError('PROFILE_INVALID');
  }
  return new DatastoreProfileError('PROFILE_UNSAFE');
}

function profileErrorMessage(code: DatastoreProfileError['code']): string {
  switch (code) {
    case 'PROFILE_DUPLICATE':
      return 'The datastore profile already exists.';
    case 'PROFILE_INVALID':
      return 'The datastore profile is invalid.';
    case 'PROFILE_LIMIT':
      return 'Datastore profiles are limited to 64 entries.';
    case 'PROFILE_NOT_FOUND':
      return 'The datastore profile was not found.';
    case 'PROFILE_OPERATION_FAILED':
      return 'The datastore profile operation failed.';
    case 'PROFILE_UNSAFE':
      return 'The datastore profile registry is not safe to use.';
  }
}
