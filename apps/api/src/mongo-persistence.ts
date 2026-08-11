import {
  apiSessionResponseSchema,
  changeRecordSchema,
  controlListPageOptionsSchema,
  decodeControlListCursor,
  deviceRecordSchema,
  encodeControlListCursor,
  inviteIdSchema,
  sha256DigestSchema,
  timestampSchema,
  vaultBootstrapRequestSchema,
  vaultBootstrapResponseSchema,
  vaultIdSchema,
  type DeviceId,
  type DeviceRecord,
  type ControlListPageOptions,
  type ControlListCursorPayload,
  type InviteId,
  type Sha256Digest,
  type Timestamp,
  type VaultBootstrapResponse,
  type VaultId,
} from '@kavrix/schemas';
import {
  assertMongoDocumentCompatibility,
  contentHashForRecord,
  fromVaultDocument,
  mongoStorageCollectionNames,
  storageCounterDocumentSchema,
  toChangeDocument,
  toVaultDocument,
  type StorageCounterDocument,
  type StoredChangeDocument,
  type StoredVaultDocument,
} from '@kavrix/storage';
import {
  MongoServerError,
  type ClientSession,
  type Collection,
  type Db,
  type MongoClient,
} from 'mongodb';

import {
  deviceDocument,
  enrollmentCompletionHash,
  inviteGrantDocument,
  mongoApiCollectionNames,
  mongoApiCollectionOptions,
  mongoApiDocumentSchemas,
  mongoApiCredentialClaimDocumentSchema,
  mongoApiDeviceDocumentSchema,
  mongoApiEnrollmentDocumentSchema,
  mongoApiIndexes,
  mongoApiInviteDocumentSchema,
  mongoApiSessionDocumentSchema,
  parseEnrollmentCompletion,
  publicInviteFromDocument,
  vaultBootstrapHash,
  type MongoApiDeviceDocument,
  type MongoApiCredentialClaimDocument,
  type MongoApiEnrollmentDocument,
  type MongoApiInviteDocument,
  type MongoApiSessionDocument,
} from './mongo-documents.js';
import type {
  AuthorizationPort,
  AuthorizationDevicePage,
  AuthorizationInvitePage,
  EnrollmentCompletion,
  InviteGrant,
  InviteRedemption,
  SessionPrincipal,
  VaultBootstrapInput,
  VaultBootstrapPort,
} from './ports.js';

const transactionOptions = {
  readConcern: { level: 'snapshot' as const },
  writeConcern: { w: 'majority' as const },
};

export async function installMongoApiContracts(database: Db): Promise<void> {
  const existing = new Set(
    (await database.listCollections({}, { nameOnly: true }).toArray()).map(
      ({ name }) => name,
    ),
  );
  for (const name of Object.values(mongoApiCollectionNames)) {
    const options = mongoApiCollectionOptions[name];
    if (existing.has(name)) {
      await database.command({
        collMod: name,
        validator: options.validator,
        validationLevel: options.validationLevel,
        validationAction: options.validationAction,
      });
    } else {
      await database.createCollection(name, options);
    }
    const indexes = mongoApiIndexes[name];
    if (indexes.length > 0) {
      await database.collection(name).createIndexes([...indexes]);
    }
  }
}

export async function assertMongoApiCompatibility(database: Db): Promise<void> {
  await assertMongoDocumentCompatibility(database, mongoApiDocumentSchemas, {
    redactDocumentIds: true,
  });
}

export async function initializeMongoApiPersistence(database: Db): Promise<void> {
  await installMongoApiContracts(database);
  await assertMongoApiCompatibility(database);
}

const bootstrapScopes = ['sync:read', 'sync:write', 'device:manage'] as const;

export class MongoVaultBootstrapPort implements VaultBootstrapPort {
  readonly #client: MongoClient;
  readonly #database: Db;

  public constructor(client: MongoClient, database: Db) {
    this.#client = client;
    this.#database = database;
  }

  public async bootstrap(
    input: VaultBootstrapInput,
  ): Promise<VaultBootstrapResponse | null> {
    const request = vaultBootstrapRequestSchema.parse({
      vault: input.vault,
      device: input.device,
    });
    const sessionTokenHash = sha256DigestSchema.parse(input.sessionTokenHash);
    const bootstrapHash = vaultBootstrapHash(request);
    const createdAt = request.vault.createdAt;
    const device = deviceRecordSchema.parse({
      id: request.device.id,
      vaultId: request.vault.id,
      schemaVersion: request.device.schemaVersion,
      tokenHash: sessionTokenHash,
      tokenVersion: 1,
      ...(request.device.encryptedLabel === undefined
        ? {}
        : { encryptedLabel: request.device.encryptedLabel }),
      scopes: bootstrapScopes,
      createdAt,
    });
    const receipt = vaultBootstrapResponseSchema.parse({
      vaultId: request.vault.id,
      deviceId: request.device.id,
    });

    try {
      return await this.#withTransaction(async (session) => {
        const previousClaimValue = await this.#credentialClaims().findOne(
          { _id: sessionTokenHash },
          { session },
        );
        if (previousClaimValue !== null) {
          const previousClaim =
            mongoApiCredentialClaimDocumentSchema.parse(previousClaimValue);
          if (
            previousClaim.kind !== 'session' ||
            previousClaim.parentHash !== undefined ||
            previousClaim.bootstrapHash !== bootstrapHash
          ) {
            return null;
          }
          return (await this.#isIntactReplay(
            request.vault.id,
            device,
            sessionTokenHash,
            session,
          ))
            ? receipt
            : null;
        }

        const vaultCollision = await this.#database
          .collection<StoredVaultDocument>(mongoStorageCollectionNames.vaults)
          .findOne({ _id: request.vault.id }, { session, projection: { _id: 1 } });
        const deviceCollision = await this.#devices().findOne(
          { _id: request.device.id },
          { session, projection: { _id: 1 } },
        );
        if (vaultCollision !== null || deviceCollision !== null) return null;

        const change = changeRecordSchema.parse({
          id: 'change.1',
          vaultId: request.vault.id,
          serverSequence: 1,
          entityType: 'vault',
          entityId: request.vault.id,
          recordRevision: request.vault.revision,
          operation: 'upsert',
          ciphertextHash: contentHashForRecord(request.vault),
          createdAt: request.vault.updatedAt,
        });

        await this.#credentialClaims().insertOne(
          mongoApiCredentialClaimDocumentSchema.parse({
            _id: sessionTokenHash,
            kind: 'session',
            bootstrapHash,
            createdAt,
          }),
          { session },
        );
        await this.#database
          .collection<StoredVaultDocument>(mongoStorageCollectionNames.vaults)
          .insertOne(toVaultDocument(request.vault), { session });
        await this.#database
          .collection<StorageCounterDocument>(mongoStorageCollectionNames.counters)
          .insertOne(
            storageCounterDocumentSchema.parse({
              _id: request.vault.id,
              changeSequence: 1,
              vaultRevision: request.vault.revision,
            }),
            { session },
          );
        await this.#database
          .collection<StoredChangeDocument>(mongoStorageCollectionNames.changes)
          .insertOne(toChangeDocument(change, request.vault), { session });
        await this.#devices().insertOne(deviceDocument(device), { session });
        await this.#sessions().insertOne(
          mongoApiSessionDocumentSchema.parse({
            _id: sessionTokenHash,
            vaultId: request.vault.id,
            deviceId: request.device.id,
            scopes: bootstrapScopes,
            createdAt,
          }),
          { session },
        );
        return receipt;
      });
    } catch (error) {
      if (isDuplicateKey(error)) return null;
      throw error;
    }
  }

  async #isIntactReplay(
    vaultId: VaultId,
    expectedDevice: DeviceRecord,
    sessionTokenHash: Sha256Digest,
    session: ClientSession,
  ): Promise<boolean> {
    const vaultValue = await this.#database
      .collection<StoredVaultDocument>(mongoStorageCollectionNames.vaults)
      .findOne({ _id: vaultId }, { session });
    const deviceValue = await this.#devices().findOne(
      { _id: expectedDevice.id, vaultId, 'record.revokedAt': { $exists: false } },
      { session },
    );
    const sessionValue = await this.#sessions().findOne(
      {
        _id: sessionTokenHash,
        vaultId,
        deviceId: expectedDevice.id,
        revokedAt: { $exists: false },
      },
      { session },
    );
    if (vaultValue === null || deviceValue === null || sessionValue === null) {
      return false;
    }
    fromVaultDocument(vaultValue);
    const storedDevice = mongoApiDeviceDocumentSchema.parse(deviceValue).record;
    const storedSession = mongoApiSessionDocumentSchema.parse(sessionValue);
    return (
      storedDevice.tokenHash === expectedDevice.tokenHash &&
      storedDevice.vaultId === expectedDevice.vaultId &&
      storedDevice.id === expectedDevice.id &&
      storedSession.scopes.length === bootstrapScopes.length &&
      bootstrapScopes.every((scope) => storedSession.scopes.includes(scope))
    );
  }

  async #withTransaction<Result>(
    work: (session: ClientSession) => Promise<Result>,
  ): Promise<Result> {
    const session = this.#client.startSession();
    try {
      return await session.withTransaction(
        async () => work(session),
        transactionOptions,
      );
    } finally {
      await session.endSession();
    }
  }

  #sessions(): Collection<MongoApiSessionDocument> {
    return this.#database.collection(mongoApiCollectionNames.sessions);
  }

  #devices(): Collection<MongoApiDeviceDocument> {
    return this.#database.collection(mongoApiCollectionNames.devices);
  }

  #credentialClaims(): Collection<MongoApiCredentialClaimDocument> {
    return this.#database.collection(mongoApiCollectionNames.credentialClaims);
  }
}

export class MongoAuthorizationPort implements AuthorizationPort {
  readonly #client: MongoClient;
  readonly #database: Db;

  public constructor(client: MongoClient, database: Db) {
    this.#client = client;
    this.#database = database;
  }

  public initialize(): Promise<void> {
    return initializeMongoApiPersistence(this.#database);
  }

  public async findSession(
    tokenHashInput: Sha256Digest,
    now: Date,
  ): Promise<SessionPrincipal | null> {
    void now;
    const tokenHash = sha256DigestSchema.parse(tokenHashInput);
    const value = await this.#sessions().findOne({
      _id: tokenHash,
      revokedAt: { $exists: false },
    });
    if (value === null) return null;
    const session = mongoApiSessionDocumentSchema.parse(value);
    const claimValue = await this.#credentialClaims().findOne({
      _id: tokenHash,
      kind: 'session',
    });
    if (claimValue === null) return null;
    mongoApiCredentialClaimDocumentSchema.parse(claimValue);
    const deviceValue = await this.#devices().findOne({
      _id: session.deviceId,
      vaultId: session.vaultId,
      'record.revokedAt': { $exists: false },
    });
    if (deviceValue === null) return null;
    mongoApiDeviceDocumentSchema.parse(deviceValue);
    return apiSessionResponseSchema.parse({
      vaultId: session.vaultId,
      deviceId: session.deviceId,
      scopes: session.scopes,
    });
  }

  public async createInvite(grantInput: InviteGrant): Promise<void> {
    const document = inviteGrantDocument(grantInput);
    await this.#withTransaction(async (session) => {
      await this.#credentialClaims().insertOne(
        mongoApiCredentialClaimDocumentSchema.parse({
          _id: document.tokenHash,
          kind: 'invite',
          createdAt: document.createdAt,
        }),
        { session },
      );
      await this.#invites().insertOne(document, { session });
    });
  }

  public async redeemInvite(
    inviteTokenHashInput: Sha256Digest,
    enrollmentTokenHashInput: Sha256Digest,
    enrollmentExpiresAtInput: Timestamp,
    now: Date,
  ): Promise<InviteRedemption | null> {
    const inviteTokenHash = sha256DigestSchema.parse(inviteTokenHashInput);
    const enrollmentTokenHash = sha256DigestSchema.parse(enrollmentTokenHashInput);
    const enrollmentExpiresAt = timestampSchema.parse(enrollmentExpiresAtInput);
    const redeemedAt = timestampSchema.parse(now.toISOString());
    try {
      return await this.#withTransaction(async (session) => {
        const value = await this.#invites().findOne(
          { tokenHash: inviteTokenHash },
          { session },
        );
        if (value === null) return null;
        const invite = mongoApiInviteDocumentSchema.parse(value);
        const parentClaimValue = await this.#credentialClaims().findOne(
          { _id: inviteTokenHash, kind: 'invite' },
          { session },
        );
        if (parentClaimValue === null) return null;
        mongoApiCredentialClaimDocumentSchema.parse(parentClaimValue);
        if (invite.state === 'redeemed') {
          if (
            invite.enrollmentExpiresAt === undefined ||
            Date.parse(invite.enrollmentExpiresAt) <= now.getTime()
          ) {
            return null;
          }
          if (invite.enrollmentTokenHash !== enrollmentTokenHash) return null;
          const childClaimValue = await this.#credentialClaims().findOne(
            {
              _id: enrollmentTokenHash,
              kind: 'enrollment',
              parentHash: inviteTokenHash,
            },
            { session },
          );
          if (childClaimValue === null) return null;
          mongoApiCredentialClaimDocumentSchema.parse(childClaimValue);
          return redemptionReceipt(invite);
        }
        if (
          invite.state !== 'active' ||
          Date.parse(invite.expiresAt) <= now.getTime()
        ) {
          return null;
        }
        const effectiveExpiry = timestampSchema.parse(
          new Date(
            Math.min(Date.parse(invite.expiresAt), Date.parse(enrollmentExpiresAt)),
          ).toISOString(),
        );
        const enrollment = mongoApiEnrollmentDocumentSchema.parse({
          _id: enrollmentTokenHash,
          vaultId: invite.vaultId,
          scopes: invite.scopes,
          state: 'active',
          createdAt: redeemedAt,
          expiresAt: effectiveExpiry,
        });
        const collision = await this.#credentialClaims().findOne(
          { _id: enrollmentTokenHash },
          { session, projection: { _id: 1 } },
        );
        if (collision !== null) return null;
        await this.#credentialClaims().insertOne(
          mongoApiCredentialClaimDocumentSchema.parse({
            _id: enrollmentTokenHash,
            kind: 'enrollment',
            parentHash: inviteTokenHash,
            createdAt: redeemedAt,
          }),
          { session },
        );
        await this.#enrollments().insertOne(enrollment, { session });
        const update = await this.#invites().updateOne(
          { _id: invite._id, state: 'active' },
          {
            $set: {
              state: 'redeemed',
              consumedAt: redeemedAt,
              enrollmentTokenHash,
              enrollmentExpiresAt: effectiveExpiry,
            },
          },
          { session },
        );
        if (update.modifiedCount !== 1) {
          throw new Error('Invite transition lost atomic ownership');
        }
        return {
          vaultId: invite.vaultId,
          scopes: invite.scopes,
          enrollmentExpiresAt: effectiveExpiry,
        };
      });
    } catch (error) {
      if (isDuplicateKey(error)) return null;
      throw error;
    }
  }

  public async completeEnrollment(
    enrollmentTokenHashInput: Sha256Digest,
    completionInput: EnrollmentCompletion,
    now: Date,
  ): Promise<DeviceRecord | null> {
    const enrollmentTokenHash = sha256DigestSchema.parse(enrollmentTokenHashInput);
    const completion = parseEnrollmentCompletion(completionInput);
    const completionHash = enrollmentCompletionHash(completion);
    const completedAt = timestampSchema.parse(now.toISOString());
    try {
      return await this.#withTransaction(async (session) => {
        const value = await this.#enrollments().findOne(
          { _id: enrollmentTokenHash },
          { session },
        );
        if (value === null) return null;
        const enrollment = mongoApiEnrollmentDocumentSchema.parse(value);
        const parentClaimValue = await this.#credentialClaims().findOne(
          { _id: enrollmentTokenHash, kind: 'enrollment' },
          { session },
        );
        if (parentClaimValue === null) return null;
        mongoApiCredentialClaimDocumentSchema.parse(parentClaimValue);
        if (enrollment.state === 'completed') {
          if (Date.parse(enrollment.expiresAt) <= now.getTime()) return null;
          if (
            enrollment.completionHash !== completionHash ||
            enrollment.sessionTokenHash !== completion.sessionTokenHash ||
            enrollment.deviceId !== completion.deviceId
          ) {
            return null;
          }
          const sessionClaimValue = await this.#credentialClaims().findOne(
            {
              _id: completion.sessionTokenHash,
              kind: 'session',
              parentHash: enrollmentTokenHash,
            },
            { session },
          );
          if (sessionClaimValue === null) return null;
          mongoApiCredentialClaimDocumentSchema.parse(sessionClaimValue);
          return this.#loadDevice(enrollment.deviceId, enrollment.vaultId, session);
        }
        if (
          enrollment.vaultId !== completion.vaultId ||
          Date.parse(enrollment.expiresAt) <= now.getTime()
        ) {
          return null;
        }
        const credentialCollision = await this.#credentialClaims().findOne(
          { _id: completion.sessionTokenHash },
          { session, projection: { _id: 1 } },
        );
        if (credentialCollision !== null) return null;
        const collision = await this.#devices().findOne(
          { _id: completion.deviceId },
          { session, projection: { _id: 1 } },
        );
        if (collision !== null) return null;
        const record = deviceRecordSchema.parse({
          id: completion.deviceId,
          vaultId: enrollment.vaultId,
          schemaVersion: completion.schemaVersion,
          tokenHash: completion.sessionTokenHash,
          tokenVersion: 1,
          ...(completion.encryptedLabel === undefined
            ? {}
            : { encryptedLabel: completion.encryptedLabel }),
          scopes: enrollment.scopes,
          createdAt: completedAt,
        });
        await this.#credentialClaims().insertOne(
          mongoApiCredentialClaimDocumentSchema.parse({
            _id: completion.sessionTokenHash,
            kind: 'session',
            parentHash: enrollmentTokenHash,
            createdAt: completedAt,
          }),
          { session },
        );
        await this.#devices().insertOne(deviceDocument(record), { session });
        await this.#sessions().insertOne(
          mongoApiSessionDocumentSchema.parse({
            _id: completion.sessionTokenHash,
            vaultId: enrollment.vaultId,
            deviceId: completion.deviceId,
            scopes: enrollment.scopes,
            createdAt: completedAt,
          }),
          { session },
        );
        const update = await this.#enrollments().updateOne(
          { _id: enrollmentTokenHash, state: 'active' },
          {
            $set: {
              state: 'completed',
              completionHash,
              sessionTokenHash: completion.sessionTokenHash,
              deviceId: completion.deviceId,
              completedAt,
            },
          },
          { session },
        );
        if (update.modifiedCount !== 1) {
          throw new Error('Enrollment transition lost atomic ownership');
        }
        return record;
      });
    } catch (error) {
      if (isDuplicateKey(error)) return null;
      throw error;
    }
  }

  public async listInvitePage(
    vaultIdInput: VaultId,
    optionsInput: ControlListPageOptions,
    now: Date,
  ): Promise<AuthorizationInvitePage> {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const options = controlListPageOptionsSchema.parse(optionsInput);
    const cursor = bindControlListCursor(options, 'invites', vaultId);
    const values = await this.#invites()
      .find(
        cursor === undefined
          ? { vaultId }
          : {
              vaultId,
              $or: [
                { createdAt: { $lt: cursor.createdAt } },
                { createdAt: cursor.createdAt, _id: { $gt: cursor.id } },
              ],
            },
      )
      .sort({ createdAt: -1, _id: 1 })
      .hint('invites_by_vault_created_id_v2')
      .limit(options.limit + 1)
      .toArray();
    const invites = values.map((value) =>
      publicInviteFromDocument(mongoApiInviteDocumentSchema.parse(value), now),
    );
    const page = invites.slice(0, options.limit);
    const final = page.at(-1);
    return {
      invites: page,
      nextCursor:
        invites.length <= options.limit || final === undefined
          ? null
          : encodeControlListCursor({
              version: 1,
              resource: 'invites',
              vaultId,
              createdAt: final.createdAt,
              id: final.id,
            }),
    };
  }

  public async revokeInvite(
    vaultIdInput: VaultId,
    inviteIdInput: InviteId,
    revokedAtInput: Timestamp,
  ): Promise<boolean> {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const inviteId = inviteIdSchema.parse(inviteIdInput);
    const revokedAt = timestampSchema.parse(revokedAtInput);
    return this.#withTransaction(async (session) => {
      const value = await this.#invites().findOne(
        { _id: inviteId, vaultId },
        { session },
      );
      if (value === null) return false;
      const invite = mongoApiInviteDocumentSchema.parse(value);
      if (invite.state === 'revoked') return true;
      if (
        invite.state !== 'active' ||
        Date.parse(invite.expiresAt) <= Date.parse(revokedAt)
      ) {
        return false;
      }
      const result = await this.#invites().updateOne(
        { _id: inviteId, vaultId, state: 'active' },
        { $set: { state: 'revoked', revokedAt } },
        { session },
      );
      if (result.modifiedCount !== 1) {
        throw new Error('Invite revocation lost atomic ownership');
      }
      return true;
    });
  }

  public async listDevicePage(
    vaultIdInput: VaultId,
    optionsInput: ControlListPageOptions,
  ): Promise<AuthorizationDevicePage> {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const options = controlListPageOptionsSchema.parse(optionsInput);
    const cursor = bindControlListCursor(options, 'devices', vaultId);
    const values = await this.#devices()
      .find(
        cursor === undefined
          ? { vaultId }
          : {
              vaultId,
              $or: [
                { 'record.createdAt': { $gt: cursor.createdAt } },
                { 'record.createdAt': cursor.createdAt, _id: { $gt: cursor.id } },
              ],
            },
      )
      .sort({ 'record.createdAt': 1, _id: 1 })
      .hint('devices_by_vault_created_id_v2')
      .limit(options.limit + 1)
      .toArray();
    const devices = values.map(
      (value) => mongoApiDeviceDocumentSchema.parse(value).record,
    );
    const page = devices.slice(0, options.limit);
    const final = page.at(-1);
    return {
      devices: page,
      nextCursor:
        devices.length <= options.limit || final === undefined
          ? null
          : encodeControlListCursor({
              version: 1,
              resource: 'devices',
              vaultId,
              createdAt: final.createdAt,
              id: final.id,
            }),
    };
  }

  public async revokeDevice(
    vaultIdInput: VaultId,
    deviceIdInput: DeviceId,
    revokedAtInput: Timestamp,
  ): Promise<boolean> {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const deviceId = deviceRecordSchema.shape.id.parse(deviceIdInput);
    const revokedAt = timestampSchema.parse(revokedAtInput);
    return this.#withTransaction(async (session) => {
      const value = await this.#devices().findOne(
        { _id: deviceId, vaultId },
        { session },
      );
      if (value === null) return false;
      const device = mongoApiDeviceDocumentSchema.parse(value).record;
      if (device.revokedAt === undefined) {
        const revoked = deviceRecordSchema.parse({ ...device, revokedAt });
        const update = await this.#devices().replaceOne(
          { _id: deviceId, vaultId, 'record.revokedAt': { $exists: false } },
          deviceDocument(revoked),
          { session },
        );
        if (update.modifiedCount !== 1) {
          throw new Error('Device revocation lost atomic ownership');
        }
      }
      await this.#sessions().updateMany(
        { vaultId, deviceId, revokedAt: { $exists: false } },
        { $set: { revokedAt } },
        { session },
      );
      return true;
    });
  }

  async #loadDevice(
    deviceId: DeviceId,
    vaultId: VaultId,
    session: ClientSession,
  ): Promise<DeviceRecord | null> {
    const value = await this.#devices().findOne(
      { _id: deviceId, vaultId },
      { session },
    );
    return value === null ? null : mongoApiDeviceDocumentSchema.parse(value).record;
  }

  async #withTransaction<Result>(
    work: (session: ClientSession) => Promise<Result>,
  ): Promise<Result> {
    const session = this.#client.startSession();
    try {
      return await session.withTransaction(
        async () => work(session),
        transactionOptions,
      );
    } finally {
      await session.endSession();
    }
  }

  #sessions(): Collection<MongoApiSessionDocument> {
    return this.#database.collection(mongoApiCollectionNames.sessions);
  }

  #devices(): Collection<MongoApiDeviceDocument> {
    return this.#database.collection(mongoApiCollectionNames.devices);
  }

  #invites(): Collection<MongoApiInviteDocument> {
    return this.#database.collection(mongoApiCollectionNames.invites);
  }

  #enrollments(): Collection<MongoApiEnrollmentDocument> {
    return this.#database.collection(mongoApiCollectionNames.enrollments);
  }

  #credentialClaims(): Collection<MongoApiCredentialClaimDocument> {
    return this.#database.collection(mongoApiCollectionNames.credentialClaims);
  }
}

function redemptionReceipt(invite: MongoApiInviteDocument): InviteRedemption {
  if (invite.enrollmentExpiresAt === undefined) {
    throw new Error('Redeemed invite is missing its receipt');
  }
  return {
    vaultId: invite.vaultId,
    scopes: invite.scopes,
    enrollmentExpiresAt: invite.enrollmentExpiresAt,
  };
}

function bindControlListCursor<Resource extends 'invites' | 'devices'>(
  options: ControlListPageOptions,
  resource: Resource,
  vaultId: VaultId,
): Extract<ControlListCursorPayload, { resource: Resource }> | undefined {
  if (options.cursor === undefined) return undefined;
  const cursor = decodeControlListCursor(options.cursor);
  if (cursor.resource !== resource || cursor.vaultId !== vaultId) {
    throw new TypeError('Control-list cursor does not match this resource');
  }
  return cursor as Extract<ControlListCursorPayload, { resource: Resource }>;
}

function isDuplicateKey(error: unknown): boolean {
  return error instanceof MongoServerError && error.code === 11_000;
}
