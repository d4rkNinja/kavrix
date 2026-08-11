import type { Db, MongoClient } from 'mongodb';
import { describe, expect, it, vi } from 'vitest';

import {
  decodeControlListCursor,
  deviceIdSchema,
  deviceRecordSchema,
  encodeControlListCursor,
  inviteIdSchema,
  schemaVersionSchema,
  sha256DigestSchema,
  timestampSchema,
  vaultIdSchema,
  type Sha256Digest,
} from '@kavrix/schemas';
import {
  apiScopesFragment,
  canonicalTimestampFragment,
  encryptedDeviceLabelFragment,
  MONGO_DOCUMENT_ID_UNAVAILABLE,
  MongoDocumentCompatibilityError,
  opaqueIdentifierFragment,
  sha256DigestFragment,
  supportedSchemaVersionFragment,
  supportedTokenVersionFragment,
} from '@kavrix/storage';

import {
  enrollmentCompletionHash,
  deviceDocument,
  inviteGrantDocument,
  mongoApiCollectionNames,
  mongoApiCollectionOptions,
  mongoApiDocumentSchemas,
  mongoApiDeviceDocumentSchema,
  mongoApiCredentialClaimDocumentSchema,
  mongoApiEnrollmentDocumentSchema,
  mongoApiIndexes,
  mongoApiInviteDocumentSchema,
  mongoApiRateLimitDocumentSchema,
  mongoApiSessionDocumentSchema,
  publicInviteFromDocument,
} from '../src/mongo-documents.js';
import {
  assertMongoApiCompatibility,
  initializeMongoApiPersistence,
  installMongoApiContracts,
  MongoAuthorizationPort,
} from '../src/mongo-persistence.js';
import { fixedWindowIdentity } from '../src/mongo-rate-limit.js';
import { parseMongoApiServerConfig } from '../src/server.js';

const vaultId = vaultIdSchema.parse('vault.mongo-test');
const otherVaultId = vaultIdSchema.parse('vault.mongo-other');
const deviceId = deviceIdSchema.parse('device.mongo-test');
const createdAt = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const expiresAt = timestampSchema.parse('2026-08-10T00:10:00.000Z');
const hash = (fill: number): Sha256Digest =>
  sha256DigestSchema.parse(Buffer.alloc(32, fill).toString('base64url'));

interface TestMongoSchema {
  bsonType?: string | readonly string[];
  required?: readonly string[];
  additionalProperties?: boolean;
  properties?: Record<string, TestMongoSchema>;
  oneOf?: readonly TestMongoSchema[];
  enum?: readonly unknown[];
  items?: TestMongoSchema;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  multipleOf?: number;
  minimum?: number;
  maximum?: number;
}

function requireValue<T>(value: T | undefined, message: string): T {
  if (value === undefined) throw new Error(message);
  return value;
}

function collectionSchema(
  name: keyof typeof mongoApiCollectionOptions,
): TestMongoSchema {
  const validator = mongoApiCollectionOptions[name].validator as
    Record<string, unknown> | undefined;
  expect(validator).toBeDefined();
  return requireValue(
    validator?.['$jsonSchema'] as TestMongoSchema | undefined,
    `missing validator for ${name}`,
  );
}

function property(schema: TestMongoSchema, ...path: string[]): TestMongoSchema {
  let current = schema;
  for (const segment of path) {
    const next = current.properties?.[segment];
    expect(next, `missing Mongo validator path ${path.join('.')}`).toBeDefined();
    current = requireValue(next, `missing Mongo validator path ${path.join('.')}`);
  }
  return current;
}

function branch(
  schema: TestMongoSchema,
  discriminator: string,
  value: string,
): TestMongoSchema {
  const match = schema.oneOf?.find((candidate) =>
    candidate.properties?.[discriminator]?.enum?.includes(value),
  );
  expect(match, `missing ${discriminator}=${value} branch`).toBeDefined();
  return requireValue(match, `missing ${discriminator}=${value} branch`);
}

function expectExactBranch(
  schema: TestMongoSchema,
  discriminator: string,
  value: string,
  required: readonly string[],
): void {
  const selected = branch(schema, discriminator, value);
  expect(selected.additionalProperties).toBe(false);
  expect([...(selected.required ?? [])].sort()).toEqual([...required].sort());
  expect(Object.keys(selected.properties ?? {}).sort()).toEqual([...required].sort());
}

function walkSchemas(
  schema: TestMongoSchema,
  visit: (schema: TestMongoSchema) => void,
): void {
  visit(schema);
  for (const child of Object.values(schema.properties ?? {})) walkSchemas(child, visit);
  for (const child of schema.oneOf ?? []) walkSchemas(child, visit);
  if (schema.items !== undefined) walkSchemas(schema.items, visit);
}

describe('Mongo API persistence contracts', () => {
  it('maps every declared API collection to its exact canonical parser', () => {
    expect(Object.keys(mongoApiDocumentSchemas).sort()).toEqual(
      Object.values(mongoApiCollectionNames).sort(),
    );
    expect(mongoApiDocumentSchemas).toEqual({
      api_sessions: mongoApiSessionDocumentSchema,
      api_devices: mongoApiDeviceDocumentSchema,
      api_invites: mongoApiInviteDocumentSchema,
      api_enrollments: mongoApiEnrollmentDocumentSchema,
      api_rate_limits: mongoApiRateLimitDocumentSchema,
      api_credential_claims: mongoApiCredentialClaimDocumentSchema,
    });
  });

  it('defines every API collection with a strict erroring validator', () => {
    const names = Object.values(mongoApiCollectionNames);
    expect(Object.keys(mongoApiCollectionOptions).sort()).toEqual([...names].sort());
    for (const name of names) {
      const options = mongoApiCollectionOptions[name];
      expect(options.validationLevel).toBe('strict');
      expect(options.validationAction).toBe('error');
      const schema = collectionSchema(name);
      expect(
        schema.additionalProperties === false ||
          schema.oneOf?.every((candidate) => candidate.additionalProperties === false),
      ).toBe(true);
    }
  });

  it('composes the same canonical fragments into API persistence validators', () => {
    const session = collectionSchema('api_sessions');
    expect(property(session, '_id')).toBe(sha256DigestFragment);
    expect(property(session, 'vaultId')).toBe(opaqueIdentifierFragment);
    expect(property(session, 'scopes')).toBe(apiScopesFragment);
    expect(property(session, 'createdAt')).toBe(canonicalTimestampFragment);

    const device = property(collectionSchema('api_devices'), 'record');
    expect(property(device, 'schemaVersion')).toBe(supportedSchemaVersionFragment);
    expect(property(device, 'tokenVersion')).toBe(supportedTokenVersionFragment);
    expect(property(device, 'tokenHash')).toBe(sha256DigestFragment);
    expect(property(device, 'encryptedLabel')).toBe(encryptedDeviceLabelFragment);
    expect(property(device, 'scopes')).toBe(apiScopesFragment);

    const invite = branch(collectionSchema('api_invites'), 'state', 'active');
    expect(property(invite, 'tokenHash')).toBe(sha256DigestFragment);
    expect(property(invite, 'createdAt')).toBe(canonicalTimestampFragment);
    const validators = JSON.stringify(mongoApiCollectionOptions);
    expect(validators).toContain('"ciphertext"');
    for (const forbidden of [
      '"passphrase"',
      '"password"',
      '"portableKey"',
      '"recoveryKey"',
      '"deviceToken"',
      '"decrypted"',
    ]) {
      expect(validators).not.toContain(forbidden);
    }
  });

  it('bounds API numeric and array fragments and closes every BSON object', () => {
    let numericCount = 0;
    let arrayCount = 0;
    for (const name of Object.values(mongoApiCollectionNames)) {
      walkSchemas(collectionSchema(name), (schema) => {
        if (schema.bsonType !== undefined && typeof schema.bsonType !== 'string') {
          const numericTypes = schema.bsonType.filter((type) =>
            ['int', 'long', 'double', 'decimal'].includes(type),
          );
          if (numericTypes.length > 0) {
            numericCount += 1;
            expect(schema.bsonType).toEqual(['int', 'long', 'double']);
            expect(schema.multipleOf).toBe(1);
            expect(Number.isSafeInteger(schema.minimum)).toBe(true);
            expect(Number.isSafeInteger(schema.maximum)).toBe(true);
          }
        }
        if (schema.bsonType === 'array') {
          arrayCount += 1;
          expect(schema.minItems).toBe(1);
          expect(schema.maxItems).toBe(3);
          expect(schema.uniqueItems).toBe(true);
        }
        if (schema.bsonType === 'object') {
          expect(schema.additionalProperties).toBe(false);
          expect(schema.required).toBeDefined();
          for (const required of schema.required ?? []) {
            expect(schema.properties).toHaveProperty(required);
          }
        }
      });
    }
    expect(numericCount).toBeGreaterThan(0);
    expect(arrayCount).toBeGreaterThan(0);

    expect(property(collectionSchema('api_rate_limits'), 'count')).toEqual({
      bsonType: ['int', 'long', 'double'],
      multipleOf: 1,
      minimum: 1,
      maximum: Number.MAX_SAFE_INTEGER,
    });
    const device = property(collectionSchema('api_devices'), 'record');
    expect(property(device, 'schemaVersion').enum).toEqual([1]);
    expect(property(device, 'tokenVersion').enum).toEqual([1]);
  });

  it('uses exact state branches for invites, enrollments, and claims', () => {
    const inviteCommon = [
      '_id',
      'tokenHash',
      'vaultId',
      'issuedByDeviceId',
      'scopes',
      'state',
      'createdAt',
      'expiresAt',
    ] as const;
    expectExactBranch(collectionSchema('api_invites'), 'state', 'active', inviteCommon);
    expectExactBranch(collectionSchema('api_invites'), 'state', 'redeemed', [
      ...inviteCommon,
      'consumedAt',
      'enrollmentTokenHash',
      'enrollmentExpiresAt',
    ]);
    expectExactBranch(collectionSchema('api_invites'), 'state', 'revoked', [
      ...inviteCommon,
      'revokedAt',
    ]);

    const enrollmentCommon = [
      '_id',
      'vaultId',
      'scopes',
      'state',
      'createdAt',
      'expiresAt',
    ] as const;
    expectExactBranch(
      collectionSchema('api_enrollments'),
      'state',
      'active',
      enrollmentCommon,
    );
    expectExactBranch(collectionSchema('api_enrollments'), 'state', 'completed', [
      ...enrollmentCommon,
      'completionHash',
      'sessionTokenHash',
      'deviceId',
      'completedAt',
    ]);

    const claims = collectionSchema('api_credential_claims');
    expectExactBranch(claims, 'kind', 'invite', ['_id', 'kind', 'createdAt']);
    expectExactBranch(claims, 'kind', 'enrollment', [
      '_id',
      'kind',
      'parentHash',
      'createdAt',
    ]);
    const sessionBranches = claims.oneOf?.filter((candidate) =>
      candidate.properties?.['kind']?.enum?.includes('session'),
    );
    expect(sessionBranches).toHaveLength(2);
    expect(
      sessionBranches?.map((candidate) =>
        Object.keys(candidate.properties ?? {}).sort(),
      ),
    ).toEqual([
      ['_id', 'createdAt', 'kind', 'parentHash'].sort(),
      ['_id', 'bootstrapHash', 'createdAt', 'kind'].sort(),
    ]);
  });

  it('rejects every partial redemption field on a revoked canonical invite', () => {
    const active = inviteGrantDocument({
      id: inviteIdSchema.parse('invite.revoked-parity'),
      tokenHash: hash(20),
      vaultId,
      scopes: ['sync:read'],
      issuedByDeviceId: deviceId,
      createdAt,
      expiresAt,
    });
    expect(
      mongoApiInviteDocumentSchema.safeParse({
        ...active,
        state: 'revoked',
        revokedAt: createdAt,
      }).success,
    ).toBe(true);
    const redemptionFields = {
      consumedAt: createdAt,
      enrollmentTokenHash: hash(21),
      enrollmentExpiresAt: expiresAt,
    };
    for (const keys of [
      ['consumedAt'],
      ['enrollmentTokenHash'],
      ['enrollmentExpiresAt'],
      ['consumedAt', 'enrollmentTokenHash'],
      ['consumedAt', 'enrollmentExpiresAt'],
      ['enrollmentTokenHash', 'enrollmentExpiresAt'],
    ] as const) {
      const partial = Object.fromEntries(
        keys.map((key) => [key, redemptionFields[key]]),
      );
      expect(
        mongoApiInviteDocumentSchema.safeParse({
          ...active,
          state: 'revoked',
          revokedAt: createdAt,
          ...partial,
        }).success,
      ).toBe(false);
    }
  });

  it('rejects every partial completion field set on an active enrollment', () => {
    const active = {
      _id: hash(30),
      vaultId,
      scopes: ['sync:read'],
      state: 'active',
      createdAt,
      expiresAt,
    } as const;
    expect(mongoApiEnrollmentDocumentSchema.safeParse(active).success).toBe(true);

    const completionFields = {
      completionHash: hash(31),
      sessionTokenHash: hash(32),
      deviceId,
      completedAt: createdAt,
    } as const;
    const entries = Object.entries(completionFields);
    for (let mask = 1; mask < 2 ** entries.length - 1; mask += 1) {
      const partial = Object.fromEntries(
        entries.filter((_, index) => (mask & (1 << index)) !== 0),
      );
      expect(
        mongoApiEnrollmentDocumentSchema.safeParse({ ...active, ...partial }).success,
      ).toBe(false);
    }
  });

  it('projects invite state without exposing token hashes', () => {
    const active = inviteGrantDocument({
      id: inviteIdSchema.parse('invite.mongo-test'),
      tokenHash: hash(1),
      vaultId,
      scopes: ['sync:read'],
      issuedByDeviceId: deviceId,
      createdAt,
      expiresAt,
    });
    const publicActive = publicInviteFromDocument(
      active,
      new Date('2026-08-10T00:01:00.000Z'),
    );
    expect(publicActive.state).toBe('active');
    expect(JSON.stringify(publicActive)).not.toContain(active.tokenHash);
    expect(
      publicInviteFromDocument(active, new Date('2026-08-10T00:11:00.000Z')).state,
    ).toBe('expired');

    const redeemed = mongoApiInviteDocumentSchema.parse({
      ...active,
      state: 'redeemed',
      consumedAt: createdAt,
      enrollmentTokenHash: hash(2),
      enrollmentExpiresAt: expiresAt,
    });
    expect(
      publicInviteFromDocument(redeemed, new Date('2026-08-10T00:01:00.000Z')),
    ).toMatchObject({ state: 'redeemed', consumedAt: createdAt });
  });

  it('adds exact v2 pagination indexes without replacing legacy indexes', () => {
    expect(mongoApiIndexes.api_invites).toEqual([
      { key: { tokenHash: 1 }, name: 'invite_token_hash', unique: true },
      { key: { vaultId: 1, createdAt: -1 }, name: 'invites_by_vault' },
      {
        key: { vaultId: 1, createdAt: -1, _id: 1 },
        name: 'invites_by_vault_created_id_v2',
      },
    ]);
    expect(mongoApiIndexes.api_devices).toEqual([
      { key: { vaultId: 1, _id: 1 }, name: 'devices_by_vault' },
      { key: { 'record.tokenHash': 1 }, name: 'device_token_hash', unique: true },
      {
        key: { vaultId: 1, 'record.createdAt': 1, _id: 1 },
        name: 'devices_by_vault_created_id_v2',
      },
    ]);
  });

  it.each([0, 1, 200, 201])(
    'bounds Mongo invite pages with %i available rows and cursors from the final returned row',
    async (rowCount) => {
      const lookaheadCreatedAt = timestampSchema.parse('2026-08-09T23:59:59.000Z');
      const rows = Array.from({ length: rowCount }, (_value, index) =>
        inviteDocument(
          `invite-page-${String(index).padStart(3, '0')}`,
          index,
          index === 200 ? lookaheadCreatedAt : createdAt,
        ),
      );
      const fixture = paginationDatabase(mongoApiCollectionNames.invites, rows);
      const authorization = new MongoAuthorizationPort(
        {} as MongoClient,
        fixture.database,
      );

      const page = await authorization.listInvitePage(
        vaultId,
        { limit: 200 },
        new Date(createdAt),
      );

      expect(page.invites).toHaveLength(Math.min(rowCount, 200));
      expect(page.nextCursor === null).toBe(rowCount <= 200);
      expect(fixture.queries).toEqual([
        {
          filter: { vaultId },
          sort: { createdAt: -1, _id: 1 },
          hint: 'invites_by_vault_created_id_v2',
          limit: 201,
        },
      ]);
      if (page.nextCursor !== null) {
        expect(decodeControlListCursor(page.nextCursor)).toEqual({
          version: 1,
          resource: 'invites',
          vaultId,
          createdAt,
          id: 'invite-page-199',
        });
      }
      expect(JSON.stringify(page)).not.toContain('tokenHash');
    },
  );

  it('uses the exact vault-bound invite continuation predicate and validates lookahead', async () => {
    const cursorCreatedAt = timestampSchema.parse('2026-08-09T23:59:59.000Z');
    const cursor = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId,
      createdAt: cursorCreatedAt,
      id: inviteIdSchema.parse('invite-cursor'),
    });
    const valid = inviteDocument('invite-after-cursor', 1, cursorCreatedAt);
    const invalidLookahead = {
      ...inviteDocument('invite-invalid-lookahead', 2),
      _id: '*',
    };
    const fixture = paginationDatabase(mongoApiCollectionNames.invites, [
      valid,
      invalidLookahead,
    ]);
    const authorization = new MongoAuthorizationPort(
      {} as MongoClient,
      fixture.database,
    );

    await expect(
      authorization.listInvitePage(vaultId, { limit: 1, cursor }, new Date(createdAt)),
    ).rejects.toThrow();
    expect(fixture.queries).toEqual([
      {
        filter: {
          vaultId,
          $or: [
            { createdAt: { $lt: cursorCreatedAt } },
            { createdAt: cursorCreatedAt, _id: { $gt: 'invite-cursor' } },
          ],
        },
        sort: { createdAt: -1, _id: 1 },
        hint: 'invites_by_vault_created_id_v2',
        limit: 2,
      },
    ]);
  });

  it('uses the exact vault-bound device continuation predicate and validates lookahead', async () => {
    const cursorCreatedAt = timestampSchema.parse('2026-08-10T00:00:01.000Z');
    const cursor = encodeControlListCursor({
      version: 1,
      resource: 'devices',
      vaultId,
      createdAt: cursorCreatedAt,
      id: deviceIdSchema.parse('device-cursor'),
    });
    const valid = apiDeviceDocument('device-after-cursor', 1, cursorCreatedAt);
    const invalidLookahead = {
      ...apiDeviceDocument('device-invalid-lookahead', 2),
      record: {
        ...apiDeviceDocument('device-invalid-lookahead', 2).record,
        tokenHash: '*',
      },
    };
    const fixture = paginationDatabase(mongoApiCollectionNames.devices, [
      valid,
      invalidLookahead,
    ]);
    const authorization = new MongoAuthorizationPort(
      {} as MongoClient,
      fixture.database,
    );

    await expect(
      authorization.listDevicePage(vaultId, { limit: 1, cursor }),
    ).rejects.toThrow();
    expect(fixture.queries).toEqual([
      {
        filter: {
          vaultId,
          $or: [
            { 'record.createdAt': { $gt: cursorCreatedAt } },
            {
              'record.createdAt': cursorCreatedAt,
              _id: { $gt: 'device-cursor' },
            },
          ],
        },
        sort: { 'record.createdAt': 1, _id: 1 },
        hint: 'devices_by_vault_created_id_v2',
        limit: 2,
      },
    ]);
  });

  it.each([0, 1, 200])(
    'bounds Mongo device pages with %i available rows',
    async (rowCount) => {
      const rows = Array.from({ length: rowCount }, (_value, index) =>
        apiDeviceDocument(`device-page-${String(index).padStart(3, '0')}`, index),
      );
      const fixture = paginationDatabase(mongoApiCollectionNames.devices, rows);
      const authorization = new MongoAuthorizationPort(
        {} as MongoClient,
        fixture.database,
      );

      const page = await authorization.listDevicePage(vaultId, { limit: 200 });

      expect(page.devices).toHaveLength(rowCount);
      expect(page.nextCursor).toBeNull();
      expect(fixture.queries).toEqual([
        {
          filter: { vaultId },
          sort: { 'record.createdAt': 1, _id: 1 },
          hint: 'devices_by_vault_created_id_v2',
          limit: 201,
        },
      ]);
    },
  );

  it('bounds a 201-row Mongo device page and resumes to an exact terminal page', async () => {
    const lookaheadCreatedAt = timestampSchema.parse('2026-08-10T00:00:02.000Z');
    const rows = Array.from({ length: 201 }, (_value, index) =>
      apiDeviceDocument(
        `device-page-${String(index).padStart(3, '0')}`,
        index,
        index === 200 ? lookaheadCreatedAt : createdAt,
      ),
    );
    const fixture = paginationDatabase(mongoApiCollectionNames.devices, rows);
    const authorization = new MongoAuthorizationPort(
      {} as MongoClient,
      fixture.database,
    );

    const first = await authorization.listDevicePage(vaultId, { limit: 200 });
    expect(first.devices).toHaveLength(200);
    expect(fixture.queries[0]).toEqual({
      filter: { vaultId },
      sort: { 'record.createdAt': 1, _id: 1 },
      hint: 'devices_by_vault_created_id_v2',
      limit: 201,
    });
    if (first.nextCursor === null) throw new Error('Missing device page cursor');
    expect(decodeControlListCursor(first.nextCursor)).toEqual({
      version: 1,
      resource: 'devices',
      vaultId,
      createdAt,
      id: 'device-page-199',
    });

    const terminalFixture = paginationDatabase(mongoApiCollectionNames.devices, [
      rows[200],
    ]);
    const terminalAuthorization = new MongoAuthorizationPort(
      {} as MongoClient,
      terminalFixture.database,
    );
    await expect(
      terminalAuthorization.listDevicePage(vaultId, {
        limit: 200,
        cursor: first.nextCursor,
      }),
    ).resolves.toMatchObject({
      devices: [expect.objectContaining({ id: 'device-page-200' })],
      nextCursor: null,
    });
  });

  it('rejects invalid limits and resource/vault cursor swaps before Mongo access', async () => {
    const fixture = paginationDatabase(mongoApiCollectionNames.invites, []);
    const authorization = new MongoAuthorizationPort(
      {} as MongoClient,
      fixture.database,
    );
    const created = timestampSchema.parse(createdAt);
    const wrongResource = encodeControlListCursor({
      version: 1,
      resource: 'devices',
      vaultId,
      createdAt: created,
      id: deviceId,
    });
    const wrongVault = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId: otherVaultId,
      createdAt: created,
      id: inviteIdSchema.parse('invite-cursor'),
    });

    for (const options of [
      { limit: 0 },
      { limit: 201 },
      { limit: 1.5 },
      { limit: 1, cursor: 'malformed' },
      { limit: 1, cursor: wrongResource },
      { limit: 1, cursor: wrongVault },
    ]) {
      await expect(
        authorization.listInvitePage(vaultId, options as never, new Date(createdAt)),
      ).rejects.toThrow();
    }
    await expect(
      authorization.listInvitePage(
        'invalid vault' as never,
        { limit: 1 },
        new Date(createdAt),
      ),
    ).rejects.toThrow();
    expect(fixture.find).not.toHaveBeenCalled();

    const deviceFixture = paginationDatabase(mongoApiCollectionNames.devices, []);
    const deviceAuthorization = new MongoAuthorizationPort(
      {} as MongoClient,
      deviceFixture.database,
    );
    const inviteCursor = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId,
      createdAt: created,
      id: inviteIdSchema.parse('invite-device-swap'),
    });
    const otherVaultDeviceCursor = encodeControlListCursor({
      version: 1,
      resource: 'devices',
      vaultId: otherVaultId,
      createdAt: created,
      id: deviceIdSchema.parse('device-cursor'),
    });
    for (const options of [
      { limit: 0 },
      { limit: 201 },
      { limit: 1.5 },
      { limit: 1, cursor: 'malformed' },
      { limit: 1, cursor: inviteCursor },
      { limit: 1, cursor: otherVaultDeviceCursor },
    ]) {
      await expect(
        deviceAuthorization.listDevicePage(vaultId, options as never),
      ).rejects.toThrow();
    }
    await expect(
      deviceAuthorization.listDevicePage('invalid vault' as never, { limit: 1 }),
    ).rejects.toThrow();
    expect(deviceFixture.find).not.toHaveBeenCalled();

    const arbitraryDeviceCursor = encodeControlListCursor({
      version: 1,
      resource: 'devices',
      vaultId,
      createdAt: created,
      id: deviceIdSchema.parse('device-arbitrary-position'),
    });
    await expect(
      deviceAuthorization.listDevicePage(vaultId, {
        limit: 1,
        cursor: arbitraryDeviceCursor,
      }),
    ).resolves.toEqual({ devices: [], nextCursor: null });
  });

  it('strictly rejects plaintext-bearing and inconsistent documents', () => {
    const active = inviteGrantDocument({
      id: inviteIdSchema.parse('invite.strict-test'),
      tokenHash: hash(3),
      vaultId,
      scopes: ['sync:read'],
      issuedByDeviceId: deviceId,
      createdAt,
      expiresAt,
    });
    expect(
      mongoApiInviteDocumentSchema.safeParse({
        ...active,
        passphrase: 'plaintext-canary',
      }).success,
    ).toBe(false);
    expect(
      mongoApiCredentialClaimDocumentSchema.safeParse({
        _id: hash(4),
        kind: 'invite',
        parentHash: hash(3),
        createdAt,
      }).success,
    ).toBe(false);
    expect(mongoApiCollectionOptions.api_sessions.validator).toMatchObject({
      $jsonSchema: { additionalProperties: false },
    });
  });

  it('hashes rate keys into aligned fixed windows', () => {
    const first = fixedWindowIdentity({
      key: 'source:/route:192.0.2.1',
      limit: 5,
      windowSeconds: 60,
      now: new Date('2026-08-10T00:00:59.999Z'),
    });
    const next = fixedWindowIdentity({
      key: 'source:/route:192.0.2.1',
      limit: 5,
      windowSeconds: 60,
      now: new Date('2026-08-10T00:01:00.000Z'),
    });
    expect(first.id).not.toContain('192.0.2.1');
    expect(first.windowStartedAt.toISOString()).toBe('2026-08-10T00:00:00.000Z');
    expect(first.expiresAt.toISOString()).toBe('2026-08-10T00:01:00.000Z');
    expect(next.id).not.toBe(first.id);
    expect(() =>
      fixedWindowIdentity({
        key: 'invalid',
        limit: 0,
        windowSeconds: 60,
        now: new Date(createdAt),
      }),
    ).toThrow('Invalid rate-limit attempt');
  });

  it('canonically binds enrollment replay receipts to all input', () => {
    const base = {
      vaultId,
      deviceId,
      schemaVersion: schemaVersionSchema.parse(1),
      sessionTokenHash: hash(5),
    };
    expect(enrollmentCompletionHash(base)).toBe(enrollmentCompletionHash(base));
    expect(enrollmentCompletionHash({ ...base, sessionTokenHash: hash(6) })).not.toBe(
      enrollmentCompletionHash(base),
    );
  });

  it('validates server configuration and rejects TLS-secret fields', () => {
    expect(
      parseMongoApiServerConfig({
        mongodbUri: 'mongodb://127.0.0.1:27017',
        databaseName: 'kavrix_api',
        environment: 'production',
      }),
    ).toMatchObject({ host: '127.0.0.1', port: 3000 });
    expect(
      parseMongoApiServerConfig({
        mongodbUri: 'mongodb://127.0.0.1:27017',
        databaseName: 'kavrix_api',
        environment: 'production',
        vaultBootstrapEnabled: true,
      }),
    ).toMatchObject({ vaultBootstrapEnabled: true });
    expect(() =>
      parseMongoApiServerConfig({
        mongodbUri: 'mongodb://127.0.0.1:27017',
        databaseName: 'kavrix_api',
        environment: 'production',
        vaultBootstrapEnabled: 'true',
      }),
    ).toThrow();
    expect(() =>
      parseMongoApiServerConfig({
        mongodbUri: 'mongodb://127.0.0.1:27017',
        databaseName: 'kavrix_api',
        environment: 'production',
        tlsPrivateKey: 'must-not-be-owned',
      }),
    ).toThrow();
  });

  it('keeps API contract installation and compatibility scanning as explicit phases', async () => {
    const names = Object.values(mongoApiCollectionNames);
    const fixture = apiInitializationDatabase({
      existingCollections: names.filter((_name, index) => index % 2 === 0),
    });

    await installMongoApiContracts(fixture.database);
    expect(fixture.scanNames).toEqual([]);

    await assertMongoApiCompatibility(fixture.database);
    expect(fixture.scanNames).toEqual(Object.values(mongoApiCollectionNames));
    expect(fixture.installWasCompleteBeforeEveryScan()).toBe(true);
  });

  it.each([
    [
      'combined API initializer',
      (database: Db) => initializeMongoApiPersistence(database),
    ],
    [
      'authorization adapter initializer',
      (database: Db) =>
        new MongoAuthorizationPort({} as MongoClient, database).initialize(),
    ],
  ])(
    '%s installs every API contract before scanning every collection',
    async (_name, run) => {
      const fixture = apiInitializationDatabase();

      await run(fixture.database);

      expect(fixture.scanNames).toEqual(Object.values(mongoApiCollectionNames));
      expect(fixture.installWasCompleteBeforeEveryScan()).toBe(true);
      expect(fixture.closeCalls).toHaveLength(
        Object.values(mongoApiCollectionNames).length,
      );
      for (const close of fixture.closeCalls) expect(close).toHaveBeenCalledOnce();
    },
  );

  it('redacts token-hash document IDs from API compatibility failures', async () => {
    const sensitiveId = hash(40);
    const fixture = apiInitializationDatabase({
      invalidCollection: mongoApiCollectionNames.sessions,
      invalidDocument: { _id: sensitiveId },
    });

    const error = await assertMongoApiCompatibility(fixture.database).catch(
      (caught: unknown) => caught,
    );

    expect(error).toBeInstanceOf(MongoDocumentCompatibilityError);
    expect(error).toMatchObject({
      collectionName: mongoApiCollectionNames.sessions,
      documentId: MONGO_DOCUMENT_ID_UNAVAILABLE,
    });
    expect(error instanceof Error ? error.message : String(error)).not.toContain(
      sensitiveId,
    );
  });
});

function apiInitializationDatabase(
  options: Readonly<{
    invalidCollection?: string;
    invalidDocument?: unknown;
    existingCollections?: readonly string[];
  }> = {},
): {
  readonly database: Db;
  readonly scanNames: readonly string[];
  readonly closeCalls: readonly ReturnType<typeof vi.fn>[];
  installWasCompleteBeforeEveryScan(): boolean;
} {
  const expectedNames = Object.values(mongoApiCollectionNames);
  const namesRequiringIndexes = expectedNames.filter(
    (name) => mongoApiIndexes[name].length > 0,
  );
  const installed = new Set<string>();
  const indexed = new Set<string>();
  const scanNames: string[] = [];
  const closeCalls: ReturnType<typeof vi.fn>[] = [];
  let installWasComplete = true;
  const database = {
    listCollections: () => ({
      toArray: () =>
        Promise.resolve((options.existingCollections ?? []).map((name) => ({ name }))),
    }),
    command: (command: Readonly<{ collMod: string }>) => {
      installed.add(command.collMod);
      return Promise.resolve({});
    },
    createCollection: (name: string) => {
      installed.add(name);
      return Promise.resolve({});
    },
    collection: (name: string) => ({
      createIndexes: () => {
        indexed.add(name);
        return Promise.resolve([]);
      },
      find: () => {
        scanNames.push(name);
        if (
          expectedNames.some((expected) => !installed.has(expected)) ||
          namesRequiringIndexes.some((expected) => !indexed.has(expected))
        ) {
          installWasComplete = false;
        }
        const rows =
          name === options.invalidCollection ? [options.invalidDocument] : [];
        let index = 0;
        const close = vi.fn(() => Promise.resolve());
        closeCalls.push(close);
        return {
          hasNext: () => Promise.resolve(index < rows.length),
          next: () => Promise.resolve(rows[index++] ?? null),
          close,
          toArray: vi.fn(() =>
            Promise.reject(new Error('api-preflight-toArray-canary')),
          ),
        };
      },
    }),
  };
  return {
    database: database as unknown as Db,
    scanNames,
    closeCalls,
    installWasCompleteBeforeEveryScan: () => installWasComplete,
  };
}

function inviteDocument(
  id: string,
  hashFill: number,
  documentCreatedAt: ReturnType<typeof timestampSchema.parse> = createdAt,
): ReturnType<typeof inviteGrantDocument> {
  return inviteGrantDocument({
    id: inviteIdSchema.parse(id),
    tokenHash: hash(hashFill % 256),
    vaultId,
    scopes: ['sync:read'],
    issuedByDeviceId: deviceId,
    createdAt: documentCreatedAt,
    expiresAt,
  });
}

function apiDeviceDocument(
  id: string,
  hashFill: number,
  documentCreatedAt: ReturnType<typeof timestampSchema.parse> = createdAt,
): ReturnType<typeof deviceDocument> {
  const parsedId = deviceIdSchema.parse(id);
  return deviceDocument(
    deviceRecordSchema.parse({
      id: parsedId,
      vaultId,
      schemaVersion: 1,
      tokenHash: hash(hashFill % 256),
      tokenVersion: 1,
      scopes: ['sync:read'],
      createdAt: documentCreatedAt,
    }),
  );
}

function paginationDatabase(
  collectionName: string,
  rows: readonly unknown[],
): {
  readonly database: Db;
  readonly find: ReturnType<typeof vi.fn>;
  readonly queries: readonly Readonly<{
    filter: unknown;
    sort?: unknown;
    hint?: unknown;
    limit?: number;
  }>[];
} {
  const queries: {
    filter: unknown;
    sort?: unknown;
    hint?: unknown;
    limit?: number;
  }[] = [];
  const find = vi.fn((filter: unknown) => {
    const query: {
      filter: unknown;
      sort?: unknown;
      hint?: unknown;
      limit?: number;
    } = { filter };
    queries.push(query);
    const cursor = {
      sort: (sort: unknown) => {
        query.sort = sort;
        return cursor;
      },
      hint: (hint: unknown) => {
        query.hint = hint;
        return cursor;
      },
      limit: (limit: number) => {
        query.limit = limit;
        return cursor;
      },
      toArray: () => Promise.resolve(rows.slice(0, query.limit)),
    };
    return cursor;
  });
  return {
    database: {
      collection: (name: string) => {
        if (name !== collectionName) {
          throw new Error(`Unexpected pagination collection ${name}`);
        }
        return { find };
      },
    } as unknown as Db,
    find,
    queries,
  };
}
