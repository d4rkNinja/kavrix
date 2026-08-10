import { createHash } from 'node:crypto';

import {
  apiSessionResponseSchema,
  deviceRecordSchema,
  enrollmentCompleteRequestSchema,
  inviteIdSchema,
  publicInviteRecordSchema,
  sha256DigestSchema,
  timestampSchema,
  vaultBootstrapRequestSchema,
  vaultIdSchema,
  type DeviceRecord,
  type PublicInviteRecord,
  type Sha256Digest,
} from '@kavrix/schemas';
import type { CreateCollectionOptions, Document, IndexDescription } from 'mongodb';
import { z } from 'zod';

import type { EnrollmentCompletion, InviteGrant } from './ports.js';

const apiScopesSchema = apiSessionResponseSchema.shape.scopes;

export const mongoApiSessionDocumentSchema = z
  .object({
    _id: sha256DigestSchema,
    vaultId: vaultIdSchema,
    deviceId: deviceRecordSchema.shape.id,
    scopes: apiScopesSchema,
    createdAt: timestampSchema,
    revokedAt: timestampSchema.optional(),
  })
  .strict();

export const mongoApiDeviceDocumentSchema = z
  .object({
    _id: deviceRecordSchema.shape.id,
    vaultId: vaultIdSchema,
    record: deviceRecordSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !== document.record.id ||
      document.vaultId !== document.record.vaultId
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Device document identity is inconsistent',
      });
    }
  });

export const mongoApiInviteDocumentSchema = z
  .object({
    _id: inviteIdSchema,
    tokenHash: sha256DigestSchema,
    vaultId: vaultIdSchema,
    issuedByDeviceId: deviceRecordSchema.shape.id,
    scopes: apiScopesSchema,
    state: z.enum(['active', 'redeemed', 'revoked']),
    createdAt: timestampSchema,
    expiresAt: timestampSchema,
    consumedAt: timestampSchema.optional(),
    revokedAt: timestampSchema.optional(),
    enrollmentTokenHash: sha256DigestSchema.optional(),
    enrollmentExpiresAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((invite, context) => {
    const hasRedemption =
      invite.consumedAt !== undefined &&
      invite.enrollmentTokenHash !== undefined &&
      invite.enrollmentExpiresAt !== undefined;
    if ((invite.state === 'redeemed') !== hasRedemption) {
      context.addIssue({ code: 'custom', message: 'Invalid invite redemption state' });
    }
    if ((invite.state === 'revoked') !== (invite.revokedAt !== undefined)) {
      context.addIssue({ code: 'custom', message: 'Invalid invite revocation state' });
    }
    if (
      invite.state === 'active' &&
      (invite.consumedAt !== undefined ||
        invite.revokedAt !== undefined ||
        invite.enrollmentTokenHash !== undefined ||
        invite.enrollmentExpiresAt !== undefined)
    ) {
      context.addIssue({ code: 'custom', message: 'Active invites are unconsumed' });
    }
  });

export const mongoApiEnrollmentDocumentSchema = z
  .object({
    _id: sha256DigestSchema,
    vaultId: vaultIdSchema,
    scopes: apiScopesSchema,
    state: z.enum(['active', 'completed']),
    createdAt: timestampSchema,
    expiresAt: timestampSchema,
    completionHash: sha256DigestSchema.optional(),
    sessionTokenHash: sha256DigestSchema.optional(),
    deviceId: deviceRecordSchema.shape.id.optional(),
    completedAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((enrollment, context) => {
    const completed =
      enrollment.completionHash !== undefined &&
      enrollment.sessionTokenHash !== undefined &&
      enrollment.deviceId !== undefined &&
      enrollment.completedAt !== undefined;
    if ((enrollment.state === 'completed') !== completed) {
      context.addIssue({ code: 'custom', message: 'Invalid enrollment state' });
    }
  });

export const mongoApiRateLimitDocumentSchema = z
  .object({
    _id: z.string().regex(/^[a-f0-9]{64}:[0-9]+$/u),
    count: z.number().int().positive(),
    windowStartedAt: z.date(),
    expiresAt: z.date(),
  })
  .strict();

export const mongoApiCredentialClaimDocumentSchema = z
  .object({
    _id: sha256DigestSchema,
    kind: z.enum(['invite', 'enrollment', 'session']),
    parentHash: sha256DigestSchema.optional(),
    bootstrapHash: sha256DigestSchema.optional(),
    createdAt: timestampSchema,
  })
  .strict()
  .superRefine((claim, context) => {
    const valid =
      (claim.kind === 'invite' &&
        claim.parentHash === undefined &&
        claim.bootstrapHash === undefined) ||
      (claim.kind === 'enrollment' &&
        claim.parentHash !== undefined &&
        claim.bootstrapHash === undefined) ||
      (claim.kind === 'session' &&
        (claim.parentHash === undefined) !== (claim.bootstrapHash === undefined));
    if (!valid) {
      context.addIssue({ code: 'custom', message: 'Invalid credential claim' });
    }
  });

export type MongoApiSessionDocument = z.infer<typeof mongoApiSessionDocumentSchema>;
export type MongoApiDeviceDocument = z.infer<typeof mongoApiDeviceDocumentSchema>;
export type MongoApiInviteDocument = z.infer<typeof mongoApiInviteDocumentSchema>;
export type MongoApiEnrollmentDocument = z.infer<
  typeof mongoApiEnrollmentDocumentSchema
>;
export type MongoApiRateLimitDocument = z.infer<typeof mongoApiRateLimitDocumentSchema>;
export type MongoApiCredentialClaimDocument = z.infer<
  typeof mongoApiCredentialClaimDocumentSchema
>;

export const mongoApiCollectionNames = {
  sessions: 'api_sessions',
  devices: 'api_devices',
  invites: 'api_invites',
  enrollments: 'api_enrollments',
  rateLimits: 'api_rate_limits',
  credentialClaims: 'api_credential_claims',
} as const;

export type MongoApiCollectionName =
  (typeof mongoApiCollectionNames)[keyof typeof mongoApiCollectionNames];

const identifier = {
  bsonType: 'string',
  minLength: 1,
  maxLength: 128,
  pattern: '^[A-Za-z0-9][A-Za-z0-9._~-]*$',
};
const digest = {
  bsonType: 'string',
  minLength: 43,
  maxLength: 43,
  pattern: '^[A-Za-z0-9_-]{43}$',
};
const timestamp = {
  bsonType: 'string',
  pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?Z$',
};
const scopes = {
  bsonType: 'array',
  minItems: 1,
  maxItems: 3,
  uniqueItems: true,
  items: { enum: ['sync:read', 'sync:write', 'device:manage'] },
};
const numberType = ['int', 'long', 'double'];

const aad = strictObject(
  [
    'version',
    'schemaVersion',
    'keyVersion',
    'vaultId',
    'entityType',
    'entityId',
    'purpose',
  ],
  {
    version: { bsonType: numberType, enum: [1] },
    schemaVersion: { bsonType: numberType, minimum: 1 },
    keyVersion: { bsonType: numberType, minimum: 1 },
    vaultId: identifier,
    groupId: identifier,
    parentId: identifier,
    entityType: { bsonType: 'string' },
    entityId: identifier,
    purpose: { bsonType: 'string' },
  },
);

const envelope = strictObject(
  [
    'version',
    'algorithm',
    'nonce',
    'ciphertext',
    'authenticationTag',
    'aad',
    'keyVersion',
  ],
  {
    version: { bsonType: numberType, enum: [1] },
    algorithm: { enum: ['xchacha20-poly1305-ietf'] },
    nonce: { bsonType: 'string' },
    ciphertext: { bsonType: 'string' },
    authenticationTag: { bsonType: 'string' },
    aad,
    keyVersion: { bsonType: numberType, minimum: 1 },
  },
);

const deviceRecord = strictObject(
  [
    'id',
    'vaultId',
    'schemaVersion',
    'tokenHash',
    'tokenVersion',
    'scopes',
    'createdAt',
  ],
  {
    id: identifier,
    vaultId: identifier,
    schemaVersion: { bsonType: numberType, minimum: 1 },
    tokenHash: digest,
    tokenVersion: { bsonType: numberType, minimum: 1 },
    encryptedLabel: envelope,
    scopes,
    createdAt: timestamp,
    lastSeenAt: timestamp,
    revokedAt: timestamp,
  },
);

export const mongoApiCollectionOptions: Readonly<
  Record<MongoApiCollectionName, CreateCollectionOptions>
> = {
  api_sessions: validator(
    strictObject(['_id', 'vaultId', 'deviceId', 'scopes', 'createdAt'], {
      _id: digest,
      vaultId: identifier,
      deviceId: identifier,
      scopes,
      createdAt: timestamp,
      revokedAt: timestamp,
    }),
  ),
  api_devices: validator(
    strictObject(['_id', 'vaultId', 'record'], {
      _id: identifier,
      vaultId: identifier,
      record: deviceRecord,
    }),
  ),
  api_invites: validator(
    strictObject(
      [
        '_id',
        'tokenHash',
        'vaultId',
        'issuedByDeviceId',
        'scopes',
        'state',
        'createdAt',
        'expiresAt',
      ],
      {
        _id: identifier,
        tokenHash: digest,
        vaultId: identifier,
        issuedByDeviceId: identifier,
        scopes,
        state: { enum: ['active', 'redeemed', 'revoked'] },
        createdAt: timestamp,
        expiresAt: timestamp,
        consumedAt: timestamp,
        revokedAt: timestamp,
        enrollmentTokenHash: digest,
        enrollmentExpiresAt: timestamp,
      },
    ),
  ),
  api_enrollments: validator(
    strictObject(['_id', 'vaultId', 'scopes', 'state', 'createdAt', 'expiresAt'], {
      _id: digest,
      vaultId: identifier,
      scopes,
      state: { enum: ['active', 'completed'] },
      createdAt: timestamp,
      expiresAt: timestamp,
      completionHash: digest,
      sessionTokenHash: digest,
      deviceId: identifier,
      completedAt: timestamp,
    }),
  ),
  api_rate_limits: validator(
    strictObject(['_id', 'count', 'windowStartedAt', 'expiresAt'], {
      _id: { bsonType: 'string', pattern: '^[a-f0-9]{64}:[0-9]+$' },
      count: { bsonType: numberType, minimum: 1 },
      windowStartedAt: { bsonType: 'date' },
      expiresAt: { bsonType: 'date' },
    }),
  ),
  api_credential_claims: validator(
    strictObject(['_id', 'kind', 'createdAt'], {
      _id: digest,
      kind: { enum: ['invite', 'enrollment', 'session'] },
      parentHash: digest,
      bootstrapHash: digest,
      createdAt: timestamp,
    }),
  ),
};

export const mongoApiIndexes: Readonly<
  Record<MongoApiCollectionName, readonly IndexDescription[]>
> = {
  api_sessions: [{ key: { vaultId: 1, deviceId: 1 }, name: 'sessions_by_device' }],
  api_devices: [
    { key: { vaultId: 1, _id: 1 }, name: 'devices_by_vault' },
    { key: { 'record.tokenHash': 1 }, name: 'device_token_hash', unique: true },
  ],
  api_invites: [
    { key: { tokenHash: 1 }, name: 'invite_token_hash', unique: true },
    { key: { vaultId: 1, createdAt: -1 }, name: 'invites_by_vault' },
  ],
  api_enrollments: [],
  api_rate_limits: [
    { key: { expiresAt: 1 }, name: 'rate_limit_expiry', expireAfterSeconds: 0 },
  ],
  api_credential_claims: [],
};

export function inviteGrantDocument(grant: InviteGrant): MongoApiInviteDocument {
  const publicGrant = publicInviteRecordSchema.parse({
    id: grant.id,
    vaultId: grant.vaultId,
    issuedByDeviceId: grant.issuedByDeviceId,
    scopes: grant.scopes,
    state: 'active',
    createdAt: grant.createdAt,
    expiresAt: grant.expiresAt,
  });
  const tokenHash = sha256DigestSchema.parse(grant.tokenHash);
  return mongoApiInviteDocumentSchema.parse({
    _id: publicGrant.id,
    tokenHash,
    vaultId: publicGrant.vaultId,
    issuedByDeviceId: publicGrant.issuedByDeviceId,
    scopes: publicGrant.scopes,
    state: 'active',
    createdAt: publicGrant.createdAt,
    expiresAt: publicGrant.expiresAt,
  });
}

export function publicInviteFromDocument(
  input: MongoApiInviteDocument,
  now: Date,
): PublicInviteRecord {
  const invite = mongoApiInviteDocumentSchema.parse(input);
  const state =
    invite.state === 'revoked'
      ? 'revoked'
      : invite.state === 'redeemed'
        ? 'redeemed'
        : Date.parse(invite.expiresAt) <= now.getTime()
          ? 'expired'
          : 'active';
  return publicInviteRecordSchema.parse({
    id: invite._id,
    vaultId: invite.vaultId,
    issuedByDeviceId: invite.issuedByDeviceId,
    scopes: invite.scopes,
    state,
    createdAt: invite.createdAt,
    expiresAt: invite.expiresAt,
    ...(invite.consumedAt === undefined ? {} : { consumedAt: invite.consumedAt }),
    ...(invite.revokedAt === undefined ? {} : { revokedAt: invite.revokedAt }),
  });
}

export function parseEnrollmentCompletion(
  input: EnrollmentCompletion,
): EnrollmentCompletion {
  const request = enrollmentCompleteRequestSchema.parse({
    vaultId: input.vaultId,
    deviceId: input.deviceId,
    schemaVersion: input.schemaVersion,
    ...(input.encryptedLabel === undefined
      ? {}
      : { encryptedLabel: input.encryptedLabel }),
  });
  return {
    vaultId: request.vaultId,
    deviceId: request.deviceId,
    schemaVersion: request.schemaVersion,
    ...(request.encryptedLabel === undefined
      ? {}
      : { encryptedLabel: request.encryptedLabel }),
    sessionTokenHash: sha256DigestSchema.parse(input.sessionTokenHash),
  };
}

export function enrollmentCompletionHash(input: EnrollmentCompletion): Sha256Digest {
  const parsed = parseEnrollmentCompletion(input);
  return sha256DigestSchema.parse(
    createHash('sha256').update(JSON.stringify(parsed), 'utf8').digest('base64url'),
  );
}

export function vaultBootstrapHash(input: unknown): Sha256Digest {
  const request = vaultBootstrapRequestSchema.parse(input);
  return sha256DigestSchema.parse(
    createHash('sha256').update(JSON.stringify(request), 'utf8').digest('base64url'),
  );
}

export function deviceDocument(record: DeviceRecord): MongoApiDeviceDocument {
  const parsed = deviceRecordSchema.parse(record);
  return mongoApiDeviceDocumentSchema.parse({
    _id: parsed.id,
    vaultId: parsed.vaultId,
    record: parsed,
  });
}

function validator(schema: Document): CreateCollectionOptions {
  return {
    validator: { $jsonSchema: schema },
    validationLevel: 'strict',
    validationAction: 'error',
  };
}

function strictObject(
  required: readonly string[],
  properties: Readonly<Record<string, unknown>>,
): Document {
  return {
    bsonType: 'object',
    additionalProperties: false,
    required: [...required],
    properties,
  };
}
