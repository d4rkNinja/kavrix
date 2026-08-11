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
import {
  apiScopesFragment,
  canonicalTimestampFragment,
  encryptedDeviceLabelFragment,
  opaqueIdentifierFragment,
  safeInteger,
  sha256DigestFragment,
  strictObject,
  supportedSchemaVersionFragment,
  supportedTokenVersionFragment,
  type MongoDocumentSchemaMap,
  type MongoJsonSchema,
} from '@kavrix/storage';
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
    const hasAnyRedemption =
      invite.consumedAt !== undefined ||
      invite.enrollmentTokenHash !== undefined ||
      invite.enrollmentExpiresAt !== undefined;
    const hasRedemption =
      invite.consumedAt !== undefined &&
      invite.enrollmentTokenHash !== undefined &&
      invite.enrollmentExpiresAt !== undefined;
    if (
      (invite.state === 'redeemed') !== hasRedemption ||
      (invite.state !== 'redeemed' && hasAnyRedemption)
    ) {
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
    const hasAnyCompletion =
      enrollment.completionHash !== undefined ||
      enrollment.sessionTokenHash !== undefined ||
      enrollment.deviceId !== undefined ||
      enrollment.completedAt !== undefined;
    const completed =
      enrollment.completionHash !== undefined &&
      enrollment.sessionTokenHash !== undefined &&
      enrollment.deviceId !== undefined &&
      enrollment.completedAt !== undefined;
    if (
      (enrollment.state === 'completed') !== completed ||
      (enrollment.state === 'active' && hasAnyCompletion)
    ) {
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

export const mongoApiDocumentSchemas: MongoDocumentSchemaMap<MongoApiCollectionName> = {
  [mongoApiCollectionNames.sessions]: mongoApiSessionDocumentSchema,
  [mongoApiCollectionNames.devices]: mongoApiDeviceDocumentSchema,
  [mongoApiCollectionNames.invites]: mongoApiInviteDocumentSchema,
  [mongoApiCollectionNames.enrollments]: mongoApiEnrollmentDocumentSchema,
  [mongoApiCollectionNames.rateLimits]: mongoApiRateLimitDocumentSchema,
  [mongoApiCollectionNames.credentialClaims]: mongoApiCredentialClaimDocumentSchema,
};

function stringEnum(values: readonly string[]): MongoJsonSchema {
  return { bsonType: 'string', enum: values };
}

const deviceRecordFragment = strictObject(
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
    id: opaqueIdentifierFragment,
    vaultId: opaqueIdentifierFragment,
    schemaVersion: supportedSchemaVersionFragment,
    tokenHash: sha256DigestFragment,
    tokenVersion: supportedTokenVersionFragment,
    encryptedLabel: encryptedDeviceLabelFragment,
    scopes: apiScopesFragment,
    createdAt: canonicalTimestampFragment,
    lastSeenAt: canonicalTimestampFragment,
    revokedAt: canonicalTimestampFragment,
  },
);

const inviteCommonProperties = {
  _id: opaqueIdentifierFragment,
  tokenHash: sha256DigestFragment,
  vaultId: opaqueIdentifierFragment,
  issuedByDeviceId: opaqueIdentifierFragment,
  scopes: apiScopesFragment,
  createdAt: canonicalTimestampFragment,
  expiresAt: canonicalTimestampFragment,
} satisfies Readonly<Record<string, MongoJsonSchema>>;
const inviteCommonRequired = [
  '_id',
  'tokenHash',
  'vaultId',
  'issuedByDeviceId',
  'scopes',
  'state',
  'createdAt',
  'expiresAt',
] as const;

const enrollmentCommonProperties = {
  _id: sha256DigestFragment,
  vaultId: opaqueIdentifierFragment,
  scopes: apiScopesFragment,
  createdAt: canonicalTimestampFragment,
  expiresAt: canonicalTimestampFragment,
} satisfies Readonly<Record<string, MongoJsonSchema>>;
const enrollmentCommonRequired = [
  '_id',
  'vaultId',
  'scopes',
  'state',
  'createdAt',
  'expiresAt',
] as const;

export const mongoApiCollectionOptions: Readonly<
  Record<MongoApiCollectionName, CreateCollectionOptions>
> = {
  api_sessions: validator(
    strictObject(['_id', 'vaultId', 'deviceId', 'scopes', 'createdAt'], {
      _id: sha256DigestFragment,
      vaultId: opaqueIdentifierFragment,
      deviceId: opaqueIdentifierFragment,
      scopes: apiScopesFragment,
      createdAt: canonicalTimestampFragment,
      revokedAt: canonicalTimestampFragment,
    }),
  ),
  api_devices: validator(
    strictObject(['_id', 'vaultId', 'record'], {
      _id: opaqueIdentifierFragment,
      vaultId: opaqueIdentifierFragment,
      record: deviceRecordFragment,
    }),
  ),
  api_invites: validator({
    oneOf: [
      strictObject(inviteCommonRequired, {
        ...inviteCommonProperties,
        state: stringEnum(['active']),
      }),
      strictObject(
        [
          ...inviteCommonRequired,
          'consumedAt',
          'enrollmentTokenHash',
          'enrollmentExpiresAt',
        ],
        {
          ...inviteCommonProperties,
          state: stringEnum(['redeemed']),
          consumedAt: canonicalTimestampFragment,
          enrollmentTokenHash: sha256DigestFragment,
          enrollmentExpiresAt: canonicalTimestampFragment,
        },
      ),
      strictObject([...inviteCommonRequired, 'revokedAt'], {
        ...inviteCommonProperties,
        state: stringEnum(['revoked']),
        revokedAt: canonicalTimestampFragment,
      }),
    ],
  }),
  api_enrollments: validator({
    oneOf: [
      strictObject(enrollmentCommonRequired, {
        ...enrollmentCommonProperties,
        state: stringEnum(['active']),
      }),
      strictObject(
        [
          ...enrollmentCommonRequired,
          'completionHash',
          'sessionTokenHash',
          'deviceId',
          'completedAt',
        ],
        {
          ...enrollmentCommonProperties,
          state: stringEnum(['completed']),
          completionHash: sha256DigestFragment,
          sessionTokenHash: sha256DigestFragment,
          deviceId: opaqueIdentifierFragment,
          completedAt: canonicalTimestampFragment,
        },
      ),
    ],
  }),
  api_rate_limits: validator(
    strictObject(['_id', 'count', 'windowStartedAt', 'expiresAt'], {
      _id: { bsonType: 'string', pattern: '^[a-f0-9]{64}:[0-9]+$' },
      count: safeInteger({ minimum: 1, maximum: Number.MAX_SAFE_INTEGER }),
      windowStartedAt: { bsonType: 'date' },
      expiresAt: { bsonType: 'date' },
    }),
  ),
  api_credential_claims: validator({
    oneOf: [
      strictObject(['_id', 'kind', 'createdAt'], {
        _id: sha256DigestFragment,
        kind: stringEnum(['invite']),
        createdAt: canonicalTimestampFragment,
      }),
      strictObject(['_id', 'kind', 'parentHash', 'createdAt'], {
        _id: sha256DigestFragment,
        kind: stringEnum(['enrollment']),
        parentHash: sha256DigestFragment,
        createdAt: canonicalTimestampFragment,
      }),
      strictObject(['_id', 'kind', 'parentHash', 'createdAt'], {
        _id: sha256DigestFragment,
        kind: stringEnum(['session']),
        parentHash: sha256DigestFragment,
        createdAt: canonicalTimestampFragment,
      }),
      strictObject(['_id', 'kind', 'bootstrapHash', 'createdAt'], {
        _id: sha256DigestFragment,
        kind: stringEnum(['session']),
        bootstrapHash: sha256DigestFragment,
        createdAt: canonicalTimestampFragment,
      }),
    ],
  }),
};

export const mongoApiIndexes: Readonly<
  Record<MongoApiCollectionName, readonly IndexDescription[]>
> = {
  api_sessions: [{ key: { vaultId: 1, deviceId: 1 }, name: 'sessions_by_device' }],
  api_devices: [
    { key: { vaultId: 1, _id: 1 }, name: 'devices_by_vault' },
    { key: { 'record.tokenHash': 1 }, name: 'device_token_hash', unique: true },
    {
      key: { vaultId: 1, 'record.createdAt': 1, _id: 1 },
      name: 'devices_by_vault_created_id_v2',
    },
  ],
  api_invites: [
    { key: { tokenHash: 1 }, name: 'invite_token_hash', unique: true },
    { key: { vaultId: 1, createdAt: -1 }, name: 'invites_by_vault' },
    {
      key: { vaultId: 1, createdAt: -1, _id: 1 },
      name: 'invites_by_vault_created_id_v2',
    },
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

function validator(schema: MongoJsonSchema): CreateCollectionOptions {
  return {
    validator: { $jsonSchema: schema as Document },
    validationLevel: 'strict',
    validationAction: 'error',
  };
}
