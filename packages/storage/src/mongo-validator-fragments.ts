import {
  AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS,
  AEAD_NONCE_BASE64URL_CHARS,
  API_SCOPE_VALUES,
  ARGON2ID_SALT_BASE64URL_CHARS,
  CANONICAL_BASE64URL_PATTERN_SOURCE,
  CANONICAL_TIMESTAMP_CHARS,
  CANONICAL_TIMESTAMP_PATTERN_SOURCE,
  HKDF_SALT_BASE64URL_CHARS,
  KEY_DERIVATION_OUTPUT_BYTES,
  MAX_API_SCOPES,
  MAX_ARGON2_MEMORY_KIB,
  MAX_ARGON2_PARALLELISM,
  MAX_ARGON2_PASSES,
  MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
  MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  MAX_ATTACHMENT_CHUNKS,
  MAX_CIPHERTEXT_CHARS,
  MAX_DEVICE_KEY_PROVIDER_CHARS,
  MAX_ENCRYPTED_DEVICE_LABEL_CIPHERTEXT_CHARS,
  MAX_OPAQUE_ID_CHARS,
  MAX_SEMANTIC_REVISION,
  MAX_SEMANTIC_VERSION,
  MIN_API_SCOPES,
  MIN_ARGON2_MEMORY_KIB,
  MIN_ARGON2_PARALLELISM,
  MIN_ARGON2_PASSES,
  MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
  MIN_OPAQUE_ID_CHARS,
  OPAQUE_ID_PATTERN_SOURCE,
  SECRETSTREAM_HEADER_BASE64URL_CHARS,
  SHA256_DIGEST_BASE64URL_CHARS,
  SUPPORTED_CRYPTOGRAPHIC_VERSIONS,
  SUPPORTED_SCHEMA_VERSIONS,
  SUPPORTED_TOKEN_VERSIONS,
} from '@kavrix/schemas';

export type MongoBsonType =
  'array' | 'bool' | 'date' | 'double' | 'int' | 'long' | 'null' | 'object' | 'string';

export type MongoJsonSchema = Readonly<{
  bsonType?: MongoBsonType | readonly MongoBsonType[];
  required?: readonly string[];
  additionalProperties?: false;
  properties?: Readonly<Record<string, MongoJsonSchema>>;
  oneOf?: readonly MongoJsonSchema[];
  enum?: readonly (string | number | boolean | null)[];
  items?: MongoJsonSchema;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: true;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  multipleOf?: number;
  minimum?: number;
  maximum?: number;
}>;

type SafeIntegerBounds = Readonly<{
  minimum: number;
  maximum: number;
}>;

export function strictObject(
  required: readonly string[],
  properties: Readonly<Record<string, MongoJsonSchema>>,
): MongoJsonSchema {
  return {
    bsonType: 'object',
    required,
    additionalProperties: false,
    properties,
  };
}

export function safeInteger({ minimum, maximum }: SafeIntegerBounds): MongoJsonSchema {
  if (
    !Number.isSafeInteger(minimum) ||
    !Number.isSafeInteger(maximum) ||
    minimum > maximum
  ) {
    throw new RangeError('Mongo safe-integer bounds must be ordered safe integers');
  }
  return {
    bsonType: ['int', 'long', 'double'],
    multipleOf: 1,
    minimum,
    maximum,
  };
}

function stringEnum(values: readonly string[]): MongoJsonSchema {
  return { bsonType: 'string', enum: values };
}

function literalInteger(value: number): MongoJsonSchema {
  return { ...safeInteger({ minimum: value, maximum: value }), enum: [value] };
}

function supportedVersion(values: readonly number[]): MongoJsonSchema {
  return {
    ...safeInteger({ minimum: 1, maximum: MAX_SEMANTIC_VERSION }),
    enum: values,
  };
}

function fixedCanonicalBase64Url(length: number): MongoJsonSchema {
  return {
    bsonType: 'string',
    minLength: length,
    maxLength: length,
    pattern: CANONICAL_BASE64URL_PATTERN_SOURCE,
  };
}

export const positiveSemanticVersionFragment = safeInteger({
  minimum: 1,
  maximum: MAX_SEMANTIC_VERSION,
});
export const nonnegativeSemanticRevisionFragment = safeInteger({
  minimum: 0,
  maximum: MAX_SEMANTIC_REVISION,
});
export const supportedSchemaVersionFragment = supportedVersion(
  SUPPORTED_SCHEMA_VERSIONS,
);
export const supportedCryptographicVersionFragment = supportedVersion(
  SUPPORTED_CRYPTOGRAPHIC_VERSIONS,
);
export const supportedTokenVersionFragment = supportedVersion(SUPPORTED_TOKEN_VERSIONS);
export const envelopeVersionFragment = literalInteger(1);
export const associatedDataVersionFragment = literalInteger(1);
export const keySlotVersionFragment = literalInteger(1);

export const opaqueIdentifierFragment: MongoJsonSchema = {
  bsonType: 'string',
  minLength: MIN_OPAQUE_ID_CHARS,
  maxLength: MAX_OPAQUE_ID_CHARS,
  pattern: OPAQUE_ID_PATTERN_SOURCE,
};

export const canonicalTimestampFragment: MongoJsonSchema = {
  bsonType: 'string',
  minLength: CANONICAL_TIMESTAMP_CHARS,
  maxLength: CANONICAL_TIMESTAMP_CHARS,
  pattern: CANONICAL_TIMESTAMP_PATTERN_SOURCE,
};

export const canonicalBase64UrlFragment: MongoJsonSchema = {
  bsonType: 'string',
  minLength: 1,
  maxLength: MAX_CIPHERTEXT_CHARS,
  pattern: CANONICAL_BASE64URL_PATTERN_SOURCE,
};
export const canonicalCiphertextFragment = canonicalBase64UrlFragment;
export const aeadNonceFragment = fixedCanonicalBase64Url(AEAD_NONCE_BASE64URL_CHARS);
export const aeadAuthenticationTagFragment = fixedCanonicalBase64Url(
  AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS,
);
export const secretStreamHeaderFragment = fixedCanonicalBase64Url(
  SECRETSTREAM_HEADER_BASE64URL_CHARS,
);
export const sha256DigestFragment = fixedCanonicalBase64Url(
  SHA256_DIGEST_BASE64URL_CHARS,
);
export const hkdfSaltFragment = fixedCanonicalBase64Url(HKDF_SALT_BASE64URL_CHARS);
export const argon2idSaltFragment = fixedCanonicalBase64Url(
  ARGON2ID_SALT_BASE64URL_CHARS,
);
export const attachmentChunkCiphertextFragment: MongoJsonSchema = {
  bsonType: 'string',
  minLength: MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
  maxLength: MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
  pattern: CANONICAL_BASE64URL_PATTERN_SOURCE,
};

export const apiScopesFragment: MongoJsonSchema = {
  bsonType: 'array',
  minItems: MIN_API_SCOPES,
  maxItems: MAX_API_SCOPES,
  uniqueItems: true,
  items: stringEnum(API_SCOPE_VALUES),
};

const associatedDataDescriptors = [
  {
    entityType: 'vault-preferences',
    purpose: 'vault-preferences',
    groupId: false,
    parentId: false,
  },
  { entityType: 'group', purpose: 'group-payload', groupId: false, parentId: false },
  { entityType: 'item', purpose: 'item-payload', groupId: true, parentId: false },
  {
    entityType: 'attachment',
    purpose: 'attachment-metadata',
    groupId: true,
    parentId: true,
  },
  {
    entityType: 'attachment-chunk',
    purpose: 'attachment-chunk',
    groupId: true,
    parentId: true,
  },
  {
    entityType: 'audit-event',
    purpose: 'audit-event',
    groupId: false,
    parentId: false,
  },
  { entityType: 'history', purpose: 'history-event', groupId: true, parentId: true },
  {
    entityType: 'device-label',
    purpose: 'device-label',
    groupId: false,
    parentId: false,
  },
  {
    entityType: 'wrapped-root-key',
    purpose: 'vrk-slot',
    groupId: false,
    parentId: false,
  },
  {
    entityType: 'wrapped-group-key',
    purpose: 'group-key',
    groupId: false,
    parentId: false,
  },
  {
    entityType: 'wrapped-item-key',
    purpose: 'item-key',
    groupId: true,
    parentId: false,
  },
  {
    entityType: 'wrapped-attachment-key',
    purpose: 'attachment-key',
    groupId: true,
    parentId: true,
  },
] as const;

type AssociatedDataDescriptor = (typeof associatedDataDescriptors)[number];

function createAssociatedDataBranch(
  descriptor: AssociatedDataDescriptor,
): MongoJsonSchema {
  const required = [
    'version',
    'schemaVersion',
    'keyVersion',
    'vaultId',
    'entityType',
    'entityId',
    'purpose',
  ];
  const properties: Record<string, MongoJsonSchema> = {
    version: associatedDataVersionFragment,
    schemaVersion: supportedSchemaVersionFragment,
    keyVersion: positiveSemanticVersionFragment,
    vaultId: opaqueIdentifierFragment,
    entityType: stringEnum([descriptor.entityType]),
    entityId: opaqueIdentifierFragment,
    purpose: stringEnum([descriptor.purpose]),
  };
  if (descriptor.groupId) {
    required.push('groupId');
    properties['groupId'] = opaqueIdentifierFragment;
  }
  if (descriptor.parentId) {
    required.push('parentId');
    properties['parentId'] = opaqueIdentifierFragment;
  }
  return strictObject(required, properties);
}

const associatedDataBranches = associatedDataDescriptors.map((descriptor) =>
  createAssociatedDataBranch(descriptor),
);

function associatedDataBranch(
  entityType: AssociatedDataDescriptor['entityType'],
): MongoJsonSchema {
  const index = associatedDataDescriptors.findIndex(
    (descriptor) => descriptor.entityType === entityType,
  );
  const branch = associatedDataBranches[index];
  if (branch === undefined) {
    throw new Error('Associated-data fragment table is incomplete');
  }
  return branch;
}

export const associatedDataFragment: MongoJsonSchema = {
  oneOf: associatedDataBranches,
};

function createAeadEnvelope(
  aad: MongoJsonSchema,
  ciphertext: MongoJsonSchema,
): MongoJsonSchema {
  return strictObject(
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
      version: envelopeVersionFragment,
      algorithm: stringEnum(['xchacha20-poly1305-ietf']),
      nonce: aeadNonceFragment,
      ciphertext,
      authenticationTag: aeadAuthenticationTagFragment,
      aad,
      keyVersion: positiveSemanticVersionFragment,
    },
  );
}

export const aeadEnvelopeFragment = createAeadEnvelope(
  associatedDataFragment,
  canonicalCiphertextFragment,
);

const encryptedDeviceLabelCiphertextFragment: MongoJsonSchema = {
  ...canonicalCiphertextFragment,
  maxLength: MAX_ENCRYPTED_DEVICE_LABEL_CIPHERTEXT_CHARS,
};
export const encryptedDeviceLabelFragment = createAeadEnvelope(
  { oneOf: [associatedDataBranch('device-label')] },
  encryptedDeviceLabelCiphertextFragment,
);
export const wrappedRootKeyEnvelopeFragment = createAeadEnvelope(
  { oneOf: [associatedDataBranch('wrapped-root-key')] },
  canonicalCiphertextFragment,
);

const derivationOutputLengthFragment = literalInteger(KEY_DERIVATION_OUTPUT_BYTES);

function hkdfDerivation(context: string, provider?: MongoJsonSchema): MongoJsonSchema {
  const required = ['algorithm', 'version', 'salt', 'context', 'outputLength'];
  const derivationProperties: Record<string, MongoJsonSchema> = {
    algorithm: stringEnum(['hkdf-sha256']),
    version: literalInteger(1),
    salt: hkdfSaltFragment,
    context: stringEnum([context]),
    outputLength: derivationOutputLengthFragment,
  };
  if (provider !== undefined) {
    required.push('provider');
    derivationProperties['provider'] = provider;
  }
  return strictObject(required, derivationProperties);
}

export const portableKeyDerivationFragment = hkdfDerivation(
  'credvault/v1/portable-key-wrap',
);
export const recoveryKeyDerivationFragment = hkdfDerivation(
  'credvault/v1/recovery-key-wrap',
);
export const deviceKeyDerivationFragment = hkdfDerivation(
  'credvault/v1/device-key-wrap',
  { bsonType: 'string', minLength: 1, maxLength: MAX_DEVICE_KEY_PROVIDER_CHARS },
);
export const passphraseDerivationFragment = strictObject(
  [
    'algorithm',
    'version',
    'salt',
    'memoryKiB',
    'passes',
    'parallelism',
    'outputLength',
  ],
  {
    algorithm: stringEnum(['argon2id']),
    version: literalInteger(1),
    salt: argon2idSaltFragment,
    memoryKiB: safeInteger({
      minimum: MIN_ARGON2_MEMORY_KIB,
      maximum: MAX_ARGON2_MEMORY_KIB,
    }),
    passes: safeInteger({ minimum: MIN_ARGON2_PASSES, maximum: MAX_ARGON2_PASSES }),
    parallelism: safeInteger({
      minimum: MIN_ARGON2_PARALLELISM,
      maximum: MAX_ARGON2_PARALLELISM,
    }),
    outputLength: derivationOutputLengthFragment,
  },
);

export const keyDerivationFragment: MongoJsonSchema = {
  oneOf: [
    portableKeyDerivationFragment,
    passphraseDerivationFragment,
    recoveryKeyDerivationFragment,
    deviceKeyDerivationFragment,
  ],
};

const keySlotTypeDescriptors = [
  { type: 'portable-key', derivation: portableKeyDerivationFragment, device: false },
  { type: 'passphrase', derivation: passphraseDerivationFragment, device: false },
  { type: 'recovery-key', derivation: recoveryKeyDerivationFragment, device: false },
  { type: 'device-key', derivation: deviceKeyDerivationFragment, device: true },
] as const;
const keySlotStateDescriptors = [
  { state: 'pending', lifecycleField: undefined },
  { state: 'active', lifecycleField: undefined },
  { state: 'superseded', lifecycleField: 'supersededAt' },
  { state: 'revoked', lifecycleField: 'revokedAt' },
] as const;

const keySlotBranches = keySlotTypeDescriptors.flatMap((typeDescriptor) =>
  keySlotStateDescriptors.map((stateDescriptor) => {
    const required = [
      'slotVersion',
      'id',
      'type',
      'state',
      'keyVersion',
      'wrappedRootKey',
      'derivation',
      'createdAt',
    ];
    const slotProperties: Record<string, MongoJsonSchema> = {
      slotVersion: keySlotVersionFragment,
      id: opaqueIdentifierFragment,
      type: stringEnum([typeDescriptor.type]),
      state: stringEnum([stateDescriptor.state]),
      keyVersion: positiveSemanticVersionFragment,
      wrappedRootKey: wrappedRootKeyEnvelopeFragment,
      derivation: typeDescriptor.derivation,
      createdAt: canonicalTimestampFragment,
    };
    if (typeDescriptor.device) {
      required.push('deviceId');
      slotProperties['deviceId'] = opaqueIdentifierFragment;
    }
    if (stateDescriptor.lifecycleField !== undefined) {
      required.push(stateDescriptor.lifecycleField);
      slotProperties[stateDescriptor.lifecycleField] = canonicalTimestampFragment;
    }
    return strictObject(required, slotProperties);
  }),
);

export const keySlotFragment: MongoJsonSchema = { oneOf: keySlotBranches };

const attachmentSecretStreamIdentityProperties = {
  version: literalInteger(1),
  algorithm: stringEnum(['secretstream-xchacha20-poly1305']),
  streamVersion: literalInteger(1),
  schemaVersion: supportedSchemaVersionFragment,
  keyVersion: positiveSemanticVersionFragment,
  vaultId: opaqueIdentifierFragment,
  groupId: opaqueIdentifierFragment,
  itemId: opaqueIdentifierFragment,
  attachmentId: opaqueIdentifierFragment,
} satisfies Readonly<Record<string, MongoJsonSchema>>;

const attachmentSecretStreamIdentityRequired = [
  'version',
  'algorithm',
  'streamVersion',
  'schemaVersion',
  'keyVersion',
  'vaultId',
  'groupId',
  'itemId',
  'attachmentId',
] as const;

export const attachmentSecretStreamHeaderRecordFragment = strictObject(
  [...attachmentSecretStreamIdentityRequired, 'recordType', 'header'],
  {
    ...attachmentSecretStreamIdentityProperties,
    recordType: stringEnum(['header']),
    header: secretStreamHeaderFragment,
  },
);

export const attachmentSecretStreamChunkRecordFragment = strictObject(
  [
    ...attachmentSecretStreamIdentityRequired,
    'recordType',
    'index',
    'ciphertext',
    'tag',
  ],
  {
    ...attachmentSecretStreamIdentityProperties,
    recordType: stringEnum(['chunk']),
    index: safeInteger({ minimum: 0, maximum: MAX_ATTACHMENT_CHUNKS - 1 }),
    ciphertext: attachmentChunkCiphertextFragment,
    tag: stringEnum(['message', 'final']),
  },
);

export const persistedAttachmentHeaderFragment = strictObject(
  ['entityType', 'record', 'recordRevision', 'contentHash', 'createdAt', 'updatedAt'],
  {
    entityType: stringEnum(['attachment-header']),
    record: attachmentSecretStreamHeaderRecordFragment,
    recordRevision: nonnegativeSemanticRevisionFragment,
    contentHash: sha256DigestFragment,
    createdAt: canonicalTimestampFragment,
    updatedAt: canonicalTimestampFragment,
  },
);

export const persistedAttachmentChunkFragment = strictObject(
  [
    'entityType',
    'record',
    'plaintextBytes',
    'recordRevision',
    'ciphertextHash',
    'createdAt',
    'updatedAt',
  ],
  {
    entityType: stringEnum(['attachment-chunk']),
    record: attachmentSecretStreamChunkRecordFragment,
    plaintextBytes: safeInteger({
      minimum: 0,
      maximum: MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
    }),
    recordRevision: nonnegativeSemanticRevisionFragment,
    ciphertextHash: sha256DigestFragment,
    createdAt: canonicalTimestampFragment,
    updatedAt: canonicalTimestampFragment,
  },
);
