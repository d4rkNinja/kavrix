import type { CreateCollectionOptions, Document, IndexDescription } from 'mongodb';

export const mongoStorageCollectionNames = {
  vaults: 'vaults',
  groups: 'groups',
  items: 'items',
  attachments: 'attachments',
  audits: 'audits',
  histories: 'histories',
  changes: 'changes',
  tombstones: 'tombstones',
  counters: 'vault_counters',
  idempotency: 'idempotency_commits',
  syncPushBatches: 'sync_push_batches',
  templateMigrationPublications: 'template_migration_publications',
  attachmentStaging: 'attachment_staging',
  attachmentStagingChunks: 'attachment_staging_chunks',
  backupRestoreSessions: 'backup_restore_sessions',
  backupRestoreEntries: 'backup_restore_entries',
} as const;

export type MongoStorageCollectionName =
  (typeof mongoStorageCollectionNames)[keyof typeof mongoStorageCollectionNames];

const numberType = ['int', 'long', 'double', 'decimal'] as const;
const timestamp = { bsonType: 'string' } as const;
const digest = { bsonType: 'string', pattern: '^[A-Za-z0-9_-]{43}$' } as const;
const identifier = {
  bsonType: 'string',
  minLength: 1,
  maxLength: 128,
  pattern: '^[A-Za-z0-9][A-Za-z0-9._~-]*$',
} as const;

const aad = {
  bsonType: 'object',
  required: [
    'version',
    'schemaVersion',
    'keyVersion',
    'vaultId',
    'entityType',
    'entityId',
    'purpose',
  ],
  additionalProperties: false,
  properties: {
    version: { bsonType: numberType },
    schemaVersion: { bsonType: numberType },
    keyVersion: { bsonType: numberType },
    vaultId: identifier,
    entityType: { bsonType: 'string' },
    entityId: identifier,
    purpose: { bsonType: 'string' },
    groupId: identifier,
    parentId: identifier,
  },
} as const;

const envelope = {
  bsonType: 'object',
  required: [
    'version',
    'algorithm',
    'nonce',
    'ciphertext',
    'authenticationTag',
    'aad',
    'keyVersion',
  ],
  additionalProperties: false,
  properties: {
    version: { bsonType: numberType },
    algorithm: { enum: ['xchacha20-poly1305-ietf'] },
    nonce: { bsonType: 'string' },
    ciphertext: { bsonType: 'string' },
    authenticationTag: { bsonType: 'string' },
    aad,
    keyVersion: { bsonType: numberType },
  },
} as const;

const derivation = {
  oneOf: [
    {
      bsonType: 'object',
      required: ['algorithm', 'version', 'salt', 'context', 'outputLength'],
      additionalProperties: false,
      properties: {
        algorithm: { enum: ['hkdf-sha256'] },
        version: { bsonType: numberType },
        salt: { bsonType: 'string' },
        context: {
          enum: [
            'credvault/v1/portable-key-wrap',
            'credvault/v1/recovery-key-wrap',
            'credvault/v1/device-key-wrap',
          ],
        },
        outputLength: { bsonType: numberType },
        provider: { bsonType: 'string' },
      },
    },
    {
      bsonType: 'object',
      required: [
        'algorithm',
        'version',
        'salt',
        'memoryKiB',
        'passes',
        'parallelism',
        'outputLength',
      ],
      additionalProperties: false,
      properties: {
        algorithm: { enum: ['argon2id'] },
        version: { bsonType: numberType },
        salt: { bsonType: 'string' },
        memoryKiB: { bsonType: numberType },
        passes: { bsonType: numberType },
        parallelism: { bsonType: numberType },
        outputLength: { bsonType: numberType },
      },
    },
  ],
} as const;

const keySlot = {
  bsonType: 'object',
  required: [
    'slotVersion',
    'id',
    'type',
    'state',
    'keyVersion',
    'wrappedRootKey',
    'derivation',
    'createdAt',
  ],
  additionalProperties: false,
  properties: {
    slotVersion: { bsonType: numberType },
    id: identifier,
    type: { enum: ['portable-key', 'passphrase', 'recovery-key', 'device-key'] },
    state: { enum: ['pending', 'active', 'superseded', 'revoked'] },
    keyVersion: { bsonType: numberType },
    wrappedRootKey: envelope,
    derivation,
    deviceId: identifier,
    createdAt: timestamp,
    supersededAt: timestamp,
    revokedAt: timestamp,
  },
} as const;

function strictObject(
  required: readonly string[],
  properties: Readonly<Record<string, unknown>>,
): Document {
  return {
    bsonType: 'object',
    required,
    additionalProperties: false,
    properties,
  };
}

const vaultRecord = strictObject(
  [
    'id',
    'schemaVersion',
    'cryptographicVersion',
    'keySlots',
    'currentKeyVersion',
    'revision',
    'encryptedPreferences',
    'createdAt',
    'updatedAt',
  ],
  {
    id: identifier,
    schemaVersion: { bsonType: numberType },
    cryptographicVersion: { bsonType: numberType },
    keySlots: { bsonType: 'array', items: keySlot },
    currentKeyVersion: { bsonType: numberType },
    revision: { bsonType: numberType },
    encryptedPreferences: envelope,
    createdAt: timestamp,
    updatedAt: timestamp,
  },
);

const groupRecord = strictObject(
  [
    'id',
    'vaultId',
    'schemaVersion',
    'wrappedGroupKey',
    'encryptedPayload',
    'templateVersion',
    'recordRevision',
    'createdAt',
    'updatedAt',
  ],
  {
    id: identifier,
    vaultId: identifier,
    schemaVersion: { bsonType: numberType },
    wrappedGroupKey: envelope,
    encryptedPayload: envelope,
    templateVersion: { bsonType: numberType },
    recordRevision: { bsonType: numberType },
    createdAt: timestamp,
    updatedAt: timestamp,
    tombstonedAt: timestamp,
  },
);

const itemRecord = strictObject(
  [
    'id',
    'vaultId',
    'groupId',
    'schemaVersion',
    'wrappedItemKey',
    'encryptedPayload',
    'recordRevision',
    'ciphertextHash',
    'createdAt',
    'updatedAt',
  ],
  {
    id: identifier,
    vaultId: identifier,
    groupId: identifier,
    schemaVersion: { bsonType: numberType },
    wrappedItemKey: envelope,
    encryptedPayload: envelope,
    recordRevision: { bsonType: numberType },
    ciphertextHash: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
    tombstonedAt: timestamp,
  },
);

const attachmentRecord = strictObject(
  [
    'id',
    'vaultId',
    'groupId',
    'itemId',
    'schemaVersion',
    'wrappedAttachmentKey',
    'encryptedManifest',
    'chunkCount',
    'recordRevision',
    'createdAt',
    'updatedAt',
  ],
  {
    id: identifier,
    vaultId: identifier,
    groupId: identifier,
    itemId: identifier,
    schemaVersion: { bsonType: numberType },
    wrappedAttachmentKey: envelope,
    encryptedManifest: envelope,
    chunkCount: { bsonType: numberType },
    recordRevision: { bsonType: numberType },
    createdAt: timestamp,
    updatedAt: timestamp,
    tombstonedAt: timestamp,
  },
);

const auditRecord = strictObject(
  ['id', 'vaultId', 'schemaVersion', 'encryptedPayload', 'recordRevision', 'createdAt'],
  {
    id: identifier,
    vaultId: identifier,
    schemaVersion: { bsonType: numberType },
    encryptedPayload: envelope,
    recordRevision: { bsonType: numberType },
    createdAt: timestamp,
  },
);

const historyRecord = strictObject(
  [
    'id',
    'vaultId',
    'groupId',
    'itemId',
    'schemaVersion',
    'encryptedPayload',
    'itemRecordRevision',
    'ciphertextHash',
    'createdAt',
  ],
  {
    id: identifier,
    vaultId: identifier,
    groupId: identifier,
    itemId: identifier,
    schemaVersion: { bsonType: numberType },
    encryptedPayload: envelope,
    itemRecordRevision: { bsonType: numberType },
    ciphertextHash: digest,
    createdAt: timestamp,
  },
);

const secretStreamIdentityProperties = {
  version: { bsonType: numberType },
  algorithm: { enum: ['secretstream-xchacha20-poly1305'] },
  streamVersion: { bsonType: numberType },
  schemaVersion: { bsonType: numberType },
  keyVersion: { bsonType: numberType },
  vaultId: identifier,
  groupId: identifier,
  itemId: identifier,
  attachmentId: identifier,
} as const;

const persistedHeader = strictObject(
  ['entityType', 'record', 'recordRevision', 'contentHash', 'createdAt', 'updatedAt'],
  {
    entityType: { enum: ['attachment-header'] },
    record: strictObject(
      [
        'version',
        'algorithm',
        'streamVersion',
        'schemaVersion',
        'keyVersion',
        'vaultId',
        'groupId',
        'itemId',
        'attachmentId',
        'recordType',
        'header',
      ],
      {
        ...secretStreamIdentityProperties,
        recordType: { enum: ['header'] },
        header: { bsonType: 'string' },
      },
    ),
    recordRevision: { bsonType: numberType },
    contentHash: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  },
);

const persistedChunk = strictObject(
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
    entityType: { enum: ['attachment-chunk'] },
    record: strictObject(
      [
        'version',
        'algorithm',
        'streamVersion',
        'schemaVersion',
        'keyVersion',
        'vaultId',
        'groupId',
        'itemId',
        'attachmentId',
        'recordType',
        'index',
        'ciphertext',
        'tag',
      ],
      {
        ...secretStreamIdentityProperties,
        recordType: { enum: ['chunk'] },
        index: { bsonType: numberType },
        ciphertext: { bsonType: 'string' },
        tag: { enum: ['message', 'final'] },
      },
    ),
    plaintextBytes: { bsonType: numberType },
    recordRevision: { bsonType: numberType },
    ciphertextHash: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  },
);

const progress = strictObject(
  ['version', 'state', 'nextChunkIndex', 'totalPlaintextBytes', 'totalCiphertextBytes'],
  {
    version: { bsonType: numberType },
    state: { enum: ['empty', 'writing', 'ready-to-finalize'] },
    nextChunkIndex: { bsonType: numberType },
    totalPlaintextBytes: { bsonType: numberType },
    totalCiphertextBytes: { bsonType: numberType },
    lastChunkIndex: { bsonType: numberType },
    lastChunkCiphertextHash: digest,
    lastChunkPlaintextBytes: { bsonType: numberType },
  },
);

const startInput = strictObject(
  ['version', 'idempotencyKey', 'expectedAttachmentRevision', 'header'],
  {
    version: { bsonType: numberType },
    idempotencyKey: { bsonType: 'string', minLength: 16, maxLength: 256 },
    expectedAttachmentRevision: { bsonType: [...numberType, 'null'] },
    header: persistedHeader,
  },
);

const changeRecord = strictObject(
  [
    'id',
    'vaultId',
    'serverSequence',
    'entityType',
    'entityId',
    'recordRevision',
    'operation',
    'createdAt',
  ],
  {
    id: identifier,
    vaultId: identifier,
    serverSequence: { bsonType: numberType },
    entityType: { enum: ['vault', 'group', 'item', 'attachment'] },
    entityId: identifier,
    recordRevision: { bsonType: numberType },
    operation: { enum: ['upsert', 'tombstone', 'restore', 'purge'] },
    ciphertextHash: digest,
    createdAt: timestamp,
  },
);

const tombstoneRecord = strictObject(
  [
    'vaultId',
    'entityType',
    'entityId',
    'state',
    'tombstoneRevision',
    'lastRecordRevision',
    'lastCiphertextHash',
    'deletedAt',
  ],
  {
    vaultId: identifier,
    entityType: { enum: ['vault', 'group', 'item', 'attachment'] },
    entityId: identifier,
    state: { enum: ['deleted', 'restored'] },
    tombstoneRevision: { bsonType: numberType },
    lastRecordRevision: { bsonType: numberType },
    lastCiphertextHash: digest,
    deletedAt: timestamp,
    restoredAt: timestamp,
    purgeAfter: timestamp,
  },
);

const opaqueSyncPayload = {
  oneOf: [
    vaultRecord,
    groupRecord,
    itemRecord,
    attachmentRecord,
    tombstoneRecord,
    { bsonType: 'null' },
  ],
} as const;

const backupEntry = {
  oneOf: [
    strictObject(['kind', 'record'], {
      kind: { enum: ['vault'] },
      record: vaultRecord,
    }),
    strictObject(['kind', 'record'], {
      kind: { enum: ['group'] },
      record: groupRecord,
    }),
    strictObject(['kind', 'record'], {
      kind: { enum: ['item'] },
      record: itemRecord,
    }),
    strictObject(['kind', 'record'], {
      kind: { enum: ['attachment'] },
      record: attachmentRecord,
    }),
    strictObject(['kind', 'record'], {
      kind: { enum: ['attachment-header'] },
      record: persistedHeader,
    }),
    strictObject(['kind', 'record'], {
      kind: { enum: ['attachment-chunk'] },
      record: persistedChunk,
    }),
    strictObject(['kind', 'record'], {
      kind: { enum: ['audit'] },
      record: auditRecord,
    }),
    strictObject(['kind', 'record'], {
      kind: { enum: ['history'] },
      record: historyRecord,
    }),
    strictObject(['kind', 'entityType', 'record'], {
      kind: { enum: ['tombstone-predecessor'] },
      entityType: { enum: ['group', 'item', 'attachment'] },
      record: { oneOf: [groupRecord, itemRecord, attachmentRecord] },
    }),
    strictObject(['kind', 'record'], {
      kind: { enum: ['tombstone'] },
      record: tombstoneRecord,
    }),
  ],
} as const;

const restoreSessionCommonProperties = {
  _id: digest,
  restoreSessionId: digest,
  maximumBytes: { bsonType: numberType },
  maximumRecords: { bsonType: numberType },
  stagedBytes: { bsonType: numberType },
  stagedRecords: { bsonType: numberType },
  createdAt: timestamp,
  updatedAt: timestamp,
  vaultId: identifier,
} as const;

const backupRestoreSession = {
  oneOf: [
    strictObject(
      [
        '_id',
        'restoreSessionId',
        'maximumBytes',
        'maximumRecords',
        'state',
        'stagedBytes',
        'stagedRecords',
        'createdAt',
        'updatedAt',
      ],
      {
        ...restoreSessionCommonProperties,
        state: { enum: ['staging'] },
      },
    ),
    strictObject(
      [
        '_id',
        'restoreSessionId',
        'maximumBytes',
        'maximumRecords',
        'state',
        'stagedBytes',
        'stagedRecords',
        'createdAt',
        'updatedAt',
        'vaultId',
        'transcriptSha256',
        'summaryRecordCount',
        'committedAt',
      ],
      {
        ...restoreSessionCommonProperties,
        state: { enum: ['committed'] },
        transcriptSha256: digest,
        summaryRecordCount: { bsonType: numberType },
        committedAt: timestamp,
      },
    ),
    strictObject(
      [
        '_id',
        'restoreSessionId',
        'maximumBytes',
        'maximumRecords',
        'state',
        'stagedBytes',
        'stagedRecords',
        'createdAt',
        'updatedAt',
        'abortedAt',
      ],
      {
        ...restoreSessionCommonProperties,
        state: { enum: ['aborted'] },
        abortedAt: timestamp,
      },
    ),
  ],
} as const;

const backupRestoreEntry = strictObject(
  [
    '_id',
    'restoreSessionId',
    'ordinal',
    'identity',
    'entryHash',
    'vaultId',
    'bytes',
    'entry',
  ],
  {
    _id: { bsonType: 'string' },
    restoreSessionId: digest,
    ordinal: { bsonType: numberType },
    identity: { bsonType: 'string' },
    entryHash: { bsonType: 'string', pattern: '^[a-f0-9]{64}$' },
    vaultId: identifier,
    bytes: { bsonType: numberType },
    entry: backupEntry,
  },
);

const syncPushResult = {
  oneOf: [
    strictObject(['status', 'idempotencyKey', 'disposition', 'change'], {
      status: { enum: ['accepted'] },
      idempotencyKey: { bsonType: 'string', minLength: 16, maxLength: 256 },
      disposition: { enum: ['committed', 'duplicate'] },
      change: changeRecord,
    }),
    strictObject(['status', 'idempotencyKey', 'currentRevision', 'current'], {
      status: { enum: ['conflict'] },
      idempotencyKey: { bsonType: 'string', minLength: 16, maxLength: 256 },
      currentRevision: { bsonType: numberType },
      current: opaqueSyncPayload,
    }),
  ],
} as const;

const syncPushResponse = strictObject(
  ['vaultId', 'serverVaultRevision', 'batchIdempotencyKey', 'results'],
  {
    vaultId: identifier,
    serverVaultRevision: { bsonType: numberType },
    batchIdempotencyKey: { bsonType: 'string', minLength: 16, maxLength: 256 },
    results: { bsonType: 'array', items: syncPushResult },
  },
);

const templateMigrationPublicationResult = strictObject(['idempotencyKey', 'change'], {
  idempotencyKey: { bsonType: 'string', minLength: 16, maxLength: 256 },
  change: changeRecord,
});

const templateMigrationPublicationResponse = strictObject(
  ['vaultId', 'batchIdempotencyKey', 'serverVaultRevision', 'results'],
  {
    vaultId: identifier,
    batchIdempotencyKey: { bsonType: 'string', minLength: 16, maxLength: 256 },
    serverVaultRevision: { bsonType: numberType },
    results: {
      bsonType: 'array',
      minItems: 1,
      maxItems: 100,
      items: templateMigrationPublicationResult,
    },
  },
);

function validator(schema: Document): CreateCollectionOptions {
  return {
    validator: { $jsonSchema: schema },
    validationLevel: 'strict',
    validationAction: 'error',
  };
}

export const mongoStorageCollectionOptions: Readonly<
  Record<MongoStorageCollectionName, CreateCollectionOptions>
> = {
  vaults: validator(
    strictObject(['_id', 'vaultId', 'record'], {
      _id: identifier,
      vaultId: identifier,
      record: vaultRecord,
    }),
  ),
  groups: validator(
    strictObject(['_id', 'vaultId', 'groupId', 'record'], {
      _id: { bsonType: 'string' },
      vaultId: identifier,
      groupId: identifier,
      record: groupRecord,
    }),
  ),
  items: validator(
    strictObject(['_id', 'vaultId', 'groupId', 'itemId', 'record'], {
      _id: { bsonType: 'string' },
      vaultId: identifier,
      groupId: identifier,
      itemId: identifier,
      record: itemRecord,
    }),
  ),
  attachments: validator(
    strictObject(
      ['_id', 'vaultId', 'groupId', 'itemId', 'attachmentId', 'stagingId', 'record'],
      {
        _id: { bsonType: 'string' },
        vaultId: identifier,
        groupId: identifier,
        itemId: identifier,
        attachmentId: identifier,
        stagingId: { bsonType: 'string' },
        record: attachmentRecord,
      },
    ),
  ),
  audits: validator(
    strictObject(['_id', 'vaultId', 'auditId', 'record'], {
      _id: { bsonType: 'string' },
      vaultId: identifier,
      auditId: identifier,
      record: auditRecord,
    }),
  ),
  histories: validator(
    strictObject(['_id', 'vaultId', 'groupId', 'itemId', 'historyId', 'record'], {
      _id: { bsonType: 'string' },
      vaultId: identifier,
      groupId: identifier,
      itemId: identifier,
      historyId: identifier,
      record: historyRecord,
    }),
  ),
  changes: validator(
    strictObject(['_id', 'vaultId', 'serverSequence', 'record', 'payload'], {
      _id: { bsonType: 'string' },
      vaultId: identifier,
      serverSequence: { bsonType: numberType },
      record: changeRecord,
      payload: opaqueSyncPayload,
    }),
  ),
  tombstones: validator(
    strictObject(['_id', 'vaultId', 'entityType', 'entityId', 'record'], {
      _id: { bsonType: 'string' },
      vaultId: identifier,
      entityType: { enum: ['vault', 'group', 'item', 'attachment'] },
      entityId: identifier,
      record: tombstoneRecord,
    }),
  ),
  vault_counters: validator(
    strictObject(['_id', 'changeSequence', 'vaultRevision'], {
      _id: identifier,
      changeSequence: { bsonType: numberType },
      vaultRevision: { bsonType: numberType },
    }),
  ),
  idempotency_commits: validator(
    strictObject(
      [
        '_id',
        'vaultId',
        'idempotencyKey',
        'inputHash',
        'entityType',
        'change',
        'committedAt',
      ],
      {
        _id: { bsonType: 'string' },
        vaultId: identifier,
        idempotencyKey: { bsonType: 'string', minLength: 16, maxLength: 256 },
        inputHash: { bsonType: 'string', pattern: '^[a-f0-9]{64}$' },
        entityType: { enum: ['vault', 'group', 'item', 'attachment'] },
        change: changeRecord,
        committedAt: timestamp,
      },
    ),
  ),
  sync_push_batches: validator(
    strictObject(
      [
        '_id',
        'vaultId',
        'batchIdempotencyKey',
        'requestHash',
        'mutationCount',
        'state',
        'nextMutationIndex',
        'results',
        'createdAt',
        'updatedAt',
      ],
      {
        _id: { bsonType: 'string' },
        vaultId: identifier,
        batchIdempotencyKey: {
          bsonType: 'string',
          minLength: 16,
          maxLength: 256,
        },
        requestHash: { bsonType: 'string', pattern: '^[a-f0-9]{64}$' },
        mutationCount: { bsonType: numberType },
        state: { enum: ['running', 'completed'] },
        nextMutationIndex: { bsonType: numberType },
        results: { bsonType: 'array', items: syncPushResult },
        response: syncPushResponse,
        createdAt: timestamp,
        updatedAt: timestamp,
        completedAt: timestamp,
      },
    ),
  ),
  template_migration_publications: validator(
    strictObject(
      [
        '_id',
        'vaultId',
        'batchIdempotencyKey',
        'requestHash',
        'response',
        'committedAt',
      ],
      {
        _id: { bsonType: 'string' },
        vaultId: identifier,
        batchIdempotencyKey: {
          bsonType: 'string',
          minLength: 16,
          maxLength: 256,
        },
        requestHash: { bsonType: 'string', pattern: '^[a-f0-9]{64}$' },
        response: templateMigrationPublicationResponse,
        committedAt: timestamp,
      },
    ),
  ),
  attachment_staging: validator(
    strictObject(
      [
        '_id',
        'vaultId',
        'attachmentId',
        'idempotencyKey',
        'inputHash',
        'state',
        'createdAt',
        'updatedAt',
      ],
      {
        _id: { bsonType: 'string' },
        vaultId: identifier,
        attachmentId: identifier,
        idempotencyKey: { bsonType: 'string', minLength: 16, maxLength: 256 },
        inputHash: { bsonType: 'string', pattern: '^[a-f0-9]{64}$' },
        state: { enum: ['active', 'finalized', 'aborted'] },
        input: startInput,
        progress,
        finalizeHash: { bsonType: 'string', pattern: '^[a-f0-9]{64}$' },
        createdAt: timestamp,
        updatedAt: timestamp,
        finalizedAt: timestamp,
        abortedAt: timestamp,
      },
    ),
  ),
  attachment_staging_chunks: validator(
    strictObject(
      ['_id', 'stagingId', 'vaultId', 'attachmentId', 'chunkIndex', 'record'],
      {
        _id: { bsonType: 'string' },
        stagingId: { bsonType: 'string' },
        vaultId: identifier,
        attachmentId: identifier,
        chunkIndex: { bsonType: numberType },
        record: persistedChunk,
      },
    ),
  ),
  backup_restore_sessions: validator(backupRestoreSession),
  backup_restore_entries: validator(backupRestoreEntry),
};

export const mongoStorageIndexes: Readonly<
  Record<MongoStorageCollectionName, readonly IndexDescription[]>
> = {
  vaults: [{ key: { vaultId: 1 }, name: 'vault_identity', unique: true }],
  groups: [
    { key: { vaultId: 1, groupId: 1 }, name: 'group_identity', unique: true },
    { key: { vaultId: 1, 'record.tombstonedAt': 1 }, name: 'groups_by_vault' },
  ],
  items: [
    { key: { vaultId: 1, itemId: 1 }, name: 'item_identity', unique: true },
    {
      key: { vaultId: 1, groupId: 1, 'record.tombstonedAt': 1, itemId: 1 },
      name: 'items_by_group',
    },
  ],
  attachments: [
    {
      key: { vaultId: 1, attachmentId: 1 },
      name: 'attachment_identity',
      unique: true,
    },
    { key: { stagingId: 1 }, name: 'attachment_staging_identity', unique: true },
  ],
  audits: [{ key: { vaultId: 1, auditId: 1 }, name: 'audit_identity', unique: true }],
  histories: [
    {
      key: { vaultId: 1, historyId: 1 },
      name: 'history_identity',
      unique: true,
    },
    {
      key: { vaultId: 1, itemId: 1, 'record.itemRecordRevision': 1 },
      name: 'histories_by_item',
    },
  ],
  changes: [
    {
      key: { vaultId: 1, serverSequence: 1 },
      name: 'changes_by_vault_sequence',
      unique: true,
    },
  ],
  tombstones: [
    {
      key: { vaultId: 1, entityType: 1, entityId: 1 },
      name: 'tombstone_identity',
      unique: true,
    },
    { key: { 'record.purgeAfter': 1 }, name: 'tombstones_by_purge_time' },
  ],
  vault_counters: [],
  idempotency_commits: [
    {
      key: { vaultId: 1, idempotencyKey: 1 },
      name: 'idempotency_key_per_vault',
      unique: true,
    },
  ],
  sync_push_batches: [
    {
      key: { vaultId: 1, batchIdempotencyKey: 1 },
      name: 'sync_push_batch_idempotency',
      unique: true,
    },
  ],
  template_migration_publications: [
    {
      key: { vaultId: 1, batchIdempotencyKey: 1 },
      name: 'template_migration_batch_idempotency',
      unique: true,
    },
  ],
  attachment_staging: [
    {
      key: { vaultId: 1, attachmentId: 1, state: 1 },
      name: 'staging_by_attachment',
    },
    {
      key: { vaultId: 1, idempotencyKey: 1 },
      name: 'staging_idempotency_key',
      unique: true,
    },
  ],
  attachment_staging_chunks: [
    {
      key: { stagingId: 1, chunkIndex: 1 },
      name: 'staged_chunks_contiguous_order',
      unique: true,
    },
  ],
  backup_restore_sessions: [
    { key: { state: 1, updatedAt: 1 }, name: 'restore_sessions_by_state' },
  ],
  backup_restore_entries: [
    {
      key: { restoreSessionId: 1, ordinal: 1 },
      name: 'restore_entries_in_order',
      unique: true,
    },
    {
      key: { restoreSessionId: 1, identity: 1 },
      name: 'restore_entry_identity',
      unique: true,
    },
  ],
};
