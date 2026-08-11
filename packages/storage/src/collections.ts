import {
  DEFAULT_MAX_BACKUP_RECORDS,
  MAX_ATTACHMENT_CHUNKS,
  MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES,
  MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
  MAX_IDEMPOTENCY_KEY_CHARS,
  MAX_SEMANTIC_REVISION,
  MAX_SUPPORTED_BACKUP_BYTES,
  MAX_SYNC_PUSH_MUTATIONS,
  MAX_TEMPLATE_MIGRATION_RESULTS,
  MAX_VAULT_KEY_SLOTS,
  MIN_IDEMPOTENCY_KEY_CHARS,
  MIN_VAULT_KEY_SLOTS,
} from '@kavrix/schemas';
import type { CreateCollectionOptions, Document, IndexDescription } from 'mongodb';

import {
  aeadEnvelopeFragment,
  canonicalTimestampFragment,
  keySlotFragment,
  nonnegativeSemanticRevisionFragment,
  opaqueIdentifierFragment,
  persistedAttachmentChunkFragment,
  persistedAttachmentHeaderFragment,
  positiveSemanticVersionFragment,
  safeInteger,
  sha256DigestFragment,
  strictObject,
  supportedCryptographicVersionFragment,
  supportedSchemaVersionFragment,
  type MongoJsonSchema,
} from './mongo-validator-fragments.js';
import type { MongoDocumentSchemaMap } from './mongo-document-preflight.js';
import {
  attachmentStagingDocumentSchema,
  idempotencyDocumentSchema,
  stagedAttachmentChunkDocumentSchema,
  storageCounterDocumentSchema,
  storedAttachmentDocumentSchema,
  storedAuditDocumentSchema,
  storedChangeDocumentSchema,
  storedGroupDocumentSchema,
  storedHistoryDocumentSchema,
  storedItemDocumentSchema,
  storedTombstoneDocumentSchema,
  storedVaultDocumentSchema,
  syncPushBatchDocumentSchema,
  templateMigrationPublicationDocumentSchema,
} from './documents.js';
import {
  MAX_MONGO_RESTORE_ENTRY_BYTES,
  backupRestoreEntryDocumentSchema,
  backupRestoreSessionDocumentSchema,
} from './restore-documents.js';

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

export const mongoStorageDocumentSchemas: MongoDocumentSchemaMap<MongoStorageCollectionName> =
  {
    [mongoStorageCollectionNames.vaults]: storedVaultDocumentSchema,
    [mongoStorageCollectionNames.groups]: storedGroupDocumentSchema,
    [mongoStorageCollectionNames.items]: storedItemDocumentSchema,
    [mongoStorageCollectionNames.attachments]: storedAttachmentDocumentSchema,
    [mongoStorageCollectionNames.audits]: storedAuditDocumentSchema,
    [mongoStorageCollectionNames.histories]: storedHistoryDocumentSchema,
    [mongoStorageCollectionNames.changes]: storedChangeDocumentSchema,
    [mongoStorageCollectionNames.tombstones]: storedTombstoneDocumentSchema,
    [mongoStorageCollectionNames.counters]: storageCounterDocumentSchema,
    [mongoStorageCollectionNames.idempotency]: idempotencyDocumentSchema,
    [mongoStorageCollectionNames.syncPushBatches]: syncPushBatchDocumentSchema,
    [mongoStorageCollectionNames.templateMigrationPublications]:
      templateMigrationPublicationDocumentSchema,
    [mongoStorageCollectionNames.attachmentStaging]: attachmentStagingDocumentSchema,
    [mongoStorageCollectionNames.attachmentStagingChunks]:
      stagedAttachmentChunkDocumentSchema,
    [mongoStorageCollectionNames.backupRestoreSessions]:
      backupRestoreSessionDocumentSchema,
    [mongoStorageCollectionNames.backupRestoreEntries]:
      backupRestoreEntryDocumentSchema,
  };

function stringEnum(values: readonly string[]): MongoJsonSchema {
  return { bsonType: 'string', enum: values };
}

function literalInteger(value: number): MongoJsonSchema {
  return { ...safeInteger({ minimum: value, maximum: value }), enum: [value] };
}

function boundedArray(
  items: MongoJsonSchema,
  minItems: number,
  maxItems: number,
): MongoJsonSchema {
  return { bsonType: 'array', minItems, maxItems, items };
}

const nonEmptyStringFragment: MongoJsonSchema = {
  bsonType: 'string',
  minLength: 1,
};
const boundedRestoreStringFragment: MongoJsonSchema = {
  bsonType: 'string',
  minLength: 1,
  maxLength: 512,
};
const sha256HexFragment: MongoJsonSchema = {
  bsonType: 'string',
  minLength: 64,
  maxLength: 64,
  pattern: '^[a-f0-9]{64}$',
};
const idempotencyKeyFragment: MongoJsonSchema = {
  bsonType: 'string',
  minLength: MIN_IDEMPOTENCY_KEY_CHARS,
  maxLength: MAX_IDEMPOTENCY_KEY_CHARS,
};
const positiveSemanticRevisionFragment = safeInteger({
  minimum: 1,
  maximum: MAX_SEMANTIC_REVISION,
});
const nullableSemanticRevisionFragment: MongoJsonSchema = {
  oneOf: [nonnegativeSemanticRevisionFragment, { bsonType: 'null' }],
};
const versionOneFragment = literalInteger(1);

const vaultRecordFragment = strictObject(
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
    id: opaqueIdentifierFragment,
    schemaVersion: supportedSchemaVersionFragment,
    cryptographicVersion: supportedCryptographicVersionFragment,
    keySlots: boundedArray(keySlotFragment, MIN_VAULT_KEY_SLOTS, MAX_VAULT_KEY_SLOTS),
    currentKeyVersion: positiveSemanticVersionFragment,
    revision: nonnegativeSemanticRevisionFragment,
    encryptedPreferences: aeadEnvelopeFragment,
    createdAt: canonicalTimestampFragment,
    updatedAt: canonicalTimestampFragment,
  },
);

const groupRecordFragment = strictObject(
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
    id: opaqueIdentifierFragment,
    vaultId: opaqueIdentifierFragment,
    schemaVersion: supportedSchemaVersionFragment,
    wrappedGroupKey: aeadEnvelopeFragment,
    encryptedPayload: aeadEnvelopeFragment,
    templateVersion: positiveSemanticVersionFragment,
    recordRevision: nonnegativeSemanticRevisionFragment,
    createdAt: canonicalTimestampFragment,
    updatedAt: canonicalTimestampFragment,
    tombstonedAt: canonicalTimestampFragment,
  },
);

const itemRecordFragment = strictObject(
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
    id: opaqueIdentifierFragment,
    vaultId: opaqueIdentifierFragment,
    groupId: opaqueIdentifierFragment,
    schemaVersion: supportedSchemaVersionFragment,
    wrappedItemKey: aeadEnvelopeFragment,
    encryptedPayload: aeadEnvelopeFragment,
    recordRevision: nonnegativeSemanticRevisionFragment,
    ciphertextHash: sha256DigestFragment,
    createdAt: canonicalTimestampFragment,
    updatedAt: canonicalTimestampFragment,
    tombstonedAt: canonicalTimestampFragment,
  },
);

const attachmentRecordFragment = strictObject(
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
    id: opaqueIdentifierFragment,
    vaultId: opaqueIdentifierFragment,
    groupId: opaqueIdentifierFragment,
    itemId: opaqueIdentifierFragment,
    schemaVersion: supportedSchemaVersionFragment,
    wrappedAttachmentKey: aeadEnvelopeFragment,
    encryptedManifest: aeadEnvelopeFragment,
    chunkCount: safeInteger({ minimum: 1, maximum: MAX_ATTACHMENT_CHUNKS }),
    recordRevision: nonnegativeSemanticRevisionFragment,
    createdAt: canonicalTimestampFragment,
    updatedAt: canonicalTimestampFragment,
    tombstonedAt: canonicalTimestampFragment,
  },
);

const auditRecordFragment = strictObject(
  ['id', 'vaultId', 'schemaVersion', 'encryptedPayload', 'recordRevision', 'createdAt'],
  {
    id: opaqueIdentifierFragment,
    vaultId: opaqueIdentifierFragment,
    schemaVersion: supportedSchemaVersionFragment,
    encryptedPayload: aeadEnvelopeFragment,
    recordRevision: nonnegativeSemanticRevisionFragment,
    createdAt: canonicalTimestampFragment,
  },
);

const historyRecordFragment = strictObject(
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
    id: opaqueIdentifierFragment,
    vaultId: opaqueIdentifierFragment,
    groupId: opaqueIdentifierFragment,
    itemId: opaqueIdentifierFragment,
    schemaVersion: supportedSchemaVersionFragment,
    encryptedPayload: aeadEnvelopeFragment,
    itemRecordRevision: nonnegativeSemanticRevisionFragment,
    ciphertextHash: sha256DigestFragment,
    createdAt: canonicalTimestampFragment,
  },
);

const changeEntityTypes = ['vault', 'group', 'item', 'attachment'] as const;
const changeOperations = ['upsert', 'tombstone', 'restore', 'purge'] as const;
const changeRecordFragment: MongoJsonSchema = {
  oneOf: changeEntityTypes.flatMap((entityType) =>
    changeOperations.map((operation) => {
      const required = [
        'id',
        'vaultId',
        'serverSequence',
        'entityType',
        'entityId',
        'recordRevision',
        'operation',
        'createdAt',
      ];
      if (operation !== 'purge') required.push('ciphertextHash');
      return strictObject(required, {
        id: opaqueIdentifierFragment,
        vaultId: opaqueIdentifierFragment,
        serverSequence: positiveSemanticRevisionFragment,
        entityType: stringEnum([entityType]),
        entityId: opaqueIdentifierFragment,
        recordRevision: nonnegativeSemanticRevisionFragment,
        operation: stringEnum([operation]),
        ciphertextHash: sha256DigestFragment,
        createdAt: canonicalTimestampFragment,
      });
    }),
  ),
};

const tombstoneRecordFragment: MongoJsonSchema = {
  oneOf: changeEntityTypes.flatMap((entityType) => [
    strictObject(
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
        vaultId: opaqueIdentifierFragment,
        entityType: stringEnum([entityType]),
        entityId: opaqueIdentifierFragment,
        state: stringEnum(['deleted']),
        tombstoneRevision: nonnegativeSemanticRevisionFragment,
        lastRecordRevision: nonnegativeSemanticRevisionFragment,
        lastCiphertextHash: sha256DigestFragment,
        deletedAt: canonicalTimestampFragment,
        purgeAfter: canonicalTimestampFragment,
      },
    ),
    strictObject(
      [
        'vaultId',
        'entityType',
        'entityId',
        'state',
        'tombstoneRevision',
        'lastRecordRevision',
        'lastCiphertextHash',
        'deletedAt',
        'restoredAt',
      ],
      {
        vaultId: opaqueIdentifierFragment,
        entityType: stringEnum([entityType]),
        entityId: opaqueIdentifierFragment,
        state: stringEnum(['restored']),
        tombstoneRevision: nonnegativeSemanticRevisionFragment,
        lastRecordRevision: nonnegativeSemanticRevisionFragment,
        lastCiphertextHash: sha256DigestFragment,
        deletedAt: canonicalTimestampFragment,
        restoredAt: canonicalTimestampFragment,
      },
    ),
  ]),
};

const opaqueSyncPayloadFragment: MongoJsonSchema = {
  oneOf: [
    vaultRecordFragment,
    groupRecordFragment,
    itemRecordFragment,
    attachmentRecordFragment,
    tombstoneRecordFragment,
    { bsonType: 'null' },
  ],
};

const syncPushResultFragment: MongoJsonSchema = {
  oneOf: [
    strictObject(['status', 'idempotencyKey', 'disposition', 'change'], {
      status: stringEnum(['accepted']),
      idempotencyKey: idempotencyKeyFragment,
      disposition: stringEnum(['committed', 'duplicate']),
      change: changeRecordFragment,
    }),
    strictObject(['status', 'idempotencyKey', 'currentRevision', 'current'], {
      status: stringEnum(['conflict']),
      idempotencyKey: idempotencyKeyFragment,
      currentRevision: nonnegativeSemanticRevisionFragment,
      current: opaqueSyncPayloadFragment,
    }),
  ],
};

const syncPushResponseFragment = strictObject(
  ['vaultId', 'serverVaultRevision', 'batchIdempotencyKey', 'results'],
  {
    vaultId: opaqueIdentifierFragment,
    serverVaultRevision: nonnegativeSemanticRevisionFragment,
    batchIdempotencyKey: idempotencyKeyFragment,
    results: boundedArray(syncPushResultFragment, 1, MAX_SYNC_PUSH_MUTATIONS),
  },
);

const templateMigrationPublicationResultFragment = strictObject(
  ['idempotencyKey', 'change'],
  {
    idempotencyKey: idempotencyKeyFragment,
    change: changeRecordFragment,
  },
);
const templateMigrationPublicationResponseFragment = strictObject(
  ['vaultId', 'batchIdempotencyKey', 'serverVaultRevision', 'results'],
  {
    vaultId: opaqueIdentifierFragment,
    batchIdempotencyKey: idempotencyKeyFragment,
    serverVaultRevision: nonnegativeSemanticRevisionFragment,
    results: boundedArray(
      templateMigrationPublicationResultFragment,
      1,
      MAX_TEMPLATE_MIGRATION_RESULTS,
    ),
  },
);

const attachmentProgressCounters = {
  version: versionOneFragment,
  nextChunkIndex: safeInteger({ minimum: 0, maximum: MAX_ATTACHMENT_CHUNKS }),
  totalPlaintextBytes: safeInteger({
    minimum: 0,
    maximum: MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
  }),
  totalCiphertextBytes: safeInteger({
    minimum: 0,
    maximum: MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES,
  }),
} satisfies Readonly<Record<string, MongoJsonSchema>>;
const attachmentProgressWithLastChunk = {
  ...attachmentProgressCounters,
  lastChunkIndex: safeInteger({
    minimum: 0,
    maximum: MAX_ATTACHMENT_CHUNKS - 1,
  }),
  lastChunkCiphertextHash: sha256DigestFragment,
  lastChunkPlaintextBytes: safeInteger({
    minimum: 0,
    maximum: MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  }),
} satisfies Readonly<Record<string, MongoJsonSchema>>;
const attachmentProgressFragment: MongoJsonSchema = {
  oneOf: [
    strictObject(
      [
        'version',
        'state',
        'nextChunkIndex',
        'totalPlaintextBytes',
        'totalCiphertextBytes',
      ],
      {
        ...attachmentProgressCounters,
        state: stringEnum(['empty']),
        nextChunkIndex: literalInteger(0),
        totalPlaintextBytes: literalInteger(0),
        totalCiphertextBytes: literalInteger(0),
      },
    ),
    ...(['writing', 'ready-to-finalize'] as const).map((state) =>
      strictObject(
        [
          'version',
          'state',
          'nextChunkIndex',
          'totalPlaintextBytes',
          'totalCiphertextBytes',
          'lastChunkIndex',
          'lastChunkCiphertextHash',
          'lastChunkPlaintextBytes',
        ],
        {
          ...attachmentProgressWithLastChunk,
          state: stringEnum([state]),
          nextChunkIndex: safeInteger({
            minimum: 1,
            maximum:
              state === 'writing' ? MAX_ATTACHMENT_CHUNKS - 1 : MAX_ATTACHMENT_CHUNKS,
          }),
        },
      ),
    ),
  ],
};

const attachmentStartInputFragment = strictObject(
  ['version', 'idempotencyKey', 'expectedAttachmentRevision', 'header'],
  {
    version: versionOneFragment,
    idempotencyKey: idempotencyKeyFragment,
    expectedAttachmentRevision: nullableSemanticRevisionFragment,
    header: persistedAttachmentHeaderFragment,
  },
);

const attachmentStagingCommonProperties = {
  _id: nonEmptyStringFragment,
  vaultId: opaqueIdentifierFragment,
  attachmentId: opaqueIdentifierFragment,
  idempotencyKey: idempotencyKeyFragment,
  inputHash: sha256HexFragment,
  createdAt: canonicalTimestampFragment,
  updatedAt: canonicalTimestampFragment,
} satisfies Readonly<Record<string, MongoJsonSchema>>;
const attachmentStagingCommonRequired = [
  '_id',
  'vaultId',
  'attachmentId',
  'idempotencyKey',
  'inputHash',
  'state',
  'createdAt',
  'updatedAt',
] as const;
const attachmentStagingFragment: MongoJsonSchema = {
  oneOf: [
    strictObject([...attachmentStagingCommonRequired, 'input', 'progress'], {
      ...attachmentStagingCommonProperties,
      state: stringEnum(['active']),
      input: attachmentStartInputFragment,
      progress: attachmentProgressFragment,
    }),
    strictObject(
      [
        ...attachmentStagingCommonRequired,
        'input',
        'progress',
        'finalizeHash',
        'finalizedAt',
      ],
      {
        ...attachmentStagingCommonProperties,
        state: stringEnum(['finalized']),
        input: attachmentStartInputFragment,
        progress: attachmentProgressFragment,
        finalizeHash: sha256HexFragment,
        finalizedAt: canonicalTimestampFragment,
      },
    ),
    strictObject([...attachmentStagingCommonRequired, 'abortedAt'], {
      ...attachmentStagingCommonProperties,
      state: stringEnum(['aborted']),
      abortedAt: canonicalTimestampFragment,
    }),
  ],
};

const backupEntryFragment: MongoJsonSchema = {
  oneOf: [
    strictObject(['kind', 'record'], {
      kind: stringEnum(['vault']),
      record: vaultRecordFragment,
    }),
    strictObject(['kind', 'record'], {
      kind: stringEnum(['group']),
      record: groupRecordFragment,
    }),
    strictObject(['kind', 'record'], {
      kind: stringEnum(['item']),
      record: itemRecordFragment,
    }),
    strictObject(['kind', 'record'], {
      kind: stringEnum(['attachment']),
      record: attachmentRecordFragment,
    }),
    strictObject(['kind', 'record'], {
      kind: stringEnum(['attachment-header']),
      record: persistedAttachmentHeaderFragment,
    }),
    strictObject(['kind', 'record'], {
      kind: stringEnum(['attachment-chunk']),
      record: persistedAttachmentChunkFragment,
    }),
    strictObject(['kind', 'record'], {
      kind: stringEnum(['audit']),
      record: auditRecordFragment,
    }),
    strictObject(['kind', 'record'], {
      kind: stringEnum(['history']),
      record: historyRecordFragment,
    }),
    strictObject(['kind', 'entityType', 'record'], {
      kind: stringEnum(['tombstone-predecessor']),
      entityType: stringEnum(['group', 'item', 'attachment']),
      record: {
        oneOf: [groupRecordFragment, itemRecordFragment, attachmentRecordFragment],
      },
    }),
    strictObject(['kind', 'record'], {
      kind: stringEnum(['tombstone']),
      record: tombstoneRecordFragment,
    }),
  ],
};

const restoreSessionCommonProperties = {
  _id: sha256DigestFragment,
  restoreSessionId: sha256DigestFragment,
  maximumBytes: safeInteger({ minimum: 1, maximum: MAX_SUPPORTED_BACKUP_BYTES }),
  maximumRecords: safeInteger({
    minimum: 1,
    maximum: DEFAULT_MAX_BACKUP_RECORDS,
  }),
  stagedBytes: safeInteger({ minimum: 0, maximum: MAX_SUPPORTED_BACKUP_BYTES }),
  stagedRecords: safeInteger({
    minimum: 0,
    maximum: DEFAULT_MAX_BACKUP_RECORDS,
  }),
  createdAt: canonicalTimestampFragment,
  updatedAt: canonicalTimestampFragment,
  vaultId: opaqueIdentifierFragment,
} satisfies Readonly<Record<string, MongoJsonSchema>>;
const restoreSessionCommonRequired = [
  '_id',
  'restoreSessionId',
  'maximumBytes',
  'maximumRecords',
  'state',
  'stagedBytes',
  'stagedRecords',
  'createdAt',
  'updatedAt',
] as const;
const backupRestoreSessionFragment: MongoJsonSchema = {
  oneOf: [
    strictObject(restoreSessionCommonRequired, {
      ...restoreSessionCommonProperties,
      state: stringEnum(['staging']),
    }),
    strictObject(
      [
        ...restoreSessionCommonRequired,
        'vaultId',
        'transcriptSha256',
        'summaryRecordCount',
        'committedAt',
      ],
      {
        ...restoreSessionCommonProperties,
        state: stringEnum(['committed']),
        transcriptSha256: sha256DigestFragment,
        summaryRecordCount: safeInteger({
          minimum: 1,
          maximum: DEFAULT_MAX_BACKUP_RECORDS,
        }),
        committedAt: canonicalTimestampFragment,
      },
    ),
    strictObject([...restoreSessionCommonRequired, 'abortedAt'], {
      ...restoreSessionCommonProperties,
      state: stringEnum(['aborted']),
      abortedAt: canonicalTimestampFragment,
    }),
  ],
};

const backupRestoreEntryFragment = strictObject(
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
    _id: boundedRestoreStringFragment,
    restoreSessionId: sha256DigestFragment,
    ordinal: safeInteger({
      minimum: 0,
      maximum: DEFAULT_MAX_BACKUP_RECORDS - 1,
    }),
    identity: boundedRestoreStringFragment,
    entryHash: sha256HexFragment,
    vaultId: opaqueIdentifierFragment,
    bytes: safeInteger({ minimum: 1, maximum: MAX_MONGO_RESTORE_ENTRY_BYTES }),
    entry: backupEntryFragment,
  },
);

function validator(schema: MongoJsonSchema): CreateCollectionOptions {
  return {
    validator: { $jsonSchema: schema as Document },
    validationLevel: 'strict',
    validationAction: 'error',
  };
}

const syncPushBatchCommonProperties = {
  _id: nonEmptyStringFragment,
  vaultId: opaqueIdentifierFragment,
  batchIdempotencyKey: idempotencyKeyFragment,
  requestHash: sha256HexFragment,
  mutationCount: safeInteger({ minimum: 1, maximum: MAX_SYNC_PUSH_MUTATIONS }),
  nextMutationIndex: safeInteger({ minimum: 0, maximum: MAX_SYNC_PUSH_MUTATIONS }),
  createdAt: canonicalTimestampFragment,
  updatedAt: canonicalTimestampFragment,
} satisfies Readonly<Record<string, MongoJsonSchema>>;
const syncPushBatchCommonRequired = [
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
] as const;

export const mongoStorageCollectionOptions: Readonly<
  Record<MongoStorageCollectionName, CreateCollectionOptions>
> = {
  vaults: validator(
    strictObject(['_id', 'vaultId', 'record'], {
      _id: opaqueIdentifierFragment,
      vaultId: opaqueIdentifierFragment,
      record: vaultRecordFragment,
    }),
  ),
  groups: validator(
    strictObject(['_id', 'vaultId', 'groupId', 'record'], {
      _id: nonEmptyStringFragment,
      vaultId: opaqueIdentifierFragment,
      groupId: opaqueIdentifierFragment,
      record: groupRecordFragment,
    }),
  ),
  items: validator(
    strictObject(['_id', 'vaultId', 'groupId', 'itemId', 'record'], {
      _id: nonEmptyStringFragment,
      vaultId: opaqueIdentifierFragment,
      groupId: opaqueIdentifierFragment,
      itemId: opaqueIdentifierFragment,
      record: itemRecordFragment,
    }),
  ),
  attachments: validator(
    strictObject(
      ['_id', 'vaultId', 'groupId', 'itemId', 'attachmentId', 'stagingId', 'record'],
      {
        _id: nonEmptyStringFragment,
        vaultId: opaqueIdentifierFragment,
        groupId: opaqueIdentifierFragment,
        itemId: opaqueIdentifierFragment,
        attachmentId: opaqueIdentifierFragment,
        stagingId: nonEmptyStringFragment,
        record: attachmentRecordFragment,
      },
    ),
  ),
  audits: validator(
    strictObject(['_id', 'vaultId', 'auditId', 'record'], {
      _id: nonEmptyStringFragment,
      vaultId: opaqueIdentifierFragment,
      auditId: opaqueIdentifierFragment,
      record: auditRecordFragment,
    }),
  ),
  histories: validator(
    strictObject(['_id', 'vaultId', 'groupId', 'itemId', 'historyId', 'record'], {
      _id: nonEmptyStringFragment,
      vaultId: opaqueIdentifierFragment,
      groupId: opaqueIdentifierFragment,
      itemId: opaqueIdentifierFragment,
      historyId: opaqueIdentifierFragment,
      record: historyRecordFragment,
    }),
  ),
  changes: validator(
    strictObject(['_id', 'vaultId', 'serverSequence', 'record', 'payload'], {
      _id: nonEmptyStringFragment,
      vaultId: opaqueIdentifierFragment,
      serverSequence: positiveSemanticRevisionFragment,
      record: changeRecordFragment,
      payload: opaqueSyncPayloadFragment,
    }),
  ),
  tombstones: validator(
    strictObject(['_id', 'vaultId', 'entityType', 'entityId', 'record'], {
      _id: nonEmptyStringFragment,
      vaultId: opaqueIdentifierFragment,
      entityType: stringEnum(changeEntityTypes),
      entityId: opaqueIdentifierFragment,
      record: tombstoneRecordFragment,
    }),
  ),
  vault_counters: validator(
    strictObject(['_id', 'changeSequence', 'vaultRevision'], {
      _id: opaqueIdentifierFragment,
      changeSequence: nonnegativeSemanticRevisionFragment,
      vaultRevision: nonnegativeSemanticRevisionFragment,
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
        _id: nonEmptyStringFragment,
        vaultId: opaqueIdentifierFragment,
        idempotencyKey: idempotencyKeyFragment,
        inputHash: sha256HexFragment,
        entityType: stringEnum(changeEntityTypes),
        change: changeRecordFragment,
        committedAt: canonicalTimestampFragment,
      },
    ),
  ),
  sync_push_batches: validator({
    oneOf: [
      strictObject(syncPushBatchCommonRequired, {
        ...syncPushBatchCommonProperties,
        state: stringEnum(['running']),
        results: boundedArray(syncPushResultFragment, 0, MAX_SYNC_PUSH_MUTATIONS),
      }),
      strictObject([...syncPushBatchCommonRequired, 'response', 'completedAt'], {
        ...syncPushBatchCommonProperties,
        state: stringEnum(['completed']),
        nextMutationIndex: safeInteger({
          minimum: 1,
          maximum: MAX_SYNC_PUSH_MUTATIONS,
        }),
        results: boundedArray(syncPushResultFragment, 1, MAX_SYNC_PUSH_MUTATIONS),
        response: syncPushResponseFragment,
        completedAt: canonicalTimestampFragment,
      }),
    ],
  }),
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
        _id: nonEmptyStringFragment,
        vaultId: opaqueIdentifierFragment,
        batchIdempotencyKey: idempotencyKeyFragment,
        requestHash: sha256HexFragment,
        response: templateMigrationPublicationResponseFragment,
        committedAt: canonicalTimestampFragment,
      },
    ),
  ),
  attachment_staging: validator(attachmentStagingFragment),
  attachment_staging_chunks: validator(
    strictObject(
      ['_id', 'stagingId', 'vaultId', 'attachmentId', 'chunkIndex', 'record'],
      {
        _id: nonEmptyStringFragment,
        stagingId: nonEmptyStringFragment,
        vaultId: opaqueIdentifierFragment,
        attachmentId: opaqueIdentifierFragment,
        chunkIndex: safeInteger({
          minimum: 0,
          maximum: MAX_ATTACHMENT_CHUNKS - 1,
        }),
        record: persistedAttachmentChunkFragment,
      },
    ),
  ),
  backup_restore_sessions: validator(backupRestoreSessionFragment),
  backup_restore_entries: validator(backupRestoreEntryFragment),
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
