import { describe, expect, it } from 'vitest';

import {
  fieldDefinitionSchema,
  groupIdSchema,
  groupPayloadSchema,
  itemPayloadSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
  vaultIdSchema,
  type GroupPayload,
  type ItemPayload,
  type TransferWithholding,
} from '@kavrix/schemas';

import {
  BackupError,
  createEncryptedTransfer,
  readEncryptedTransfer,
  resolveTransferLimits,
  type TransferDocument,
} from '../src/index.js';

const CREATED_AT = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const VAULT_ID = vaultIdSchema.parse('vault-1');
const OTHER_VAULT_ID = vaultIdSchema.parse('vault-2');
const GROUP_ID = groupIdSchema.parse('group-1');
const SCHEMA_VERSION = supportedSchemaVersionSchema.parse(1);
const PASSPHRASE = Buffer.from('correct horse battery staple', 'utf8');
const WRONG_PASSPHRASE = Buffer.from('correct horse battery stapler', 'utf8');
const SECRET_CANARY = 'KAVRIX-TRANSFER-PLAINTEXT-CANARY';

/**
 * Argon2id at the canonical minimums is deliberately slow, so every test shares
 * one derivation rather than paying for it per call. The parameters still travel
 * in the header and are still reproduced by the reader from the file alone.
 */
const LIMITS = { maximumDocuments: 8 } as const;

describe('encrypted transfer streaming format', () => {
  it('round-trips group and item documents losslessly', async () => {
    const group = buildGroup();
    const item = buildItem();

    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents(
            { kind: 'group', group },
            { kind: 'item', item, withheld: [] },
          ),
        },
        PASSPHRASE,
      ),
    );

    const result = await readEncryptedTransfer(chunks(bytes), PASSPHRASE);

    expect(result.header.format).toBe('kavrix-encrypted-transfer');
    expect(result.header.vaultId).toBe(VAULT_ID);
    expect(result.header.createdAt).toBe(CREATED_AT);
    expect(result.groups).toStrictEqual([group]);
    expect(result.items).toStrictEqual([{ item, withheld: [] }]);
  });

  it('carries a withholding manifest alongside the item it describes', async () => {
    const withheld: readonly TransferWithholding[] = [
      { stableKey: 'master_key', scope: 'template', reason: 'export-policy' },
      { stableKey: 'contract', scope: 'item', reason: 'attachment-unsupported' },
    ];

    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents({ kind: 'item', item: buildItem(), withheld }),
        },
        PASSPHRASE,
      ),
    );

    const result = await readEncryptedTransfer(chunks(bytes), PASSPHRASE);

    expect(result.items[0]?.withheld).toStrictEqual(withheld);
  });

  it('never emits a document value in plaintext', async () => {
    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents({
            kind: 'item',
            item: buildItem({ title: SECRET_CANARY }),
            withheld: [],
          }),
        },
        PASSPHRASE,
      ),
    );

    expect(bytes.toString('utf8')).not.toContain(SECRET_CANARY);
    expect(bytes.toString('utf8')).not.toContain('db.internal.invalid');
    // The passphrase itself must never be echoed into the file it protects.
    expect(bytes.toString('utf8')).not.toContain(PASSPHRASE.toString('utf8'));
  });

  it('refuses a transfer whose passphrase does not match', async () => {
    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents({ kind: 'group', group: buildGroup() }),
        },
        PASSPHRASE,
      ),
    );

    await expect(
      readEncryptedTransfer(chunks(bytes), WRONG_PASSPHRASE),
    ).rejects.toThrow(
      expect.objectContaining({ code: 'BACKUP_AUTHENTICATION_FAILED' }) as Error,
    );
  });

  it('rejects a document whose ciphertext was altered', async () => {
    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents({ kind: 'group', group: buildGroup() }),
        },
        PASSPHRASE,
      ),
    );
    const lines = splitLines(bytes);
    const entry = JSON.parse(lines[1] ?? '') as {
      envelope: { ciphertext: string };
    };
    entry.envelope.ciphertext = flipLastBase64UrlCharacter(entry.envelope.ciphertext);
    lines[1] = JSON.stringify(entry);

    await expect(
      readEncryptedTransfer(chunks(joinLines(lines)), PASSPHRASE),
    ).rejects.toThrow(
      expect.objectContaining({ code: 'BACKUP_AUTHENTICATION_FAILED' }) as Error,
    );
  });

  it('rejects a transfer whose documents were reordered', async () => {
    const first = buildItem();
    const second = buildItem({ id: 'item-2', title: 'Replica DB' });
    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents(
            { kind: 'item', item: first, withheld: [] },
            { kind: 'item', item: second, withheld: [] },
          ),
        },
        PASSPHRASE,
      ),
    );
    const lines = splitLines(bytes);
    const [header, one, two, footer] = lines;

    await expect(
      readEncryptedTransfer(
        chunks(joinLines([header ?? '', two ?? '', one ?? '', footer ?? ''])),
        PASSPHRASE,
      ),
    ).rejects.toThrow(
      expect.objectContaining({ code: 'BACKUP_AUTHENTICATION_FAILED' }) as Error,
    );
  });

  it('rejects a truncated transfer before returning any document', async () => {
    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents({ kind: 'group', group: buildGroup() }),
        },
        PASSPHRASE,
      ),
    );
    const lines = splitLines(bytes);

    await expect(
      readEncryptedTransfer(chunks(joinLines(lines.slice(0, -1))), PASSPHRASE),
    ).rejects.toThrow(expect.objectContaining({ code: 'BACKUP_INCOMPLETE' }) as Error);
  });

  it('rejects a transfer whose footer under-counts its documents', async () => {
    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents({ kind: 'group', group: buildGroup() }),
        },
        PASSPHRASE,
      ),
    );
    const lines = splitLines(bytes);
    const footer = JSON.parse(lines[lines.length - 1] ?? '') as { groupCount: number };
    footer.groupCount = 0;
    lines[lines.length - 1] = JSON.stringify(footer);

    await expect(
      readEncryptedTransfer(chunks(joinLines(lines)), PASSPHRASE),
    ).rejects.toThrow(expect.objectContaining({ code: 'BACKUP_INVALID' }) as Error);
  });

  it('rejects data appended after the footer', async () => {
    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents({ kind: 'group', group: buildGroup() }),
        },
        PASSPHRASE,
      ),
    );
    const lines = splitLines(bytes);
    lines.push(lines[1] ?? '');

    await expect(
      readEncryptedTransfer(chunks(joinLines(lines)), PASSPHRASE),
    ).rejects.toThrow(expect.objectContaining({ code: 'BACKUP_INVALID' }) as Error);
  });

  it('rejects a malformed line before deriving anything from it', async () => {
    await expect(
      readEncryptedTransfer(chunks(Buffer.from('not json\n', 'utf8')), PASSPHRASE),
    ).rejects.toThrow(expect.objectContaining({ code: 'BACKUP_INVALID' }) as Error);
  });

  it('rejects an empty source as incomplete', async () => {
    await expect(
      readEncryptedTransfer(chunks(Buffer.alloc(0)), PASSPHRASE),
    ).rejects.toThrow(expect.objectContaining({ code: 'BACKUP_INCOMPLETE' }) as Error);
  });

  it('refuses to write more documents than the declared limit allows', async () => {
    const source = createEncryptedTransfer(
      {
        vaultId: VAULT_ID,
        schemaVersion: SCHEMA_VERSION,
        createdAt: CREATED_AT,
        limits: { maximumDocuments: 1 },
        documents: documents(
          { kind: 'group', group: buildGroup() },
          { kind: 'group', group: buildGroup({ id: 'group-2', name: 'Cache' }) },
        ),
      },
      PASSPHRASE,
    );

    await expect(collect(source)).rejects.toThrow(
      expect.objectContaining({ code: 'BACKUP_TOO_LARGE' }) as Error,
    );
  });

  it('refuses to write beyond the declared aggregate byte limit', async () => {
    const source = createEncryptedTransfer(
      {
        vaultId: VAULT_ID,
        schemaVersion: SCHEMA_VERSION,
        createdAt: CREATED_AT,
        limits: { maximumBytes: 256 },
        documents: documents({ kind: 'group', group: buildGroup() }),
      },
      PASSPHRASE,
    );

    await expect(collect(source)).rejects.toThrow(
      expect.objectContaining({ code: 'BACKUP_TOO_LARGE' }) as Error,
    );
  });

  it('refuses to read a source larger than the declared byte limit', async () => {
    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents({ kind: 'group', group: buildGroup() }),
        },
        PASSPHRASE,
      ),
    );

    await expect(
      readEncryptedTransfer(chunks(bytes), PASSPHRASE, { maximumBytes: 128 }),
    ).rejects.toThrow(BackupError);
  });

  it('refuses to seal a document belonging to another vault', async () => {
    const source = createEncryptedTransfer(
      {
        vaultId: VAULT_ID,
        schemaVersion: SCHEMA_VERSION,
        createdAt: CREATED_AT,
        documents: documents({
          kind: 'group',
          group: buildGroup({ vaultId: OTHER_VAULT_ID }),
        }),
      },
      PASSPHRASE,
    );

    await expect(collect(source)).rejects.toThrow(
      expect.objectContaining({ code: 'BACKUP_WRONG_VAULT' }) as Error,
    );
  });

  it('rejects a document relabelled with another document identity', async () => {
    const bytes = await collect(
      createEncryptedTransfer(
        {
          vaultId: VAULT_ID,
          schemaVersion: SCHEMA_VERSION,
          createdAt: CREATED_AT,
          documents: documents(
            { kind: 'group', group: buildGroup() },
            { kind: 'group', group: buildGroup({ id: 'group-2', name: 'Cache' }) },
          ),
        },
        PASSPHRASE,
      ),
    );
    const lines = splitLines(bytes);
    const [header, one, two, footer] = lines;
    const first = JSON.parse(one ?? '') as { groupId: string };
    const second = JSON.parse(two ?? '') as { envelope: unknown };
    // Keep the first entry's label but graft the second entry's ciphertext onto it.
    const forged = JSON.stringify({ ...first, envelope: second.envelope });

    await expect(
      readEncryptedTransfer(
        chunks(joinLines([header ?? '', forged, two ?? '', footer ?? ''])),
        PASSPHRASE,
      ),
    ).rejects.toThrow(
      expect.objectContaining({ code: 'BACKUP_AUTHENTICATION_FAILED' }) as Error,
    );
  });

  it('resolves declared limits and rejects unsupported ones', () => {
    expect(resolveTransferLimits(LIMITS).maximumDocuments).toBe(8);
    expect(resolveTransferLimits(undefined).maximumDocuments).toBeGreaterThan(0);
    expect(() => resolveTransferLimits({ maximumBytes: 0 })).toThrow(RangeError);
    expect(() => resolveTransferLimits({ maximumDocuments: 0 })).toThrow(RangeError);
    expect(() => resolveTransferLimits({ maximumBytes: 2 ** 60 })).toThrow(RangeError);
    expect(() => resolveTransferLimits({ maximumDocuments: 10 ** 9 })).toThrow(
      RangeError,
    );
  });
});

function buildGroup(overrides: Record<string, unknown> = {}): GroupPayload {
  return groupPayloadSchema.parse({
    id: GROUP_ID,
    vaultId: VAULT_ID,
    name: 'Databases',
    aliases: [],
    tags: [],
    notes: [],
    template: buildTemplate(),
    sortOrder: 0,
    revision: 1,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
    ...overrides,
  });
}

function buildTemplate(): Record<string, unknown> {
  return {
    id: 'template.database',
    name: 'Database',
    version: 1,
    fields: [
      fieldDefinitionSchema.parse({
        id: 'field.hostname',
        stableKey: 'hostname',
        label: 'Hostname',
        type: 'text',
        required: false,
        sensitive: false,
        repeatable: false,
        copyable: true,
        searchableLocally: true,
        showInPreview: true,
        copyPolicy: 'allowed',
        revealPolicy: 'never',
        reauthenticationPolicy: 'never',
        exportPolicy: 'encrypted-only',
        sortOrder: 0,
        createdAt: CREATED_AT,
        updatedAt: CREATED_AT,
      }),
    ],
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
}

function buildItem(overrides: Record<string, unknown> = {}): ItemPayload {
  return itemPayloadSchema.parse({
    version: 1,
    id: 'item-1',
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    templateId: 'template.database',
    templateVersion: 1,
    title: 'Primary DB',
    aliases: [],
    templateValues: [
      {
        fieldId: 'field.hostname',
        stableKey: 'hostname',
        value: {
          version: 1,
          state: 'present',
          content: {
            cardinality: 'single',
            value: { kind: 'text', value: 'db.internal.invalid' },
          },
        },
        updatedAt: CREATED_AT,
      },
    ],
    itemFields: [],
    itemValues: [],
    archivedFieldValues: [],
    notes: [],
    tags: [],
    favorite: false,
    productionSensitive: false,
    relatedItemIds: [],
    attachmentIds: [],
    copySequences: [],
    revision: 1,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
    ...overrides,
  });
}

function documents(
  ...values: readonly TransferDocument[]
): AsyncIterable<TransferDocument> {
  return asyncIterable(values);
}

async function collect(source: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const values: Uint8Array[] = [];
  for await (const value of source) {
    values.push(Uint8Array.from(value));
  }
  return Buffer.concat(values);
}

function splitLines(value: Buffer): string[] {
  return value
    .toString('utf8')
    .split('\n')
    .filter((line) => line.length > 0);
}

function joinLines(lines: readonly string[]): Buffer {
  return Buffer.from(`${lines.join('\n')}\n`, 'utf8');
}

function flipLastBase64UrlCharacter(value: string): string {
  const last = value.slice(-1);
  return `${value.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`;
}

function chunks(
  value: Uint8Array,
  chunkSize = Math.max(1, value.byteLength),
): AsyncIterable<Uint8Array> {
  const values: Uint8Array[] = [];
  for (let offset = 0; offset < value.byteLength; offset += chunkSize) {
    values.push(value.subarray(offset, Math.min(offset + chunkSize, value.byteLength)));
  }
  return asyncIterable(values);
}

function asyncIterable<Value>(values: readonly Value[]): AsyncIterable<Value> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Value> {
      let index = 0;
      return {
        next(): Promise<IteratorResult<Value>> {
          const value = values[index];
          index += 1;
          return Promise.resolve(
            value === undefined
              ? { done: true, value: undefined }
              : { done: false, value },
          );
        },
      };
    },
  };
}
