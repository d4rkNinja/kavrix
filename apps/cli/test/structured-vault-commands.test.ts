import { Command } from 'commander';
import {
  FileEncryptedDatabaseStore,
  MongoEncryptedDatabaseStore,
} from '@kavrix/storage';
import { describe, expect, it, vi } from 'vitest';

import {
  aeadEnvelopeSchema,
  encryptedAttachmentRecordSchema,
  encryptedHistoryRecordSchema,
  fieldValueSchema,
  historyIdSchema,
  sha256DigestSchema,
  structuredVaultPayloadSchema,
  timestampSchema,
  vaultIdSchema,
} from '@kavrix/schemas';

import {
  DEFAULT_PROJECT_CONTEXT_NAME,
  DEFAULT_SERVICE_NAME,
  assertStructuredFieldRevealAllowed,
  createProjectContext,
  createStructuredItem,
  createStructuredService,
  displayStructuredFieldValue,
  encodeStructuredFieldValueBase64,
  projectStructuredField,
  redactStructuredFieldValue,
  registerStructuredVaultCommands,
  removeProjectContext,
  removeStructuredField,
  removeStructuredItem,
  removeStructuredService,
  renameProjectContext,
  renameStructuredItem,
  renameStructuredService,
  resolveItem,
  resolveProjectContext,
  resolveService,
  setStructuredField,
  structuredRoutingOverrides,
} from '../src/structured-vault-commands.js';
import {
  createEmptyStructuredVaultPayload,
  projectFlatVaultPayload,
} from '../src/structured-vault-projection.js';
import { buildLocalCli } from '../src/local-vault-cli.js';
import { DatabaseSession } from '../src/database-session.js';
import { DatastoreProfileRegistry } from '../src/datastore-profiles.js';
import { LocalSecretInput } from '../src/local-secrets.js';
import { STDIN_FRAME_CONTRACTS } from '../src/stdin-frames.js';

const at = timestampSchema.parse('2026-08-29T00:00:00.000Z');

function emptyPayload() {
  return createEmptyStructuredVaultPayload(vaultIdSchema.parse('vault.test'), at);
}

function projectPayload() {
  let payload = emptyPayload();
  payload = createProjectContext(payload, 'Project/Production', 'production', at);
  payload = createStructuredService(payload, 'Project/Production', 'api/v1', at);
  payload = createStructuredItem(
    payload,
    'Project/Production',
    'api/v1',
    'database/prod',
    at,
  );
  return payload;
}

function fieldPayload() {
  let payload = projectPayload();
  const fields = [
    ['username', 'username', 'alice'],
    ['password', 'password', 'correct horse battery staple'],
    ['api-key', 'api-key', 'key-value'],
    ['url', 'url', 'https://example.com'],
    ['certificate', 'certificate', 'certificate-data'],
    ['totp', 'totp-seed', 'totp-seed-value'],
    ['recovery', 'recovery-code', 'recovery-code'],
    ['document', 'json', '{"region":"eu"}'],
    ['environment', 'environment-map', 'API_TOKEN=token-value'],
  ] as const;
  for (const [name, type, rawValue] of fields) {
    payload = setStructuredField(
      payload,
      'Project/Production',
      'api/v1',
      'database/prod',
      { name, type, rawValue, now: at },
    );
  }
  return payload;
}

function envelope(
  entityType: 'attachment' | 'wrapped-attachment-key' | 'history',
  entityId: string,
  vaultId: string,
  groupId: string,
  itemId: string,
) {
  return aeadEnvelopeSchema.parse({
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType,
      entityId,
      groupId,
      parentId: itemId,
      purpose:
        entityType === 'attachment'
          ? 'attachment-metadata'
          : entityType === 'history'
            ? 'history-event'
            : 'attachment-key',
    },
    keyVersion: 1,
  });
}

describe('structured vault command model', () => {
  it('documents every structured protected-input frame contract', () => {
    for (const command of [
      'context create',
      'context list',
      'context rename',
      'context remove',
      'service create',
      'service list',
      'service rename',
      'service remove',
      'item create',
      'item list',
      'item show',
      'item rename',
      'item remove',
      'field set',
      'field list',
      'field get',
      'field remove',
    ]) {
      expect(STDIN_FRAME_CONTRACTS[command], command).toBeDefined();
    }
    expect(STDIN_FRAME_CONTRACTS['field set']).toContain('value');
  });

  it('registers one command for each alias pair', () => {
    const program = new Command();
    registerStructuredVaultCommands(program);
    const aliases = new Map(
      program.commands.map((command) => [command.name(), command.aliases()]),
    );
    expect(aliases.get('context')).toContain('environment');
    expect(aliases.get('service')).toContain('group');
    expect(aliases.get('item')).toContain('credential');
  });

  it('maps explicit routing flags to the shared database profile override contract', () => {
    expect(structuredRoutingOverrides({})).toEqual({});
    expect(
      structuredRoutingOverrides({
        datastore: 'file',
        dataFile: './structured.database',
        database: 'credentials',
        collection: 'vaults',
        keyFile: './structured.key',
      }),
    ).toEqual({
      datastore: 'file',
      dataFile: './structured.database',
      database: 'credentials',
      vaultCollection: 'vaults',
      keyFile: './structured.key',
    });
    expect(() => structuredRoutingOverrides({ datastore: 'other' })).toThrow(
      '--datastore must be mongodb or file.',
    );
  });

  it('creates a hierarchy while preserving exact path-like names', () => {
    const payload = projectPayload();
    const context = resolveProjectContext(payload, 'Project/Production');
    const group = resolveService(payload, context.id, 'api/v1');
    expect(context.name).toBe('Project/Production');
    expect(group.name).toBe('api/v1');
    expect(payload.items[0]?.title).toBe('database/prod');
    expect(payload.projectContexts[0]?.name).toBe(DEFAULT_PROJECT_CONTEXT_NAME);
    expect(payload.groups[0]?.name).toBe(DEFAULT_SERVICE_NAME);
    expect(structuredVaultPayloadSchema.safeParse(payload).success).toBe(true);
  });

  it('accepts the requested typed fields and applies schema-driven policy defaults', () => {
    const payload = fieldPayload();
    const item = payload.items.find((candidate) => candidate.title === 'database/prod');
    expect(item).toBeDefined();
    const fields = item?.itemFields ?? [];
    expect(fields.map((field) => field.type)).toEqual([
      'username',
      'password',
      'api-key',
      'url',
      'certificate',
      'totp-secret',
      'recovery-code-list',
      'json',
      'environment-map',
    ]);
    const password = fields.find((field) => field.label === 'password');
    const username = fields.find((field) => field.label === 'username');
    const environment = fields.find((field) => field.label === 'environment');
    expect(password).toMatchObject({
      sensitive: true,
      copyPolicy: 'confirm',
      revealPolicy: 'timed',
      reauthenticationPolicy: 'after-lock',
      exportPolicy: 'guarded',
    });
    expect(username).toMatchObject({
      sensitive: false,
      copyPolicy: 'allowed',
      revealPolicy: 'never',
      reauthenticationPolicy: 'never',
      exportPolicy: 'encrypted-only',
    });
    expect(environment).toMatchObject({ sensitive: true, type: 'environment-map' });
    const environmentId = environment?.id;
    const environmentValue = item?.itemValues.find(
      (stored) => stored.fieldId === environmentId,
    )?.value;
    expect(environmentValue).toMatchObject({
      state: 'present',
      content: {
        cardinality: 'multiple',
        elements: [
          {
            value: {
              kind: 'environment-entry',
              key: 'API_TOKEN',
              value: { classification: 'secret', value: 'token-value' },
            },
          },
        ],
      },
    });
    expect(structuredVaultPayloadSchema.safeParse(payload).success).toBe(true);
  });

  it('redacts field reads by default and refuses reveal when policy is never', () => {
    const payload = fieldPayload();
    const item = payload.items.find((candidate) => candidate.title === 'database/prod');
    if (item === undefined) throw new Error('fixture item missing');
    expect(redactStructuredFieldValue(item, 'password')).toBe('[REDACTED]');
    expect(redactStructuredFieldValue(item, 'username')).toBe('[REDACTED]');
    const serializedSafeReads = JSON.stringify({
      list: item.itemFields.map((field) => ({
        name: field.label,
        type: field.type,
        policy: field.revealPolicy,
        value: redactStructuredFieldValue(item, field.label),
      })),
      show: item.itemFields.map((field) => ({
        name: field.label,
        state: item.itemValues.find((entry) => entry.fieldId === field.id)?.value.state,
        value: redactStructuredFieldValue(item, field.label),
      })),
      get: { name: 'password', value: redactStructuredFieldValue(item, 'password') },
    });
    expect(serializedSafeReads).not.toContain('correct horse battery staple');
    const username = item.itemFields.find((field) => field.label === 'username');
    if (username === undefined) throw new Error('fixture field missing');
    expect(() => assertStructuredFieldRevealAllowed(username)).toThrow(
      'Field reveal is disabled by its schema policy.',
    );
  });

  it('renders public fields and base64-transports authorized multiline values', () => {
    let payload = fieldPayload();
    payload = setStructuredField(
      payload,
      'Project/Production',
      'api/v1',
      'database/prod',
      { name: 'certificate', type: 'certificate', rawValue: 'BEGIN\nEND', now: at },
    );
    payload = setStructuredField(
      payload,
      'Project/Production',
      'api/v1',
      'database/prod',
      { name: 'recovery', type: 'recovery-code', rawValue: 'one\ntwo', now: at },
    );
    const item = payload.items.find((entry) => entry.title === 'database/prod');
    if (item === undefined) throw new Error('fixture item missing');

    expect(displayStructuredFieldValue(item, 'username')).toBe('alice');
    expect(displayStructuredFieldValue(item, 'document')).toBe('{"region":"eu"}');
    expect(displayStructuredFieldValue(item, 'certificate')).toBe('BEGIN\nEND');
    expect(displayStructuredFieldValue(item, 'password')).toBe('[REDACTED]');

    const recovery = projectStructuredField(item, 'recovery').value;
    if (recovery === undefined) throw new Error('fixture field missing');
    expect(
      Buffer.from(encodeStructuredFieldValueBase64(recovery), 'base64').toString(
        'utf8',
      ),
    ).toBe('one\ntwo');
  });

  it('renders every scalar transport and rejects non-present transports', () => {
    const present = (value: unknown) =>
      fieldValueSchema.parse({
        version: 1,
        state: 'present',
        content: { cardinality: 'single', value },
      });
    expect(
      Buffer.from(
        encodeStructuredFieldValueBase64(present({ kind: 'number', value: 5432 })),
        'base64',
      ).toString('utf8'),
    ).toBe('5432');
    expect(
      Buffer.from(
        encodeStructuredFieldValueBase64(present({ kind: 'boolean', value: true })),
        'base64',
      ).toString('utf8'),
    ).toBe('true');
    expect(
      Buffer.from(
        encodeStructuredFieldValueBase64(
          present({ kind: 'item-reference', itemId: 'item.reference' }),
        ),
        'base64',
      ).toString('utf8'),
    ).toBe('item:item.reference');
    expect(
      Buffer.from(
        encodeStructuredFieldValueBase64(
          present({
            kind: 'attachment-reference',
            attachmentId: 'attachment.reference',
          }),
        ),
        'base64',
      ).toString('utf8'),
    ).toBe('attachment:attachment.reference');
    expect(() =>
      encodeStructuredFieldValueBase64(
        fieldValueSchema.parse({ version: 1, state: 'empty' }),
      ),
    ).toThrow('no readable value');
  });

  it('keeps the reserved default hierarchy valid for every flat root command', () => {
    let payload = createStructuredItem(
      emptyPayload(),
      DEFAULT_PROJECT_CONTEXT_NAME,
      DEFAULT_SERVICE_NAME,
      'literal/path',
      at,
    );
    expect(projectFlatVaultPayload(payload)).toEqual({
      records: { 'literal/path': { value: '', updatedAt: at } },
    });
    expect(() =>
      removeStructuredField(
        payload,
        DEFAULT_PROJECT_CONTEXT_NAME,
        DEFAULT_SERVICE_NAME,
        'literal/path',
        'value',
        at,
      ),
    ).toThrow('reserved for flat-command compatibility');
    expect(() =>
      renameProjectContext(payload, DEFAULT_PROJECT_CONTEXT_NAME, 'Renamed', at),
    ).toThrow('reserved for flat-command compatibility');
    expect(() =>
      renameStructuredService(
        payload,
        DEFAULT_PROJECT_CONTEXT_NAME,
        DEFAULT_SERVICE_NAME,
        'Renamed',
        at,
      ),
    ).toThrow('reserved for flat-command compatibility');

    payload = removeStructuredItem(
      payload,
      DEFAULT_PROJECT_CONTEXT_NAME,
      DEFAULT_SERVICE_NAME,
      'literal/path',
      at,
    );
    expect(() =>
      removeStructuredService(
        payload,
        DEFAULT_PROJECT_CONTEXT_NAME,
        DEFAULT_SERVICE_NAME,
      ),
    ).toThrow('reserved for flat-command compatibility');
    expect(() => removeProjectContext(payload, DEFAULT_PROJECT_CONTEXT_NAME)).toThrow(
      'reserved for flat-command compatibility',
    );
  });

  it('rejects contradictory field classification flags', () => {
    expect(() =>
      setStructuredField(
        projectPayload(),
        'Project/Production',
        'api/v1',
        'database/prod',
        {
          name: 'conflict',
          type: 'text',
          rawValue: 'value',
          sensitive: true,
          publicValue: true,
          now: at,
        },
      ),
    ).toThrow('both sensitive and public');
  });

  it('fails closed on invalid hierarchy transitions and malformed typed values', () => {
    const empty = emptyPayload();
    expect(() => createProjectContext(empty, '')).toThrow('name is invalid');
    expect(() => createProjectContext(empty, 'bad\u0000name')).toThrow(
      'name is invalid',
    );
    expect(() => createProjectContext(empty, 'x'.repeat(257))).toThrow(
      'name is invalid',
    );
    expect(() => createProjectContext(empty, 'invalid-env', '')).toThrow(
      'Environment name is invalid',
    );
    expect(() => resolveProjectContext(empty, 'missing')).toThrow('was not found');

    let payload = createProjectContext(empty, 'one', undefined, at);
    payload = createProjectContext(payload, 'two', 'test', at);
    expect(() => createProjectContext(payload, 'one', undefined, at)).toThrow(
      'already exists',
    );
    expect(() => renameProjectContext(payload, 'one', 'two', at)).toThrow(
      'already exists',
    );
    expect(() => resolveService(payload, 'missing-context', 'service')).toThrow(
      'was not found',
    );

    payload = createStructuredService(payload, 'one', 'first', at);
    payload = createStructuredService(payload, 'one', 'second', at);
    expect(() => createStructuredService(payload, 'one', 'first', at)).toThrow(
      'already exists',
    );
    expect(() =>
      renameStructuredService(payload, 'one', 'first', 'second', at),
    ).toThrow('already exists');
    const first = resolveService(
      payload,
      resolveProjectContext(payload, 'one').id,
      'first',
    );
    expect(() => resolveItem(payload, first.id, 'missing')).toThrow('was not found');

    payload = createStructuredItem(payload, 'one', 'first', 'alpha', at);
    payload = createStructuredItem(payload, 'one', 'first', 'beta', at);
    expect(() => createStructuredItem(payload, 'one', 'first', 'alpha', at)).toThrow(
      'already exists',
    );
    expect(() =>
      renameStructuredItem(payload, 'one', 'first', 'alpha', 'beta', at),
    ).toThrow('already exists');
    expect(() =>
      projectStructuredField(resolveItem(payload, first.id, 'alpha'), 'missing'),
    ).toThrow('Field was not found');

    const invalid = (name: string, type: string, rawValue: string) =>
      setStructuredField(payload, 'one', 'first', 'alpha', {
        name,
        type,
        rawValue,
        now: at,
      });
    expect(() => invalid('unsupported', 'unsupported', 'value')).toThrow(
      'Unsupported field type',
    );
    expect(() => invalid('empty', 'text', '')).toThrow('Field value is empty');
    expect(() => invalid('number', 'number', 'NaN')).toThrow(
      'Numeric field value is invalid',
    );
    expect(() => invalid('boolean', 'boolean', 'yes')).toThrow(
      'Boolean field values must be true or false',
    );
    expect(() => invalid('environment', 'environment-map', 'MISSING')).toThrow(
      'KEY=VALUE',
    );
    expect(() => invalid('environment', 'environment-map', ' KEY=value')).toThrow(
      'non-empty keys and values',
    );
    expect(() => invalid('recovery', 'recovery-code', 'one\n')).toThrow(
      'cannot contain empty entries',
    );
    expect(() => invalid('attachment', 'attachment', 'attachment-id')).toThrow(
      'dedicated encrypted records',
    );
    expect(() => invalid('reference', 'item-reference', 'item-id')).toThrow(
      'dedicated encrypted records',
    );
    expect(() => invalid('select', 'select', 'choice')).toThrow(
      'Select fields require at least one option',
    );
    expect(() =>
      setStructuredField(payload, 'one', 'first', 'alpha', {
        name: 'password',
        type: 'password',
        rawValue: 'secret',
        publicValue: true,
        now: at,
      }),
    ).toThrow('cannot be public');

    payload = invalid('number', 'number', '42');
    payload = setStructuredField(payload, 'one', 'first', 'alpha', {
      name: 'boolean',
      type: 'boolean',
      rawValue: 'false',
      now: at,
    });
    payload = setStructuredField(payload, 'one', 'first', 'alpha', {
      name: 'number',
      type: 'number',
      rawValue: '43',
      now: at,
    });
    payload = setStructuredField(payload, 'one', 'first', 'alpha', {
      name: 'boolean',
      type: 'boolean',
      rawValue: 'true',
      now: at,
    });
    payload = setStructuredField(payload, 'one', 'first', 'alpha', {
      name: 'Display Name',
      type: 'text',
      rawValue: 'display',
      now: at,
    });
    payload = setStructuredField(payload, 'one', 'first', 'alpha', {
      name: 'public-environment',
      type: 'environment-map',
      rawValue: 'REGION=eu\nPORT=5432',
      publicValue: true,
      now: at,
    });
    const alpha = resolveItem(payload, first.id, 'alpha');
    expect(displayStructuredFieldValue(alpha, 'number')).toBe('43');
    expect(displayStructuredFieldValue(alpha, 'boolean')).toBe('true');
    expect(displayStructuredFieldValue(alpha, 'public-environment')).toBe(
      'REGION=eu\nPORT=5432',
    );
    expect(() => invalid('number', 'text', '42')).toThrow(
      'Field type cannot change in place',
    );
    expect(() =>
      setStructuredField(payload, 'one', 'first', 'alpha', {
        name: 'number',
        type: 'number',
        rawValue: '42',
        sensitive: true,
        now: at,
      }),
    ).toThrow('Field sensitivity cannot change in place');

    const number = projectStructuredField(alpha, 'number').definition;
    const withoutNumberValue = structuredVaultPayloadSchema.parse({
      ...payload,
      items: payload.items.map((entry) =>
        entry.id === alpha.id
          ? {
              ...entry,
              itemValues: entry.itemValues.filter(
                (stored) => stored.fieldId !== number.id,
              ),
            }
          : entry,
      ),
    });
    const alphaWithoutNumber = resolveItem(withoutNumberValue, first.id, 'alpha');
    expect(redactStructuredFieldValue(alphaWithoutNumber, 'number')).toBe('[MISSING]');
    expect(displayStructuredFieldValue(alphaWithoutNumber, 'number')).toBe('[MISSING]');
    const archivedMissing = removeStructuredField(
      withoutNumberValue,
      'one',
      'first',
      'alpha',
      'number',
      at,
    );
    expect(
      resolveItem(archivedMissing, first.id, 'alpha').archivedFieldValues.at(-1),
    ).toMatchObject({ value: { originalValue: { state: 'missing' } } });
    const renamed = renameStructuredItem(
      archivedMissing,
      'one',
      'first',
      'alpha',
      'gamma',
      at,
    );
    expect(resolveItem(renamed, first.id, 'gamma').title).toBe('gamma');
  });

  it('rejects non-empty parent removal and removes owned attachment/history records with an item', () => {
    const payload = projectPayload();
    expect(() => removeProjectContext(payload, 'Project/Production')).toThrow(
      'Project context is not empty',
    );
    expect(() =>
      removeStructuredService(payload, 'Project/Production', 'api/v1'),
    ).toThrow('Service is not empty');

    const item = payload.items.find((candidate) => candidate.title === 'database/prod');
    const group = payload.groups.find((candidate) => candidate.name === 'api/v1');
    if (item === undefined || group === undefined)
      throw new Error('fixture hierarchy missing');
    const vaultId = payload.vaultId;
    const attachmentId = 'attachment.owned';
    const historyId = historyIdSchema.parse('history.owned');
    const attachment = encryptedAttachmentRecordSchema.parse({
      id: attachmentId,
      vaultId,
      groupId: group.id,
      itemId: item.id,
      schemaVersion: 1,
      wrappedAttachmentKey: envelope(
        'wrapped-attachment-key',
        attachmentId,
        vaultId,
        group.id,
        item.id,
      ),
      encryptedManifest: envelope(
        'attachment',
        attachmentId,
        vaultId,
        group.id,
        item.id,
      ),
      chunkCount: 1,
      recordRevision: 1,
      createdAt: at,
      updatedAt: at,
    });
    const history = encryptedHistoryRecordSchema.parse({
      id: historyId,
      vaultId,
      groupId: group.id,
      itemId: item.id,
      schemaVersion: 1,
      encryptedPayload: envelope('history', historyId, vaultId, group.id, item.id),
      itemRecordRevision: 1,
      ciphertextHash: sha256DigestSchema.parse(
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      ),
      createdAt: at,
    });
    const withRecords = structuredVaultPayloadSchema.parse({
      ...payload,
      items: payload.items.map((candidate) =>
        candidate.id === item.id
          ? { ...candidate, attachmentIds: [attachmentId] }
          : candidate,
      ),
      attachments: [attachment],
      history: [history],
    });
    const removed = removeStructuredItem(
      withRecords,
      'Project/Production',
      'api/v1',
      'database/prod',
    );
    expect(removed.items.some((candidate) => candidate.id === item.id)).toBe(false);
    expect(removed.attachments).toHaveLength(0);
    expect(removed.history).toHaveLength(0);
    expect(structuredVaultPayloadSchema.safeParse(removed).success).toBe(true);
  });

  it('updates inbound item relationships while leaving unrelated items unchanged', () => {
    let payload = projectPayload();
    payload = createStructuredItem(
      payload,
      'Project/Production',
      'api/v1',
      'related/item',
      at,
    );
    payload = createStructuredItem(
      payload,
      'Project/Production',
      'api/v1',
      'unrelated/item',
      at,
    );
    const removedItem = payload.items.find(
      (candidate) => candidate.title === 'database/prod',
    );
    const relatedItem = payload.items.find(
      (candidate) => candidate.title === 'related/item',
    );
    if (removedItem === undefined || relatedItem === undefined) {
      throw new Error('fixture hierarchy missing');
    }
    const unrelatedItem = payload.items.find(
      (candidate) => candidate.title === 'unrelated/item',
    );
    if (unrelatedItem === undefined) throw new Error('fixture hierarchy missing');
    const linked = structuredVaultPayloadSchema.parse({
      ...payload,
      items: payload.items.map((candidate) =>
        candidate.id === relatedItem.id
          ? { ...candidate, relatedItemIds: [removedItem.id] }
          : candidate,
      ),
    });
    const removed = removeStructuredItem(
      linked,
      'Project/Production',
      'api/v1',
      'database/prod',
      '2026-08-29T00:00:01.000Z',
    );
    const remaining = removed.items.find(
      (candidate) => candidate.id === relatedItem.id,
    );
    const untouched = removed.items.find(
      (candidate) => candidate.id === unrelatedItem.id,
    );
    expect(remaining).toMatchObject({
      relatedItemIds: [],
      revision: 1,
      updatedAt: '2026-08-29T00:00:01.000Z',
    });
    expect(untouched).toEqual(unrelatedItem);
  });

  it('allows empty parent removal after its children are removed', () => {
    let payload = projectPayload();
    payload = removeStructuredItem(
      payload,
      'Project/Production',
      'api/v1',
      'database/prod',
    );
    payload = removeStructuredService(payload, 'Project/Production', 'api/v1');
    payload = removeProjectContext(payload, 'Project/Production');
    expect(() => resolveProjectContext(payload, 'Project/Production')).toThrow();
    expect(payload.groups.some((group) => group.name === 'api/v1')).toBe(false);
    expect(payload.items).toHaveLength(0);
  });

  it('executes every structured command family through database routing', async () => {
    let payload = createEmptyStructuredVaultPayload(
      vaultIdSchema.parse('vault_structured'),
      at,
    );
    let revision = 0;
    let nextFieldValue: string | undefined;
    let omitFieldValue = false;
    let profile: {
      id: string;
      datastore: 'file' | 'mongodb';
      databaseId: string;
      defaultVaultId: string;
      dataFile?: string;
      database?: string;
      databaseCollection?: string;
      vaultCollection?: string;
      keyFile: string;
    } = {
      id: 'structured',
      datastore: 'file',
      databaseId: 'db_structured',
      defaultVaultId: 'vault_structured',
      dataFile: 'structured.database',
      keyFile: 'structured.key',
    } as const;
    vi.spyOn(DatastoreProfileRegistry, 'open').mockResolvedValue({
      get: vi.fn(async () => profile),
    } as never);
    vi.spyOn(FileEncryptedDatabaseStore, 'open').mockResolvedValue({
      close: vi.fn(async () => undefined),
    } as never);
    vi.spyOn(MongoEncryptedDatabaseStore, 'connect').mockResolvedValue({
      close: vi.fn(async () => undefined),
    } as never);
    const session = {
      updateStructuredVault: vi.fn(async (_vaultId, update) => {
        payload = await update(payload);
        revision += 1;
        return { revision };
      }),
      inspectStructuredVault: vi.fn(async (_vaultId, inspect) => {
        await inspect(payload);
        return { revision };
      }),
      close: vi.fn(async () => undefined),
    };
    vi.spyOn(DatabaseSession, 'open').mockResolvedValue(session as never);
    vi.spyOn(LocalSecretInput.prototype, 'read').mockImplementation(async (kinds) => {
      const requested = omitFieldValue
        ? kinds.filter(
            (kind) => kind !== 'field-value' && kind !== 'field-value-base64',
          )
        : kinds;
      return requested.map((kind) => {
        if (kind === 'field-value') {
          if (nextFieldValue === undefined) throw new Error('missing field fixture');
          const value = nextFieldValue;
          nextFieldValue = undefined;
          return value;
        }
        if (kind === 'database-url') return 'mongodb://localhost:27017';
        return 'owner-passphrase';
      });
    });
    const output: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      return true;
    });
    const route = [
      '--profile',
      'structured',
      '--profile-config-dir',
      'ignored',
      '--datastore',
      'file',
      '--data-file',
      'structured-override.database',
      '--key-file',
      'structured-override.key',
    ];
    const execute = async (...args: string[]) => {
      output.length = 0;
      await buildLocalCli().parseAsync(['node', 'kavrix', ...args, ...route]);
      return JSON.parse(output.join('')) as Record<string, unknown>;
    };
    const executeRaw = (...args: string[]) =>
      buildLocalCli().parseAsync(['node', 'kavrix', ...args, ...route]);

    await expect(
      execute('environment', 'create', 'project', '--environment', 'production'),
    ).resolves.toMatchObject({ created: true, type: 'context' });
    await expect(execute('context', 'create', 'no-environment')).resolves.toMatchObject(
      { created: true, type: 'context' },
    );
    await expect(execute('context', 'list')).resolves.toMatchObject({
      contexts: expect.arrayContaining([
        expect.objectContaining({ name: 'project', environment: 'production' }),
        expect.objectContaining({ name: 'no-environment' }),
      ]),
    });
    await expect(execute('context', 'remove', 'no-environment')).resolves.toMatchObject(
      { removed: true, type: 'context' },
    );
    await expect(
      execute('context', 'rename', 'project', 'production-project'),
    ).resolves.toMatchObject({ renamed: true, type: 'context' });
    await expect(
      execute('group', 'create', 'database', '--context', 'production-project'),
    ).resolves.toMatchObject({ created: true, type: 'service' });
    await expect(
      execute('service', 'list', '--context', 'production-project'),
    ).resolves.toMatchObject({ services: ['database'] });
    await expect(
      execute(
        'service',
        'rename',
        'database',
        'postgres',
        '--context',
        'production-project',
      ),
    ).resolves.toMatchObject({ renamed: true, type: 'service' });
    await expect(
      execute(
        'credential',
        'create',
        'primary',
        '--context',
        'production-project',
        '--service',
        'postgres',
      ),
    ).resolves.toMatchObject({ created: true, type: 'item' });
    await expect(
      execute(
        'item',
        'list',
        '--context',
        'production-project',
        '--service',
        'postgres',
      ),
    ).resolves.toMatchObject({ items: ['primary'] });
    await expect(
      execute(
        'item',
        'show',
        'primary',
        '--context',
        'production-project',
        '--service',
        'postgres',
      ),
    ).resolves.toMatchObject({ title: 'primary', fields: [] });
    await expect(
      execute(
        'item',
        'rename',
        'primary',
        'main',
        '--context',
        'production-project',
        '--service',
        'postgres',
      ),
    ).resolves.toMatchObject({ renamed: true, type: 'item' });

    nextFieldValue = 'alice';
    await expect(
      execute(
        'field',
        'set',
        'username',
        '--type',
        'username',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).resolves.toMatchObject({ saved: true, type: 'field' });
    await expect(
      execute(
        'field',
        'list',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).resolves.toMatchObject({
      fields: [expect.objectContaining({ name: 'username', sensitive: false })],
    });
    await expect(
      execute(
        'field',
        'get',
        'username',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).resolves.toMatchObject({ value: 'alice', type: 'username' });

    nextFieldValue = 'secret-value';
    await execute(
      'field',
      'set',
      'password',
      '--type',
      'password',
      '--context',
      'production-project',
      '--service',
      'postgres',
      '--item',
      'main',
    );
    await expect(
      execute(
        'field',
        'get',
        'password',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).resolves.toMatchObject({ value: '[REDACTED]', type: 'password' });
    await expect(
      execute(
        'field',
        'get',
        'username',
        '--reveal',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).resolves.toMatchObject({ value: 'alice' });
    await expect(
      executeRaw(
        'field',
        'get',
        'password',
        '--reveal',
        '--reveal-base64',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).rejects.toThrow('either --reveal or --reveal-base64');
    await expect(
      executeRaw(
        'field',
        'set',
        'conflict',
        '--type',
        'text',
        '--sensitive',
        '--public',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).rejects.toThrow('both sensitive and public');
    await expect(
      executeRaw(
        'field',
        'set',
        'conflict',
        '--type',
        'text',
        '--value-stdin',
        '--value-stdin-base64',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).rejects.toThrow('either --value-stdin or --value-stdin-base64');
    omitFieldValue = true;
    await expect(
      executeRaw(
        'field',
        'set',
        'missing-value',
        '--type',
        'text',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).rejects.toThrow('Secret input is incomplete');
    omitFieldValue = false;
    session.inspectStructuredVault.mockImplementationOnce(async () => ({ revision }));
    await expect(
      executeRaw(
        'field',
        'get',
        'username',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).rejects.toThrow('Field was not found');
    await expect(
      execute(
        'field',
        'remove',
        'username',
        '--context',
        'production-project',
        '--service',
        'postgres',
        '--item',
        'main',
      ),
    ).resolves.toMatchObject({ removed: true, type: 'field' });
    await execute(
      'item',
      'remove',
      'main',
      '--context',
      'production-project',
      '--service',
      'postgres',
    );
    await execute('service', 'remove', 'postgres', '--context', 'production-project');
    await expect(
      execute('context', 'remove', 'production-project'),
    ).resolves.toMatchObject({ removed: true, type: 'context' });

    await execute(
      'item',
      'create',
      'empty-default',
      '--context',
      DEFAULT_PROJECT_CONTEXT_NAME,
      '--service',
      DEFAULT_SERVICE_NAME,
    );
    await expect(
      execute(
        'field',
        'get',
        'value',
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--item',
        'empty-default',
      ),
    ).resolves.toMatchObject({ value: '[EMPTY]' });
    await expect(
      executeRaw(
        'field',
        'get',
        'value',
        '--reveal',
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--item',
        'empty-default',
      ),
    ).rejects.toThrow('Field has no readable value');
    const defaultItem = payload.items.find((entry) => entry.title === 'empty-default');
    if (defaultItem === undefined) throw new Error('default fixture missing');
    const defaultValue = projectStructuredField(defaultItem, 'value');
    expect(redactStructuredFieldValue(defaultItem, 'value')).toBe('[EMPTY]');
    expect(displayStructuredFieldValue(defaultItem, 'value')).toBe('[EMPTY]');
    expect(() =>
      assertStructuredFieldRevealAllowed(defaultValue.definition),
    ).not.toThrow();
    await execute(
      'item',
      'remove',
      'empty-default',
      '--context',
      DEFAULT_PROJECT_CONTEXT_NAME,
      '--service',
      DEFAULT_SERVICE_NAME,
    );

    output.length = 0;
    await buildLocalCli().parseAsync([
      'node',
      'kavrix',
      'context',
      'list',
      '--profile',
      'structured',
      '--vault',
      'vault_explicit',
    ]);
    expect(session.inspectStructuredVault).toHaveBeenLastCalledWith(
      'vault_explicit',
      expect.any(Function),
    );
    expect(JSON.parse(output.join(''))).toMatchObject({
      contexts: [expect.objectContaining({ name: DEFAULT_PROJECT_CONTEXT_NAME })],
    });

    await execute(
      'item',
      'create',
      'classification-item',
      '--context',
      DEFAULT_PROJECT_CONTEXT_NAME,
      '--service',
      DEFAULT_SERVICE_NAME,
    );
    nextFieldValue = 'classified-value';
    await execute(
      'field',
      'set',
      'classified',
      '--type',
      'text',
      '--sensitive',
      '--context',
      DEFAULT_PROJECT_CONTEXT_NAME,
      '--service',
      DEFAULT_SERVICE_NAME,
      '--item',
      'classification-item',
    );
    nextFieldValue = 'REGION=eu';
    await execute(
      'field',
      'set',
      'public-environment',
      '--type',
      'environment-map',
      '--public',
      '--context',
      DEFAULT_PROJECT_CONTEXT_NAME,
      '--service',
      DEFAULT_SERVICE_NAME,
      '--item',
      'classification-item',
    );
    nextFieldValue = 'base64-transport-value';
    await executeRaw(
      'field',
      'set',
      'base64-input',
      '--type',
      'text',
      '--passphrase-stdin',
      '--value-stdin-base64',
      '--context',
      DEFAULT_PROJECT_CONTEXT_NAME,
      '--service',
      DEFAULT_SERVICE_NAME,
      '--item',
      'classification-item',
    );
    await execute(
      'item',
      'remove',
      'classification-item',
      '--context',
      DEFAULT_PROJECT_CONTEXT_NAME,
      '--service',
      DEFAULT_SERVICE_NAME,
    );
    expect(payload.projectContexts.map((entry) => entry.name)).toEqual([
      DEFAULT_PROJECT_CONTEXT_NAME,
    ]);

    profile = {
      id: 'structured',
      datastore: 'mongodb',
      databaseId: 'db_structured',
      defaultVaultId: 'vault_structured',
      database: 'credentials',
      databaseCollection: 'databases',
      vaultCollection: 'vaults',
      keyFile: 'structured.key',
    };
    output.length = 0;
    await buildLocalCli().parseAsync([
      'node',
      'kavrix',
      'context',
      'list',
      '--profile',
      'structured',
      '--profile-config-dir',
      'ignored',
      '--vault',
      'vault_structured',
      '--datastore',
      'mongodb',
      '--database',
      'override_database',
      '--collection',
      'override_vaults',
      '--key-file',
      'override.key',
      '--database-url-stdin',
      '--passphrase-stdin',
      '--allow-insecure-transport',
    ]);
    expect(JSON.parse(output.join(''))).toMatchObject({
      contexts: [expect.objectContaining({ name: DEFAULT_PROJECT_CONTEXT_NAME })],
    });
  });
});
