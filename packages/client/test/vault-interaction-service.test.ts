import { describe, expect, it, vi } from 'vitest';

import type {
  ClipboardCopyOptions,
  ClipboardCopyReceipt,
  SecureClipboardPort,
} from '@kavrix/clipboard';
import { AmbiguousNameError, NotFoundError } from '@kavrix/core';
import {
  fieldDefinitionSchema,
  itemPayloadSchema,
  noteSchema,
  vaultIdSchema,
  type FieldDefinition,
  type Note,
} from '@kavrix/schemas';

import {
  VaultInteractionService,
  VaultReadSession,
  type CopyAuthorizationPort,
} from '../src/index.js';
import {
  MemoryReadSource,
  encryptedFixture,
  type EncryptedFixture,
} from './fixtures.js';

const NOW = '2026-08-10T00:00:00.000Z';
const PUBLIC_CANARY = 'public-user-canary';
const SECRET_CANARY = 'secret-copy-canary';
const NOTE_CANARY = 'secret-note-copy-canary';

describe('VaultInteractionService', () => {
  it('projects the complete record with all field states and note bodies redacted', async () => {
    const fixture = await interactionFixture();
    const source = new MemoryReadSource(fixture);
    const service = await unlockedService(source, fixture.rootKey);

    const result = await service.show('Production', 'Primary');
    expect(result).toMatchObject({
      group: {
        id: 'group.1',
        name: 'Production',
        description: 'Production credentials',
        aliases: ['g1'],
        notes: [{ id: 'note.group', content: '[REDACTED]' }],
      },
      id: 'item.1.1',
      aliases: ['i1', 'primary-alias'],
      environment: 'production',
      owner: 'Platform team',
      purpose: 'Deploy services',
      favorite: true,
      productionSensitive: false,
      expiresAt: '2026-12-01T00:00:00.000Z',
      rotationIntervalDays: 30,
      lastRotatedAt: NOW,
      lastVerifiedAt: NOW,
      relatedItemCount: 1,
      attachmentCount: 1,
      noteCount: 1,
      activeNoteCount: 1,
      archivedNoteCount: 0,
      notes: [{ id: 'note.item', content: '[REDACTED]' }],
    });
    expect(result.fields).toHaveLength(14);
    expect(result.fields).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ stableKey: 'username', value: PUBLIC_CANARY }),
        expect.objectContaining({ stableKey: 'password', value: '[REDACTED]' }),
        expect.objectContaining({ stableKey: 'missing', state: 'missing' }),
        expect.objectContaining({ stableKey: 'empty', state: 'empty' }),
        expect.objectContaining({
          stableKey: 'inapplicable',
          state: 'inapplicable',
        }),
        expect.objectContaining({ stableKey: 'unreadable', state: 'unreadable' }),
        expect.objectContaining({
          stableKey: 'legacy',
          state: 'orphaned',
          value: '[ORPHANED]',
        }),
      ]),
    );
    expect(JSON.stringify(result)).not.toContain(SECRET_CANARY);
    expect(JSON.stringify(result)).not.toContain(NOTE_CANARY);
  });

  it('uses getGroup/getItem only for exact IDs and preserves named resolution', async () => {
    const exactFixture = await interactionFixture();
    const exactSource = new MemoryReadSource(exactFixture);
    const exactClipboard = new RecordingClipboard();
    const exact = await unlockedService(
      exactSource,
      exactFixture.rootKey,
      exactClipboard,
    );
    await exact.copy('group.1', 'item.1.1', 'username');
    expect(exactSource.calls).toMatchObject({
      getGroup: 1,
      getItem: 1,
      listGroups: 0,
      listItems: 0,
    });

    const namedFixture = await interactionFixture();
    const namedSource = new MemoryReadSource(namedFixture);
    const named = await unlockedService(namedSource, namedFixture.rootKey);
    await expect(named.show('Production', 'Primary')).resolves.toMatchObject({
      id: 'item.1.1',
      group: { id: 'group.1' },
    });
    expect(namedSource.calls).toMatchObject({
      getGroup: 1,
      getItem: 0,
      listGroups: 1,
      listItems: 1,
    });
  });

  it('copies exactly one selected scalar, wipes owned bytes, and returns no value', async () => {
    const fixture = await interactionFixture();
    const clipboard = new RecordingClipboard();
    const service = await unlockedService(
      new MemoryReadSource(fixture),
      fixture.rootKey,
      clipboard,
    );

    const receipt = await service.copy('group.1', 'item.1.1', 'recovery_codes', {
      index: 2,
    });
    expect(clipboard.observed).toEqual(new TextEncoder().encode('recovery-two'));
    expect(clipboard.reference).toBeDefined();
    expect(clipboard.reference?.every((byte) => byte === 0)).toBe(true);
    expect(clipboard.options).toEqual({ clearAfterMs: 30_000 });
    expect(receipt).toEqual({ label: 'Recovery codes', clearAfterSeconds: 30 });
    expect(JSON.stringify(receipt)).not.toContain('recovery-two');
  });

  it('resolves fields by ID/key, label, case-insensitive exact, and unique prefix', async () => {
    const fixture = await interactionFixture();
    const clipboard = new RecordingClipboard();
    const service = await unlockedService(
      new MemoryReadSource(fixture),
      fixture.rootKey,
      clipboard,
    );

    await service.copy('group.1', 'item.1.1', 'field.username');
    expect(clipboard.text()).toBe(PUBLIC_CANARY);
    await service.copy('group.1', 'item.1.1', 'target');
    expect(clipboard.text()).toBe('stable-key-wins');
    await service.copy('group.1', 'item.1.1', 'PASSWORD');
    expect(clipboard.text()).toBe(SECRET_CANARY);
    await service.copy('group.1', 'item.1.1', 'User');
    expect(clipboard.text()).toBe(PUBLIC_CANARY);

    await expect(
      service.copy('group.1', 'item.1.1', 'Token Al'),
    ).rejects.toBeInstanceOf(AmbiguousNameError);
    await expect(
      service.copy('missing-group', 'item.1.1', 'username'),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('distinguishes states, repeat bounds, copy policy, and used elements', async () => {
    const fixture = await interactionFixture();
    const clipboard = new RecordingClipboard();
    const service = await unlockedService(
      new MemoryReadSource(fixture),
      fixture.rootKey,
      clipboard,
    );

    await expectKind(service.copy('group.1', 'item.1.1', 'missing'), 'missing');
    await expectKind(service.copy('group.1', 'item.1.1', 'empty'), 'empty');
    await expectKind(
      service.copy('group.1', 'item.1.1', 'inapplicable'),
      'inapplicable',
    );
    await expectKind(service.copy('group.1', 'item.1.1', 'unreadable'), 'unreadable');
    await expectKind(service.copy('group.1', 'item.1.1', 'legacy'), 'orphaned');
    await expectKind(service.copy('group.1', 'item.1.1', 'never'), 'not-copyable');
    await expectKind(
      service.copy('group.1', 'item.1.1', 'recovery_codes'),
      'index-required',
    );
    await expectKind(
      service.copy('group.1', 'item.1.1', 'username', { index: 1 }),
      'index-inapplicable',
    );
    await expectKind(
      service.copy('group.1', 'item.1.1', 'recovery_codes', { index: 0 }),
      'index-out-of-range',
    );
    await expectKind(
      service.copy('group.1', 'item.1.1', 'recovery_codes', { index: 9 }),
      'index-out-of-range',
    );
    await expectKind(
      service.copy('group.1', 'item.1.1', 'recovery_codes', { index: 3 }),
      'used',
    );
    expect(clipboard.copyCalls).toBe(0);
  });

  it('requires explicit authorization for confirm and production-sensitive copies', async () => {
    const fixture = await interactionFixture();
    const withoutAuthorization = await unlockedService(
      new MemoryReadSource(fixture),
      fixture.rootKey,
    );
    await expectKind(
      withoutAuthorization.copy('group.1', 'item.1.1', 'confirm_secret'),
      'authorization-required',
    );

    const requests: unknown[] = [];
    const authorization: CopyAuthorizationPort = {
      authorizeCopy: vi.fn((request) => {
        requests.push(request);
        return Promise.resolve(true);
      }),
    };
    const clipboard = new RecordingClipboard();
    const service = await unlockedService(
      new MemoryReadSource(fixture),
      fixture.rootKey,
      clipboard,
      authorization,
    );
    await expect(
      service.copy('group.1', 'item.1.1', 'confirm_secret'),
    ).resolves.toMatchObject({ label: 'Confirm secret' });
    expect(JSON.stringify(requests)).not.toContain(SECRET_CANARY);

    const highRiskFixture = await interactionFixture(true);
    const denied: CopyAuthorizationPort = {
      authorizeCopy: () => Promise.resolve(false),
    };
    const deniedService = await unlockedService(
      new MemoryReadSource(highRiskFixture),
      highRiskFixture.rootKey,
      new RecordingClipboard(),
      denied,
    );
    await expectKind(
      deniedService.copy('group.1', 'item.1.1', 'username'),
      'authorization-denied',
    );

    const authorizationCanary = `${SECRET_CANARY}-authorization-error`;
    const failed: CopyAuthorizationPort = {
      authorizeCopy: () => Promise.reject(new Error(authorizationCanary)),
    };
    const failedService = await unlockedService(
      new MemoryReadSource(fixture),
      fixture.rootKey,
      new RecordingClipboard(),
      failed,
    );
    try {
      await failedService.copy('group.1', 'item.1.1', 'confirm_secret');
      expect.unreachable();
    } catch (error) {
      expect(error).toMatchObject({ kind: 'authorization-failed' });
      expect(String(error)).not.toContain(authorizationCanary);
    }
  });

  it('contains hostile clipboard failures and still wipes the attempted bytes', async () => {
    const fixture = await interactionFixture();
    const clipboard = new RecordingClipboard(`${SECRET_CANARY}-clipboard-error`);
    const service = await unlockedService(
      new MemoryReadSource(fixture),
      fixture.rootKey,
      clipboard,
    );
    try {
      await service.copy('group.1', 'item.1.1', 'password');
      expect.unreachable();
    } catch (error) {
      expect(error).toMatchObject({ kind: 'clipboard-failed' });
      expect(String(error)).not.toContain(SECRET_CANARY);
    }
    expect(clipboard.reference?.every((byte) => byte === 0)).toBe(true);
  });
});

async function unlockedService(
  source: MemoryReadSource,
  rootKey: Parameters<VaultReadSession['unlock']>[0],
  clipboard: SecureClipboardPort = new RecordingClipboard(),
  authorization?: CopyAuthorizationPort,
): Promise<VaultInteractionService> {
  const session = new VaultReadSession(
    source,
    source.vault?.id ?? vaultIdSchema.parse('vault.client'),
  );
  await session.unlock(rootKey);
  return new VaultInteractionService(session, clipboard, {
    clearAfterMs: 30_000,
    ...(authorization === undefined ? {} : { authorization }),
  });
}

async function interactionFixture(
  productionSensitive = false,
): Promise<EncryptedFixture> {
  const definitions = testDefinitions();
  return encryptedFixture({
    transformGroup: (group) => ({
      ...group,
      description: 'Production credentials',
      tags: ['critical'],
      notes: [note('note.group', 'Group recovery')],
      template: { ...group.template, fields: definitions.slice(0, 11) },
    }),
    transformItem: (item) =>
      itemPayloadSchema.parse({
        ...item,
        aliases: [...item.aliases, 'primary-alias'],
        environment: 'production',
        owner: 'Platform team',
        purpose: 'Deploy services',
        favorite: true,
        productionSensitive,
        expiresAt: '2026-12-01T00:00:00.000Z',
        rotationIntervalDays: 30,
        lastRotatedAt: NOW,
        lastVerifiedAt: NOW,
        relatedItemIds: ['item.related'],
        attachmentIds: ['attachment.primary'],
        notes: [note('note.item', 'Item recovery')],
        templateValues: [
          stored(definitions[0], present('text', PUBLIC_CANARY)),
          stored(definitions[1], present('secret', SECRET_CANARY)),
          stored(
            definitions[2],
            multiple([
              element('element.one', 'recovery-one'),
              element('element.two', 'recovery-two'),
              element('element.used', 'recovery-used', true),
            ]),
          ),
          stored(definitions[3], present('secret', 'confirm-value')),
          stored(definitions[4], present('text', 'never-value')),
          stored(definitions[5], { version: 1, state: 'missing' }),
          stored(definitions[6], { version: 1, state: 'empty' }),
          stored(definitions[7], {
            version: 1,
            state: 'inapplicable',
            reason: 'not configured',
          }),
          stored(definitions[8], {
            version: 1,
            state: 'unreadable',
            reason: 'unsupported-version',
          }),
          stored(definitions[9], present('text', 'token-alpha')),
          stored(definitions[10], present('text', 'token-alpine')),
        ],
        itemFields: [definitions[11], definitions[12]],
        itemValues: [
          stored(definitions[11], present('text', 'label-loses')),
          stored(definitions[12], present('text', 'stable-key-wins')),
        ],
        archivedFieldValues: [
          {
            definition: field('field.legacy', 'legacy', 'Legacy field', false, 50),
            value: {
              version: 1,
              state: 'orphaned',
              originalValue: present('text', 'legacy-value'),
            },
            sourceTemplateId: item.templateId,
            sourceTemplateVersion: item.templateVersion,
            archivedAt: NOW,
            reason: 'template-field-removed',
          },
        ],
      }),
  });
}

type DefinitionTuple = readonly [
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
  FieldDefinition,
];

function testDefinitions(): DefinitionTuple {
  return [
    field('field.username', 'username', 'Username', false, 0),
    field('field.password', 'password', 'Password', true, 1),
    field('field.recovery', 'recovery_codes', 'Recovery codes', true, 2, {
      repeatable: true,
      type: 'recovery-code-list',
    }),
    field('field.confirm', 'confirm_secret', 'Confirm secret', true, 3, {
      copyPolicy: 'confirm',
    }),
    field('field.never', 'never', 'Never', false, 4, {
      copyPolicy: 'never',
    }),
    field('field.missing', 'missing', 'Missing', false, 5),
    field('field.empty', 'empty', 'Empty', false, 6),
    field('field.inapplicable', 'inapplicable', 'Inapplicable', false, 7),
    field('field.unreadable', 'unreadable', 'Unreadable', false, 8),
    field('field.alpha', 'token_alpha', 'Token Alpha', false, 9),
    field('field.alpine', 'token_alpine', 'Token Alpine', false, 10),
    field('field.target-label', 'other_key', 'target', false, 11),
    field('field.target-key', 'target', 'Stable key target', false, 12),
  ] as const;
}

function field(
  id: string,
  stableKey: string,
  label: string,
  sensitive: boolean,
  sortOrder: number,
  overrides: Readonly<{
    repeatable?: boolean;
    type?: 'text' | 'secret' | 'recovery-code-list';
    copyPolicy?: 'allowed' | 'confirm' | 'never';
  }> = {},
): FieldDefinition {
  const copyPolicy = overrides.copyPolicy ?? 'allowed';
  return fieldDefinitionSchema.parse({
    id,
    stableKey,
    label,
    type: overrides.type ?? (sensitive ? 'secret' : 'text'),
    required: false,
    sensitive,
    repeatable: overrides.repeatable ?? false,
    copyable: copyPolicy !== 'never',
    searchableLocally: !sensitive,
    showInPreview: !sensitive,
    copyPolicy,
    revealPolicy: sensitive ? 'timed' : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    exportPolicy: sensitive ? 'guarded' : 'encrypted-only',
    sortOrder,
    createdAt: NOW,
    updatedAt: NOW,
  });
}

function stored(definition: FieldDefinition, value: unknown): unknown {
  return {
    fieldId: definition.id,
    stableKey: definition.stableKey,
    value,
    updatedAt: NOW,
  };
}

function present(kind: 'text' | 'secret', value: string): unknown {
  return {
    version: 1,
    state: 'present',
    content: { cardinality: 'single', value: { kind, value } },
  } as const;
}

function multiple(elements: readonly unknown[]): unknown {
  return {
    version: 1,
    state: 'present',
    content: { cardinality: 'multiple', elements },
  } as const;
}

function element(id: string, value: string, used = false): unknown {
  return {
    id,
    value: { kind: 'secret', value },
    lifecycle: used
      ? { version: 1, status: 'used', usedAt: NOW }
      : { version: 1, status: 'available' },
  } as const;
}

function note(id: string, title: string): Note {
  return noteSchema.parse({
    id,
    title,
    content: NOTE_CANARY,
    isSensitive: false,
    isPinned: true,
    tags: ['recovery'],
    sortOrder: 0,
    createdAt: NOW,
    updatedAt: NOW,
  });
}

async function expectKind(promise: Promise<unknown>, kind: string): Promise<void> {
  await expect(promise).rejects.toMatchObject({ kind });
}

class RecordingClipboard implements SecureClipboardPort {
  observed: Uint8Array | undefined;
  reference: Uint8Array | undefined;
  options: ClipboardCopyOptions | undefined;
  copyCalls = 0;
  readonly #failure: string | undefined;

  constructor(failure?: string) {
    this.#failure = failure;
  }

  copy(
    secret: Uint8Array,
    options: ClipboardCopyOptions,
  ): Promise<ClipboardCopyReceipt> {
    this.copyCalls += 1;
    this.reference = secret;
    this.observed = Uint8Array.from(secret);
    this.options = options;
    if (this.#failure !== undefined) return Promise.reject(new Error(this.#failure));
    return Promise.resolve({ generation: this.copyCalls, clearAfterMs: 30_000 });
  }

  lock(): Promise<boolean> {
    return Promise.resolve(true);
  }

  dispose(): Promise<boolean> {
    return Promise.resolve(true);
  }

  takeBackgroundError(): Error | null {
    return null;
  }

  text(): string {
    return new TextDecoder().decode(this.observed);
  }
}
