import {
  lifecycleOperationIdSchema,
  vaultProfileSchema,
  type PortableKeyRotationJournalPort,
  type PortableKeyRotationJournalRecord,
} from '@kavrix/client';
import {
  associatedDataSchema,
  auditEventIdSchema,
  deviceIdSchema,
  keySlotIdSchema,
  sessionCredentialSecretSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type ApiSessionResponse,
  type KeySlotId,
  type Timestamp,
  type VaultRecord,
} from '@kavrix/schemas';
import {
  createDeviceKeySlot,
  createPortableKeySlot,
  encryptPayload,
  formatPortableKey,
  generateDeviceKey,
  generatePortableKey,
  generateVaultRootKey,
  unlockPortableKeySlot,
  zeroize,
  type PortableKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type * as KeyFiles from '@kavrix/key-files';

const mockedKeyFiles = vi.hoisted(() => ({
  entries: new Map<
    string,
    Readonly<{
      key: Uint8Array;
      binding:
        | Readonly<{ kind: 'unbound' }>
        | Readonly<{ kind: 'bound'; vaultId: string; keySlotId: string }>;
    }>
  >(),
}));

vi.mock('@kavrix/key-files', async () => {
  const actual = await vi.importActual<typeof KeyFiles>('@kavrix/key-files');
  return {
    ...actual,
    writePortableKeyFile: (
      path: string,
      key: Uint8Array,
      binding: Readonly<
        { kind: 'unbound' } | { kind: 'bound'; vaultId: string; keySlotId: string }
      >,
    ): Promise<void> => {
      mockedKeyFiles.entries.set(path, {
        key: Uint8Array.from(key),
        binding: structuredClone(binding),
      });
      return Promise.resolve();
    },
    readPortableKeyFile: (
      path: string,
      _protection: unknown,
      expectedBinding?: Readonly<
        { kind: 'unbound' } | { kind: 'bound'; vaultId: string; keySlotId: string }
      >,
    ): Promise<{
      readonly kind: 'unbound' | 'bound';
      readonly vaultId?: string;
      readonly keySlotId?: string;
      readonly key: Uint8Array;
      readonly protected: false;
    }> => {
      const entry = mockedKeyFiles.entries.get(path);
      if (entry === undefined) throw new Error('missing mocked key file');
      if (
        expectedBinding !== undefined &&
        JSON.stringify(entry.binding) !== JSON.stringify(expectedBinding)
      ) {
        throw new Error('mocked binding mismatch');
      }
      return Promise.resolve({
        ...entry.binding,
        key: Uint8Array.from(entry.key),
        protected: false,
      });
    },
  };
});

import {
  managePortableKeyRotation,
  type PortableKeyRotationControlPlane,
  type PortableKeyRotationBackend,
  type PortableKeyRotationOperation,
  type PortableKeyRotationOptions,
} from '../src/production/portable-key-rotation.js';

const VAULT_ID = vaultIdSchema.parse('vault.portable.rotation.test0001');
const DEVICE_ID = deviceIdSchema.parse('device.portable.rotation.test001');
const SOURCE_SLOT_ID = keySlotIdSchema.parse('slot.portable.rotation.source');
const DEVICE_SLOT_ID = keySlotIdSchema.parse('slot.device.rotation.current');
const OPERATION_ID = lifecycleOperationIdSchema.parse('operation.rotation.test.0001');
const SERVER_URL = 'https://rotation.example/';
const SESSION_LOCATOR = {
  version: 1 as const,
  vaultId: VAULT_ID,
  deviceId: DEVICE_ID,
  purpose: 'api-session' as const,
};

describe('production portable-key rotation', () => {
  beforeEach(() => {
    mockedKeyFiles.entries.clear();
  });

  it('rotates an imported key without changing encrypted payloads or leaking key material', async () => {
    const fixture = await createFixture();
    const replacement = generatePortableKey();
    const replacementPath = 'C:\\rotation-import-replacement.cvk';
    mockedKeyFiles.entries.set(replacementPath, {
      key: Uint8Array.from(replacement),
      binding: { kind: 'unbound' },
    });
    const journal = new MemoryRotationJournal();
    const control = new MemoryRotationControlPlane(fixture.vault);
    const beforePreferences = fixture.vault.encryptedPreferences;
    const formattedReplacement = formatPortableKey(replacement);
    const base = createOptions(fixture, journal, control);

    const result = await managePortableKeyRotation({
      ...base,
      operation: {
        kind: 'start',
        replacement: {
          kind: 'import-file',
          path: replacementPath,
          passphraseFromStdin: false,
        },
        reauthentication: {
          kind: 'portable-key',
          formattedKey: formatPortableKey(fixture.sourceKey),
          slotId: SOURCE_SLOT_ID,
        },
      },
    });

    expect(result).toMatchObject({
      action: 'rotated',
      operationId: OPERATION_ID,
      sourceSlotId: SOURCE_SLOT_ID,
      state: 'completed',
    });
    const remote = control.current();
    const replacementSlot = remote.keySlots.find(
      (slot) => slot.id === keySlotIdSchema.parse('slot.rotation.replacement.1'),
    );
    expect(replacementSlot?.state).toBe('active');
    expect(remote.keySlots.find((slot) => slot.id === SOURCE_SLOT_ID)?.state).toBe(
      'revoked',
    );
    expect(remote.encryptedPreferences).toEqual(beforePreferences);
    expect(
      control.requests.every((request) => !request.includes(formattedReplacement)),
    ).toBe(true);
    const journalJson = JSON.stringify(await journal.load(OPERATION_ID));
    expect(journalJson).not.toContain(formattedReplacement);
    expect(journalJson).not.toContain('rotation-import-plaintext-canary');
    if (replacementSlot?.type !== 'portable-key') {
      throw new Error('replacement slot missing');
    }
    const unlocked = await unlockPortableKeySlot(
      replacementSlot,
      formattedReplacement,
      {
        vaultId: VAULT_ID,
        slotId: replacementSlot.id,
        schemaVersion: 1,
        keyVersion: 1,
      },
    );
    expect(unlocked).toEqual(fixture.rootKey);

    zeroize(unlocked);
    cleanup(fixture);
    zeroize(replacement);
  });

  it('generates a bound replacement file and resumes after a durable checkpoint interruption', async () => {
    const fixture = await createFixture();
    const generatedPath = 'C:\\rotation-generated.cvk';
    const journal = new MemoryRotationJournal();
    journal.failPendingTransition = true;
    const control = new MemoryRotationControlPlane(fixture.vault);
    const base = createOptions(fixture, journal, control);
    const operation: PortableKeyRotationOperation = {
      kind: 'start',
      replacement: {
        kind: 'generate-file',
        path: generatedPath,
        protectWithPassphrase: false,
        passphraseFromStdin: false,
      },
      reauthentication: {
        kind: 'device-key',
        slotId: DEVICE_SLOT_ID,
      },
    };

    await expect(managePortableKeyRotation({ ...base, operation })).rejects.toThrow();
    expect((await journal.load(OPERATION_ID))?.state).toBe('prepared');
    expect(control.current().keySlots.some((slot) => slot.state === 'pending')).toBe(
      true,
    );

    const resumed = await managePortableKeyRotation({
      ...base,
      operation: {
        kind: 'resume',
        operationId: OPERATION_ID,
        replacementFile: {
          path: generatedPath,
          passphraseFromStdin: false,
        },
        reauthentication: {
          kind: 'device-key',
          slotId: DEVICE_SLOT_ID,
        },
      },
    });
    expect(resumed).toMatchObject({ action: 'resumed', state: 'completed' });
    expect(
      control.current().keySlots.find((slot) => slot.id === SOURCE_SLOT_ID)?.state,
    ).toBe('revoked');
    const completed = await journal.load(OPERATION_ID);
    expect(completed?.state).toBe('completed');
    expect(
      control.requests.some((request) =>
        request.includes('rotation-import-plaintext-canary'),
      ),
    ).toBe(false);

    const generatedSlot = control
      .current()
      .keySlots.find(
        (slot) => slot.id === keySlotIdSchema.parse('slot.rotation.replacement.1'),
      );
    expect(generatedSlot?.state).toBe('active');
    const parsed = mockedKeyFiles.entries.get(generatedPath);
    expect(parsed?.binding).toEqual({
      kind: 'bound',
      vaultId: VAULT_ID,
      keySlotId: generatedSlot?.id,
    });
    cleanup(fixture);
  });

  it('fails closed when the journal replacement snapshot is tampered', async () => {
    const fixture = await createFixture();
    const replacement = generatePortableKey();
    const replacementPath = 'C:\\rotation-tamper-replacement.cvk';
    mockedKeyFiles.entries.set(replacementPath, {
      key: Uint8Array.from(replacement),
      binding: { kind: 'unbound' },
    });
    const journal = new MemoryRotationJournal();
    const control = new MemoryRotationControlPlane(fixture.vault);
    const base = createOptions(fixture, journal, control);
    const startOperation: PortableKeyRotationOperation = {
      kind: 'start',
      replacement: {
        kind: 'import-file',
        path: replacementPath,
        passphraseFromStdin: false,
      },
      reauthentication: {
        kind: 'portable-key',
        formattedKey: formatPortableKey(fixture.sourceKey),
        slotId: SOURCE_SLOT_ID,
      },
    };
    journal.failPendingTransition = true;
    await expect(
      managePortableKeyRotation({ ...base, operation: startOperation }),
    ).rejects.toThrow();
    journal.tamperReplacement();
    const before = control.current();
    await expect(
      managePortableKeyRotation({
        ...base,
        operation: {
          kind: 'resume',
          operationId: OPERATION_ID,
          replacementFile: { path: replacementPath, passphraseFromStdin: false },
          reauthentication: {
            kind: 'portable-key',
            formattedKey: formatPortableKey(fixture.sourceKey),
            slotId: SOURCE_SLOT_ID,
          },
        },
      }),
    ).rejects.toThrow();
    expect(control.current()).toEqual(before);
    expect(
      control.current().keySlots.find((slot) => slot.id === SOURCE_SLOT_ID)?.state,
    ).toBe('active');
    cleanup(fixture);
    zeroize(replacement);
  });
});

class MemoryRotationJournal implements PortableKeyRotationJournalPort {
  readonly records = new Map<string, PortableKeyRotationJournalRecord>();
  failPendingTransition = false;

  createPrepared(record: PortableKeyRotationJournalRecord): Promise<void> {
    const prior = this.records.get(record.operationId);
    if (prior !== undefined && JSON.stringify(prior) !== JSON.stringify(record)) {
      throw new Error('journal conflict');
    }
    this.records.set(record.operationId, structuredClone(record));
    return Promise.resolve();
  }

  listOperationIds(): Promise<
    readonly ReturnType<typeof lifecycleOperationIdSchema.parse>[]
  > {
    return Promise.resolve(
      [...this.records.keys()]
        .sort()
        .map((value) => lifecycleOperationIdSchema.parse(value)),
    );
  }

  load(
    operationId: ReturnType<typeof lifecycleOperationIdSchema.parse>,
  ): Promise<PortableKeyRotationJournalRecord | null> {
    const record = this.records.get(operationId);
    return Promise.resolve(record === undefined ? null : structuredClone(record));
  }

  markPendingPublished(
    operationId: ReturnType<typeof lifecycleOperationIdSchema.parse>,
    updatedAt: Timestamp,
    checkpoint: PortableKeyRotationJournalRecord['checkpoint'],
  ): Promise<void> {
    if (this.failPendingTransition) {
      this.failPendingTransition = false;
      throw new Error('simulated durable interruption');
    }
    this.transition(operationId, 'pending-published', updatedAt, checkpoint);
    return Promise.resolve();
  }

  markActivePublished(
    operationId: ReturnType<typeof lifecycleOperationIdSchema.parse>,
    updatedAt: Timestamp,
    checkpoint: PortableKeyRotationJournalRecord['checkpoint'],
  ): Promise<void> {
    this.transition(operationId, 'active-published', updatedAt, checkpoint);
    return Promise.resolve();
  }

  complete(
    operationId: ReturnType<typeof lifecycleOperationIdSchema.parse>,
    completedAt: Timestamp,
    checkpoint: PortableKeyRotationJournalRecord['checkpoint'],
  ): Promise<void> {
    this.transition(operationId, 'completed', completedAt, checkpoint);
    return Promise.resolve();
  }

  tamperReplacement(): void {
    const record = this.records.get(OPERATION_ID);
    if (record === undefined) throw new Error('missing record');
    this.records.set(
      OPERATION_ID,
      structuredClone({
        ...record,
        replacementSlot: {
          ...record.replacementSlot,
          id: keySlotIdSchema.parse('slot.tampered.replacement'),
        },
      }),
    );
  }

  private transition(
    operationId: ReturnType<typeof lifecycleOperationIdSchema.parse>,
    state: PortableKeyRotationJournalRecord['state'],
    updatedAt: Timestamp,
    checkpoint: PortableKeyRotationJournalRecord['checkpoint'],
  ): void {
    const prior = this.records.get(operationId);
    if (prior === undefined) throw new Error('missing record');
    this.records.set(
      operationId,
      structuredClone({
        ...prior,
        state,
        updatedAt,
        checkpoint,
        replacementSlot:
          state === 'active-published' || state === 'completed'
            ? { ...prior.replacementSlot, state: 'active' }
            : prior.replacementSlot,
      }),
    );
  }
}

class MemoryRotationControlPlane implements PortableKeyRotationControlPlane {
  readonly requests: string[] = [];
  #vault: VaultRecord;

  constructor(vault: VaultRecord) {
    this.#vault = structuredClone(vault);
  }

  getSession(): Promise<Pick<ApiSessionResponse, 'vaultId' | 'deviceId' | 'scopes'>> {
    return Promise.resolve({
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
      scopes: ['sync:read', 'sync:write', 'device:manage'],
    });
  }

  fetchVault(): Promise<VaultRecord> {
    return Promise.resolve(structuredClone(this.#vault));
  }

  publishKeySlot(
    _bearer: ApiBearerToken,
    _vaultId: VaultRecord['id'],
    _slotId: KeySlotId,
    request: { record: VaultRecord },
  ): Promise<void> {
    this.requests.push(JSON.stringify(request));
    this.#vault = structuredClone(request.record);
    return Promise.resolve();
  }

  revokeKeySlot(
    _bearer: ApiBearerToken,
    _vaultId: VaultRecord['id'],
    _slotId: KeySlotId,
    request: { record: VaultRecord },
  ): Promise<void> {
    this.requests.push(JSON.stringify(request));
    this.#vault = structuredClone(request.record);
    return Promise.resolve();
  }

  current(): VaultRecord {
    return structuredClone(this.#vault);
  }
}

async function createFixture(): Promise<{
  vault: VaultRecord;
  rootKey: VaultRootKey;
  sourceKey: PortableKey;
  deviceKey: Uint8Array;
}> {
  const rootKey = generateVaultRootKey();
  const sourceKey = generatePortableKey();
  const deviceKey = generateDeviceKey();
  const sourceSlot = await createPortableKeySlot(
    {
      vaultId: VAULT_ID,
      slotId: SOURCE_SLOT_ID,
      schemaVersion: 1,
      keyVersion: 1,
      createdAt: '2026-08-13T00:00:00.000Z',
    },
    sourceKey,
    rootKey,
  );
  const deviceSlot = await createDeviceKeySlot(
    {
      vaultId: VAULT_ID,
      slotId: DEVICE_SLOT_ID,
      schemaVersion: 1,
      keyVersion: 1,
      createdAt: '2026-08-13T00:00:00.000Z',
      deviceId: DEVICE_ID,
      provider: 'test',
    },
    deviceKey,
    rootKey,
  );
  const encryptedPreferences = await encryptPayload(
    new TextEncoder().encode('rotation-import-plaintext-canary'),
    rootKey,
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType: 'vault-preferences',
      entityId: VAULT_ID,
      purpose: 'vault-preferences',
    }),
  );
  return {
    vault: vaultRecordSchema.parse({
      id: VAULT_ID,
      schemaVersion: 1,
      cryptographicVersion: 1,
      keySlots: [sourceSlot, deviceSlot],
      currentKeyVersion: 1,
      revision: 0,
      encryptedPreferences,
      createdAt: '2026-08-13T00:00:00.000Z',
      updatedAt: '2026-08-13T00:00:00.000Z',
    }),
    rootKey,
    sourceKey,
    deviceKey,
  };
}

function createOptions(
  fixture: Awaited<ReturnType<typeof createFixture>>,
  journal: PortableKeyRotationJournalPort,
  control: PortableKeyRotationControlPlane,
): Omit<PortableKeyRotationOptions, 'operation'> {
  const profile = vaultProfileSchema.parse({
    version: 1,
    serverUrl: SERVER_URL,
    vaultId: VAULT_ID,
    deviceId: DEVICE_ID,
    deviceLocator: {
      version: 1,
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
      keySlotId: DEVICE_SLOT_ID,
    },
    sessionLocator: SESSION_LOCATOR,
  });
  const session = sessionCredentialSecretSchema.parse(new Uint8Array(32).fill(7));
  const backend: PortableKeyRotationBackend = {
    sessions: {
      load: () => Promise.resolve(Uint8Array.from(session)),
    } as never,
    keychain: {
      load: () => Promise.resolve(Uint8Array.from(fixture.deviceKey)),
    } as never,
  };
  return {
    environment: {
      profiles: {
        store: () => Promise.resolve(),
        load: () => Promise.resolve(profile),
      },
      rotationJournal: journal,
    },
    backend,
    profile,
    controlPlane: control,
    secrets: {
      read: () => Promise.reject(new Error('unexpected secret read')),
      readBatch: () => Promise.reject(new Error('unexpected secret batch read')),
    },
    clock: { now: () => new Date('2026-08-13T01:00:00.000Z') },
    operationIds: { next: () => OPERATION_ID },
    slotIds: {
      next: () => keySlotIdSchema.parse('slot.rotation.replacement.1'),
    },
    idempotencyKeys: { next: () => 'rotation-idempotency-0001' },
    auditIds: { next: () => auditEventIdSchema.parse('audit.rotation.test.1') },
  };
}

function cleanup(fixture: {
  rootKey: VaultRootKey;
  sourceKey: PortableKey;
  deviceKey: Uint8Array;
}): void {
  zeroize(fixture.rootKey);
  zeroize(fixture.sourceKey);
  zeroize(fixture.deviceKey);
}
