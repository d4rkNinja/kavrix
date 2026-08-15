import { describe, expect, it } from 'vitest';

import { NotFoundError } from '@kavrix/core';
import {
  opaqueMutationSchema,
  vaultRecordSchema,
  vaultIdSchema,
  type OpaqueMutation,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';

import {
  buildLocalAuditProjection,
  executeProductionListAuditEvents,
  executeProductionShowAuditEvent,
  type AuditProjectionSourcePort,
} from '../src/production/audit.js';
import { CliUsageError } from '../src/errors.js';

const VAULT_ID: VaultId = vaultIdSchema.parse('vault.1');
/** Canonical unpadded base64url fillers of the exact lengths each field requires. */
const HKDF_SALT = Buffer.alloc(32, 0x11).toString('base64url');
const ARGON2_SALT = Buffer.alloc(16, 0x22).toString('base64url');
const NONCE = Buffer.alloc(24, 0x33).toString('base64url');
const AUTHENTICATION_TAG = Buffer.alloc(16, 0x44).toString('base64url');
const CIPHERTEXT_CANARY = Buffer.from('plaintext-audit-canary').toString('base64url');
const IDEMPOTENCY_CANARY = 'idempotency-audit-canary-0001';

function envelope(
  entityType: 'wrapped-root-key' | 'vault-preferences' | 'item' | 'wrapped-item-key',
  entityId: string,
  options: { readonly groupId?: string; readonly ciphertext?: string } = {},
): Record<string, unknown> {
  const purpose = {
    'wrapped-root-key': 'vrk-slot',
    'vault-preferences': 'vault-preferences',
    item: 'item-payload',
    'wrapped-item-key': 'item-key',
  }[entityType];
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: NONCE,
    ciphertext: options.ciphertext ?? 'AQID',
    authenticationTag: AUTHENTICATION_TAG,
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType,
      entityId,
      ...(options.groupId === undefined ? {} : { groupId: options.groupId }),
      purpose,
    },
    keyVersion: 1,
  };
}

function slot(
  id: string,
  overrides: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return {
    id,
    slotVersion: 1,
    keyVersion: 1,
    wrappedRootKey: envelope('wrapped-root-key', id),
    ...overrides,
  };
}

const PORTABLE_SLOT = slot('slot.portable.one', {
  type: 'portable-key',
  state: 'active',
  createdAt: '2026-08-01T00:00:00.000Z',
  derivation: {
    algorithm: 'hkdf-sha256',
    version: 1,
    salt: HKDF_SALT,
    context: 'credvault/v1/portable-key-wrap',
    outputLength: 32,
  },
});

const PASSPHRASE_SLOT = slot('slot.passphrase.one', {
  type: 'passphrase',
  state: 'superseded',
  createdAt: '2026-08-02T00:00:00.000Z',
  supersededAt: '2026-08-06T00:00:00.000Z',
  derivation: {
    algorithm: 'argon2id',
    version: 1,
    salt: ARGON2_SALT,
    memoryKiB: 65_536,
    passes: 3,
    parallelism: 4,
    outputLength: 32,
  },
});

const DEVICE_SLOT = slot('slot.device.one', {
  type: 'device-key',
  state: 'active',
  deviceId: 'device.workstation',
  createdAt: '2026-08-03T00:00:00.000Z',
  derivation: {
    algorithm: 'hkdf-sha256',
    version: 1,
    salt: HKDF_SALT,
    context: 'credvault/v1/device-key-wrap',
    outputLength: 32,
    provider: 'test-keychain',
  },
});

const RECOVERY_SLOT = slot('slot.recovery.one', {
  type: 'recovery-key',
  state: 'revoked',
  createdAt: '2026-08-04T00:00:00.000Z',
  revokedAt: '2026-08-07T00:00:00.000Z',
  derivation: {
    algorithm: 'hkdf-sha256',
    version: 1,
    salt: HKDF_SALT,
    context: 'credvault/v1/recovery-key-wrap',
    outputLength: 32,
  },
});

function vaultRecord(
  keySlots: readonly Record<string, unknown>[],
  revision = 0,
  updatedAt = '2026-08-04T00:00:00.000Z',
): VaultRecord {
  return vaultRecordSchema.parse({
    id: VAULT_ID,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots,
    currentKeyVersion: 1,
    revision,
    encryptedPreferences: envelope('vault-preferences', VAULT_ID, {
      ciphertext: CIPHERTEXT_CANARY,
    }),
    createdAt: '2026-08-01T00:00:00.000Z',
    updatedAt,
  });
}

function itemMutation(recordRevision: number, updatedAt: string): OpaqueMutation {
  return opaqueMutationSchema.parse({
    entityType: 'item',
    expectedRecordRevision: recordRevision - 1,
    idempotencyKey: IDEMPOTENCY_CANARY,
    record: {
      id: 'item.1',
      vaultId: VAULT_ID,
      groupId: 'group.1',
      schemaVersion: 1,
      wrappedItemKey: envelope('wrapped-item-key', 'item.1', { groupId: 'group.1' }),
      encryptedPayload: envelope('item', 'item.1', {
        groupId: 'group.1',
        ciphertext: CIPHERTEXT_CANARY,
      }),
      recordRevision,
      ciphertextHash: HKDF_SALT,
      createdAt: '2026-08-01T00:00:00.000Z',
      updatedAt,
    },
  });
}

function vaultMutation(revision: number, updatedAt: string): OpaqueMutation {
  return opaqueMutationSchema.parse({
    entityType: 'vault',
    expectedVaultRevision: revision - 1,
    idempotencyKey: IDEMPOTENCY_CANARY,
    record: vaultRecord([PORTABLE_SLOT], revision, updatedAt),
  });
}

function source(
  vault: VaultRecord | null,
  pending: readonly OpaqueMutation[] = [],
): AuditProjectionSourcePort {
  return {
    getVault: (vaultId) => {
      expect(vaultId).toBe(VAULT_ID);
      return Promise.resolve(vault);
    },
    listPendingMutations: (vaultId) => {
      expect(vaultId).toBe(VAULT_ID);
      return Promise.resolve(pending);
    },
  };
}

/** The full four-slot, two-mutation projection used by most assertions. */
function fullOptions(): { source: AuditProjectionSourcePort; vaultId: VaultId } {
  return {
    source: source(
      vaultRecord([PORTABLE_SLOT, PASSPHRASE_SLOT, DEVICE_SLOT, RECOVERY_SLOT]),
      [
        vaultMutation(1, '2026-08-08T00:00:00.000Z'),
        itemMutation(2, '2026-08-09T00:00:00.000Z'),
      ],
    ),
    vaultId: VAULT_ID,
  };
}

const EXPECTED_ORDER = [
  ['audit.mutation.item.1.r2', 'mutation', 'queue'],
  ['audit.mutation.vault.1.r1', 'mutation', 'queue'],
  ['audit.slot.slot.recovery.one.revoke', 'recovery', 'revoke'],
  ['audit.slot.slot.passphrase.one.supersede', 'slot', 'supersede'],
  ['audit.slot.slot.recovery.one.create', 'recovery', 'create'],
  ['audit.slot.slot.device.one.create', 'device', 'create'],
  ['audit.slot.slot.passphrase.one.create', 'slot', 'create'],
  ['audit.slot.slot.portable.one.create', 'slot', 'create'],
] as const;

describe('local audit projection', () => {
  it('maps every slot type and queued mutation onto its class, newest first', async () => {
    const projection = await buildLocalAuditProjection(fullOptions());

    expect(
      projection.map((event) => [event.eventId, event.eventClass, event.action]),
    ).toEqual(EXPECTED_ORDER.map((entry) => [...entry]));
  });

  it('carries the device identifier only on device-key slot events', async () => {
    const projection = await buildLocalAuditProjection(fullOptions());
    const withDevice = projection.filter((event) => event.deviceId !== undefined);

    expect(withDevice.map((event) => event.eventId)).toEqual([
      'audit.slot.slot.device.one.create',
    ]);
    expect(withDevice[0]?.deviceId).toBe('device.workstation');
    expect(
      projection.every((event) => event.keyVersion === 1 || event.action === 'queue'),
    ).toBe(true);
  });

  it('never infers the creation-time state of a slot that later transitioned', async () => {
    const projection = await buildLocalAuditProjection(fullOptions());
    const state = (eventId: string): string | undefined =>
      projection.find((event) => event.eventId === eventId)?.state;

    expect(state('audit.slot.slot.portable.one.create')).toBe('active');
    expect(state('audit.slot.slot.device.one.create')).toBe('active');
    expect(state('audit.slot.slot.passphrase.one.create')).toBeUndefined();
    expect(state('audit.slot.slot.recovery.one.create')).toBeUndefined();
    expect(state('audit.slot.slot.passphrase.one.supersede')).toBe('superseded');
    expect(state('audit.slot.slot.recovery.one.revoke')).toBe('revoked');
  });

  it('breaks identical timestamps by ascending event identifier', async () => {
    const first = slot('slot.portable.aaa', {
      type: 'portable-key',
      state: 'active',
      createdAt: '2026-08-05T00:00:00.000Z',
      derivation: {
        algorithm: 'hkdf-sha256',
        version: 1,
        salt: HKDF_SALT,
        context: 'credvault/v1/portable-key-wrap',
        outputLength: 32,
      },
    });
    const second = slot('slot.portable.bbb', {
      type: 'portable-key',
      state: 'active',
      createdAt: '2026-08-05T00:00:00.000Z',
      derivation: {
        algorithm: 'hkdf-sha256',
        version: 1,
        salt: HKDF_SALT,
        context: 'credvault/v1/portable-key-wrap',
        outputLength: 32,
      },
    });

    const descending = await buildLocalAuditProjection({
      source: source(vaultRecord([second, first])),
      vaultId: VAULT_ID,
    });
    const ascending = await buildLocalAuditProjection({
      source: source(vaultRecord([first, second])),
      vaultId: VAULT_ID,
    });

    expect(descending.map((event) => event.eventId)).toEqual([
      'audit.slot.slot.portable.aaa.create',
      'audit.slot.slot.portable.bbb.create',
    ]);
    expect(ascending.map((event) => event.eventId)).toEqual(
      descending.map((event) => event.eventId),
    );
  });

  it('reports a missing vault as not found for both list and show', async () => {
    const options = { source: source(null), vaultId: VAULT_ID };

    await expect(executeProductionListAuditEvents(options, {})).rejects.toBeInstanceOf(
      NotFoundError,
    );
    await expect(
      executeProductionShowAuditEvent(options, {
        eventId: 'audit.slot.slot.portable.one.create',
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe('audit event listing', () => {
  it('paginates by keyset without repeating or dropping an event', async () => {
    const first = await executeProductionListAuditEvents(fullOptions(), { limit: 3 });
    expect(first.events.map((event) => event.eventId)).toEqual([
      EXPECTED_ORDER[0][0],
      EXPECTED_ORDER[1][0],
      EXPECTED_ORDER[2][0],
    ]);
    expect(first.totalCount).toBe(EXPECTED_ORDER.length);
    expect(first.nextCursor).toBe(EXPECTED_ORDER[2][0]);

    const second = await executeProductionListAuditEvents(fullOptions(), {
      limit: 3,
      cursor: first.nextCursor ?? '',
    });
    const third = await executeProductionListAuditEvents(fullOptions(), {
      limit: 3,
      cursor: second.nextCursor ?? '',
    });

    expect(third.events).toHaveLength(2);
    expect(third.nextCursor).toBeNull();
    expect(third.totalCount).toBe(EXPECTED_ORDER.length);
    expect(
      [...first.events, ...second.events, ...third.events].map((e) => e.eventId),
    ).toEqual(EXPECTED_ORDER.map((entry) => entry[0]));
  });

  it('returns the whole projection and a null cursor by default', async () => {
    const page = await executeProductionListAuditEvents(fullOptions(), {});

    expect(page.events).toHaveLength(EXPECTED_ORDER.length);
    expect(page.nextCursor).toBeNull();
    expect(page.totalCount).toBe(EXPECTED_ORDER.length);
  });

  it('restricts the feed and the total count to one requested class', async () => {
    const page = await executeProductionListAuditEvents(fullOptions(), {
      eventClass: 'recovery',
    });

    expect(page.events.map((event) => event.eventId)).toEqual([
      'audit.slot.slot.recovery.one.revoke',
      'audit.slot.slot.recovery.one.create',
    ]);
    expect(page.totalCount).toBe(2);
    expect(page.nextCursor).toBeNull();
  });

  it('accepts the backup class and reports no locally derived events', async () => {
    const page = await executeProductionListAuditEvents(fullOptions(), {
      eventClass: 'backup',
    });

    expect(page).toEqual({ events: [], nextCursor: null, totalCount: 0 });
  });

  it('fails closed on a cursor absent from the requested projection', async () => {
    await expect(
      executeProductionListAuditEvents(fullOptions(), {
        cursor: 'audit.slot.absent.create',
      }),
    ).rejects.toBeInstanceOf(CliUsageError);

    // Valid in the unfiltered feed, but not within the filtered one.
    await expect(
      executeProductionListAuditEvents(fullOptions(), {
        eventClass: 'recovery',
        cursor: 'audit.slot.slot.portable.one.create',
      }),
    ).rejects.toBeInstanceOf(CliUsageError);
  });

  it('never exposes ciphertext, derivation salts, or idempotency keys', async () => {
    const page = await executeProductionListAuditEvents(fullOptions(), {});
    const serialized = JSON.stringify(page);

    expect(serialized).not.toContain(CIPHERTEXT_CANARY);
    expect(serialized).not.toContain(IDEMPOTENCY_CANARY);
    expect(serialized).not.toContain(HKDF_SALT);
    expect(serialized).not.toContain(ARGON2_SALT);
    expect(serialized).not.toContain('xchacha20-poly1305-ietf');
    expect(serialized).not.toContain('argon2id');
  });
});

describe('audit event inspection', () => {
  it('returns the addressed event bound to its vault', async () => {
    const detail = await executeProductionShowAuditEvent(fullOptions(), {
      eventId: 'audit.mutation.item.1.r2',
    });

    expect(detail.vaultId).toBe(VAULT_ID);
    expect(detail.event).toEqual({
      version: 1,
      eventId: 'audit.mutation.item.1.r2',
      eventClass: 'mutation',
      action: 'queue',
      subject: 'item.1',
      occurredAt: '2026-08-09T00:00:00.000Z',
      recordRevision: 2,
    });
  });

  it('reports an unknown event identifier as not found', async () => {
    await expect(
      executeProductionShowAuditEvent(fullOptions(), {
        eventId: 'audit.slot.slot.portable.one.revoke',
      }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});
