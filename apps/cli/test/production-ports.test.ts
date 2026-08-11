import {
  apiBearerTokenSchema,
  deviceIdSchema,
  keychainLocatorSchema,
  protectedLocalDeviceStateSchema,
  publicInviteRecordSchema,
  sessionCredentialLocatorSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { ControlPlaneClient } from '@kavrix/client';
import { describe, expect, it, vi } from 'vitest';

import { shapeInviteJoinRequest } from '../src/contracts.js';
import {
  createProductionPorts,
  readProductionStatus,
  type ProductionPortsOptions,
  type ProductionVaultSession,
} from '../src/production/ports.js';
import { CliUnavailableError } from '../src/errors.js';
import { showFixture } from './fixtures.js';

describe('production CLI ports', () => {
  it('forwards one invite page request and exposes no device-list adapter', async () => {
    const options = productionOptions();
    const sessionSecret = new Uint8Array(32).fill(7);
    Object.assign(options.secrets.sessions, {
      load: vi.fn(() => Promise.resolve(sessionSecret)),
    });
    const invite = publicInviteRecordSchema.parse({
      id: 'invite.primary',
      vaultId: options.profile.vaultId,
      issuedByDeviceId: options.profile.deviceId,
      scopes: ['sync:read'],
      state: 'active',
      createdAt: '2026-08-10T00:00:00.000Z',
      expiresAt: '2026-08-10T01:00:00.000Z',
    });
    const page = { invites: [invite], nextCursor: null };
    const listInvitePage = vi
      .spyOn(ControlPlaneClient.prototype, 'listInvitePage')
      .mockResolvedValue(page);
    const ports = createProductionPorts(options);

    await expect(
      ports.listInvitePage(options.profile.vaultId, { limit: 1 }),
    ).resolves.toEqual(page);

    expect(listInvitePage).toHaveBeenCalledWith(
      apiBearerTokenSchema.parse(Buffer.alloc(32, 7).toString('base64url')),
      options.profile.vaultId,
      { limit: 1 },
    );
    expect(ports).not.toHaveProperty('listDevicePage');
    expect([...sessionSecret]).toEqual(Array.from({ length: 32 }, () => 0));
  });

  it('forwards the invite server only when explicitly supplied', async () => {
    const request = shapeInviteJoinRequest(
      'A'.repeat(43),
      vaultIdSchema.parse('vault.primary'),
      1,
    );
    const result = {
      vaultId: vaultIdSchema.parse('vault.primary'),
      deviceId: deviceIdSchema.parse('device.new'),
    };
    const join = vi.fn(() => Promise.resolve(result));
    const options: ProductionPortsOptions = {
      profile: {} as never,
      environment: {} as never,
      secrets: {} as never,
      join,
    };
    const ports = createProductionPorts(options);

    await ports.joinInvite(request, 'portable-key');
    await ports.joinInvite(request, 'portable-key', 'https://sync.example/');

    expect(join).toHaveBeenNthCalledWith(1, request, 'portable-key');
    expect(join).toHaveBeenNthCalledWith(
      2,
      request,
      'portable-key',
      'https://sync.example/',
    );
  });

  it('propagates protected status corruption instead of reporting it absent', async () => {
    const failure = new Error('protected-state-corrupt');
    const options = productionOptions();
    options.secrets.protectedSyncState.load = vi.fn(() => Promise.reject(failure));

    await expect(createProductionPorts(options).status()).rejects.toBe(failure);
  });

  it('uses the extracted status reader without changing its locked projection', async () => {
    const options = productionOptions();
    const protectedState = protectedLocalDeviceStateSchema.parse({
      vaultId: options.profile.vaultId,
      deviceId: options.profile.deviceId,
      highestSeenVaultRevision: 4,
      updatedAt: '2026-08-10T01:02:03.000Z',
    });
    options.secrets.protectedSyncState.load.mockResolvedValue(protectedState);

    const direct = await readProductionStatus({
      profile: options.profile,
      environment: options.environment,
      protectedSyncState: options.secrets.protectedSyncState,
      syncState: 'offline',
    });
    const throughPorts = await createProductionPorts(options).status();

    expect(throughPorts).toEqual(direct);
    expect(throughPorts).toEqual({
      vaultState: 'locked',
      vaultId: 'vault.primary',
      deviceId: 'device.primary',
      syncState: 'offline',
      pendingChanges: 2,
      lastSyncAt: '2026-08-10T01:02:03.000Z',
    });
  });

  it('opens, unlocks, synchronizes, shows, and always locks in exact order', async () => {
    const events: string[] = [];
    const fixture = showFixture();
    const options = productionOptions(events, {
      unlockRememberedDevice: () => {
        events.push('unlock');
        return Promise.resolve();
      },
      synchronize: () => {
        events.push('sync');
        return Promise.resolve({} as never);
      },
      show: () => {
        events.push('show');
        return Promise.resolve(fixture);
      },
      lock: () => {
        events.push('lock');
        return Promise.resolve();
      },
    });

    await expect(createProductionPorts(options).show('group', 'item')).resolves.toBe(
      fixture,
    );
    expect(events).toEqual(['open-store', 'open', 'unlock', 'sync', 'show', 'lock']);
  });

  it('does not show after synchronization failure and preserves cleanup failure too', async () => {
    const events: string[] = [];
    const operationFailure = new Error('sync-secret-canary');
    const cleanupFailure = new Error('lock-secret-canary');
    const show = vi.fn(() => Promise.resolve(showFixture()));
    const options = productionOptions(events, {
      unlockRememberedDevice: () => Promise.resolve(),
      synchronize: () => Promise.reject(operationFailure),
      show,
      lock: () => {
        events.push('lock');
        return Promise.reject(cleanupFailure);
      },
    });

    await expect(
      createProductionPorts(options).show('group', 'item'),
    ).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof AggregateError &&
        error.errors[0] === operationFailure &&
        error.errors[1] === cleanupFailure &&
        !error.message.includes('secret-canary'),
    );
    expect(show).not.toHaveBeenCalled();
    expect(events).toEqual(['open-store', 'open', 'lock']);
  });

  it('fails copy closed before opening or unlocking a session', async () => {
    const events: string[] = [];
    const options = productionOptions(events);

    await expect(
      createProductionPorts(options).copy('group', 'item', 'password'),
    ).rejects.toEqual(new CliUnavailableError('copy'));
    expect(events).toEqual([]);
  });
});

function productionOptions(
  events: string[] = [],
  session: ProductionVaultSession = {} as never,
): ProductionPortsOptions & {
  secrets: ProductionPortsOptions['secrets'] & {
    protectedSyncState: { load: ReturnType<typeof vi.fn> };
  };
} {
  const vaultId = vaultIdSchema.parse('vault.primary');
  const deviceId = deviceIdSchema.parse('device.primary');
  return {
    profile: {
      version: 1,
      serverUrl: 'https://sync.example/',
      vaultId,
      deviceId,
      deviceLocator: keychainLocatorSchema.parse({
        version: 1,
        vaultId,
        deviceId,
        keySlotId: 'slot.primary',
      }),
      sessionLocator: sessionCredentialLocatorSchema.parse({
        version: 1,
        vaultId,
        deviceId,
        purpose: 'api-session',
      }),
    },
    environment: {
      openSyncStore: () => {
        events.push('open-store');
        return Promise.resolve({
          listPendingMutations: () => Promise.resolve([{} as never, {} as never]),
        } as never);
      },
      clipboard: {} as never,
    } as never,
    secrets: {
      sessions: {} as never,
      keychain: {} as never,
      protectedSyncState: {
        load: vi.fn(() => Promise.resolve(null)),
      },
    } as never,
    join: () => Promise.reject(new Error('unexpected join')),
    sessionFactory: () => {
      events.push('open');
      return session;
    },
  };
}
