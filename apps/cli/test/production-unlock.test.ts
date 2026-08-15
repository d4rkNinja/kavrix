import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { vaultProfileSchema } from '@kavrix/client';
import { openSqliteVaultProfileStore } from '@kavrix/local-store';
import {
  deviceIdSchema,
  keySlotIdSchema,
  vaultIdSchema,
  type SessionLifetimePolicy,
} from '@kavrix/schemas';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';

import { resolveCliDataPaths } from '../src/production/paths.js';
import type { ProductionCommandEnvironment } from '../src/production/environment.js';
import { ensureDataDirectory } from '../src/production/runtime-adapters.js';
import {
  runProductionLock,
  runProductionUnlocked,
  unlockMethodSchema,
} from '../src/production/unlock.js';
import { sessionHarness, stalled } from './session-harness.js';

/**
 * Short enough to reach every deadline within one driven clock, still in bounds.
 * The two limits are equal so the ceiling is the first deadline the driven clock
 * reaches, making the invocation timeout observable on its own.
 */
const SHORT_POLICY: SessionLifetimePolicy = Object.freeze({
  invocationTimeoutMs: 10_000,
  idleTimeoutMs: 10_000,
  reauthenticationWindowMs: 5_000,
});

/**
 * Counts closes while still performing the real one, so a test proves the
 * production environment was released rather than that a stub was called.
 */
function countCloses(environment: ProductionCommandEnvironment): () => number {
  let calls = 0;
  const close = environment.close.bind(environment);
  vi.spyOn(environment, 'close').mockImplementation(async () => {
    calls += 1;
    await close();
  });
  return () => calls;
}

describe('production unlocked command runner', () => {
  let tempHome: string;

  beforeEach(async () => {
    tempHome = join(
      tmpdir(),
      `kavrix-prod-unlock-test-${Math.random().toString(36).slice(2)}`,
    );
    await ensureDataDirectory(tempHome);
    const paths = resolveCliDataPaths({ CREDS_HOME: tempHome });
    const profileStore = await openSqliteVaultProfileStore({
      path: paths.profileStore,
    });
    const profile = vaultProfileSchema.parse({
      version: 1,
      serverUrl: 'https://vault.example/',
      vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
      deviceId: deviceIdSchema.parse('device.test00000000000000001'),
      deviceLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        keySlotId: 'slot.device.001',
      },
      sessionLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        purpose: 'api-session',
      },
    });
    await profileStore.store(profile);
    await profileStore.close();
  });

  afterEach(async () => {
    try {
      await rm(tempHome, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on temp teardown
    }
  });

  it('validates unlockMethod runtime contracts strictly', () => {
    expect(unlockMethodSchema.parse({ kind: 'remembered-device' })).toEqual({
      kind: 'remembered-device',
    });

    expect(
      unlockMethodSchema.parse({
        kind: 'portable',
        formattedKey: 'KAVRIX-PORTABLE-KEY-001',
      }),
    ).toEqual({
      kind: 'portable',
      formattedKey: 'KAVRIX-PORTABLE-KEY-001',
    });

    const slotId = keySlotIdSchema.parse('slot.passphrase.001');
    expect(
      unlockMethodSchema.parse({
        kind: 'passphrase',
        passphraseSlotId: slotId,
      }),
    ).toEqual({
      kind: 'passphrase',
      passphraseSlotId: slotId,
    });

    expect(() => unlockMethodSchema.parse({ kind: 'unknown' })).toThrow();
  });

  it('runs an operation within an unlocked environment lifecycle and closes resources', async () => {
    const mockSecretsInput = {
      read: vi.fn(),
      readBatch: vi.fn(),
      clear: vi.fn(),
    };

    const result = await runProductionUnlocked(
      {
        environment: { CREDS_HOME: tempHome },
        secrets: mockSecretsInput,
        backendPolicy: { kind: 'native' },
        unlockMethod: { kind: 'remembered-device' },
      },
      (context) => {
        expect(context.profile).toBeDefined();
        expect(context.ports).toBeDefined();
        return Promise.resolve('operation-result');
      },
    );

    expect(result).toBe('operation-result');
  });

  it('locks vault and clears managed clipboard state in production', async () => {
    const mockSecretsInput = {
      read: vi.fn(),
      readBatch: vi.fn(),
      clear: vi.fn(),
    };

    await expect(
      runProductionLock({
        environment: { CREDS_HOME: tempHome },
        secrets: mockSecretsInput,
        backendPolicy: { kind: 'native' },
      }),
    ).resolves.toBeUndefined();
  });

  it('surfaces aggregate error when operation and cleanup both fail', async () => {
    const mockSecretsInput = {
      read: vi.fn(),
      readBatch: vi.fn(),
      clear: vi.fn(),
    };

    const operationError = new Error('operation failed');

    await expect(
      runProductionUnlocked(
        {
          environment: { CREDS_HOME: tempHome },
          secrets: mockSecretsInput,
          backendPolicy: { kind: 'native' },
        },
        (context) => {
          vi.spyOn(context.environment, 'close').mockRejectedValueOnce(
            new Error('cleanup failed'),
          );
          return Promise.reject(operationError);
        },
      ),
    ).rejects.toThrow(AggregateError);
  });

  it('closes the real environment when the invocation deadline passes mid-operation', async () => {
    const mockSecretsInput = { read: vi.fn(), readBatch: vi.fn(), clear: vi.fn() };
    const { runtime, ports } = sessionHarness();
    let closes: (() => number) | undefined;
    let reachedSuccess = false;

    const pending = runProductionUnlocked(
      {
        environment: { CREDS_HOME: tempHome },
        secrets: mockSecretsInput,
        backendPolicy: { kind: 'native' },
        sessionPolicy: SHORT_POLICY,
        sessionPorts: ports,
      },
      async (context) => {
        closes = countCloses(context.environment);
        runtime.advance(SHORT_POLICY.invocationTimeoutMs);
        await stalled();
        reachedSuccess = true;
        return 'unreachable';
      },
    );

    await expect(pending).rejects.toMatchObject({
      name: 'CliSessionEndedError',
      code: 'SESSION_TIMEOUT',
    });
    expect(closes?.()).toBe(1);
    expect(reachedSuccess).toBe(false);
  });

  it('closes the real environment when the invocation is interrupted mid-operation', async () => {
    const mockSecretsInput = { read: vi.fn(), readBatch: vi.fn(), clear: vi.fn() };
    const { signals, ports } = sessionHarness();
    let closes: (() => number) | undefined;

    const pending = runProductionUnlocked(
      {
        environment: { CREDS_HOME: tempHome },
        secrets: mockSecretsInput,
        backendPolicy: { kind: 'native' },
        sessionPolicy: SHORT_POLICY,
        sessionPorts: ports,
      },
      async (context) => {
        closes = countCloses(context.environment);
        signals.raise('SIGINT');
        await stalled();
        return 'unreachable';
      },
    );

    await expect(pending).rejects.toMatchObject({ code: 'SESSION_INTERRUPTED' });
    expect(closes?.()).toBe(1);
  });

  it('refuses to report an unlocked result once the deadline has passed', async () => {
    const mockSecretsInput = { read: vi.fn(), readBatch: vi.fn(), clear: vi.fn() };
    const { runtime, ports } = sessionHarness();
    let closes: (() => number) | undefined;

    await expect(
      runProductionUnlocked(
        {
          environment: { CREDS_HOME: tempHome },
          secrets: mockSecretsInput,
          backendPolicy: { kind: 'native' },
          sessionPolicy: SHORT_POLICY,
          sessionPorts: ports,
        },
        (context) => {
          closes = countCloses(context.environment);
          // The work completed, but only after its deadline lapsed.
          runtime.jump(SHORT_POLICY.invocationTimeoutMs);
          return Promise.resolve('projection');
        },
      ),
    ).rejects.toMatchObject({ code: 'SESSION_TIMEOUT' });
    expect(closes?.()).toBe(1);
  });

  it('rejects an invalid session deadline override without echoing it', async () => {
    const mockSecretsInput = { read: vi.fn(), readBatch: vi.fn(), clear: vi.fn() };
    let started = false;

    await expect(
      runProductionUnlocked(
        {
          environment: { CREDS_HOME: tempHome, CREDS_SESSION_TIMEOUT_MS: 'never' },
          secrets: mockSecretsInput,
          backendPolicy: { kind: 'native' },
        },
        () => {
          started = true;
          return Promise.resolve('unreachable');
        },
      ),
    ).rejects.toThrow('The session lifetime policy is invalid.');
    // A policy that cannot be understood must not open an unlocked environment.
    expect(started).toBe(false);
  });
});
