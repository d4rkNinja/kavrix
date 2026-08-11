import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { deviceIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  openProductionEnvironment,
  type ProductionEnvironmentDependencies,
} from '../src/production/environment.js';
import { resolveCliDataPaths } from '../src/production/paths.js';
import type { SecretBackend } from '../src/production/secret-backend.js';
import { createSecretBackend } from '../src/production/secret-backend.js';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

describe('production environment ownership', () => {
  it('holds one global lease and caches one real SQLite sync store per vault', async () => {
    const home = await temporaryHome();
    const paths = resolveCliDataPaths({ CREDS_HOME: home });
    const firstSecrets = await sealedBackend(paths);
    const first = await openProductionEnvironment(paths, firstSecrets);
    const profile = {
      vaultId: vaultIdSchema.parse('vault.primary'),
      deviceId: deviceIdSchema.parse('device.primary'),
    } as never;

    expect(await first.openSyncStore(profile)).toBe(await first.openSyncStore(profile));
    await expect(
      openProductionEnvironment(paths, await sealedBackend(paths)),
    ).rejects.toBeDefined();

    await first.close();
    await first.close();
    const reopened = await openProductionEnvironment(paths, await sealedBackend(paths));
    await reopened.close();
  });

  it('recovers a stale owner at most once and retries acquisition at most once', async () => {
    const events: string[] = [];
    const dependencies = lifecycleDependencies(events, {
      acquireLease: vi
        .fn()
        .mockRejectedValueOnce(new Error('occupied'))
        .mockResolvedValueOnce({
          path: 'lease',
          release: () => {
            events.push('lease');
            return Promise.resolve();
          },
        }),
      recoverLease: vi.fn(() => {
        events.push('recover');
        return Promise.resolve('recovered' as const);
      }),
    });
    const environment = await openProductionEnvironment(
      fakePaths(),
      secretBackend(events),
      dependencies,
    );

    expect(dependencies.acquireLease).toHaveBeenCalledTimes(2);
    expect(dependencies.recoverLease).toHaveBeenCalledTimes(1);
    await environment.close();
  });

  it('acquires the global lease before opening any mutable store', async () => {
    const acquisitions: string[] = [];
    const dependencies = lifecycleDependencies([], {
      ensureDataDirectory: () => {
        acquisitions.push('secure-directory');
        return Promise.resolve();
      },
      acquireLease: () => {
        acquisitions.push('global-lease');
        return Promise.resolve({
          path: 'lease',
          release: () => Promise.resolve(),
        });
      },
      openProfiles: () => {
        acquisitions.push('profiles');
        return Promise.resolve({ close: () => Promise.resolve() } as never);
      },
      openInitializationJournal: () => {
        acquisitions.push('initialization');
        return Promise.resolve({ close: () => Promise.resolve() } as never);
      },
      openJoinJournal: () => {
        acquisitions.push('join');
        return Promise.resolve({ close: () => Promise.resolve() } as never);
      },
      createClipboard: () => {
        acquisitions.push('clipboard');
        return { dispose: () => Promise.resolve() } as never;
      },
    });

    const environment = await openProductionEnvironment(
      fakePaths(),
      secretBackend(),
      dependencies,
    );

    expect(acquisitions).toEqual([
      'secure-directory',
      'global-lease',
      'profiles',
      'initialization',
      'join',
      'clipboard',
    ]);
    await environment.close();
  });

  it('rolls back a failed open in reverse ownership order and surfaces cleanup failures', async () => {
    const events: string[] = [];
    const dependencies = lifecycleDependencies(events, {
      openJoinJournal: vi.fn(() => Promise.reject(new Error('open-canary'))),
      openInitializationJournal: vi.fn(() =>
        Promise.resolve({
          close: () => {
            events.push('initialization');
            return Promise.reject(new Error('cleanup-canary'));
          },
        } as never),
      ),
    });

    await expect(
      openProductionEnvironment(fakePaths(), secretBackend(events), dependencies),
    ).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof AggregateError &&
        error.message === 'Production resources could not be closed.',
    );
    expect(events).toEqual(['initialization', 'profiles', 'secrets', 'lease']);
  });

  it('attempts every close in order after synchronous and asynchronous failures', async () => {
    const events: string[] = [];
    const dependencies = lifecycleDependencies(events, {
      openSyncStore: vi.fn(() =>
        Promise.resolve({
          close: () => {
            events.push('sync');
            throw new Error('sync-close-canary');
          },
        } as never),
      ),
      createClipboard: vi.fn(
        () =>
          ({
            dispose: () => {
              events.push('clipboard');
              return Promise.reject(new Error('clipboard-close-canary'));
            },
          }) as never,
      ),
    });
    const environment = await openProductionEnvironment(
      fakePaths(),
      secretBackend(events),
      dependencies,
    );
    await environment.openSyncStore({ vaultId: 'vault.primary' } as never);

    await expect(environment.close()).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof AggregateError &&
        error.errors.length === 2 &&
        error.message === 'Production resources could not be closed.',
    );
    expect(events).toEqual([
      'sync',
      'clipboard',
      'join',
      'initialization',
      'profiles',
      'secrets',
      'lease',
    ]);
    await expect(environment.close()).rejects.toBeInstanceOf(AggregateError);
    expect(events).toHaveLength(7);
  });
});

async function temporaryHome(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), 'kavrix-cli-environment-'));
  temporaryDirectories.push(path);
  return path;
}

function fakePaths(): ReturnType<typeof resolveCliDataPaths> {
  return resolveCliDataPaths({ CREDS_HOME: join(tmpdir(), 'kavrix-fake-home') });
}

function secretBackend(events: string[] = []): SecretBackend {
  return {
    kind: 'native',
    keychain: {} as never,
    sessions: {} as never,
    protectedSyncState: {} as never,
    joinJournalSecrets: {} as never,
    close: () => {
      events.push('secrets');
      return Promise.resolve();
    },
  };
}

function sealedBackend(
  paths: ReturnType<typeof resolveCliDataPaths>,
): Promise<SecretBackend> {
  return createSecretBackend(
    paths,
    {
      read: () => Promise.reject(new Error('unexpected secret read')),
      readBatch: () => Promise.reject(new Error('unexpected secret batch read')),
    },
    'sealed-file',
  );
}

function lifecycleDependencies(
  events: string[],
  overrides: Partial<ProductionEnvironmentDependencies> = {},
): ProductionEnvironmentDependencies {
  return {
    ensureDataDirectory: () => Promise.resolve(),
    acquireLease: () =>
      Promise.resolve({
        path: 'lease',
        release: () => {
          events.push('lease');
          return Promise.resolve();
        },
      }),
    recoverLease: () => Promise.resolve('absent'),
    openProfiles: () =>
      Promise.resolve({
        close: () => {
          events.push('profiles');
          return Promise.resolve();
        },
      } as never),
    openInitializationJournal: () =>
      Promise.resolve({
        close: () => {
          events.push('initialization');
          return Promise.resolve();
        },
      } as never),
    openJoinJournal: () =>
      Promise.resolve({
        close: () => {
          events.push('join');
          return Promise.resolve();
        },
      } as never),
    openSyncStore: () => Promise.resolve({ close: () => undefined } as never),
    createClipboard: () =>
      ({
        dispose: () => {
          events.push('clipboard');
          return Promise.resolve();
        },
      }) as never,
    ...overrides,
  };
}
