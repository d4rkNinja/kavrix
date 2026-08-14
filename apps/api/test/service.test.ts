import { EventEmitter } from 'node:events';

import type { Db, MongoClient } from 'mongodb';
import { describe, expect, it, vi } from 'vitest';

import { mongoStorageCollectionNames, mongoStorageIndexes } from '@kavrix/storage';

import { mongoApiCollectionNames, mongoApiIndexes } from '../src/mongo-documents.js';
import { createMongoApiServer, type MongoApiServerRuntime } from '../src/server.js';
import {
  apiServiceExitCode,
  runMongoApiService,
  type MongoApiServiceRuntime,
} from '../src/service.js';

class TestSignals {
  readonly #events = new EventEmitter();

  public on(signal: 'SIGINT' | 'SIGTERM', listener: () => void): void {
    this.#events.on(signal, listener);
  }

  public off(signal: 'SIGINT' | 'SIGTERM', listener: () => void): void {
    this.#events.off(signal, listener);
  }

  public send(signal: 'SIGINT' | 'SIGTERM'): void {
    this.#events.emit(signal);
  }

  public listenerCount(signal: 'SIGINT' | 'SIGTERM'): number {
    return this.#events.listenerCount(signal);
  }
}

describe('Mongo API service lifecycle', () => {
  it('installs both contract families, scans both, and only then builds Fastify', async () => {
    const fixture = mongoApiServerRuntime();

    const server = await createMongoApiServer(
      {
        mongodbUri: 'mongodb://127.0.0.1:27017',
        databaseName: 'kavrix_test',
        environment: 'test',
        host: '127.0.0.1',
        port: 3_000,
      },
      fixture.runtime,
      { schemaMode: 'install' },
    );

    expect(fixture.installedNames).toEqual([
      ...Object.values(mongoStorageCollectionNames),
      ...Object.values(mongoApiCollectionNames),
    ]);
    expect(fixture.scanNames).toEqual([
      ...Object.values(mongoStorageCollectionNames),
      ...Object.values(mongoApiCollectionNames),
    ]);
    expect(fixture.installWasCompleteBeforeEveryScan()).toBe(true);
    expect(fixture.buildWasAfterEveryScan()).toBe(true);
    expect(fixture.buildApi).toHaveBeenCalledOnce();
    expect(fixture.listen).not.toHaveBeenCalled();
    expect(fixture.closeClient).not.toHaveBeenCalled();

    await server.close();
    expect(fixture.closeApp).toHaveBeenCalledOnce();
    expect(fixture.closeClient).toHaveBeenCalledOnce();
  });

  it.each([
    ['storage', mongoStorageCollectionNames.vaults],
    ['API', mongoApiCollectionNames.sessions],
  ])(
    'closes Mongo without building Fastify when the %s compatibility scan fails',
    async (_layer, failingCollection) => {
      const fixture = mongoApiServerRuntime(failingCollection);

      await expect(
        createMongoApiServer(
          {
            mongodbUri: 'mongodb://127.0.0.1:27017',
            databaseName: 'kavrix_test',
            environment: 'test',
            host: '127.0.0.1',
            port: 3_000,
          },
          fixture.runtime,
          { schemaMode: 'install' },
        ),
      ).rejects.toThrow();

      expect(fixture.connect).toHaveBeenCalledOnce();
      expect(fixture.closeClient).toHaveBeenCalledOnce();
      expect(fixture.buildApi).not.toHaveBeenCalled();
      expect(fixture.listen).not.toHaveBeenCalled();
      expect(fixture.installWasCompleteBeforeEveryScan()).toBe(true);
      expect(fixture.installedNames).toEqual([
        ...Object.values(mongoStorageCollectionNames),
        ...Object.values(mongoApiCollectionNames),
      ]);
      expect(fixture.scanNames).toEqual(
        failingCollection === mongoStorageCollectionNames.vaults
          ? [mongoStorageCollectionNames.vaults]
          : [
              ...Object.values(mongoStorageCollectionNames),
              mongoApiCollectionNames.sessions,
            ],
      );
    },
  );

  it('starts once and closes exactly once on repeated termination signals', async () => {
    const signals = new TestSignals();
    const close = vi.fn(() => Promise.resolve());
    const startServer = vi.fn(() =>
      Promise.resolve({ address: 'http://127.0.0.1:3000', close }),
    );
    const output = captureOutput();
    const running = runMongoApiService(runtime({ signals, output, startServer }));
    await vi.waitFor(() => {
      expect(startServer).toHaveBeenCalledOnce();
    });

    signals.send('SIGTERM');
    signals.send('SIGINT');

    await expect(running).resolves.toBe(apiServiceExitCode.success);
    expect(close).toHaveBeenCalledOnce();
    expect(signals.listenerCount('SIGINT')).toBe(0);
    expect(signals.listenerCount('SIGTERM')).toBe(0);
    expect(output.text()).toBe(
      '[kavrix-api] started\n[kavrix-api] shutdown requested\n[kavrix-api] stopped\n',
    );
  });

  it('latches a termination signal received while Mongo startup is pending', async () => {
    const signals = new TestSignals();
    const close = vi.fn(() => Promise.resolve());
    let finishStart:
      ((value: { address: string; close(): Promise<void> }) => void) | undefined;
    const startServer = vi.fn(
      () =>
        new Promise<{ address: string; close(): Promise<void> }>((resolve) => {
          finishStart = resolve;
        }),
    );
    const output = captureOutput();
    const running = runMongoApiService(runtime({ signals, output, startServer }));
    await vi.waitFor(() => {
      expect(startServer).toHaveBeenCalledOnce();
    });

    signals.send('SIGINT');
    finishStart?.({ address: 'http://127.0.0.1:3000', close });

    await expect(running).resolves.toBe(apiServiceExitCode.success);
    expect(close).toHaveBeenCalledOnce();
    expect(output.text()).not.toContain('started');
  });

  it('reports a redacted startup failure after a latched termination signal', async () => {
    const signals = new TestSignals();
    const output = captureOutput();
    let failStart: ((reason: Error) => void) | undefined;
    const startServer = vi.fn(
      () =>
        new Promise<{ address: string; close(): Promise<void> }>((_resolve, reject) => {
          failStart = reject;
        }),
    );
    const running = runMongoApiService(runtime({ signals, output, startServer }));
    await vi.waitFor(() => {
      expect(startServer).toHaveBeenCalledOnce();
    });

    signals.send('SIGTERM');
    failStart?.(new Error('startup plaintext-canary'));

    await expect(running).resolves.toBe(apiServiceExitCode.runtimeFailure);
    expect(output.text()).toBe('[kavrix-api] startup failed\n');
    expect(output.text()).not.toContain('plaintext-canary');
  });

  it('returns a redacted startup failure without leaking the Mongo URI', async () => {
    const output = captureOutput();
    const secretUri = 'mongodb://operator:plaintext-canary@db.invalid/kavrix';
    const exitCode = await runMongoApiService(
      runtime({
        environment: { KAVRIX_MONGODB_URI: secretUri },
        output,
        startServer: () =>
          Promise.reject(new Error(`connection refused: ${secretUri}`)),
      }),
    );

    expect(exitCode).toBe(apiServiceExitCode.runtimeFailure);
    expect(output.text()).toBe('[kavrix-api] startup failed\n');
    expect(output.text()).not.toContain('plaintext-canary');
    expect(output.text()).not.toContain('mongodb://');
  });

  it('returns EX_CONFIG for invalid input and identifies only the setting name', async () => {
    const output = captureOutput();
    const startServer = vi.fn();
    const exitCode = await runMongoApiService(
      runtime({
        environment: {
          KAVRIX_MONGODB_URI: 'mongodb://operator:plaintext-canary@db.invalid',
          KAVRIX_API_PORT: 'not-a-port',
        },
        output,
        startServer,
      }),
    );

    expect(exitCode).toBe(apiServiceExitCode.invalidConfiguration);
    expect(startServer).not.toHaveBeenCalled();
    expect(output.text()).toBe(
      '[kavrix-api] configuration invalid (KAVRIX_API_PORT)\n',
    );
    expect(output.text()).not.toContain('plaintext-canary');
  });

  it('redacts an unexpected configuration-reader failure', async () => {
    const output = captureOutput();
    const environment = new Proxy<Record<string, string | undefined>>(
      {},
      {
        ownKeys: () => {
          throw new Error('configuration plaintext-canary');
        },
      },
    );

    await expect(runMongoApiService(runtime({ environment, output }))).resolves.toBe(
      apiServiceExitCode.invalidConfiguration,
    );
    expect(output.text()).toBe('[kavrix-api] configuration invalid\n');
    expect(output.text()).not.toContain('plaintext-canary');
  });

  it('returns a failure when graceful shutdown rejects', async () => {
    const signals = new TestSignals();
    const output = captureOutput();
    const running = runMongoApiService(
      runtime({
        signals,
        output,
        startServer: () =>
          Promise.resolve({
            address: 'http://127.0.0.1:3000',
            close: () => Promise.reject(new Error('shutdown plaintext-canary')),
          }),
      }),
    );
    await vi.waitFor(() => {
      expect(output.text()).toContain('started');
    });
    signals.send('SIGTERM');

    await expect(running).resolves.toBe(apiServiceExitCode.runtimeFailure);
    expect(output.text()).toContain('[kavrix-api] shutdown failed\n');
    expect(output.text()).not.toContain('plaintext-canary');
  });

  it('bounds graceful shutdown and reports a timeout', async () => {
    vi.useFakeTimers();
    try {
      const signals = new TestSignals();
      const output = captureOutput();
      let finishClose: (() => void) | undefined;
      const running = runMongoApiService(
        runtime({
          environment: {
            KAVRIX_MONGODB_URI: 'mongodb://127.0.0.1:27017',
            KAVRIX_API_SHUTDOWN_TIMEOUT_MS: '100',
          },
          signals,
          output,
          startServer: () =>
            Promise.resolve({
              address: 'http://127.0.0.1:3000',
              close: () =>
                new Promise((resolve) => {
                  finishClose = resolve;
                }),
            }),
        }),
      );
      await Promise.resolve();
      await Promise.resolve();
      signals.send('SIGTERM');
      await vi.advanceTimersByTimeAsync(100);

      await expect(running).resolves.toBe(apiServiceExitCode.runtimeFailure);
      expect(output.text()).toContain('[kavrix-api] shutdown timed out\n');
      finishClose?.();
      await Promise.resolve();
    } finally {
      vi.useRealTimers();
    }
  });
});

function runtime(overrides: Partial<MongoApiServiceRuntime>): MongoApiServiceRuntime {
  return {
    environment: { KAVRIX_MONGODB_URI: 'mongodb://127.0.0.1:27017' },
    signals: new TestSignals(),
    output: captureOutput(),
    startServer: () =>
      Promise.resolve({
        address: 'http://127.0.0.1:3000',
        close: () => Promise.resolve(),
      }),
    ...overrides,
  };
}

function captureOutput(): { write(message: string): void; text(): string } {
  const messages: string[] = [];
  return {
    write: (message) => {
      messages.push(message);
    },
    text: () => messages.join(''),
  };
}

function mongoApiServerRuntime(failingCollection?: string): {
  readonly runtime: MongoApiServerRuntime;
  readonly connect: ReturnType<typeof vi.fn>;
  readonly closeClient: ReturnType<typeof vi.fn>;
  readonly buildApi: ReturnType<typeof vi.fn>;
  readonly closeApp: ReturnType<typeof vi.fn>;
  readonly listen: ReturnType<typeof vi.fn>;
  readonly installedNames: readonly string[];
  readonly scanNames: readonly string[];
  installWasCompleteBeforeEveryScan(): boolean;
  buildWasAfterEveryScan(): boolean;
} {
  const storageNames = Object.values(mongoStorageCollectionNames);
  const apiNames = Object.values(mongoApiCollectionNames);
  const expectedNames = [...storageNames, ...apiNames];
  const indexedNames = [
    ...storageNames.filter((name) => mongoStorageIndexes[name].length > 0),
    ...apiNames.filter((name) => mongoApiIndexes[name].length > 0),
  ];
  const installed = new Set<string>();
  const indexed = new Set<string>();
  const installedNames: string[] = [];
  const scanNames: string[] = [];
  let installWasComplete = true;
  let buildWasAfterEveryScan = true;
  const database = {
    listCollections: () => ({ toArray: () => Promise.resolve([]) }),
    createCollection: (name: string) => {
      installed.add(name);
      installedNames.push(name);
      return Promise.resolve({});
    },
    collection: (name: string) => ({
      createIndexes: () => {
        indexed.add(name);
        return Promise.resolve([]);
      },
      find: () => {
        scanNames.push(name);
        if (
          expectedNames.some((expected) => !installed.has(expected)) ||
          indexedNames.some((expected) => !indexed.has(expected))
        ) {
          installWasComplete = false;
        }
        const rows = name === failingCollection ? [{ _id: 'invalid.document' }] : [];
        let index = 0;
        return {
          hasNext: () => Promise.resolve(index < rows.length),
          next: () => Promise.resolve(rows[index++] ?? null),
          close: () => Promise.resolve(),
          toArray: vi.fn(() =>
            Promise.reject(new Error('server-preflight-toArray-canary')),
          ),
        };
      },
    }),
  } as unknown as Db;
  const connect = vi.fn(() => Promise.resolve());
  const closeClient = vi.fn(() => Promise.resolve());
  const client = {
    connect,
    close: closeClient,
    db: () => database,
  } as unknown as MongoClient;
  let closeHook: (() => Promise<void>) | undefined;
  const listen = vi.fn(() => Promise.resolve('http://127.0.0.1:3000'));
  const closeApp = vi.fn(async (): Promise<void> => {
    await closeHook?.();
  });
  const app = {
    addHook: (name: string, hook: () => Promise<void>) => {
      if (name === 'onClose') closeHook = hook;
    },
    close: closeApp,
    listen,
  };
  const buildApi = vi.fn(() => {
    if (scanNames.length !== expectedNames.length) buildWasAfterEveryScan = false;
    return app;
  });
  return {
    runtime: {
      createClient: () => client,
      buildApi: buildApi as unknown as MongoApiServerRuntime['buildApi'],
    },
    connect,
    closeClient,
    buildApi,
    installedNames,
    scanNames,
    installWasCompleteBeforeEveryScan: () => installWasComplete,
    buildWasAfterEveryScan: () => buildWasAfterEveryScan,
    closeApp,
    listen,
  };
}
