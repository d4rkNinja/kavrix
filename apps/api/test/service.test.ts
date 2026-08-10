import { EventEmitter } from 'node:events';

import { describe, expect, it, vi } from 'vitest';

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
