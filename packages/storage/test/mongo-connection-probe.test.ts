import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
const ports = vi.hoisted(() => ({
  construct: vi.fn(),
  terminate: vi.fn(),
  instance: null as EventEmitter | null,
}));
vi.mock('node:worker_threads', () => ({
  Worker: class extends EventEmitter {
    stdout = new PassThrough();
    stderr = new PassThrough();
    constructor(code: string, options: unknown) {
      super();
      ports.construct(code, options);
      ports.instance = this;
    }
    terminate = ports.terminate;
  },
}));
import { probeMongoConnection } from '../src/mongo-connection-probe.js';
beforeEach(() => {
  vi.useFakeTimers();
  ports.construct.mockReset();
  ports.terminate.mockReset().mockResolvedValue(0);
  ports.instance = null;
});
afterEach(() => {
  vi.useRealTimers();
});
describe('bounded non-mutating MongoDB connection probe', () => {
  it('makes the driver TLS default explicit for SRV while refusing an explicit disable', async () => {
    const pending = probeMongoConnection('mongodb+srv://vault.example/test', 'test');
    expect(ports.construct).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        workerData: expect.objectContaining({
          uri: 'mongodb+srv://vault.example/test?tls=true',
        }),
      }),
    );
    ports.instance?.emit('message', 'ok');
    expect(await pending).toBe('ok');
    ports.construct.mockClear();
    expect(
      await probeMongoConnection('mongodb+srv://vault.example/test?tls=false', 'test'),
    ).toBe('transport');
    expect(ports.construct).not.toHaveBeenCalled();
  });
  it('uses fixed worker code and memory-only inputs, suppresses logs, and terminates after success', async () => {
    const pending = probeMongoConnection('mongodb://localhost/test', 'test');
    expect(ports.construct).toHaveBeenCalledWith(
      expect.stringContaining('command({ ping: 1 })'),
      expect.objectContaining({
        eval: true,
        execArgv: [],
        stdout: true,
        stderr: true,
        workerData: expect.objectContaining({ database: 'test' }),
      }),
    );
    const code = ports.construct.mock.calls[0]?.[0] as string;
    expect(code).not.toContain('mongodb://localhost/test');
    expect(code).toContain("default: 'off'");
    expect(code).toContain('serverSelectionTimeoutMS: 5000');
    expect(code).not.toContain('insertOne');
    ports.instance?.emit('message', 'ok');
    expect(await pending).toBe('ok');
    expect(ports.terminate).toHaveBeenCalledOnce();
  });
  it.each([
    ['not-a-url', 'invalid'],
    ['mongodb://vault.example/test', 'transport'],
    ['mongodb://vault.example/test?tls=true&tlsInsecure=true', 'transport'],
  ])('rejects %s before worker creation', async (uri, status) => {
    expect(await probeMongoConnection(uri, 'test')).toBe(status);
    expect(ports.construct).not.toHaveBeenCalled();
  });
  it.each(['authentication', 'private-error-canary'])(
    'returns only finite categories for worker messages %s',
    async (message) => {
      const pending = probeMongoConnection('mongodb://localhost/test', 'test');
      ports.instance?.emit('message', message);
      expect(await pending).toBe(
        message === 'authentication' ? message : 'unreachable',
      );
    },
  );
  it('ends a stalled DNS/connect worker within 15 seconds and ignores late success', async () => {
    const pending = probeMongoConnection('mongodb://localhost/test', 'test');
    await vi.advanceTimersByTimeAsync(15000);
    expect(await pending).toBe('unreachable');
    ports.instance?.emit('message', 'ok');
    expect(ports.terminate).toHaveBeenCalledOnce();
  });
  it.each(['error', 'exit'])('fails closed on worker %s', async (event) => {
    const pending = probeMongoConnection('mongodb://localhost/test', 'test');
    ports.instance?.emit(event, new Error('private-error-canary'));
    expect(await pending).toBe('unreachable');
  });
  it('fails closed when construction or termination fails', async () => {
    ports.construct.mockImplementationOnce(() => {
      throw new Error('private');
    });
    expect(await probeMongoConnection('mongodb://localhost/test', 'test')).toBe(
      'unreachable',
    );
    ports.terminate.mockRejectedValueOnce(new Error('private'));
    const pending = probeMongoConnection('mongodb://localhost/test', 'test');
    ports.instance?.emit('message', 'ok');
    expect(await pending).toBe('unreachable');
  });
  it.each(['', 'bad/name', 'bad\u0000name', 'x'.repeat(129)])(
    'rejects invalid database names',
    async (database) => {
      expect(await probeMongoConnection('mongodb://localhost/test', database)).toBe(
        'invalid',
      );
      expect(ports.construct).not.toHaveBeenCalled();
    },
  );
});
