import { PassThrough } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  mountKavrixApp,
  mountOnboardingApp,
  type InteractiveAppBackend,
  emptySnapshot,
} from '../../src/index.js';

class TestOutput extends PassThrough {
  columns = 80;
  rows = 24;
  readonly isTTY = true;
}

class TestInput extends PassThrough {
  readonly isTTY = true;
  isRaw = false;

  setRawMode(value: boolean): this {
    this.isRaw = value;
    return this;
  }

  ref(): this {
    return this;
  }

  unref(): this {
    return this;
  }
}

function deferredBackend(): InteractiveAppBackend {
  return {
    load: () =>
      new Promise(() => {
        /* never resolves — first paint must not wait on hydrate */
      }),
    dispatch: async () => ({ snapshot: emptySnapshot() }),
  };
}

describe('CI live-TTY first frame (xfce4-terminal regression)', () => {
  const previousCi = process.env['CI'];
  let handle: { unmount: () => void } | undefined;

  afterEach(() => {
    handle?.unmount();
    handle = undefined;
    if (previousCi === undefined) {
      Reflect.deleteProperty(process.env, 'CI');
    } else {
      process.env['CI'] = previousCi;
    }
  });

  it('mountKavrixApp paints under CI=true with noSplash (Mid/Jr live blank)', async () => {
    process.env['CI'] = 'true';
    const stdout = new TestOutput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => {
      chunks.push(Buffer.from(chunk));
    });
    handle = mountKavrixApp({
      backend: deferredBackend(),
      ascii: true,
      color: false,
      noSplash: true,
      stdout: stdout as unknown as NodeJS.WriteStream,
      stdin: new TestInput() as unknown as NodeJS.ReadStream,
    });
    await vi.waitFor(
      () => {
        const painted = Buffer.concat(chunks).toString('utf8');
        expect(painted.length).toBeGreaterThan(20);
        expect(painted).toMatch(/Loading vault session/i);
      },
      { timeout: 2_000, interval: 40 },
    );
  });

  it('mountOnboardingApp paints under CI=true (Jr init blank)', async () => {
    process.env['CI'] = 'true';
    const stdout = new TestOutput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => {
      chunks.push(Buffer.from(chunk));
    });
    handle = mountOnboardingApp({
      backend: deferredBackend(),
      ascii: true,
      color: false,
      noSplash: true,
      stdout: stdout as unknown as NodeJS.WriteStream,
      stdin: new TestInput() as unknown as NodeJS.ReadStream,
    });
    await vi.waitFor(
      () => {
        expect(Buffer.concat(chunks).length).toBeGreaterThan(20);
      },
      { timeout: 2_000, interval: 40 },
    );
  });
});
