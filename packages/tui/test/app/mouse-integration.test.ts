import { PassThrough } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { mountKavrixApp, type KavrixAppHandle } from '../../src/app/app.js';
import {
  emptySnapshot,
  type AppBackendAction,
  type AppBackendResult,
  type AppSnapshot,
  type InteractiveAppBackend,
} from '../../src/app/backend.js';

const ESC = String.fromCharCode(27);
const ANSI_PATTERN = new RegExp(
  `${ESC}(?:\\[[0-?]*[ -/]*[@-~]|\\][^${String.fromCharCode(7)}]*(?:${String.fromCharCode(7)}|${ESC}\\\\))`,
  'gu',
);

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

class TestOutput extends PassThrough {
  columns = 120;
  rows = 30;
  readonly isTTY = true;
  readonly chunks: string[] = [];

  constructor() {
    super();
    this.on('data', (chunk: Buffer) => {
      this.chunks.push(chunk.toString('utf8'));
    });
  }

  allOutput(): string {
    return this.chunks.join('');
  }

  latestFrame(): string {
    for (let index = this.chunks.length - 1; index >= 0; index -= 1) {
      const chunk = this.chunks[index];
      if (chunk !== undefined && stripAnsi(chunk).toLowerCase().includes('kavrix /')) {
        return stripAnsi(chunk).replaceAll('\r', '');
      }
    }

    return '';
  }
}

function stripAnsi(value: string): string {
  return value.replace(ANSI_PATTERN, '');
}

function snapshot(
  options: Readonly<{ unlocked?: boolean; count?: number }> = {},
): AppSnapshot {
  const count = options.count ?? 8;
  return {
    ...emptySnapshot(),
    home: {
      profileId: 'mouse-profile',
      vaultId: 'mouse-vault',
      unlocked: options.unlocked ?? true,
      credentialCount: count,
      datastore: 'file',
      message: 'Mouse integration fixture.',
    },
    credentials: Array.from({ length: count }, (_, index) => ({
      name: `credential-${String(index + 1).padStart(2, '0')}`,
      maskedValue: '********',
    })),
    notice: 'Ready for integration input.',
    noticeTone: 'info',
  };
}

function backendFor(
  initial: AppSnapshot,
  dispatch: InteractiveAppBackend['dispatch'] = () =>
    Promise.resolve({ snapshot: initial }),
): InteractiveAppBackend {
  return {
    load: () => Promise.resolve(initial),
    dispatch,
  };
}

async function waitForFrame(
  output: TestOutput,
  expected: string | RegExp,
): Promise<string> {
  let frame = '';
  await vi.waitFor(
    () => {
      frame = output.latestFrame();
      if (typeof expected === 'string') {
        expect(frame).toContain(expected);
      } else {
        expect(frame).toMatch(expected);
      }
    },
    { timeout: 3_000, interval: 20 },
  );
  // Ink can paint before React has flushed passive effects that register
  // measured click regions. Wait one bounded post-commit turn before input.
  await new Promise((resolve) => setTimeout(resolve, 40));
  return frame;
}

function coordinateOf(
  frame: string,
  label: string,
  occurrence: 'first' | 'last' = 'first',
): Readonly<{ x: number; y: number }> {
  const lines = frame.split('\n');
  const y =
    occurrence === 'first'
      ? lines.findIndex((line) => line.includes(label))
      : lines.findLastIndex((line) => line.includes(label));
  if (y === -1) {
    throw new Error(`Label not rendered: ${label}`);
  }
  const x = lines[y]?.indexOf(label) ?? -1;
  if (x === -1) {
    throw new Error(`Label has no cell coordinate: ${label}`);
  }
  return { x, y };
}

function click(input: TestInput, coordinate: Readonly<{ x: number; y: number }>): void {
  input.write(`${ESC}[<0;${String(coordinate.x + 1)};${String(coordinate.y + 1)}M`);
}

function wheelDown(
  input: TestInput,
  coordinate: Readonly<{ x: number; y: number }>,
): void {
  input.write(`${ESC}[<65;${String(coordinate.x + 1)};${String(coordinate.y + 1)}M`);
}

function mount(
  backend: InteractiveAppBackend,
  input: TestInput,
  output: TestOutput,
  mouse = true,
): KavrixAppHandle {
  vi.stubEnv('TERM', 'xterm-256color');
  vi.stubEnv('KAVRIX_TUI_MOUSE', '1');
  vi.stubEnv('INK_SCREEN_READER', '');
  return mountKavrixApp({
    backend,
    stdin: input as unknown as NodeJS.ReadStream,
    stdout: output as unknown as NodeJS.WriteStream,
    ascii: true,
    color: false,
    noSplash: true,
    mouse,
  });
}

function deferredResult(): Readonly<{
  promise: Promise<AppBackendResult>;
  resolve: (result: AppBackendResult) => void;
}> {
  let resolvePromise: ((result: AppBackendResult) => void) | undefined;
  return {
    promise: new Promise((resolve) => {
      resolvePromise = resolve;
    }),
    resolve: (result) => {
      resolvePromise?.(result);
    },
  };
}

const mounted = new Set<KavrixAppHandle>();

afterEach(() => {
  for (const handle of mounted) {
    handle.unmount();
  }
  mounted.clear();
});

describe('mounted Kavrix mouse interaction', () => {
  it('clicks tabs and a credential row while preserving reveal and removal confirmation', async () => {
    const initial = snapshot();
    const actions: AppBackendAction[] = [];
    const backend = backendFor(initial, (action) => {
      actions.push(action);
      return Promise.resolve(
        action.type === 'reveal-credential'
          ? { snapshot: initial, revealedSecret: 'REVEALED-TEST-CANARY' }
          : { snapshot: initial },
      );
    });
    const input = new TestInput();
    const output = new TestOutput();
    const handle = mount(backend, input, output);
    mounted.add(handle);

    let frame = await waitForFrame(output, '1 Home');
    click(input, coordinateOf(frame, '4 Creds'));
    frame = await waitForFrame(output, 'kavrix / Creds');
    click(input, coordinateOf(frame, 'credential-01'));
    frame = await waitForFrame(output, 'Credential detail');
    expect(frame).toContain('********');

    input.write('r');
    frame = await waitForFrame(output, 'REVEAL selected secret? y/n');
    expect(actions).toEqual([]);
    const confirmation = coordinateOf(frame, 'y confirm');
    input.write(
      `${ESC}[200~${ESC}[<0;${String(confirmation.x + 1)};${String(confirmation.y + 1)}M${ESC}[201~`,
    );
    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(actions).toEqual([]);
    expect(output.latestFrame()).toContain('REVEAL selected secret? y/n');
    input.write('y');
    await vi.waitFor(() => {
      expect(actions).toContainEqual({
        type: 'reveal-credential',
        name: 'credential-01',
      });
    });

    await waitForFrame(output, 'REVEAL: REVEALED-TEST-CANARY');
    input.write('x');
    await waitForFrame(output, 'Remove credential? y/n');
    expect(actions).not.toContainEqual({
      type: 'remove-credential',
      name: 'credential-01',
    });

    input.write(String.fromCharCode(27));
    frame = await waitForFrame(output, 'Remove cancelled.');
    click(input, coordinateOf(frame, '1 Home'));
    await waitForFrame(output, 'kavrix / Home');
  });

  it('moves the credential window by wheel and keeps the selected pointer after resize', async () => {
    const initial = snapshot({ count: 12 });
    const input = new TestInput();
    const output = new TestOutput();
    const handle = mount(backendFor(initial), input, output);
    mounted.add(handle);

    let frame = await waitForFrame(output, '4 Creds');
    click(input, coordinateOf(frame, '4 Creds'));
    frame = await waitForFrame(output, 'credential-01');
    expect(frame).toMatch(/>\s+credential-01/u);

    wheelDown(input, coordinateOf(frame, 'credential-01'));
    await waitForFrame(output, />\s+credential-02/u);

    output.columns = 72;
    output.rows = 18;
    output.chunks.length = 0;
    output.emit('resize');
    frame = await waitForFrame(output, />\s+credential-02/u);
    expect(frame).toContain('credential-02');
    expect(frame).toMatch(/>\s+credential-02/u);
  });

  it('filters split mouse frames from a secret input when mouse mode is disabled', async () => {
    const initial = snapshot({ unlocked: false, count: 0 });
    const actions: AppBackendAction[] = [];
    const backend = backendFor(initial, (action) => {
      actions.push(action);
      return Promise.resolve({ snapshot: initial });
    });
    const input = new TestInput();
    const output = new TestOutput();
    const handle = mount(backend, input, output, false);
    mounted.add(handle);

    await waitForFrame(output, 'kavrix / Home');
    expect(output.allOutput()).not.toContain(`${ESC}[?1000h`);
    expect(output.allOutput()).not.toContain(`${ESC}[?1006h`);
    // Disabling the mouse keeps native text selection without demoting the UI to
    // an inline frame, so the alternate screen is independent of mouse support.
    expect(output.allOutput()).toContain(`${ESC}[?1049h`);

    input.write('u');
    await waitForFrame(output, 'Unlock vault');
    input.write('SECRET-INPUT-CANARY');
    await waitForFrame(output, '*'.repeat('SECRET-INPUT-CANARY'.length));
    input.write(`${ESC}[<0;1;`);
    input.write('1M');
    await new Promise((resolve) => setImmediate(resolve));
    input.write('\r');
    await vi.waitFor(() => {
      expect(actions).toContainEqual({
        type: 'unlock',
        passphrase: 'SECRET-INPUT-CANARY',
      });
    });
    expect(stripAnsi(output.allOutput())).not.toContain('SECRET-INPUT-CANARY');
    handle.unmount();
    mounted.delete(handle);
    expect(input.isRaw).toBe(false);
  });

  it('blocks duplicate clicks while dispatch is unresolved and restores terminal state on quit', async () => {
    const initial = snapshot();
    const pending = deferredResult();
    const dispatch = vi
      .fn<InteractiveAppBackend['dispatch']>()
      .mockImplementation(async () => pending.promise);
    const input = new TestInput();
    const output = new TestOutput();
    const handle = mount(backendFor(initial, dispatch), input, output);
    mounted.add(handle);

    const frame = await waitForFrame(output, '5 Doctor');
    expect(output.allOutput()).toContain(`${ESC}[?1000h${ESC}[?1006h`);
    expect(input.isRaw).toBe(true);
    const doctor = coordinateOf(frame, '5 Doctor');
    const report = `${ESC}[<0;${String(doctor.x + 1)};${String(doctor.y + 1)}M`;
    input.write(report + report);
    await vi.waitFor(() => {
      expect(dispatch).toHaveBeenCalledOnce();
    });
    expect(dispatch).toHaveBeenCalledWith({ type: 'run-doctor' });
    expect(input.isRaw).toBe(true);

    pending.resolve({ snapshot: initial });
    await waitForFrame(output, 'Ready for integration input.');
    input.write('q');
    mounted.delete(handle);
    await handle.waitUntilExit();

    expect(input.isRaw).toBe(false);
    expect(output.allOutput()).toContain(`${ESC}[?1006l${ESC}[?1000l`);
    expect(output.allOutput()).toContain(`${ESC}[?1049l`);
    expect(input.listenerCount('data')).toBe(0);
  });

  it('rejects a second stale Home click from the same input read', async () => {
    const base = snapshot({ count: 1 });
    const initial: AppSnapshot = {
      ...base,
      profiles: [
        {
          id: 'profile-canary',
          datastore: 'file',
          selected: true,
          detail: 'Must not be activated by stale Home input.',
        },
      ],
    };
    const actions: AppBackendAction[] = [];
    const input = new TestInput();
    const output = new TestOutput();
    const handle = mount(
      backendFor(initial, (action) => {
        actions.push(action);
        return Promise.resolve({ snapshot: initial });
      }),
      input,
      output,
    );
    mounted.add(handle);

    const frame = await waitForFrame(output, 'Datastore routes');
    const profiles = coordinateOf(frame, 'Datastore routes');
    const report = `${ESC}[<0;${String(profiles.x + 1)};${String(profiles.y + 1)}M`;
    input.write(report + report);
    await waitForFrame(output, 'kavrix / Profiles');
    expect(actions).not.toContainEqual({
      type: 'use-profile',
      profileId: 'profile-canary',
    });
  });
});
