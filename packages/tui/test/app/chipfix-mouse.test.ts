import { PassThrough } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { mountKavrixApp, type KavrixAppHandle } from '../../src/app/app.js';
import {
  emptySnapshot,
  type AppBackendAction,
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

  setRawMode(): this {
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

  latestFrame(): string {
    for (let index = this.chunks.length - 1; index >= 0; index -= 1) {
      const chunk = this.chunks[index];
      if (chunk !== undefined && stripAnsi(chunk).toLowerCase().includes('kavrix /')) {
        return stripAnsi(chunk).replaceAll('\r', '');
      }
    }

    return '';
  }

  /** Resolves when click regions are registered; set by the mount helper. */
  inputReady: () => Promise<void> = () => Promise.resolve();
}

function stripAnsi(value: string): string {
  return value.replace(ANSI_PATTERN, '');
}

function snapshot(
  options: Readonly<{ unlocked?: boolean; count?: number }> = {},
): AppSnapshot {
  const unlocked = options.unlocked ?? true;
  const count = options.count ?? 8;
  return {
    ...emptySnapshot('chipfix mouse fixture'),
    home: {
      profileId: 'chipfix-mouse',
      vaultId: 'chipfix-vault',
      unlocked,
      credentialCount: unlocked ? count : 0,
      datastore: 'file',
      message: 'chipfix mouse fixture',
    },
    credentials: Array.from({ length: unlocked ? count : 0 }, (_, index) => ({
      name: `credential-${String(index + 1).padStart(2, '0')}`,
      maskedValue: '********',
    })),
  };
}

function backendFor(
  initial: AppSnapshot,
  actions: AppBackendAction[],
): InteractiveAppBackend {
  return {
    load: () => Promise.resolve(initial),
    dispatch: (action) => {
      actions.push(action);
      return Promise.resolve({ snapshot: initial });
    },
  };
}

/**
 * Waits for the painted frame that already carries the hydrated session, so
 * measured cell coordinates are never taken from the pre-hydrate Loading frame
 * (which has a different row layout).
 */
async function waitForFrame(
  output: TestOutput,
  expected: readonly (string | RegExp)[],
): Promise<string> {
  let frame = '';
  await vi.waitFor(
    () => {
      frame = output.latestFrame();
      expect(frame).not.toContain('Loading vault session');
      for (const entry of expected) {
        if (typeof entry === 'string') {
          expect(frame).toContain(entry);
        } else {
          expect(frame).toMatch(entry);
        }
      }
    },
    { timeout: 10_000, interval: 20 },
  );
  // Ink can paint before React has flushed the passive effects that measure and
  // register click regions, so a click sent straight after the first frame can
  // land with nothing to hit. `inputReady` resolves when that registration
  // happened; the bounded settle covers Ink's separate raw-mode and stdin
  // subscription effect, which that signal cannot observe.
  await output.inputReady();
  await new Promise((resolve) => setTimeout(resolve, 60));
  return frame;
}

function coordinateOf(
  frame: string,
  label: string | RegExp,
  occurrence: 'first' | 'last' = 'first',
): Readonly<{ x: number; y: number }> {
  const lines = frame.split('\n');
  const matches = (line: string): boolean =>
    typeof label === 'string' ? line.includes(label) : label.test(line);
  const y =
    occurrence === 'first' ? lines.findIndex(matches) : lines.findLastIndex(matches);
  if (y === -1) {
    throw new Error(`Label not rendered: ${String(label)}`);
  }
  const line = lines[y] ?? '';
  const x = typeof label === 'string' ? line.indexOf(label) : line.search(label);
  if (x === -1) {
    throw new Error(`Label has no cell coordinate: ${String(label)}`);
  }
  return { x, y };
}

function click(input: TestInput, coordinate: Readonly<{ x: number; y: number }>): void {
  input.write(`${ESC}[<0;${String(coordinate.x + 1)};${String(coordinate.y + 1)}M`);
}

function mount(
  backend: InteractiveAppBackend,
  input: TestInput,
  output: TestOutput,
): KavrixAppHandle {
  vi.stubEnv('TERM', 'xterm-256color');
  vi.stubEnv('KAVRIX_TUI_MOUSE', '1');
  vi.stubEnv('INK_SCREEN_READER', '');
  const handle = mountKavrixApp({
    backend,
    stdin: input as unknown as NodeJS.ReadStream,
    stdout: output as unknown as NodeJS.WriteStream,
    ascii: true,
    color: false,
    noSplash: true,
    mouse: true,
  });
  output.inputReady = () => handle.waitForInputReady();
  return handle;
}

const mounted = new Set<KavrixAppHandle>();

afterEach(() => {
  for (const handle of mounted) {
    handle.unmount();
  }
  mounted.clear();
});

describe('footer chip click affordances', () => {
  it('ignores a click on the +N more overflow chip and opens Help from the ? chip', async () => {
    const initial = snapshot();
    const actions: AppBackendAction[] = [];
    const input = new TestInput();
    const output = new TestOutput();
    output.columns = 110;
    output.rows = 30;
    const handle = mount(backendFor(initial, actions), input, output);
    mounted.add(handle);

    const home = await waitForFrame(output, [
      'kavrix / Home',
      '8 credentials',
      // The exact overflow count depends on how many global chips fit at this
      // width; the invariant is that an overflow summary exists at all.
      /\+[1-9]\d* more/u,
    ]);
    const overflow = coordinateOf(home, /\+[1-9]\d* more/u);
    click(input, { x: overflow.x + 1, y: overflow.y });
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(output.latestFrame()).toContain('kavrix / Home');
    expect(output.latestFrame()).not.toContain('kavrix / Help');

    click(input, coordinateOf(home, '? help'));
    await waitForFrame(output, ['kavrix / Help', /HELP \/ KEYMAP/u]);
    expect(actions).toEqual([]);

    input.write(ESC);
    const backHome = await waitForFrame(output, ['kavrix / Home', '4 Creds']);
    click(input, coordinateOf(backHome, '4 Creds'));
    await waitForFrame(output, ['kavrix / Creds', 'credential-01']);
    input.write('?');
    await waitForFrame(output, ['kavrix / Help', /HELP \/ KEYMAP/u]);
    expect(actions).toEqual([]);
  });

  it('exposes a clickable u unlock chip on a locked narrow home', async () => {
    const initial = snapshot({ unlocked: false, count: 0 });
    const actions: AppBackendAction[] = [];
    const input = new TestInput();
    const output = new TestOutput();
    output.columns = 40;
    output.rows = 24;
    const handle = mount(backendFor(initial, actions), input, output);
    mounted.add(handle);

    const home = await waitForFrame(output, ['kavrix / Home', 'chipfix-mouse']);
    expect(home).not.toContain('unlock your vault');
    const unlock = coordinateOf(home, 'u unlock');
    click(input, { x: unlock.x + 1, y: unlock.y });
    await waitForFrame(output, ['Unlock vault', 'Enter continue']);
    expect(actions).toEqual([]);
    input.write(ESC);
    await waitForFrame(output, ['kavrix / Home']);
  });
});
