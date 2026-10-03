import { PassThrough } from 'node:stream';
import { createElement } from 'react';

import { renderToString } from 'ink';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { mountKavrixApp, type KavrixAppHandle } from '../../src/app/app.js';
import {
  emptySnapshot,
  type AppBackendAction,
  type AppSnapshot,
  type InteractiveAppBackend,
} from '../../src/app/backend.js';
import {
  createInitialAppRouterState,
  navigateToScreen,
  transitionAppRouter,
} from '../../src/app/router.js';
import { AppChrome, renderActiveScreen } from '../../src/app/screens.js';

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

  /** Resolves when click regions are registered; set by the `mount` helper. */
  inputReady: () => Promise<void> = () => Promise.resolve();
}

function stripAnsi(value: string): string {
  return value.replace(ANSI_PATTERN, '');
}

function snapshot(
  options: Readonly<{ unlocked?: boolean; count?: number }> = {},
): AppSnapshot {
  const count = options.count ?? 3;
  return {
    ...emptySnapshot(),
    home: {
      profileId: 'regression-profile',
      vaultId: 'regression-vault',
      unlocked: options.unlocked ?? true,
      credentialCount: count,
      datastore: 'file',
      message: 'Regression fixture.',
    },
    profiles: [
      {
        id: 'first-profile',
        datastore: 'file',
        selected: false,
        detail: 'Not the active route.',
      },
      {
        id: 'second-profile',
        datastore: 'file',
        selected: true,
        detail: 'The active route.',
      },
    ],
    credentials: Array.from({ length: count }, (_, index) => ({
      name: `credential-${String(index + 1).padStart(2, '0')}`,
      maskedValue: '********',
    })),
    notice: 'Regression fixture ready.',
    noticeTone: 'info',
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
 * Ink can paint a frame before React has flushed the passive effects that
 * measure and register click regions, so a click sent right after the first
 * frame can land with nothing to hit. `output.inputReady` resolves when that
 * registration actually happened, which is deterministic; the bounded sleep
 * this keeps covers Ink's separate raw-mode and stdin subscription effect, which
 * that signal cannot observe.
 */
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
    { timeout: 10_000, interval: 20 },
  );
  await output.inputReady();
  await new Promise((resolve) => setTimeout(resolve, 40));
  return frame;
}

function coordinateOf(
  frame: string,
  label: string,
): Readonly<{ x: number; y: number }> {
  const lines = frame.split('\n');
  const y = lines.findIndex((line) => line.includes(label));
  if (y === -1) throw new Error(`Label not rendered: ${label}`);
  const x = lines[y]?.indexOf(label) ?? -1;
  if (x === -1) throw new Error(`Label has no cell coordinate: ${label}`);
  return { x, y };
}

function clickReport(coordinate: Readonly<{ x: number; y: number }>): string {
  return `${ESC}[<0;${String(coordinate.x + 1)};${String(coordinate.y + 1)}M`;
}

/**
 * Clicks a label until `expected` is painted, within a bounded budget.
 *
 * A click can be lost when it lands in the React commit that remounts the chrome
 * and re-registers every region. Retrying is bounded and only used for clicks
 * that must act, so a genuinely broken click — wrong coordinates, a disabled
 * region, or one the stale-frame guard rejects — still fails on every attempt.
 */
async function clickUntil(
  output: TestOutput,
  input: TestInput,
  label: string,
  expected: string,
): Promise<string> {
  const deadline = Date.now() + 8_000;
  for (;;) {
    await output.inputReady();
    input.write(clickReport(coordinateOf(output.latestFrame(), label)));
    try {
      let frame = '';
      await vi.waitFor(
        () => {
          frame = output.latestFrame();
          expect(frame).toContain(expected);
        },
        { timeout: 400, interval: 20 },
      );
      return frame;
    } catch {
      if (Date.now() >= deadline) {
        throw new Error(`Clicking "${label}" never produced "${expected}".`);
      }
    }
  }
}

const mounted = new Set<KavrixAppHandle>();

afterEach(() => {
  for (const handle of mounted) handle.unmount();
  mounted.clear();
});

function mount(
  initial: AppSnapshot,
  actions: AppBackendAction[],
  options: Readonly<{ columns?: number; rows?: number }> = {},
): Readonly<{ input: TestInput; output: TestOutput; handle: KavrixAppHandle }> {
  const input = new TestInput();
  const output = new TestOutput();
  if (options.columns !== undefined) output.columns = options.columns;
  if (options.rows !== undefined) output.rows = options.rows;
  vi.stubEnv('TERM', 'xterm-256color');
  vi.stubEnv('KAVRIX_TUI_MOUSE', '1');
  const handle = mountKavrixApp({
    backend: backendFor(initial, actions),
    stdin: input as unknown as NodeJS.ReadStream,
    stdout: output as unknown as NodeJS.WriteStream,
    ascii: true,
    color: false,
    noSplash: true,
  });
  mounted.add(handle);
  // Resolved at await time, not captured here: the chrome remounts on navigation,
  // which disposes and re-registers every region, so readiness has to be
  // re-checked against the live set after each frame.
  output.inputReady = () => handle.waitForInputReady();
  return { input, output, handle };
}

describe('Ctrl+C exit', () => {
  it('quits the app instead of leaving the user stuck in a wedged session', async () => {
    const actions: AppBackendAction[] = [];
    const { input, output, handle } = mount(snapshot(), actions);
    await waitForFrame(output, 'kavrix /');

    input.write('\u0003');
    mounted.delete(handle);
    await expect(handle.waitUntilExit()).resolves.toBeUndefined();
    expect(output.allOutput()).toContain(`${ESC}[?1049l`);
    expect(input.isRaw).toBe(false);
  });

  it('quits from an open unlock overlay so a blocked command is always abortable', async () => {
    const actions: AppBackendAction[] = [];
    const { input, output, handle } = mount(snapshot({ unlocked: false }), actions);
    await waitForFrame(output, 'unlock your vault');

    input.write('u');
    await waitForFrame(output, 'Unlock vault');

    input.write('\u0003');
    mounted.delete(handle);
    await expect(handle.waitUntilExit()).resolves.toBeUndefined();
    expect(output.allOutput()).toContain(`${ESC}[?1049l`);
    expect(actions).toEqual([]);
  });
});

describe('terminal restoration order', () => {
  it('releases mouse reporting before Ink leaves the alternate screen', async () => {
    const actions: AppBackendAction[] = [];
    const { input, output, handle } = mount(snapshot(), actions);
    await waitForFrame(output, 'kavrix /');

    input.write('q');
    mounted.delete(handle);
    await handle.waitUntilExit();

    const written = output.allOutput();
    const disable = written.indexOf(`${ESC}[?1006l`);
    const leave = written.indexOf(`${ESC}[?1049l`);
    expect(disable).toBeGreaterThan(-1);
    expect(leave).toBeGreaterThan(-1);
    // The shell must never come back with mouse reporting still switched on.
    expect(disable).toBeLessThan(leave);
  });
});

describe('frame-exact click handling', () => {
  it('ignores the second click of one read even when it targets another tab', async () => {
    const actions: AppBackendAction[] = [];
    const { input, output } = mount(snapshot(), actions);
    const frame = await waitForFrame(output, '1 Home');

    // Both reports were decoded against the same painted frame. Acting on the
    // second would resolve coordinates that belonged to the previous screen.
    input.write(
      clickReport(coordinateOf(frame, '4 Creds')) +
        clickReport(coordinateOf(frame, '5 Doctor')),
    );

    await clickUntil(output, input, '4 Creds', 'kavrix / Creds');
    // The rejected second click must not fire later, on its own.
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(output.latestFrame()).not.toContain('kavrix / Doctor');
  });

  it('still accepts a click that arrives after the frame has been repainted', async () => {
    const actions: AppBackendAction[] = [];
    const { input, output } = mount(snapshot(), actions);
    await waitForFrame(output, '4 Creds');

    await clickUntil(output, input, '5 Doctor', 'kavrix / Doctor');
  });
});

describe('profile selection requires an explicit second click', () => {
  it('does not switch the active datastore profile on a single row click', async () => {
    const actions: AppBackendAction[] = [];
    const { input, output } = mount(snapshot(), actions);
    await waitForFrame(output, 'kavrix / Home');

    const frame = await clickUntil(output, input, '2 Profiles', 'kavrix / Profiles');
    expect(frame).toContain('first-profile');

    input.write(clickReport(coordinateOf(frame, 'first-profile')));
    // The row is now selected, but switching the active route is a real state
    // change and must not ride along with the selection.
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(actions).toEqual([]);

    expect(output.latestFrame()).toMatch(/>\s+first-profile/u);

    // Second click on the already selected row applies it.
    await vi.waitFor(
      () => {
        input.write(clickReport(coordinateOf(output.latestFrame(), 'first-profile')));
        expect(actions).toContainEqual({
          type: 'use-profile',
          profileId: 'first-profile',
        });
      },
      { timeout: 5_000, interval: 100 },
    );
  });
});

describe('masked fields reject orphaned control-sequence bytes', () => {
  it('never lets a mouse report split after the introducer reach the passphrase', async () => {
    const actions: AppBackendAction[] = [];
    const { input, output } = mount(snapshot({ unlocked: false }), actions);
    await waitForFrame(output, 'unlock your vault');

    input.write('u');
    await waitForFrame(output, 'Unlock vault');

    // Split at every boundary from `ESC[` onward, pausing past both the
    // decoder's and Ink's escape windows each time. The decoder holds these
    // tails, so none of it may reach the masked field as text.
    const report = `${ESC}[<0;40;12M`;
    for (let cut = 2; cut < report.length; cut += 1) {
      input.write(report.slice(0, cut));
      await new Promise((resolve) => setTimeout(resolve, 45));
      input.write(report.slice(cut));
      await new Promise((resolve) => setTimeout(resolve, 45));
    }

    expect(output.latestFrame()).toContain('Unlock vault');

    input.write('canary-passphrase');
    await waitForFrame(output, '*'.repeat('canary-passphrase'.length));
    input.write('\r');

    await vi.waitFor(() => {
      expect(actions).toContainEqual({
        type: 'unlock',
        passphrase: 'canary-passphrase',
      });
    });
    expect(actions.filter((action) => action.type === 'unlock')).toHaveLength(1);
    expect(stripAnsi(output.allOutput())).not.toContain('canary-passphrase');
  });

  it('treats a lone escape byte as the Escape key rather than leaking a report', async () => {
    const actions: AppBackendAction[] = [];
    const { input, output } = mount(snapshot({ unlocked: false }), actions);
    await waitForFrame(output, 'unlock your vault');

    input.write('u');
    await waitForFrame(output, 'Unlock vault');

    // A single ESC byte is indistinguishable from the first byte of a report.
    // Resolving it as Escape cancels the overlay, which is the safe direction:
    // an operation is abandoned, never completed with corrupted input.
    input.write(ESC);
    await waitForFrame(output, 'Unlock cancelled.');
    expect(actions).toEqual([]);

    // The report tail that follows must not be typed anywhere.
    input.write('[<0;40;12M');
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(output.latestFrame()).not.toContain('[<0;40;12M');
    expect(output.latestFrame()).not.toContain('40;12M');
  });

  it('keeps the masked row exactly as long as what was typed', async () => {
    const actions: AppBackendAction[] = [];
    const { input, output } = mount(snapshot({ unlocked: false }), actions);
    await waitForFrame(output, 'unlock your vault');

    input.write('u');
    await waitForFrame(output, 'Unlock vault');

    input.write('abcdefgh');
    await waitForFrame(output, '*'.repeat(8));

    // A click anywhere must not alter the field, and a scroll must not either.
    input.write(`${ESC}[<0;10;5M${ESC}[<65;10;5M`);
    await new Promise((resolve) => setTimeout(resolve, 120));

    expect(output.latestFrame()).toContain('*'.repeat(8));
    expect(output.latestFrame()).not.toContain('*'.repeat(9));
  });
});

describe('layout on short terminals', () => {
  function chromeAt(width: number, height: number, overlay: boolean): string {
    let state = navigateToScreen(
      createInitialAppRouterState({ width, height, ascii: true, color: false }),
      'home',
    );
    if (overlay) {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: 't' },
        nowMs: 0,
      }).state;
    }
    return renderToString(
      createElement(AppChrome, { state, children: renderActiveScreen(state) }),
      { columns: width },
    );
  }

  it('does not render a dangling panel border at the minimum supported height', () => {
    const frame = chromeAt(40, 12, false);
    const lines = frame.split('\n');
    // A panel that opens and never closes is the signature of the root clip
    // landing inside a bordered box.
    for (const line of lines) {
      const opens = /^\s*\+-+\+?\s*$/u.test(line);
      if (!opens) continue;
      expect(line).toMatch(/^\s*\+.*\+\s*$/u);
    }
    expect(frame).toMatch(/q quit/u);
  });

  it('keeps the theme picker action row on a 14 row terminal', () => {
    const frame = chromeAt(80, 14, true);
    expect(frame).toContain('apply theme');
    expect(frame).toContain('cancel');
  });
});
