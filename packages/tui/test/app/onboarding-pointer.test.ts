import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  mountOnboardingApp,
  type OnboardingAppHandle,
} from '../../src/app/onboarding-app.js';
import {
  emptySnapshot,
  type AppBackendAction,
  type InteractiveAppBackend,
} from '../../src/app/backend.js';

const ESC = String.fromCharCode(27);
const ANSI = new RegExp(`${ESC}\\[[0-?]*[ -/]*[@-~]`, 'gu');
class Input extends PassThrough {
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
class Output extends PassThrough {
  readonly isTTY = true;
  columns = 100;
  rows = 30;
  readonly chunks: string[] = [];
  constructor() {
    super();
    this.on('data', (chunk: Buffer) => {
      this.chunks.push(chunk.toString('utf8'));
    });
  }
  frame(): string {
    return (
      this.chunks
        .findLast((chunk) => chunk.includes('kavrix / SETUP'))
        ?.replace(ANSI, '')
        .replaceAll('\r', '') ?? ''
    );
  }
}
const handles = new Set<OnboardingAppHandle>();
afterEach(() => {
  for (const handle of handles) handle.unmount();
  handles.clear();
});

function mount(
  mouse = true,
  dispatch?: InteractiveAppBackend['dispatch'],
): {
  input: Input;
  output: Output;
  handle: OnboardingAppHandle;
  calls: AppBackendAction[];
} {
  vi.stubEnv('TERM', 'xterm-256color');
  vi.stubEnv('INK_SCREEN_READER', '');
  vi.stubEnv('KAVRIX_TUI_MOUSE', '1');
  const input = new Input();
  const output = new Output();
  const calls: AppBackendAction[] = [];
  const backend: InteractiveAppBackend = {
    load: () => Promise.resolve(emptySnapshot()),
    dispatch: (action, onProgress) => {
      calls.push(action);
      return (
        dispatch?.(action, onProgress) ??
        Promise.resolve({
          snapshot: {
            ...emptySnapshot(),
            noticeTone: 'success',
            notice: 'Destination checked.',
          },
        })
      );
    },
  };
  const handle = mountOnboardingApp({
    backend,
    stdin: input as unknown as NodeJS.ReadStream,
    stdout: output as unknown as NodeJS.WriteStream,
    mouse,
    ascii: true,
    color: false,
    noSplash: true,
  });
  handles.add(handle);
  return { input, output, handle, calls };
}

async function ready(
  fixture: ReturnType<typeof mount>,
  expected: string,
  waitForInput = true,
): Promise<void> {
  await vi.waitFor(
    () => {
      expect(fixture.output.frame()).toContain(expected);
    },
    { timeout: 5_000 },
  );
  if (waitForInput) await fixture.handle.waitForInputReady();
  await new Promise((resolve) => setTimeout(resolve, 40));
}
function report(
  fixture: ReturnType<typeof mount>,
  label: string,
  rowOffset = 0,
): string {
  const lines = fixture.output.frame().split('\n');
  const row = lines.findLastIndex((line) => line.includes(label));
  expect(row).toBeGreaterThanOrEqual(0);
  const column = lines[row]?.indexOf(label) ?? -1;
  return `${ESC}[<0;${String(column + 1)};${String(row + 1 + rowOffset)}M`;
}
async function click(
  fixture: ReturnType<typeof mount>,
  label: string,
  expected: string,
  rowOffset = 0,
): Promise<void> {
  await fixture.handle.waitForInputReady();
  fixture.input.write(report(fixture, label, rowOffset));
  await ready(fixture, expected);
}

describe('mounted setup pointer and full-screen controls', () => {
  it('reviews before creation, streams real stages and elapsed time, and rejects duplicate create clicks', async () => {
    let complete:
      | ((result: Awaited<ReturnType<InteractiveAppBackend['dispatch']>>) => void)
      | undefined;
    let reportProgress: Parameters<InteractiveAppBackend['dispatch']>[1];
    const fixture = mount(true, (action, progress) => {
      if (action.type !== 'create-file-profile')
        return Promise.resolve({
          snapshot: {
            ...emptySnapshot(),
            noticeTone: 'success',
            notice: 'Destination checked.',
          },
        });
      reportProgress = progress;
      return new Promise((resolve) => {
        complete = resolve;
      });
    });
    await ready(fixture, 'Welcome');
    await click(fixture, 'Enter start', 'Local encrypted file');
    await click(fixture, 'Enter continue', 'Profile id:');
    await click(fixture, 'Enter continue', 'Data file:');
    await click(fixture, 'Enter continue', 'Key file:');
    await click(fixture, 'Enter continue', 'Owner passphrase:');
    const owner = 'mounted-owner-canary';
    const recovery = 'mounted-recovery-canary';
    fixture.input.write(owner);
    await new Promise((resolve) => setTimeout(resolve, 40));
    await click(fixture, 'Enter continue', 'Confirm owner passphrase:');
    fixture.input.write(owner);
    await new Promise((resolve) => setTimeout(resolve, 40));
    await click(fixture, 'Enter continue', 'Recovery-kit passphrase:');
    fixture.input.write(recovery);
    await new Promise((resolve) => setTimeout(resolve, 40));
    await click(fixture, 'Enter continue', 'Confirm recovery-kit passphrase:');
    fixture.input.write(recovery);
    await new Promise((resolve) => setTimeout(resolve, 40));
    await click(fixture, 'Enter continue', 'Recovery kit path:');
    await click(fixture, 'Enter continue', 'REVIEW BEFORE CREATING');
    expect(fixture.calls.some((action) => action.type === 'create-file-profile')).toBe(
      false,
    );
    fixture.input.write(report(fixture, 'Enter create'));
    await ready(fixture, 'Checking protected destinations', false);
    reportProgress?.({ stage: 'verifying-recovery' });
    await ready(fixture, 'Verifying recovery kit', false);
    await vi.waitFor(
      () => {
        expect(fixture.output.frame()).toContain('Elapsed 1s');
      },
      {
        timeout: 2500,
      },
    );
    fixture.input.write('\r\r');
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(
      fixture.calls.filter((action) => action.type === 'create-file-profile'),
    ).toHaveLength(1);
    complete?.({
      snapshot: { ...emptySnapshot(), noticeTone: 'success', notice: 'Created.' },
    });
    await ready(fixture, 'Session unlock');
    const output = fixture.output.chunks.join('');
    expect(output).not.toContain(owner);
    expect(output).not.toContain(recovery);
  });
  it('uses larger button padding to start, select MongoDB, continue, and quit', async () => {
    const fixture = mount();
    await ready(fixture, 'Welcome');
    expect(fixture.output.chunks.join('')).toContain(`${ESC}[?1049h`);
    expect(fixture.output.chunks.join('')).toContain(`${ESC}[?1006h`);
    await click(fixture, 'Enter start', 'Local encrypted file', -1);
    await click(fixture, '2  MongoDB', 'MongoDB selected.');
    await click(fixture, 'Enter continue', 'Profile id:');
    expect(fixture.calls).toHaveLength(0);
    fixture.input.write(report(fixture, '^C quit'));
    expect(await fixture.handle.waitUntilExit()).toEqual({ status: 'cancelled' });
    const all = fixture.output.chunks.join('');
    expect(all.lastIndexOf(`${ESC}[?1006l`)).toBeLessThan(
      all.lastIndexOf(`${ESC}[?1049l`),
    );
    expect(fixture.input.isRaw).toBe(false);
  });

  it('rejects a second click in the same stale input frame', async () => {
    const fixture = mount();
    await ready(fixture, 'Welcome');
    const start = report(fixture, 'Enter start');
    fixture.input.write(start + start);
    await ready(fixture, 'Local encrypted file');
    expect(fixture.output.frame()).not.toContain('Profile id:');
  });

  it('keeps reports out of masked input and routes keyboard Enter through Help', async () => {
    const fixture = mount();
    await ready(fixture, 'Welcome');
    await click(fixture, 'Enter start', 'Local encrypted file');
    await click(fixture, 'Enter continue', 'Profile id:');
    await click(fixture, 'Enter continue', 'Data file:');
    await click(fixture, 'Enter continue', 'Key file:');
    await click(fixture, 'Enter continue', 'Owner passphrase:');
    const canary = 'private-pointer-canary-7326';
    fixture.input.write(canary);
    await ready(fixture, '*'.repeat(canary.length));
    fixture.input.write(`${ESC}[<0;`);
    fixture.input.write('999;999M');
    await click(fixture, '^G help', 'SETUP GUIDANCE');
    const count = fixture.calls.length;
    fixture.input.write('\r');
    await ready(fixture, 'Owner passphrase:');
    expect(fixture.calls).toHaveLength(count);
    fixture.input.write('\u0007');
    await ready(fixture, 'SETUP GUIDANCE');
    fixture.input.write(ESC);
    await ready(fixture, 'Owner passphrase:');
    expect(fixture.output.frame()).toContain('*'.repeat(canary.length));
    expect(fixture.output.chunks.join('')).not.toContain(canary);
  });

  it('keeps fullscreen with mouse disabled and resizes to a compact keyboard layout', async () => {
    const fixture = mount(false);
    await ready(fixture, 'Welcome');
    expect(fixture.output.chunks.join('')).toContain(`${ESC}[?1049h`);
    expect(fixture.output.chunks.join('')).not.toContain(`${ESC}[?1006h`);
    fixture.output.columns = 40;
    fixture.output.rows = 12;
    fixture.output.emit('resize');
    await ready(fixture, 'THIS STEP IS ACTIVE');
    expect(fixture.output.frame().split('\n')).toHaveLength(12);
    expect(fixture.output.frame()).toContain('^C quit');
    fixture.input.write('\r');
    await ready(fixture, 'Local encrypted file');
  });

  it('blocks duplicate clicks while a destination is being checked', async () => {
    let resolveCheck:
      | ((value: Awaited<ReturnType<InteractiveAppBackend['dispatch']>>) => void)
      | undefined;
    const fixture = mount(
      true,
      () =>
        new Promise((resolve) => {
          resolveCheck = resolve;
        }),
    );
    await ready(fixture, 'Welcome');
    await click(fixture, 'Enter start', 'Local encrypted file');
    await click(fixture, 'Enter continue', 'Profile id:');
    await click(fixture, 'Enter continue', 'Data file:');
    fixture.input.write(report(fixture, 'Enter continue'));
    await vi.waitFor(() => {
      expect(fixture.calls).toHaveLength(1);
    });
    fixture.input.write('\r\r');
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(fixture.calls).toHaveLength(1);
    resolveCheck?.({
      snapshot: {
        ...emptySnapshot(),
        noticeTone: 'error',
        notice: 'Choose a protected directory. Edit the destination and check again.',
      },
    });
    await ready(fixture, 'Choose a protected directory.');
    expect(fixture.output.frame()).toContain('Data file:');
  });

  it('pages full repair instructions on a small terminal without committing the field', async () => {
    const instructions =
      'Choose a private folder. ' +
      'Repair ownership and restrict directory access before saving a key. '.repeat(8) +
      'END OF GUIDANCE';
    const fixture = mount(true, () =>
      Promise.resolve({
        snapshot: { ...emptySnapshot(), noticeTone: 'error', notice: instructions },
      }),
    );
    await ready(fixture, 'Welcome');
    await click(fixture, 'Enter start', 'Local encrypted file');
    await click(fixture, 'Enter continue', 'Profile id:');
    await click(fixture, 'Enter continue', 'Data file:');
    await click(fixture, 'Enter continue', 'Choose a private folder.');
    fixture.output.columns = 40;
    fixture.output.rows = 12;
    fixture.output.emit('resize');
    await ready(fixture, 'Data file:');
    await click(fixture, '^G help', 'Page 1/');
    const pages = Number(/Page 1\/(\d+)/u.exec(fixture.output.frame())?.[1]);
    expect(pages).toBeGreaterThan(1);
    for (let page = 2; page <= pages; page += 1) {
      fixture.input.write('\r');
      await ready(fixture, `Page ${String(page)}/${String(pages)}`);
      expect(fixture.output.frame().split('\n')).toHaveLength(12);
    }
    expect(fixture.output.frame().replace(/\|/gu, ' ').replace(/\s+/gu, ' ')).toContain(
      'END OF GUIDANCE',
    );
    expect(fixture.calls).toHaveLength(1);
    fixture.input.write(ESC);
    await ready(fixture, 'Data file:');
    expect(fixture.calls).toHaveLength(1);
  });
});
