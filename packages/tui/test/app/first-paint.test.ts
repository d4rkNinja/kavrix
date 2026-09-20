import { PassThrough } from 'node:stream';

import { createElement } from 'react';
import { render, renderToString } from 'ink';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createInitialAppRouterState,
  describeAppScreen,
  ensureTtySize,
  filteredCredentials,
  KavrixApp,
  mountKavrixApp,
  navigateToScreen,
  prioritizeFooterChips,
  resolveTtySize,
  transitionAppRouter,
  visibleListWindow,
} from '../../src/index.js';
import {
  AppChrome,
  BrowseScreen,
  CredentialsScreen,
  DoctorScreen,
  HelpScreen,
  RecoveryScreen,
  renderActiveScreen,
} from '../../src/app/screens.js';
import {
  emptySnapshot,
  type AppSnapshot,
  type InteractiveAppBackend,
} from '../../src/app/backend.js';

class TestOutput extends PassThrough {
  columns = 80;
  rows = 24;
  readonly isTTY = true;
}

class MidOutput extends PassThrough {
  columns = 0;
  rows = 0;
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

const ESC = String.fromCharCode(27);

function stripAnsi(value: string): string {
  return value.replace(new RegExp(`${ESC}\\[[0-9;?]*[A-Za-z]`, 'g'), '');
}

function midSnapshot(): AppSnapshot {
  return {
    ...emptySnapshot(),
    home: {
      profileId: 'mid',
      vaultId: 'default',
      unlocked: true,
      credentialCount: 1,
      datastore: 'file',
      message: 'mid fixture',
    },
    credentials: [{ name: 'mid-secret', maskedValue: '********' }],
    notice: 'mid fixture',
    noticeTone: 'info',
  };
}

function deferredLoadBackend(snapshot: AppSnapshot): Readonly<{
  backend: InteractiveAppBackend;
  resolveLoad: (next?: AppSnapshot) => void;
  rejectLoad: (error: Error) => void;
}> {
  let resolveLoad!: (next: AppSnapshot) => void;
  let rejectLoad!: (error: Error) => void;
  const load = new Promise<AppSnapshot>((resolve, reject) => {
    resolveLoad = resolve;
    rejectLoad = reject;
  });
  return {
    backend: {
      load: async () => load,
      dispatch: () => Promise.resolve({ snapshot }),
    },
    resolveLoad: (next = snapshot) => {
      resolveLoad(next);
    },
    rejectLoad,
  };
}

/**
 * Regression for blank TTY hydrate: chrome must paint on tall terminals without
 * pinning height={rows} (Ink/Yoga blank). renderToString exercises layout.
 */
describe('TUI first paint reliability', () => {
  it('renders home chrome for a tall terminal size without blanking', () => {
    const state = createInitialAppRouterState({
      width: 120,
      height: 60,
      ascii: true,
      color: false,
    });
    const frame = renderToString(
      createElement(AppChrome, {
        state,
        children: renderActiveScreen(state),
      }),
      { columns: 120 },
    );
    expect(frame.length).toBeGreaterThan(40);
    expect(frame).toMatch(/product|lock|profile|CredVault|KAVRIX|Navigate|home/i);
  });

  it('paints vault chrome when TTY columns/rows are missing (Mid fixture)', () => {
    const size = resolveTtySize({});
    expect(size).toEqual({ width: 80, height: 24 });
    expect(resolveTtySize({ columns: 0, rows: 0 })).toEqual({ width: 80, height: 24 });
    const state = {
      ...createInitialAppRouterState({
        width: size.width,
        height: size.height,
        ascii: true,
        color: false,
      }),
      sessionReady: true,
      snapshot: {
        ...emptySnapshot(),
        home: {
          profileId: 'mid',
          vaultId: 'default',
          unlocked: true,
          credentialCount: 1,
          datastore: 'file',
          message: 'mid fixture',
        },
        credentials: [{ name: 'mid-secret', maskedValue: '********' }],
      },
    };
    const frame = renderToString(
      createElement(AppChrome, {
        state,
        children: renderActiveScreen(state),
      }),
      { columns: size.width },
    );
    expect(frame.length).toBeGreaterThan(40);
    expect(frame).toMatch(/product|lock|profile|HOME|Navigate/i);
    expect(frame).toMatch(/mid/i);
  });

  it('advertises Enter/detail in the credentials footer', () => {
    const state = navigateToScreen(
      createInitialAppRouterState({
        width: 100,
        height: 24,
        ascii: true,
        color: false,
      }),
      'credentials',
    );
    const frame = renderToString(
      createElement(AppChrome, {
        state,
        children: renderActiveScreen(state),
      }),
      { columns: 100 },
    );
    expect(frame).toMatch(/Enter/i);
    expect(frame).toMatch(/detail|open/i);
  });

  it('prioritizes critical footer chips on a narrow terminal', () => {
    const chips = prioritizeFooterChips(
      [
        { keyLabel: 'Enter', hint: 'detail', accent: 'yellow' },
        { keyLabel: 'j/k', hint: 'move', accent: 'yellow' },
        { keyLabel: 'c', hint: 'copy', accent: 'yellow' },
        { keyLabel: 'r', hint: 'reveal', accent: 'red' },
        { keyLabel: 'n', hint: 'put', accent: 'yellow' },
        { keyLabel: 'm', hint: 'rename', accent: 'yellow' },
        { keyLabel: 'x', hint: 'remove', accent: 'red' },
        { keyLabel: '/', hint: 'search', accent: 'yellow' },
        { keyLabel: 'u', hint: 'unlock', accent: 'yellow' },
        { keyLabel: 'Esc', hint: 'home', accent: 'yellow' },
        { keyLabel: 'q', hint: 'quit', accent: 'red' },
      ],
      36,
    );
    expect(chips.some((chip) => chip.keyLabel === 'Enter')).toBe(true);
    expect(chips.some((chip) => chip.keyLabel === 'Esc')).toBe(true);
    expect(chips.some((chip) => chip.keyLabel === 'q')).toBe(true);
    expect(chips.length).toBeLessThan(11);
    expect(chips.some((chip) => chip.keyLabel.startsWith('+'))).toBe(true);
  });

  it('labels recovery kit separately from doctor heal and run --environment', () => {
    const base = {
      ...createInitialAppRouterState({
        width: 100,
        height: 24,
        ascii: true,
        color: false,
      }),
      sessionReady: true,
    };
    const recovery = renderToString(
      createElement(RecoveryScreen, { state: navigateToScreen(base, 'recovery') }),
      { columns: 100 },
    );
    const doctor = renderToString(
      createElement(DoctorScreen, { state: navigateToScreen(base, 'doctor') }),
      { columns: 100 },
    );
    const browse = renderToString(
      createElement(BrowseScreen, { state: navigateToScreen(base, 'browse') }),
      { columns: 100 },
    );
    const help = renderToString(
      createElement(HelpScreen, { state: navigateToScreen(base, 'help') }),
      { columns: 100 },
    );
    expect(recovery).toMatch(/Recovery kit/i);
    expect(recovery).toMatch(/key material/i);
    expect(recovery).toMatch(/Doctor heal is/i);
    expect(recovery).toMatch(/different command/i);
    expect(doctor).toMatch(/Doctor \/ heal/i);
    expect(doctor).toMatch(/not recovery kit/i);
    expect(browse).toMatch(/Vault context/i);
    expect(browse).toMatch(/not[\s\S]*run --environment/i);
    expect(help).toMatch(/project-file --environment is CLI-only/i);
    expect(help).not.toMatch(/Vault environment/i);
  });

  it('virtualizes and searches a large credential fixture', () => {
    const credentials = Array.from({ length: 400 }, (_, index) => ({
      name: index === 317 ? 'zz-needle' : `cred-${String(index).padStart(3, '0')}`,
      maskedValue: '********',
    }));
    let state = navigateToScreen(
      {
        ...createInitialAppRouterState({
          width: 80,
          height: 24,
          ascii: true,
          color: false,
        }),
        snapshot: {
          ...emptySnapshot(),
          credentials,
          home: {
            profileId: 'dev',
            vaultId: 'default',
            unlocked: true,
            credentialCount: credentials.length,
            datastore: 'file',
            message: 'large fixture',
          },
        },
        sessionReady: true,
      },
      'credentials',
    );
    const window = visibleListWindow(filteredCredentials(state), state.listIndex, 12);
    expect(window.items.length).toBeLessThanOrEqual(12);
    expect(window.items.length).toBeGreaterThan(0);
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: '/' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-search');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'zz-needle' },
      nowMs: 1,
    }).state;
    state = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 2,
    }).state;
    expect(state.overlay).toBe('none');
    expect(state.credentialFilter).toBe('zz-needle');
    const filtered = filteredCredentials(state);
    expect(filtered).toHaveLength(1);
    expect(filtered[0]?.name).toBe('zz-needle');
    const painted = renderToString(createElement(CredentialsScreen, { state }), {
      columns: 80,
    });
    expect(painted).toContain('zz-needle');
    expect(painted).not.toContain('cred-000');
  });

  it('paints chrome before sessionReady so hydrate cannot blank Mid fixtures', () => {
    const size = ensureTtySize({ columns: 0, rows: 0 });
    expect(size).toEqual({ width: 80, height: 24 });
    const pending = createInitialAppRouterState({
      width: size.width,
      height: size.height,
      ascii: true,
      color: false,
    });
    expect(pending.sessionReady).toBe(false);
    expect(pending.credentialFilter).toBe('');
    const frame = renderToString(
      createElement(AppChrome, {
        state: pending,
        children: renderActiveScreen(pending),
      }),
      { columns: size.width },
    );
    expect(frame.length).toBeGreaterThan(40);
    expect(frame).toMatch(/product|lock|profile|Navigate|home/i);
    expect(describeAppScreen(pending)).toMatch(/screen=home/);
    expect(describeAppScreen(pending)).toMatch(/credentials=0/);
  });

  it('keeps Enter/detail and q on a painted narrow credentials footer', () => {
    const state = navigateToScreen(
      createInitialAppRouterState({
        width: 36,
        height: 16,
        ascii: true,
        color: false,
      }),
      'credentials',
    );
    const frame = renderToString(
      createElement(AppChrome, {
        state,
        children: renderActiveScreen(state),
      }),
      { columns: 36 },
    );
    expect(frame).toMatch(/Enter/i);
    expect(frame).toMatch(/detail|open/i);
    expect(frame).toMatch(/\bq\b/i);
    expect(frame).toMatch(/\+/);
  });

  it('advertises Enter/open on the home footer', () => {
    const state = createInitialAppRouterState({
      width: 80,
      height: 24,
      ascii: true,
      color: false,
    });
    const frame = renderToString(
      createElement(AppChrome, {
        state,
        children: renderActiveScreen(state),
      }),
      { columns: 80 },
    );
    expect(frame).toMatch(/Enter/i);
    expect(frame).toMatch(/open/i);
  });
});

describe('KavrixApp vault-shell first paint', () => {
  let instance:
    ReturnType<typeof render> | ReturnType<typeof mountKavrixApp> | undefined;

  afterEach(() => {
    instance?.unmount();
    instance = undefined;
  });

  it('paints Loading vault session instead of a blank frame before hydrate', async () => {
    const stdout = new TestOutput();
    const stdin = new TestInput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    const { backend } = deferredLoadBackend(midSnapshot());
    instance = render(
      createElement(KavrixApp, {
        backend,
        ascii: true,
        color: false,
        noSplash: true,
      }),
      {
        stdout: stdout as unknown as NodeJS.WriteStream,
        stdin: stdin as unknown as NodeJS.ReadStream,
        exitOnCtrlC: false,
        patchConsole: false,
      },
    );
    await instance.waitUntilRenderFlush();
    const painted = stripAnsi(Buffer.concat(chunks).toString('utf8'));
    expect(painted.length).toBeGreaterThan(20);
    expect(painted).toMatch(/Loading vault session/i);
    expect(painted).toMatch(/product|lock|profile/i);
  });

  it('hydrates a Mid 0x0 TTY into a visible home frame', async () => {
    const stdout = new MidOutput();
    const stdin = new TestInput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    const { backend, resolveLoad } = deferredLoadBackend(midSnapshot());
    instance = mountKavrixApp({
      backend,
      ascii: true,
      color: false,
      noSplash: true,
      stdout: stdout as unknown as NodeJS.WriteStream,
      stdin: stdin as unknown as NodeJS.ReadStream,
    });
    expect(stdout.columns).toBe(80);
    expect(stdout.rows).toBe(24);
    resolveLoad();
    await vi.waitFor(
      () => {
        const painted = stripAnsi(Buffer.concat(chunks).toString('utf8'));
        const last = painted.slice(Math.max(0, painted.lastIndexOf('KAVRIX')));
        expect(last).toMatch(/profile:mid/i);
        expect(last).toMatch(/Navigate|HOME/i);
        expect(last).not.toMatch(/Loading vault session/i);
      },
      { timeout: 3_000, interval: 40 },
    );
  });

  it('paints a hydrate error instead of staying blank', async () => {
    const stdout = new TestOutput();
    const stdin = new TestInput();
    const chunks: Buffer[] = [];
    stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    const { backend, rejectLoad } = deferredLoadBackend(midSnapshot());
    instance = render(
      createElement(KavrixApp, {
        backend,
        ascii: true,
        color: false,
        noSplash: true,
      }),
      {
        stdout: stdout as unknown as NodeJS.WriteStream,
        stdin: stdin as unknown as NodeJS.ReadStream,
        exitOnCtrlC: false,
        patchConsole: false,
      },
    );
    await instance.waitUntilRenderFlush();
    rejectLoad(new Error('mid hydrate failed'));
    await vi.waitFor(
      () => {
        const painted = stripAnsi(Buffer.concat(chunks).toString('utf8'));
        expect(painted).toMatch(/Hydrate failed/i);
        expect(painted).toMatch(/mid hydrate failed/i);
      },
      { timeout: 3_000, interval: 40 },
    );
  });
});
