import { PassThrough } from 'node:stream';

import { render, renderToString } from 'ink';
import { createElement } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { keyForChip } from '../../src/app/interaction.js';
import { AppInteractionProvider } from '../../src/app/interaction.js';
import type { MouseInput } from '../../src/app/mouse.js';
import { MouseProvider } from '../../src/app/mouse.js';
import {
  AppChrome,
  createInitialAppRouterState,
  emptySnapshot,
  navigateToScreen,
  renderActiveScreen,
  TabNav,
  transitionAppRouter,
  type AppRouterState,
  type AppScreenId,
  type AppSnapshot,
} from '../../src/index.js';

function fixtureSnapshot(
  options: Readonly<{ unlocked?: boolean; credentials?: number }> = {},
): AppSnapshot {
  const unlocked = options.unlocked ?? true;
  const count = options.credentials ?? 6;
  return {
    ...emptySnapshot('chipfix fixture'),
    home: {
      profileId: 'chipfix',
      vaultId: 'chipfix-vault',
      unlocked,
      credentialCount: unlocked ? count : 0,
      datastore: 'file',
      message: 'chipfix fixture session',
    },
    credentials: Array.from({ length: unlocked ? count : 0 }, (_, index) => ({
      name: `credential-${String(index + 1).padStart(2, '0')}`,
      maskedValue: '********',
    })),
  };
}

function hydrated(
  options: Readonly<{ unlocked?: boolean; credentials?: number; width?: number }> = {},
): AppRouterState {
  return transitionAppRouter(
    createInitialAppRouterState({
      width: options.width ?? 100,
      height: 30,
      ascii: true,
      color: false,
    }),
    { type: 'hydrate', snapshot: fixtureSnapshot(options) },
  ).state;
}

function chrome(state: AppRouterState, columns = state.width): string {
  return renderToString(
    createElement(AppChrome, {
      state,
      children: renderActiveScreen(state),
    }),
    { columns },
  );
}

describe('BUG 1: the footer overflow chip is a status hint, not an action', () => {
  it('maps no key for the +N overflow chip while real chips stay mapped', () => {
    expect(keyForChip('+1')).toBeNull();
    expect(keyForChip('+5')).toBeNull();
    expect(keyForChip('+99')).toBeNull();
    expect(keyForChip('u')).toEqual({ text: 'u' });
    expect(keyForChip('Enter')).toEqual({ name: 'return' });
    expect(keyForChip('Esc')).toEqual({ name: 'escape' });
    expect(keyForChip('?')).toEqual({ text: '?' });
  });

  it('still renders the muted overflow chip in the footer', () => {
    const frame = chrome(navigateToScreen(hydrated(), 'credentials'), 120);
    expect(frame).toMatch(/\+\d+ more/u);
  });
});

describe('BUG 2: ? help works from every screen', () => {
  const screens: readonly AppScreenId[] = [
    'profiles',
    'vaults',
    'credentials',
    'session',
    'doctor',
    'recovery',
    'run',
    'policy',
    'agent',
    'browse',
    'showcase',
    'home',
  ];

  for (const screen of screens) {
    it(`opens Help from ${screen}`, () => {
      const opened = transitionAppRouter(navigateToScreen(hydrated(), screen), {
        type: 'key',
        key: { text: '?' },
        nowMs: 0,
      });
      expect(opened.state.screen).toBe('help');
      expect(opened.state.listIndex).toBe(0);
    });
  }

  it('keeps ? inert while an overlay owns the screen', () => {
    const overlayState: AppRouterState = {
      ...navigateToScreen(hydrated(), 'credentials'),
      overlay: 'confirm-lock',
    };
    const blocked = transitionAppRouter(overlayState, {
      type: 'key',
      key: { text: '?' },
      nowMs: 0,
    });
    expect(blocked.state).toBe(overlayState);
    expect(blocked.effect).toEqual({ kind: 'none' });
  });

  it('does not reset the help topic cursor when already on Help', () => {
    const help = transitionAppRouter(navigateToScreen(hydrated(), 'help'), {
      type: 'select-row',
      index: 3,
      nowMs: 0,
    }).state;
    expect(help.listIndex).toBe(3);
    const again = transitionAppRouter(help, {
      type: 'key',
      key: { text: '?' },
      nowMs: 0,
    });
    expect(again.state).toBe(help);
  });
});

describe('BUG 3: the unlock affordance survives footer overflow', () => {
  it('keeps u unlock on credentials at width 120 while locked', () => {
    const frame = chrome(
      navigateToScreen(hydrated({ unlocked: false }), 'credentials'),
      120,
    );
    expect(frame).toMatch(/u unlock/u);
  });

  it('keeps u unlock on narrow home while locked', () => {
    const frame = chrome(
      navigateToScreen(hydrated({ unlocked: false, width: 40 }), 'home'),
      40,
    );
    expect(frame).toMatch(/u unlock/u);
  });

  it('offers u unlock on every screen while locked and drops it once unlocked', () => {
    for (const screen of [
      'credentials',
      'vaults',
      'profiles',
      'doctor',
      'session',
    ] as const) {
      expect(
        chrome(navigateToScreen(hydrated({ unlocked: false }), screen), 160),
      ).toMatch(/u unlock/u);
      expect(chrome(navigateToScreen(hydrated(), screen), 160)).not.toMatch(
        /u unlock/u,
      );
    }
  });

  it('keeps unlock clickable after overflow prioritization', () => {
    const state = navigateToScreen(hydrated({ unlocked: false }), 'credentials');
    const unlocked = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'u' },
      nowMs: 0,
    });
    expect(unlocked.state.overlay).toBe('input-passphrase');
  });
});

type RecordedRegion = Parameters<MouseInput['registerRegion']>[0];

class RecordingMouse implements MouseInput {
  readonly stdin = new PassThrough() as unknown as NodeJS.ReadStream;
  readonly enabled = true;
  readonly regions = new Set<RecordedRegion>();

  registerRegion(region: RecordedRegion): () => void {
    this.regions.add(region);
    return () => {
      this.regions.delete(region);
    };
  }

  dispose(): void {
    this.regions.clear();
  }
}

class TestOutput extends PassThrough {
  columns = 120;
  rows = 30;
  readonly isTTY = true;
}

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

const mounted: (() => void)[] = [];

afterEach(() => {
  for (const dispose of mounted.splice(0)) dispose();
});

async function countTabRegions(navigable: boolean): Promise<number> {
  const mouse = new RecordingMouse();
  const output = new TestOutput() as unknown as NodeJS.WriteStream;
  const stdin = new TestInput() as unknown as NodeJS.ReadStream;
  const instance = render(
    createElement(
      MouseProvider,
      { controller: mouse },
      createElement(AppInteractionProvider, {
        value: {
          dispatch: () => undefined,
          press: () => undefined,
          enabled: true,
          mouse: true,
          busy: false,
        },
        children: createElement(TabNav, {
          activeId: 'home',
          navigable,
          color: false,
          ascii: true,
          width: 120,
        }),
      }),
    ),
    { stdout: output, stdin, exitOnCtrlC: false, patchConsole: false },
  );
  mounted.push(() => {
    instance.unmount();
  });
  if (navigable) {
    await vi.waitFor(() => {
      expect(mouse.regions.size).toBeGreaterThan(0);
    });
  } else {
    await new Promise((resolve) => setTimeout(resolve, 120));
  }
  return mouse.regions.size;
}

describe('BUG 4: tab strip stops accepting clicks while an overlay is open', () => {
  it('registers tab click regions only while navigation is allowed', async () => {
    expect(await countTabRegions(true)).toBeGreaterThan(0);
    expect(await countTabRegions(false)).toBe(0);
  });

  it('keeps painting the tab strip while it is inert', () => {
    const frame = renderToString(
      createElement(TabNav, {
        activeId: 'home',
        navigable: false,
        color: false,
        ascii: true,
        width: 120,
      }),
      { columns: 120 },
    );
    expect(frame).toContain('1 Home');
    expect(frame).toContain('4 Creds');
  });

  it('still rejects navigation routed while an overlay is open', () => {
    const overlayState: AppRouterState = {
      ...navigateToScreen(hydrated(), 'credentials'),
      overlay: 'credential-detail',
    };
    const blocked = transitionAppRouter(overlayState, {
      type: 'navigate',
      screen: 'doctor',
    });
    expect(blocked.state).toBe(overlayState);
  });
});

describe('BUG 5: empty unlock attempts stay in the overlay', () => {
  function passphraseOverlay(): AppRouterState {
    const state = transitionAppRouter(
      navigateToScreen(hydrated({ unlocked: false }), 'credentials'),
      { type: 'key', key: { text: 'u' }, nowMs: 0 },
    ).state;
    expect(state.overlay).toBe('input-passphrase');
    return state;
  }

  it('keeps the overlay open and reports a local validation notice', () => {
    const empty = transitionAppRouter(passphraseOverlay(), {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    });
    expect(empty.effect).toEqual({ kind: 'none' });
    expect(empty.state.overlay).toBe('input-passphrase');
    expect(empty.state.query).toBe('');
    expect(empty.state.message).toBe('Passphrase cannot be empty.');
  });

  it('rejects whitespace-only input without echoing it', () => {
    const typed = transitionAppRouter(passphraseOverlay(), {
      type: 'key',
      key: { text: '   ' },
      nowMs: 0,
    }).state;
    const blank = transitionAppRouter(typed, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    });
    expect(blank.effect).toEqual({ kind: 'none' });
    expect(blank.state.overlay).toBe('input-passphrase');
    expect(blank.state.message).toBe('Passphrase cannot be empty.');
    expect(blank.state.message).not.toContain('   ');
  });

  it('still unlocks with a real passphrase', () => {
    let state = passphraseOverlay();
    for (const character of 'chipfix-passphrase') {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: character },
        nowMs: 0,
      }).state;
    }
    const submitted = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    });
    expect(submitted.effect).toEqual({
      kind: 'backend',
      action: { type: 'unlock', passphrase: 'chipfix-passphrase' },
    });
    expect(submitted.state.overlay).toBe('none');
    expect(submitted.state.query).toBe('');
  });

  it('never renders the typed passphrase or the notice in plaintext', () => {
    const typed = transitionAppRouter(passphraseOverlay(), {
      type: 'key',
      key: { text: 'CHIPFIX-SECRET-CANARY' },
      nowMs: 0,
    });
    const frame = renderToString(
      createElement(AppChrome, {
        state: typed.state,
        children: renderActiveScreen(typed.state),
      }),
      { columns: 100 },
    );
    expect(frame).not.toContain('CHIPFIX-SECRET-CANARY');
    expect(frame).toContain('********');
  });
});
