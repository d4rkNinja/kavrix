import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it } from 'vitest';

import {
  APP_MENU,
  NAV_GROUPS,
  groupedNavRows,
  groupedNavWindow,
  screenGuide,
  type AppNavGroup,
} from '../../src/index.js';
import {
  AppChrome,
  CredentialsScreen,
  HomeScreen,
  ProfilesScreen,
  VaultsScreen,
  renderActiveScreen,
} from '../../src/app/screens.js';
import {
  createInitialAppRouterState,
  navigateToScreen,
  transitionAppRouter,
  type AppRouterState,
} from '../../src/app/router.js';
import { emptySnapshot, type AppSnapshot } from '../../src/app/backend.js';

const ASCII_ONLY = /^[\x20-\x7e\n]*$/u;

function fixtureSnapshot(
  options: Readonly<{ unlocked?: boolean; credentials?: number }> = {},
): AppSnapshot {
  const unlocked = options.unlocked ?? true;
  const count = options.credentials ?? 6;
  return {
    ...emptySnapshot('friendly fixture'),
    home: {
      profileId: 'friendly',
      vaultId: 'friendly-vault',
      unlocked,
      credentialCount: unlocked ? count : 0,
      datastore: 'file',
      message: 'friendly fixture session',
    },
    credentials: Array.from({ length: unlocked ? count : 0 }, (_, index) => ({
      name: `credential-${String(index + 1).padStart(2, '0')}`,
      maskedValue: '********',
    })),
  };
}

function hydrated(
  options: Readonly<{
    unlocked?: boolean;
    credentials?: number;
    width?: number;
    height?: number;
  }> = {},
): AppRouterState {
  return transitionAppRouter(
    createInitialAppRouterState({
      width: options.width ?? 100,
      height: options.height ?? 30,
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

describe('grouped Home navigation model', () => {
  const entries = APP_MENU.filter((entry) => entry.id !== 'home');

  it('lists every destination exactly once, grouped in declared order', () => {
    const rows = groupedNavRows(entries);
    const rendered = rows.flatMap((row) =>
      row.kind === 'entry' ? [row.entry.id] : [],
    );
    expect(rendered).toHaveLength(entries.length);
    expect(new Set(rendered).size).toBe(entries.length);
    expect([...rendered].sort()).toEqual([...entries.map((e) => e.id)].sort());

    const groupOrder: AppNavGroup[] = [];
    for (const row of rows) {
      if (row.kind === 'band') {
        // A band always opens a new group and is immediately followed by entries.
        expect(groupOrder).not.toContain(row.group);
        groupOrder.push(row.group);
      }
    }
    expect(groupOrder).toEqual(NAV_GROUPS.map((group) => group.id));
  });

  it('counts the destinations each band introduces', () => {
    for (const group of NAV_GROUPS) {
      const rows = groupedNavRows(entries);
      const band = rows.find((row) => row.kind === 'band' && row.group === group.id);
      const owned = entries.filter((entry) => entry.group === group.id);
      if (owned.length === 0) {
        expect(band).toBeUndefined();
        continue;
      }
      expect(band).toBeDefined();
      expect(band?.kind === 'band' && band.count).toBe(owned.length);
    }
  });

  it.each([1, 2, 3, 5, 8, 13, 40])('bounds the window to %i rows', (size) => {
    const rows = groupedNavRows(entries);
    const window = groupedNavWindow(rows, 0, size);
    expect(window.rows.length).toBeLessThanOrEqual(Math.max(1, size));
    // A band must never be the last visible row: it would promise destinations
    // that are scrolled out of view.
    expect(window.rows[window.rows.length - 1]?.kind).not.toBe('band');
  });

  it('keeps the cursor visible at every position', () => {
    const rows = groupedNavRows(entries);
    for (let index = 0; index < entries.length; index += 1) {
      const window = groupedNavWindow(rows, index, 5);
      const hasCursor = window.rows.some(
        (row) => row.kind === 'entry' && row.index === index,
      );
      expect(hasCursor).toBe(true);
    }
  });

  it('returns the whole list when it fits', () => {
    const rows = groupedNavRows(entries);
    expect(groupedNavWindow(rows, 0, rows.length).rows).toEqual(rows);
  });
});

describe('per-screen orientation guide', () => {
  it('describes the open name filter instead of advertising filter-text keys', () => {
    const filtering = screenGuide('credentials', true);
    expect(filtering).toMatch(/Name filter open/u);
    expect(filtering).not.toMatch(/\bn put\b/u);
    expect(filtering).not.toMatch(/\bc copy\b/u);
    expect(filtering).not.toMatch(/\br reveal\b/u);
  });

  it('keeps the credential keymap when no filter is open', () => {
    expect(screenGuide('credentials', false)).toMatch(/\/ filters names/u);
  });

  it('has a guide that survives the 80-column layout matrix', () => {
    for (const entry of APP_MENU) {
      // The header panel's content width at 80 columns is 76 cells; the guide
      // owns three of them for its info glyph.
      expect(screenGuide(entry.id).length).toBeLessThanOrEqual(73);
      expect(screenGuide(entry.id, true).length).toBeLessThanOrEqual(73);
    }
  });
});

describe('friendly chrome', () => {
  it('paints the guide row under the header and still fills the frame', () => {
    for (const [width, height] of [
      [80, 24],
      [120, 36],
      [100, 30],
    ] as const) {
      const state = hydrated({ width, height });
      const frame = chrome(state, width);
      expect(frame.split('\n')).toHaveLength(height);
      expect(frame.split('\n').every((line) => line.length <= width)).toBe(true);
      expect(frame).toMatch(/Pick a destination below/u);
    }
  });

  it('omits the guide row on short terminals instead of clipping the body', () => {
    const state = hydrated({ width: 80, height: 12 });
    const frame = chrome(state, 80);
    expect(frame.split('\n')).toHaveLength(12);
  });

  it('swaps the guide to the filter state while Credentials filters names', () => {
    let state = navigateToScreen(hydrated({ width: 100, height: 30 }), 'credentials');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: '/' },
      nowMs: 0,
    }).state;
    const frame = chrome(state, 100);
    expect(frame).toMatch(/Name filter open/u);
    expect(frame).not.toMatch(/\bn put\b/u);
    expect(frame).not.toMatch(/\bc copy\b/u);
    expect(frame).not.toMatch(/\br reveal\b/u);
  });

  it('renders ASCII-only chrome for every screen', () => {
    for (const entry of APP_MENU) {
      const frame = chrome(navigateToScreen(hydrated(), entry.id), 100);
      expect(frame).toMatch(ASCII_ONLY);
    }
  });
});

describe('grouped Home menu rendering', () => {
  it('names each section and keeps the tab-strip numbering', () => {
    const frame = renderToString(createElement(HomeScreen, { state: hydrated() }), {
      columns: 100,
    });
    expect(frame).toMatch(/SET UP/u);
    expect(frame).toMatch(/SECRETS/u);
    expect(frame).toMatch(/SECURITY/u);
    expect(frame).toMatch(/TOOLS/u);
    expect(frame).toContain('2 Profiles');
    expect(frame).toContain('4 Creds');
  });

  it('stays ASCII-safe on Home', () => {
    const frame = renderToString(createElement(HomeScreen, { state: hydrated() }), {
      columns: 100,
    });
    expect(frame).toMatch(ASCII_ONLY);
  });

  it('reports how many destinations are shown out of the total', () => {
    const frame = renderToString(
      createElement(HomeScreen, { state: hydrated({ height: 24, width: 80 }) }),
      { columns: 80 },
    );
    expect(frame).toMatch(/\/ 12 destinations shown/u);
  });
});

describe('empty states carry the next step', () => {
  it('offers put on an empty, unlocked credentials list', () => {
    const state = {
      ...hydrated({ credentials: 0, unlocked: true }),
      screen: 'credentials' as const,
    };
    const frame = renderToString(createElement(CredentialsScreen, { state }), {
      columns: 100,
    });
    expect(frame).toMatch(/n put a credential/u);
  });

  it('offers unlock on a locked credentials list and never a put action', () => {
    const state = {
      ...hydrated({ credentials: 0, unlocked: false }),
      screen: 'credentials' as const,
    };
    const frame = renderToString(createElement(CredentialsScreen, { state }), {
      columns: 100,
    });
    expect(frame).toMatch(/u unlock your vault/u);
    expect(frame).not.toMatch(/n put a credential/u);
  });

  it('offers a file profile on an empty profiles list', () => {
    const state = hydrated();
    const cleared: AppRouterState = {
      ...state,
      snapshot: { ...state.snapshot, profiles: [] },
    };
    const frame = renderToString(createElement(ProfilesScreen, { state: cleared }), {
      columns: 100,
    });
    expect(frame).toMatch(/n create a file profile/u);
  });

  it('offers unlock on a locked vault list and drops it once unlocked', () => {
    const base = hydrated({ unlocked: false });
    const cleared: AppRouterState = {
      ...base,
      snapshot: { ...base.snapshot, vaults: [] },
      screen: 'vaults',
    };
    const locked = renderToString(createElement(VaultsScreen, { state: cleared }), {
      columns: 100,
    });
    expect(locked).toMatch(/u unlock your vault/u);

    const open: AppRouterState = {
      ...cleared,
      snapshot: {
        ...cleared.snapshot,
        home: { ...cleared.snapshot.home, unlocked: true },
      },
    };
    const unlocked = renderToString(createElement(VaultsScreen, { state: open }), {
      columns: 100,
    });
    expect(unlocked).not.toMatch(/u unlock your vault/u);
  });

  it('states the row guidance once rows exist', () => {
    const frame = renderToString(createElement(ProfilesScreen, { state: hydrated() }), {
      columns: 100,
    });
    expect(frame).toMatch(/Enter uses the selected profile/u);
  });
});
