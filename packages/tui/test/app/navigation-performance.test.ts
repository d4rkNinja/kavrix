import { describe, expect, it } from 'vitest';

import { APP_MENU } from '../../src/app/ids.js';
import { groupedNavRows } from '../../src/app/navigation.js';
import { allCommands, commandGroups } from '../../src/app/commands.js';
import {
  createInitialAppRouterState,
  filteredCredentials,
  transitionAppRouter,
} from '../../src/app/router.js';

describe('Home navigation follows the displayed groups', () => {
  const entries = APP_MENU.filter((entry) => entry.id !== 'home');
  const order = groupedNavRows(entries).flatMap((row) =>
    row.kind === 'entry' ? [row.index] : [],
  );

  it('moves down and up through every displayed destination and opens it', () => {
    let state = createInitialAppRouterState();
    for (const index of order) {
      expect(state.menuIndex).toBe(index);
      const opened = transitionAppRouter(state, {
        type: 'key',
        key: { name: 'return' },
        nowMs: 0,
      });
      expect(opened.state.screen).toBe(entries[index]?.id);
      state = transitionAppRouter(state, {
        type: 'key',
        key: { name: 'down' },
        nowMs: 0,
      }).state;
    }
    for (const index of [...order].reverse()) {
      expect(state.menuIndex).toBe(index);
      state = transitionAppRouter(state, {
        type: 'key',
        key: { name: 'up' },
        nowMs: 0,
      }).state;
    }
  });

  it('pages through visual positions while retaining stable mouse row indexes', () => {
    const state = createInitialAppRouterState({ height: 24 });
    const paged = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'page-down' },
      nowMs: 0,
    }).state;
    expect(paged.menuIndex).toBe(order[7]);
    for (const index of order) {
      const clicked = transitionAppRouter(state, {
        type: 'select-row',
        index,
        activate: true,
        nowMs: 0,
      });
      expect(clicked.state.screen).toBe(entries[index]?.id);
    }
  });
});

describe('responsive selector reuse', () => {
  it('reuses command descriptors while checking current authorization state', () => {
    const locked = createInitialAppRouterState();
    const unlocked = {
      ...locked,
      snapshot: {
        ...locked.snapshot,
        home: { ...locked.snapshot.home, unlocked: true },
      },
    };
    expect(commandGroups(unlocked)).toBe(commandGroups(locked));
    expect(allCommands(unlocked)).toBe(allCommands(locked));
    const unlock = allCommands(locked).find((command) => command.id === 'unlock');
    expect(unlock?.blocked(locked)).toBeNull();
    expect(unlock?.blocked(unlocked)).not.toBeNull();
  });

  it('invalidates search results when refreshed names or lists change', () => {
    const base = createInitialAppRouterState();
    const state = {
      ...base,
      credentialFilter: 'ALPHA',
      snapshot: {
        ...base.snapshot,
        credentials: [{ name: 'Alpha', maskedValue: '********' }],
      },
    };
    expect(filteredCredentials(state)).toHaveLength(1);
    expect(filteredCredentials({ ...state })).toBe(filteredCredentials(state));
    const refreshed = {
      ...state,
      snapshot: {
        ...state.snapshot,
        credentials: [{ name: 'Beta', maskedValue: '********' }],
      },
    };
    expect(filteredCredentials(refreshed)).toHaveLength(0);
    expect(
      filteredCredentials({ ...refreshed, credentialFilter: 'beta' }),
    ).toHaveLength(1);
  });
});
