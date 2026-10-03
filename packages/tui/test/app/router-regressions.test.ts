import { describe, expect, it } from 'vitest';

import {
  createInitialAppRouterState,
  emptySnapshot,
  navigateToScreen,
  transitionAppRouter,
  type AppRouterState,
  type AppSnapshot,
} from '../../src/index.js';

function snapshot(credentialNames: readonly string[] = ['alpha', 'beta']): AppSnapshot {
  return {
    ...emptySnapshot('router regression fixture'),
    home: {
      profileId: 'fixture',
      vaultId: 'fixture',
      unlocked: true,
      credentialCount: credentialNames.length,
      datastore: 'file',
      message: 'fixture',
    },
    credentials: credentialNames.map((name) => ({
      name,
      maskedValue: '********',
    })),
  };
}

function hydrated(): AppRouterState {
  return transitionAppRouter(createInitialAppRouterState(), {
    type: 'hydrate',
    snapshot: snapshot(),
  }).state;
}

describe('router regressions', () => {
  it('discards a late reveal result after navigating away', () => {
    let state = navigateToScreen(hydrated(), 'credentials');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'r' },
      nowMs: 1,
    }).state;
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'y' },
      nowMs: 2,
    }).state;

    state = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'tab' },
      nowMs: 3,
    }).state;
    expect(state.screen).not.toBe('credentials');

    const late = transitionAppRouter(state, {
      type: 'backend-result',
      snapshot: snapshot(),
      revealedSecret: 'TEST-CANARY-NOT-A-SECRET',
      nowMs: 4,
    }).state;

    expect(late.pendingRevealName).toBeNull();
    expect(late.revealedName).toBeNull();
    expect(late.revealedValue).toBeNull();
    expect(late.revealedUntilMs).toBe(0);
  });

  it('cannot restore a pending reveal after the vault is locked', () => {
    let state = navigateToScreen(hydrated(), 'credentials');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'r' },
      nowMs: 1,
    }).state;
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'y' },
      nowMs: 2,
    }).state;
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'l' },
      nowMs: 3,
    }).state;
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'y' },
      nowMs: 4,
    }).state;
    expect(state.pendingRevealName).toBeNull();

    const lockedSnapshot: AppSnapshot = {
      ...snapshot(),
      home: { ...snapshot().home, unlocked: false },
    };
    const late = transitionAppRouter(state, {
      type: 'backend-result',
      snapshot: lockedSnapshot,
      revealedSecret: 'TEST-CANARY-NOT-A-SECRET',
      nowMs: 5,
    }).state;

    expect(late.revealedName).toBeNull();
    expect(late.revealedValue).toBeNull();
    expect(late.revealedUntilMs).toBe(0);
  });

  it('preserves an overlay opened while an earlier backend action resolves', () => {
    let state = navigateToScreen(hydrated(), 'credentials');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: '/' },
      nowMs: 1,
    }).state;
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'alpha' },
      nowMs: 2,
    }).state;

    const refreshed = transitionAppRouter(state, {
      type: 'backend-result',
      snapshot: snapshot(),
      nowMs: 3,
    }).state;

    expect(refreshed.overlay).toBe('input-search');
    expect(refreshed.query).toBe('alpha');
  });

  it('clamps a stale list index when refreshed rows shrink', () => {
    const state: AppRouterState = {
      ...navigateToScreen(hydrated(), 'credentials'),
      listIndex: 1,
    };

    const refreshed = transitionAppRouter(state, {
      type: 'backend-result',
      snapshot: snapshot(['alpha']),
      nowMs: 1,
    }).state;

    expect(refreshed.listIndex).toBe(0);
  });
});

describe('mouse-friendly router intents', () => {
  it('navigates through the existing screen entry path and blocks navigation under overlays', () => {
    const start = hydrated();
    const opened = transitionAppRouter(start, {
      type: 'navigate',
      screen: 'doctor',
    });
    expect(opened.state.screen).toBe('doctor');
    expect(opened.effect).toEqual({
      kind: 'backend',
      action: { type: 'run-doctor' },
    });

    const overlayState: AppRouterState = {
      ...start,
      overlay: 'confirm-lock',
    };
    const blocked = transitionAppRouter(overlayState, {
      type: 'navigate',
      screen: 'help',
    });
    expect(blocked.state).toBe(overlayState);
    expect(blocked.effect).toEqual({ kind: 'none' });
  });

  it('selects and activates rows only through the existing return-key behavior', () => {
    const state = navigateToScreen(hydrated(), 'credentials');
    const selected = transitionAppRouter(state, {
      type: 'select-row',
      index: 1,
      nowMs: 1,
    });
    expect(selected.state.listIndex).toBe(1);
    expect(selected.effect).toEqual({ kind: 'none' });

    const activated = transitionAppRouter(state, {
      type: 'select-row',
      index: 1,
      activate: true,
      nowMs: 2,
    });
    expect(activated.state.listIndex).toBe(1);
    expect(activated.state.overlay).toBe('credential-detail');
    expect(activated.state.pendingName).toBe('beta');
    expect(activated.effect).toEqual({ kind: 'none' });

    const invalid = transitionAppRouter(state, {
      type: 'select-row',
      index: 99,
      activate: true,
      nowMs: 3,
    });
    expect(invalid.state).toBe(state);
    expect(invalid.effect).toEqual({ kind: 'none' });
  });

  it('uses home menu row indices and previews themes only inside the picker', () => {
    const homeActivated = transitionAppRouter(hydrated(), {
      type: 'select-row',
      index: 1,
      activate: true,
      nowMs: 1,
    });
    expect(homeActivated.state.screen).toBe('vaults');

    const outsidePicker = transitionAppRouter(hydrated(), {
      type: 'select-theme',
      index: 1,
    });
    expect(outsidePicker.state.themeCursor).toBe(0);

    const picker: AppRouterState = {
      ...hydrated(),
      overlay: 'theme-picker',
    };
    const previewed = transitionAppRouter(picker, {
      type: 'select-theme',
      index: 1,
    });
    expect(previewed.state.overlay).toBe('theme-picker');
    expect(previewed.state.themeCursor).toBe(1);
    expect(previewed.effect).toEqual({ kind: 'none' });

    transitionAppRouter(previewed.state, {
      type: 'key',
      key: { name: 'escape' },
      nowMs: 2,
    });
  });

  it('selects bounded Help topics with keyboard and pointer intents', () => {
    const help = navigateToScreen(hydrated(), 'help');
    const lastTopic = transitionAppRouter(help, {
      type: 'select-row',
      index: 4,
      nowMs: 1,
    });
    expect(lastTopic.state.listIndex).toBe(4);

    const bounded = transitionAppRouter(lastTopic.state, {
      type: 'key',
      key: { name: 'down' },
      nowMs: 2,
    });
    expect(bounded.state.listIndex).toBe(4);

    const invalid = transitionAppRouter(help, {
      type: 'select-row',
      index: 5,
      nowMs: 3,
    });
    expect(invalid.state).toBe(help);
  });
});
