import { describe, expect, it } from 'vitest';

import { emptySnapshot } from '../../src/app/backend.js';
import {
  createInitialAppRouterState,
  navigateToScreen,
  transitionAppRouter,
  type AppKey,
  type AppRouterState,
} from '../../src/app/router.js';

function credentials(height = 24): AppRouterState {
  const snapshot = emptySnapshot();
  return navigateToScreen(
    {
      ...createInitialAppRouterState({ width: 80, height, ascii: true, color: false }),
      snapshot: {
        ...snapshot,
        home: { ...snapshot.home, unlocked: true },
        credentials: Array.from({ length: 100 }, (_, index) => ({
          name: `entry-${String(index).padStart(3, '0')}`,
          maskedValue: '********',
        })),
      },
    },
    'credentials',
  );
}

function press(state: AppRouterState, name: AppKey['name']): AppRouterState {
  return transitionAppRouter(state, {
    type: 'key',
    key: { ...(name === undefined ? {} : { name }) },
    nowMs: 0,
  }).state;
}

describe('responsive list navigation and reveal rendering', () => {
  it('pages by the visible credential rows and clamps at both ends', () => {
    let state = credentials();
    state = press(state, 'page-down');
    expect(state.listIndex).toBe(4);
    state = press(state, 'end');
    expect(state.listIndex).toBe(99);
    expect(press(state, 'page-down').listIndex).toBe(99);
    expect(press(state, 'page-up').listIndex).toBe(95);
    state = press(state, 'home');
    expect(state.listIndex).toBe(0);
    expect(press(state, 'page-up').listIndex).toBe(0);
  });

  it('uses the current terminal height and filtered list', () => {
    let state = { ...credentials(40), credentialFilter: 'entry-09' };
    state = press(state, 'page-down');
    expect(state.listIndex).toBe(9);
    state = press({ ...state, credentialFilter: 'absent' }, 'end');
    expect(state.listIndex).toBe(0);
  });

  it('does not navigate behind a protected input overlay', () => {
    const state: AppRouterState = {
      ...credentials(),
      overlay: 'input-passphrase',
      query: '',
    };
    for (const name of ['home', 'end', 'page-up', 'page-down'] as const) {
      const next = press(state, name);
      expect(next.listIndex).toBe(0);
      expect(next.query).toBe('');
      expect(next.overlay).toBe(state.overlay);
    }
  });

  it('supports first and last destinations on Home', () => {
    const state = createInitialAppRouterState();
    const end = press(state, 'end');
    expect(end.menuIndex).toBeGreaterThan(0);
    expect(press(end, 'home').menuIndex).toBe(0);
  });

  it('retains state for duplicate sizes and ignored keys', () => {
    const state = credentials();
    expect(
      transitionAppRouter(state, { type: 'resize', width: 80, height: 24 }).state,
    ).toBe(state);
    expect(press(state, undefined)).toBe(state);
  });

  it('repaints once per displayed second and still clears at the exact expiry', () => {
    const state: AppRouterState = {
      ...credentials(),
      revealedName: 'entry-000',
      revealedValue: 'synthetic-display-canary',
      revealedUntilMs: 16_000,
      nowMs: 1_000,
    };
    expect(transitionAppRouter(state, { type: 'tick', nowMs: 1_250 }).state).toBe(
      state,
    );
    const next = transitionAppRouter(state, { type: 'tick', nowMs: 2_000 }).state;
    expect(next.nowMs).toBe(2_000);
    const expired = transitionAppRouter(next, { type: 'tick', nowMs: 16_000 }).state;
    expect(expired.revealedValue).toBeNull();
    expect(expired.revealedName).toBeNull();
    expect(expired.revealedUntilMs).toBe(0);
  });

  it('initializes the reveal clock immediately and pages around its panel', () => {
    const state = { ...credentials(), pendingRevealName: 'entry-000' };
    const revealed = transitionAppRouter(state, {
      type: 'backend-result',
      snapshot: state.snapshot,
      revealedSecret: 'synthetic-display-canary',
      nowMs: 100_000,
    }).state;
    expect(revealed.revealedUntilMs - revealed.nowMs).toBe(15_000);
    expect(press(revealed, 'page-down').listIndex).toBe(1);
  });
});
