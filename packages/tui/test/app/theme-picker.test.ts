import { describe, expect, it } from 'vitest';

import {
  createInitialAppRouterState,
  createStaticAppBackend,
  emptySnapshot,
  transitionAppRouter,
  type AppKey,
  type AppRouterState,
  type AppSnapshot,
} from '../../src/index.js';
import { activeTuiThemeId, applyTuiTheme, THEMES } from '../../src/app/theme.js';

function key(state: AppRouterState, input: Readonly<Partial<AppKey>>): AppRouterState {
  return transitionAppRouter(state, {
    type: 'key',
    key: { ...input },
    nowMs: 0,
  }).state;
}

function hydrated(theme?: string): AppRouterState {
  const snapshot: AppSnapshot = {
    ...emptySnapshot('fixture'),
    ...(theme === undefined ? {} : { theme }),
  };
  return transitionAppRouter(createInitialAppRouterState(), {
    type: 'hydrate',
    snapshot,
  }).state;
}

describe('TUI theme picker', () => {
  it("'t' opens the picker with the cursor on the active theme", () => {
    applyTuiTheme('gold');
    const state = key(hydrated('gold'), { text: 't' });
    expect(state.overlay).toBe('theme-picker');
    expect(state.themeCursor).toBe(0);
    expect(state.message).toContain('Theme picker');
  });

  it('arrow keys and digits move the cursor with live preview', () => {
    applyTuiTheme('gold');
    let state = key(hydrated('gold'), { text: 't' });
    state = key(state, { name: 'down' });
    expect(state.themeCursor).toBe(1);
    expect(activeTuiThemeId()).toBe('ocean');
    state = key(state, { text: '5' });
    expect(state.themeCursor).toBe(4);
    expect(activeTuiThemeId()).toBe('violet');
    state = key(state, { name: 'up' });
    expect(state.themeCursor).toBe(3);
    expect(activeTuiThemeId()).toBe('forest');
    // Cursor stays clamped inside the list.
    state = key({ ...state, themeCursor: 0 }, { name: 'up' });
    expect(state.themeCursor).toBe(0);
  });

  it('Enter commits the previewed theme and dispatches set-theme', () => {
    applyTuiTheme('gold');
    let state = key(hydrated('gold'), { text: 't' });
    state = key(state, { text: '3' });
    const committed = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    });
    expect(committed.state.overlay).toBe('none');
    expect(committed.state.themeId).toBe('magma');
    expect(committed.effect).toEqual({
      kind: 'backend',
      action: { type: 'set-theme', themeId: 'magma' },
    });
    expect(activeTuiThemeId()).toBe('magma');
  });

  it('Escape closes the picker and restores the committed theme', () => {
    applyTuiTheme('ocean');
    let state = key(hydrated('ocean'), { text: 't' });
    state = key(state, { text: '4' });
    expect(activeTuiThemeId()).toBe('forest');
    state = key(state, { name: 'escape' });
    expect(state.overlay).toBe('none');
    expect(state.themeId).toBe('ocean');
    expect(activeTuiThemeId()).toBe('ocean');
    expect(state.message).toContain('Theme unchanged');
  });

  it('digits select themes inside the picker instead of jumping screens', () => {
    applyTuiTheme('gold');
    let state = key(hydrated('gold'), { text: 't' });
    state = key(state, { text: '2' });
    expect(state.screen).toBe('home');
    expect(state.themeCursor).toBe(1);
  });

  it('hydrate adopts a valid host theme and ignores unknown ids', () => {
    applyTuiTheme('gold');
    const state = hydrated('violet');
    expect(state.themeId).toBe('violet');
    expect(activeTuiThemeId()).toBe('violet');

    applyTuiTheme('gold');
    const hostile = hydrated('neon-rainbow');
    expect(hostile.themeId).toBe('gold');
    expect(activeTuiThemeId()).toBe('gold');
  });

  it('backend set-theme results flow back into router state', async () => {
    applyTuiTheme('gold');
    const backend = createStaticAppBackend();
    const result = await backend.dispatch({ type: 'set-theme', themeId: 'magma' });
    expect(result.snapshot.theme).toBe('magma');
    expect(result.snapshot.noticeTone).toBe('success');

    const adopted = transitionAppRouter(hydrated('gold'), {
      type: 'backend-result',
      snapshot: result.snapshot,
      nowMs: 0,
    }).state;
    expect(adopted.themeId).toBe('magma');
    expect(activeTuiThemeId()).toBe('magma');
  });

  it('renders a row per theme through the app chrome', async () => {
    const { renderToString } = await import('ink');
    const { createElement } = await import('react');
    const { AppChrome, renderActiveScreen } = await import('../../src/index.js');
    applyTuiTheme('gold');
    const state = key(hydrated('gold'), { text: 't' });
    const painted = renderToString(
      createElement(AppChrome, {
        state,
        children: renderActiveScreen(state),
      }),
      { columns: 120 },
    ).replace(/\s+/gu, ' ');
    for (const theme of THEMES) {
      expect(painted).toContain(theme.label);
    }
    expect(painted).toContain('Enter applies');
  });
});
