import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it } from 'vitest';

import {
  animatedDots,
  barFill,
  progressCells,
  revealProgress,
  revealRemainingMs,
  sweepBarRow,
  sweepOffset,
} from '../src/motion.js';
import {
  dividerRule,
  maskBullets,
  sectionTitleWide,
  toneGlyph,
  type AppAccent,
} from '../src/app/theme.js';
import {
  ProgressBar,
  RevealCountdown,
  StepDots,
  SweepBar,
  TabNav,
} from '../src/app/widgets.js';
import { CredentialsScreen, HelpScreen, HomeScreen } from '../src/app/screens.js';
import {
  createInitialAppRouterState,
  transitionAppRouter,
  type AppKey,
  type AppRouterState,
  type AppRouterTransition,
} from '../src/app/router.js';
import { emptySnapshot } from '../src/app/backend.js';
import { createInitialOnboardingState } from '../src/app/onboarding-router.js';
import { renderOnboardingScreen } from '../src/app/onboarding-app.js';
import { sanitizeTerminalText } from '../src/terminal-text.js';

function isAsciiOnly(value: string): boolean {
  return Array.from(value).every((glyph) => (glyph.codePointAt(0) ?? 128) <= 0x7f);
}

describe('motion primitives for bars and countdowns', () => {
  it('renders determinate bars on the character grid', () => {
    expect(progressCells(0, 10)).toBe(0);
    expect(progressCells(0.5, 10)).toBe(5);
    expect(progressCells(1, 10)).toBe(10);
    expect(progressCells(2, 10)).toBe(10);
    expect(barFill(0.5, 6, false)).toBe('\u2588\u2588\u2588\u2591\u2591\u2591');
    expect(barFill(1, 3, true)).toBe('###');
    expect(barFill(0, 3, true)).toBe('---');
    expect(barFill(0.5, 0, false)).toBe('');
  });

  it('keeps the indeterminate sweep inside the track and ASCII-safe', () => {
    for (let frame = 0; frame < 40; frame += 1) {
      const row = sweepBarRow(frame, 10, 3, true);
      expect(row).toHaveLength(10);
      expect(isAsciiOnly(row)).toBe(true);
    }
    const unicodeRow = sweepBarRow(2, 10, 3, false);
    expect(unicodeRow).toHaveLength(10);
    expect(sweepOffset(0, 6, 3)).toBe(0);
    expect(sweepOffset(3, 6, 3)).toBe(3);
    expect(sweepOffset(4, 6, 3)).toBe(0);
    expect(sweepOffset(0, 2, 5)).toBe(0);
  });

  it('computes the timed-reveal countdown and busy dots', () => {
    expect(revealRemainingMs(15_000, 5_000)).toBe(10_000);
    expect(revealRemainingMs(15_000, 20_000)).toBe(0);
    expect(revealProgress(15_000, 5_000, 15_000)).toBeCloseTo(10 / 15, 5);
    expect(revealProgress(15_000, 15_000, 15_000)).toBe(0);
    expect(revealProgress(0, 5_000, 15_000)).toBe(0);
    expect(animatedDots(0)).toBe('.');
    expect(animatedDots(1)).toBe('..');
    expect(animatedDots(2)).toBe('...');
    expect(animatedDots(3)).toBe('.');
    expect(animatedDots(0, 0)).toBe('');
  });
});

describe('theme glyphs stay printable and mode-safe', () => {
  const accents: readonly AppAccent[] = [
    'cyan',
    'green',
    'yellow',
    'magenta',
    'blue',
    'red',
    'white',
    'gray',
  ];
  const tones = ['success', 'warning', 'error', 'info', 'muted'] as const;

  it('gives every tone an ASCII fallback and a unicode glyph', () => {
    for (const tone of tones) {
      expect(isAsciiOnly(toneGlyph(tone, true))).toBe(true);
      expect(toneGlyph(tone, false).trim().length).toBeGreaterThan(0);
    }
    expect(accents.length).toBe(8);
  });

  it('masks typed secrets with bullets only in unicode mode', () => {
    expect(maskBullets(5, false)).toBe('\u2022\u2022\u2022\u2022\u2022');
    expect(maskBullets(5, true)).toBe('*****');
    expect(maskBullets(100, true)).toHaveLength(32);
    expect(maskBullets(-1, false)).toBe('');
  });

  it('pads wide section titles into a full rule and keeps ASCII bracketed', () => {
    const wide = sectionTitleWide('Credentials', false, 40);
    expect(wide.startsWith(' \u2500 CREDENTIALS \u2500')).toBe(true);
    expect(wide).toHaveLength(40);
    expect(sectionTitleWide('Credentials', true, 40)).toBe('[ CREDENTIALS ]');
    expect(dividerRule(false, 5)).toBe('\u2500\u2500\u2500\u2500\u2500');
    expect(dividerRule(true, 5)).toBe('-----');
  });

  it('degrades authored typographic punctuation to readable ASCII separators', () => {
    expect(sanitizeTerminalText('a · b — c… d – e', true)).toBe('a - b - c... d - e');
    expect(sanitizeTerminalText('a · b', false)).toBe('a \u00b7 b');
    // Unknown non-ASCII still fails closed to '?' in ascii mode.
    expect(sanitizeTerminalText('\u{1F512}', true)).toBe('?');
  });
});

describe('screen tab strip', () => {
  it('numbers entries to mirror digit shortcuts and highlights the active screen', () => {
    const frame = renderToString(
      createElement(TabNav, {
        activeId: 'home',
        color: false,
        ascii: false,
        width: 80,
      }),
      { columns: 80 },
    );
    expect(frame).toContain('1 Home');
    expect(frame).toContain('2 Profiles');
    expect(frame).toContain('4 Creds');
    expect(frame).toContain('7 Recovery');
    // At 80 columns the eight tabs need all 78 usable cells, leaving no room for
    // the overflow marker. The strip keeps the marker and drops the eighth tab
    // rather than rendering a marker that `overflow: hidden` would clip away.
    expect(frame).toContain('…');
    expect(frame).not.toContain('8 Run');
    expect(frame).not.toContain('9 Policy');
  });

  it('spends every free column instead of over-reserving the overflow marker', () => {
    // 84 columns is the first width where the eighth tab and the marker both
    // fit. An over-reserved budget silently drops back to seven tabs here.
    const frame = renderToString(
      createElement(TabNav, {
        activeId: 'home',
        color: false,
        ascii: false,
        width: 84,
      }),
      { columns: 84 },
    );
    expect(frame).toContain('8 Run');
    expect(frame).toContain('…');
    expect(frame).not.toContain('9 Policy');
  });

  it('forces the active tab into the kept set when it would truncate away', () => {
    const frame = renderToString(
      createElement(TabNav, {
        activeId: 'showcase',
        color: false,
        ascii: false,
        width: 80,
      }),
      { columns: 80 },
    );
    expect(frame).toContain('Docs');
  });

  it('hides on narrow terminals and stays ASCII-safe in ascii mode', () => {
    const narrow = renderToString(
      createElement(TabNav, {
        activeId: 'home',
        color: false,
        ascii: false,
        width: 40,
      }),
      { columns: 40 },
    );
    expect(narrow).not.toContain('Home');

    const asciiFrame = renderToString(
      createElement(TabNav, {
        activeId: 'credentials',
        color: false,
        ascii: true,
        width: 80,
      }),
      { columns: 80 },
    );
    expect(isAsciiOnly(asciiFrame)).toBe(true);
    expect(asciiFrame).toContain('4 Creds');
  });
});

describe('router keymap: digit jumps and tab cycling', () => {
  function state(): AppRouterState {
    return createInitialAppRouterState({ width: 80, height: 24, ascii: true });
  }
  function press(current: AppRouterState, key: AppKey): AppRouterTransition {
    return transitionAppRouter(current, { type: 'key', key, nowMs: 1_000 });
  }

  it('jumps to the numbered screen shown in the tab strip', () => {
    const jumped = press(state(), { text: '4' });
    expect(jumped.state.screen).toBe('credentials');
    expect(jumped.state.navDirection).toBe('forward');
  });

  it('runs the target screen refresh effect when a digit lands on doctor', () => {
    const jumped = press(state(), { text: '5' });
    expect(jumped.state.screen).toBe('doctor');
    expect(jumped.effect).toEqual({ kind: 'backend', action: { type: 'run-doctor' } });
  });

  it('ignores a digit that names the current screen', () => {
    const current = state();
    const here = press(current, { text: '1' });
    expect(here.state).toBe(current);
    expect(here.state.navDirection).toBe('none');
  });

  it('cycles forward with wrap-around and backward with Shift+Tab', () => {
    const forward = press(state(), { name: 'tab' });
    expect(forward.state.screen).toBe('profiles');
    expect(forward.state.navDirection).toBe('forward');

    const wrapped = press({ ...state(), screen: 'showcase' }, { name: 'tab' });
    expect(wrapped.state.screen).toBe('home');
    expect(wrapped.state.navDirection).toBe('back');

    const back = press(forward.state, { name: 'tab', shift: true });
    expect(back.state.screen).toBe('home');
    expect(back.state.navDirection).toBe('back');
  });

  it('never moves screens while an overlay owns the keyboard', () => {
    const typing = press(
      { ...state(), overlay: 'input-search', query: 'api' },
      { name: 'tab' },
    );
    expect(typing.state.screen).toBe('home');
    expect(typing.state.overlay).toBe('input-search');
    expect(typing.state.query).toBe('api');
  });

  it('marks Escape-to-home as a backward navigation', () => {
    const escaped = press({ ...state(), screen: 'credentials' }, { name: 'escape' });
    expect(escaped.state.screen).toBe('home');
    expect(escaped.state.navDirection).toBe('back');
  });

  it('advances the reveal clock each tick and clears it on expiry', () => {
    const base = {
      ...state(),
      screen: 'credentials' as const,
      revealedName: 'api-key',
      revealedValue: 'temporary',
      revealedUntilMs: 20_000,
    };
    const quiet = state();
    const idle = transitionAppRouter(quiet, { type: 'tick', nowMs: 5_000 });
    expect(idle.state).toBe(quiet);

    const ticking = transitionAppRouter(base, { type: 'tick', nowMs: 10_000 });
    expect(ticking.state.nowMs).toBe(10_000);
    expect(ticking.state.revealedValue).toBe('temporary');

    const expired = transitionAppRouter(base, { type: 'tick', nowMs: 20_000 });
    expect(expired.state.revealedValue).toBeNull();
    expect(expired.state.message).toContain('Reveal expired');
  });
});

describe('rendered feedback widgets', () => {
  it('shows a live seconds countdown next to a depleting bar', () => {
    const frame = renderToString(
      createElement(RevealCountdown, {
        expiresAtMs: 20_000,
        nowMs: 5_000,
        color: false,
        ascii: false,
      }),
      { columns: 80 },
    );
    expect(frame).toContain('REVEAL remasks in 15s');
    expect(frame).toContain('\u2588');

    const asciiFrame = renderToString(
      createElement(RevealCountdown, {
        expiresAtMs: 20_000,
        nowMs: 5_000,
        color: false,
        ascii: true,
      }),
      { columns: 80 },
    );
    expect(isAsciiOnly(asciiFrame)).toBe(true);
  });

  it('renders determinate progress, wizard dots, and a settled sweep bar', () => {
    const bar = renderToString(
      createElement(ProgressBar, {
        progress: 0.5,
        width: 6,
        color: false,
        ascii: true,
      }),
      { columns: 40 },
    );
    expect(bar).toContain('###---');
    expect(bar).toContain('50%');

    const dots = renderToString(
      createElement(StepDots, { index: 1, total: 4, color: false, ascii: true }),
      { columns: 40 },
    );
    expect(dots).toContain('2/4');

    const sweep = renderToString(
      createElement(SweepBar, { width: 8, color: false, ascii: true, animate: false }),
      { columns: 40 },
    );
    expect(sweep).toContain('########');
  });

  it('paints the countdown under an active reveal on the credentials screen', () => {
    const state = {
      ...createInitialAppRouterState({ width: 80, height: 24, ascii: true }),
      screen: 'credentials' as const,
      sessionReady: true,
      revealedName: 'api-key',
      revealedValue: 'temporary',
      revealedUntilMs: 20_000,
      nowMs: 5_000,
      snapshot: {
        ...emptySnapshot(),
        credentials: [{ name: 'api-key', maskedValue: '********' }],
      },
    };
    const frame = renderToString(createElement(CredentialsScreen, { state }), {
      columns: 80,
    });
    expect(frame).toContain('REVEAL: temporary');
    expect(frame).toContain('remasks in 15s');
  });

  it('numbers home menu rows with the same numbers as the tab strip', () => {
    const state = createInitialAppRouterState({ width: 80, height: 24, ascii: true });
    const frame = renderToString(createElement(HomeScreen, { state }), { columns: 80 });
    expect(frame).toContain('2 Profiles');
    expect(frame).toContain('4 Creds');
  });

  it('documents tab cycling and digit jumps on the help screen', () => {
    const state = createInitialAppRouterState({ width: 80, height: 24, ascii: true });
    const frame = renderToString(createElement(HelpScreen, { state }), { columns: 80 });
    expect(frame).toContain('Tab / Shift+Tab cycle');
    expect(frame).toContain('digits 1-9 jump');
  });
});

describe('onboarding progress affordances', () => {
  it('shows step dots and a determinate progress bar beside the ACTIVE cue', () => {
    const state = createInitialOnboardingState({ width: 80, height: 24, ascii: false });
    const frame = renderToString(renderOnboardingScreen(state), { columns: 80 });
    expect(frame).toMatch(/ACTIVE 1\/\d+/u);
    expect(frame).toContain('1/');
    expect(frame).toContain('%');

    const asciiState = createInitialOnboardingState({
      width: 80,
      height: 24,
      ascii: true,
    });
    const asciiFrame = renderToString(renderOnboardingScreen(asciiState), {
      columns: 80,
    });
    expect(isAsciiOnly(asciiFrame)).toBe(true);
    expect(asciiFrame).toMatch(/ACTIVE 1\/\d+/u);
  });
});
