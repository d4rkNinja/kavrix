import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it } from 'vitest';

import {
  APP_SCREEN_IDS,
  createInitialAppRouterState,
  emptySnapshot,
  filteredCredentials,
  navigateToScreen,
  transitionAppRouter,
  type AppKey,
  type AppRouterState,
} from '../../src/index.js';
import {
  AppChrome,
  CredentialsScreen,
  footerChips,
  renderActiveScreen,
} from '../../src/app/screens.js';
import { sanitizeTerminalText } from '../../src/terminal-text.js';
import type { AppSnapshot } from '../../src/app/backend.js';

const CREDENTIAL_NAMES = ['api-key', 'api-secret', 'db-pass', 'token'] as const;

function fixture(): AppSnapshot {
  return {
    ...emptySnapshot('credential filter fixture'),
    home: {
      profileId: 'probe',
      vaultId: 'probe-vault',
      unlocked: true,
      credentialCount: CREDENTIAL_NAMES.length,
      datastore: 'file',
      message: 'fixture',
    },
    credentials: CREDENTIAL_NAMES.map((name) => ({ name, maskedValue: '********' })),
  };
}

function credentialsScreen(
  screen: AppRouterState['screen'] = 'credentials',
  width = 100,
): AppRouterState {
  const hydrated = transitionAppRouter(
    createInitialAppRouterState({ width, height: 30, ascii: true, color: false }),
    { type: 'hydrate', snapshot: fixture() },
  ).state;
  return navigateToScreen(hydrated, screen);
}

function type(state: AppRouterState, text: string, nowMs = 0): AppRouterState {
  return transitionAppRouter(state, { type: 'key', key: { text }, nowMs }).state;
}

function pressKey(state: AppRouterState, key: AppKey, nowMs = 0): AppRouterState {
  return transitionAppRouter(state, { type: 'key', key, nowMs }).state;
}

function names(state: AppRouterState): readonly string[] {
  return filteredCredentials(state).map((credential) => credential.name);
}

function paint(state: AppRouterState, columns = state.width): string {
  return renderToString(
    createElement(AppChrome, {
      state,
      children: renderActiveScreen(state),
    }),
    { columns },
  );
}

describe('`/` opens a live name filter on the Credentials screen', () => {
  it('filters as each character is typed and never opens an overlay', () => {
    let state = credentialsScreen();
    expect(state.overlay).toBe('none');

    state = pressKey(state, { text: '/' });
    expect(state.filtering).toBe(true);
    expect(state.overlay).toBe('none');
    expect(state.credentialFilter).toBe('');
    // The unfiltered list is still whole while the filter is empty.
    expect(names(state)).toEqual([...CREDENTIAL_NAMES]);

    state = type(state, 'a');
    expect(state.credentialFilter).toBe('a');
    expect(names(state)).toEqual(['api-key', 'api-secret', 'db-pass']);

    state = type(state, 'p');
    expect(state.credentialFilter).toBe('ap');
    expect(names(state)).toEqual(['api-key', 'api-secret']);

    state = type(state, 'i');
    expect(state.credentialFilter).toBe('api');
    expect(names(state)).toEqual(['api-key', 'api-secret']);

    state = type(state, '-');
    expect(state.credentialFilter).toBe('api-');
    expect(names(state)).toEqual(['api-key', 'api-secret']);

    state = type(state, 's');
    expect(state.credentialFilter).toBe('api-s');
    expect(names(state)).toEqual(['api-secret']);
    // Typing never opens a modal, so nothing the user types can be invisible.
    expect(state.overlay).toBe('none');
  });

  it('renders the live filter with a caret and drops non-matching rows', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    for (const character of 'db-pa') state = type(state, character);
    const frame = renderToString(createElement(CredentialsScreen, { state }), {
      columns: 100,
    });
    expect(frame).toContain('db-pass');
    expect(frame).toContain('filter: db-pa_');
    expect(frame).not.toContain('api-key');
    expect(frame).not.toContain('token');
  });

  it('edits with Backspace and ends the session when the filter empties', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'to');
    expect(state.credentialFilter).toBe('to');
    expect(names(state)).toEqual(['token']);

    state = pressKey(state, { name: 'backspace' });
    expect(state.credentialFilter).toBe('t');
    expect(state.filtering).toBe(true);

    state = pressKey(state, { name: 'backspace' });
    expect(state.credentialFilter).toBe('');
    expect(state.filtering).toBe(false);
    expect(names(state)).toEqual([...CREDENTIAL_NAMES]);
  });

  it('opens the filtered row on Enter and stops collecting filter text', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'd');
    expect(names(state)).toEqual(['db-pass']);

    const opened = pressKey(state, { name: 'return' });
    expect(opened.overlay).toBe('credential-detail');
    expect(opened.pendingName).toBe('db-pass');
    expect(opened.filtering).toBe(false);
    // The filter itself stays applied, so `c` copies the filtered row rather
    // than whatever row zero of the whole vault happens to be.
    expect(names(opened)).toEqual(['db-pass']);
    const copied = transitionAppRouter(opened, {
      type: 'key',
      key: { text: 'c' },
      nowMs: 1,
    });
    expect(copied.effect).toEqual({
      kind: 'backend',
      action: { type: 'copy-credential', name: 'db-pass' },
    });
    expect(copied.state.credentialFilter).toBe('d');
  });

  it('suspends screen mnemonics and digit jumps while filtering', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'n');
    expect(state.credentialFilter).toBe('n');
    // `n` is filter text, not "put a credential".
    expect(state.overlay).toBe('none');
    expect(state.pendingName).toBeNull();

    // A digit is filter text, not a tab-strip jump.
    state = type(state, '1');
    expect(state.credentialFilter).toBe('n1');
    expect(state.screen).toBe('credentials');

    // Quitting is Ctrl+C only while a filter is open, exactly as in the
    // command palette; `q` is filter text.
    expect(pressKey(state, { text: 'q' }).quit).toBe(false);
    expect(pressKey(state, { text: 'q' }).credentialFilter).toBe('n1q');
    expect(pressKey(state, { text: 'c', ctrl: true }).quit).toBe(true);
  });

  it('moves the cursor through matches with arrows and j/k', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'a');
    expect(state.listIndex).toBe(0);
    state = pressKey(state, { name: 'down' });
    expect(state.listIndex).toBe(1);
    state = pressKey(state, { text: 'k' });
    expect(state.listIndex).toBe(0);
    state = pressKey(state, { text: 'j' });
    expect(state.listIndex).toBe(1);
    state = pressKey(state, { name: 'end' });
    expect(state.listIndex).toBe(2);
    state = pressKey(state, { name: 'up' });
    expect(state.listIndex).toBe(1);
    state = pressKey(state, { name: 'home' });
    expect(state.listIndex).toBe(0);
  });
});

describe('`/` stays honest on screens that cannot filter', () => {
  it('names the filtering screen instead of opening an input on every other screen', () => {
    for (const screen of APP_SCREEN_IDS) {
      if (screen === 'credentials') continue;
      const searched = pressKey(credentialsScreen(screen), { text: '/' });
      expect(searched.overlay, screen).toBe('none');
      expect(searched.filtering, screen).toBe(false);
      expect(searched.credentialFilter, screen).toBe('');
      expect(searched.message, screen).toBe(
        'Search is available on the Credentials screen (press 4).',
      );
      // The screen itself is untouched: `/` answers, it does not navigate.
      expect(searched.screen, screen).toBe(screen);
      expect(paint(searched, 120), screen).not.toMatch(/Search:/u);
    }
  });

  it('answers on Home, which owns no list to narrow', () => {
    const home = credentialsScreen('home');
    const answered = pressKey(home, { text: '/' });
    expect(answered.screen).toBe('home');
    expect(answered.overlay).toBe('none');
    expect(answered.message).toBe(
      'Search is available on the Credentials screen (press 4).',
    );
  });
});

describe('Escape clears the filter', () => {
  it('clears the filter, exits filter mode, and restores every row', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'db');
    expect(names(state)).toEqual(['db-pass']);

    const cleared = pressKey(state, { name: 'escape' });
    expect(cleared.credentialFilter).toBe('');
    expect(cleared.filtering).toBe(false);
    expect(names(cleared)).toEqual([...CREDENTIAL_NAMES]);
    expect(cleared.message).toBe('Credential filter cleared.');
    expect(cleared.screen).toBe('credentials');
  });

  it('retires an on-screen reveal instead of leaving plaintext visible', () => {
    let state = credentialsScreen();
    state = {
      ...state,
      revealedName: 'db-pass',
      revealedValue: 'REVEAL-CANARY-MUST-NOT-SURVIVE',
      revealedUntilMs: 999_999,
    };
    state = pressKey(state, { text: '/' });
    state = type(state, 'db');

    const cleared = pressKey(state, { name: 'escape' });
    expect(cleared.revealedName).toBeNull();
    expect(cleared.revealedValue).toBeNull();
    expect(cleared.revealedUntilMs).toBe(0);
    expect(cleared.credentialFilter).toBe('');
    expect(cleared.message).toContain('Reveal cleared');
    expect(JSON.stringify(cleared)).not.toContain('REVEAL-CANARY-MUST-NOT-SURVIVE');
  });

  it('goes home once the filter session is over', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'db');
    state = pressKey(state, { name: 'escape' });
    const home = pressKey(state, { name: 'escape' });
    expect(home.screen).toBe('home');
  });

  it('drops the filter when the screen is left', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'db');
    const away = pressKey(state, { name: 'tab' });
    expect(away.screen).not.toBe('credentials');
    expect(away.credentialFilter).toBe('');
    expect(away.filtering).toBe(false);
    expect(names(away)).toEqual([...CREDENTIAL_NAMES]);

    const back = pressKey(away, { text: '4' });
    expect(back.screen).toBe('credentials');
    expect(back.credentialFilter).toBe('');
  });
});

describe('a filter with no matches is stated, not silent', () => {
  it('reports the empty result in the message and the panel', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'zzz');
    expect(names(state)).toEqual([]);
    expect(state.message).toBe(
      "No credentials match 'zzz'. Backspace edits, Esc clears.",
    );

    const frame = renderToString(createElement(CredentialsScreen, { state }), {
      columns: 100,
    });
    expect(frame).toContain('No credentials match this search.');
    expect(frame).toContain('Esc clears it');
    expect(frame).toContain('0/4 credentials');

    // Enter has no row to open, so it says so rather than closing the filter.
    const entered = pressKey(state, { name: 'return' });
    expect(entered.overlay).toBe('none');
    expect(entered.filtering).toBe(true);
    expect(entered.message).toContain('No credentials match');
  });

  it('recovers by editing the filter back to a match', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'zzz');
    expect(state.message).toContain('No credentials match');

    state = pressKey(state, { name: 'backspace' });
    state = pressKey(state, { name: 'backspace' });
    state = pressKey(state, { name: 'backspace' });
    expect(state.message).toBeNull();
    expect(names(state)).toEqual([...CREDENTIAL_NAMES]);
  });
});

describe('the filter is sanitized terminal input', () => {
  it('strips escape and control sequences from a pasted name', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, '\u001b[31mapi\u001b[0m\u0007');
    expect(state.credentialFilter).toBe('api');
    expect(state.credentialFilter).not.toMatch(/\p{C}/u);
    expect(names(state)).toEqual(['api-key', 'api-secret']);
  });

  it('strips OSC and CSI payloads a paste can carry', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, '\u001b]0;owned\u0007db\u001b[2K\u009b31m');
    expect(state.credentialFilter).toBe('db');
    expect(names(state)).toEqual(['db-pass']);
  });

  it('sanitizes a hostile filter written straight into state before matching', () => {
    const hostile = '\u001b]0;owned\u0007db\u001b[2K\u009b31m';
    const state: AppRouterState = {
      ...credentialsScreen(),
      credentialFilter: hostile,
    };
    expect(names(state)).toEqual(['db-pass']);
    expect(sanitizeTerminalText(hostile)).not.toMatch(/\p{C}/u);
  });

  it('never paints control characters from the filter', () => {
    const state: AppRouterState = {
      ...credentialsScreen(),
      filtering: true,
      credentialFilter: 'db\u0007\u001b[31m',
    };
    const frame = paint(state);
    expect(frame).toContain('filter: db_');
    // eslint-disable-next-line no-control-regex -- the painted frame must carry no control bytes
    expect(frame).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f]/u);
  });

  it('bounds the filter so typing cannot grow it without limit', () => {
    let state = credentialsScreen();
    state = pressKey(state, { text: '/' });
    state = type(state, 'a'.repeat(500));
    expect(Array.from(state.credentialFilter)).toHaveLength(64);
  });
});

describe('the footer only advertises `/` where it works', () => {
  it('offers the filter chip on Credentials and on no other screen', () => {
    for (const screen of APP_SCREEN_IDS) {
      const chips = footerChips(credentialsScreen(screen)).map((chip) => chip.keyLabel);
      expect(chips.includes('/'), screen).toBe(screen === 'credentials');
    }
  });

  it('advertises only keys that act on the list while filtering', () => {
    const state = pressKey(credentialsScreen(), { text: '/' });
    const chips = footerChips(state);
    expect(chips.map((chip) => `${chip.keyLabel} ${chip.hint}`)).toEqual([
      'Enter detail',
      'j/k move',
      'Backspace edit',
      'Esc clear filter',
      'Tab screens',
    ]);
    // Every one of these is filter text while a filter is open, so none of them
    // may be offered.
    const frame = paint(state, 120);
    expect(frame).not.toMatch(/\bn put\b/u);
    expect(frame).not.toMatch(/\bc copy\b/u);
    expect(frame).not.toMatch(/\br reveal\b/u);
    expect(frame).not.toMatch(/u unlock/u);
    expect(frame).not.toMatch(/q quit/u);
  });
});
