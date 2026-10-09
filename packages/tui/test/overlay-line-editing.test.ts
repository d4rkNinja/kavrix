import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it } from 'vitest';

import { emptySnapshot } from '../src/app/backend.js';
import {
  createInitialAppRouterState,
  navigateToScreen,
  transitionAppRouter,
  type AppKey,
  type AppRouterState,
} from '../src/app/router.js';
import { AppChrome, renderActiveScreen } from '../src/app/screens.js';

function credentials(): AppRouterState {
  const snapshot = {
    ...emptySnapshot('fixture'),
    home: {
      ...emptySnapshot('fixture').home,
      unlocked: true,
      profileId: 'dev',
      vaultId: 'default',
    },
  };
  return navigateToScreen(
    transitionAppRouter(createInitialAppRouterState({ width: 120, height: 30 }), {
      type: 'hydrate',
      snapshot,
    }).state,
    'credentials',
  );
}

function press(state: AppRouterState, key: AppKey): AppRouterState {
  return transitionAppRouter(state, { type: 'key', key, nowMs: 0 }).state;
}

function type(state: AppRouterState, text: string): AppRouterState {
  return Array.from(text).reduce(
    (current, char) => press(current, { text: char }),
    state,
  );
}

/** Opens the put-credential wizard and fills the name field. */
function putName(name: string): AppRouterState {
  return type(press(credentials(), { text: 'n' }), name);
}

describe('overlay line editing', () => {
  it('keeps Backspace deleting one code point', () => {
    const state = putName('aws-access-key');
    expect(press(state, { name: 'backspace' }).query).toBe('aws-access-ke');
    // Backspace on an empty field is a no-op, not an error.
    expect(press(putName(''), { name: 'backspace' }).query).toBe('');
  });

  it('deletes one code point, never half a surrogate pair', () => {
    const emoji = putName('key-\u{1F600}');
    expect(emoji.query).toBe('key-\u{1F600}');
    expect(press(emoji, { name: 'backspace' }).query).toBe('key-');
    expect(press(emoji, { name: 'backspace' }).query).not.toContain('\uFFFD');
  });

  it('clears the whole field with Ctrl+U without closing the overlay', () => {
    const cleared = press(putName('a-very-long-credential-name'), {
      ctrl: true,
      text: 'u',
    });
    expect(cleared.query).toBe('');
    // The overlay stays open, so the user retypes instead of restarting.
    expect(cleared.overlay).toBe('input-put-name');
    expect(cleared.message).toMatch(/cleared/u);
  });

  it('deletes the last word with Ctrl+W, taking the whitespace with it', () => {
    // A word is whitespace-delimited, so a path segment is part of its word and
    // the space in front of it goes too (`unix-word-rubout`, as in Bash).
    expect(
      press(putName('db/hostname backup/2024'), { ctrl: true, text: 'w' }).query,
    ).toBe('db/hostname');
    expect(press(putName('alpha  beta'), { ctrl: true, text: 'w' }).query).toBe(
      'alpha',
    );
    // Whitespace only: the field empties rather than looping.
    expect(press(putName('   '), { ctrl: true, text: 'w' }).query).toBe('');
  });
  it('still submits on Enter after editing, with the corrected value', () => {
    let state = press(putName('typo-name'), { ctrl: true, text: 'w' });
    expect(state.query).toBe('');
    state = type(state, 'corrected');
    const advanced = press(state, { name: 'return' });
    expect(advanced.overlay).toBe('input-put-value');
    expect(advanced.pendingName).toBe('corrected');
  });

  it('keeps the per-field bound, so editing is not a way past it', () => {
    // input-vault-label is the tightest bound (128).
    const opened = press(navigateToScreen(credentials(), 'vaults'), { text: 'n' });
    expect(opened.overlay).toBe('input-vault-label');
    const long = type(opened, 'a'.repeat(200));
    expect(long.query).toHaveLength(128);
    expect(type(press(long, { ctrl: true, text: 'u' }), 'b'.repeat(200)).query).toBe(
      'b'.repeat(128),
    );
  });

  it('clears only on the Ctrl-modified key, never on a leaked control word', () => {
    // A plain `u` is field text, which is what makes a credential name like
    // "username" usable at all.
    const state = putName('username');
    expect(state.query).toBe('username');

    const cleared = press(state, { ctrl: true, text: 'u' });
    expect(cleared.query).toBe('');

    // An unrelated Ctrl combination is not a clear either.
    const other = press(putName(''), { ctrl: true, text: 'z' });
    expect(other.query).toBe('z');
    expect(other.overlay).toBe('input-put-name');
  });

  it('advertises the editing bindings in the overlay action row', () => {
    const frame = renderToString(
      createElement(AppChrome, {
        state: putName('name'),
        children: renderActiveScreen(putName('name')),
      }),
      { columns: 120 },
    );
    expect(frame).toMatch(/\^W/u);
    expect(frame).toMatch(/\^U/u);
    expect(frame).toMatch(/\^V/u);
  });
});
