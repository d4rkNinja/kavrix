import { renderToString } from 'ink';
import { createElement } from 'react';
import { describe, expect, it } from 'vitest';

import { allCommands, commandGroups, filterCommands } from '../src/app/commands.js';
import { APP_MENU, type AppScreenId } from '../src/app/ids.js';
import { CommandPaletteRows, footerChips } from '../src/app/screens.js';
import { emptySnapshot, type AppSnapshot } from '../src/app/backend.js';
import {
  createInitialAppRouterState,
  navigateToScreen,
  paletteEntries,
  transitionAppRouter,
  type AppKey,
  type AppRouterState,
} from '../src/app/router.js';

function sampleSnapshot(): AppSnapshot {
  return {
    ...emptySnapshot('fixture'),
    home: {
      profileId: 'dev',
      vaultId: 'default',
      unlocked: true,
      credentialCount: 2,
      datastore: 'file',
      message: 'fixture session',
    },
    profiles: [
      { id: 'dev', datastore: 'file', selected: true, detail: 'file ./vault' },
    ],
    vaults: [
      { id: 'default', selected: true, credentialCount: 2, detail: '2 credentials' },
    ],
    credentials: [
      { name: 'api-key', maskedValue: '********' },
      { name: 'db-pass', maskedValue: '********' },
    ],
    doctor: [{ name: 'session', status: 'ok', detail: 'healthy' }],
    recovery: [{ slotId: 'slot-1', status: 'active', detail: 'active kit' }],
    policies: [{ id: 'p1', kind: 'policy', summary: 'deny reveal' }],
    browse: [{ id: 'ctx', kind: 'context', label: 'app', detail: 'root' }],
    runPreview: 'Dry preview ready',
    agentStatus: 'idle',
    notice: 'fixture',
    noticeTone: 'info',
  };
}

function baseScreen(screen: AppScreenId, unlocked = true): AppRouterState {
  const hydrated = transitionAppRouter(
    createInitialAppRouterState({ width: 120, height: 30 }),
    {
      type: 'hydrate',
      snapshot: unlocked ? sampleSnapshot() : emptySnapshot('locked'),
    },
  ).state;
  return navigateToScreen(hydrated, screen);
}

function press(state: AppRouterState, key: AppKey): AppRouterState {
  return transitionAppRouter(state, { type: 'key', key, nowMs: 0 }).state;
}

describe('command palette catalogue', () => {
  it('gives every screen at least the global actions and no duplicate keys', () => {
    for (const entry of APP_MENU) {
      const commands = allCommands(baseScreen(entry.id));
      expect(commands.length).toBeGreaterThan(0);
      const keys = commands.map((command) => command.keyLabel);
      expect(new Set(keys).size, entry.id).toBe(keys.length);
    }
  });

  it('runs the same transition as pressing the key directly', () => {
    // The palette must not grow a parallel implementation of each action, so
    // every choice is asserted to be exactly the keystroke it names.
    for (const entry of APP_MENU) {
      const state = baseScreen(entry.id);
      const palette = press(state, { text: ':' });
      expect(palette.overlay).toBe('command-palette');

      for (const command of allCommands(state)) {
        // `q` quits and `?` navigates before screen handling ever runs, so the
        // pre-palette state is not where those two are meaningful.
        if (command.id === 'quit' || command.id === 'help') continue;
        const direct = transitionAppRouter(state, {
          type: 'key',
          key: command.key,
          nowMs: 0,
        });
        // Look the entry up by id, never by identity: every call rebuilds the
        // catalogue, so reference equality would silently miss.
        const index = allCommands(palette).findIndex(
          (entry) => entry.id === command.id,
        );
        const chosen = { ...palette, paletteIndex: index };
        const blocked = command.blocked(state);
        if (blocked !== null) {
          // A blocked action must explain itself rather than run or vanish.
          const refused = transitionAppRouter(chosen, {
            type: 'key',
            key: { name: 'return' },
            nowMs: 0,
          });
          expect(refused.effect, `${entry.id}/${command.id}`).toEqual({ kind: 'none' });
          expect(refused.state.message, `${entry.id}/${command.id}`).toBe(blocked);
          expect(refused.state.overlay, `${entry.id}/${command.id}`).toBe(
            'command-palette',
          );
          continue;
        }
        const viaPalette = transitionAppRouter(chosen, {
          type: 'key',
          key: { name: 'return' },
          nowMs: 0,
        });
        expect(viaPalette.state.overlay, `${entry.id}/${command.id}`).toBe(
          direct.state.overlay,
        );
        expect(viaPalette.effect, `${entry.id}/${command.id}`).toEqual(direct.effect);
      }
    }
  });

  it('opens from `:` and Ctrl+K but never steals a colon typed into a field', () => {
    const state = baseScreen('credentials');
    const field = press(state, { text: 'n' });
    expect(field.overlay).toBe('input-put-name');

    const typed = press(field, { text: ':' });
    expect(typed.overlay).toBe('input-put-name');
    expect(typed.query).toBe(':');

    expect(press(state, { text: ':' }).overlay).toBe('command-palette');
    expect(press(state, { ctrl: true, text: 'k' }).overlay).toBe('command-palette');
  });

  it('runs the action the cursor points at on Enter', () => {
    const palette = press(baseScreen('credentials'), { text: ':' });
    // Row 1 on credentials is the screen's own "Enter → view masked detail".
    const opened = press(palette, { text: '1' });
    expect(opened.overlay).toBe('credential-detail');
    expect(opened.pendingName).toBe('api-key');
    expect(opened.paletteFilter).toBe('');
  });

  it('explains a blocked action instead of silently doing nothing', () => {
    const locked = press(baseScreen('credentials', false), { text: ':' });
    const putIndex = allCommands(locked).findIndex(
      (command) => command.id === 'credential-put',
    );
    const blocked = transitionAppRouter(
      { ...locked, paletteIndex: putIndex },
      { type: 'key', key: { name: 'return' }, nowMs: 0 },
    );
    expect(blocked.effect).toEqual({ kind: 'none' });
    expect(blocked.state.message).toMatch(/unlock the vault first/i);
  });

  it('closes on Escape without running anything', () => {
    const closed = press(press(baseScreen('credentials'), { text: ':' }), {
      name: 'escape',
    });
    expect(closed.overlay).toBe('none');
    expect(closed.paletteFilter).toBe('');
    expect(closed.paletteIndex).toBe(0);
  });

  it('filters by label, hint, and key, and clamps the cursor', () => {
    const state = baseScreen('credentials');
    const commands = allCommands(state);
    expect(filterCommands(commands, '')).toHaveLength(commands.length);
    expect(filterCommands(commands, 'reveal').map((entry) => entry.id)).toEqual([
      'credential-reveal',
    ]);
    expect(filterCommands(commands, 'theme').map((entry) => entry.id)).toEqual([
      'theme',
    ]);
    expect(filterCommands(commands, 'no such action')).toHaveLength(0);
    // Matching is case-insensitive over label, hint, and key.
    expect(filterCommands(commands, 'REVEAL').map((entry) => entry.id)).toEqual([
      'credential-reveal',
    ]);

    let filtered = press(state, { text: ':' });
    for (const char of 'theme') {
      filtered = press(filtered, { text: char });
    }
    expect(filtered.paletteFilter).toBe('theme');
    expect(paletteEntries(filtered).map((entry) => entry.id)).toEqual(['theme']);

    // A single match keeps the cursor at row 0 rather than stranding it past the end.
    const moved = press(press(press(filtered, { name: 'down' }), { text: 'j' }), {
      name: 'down',
    });
    expect(moved.paletteIndex).toBe(0);

    const cleared = press(filtered, { name: 'backspace' });
    expect(cleared.paletteFilter).toBe('them');
  });

  it('groups screen actions ahead of always-available ones', () => {
    const groups = commandGroups(baseScreen('policy'));
    expect(groups.length).toBe(2);
    expect(groups[0]?.label).toMatch(/policy/i);
    expect(groups[1]?.label).toBe('Always available');
    expect(groups[1]?.commands.some((command) => command.id === 'quit')).toBe(true);
  });

  it('renders a readable action list with keys and reasons', () => {
    // Filtered first: a short list has no scrolling, so every row is asserted
    // rather than whichever twelve happened to fit.
    let palette = press(baseScreen('credentials'), { text: ':' });
    for (const char of 'reveal') {
      palette = press(palette, { text: char });
    }
    const frame = renderToString(
      createElement(CommandPaletteRows, { state: palette }),
      {
        columns: 120,
      },
    );
    expect(frame).toMatch(/reveal value/u);

    const locked = press(baseScreen('credentials', false), { text: ':' });
    let lockedFiltered = locked;
    for (const char of 'put') {
      lockedFiltered = press(lockedFiltered, { text: char });
    }
    const blockedFrame = renderToString(
      createElement(CommandPaletteRows, {
        state: lockedFiltered,
      }),
      { columns: 120 },
    );
    expect(blockedFrame).toMatch(/add credential/u);
    expect(blockedFrame).toMatch(/unlock the vault first/iu);
  });
});

describe('footer and palette parity', () => {
  /**
   * The audit found global keys that worked everywhere but were only advertised
   * somewhere. This matrix is the guard: every key the footer advertises must be
   * a palette entry for that same screen, and the global controls must always be
   * present.
   */
  it('advertises the same keys in the footer and the palette on every screen', () => {
    for (const entry of APP_MENU) {
      const chips = footerChips(baseScreen(entry.id)).map((chip) => chip.keyLabel);
      const paletteKeys = new Set(
        allCommands(baseScreen(entry.id)).map((c) => c.keyLabel),
      );
      for (const chip of chips) {
        // `j/k` is the list cursor, which has no palette row of its own, and `:`
        // opens the palette itself — a row cannot list the control that lists it.
        if (chip === 'j/k' || chip === ':') continue;
        expect(paletteKeys.has(chip), `${entry.id} advertises '${chip}'`).toBe(true);
      }
    }
  });

  it('advertises the global controls on every screen where they work', () => {
    for (const entry of APP_MENU) {
      const chips = footerChips(baseScreen(entry.id)).map((chip) => chip.keyLabel);
      expect(chips, entry.id).toContain(':');
      expect(chips, entry.id).toContain('?');
      expect(chips, entry.id).toContain('q');
      expect(chips, entry.id).toContain('l');
    }
  });
});
