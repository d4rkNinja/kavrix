import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it } from 'vitest';

import {
  APP_SCREEN_IDS,
  createInitialAppRouterState,
  createStaticAppBackend,
  emptySnapshot,
  navigateToScreen,
  transitionAppRouter,
  HomeScreen,
  ProfilesScreen,
  VaultsScreen,
  CredentialsScreen,
  DoctorScreen,
  RecoveryScreen,
  RunScreen,
  PolicyScreen,
  AgentScreen,
  BrowseScreen,
  HelpScreen,
  renderActiveScreen,
  resolveAppPresentation,
  listScreenInventory,
  type AppRouterState,
  type AppSnapshot,
} from '../../src/index.js';

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
      {
        id: 'dev',
        datastore: 'file',
        selected: true,
        detail: 'file ./vault',
      },
    ],
    vaults: [
      {
        id: 'default',
        selected: true,
        credentialCount: 2,
        detail: '2 credentials',
      },
    ],
    credentials: [
      { name: 'api-key', maskedValue: '********' },
      { name: 'db-pass', maskedValue: '********' },
    ],
    doctor: [{ name: 'session', status: 'ok', detail: 'healthy' }],
    recovery: [{ slotId: 'slot-1', status: 'active', detail: 'active kit' }],
    policies: [{ id: 'p1', kind: 'policy', summary: 'deny reveal' }],
    browse: [
      {
        id: 'ctx',
        kind: 'context',
        label: 'app',
        detail: 'root',
      },
    ],
    runPreview: 'Dry preview ready',
    agentStatus: 'idle',
    notice: 'fixture',
    noticeTone: 'info',
  };
}

function hydrate(ascii = false, color = true): AppRouterState {
  const base = createInitialAppRouterState({ ascii, color, width: 100, height: 30 });
  return transitionAppRouter(base, {
    type: 'hydrate',
    snapshot: sampleSnapshot(),
  }).state;
}

function frame(state: AppRouterState): string {
  return renderToString(renderActiveScreen(state), { columns: 100 });
}

describe('app router navigation', () => {
  it('lists every required screen id', () => {
    expect(listScreenInventory()).toEqual([...APP_SCREEN_IDS]);
  });

  it('moves the home menu and opens screens', () => {
    let state = hydrate();
    state = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'down' },
      nowMs: 0,
    }).state;
    const opened = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    });
    expect(opened.state.screen).toBe('vaults');
  });

  it('returns home on escape and quits on q', () => {
    let state = navigateToScreen(hydrate(), 'help');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'escape' },
      nowMs: 0,
    }).state;
    expect(state.screen).toBe('home');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'q' },
      nowMs: 0,
    }).state;
    expect(state.quit).toBe(true);
  });

  it('requires REVEAL confirmation before backend reveal', () => {
    const state = navigateToScreen(hydrate(), 'credentials');
    const pending = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'r' },
      nowMs: 0,
    });
    expect(pending.state.overlay).toBe('confirm-reveal');
    expect(pending.effect.kind).toBe('none');
    const confirmed = transitionAppRouter(pending.state, {
      type: 'key',
      key: { text: 'y' },
      nowMs: 1,
    });
    expect(confirmed.effect).toEqual({
      kind: 'backend',
      action: { type: 'reveal-credential', name: 'api-key' },
    });
  });

  it('blocks final recovery-slot revoke without warning overlay', () => {
    let state = navigateToScreen(hydrate(), 'recovery');
    state = {
      ...state,
      snapshot: {
        ...state.snapshot,
        recovery: [{ slotId: 'only', status: 'active', detail: 'last' }],
      },
    };
    const next = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    });
    expect(next.state.overlay).toBe('confirm-revoke-last');
  });
});

describe('screen renders', () => {
  const screens = [
    ['home', HomeScreen],
    ['profiles', ProfilesScreen],
    ['vaults', VaultsScreen],
    ['credentials', CredentialsScreen],
    ['doctor', DoctorScreen],
    ['recovery', RecoveryScreen],
    ['run', RunScreen],
    ['policy', PolicyScreen],
    ['agent', AgentScreen],
    ['browse', BrowseScreen],
    ['help', HelpScreen],
  ] as const;

  for (const [id, Component] of screens) {
    it(`renders ${id}`, () => {
      const state = navigateToScreen(hydrate(), id);
      const output = renderToString(createElement(Component, { state }), {
        columns: 100,
      });
      expect(output.length).toBeGreaterThan(10);
      expect(output).not.toContain('\u0007');
      expect(output).not.toContain('PASSWORD-CANARY');
    });
  }

  it('renders showcase destination via active screen helper', () => {
    const state = navigateToScreen(hydrate(), 'showcase');
    const output = renderToString(renderActiveScreen(state), { columns: 100 });
    expect(output).toContain('Storage showcase');
  });
});

describe('ASCII and NO_COLOR presentation', () => {
  it('defaults ascii on win32 and honors NO_COLOR', () => {
    const win = resolveAppPresentation({
      platform: 'win32',
      term: 'xterm-256color',
      noColor: false,
    });
    expect(win.ascii).toBe(true);
    const dumb = resolveAppPresentation({
      platform: 'linux',
      term: 'dumb',
      noColor: false,
    });
    expect(dumb.color).toBe(false);
    expect(dumb.ascii).toBe(true);
  });

  it('snapshots home and credentials in ASCII and NO_COLOR modes', () => {
    const asciiHome = frame(navigateToScreen(hydrate(true, false), 'home'));
    const asciiCreds = frame(navigateToScreen(hydrate(true, false), 'credentials'));
    expect(asciiHome).toContain('HOME / DASHBOARD');
    expect(asciiHome).not.toContain('\u276f');
    expect(asciiCreds).toContain('api-key');
    expect(asciiCreds).toContain('********');
    expect(asciiCreds).not.toContain('\u2022');
  });
});

describe('static backend', () => {
  it('loads and dispatches without unlocking', async () => {
    const backend = createStaticAppBackend(sampleSnapshot());
    const loaded = await backend.load();
    expect(loaded.credentials).toHaveLength(2);
    const result = await backend.dispatch({
      type: 'unlock',
      passphrase: 'secret',
    });
    expect(result.snapshot.noticeTone).toBe('warning');
  });
});

describe('credential mutation overlays', () => {
  it('dispatches put-credential after name and value overlays', () => {
    let state = navigateToScreen(hydrate(), 'credentials');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'n' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-put-name');
    for (const ch of 'new-secret') {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: ch },
        nowMs: 0,
      }).state;
    }
    state = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-put-value');
    expect(state.pendingName).toBe('new-secret');
    for (const ch of 'value') {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: ch },
        nowMs: 0,
      }).state;
    }
    const saved = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 1,
    });
    expect(saved.effect).toEqual({
      kind: 'backend',
      action: { type: 'put-credential', name: 'new-secret', value: 'value' },
    });
  });

  it('dispatches rename-credential from m overlay', () => {
    let state = navigateToScreen(hydrate(), 'credentials');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'm' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-rename');
    expect(state.pendingName).toBe('api-key');
    for (const ch of 'api-key-2') {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: ch },
        nowMs: 0,
      }).state;
    }
    const renamed = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 1,
    });
    expect(renamed.effect).toEqual({
      kind: 'backend',
      action: { type: 'rename-credential', from: 'api-key', to: 'api-key-2' },
    });
  });

  it('requires confirm before remove-credential', () => {
    let state = navigateToScreen(hydrate(), 'credentials');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'x' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('confirm-remove');
    expect(state.pendingName).toBe('api-key');
    const removed = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'y' },
      nowMs: 1,
    });
    expect(removed.effect).toEqual({
      kind: 'backend',
      action: { type: 'remove-credential', name: 'api-key' },
    });
  });
});

describe('static backend mutations', () => {
  it('puts renames and removes credentials in memory', async () => {
    const backend = createStaticAppBackend(sampleSnapshot());
    let result = await backend.dispatch({
      type: 'put-credential',
      name: 'token',
      value: 'abc',
    });
    expect(result.snapshot.credentials.map((c) => c.name)).toContain('token');
    expect(result.snapshot.noticeTone).toBe('success');

    result = await backend.dispatch({
      type: 'rename-credential',
      from: 'token',
      to: 'token-renamed',
    });
    expect(result.snapshot.credentials.map((c) => c.name)).toContain('token-renamed');
    expect(result.snapshot.credentials.map((c) => c.name)).not.toContain('token');

    result = await backend.dispatch({
      type: 'remove-credential',
      name: 'token-renamed',
    });
    expect(result.snapshot.credentials.map((c) => c.name)).not.toContain(
      'token-renamed',
    );

    result = await backend.dispatch({ type: 'recovery-status' });
    expect(result.snapshot.recovery.length).toBeGreaterThan(0);
    expect(result.snapshot.notice).toMatch(/Recovery status/i);
  });
});
