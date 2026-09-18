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
  sanitizePasteText,
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
  defaultFileProfilePaths,
  pathSeparator,
  type AppRouterState,
  type AppSnapshot,
} from '../../src/index.js';
import { join, sep } from 'node:path';

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
    // Color may still be false when the process env has NO_COLOR/TERM=dumb.
    const dumb = resolveAppPresentation({
      platform: 'linux',
      term: 'dumb',
      noColor: false,
    });
    expect(dumb.color).toBe(false);
    expect(dumb.ascii).toBe(true);
  });

  it('forces ascii when --ascii is set even on unix UTF terminals', () => {
    const forced = resolveAppPresentation({
      platform: 'linux',
      term: 'xterm-256color',
      ascii: true,
      noColor: false,
    });
    expect(forced.ascii).toBe(true);
  });

  it('disables color when noColor is set (NO_COLOR path)', () => {
    const noColor = resolveAppPresentation({
      platform: 'linux',
      term: 'xterm-256color',
      noColor: true,
      ascii: false,
    });
    expect(noColor.color).toBe(false);
  });

  it('uses node:path separators for default file profile paths', () => {
    expect(pathSeparator()).toBe(sep);
    const home = join('Users', 'demo');
    const paths = defaultFileProfilePaths('demo', home);
    expect(paths.dataFile).toBe(
      join(home, '.local', 'share', 'kavrix', 'demo', 'db.kavrix'),
    );
    expect(paths.keyFile).toBe(
      join(home, '.local', 'share', 'kavrix', 'demo', 'owner.key'),
    );
    // No bashisms: removing path.sep leaves no other directory separators.
    for (const candidate of [paths.dataFile, paths.keyFile]) {
      const withoutSep = candidate.split(sep).join('');
      expect(withoutSep.includes('/')).toBe(false);
      expect(withoutSep.includes('\\')).toBe(false);
    }
  });

  it('snapshots home and credentials in ASCII and NO_COLOR modes', () => {
    const asciiHome = frame(navigateToScreen(hydrate(true, false), 'home'));
    const asciiCreds = frame(navigateToScreen(hydrate(true, false), 'credentials'));
    expect(asciiHome).toContain('HOME / DASHBOARD');
    expect(asciiHome).not.toContain('\u276f');
    expect(asciiCreds).toContain('api-key');
    expect(asciiCreds).toContain('********');
    expect(asciiCreds).not.toContain('\u2022');
    const asciiProfiles = frame(navigateToScreen(hydrate(true, false), 'profiles'));
    expect(asciiProfiles).toContain('[ PROFILES ]');
    expect(asciiProfiles).not.toContain('\u276f');
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

describe('create-file-profile overlays', () => {
  it('dispatches create-file-profile after id/paths/passphrase overlays', () => {
    let state = navigateToScreen(hydrate(), 'profiles');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'n' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-profile-id');
    for (const ch of 'work') {
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
    expect(state.overlay).toBe('input-profile-data-file');
    expect(state.pendingName).toBe('work');
    expect(state.query.length).toBeGreaterThan(0);

    // Accept default data file
    state = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-profile-key-file');
    expect(state.pendingDataFile).toBeTruthy();

    state = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-profile-passphrase');
    expect(state.pendingKeyFile).toBeTruthy();

    for (const ch of 'passphrase-one') {
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
    expect(state.overlay).toBe('input-profile-passphrase-confirm');
    expect(state.pendingPassphrase).toBe('passphrase-one');

    for (const ch of 'passphrase-one') {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: ch },
        nowMs: 0,
      }).state;
    }
    const created = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 1,
    });
    expect(created.effect.kind).toBe('backend');
    if (created.effect.kind !== 'backend') return;
    expect(created.effect.action.type).toBe('create-file-profile');
    if (created.effect.action.type !== 'create-file-profile') return;
    expect(created.effect.action.profileId).toBe('work');
    expect(created.effect.action.passphrase).toBe('passphrase-one');
    expect(created.effect.action.dataFile).toContain('work');
    expect(created.effect.action.keyFile).toContain('work');
    expect(created.state.pendingPassphrase).toBeNull();
  });

  it('rejects mismatched passphrase confirm without dispatching', () => {
    let state = navigateToScreen(hydrate(), 'profiles');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'n' },
      nowMs: 0,
    }).state;
    for (const ch of 'x') {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: ch },
        nowMs: 0,
      }).state;
    }
    // id → data → key → passphrase
    for (let i = 0; i < 3; i += 1) {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { name: 'return' },
        nowMs: 0,
      }).state;
    }
    for (const ch of 'aaa') {
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
    for (const ch of 'bbb') {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: ch },
        nowMs: 0,
      }).state;
    }
    const mismatch = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 1,
    });
    expect(mismatch.effect.kind).toBe('none');
    expect(mismatch.state.overlay).toBe('input-profile-passphrase');
    expect(mismatch.state.message).toMatch(/did not match/i);
  });
});

describe('create-mongodb-profile overlays', () => {
  it('dispatches create-mongodb-profile after id/database/key/url/passphrase overlays', () => {
    let state = navigateToScreen(hydrate(), 'profiles');
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'm' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-mongo-profile-id');
    for (const ch of 'mongo') {
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
    expect(state.overlay).toBe('input-mongo-database');
    expect(state.pendingName).toBe('mongo');

    state = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-mongo-key-file');
    expect(state.pendingMongoDatabase).toBeTruthy();

    state = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-mongo-url');

    for (const ch of 'mongodb://127.0.0.1:27017') {
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
    expect(state.overlay).toBe('input-mongo-passphrase');
    expect(state.pendingMongoUrl).toContain('mongodb://');

    for (const ch of 'passphrase-one') {
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
    expect(state.overlay).toBe('input-mongo-passphrase-confirm');

    for (const ch of 'passphrase-one') {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: ch },
        nowMs: 0,
      }).state;
    }
    const created = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 1,
    });
    expect(created.effect.kind).toBe('backend');
    if (created.effect.kind !== 'backend') return;
    expect(created.effect.action.type).toBe('create-mongodb-profile');
    if (created.effect.action.type !== 'create-mongodb-profile') return;
    expect(created.effect.action.profileId).toBe('mongo');
    expect(created.effect.action.databaseUrl).toContain('mongodb://');
    expect(created.effect.action.passphrase).toBe('passphrase-one');
    expect(created.state.pendingMongoUrl).toBeNull();
    expect(created.state.pendingPassphrase).toBeNull();
  });
});

describe('mongodb unlock overlay', () => {
  it('collects URL before passphrase when datastore is mongodb', () => {
    const base = createInitialAppRouterState({ width: 100, height: 30 });
    let state = transitionAppRouter(base, {
      type: 'hydrate',
      snapshot: {
        ...sampleSnapshot(),
        home: {
          ...sampleSnapshot().home,
          datastore: 'mongodb',
        },
      },
    }).state;
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'u' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-unlock-mongo-url');
    for (const ch of 'mongodb://localhost') {
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
    expect(state.overlay).toBe('input-passphrase');
    expect(state.pendingMongoUrl).toBe('mongodb://localhost');
    for (const ch of 'secret') {
      state = transitionAppRouter(state, {
        type: 'key',
        key: { text: ch },
        nowMs: 0,
      }).state;
    }
    const unlocked = transitionAppRouter(state, {
      type: 'key',
      key: { name: 'return' },
      nowMs: 1,
    });
    expect(unlocked.effect.kind).toBe('backend');
    if (unlocked.effect.kind !== 'backend') return;
    expect(unlocked.effect.action.type).toBe('unlock');
    if (unlocked.effect.action.type !== 'unlock') return;
    expect(unlocked.effect.action.databaseUrl).toBe('mongodb://localhost');
    expect(unlocked.effect.action.passphrase).toBe('secret');
  });
});

describe('static backend create-file-profile', () => {
  it('adds a selected file profile to the snapshot', async () => {
    const backend = createStaticAppBackend(sampleSnapshot());
    const result = await backend.dispatch({
      type: 'create-file-profile',
      profileId: 'fresh',
      dataFile: join('tmp', 'fresh', 'db.kavrix'),
      keyFile: join('tmp', 'fresh', 'owner.key'),
      passphrase: 'secret',
    });
    expect(result.snapshot.noticeTone).toBe('success');
    expect(result.snapshot.home.profileId).toBe('fresh');
    expect(result.snapshot.profiles.some((p) => p.id === 'fresh' && p.selected)).toBe(
      true,
    );
  });
});


describe('paste into overlays', () => {
  it('sanitizes bracketed-paste noise and trailing newlines', () => {
    expect(sanitizePasteText('\x1b[200~secret-value\r\n\x1b[201~')).toBe('secret-value');
    expect(sanitizePasteText('mongo://url\n')).toBe('mongo://url');
  });

  it('appends multi-character paste once without treating it as Enter', () => {
    let state = hydrate();
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'u' },
      nowMs: 0,
    }).state;
    expect(state.overlay).toBe('input-passphrase');
    const pasted = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'long-passphrase-paste\r\n' },
      nowMs: 1,
    });
    expect(pasted.state.overlay).toBe('input-passphrase');
    expect(pasted.state.query).toBe('long-passphrase-paste');
    expect(pasted.effect.kind).toBe('none');
  });

  it('pastes long URLs into unlock mongo URL overlay', () => {
    const base = createInitialAppRouterState({ width: 100, height: 30 });
    let state = transitionAppRouter(base, {
      type: 'hydrate',
      snapshot: {
        ...sampleSnapshot(),
        home: { ...sampleSnapshot().home, datastore: 'mongodb' },
      },
    }).state;
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'u' },
      nowMs: 0,
    }).state;
    const url = 'mongodb://user:pass@127.0.0.1:27017/db?authSource=admin';
    state = transitionAppRouter(state, {
      type: 'key',
      key: { text: `${url}\n` },
      nowMs: 1,
    }).state;
    expect(state.overlay).toBe('input-unlock-mongo-url');
    expect(state.query).toBe(url);
  });
});

describe('copy credential', () => {
  it('dispatches copy-credential without reveal overlay', () => {
    const state = navigateToScreen(hydrate(), 'credentials');
    const copied = transitionAppRouter(state, {
      type: 'key',
      key: { text: 'c' },
      nowMs: 0,
    });
    expect(copied.state.overlay).toBe('none');
    expect(copied.state.revealedValue).toBeNull();
    expect(copied.effect).toEqual({
      kind: 'backend',
      action: { type: 'copy-credential', name: 'api-key' },
    });
  });

  it('static backend reports clipboard clear notice without plaintext', async () => {
    const backend = createStaticAppBackend(sampleSnapshot());
    const result = await backend.dispatch({ type: 'copy-credential', name: 'api-key' });
    expect(result.revealedSecret).toBeUndefined();
    expect(result.snapshot.notice).toMatch(/Copied \(clipboard clears/i);
  });
});

describe('help and credentials UX', () => {
  it('documents copy/paste and getting started on Help', () => {
    const frameText = frame(navigateToScreen(hydrate(), 'help'));
    expect(frameText).toMatch(/Getting started/i);
    expect(frameText).toMatch(/Paste into overlays/i);
    expect(frameText).toMatch(/c copy/i);
    expect(frameText).toMatch(/Mouse tracking is NOT enabled/i);
  });

  it('shows unlock empty-state guidance on credentials', () => {
    const locked = transitionAppRouter(createInitialAppRouterState({ width: 100, height: 30 }), {
      type: 'hydrate',
      snapshot: {
        ...sampleSnapshot(),
        home: { ...sampleSnapshot().home, unlocked: false, credentialCount: 0 },
        credentials: [],
      },
    }).state;
    const frameText = frame(navigateToScreen(locked, 'credentials'));
    expect(frameText).toMatch(/Press u to unlock/i);
  });
});
