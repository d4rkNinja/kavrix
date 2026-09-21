import { APP_MENU, type AppScreenId } from './ids.js';
import type { AppBackendAction, AppSnapshot } from './backend.js';
import { emptySnapshot } from './backend.js';
import { defaultFileProfilePaths, defaultMongoProfilePaths } from './paths.js';

export interface AppKey {
  readonly name?:
    'up' | 'down' | 'left' | 'right' | 'tab' | 'return' | 'escape' | 'backspace';
  readonly text?: string;
  readonly ctrl?: boolean;
}

export type AppOverlay =
  | 'none'
  | 'confirm-reveal'
  | 'confirm-lock'
  | 'confirm-revoke-last'
  | 'confirm-remove'
  | 'confirm-recovery-revoke'
  | 'confirm-policy-remove'
  | 'confirm-grant-revoke'
  | 'confirm-remove-profile'
  | 'confirm-session-revoke'
  | 'input-search'
  | 'input-run'
  | 'input-passphrase'
  | 'input-put-name'
  | 'input-put-value'
  | 'input-rename'
  | 'input-vault-label'
  | 'input-profile-id'
  | 'input-profile-data-file'
  | 'input-profile-key-file'
  | 'input-profile-passphrase'
  | 'input-profile-passphrase-confirm'
  | 'input-mongo-profile-id'
  | 'input-mongo-database'
  | 'input-mongo-key-file'
  | 'input-mongo-url'
  | 'input-mongo-passphrase'
  | 'input-mongo-passphrase-confirm'
  | 'input-unlock-mongo-url'
  | 'input-recovery-file'
  | 'input-recovery-passphrase'
  | 'input-recovery-passphrase-confirm'
  | 'input-recovery-verify-file'
  | 'input-recovery-verify-passphrase'
  | 'input-policy-id'
  | 'input-policy-secret'
  | 'input-policy-command'
  | 'input-grant-secret'
  | 'input-grant-command'
  | 'input-grant-ttl'
  | 'input-agent-name'
  | 'input-agent-config'
  | 'credential-detail';

export interface AppRouterState {
  readonly screen: AppScreenId;
  readonly menuIndex: number;
  readonly listIndex: number;
  readonly overlay: AppOverlay;
  readonly query: string;
  readonly ascii: boolean;
  readonly color: boolean;
  readonly width: number;
  readonly height: number;
  readonly snapshot: AppSnapshot;
  readonly pendingRevealName: string | null;
  /** Shared pending credential name for put/rename/remove overlays. */
  readonly pendingName: string | null;
  /** Pending paths while creating a file profile. */
  readonly pendingDataFile: string | null;
  readonly pendingKeyFile: string | null;
  /** Ephemeral passphrase held only across create-profile confirm; never snapshotted. */
  readonly pendingPassphrase: string | null;
  /** Ephemeral MongoDB URL for create/unlock overlays; never snapshotted. */
  readonly pendingMongoUrl: string | null;
  readonly pendingMongoDatabase: string | null;
  /** Recovery / policy / grant wizard ephemeral fields (never snapshotted). */
  readonly pendingRecoveryFile: string | null;
  readonly pendingRecoveryPassphrase: string | null;
  readonly pendingPolicyId: string | null;
  readonly pendingPolicySecret: string | null;
  readonly pendingGrantSecret: string | null;
  readonly pendingGrantCommand: string | null;
  readonly pendingSlotId: string | null;
  readonly pendingGrantId: string | null;
  /** Ephemeral agent name while collecting dry-run overlays (never snapshotted). */
  readonly pendingAgentName: string | null;
  readonly revealedName: string | null;
  /** Ephemeral plaintext; never copied into AppSnapshot. */
  readonly revealedValue: string | null;
  readonly revealedUntilMs: number;
  readonly message: string | null;
  readonly quit: boolean;
  /** Client-side credential name filter from `/` search. */
  readonly credentialFilter: string;
  /** True after the first successful hydrate so motion can start. */
  readonly sessionReady: boolean;
}

export type AppRouterEffect =
  Readonly<{ kind: 'backend'; action: AppBackendAction }> | Readonly<{ kind: 'none' }>;

export interface AppRouterTransition {
  readonly state: AppRouterState;
  readonly effect: AppRouterEffect;
}

export type AppRouterAction =
  | Readonly<{ type: 'hydrate'; snapshot: AppSnapshot }>
  | Readonly<{
      type: 'backend-result';
      snapshot: AppSnapshot;
      revealedSecret?: string;
      nowMs: number;
    }>
  | Readonly<{ type: 'resize'; width: number; height: number }>
  | Readonly<{ type: 'tick'; nowMs: number }>
  | Readonly<{ type: 'key'; key: AppKey; nowMs: number }>;

/** Clamp missing/zero TTY sizes so Ink/Yoga cannot blank the first frame. */
export function resolveTtySize(
  stdout: Readonly<{ columns?: number; rows?: number }>,
): Readonly<{ width: number; height: number }> {
  const width = stdout.columns;
  const height = stdout.rows;
  return {
    width:
      typeof width === 'number' && Number.isFinite(width) && width > 0 ? width : 80,
    height:
      typeof height === 'number' && Number.isFinite(height) && height > 0 ? height : 24,
  };
}

/**
 * Write fallback columns/rows onto a TTY so Ink/Yoga cannot layout at 0×0
 * (Mid fixtures and hosts that omit size).
 */
export function ensureTtySize(stdout: {
  columns?: number;
  rows?: number;
}): Readonly<{ width: number; height: number }> {
  const size = resolveTtySize(stdout);
  stdout.columns = size.width;
  stdout.rows = size.height;
  return size;
}

export function createInitialAppRouterState(
  options: Readonly<{
    width?: number;
    height?: number;
    ascii?: boolean;
    color?: boolean;
  }> = {},
): AppRouterState {
  return {
    screen: 'home',
    menuIndex: 0,
    listIndex: 0,
    overlay: 'none',
    query: '',
    ascii: options.ascii ?? false,
    color: options.color ?? true,
    width: Math.max(40, options.width ?? 80),
    height: Math.max(12, options.height ?? 24),
    snapshot: emptySnapshot(),
    pendingRevealName: null,
    pendingName: null,
    pendingDataFile: null,
    pendingKeyFile: null,
    pendingPassphrase: null,
    pendingMongoUrl: null,
    pendingMongoDatabase: null,
    pendingRecoveryFile: null,
    pendingRecoveryPassphrase: null,
    pendingPolicyId: null,
    pendingPolicySecret: null,
    pendingGrantSecret: null,
    pendingGrantCommand: null,
    pendingSlotId: null,
    pendingGrantId: null,
    pendingAgentName: null,
    revealedName: null,
    revealedValue: null,
    revealedUntilMs: 0,
    message: null,
    quit: false,
    credentialFilter: '',
    sessionReady: false,
  };
}

export function transitionAppRouter(
  state: AppRouterState,
  action: AppRouterAction,
): AppRouterTransition {
  switch (action.type) {
    case 'hydrate':
      return unchanged({
        ...state,
        snapshot: action.snapshot,
        message: action.snapshot.notice,
        sessionReady: true,
      });
    case 'backend-result': {
      const revealedName =
        action.revealedSecret === undefined
          ? state.revealedName
          : state.pendingRevealName;
      return unchanged({
        ...state,
        snapshot: action.snapshot,
        message: action.snapshot.notice ?? state.message,
        pendingRevealName:
          action.revealedSecret === undefined ? state.pendingRevealName : null,
        revealedName,
        revealedValue: action.revealedSecret ?? state.revealedValue,
        revealedUntilMs:
          action.revealedSecret === undefined
            ? state.revealedUntilMs
            : action.nowMs + 15_000,
        overlay: 'none',
        sessionReady: true,
      });
    }
    case 'resize':
      return unchanged({
        ...state,
        width: Math.max(40, action.width),
        height: Math.max(12, action.height),
      });
    case 'tick':
      if (state.revealedUntilMs > 0 && action.nowMs >= state.revealedUntilMs) {
        return unchanged({
          ...state,
          revealedName: null,
          revealedValue: null,
          revealedUntilMs: 0,
          message: 'Reveal expired; value cleared from the screen.',
        });
      }
      return unchanged(state);
    case 'key':
      return keyTransition(state, action.key, action.nowMs);
  }
}

function keyTransition(
  state: AppRouterState,
  key: AppKey,
  nowMs: number,
): AppRouterTransition {
  if (key.ctrl === true && key.text?.toLowerCase() === 'c') {
    return unchanged({ ...state, quit: true });
  }
  if (key.text?.toLowerCase() === 'q' && state.overlay === 'none') {
    return unchanged({ ...state, quit: true });
  }
  if (key.text?.toLowerCase() === 'a' && state.overlay === 'none') {
    return unchanged({ ...state, ascii: !state.ascii });
  }

  if (state.overlay !== 'none') return overlayKey(state, key, nowMs);

  if (
    key.name === 'escape' &&
    state.revealedName !== null &&
    state.screen === 'credentials'
  ) {
    return unchanged({
      ...state,
      revealedName: null,
      revealedValue: null,
      revealedUntilMs: 0,
      message: 'Reveal cleared; value remasked.',
    });
  }

  if (key.name === 'escape' && state.screen !== 'home') {
    return unchanged({ ...state, screen: 'home', listIndex: 0, message: null });
  }

  if (key.text?.toLowerCase() === 'u') {
    return unlockIntent(state);
  }
  if (key.text?.toLowerCase() === 'l') {
    return unchanged({ ...state, overlay: 'confirm-lock' });
  }

  if (state.screen === 'home') return homeKey(state, key);
  return screenKey(state, key);
}

/**
 * `u` resolves the unlock path: an enabled, unexpired OS session unlocks
 * immediately through the keychain; otherwise the passphrase overlay opens.
 */
function unlockIntent(state: AppRouterState): AppRouterTransition {
  const session = state.snapshot.session;
  if (session.enabled && !session.expired) {
    return effect(state, {
      kind: 'backend',
      action: { type: 'session-unlock' },
    });
  }
  if (session.enabled && session.expired) {
    return unchanged({
      ...state,
      message:
        'Session unlock has expired; unlock with the passphrase, then enable a new session on the Session screen.',
    });
  }
  if (state.snapshot.home.datastore === 'mongodb') {
    return unchanged({
      ...state,
      overlay: 'input-unlock-mongo-url',
      query: '',
      pendingMongoUrl: null,
      message:
        'MongoDB URL (masked). Paste works (Ctrl+Shift+V / Cmd+V). Enter continues; Esc cancels.',
    });
  }
  return unchanged({
    ...state,
    overlay: 'input-passphrase',
    query: '',
    pendingMongoUrl: null,
    message:
      'Unlock vault — enter passphrase (masked). Paste works (Ctrl+Shift+V / Cmd+V). Enter unlocks; Esc cancels.',
  });
}

function homeKey(state: AppRouterState, key: AppKey): AppRouterTransition {
  const entries = APP_MENU.filter((entry) => entry.id !== 'home');
  if (key.name === 'up' || key.text === 'k') {
    return unchanged({
      ...state,
      menuIndex: clamp(state.menuIndex - 1, entries.length),
    });
  }
  if (key.name === 'down' || key.text === 'j') {
    return unchanged({
      ...state,
      menuIndex: clamp(state.menuIndex + 1, entries.length),
    });
  }
  if (key.name === 'return' || key.name === 'right') {
    const target = entries[state.menuIndex];
    if (target === undefined) return unchanged(state);
    return enterScreen(state, target.id);
  }
  if (key.text === '?') return enterScreen(state, 'help');
  if (key.text?.toLowerCase() === 'r') {
    return effect(state, { kind: 'backend', action: { type: 'refresh' } });
  }
  return unchanged(state);
}

function screenKey(state: AppRouterState, key: AppKey): AppRouterTransition {
  const length = listLength(state);
  if (key.name === 'up' || key.text === 'k') {
    return unchanged({ ...state, listIndex: clamp(state.listIndex - 1, length) });
  }
  if (key.name === 'down' || key.text === 'j') {
    return unchanged({ ...state, listIndex: clamp(state.listIndex + 1, length) });
  }
  if (key.text === '/') {
    return unchanged({ ...state, overlay: 'input-search', query: '' });
  }
  if (key.text?.toLowerCase() === 'r' && state.screen === 'credentials') {
    const name = filteredCredentials(state)[state.listIndex]?.name;
    if (name === undefined) return unchanged(state);
    return unchanged({
      ...state,
      overlay: 'confirm-reveal',
      pendingRevealName: name,
      message: `REVEAL confirmation required for '${name}'.`,
    });
  }
  if (key.text?.toLowerCase() === 'c' && state.screen === 'credentials') {
    const name = filteredCredentials(state)[state.listIndex]?.name;
    if (name === undefined) {
      return unchanged({
        ...state,
        message: 'Select a credential to copy (c), or unlock / n put.',
      });
    }
    // Flat credentials have no per-field copy policy; copy without on-screen reveal.
    return effect(state, {
      kind: 'backend',
      action: { type: 'copy-credential', name },
    });
  }
  if (key.text?.toLowerCase() === 'n' && state.screen === 'profiles') {
    return unchanged({
      ...state,
      overlay: 'input-profile-id',
      query: '',
      pendingName: null,
      pendingDataFile: null,
      pendingKeyFile: null,
      pendingPassphrase: null,
      pendingMongoUrl: null,
      pendingMongoDatabase: null,
      message: 'New file profile id. Enter continues; Esc cancels.',
    });
  }
  if (key.text?.toLowerCase() === 'm' && state.screen === 'profiles') {
    return unchanged({
      ...state,
      overlay: 'input-mongo-profile-id',
      query: '',
      pendingName: null,
      pendingDataFile: null,
      pendingKeyFile: null,
      pendingPassphrase: null,
      pendingMongoUrl: null,
      pendingMongoDatabase: null,
      message: 'New mongodb profile id. Enter continues; Esc cancels.',
    });
  }
  if (key.text?.toLowerCase() === 'x' && state.screen === 'profiles') {
    const profile = state.snapshot.profiles[state.listIndex];
    if (profile === undefined) {
      return unchanged({
        ...state,
        message: 'Select a profile to remove (n file, m mongodb, Enter use).',
      });
    }
    return unchanged({
      ...state,
      overlay: 'confirm-remove-profile',
      pendingName: profile.id,
      message: `Remove profile '${profile.id}'? Its key/data files are kept; y/n`,
    });
  }
  if (key.text?.toLowerCase() === 'n' && state.screen === 'vaults') {
    if (!state.snapshot.home.unlocked) {
      return unchanged({
        ...state,
        message: 'Unlock first (u), then n creates a new vault in this database.',
      });
    }
    return unchanged({
      ...state,
      overlay: 'input-vault-label',
      query: '',
      message: 'New vault label. Enter creates and selects it; Esc cancels.',
    });
  }
  if (key.text?.toLowerCase() === 'n' && state.screen === 'credentials') {
    return unchanged({
      ...state,
      overlay: 'input-put-name',
      query: '',
      pendingName: null,
      message: 'New credential name. Enter continues; Esc cancels.',
    });
  }
  if (key.text?.toLowerCase() === 'm' && state.screen === 'credentials') {
    const name = filteredCredentials(state)[state.listIndex]?.name;
    if (name === undefined) return unchanged(state);
    return unchanged({
      ...state,
      overlay: 'input-rename',
      query: '',
      pendingName: name,
      message: `Rename '${name}' to:`,
    });
  }
  if (key.text?.toLowerCase() === 'x' && state.screen === 'credentials') {
    const name = filteredCredentials(state)[state.listIndex]?.name;
    if (name === undefined) return unchanged(state);
    return unchanged({
      ...state,
      overlay: 'confirm-remove',
      pendingName: name,
      message: `Remove credential '${name}'? y/n`,
    });
  }
  if (key.text?.toLowerCase() === 'u') {
    if (state.snapshot.home.datastore === 'mongodb') {
      return unchanged({
        ...state,
        overlay: 'input-unlock-mongo-url',
        query: '',
        pendingMongoUrl: null,
        message:
          'MongoDB URL (masked). Paste works (Ctrl+Shift+V / Cmd+V). Enter continues; Esc cancels.',
      });
    }
    return unchanged({
      ...state,
      overlay: 'input-passphrase',
      query: '',
      pendingMongoUrl: null,
      message:
        'Unlock vault — enter passphrase (masked). Paste works (Ctrl+Shift+V / Cmd+V). Enter unlocks; Esc cancels.',
    });
  }
  if (key.text?.toLowerCase() === 'l') {
    return unchanged({ ...state, overlay: 'confirm-lock' });
  }
  if (key.name === 'return') return activateSelection(state);
  if (key.text?.toLowerCase() === 'd' && state.screen === 'doctor') {
    return effect(state, { kind: 'backend', action: { type: 'run-doctor' } });
  }
  if (key.text?.toLowerCase() === 'p' && state.screen === 'run') {
    return unchanged({ ...state, overlay: 'input-run', query: '' });
  }
  if (key.text?.toLowerCase() === 'g' && state.screen === 'agent') {
    return unchanged({
      ...state,
      overlay: 'input-agent-name',
      query: '',
      pendingAgentName: null,
      message:
        'Agent name from project config (required). Then optional --config path. Esc cancels.',
    });
  }
  if (state.screen === 'recovery') {
    if (key.text?.toLowerCase() === 'n' || key.text?.toLowerCase() === 'c') {
      return unchanged({
        ...state,
        overlay: 'input-recovery-file',
        query: '',
        pendingRecoveryFile: null,
        pendingRecoveryPassphrase: null,
        message: 'Recovery kit file path:',
      });
    }
    if (key.text?.toLowerCase() === 'v') {
      return unchanged({
        ...state,
        overlay: 'input-recovery-verify-file',
        query: '',
        pendingRecoveryFile: null,
        pendingRecoveryPassphrase: null,
        message: 'Recovery kit file to verify:',
      });
    }
    if (key.text?.toLowerCase() === 'x') {
      const slot = state.snapshot.recovery[state.listIndex];
      if (slot === undefined || slot.slotId.startsWith('(')) return unchanged(state);
      const active = state.snapshot.recovery.filter(
        (entry) => entry.status === 'active',
      );
      if (active.length <= 1 && slot.status === 'active') {
        return unchanged({
          ...state,
          overlay: 'confirm-revoke-last',
          pendingSlotId: slot.slotId,
          message: 'Cannot revoke the final recovery slot without an explicit warning.',
        });
      }
      return unchanged({
        ...state,
        overlay: 'confirm-recovery-revoke',
        pendingSlotId: slot.slotId,
        message: `Revoke recovery slot '${slot.slotId}'? y/n`,
      });
    }
  }
  if (state.screen === 'session') {
    if (key.text?.toLowerCase() === 'n') {
      if (!state.snapshot.home.unlocked) {
        return unchanged({
          ...state,
          message:
            'Unlock with the passphrase first (u); enabling stores that unlock behind the OS credential store.',
        });
      }
      return effect(state, {
        kind: 'backend',
        action: { type: 'session-enable' },
      });
    }
    if (key.text?.toLowerCase() === 'x') {
      if (!state.snapshot.session.enabled) {
        return unchanged({
          ...state,
          message: 'No session unlock to remove; n enables one after unlock.',
        });
      }
      return unchanged({
        ...state,
        overlay: 'confirm-session-revoke',
        message: 'Remove session unlock? The passphrase will be required again. y/n',
      });
    }
  }
  if (state.screen === 'policy') {
    if (key.text?.toLowerCase() === 'n') {
      return unchanged({
        ...state,
        overlay: 'input-policy-id',
        query: '',
        pendingPolicyId: null,
        pendingPolicySecret: null,
        message: 'New policy id:',
      });
    }
    if (key.text?.toLowerCase() === 'x') {
      const row = state.snapshot.policies[state.listIndex];
      if (row?.kind !== 'policy') {
        return unchanged({
          ...state,
          message: 'Select a policy row to remove (n create, g grant, r revoke grant).',
        });
      }
      return unchanged({
        ...state,
        overlay: 'confirm-policy-remove',
        pendingPolicyId: row.id,
        message: `Remove policy '${row.id}'? y/n`,
      });
    }
    if (key.text?.toLowerCase() === 'g') {
      return unchanged({
        ...state,
        overlay: 'input-grant-secret',
        query: '',
        pendingGrantSecret: null,
        pendingGrantCommand: null,
        message: 'Grant secret name:',
      });
    }
    if (key.text?.toLowerCase() === 'r') {
      const row = state.snapshot.policies[state.listIndex];
      if (row?.kind !== 'grant') {
        return unchanged({
          ...state,
          message: 'Select a grant row to revoke.',
        });
      }
      return unchanged({
        ...state,
        overlay: 'confirm-grant-revoke',
        pendingGrantId: row.id,
        message: `Revoke grant '${row.id}'? y/n`,
      });
    }
  }
  return unchanged(state);
}

function overlayKey(
  state: AppRouterState,
  key: AppKey,
  nowMs: number,
): AppRouterTransition {
  if (state.overlay === 'credential-detail') {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        message: 'Closed credential detail.',
      });
    }
    if (key.text?.toLowerCase() === 'r') {
      const name =
        state.pendingName ?? filteredCredentials(state)[state.listIndex]?.name;
      if (name === undefined) return unchanged(state);
      return unchanged({
        ...state,
        overlay: 'confirm-reveal',
        pendingRevealName: name,
        message: `REVEAL confirmation required for '${name}'.`,
      });
    }
    if (key.text?.toLowerCase() === 'c') {
      const name =
        state.pendingName ?? filteredCredentials(state)[state.listIndex]?.name;
      if (name === undefined) return unchanged(state);
      return effect(
        { ...state, overlay: 'none' },
        { kind: 'backend', action: { type: 'copy-credential', name } },
      );
    }
    return unchanged(state);
  }
  if (state.overlay === 'confirm-reveal') {
    if (key.text?.toLowerCase() === 'y') {
      const name = state.pendingRevealName;
      if (name === null) return unchanged({ ...state, overlay: 'none' });
      return effect(
        { ...state, overlay: 'none' },
        { kind: 'backend', action: { type: 'reveal-credential', name } },
      );
    }
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        pendingRevealName: null,
        message: 'Reveal cancelled.',
      });
    }
    return unchanged(state);
  }
  if (state.overlay === 'confirm-lock') {
    if (key.text?.toLowerCase() === 'y') {
      return effect(
        {
          ...state,
          overlay: 'none',
          revealedName: null,
          revealedValue: null,
          revealedUntilMs: 0,
        },
        { kind: 'backend', action: { type: 'lock' } },
      );
    }
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({ ...state, overlay: 'none' });
    }
    return unchanged(state);
  }
  if (state.overlay === 'input-unlock-mongo-url') {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        pendingMongoUrl: null,
        message: 'Unlock cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      const url = state.query.trim();
      if (url.length === 0) {
        return unchanged({ ...state, message: 'MongoDB URL cannot be empty.' });
      }
      return unchanged({
        ...state,
        overlay: 'input-passphrase',
        pendingMongoUrl: url,
        query: '',
        message:
          'Unlock vault — enter passphrase (masked). Paste works (Ctrl+Shift+V / Cmd+V). Enter unlocks; Esc cancels.',
      });
    }
    return appendOverlayText(state, key.text, 2048);
  }
  if (state.overlay === 'input-passphrase') {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        pendingMongoUrl: null,
        message: 'Unlock cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      const passphrase = state.query;
      const databaseUrl = state.pendingMongoUrl ?? undefined;
      return effect(
        { ...state, overlay: 'none', query: '', pendingMongoUrl: null },
        {
          kind: 'backend',
          action: {
            type: 'unlock',
            passphrase,
            ...(databaseUrl === undefined ? {} : { databaseUrl }),
          },
        },
      );
    }
    return appendOverlayText(state, key.text, 1024);
  }
  if (state.overlay === 'confirm-remove') {
    if (key.text?.toLowerCase() === 'y') {
      const name = state.pendingName;
      if (name === null) return unchanged({ ...state, overlay: 'none' });
      return effect(
        { ...state, overlay: 'none', pendingName: null },
        { kind: 'backend', action: { type: 'remove-credential', name } },
      );
    }
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        pendingName: null,
        message: 'Remove cancelled.',
      });
    }
    return unchanged(state);
  }
  if (state.overlay === 'confirm-session-revoke') {
    if (key.text?.toLowerCase() === 'y') {
      return effect(
        { ...state, overlay: 'none' },
        { kind: 'backend', action: { type: 'session-revoke' } },
      );
    }
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        message: 'Session removal cancelled.',
      });
    }
    return unchanged(state);
  }
  if (state.overlay === 'confirm-remove-profile') {
    if (key.text?.toLowerCase() === 'y') {
      const profileId = state.pendingName;
      if (profileId === null) return unchanged({ ...state, overlay: 'none' });
      return effect(
        { ...state, overlay: 'none', pendingName: null },
        { kind: 'backend', action: { type: 'remove-profile', profileId } },
      );
    }
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        pendingName: null,
        message: 'Profile removal cancelled.',
      });
    }
    return unchanged(state);
  }
  if (state.overlay === 'input-vault-label') {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        message: 'Vault create cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      const label = state.query.trim();
      if (label.length === 0) {
        return unchanged({ ...state, message: 'Vault label cannot be empty.' });
      }
      if (label.length > 64 || hasControlCharacter(label)) {
        return unchanged({ ...state, message: 'Vault label is invalid.' });
      }
      return effect(
        { ...state, overlay: 'none', query: '' },
        { kind: 'backend', action: { type: 'create-vault', label } },
      );
    }
    return appendOverlayText(state, key.text, 128);
  }
  if (
    state.overlay === 'input-put-name' ||
    state.overlay === 'input-put-value' ||
    state.overlay === 'input-rename'
  ) {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        pendingName: null,
        message: 'Credential edit cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      if (state.overlay === 'input-put-name') {
        const name = state.query.trim();
        if (name.length === 0) {
          return unchanged({
            ...state,
            message: 'Credential name cannot be empty.',
          });
        }
        return unchanged({
          ...state,
          overlay: 'input-put-value',
          pendingName: name,
          query: '',
          message: `Value for '${name}' (masked). Enter saves; Esc cancels.`,
        });
      }
      if (state.overlay === 'input-put-value') {
        const name = state.pendingName;
        const value = state.query;
        if (name === null || value.length === 0) {
          return unchanged({
            ...state,
            message: 'Credential value cannot be empty.',
          });
        }
        return effect(
          { ...state, overlay: 'none', query: '', pendingName: null },
          { kind: 'backend', action: { type: 'put-credential', name, value } },
        );
      }
      const from = state.pendingName;
      const to = state.query.trim();
      if (from === null || to.length === 0) {
        return unchanged({
          ...state,
          message: 'New credential name cannot be empty.',
        });
      }
      return effect(
        { ...state, overlay: 'none', query: '', pendingName: null },
        { kind: 'backend', action: { type: 'rename-credential', from, to } },
      );
    }
    const putLimit = state.overlay === 'input-put-value' ? 4096 : 256;
    return appendOverlayText(state, key.text, putLimit);
  }
  if (
    state.overlay === 'input-profile-id' ||
    state.overlay === 'input-profile-data-file' ||
    state.overlay === 'input-profile-key-file' ||
    state.overlay === 'input-profile-passphrase' ||
    state.overlay === 'input-profile-passphrase-confirm'
  ) {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        pendingName: null,
        pendingDataFile: null,
        pendingKeyFile: null,
        pendingPassphrase: null,
        message: 'Create file profile cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      if (state.overlay === 'input-profile-id') {
        const profileId = state.query.trim();
        if (profileId.length === 0) {
          return unchanged({
            ...state,
            message: 'Profile id cannot be empty.',
          });
        }
        const defaults = defaultFileProfilePaths(profileId);
        return unchanged({
          ...state,
          overlay: 'input-profile-data-file',
          pendingName: profileId,
          query: defaults.dataFile,
          message: `Data file for '${profileId}' (Enter accepts default).`,
        });
      }
      if (state.overlay === 'input-profile-data-file') {
        const profileId = state.pendingName;
        if (profileId === null) {
          return unchanged({ ...state, overlay: 'none', query: '' });
        }
        const dataFile =
          state.query.trim() || defaultFileProfilePaths(profileId).dataFile;
        return unchanged({
          ...state,
          overlay: 'input-profile-key-file',
          pendingDataFile: dataFile,
          query: defaultFileProfilePaths(profileId).keyFile,
          message: `Key file for '${profileId}' (Enter accepts default).`,
        });
      }
      if (state.overlay === 'input-profile-key-file') {
        const profileId = state.pendingName;
        if (profileId === null || state.pendingDataFile === null) {
          return unchanged({ ...state, overlay: 'none', query: '' });
        }
        const keyFile =
          state.query.trim() || defaultFileProfilePaths(profileId).keyFile;
        return unchanged({
          ...state,
          overlay: 'input-profile-passphrase',
          pendingKeyFile: keyFile,
          query: '',
          message: 'Owner passphrase (masked). Enter continues; Esc cancels.',
        });
      }
      if (state.overlay === 'input-profile-passphrase') {
        if (state.query.length === 0) {
          return unchanged({
            ...state,
            message: 'Passphrase cannot be empty.',
          });
        }
        return unchanged({
          ...state,
          overlay: 'input-profile-passphrase-confirm',
          pendingPassphrase: state.query,
          query: '',
          message: 'Confirm passphrase (masked). Enter creates the profile.',
        });
      }
      const profileId = state.pendingName;
      const dataFile = state.pendingDataFile;
      const keyFile = state.pendingKeyFile;
      const passphrase = state.pendingPassphrase;
      const confirm = state.query;
      if (
        profileId === null ||
        dataFile === null ||
        keyFile === null ||
        passphrase === null
      ) {
        return unchanged({
          ...state,
          overlay: 'none',
          query: '',
          pendingName: null,
          pendingDataFile: null,
          pendingKeyFile: null,
          pendingPassphrase: null,
          message: 'Create file profile cancelled.',
        });
      }
      if (confirm !== passphrase) {
        return unchanged({
          ...state,
          overlay: 'input-profile-passphrase',
          pendingPassphrase: null,
          query: '',
          message: 'Passphrases did not match. Re-enter passphrase.',
        });
      }
      return effect(
        {
          ...state,
          overlay: 'none',
          query: '',
          pendingName: null,
          pendingDataFile: null,
          pendingKeyFile: null,
          pendingPassphrase: null,
          message: `Creating file profile '${profileId}'…`,
        },
        {
          kind: 'backend',
          action: {
            type: 'create-file-profile',
            profileId,
            dataFile,
            keyFile,
            passphrase,
          },
        },
      );
    }
    const profileLimit =
      state.overlay === 'input-profile-passphrase' ||
      state.overlay === 'input-profile-passphrase-confirm'
        ? 1024
        : 512;
    return appendOverlayText(state, key.text, profileLimit);
  }

  if (
    state.overlay === 'input-mongo-profile-id' ||
    state.overlay === 'input-mongo-database' ||
    state.overlay === 'input-mongo-key-file' ||
    state.overlay === 'input-mongo-url' ||
    state.overlay === 'input-mongo-passphrase' ||
    state.overlay === 'input-mongo-passphrase-confirm'
  ) {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        pendingName: null,
        pendingKeyFile: null,
        pendingPassphrase: null,
        pendingMongoUrl: null,
        pendingMongoDatabase: null,
        message: 'Create mongodb profile cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      if (state.overlay === 'input-mongo-profile-id') {
        const profileId = state.query.trim();
        if (profileId.length === 0) {
          return unchanged({ ...state, message: 'Profile id cannot be empty.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-mongo-database',
          pendingName: profileId,
          query: profileId.replace(/[^a-zA-Z0-9_-]/gu, '').slice(0, 48) || 'kavrix',
          message: 'MongoDB database routing name. Enter continues.',
        });
      }
      if (state.overlay === 'input-mongo-database') {
        const database = state.query.trim();
        if (database.length === 0) {
          return unchanged({ ...state, message: 'Database name cannot be empty.' });
        }
        const profileId = state.pendingName;
        if (profileId === null) {
          return unchanged({ ...state, overlay: 'none', query: '' });
        }
        const defaults = defaultMongoProfilePaths(profileId);
        return unchanged({
          ...state,
          overlay: 'input-mongo-key-file',
          pendingMongoDatabase: database,
          query: defaults.keyFile,
          message: 'Owner key file path. Enter accepts default.',
        });
      }
      if (state.overlay === 'input-mongo-key-file') {
        const keyFile = state.query.trim();
        if (keyFile.length === 0 || state.pendingName === null) {
          return unchanged({ ...state, overlay: 'none', query: '' });
        }
        return unchanged({
          ...state,
          overlay: 'input-mongo-url',
          pendingKeyFile: keyFile,
          query: '',
          message: 'MongoDB URL (masked, stdin frames only). Enter continues.',
        });
      }
      if (state.overlay === 'input-mongo-url') {
        const url = state.query.trim();
        if (url.length === 0) {
          return unchanged({ ...state, message: 'MongoDB URL cannot be empty.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-mongo-passphrase',
          pendingMongoUrl: url,
          query: '',
          message: 'Passphrase (masked). Enter continues.',
        });
      }
      if (state.overlay === 'input-mongo-passphrase') {
        if (state.query.length === 0) {
          return unchanged({ ...state, message: 'Passphrase cannot be empty.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-mongo-passphrase-confirm',
          pendingPassphrase: state.query,
          query: '',
          message: 'Confirm passphrase (masked). Enter creates the profile.',
        });
      }
      const profileId = state.pendingName;
      const database = state.pendingMongoDatabase;
      const keyFile = state.pendingKeyFile;
      const databaseUrl = state.pendingMongoUrl;
      const passphrase = state.pendingPassphrase;
      const confirm = state.query;
      if (
        profileId === null ||
        database === null ||
        keyFile === null ||
        databaseUrl === null ||
        passphrase === null
      ) {
        return unchanged({
          ...state,
          overlay: 'none',
          query: '',
          pendingName: null,
          pendingKeyFile: null,
          pendingPassphrase: null,
          pendingMongoUrl: null,
          pendingMongoDatabase: null,
          message: 'Create mongodb profile cancelled.',
        });
      }
      if (confirm !== passphrase) {
        return unchanged({
          ...state,
          overlay: 'input-mongo-passphrase',
          pendingPassphrase: null,
          query: '',
          message: 'Passphrases did not match. Re-enter passphrase.',
        });
      }
      return effect(
        {
          ...state,
          overlay: 'none',
          query: '',
          pendingName: null,
          pendingKeyFile: null,
          pendingPassphrase: null,
          pendingMongoUrl: null,
          pendingMongoDatabase: null,
          message: `Creating mongodb profile '${profileId}'…`,
        },
        {
          kind: 'backend',
          action: {
            type: 'create-mongodb-profile',
            profileId,
            database,
            keyFile,
            databaseUrl,
            passphrase,
          },
        },
      );
    }
    const mongoLimit =
      state.overlay === 'input-mongo-url' ||
      state.overlay === 'input-mongo-passphrase' ||
      state.overlay === 'input-mongo-passphrase-confirm'
        ? 2048
        : 512;
    return appendOverlayText(state, key.text, mongoLimit);
  }
  if (state.overlay === 'input-agent-name' || state.overlay === 'input-agent-config') {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        pendingAgentName: null,
        message: 'Agent dry-run cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      if (state.overlay === 'input-agent-name') {
        const agentName = state.query.trim();
        if (agentName.length === 0) {
          return unchanged({
            ...state,
            message: 'Agent name required (kavrix agent run --agent <name>).',
          });
        }
        return unchanged({
          ...state,
          overlay: 'input-agent-config',
          pendingAgentName: agentName,
          query: '',
          message:
            'Optional project config path (--config). Enter empty to use default discovery.',
        });
      }
      const agentName = state.pendingAgentName;
      if (agentName === null || agentName.trim().length === 0) {
        return unchanged({
          ...state,
          overlay: 'none',
          query: '',
          pendingAgentName: null,
          message: 'Agent dry-run cancelled: missing agent name.',
        });
      }
      const configPath = state.query.trim();
      return effect(
        {
          ...state,
          overlay: 'none',
          query: '',
          pendingAgentName: null,
        },
        {
          kind: 'backend',
          action: {
            type: 'agent-dry-run',
            agentName,
            ...(configPath.length > 0 ? { configPath } : {}),
          },
        },
      );
    }
    return appendOverlayText(state, key.text, 512);
  }

  if (state.overlay === 'input-search' || state.overlay === 'input-run') {
    if (key.name === 'escape') {
      return unchanged({ ...state, overlay: 'none', query: '' });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      if (state.overlay === 'input-search') {
        return unchanged({
          ...state,
          overlay: 'none',
          credentialFilter: state.query.trim(),
          listIndex: 0,
          query: '',
          message:
            state.query.trim().length === 0
              ? 'Credential search cleared.'
              : `Credential search: ${state.query.trim()}`,
        });
      }
      const names = state.query
        .split(/[,\s]+/u)
        .map((part) => part.trim())
        .filter((part) => part.length > 0);
      return effect(
        { ...state, overlay: 'none' },
        { kind: 'backend', action: { type: 'preview-run', credentialNames: names } },
      );
    }
    return appendOverlayText(state, key.text, 256);
  }

  if (state.overlay === 'confirm-revoke-last') {
    if (key.name === 'escape' || key.text?.toLowerCase() === 'n') {
      return unchanged({
        ...state,
        overlay: 'none',
        pendingSlotId: null,
        message: 'Final-slot revoke cancelled.',
      });
    }
    return unchanged(state);
  }
  if (state.overlay === 'confirm-recovery-revoke') {
    if (key.text?.toLowerCase() === 'y') {
      const slotId = state.pendingSlotId;
      if (slotId === null) return unchanged({ ...state, overlay: 'none' });
      return effect(
        { ...state, overlay: 'none', pendingSlotId: null },
        { kind: 'backend', action: { type: 'recovery-revoke', slotId } },
      );
    }
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        pendingSlotId: null,
        message: 'Recovery revoke cancelled.',
      });
    }
    return unchanged(state);
  }
  if (state.overlay === 'confirm-policy-remove') {
    if (key.text?.toLowerCase() === 'y') {
      const id = state.pendingPolicyId;
      if (id === null) return unchanged({ ...state, overlay: 'none' });
      return effect(
        { ...state, overlay: 'none', pendingPolicyId: null },
        { kind: 'backend', action: { type: 'policy-remove', id } },
      );
    }
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        pendingPolicyId: null,
        message: 'Policy remove cancelled.',
      });
    }
    return unchanged(state);
  }
  if (state.overlay === 'confirm-grant-revoke') {
    if (key.text?.toLowerCase() === 'y') {
      const grantId = state.pendingGrantId;
      if (grantId === null) return unchanged({ ...state, overlay: 'none' });
      return effect(
        { ...state, overlay: 'none', pendingGrantId: null },
        { kind: 'backend', action: { type: 'grant-revoke', grantId } },
      );
    }
    if (key.text?.toLowerCase() === 'n' || key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        pendingGrantId: null,
        message: 'Grant revoke cancelled.',
      });
    }
    return unchanged(state);
  }
  if (
    state.overlay === 'input-recovery-file' ||
    state.overlay === 'input-recovery-passphrase' ||
    state.overlay === 'input-recovery-passphrase-confirm' ||
    state.overlay === 'input-recovery-verify-file' ||
    state.overlay === 'input-recovery-verify-passphrase'
  ) {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        pendingRecoveryFile: null,
        pendingRecoveryPassphrase: null,
        message: 'Recovery flow cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      if (state.overlay === 'input-recovery-file') {
        const recoveryFile = state.query.trim();
        if (recoveryFile.length === 0) {
          return unchanged({ ...state, message: 'Recovery file path required.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-recovery-passphrase',
          pendingRecoveryFile: recoveryFile,
          query: '',
          message: 'Recovery passphrase (masked):',
        });
      }
      if (state.overlay === 'input-recovery-passphrase') {
        if (state.query.length === 0) {
          return unchanged({ ...state, message: 'Recovery passphrase required.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-recovery-passphrase-confirm',
          pendingRecoveryPassphrase: state.query,
          query: '',
          message: 'Confirm recovery passphrase:',
        });
      }
      if (state.overlay === 'input-recovery-passphrase-confirm') {
        const recoveryFile = state.pendingRecoveryFile;
        const recoveryPassphrase = state.pendingRecoveryPassphrase;
        if (recoveryFile === null || recoveryPassphrase === null) {
          return unchanged({ ...state, overlay: 'none', query: '' });
        }
        if (state.query !== recoveryPassphrase) {
          return unchanged({
            ...state,
            overlay: 'input-recovery-passphrase',
            pendingRecoveryPassphrase: null,
            query: '',
            message: 'Passphrases did not match. Re-enter recovery passphrase:',
          });
        }
        return effect(
          {
            ...state,
            overlay: 'none',
            query: '',
            pendingRecoveryFile: null,
            pendingRecoveryPassphrase: null,
          },
          {
            kind: 'backend',
            action: {
              type: 'recovery-create',
              recoveryFile,
              recoveryPassphrase,
            },
          },
        );
      }
      if (state.overlay === 'input-recovery-verify-file') {
        const recoveryFile = state.query.trim();
        if (recoveryFile.length === 0) {
          return unchanged({ ...state, message: 'Recovery file path required.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-recovery-verify-passphrase',
          pendingRecoveryFile: recoveryFile,
          query: '',
          message: 'Recovery passphrase (masked):',
        });
      }
      const recoveryFile = state.pendingRecoveryFile;
      if (recoveryFile === null || state.query.length === 0) {
        return unchanged({ ...state, overlay: 'none', query: '' });
      }
      return effect(
        {
          ...state,
          overlay: 'none',
          query: '',
          pendingRecoveryFile: null,
          pendingRecoveryPassphrase: null,
        },
        {
          kind: 'backend',
          action: {
            type: 'recovery-verify',
            recoveryFile,
            recoveryPassphrase: state.query,
          },
        },
      );
    }
    const recoveryLimit =
      state.overlay === 'input-recovery-passphrase' ||
      state.overlay === 'input-recovery-passphrase-confirm' ||
      state.overlay === 'input-recovery-verify-passphrase'
        ? 1024
        : 512;
    return appendOverlayText(state, key.text, recoveryLimit);
  }
  if (
    state.overlay === 'input-policy-id' ||
    state.overlay === 'input-policy-secret' ||
    state.overlay === 'input-policy-command'
  ) {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        pendingPolicyId: null,
        pendingPolicySecret: null,
        message: 'Policy create cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      if (state.overlay === 'input-policy-id') {
        const id = state.query.trim();
        if (id.length === 0) {
          return unchanged({ ...state, message: 'Policy id required.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-policy-secret',
          pendingPolicyId: id,
          query: '',
          message: `Secret name for policy '${id}':`,
        });
      }
      if (state.overlay === 'input-policy-secret') {
        const secret = state.query.trim();
        if (secret.length === 0) {
          return unchanged({ ...state, message: 'Secret name required.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-policy-command',
          pendingPolicySecret: secret,
          query: '',
          message: 'Allowed command (executable name):',
        });
      }
      const id = state.pendingPolicyId;
      const secret = state.pendingPolicySecret;
      const command = state.query.trim();
      if (id === null || secret === null || command.length === 0) {
        return unchanged({ ...state, overlay: 'none', query: '' });
      }
      return effect(
        {
          ...state,
          overlay: 'none',
          query: '',
          pendingPolicyId: null,
          pendingPolicySecret: null,
        },
        {
          kind: 'backend',
          action: { type: 'policy-create', id, secret, command },
        },
      );
    }
    return appendOverlayText(state, key.text, 256);
  }
  if (
    state.overlay === 'input-grant-secret' ||
    state.overlay === 'input-grant-command' ||
    state.overlay === 'input-grant-ttl'
  ) {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        pendingGrantSecret: null,
        pendingGrantCommand: null,
        message: 'Grant create cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      if (state.overlay === 'input-grant-secret') {
        const secret = state.query.trim();
        if (secret.length === 0) {
          return unchanged({ ...state, message: 'Secret name required.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-grant-command',
          pendingGrantSecret: secret,
          query: '',
          message: 'Allowed command for grant:',
        });
      }
      if (state.overlay === 'input-grant-command') {
        const command = state.query.trim();
        if (command.length === 0) {
          return unchanged({ ...state, message: 'Command required.' });
        }
        return unchanged({
          ...state,
          overlay: 'input-grant-ttl',
          pendingGrantCommand: command,
          query: '15m',
          message: 'Grant TTL (e.g. 15m):',
        });
      }
      const secret = state.pendingGrantSecret;
      const command = state.pendingGrantCommand;
      const ttl = state.query.trim() || '15m';
      if (secret === null || command === null) {
        return unchanged({ ...state, overlay: 'none', query: '' });
      }
      return effect(
        {
          ...state,
          overlay: 'none',
          query: '',
          pendingGrantSecret: null,
          pendingGrantCommand: null,
        },
        {
          kind: 'backend',
          action: { type: 'grant-create', secret, command, ttl },
        },
      );
    }
    return appendOverlayText(state, key.text, 256);
  }

  void nowMs;
  return unchanged(state);
}

function activateSelection(state: AppRouterState): AppRouterTransition {
  switch (state.screen) {
    case 'credentials': {
      const credential = filteredCredentials(state)[state.listIndex];
      if (credential === undefined) return unchanged(state);
      return unchanged({
        ...state,
        overlay: 'credential-detail',
        pendingName: credential.name,
        message: `Credential detail (masked): ${credential.name}. r REVEAL · c copy · Esc close.`,
      });
    }
    case 'profiles': {
      const profile = state.snapshot.profiles[state.listIndex];
      if (profile === undefined) return unchanged(state);
      return effect(state, {
        kind: 'backend',
        action: { type: 'use-profile', profileId: profile.id },
      });
    }
    case 'vaults': {
      const vault = state.snapshot.vaults[state.listIndex];
      if (vault === undefined) return unchanged(state);
      return effect(state, {
        kind: 'backend',
        action: { type: 'use-vault', vaultId: vault.id },
      });
    }
    case 'recovery': {
      const slot = state.snapshot.recovery[state.listIndex];
      if (slot === undefined || slot.slotId.startsWith('(')) {
        return effect(state, { kind: 'backend', action: { type: 'recovery-status' } });
      }
      const active = state.snapshot.recovery.filter(
        (entry) => entry.status === 'active',
      );
      if (active.length <= 1 && slot.status === 'active') {
        return unchanged({
          ...state,
          overlay: 'confirm-revoke-last',
          pendingSlotId: slot.slotId,
          message: 'Cannot revoke the final recovery slot without an explicit warning.',
        });
      }
      return unchanged({
        ...state,
        overlay: 'confirm-recovery-revoke',
        pendingSlotId: slot.slotId,
        message: `Revoke recovery slot '${slot.slotId}'? y/n`,
      });
    }
    case 'session':
      return effect(state, { kind: 'backend', action: { type: 'refresh-session' } });
    case 'policy':
      return effect(state, { kind: 'backend', action: { type: 'refresh-policy' } });
    case 'browse':
      return effect(state, { kind: 'backend', action: { type: 'refresh-browse' } });
    default:
      return unchanged(state);
  }
}

function enterScreen(state: AppRouterState, screen: AppScreenId): AppRouterTransition {
  const next = {
    ...state,
    screen,
    listIndex: 0,
    message: null,
  };
  if (screen === 'doctor') {
    return effect(next, { kind: 'backend', action: { type: 'run-doctor' } });
  }
  if (screen === 'recovery') {
    return effect(next, { kind: 'backend', action: { type: 'recovery-status' } });
  }
  if (screen === 'policy') {
    return effect(next, { kind: 'backend', action: { type: 'refresh-policy' } });
  }
  if (screen === 'browse') {
    return effect(next, { kind: 'backend', action: { type: 'refresh-browse' } });
  }
  return unchanged(next);
}

function listLength(state: AppRouterState): number {
  switch (state.screen) {
    case 'profiles':
      return state.snapshot.profiles.length;
    case 'vaults':
      return state.snapshot.vaults.length;
    case 'credentials':
      return filteredCredentials(state).length;
    case 'doctor':
      return state.snapshot.doctor.length;
    case 'recovery':
      return state.snapshot.recovery.length;
    case 'policy':
      return state.snapshot.policies.length;
    case 'browse':
      return state.snapshot.browse.length;
    default:
      return 0;
  }
}

function clamp(index: number, length: number): number {
  if (length <= 0) return 0;
  return Math.max(0, Math.min(index, length - 1));
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

function removeLast(value: string): string {
  return Array.from(value).slice(0, -1).join('');
}

/**
 * Normalize pasted text for overlay fields.
 * Strips bracketed-paste markers and trailing CR/LF so paste never acts as Enter.
 */
export function sanitizePasteText(raw: string): string {
  let text = raw;
  // eslint-disable-next-line no-control-regex -- strip bracketed-paste / OSC markers
  text = text.replace(/\x1b\[200~/gu, '').replace(/\x1b\[201~/gu, '');
  // eslint-disable-next-line no-control-regex -- strip OSC sequences terminated by BEL/ST
  text = text.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/gu, '');
  text = text.replace(/\r/gu, '');
  text = text.replace(/^\n+/u, '').replace(/\n+$/u, '');
  // Drop remaining C0/C1 controls (keep printable + spaces).
  text = text.replace(/\p{C}/gu, '');
  return text;
}

function isPrintable(value: string | undefined): value is string {
  return typeof value === 'string' && value.length === 1 && !/\p{C}/u.test(value);
}

/** Append typed char or multi-char paste into the overlay query (once). */
function appendOverlayText(
  state: AppRouterState,
  text: string | undefined,
  limit: number,
): AppRouterTransition {
  if (text === undefined || text.length === 0) return unchanged(state);
  const chunk =
    text.length > 1 ? sanitizePasteText(text) : isPrintable(text) ? text : '';
  if (chunk.length === 0) return unchanged(state);
  return unchanged({
    ...state,
    query: `${state.query}${chunk}`.slice(0, limit),
  });
}

function unchanged(state: AppRouterState): AppRouterTransition {
  return { state, effect: { kind: 'none' } };
}

function effect(
  state: AppRouterState,
  nextEffect: AppRouterEffect,
): AppRouterTransition {
  return { state, effect: nextEffect };
}

/** Pure navigation helper used by smoke scripts and tests. */
export function navigateToScreen(
  state: AppRouterState,
  screen: AppScreenId,
): AppRouterState {
  return { ...state, screen, listIndex: 0, overlay: 'none' };
}

/** Credentials visible under the current `/` search filter. */
export function filteredCredentials(
  state: AppRouterState,
): AppRouterState['snapshot']['credentials'] {
  const query = state.credentialFilter.trim().toLocaleLowerCase();
  if (query.length === 0) return state.snapshot.credentials;
  return state.snapshot.credentials.filter((credential) =>
    credential.name.toLocaleLowerCase().includes(query),
  );
}

/**
 * Bounded window around the selected index so large vault lists stay
 * measurable and do not render every row at once.
 */
export function visibleListWindow<T>(
  items: readonly T[],
  selectedIndex: number,
  windowSize: number,
): Readonly<{ start: number; items: readonly T[] }> {
  const size = Math.max(1, windowSize);
  if (items.length <= size) return { start: 0, items };
  const half = Math.floor(size / 2);
  const start = Math.max(0, Math.min(selectedIndex - half, items.length - size));
  return { start, items: items.slice(start, start + size) };
}
