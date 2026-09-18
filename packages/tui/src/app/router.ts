import { APP_MENU, type AppScreenId } from './ids.js';
import type { AppSnapshot } from './backend.js';
import { emptySnapshot } from './backend.js';

export interface AppKey {
  readonly name?:
    | 'up'
    | 'down'
    | 'left'
    | 'right'
    | 'tab'
    | 'return'
    | 'escape'
    | 'backspace';
  readonly text?: string;
  readonly ctrl?: boolean;
}

export type AppOverlay =
  | 'none'
  | 'confirm-reveal'
  | 'confirm-lock'
  | 'confirm-revoke-last'
  | 'confirm-remove'
  | 'input-search'
  | 'input-run'
  | 'input-passphrase'
  | 'input-put-name'
  | 'input-put-value'
  | 'input-rename';

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
  readonly revealedName: string | null;
  /** Ephemeral plaintext; never copied into AppSnapshot. */
  readonly revealedValue: string | null;
  readonly revealedUntilMs: number;
  readonly message: string | null;
  readonly quit: boolean;
}

export type AppRouterEffect =
  | Readonly<{ kind: 'backend'; action: import('./backend.js').AppBackendAction }>
  | Readonly<{ kind: 'none' }>;

export interface AppRouterTransition {
  readonly state: AppRouterState;
  readonly effect: AppRouterEffect;
}

export type AppRouterAction =
  | Readonly<{ type: 'hydrate'; snapshot: AppSnapshot }>
  | Readonly<{ type: 'backend-result'; snapshot: AppSnapshot; revealedSecret?: string; nowMs: number }>
  | Readonly<{ type: 'resize'; width: number; height: number }>
  | Readonly<{ type: 'tick'; nowMs: number }>
  | Readonly<{ type: 'key'; key: AppKey; nowMs: number }>;

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
    revealedName: null,
    revealedValue: null,
    revealedUntilMs: 0,
    message: null,
    quit: false,
  };
}

export function transitionAppRouter(
  state: AppRouterState,
  action: AppRouterAction,
): AppRouterTransition {
  switch (action.type) {
    case 'hydrate':
      return unchanged({ ...state, snapshot: action.snapshot, message: action.snapshot.notice });
    case 'backend-result': {
      const revealedName =
        action.revealedSecret === undefined ? state.revealedName : state.pendingRevealName;
      return unchanged({
        ...state,
        snapshot: action.snapshot,
        message: action.snapshot.notice ?? state.message,
        pendingRevealName: action.revealedSecret === undefined ? state.pendingRevealName : null,
        revealedName,
        revealedValue:
          action.revealedSecret === undefined ? state.revealedValue : action.revealedSecret,
        revealedUntilMs:
          action.revealedSecret === undefined ? state.revealedUntilMs : action.nowMs + 15_000,
        overlay: 'none',
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

function keyTransition(state: AppRouterState, key: AppKey, nowMs: number): AppRouterTransition {
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

  if (key.name === 'escape' && state.screen !== 'home') {
    return unchanged({ ...state, screen: 'home', listIndex: 0, message: null });
  }

  if (state.screen === 'home') return homeKey(state, key);
  return screenKey(state, key, nowMs);
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

function screenKey(
  state: AppRouterState,
  key: AppKey,
  nowMs: number,
): AppRouterTransition {
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
    const name = state.snapshot.credentials[state.listIndex]?.name;
    if (name === undefined) return unchanged(state);
    return unchanged({
      ...state,
      overlay: 'confirm-reveal',
      pendingRevealName: name,
      message: `REVEAL confirmation required for '${name}'.`,
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
    const name = state.snapshot.credentials[state.listIndex]?.name;
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
    const name = state.snapshot.credentials[state.listIndex]?.name;
    if (name === undefined) return unchanged(state);
    return unchanged({
      ...state,
      overlay: 'confirm-remove',
      pendingName: name,
      message: `Remove credential '${name}'? y/n`,
    });
  }
  if (key.text?.toLowerCase() === 'u') {
    return unchanged({
      ...state,
      overlay: 'input-passphrase',
      query: '',
      message: 'Enter passphrase (masked). Enter unlocks; Esc cancels.',
    });
  }
  if (key.text?.toLowerCase() === 'l') {
    return unchanged({ ...state, overlay: 'confirm-lock' });
  }
  if (key.name === 'return') return activateSelection(state, nowMs);
  if (key.text?.toLowerCase() === 'd' && state.screen === 'doctor') {
    return effect(state, { kind: 'backend', action: { type: 'run-doctor' } });
  }
  if (key.text?.toLowerCase() === 'p' && state.screen === 'run') {
    return unchanged({ ...state, overlay: 'input-run', query: '' });
  }
  if (key.text?.toLowerCase() === 'g' && state.screen === 'agent') {
    return effect(state, { kind: 'backend', action: { type: 'agent-dry-run' } });
  }
  return unchanged(state);
}

function overlayKey(
  state: AppRouterState,
  key: AppKey,
  nowMs: number,
): AppRouterTransition {
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
  if (state.overlay === 'confirm-revoke-last') {
    if (key.name === 'escape' || key.text?.toLowerCase() === 'n') {
      return unchanged({
        ...state,
        overlay: 'none',
        message: 'Final-slot revoke cancelled.',
      });
    }
    return unchanged(state);
  }
  if (state.overlay === 'input-passphrase') {
    if (key.name === 'escape') {
      return unchanged({
        ...state,
        overlay: 'none',
        query: '',
        message: 'Unlock cancelled.',
      });
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      const passphrase = state.query;
      return effect(
        { ...state, overlay: 'none', query: '' },
        { kind: 'backend', action: { type: 'unlock', passphrase } },
      );
    }
    if (isPrintable(key.text)) {
      return unchanged({
        ...state,
        query: `${state.query}${key.text}`.slice(0, 1024),
      });
    }
    return unchanged(state);
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
    if (isPrintable(key.text)) {
      const limit = state.overlay === 'input-put-value' ? 4096 : 256;
      return unchanged({
        ...state,
        query: `${state.query}${key.text}`.slice(0, limit),
      });
    }
    return unchanged(state);
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
        return effect(
          { ...state, overlay: 'none' },
          { kind: 'backend', action: { type: 'search-credentials', query: state.query } },
        );
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
    if (isPrintable(key.text)) {
      return unchanged({
        ...state,
        query: `${state.query}${key.text}`.slice(0, 256),
      });
    }
    return unchanged(state);
  }
  void nowMs;
  return unchanged(state);
}

function activateSelection(state: AppRouterState, _nowMs: number): AppRouterTransition {
  switch (state.screen) {
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
      const active = state.snapshot.recovery.filter((slot) => slot.status === 'active');
      if (active.length <= 1) {
        return unchanged({
          ...state,
          overlay: 'confirm-revoke-last',
          message: 'Cannot revoke the final recovery slot without an explicit warning.',
        });
      }
      return unchanged({
        ...state,
        message: 'Use CLI `kavrix recovery revoke` for slot revocation.',
      });
    }
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
      return state.snapshot.credentials.length;
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

function removeLast(value: string): string {
  return Array.from(value).slice(0, -1).join('');
}

function isPrintable(value: string | undefined): value is string {
  return value !== undefined && value.length > 0 && !/\p{C}/u.test(value);
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
