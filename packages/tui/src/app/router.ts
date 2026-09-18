import { APP_MENU, type AppScreenId } from './ids.js';
import type { AppSnapshot } from './backend.js';
import { emptySnapshot } from './backend.js';
import { defaultFileProfilePaths } from './paths.js';

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
  | 'confirm-recovery-revoke'
  | 'confirm-policy-remove'
  | 'confirm-grant-revoke'
  | 'input-search'
  | 'input-run'
  | 'input-passphrase'
  | 'input-put-name'
  | 'input-put-value'
  | 'input-rename'
  | 'input-profile-id'
  | 'input-profile-data-file'
  | 'input-profile-key-file'
  | 'input-profile-passphrase'
  | 'input-profile-passphrase-confirm'
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
  | 'input-grant-ttl';

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
  /** Recovery / policy / grant wizard ephemeral fields (never snapshotted). */
  readonly pendingRecoveryFile: string | null;
  readonly pendingRecoveryPassphrase: string | null;
  readonly pendingPolicyId: string | null;
  readonly pendingPolicySecret: string | null;
  readonly pendingGrantSecret: string | null;
  readonly pendingGrantCommand: string | null;
  readonly pendingSlotId: string | null;
  readonly pendingGrantId: string | null;
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
    pendingDataFile: null,
    pendingKeyFile: null,
    pendingPassphrase: null,
    pendingRecoveryFile: null,
    pendingRecoveryPassphrase: null,
    pendingPolicyId: null,
    pendingPolicySecret: null,
    pendingGrantSecret: null,
    pendingGrantCommand: null,
    pendingSlotId: null,
    pendingGrantId: null,
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
  if (key.text?.toLowerCase() === 'n' && state.screen === 'profiles') {
    return unchanged({
      ...state,
      overlay: 'input-profile-id',
      query: '',
      pendingName: null,
      pendingDataFile: null,
      pendingKeyFile: null,
      pendingPassphrase: null,
      message: 'New file profile id. Enter continues; Esc cancels.',
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
      const active = state.snapshot.recovery.filter((entry) => entry.status === 'active');
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
      if (row === undefined || row.kind !== 'policy') {
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
      if (row === undefined || row.kind !== 'grant') {
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
        const dataFile = state.query.trim() || defaultFileProfilePaths(profileId).dataFile;
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
    if (isPrintable(key.text)) {
      const masked =
        state.overlay === 'input-profile-passphrase' ||
        state.overlay === 'input-profile-passphrase-confirm';
      const limit = masked ? 1024 : 512;
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
    if (isPrintable(key.text)) {
      const masked =
        state.overlay === 'input-recovery-passphrase' ||
        state.overlay === 'input-recovery-passphrase-confirm' ||
        state.overlay === 'input-recovery-verify-passphrase';
      const limit = masked ? 1024 : 512;
      return unchanged({
        ...state,
        query: `${state.query}${key.text}`.slice(0, limit),
      });
    }
    return unchanged(state);
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
    if (isPrintable(key.text)) {
      return unchanged({
        ...state,
        query: `${state.query}${key.text}`.slice(0, 256),
      });
    }
    return unchanged(state);
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
      const slot = state.snapshot.recovery[state.listIndex];
      if (slot === undefined || slot.slotId.startsWith('(')) {
        return effect(state, { kind: 'backend', action: { type: 'recovery-status' } });
      }
      const active = state.snapshot.recovery.filter((entry) => entry.status === 'active');
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
