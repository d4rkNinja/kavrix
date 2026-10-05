import {
  profileIdSchema,
  type SetupToolAction,
  type SetupToolResult,
  type SetupProgress,
} from '@kavrix/schemas';
import { basename, dirname, join } from 'node:path';

import type { AppBackendAction } from './backend.js';
import {
  defaultFileProfilePaths,
  defaultMongoProfilePaths,
  defaultRecoveryFilePath,
} from './paths.js';
import { sanitizePasteText, type AppKey } from './router.js';

/** Matches @kavrix/crypto MIN_PASSPHRASE_BYTES without pulling crypto into TUI. */
const MIN_ONBOARDING_PASSPHRASE_BYTES = 16;

export type OnboardingStorage = 'file' | 'mongodb';

export type OnboardingStep =
  | 'welcome'
  | 'storage'
  | 'file-profile-id'
  | 'file-data-file'
  | 'file-key-file'
  | 'file-passphrase'
  | 'file-passphrase-confirm'
  | 'file-recovery-passphrase'
  | 'file-recovery-passphrase-confirm'
  | 'file-recovery-file'
  | 'mongo-profile-id'
  | 'mongo-database'
  | 'mongo-key-file'
  | 'mongo-url'
  | 'mongo-passphrase'
  | 'mongo-passphrase-confirm'
  | 'mongo-recovery-passphrase'
  | 'mongo-recovery-passphrase-confirm'
  | 'mongo-recovery-file'
  | 'review'
  | 'creating'
  | 'enable-session'
  | 'success'
  | 'error';

export type OnboardingKey = Pick<AppKey, 'name' | 'text' | 'ctrl'>;

export interface OnboardingState {
  readonly cursor: number | null;
  readonly editingReview: boolean;
  readonly pendingTool: SetupToolAction['type'] | null;
  readonly toolView: SetupToolResult | null;
  readonly folderIndex: number;
  readonly progress: SetupProgress | null;
  readonly elapsedSeconds: number;
  readonly connectionVerified: boolean;
  readonly destinationRejected: boolean;
  readonly checkingDestination: boolean;
  readonly step: OnboardingStep;
  readonly storage: OnboardingStorage | null;
  readonly storageIndex: 0 | 1;
  readonly query: string;
  readonly profileId: string | null;
  readonly dataFile: string | null;
  readonly keyFile: string | null;
  readonly database: string | null;
  readonly databaseUrl: string | null;
  readonly passphrase: string | null;
  readonly recoveryPassphrase: string | null;
  readonly recoveryFile: string | null;
  readonly message: string | null;
  readonly error: string | null;
  readonly ascii: boolean;
  readonly color: boolean;
  readonly width: number;
  readonly height: number;
  readonly quit: boolean;
  /** True while the post-create session-enable round trip is in flight. */
  readonly sessionAttempt: boolean;
  readonly completed: boolean;
  readonly completedProfileId: string | null;
  readonly completedDatastore: OnboardingStorage | null;
  readonly completedRecoveryFile: string | null;
}

export type OnboardingEffect =
  Readonly<{ kind: 'backend'; action: AppBackendAction }> | Readonly<{ kind: 'none' }>;

export interface OnboardingTransition {
  readonly state: OnboardingState;
  readonly effect: OnboardingEffect;
}

export type OnboardingAction =
  | Readonly<{ type: 'progress'; progress: SetupProgress }>
  | Readonly<{ type: 'elapsed'; seconds: number }>
  | Readonly<{ type: 'resize'; width: number; height: number }>
  | Readonly<{ type: 'key'; key: OnboardingKey }>
  | Readonly<{
      type: 'backend-result';
      ok: boolean;
      notice: string | null;
      profileId: string | null;
      datastore: OnboardingStorage | null;
      setup?: SetupToolResult;
    }>;

const STORAGE_OPTIONS: readonly OnboardingStorage[] = ['file', 'mongodb'];

export function createInitialOnboardingState(
  options: Readonly<{
    width?: number;
    height?: number;
    ascii?: boolean;
    color?: boolean;
  }> = {},
): OnboardingState {
  return {
    cursor: null,
    editingReview: false,
    pendingTool: null,
    toolView: null,
    folderIndex: 0,
    progress: null,
    elapsedSeconds: 0,
    connectionVerified: false,
    destinationRejected: false,
    checkingDestination: false,
    step: 'welcome',
    storage: null,
    storageIndex: 0,
    query: '',
    profileId: null,
    dataFile: null,
    keyFile: null,
    database: null,
    databaseUrl: null,
    passphrase: null,
    recoveryPassphrase: null,
    recoveryFile: null,
    message: 'Welcome — press Enter to begin setup.',
    error: null,
    ascii: options.ascii ?? false,
    color: options.color ?? true,
    width: Math.max(40, options.width ?? 80),
    height: Math.max(12, options.height ?? 24),
    quit: false,
    completed: false,
    sessionAttempt: false,
    completedProfileId: null,
    completedDatastore: null,
    completedRecoveryFile: null,
  };
}

export function transitionOnboarding(
  state: OnboardingState,
  action: OnboardingAction,
): OnboardingTransition {
  const next = transitionOnboardingState(state, action);
  return next.state.step === state.step
    ? next
    : {
        ...next,
        state: {
          ...next.state,
          cursor: null,
          toolView: null,
          destinationRejected: false,
          connectionVerified:
            next.state.step === 'mongo-url' ? false : next.state.connectionVerified,
        },
      };
}

function transitionOnboardingState(
  state: OnboardingState,
  action: OnboardingAction,
): OnboardingTransition {
  if (action.type === 'progress')
    return unchanged({ ...state, progress: action.progress });
  if (action.type === 'elapsed')
    return unchanged({
      ...state,
      elapsedSeconds: Math.max(0, Math.floor(action.seconds)),
    });
  if (action.type === 'resize') {
    return unchanged({
      ...state,
      width: Math.max(40, action.width),
      height: Math.max(12, action.height),
    });
  }

  if (action.type === 'backend-result') {
    if (state.pendingTool !== null) {
      const ready = { ...state, pendingTool: null };
      const setup = action.setup;
      const expectedKind =
        state.pendingTool === 'test-setup-mongodb'
          ? 'connection'
          : state.pendingTool === 'repair-setup-directory'
            ? 'repair'
            : 'folders';
      if (setup !== undefined && setup.kind !== expectedKind)
        return unchanged({
          ...ready,
          toolView: null,
          connectionVerified: false,
          message: 'Tool returned an unexpected result. Review the settings and retry.',
        });
      if (setup?.kind === 'connection')
        return unchanged({
          ...ready,
          connectionVerified: action.ok && setup.status === 'ok',
          message: action.notice,
        });
      if (action.ok && setup !== undefined)
        return unchanged({
          ...ready,
          toolView: setup.kind === 'repair' && setup.mode === 'apply' ? null : setup,
          folderIndex: 0,
          message: action.notice,
          destinationRejected: false,
        });
      return unchanged({
        ...ready,
        toolView: null,
        message:
          action.notice ??
          'Tool could not complete. Edit the path or choose a secure default.',
      });
    }
    if (state.checkingDestination) {
      const ready = {
        ...state,
        checkingDestination: false,
        destinationRejected: !action.ok,
      };
      return action.ok
        ? commitInput(ready, true)
        : unchanged({
            ...ready,
            message:
              action.notice ??
              'Choose a protected destination and press Enter to check again.',
          });
    }
    // The post-create session-enable round trip never fails setup: the vault
    // already exists, so any outcome lands on success with guidance.
    if (state.step === 'enable-session') {
      return unchanged({
        ...state,
        step: 'success',
        query: '',
        passphrase: null,
        recoveryPassphrase: null,
        databaseUrl: null,
        message: action.ok
          ? 'Session unlock enabled — future unlocks use the OS credential store.'
          : 'Setup complete; session unlock could not be enabled. Enable it later from the Session screen in kavrix tui.',
        error: null,
        sessionAttempt: false,
        completed: true,
        completedProfileId: action.profileId,
        completedDatastore: action.datastore ?? state.storage,
        completedRecoveryFile: state.recoveryFile,
      });
    }
    if (action.ok) {
      return unchanged({
        ...state,
        step: 'enable-session',
        query: '',
        message:
          'Setup complete. Enable OS session unlock (Windows Hello / keychain)? Enter = yes · Esc = skip',
        error: null,
      });
    }
    return unchanged({
      ...state,
      step: 'error',
      query: '',
      passphrase: null,
      recoveryPassphrase: null,
      databaseUrl: null,
      message: null,
      error: action.notice ?? 'Setup failed safely.',
    });
  }

  return keyTransition(state, action.key);
}

function keyTransition(
  state: OnboardingState,
  key: OnboardingKey,
): OnboardingTransition {
  if (state.checkingDestination || state.sessionAttempt || state.pendingTool !== null)
    return unchanged(state);
  // Never abort mid-create — avoids partial profile corruption from Ctrl+C.
  if (state.step === 'creating') {
    return unchanged({
      ...state,
      message: state.message ?? 'Creating profile — please wait…',
    });
  }

  if (key.ctrl === true && key.text === 'c') {
    return unchanged({
      ...state,
      quit: true,
      message: 'Setup cancelled.',
    });
  }
  if (state.toolView?.kind === 'folders') return folderKey(state, key);
  if (state.toolView?.kind === 'repair') {
    if (key.name === 'escape') return unchanged({ ...state, toolView: null });
    if (key.name === 'return')
      return setupTool(state, {
        type: 'repair-setup-directory',
        path: state.query || defaultPathForStep(state),
        mode: 'apply',
      });
    return unchanged(state);
  }
  if (state.step === 'review') return reviewKey(state, key);
  if (isPathStep(state.step) && key.ctrl) {
    if (key.text === 'd')
      return unchanged({
        ...state,
        query: defaultPathForStep(state),
        cursor: null,
        destinationRejected: false,
      });
    if (key.text === 'r')
      return setupTool(state, {
        type: 'repair-setup-directory',
        path: state.query || defaultPathForStep(state),
        mode: 'preview',
      });
    if (key.text === 'b') {
      const defaultPath = defaultPathForStep(state);
      const selectedPath = state.query || defaultPath;
      return setupTool(state, {
        type: 'browse-setup-folders',
        // Home exists on a fresh installation; the default artifact directory
        // is created only when its destination is explicitly validated.
        path:
          selectedPath === defaultPath
            ? dirname(dirname(defaultPath))
            : dirname(selectedPath),
      });
    }
  }
  if (state.step === 'mongo-url' && key.ctrl && key.text === 't') {
    if (!state.query.trim())
      return unchanged({
        ...state,
        message: 'Enter the MongoDB address before testing.',
      });
    return setupTool(state, {
      type: 'test-setup-mongodb',
      databaseUrl: state.query.trim(),
      database: state.database ?? 'default',
    });
  }

  if (state.step === 'enable-session') {
    if (key.name === 'return') {
      return {
        state: { ...state, sessionAttempt: true, message: 'Enabling session unlock…' },
        effect: { kind: 'backend', action: { type: 'session-enable' } },
      };
    }
    if (key.name === 'escape' || key.text?.toLowerCase() === 'q') {
      return unchanged({
        ...state,
        step: 'success',
        query: '',
        passphrase: null,
        recoveryPassphrase: null,
        databaseUrl: null,
        message:
          'Setup complete. You can enable session unlock later from the Session screen.',
        error: null,
        sessionAttempt: false,
        completed: true,
      });
    }
    return unchanged(state);
  }

  if (state.step === 'success') {
    if (
      key.name === 'return' ||
      key.name === 'escape' ||
      key.text?.toLowerCase() === 'q'
    ) {
      return unchanged({ ...state, quit: true });
    }
    return unchanged(state);
  }

  if (state.step === 'error') {
    if (key.name === 'escape' || key.text?.toLowerCase() === 'q') {
      return unchanged({ ...state, quit: true });
    }
    if (key.name === 'return' || key.text?.toLowerCase() === 'r') {
      if (state.storage !== null && state.profileId !== null) {
        return unchanged({
          ...state,
          step: state.storage === 'file' ? 'file-data-file' : 'mongo-key-file',
          query:
            state.storage === 'file' ? (state.dataFile ?? '') : (state.keyFile ?? ''),
          error: null,
          message:
            'Review the destinations, then press Enter to check each one. Protected inputs must be entered again.',
        });
      }
      return unchanged({
        ...createInitialOnboardingState({
          width: state.width,
          height: state.height,
          ascii: state.ascii,
          color: state.color,
        }),
        message: 'Restarted onboarding.',
      });
    }
    return unchanged(state);
  }

  if (state.step === 'welcome') {
    if (key.name === 'escape' || key.text?.toLowerCase() === 'q') {
      return unchanged({ ...state, quit: true, message: 'Setup cancelled.' });
    }
    if (key.name === 'return') {
      return unchanged({
        ...state,
        step: 'storage',
        message: 'Choose storage with ↑/↓, Enter to confirm.',
      });
    }
    return unchanged(state);
  }

  if (state.step === 'storage') {
    if (key.name === 'escape' || key.text?.toLowerCase() === 'q') {
      return unchanged({ ...state, quit: true, message: 'Setup cancelled.' });
    }
    if (key.name === 'up' || key.name === 'left') {
      return unchanged({
        ...state,
        storageIndex: 0,
        message: 'Local encrypted file selected.',
      });
    }
    if (key.name === 'down' || key.name === 'right' || key.name === 'tab') {
      return unchanged({
        ...state,
        storageIndex: 1,
        message: 'MongoDB selected.',
      });
    }
    if (key.text === '1') {
      return unchanged({
        ...state,
        storageIndex: 0,
        message: 'Local encrypted file selected.',
      });
    }
    if (key.text === '2') {
      return unchanged({
        ...state,
        storageIndex: 1,
        message: 'MongoDB selected.',
      });
    }
    if (key.name === 'return') {
      const storage = STORAGE_OPTIONS[state.storageIndex] ?? 'file';
      if (storage === 'file') {
        return unchanged({
          ...state,
          storage,
          step: 'file-profile-id',
          query: 'default',
          message: 'Profile id (Enter accepts default).',
        });
      }
      return unchanged({
        ...state,
        storage,
        step: 'mongo-profile-id',
        query: 'default',
        message: 'Profile id (Enter accepts default).',
      });
    }
    return unchanged(state);
  }

  if (isInputStep(state.step)) {
    if (state.editingReview && key.name === 'escape')
      return unchanged({ ...state, step: 'review', query: '', editingReview: false });
    if (key.name === 'escape') {
      return stepBack(state);
    }
    if (key.name === 'backspace') {
      return editInput(state, 'backspace');
    }
    if (key.name === 'delete') return editInput(state, 'delete');
    if (
      key.name === 'left' ||
      key.name === 'right' ||
      key.name === 'home' ||
      key.name === 'end'
    )
      return editInput(state, key.name);
    if (key.ctrl && key.text === 'a') return editInput(state, 'home');
    if (key.ctrl && key.text === 'e') return editInput(state, 'end');
    if (key.ctrl && key.text === 'u')
      return unchanged({
        ...state,
        query: '',
        cursor: null,
        connectionVerified: false,
      });
    if (key.ctrl) return unchanged(state);
    if (key.name === 'return') {
      return commitInput(state);
    }
    const limit = isSecretStep(state.step) ? 1024 : 512;
    return appendText(state, key.text, limit);
  }

  return unchanged(state);
}

function commitInput(
  state: OnboardingState,
  destinationValidated = false,
): OnboardingTransition {
  if (state.editingReview) return commitReviewEdit(state, destinationValidated);
  switch (state.step) {
    case 'file-profile-id': {
      const profileId = state.query.trim() || 'default';
      const idError = validateProfileId(profileId);
      if (idError !== null) {
        return unchanged({ ...state, message: idError });
      }
      const defaults = defaultFileProfilePaths(profileId);
      return unchanged({
        ...state,
        profileId,
        step: 'file-data-file',
        query: defaults.dataFile,
        message: `Data file for '${profileId}' (Enter accepts default).`,
      });
    }
    case 'file-data-file': {
      const profileId = state.profileId;
      if (profileId === null) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Restarted.',
        });
      }
      const dataFile =
        state.query.trim() || defaultFileProfilePaths(profileId).dataFile;
      const pathError = validatePathInput(dataFile, 'Data file');
      if (pathError !== null) {
        return unchanged({ ...state, message: pathError });
      }
      if (!destinationValidated) return checkDestination(state, dataFile);
      return unchanged({
        ...state,
        dataFile,
        step: 'file-key-file',
        query: state.keyFile ?? defaultFileProfilePaths(profileId).keyFile,
        message: `Key file for '${profileId}' (Enter accepts default).`,
      });
    }
    case 'file-key-file': {
      const profileId = state.profileId;
      if (profileId === null || state.dataFile === null) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Restarted.',
        });
      }
      const keyFile = state.query.trim() || defaultFileProfilePaths(profileId).keyFile;
      const pathError = validatePathInput(keyFile, 'Key file');
      if (pathError !== null) {
        return unchanged({ ...state, message: pathError });
      }
      if (!destinationValidated) return checkDestination(state, keyFile);
      return unchanged({
        ...state,
        keyFile,
        step: 'file-passphrase',
        query: '',
        message: 'Owner passphrase (masked). Enter continues; Esc back.',
      });
    }
    case 'file-passphrase': {
      if (state.query.length === 0) {
        return unchanged({ ...state, message: 'Passphrase cannot be empty.' });
      }
      if (passphraseTooShort(state.query)) {
        return unchanged({
          ...state,
          message: `Passphrase must be at least ${String(MIN_ONBOARDING_PASSPHRASE_BYTES)} UTF-8 bytes.`,
        });
      }
      return unchanged({
        ...state,
        passphrase: state.query,
        step: 'file-passphrase-confirm',
        query: '',
        message: 'Confirm owner passphrase (masked). Enter continues to recovery kit.',
      });
    }
    case 'file-passphrase-confirm': {
      const passphrase = state.passphrase;
      if (passphrase === null) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Create cancelled.',
        });
      }
      if (state.query !== passphrase) {
        return unchanged({
          ...state,
          step: 'file-passphrase',
          passphrase: null,
          query: '',
          message: 'Passphrases did not match. Re-enter passphrase.',
        });
      }
      return unchanged({
        ...state,
        step: 'file-recovery-passphrase',
        query: '',
        message:
          'Recovery-kit passphrase (masked; separate from owner). Enter continues.',
      });
    }
    case 'file-recovery-passphrase': {
      if (state.query.length === 0) {
        return unchanged({ ...state, message: 'Recovery passphrase cannot be empty.' });
      }
      if (passphraseTooShort(state.query)) {
        return unchanged({
          ...state,
          message: `Passphrase must be at least ${String(MIN_ONBOARDING_PASSPHRASE_BYTES)} UTF-8 bytes.`,
        });
      }
      return unchanged({
        ...state,
        recoveryPassphrase: state.query,
        step: 'file-recovery-passphrase-confirm',
        query: '',
        message: 'Confirm recovery-kit passphrase (masked).',
      });
    }
    case 'file-recovery-passphrase-confirm': {
      const recoveryPassphrase = state.recoveryPassphrase;
      const profileId = state.profileId;
      if (recoveryPassphrase === null || profileId === null) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Create cancelled.',
        });
      }
      if (state.query !== recoveryPassphrase) {
        return unchanged({
          ...state,
          step: 'file-recovery-passphrase',
          recoveryPassphrase: null,
          query: '',
          message: 'Recovery passphrases did not match. Re-enter recovery passphrase.',
        });
      }
      return unchanged({
        ...state,
        step: 'file-recovery-file',
        query: state.recoveryFile ?? defaultRecoveryFilePath(profileId),
        message: `Recovery kit path for '${profileId}' (Enter accepts secure ~/.kavrix default).`,
      });
    }
    case 'file-recovery-file': {
      const profileId = state.profileId;
      const dataFile = state.dataFile;
      const keyFile = state.keyFile;
      const passphrase = state.passphrase;
      const recoveryPassphrase = state.recoveryPassphrase;
      if (
        profileId === null ||
        dataFile === null ||
        keyFile === null ||
        passphrase === null ||
        recoveryPassphrase === null
      ) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Create cancelled.',
        });
      }
      const recoveryFile = state.query.trim() || defaultRecoveryFilePath(profileId);
      const pathError = validatePathInput(recoveryFile, 'Recovery file');
      if (pathError !== null) {
        return unchanged({ ...state, message: pathError });
      }
      if (!destinationValidated) return checkDestination(state, recoveryFile);
      return unchanged({
        ...state,
        recoveryFile,
        step: 'review',
        query: '',
        message:
          'Review the public settings. Enter creates; choose an Edit control to change a setting. Protected values stay hidden.',
      });
    }
    case 'mongo-profile-id': {
      const profileId = state.query.trim() || 'default';
      const idError = validateProfileId(profileId);
      if (idError !== null) {
        return unchanged({ ...state, message: idError });
      }
      return unchanged({
        ...state,
        profileId,
        step: 'mongo-database',
        query: profileId,
        message: `MongoDB database name for '${profileId}'.`,
      });
    }
    case 'mongo-database': {
      const profileId = state.profileId;
      if (profileId === null) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Restarted.',
        });
      }
      const database = state.query.trim() || profileId;
      if (database.length === 0 || database.includes('\0')) {
        return unchanged({ ...state, message: 'Database name is invalid.' });
      }
      return unchanged({
        ...state,
        database,
        step: 'mongo-key-file',
        query: defaultMongoProfilePaths(profileId).keyFile,
        message: `Key file for '${profileId}' (Enter accepts default).`,
      });
    }
    case 'mongo-key-file': {
      const profileId = state.profileId;
      if (profileId === null || state.database === null) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Restarted.',
        });
      }
      const keyFile = state.query.trim() || defaultMongoProfilePaths(profileId).keyFile;
      const pathError = validatePathInput(keyFile, 'Key file');
      if (pathError !== null) {
        return unchanged({ ...state, message: pathError });
      }
      if (!destinationValidated) return checkDestination(state, keyFile);
      return unchanged({
        ...state,
        keyFile,
        step: 'mongo-url',
        query: '',
        message: 'MongoDB URL (masked). Never stored by the TUI.',
      });
    }
    case 'mongo-url': {
      if (state.query.trim().length === 0) {
        return unchanged({ ...state, message: 'MongoDB URL cannot be empty.' });
      }
      if (!state.connectionVerified)
        return setupTool(state, {
          type: 'test-setup-mongodb',
          databaseUrl: state.query.trim(),
          database: state.database ?? 'default',
        });
      return unchanged({
        ...state,
        databaseUrl: state.query.trim(),
        step: 'mongo-passphrase',
        query: '',
        message: 'Owner passphrase (masked). Enter continues; Esc back.',
      });
    }
    case 'mongo-passphrase': {
      if (state.query.length === 0) {
        return unchanged({ ...state, message: 'Passphrase cannot be empty.' });
      }
      if (passphraseTooShort(state.query)) {
        return unchanged({
          ...state,
          message: `Passphrase must be at least ${String(MIN_ONBOARDING_PASSPHRASE_BYTES)} UTF-8 bytes.`,
        });
      }
      return unchanged({
        ...state,
        passphrase: state.query,
        step: 'mongo-passphrase-confirm',
        query: '',
        message: 'Confirm owner passphrase (masked). Enter continues to recovery kit.',
      });
    }
    case 'mongo-passphrase-confirm': {
      const passphrase = state.passphrase;
      if (passphrase === null) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Create cancelled.',
        });
      }
      if (state.query !== passphrase) {
        return unchanged({
          ...state,
          step: 'mongo-passphrase',
          passphrase: null,
          query: '',
          message: 'Passphrases did not match. Re-enter passphrase.',
        });
      }
      return unchanged({
        ...state,
        step: 'mongo-recovery-passphrase',
        query: '',
        message:
          'Recovery-kit passphrase (masked; separate from owner). Enter continues.',
      });
    }
    case 'mongo-recovery-passphrase': {
      if (state.query.length === 0) {
        return unchanged({ ...state, message: 'Recovery passphrase cannot be empty.' });
      }
      if (passphraseTooShort(state.query)) {
        return unchanged({
          ...state,
          message: `Passphrase must be at least ${String(MIN_ONBOARDING_PASSPHRASE_BYTES)} UTF-8 bytes.`,
        });
      }
      return unchanged({
        ...state,
        recoveryPassphrase: state.query,
        step: 'mongo-recovery-passphrase-confirm',
        query: '',
        message: 'Confirm recovery-kit passphrase (masked).',
      });
    }
    case 'mongo-recovery-passphrase-confirm': {
      const recoveryPassphrase = state.recoveryPassphrase;
      const profileId = state.profileId;
      if (recoveryPassphrase === null || profileId === null) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Create cancelled.',
        });
      }
      if (state.query !== recoveryPassphrase) {
        return unchanged({
          ...state,
          step: 'mongo-recovery-passphrase',
          recoveryPassphrase: null,
          query: '',
          message: 'Recovery passphrases did not match. Re-enter recovery passphrase.',
        });
      }
      return unchanged({
        ...state,
        step: 'mongo-recovery-file',
        query: state.recoveryFile ?? defaultRecoveryFilePath(profileId),
        message: `Recovery kit path for '${profileId}' (Enter accepts secure ~/.kavrix default).`,
      });
    }
    case 'mongo-recovery-file': {
      const profileId = state.profileId;
      const database = state.database;
      const keyFile = state.keyFile;
      const databaseUrl = state.databaseUrl;
      const passphrase = state.passphrase;
      const recoveryPassphrase = state.recoveryPassphrase;
      if (
        profileId === null ||
        database === null ||
        keyFile === null ||
        databaseUrl === null ||
        passphrase === null ||
        recoveryPassphrase === null
      ) {
        return unchanged({
          ...state,
          step: 'storage',
          query: '',
          message: 'Create cancelled.',
        });
      }
      const recoveryFile = state.query.trim() || defaultRecoveryFilePath(profileId);
      const pathError = validatePathInput(recoveryFile, 'Recovery file');
      if (pathError !== null) {
        return unchanged({ ...state, message: pathError });
      }
      if (!destinationValidated) return checkDestination(state, recoveryFile);
      return unchanged({
        ...state,
        recoveryFile,
        step: 'review',
        query: '',
        message:
          'Review the public settings. Enter creates; choose an Edit control to change a setting. Protected values stay hidden.',
      });
    }
    default:
      return unchanged(state);
  }
}

function checkDestination(state: OnboardingState, path: string): OnboardingTransition {
  return effect(
    {
      ...state,
      checkingDestination: true,
      query: path,
      message: 'Checking destination permissions before continuing…',
    },
    { kind: 'backend', action: { type: 'validate-profile-destination', path } },
  );
}

export function isPathStep(step: OnboardingStep): boolean {
  return [
    'file-data-file',
    'file-key-file',
    'mongo-key-file',
    'file-recovery-file',
    'mongo-recovery-file',
  ].includes(step);
}

function defaultPathForStep(state: OnboardingState): string {
  const id = state.profileId ?? 'default';
  if (state.step.endsWith('recovery-file')) return defaultRecoveryFilePath(id);
  if (state.step === 'file-data-file') return defaultFileProfilePaths(id).dataFile;
  return defaultFileProfilePaths(id).keyFile;
}

function setupTool(
  state: OnboardingState,
  action: SetupToolAction,
): OnboardingTransition {
  return effect(
    {
      ...state,
      pendingTool: action.type,
      elapsedSeconds: 0,
      message:
        action.type === 'test-setup-mongodb'
          ? 'Testing MongoDB connection without creating vault records…'
          : action.type === 'repair-setup-directory'
            ? 'Checking the Kavrix repair target…'
            : 'Reading folder names only…',
    },
    { kind: 'backend', action },
  );
}

function folderKey(state: OnboardingState, key: OnboardingKey): OnboardingTransition {
  const view = state.toolView;
  if (view?.kind !== 'folders') return unchanged(state);
  if (key.name === 'escape') return unchanged({ ...state, toolView: null });
  if (key.ctrl && key.text === 's')
    return unchanged({
      ...state,
      query: join(view.directory, basename(state.query || defaultPathForStep(state))),
      cursor: null,
      toolView: null,
      destinationRejected: false,
      message:
        'Folder selected. Review the filename, then Enter checks its permissions.',
    });
  if (key.name === 'backspace' || (key.ctrl && key.text === 'p'))
    return setupTool(state, { type: 'browse-setup-folders', path: view.parent });
  if (key.name === 'up' || key.name === 'down')
    return unchanged({
      ...state,
      folderIndex: Math.max(
        0,
        Math.min(
          view.entries.length - 1,
          state.folderIndex + (key.name === 'up' ? -1 : 1),
        ),
      ),
    });
  if (key.name === 'return') {
    const entry = view.entries[state.folderIndex];
    return entry === undefined
      ? unchanged(state)
      : setupTool(state, { type: 'browse-setup-folders', path: entry.path });
  }
  if (key.text !== undefined && /^\d+$/u.test(key.text)) {
    const index = Number(key.text);
    if (view.entries[index] !== undefined)
      return unchanged({ ...state, folderIndex: index });
  }
  return unchanged(state);
}

function editInput(
  state: OnboardingState,
  operation: 'left' | 'right' | 'home' | 'end' | 'delete' | 'backspace',
): OnboardingTransition {
  const glyphs = Array.from(state.query);
  let cursor = Math.min(glyphs.length, state.cursor ?? glyphs.length);
  if (operation === 'left') cursor = Math.max(0, cursor - 1);
  if (operation === 'right') cursor = Math.min(glyphs.length, cursor + 1);
  if (operation === 'home') cursor = 0;
  if (operation === 'end') cursor = glyphs.length;
  if (operation === 'backspace' && cursor > 0) {
    glyphs.splice(--cursor, 1);
  }
  if (operation === 'delete') glyphs.splice(cursor, 1);
  return unchanged({
    ...state,
    query: glyphs.join(''),
    cursor,
    connectionVerified:
      state.step === 'mongo-url' && ['delete', 'backspace'].includes(operation)
        ? false
        : state.connectionVerified,
  });
}

function reviewKey(state: OnboardingState, key: OnboardingKey): OnboardingTransition {
  if (key.name === 'up' || key.name === 'down')
    return unchanged({
      ...state,
      folderIndex: Math.max(
        0,
        Math.min(4, state.folderIndex + (key.name === 'down' ? 1 : -1)),
      ),
    });
  if (key.name === 'return') return createReviewedProfile(state);
  if (key.name === 'escape')
    return unchanged({
      ...state,
      step: state.storage === 'file' ? 'file-recovery-file' : 'mongo-recovery-file',
      query: state.recoveryFile ?? '',
    });
  const edits =
    state.storage === 'file'
      ? [
          { step: 'file-profile-id' as const, value: state.profileId },
          { step: 'file-data-file' as const, value: state.dataFile },
          { step: 'file-key-file' as const, value: state.keyFile },
          { step: 'file-recovery-file' as const, value: state.recoveryFile },
        ]
      : [
          { step: 'mongo-profile-id' as const, value: state.profileId },
          { step: 'mongo-database' as const, value: state.database },
          { step: 'mongo-key-file' as const, value: state.keyFile },
          { step: 'mongo-recovery-file' as const, value: state.recoveryFile },
        ];
  const edit = key.text === undefined ? undefined : edits[Number(key.text) - 1];
  return edit === undefined
    ? unchanged(state)
    : unchanged({
        ...state,
        step: edit.step,
        query: edit.value ?? '',
        editingReview: true,
        message:
          'Edit this public setting. Enter validates and returns to review; Escape discards this edit.',
      });
}

function commitReviewEdit(
  state: OnboardingState,
  validated: boolean,
): OnboardingTransition {
  const value = state.query.trim();
  if (isPathStep(state.step)) {
    if (validatePathInput(value, 'Destination') !== null)
      return unchanged({ ...state, message: 'Destination path is invalid.' });
    if (!validated) return checkDestination(state, value);
  } else if (state.step.endsWith('profile-id')) {
    const error = validateProfileId(value);
    if (error !== null) return unchanged({ ...state, message: error });
  } else if (!value || value.length > 128 || /[/\\. "$\0]/u.test(value))
    return unchanged({ ...state, message: 'Database name is invalid.' });
  const patch = state.step.endsWith('profile-id')
    ? { profileId: value }
    : state.step === 'file-data-file'
      ? { dataFile: value }
      : state.step.endsWith('key-file')
        ? { keyFile: value }
        : state.step.endsWith('recovery-file')
          ? { recoveryFile: value }
          : { database: value, connectionVerified: false };
  return unchanged({
    ...state,
    ...patch,
    step: 'review',
    query: '',
    editingReview: false,
    message: 'Setting updated. Review before creating.',
  });
}

function createReviewedProfile(state: OnboardingState): OnboardingTransition {
  const {
    profileId,
    dataFile,
    keyFile,
    database,
    databaseUrl,
    passphrase,
    recoveryFile,
    recoveryPassphrase,
  } = state;
  if (
    profileId === null ||
    keyFile === null ||
    passphrase === null ||
    recoveryFile === null ||
    recoveryPassphrase === null ||
    state.storage === null ||
    (state.storage === 'file' && dataFile === null) ||
    (state.storage === 'mongodb' && (database === null || databaseUrl === null))
  )
    return unchanged({
      ...state,
      message: 'Setup is incomplete. Go back and enter the required settings.',
    });
  if (state.storage === 'mongodb' && !state.connectionVerified)
    return setupTool(state, {
      type: 'test-setup-mongodb',
      databaseUrl: databaseUrl ?? '',
      database: database ?? '',
    });
  const action: AppBackendAction =
    state.storage === 'file'
      ? {
          type: 'create-file-profile',
          profileId,
          dataFile: dataFile ?? '',
          keyFile,
          passphrase,
          recoveryFile,
          recoveryPassphrase,
        }
      : {
          type: 'create-mongodb-profile',
          profileId,
          database: database ?? '',
          keyFile,
          databaseUrl: databaseUrl ?? '',
          passphrase,
          recoveryFile,
          recoveryPassphrase,
        };
  return effect(
    {
      ...state,
      step: 'creating',
      query: '',
      passphrase: null,
      recoveryPassphrase: null,
      databaseUrl: null,
      elapsedSeconds: 0,
      progress: { stage: 'checking-permissions' },
      message: 'Creating encrypted storage. Please wait until the operation completes.',
    },
    { kind: 'backend', action },
  );
}

function stepBack(state: OnboardingState): OnboardingTransition {
  switch (state.step) {
    case 'file-profile-id':
    case 'mongo-profile-id':
      return unchanged({
        ...state,
        step: 'storage',
        query: '',
        profileId: null,
        dataFile: null,
        keyFile: null,
        database: null,
        databaseUrl: null,
        passphrase: null,
        recoveryPassphrase: null,
        recoveryFile: null,
        message: 'Back to storage choice.',
      });
    case 'file-data-file':
      return unchanged({
        ...state,
        step: 'file-profile-id',
        query: state.profileId ?? 'default',
        dataFile: null,
        message: 'Profile id (Enter accepts default).',
      });
    case 'file-key-file':
      return unchanged({
        ...state,
        step: 'file-data-file',
        query: state.dataFile ?? '',
        keyFile: null,
        message: `Data file for '${state.profileId ?? 'default'}' (Enter accepts default).`,
      });
    case 'file-passphrase':
      return unchanged({
        ...state,
        step: 'file-key-file',
        query: state.keyFile ?? '',
        passphrase: null,
        message: `Key file for '${state.profileId ?? 'default'}' (Enter accepts default).`,
      });
    case 'file-passphrase-confirm':
      return unchanged({
        ...state,
        step: 'file-passphrase',
        query: '',
        passphrase: null,
        message: 'Owner passphrase (masked). Enter continues; Esc back.',
      });
    case 'file-recovery-passphrase':
      return unchanged({
        ...state,
        step: 'file-passphrase-confirm',
        query: '',
        recoveryPassphrase: null,
        message: 'Confirm owner passphrase (masked). Enter continues to recovery kit.',
      });
    case 'file-recovery-passphrase-confirm':
      return unchanged({
        ...state,
        step: 'file-recovery-passphrase',
        query: '',
        recoveryPassphrase: null,
        message:
          'Recovery-kit passphrase (masked; separate from owner). Enter continues.',
      });
    case 'file-recovery-file':
      return unchanged({
        ...state,
        step: 'file-recovery-passphrase-confirm',
        query: '',
        recoveryFile: null,
        message: 'Confirm recovery-kit passphrase (masked).',
      });
    case 'mongo-database':
      return unchanged({
        ...state,
        step: 'mongo-profile-id',
        query: state.profileId ?? 'default',
        database: null,
        message: 'Profile id (Enter accepts default).',
      });
    case 'mongo-key-file':
      return unchanged({
        ...state,
        step: 'mongo-database',
        query: state.database ?? state.profileId ?? '',
        keyFile: null,
        message: `MongoDB database name for '${state.profileId ?? 'default'}'.`,
      });
    case 'mongo-url':
      return unchanged({
        ...state,
        step: 'mongo-key-file',
        query: state.keyFile ?? '',
        databaseUrl: null,
        message: `Key file for '${state.profileId ?? 'default'}' (Enter accepts default).`,
      });
    case 'mongo-passphrase':
      return unchanged({
        ...state,
        step: 'mongo-url',
        query: '',
        passphrase: null,
        databaseUrl: null,
        message: 'MongoDB URL (masked). Never stored by the TUI.',
      });
    case 'mongo-passphrase-confirm':
      return unchanged({
        ...state,
        step: 'mongo-passphrase',
        query: '',
        passphrase: null,
        message: 'Owner passphrase (masked). Enter continues; Esc back.',
      });
    case 'mongo-recovery-passphrase':
      return unchanged({
        ...state,
        step: 'mongo-passphrase-confirm',
        query: '',
        recoveryPassphrase: null,
        message: 'Confirm owner passphrase (masked). Enter continues to recovery kit.',
      });
    case 'mongo-recovery-passphrase-confirm':
      return unchanged({
        ...state,
        step: 'mongo-recovery-passphrase',
        query: '',
        recoveryPassphrase: null,
        message:
          'Recovery-kit passphrase (masked; separate from owner). Enter continues.',
      });
    case 'mongo-recovery-file':
      return unchanged({
        ...state,
        step: 'mongo-recovery-passphrase-confirm',
        query: '',
        recoveryFile: null,
        message: 'Confirm recovery-kit passphrase (masked).',
      });
    default:
      return unchanged({
        ...state,
        step: 'storage',
        query: '',
        message: 'Back to storage choice.',
      });
  }
}

function validateProfileId(profileId: string): string | null {
  const parsed = profileIdSchema.safeParse(profileId);
  if (parsed.success) return null;
  return 'Profile id must be 1–128 chars: letters, digits, . _ ~ - (start alnum).';
}

function validatePathInput(value: string, label: string): string | null {
  if (value.length === 0 || value.includes('\0')) {
    return `${label} path is invalid.`;
  }
  return null;
}

function passphraseTooShort(value: string): boolean {
  return new TextEncoder().encode(value).byteLength < MIN_ONBOARDING_PASSPHRASE_BYTES;
}

function isInputStep(step: OnboardingStep): boolean {
  return (
    step === 'file-profile-id' ||
    step === 'file-data-file' ||
    step === 'file-key-file' ||
    step === 'file-passphrase' ||
    step === 'file-passphrase-confirm' ||
    step === 'file-recovery-passphrase' ||
    step === 'file-recovery-passphrase-confirm' ||
    step === 'file-recovery-file' ||
    step === 'mongo-profile-id' ||
    step === 'mongo-database' ||
    step === 'mongo-key-file' ||
    step === 'mongo-url' ||
    step === 'mongo-passphrase' ||
    step === 'mongo-passphrase-confirm' ||
    step === 'mongo-recovery-passphrase' ||
    step === 'mongo-recovery-passphrase-confirm' ||
    step === 'mongo-recovery-file'
  );
}

function isSecretStep(step: OnboardingStep): boolean {
  return (
    step === 'file-passphrase' ||
    step === 'file-passphrase-confirm' ||
    step === 'file-recovery-passphrase' ||
    step === 'file-recovery-passphrase-confirm' ||
    step === 'mongo-url' ||
    step === 'mongo-passphrase' ||
    step === 'mongo-passphrase-confirm' ||
    step === 'mongo-recovery-passphrase' ||
    step === 'mongo-recovery-passphrase-confirm'
  );
}

function appendText(
  state: OnboardingState,
  text: string | undefined,
  limit: number,
): OnboardingTransition {
  if (text === undefined || text.length === 0) return unchanged(state);
  const chunk =
    text.length > 1 ? sanitizePasteText(text) : isPrintable(text) ? text : '';
  if (chunk.length === 0) return unchanged(state);
  const glyphs = Array.from(state.query);
  const cursor = Math.min(glyphs.length, state.cursor ?? glyphs.length);
  let inserted = '';
  for (const glyph of Array.from(chunk)) {
    if (state.query.length + inserted.length + glyph.length > limit) break;
    inserted += glyph;
  }
  const input = Array.from(inserted);
  return unchanged({
    ...state,
    query: [...glyphs.slice(0, cursor), ...input, ...glyphs.slice(cursor)].join(''),
    cursor: cursor + input.length,
    connectionVerified: state.step === 'mongo-url' ? false : state.connectionVerified,
  });
}

function isPrintable(value: string | undefined): value is string {
  return typeof value === 'string' && value.length === 1 && !/\p{C}/u.test(value);
}

function unchanged(state: OnboardingState): OnboardingTransition {
  return { state, effect: { kind: 'none' } };
}

function effect(
  state: OnboardingState,
  nextEffect: OnboardingEffect,
): OnboardingTransition {
  return { state, effect: nextEffect };
}

const FILE_FOCUS_STEPS: readonly OnboardingStep[] = [
  'welcome',
  'storage',
  'file-profile-id',
  'file-data-file',
  'file-key-file',
  'file-passphrase',
  'file-passphrase-confirm',
  'file-recovery-passphrase',
  'file-recovery-passphrase-confirm',
  'file-recovery-file',
  'review',
  'creating',
  'enable-session',
  'success',
];

const MONGO_FOCUS_STEPS: readonly OnboardingStep[] = [
  'welcome',
  'storage',
  'mongo-profile-id',
  'mongo-database',
  'mongo-key-file',
  'mongo-url',
  'mongo-passphrase',
  'mongo-passphrase-confirm',
  'mongo-recovery-passphrase',
  'mongo-recovery-passphrase-confirm',
  'mongo-recovery-file',
  'review',
  'creating',
  'enable-session',
  'success',
];

/** Active onboarding step for operators: index, title, and type-here cue. */
export function onboardingStepFocus(
  step: OnboardingStep,
  storage?: OnboardingStorage | null,
): Readonly<{ index: number; total: number; title: string; cue: string }> {
  const chain =
    step.startsWith('mongo') || storage === 'mongodb'
      ? MONGO_FOCUS_STEPS
      : FILE_FOCUS_STEPS;
  const index = Math.max(0, chain.indexOf(step));
  const title = onboardingFocusTitle(step);
  const cue =
    step === 'review'
      ? 'REVIEW SETTINGS - ENTER CREATES'
      : step === 'creating'
        ? 'PLEASE WAIT — do not type'
        : step === 'error' || step === 'success'
          ? 'THIS STEP IS ACTIVE'
          : step.includes('passphrase') || step === 'mongo-url'
            ? 'TYPE HERE (masked)'
            : step === 'storage' || step === 'welcome'
              ? 'THIS STEP IS ACTIVE'
              : 'TYPE HERE';
  return {
    index: step === 'error' ? chain.length : index + 1,
    total: chain.length,
    title,
    cue,
  };
}

function onboardingFocusTitle(step: OnboardingStep): string {
  switch (step) {
    case 'welcome':
      return 'Welcome';
    case 'storage':
      return 'Choose storage';
    case 'file-profile-id':
    case 'mongo-profile-id':
      return 'Profile id';
    case 'file-data-file':
      return 'Data file';
    case 'file-key-file':
    case 'mongo-key-file':
      return 'Key file';
    case 'mongo-database':
      return 'Database name';
    case 'mongo-url':
      return 'MongoDB URL';
    case 'file-passphrase':
    case 'mongo-passphrase':
      return 'Owner passphrase';
    case 'file-passphrase-confirm':
    case 'mongo-passphrase-confirm':
      return 'Confirm owner passphrase';
    case 'file-recovery-passphrase':
    case 'mongo-recovery-passphrase':
      return 'Recovery-kit passphrase';
    case 'file-recovery-passphrase-confirm':
    case 'mongo-recovery-passphrase-confirm':
      return 'Confirm recovery-kit passphrase';
    case 'file-recovery-file':
    case 'mongo-recovery-file':
      return 'Recovery kit path';
    case 'review':
      return 'Review setup';
    case 'creating':
      return 'Creating vault';
    case 'enable-session':
      return 'Session unlock';
    case 'success':
      return 'Setup complete';
    case 'error':
      return 'Setup failed';
    default:
      return 'Input';
  }
}

/** Presentational snapshot for deterministic tests. */
export function describeOnboardingScreen(state: OnboardingState): string {
  const focus = onboardingStepFocus(state.step, state.storage);
  return [
    `step=${state.step}`,
    `storage=${state.storage ?? '-'}`,
    `idx=${String(state.storageIndex)}`,
    `queryLen=${String(state.query.length)}`,
    `completed=${String(state.completed)}`,
    `quit=${String(state.quit)}`,
    `focus=${String(focus.index)}/${String(focus.total)}:${focus.title}:${focus.cue}`,
  ].join(' ');
}
