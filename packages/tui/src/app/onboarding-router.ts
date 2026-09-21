import { profileIdSchema } from '@kavrix/schemas';

import type { AppBackendAction } from './backend.js';
import {
  defaultFileProfilePaths,
  defaultMongoProfilePaths,
  defaultRecoveryFilePath,
} from './paths.js';
import { sanitizePasteText } from './router.js';

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
  | 'creating'
  | 'enable-session'
  | 'success'
  | 'error';

export interface OnboardingKey {
  readonly name?:
    'up' | 'down' | 'left' | 'right' | 'tab' | 'return' | 'escape' | 'backspace';
  readonly text?: string;
  readonly ctrl?: boolean;
}

export interface OnboardingState {
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
  | Readonly<{ type: 'resize'; width: number; height: number }>
  | Readonly<{ type: 'key'; key: OnboardingKey }>
  | Readonly<{
      type: 'backend-result';
      ok: boolean;
      notice: string | null;
      profileId: string | null;
      datastore: OnboardingStorage | null;
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
  if (action.type === 'resize') {
    return unchanged({
      ...state,
      width: Math.max(40, action.width),
      height: Math.max(12, action.height),
    });
  }

  if (action.type === 'backend-result') {
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
    if (key.name === 'escape') {
      return stepBack(state);
    }
    if (key.name === 'backspace') {
      return unchanged({ ...state, query: removeLast(state.query) });
    }
    if (key.name === 'return') {
      return commitInput(state);
    }
    const limit = isSecretStep(state.step) ? 1024 : 512;
    return appendText(state, key.text, limit);
  }

  return unchanged(state);
}

function commitInput(state: OnboardingState): OnboardingTransition {
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
      return unchanged({
        ...state,
        dataFile,
        step: 'file-key-file',
        query: defaultFileProfilePaths(profileId).keyFile,
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
        query: defaultRecoveryFilePath(profileId),
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
      return effect(
        {
          ...state,
          recoveryFile,
          step: 'creating',
          query: '',
          passphrase: null,
          recoveryPassphrase: null,
          message: `Creating file profile '${profileId}' and recovery kit…`,
        },
        {
          kind: 'backend',
          action: {
            type: 'create-file-profile',
            profileId,
            dataFile,
            keyFile,
            passphrase,
            recoveryFile,
            recoveryPassphrase,
          },
        },
      );
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
        query: defaultRecoveryFilePath(profileId),
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
      return effect(
        {
          ...state,
          recoveryFile,
          step: 'creating',
          query: '',
          passphrase: null,
          recoveryPassphrase: null,
          databaseUrl: null,
          message: `Creating MongoDB profile '${profileId}' and recovery kit…`,
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
            recoveryFile,
            recoveryPassphrase,
          },
        },
      );
    }
    default:
      return unchanged(state);
  }
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
  return unchanged({
    ...state,
    query: `${state.query}${chunk}`.slice(0, limit),
  });
}

function isPrintable(value: string | undefined): value is string {
  return typeof value === 'string' && value.length === 1 && !/\p{C}/u.test(value);
}

function removeLast(value: string): string {
  return Array.from(value).slice(0, -1).join('');
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
  'creating',
  'enable-session',
  'success',
];

/** Active onboarding step for operators: index, title, and type-here cue. */
export function onboardingStepFocus(
  step: OnboardingStep,
): Readonly<{ index: number; total: number; title: string; cue: string }> {
  const chain = step.startsWith('mongo') ? MONGO_FOCUS_STEPS : FILE_FOCUS_STEPS;
  const index = Math.max(0, chain.indexOf(step));
  const title = onboardingFocusTitle(step);
  const cue =
    step === 'creating'
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
  const focus = onboardingStepFocus(state.step);
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
