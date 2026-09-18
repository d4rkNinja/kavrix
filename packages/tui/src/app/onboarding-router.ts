import { profileIdSchema } from '@kavrix/schemas';

import type { AppBackendAction } from './backend.js';
import { defaultFileProfilePaths, defaultMongoProfilePaths } from './paths.js';
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
  | 'mongo-profile-id'
  | 'mongo-database'
  | 'mongo-key-file'
  | 'mongo-url'
  | 'mongo-passphrase'
  | 'mongo-passphrase-confirm'
  | 'creating'
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
  readonly message: string | null;
  readonly error: string | null;
  readonly ascii: boolean;
  readonly color: boolean;
  readonly width: number;
  readonly height: number;
  readonly quit: boolean;
  readonly completed: boolean;
  readonly completedProfileId: string | null;
  readonly completedDatastore: OnboardingStorage | null;
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
    message: 'Welcome — press Enter to begin setup.',
    error: null,
    ascii: options.ascii ?? false,
    color: options.color ?? true,
    width: Math.max(40, options.width ?? 80),
    height: Math.max(12, options.height ?? 24),
    quit: false,
    completed: false,
    completedProfileId: null,
    completedDatastore: null,
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
    if (action.ok) {
      return unchanged({
        ...state,
        step: 'success',
        query: '',
        passphrase: null,
        databaseUrl: null,
        message: action.notice ?? 'Vault ready.',
        error: null,
        completed: true,
        completedProfileId: action.profileId,
        completedDatastore: action.datastore ?? state.storage,
      });
    }
    return unchanged({
      ...state,
      step: 'error',
      query: '',
      passphrase: null,
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
        message: 'Confirm passphrase (masked). Enter creates the vault.',
      });
    }
    case 'file-passphrase-confirm': {
      const profileId = state.profileId;
      const dataFile = state.dataFile;
      const keyFile = state.keyFile;
      const passphrase = state.passphrase;
      if (
        profileId === null ||
        dataFile === null ||
        keyFile === null ||
        passphrase === null
      ) {
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
      return effect(
        {
          ...state,
          step: 'creating',
          query: '',
          passphrase: null,
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
        message: 'Confirm passphrase (masked). Enter creates the vault.',
      });
    }
    case 'mongo-passphrase-confirm': {
      const profileId = state.profileId;
      const database = state.database;
      const keyFile = state.keyFile;
      const databaseUrl = state.databaseUrl;
      const passphrase = state.passphrase;
      if (
        profileId === null ||
        database === null ||
        keyFile === null ||
        databaseUrl === null ||
        passphrase === null
      ) {
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
      return effect(
        {
          ...state,
          step: 'creating',
          query: '',
          passphrase: null,
          databaseUrl: null,
          message: `Creating MongoDB profile '${profileId}'…`,
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
    step === 'mongo-profile-id' ||
    step === 'mongo-database' ||
    step === 'mongo-key-file' ||
    step === 'mongo-url' ||
    step === 'mongo-passphrase' ||
    step === 'mongo-passphrase-confirm'
  );
}

function isSecretStep(step: OnboardingStep): boolean {
  return (
    step === 'file-passphrase' ||
    step === 'file-passphrase-confirm' ||
    step === 'mongo-url' ||
    step === 'mongo-passphrase' ||
    step === 'mongo-passphrase-confirm'
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

/** Presentational snapshot for deterministic tests. */
export function describeOnboardingScreen(state: OnboardingState): string {
  return [
    `step=${state.step}`,
    `storage=${state.storage ?? '-'}`,
    `idx=${String(state.storageIndex)}`,
    `queryLen=${String(state.query.length)}`,
    `completed=${String(state.completed)}`,
    `quit=${String(state.quit)}`,
  ].join(' ');
}
