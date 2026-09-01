/**
 * The interactive, non-secret part of `kavrix init`.
 *
 * This module deliberately knows nothing about readline, files, MongoDB, or
 * secret input. The command owns those concerns and injects a line reader and
 * a writer. Keeping the boundary this small also makes the onboarding flow
 * usable in tests without a terminal or a TUI dependency.
 */

const ANSI_ESCAPE = '\u001b';
const ANSI_RESET = `${ANSI_ESCAPE}[0m`;
const MAX_NON_SECRET_INPUT_LENGTH = 4_096;

const DEFAULT_DATA_FILE = './kavrix.vault';
const DEFAULT_KEY_FILE = './kavrix.key';
const DEFAULT_COLLECTION = 'kavrix_vaults';

export type InitOnboardingStorage = 'file' | 'mongodb';

export type InitOnboardingPatch =
  | Readonly<{
      datastore: 'file';
      dataFile: string;
      keyFile: string;
    }>
  | Readonly<{
      datastore: 'mongodb';
      database?: string;
      collection: string;
      keyFile: string;
    }>;

export type InitOnboardingOptions = Readonly<{
  /** Read one visible line. The prompt is always static and contains no input. */
  question: (prompt: string) => Promise<string>;
  /** Select a storage backend with terminal navigation when available. */
  selectStorage?: () => Promise<InitOnboardingStorage | 'back' | 'cancel'>;
  /** Resolve and validate destinations before advancing to secret input. */
  validateDestination?: (patch: InitOnboardingPatch) => Promise<InitOnboardingPatch>;
  /** Write static onboarding text (normally to stderr). */
  write: (text: string) => void;
  /** ANSI styling is enabled only when explicitly requested. */
  color?: boolean;
}>;

export type InitOnboardingCompleteOptions = Readonly<{
  /** Write static completion text (normally to stderr). */
  write: (text: string) => void;
  /** ANSI styling is enabled only when explicitly requested. */
  color?: boolean;
  /** The datastore the wizard actually configured, for accurate next steps. */
  datastore?: InitOnboardingStorage;
  /** A database-bound profile is selected and will route flat commands. */
  profileHijackWarning?: boolean;
}>;

export class InitOnboardingCancelledError extends Error {
  public constructor() {
    super('Setup cancelled. No vault was created.');
    this.name = 'InitOnboardingCancelledError';
  }
}

export type InitOnboardingDestinationErrorKind =
  | 'unsafe-default-directory'
  | 'unsafe-key-file'
  | 'invalid-database'
  | 'invalid-collection'
  | 'invalid-destination';

export class InitOnboardingDestinationError extends Error {
  public constructor(public readonly kind: InitOnboardingDestinationErrorKind) {
    super('The selected destination is invalid.');
    this.name = 'InitOnboardingDestinationError';
  }
}

type InitOnboardingStep = 'welcome' | 'storage' | 'destination' | 'protect-key';

type ReadResult =
  | Readonly<{ kind: 'value'; value: string }>
  | Readonly<{ kind: 'back' }>
  | Readonly<{ kind: 'cancel' }>;

type DestinationResult =
  Readonly<{ kind: 'back' }> | Readonly<{ kind: 'done'; patch: InitOnboardingPatch }>;

/**
 * Run the four-step interactive onboarding flow for root `kavrix init`.
 *
 * The returned object is an option patch for the existing init handler. It
 * contains only routing and path values; database URIs and passphrases are
 * intentionally outside this API and must continue through LocalSecretInput.
 */
export async function runInitOnboarding(
  options: InitOnboardingOptions,
): Promise<InitOnboardingPatch> {
  const color = options.color === true;
  const style = createStyler(color);
  let step: InitOnboardingStep = 'welcome';
  let storage: InitOnboardingStorage | undefined;
  let patch: InitOnboardingPatch | undefined;

  for (;;) {
    if (step === 'welcome') {
      writeWelcome(options.write, style);
      const result = await readControl(options, style('Press Enter to continue', '2'));
      if (result.kind === 'cancel') throw new InitOnboardingCancelledError();
      if (result.kind === 'back') {
        writeNotice(options.write, style, 'You are already at the first step.');
        continue;
      }
      if (result.value.trim().length > 0) {
        writeNotice(
          options.write,
          style,
          'Press Enter to continue, B to go back, or Q to cancel.',
        );
        continue;
      }
      step = 'storage';
      continue;
    }

    if (step === 'storage') {
      writeStorageChoice(options.write, style);
      if (options.selectStorage !== undefined) {
        const selected = await options.selectStorage();
        if (selected === 'cancel') throw new InitOnboardingCancelledError();
        if (selected === 'back') {
          step = 'welcome';
          continue;
        }
        storage = selected;
        patch = undefined;
        step = 'destination';
        continue;
      }
      const result = await readChoice(
        options,
        style('Choose storage [1/2, Enter=1, B=back, Q=cancel]', '2'),
      );
      if (result.kind === 'cancel') throw new InitOnboardingCancelledError();
      if (result.kind === 'back') {
        step = 'welcome';
        continue;
      }
      if (result.value === '1' || result.value.length === 0) {
        storage = 'file';
      } else if (result.value === '2') {
        storage = 'mongodb';
      } else {
        writeNotice(
          options.write,
          style,
          'Choose 1 for local encrypted file or 2 for MongoDB.',
        );
        continue;
      }
      patch = undefined;
      step = 'destination';
      continue;
    }

    if (step === 'destination') {
      if (storage === undefined) {
        // This is an internal invariant, but keeping the flow fail-closed is
        // preferable if the state is ever changed during future maintenance.
        step = 'storage';
        continue;
      }
      const result = await collectDestination(options, style, storage, patch);
      if (result.kind === 'back') {
        step = 'storage';
        patch = undefined;
        continue;
      }
      try {
        patch =
          options.validateDestination === undefined
            ? result.patch
            : await options.validateDestination(result.patch);
      } catch (error) {
        if (!(error instanceof InitOnboardingDestinationError)) throw error;
        writeNotice(options.write, style, destinationValidationMessage(error));
        patch = result.patch;
        continue;
      }
      step = 'protect-key';
      continue;
    }

    writeProtectKey(options.write, style);
    const result = await readControl(
      options,
      style('Press Enter for masked secret prompts', '2'),
    );
    if (result.kind === 'cancel') throw new InitOnboardingCancelledError();
    if (result.kind === 'back') {
      step = 'destination';
      continue;
    }
    if (result.value.trim().length > 0) {
      writeNotice(
        options.write,
        style,
        'Press Enter to begin the masked secret prompts.',
      );
      continue;
    }
    if (patch === undefined) {
      // See the invariant guard above. No partial options leave this module.
      step = 'storage';
      continue;
    }
    return patch;
  }
}

/**
 * Render the post-init handoff. Routing hints adapt to the configured
 * datastore and warn when an ambient profile will hijack flat commands; the
 * function never receives secret material.
 */
export function writeInitOnboardingComplete(
  options: InitOnboardingCompleteOptions,
): void {
  const style = createStyler(options.color === true);
  const datastore = options.datastore ?? 'file';
  const routing =
    datastore === 'file'
      ? '--datastore file --data-file <vault-path>'
      : '--datastore mongodb';
  const lines = [
    '',
    style('SETUP COMPLETE', '1;32'),
    '',
    `${style('[OK]', '32')} Vault initialized with client-side encryption.`,
    `${style('[OK]', '32')} Datastore configured for ciphertext-only records.`,
    `${style('[OK]', '32')} Portable key protected by your passphrase.`,
    `${style('[!]', '33')} Recovery not configured; init does not create a recovery kit.`,
    '',
  ];
  if (options.profileHijackWarning === true) {
    lines.push(
      style('NOTICE', '1;33') +
        ' A database-bound datastore profile is currently selected.',
      'Flat commands (`put`, `get`, `list`, `run`, ...) route through that',
      'profile and use its stored default vault. If none is selected, run',
      '`kavrix db vault use <id>`. Pass explicit `--datastore/--data-file`',
      'flags (as below) to bypass it, or select a',
      'different profile with `kavrix db profile use <id>`.',
      '',
    );
  }
  lines.push(
    'Next steps:',
    `  kavrix recovery create --recovery-file <protected-path> ${routing}`,
    `  kavrix put <name> ${routing} --key-file <key-path> --passphrase-stdin`,
    `  kavrix list ${routing} --key-file <key-path> --passphrase-stdin`,
    '',
    'Keep the portable key and recovery kit in separate secure locations.',
    '',
  );
  options.write(lines.join('\n'));
}

async function collectDestination(
  options: InitOnboardingOptions,
  style: (text: string, code: string) => string,
  storage: InitOnboardingStorage,
  previous: InitOnboardingPatch | undefined,
): Promise<DestinationResult> {
  writeDestinationIntro(options.write, style, storage);
  const fields =
    storage === 'file'
      ? ([
          {
            key: 'dataFile',
            prompt: 'Data file path (Enter for default)',
            fallback: DEFAULT_DATA_FILE,
          },
          {
            key: 'keyFile',
            prompt: 'Portable key file path (Enter for default)',
            fallback: DEFAULT_KEY_FILE,
          },
        ] as const)
      : ([
          {
            key: 'database',
            prompt: 'MongoDB database name (Enter to infer from the URI)',
            fallback: undefined,
          },
          {
            key: 'collection',
            prompt: 'MongoDB collection name (Enter for default)',
            fallback: DEFAULT_COLLECTION,
          },
          {
            key: 'keyFile',
            prompt: 'Portable key file path (Enter for default)',
            fallback: DEFAULT_KEY_FILE,
          },
        ] as const);
  const values: Partial<{
    dataFile: string;
    database: string;
    collection: string;
    keyFile: string;
  }> = {
    ...(previous?.datastore === 'file' ? { dataFile: previous.dataFile } : {}),
    ...(previous?.datastore === 'mongodb' && previous.database !== undefined
      ? { database: previous.database }
      : {}),
    ...(previous?.datastore === 'mongodb' ? { collection: previous.collection } : {}),
    ...(previous?.keyFile === undefined ? {} : { keyFile: previous.keyFile }),
  };

  let index = 0;
  while (index < fields.length) {
    const field = fields[index];
    if (field === undefined) return { kind: 'back' };
    const result = await readField(options, style, field.prompt, field.fallback);
    if (result.kind === 'cancel') throw new InitOnboardingCancelledError();
    if (result.kind === 'back') {
      if (index === 0) return { kind: 'back' };
      index -= 1;
      continue;
    }
    values[field.key] = result.value;
    index += 1;
  }

  const keyFile = values.keyFile;
  if (keyFile === undefined) return { kind: 'back' };
  if (storage === 'file') {
    const dataFile = values.dataFile;
    if (dataFile === undefined) return { kind: 'back' };
    return {
      kind: 'done',
      patch: { datastore: 'file', dataFile, keyFile },
    };
  }
  const database = values.database;
  const collection = values.collection;
  if (collection === undefined) return { kind: 'back' };
  return {
    kind: 'done',
    patch: {
      datastore: 'mongodb',
      ...(database === undefined || database.length === 0 ? {} : { database }),
      collection,
      keyFile,
    },
  };
}

async function readField(
  options: InitOnboardingOptions,
  style: (text: string, code: string) => string,
  prompt: string,
  fallback: string | undefined,
): Promise<ReadResult> {
  for (;;) {
    const result = await readControl(options, style(prompt, '2'));
    if (result.kind !== 'value') return result;
    const normalized = normalizeField(result.value, fallback);
    if (normalized !== undefined) return { kind: 'value', value: normalized };
    writeNotice(
      options.write,
      style,
      'Enter a non-empty value, or press Enter for the default.',
    );
  }
}

async function readChoice(
  options: InitOnboardingOptions,
  prompt: string,
): Promise<ReadResult> {
  const result = await readControl(options, prompt);
  if (result.kind !== 'value') return result;
  return { kind: 'value', value: result.value.trim() };
}

async function readControl(
  options: InitOnboardingOptions,
  prompt: string,
): Promise<ReadResult> {
  const raw = await options.question(`${prompt}: `);
  if (typeof raw !== 'string') return { kind: 'value', value: '' };
  const trimmed = raw.trim();
  if (
    trimmed.toLowerCase() === 'q' ||
    trimmed.toLowerCase() === 'quit' ||
    trimmed.toLowerCase() === 'cancel' ||
    raw === '\u0003'
  ) {
    return { kind: 'cancel' };
  }
  if (trimmed.toLowerCase() === 'b' || trimmed.toLowerCase() === 'back') {
    return { kind: 'back' };
  }
  return { kind: 'value', value: raw };
}

function normalizeField(raw: string, fallback: string | undefined): string | undefined {
  if (hasUnsafeControl(raw) || raw.length > MAX_NON_SECRET_INPUT_LENGTH)
    return undefined;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return fallback ?? '';
  return trimmed;
}

function hasUnsafeControl(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
}

function writeWelcome(
  write: (text: string) => void,
  style: (text: string, code: string) => string,
): void {
  write(
    [
      '',
      style('STEP 1 / WELCOME & SECURITY', '1;36'),
      '',
      'Kavrix encrypts credentials on this device before they leave it.',
      'The selected datastore receives ciphertext-only records and cannot unlock your vault.',
      'Your portable key and recovery material are essential. Losing them can make',
      'the encrypted vault permanently unrecoverable.',
      '',
      'This short setup chooses where ciphertext lives and where the protected key lives.',
      '',
    ].join('\n'),
  );
}

function writeStorageChoice(
  write: (text: string) => void,
  style: (text: string, code: string) => string,
): void {
  write(
    [
      '',
      style('STEP 2 / STORAGE', '1;36'),
      '',
      'Local encrypted file — simplest choice for one device',
      'MongoDB — sync opaque ciphertext through your own MongoDB deployment',
      '',
      'Both choices preserve client-side encryption. The datastore never receives a vault key.',
      'Use Up/Down and Enter to select. Esc goes back; Ctrl+C cancels.',
      '',
    ].join('\n'),
  );
}

function writeDestinationIntro(
  write: (text: string) => void,
  style: (text: string, code: string) => string,
  storage: InitOnboardingStorage,
): void {
  const destination = storage === 'file' ? 'LOCAL FILE' : 'MONGODB';
  write(
    [
      '',
      style(`STEP 3 / ${destination} DESTINATION`, '1;36'),
      '',
      storage === 'file'
        ? 'Choose the encrypted vault file and protected portable-key file paths.'
        : 'Choose the database name, ciphertext collection, and protected key-file path.',
      storage === 'file'
        ? 'The key file must be in a private directory that only your account can access.'
        : 'Your MongoDB URL is entered next in a masked prompt so credentials never appear on screen.',
      storage === 'file'
        ? 'Press Enter on a blank field to use the protected Kavrix user-data default.'
        : 'Atlas, replica-set, and sharded-cluster URLs are accepted, including replicaSet and TLS options. Transactional database-container commands require a replica set or sharded cluster; this single-vault setup also supports standalone MongoDB.',
      '',
    ].join('\n'),
  );
}

function writeProtectKey(
  write: (text: string) => void,
  style: (text: string, code: string) => string,
): void {
  write(
    [
      '',
      style('STEP 4 / CONNECT & PROTECT', '1;36'),
      '',
      'Next, masked prompts collect the MongoDB URL when needed, then your passphrase.',
      'The MongoDB URL selects the remote ciphertext store; it may include replicaSet and TLS options.',
      'The passphrase is never shown, logged, or sent to the datastore.',
      'Keep the portable key and a recovery kit safe and separate from the vault.',
      'Init does not create a recovery kit; after setup, run `kavrix recovery create`.',
      '',
      style('Press Enter to begin the masked secret prompts.', '1'),
      '',
    ].join('\n'),
  );
}

function destinationValidationMessage(error: unknown): string {
  if (error instanceof InitOnboardingDestinationError) {
    if (error.kind === 'unsafe-default-directory') {
      return 'Kavrix could not safely use its protected default directory. The parent directory permissions or filesystem protections do not meet the fail-closed vault/key-file policy. Choose vault and key paths inside an existing private directory that only your account can modify.';
    }
    if (error.kind === 'unsafe-key-file') {
      return 'That portable-key path is not private enough. Choose a path inside a directory accessible only to your account, or press Enter to use Kavrix’s protected default.';
    }
    if (error.kind === 'invalid-database') {
      return 'That MongoDB database name is invalid. Use 1–63 letters, numbers, underscores, or hyphens.';
    }
    if (error.kind === 'invalid-collection') {
      return 'That MongoDB collection name is invalid. Use 1–64 letters, numbers, underscores, or hyphens.';
    }
  }
  return 'Those destinations are not safe to use. Review this step and try again.';
}

function writeNotice(
  write: (text: string) => void,
  style: (text: string, code: string) => string,
  message: string,
): void {
  write(`${style(message, '33')}\n`);
}

function createStyler(color: boolean): (text: string, code: string) => string {
  if (!color) return (text) => text;
  return (text, code) => `${ANSI_ESCAPE}[${code}m${text}${ANSI_RESET}`;
}
