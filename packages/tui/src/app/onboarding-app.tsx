import { Box, Text, render, useApp, useInput, usePaste, useStdout } from 'ink';
import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react';

import { BrandBanner } from '../showcase.js';
import { sanitizeTerminalText } from '../terminal-text.js';
import type { InteractiveAppBackend, AppBackendAction } from './backend.js';
import {
  createInitialOnboardingState,
  transitionOnboarding,
  type OnboardingKey,
  type OnboardingState,
  type OnboardingStorage,
} from './onboarding-router.js';
import { resolveAppPresentation, type AppAccent } from './theme.js';
import { KeyChip, Panel, SelectRow, StatusPill } from './widgets.js';

export interface KavrixOnboardingAppProps {
  readonly backend: InteractiveAppBackend;
  readonly ascii?: boolean;
  readonly color?: boolean;
  readonly onComplete?: (result: OnboardingAppResult) => void;
}

export type OnboardingAppResult =
  | Readonly<{
      status: 'completed';
      profileId: string;
      datastore: OnboardingStorage;
    }>
  | Readonly<{ status: 'cancelled' }>
  | Readonly<{ status: 'failed'; message: string }>;

export interface MountOnboardingAppOptions {
  readonly backend: InteractiveAppBackend;
  readonly stdout?: NodeJS.WriteStream;
  readonly stdin?: NodeJS.ReadStream;
  readonly ascii?: boolean;
  readonly color?: boolean;
}

export interface OnboardingAppHandle {
  waitUntilExit: () => Promise<OnboardingAppResult>;
  unmount: () => void;
}

function tint(
  enabled: boolean,
  accent: AppAccent,
): Readonly<{ color: AppAccent }> | Readonly<Record<string, never>> {
  return enabled ? { color: accent } : {};
}

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

export function KavrixOnboardingApp({
  backend,
  ascii,
  color,
  onComplete,
}: KavrixOnboardingAppProps): ReactElement {
  const { stdout } = useStdout();
  const { exit } = useApp();
  const presentation = resolveAppPresentation({
    ...(ascii === undefined ? {} : { ascii }),
    ...(color === undefined ? {} : { color }),
  });
  const [state, setState] = useState(() =>
    createInitialOnboardingState({
      width: stdout.columns,
      height: stdout.rows,
      ascii: presentation.ascii,
      color: presentation.color,
    }),
  );
  const stateRef = useRef(state);
  const backendRef = useRef(backend);
  const onCompleteRef = useRef(onComplete);
  const exitRef = useRef(exit);
  const finishedRef = useRef(false);
  backendRef.current = backend;
  onCompleteRef.current = onComplete;
  exitRef.current = exit;

  const finish = useCallback((result: OnboardingAppResult): void => {
    if (finishedRef.current) return;
    finishedRef.current = true;
    onCompleteRef.current?.(result);
    exitRef.current();
  }, []);

  const runBackend = useCallback(async (action: AppBackendAction): Promise<void> => {
    try {
      const result = await backendRef.current.dispatch(action);
      const ok = result.snapshot.noticeTone === 'success';
      const next = transitionOnboarding(stateRef.current, {
        type: 'backend-result',
        ok,
        notice: result.snapshot.notice,
        profileId: result.snapshot.home.profileId,
        datastore:
          result.snapshot.home.datastore === 'mongodb'
            ? 'mongodb'
            : result.snapshot.home.datastore === 'file'
              ? 'file'
              : null,
      });
      stateRef.current = next.state;
      setState(next.state);
    } catch {
      const next = transitionOnboarding(stateRef.current, {
        type: 'backend-result',
        ok: false,
        notice: 'Operation failed safely.',
        profileId: null,
        datastore: null,
      });
      stateRef.current = next.state;
      setState(next.state);
    }
  }, []);

  const dispatchKey = useCallback(
    (key: OnboardingKey): void => {
      const next = transitionOnboarding(stateRef.current, { type: 'key', key });
      stateRef.current = next.state;
      setState(next.state);
      if (next.effect.kind === 'backend') {
        void runBackend(next.effect.action);
      }
    },
    [runBackend],
  );

  useEffect(() => {
    const resize = (): void => {
      const next = transitionOnboarding(stateRef.current, {
        type: 'resize',
        width: stdout.columns,
        height: stdout.rows,
      });
      stateRef.current = next.state;
      setState(next.state);
    };
    stdout.on('resize', resize);
    return () => {
      stdout.off('resize', resize);
    };
  }, [stdout]);

  useEffect(() => {
    if (!state.quit) return;
    if (
      state.completed &&
      state.completedProfileId !== null &&
      state.completedDatastore !== null
    ) {
      finish({
        status: 'completed',
        profileId: state.completedProfileId,
        datastore: state.completedDatastore,
      });
      return;
    }
    if (state.step === 'error' && state.error !== null) {
      finish({ status: 'failed', message: state.error });
      return;
    }
    finish({ status: 'cancelled' });
  }, [finish, state]);

  useInput((input, key) => {
    const mapped = mapInkInput(input, key);
    if (mapped !== null) dispatchKey(mapped);
  });

  usePaste((text) => {
    const cleaned = sanitizePasteTextLocal(text);
    if (cleaned.length === 0) return;
    dispatchKey({ text: cleaned });
  });

  return <OnboardingChrome state={state} />;
}

function sanitizePasteTextLocal(raw: string): string {
  let text = raw;
  // eslint-disable-next-line no-control-regex -- strip bracketed-paste / OSC markers
  text = text.replace(/\x1b\[200~/gu, '').replace(/\x1b\[201~/gu, '');
  // eslint-disable-next-line no-control-regex -- strip OSC sequences terminated by BEL/ST
  text = text.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/gu, '');
  text = text.replace(/\r/gu, '');
  text = text.replace(/^\n+/u, '').replace(/\n+$/u, '');
  text = text.replace(/\p{C}/gu, '');
  return text;
}

function OnboardingChrome({
  state,
}: Readonly<{ state: OnboardingState }>): ReactElement {
  const { color, ascii, width, height } = state;
  const accent: AppAccent =
    state.step === 'success' ? 'green' : state.step === 'error' ? 'red' : 'cyan';

  return (
    <Box flexDirection="column" width={width} height={height}>
      <Panel accent={accent} ascii={ascii} color={color} paddingX={1} paddingY={0}>
        <BrandBanner color={color} ascii={ascii} dualTone />
        <Box flexDirection="row" columnGap={1} flexWrap="wrap" marginTop={0}>
          <StatusPill
            label="mode"
            value="init"
            accent="cyan"
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="step"
            value={state.step}
            accent={accent}
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="storage"
            value={state.storage ?? (state.storageIndex === 0 ? 'file?' : 'mongo?')}
            accent="blue"
            color={color}
            ascii={ascii}
          />
        </Box>
      </Panel>

      <Box flexDirection="column" flexGrow={1} paddingX={1} paddingY={1}>
        {renderOnboardingBody(state)}
      </Box>

      <Box flexDirection="row" columnGap={2} paddingX={1}>
        <KeyChip keyLabel="Enter" hint="continue" color={color} />
        <KeyChip keyLabel="Esc" hint="back / cancel" color={color} keyAccent="yellow" />
        <KeyChip keyLabel="q" hint="quit" color={color} keyAccent="red" />
      </Box>
      {state.message === null && state.error === null ? null : (
        <Box paddingX={1}>
          <Text {...tint(color, state.error === null ? 'cyan' : 'red')}>
            {safe(state.error ?? state.message ?? '', ascii)}
          </Text>
        </Box>
      )}
    </Box>
  );
}

function renderOnboardingBody(state: OnboardingState): ReactElement {
  const { ascii, color, query } = state;
  const masked = '*'.repeat(Math.min(query.length, 32));

  if (state.step === 'welcome') {
    return (
      <Panel
        title="Welcome"
        accent="cyan"
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <Text bold {...tint(color, 'cyan')}>
          {safe('Initialize a Kavrix vault', ascii)}
        </Text>
        <Text {...tint(color, 'gray')}>
          {safe(
            'Interactive setup creates a real profile + vault via the CLI backend.',
            ascii,
          )}
        </Text>
        <Text {...tint(color, 'gray')}>
          {safe('Secrets stay masked. Press Enter to choose storage.', ascii)}
        </Text>
      </Panel>
    );
  }

  if (state.step === 'storage') {
    return (
      <Panel
        title="Storage"
        accent="magenta"
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <SelectRow
          active={state.storageIndex === 0}
          label="1  Local encrypted file"
          hint="Simplest for one device"
          accent="green"
          color={color}
          ascii={ascii}
        />
        <SelectRow
          active={state.storageIndex === 1}
          label="2  MongoDB"
          hint="Shared / remote datastore"
          accent="blue"
          color={color}
          ascii={ascii}
        />
      </Panel>
    );
  }

  if (state.step === 'creating') {
    return (
      <Panel
        title="Creating"
        accent="yellow"
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <Text bold {...tint(color, 'yellow')}>
          {safe(state.message ?? 'Working…', ascii)}
        </Text>
        <Text {...tint(color, 'gray')}>
          {safe(
            'Running real CLI create-file-profile / create-mongodb-profile…',
            ascii,
          )}
        </Text>
      </Panel>
    );
  }

  if (state.step === 'success') {
    return (
      <Panel
        title="Success"
        accent="green"
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <Text bold {...tint(color, 'green')}>
          {safe('SETUP COMPLETE', ascii)}
        </Text>
        <Text {...tint(color, 'green')}>
          {safe(
            `Profile selected: ${state.completedProfileId ?? state.profileId ?? 'default'}`,
            ascii,
          )}
        </Text>
        <Text {...tint(color, 'gray')}>
          {safe('Press Enter to finish, then run: kavrix tui', ascii)}
        </Text>
      </Panel>
    );
  }

  if (state.step === 'error') {
    return (
      <Panel
        title="Error"
        accent="red"
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <Text bold {...tint(color, 'red')}>
          {safe(state.error ?? 'Setup failed.', ascii)}
        </Text>
        <Text {...tint(color, 'gray')}>
          {safe('Enter/r retry · Esc/q quit', ascii)}
        </Text>
      </Panel>
    );
  }

  const title = inputTitle(state.step);
  const body = isMaskedStep(state.step)
    ? `${title}: ${masked}_`
    : `${title}: ${safe(query, ascii)}_`;
  return (
    <Panel
      title="Input"
      accent="cyan"
      ascii={ascii}
      color={color}
      paddingX={1}
      paddingY={1}
    >
      <Text bold {...tint(color, 'cyan')}>
        {safe(body, ascii)}
      </Text>
      {isMaskedStep(state.step) ? (
        <Text {...tint(color, 'gray')}>
          {safe('Paste works (Ctrl+Shift+V / Cmd+V)', ascii)}
        </Text>
      ) : null}
    </Panel>
  );
}

function inputTitle(step: OnboardingState['step']): string {
  switch (step) {
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
      return 'Passphrase';
    case 'file-passphrase-confirm':
    case 'mongo-passphrase-confirm':
      return 'Confirm passphrase';
    default:
      return 'Value';
  }
}

function isMaskedStep(step: OnboardingState['step']): boolean {
  return (
    step === 'file-passphrase' ||
    step === 'file-passphrase-confirm' ||
    step === 'mongo-url' ||
    step === 'mongo-passphrase' ||
    step === 'mongo-passphrase-confirm'
  );
}

/** Mounts init onboarding on validated TTY streams. */
export function mountOnboardingApp(
  options: MountOnboardingAppOptions,
): OnboardingAppHandle {
  const presentation = resolveAppPresentation({
    ...(options.ascii === undefined ? {} : { ascii: options.ascii }),
    ...(options.color === undefined ? {} : { color: options.color }),
  });
  let settle: ((result: OnboardingAppResult) => void) | undefined;
  const resultPromise = new Promise<OnboardingAppResult>((resolve) => {
    settle = resolve;
  });
  const instance = render(
    <KavrixOnboardingApp
      backend={options.backend}
      ascii={presentation.ascii}
      color={presentation.color}
      onComplete={(result) => {
        settle?.(result);
      }}
    />,
    {
      stdout: options.stdout ?? process.stdout,
      stdin: options.stdin ?? process.stdin,
      exitOnCtrlC: false,
      patchConsole: false,
    },
  );
  return {
    waitUntilExit: async () => {
      const fromCallback = await Promise.race([
        resultPromise,
        instance
          .waitUntilExit()
          .then((): OnboardingAppResult => ({ status: 'cancelled' })),
      ]);
      return fromCallback;
    },
    unmount: () => {
      instance.unmount();
    },
  };
}

function mapInkInput(
  input: string,
  key: Readonly<{
    upArrow: boolean;
    downArrow: boolean;
    leftArrow: boolean;
    rightArrow: boolean;
    tab: boolean;
    return: boolean;
    escape: boolean;
    backspace: boolean;
    ctrl: boolean;
    shift: boolean;
  }>,
): OnboardingKey | null {
  if (key.upArrow) return { name: 'up' };
  if (key.downArrow) return { name: 'down' };
  if (key.leftArrow) return { name: 'left' };
  if (key.rightArrow) return { name: 'right' };
  if (key.tab) return { name: 'tab' };
  if (key.return) return { name: 'return' };
  if (key.escape) return { name: 'escape' };
  if (key.backspace) return { name: 'backspace' };
  if (input.length === 0) return null;
  return { text: input, ctrl: key.ctrl };
}
