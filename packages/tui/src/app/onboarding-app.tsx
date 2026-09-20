import { Box, Text, render, useApp, useInput, usePaste, useStdout } from 'ink';
import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react';

import { BrandBanner } from '../showcase.js';
import { SplashGate } from '../splash-gate.js';
import { armFirstFrameWatchdog } from '../first-frame-watchdog.js';
import { sanitizeTerminalText } from '../terminal-text.js';
import type { InteractiveAppBackend, AppBackendAction } from './backend.js';
import { resolveTtySize } from './router.js';
import {
  createInitialOnboardingState,
  onboardingStepFocus,
  transitionOnboarding,
  type OnboardingKey,
  type OnboardingState,
  type OnboardingStorage,
} from './onboarding-router.js';
import { resolveMotionPolicy } from '../motion.js';
import { resolveProductIdentity } from '../product.js';
import {
  accentColor,
  CHROME,
  resolveAppPresentation,
  type AppAccent,
} from './theme.js';
import {
  ErrorState,
  KeyChip,
  LoadingState,
  Panel,
  SelectRow,
  StatusPill,
} from './widgets.js';

export interface KavrixOnboardingAppProps {
  readonly backend: InteractiveAppBackend;
  readonly ascii?: boolean;
  readonly color?: boolean;
  readonly version?: string;
  readonly noSplash?: boolean;
  readonly onComplete?: (result: OnboardingAppResult) => void;
}

export type OnboardingAppResult =
  | Readonly<{
      status: 'completed';
      profileId: string;
      datastore: OnboardingStorage;
      recoveryFile?: string;
    }>
  | Readonly<{ status: 'cancelled' }>
  | Readonly<{ status: 'failed'; message: string }>;

export interface MountOnboardingAppOptions {
  readonly backend: InteractiveAppBackend;
  readonly stdout?: NodeJS.WriteStream;
  readonly stdin?: NodeJS.ReadStream;
  readonly ascii?: boolean;
  readonly color?: boolean;
  readonly version?: string;
  readonly noSplash?: boolean;
}

export interface OnboardingAppHandle {
  waitUntilExit: () => Promise<OnboardingAppResult>;
  unmount: () => void;
}

function safe(value: string, ascii: boolean): string {
  return sanitizeTerminalText(value, ascii);
}

export function KavrixOnboardingApp({
  backend,
  ascii,
  color,
  version,
  noSplash,
  onComplete,
}: KavrixOnboardingAppProps): ReactElement {
  const { stdout } = useStdout();
  const { exit } = useApp();
  const presentation = resolveAppPresentation({
    ...(ascii === undefined ? {} : { ascii }),
    ...(color === undefined ? {} : { color }),
  });
  // Onboarding has no backend hydrate gate; treat first paint as ready.
  const [splashReady] = useState(true);
  // paintEpoch forces Ink to remount chrome after each step so transitions
  // cannot leave a blank/stale alternate frame on flaky TTYs.
  const [paintEpoch, setPaintEpoch] = useState(0);
  const [state, setState] = useState(() => {
    const size = resolveTtySize(stdout);
    return createInitialOnboardingState({
      width: size.width,
      height: size.height,
      ascii: presentation.ascii,
      color: presentation.color,
    });
  });
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
      setPaintEpoch((epoch) => epoch + 1);
    } catch (error) {
      const notice =
        error instanceof Error && error.message.trim().length > 0
          ? error.message
          : 'Operation failed safely.';
      const next = transitionOnboarding(stateRef.current, {
        type: 'backend-result',
        ok: false,
        notice,
        profileId: null,
        datastore: null,
      });
      stateRef.current = next.state;
      setState(next.state);
      setPaintEpoch((epoch) => epoch + 1);
    }
  }, []);

  const dispatchKey = useCallback(
    (key: OnboardingKey): void => {
      const previousStep = stateRef.current.step;
      const next = transitionOnboarding(stateRef.current, { type: 'key', key });
      stateRef.current = next.state;
      setState(next.state);
      // Remount only when the step changes. Remounting on every keystroke
      // left stale Storage / Key-file frames while typing passphrases.
      if (next.state.step !== previousStep) {
        setPaintEpoch((epoch) => epoch + 1);
      }
      if (next.effect.kind === 'backend') {
        void runBackend(next.effect.action);
      }
    },
    [runBackend],
  );

  useEffect(() => {
    // Kick Ink's first paint immediately; some TTYs stay blank until a second frame.
    const kick = setTimeout(() => {
      setPaintEpoch((epoch) => epoch + 1);
    }, 0);
    return () => {
      clearTimeout(kick);
    };
  }, []);

  useEffect(() => {
    const resize = (): void => {
      const next = transitionOnboarding(stateRef.current, {
        type: 'resize',
        width: resolveTtySize(stdout).width,
        height: resolveTtySize(stdout).height,
      });
      stateRef.current = next.state;
      setState(next.state);
      setPaintEpoch((epoch) => epoch + 1);
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
        ...(state.completedRecoveryFile === null
          ? {}
          : { recoveryFile: state.completedRecoveryFile }),
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

  return (
    <SplashGate
      color={presentation.color}
      ascii={presentation.ascii}
      {...(version === undefined ? {} : { version })}
      noSplash={noSplash !== false}
      width={state.width}
      height={state.height}
      ready={splashReady}
    >
      <OnboardingChrome
        key={`onboard-${state.step}-${String(paintEpoch)}`}
        state={state}
      />
    </SplashGate>
  );
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

/** Presentational onboarding chrome for first-paint tests (no Ink hooks). */
export function renderOnboardingScreen(state: OnboardingState): ReactElement {
  return <OnboardingChrome state={state} />;
}

function OnboardingChrome({
  state,
}: Readonly<{ state: OnboardingState }>): ReactElement {
  const { color, ascii, width } = state;
  const focus = onboardingStepFocus(state.step);
  const product = resolveProductIdentity();
  const accent: AppAccent =
    state.step === 'success'
      ? CHROME.success
      : state.step === 'error'
        ? CHROME.danger
        : CHROME.accent;

  // Content-sized height: pinning height={rows} blanks some TTYs (Ink/Yoga).
  return (
    <Box flexDirection="column" width={width}>
      <Panel accent={accent} ascii={ascii} color={color} paddingX={1} paddingY={0}>
        <BrandBanner color={color} ascii={ascii} dualTone />
        <Box flexDirection="row" columnGap={1} flexWrap="wrap" marginTop={0}>
          <StatusPill
            label="product"
            value={product.productLabel}
            accent={CHROME.accent}
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="mode"
            value="init"
            accent={CHROME.heading}
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="step"
            value={`${String(focus.index)}/${String(focus.total)} ${focus.title}`}
            accent={accent}
            color={color}
            ascii={ascii}
          />
          <StatusPill
            label="storage"
            value={state.storage ?? (state.storageIndex === 0 ? 'file?' : 'mongo?')}
            accent={CHROME.heading}
            color={color}
            ascii={ascii}
          />
        </Box>
      </Panel>

      <Box flexDirection="column" flexGrow={1} paddingX={1} paddingY={1}>
        <Text bold {...accentColor(color, CHROME.warning)}>
          {safe(
            `ACTIVE ${String(focus.index)}/${String(focus.total)} - ${focus.title} - ${focus.cue}`,
            ascii,
          )}
        </Text>
        {renderOnboardingBody(state)}
      </Box>

      <Box flexDirection="row" columnGap={2} paddingX={1}>
        <KeyChip keyLabel="Enter" hint="continue" color={color} />
        <KeyChip
          keyLabel="Esc"
          hint="back / cancel"
          color={color}
          keyAccent={CHROME.warning}
        />
        <KeyChip keyLabel="q" hint="quit" color={color} keyAccent={CHROME.danger} />
      </Box>
      {state.message === null && state.error === null ? null : (
        <Box paddingX={1}>
          <Text
            {...accentColor(
              color,
              state.error === null ? CHROME.accent : CHROME.danger,
            )}
          >
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
        accent={CHROME.accent}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <Text bold {...accentColor(color, CHROME.accent)}>
          {safe('Initialize a Kavrix vault', ascii)}
        </Text>
        <Text {...accentColor(color, CHROME.muted)}>
          {safe(
            'Interactive setup creates a real profile, vault, and verified recovery kit.',
            ascii,
          )}
        </Text>
        <Text {...accentColor(color, CHROME.muted)}>
          {safe('Secrets stay masked. Press Enter to choose storage.', ascii)}
        </Text>
      </Panel>
    );
  }

  if (state.step === 'storage') {
    return (
      <Panel
        title="Storage"
        accent={CHROME.accent}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <SelectRow
          active={state.storageIndex === 0}
          label="1  Local encrypted file"
          hint="Simplest for one device"
          accent={CHROME.accent}
          color={color}
          ascii={ascii}
        />
        <SelectRow
          active={state.storageIndex === 1}
          label="2  MongoDB"
          hint="Shared / remote datastore"
          accent={CHROME.accent}
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
        accent={CHROME.warning}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <LoadingState
          label={state.message ?? 'Working…'}
          color={color}
          ascii={ascii}
          animate={resolveMotionPolicy().animate}
        />
        <Text {...accentColor(color, CHROME.muted)}>
          {safe('Running real CLI create + recovery create/verify…', ascii)}
        </Text>
      </Panel>
    );
  }

  if (state.step === 'success') {
    return (
      <Panel
        title="Success"
        accent={CHROME.success}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <Text bold {...accentColor(color, CHROME.success)}>
          {safe('SETUP COMPLETE', ascii)}
        </Text>
        <Text {...accentColor(color, CHROME.success)}>
          {safe(
            `Profile selected: ${state.completedProfileId ?? state.profileId ?? 'default'}`,
            ascii,
          )}
        </Text>
        {state.completedRecoveryFile !== null ? (
          <Text {...accentColor(color, CHROME.success)}>
            {safe(`Recovery kit verified: ${state.completedRecoveryFile}`, ascii)}
          </Text>
        ) : null}
        <Text {...accentColor(color, CHROME.muted)}>
          {safe('Press Enter to finish, then run: kavrix tui', ascii)}
        </Text>
      </Panel>
    );
  }

  if (state.step === 'error') {
    return (
      <Panel
        title="Error"
        accent={CHROME.danger}
        ascii={ascii}
        color={color}
        paddingX={1}
        paddingY={1}
      >
        <ErrorState
          title={state.error ?? 'Setup failed.'}
          recovery="Enter/r retry · Esc/q quit"
          color={color}
          ascii={ascii}
        />
      </Panel>
    );
  }

  const title = inputTitle(state.step);
  const body = isMaskedStep(state.step)
    ? `${title}: ${masked}_`
    : `${title}: ${safe(query, ascii)}_`;
  return (
    <Panel
      title={`ACTIVE · ${title}`}
      accent={CHROME.accent}
      ascii={ascii}
      color={color}
      paddingX={1}
      paddingY={1}
    >
      <Text bold {...accentColor(color, CHROME.accent)}>
        {safe(body, ascii)}
      </Text>
      {isMaskedStep(state.step) ? (
        <Text {...accentColor(color, CHROME.muted)}>
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
    default:
      return 'Value';
  }
}

function isMaskedStep(step: OnboardingState['step']): boolean {
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
  const stdout = options.stdout ?? process.stdout;
  const watchdog = armFirstFrameWatchdog({
    stdout,
    label: 'kavrix init',
    onTimeout: (error) => {
      try {
        process.stderr.write(`${error.message}\n`);
      } catch {
        // ignore
      }
      process.exitCode = 1;
    },
  });
  const instance = render(
    <KavrixOnboardingApp
      backend={options.backend}
      ascii={presentation.ascii}
      color={presentation.color}
      {...(options.version === undefined ? {} : { version: options.version })}
      {...(options.noSplash === undefined ? {} : { noSplash: options.noSplash })}
      onComplete={(result) => {
        settle?.(result);
      }}
    />,
    {
      stdout,
      stdin: options.stdin ?? process.stdin,
      exitOnCtrlC: false,
      patchConsole: false,
      interactive: true,
    },
  );
  return {
    waitUntilExit: async () => {
      try {
        return await Promise.race([
          resultPromise,
          instance
            .waitUntilExit()
            .then((): OnboardingAppResult => ({ status: 'cancelled' })),
        ]);
      } finally {
        watchdog.dispose();
      }
    },
    unmount: () => {
      watchdog.dispose();
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
