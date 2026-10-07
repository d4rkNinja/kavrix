import { render, useApp, useInput, usePaste, useStdout } from 'ink';
import { setupProgressSchema, setupToolResultSchema } from '@kavrix/schemas';
import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react';

import { SplashGate } from '../splash-gate.js';
import { armFirstFrameWatchdog } from '../first-frame-watchdog.js';
import type { InteractiveAppBackend, AppBackendAction } from './backend.js';
import { ensureTtySize, resolveTtySize } from './router.js';
import type { FrameClock } from './app.js';
import { InputInteractionProvider } from './interaction.js';
import { createMouseInput, MouseProvider } from './mouse.js';
import { terminalFullscreenEnabled } from './viewport.js';
import { createInputReadiness } from './input-readiness.js';
import { subscribeToTerminalResize } from './terminal-resize.js';
import {
  createInitialOnboardingState,
  transitionOnboarding,
  type OnboardingKey,
  type OnboardingStorage,
} from './onboarding-router.js';
import { resolveAppPresentation } from './theme.js';
import { OnboardingChrome } from './onboarding-screen.js';
export { renderOnboardingScreen } from './onboarding-screen.js';

export interface KavrixOnboardingAppProps {
  readonly backend: InteractiveAppBackend;
  readonly ascii?: boolean;
  readonly color?: boolean;
  readonly version?: string;
  readonly noSplash?: boolean;
  readonly onComplete?: (result: OnboardingAppResult) => void;
  readonly mouse?: boolean;
  readonly frameClock?: FrameClock;
  readonly releaseInput?: () => void;
  readonly holdInput?: () => () => void;
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
  readonly mouse?: boolean;
}

export interface OnboardingAppHandle {
  waitUntilExit: () => Promise<OnboardingAppResult>;
  waitForInputReady: () => Promise<void>;
  unmount: () => void;
}

export function KavrixOnboardingApp({
  backend,
  ascii,
  color,
  version,
  noSplash,
  onComplete,
  mouse = false,
  frameClock,
  releaseInput,
  holdInput,
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
  const ownClock = useRef<FrameClock>({ current: 0 });
  const clock = frameClock ?? ownClock.current;
  const releaseInputRef = useRef(releaseInput);
  releaseInputRef.current = releaseInput;
  backendRef.current = backend;
  onCompleteRef.current = onComplete;
  exitRef.current = exit;

  const finish = useCallback((result: OnboardingAppResult): void => {
    if (finishedRef.current) return;
    finishedRef.current = true;
    releaseInputRef.current?.();
    onCompleteRef.current?.(result);
    exitRef.current();
  }, []);

  const runBackend = useCallback(async (action: AppBackendAction): Promise<void> => {
    try {
      const result = await backendRef.current.dispatch(action, (progress) => {
        if (finishedRef.current) return;
        const parsed = setupProgressSchema.safeParse(progress);
        if (!parsed.success) return;
        const next = transitionOnboarding(stateRef.current, {
          type: 'progress',
          progress: parsed.data,
        });
        stateRef.current = next.state;
        setState(next.state);
      });
      if (finishedRef.current) return;
      const ok = result.snapshot.noticeTone === 'success';
      const next = transitionOnboarding(stateRef.current, {
        type: 'backend-result',
        ok,
        notice: result.snapshot.notice,
        ...(result.setup === undefined
          ? {}
          : { setup: setupToolResultSchema.parse(result.setup) }),
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
      clock.current += 1;
      setPaintEpoch((epoch) => epoch + 1);
      if (next.effect.kind === 'backend') {
        void runBackend(next.effect.action);
      }
    } catch {
      if (finishedRef.current) return;
      const notice = 'Operation failed safely. Review your settings and retry.';
      const next = transitionOnboarding(stateRef.current, {
        type: 'backend-result',
        ok: false,
        notice,
        profileId: null,
        datastore: null,
      });
      stateRef.current = next.state;
      setState(next.state);
      clock.current += 1;
      setPaintEpoch((epoch) => epoch + 1);
    }
  }, []);

  const dispatchKey = useCallback(
    (key: OnboardingKey): void => {
      if (viewInputRef.current?.(key) === true) return;
      const previousStep = stateRef.current.step;
      const next = transitionOnboarding(stateRef.current, { type: 'key', key });
      if (next.state === stateRef.current && next.effect.kind === 'none') return;
      stateRef.current = next.state;
      setState(next.state);
      clock.current += 1;
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

  const viewInputRef = useRef<((key: OnboardingKey) => boolean) | null>(null);
  const registerViewInput = useCallback(
    (handler: (key: OnboardingKey) => boolean): (() => void) => {
      viewInputRef.current = handler;
      return () => {
        viewInputRef.current = null;
      };
    },
    [],
  );

  useEffect(() => {
    finishedRef.current = false;
    return () => {
      finishedRef.current = true;
    };
  }, []);

  const busy =
    state.checkingDestination ||
    state.pendingTool !== null ||
    state.step === 'creating' ||
    state.sessionAttempt;
  useEffect(() => {
    if (!busy) return;
    const started = Date.now();
    const timer = setInterval(() => {
      if (finishedRef.current) return;
      const next = transitionOnboarding(stateRef.current, {
        type: 'elapsed',
        seconds: (Date.now() - started) / 1000,
      });
      stateRef.current = next.state;
      setState(next.state);
    }, 1000);
    return () => {
      clearInterval(timer);
    };
  }, [busy, state.pendingTool, state.step]);

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
      const size = resolveTtySize(stdout);
      const next = transitionOnboarding(stateRef.current, {
        type: 'resize',
        width: size.width,
        height: size.height,
      });
      if (next.state === stateRef.current) return;
      stateRef.current = next.state;
      setState(next.state);
      clock.current += 1;
      setPaintEpoch((epoch) => epoch + 1);
    };
    return subscribeToTerminalResize(stdout, resize, holdInput);
  }, [stdout, holdInput]);

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
    <InputInteractionProvider
      value={{
        press: dispatchKey,
        enabled:
          !state.checkingDestination &&
          state.pendingTool === null &&
          state.step !== 'creating' &&
          !state.sessionAttempt,
        busy:
          state.checkingDestination ||
          state.pendingTool !== null ||
          state.step === 'creating' ||
          state.sessionAttempt,
        mouse,
      }}
    >
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
          registerViewInput={registerViewInput}
          invalidateFrame={() => {
            clock.current += 1;
          }}
        />
      </SplashGate>
    </InputInteractionProvider>
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

/** Mount setup with the same alternate-screen and protected pointer input as the app. */
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
  ensureTtySize(stdout);
  const alternateScreen = terminalFullscreenEnabled();
  const frameClock: FrameClock = { current: 0 };
  const inputReadiness = createInputReadiness(() => frameClock.current);
  const mouse = createMouseInput({
    stdin: options.stdin ?? process.stdin,
    stdout,
    enabled:
      options.mouse !== false &&
      process.env['KAVRIX_TUI_MOUSE'] !== '0' &&
      alternateScreen,
    getFrame: () => frameClock.current,
    isInputReady: inputReadiness.isReady,
  });
  let instance: ReturnType<typeof render> | undefined;
  const restoreTerminal = (): void => {
    inputReadiness.dispose();
    mouse.dispose();
    instance?.unmount();
    instance = undefined;
  };
  const watchdog = armFirstFrameWatchdog({
    stdout,
    label: 'kavrix init',
    onTimeout: (error) => {
      try {
        process.stderr.write(error.message + '\n');
      } finally {
        process.exitCode = 1;
        watchdog.dispose();
        restoreTerminal();
      }
    },
  });
  try {
    instance = render(
      <MouseProvider controller={mouse}>
        <KavrixOnboardingApp
          backend={options.backend}
          ascii={presentation.ascii}
          color={presentation.color}
          mouse={mouse.enabled}
          frameClock={frameClock}
          holdInput={inputReadiness.hold}
          releaseInput={() => {
            mouse.dispose();
          }}
          {...(options.version === undefined ? {} : { version: options.version })}
          {...(options.noSplash === undefined ? {} : { noSplash: options.noSplash })}
          onComplete={(result) => {
            settle?.(result);
          }}
        />
      </MouseProvider>,
      {
        stdout,
        stdin: mouse.stdin,
        exitOnCtrlC: false,
        patchConsole: false,
        interactive: true,
        alternateScreen,
        onRender: inputReadiness.painted,
      },
    );
  } catch (error) {
    watchdog.dispose();
    restoreTerminal();
    throw error;
  }
  const shutdown = (): void => {
    watchdog.dispose();
    restoreTerminal();
  };
  return {
    waitUntilExit: async () => {
      const active = instance;
      if (active === undefined) return { status: 'cancelled' };
      try {
        return await Promise.race([
          resultPromise,
          active
            .waitUntilExit()
            .then((): OnboardingAppResult => ({ status: 'cancelled' })),
        ]);
      } finally {
        shutdown();
      }
    },
    waitForInputReady: async () => {
      await inputReadiness.wait();
      await instance?.waitUntilRenderFlush();
      await mouse.whenInteractive();
    },
    unmount: shutdown,
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
    home: boolean;
    end: boolean;
    delete: boolean;
    ctrl: boolean;
    shift: boolean;
  }>,
): OnboardingKey | null {
  if (input === '\u0003' || (key.ctrl && input === 'c'))
    return { text: 'c', ctrl: true };
  if (key.ctrl && input === 'g') return { name: 'help' };
  if (key.upArrow) return { name: 'up' };
  if (key.downArrow) return { name: 'down' };
  if (key.leftArrow) return { name: 'left' };
  if (key.rightArrow) return { name: 'right' };
  if (key.tab) return { name: 'tab' };
  if (key.return) return { name: 'return' };
  if (key.escape) return { name: 'escape' };
  if (key.backspace) return { name: 'backspace' };
  if (key.home) return { name: 'home' };
  if (key.end) return { name: 'end' };
  if (key.delete) return { name: 'delete' };
  if (input.length === 0) return null;
  return { text: input, ctrl: key.ctrl };
}
