import { render, useApp, useInput, usePaste, useStdout } from 'ink';
import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react';

import type { AppBackendAction, InteractiveAppBackend } from './backend.js';
import {
  createInitialAppRouterState,
  ensureTtySize,
  sanitizePasteText,
  transitionAppRouter,
  type AppKey,
  type AppRouterAction,
  type AppRouterState,
} from './router.js';
import { AppChrome, renderActiveScreen } from './screens.js';
import { resolveAppPresentation } from './theme.js';
import { ErrorState, LoadingState } from './widgets.js';
import { SplashGate } from '../splash-gate.js';
import { armFirstFrameWatchdog } from '../first-frame-watchdog.js';
import { AppInteractionProvider } from './interaction.js';
import { ClickTarget, createMouseInput, MouseProvider } from './mouse.js';

/** Monotonic frame id shared between the router and the mouse decoder. */
export interface FrameClock {
  current: number;
}

export interface KavrixAppProps {
  readonly backend: InteractiveAppBackend;
  readonly ascii?: boolean;
  readonly color?: boolean;
  readonly version?: string;
  readonly noSplash?: boolean;
  readonly now?: () => number;
  readonly onQuit?: () => void;
  readonly mouse?: boolean;
  /** Shared with the mouse decoder so a click can be matched to a frame. */
  readonly frameClock?: FrameClock;
  /**
   * Releases terminal input modes. Called the moment a quit is requested, before
   * Ink restores the primary screen, so the shell never regains the terminal
   * with mouse reporting still enabled.
   */
  readonly releaseInput?: () => void;
}

export function KavrixApp({
  backend,
  ascii,
  color,
  version,
  noSplash,
  now = Date.now,
  onQuit,
  mouse = false,
  frameClock,
  releaseInput,
}: KavrixAppProps): ReactElement {
  const { stdout } = useStdout();
  const { exit } = useApp();
  const presentation = resolveAppPresentation({
    ...(ascii === undefined ? {} : { ascii }),
    ...(color === undefined ? {} : { color }),
  });
  const [backendReady, setBackendReady] = useState(false);
  const [hydrateError, setHydrateError] = useState<string | null>(null);
  const [paintEpoch, setPaintEpoch] = useState(0);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const mountedRef = useRef(true);
  const [state, setState] = useState(() => {
    const size = ensureTtySize(stdout);
    return createInitialAppRouterState({
      width: size.width,
      height: size.height,
      ascii: presentation.ascii,
      color: presentation.color,
    });
  });
  const stateRef = useRef(state);
  const backendRef = useRef(backend);
  const onQuitRef = useRef(onQuit);
  const exitRef = useRef(exit);
  const releaseInputRef = useRef(releaseInput);
  const ownClock = useRef<FrameClock>({ current: 0 });
  const clock = frameClock ?? ownClock.current;
  const dispatchRef = useRef<(action: AppRouterAction) => void>(() => undefined);
  backendRef.current = backend;
  onQuitRef.current = onQuit;
  exitRef.current = exit;
  releaseInputRef.current = releaseInput;

  const runBackend = useCallback(
    async (action: AppBackendAction): Promise<void> => {
      busyRef.current = true;
      setBusy(true);
      try {
        const result = await backendRef.current.dispatch(action);
        if (!mountedRef.current || stateRef.current.quit) return;
        dispatchRef.current({
          type: 'backend-result',
          snapshot: result.snapshot,
          ...(result.revealedSecret === undefined
            ? {}
            : { revealedSecret: result.revealedSecret }),
          nowMs: now(),
        });
      } catch {
        if (!mountedRef.current || stateRef.current.quit) return;
        dispatchRef.current({
          type: 'backend-result',
          snapshot: {
            ...stateRef.current.snapshot,
            notice: 'Operation failed safely.',
            noticeTone: 'error',
          },
          nowMs: now(),
        });
      } finally {
        busyRef.current = false;
        if (mountedRef.current) setBusy(false);
      }
    },
    [now],
  );

  const dispatch = useCallback(
    (action: AppRouterAction): void => {
      const isIntent =
        action.type === 'key' ||
        action.type === 'navigate' ||
        action.type === 'select-row' ||
        action.type === 'select-theme';
      const isExit =
        action.type === 'key' &&
        (action.key.name === 'escape' ||
          (action.key.ctrl === true && action.key.text === 'c') ||
          (action.key.text === 'q' && stateRef.current.overlay === 'none'));
      if (
        isIntent &&
        (!backendReady || hydrateError !== null || busyRef.current) &&
        !isExit
      )
        return;
      const previousScreen = stateRef.current.screen;
      const previousOverlay = stateRef.current.overlay;
      const next = transitionAppRouter(stateRef.current, action);
      stateRef.current = next.state;
      setState(next.state);
      // Every repaint invalidates the geometry a mouse report was aimed at, so
      // the frame id is what decides whether a click is still meaningful.
      clock.current += 1;
      // Remount chrome after hydrate/resize/navigation — not every keystroke —
      // so Mid fixtures and flaky TTYs cannot keep a blank or stale frame.
      if (
        action.type === 'hydrate' ||
        action.type === 'backend-result' ||
        action.type === 'resize' ||
        next.state.screen !== previousScreen ||
        next.state.overlay !== previousOverlay
      ) {
        setPaintEpoch((epoch) => epoch + 1);
      }
      if (next.effect.kind === 'backend') {
        void runBackend(next.effect.action);
      }
    },
    [backendReady, hydrateError, runBackend],
  );
  dispatchRef.current = dispatch;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    let settled = false;
    const timeout = setTimeout(() => {
      if (cancelled || settled) return;
      settled = true;
      setHydrateError(
        'Vault session hydrate timed out. Press q to quit, then retry with --no-splash or check --config-dir.',
      );
      setBackendReady(true);
      setPaintEpoch((epoch) => epoch + 1);
    }, 8_000);
    void backendRef.current
      .load()
      .then((snapshot) => {
        if (cancelled || settled) return;
        settled = true;
        dispatchRef.current({ type: 'hydrate', snapshot });
        setBackendReady(true);
        setPaintEpoch((epoch) => epoch + 1);
      })
      .catch(() => {
        if (cancelled || settled) return;
        settled = true;
        setHydrateError(
          'Vault session could not be loaded. Press q to quit and check your profile configuration.',
        );
        setBackendReady(true);
        setPaintEpoch((epoch) => epoch + 1);
      });
    return () => {
      cancelled = true;
      clearTimeout(timeout);
    };
  }, []);

  useEffect(() => {
    // Kick Ink's first paint; some TTYs stay blank until a second frame.
    const kick = setTimeout(() => {
      setPaintEpoch((epoch) => epoch + 1);
    }, 0);
    return () => {
      clearTimeout(kick);
    };
  }, []);

  useEffect(() => {
    const resize = (): void => {
      const size = ensureTtySize(stdout);
      dispatch({
        type: 'resize',
        width: size.width,
        height: size.height,
      });
    };
    stdout.on('resize', resize);
    return () => {
      stdout.off('resize', resize);
    };
  }, [dispatch, stdout]);

  useEffect(() => {
    if (state.revealedUntilMs === 0) return undefined;
    const interval = setInterval(() => {
      dispatch({ type: 'tick', nowMs: now() });
    }, 250);
    return () => {
      clearInterval(interval);
    };
  }, [dispatch, now, state.revealedUntilMs]);

  useEffect(() => {
    if (!state.quit) return;
    onQuitRef.current?.();
    // Hand the terminal back before Ink restores the primary screen, not after.
    // Waiting until `waitUntilExit` resolves leaves the shell sitting in the
    // restored buffer with mouse reporting still on, so a click typed at the
    // prompt would arrive as a mouse report.
    releaseInputRef.current?.();
    exitRef.current();
  }, [state.quit]);

  useInput((input, key) => {
    const mapped = mapInkInput(input, key);
    if (mapped !== null) dispatch({ type: 'key', key: mapped, nowMs: now() });
  });

  // Bracketed paste arrives here (not via useInput) so multi-char paste never
  // looks like Enter. Overlay fields append the full sanitized string once.
  usePaste((text) => {
    if (!stateRef.current.overlay.startsWith('input-')) return;
    const cleaned = sanitizePasteText(text);
    if (cleaned.length === 0) return;
    dispatch({ type: 'key', key: { text: cleaned }, nowMs: now() });
  });

  const body =
    hydrateError !== null ? (
      <ErrorState
        title="Hydrate failed"
        recovery={hydrateError}
        color={presentation.color}
        ascii={presentation.ascii}
      />
    ) : !backendReady ? (
      <LoadingState
        label="Loading vault session…"
        color={presentation.color}
        ascii={presentation.ascii}
        animate
      />
    ) : (
      renderActiveScreen(state)
    );

  return (
    <AppInteractionProvider
      value={{
        dispatch,
        press: (key) => {
          dispatch({ type: 'key', key, nowMs: now() });
        },
        enabled: backendReady && hydrateError === null && !busy,
        mouse,
        busy,
      }}
    >
      <ClickTarget
        enabled={backendReady && !busy && state.overlay === 'none'}
        onScroll={(delta) => {
          dispatch({
            type: 'key',
            key: { name: delta < 0 ? 'up' : 'down' },
            nowMs: now(),
          });
        }}
      >
        <SplashGate
          color={presentation.color}
          ascii={presentation.ascii}
          {...(version === undefined ? {} : { version })}
          {...(noSplash === undefined ? {} : { noSplash })}
          width={state.width}
          height={state.height}
          ready={backendReady}
          now={now}
        >
          <AppChrome key={`chrome-${state.screen}-${String(paintEpoch)}`} state={state}>
            {body}
          </AppChrome>
        </SplashGate>
      </ClickTarget>
    </AppInteractionProvider>
  );
}

export interface MountKavrixAppOptions {
  readonly backend: InteractiveAppBackend;
  readonly stdout?: NodeJS.WriteStream;
  readonly stdin?: NodeJS.ReadStream;
  readonly ascii?: boolean;
  readonly color?: boolean;
  readonly version?: string;
  readonly noSplash?: boolean;
  readonly mouse?: boolean;
}

export interface KavrixAppHandle {
  waitUntilExit: () => Promise<void>;
  /**
   * Resolves once click regions are measured and registered, so a caller driving
   * synthetic pointer input cannot race React's passive effects.
   */
  waitForInputReady: () => Promise<void>;
  unmount: () => void;
}

/** Mounts the interactive app on validated TTY streams. */
export function mountKavrixApp(options: MountKavrixAppOptions): KavrixAppHandle {
  const presentation = resolveAppPresentation({
    ...(options.ascii === undefined ? {} : { ascii: options.ascii }),
    ...(options.color === undefined ? {} : { color: options.color }),
  });
  const stdout = options.stdout ?? process.stdout;
  // Ink itself ignores the alternate screen outside interactive TTY sessions, so
  // fullscreen stays independent of mouse support: `--no-mouse` keeps native text
  // selection without demoting the UI to an inline, scrollback-eating frame.
  // Screen-reader output is line oriented and cannot compose with a full-screen
  // repaint, so it is the one opt-out. Ink reads INK_SCREEN_READER as 'true'.
  const screenReader = process.env['INK_SCREEN_READER'] === 'true';
  const alternateScreen = !screenReader && process.env['TERM'] !== 'dumb';
  const frameClock: FrameClock = { current: 0 };
  const mouse = createMouseInput({
    stdin: options.stdin ?? process.stdin,
    stdout,
    enabled:
      options.mouse !== false &&
      process.env['KAVRIX_TUI_MOUSE'] !== '0' &&
      alternateScreen,
    getFrame: () => frameClock.current,
  });
  ensureTtySize(stdout);
  // Ink 7 skips live frames under CI=1 even on a real TTY (xfce4-terminal stays
  // blank while the process lives). Force interactive and fail loudly if the
  // first frame never arrives.
  let instance: ReturnType<typeof render> | undefined;
  const restoreTerminal = (): void => {
    // Release terminal input modes before Ink restores the primary screen, so
    // no report can arrive in an encoding the decoder has already stopped
    // filtering and the shell never inherits a live mouse reporter.
    mouse.dispose();
    instance?.unmount();
    instance = undefined;
  };
  const watchdog = armFirstFrameWatchdog({
    stdout,
    label: 'kavrix tui',
    onTimeout: (error) => {
      try {
        process.stderr.write(`${error.message}\n`);
      } catch {
        // ignore
      }
      process.exitCode = 1;
      // A blank mount is still holding the alternate screen, a hidden cursor,
      // and raw input. Leaving them behind strands the user in an unusable
      // terminal, so the timeout path tears the session down before exiting.
      watchdog.dispose();
      restoreTerminal();
    },
  });
  try {
    instance = render(
      <MouseProvider controller={mouse}>
        <KavrixApp
          backend={options.backend}
          ascii={presentation.ascii}
          color={presentation.color}
          mouse={mouse.enabled}
          frameClock={frameClock}
          releaseInput={() => {
            mouse.dispose();
          }}
          {...(options.version === undefined ? {} : { version: options.version })}
          {...(options.noSplash === undefined ? {} : { noSplash: options.noSplash })}
        />
      </MouseProvider>,
      {
        stdout,
        stdin: mouse.stdin,
        exitOnCtrlC: false,
        patchConsole: false,
        interactive: true,
        alternateScreen,
      },
    );
  } catch (error) {
    watchdog.dispose();
    mouse.dispose();
    throw error;
  }
  const shutdown = (): void => {
    watchdog.dispose();
    restoreTerminal();
  };
  return {
    waitUntilExit: async () => {
      const active = instance;
      if (active === undefined) return;
      try {
        await active.waitUntilExit();
      } finally {
        shutdown();
      }
    },
    unmount: shutdown,
    waitForInputReady: () => mouse.whenInteractive(),
  };
}

/** Presentational snapshot of router state for deterministic tests. */
export function describeAppScreen(state: AppRouterState): string {
  return [
    `screen=${state.screen}`,
    `ascii=${String(state.ascii)}`,
    `color=${String(state.color)}`,
    `menu=${String(state.menuIndex)}`,
    `list=${String(state.listIndex)}`,
    `overlay=${state.overlay}`,
    `profiles=${String(state.snapshot.profiles.length)}`,
    `vaults=${String(state.snapshot.vaults.length)}`,
    `credentials=${String(state.snapshot.credentials.length)}`,
  ].join(' ');
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
    name?: string;
  }>,
): AppKey | null {
  // Ink reports Ctrl+C as the raw byte with `key.name === 'c'`. Without this the
  // control byte reaches the router as `text: '\x03'`, which matches no exit
  // path, and the documented Ctrl+C quit silently does nothing.
  if (input === '\u0003' || (key.ctrl && key.name === 'c')) {
    return { text: 'c', ctrl: true };
  }
  if (key.upArrow) return { name: 'up' };
  if (key.downArrow) return { name: 'down' };
  if (key.leftArrow) return { name: 'left' };
  if (key.rightArrow) return { name: 'right' };
  if (key.tab) return { name: 'tab', shift: key.shift };
  if (key.return) return { name: 'return' };
  if (key.escape) return { name: 'escape' };
  if (key.backspace) return { name: 'backspace' };
  if (input.length === 0) return null;
  return { text: input, ctrl: key.ctrl };
}
