import { render, useApp, useInput, usePaste, useStdout } from 'ink';
import { useCallback, useEffect, useRef, useState, type ReactElement } from 'react';

import type { AppBackendAction, InteractiveAppBackend } from './backend.js';
import {
  createInitialAppRouterState,
  sanitizePasteText,
  transitionAppRouter,
  type AppKey,
  type AppRouterAction,
  type AppRouterState,
} from './router.js';
import { AppChrome, renderActiveScreen } from './screens.js';
import { resolveAppPresentation } from './theme.js';
import { SplashGate } from '../splash-gate.js';

export interface KavrixAppProps {
  readonly backend: InteractiveAppBackend;
  readonly ascii?: boolean;
  readonly color?: boolean;
  readonly version?: string;
  readonly noSplash?: boolean;
  readonly now?: () => number;
  readonly onQuit?: () => void;
}

export function KavrixApp({
  backend,
  ascii,
  color,
  version,
  noSplash,
  now = Date.now,
  onQuit,
}: KavrixAppProps): ReactElement {
  const { stdout } = useStdout();
  const { exit } = useApp();
  const presentation = resolveAppPresentation({
    ...(ascii === undefined ? {} : { ascii }),
    ...(color === undefined ? {} : { color }),
  });
  const [backendReady, setBackendReady] = useState(false);
  const [state, setState] = useState(() =>
    createInitialAppRouterState({
      width: stdout.columns,
      height: stdout.rows,
      ascii: presentation.ascii,
      color: presentation.color,
    }),
  );
  const stateRef = useRef(state);
  const backendRef = useRef(backend);
  const onQuitRef = useRef(onQuit);
  const exitRef = useRef(exit);
  const dispatchRef = useRef<(action: AppRouterAction) => void>(() => undefined);
  backendRef.current = backend;
  onQuitRef.current = onQuit;
  exitRef.current = exit;

  const runBackend = useCallback(
    async (action: AppBackendAction): Promise<void> => {
      try {
        const result = await backendRef.current.dispatch(action);
        dispatchRef.current({
          type: 'backend-result',
          snapshot: result.snapshot,
          ...(result.revealedSecret === undefined
            ? {}
            : { revealedSecret: result.revealedSecret }),
          nowMs: now(),
        });
      } catch {
        dispatchRef.current({
          type: 'backend-result',
          snapshot: {
            ...stateRef.current.snapshot,
            notice: 'Operation failed safely.',
            noticeTone: 'error',
          },
          nowMs: now(),
        });
      }
    },
    [now],
  );

  const dispatch = useCallback(
    (action: AppRouterAction): void => {
      const next = transitionAppRouter(stateRef.current, action);
      stateRef.current = next.state;
      setState(next.state);
      if (next.effect.kind === 'backend') {
        void runBackend(next.effect.action);
      }
    },
    [runBackend],
  );
  dispatchRef.current = dispatch;

  useEffect(() => {
    void backendRef.current.load().then((snapshot) => {
      dispatch({ type: 'hydrate', snapshot });
      setBackendReady(true);
    });
  }, [dispatch]);

  useEffect(() => {
    const resize = (): void => {
      dispatch({ type: 'resize', width: stdout.columns, height: stdout.rows });
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
    exitRef.current();
  }, [state.quit]);

  useInput((input, key) => {
    const mapped = mapInkInput(input, key);
    if (mapped !== null) dispatch({ type: 'key', key: mapped, nowMs: now() });
  });

  // Bracketed paste arrives here (not via useInput) so multi-char paste never
  // looks like Enter. Overlay fields append the full sanitized string once.
  usePaste((text) => {
    const cleaned = sanitizePasteText(text);
    if (cleaned.length === 0) return;
    dispatch({ type: 'key', key: { text: cleaned }, nowMs: now() });
  });

  return (
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
      <AppChrome state={state}>{renderActiveScreen(state)}</AppChrome>
    </SplashGate>
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
}

export interface KavrixAppHandle {
  waitUntilExit: () => Promise<void>;
  unmount: () => void;
}

/** Mounts the interactive app on validated TTY streams. */
export function mountKavrixApp(options: MountKavrixAppOptions): KavrixAppHandle {
  const presentation = resolveAppPresentation({
    ...(options.ascii === undefined ? {} : { ascii: options.ascii }),
    ...(options.color === undefined ? {} : { color: options.color }),
  });
  const instance = render(
    <KavrixApp
      backend={options.backend}
      ascii={presentation.ascii}
      color={presentation.color}
      {...(options.version === undefined ? {} : { version: options.version })}
      {...(options.noSplash === undefined ? {} : { noSplash: options.noSplash })}
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
      await instance.waitUntilExit();
    },
    unmount: () => {
      instance.unmount();
    },
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
  }>,
): AppKey | null {
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
