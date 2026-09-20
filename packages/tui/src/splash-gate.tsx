import { useEffect, useRef, useState, type ReactElement } from 'react';

import { resolveMotionPolicy } from './motion.js';
import {
  SplashScreen,
  shouldDismissSplash,
  splashEnabled,
  SPLASH_MAX_MS,
  SPLASH_MIN_MS,
} from './splash.js';

export interface SplashGateProps {
  readonly color: boolean;
  readonly ascii: boolean;
  readonly version?: string;
  readonly width: number;
  readonly height: number;
  /** Backend hydrate / first paint ready. */
  readonly ready: boolean;
  readonly noSplash?: boolean;
  readonly now?: () => number;
  readonly children: ReactElement;
}

/**
 * Shows the animated splash until ready+minMs (or maxMs), then renders children.
 * Presentation-only gate — does not touch vault data.
 */
export function SplashGate({
  color,
  ascii,
  version,
  width,
  height,
  ready,
  noSplash,
  now = Date.now,
  children,
}: SplashGateProps): ReactElement {
  const startedAtMs = useRef(now());
  const [visible, setVisible] = useState(() =>
    splashEnabled(noSplash === undefined ? {} : { noSplash }),
  );

  useEffect(() => {
    if (!visible) return undefined;
    const tick = (): void => {
      if (
        shouldDismissSplash({
          startedAtMs: startedAtMs.current,
          nowMs: now(),
          ready,
          minMs: SPLASH_MIN_MS,
          maxMs: SPLASH_MAX_MS,
        })
      ) {
        setVisible(false);
      }
    };
    tick();
    const interval = setInterval(tick, 50);
    return () => {
      clearInterval(interval);
    };
  }, [visible, ready, now]);

  if (!visible) return children;

  return (
    <SplashScreen
      color={color}
      ascii={ascii}
      {...(version === undefined ? {} : { version })}
      width={width}
      height={height}
      animate={resolveMotionPolicy().animate}
    />
  );
}
