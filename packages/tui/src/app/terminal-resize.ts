import type { EventEmitter } from 'node:events';

import { FRAME_TICK_MS } from '../frame-clock.js';

/** Coalesce a resize burst into one update using the latest terminal dimensions. */
export function subscribeToTerminalResize(
  stdout: Pick<EventEmitter, 'on' | 'off'>,
  update: () => void,
  holdInput?: () => () => void,
): () => void {
  let pending: ReturnType<typeof setTimeout> | undefined;
  let releaseInput: (() => void) | undefined;
  const resize = (): void => {
    if (pending !== undefined) return;
    releaseInput = holdInput?.();
    pending = setTimeout(() => {
      const release = releaseInput;
      pending = undefined;
      releaseInput = undefined;
      // The update runs from a timer with the app's input held: a throwing
      // update must still release input and must not escape the timer as an
      // uncaught exception.
      try {
        update();
      } catch {
        // A failed resize update keeps the previous dimensions; the next
        // resize event retries with fresh geometry.
      } finally {
        release?.();
      }
    }, FRAME_TICK_MS);
  };
  stdout.on('resize', resize);
  return () => {
    stdout.off('resize', resize);
    if (pending !== undefined) clearTimeout(pending);
    releaseInput?.();
    releaseInput = undefined;
  };
}
