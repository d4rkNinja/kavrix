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
      try {
        update();
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
