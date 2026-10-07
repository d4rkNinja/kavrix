/** Match synthetic input readiness to a committed Ink frame, not just regions. */
export function createInputReadiness(getFrame: () => number): {
  readonly painted: () => void;
  readonly wait: () => Promise<void>;
  readonly dispose: () => void;
  readonly hold: () => () => void;
  readonly isReady: () => boolean;
} {
  let paintedFrame = -1;
  let disposed = false;
  let holds = 0;
  const waiters = new Set<() => void>();
  const settle = (): void => {
    for (const resolve of waiters) resolve();
    waiters.clear();
  };
  return {
    isReady: () => !disposed && holds === 0 && paintedFrame === getFrame(),
    hold: () => {
      holds += 1;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        holds -= 1;
        settle();
      };
    },
    painted: () => {
      paintedFrame = getFrame();
      settle();
    },
    wait: async () => {
      while (!disposed && (holds > 0 || paintedFrame !== getFrame())) {
        await new Promise<void>((resolve) => waiters.add(resolve));
      }
    },
    dispose: () => {
      disposed = true;
      settle();
    },
  };
}
