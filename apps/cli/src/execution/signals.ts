/** Signals a supervisor forwards to its child while it waits. */
export function forwardableSignals(
  platform: NodeJS.Platform,
): readonly NodeJS.Signals[] {
  return platform === 'win32'
    ? ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGBREAK']
    : ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'];
}

/** Conventional shell exit code for a child terminated by a signal. */
export function signalExitCode(signal: NodeJS.Signals | null): number {
  if (signal === null) return 1;
  const table: Partial<Record<NodeJS.Signals, number>> = {
    SIGHUP: 129,
    SIGINT: 130,
    SIGQUIT: 131,
    SIGKILL: 137,
    SIGTERM: 143,
  };
  return table[signal] ?? 128;
}
