import type { SecureRunResult } from '@kavrix/runner';

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

/**
 * Converts a runner result into the process exit code exposed by the CLI.
 * A child can race a requested termination and exit zero before the signal is
 * observed, but timeout, abort, and output-limit outcomes must remain failures.
 */
export function effectiveExitCode(
  result: Pick<SecureRunResult, 'exitCode' | 'signal' | 'termination'>,
): number {
  if (result.termination === 'exit') return result.exitCode ?? 1;
  if (result.termination === 'signal') {
    return result.exitCode ?? signalExitCode(result.signal);
  }
  if (result.exitCode !== null && result.exitCode !== 0) return result.exitCode;
  return signalExitCode(result.signal ?? 'SIGTERM');
}
