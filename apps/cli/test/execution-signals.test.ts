import { describe, expect, it } from 'vitest';

import {
  effectiveExitCode,
  forwardableSignals,
  signalExitCode,
} from '../src/execution/signals.js';

describe('forwardableSignals', () => {
  it('includes console-break forwarding on Windows only', () => {
    const windows = forwardableSignals('win32');
    expect(windows).toContain('SIGINT');
    expect(windows).toContain('SIGTERM');
    expect(windows).toContain('SIGBREAK');
    expect(windows).not.toContain('SIGQUIT');

    const posix = forwardableSignals('linux');
    expect(posix).toContain('SIGINT');
    expect(posix).toContain('SIGTERM');
    expect(posix).toContain('SIGHUP');
    expect(posix).toContain('SIGQUIT');
    expect(posix).not.toContain('SIGBREAK');
  });
});

describe('signalExitCode', () => {
  it('maps conventional signals onto shell exit codes', () => {
    expect(signalExitCode(null)).toBe(1);
    expect(signalExitCode('SIGHUP')).toBe(129);
    expect(signalExitCode('SIGINT')).toBe(130);
    expect(signalExitCode('SIGQUIT')).toBe(131);
    expect(signalExitCode('SIGKILL')).toBe(137);
    expect(signalExitCode('SIGTERM')).toBe(143);
  });

  it('falls back to the generic 128 baseline for uncommon signals', () => {
    expect(signalExitCode('SIGUSR2')).toBe(128);
  });
});

describe('effectiveExitCode', () => {
  it('fails closed when a child exits zero after a supervised termination was requested', () => {
    expect(
      effectiveExitCode({
        exitCode: 0,
        signal: null,
        termination: 'output-limit',
      }),
    ).toBe(143);
    expect(
      effectiveExitCode({ exitCode: 0, signal: null, termination: 'timeout' }),
    ).toBe(143);
  });

  it('preserves ordinary exits and observed termination signals', () => {
    expect(effectiveExitCode({ exitCode: 0, signal: null, termination: 'exit' })).toBe(
      0,
    );
    expect(
      effectiveExitCode({
        exitCode: null,
        signal: 'SIGKILL',
        termination: 'output-limit',
      }),
    ).toBe(137);
    expect(
      effectiveExitCode({ exitCode: 7, signal: null, termination: 'aborted' }),
    ).toBe(7);
  });
});
