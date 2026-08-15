import {
  DEFAULT_SESSION_LIFETIME_POLICY,
  type SessionLifetimePolicy,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import { CliSessionEndedError, presentCliError } from '../src/errors.js';
import { resolveSessionLifetimePolicy } from '../src/production/session-policy.js';
import { InvocationSession, runWithInvocationSession } from '../src/session.js';
import {
  ManualSignals,
  sessionHarness as harness,
  stalled,
} from './session-harness.js';

const POLICY: SessionLifetimePolicy = Object.freeze({
  invocationTimeoutMs: 10_000,
  idleTimeoutMs: 3_000,
  reauthenticationWindowMs: 5_000,
});

describe('invocation session cleanup', () => {
  it('releases resources in reverse acquisition order exactly once', async () => {
    const { runtime, ports } = harness();
    const released: string[] = [];

    const value = await runWithInvocationSession(
      { policy: POLICY, ports },
      (session) => {
        session.register('command environment', () => {
          released.push('command environment');
        });
        session.register('vault root key', () => {
          released.push('vault root key');
        });
        return Promise.resolve('listed');
      },
    );

    expect(value).toBe('listed');
    expect(released).toEqual(['vault root key', 'command environment']);
    expect(runtime.armedCount).toBe(0);
  });

  it('releases resources when the operation throws and reports the original failure', async () => {
    const { ports } = harness();
    const released: string[] = [];

    await expect(
      runWithInvocationSession({ policy: POLICY, ports }, (session) => {
        session.register('vault root key', () => {
          released.push('vault root key');
        });
        return Promise.reject(new Error('decrypt failed'));
      }),
    ).rejects.toThrow('decrypt failed');

    expect(released).toEqual(['vault root key']);
  });

  it('runs every release step even when an earlier one fails and reports them together', async () => {
    const { ports } = harness();
    const released: string[] = [];

    const failure = await runWithInvocationSession(
      { policy: POLICY, ports },
      (session) => {
        session.register('command environment', () => {
          released.push('command environment');
        });
        session.register('vault root key', () => {
          throw new Error('zeroize failed');
        });
        return Promise.resolve('ok');
      },
    ).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).errors).toHaveLength(1);
    // The later step still ran even though the step above it threw.
    expect(released).toEqual(['command environment']);
  });

  it('aggregates an operation failure with a cleanup failure instead of masking either', async () => {
    const { ports } = harness();

    const failure = await runWithInvocationSession(
      { policy: POLICY, ports },
      (session) => {
        session.register('vault root key', () => {
          throw new Error('zeroize failed');
        });
        return Promise.reject(new Error('decrypt failed'));
      },
    ).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(AggregateError);
    const messages = (failure as AggregateError).errors.map((error) =>
      error instanceof Error ? error.message : String(error),
    );
    expect(messages).toEqual([
      'decrypt failed',
      'Session resources could not be released.',
    ]);
  });

  it('closes once across concurrent and repeated close calls', async () => {
    const { ports } = harness();
    let releases = 0;
    const session = new InvocationSession({ policy: POLICY, ports });
    session.register('vault root key', () => {
      releases += 1;
    });

    await Promise.all([session.close(), session.close()]);
    await session.close();

    expect(releases).toBe(1);
  });

  it('releases a resource registered after the session already closed', async () => {
    const { ports } = harness();
    let released = false;
    const session = new InvocationSession({ policy: POLICY, ports });

    await session.close();
    session.register('late root key', () => {
      released = true;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(released).toBe(true);
  });
});

describe('invocation session expiry', () => {
  it('locks and releases on the invocation deadline even when the operation never settles', async () => {
    const { runtime, ports } = harness();
    const released: string[] = [];
    let reachedSuccess = false;

    const pending = runWithInvocationSession(
      { policy: POLICY, ports },
      async (session) => {
        session.register('command environment', () => {
          released.push('command environment');
        });
        session.register('vault root key', () => {
          released.push('vault root key');
        });
        // Progress is recorded throughout, so the inactivity limit is never what
        // ends this session: only the invocation ceiling can.
        for (let elapsed = 0; elapsed < POLICY.invocationTimeoutMs; elapsed += 2_000) {
          runtime.advance(2_000);
          session.touch();
        }
        await stalled();
        reachedSuccess = true;
        return 'unreachable';
      },
    );

    await expect(pending).rejects.toMatchObject({
      name: 'CliSessionEndedError',
      code: 'SESSION_TIMEOUT',
      reason: 'invocation-timeout',
    });
    expect(released).toEqual(['vault root key', 'command environment']);
    expect(reachedSuccess).toBe(false);
    expect(runtime.armedCount).toBe(0);
  });

  it('locks and releases on the inactivity limit', async () => {
    const { runtime, ports } = harness();
    const released: string[] = [];

    const pending = runWithInvocationSession(
      { policy: POLICY, ports },
      async (session) => {
        session.register('vault root key', () => {
          released.push('vault root key');
        });
        await stalled();
        return 'unreachable';
      },
    );
    runtime.advance(POLICY.idleTimeoutMs);

    await expect(pending).rejects.toMatchObject({
      code: 'SESSION_IDLE_TIMEOUT',
      reason: 'idle-timeout',
    });
    expect(released).toEqual(['vault root key']);
  });

  it('restarts the inactivity limit on recorded progress without extending the invocation', async () => {
    const { runtime, ports } = harness();
    const observed: (string | undefined)[] = [];

    const pending = runWithInvocationSession(
      { policy: POLICY, ports },
      async (session) => {
        // Four inactivity limits' worth of elapsed time, none of which ends the
        // session because progress is recorded before each one lapses.
        for (let step = 0; step < 4; step += 1) {
          runtime.advance(2_000);
          session.touch();
          observed.push(session.endedBecause);
        }
        await stalled();
        return 'unreachable';
      },
    );
    runtime.advance(POLICY.invocationTimeoutMs);

    await expect(pending).rejects.toMatchObject({
      code: 'SESSION_TIMEOUT',
      reason: 'invocation-timeout',
    });
    expect(observed).toEqual([undefined, undefined, undefined, undefined]);
  });

  it.each([
    ['SIGINT', 'SESSION_INTERRUPTED', 'interrupted'],
    ['SIGTERM', 'SESSION_TERMINATED', 'terminated'],
    ['SIGHUP', 'SESSION_TERMINATED', 'hangup'],
  ] as const)('locks and releases on %s', async (signal, code, reason) => {
    const { signals, ports } = harness();
    const released: string[] = [];

    const pending = runWithInvocationSession(
      { policy: POLICY, ports },
      async (session) => {
        session.register('command environment', () => {
          released.push('command environment');
        });
        session.register('vault root key', () => {
          released.push('vault root key');
        });
        await stalled();
        return 'unreachable';
      },
    );
    signals.raise(signal);

    await expect(pending).rejects.toMatchObject({ code, reason });
    expect(released).toEqual(['vault root key', 'command environment']);
    expect(signals.listenerCount()).toBe(0);
  });

  it('keeps the first ending reason when a signal arrives during cleanup', async () => {
    const { runtime, signals, ports } = harness();

    const pending = runWithInvocationSession(
      { policy: POLICY, ports },
      async (session) => {
        session.register('vault root key', () => {
          signals.raise('SIGTERM');
        });
        await stalled();
        return 'unreachable';
      },
    );
    runtime.advance(POLICY.idleTimeoutMs);

    await expect(pending).rejects.toMatchObject({ reason: 'idle-timeout' });
  });

  it('removes its signal listeners on a normal ending', async () => {
    const { signals, ports } = harness();

    expect(
      await runWithInvocationSession({ policy: POLICY, ports }, () =>
        Promise.resolve('done'),
      ),
    ).toBe('done');
    expect(signals.listenerCount()).toBe(0);
  });

  it('refuses to report success for a result produced after the deadline passed', async () => {
    const { runtime, ports } = harness();
    let released = false;

    const pending = runWithInvocationSession(
      { policy: POLICY, ports },
      async (session) => {
        session.register('vault root key', () => {
          released = true;
        });
        await Promise.resolve();
        // The deadline lapses while the timer is still waiting to be serviced, so
        // the operation completes and the abort has not fired. The final liveness
        // check, not the timer, is what has to refuse this result.
        runtime.jump(POLICY.invocationTimeoutMs);
        return 'secret revealed';
      },
    );

    await expect(pending).rejects.toMatchObject({
      code: 'SESSION_TIMEOUT',
      reason: 'invocation-timeout',
    });
    // Cleanup already ran, and success is still refused afterwards.
    expect(released).toBe(true);
  });

  it('reports the vault as no longer unlocked once the session has ended', async () => {
    const { runtime, signals, ports } = harness();
    const session = new InvocationSession({ policy: POLICY, ports });

    session.authorize();
    expect(session.authorized()).toBe(true);
    expect(session.endedBecause).toBeUndefined();

    signals.raise('SIGINT');

    expect(session.endedBecause).toBe('interrupted');
    expect(session.authorized()).toBe(false);
    expect(() => {
      session.assertLive();
    }).toThrow(CliSessionEndedError);
    expect(session.signal.aborted).toBe(true);
    runtime.advance(POLICY.invocationTimeoutMs);
    await session.close();
  });

  it('closes the reauthentication window when authorization is revoked', async () => {
    const { runtime, ports } = harness();
    const session = new InvocationSession({ policy: POLICY, ports });

    session.authorize();
    runtime.advance(1_000);
    expect(session.authorized()).toBe(true);

    session.revokeAuthorization();
    expect(session.authorized()).toBe(false);
    // Revoking a window is not an ending: the invocation is still usable.
    expect(session.endedBecause).toBeUndefined();
    session.assertLive();
    await session.close();
  });

  it('fails closed when the monotonic clock moves backward', async () => {
    let reading = 5_000;
    const signals = new ManualSignals();
    const session = new InvocationSession({
      policy: POLICY,
      ports: {
        clock: { now: () => reading },
        timer: { set: () => ({}), clear: () => undefined },
        signals: signals.port,
      },
    });

    reading = 4_000;
    expect(() => {
      session.assertLive();
    }).toThrow(CliSessionEndedError);
    expect(session.endedBecause).toBe('clock-regression');
    await session.close();
  });

  it('cancels work threaded onto the session signal', async () => {
    const { signals, ports } = harness();
    const session = new InvocationSession({ policy: POLICY, ports });
    let cancelled = false;
    session.signal.addEventListener('abort', () => {
      cancelled = true;
    });

    signals.raise('SIGINT');

    expect(cancelled).toBe(true);
    expect(session.signal.reason).toBeInstanceOf(CliSessionEndedError);
    await session.close();
  });
});

describe('session ended presentation', () => {
  it.each([
    ['invocation-timeout', 'SESSION_TIMEOUT'],
    ['idle-timeout', 'SESSION_IDLE_TIMEOUT'],
    ['interrupted', 'SESSION_INTERRUPTED'],
    ['terminated', 'SESSION_TERMINATED'],
    ['hangup', 'SESSION_TERMINATED'],
    ['clock-regression', 'SESSION_CLOCK_UNUSABLE'],
  ] as const)('presents %s as a safe failure', (reason, code) => {
    const presentation = presentCliError(new CliSessionEndedError(reason));

    expect(presentation.exitCode).toBe(1);
    expect(presentation.code).toBe(code);
    expect(presentation.message).toMatch(/lock/iu);
  });
});

describe('session lifetime policy resolution', () => {
  it('uses the shipped defaults when nothing is configured', () => {
    expect(resolveSessionLifetimePolicy({})).toEqual(DEFAULT_SESSION_LIFETIME_POLICY);
  });

  it('accepts operator overrides within bounds', () => {
    expect(
      resolveSessionLifetimePolicy({
        CREDS_SESSION_TIMEOUT_MS: '60000',
        CREDS_SESSION_IDLE_TIMEOUT_MS: '30000',
        CREDS_REAUTH_WINDOW_MS: '15000',
      }),
    ).toEqual({
      invocationTimeoutMs: 60_000,
      idleTimeoutMs: 30_000,
      reauthenticationWindowMs: 15_000,
    });
  });

  it('treats a blank override as unset rather than as a disabled limit', () => {
    expect(resolveSessionLifetimePolicy({ CREDS_SESSION_TIMEOUT_MS: '   ' })).toEqual(
      DEFAULT_SESSION_LIFETIME_POLICY,
    );
  });

  it.each([
    ['a non-numeric value', { CREDS_SESSION_TIMEOUT_MS: 'forever' }],
    ['an exponential form', { CREDS_SESSION_TIMEOUT_MS: '1e6' }],
    ['a hexadecimal form', { CREDS_SESSION_TIMEOUT_MS: '0x3e8' }],
    ['a signed value', { CREDS_SESSION_TIMEOUT_MS: '+60000' }],
    ['a negative value', { CREDS_SESSION_TIMEOUT_MS: '-1' }],
    ['a fractional value', { CREDS_SESSION_TIMEOUT_MS: '1000.5' }],
    ['a leading-zero form', { CREDS_SESSION_TIMEOUT_MS: '060000' }],
    ['a value below the floor', { CREDS_SESSION_TIMEOUT_MS: '10' }],
    ['a value above the ceiling', { CREDS_SESSION_TIMEOUT_MS: '86400001' }],
    [
      'an inactivity limit above the invocation limit',
      { CREDS_SESSION_TIMEOUT_MS: '5000', CREDS_SESSION_IDLE_TIMEOUT_MS: '6000' },
    ],
    [
      'a reauthentication window above the invocation limit',
      { CREDS_SESSION_TIMEOUT_MS: '5000', CREDS_REAUTH_WINDOW_MS: '6000' },
    ],
  ])('refuses %s', (_label, environment) => {
    expect(() => resolveSessionLifetimePolicy(environment)).toThrow(
      'The session lifetime policy is invalid.',
    );
  });

  it('never echoes the rejected value', () => {
    const failure = (() => {
      try {
        resolveSessionLifetimePolicy({ CREDS_SESSION_TIMEOUT_MS: 'not-a-duration' });
        return undefined;
      } catch (error: unknown) {
        return error;
      }
    })();

    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).not.toContain('not-a-duration');
  });
});
