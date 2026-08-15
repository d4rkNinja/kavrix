import { describe, expect, it } from 'vitest';

import {
  DEFAULT_SESSION_LIFETIME_POLICY,
  MAX_SESSION_TIMEOUT_MS,
  MIN_SESSION_TIMEOUT_MS,
  sessionLifetimePolicySchema,
  type SessionLifetimePolicy,
} from '@kavrix/schemas';

import {
  authorizationValid,
  beginSession,
  evaluateSession,
  recordActivity,
  recordAuthorization,
  withdrawAuthorization,
} from '../src/policies/session-lifetime.js';
import { ValidationError } from '../src/errors.js';

const POLICY: SessionLifetimePolicy = Object.freeze({
  invocationTimeoutMs: 10_000,
  idleTimeoutMs: 3_000,
  reauthenticationWindowMs: 5_000,
});

describe('session lifetime policy schema', () => {
  it('accepts the shipped defaults', () => {
    expect(sessionLifetimePolicySchema.parse(DEFAULT_SESSION_LIFETIME_POLICY)).toEqual(
      DEFAULT_SESSION_LIFETIME_POLICY,
    );
  });

  it.each([
    ['inactivity above invocation', { idleTimeoutMs: 20_000 }],
    ['reauthentication above invocation', { reauthenticationWindowMs: 20_000 }],
    ['invocation below the floor', { invocationTimeoutMs: MIN_SESSION_TIMEOUT_MS - 1 }],
    [
      'invocation above the ceiling',
      { invocationTimeoutMs: MAX_SESSION_TIMEOUT_MS + 1 },
    ],
    ['fractional inactivity', { idleTimeoutMs: 1_500.5 }],
  ])('rejects %s', (_label, override) => {
    expect(() =>
      sessionLifetimePolicySchema.parse({ ...POLICY, ...override }),
    ).toThrow();
  });

  it('rejects an unknown limit rather than ignoring it', () => {
    expect(() =>
      sessionLifetimePolicySchema.parse({ ...POLICY, graceMs: 1_000 }),
    ).toThrow();
  });
});

describe('session lifetime decisions', () => {
  it('reports the earliest of the two deadlines while live', () => {
    const state = beginSession(POLICY, 1_000);

    expect(evaluateSession(state, 1_000)).toEqual({
      expired: false,
      remainingMs: 3_000,
    });
    expect(evaluateSession(state, 2_500)).toEqual({
      expired: false,
      remainingMs: 1_500,
    });
  });

  it('expires exactly at the inactivity limit, not one tick later', () => {
    const state = beginSession(POLICY, 0);

    expect(evaluateSession(state, 2_999)).toEqual({ expired: false, remainingMs: 1 });
    expect(evaluateSession(state, 3_000)).toEqual({
      expired: true,
      reason: 'idle-timeout',
    });
  });

  it('restarts the inactivity limit on activity without extending the invocation limit', () => {
    const active = recordActivity(
      recordActivity(beginSession(POLICY, 0), 2_000),
      4_000,
    );

    expect(evaluateSession(active, 6_500)).toEqual({
      expired: false,
      remainingMs: 500,
    });
    expect(evaluateSession(active, 9_999)).toEqual({
      expired: true,
      reason: 'idle-timeout',
    });

    // Activity right up to the invocation deadline cannot push it out.
    const busy = recordActivity(active, 9_500);
    expect(evaluateSession(busy, 10_000)).toEqual({
      expired: true,
      reason: 'invocation-timeout',
    });
  });

  it('reports the invocation limit when both deadlines have passed', () => {
    const state = beginSession(POLICY, 0);

    expect(evaluateSession(state, 50_000)).toEqual({
      expired: true,
      reason: 'invocation-timeout',
    });
  });

  it('fails closed when the monotonic clock moves backward', () => {
    const state = recordActivity(beginSession(POLICY, 5_000), 6_000);

    expect(evaluateSession(state, 4_999)).toEqual({
      expired: true,
      reason: 'clock-regression',
    });
    expect(evaluateSession(state, Number.NaN)).toEqual({
      expired: true,
      reason: 'clock-regression',
    });
    expect(() => recordActivity(state, 5_500)).toThrow(ValidationError);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1])(
    'refuses to open a session at an unusable clock reading %s',
    (reading) => {
      expect(() => beginSession(POLICY, reading)).toThrow(ValidationError);
    },
  );

  it('rejects an out-of-bounds policy when opening a session', () => {
    expect(() => beginSession({ ...POLICY, idleTimeoutMs: 20_000 }, 0)).toThrow();
  });

  it('keeps state immutable across recorders', () => {
    const opened = beginSession(POLICY, 0);
    const active = recordActivity(opened, 1_000);

    expect(opened.lastActivityAtMs).toBe(0);
    expect(active.lastActivityAtMs).toBe(1_000);
    expect(Object.isFrozen(active)).toBe(true);
  });
});

describe('reauthentication window', () => {
  it('is closed until an authorization is recorded', () => {
    const state = beginSession(POLICY, 0);

    expect(state.authorizedAtMs).toBeNull();
    expect(authorizationValid(state, 0)).toBe(false);
  });

  it('opens on authorization and is never refreshed by mere activity', () => {
    const opened = recordAuthorization(beginSession(POLICY, 0), 1_000);
    // Activity keeps the session live but must not extend the window: only a
    // fresh authorization may do that.
    const busy = recordActivity(recordActivity(opened, 3_500), 5_999);

    expect(authorizationValid(opened, 1_000)).toBe(true);
    expect(authorizationValid(busy, 5_999)).toBe(true);
    expect(evaluateSession(busy, 6_000).expired).toBe(false);
    expect(authorizationValid(busy, 6_000)).toBe(false);

    // A second authorization opens a new window from its own reading, but the
    // window still cannot outlive the invocation limit.
    expect(authorizationValid(recordAuthorization(busy, 6_000), 8_000)).toBe(true);
    expect(authorizationValid(recordAuthorization(busy, 6_000), 10_000)).toBe(false);
  });

  it('counts authorization as activity', () => {
    const authorized = recordAuthorization(beginSession(POLICY, 0), 2_500);

    expect(evaluateSession(authorized, 5_000)).toEqual({
      expired: false,
      remainingMs: 500,
    });
  });

  it('never reports an open window on an expired session', () => {
    const authorized = recordAuthorization(beginSession(POLICY, 0), 0);

    expect(authorizationValid(authorized, 3_000)).toBe(false);
    expect(evaluateSession(authorized, 3_000).expired).toBe(true);
  });

  it('closes the window on withdrawal while leaving the session live', () => {
    const withdrawn = withdrawAuthorization(
      recordAuthorization(beginSession(POLICY, 0), 0),
    );

    expect(authorizationValid(withdrawn, 1_000)).toBe(false);
    expect(evaluateSession(withdrawn, 1_000).expired).toBe(false);
  });
});
