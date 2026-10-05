import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it, vi } from 'vitest';

import { createStaticAppBackend } from '../../src/app/static-backend.js';
import {
  KavrixOnboardingApp,
  renderOnboardingScreen,
} from '../../src/app/onboarding-app.js';
import {
  createInitialOnboardingState,
  describeOnboardingScreen,
  onboardingStepFocus,
  transitionOnboarding as rawTransition,
  type OnboardingKey,
  type OnboardingState,
} from '../../src/app/onboarding-router.js';

function transitionOnboarding(
  state: OnboardingState,
  action: Parameters<typeof rawTransition>[1],
): ReturnType<typeof rawTransition> {
  const next = rawTransition(state, action);
  return next.state.checkingDestination
    ? rawTransition(next.state, {
        type: 'backend-result',
        ok: true,
        notice: null,
        profileId: null,
        datastore: null,
      })
    : next;
}

function press(state: OnboardingState, key: OnboardingKey): OnboardingState {
  return transitionOnboarding(state, { type: 'key', key }).state;
}

function paint(state: OnboardingState): string {
  return renderToString(renderOnboardingScreen(state), { columns: state.width });
}

function reachFilePassphrase(): OnboardingState {
  let state = createInitialOnboardingState({
    width: 80,
    height: 24,
    ascii: true,
    color: false,
  });
  state = press(state, { name: 'return' });
  state = press(state, { name: 'return' });
  state = press(state, { name: 'return' });
  state = press(state, { name: 'return' });
  state = press(state, { name: 'return' });
  return state;
}

describe('init onboarding first paint and focus', () => {
  it.each([12, 24, 30])(
    'keeps review controls visible at height %s and omits all protected inputs',
    (height) => {
      vi.stubEnv('TERM', 'xterm-256color');
      vi.stubEnv('INK_SCREEN_READER', '');
      const state: OnboardingState = {
        ...createInitialOnboardingState({
          width: 40,
          height,
          ascii: true,
          color: false,
        }),
        step: 'review',
        storage: 'mongodb',
        profileId: 'chosen',
        database: 'chosen-db',
        keyFile: '/private/key',
        recoveryFile: '/private/recovery',
        passphrase: 'owner-canary',
        recoveryPassphrase: 'recovery-canary',
        databaseUrl: 'private-uri-canary',
      };
      const output = paint(state);
      expect(output.split('\n')).toHaveLength(height);
      expect(output).toContain('Enter create');
      expect(output).toContain('1 profile');
      expect(output).toContain('4 recovery');
      expect(output).not.toContain('owner-canary');
      expect(output).not.toContain('recovery-canary');
      expect(output).not.toContain('private-uri-canary');
    },
  );
  it('masks protected input on both sides of a moved cursor', () => {
    const state = {
      ...createInitialOnboardingState({ ascii: true, color: false }),
      step: 'mongo-url' as const,
      query: 'private-uri-canary',
      cursor: 4,
    };
    const output = paint(state);
    expect(output).toContain('****_');
    expect(output).not.toContain('private-uri-canary');
  });
  it('renders a public operation stage with elapsed time without protected values', () => {
    const state = {
      ...createInitialOnboardingState({ ascii: true, color: false }),
      step: 'creating' as const,
      progress: { stage: 'verifying-recovery' as const },
      elapsedSeconds: 7,
      message: 'private-stage-message-canary',
    };
    const output = paint(state);
    expect(output).toContain('Verifying recovery kit');
    expect(output).toContain('Elapsed 7s');
    expect(output).not.toMatch(/\d+%/u);
  });
  it('does not let the showcase backend claim that filesystem permissions were verified', async () => {
    const result = await createStaticAppBackend().dispatch({
      type: 'validate-profile-destination',
      path: '/private/new.key',
    });
    expect(result.snapshot.noticeTone).toBe('error');
    expect(result.snapshot.notice).toContain('cannot verify filesystem permissions');
  });
  it('paints welcome with an obvious ACTIVE step on tall terminals', () => {
    const state = createInitialOnboardingState({
      width: 120,
      height: 60,
      ascii: true,
      color: false,
    });
    expect(describeOnboardingScreen(state)).toContain('step=welcome');
    expect(onboardingStepFocus(state.step)).toMatchObject({
      title: 'Welcome',
      cue: 'THIS STEP IS ACTIVE',
    });
    expect(() =>
      createElement(KavrixOnboardingApp, {
        backend: createStaticAppBackend(),
        ascii: true,
        color: false,
        noSplash: true,
      }),
    ).not.toThrow();
    const frame = paint(state);
    expect(frame.length).toBeGreaterThan(40);
    expect(frame).toMatch(/ACTIVE 1\/\d+/i);
    expect(frame).toMatch(/Welcome/i);
    expect(frame).toMatch(/THIS STEP IS\s+ACTIVE/i);
    expect(frame).toMatch(/Initialize a Kavrix vault/i);
  });

  it('paints the passphrase step instead of a stale Storage or Key-file frame', () => {
    const state = reachFilePassphrase();
    expect(state.step).toBe('file-passphrase');
    const focus = onboardingStepFocus(state.step);
    expect(focus.title).toBe('Owner passphrase');
    expect(focus.cue).toBe('TYPE HERE (masked)');
    const frame = paint(state);
    expect(frame).toMatch(/ACTIVE \d+\/\d+/i);
    expect(frame).toMatch(/Owner passphrase/i);
    expect(frame).toMatch(/TYPE HERE \(masked\)/i);
    expect(frame).toMatch(/ACTIVE - OWNER PASSPHRASE/i);
    expect(frame).not.toMatch(/Local encrypted file/i);
    expect(frame).not.toMatch(/Key file:/i);
  });

  it('keeps recovery-kit input focused and finishable after owner passphrase', () => {
    let state = reachFilePassphrase();
    for (const ch of 'correct-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'correct-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-recovery-passphrase');
    const recoveryFrame = paint(state);
    expect(recoveryFrame).toMatch(/ACTIVE \d+\/\d+/i);
    expect(recoveryFrame).toMatch(/Recovery-kit passphrase/i);
    expect(recoveryFrame).toMatch(/TYPE HERE \(masked\)/i);
    expect(recoveryFrame).not.toMatch(/Owner passphrase:/i);
    for (const ch of 'recovery-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'recovery-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-recovery-file');
    const pathFrame = paint(state);
    expect(pathFrame).toMatch(/ACTIVE \d+\/\d+/i);
    expect(pathFrame).toMatch(/Recovery kit path/i);
    expect(pathFrame).toMatch(/TYPE HERE/i);
    const reviewed = transitionOnboarding(state, {
      type: 'key',
      key: { name: 'return' },
    });
    expect(reviewed.state.step).toBe('review');
    expect(paint(reviewed.state)).not.toContain('correct-horse-battery');
    const finished = transitionOnboarding(reviewed.state, {
      type: 'key',
      key: { name: 'return' },
    });
    expect(finished.state.step).toBe('creating');
    expect(finished.effect.kind).toBe('backend');
    const creating = paint(finished.state);
    expect(creating).toMatch(/PLEASE WAIT/i);
    expect(creating).not.toMatch(/TYPE HERE/i);
  });

  it('clamps missing TTY size so first chrome still has a usable width', () => {
    const state = createInitialOnboardingState({
      width: 0,
      height: 0,
      ascii: true,
      color: false,
    });
    expect(state.width).toBeGreaterThanOrEqual(40);
    expect(state.height).toBeGreaterThanOrEqual(12);
    const frame = paint(state);
    expect(frame.length).toBeGreaterThan(40);
    expect(frame).toMatch(/ACTIVE 1\/\d+/i);
    expect(frame).toMatch(/Welcome/i);
    expect(frame).toMatch(/THIS STEP IS\s+ACTIVE/i);
  });
});
