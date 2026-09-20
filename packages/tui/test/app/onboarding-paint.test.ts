import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it } from 'vitest';

import { createStaticAppBackend } from '../../src/app/static-backend.js';
import {
  KavrixOnboardingApp,
  renderOnboardingScreen,
} from '../../src/app/onboarding-app.js';
import {
  createInitialOnboardingState,
  describeOnboardingScreen,
  onboardingStepFocus,
  transitionOnboarding,
  type OnboardingKey,
  type OnboardingState,
} from '../../src/app/onboarding-router.js';

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
    expect(frame).toMatch(/ACTIVE · OWNER PASSPHRASE/i);
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
    const finished = transitionOnboarding(state, {
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
