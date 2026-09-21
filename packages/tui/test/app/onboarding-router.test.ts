import { describe, expect, it } from 'vitest';

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

describe('init onboarding router', () => {
  it('walks welcome → storage → file create effect with recovery kit', () => {
    let state = createInitialOnboardingState({ ascii: true, color: false });
    expect(describeOnboardingScreen(state)).toContain('step=welcome');

    state = press(state, { name: 'return' });
    expect(state.step).toBe('storage');

    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-profile-id');
    expect(state.query).toBe('default');

    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-data-file');

    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-key-file');

    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-passphrase');

    for (const ch of 'correct-horse-battery') {
      state = press(state, { text: ch });
    }
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-passphrase-confirm');

    for (const ch of 'correct-horse-battery') {
      state = press(state, { text: ch });
    }
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-recovery-passphrase');

    for (const ch of 'recovery-horse-battery') {
      state = press(state, { text: ch });
    }
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-recovery-passphrase-confirm');

    for (const ch of 'recovery-horse-battery') {
      state = press(state, { text: ch });
    }
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-recovery-file');
    expect(state.query).toMatch(/\.kavrix[/\\]kavrix\.recovery$/);

    const transition = transitionOnboarding(state, {
      type: 'key',
      key: { name: 'return' },
    });
    expect(transition.state.step).toBe('creating');
    expect(transition.effect.kind).toBe('backend');
    if (transition.effect.kind === 'backend') {
      expect(transition.effect.action).toMatchObject({
        type: 'create-file-profile',
        profileId: 'default',
        passphrase: 'correct-horse-battery',
        recoveryPassphrase: 'recovery-horse-battery',
      });
      expect(
        'dataFile' in transition.effect.action &&
          transition.effect.action.dataFile.length > 0,
      ).toBe(true);
      expect(
        'recoveryFile' in transition.effect.action &&
          typeof transition.effect.action.recoveryFile === 'string' &&
          transition.effect.action.recoveryFile.includes('.kavrix'),
      ).toBe(true);
    }
  });

  it('selects mongodb path and masks URL step', () => {
    let state = createInitialOnboardingState();
    state = press(state, { name: 'return' });
    state = press(state, { name: 'down' });
    expect(state.storageIndex).toBe(1);
    state = press(state, { name: 'return' });
    expect(state.step).toBe('mongo-profile-id');
    state = press(state, { name: 'return' });
    expect(state.step).toBe('mongo-database');
    state = press(state, { name: 'return' });
    expect(state.step).toBe('mongo-key-file');
    state = press(state, { name: 'return' });
    expect(state.step).toBe('mongo-url');
  });

  it('cancels from welcome with q', () => {
    let state = createInitialOnboardingState();
    state = press(state, { text: 'q' });
    expect(state.quit).toBe(true);
  });

  it('marks success from backend-result', () => {
    const state = {
      ...createInitialOnboardingState(),
      step: 'creating' as const,
      storage: 'file' as const,
      profileId: 'default',
    };
    const next = transitionOnboarding(state, {
      type: 'backend-result',
      ok: true,
      notice: 'Created',
      profileId: 'default',
      datastore: 'file',
    });
    // Create success now lands on the enable-session ask (0.2.24).
    expect(next.state.step).toBe('enable-session');
    expect(next.state.completed).toBe(false);
    expect(next.state.passphrase).toBeNull();
    expect(next.state.message).toMatch(/Enable OS session unlock/i);

    const enable = transitionOnboarding(next.state, {
      type: 'backend-result',
      ok: true,
      notice: 'Session unlock enabled.',
      profileId: 'default',
      datastore: 'file',
    });
    expect(enable.state.step).toBe('success');
    expect(enable.state.completed).toBe(true);
    expect(enable.state.completedProfileId).toBe('default');
    expect(enable.state.passphrase).toBeNull();
  });

  it('rejects mismatched passphrase confirm', () => {
    let state = createInitialOnboardingState({ ascii: true });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    for (const ch of 'correct-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'correct-horse-staple!') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-passphrase');
    expect(state.message).toMatch(/did not match/i);
  });

  it('rejects short passphrases before create', () => {
    let state = createInitialOnboardingState({ ascii: true });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    for (const ch of 'short') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-passphrase');
    expect(state.message).toMatch(/at least 16/i);
  });

  it('steps back one field on Esc', () => {
    let state = createInitialOnboardingState();
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-profile-id');
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-data-file');
    state = press(state, { name: 'escape' });
    expect(state.step).toBe('file-profile-id');
    expect(state.query).toBe('default');
    state = press(state, { name: 'escape' });
    expect(state.step).toBe('storage');
  });

  it('ignores Ctrl+C while creating', () => {
    const state = {
      ...createInitialOnboardingState(),
      step: 'creating' as const,
      storage: 'file' as const,
      message: 'Creating…',
    };
    const next = press(state, { text: 'c', ctrl: true });
    expect(next.quit).toBe(false);
    expect(next.step).toBe('creating');
  });

  it('cancels from welcome with Esc', () => {
    let state = createInitialOnboardingState();
    state = press(state, { name: 'escape' });
    expect(state.quit).toBe(true);
  });

  it('wires mongodb create-mongodb-profile effect with recovery kit', () => {
    let state = createInitialOnboardingState();
    state = press(state, { name: 'return' });
    state = press(state, { name: 'down' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' }); // profile id
    state = press(state, { name: 'return' }); // database
    state = press(state, { name: 'return' }); // key file
    for (const ch of 'mongodb://127.0.0.1:27017') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('mongo-passphrase');
    for (const ch of 'correct-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'correct-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('mongo-recovery-passphrase');
    for (const ch of 'recovery-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'recovery-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('mongo-recovery-file');
    const transition = transitionOnboarding(state, {
      type: 'key',
      key: { name: 'return' },
    });
    expect(transition.state.step).toBe('creating');
    expect(transition.effect.kind).toBe('backend');
    if (transition.effect.kind === 'backend') {
      expect(transition.effect.action).toMatchObject({
        type: 'create-mongodb-profile',
        profileId: 'default',
        databaseUrl: 'mongodb://127.0.0.1:27017',
        passphrase: 'correct-horse-battery',
        recoveryPassphrase: 'recovery-horse-battery',
      });
      expect(
        'recoveryFile' in transition.effect.action &&
          typeof transition.effect.action.recoveryFile === 'string',
      ).toBe(true);
    }
  });

  it('rejects invalid profile ids with a clear message', () => {
    let state = createInitialOnboardingState();
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'backspace' });
    state = press(state, { name: 'backspace' });
    state = press(state, { name: 'backspace' });
    state = press(state, { name: 'backspace' });
    state = press(state, { name: 'backspace' });
    state = press(state, { name: 'backspace' });
    state = press(state, { name: 'backspace' });
    for (const ch of '-bad') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-profile-id');
    expect(state.message).toMatch(/Profile id must/i);
  });

  it('surfaces backend failure without quitting so user can retry', () => {
    const state = {
      ...createInitialOnboardingState(),
      step: 'creating' as const,
      storage: 'file' as const,
    };
    const next = transitionOnboarding(state, {
      type: 'backend-result',
      ok: false,
      notice: 'The datastore profile already exists.',
      profileId: null,
      datastore: null,
    });
    expect(next.state.step).toBe('error');
    expect(next.state.quit).toBe(false);
    expect(next.state.error).toMatch(/already exists/i);
  });

  it('rejects mismatched recovery passphrase confirm', () => {
    let state = createInitialOnboardingState({ ascii: true });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    for (const ch of 'correct-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'correct-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-recovery-passphrase');
    for (const ch of 'recovery-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'recovery-horse-staple!') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-recovery-passphrase');
    expect(state.message).toMatch(/did not match/i);
  });

  it('steps back from recovery file to recovery passphrase confirm', () => {
    let state = createInitialOnboardingState();
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    state = press(state, { name: 'return' });
    for (const ch of 'correct-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'correct-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'recovery-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    for (const ch of 'recovery-horse-battery') state = press(state, { text: ch });
    state = press(state, { name: 'return' });
    expect(state.step).toBe('file-recovery-file');
    state = press(state, { name: 'escape' });
    expect(state.step).toBe('file-recovery-passphrase-confirm');
  });

  it('exposes an obvious focus cue for welcome, passphrase, and recovery', () => {
    expect(onboardingStepFocus('welcome').cue).toBe('THIS STEP IS ACTIVE');
    expect(onboardingStepFocus('storage').title).toBe('Choose storage');
    expect(onboardingStepFocus('file-passphrase')).toMatchObject({
      title: 'Owner passphrase',
      cue: 'TYPE HERE (masked)',
    });
    expect(onboardingStepFocus('file-recovery-passphrase')).toMatchObject({
      title: 'Recovery-kit passphrase',
      cue: 'TYPE HERE (masked)',
    });
    expect(onboardingStepFocus('creating').cue).toMatch(/PLEASE WAIT/i);
    expect(describeOnboardingScreen(createInitialOnboardingState())).toMatch(
      /focus=1\/\d+:Welcome:THIS STEP IS ACTIVE/,
    );
  });

  it('records completedRecoveryFile on backend success', () => {
    const state = {
      ...createInitialOnboardingState(),
      step: 'creating' as const,
      storage: 'file' as const,
      profileId: 'default',
      recoveryFile: '/home/user/.kavrix/kavrix.recovery',
    };
    const next = transitionOnboarding(state, {
      type: 'backend-result',
      ok: true,
      notice: 'Created',
      profileId: 'default',
      datastore: 'file',
    });
    expect(next.state.step).toBe('enable-session');
    const finish = transitionOnboarding(next.state, {
      type: 'backend-result',
      ok: true,
      notice: 'ok',
      profileId: 'default',
      datastore: 'file',
    });
    expect(finish.state.completedRecoveryFile).toBe(
      '/home/user/.kavrix/kavrix.recovery',
    );
  });
});
