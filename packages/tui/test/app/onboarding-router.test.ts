import { describe, expect, it } from 'vitest';

import {
  createInitialOnboardingState,
  describeOnboardingScreen,
  transitionOnboarding,
  type OnboardingKey,
  type OnboardingState,
} from '../../src/index.js';

function press(state: OnboardingState, key: OnboardingKey): OnboardingState {
  return transitionOnboarding(state, { type: 'key', key }).state;
}

describe('init onboarding router', () => {
  it('walks welcome → storage → file create effect', () => {
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
      });
      expect(
        'dataFile' in transition.effect.action &&
          transition.effect.action.dataFile.length > 0,
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
    expect(next.state.step).toBe('success');
    expect(next.state.completed).toBe(true);
    expect(next.state.completedProfileId).toBe('default');
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

  it('wires mongodb create-mongodb-profile effect', () => {
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
      });
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
});
