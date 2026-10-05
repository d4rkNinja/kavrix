import { describe, expect, it } from 'vitest';
import {
  createInitialOnboardingState,
  transitionOnboarding,
  type OnboardingState,
  type OnboardingKey,
} from '../../src/app/onboarding-router.js';
import { homedir } from 'node:os';

const key = (
  state: OnboardingState,
  key: OnboardingKey,
): ReturnType<typeof transitionOnboarding> =>
  transitionOnboarding(state, { type: 'key', key });
const result = (
  state: OnboardingState,
  setup: Parameters<typeof transitionOnboarding>[1] & { type: 'backend-result' },
): ReturnType<typeof transitionOnboarding> => transitionOnboarding(state, setup);
const reply = {
  type: 'backend-result' as const,
  ok: true,
  notice: 'Checked.',
  profileId: null,
  datastore: null,
};
function review(): OnboardingState {
  return {
    ...createInitialOnboardingState(),
    storage: 'file',
    step: 'review',
    profileId: 'chosen',
    dataFile: '/private/data',
    keyFile: '/private/key',
    recoveryFile: '/private/recovery',
    passphrase: 'owner-input-canary',
    recoveryPassphrase: 'recovery-input-canary',
  };
}
describe('setup correction and review controls', () => {
  it('starts browsing at home for secure defaults even before the artifact folder exists', () => {
    const state: OnboardingState = { ...review(), step: 'file-key-file', query: '' };
    const empty = key(state, { text: 'b', ctrl: true });
    expect(empty.effect).toEqual({
      kind: 'backend',
      action: { type: 'browse-setup-folders', path: homedir() },
    });
    const populated = key(key(state, { text: 'd', ctrl: true }).state, {
      text: 'b',
      ctrl: true,
    });
    expect(populated.effect).toEqual(empty.effect);
  });
  it('refuses mismatched tool results and a successful status paired with a failed operation', () => {
    const checking = key(
      {
        ...review(),
        step: 'mongo-url',
        query: 'mongodb://localhost/test',
        database: 'test',
      },
      { text: 't', ctrl: true },
    ).state;
    const mismatch = result(checking, {
      ...reply,
      setup: { kind: 'repair', directory: '/private', mode: 'preview' },
    });
    expect(mismatch.state.toolView).toBeNull();
    expect(mismatch.state.connectionVerified).toBe(false);
    expect(mismatch.state.step).toBe('mongo-url');
    const disagreement = result(checking, {
      ...reply,
      ok: false,
      setup: { kind: 'connection', status: 'ok' },
    });
    expect(disagreement.state.connectionVerified).toBe(false);
    expect(key(disagreement.state, { name: 'return' }).effect).toMatchObject({
      kind: 'backend',
      action: { type: 'test-setup-mongodb' },
    });
  });
  it('edits public review choices without requesting protected inputs again', () => {
    const editing = key(review(), { text: '1' }).state;
    expect(editing.step).toBe('file-profile-id');
    const cleared = key(editing, { text: 'u', ctrl: true }).state;
    const typed = key(cleared, { text: 'renamed' }).state;
    const saved = key(typed, { name: 'return' });
    expect(saved.effect.kind).toBe('none');
    expect(saved.state.step).toBe('review');
    expect(saved.state.profileId).toBe('renamed');
    expect(saved.state.passphrase).toBe('owner-input-canary');
    const create = key(saved.state, { name: 'return' });
    expect(create.effect).toMatchObject({
      kind: 'backend',
      action: {
        type: 'create-file-profile',
        profileId: 'renamed',
        passphrase: 'owner-input-canary',
      },
    });
    expect(create.state.passphrase).toBeNull();
    expect(create.state.recoveryPassphrase).toBeNull();
    expect(key(create.state, { name: 'return' }).effect.kind).toBe('none');
  });
  it('checks edited destinations before returning to review, retaining answers after rejection', () => {
    const editing = key(review(), { text: '3' }).state;
    const checking = key(editing, { name: 'return' });
    expect(checking.effect).toEqual({
      kind: 'backend',
      action: { type: 'validate-profile-destination', path: '/private/key' },
    });
    const rejected = result(checking.state, {
      ...reply,
      ok: false,
      notice: 'Unsafe folder.',
    }).state;
    expect(rejected.step).toBe('file-key-file');
    expect(rejected.passphrase).toBe('owner-input-canary');
    expect(rejected.destinationRejected).toBe(true);
    const retry = key(rejected, { name: 'return' });
    expect(result(retry.state, reply).state.step).toBe('review');
  });
  it('requires preview and confirmation before applying a directory repair', () => {
    const state: OnboardingState = {
      ...review(),
      step: 'file-key-file',
      query: '/private/key',
      editingReview: true,
    };
    const preview = key(state, { text: 'r', ctrl: true });
    expect(preview.effect).toEqual({
      kind: 'backend',
      action: { type: 'repair-setup-directory', path: '/private/key', mode: 'preview' },
    });
    expect(key(preview.state, { name: 'return' }).effect.kind).toBe('none');
    const viewed = result(preview.state, {
      ...reply,
      setup: { kind: 'repair', directory: '/private', mode: 'preview' },
    }).state;
    expect(key(viewed, { name: 'escape' }).state.toolView).toBeNull();
    expect(key(viewed, { name: 'return' }).effect).toEqual({
      kind: 'backend',
      action: { type: 'repair-setup-directory', path: '/private/key', mode: 'apply' },
    });
  });
  it('chooses a browsed folder while preserving the filename and requiring validation', () => {
    const state: OnboardingState = {
      ...review(),
      step: 'file-key-file',
      query: '/private/key',
      editingReview: true,
    };
    const browse = key(state, { text: 'b', ctrl: true });
    const viewed = result(browse.state, {
      ...reply,
      setup: {
        kind: 'folders',
        directory: '/chosen',
        parent: '/',
        entries: [],
        truncated: false,
      },
    }).state;
    const selected = key(viewed, { text: 's', ctrl: true });
    expect(selected.state.query.replaceAll('\\', '/')).toBe('/chosen/key');
    expect(selected.state.toolView).toBeNull();
    expect(key(selected.state, { name: 'return' }).effect).toMatchObject({
      kind: 'backend',
      action: { type: 'validate-profile-destination' },
    });
    expect(key(selected.state, { text: 'd', ctrl: true }).state.query).toContain(
      '.kavrix',
    );
  });
  it('supports Unicode insertion and deletion at the cursor', () => {
    let state: OnboardingState = { ...review(), step: 'file-data-file', query: 'a😀c' };
    state = key(state, { name: 'left' }).state;
    state = key(state, { text: 'b' }).state;
    expect(state.query).toBe('a😀bc');
    state = key(state, { name: 'backspace' }).state;
    expect(state.query).toBe('a😀c');
    state = key(state, { name: 'home' }).state;
    state = key(state, { name: 'delete' }).state;
    expect(state.query).toBe('😀c');
    state = key(state, { name: 'end' }).state;
    state = key(state, { text: 'z' }).state;
    expect(state.query).toBe('😀cz');
  });
  it('invalidates a verified connection after URI edits and blocks duplicate tests', () => {
    let state: OnboardingState = {
      ...review(),
      storage: 'mongodb',
      step: 'mongo-url',
      database: 'chosen',
      query: 'mongodb://localhost/test',
    };
    const check = key(state, { text: 't', ctrl: true });
    expect(check.effect).toMatchObject({
      kind: 'backend',
      action: { type: 'test-setup-mongodb' },
    });
    expect(key(check.state, { name: 'return' }).effect.kind).toBe('none');
    state = result(check.state, {
      ...reply,
      setup: { kind: 'connection', status: 'ok' },
    }).state;
    expect(state.connectionVerified).toBe(true);
    state = key(state, { name: 'backspace' }).state;
    expect(state.connectionVerified).toBe(false);
    expect(key(state, { name: 'return' }).effect).toMatchObject({
      kind: 'backend',
      action: { type: 'test-setup-mongodb' },
    });
  });
  it('retests after editing a database name from review', () => {
    const state: OnboardingState = {
      ...review(),
      storage: 'mongodb',
      database: 'old',
      databaseUrl: 'mongodb://localhost/test',
      connectionVerified: true,
    };
    const edited = key(key(state, { text: '2' }).state, {
      text: 'u',
      ctrl: true,
    }).state;
    const saved = key(key(edited, { text: 'new' }).state, { name: 'return' }).state;
    expect(saved.step).toBe('review');
    expect(saved.connectionVerified).toBe(false);
    expect(key(saved, { name: 'return' }).effect).toMatchObject({
      kind: 'backend',
      action: { type: 'test-setup-mongodb', database: 'new' },
    });
  });
});
