import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it, vi } from 'vitest';

import { AppChrome, renderActiveScreen } from '../../src/app/screens.js';
import { createInitialAppRouterState } from '../../src/app/router.js';
import { renderOnboardingScreen } from '../../src/app/onboarding-app.js';
import { createInitialOnboardingState } from '../../src/app/onboarding-router.js';
import type { OnboardingStep } from '../../src/app/onboarding-router.js';

describe('terminal-filling app layouts', () => {
  it.each([
    [80, 24],
    [120, 60],
    [40, 12],
  ])('fills %i columns / %i rows and keeps setup controls visible', (width, height) => {
    vi.stubEnv('TERM', 'xterm-256color');
    vi.stubEnv('INK_SCREEN_READER', '');
    const state = createInitialOnboardingState({
      width,
      height,
      ascii: true,
      color: false,
    });
    const frame = renderToString(renderOnboardingScreen(state), { columns: width });
    const lines = frame.split('\n');
    expect(lines).toHaveLength(height);
    expect(frame).toContain('Welcome');
    expect(lines.slice(-4).join('\n')).toContain('Enter');
    expect(lines.slice(-4).join('\n')).toContain('Esc');
    expect(lines.every((line) => line.length <= width)).toBe(true);
  });

  it.each([
    [80, 24],
    [120, 60],
    [40, 12],
  ])(
    'fills %i columns / %i rows and pins main navigation to the bottom',
    (width, height) => {
      vi.stubEnv('TERM', 'xterm-256color');
      vi.stubEnv('INK_SCREEN_READER', '');
      const state = createInitialAppRouterState({
        width,
        height,
        ascii: true,
        color: false,
      });
      const frame = renderToString(
        createElement(AppChrome, { state, children: renderActiveScreen(state) }),
        { columns: width },
      );
      const lines = frame.split('\n');
      expect(lines).toHaveLength(height);
      expect(frame).toContain('kavrix');
      expect(lines.slice(-4).join('\n')).toContain('q quit');
    },
  );

  it('keeps screen-reader output content sized', () => {
    vi.stubEnv('INK_SCREEN_READER', 'true');
    const state = createInitialOnboardingState({
      width: 120,
      height: 60,
      ascii: true,
      color: false,
    });
    expect(
      renderToString(renderOnboardingScreen(state), { columns: 120 }).split('\n')
        .length,
    ).toBeLessThan(60);
  });

  it.each<OnboardingStep>([
    'storage',
    'file-key-file',
    'file-passphrase-confirm',
    'mongo-url',
    'file-recovery-passphrase-confirm',
    'error',
    'success',
  ])('keeps compact %s setup controls, focus, and ASCII output intact', (step) => {
    vi.stubEnv('TERM', 'xterm-256color');
    vi.stubEnv('INK_SCREEN_READER', '');
    const state = {
      ...createInitialOnboardingState({
        width: 40,
        height: 12,
        ascii: true,
        color: false,
      }),
      step,
      query: 'private-layout-canary',
      error: step === 'error' ? 'Please review the destination.' : null,
    };
    const frame = renderToString(renderOnboardingScreen(state), { columns: 40 });
    expect(frame.split('\n')).toHaveLength(12);
    expect(frame.split('\n').slice(-4).join('\n')).toContain('^C quit');
    expect(frame).toContain('ACTIVE');
    expect(frame).not.toMatch(/[^\x20-\x7e\n]/u);
    if (step.includes('passphrase') || step === 'mongo-url') {
      expect(frame).not.toContain(state.query);
      expect(frame).toContain('********');
    }
  });
});
