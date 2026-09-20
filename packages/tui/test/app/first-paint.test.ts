import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it } from 'vitest';

import {
  createInitialAppRouterState,
  createInitialOnboardingState,
  describeOnboardingScreen,
} from '../../src/index.js';
import { AppChrome, renderActiveScreen } from '../../src/app/screens.js';
import { KavrixOnboardingApp } from '../../src/app/onboarding-app.js';
import { createStaticAppBackend } from '../../src/app/static-backend.js';

/**
 * Regression for blank TTY hydrate: chrome must paint on tall terminals without
 * pinning height={rows} (Ink/Yoga blank). renderToString exercises layout.
 */
describe('TUI first paint reliability', () => {
  it('renders home chrome for a tall terminal size without blanking', () => {
    const state = createInitialAppRouterState({
      width: 120,
      height: 60,
      ascii: true,
      color: false,
    });
    const frame = renderToString(
      createElement(AppChrome, {
        state,
        children: renderActiveScreen(state),
      }),
      { columns: 120 },
    );
    expect(frame.length).toBeGreaterThan(40);
    expect(frame).toMatch(/product|lock|profile|CredVault|KAVRIX|Navigate|home/i);
  });

  it('keeps onboarding initial step visible for tall terminals', () => {
    const state = createInitialOnboardingState({
      width: 120,
      height: 60,
      ascii: true,
      color: false,
    });
    expect(describeOnboardingScreen(state)).toContain('step=welcome');
    // Mount path still constructs without throwing for large sizes.
    expect(() =>
      createElement(KavrixOnboardingApp, {
        backend: createStaticAppBackend(),
        ascii: true,
        color: false,
        noSplash: true,
      }),
    ).not.toThrow();
  });
});
