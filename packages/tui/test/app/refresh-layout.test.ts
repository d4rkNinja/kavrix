import { createElement } from 'react';
import { renderToString } from 'ink';
import { describe, expect, it } from 'vitest';

import { emptySnapshot } from '../../src/app/backend.js';
import { APP_SCREEN_IDS } from '../../src/app/ids.js';
import {
  createInitialAppRouterState,
  navigateToScreen,
  transitionAppRouter,
} from '../../src/app/router.js';
import { AppChrome, renderActiveScreen } from '../../src/app/screens.js';

describe('refreshed terminal layout', () => {
  for (const [width, height] of [
    [40, 18],
    [80, 24],
    [120, 36],
  ] as const) {
    it(`keeps every screen and its exit controls within ${String(width)}x${String(height)}`, () => {
      for (const screen of APP_SCREEN_IDS) {
        const state = navigateToScreen(
          createInitialAppRouterState({ width, height, ascii: true, color: false }),
          screen,
        );
        const frame = renderToString(
          createElement(AppChrome, { state, children: renderActiveScreen(state) }),
          { columns: width },
        );
        const lines = frame.split('\n');
        expect(lines.length, screen).toBeLessThan(height);
        expect(
          Math.max(...lines.map((line) => line.length)),
          screen,
        ).toBeLessThanOrEqual(width);
        expect(frame, screen).toMatch(/q quit/u);
        expect(frame, screen).toMatch(/^[\x20-\x7e\n]*$/u);
      }
    });

    it(`keeps all themes and confirmation controls visible at ${String(width)}x${String(height)}`, () => {
      const base = createInitialAppRouterState({
        width,
        height,
        ascii: true,
        color: false,
      });
      for (const key of ['t', 'l']) {
        const state = transitionAppRouter(base, {
          type: 'key',
          key: { text: key },
          nowMs: 0,
        }).state;
        const frame = renderToString(
          createElement(AppChrome, { state, children: renderActiveScreen(state) }),
          { columns: width },
        );
        expect(frame.split('\n').length).toBeLessThan(height);
        expect(frame).toContain('Esc cancel');
        if (key === 't') {
          expect(frame).toContain('Classic Gold');
          expect(frame).toContain('Deep Ocean');
          expect(frame).toContain('Violet Dusk');
          expect(frame).toContain('Enter apply theme');
        } else {
          expect(frame).toContain('y confirm');
          expect(frame).toContain('n cancel');
        }
      }
    });

    it(`keeps the selected row in a large profile list visible at ${String(width)}x${String(height)}`, () => {
      const state = {
        ...navigateToScreen(
          createInitialAppRouterState({ width, height, ascii: true, color: false }),
          'profiles',
        ),
        listIndex: 73,
        snapshot: {
          ...emptySnapshot(),
          profiles: Array.from({ length: 100 }, (_, index) => ({
            id: `profile-${String(index)}`,
            datastore: 'file' as const,
            selected: false,
            detail: 'A long display label '.repeat(20),
          })),
        },
      };
      const frame = renderToString(
        createElement(AppChrome, { state, children: renderActiveScreen(state) }),
        { columns: width },
      );
      expect(frame).toContain('> profile-73');
      expect(frame).not.toContain('profile-0 ');
      expect(frame.split('\n').length).toBeLessThan(height);
      expect(frame).toMatch(/q quit/u);
      expect(frame).toMatch(/^[\x20-\x7e\n]*$/u);
    });
  }
});
