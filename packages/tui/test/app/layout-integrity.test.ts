import { createElement } from 'react';
import { Box, renderToString } from 'ink';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { emptySnapshot, type AppSnapshot } from '../../src/app/backend.js';
import { APP_SCREEN_IDS } from '../../src/app/ids.js';
import { renderOnboardingScreen } from '../../src/app/onboarding-app.js';
import { createInitialOnboardingState } from '../../src/app/onboarding-router.js';
import { createInitialAppRouterState, navigateToScreen } from '../../src/app/router.js';
import { AppChrome, renderActiveScreen } from '../../src/app/screens.js';
import { Panel, PanelFillContext, SingleLine } from '../../src/app/widgets.js';

const SIZES = [
  [40, 12],
  [60, 20],
  [80, 24],
  [120, 36],
  [200, 50],
] as const;

function populatedSnapshot(): AppSnapshot {
  const base = emptySnapshot();
  return {
    ...base,
    home: {
      profileId: 'work',
      vaultId: 'main',
      unlocked: true,
      credentialCount: 30,
      datastore: 'file',
      message: 'Unlocked.',
    },
    profiles: [
      {
        id: 'work',
        datastore: 'file',
        selected: true,
        vault: 'main',
        detail: 'C:/Users/me/.kavrix/work.vault',
      },
      {
        id: 'cloud-team-shared-long-profile-name',
        datastore: 'mongodb',
        selected: false,
        detail: 'mongodb database kavrix_prod',
      },
    ],
    vaults: [
      {
        id: 'main',
        selected: true,
        revision: 12,
        credentialCount: 30,
        detail: 'Primary vault',
      },
    ],
    credentials: Array.from({ length: 30 }, (_, index) => ({
      name:
        index === 3
          ? 'VERY_LONG_CREDENTIAL_NAME_FOR_THE_PRODUCTION_WEBHOOK_SIGNING_KEY'
          : `API_KEY_${String(index)}`,
      maskedValue: '********',
      updatedAt: '2026-10-20T10:00:00Z',
    })),
    doctor: [
      { name: 'key-file permissions', status: 'ok', detail: 'Owner-only ACL' },
      {
        name: 'session',
        status: 'warning',
        detail:
          'Session caching is disabled for this profile so every command will prompt.',
      },
    ],
    recovery: [{ slotId: 'slot-1', status: 'active', detail: 'Created 2026-10-01' }],
    policies: [
      {
        id: 'p1',
        kind: 'policy',
        summary: 'allow node to read API_KEY_* within project scope',
        status: 'active',
      },
    ],
    browse: [{ id: 'b1', kind: 'service', label: 'stripe', detail: '3 items' }],
    session: {
      enabled: true,
      expired: false,
      createdAt: '2026-10-21T08:00:00Z',
      ttlHours: 8,
    },
    notice: 'Vault refreshed.',
    noticeTone: 'success',
  };
}

function renderScreen(
  screen: (typeof APP_SCREEN_IDS)[number],
  width: number,
  height: number,
): string {
  const state = navigateToScreen(
    {
      ...createInitialAppRouterState({ width, height, ascii: false, color: false }),
      snapshot: populatedSnapshot(),
    },
    screen,
  );
  return renderToString(
    createElement(AppChrome, { state, children: renderActiveScreen(state) }),
    {
      columns: width,
    },
  );
}

/** A closing border row must contain only border glyphs; text there is bleed. */
function bleedingBorderRows(frame: string): string[] {
  return frame
    .split('\n')
    .filter((line) => line.trimStart().startsWith('└'))
    .filter((line) => !/^[\s└┘─]+$/u.test(line));
}

function assertFrameFits(frame: string, width: number, height: number): void {
  const lines = frame.split('\n');
  expect(lines.length).toBeLessThanOrEqual(height);
  // Every glyph the TUI draws is a single-cell code point, so code points count cells.
  for (const line of lines) expect(Array.from(line).length).toBeLessThanOrEqual(width);
  expect(bleedingBorderRows(frame)).toEqual([]);
  const opened = (frame.match(/┌/gu) ?? []).length;
  const closed = (frame.match(/└/gu) ?? []).length;
  expect(closed).toBe(opened);
}

describe('responsive layout integrity', () => {
  beforeEach(() => {
    vi.stubEnv('TERM', 'xterm-256color');
    vi.stubEnv('INK_SCREEN_READER', '');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  for (const [width, height] of SIZES) {
    it(`every screen fits and keeps closed panels at ${String(width)}x${String(height)}`, () => {
      for (const screen of APP_SCREEN_IDS) {
        const frame = renderScreen(screen, width, height);
        try {
          assertFrameFits(frame, width, height);
        } catch (error) {
          throw new Error(
            `${screen} at ${String(width)}x${String(height)}:\n${frame}`,
            { cause: error },
          );
        }
      }
    });

    it(`onboarding fits at ${String(width)}x${String(height)}`, () => {
      const state = createInitialOnboardingState({
        width,
        height,
        ascii: false,
        color: false,
      });
      assertFrameFits(
        renderToString(renderOnboardingScreen(state), { columns: width }),
        width,
        height,
      );
    });
  }

  it('keeps the notice row clear of body text on a short terminal', () => {
    const frame = renderScreen('credentials', 40, 12);
    const notice = frame.split('\n').find((line) => line.includes('Vault refreshed.'));
    expect(notice?.trim()).toBe('✓ Vault refreshed.');
  });

  it('shows each credential on one row with its mask from 60 columns', () => {
    const frame = renderScreen('credentials', 60, 20);
    expect(frame).toMatch(/API_KEY_1\s+\*{8}/u);
    expect(frame).toMatch(/VERY_LONG_CREDENTIAL_NAME_FOR_T\S*…\s+\*{8}/u);
  });

  it('clips nested single-line rows inside a filled panel', () => {
    const frame = renderToString(
      createElement(
        Box,
        { flexDirection: 'column', height: 4, width: 20 },
        createElement(
          PanelFillContext.Provider,
          { value: true },
          createElement(Panel, {
            ascii: false,
            color: false,
            children: ['one', 'two', 'three', 'four'].map((label) =>
              createElement(SingleLine, { key: label }, `row ${label}`),
            ),
          }),
        ),
      ),
      { columns: 20 },
    );
    const lines = frame.split('\n');
    expect(lines).toHaveLength(4);
    expect(lines[3]).toMatch(/^└─+┘$/u);
    expect(frame).not.toContain('row three');
  });
});
