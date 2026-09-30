import { afterEach, describe, expect, it } from 'vitest';

import {
  activeTuiTheme,
  activeTuiThemeId,
  applyTuiTheme,
  CHROME,
  defaultThemeForPlatform,
  isThemeId,
  panelBorderStyle,
  screenAccent,
  THEMES,
  toneAccent,
  TUI_THEME_IDS,
} from '../src/app/theme.js';

const ORIGINAL = activeTuiThemeId();

afterEach(() => {
  applyTuiTheme(ORIGINAL);
});

describe('TUI theme registry', () => {
  it('ships exactly five distinct themes', () => {
    expect(THEMES).toHaveLength(5);
    expect(TUI_THEME_IDS).toEqual(['gold', 'ocean', 'magma', 'forest', 'violet']);
    expect(new Set(THEMES.map((theme) => theme.id)).size).toBe(5);
    // Five genuinely different accent hues.
    expect(new Set(THEMES.map((theme) => theme.accent)).size).toBe(5);
    for (const theme of THEMES) {
      expect(theme.label.length).toBeGreaterThan(0);
      expect(theme.description.length).toBeGreaterThan(0);
    }
  });

  it('validates theme ids', () => {
    for (const id of TUI_THEME_IDS) expect(isThemeId(id)).toBe(true);
    expect(isThemeId('neon')).toBe(false);
    expect(isThemeId('')).toBe(false);
    expect(isThemeId('GOLD')).toBe(false);
  });

  it('maps platform defaults: ocean on Windows, gold elsewhere', () => {
    expect(defaultThemeForPlatform('win32')).toBe('ocean');
    expect(defaultThemeForPlatform('darwin')).toBe('gold');
    expect(defaultThemeForPlatform('linux')).toBe('gold');
  });

  it('applyTuiTheme swaps chrome tokens and the active id together', () => {
    applyTuiTheme('magma');
    expect(activeTuiThemeId()).toBe('magma');
    expect(activeTuiTheme().label).toBe('Magma');
    expect(CHROME.accent).toBe('red');
    expect(CHROME.heading).toBe('magenta');
    expect(CHROME.selection).toBe('magenta');
    expect(CHROME.bar).toBe('red');

    applyTuiTheme('forest');
    expect(CHROME.accent).toBe('green');
    expect(CHROME.bar).toBe('green');

    applyTuiTheme('violet');
    expect(CHROME.accent).toBe('magenta');
    expect(CHROME.selection).toBe('blue');
  });

  it('keeps semantic status tones fixed across every theme', () => {
    for (const theme of THEMES) {
      applyTuiTheme(theme.id);
      expect(toneAccent('success')).toBe('green');
      expect(toneAccent('warning')).toBe('yellow');
      expect(toneAccent('error')).toBe('red');
      expect(toneAccent('info')).toBe('cyan');
    }
  });

  it('uses the theme panel border, forces double for modals, classic for ascii', () => {
    applyTuiTheme('ocean');
    expect(panelBorderStyle(false)).toBe('single');
    applyTuiTheme('magma');
    expect(panelBorderStyle(false)).toBe('double');
    applyTuiTheme('gold');
    expect(panelBorderStyle(false)).toBe('round');
    expect(panelBorderStyle(false, 'modal')).toBe('double');
    // ASCII degradation wins regardless of theme.
    applyTuiTheme('ocean');
    expect(panelBorderStyle(true)).toBe('classic');
    expect(panelBorderStyle(true, 'modal')).toBe('classic');
  });

  it('screenAccent follows the active theme with fixed recovery/help overrides', () => {
    applyTuiTheme('forest');
    expect(screenAccent('home')).toBe('green');
    expect(screenAccent('credentials')).toBe('green');
    expect(screenAccent('recovery')).toBe('red');
    expect(screenAccent('help')).toBe(CHROME.heading);
  });
});
