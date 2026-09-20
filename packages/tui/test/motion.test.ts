import { describe, expect, it } from 'vitest';

import {
  applyEase,
  clamp01,
  easeOutExpo,
  easeOutQuad,
  enterDimmed,
  enterOffsetCells,
  MOTION,
  resolveMotionPolicy,
  staggerVisibleCount,
} from '../src/motion.js';
import {
  DEFAULT_EXECUTABLE_NAME,
  DEFAULT_PRODUCT_LABEL,
  resolveProductIdentity,
} from '../src/product.js';
import { splashEnabled } from '../src/splash.js';

describe('motion policy', () => {
  it('animates by default and fail-closes on reduced-motion flags', () => {
    expect(resolveMotionPolicy({ env: {} }).animate).toBe(true);
    expect(resolveMotionPolicy({ requested: false, env: {} }).animate).toBe(false);
    expect(
      resolveMotionPolicy({ env: { KAVRIX_TUI_REDUCED_MOTION: '1' } }).animate,
    ).toBe(false);
    expect(
      resolveMotionPolicy({ env: { PREFERS_REDUCED_MOTION: 'true' } }).animate,
    ).toBe(false);
  });

  it('skips splash when reduced motion is set', () => {
    expect(splashEnabled({ env: {} })).toBe(true);
    expect(splashEnabled({ env: { KAVRIX_TUI_REDUCED_MOTION: '1' } })).toBe(false);
    expect(splashEnabled({ noSplash: true, env: {} })).toBe(false);
  });
});

describe('easing and stagger', () => {
  it('uses OpenTUI outQuad / outExpo and keeps stagger decorative', () => {
    expect(clamp01(-1)).toBe(0);
    expect(clamp01(2)).toBe(1);
    expect(easeOutQuad(0)).toBe(0);
    expect(easeOutQuad(1)).toBe(1);
    expect(easeOutQuad(0.5)).toBeGreaterThan(0.5);
    expect(easeOutExpo(1)).toBe(1);
    expect(applyEase(0.25, 'linear')).toBe(0.25);
    expect(staggerVisibleCount(0, 12, MOTION.staggerMs)).toBe(1);
    expect(staggerVisibleCount(MOTION.staggerMs * 3, 12)).toBe(4);
    expect(staggerVisibleCount(MOTION.staggerMs * MOTION.staggerCap, 12)).toBe(12);
    expect(enterOffsetCells(0.2, true)).toBe(1);
    expect(enterOffsetCells(1, true)).toBe(0);
    expect(enterDimmed(0.2, true)).toBe(true);
    expect(enterDimmed(1, true)).toBe(false);
  });
});

describe('product identity', () => {
  it('defaults to CredVault / creds and accepts overrides', () => {
    expect(resolveProductIdentity()).toEqual({
      productLabel: DEFAULT_PRODUCT_LABEL,
      executableName: DEFAULT_EXECUTABLE_NAME,
    });
    expect(resolveProductIdentity({ productLabel: '  ', executableName: '' })).toEqual({
      productLabel: 'CredVault',
      executableName: 'creds',
    });
    expect(
      resolveProductIdentity({ productLabel: 'VaultOne', executableName: 'vo' }),
    ).toEqual({
      productLabel: 'VaultOne',
      executableName: 'vo',
    });
  });
});
