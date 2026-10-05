import { describe, expect, it } from 'vitest';
import {
  setupToolActionSchema,
  setupToolResultSchema,
  setupProgressSchema,
} from '../src/setup-tools.js';

describe('bounded setup tools', () => {
  it('keeps protected input out of filesystem actions', () => {
    expect(
      setupToolActionSchema.safeParse({
        type: 'browse-setup-folders',
        path: '/private',
        databaseUrl: 'protected',
      }).success,
    ).toBe(false);
    expect(
      setupToolActionSchema.safeParse({
        type: 'repair-setup-directory',
        path: '/private/key',
        mode: 'preview',
        passphrase: 'protected',
      }).success,
    ).toBe(false);
    for (const path of ['', 'x'.repeat(4097), 'bad\0path'])
      expect(
        setupToolActionSchema.safeParse({ type: 'browse-setup-folders', path }).success,
      ).toBe(false);
  });
  it('bounds directory listings and excludes file content', () => {
    const value = {
      kind: 'folders',
      directory: '/private',
      parent: '/',
      entries: [{ name: 'child', path: '/private/child' }],
      truncated: false,
    };
    expect(setupToolResultSchema.parse(value)).toEqual(value);
    expect(
      setupToolResultSchema.safeParse({
        ...value,
        entries: Array.from({ length: 101 }, () => value.entries[0]),
      }).success,
    ).toBe(false);
    expect(
      setupToolResultSchema.safeParse({ ...value, contents: 'protected' }).success,
    ).toBe(false);
  });
  it('accepts only known progress stages without secret-bearing free text', () => {
    expect(setupProgressSchema.parse({ stage: 'verifying-recovery' })).toEqual({
      stage: 'verifying-recovery',
    });
    expect(
      setupProgressSchema.safeParse({
        stage: 'verifying-recovery',
        detail: 'protected',
      }).success,
    ).toBe(false);
    expect(setupProgressSchema.safeParse({ stage: 'invented' }).success).toBe(false);
  });
});
