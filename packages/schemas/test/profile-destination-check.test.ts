import { describe, expect, it } from 'vitest';
import { profileDestinationCheckActionSchema } from '../src/cli-contract.js';

describe('non-secret profile destination check contract', () => {
  it('accepts a destination and rejects missing paths, oversized input, and protected fields', () => {
    const action = { type: 'validate-profile-destination', path: '/private/new.key' };
    expect(profileDestinationCheckActionSchema.parse(action)).toEqual(action);
    expect(
      profileDestinationCheckActionSchema.safeParse({ ...action, path: '' }).success,
    ).toBe(false);
    expect(
      profileDestinationCheckActionSchema.safeParse({
        ...action,
        path: 'x'.repeat(4097),
      }).success,
    ).toBe(false);
    expect(
      profileDestinationCheckActionSchema.safeParse({
        ...action,
        passphrase: 'test-protected-input',
      }).success,
    ).toBe(false);
    expect(
      profileDestinationCheckActionSchema.safeParse({
        ...action,
        databaseUrl: 'test-protected-url',
      }).success,
    ).toBe(false);
  });
});
