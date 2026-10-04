import { afterEach, describe, expect, it } from 'vitest';
import { PortableKeyFileError } from '@kavrix/key-files';

import { keyFileGuidance } from '../src/key-file-guidance.js';
import { classifyCliFailure } from '../src/cli-errors.js';

const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');
afterEach(() => {
  if (platformDescriptor !== undefined)
    Object.defineProperty(process, 'platform', platformDescriptor);
});

describe('permission repair guidance on every supported OS', () => {
  it.each(['win32', 'linux', 'darwin'] as const)(
    'provides actionable %s repair instructions without changing exit codes',
    (platform) => {
      Object.defineProperty(process, 'platform', {
        configurable: true,
        value: platform,
      });
      const error = new PortableKeyFileError('KEY_FILE_UNSAFE');
      const message = keyFileGuidance(error);
      expect(message).toContain('Edit the destination and press Enter');
      expect(message).not.toMatch(/\u001b|\u0000/);
      expect(message).toContain(
        platform === 'win32' ? 'Properties > Security > Advanced' : 'mode 700',
      );
      expect(classifyCliFailure(error)).toEqual({ message, exitCode: 14 });
    },
  );

  it('distinguishes missing parents and existing destinations', () => {
    expect(keyFileGuidance(new PortableKeyFileError('KEY_FILE_NOT_FOUND'))).toContain(
      'existing private parent',
    );
    expect(
      keyFileGuidance(new PortableKeyFileError('KEY_FILE_ALREADY_EXISTS')),
    ).toContain('will not be overwritten');
  });
});
