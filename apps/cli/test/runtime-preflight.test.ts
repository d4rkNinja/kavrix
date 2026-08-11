import * as nodeCrypto from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { CLI_EXIT_CODES, presentCliError } from '../src/errors.js';
import {
  CliUnsupportedRuntimeError,
  SUPPORTED_NODE_RANGE,
  assertSupportedRuntime,
  isSupportedNodeVersion,
} from '../src/runtime-preflight.js';

const CAPABLE = Object.freeze({ argon2: () => undefined, argon2Sync: () => undefined });

describe('supported Node range', () => {
  it('admits the 24.12 floor and every later 24.x patch', () => {
    for (const version of ['24.12.0', '24.12.7', '24.19.0', '24.99.12']) {
      expect(isSupportedNodeVersion(version)).toBe(true);
    }
  });

  it('rejects releases below the API floor', () => {
    // crypto.argon2 does not exist in any 22.x release, and 24.11 predates the
    // DatabaseSync.enableDefensive backport the local store depends on.
    for (const version of ['22.11.0', '24.0.0', '24.7.0', '24.11.9']) {
      expect(isSupportedNodeVersion(version)).toBe(false);
    }
  });

  it('excludes the 25.0.x gap between the backport and the forward release', () => {
    expect(isSupportedNodeVersion('25.0.0')).toBe(false);
    expect(isSupportedNodeVersion('25.0.9')).toBe(false);
    expect(isSupportedNodeVersion('25.1.0')).toBe(true);
    expect(isSupportedNodeVersion('25.4.2')).toBe(true);
  });

  it('admits every major above the gap so a newer Node still installs', () => {
    for (const version of ['26.0.0', '27.3.1', '100.0.0']) {
      expect(isSupportedNodeVersion(version)).toBe(true);
    }
  });

  it('judges a pre-release on its numeric core', () => {
    expect(isSupportedNodeVersion('26.0.0-pre')).toBe(true);
    expect(isSupportedNodeVersion('25.0.0-nightly20260101')).toBe(false);
    expect(isSupportedNodeVersion('24.13.0+build.1')).toBe(true);
  });

  it('rejects a version string it cannot parse rather than guessing', () => {
    for (const value of ['', 'v24.13.1', '24.13', '24.13.1.2', 'latest', '24.x.0']) {
      expect(isSupportedNodeVersion(value)).toBe(false);
    }
  });

  it('accepts the runtime executing this suite', () => {
    expect(isSupportedNodeVersion(process.versions.node)).toBe(true);
  });
});

describe('runtime preflight', () => {
  it('passes on a supported version with both Argon2 primitives', () => {
    expect(() => {
      assertSupportedRuntime('24.13.1', CAPABLE);
    }).not.toThrow();
  });

  it('passes on the real runtime and its real node:crypto', () => {
    expect(() => {
      assertSupportedRuntime();
    }).not.toThrow();
  });

  it('names the offending version and the required range', () => {
    expect(() => {
      assertSupportedRuntime('24.11.0', CAPABLE);
    }).toThrow(
      new RegExp(
        `Unsupported Node runtime v24\\.11\\.0\\..*${SUPPORTED_NODE_RANGE.replaceAll(/[.*+?^${}()|[\]\\]/gu, '\\$&')}`,
        'u',
      ),
    );
  });

  it('fails closed when a required Argon2 primitive is missing', () => {
    for (const missing of ['argon2', 'argon2Sync'] as const) {
      const capabilities = { ...CAPABLE, [missing]: undefined };
      expect(() => {
        assertSupportedRuntime('24.13.1', capabilities);
      }).toThrow(new RegExp(`missing crypto\\.${missing}`, 'u'));
    }
  });

  it('rejects a primitive that is present but not callable', () => {
    expect(() => {
      assertSupportedRuntime('24.13.1', { ...CAPABLE, argon2: 'yes' });
    }).toThrow(CliUnsupportedRuntimeError);
  });

  it('checks the version before the capabilities', () => {
    // An old runtime should be reported as old, not as one missing a primitive
    // it was never expected to have.
    expect(() => {
      assertSupportedRuntime('22.11.0', {});
    }).toThrow(/Unsupported Node runtime v22\.11\.0\./u);
  });

  it('confirms this Node build really exposes both primitives', () => {
    expect(typeof nodeCrypto.argon2).toBe('function');
    expect(typeof nodeCrypto.argon2Sync).toBe('function');
  });

  it('presents as an unavailable-runtime failure with a safe message', () => {
    const error = new CliUnsupportedRuntimeError('Unsupported Node runtime v24.0.0.');
    expect(error.safe).toBe(true);
    expect(presentCliError(error)).toEqual({
      exitCode: CLI_EXIT_CODES.unavailable,
      code: 'CLI_UNSUPPORTED_RUNTIME',
      message: `Unsupported Node runtime v24.0.0. CredVault requires Node ${SUPPORTED_NODE_RANGE}.`,
    });
  });
});
