import { describe, expect, it } from 'vitest';
import { executionReference, timestampSchema, vaultIdSchema } from '@kavrix/schemas';
import {
  createEmptyStructuredVaultPayload,
  DEFAULT_PROJECT_CONTEXT_NAME,
  DEFAULT_SERVICE_NAME,
} from '../src/structured-vault-projection.js';
import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  runCli,
} from './execution-helpers.js';

import { executionReferenceIdentities } from '../src/execution/reference-identity.js';

describe('credential identity across flat and structured references', () => {
  it('derives compatibility aliases from identities rather than display names', () => {
    const payload = createEmptyStructuredVaultPayload(
      vaultIdSchema.parse('vault_identity'),
      timestampSchema.parse('2026-10-28T00:00:00.000Z'),
    );
    const renamed = {
      ...payload,
      projectContexts: payload.projectContexts.map((entry) => ({
        ...entry,
        name: 'Renamed context',
      })),
      groups: payload.groups.map((entry) => ({ ...entry, name: 'Renamed service' })),
    };
    const ref = executionReference({
      context: 'Renamed context',
      service: 'Renamed service',
      item: 'token',
      field: 'value',
    });
    expect(executionReferenceIdentities(renamed, 'token')).toContain(ref);
    expect(executionReferenceIdentities(renamed, ref)).toContain('token');
    for (const field of ['password', 'value']) {
      const other = executionReference({
        context: field === 'value' ? 'Other context' : 'Renamed context',
        service: 'Renamed service',
        item: 'token',
        field,
      });
      expect(executionReferenceIdentities(renamed, other)).not.toContain('token');
    }
    expect(executionReferenceIdentities({ ...renamed, groups: [] }, 'token')).toEqual([
      'token',
    ]);
    expect(executionReferenceIdentities(renamed, ' spaced ')).toEqual([' spaced ']);
    expect(executionReferenceIdentities(renamed, '\ud800')).toEqual(['\ud800']);
    const longName = '界'.repeat(100);
    expect(executionReferenceIdentities(renamed, longName)).toEqual([longName]);
  });
  it('applies deny and reveal rules to both spellings of a default value', async () => {
    const fixture = await createExecutionFixture({
      'legacy/token': 'identity-regression-canary',
    });
    const reference = executionReference({
      context: DEFAULT_PROJECT_CONTEXT_NAME,
      service: DEFAULT_SERVICE_NAME,
      item: 'legacy/token',
      field: 'value',
    });
    const route = [...fixture.routingArgs, '--passphrase-stdin', '--json'];
    const frame = EXEC_PASSPHRASE + '\n';
    const child = [
      process.execPath,
      '-e',
      'process.exit(process.env.TARGET_TOKEN ? 0 : 3)',
    ];
    try {
      const allowed = await runCli(
        ['run', '--secret', `TARGET_TOKEN=${reference}`, ...route, '--', ...child],
        frame,
      );
      expect(allowed.exitCode).toBe(0);
      const flatDeny = await runCli(
        [
          'policy',
          'create',
          'flat-deny',
          '--secret',
          'legacy/token',
          '--deny',
          ...route,
        ],
        frame,
      );
      expect(flatDeny.exitCode).toBe(0);
      const deniedStructured = await runCli(
        ['run', '--secret', `TARGET_TOKEN=${reference}`, ...route, '--', ...child],
        frame,
      );
      expect(deniedStructured.exitCode).toBe(12);
      const fieldReveal = await runCli(
        [
          'field',
          'get',
          'value',
          '--context',
          DEFAULT_PROJECT_CONTEXT_NAME,
          '--service',
          DEFAULT_SERVICE_NAME,
          '--item',
          'legacy/token',
          '--reveal',
          ...route,
        ],
        frame,
      );
      expect(fieldReveal.exitCode).toBe(12);
      expect(fieldReveal.stdout + fieldReveal.stderr).not.toContain(
        'identity-regression-canary',
      );
      expect(
        (await runCli(['policy', 'remove', 'flat-deny', ...route], frame)).exitCode,
      ).toBe(0);
      expect(
        (
          await runCli(
            [
              'policy',
              'create',
              'structured-deny',
              '--secret',
              reference,
              '--deny',
              ...route,
            ],
            frame,
          )
        ).exitCode,
      ).toBe(0);
      const deniedFlat = await runCli(
        ['run', '--secret', 'TARGET_TOKEN=legacy/token', ...route, '--', ...child],
        frame,
      );
      expect(deniedFlat.exitCode).toBe(12);
      const flatReveal = await runCli(
        ['get', 'legacy/token', '--reveal', ...route],
        frame,
      );
      expect(flatReveal.exitCode).toBe(12);
      expect(flatReveal.stdout + flatReveal.stderr).not.toContain(
        'identity-regression-canary',
      );
    } finally {
      await destroyFixture(fixture);
    }
  });
});
