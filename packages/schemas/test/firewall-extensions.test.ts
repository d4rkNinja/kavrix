import { describe, expect, it } from 'vitest';
import {
  executionReference,
  parseExecutionReference,
  permissionEntrySchema,
} from '../src/index.js';

describe('execution reference and operation contracts', () => {
  it('round-trips exact structured identities without path ambiguity', () => {
    const reference = executionReference({
      context: 'project/prod',
      service: 'api',
      item: 'deploy',
      field: 'token',
    });
    expect(parseExecutionReference(reference)).toEqual({
      kind: 'field',
      context: 'project/prod',
      service: 'api',
      item: 'deploy',
      field: 'token',
    });
    expect(parseExecutionReference('github/token')).toEqual({
      kind: 'flat',
      name: 'github/token',
    });
  });
  it('rejects malformed, noncanonical, and control-bearing structured references', () => {
    for (const reference of [
      'field:a/b/c',
      'field:a/b/c/%74oken',
      'field:a/b/c/%0A',
      'field:a/b/c/%',
      'field:a/b/c/',
      'field:%20a/b/c/token',
    ]) {
      expect(() => parseExecutionReference(reference)).toThrow();
      expect(
        permissionEntrySchema.safeParse({ secret: reference, commands: ['gh'] })
          .success,
      ).toBe(false);
    }
  });
  it('validates exact operations and rejects command mismatches', () => {
    const entry = {
      secret: 'github/token',
      commands: ['gh'],
      operations: [
        { command: 'gh', args: ['issue', 'list', '--repo', 'example/project'] },
      ],
    };
    expect(permissionEntrySchema.safeParse(entry).success).toBe(true);
    expect(
      permissionEntrySchema.safeParse({ ...entry, commands: ['node'] }).success,
    ).toBe(false);
    expect(permissionEntrySchema.safeParse({ ...entry, operations: [] }).success).toBe(
      false,
    );
    expect(permissionEntrySchema.safeParse({ ...entry, deny: true }).success).toBe(
      false,
    );
  });
});
