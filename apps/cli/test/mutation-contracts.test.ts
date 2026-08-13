import { groupIdSchema, itemIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  cliArchiveEntityRequestSchema,
  cliCreateCredentialRequestSchema,
  cliCreateGroupRequestSchema,
  cliCredentialMutationResultSchema,
  cliGroupMutationResultSchema,
  cliRestoreEntityRequestSchema,
  cliSetFieldRequestSchema,
} from '../src/mutation-contracts.js';

describe('CLI mutation contracts and Zod schemas', () => {
  it('parses valid group create request and rejects invalid/control/unknown keys', () => {
    const valid = cliCreateGroupRequestSchema.parse({
      name: 'Engineering',
      description: 'DevOps & Backend credentials',
    });
    expect(valid.name).toBe('Engineering');

    expect(() =>
      cliCreateGroupRequestSchema.parse({
        name: 'Bad\0Group',
      }),
    ).toThrow();

    expect(() =>
      cliCreateGroupRequestSchema.parse({
        name: 'Engineering',
        extraField: 'unsupported',
      }),
    ).toThrow();
  });

  it('parses valid credential create request and rejects invalid input', () => {
    const valid = cliCreateCredentialRequestSchema.parse({
      groupQuery: 'Engineering',
      title: 'Database Admin',
      note: 'Production primary DB credentials',
    });
    expect(valid.title).toBe('Database Admin');

    expect(() =>
      cliCreateCredentialRequestSchema.parse({
        groupQuery: '',
        title: 'Title',
      }),
    ).toThrow();
  });

  it('enforces owned Uint8Array secret values for set-field and rejects strings', () => {
    const secretBytes = new TextEncoder().encode('supersecret123');
    const valid = cliSetFieldRequestSchema.parse({
      groupQuery: 'Engineering',
      credentialQuery: 'Database Admin',
      fieldKey: 'password',
      value: secretBytes,
    });
    expect(valid.value).toBeInstanceOf(Uint8Array);

    expect(() =>
      cliSetFieldRequestSchema.parse({
        groupQuery: 'Engineering',
        credentialQuery: 'Database Admin',
        fieldKey: 'password',
        value: 'supersecret123' as never,
      }),
    ).toThrow();
  });

  it('parses archive and restore requests correctly', () => {
    const archiveGroup = cliArchiveEntityRequestSchema.parse({
      groupQuery: 'Engineering',
    });
    expect(archiveGroup.groupQuery).toBe('Engineering');

    const restoreCred = cliRestoreEntityRequestSchema.parse({
      groupQuery: 'Engineering',
      credentialQuery: 'Database Admin',
    });
    expect(restoreCred.credentialQuery).toBe('Database Admin');
  });

  it('parses group and credential mutation result schemas', () => {
    const groupResult = cliGroupMutationResultSchema.parse({
      vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
      groupId: groupIdSchema.parse('group.test000000000000000001'),
      name: 'Engineering',
    });
    expect(groupResult.name).toBe('Engineering');

    const credResult = cliCredentialMutationResultSchema.parse({
      vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
      groupId: groupIdSchema.parse('group.test000000000000000001'),
      credentialId: itemIdSchema.parse('item.test000000000000000001'),
      title: 'Database Admin',
    });
    expect(credResult.title).toBe('Database Admin');
  });
});
