import {
  AmbiguousNameError,
  NetworkUnavailableError,
  NotFoundError,
  ValidationError,
  VaultLockedError,
} from '@kavrix/core';
import { publicInviteRecordSchema, vaultIdSchema } from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  CLI_EXIT_CODES,
  CliUnavailableError,
  CliUsageError,
  parseInviteId,
  parseStatus,
  parseVaultId,
  presentCliError,
  renderInvites,
  renderShow,
  renderStatus,
  safeJson,
  sanitizeTerminalOutput,
  sanitizeTerminalText,
  shapeInviteJoinRequest,
} from '../src/index.js';
import { SECRET_CANARY, showFixture } from './fixtures.js';

describe('CLI runtime boundaries', () => {
  it('maps safe typed failures to stable exit codes', () => {
    expect(presentCliError(new CliUsageError('Safe usage.'))).toEqual({
      exitCode: CLI_EXIT_CODES.usage,
      code: 'CLI_USAGE',
      message: 'Safe usage.',
    });
    expect(presentCliError(new CliUnavailableError('status'))).toMatchObject({
      exitCode: CLI_EXIT_CODES.unavailable,
      code: 'CLI_UNAVAILABLE',
    });
    expect(presentCliError(new ValidationError())).toMatchObject({
      exitCode: CLI_EXIT_CODES.usage,
      code: 'VALIDATION_FAILED',
    });
    expect(presentCliError(new NotFoundError())).toMatchObject({
      exitCode: CLI_EXIT_CODES.notFound,
      code: 'NOT_FOUND',
    });
    expect(presentCliError(new AmbiguousNameError(['one', 'two']))).toMatchObject({
      exitCode: CLI_EXIT_CODES.ambiguous,
      code: 'AMBIGUOUS_NAME',
    });
    expect(presentCliError(new NetworkUnavailableError())).toMatchObject({
      exitCode: CLI_EXIT_CODES.unavailable,
      code: 'NETWORK_UNAVAILABLE',
    });
    expect(presentCliError(new VaultLockedError())).toMatchObject({
      exitCode: CLI_EXIT_CODES.failure,
      code: 'VAULT_LOCKED',
    });
    expect(presentCliError(new Error('private detail'))).toEqual({
      exitCode: CLI_EXIT_CODES.failure,
      code: 'UNEXPECTED_FAILURE',
      message: 'The command failed without exposing internal details.',
    });
  });

  it('renders only the explicit redacted show projection and rejects malformed IDs', () => {
    const fixture = showFixture();
    const boundaryCanary = 'boundary-extra-secret-canary';
    const output = renderShow(
      { ...fixture, secretValue: boundaryCanary } as never,
      true,
    );
    expect(output).not.toContain(boundaryCanary);
    expect(output).not.toContain(SECRET_CANARY);
    expect(() => parseVaultId('../vault')).toThrow();
    expect(() => parseInviteId('invite with spaces')).toThrow();
  });

  it('requires coherent status and canonical invite join shaping', () => {
    expect(() =>
      parseStatus({
        vaultState: 'unlocked',
        syncState: 'idle',
        pendingChanges: 0,
      }),
    ).toThrow();
    expect(shapeInviteJoinRequest('A'.repeat(43), 'vault.primary', 2)).toEqual({
      inviteToken: 'A'.repeat(43),
      vaultId: 'vault.primary',
      schemaVersion: 2,
    });
    expect(() => shapeInviteJoinRequest('raw-invite', 'vault.primary', 1)).toThrow();
  });

  it('renders absent status metadata and invite lifecycle fields deterministically', () => {
    expect(
      renderStatus(
        parseStatus({
          vaultState: 'locked',
          syncState: 'offline',
          pendingChanges: 0,
        }),
        false,
      ),
    ).toBe('Vault: locked\nSync: offline\nPending changes: 0\n');
    expect(renderInvites({ invites: [], nextCursor: null }, false)).toBe(
      'No device invites.\n',
    );

    const invite = publicInviteRecordSchema.parse({
      id: 'invite.redeemed',
      vaultId: vaultIdSchema.parse('vault.primary'),
      issuedByDeviceId: 'device.owner',
      scopes: ['sync:read'],
      state: 'redeemed',
      createdAt: '2026-08-10T00:00:00.000Z',
      expiresAt: '2026-08-10T01:00:00.000Z',
      consumedAt: '2026-08-10T00:30:00.000Z',
    });
    const output = renderInvites({ invites: [invite], nextCursor: null }, false);
    expect(output).toBe(
      'invite.redeemed\tredeemed\tsync:read\t2026-08-10T01:00:00.000Z\n',
    );
    expect(
      JSON.parse(renderInvites({ invites: [invite], nextCursor: null }, true)),
    ).toEqual({
      invites: [invite],
      nextCursor: null,
    });
  });

  it('preserves server invite order and sanitizes one continuation hint', () => {
    const newer = publicInviteRecordSchema.parse({
      id: 'invite.newer',
      vaultId: vaultIdSchema.parse('vault.primary'),
      issuedByDeviceId: 'device.owner',
      scopes: ['sync:read'],
      state: 'active',
      createdAt: '2026-08-10T01:00:00.000Z',
      expiresAt: '2026-08-10T02:00:00.000Z',
    });
    const older = publicInviteRecordSchema.parse({
      ...newer,
      id: 'invite.older',
      createdAt: '2026-08-10T00:00:00.000Z',
      expiresAt: '2026-08-10T01:00:00.000Z',
    });
    const hostileCursor = 'cursor\u001b]8;;https://unsafe.invalid\u0007\r\nnext';
    const hostilePage = {
      invites: [
        {
          ...newer,
          issuedByDeviceId: 'device\u001b[2Jowner',
          scopes: ['sync:read\u0007'],
        },
        older,
      ],
      nextCursor: hostileCursor,
    } as never;

    const text = renderInvites(hostilePage, false);
    expect(text.indexOf('invite.newer')).toBeLessThan(text.indexOf('invite.older'));
    expect(text).not.toContain('\u001b');
    expect(text).not.toContain('\u0007');
    expect(text).not.toContain('https://unsafe.invalid');
    expect(text.match(/Next cursor:/gu)).toHaveLength(1);
    expect(text).toContain('\\r\\nnext');

    const json = JSON.parse(renderInvites(hostilePage, true)) as {
      invites: readonly { id: string }[];
      nextCursor: string;
    };
    expect(json.invites.map(({ id }) => id)).toEqual(['invite.newer', 'invite.older']);
    expect(json.nextCursor).not.toContain('\u001b');
    expect(json).toEqual({
      invites: json.invites,
      nextCursor: sanitizeTerminalText(hostileCursor),
    });
  });

  it('neutralizes CSI, OSC, string commands, C1 controls, bidi, and JSON keys', () => {
    const hostile = [
      'safe',
      '\u001b[31mred',
      '\u001b]8;;https://unsafe.invalid\u001b\\link',
      '\u001bPdevice-command\u0007tail',
      '\u001bcreset',
      '\u009b2Jclear',
      '\u009d8;;https://c1-osc.invalid\u009cC1-OSC-PAYLOAD',
      '\u0090C1-DCS-PAYLOAD\u009c',
      '\u0098C1-SOS-PAYLOAD\u009c',
      '\u009eC1-PM-PAYLOAD\u009c',
      '\u009fC1-APC-PAYLOAD\u009c',
      '\u202ereverse',
      '\u2028line-separator\u2029paragraph-separator',
      '\r\n\t',
    ].join('|');
    const safe = sanitizeTerminalText(hostile);
    expect(safe).not.toContain('\u001b');
    expect(safe).not.toContain('\u009b');
    expect(safe).not.toContain('c1-osc.invalid');
    expect(safe).not.toContain('C1-DCS-PAYLOAD');
    expect(safe).not.toContain('C1-SOS-PAYLOAD');
    expect(safe).not.toContain('C1-PM-PAYLOAD');
    expect(safe).not.toContain('C1-APC-PAYLOAD');
    expect(safe).not.toContain('\u202e');
    expect(safe).not.toContain('\u2028');
    expect(safe).not.toContain('\u2029');
    expect(safe).not.toContain('https://unsafe.invalid');
    expect(safe).toContain('\\r\\n\\t');
    expect(sanitizeTerminalText('\u009dunterminated-C1-STRING')).toBe('�');
    expect(sanitizeTerminalOutput('one\r\ntwo\rthree')).toBe('one\ntwo\nthree');
    expect(safeJson({ ['bad\u001b[2J']: ['ok', 'bad\u202e'] })).toBe(
      '{\n  "bad�": [\n    "ok",\n    "bad�"\n  ]\n}\n',
    );
  });
});
