import { AmbiguousNameError, NotFoundError } from '@kavrix/core';
import {
  apiBearerTokenSchema,
  deviceIdSchema,
  inviteIdSchema,
  publicInviteRecordSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { Readable, Writable } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  CLI_VERSION,
  acquiredSecretSchema,
  runCli,
  runPublicCli,
  type CliDependencies,
  type CliUseCasePorts,
  type SecretInputPort,
} from '../src/index.js';
import { NOTE_CANARY, PUBLIC_CANARY, SECRET_CANARY, showFixture } from './fixtures.js';

const TOKEN = apiBearerTokenSchema.parse('A'.repeat(43));
const ACQUIRED_TOKEN = acquiredSecretSchema.parse(TOKEN);
// Clearly fake key material; only its round-trip through the command matters.
const PORTABLE_KEY = 'B'.repeat(43);
const ACQUIRED_PORTABLE_KEY = acquiredSecretSchema.parse(PORTABLE_KEY);

describe('CLI command shell', () => {
  it('provides the static version command without operational dependencies', async () => {
    const full = await execute(['version']);
    const publicResult = await executePublic(['version']);
    expect(full).toMatchObject({ exitCode: CLI_EXIT_CODES.success });
    expect(publicResult).toMatchObject({ exitCode: CLI_EXIT_CODES.success });
    expect(full.stdout).toBe(`${CLI_VERSION}\n`);
    expect(publicResult.stdout).toBe(`${CLI_VERSION}\n`);
  });

  it('reports schema-validated status in stable text and JSON', async () => {
    const status = vi.fn(() =>
      Promise.resolve({
        vaultState: 'unlocked' as const,
        vaultId: vaultIdSchema.parse('vault.primary'),
        deviceId: deviceIdSchema.parse('device.primary'),
        syncState: 'idle' as const,
        pendingChanges: 2,
        lastSyncAt: '2026-08-10T01:02:03.000Z',
      }),
    );
    const text = await execute(['status'], { status });
    expect(text.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(text.stdout).toBe(
      'Vault: unlocked\nVault ID: vault.primary\nDevice ID: device.primary\nSync: idle\nPending changes: 2\nLast sync: 2026-08-10T01:02:03.000Z\n',
    );
    const json = await execute(['status', '--json'], { status });
    expect(JSON.parse(json.stdout)).toEqual({
      vaultState: 'unlocked',
      vaultId: 'vault.primary',
      deviceId: 'device.primary',
      syncState: 'idle',
      pendingChanges: 2,
      lastSyncAt: '2026-08-10T01:02:03.000Z',
    });
    expect(json.stdout).not.toContain('\u001b');
  });

  it('locks through the injected use case without accepting secret input', async () => {
    const lock = vi.fn(() => Promise.resolve());
    const result = await execute(['lock'], { lock });
    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.success,
      stdout: 'Vault locked.\n',
      stderr: '',
    });
    expect(lock).toHaveBeenCalledOnce();
  });

  it('resolves show with group and credential names and redacts every secret', async () => {
    const show = vi.fn(() => Promise.resolve(showFixture()));
    const text = await execute(['show', 'Production', 'Primary'], { show });
    expect(text.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(show).toHaveBeenCalledWith('Production', 'Primary');
    expect(text.stdout).toContain(PUBLIC_CANARY);
    expect(text.stdout).toContain('[REDACTED]');
    expect(text.stdout).not.toContain(SECRET_CANARY);
    expect(text.stdout).not.toContain(NOTE_CANARY);
    expect(text.stdout).not.toContain('\u001b');
    expect(text.stdout).not.toContain('\u202e');

    const json = await execute(['show', 'Production', 'Primary', '--json'], { show });
    const parsed = JSON.parse(json.stdout) as Record<string, unknown>;
    expect(parsed).toMatchObject({
      id: 'item.primary',
      notes: [{ content: '[REDACTED]' }],
      group: { notes: [{ content: '[REDACTED]' }] },
    });
    expect(parsed['fields']).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ stableKey: 'username', value: PUBLIC_CANARY }),
        expect.objectContaining({ stableKey: 'password', value: '[REDACTED]' }),
        expect.objectContaining({
          stableKey: 'archived_secret',
          value: '[ORPHANED]',
        }),
      ]),
    );
    expect(json.stdout).not.toContain(SECRET_CANARY);
    expect(json.stdout).not.toContain(NOTE_CANARY);
    expect(json.stdout).not.toContain('https://unsafe.invalid');
  });

  it('copies through the injected use case without putting plaintext in argv or output', async () => {
    const historyCanary = `${SECRET_CANARY}-shell-history`;
    const copy = vi.fn(() =>
      Promise.resolve({ label: 'Password', clearAfterSeconds: 30 }),
    );
    const arguments_ = [
      'copy',
      'Production',
      'Primary',
      'recovery_codes',
      '--index',
      '2',
    ] as const;
    const result = await execute(arguments_, { copy });
    expect(copy).toHaveBeenCalledWith('Production', 'Primary', 'recovery_codes', {
      index: 2,
    });
    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.success,
      stdout: 'Copied Password — clipboard clears in 30 seconds.\n',
      stderr: '',
    });
    expect(`${arguments_.join(' ')}${result.stdout}${result.stderr}`).not.toContain(
      historyCanary,
    );

    const invalid = await execute(
      ['copy', 'Production', 'Primary', 'recovery_codes', '--index', '0'],
      { copy },
    );
    expect(invalid.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(copy).toHaveBeenCalledTimes(1);

    const hostileReceipt = await execute(
      ['copy', 'Production', 'Primary', 'password'],
      {
        copy: () =>
          Promise.resolve({
            label: `Password${historyCanary}\u001b]2;owned\u0007`,
            clearAfterSeconds: 30,
          }),
      },
    );
    expect(hostileReceipt.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(hostileReceipt.stdout).toBe('');
    expect(hostileReceipt.stderr).not.toContain(historyCanary);
    expect(hostileReceipt.stderr).not.toContain('\u001b');

    const failed = await execute(['copy', 'Production', 'Primary', 'password'], {
      copy: () => Promise.reject(new Error(historyCanary)),
    });
    expect(failed.stderr).toBe(
      'Error [UNEXPECTED_FAILURE]: The command failed without exposing internal details.\n',
    );
    expect(failed.stderr).not.toContain(historyCanary);
  });

  it('does not disclose ambiguous candidates or unexpected boundary data', async () => {
    const ambiguous = await execute(['show', 'group', 'duplicate'], {
      show: () =>
        Promise.reject(
          new AmbiguousNameError([
            'item.secret-candidate-one',
            'item.secret-candidate-two',
          ]),
        ),
    });
    expect(ambiguous.exitCode).toBe(CLI_EXIT_CODES.ambiguous);
    expect(ambiguous.stderr).toContain('More than one record matches.');
    expect(ambiguous.stderr).not.toContain('secret-candidate');

    const fixture = showFixture();
    const malicious = await execute(['show', 'group', 'credential'], {
      show: () =>
        Promise.resolve({
          ...fixture,
          notes: fixture.notes.map((note) => ({ ...note, content: NOTE_CANARY })),
          fields: fixture.fields.map((field) =>
            field.stableKey === 'password'
              ? { ...field, sensitive: false, value: SECRET_CANARY }
              : field,
          ),
        } as never),
    });
    expect(malicious.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(malicious.stdout).toBe('');
    expect(malicious.stderr).not.toContain(SECRET_CANARY);
    expect(malicious.stderr).not.toContain(NOTE_CANARY);

    const malformed = await execute(['status'], {
      status: () =>
        Promise.resolve({
          vaultState: 'locked',
          syncState: 'idle',
          pendingChanges: 0,
          secretValue: SECRET_CANARY,
        } as never),
    });
    expect(malformed.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(malformed.stderr).toBe(
      'Error [UNEXPECTED_FAILURE]: The command failed without exposing internal details.\n',
    );
    expect(malformed.stderr).not.toContain(SECRET_CANARY);
  });

  it('uses stable not-found and usage exits without reflecting hostile argv', async () => {
    const missing = await execute(['show', 'group', 'missing'], {
      show: () => Promise.reject(new NotFoundError()),
    });
    expect(missing.exitCode).toBe(CLI_EXIT_CODES.notFound);

    const argvCanary = `token-${SECRET_CANARY}\u001b]2;owned\u0007`;
    const secretRead = vi.fn<SecretInputPort['read']>();
    const invalid = await execute(
      [
        'device',
        'invite',
        'join',
        '--device',
        'device.primary',
        '--invite',
        argvCanary,
      ],
      {},
      {
        read: secretRead,
        readBatch: () => Promise.reject(new Error('Unexpected secret batch read')),
      },
    );
    expect(invalid.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(invalid.stderr).toBe(
      "Error [CLI_USAGE]: Invalid command usage. Run 'creds --help'.\n",
    );
    expect(invalid.stderr).not.toContain(SECRET_CANARY);
    expect(invalid.stderr).not.toContain('\u001b');
    expect(secretRead).not.toHaveBeenCalled();
  });

  it('lists and revokes only canonical public invite metadata', async () => {
    const invite = publicInviteRecordSchema.parse({
      id: 'invite.primary',
      vaultId: 'vault.primary',
      issuedByDeviceId: 'device.owner',
      scopes: ['sync:read', 'sync:write'],
      state: 'active',
      createdAt: '2026-08-10T00:00:00.000Z',
      expiresAt: '2026-08-10T01:00:00.000Z',
    });
    const listInvites = vi.fn(() => Promise.resolve([invite]));
    const listed = await execute(
      ['device', 'invite', 'list', '--vault', 'vault.primary', '--json'],
      { listInvites },
    );
    expect(listed.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(JSON.parse(listed.stdout)).toEqual({ invites: [invite] });
    expect(listed.stdout).not.toMatch(/token|hash/iu);

    const revokeInvite = vi.fn(() => Promise.resolve());
    const revoked = await execute(
      [
        'device',
        'invite',
        'revoke',
        inviteIdSchema.parse('invite.primary'),
        '--vault',
        vaultIdSchema.parse('vault.primary'),
      ],
      { revokeInvite },
    );
    expect(revoked.stdout).toBe('Invite revoked.\n');
    expect(revokeInvite).toHaveBeenCalledWith('vault.primary', 'invite.primary');
  });

  it('shapes join input from a masked prompt or explicit stdin and never prints secrets', async () => {
    const reads: boolean[] = [];
    const secrets: SecretInputPort = {
      read: () => Promise.reject(new Error('Unexpected single secret read')),
      // Redemption needs the invite token and the portable key together, so the
      // command reads one framed batch rather than two independent secrets.
      readBatch: ({ kinds, fromStdin, requireEnd }) => {
        expect(kinds).toEqual(['invite', 'portable-key']);
        expect(requireEnd).toBe(fromStdin);
        reads.push(fromStdin);
        return Promise.resolve([ACQUIRED_TOKEN, ACQUIRED_PORTABLE_KEY]);
      },
    };
    const joinInvite = vi.fn(
      (
        request: Parameters<CliUseCasePorts['joinInvite']>[0],
        portableKey: Parameters<CliUseCasePorts['joinInvite']>[1],
      ) => {
        expect(request).toEqual({
          inviteToken: TOKEN,
          vaultId: 'vault.primary',
          schemaVersion: 1,
        });
        // The key that unlocks the redeemed vault travels beside the validated
        // request and never becomes part of it.
        expect(portableKey).toBe(PORTABLE_KEY);
        return Promise.resolve({
          vaultId: vaultIdSchema.parse('vault.primary'),
          deviceId: deviceIdSchema.parse('device.new'),
        });
      },
    );
    const prompt = await execute(
      ['device', 'invite', 'join', '--vault', 'vault.primary'],
      { joinInvite },
      secrets,
    );
    const stdin = await execute(
      [
        'device',
        'invite',
        'join',
        '--vault',
        'vault.primary',
        '--invite-stdin',
        '--json',
      ],
      { joinInvite },
      secrets,
    );
    expect(reads).toEqual([false, true]);
    expect(prompt.stdout).toBe('Device joined vault vault.primary.\n');
    expect(JSON.parse(stdin.stdout)).toEqual({
      vaultId: 'vault.primary',
      deviceId: 'device.new',
    });
    const emitted = `${prompt.stdout}${stdin.stdout}${prompt.stderr}${stdin.stderr}`;
    expect(emitted).not.toContain(TOKEN);
    expect(emitted).not.toContain(PORTABLE_KEY);
  });

  it('keeps help and completions static and free of runtime values', async () => {
    const runtimeCanary = 'runtime-vault-secret-canary';
    const show = vi.fn(() => Promise.reject(new Error(runtimeCanary)));
    const help = await execute(['--help'], { show });
    const joinHelp = await execute(['device', 'invite', 'join', '--help'], { show });
    expect(help.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(help.stdout).toContain('show [options] <group> <credential>');
    expect(help.stdout).toContain('copy [options] <group> <credential> <field>');
    expect(joinHelp.stdout).toContain('--invite-stdin');
    expect(joinHelp.stdout).not.toContain('--invite <');
    expect(joinHelp.stdout).not.toContain('--passphrase <');
    expect(joinHelp.stdout).not.toContain('--portable-key <');
    expect(help.stdout).not.toContain(runtimeCanary);

    for (const shell of ['bash', 'zsh', 'fish', 'powershell']) {
      const completion = await execute(['completion', shell], { show });
      expect(completion.exitCode).toBe(CLI_EXIT_CODES.success);
      expect(completion.stdout).toContain('completion');
      expect(completion.stdout).not.toContain(runtimeCanary);
    }
    expect(show).not.toHaveBeenCalled();
  });

  it('limits the production bin catalog to commands with real static behavior', async () => {
    const publishedCommands = 'version generate totp key completion';
    const unavailableCommands = /\b(?:init|status|lock|show|copy|device)\b/u;
    const help = await executePublic(['--help']);
    expect(help.exitCode).toBe(CLI_EXIT_CODES.success);
    for (const command of publishedCommands.split(' ')) {
      expect(help.stdout).toContain(command);
    }
    expect(help.stdout).not.toMatch(unavailableCommands);

    for (const shell of ['bash', 'zsh', 'fish', 'powershell']) {
      const completion = await executePublic(['completion', shell]);
      expect(completion.exitCode).toBe(CLI_EXIT_CODES.success);
      expect(completion.stdout).toContain(publishedCommands);
      expect(completion.stdout).not.toMatch(unavailableCommands);
    }

    for (const unavailableOperation of [
      ['init'],
      ['status'],
      ['lock'],
      ['show'],
      ['copy'],
      ['device'],
    ]) {
      const result = await executePublic(unavailableOperation);
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stderr).toBe(
        "Error [CLI_USAGE]: Invalid command usage. Run 'creds --help'.\n",
      );
    }
  });

  it('forwards the invite server only when explicitly supplied', async () => {
    const joinInvite = vi.fn(() =>
      Promise.resolve({
        vaultId: vaultIdSchema.parse('vault.primary'),
        deviceId: deviceIdSchema.parse('device.new'),
      }),
    );
    const secrets: SecretInputPort = {
      read: () => Promise.reject(new Error('Unexpected single secret read')),
      readBatch: () => Promise.resolve([ACQUIRED_TOKEN, ACQUIRED_PORTABLE_KEY]),
    };

    await execute(
      ['device', 'invite', 'join', '--vault', 'vault.primary'],
      { joinInvite },
      secrets,
    );
    await execute(
      [
        'device',
        'invite',
        'join',
        '--vault',
        'vault.primary',
        '--server',
        'https://sync.example/',
      ],
      { joinInvite },
      secrets,
    );

    expect(joinInvite).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ vaultId: 'vault.primary' }),
      PORTABLE_KEY,
    );
    expect(joinInvite).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ vaultId: 'vault.primary' }),
      PORTABLE_KEY,
      'https://sync.example/',
    );
  });
});

async function execute(
  arguments_: readonly string[],
  overrides: Partial<CliUseCasePorts> = {},
  secrets: SecretInputPort = {
    read: () => Promise.reject(new Error('Unexpected secret read')),
    readBatch: () => Promise.reject(new Error('Unexpected secret batch read')),
  },
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const output = memoryOutput();
  const dependencies: CliDependencies = {
    ports: useCases(overrides),
    secrets,
    runtime: {
      stdin: Readable.from([]),
      stdout: output.stdout.stream,
      stderr: output.stderr.stream,
    },
  };
  const exitCode = await runCli(arguments_, dependencies);
  return { exitCode, stdout: output.stdout.value(), stderr: output.stderr.value() };
}

async function executePublic(
  arguments_: readonly string[],
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const output = memoryOutput();
  const exitCode = await runPublicCli(arguments_, {
    stdin: Readable.from([]),
    stdout: output.stdout.stream,
    stderr: output.stderr.stream,
  });
  return { exitCode, stdout: output.stdout.value(), stderr: output.stderr.value() };
}

function useCases(overrides: Partial<CliUseCasePorts>): CliUseCasePorts {
  const unexpected = (): Promise<never> => Promise.reject(new Error('Unexpected call'));
  return {
    status: unexpected,
    lock: unexpected,
    show: unexpected,
    copy: unexpected,
    listInvites: unexpected,
    revokeInvite: unexpected,
    joinInvite: unexpected,
    ...overrides,
  };
}

function memoryOutput(): Readonly<{
  stdout: MemoryWritable;
  stderr: MemoryWritable;
}> {
  return { stdout: writable(), stderr: writable() };
}

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;

function writable(): MemoryWritable {
  let content = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      content += Buffer.from(chunk).toString('utf8');
      callback();
    },
  });
  return { stream, value: () => content };
}
