import { AmbiguousNameError, NotFoundError } from '@kavrix/core';
import {
  apiBearerTokenSchema,
  deviceIdSchema,
  encodeControlListCursor,
  inviteIdSchema,
  publicInviteRecordSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { Readable, Writable } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  CLI_VERSION,
  PUBLIC_CLI_COMMAND_CATALOG,
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

type PublicStatusRequest = Readonly<{
  backendPolicy:
    | Readonly<{ kind: 'native' }>
    | Readonly<{ kind: 'sealed-file'; passphraseFromStdin: boolean }>;
  environment: Readonly<Record<string, string | undefined>>;
  secrets: SecretInputPort;
}>;
type PublicStatusCallback = (
  request: PublicStatusRequest,
) => ReturnType<CliUseCasePorts['status']>;

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

  it('lists canonical public invite pages and forwards bounded pagination options', async () => {
    const invite = publicInviteRecordSchema.parse({
      id: 'invite.primary',
      vaultId: 'vault.primary',
      issuedByDeviceId: 'device.owner',
      scopes: ['sync:read', 'sync:write'],
      state: 'active',
      createdAt: '2026-08-10T00:00:00.000Z',
      expiresAt: '2026-08-10T01:00:00.000Z',
    });
    const nextCursor = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId: invite.vaultId,
      createdAt: invite.createdAt,
      id: invite.id,
    });
    const page = { invites: [invite], nextCursor };
    const listInvitePage = vi.fn(() => Promise.resolve(page));
    const argumentSets = [
      [
        ['device', 'invite', 'list', '--vault', 'vault.primary', '--json'],
        { limit: 50 },
      ],
      [
        [
          'device',
          'invite',
          'list',
          '--vault',
          'vault.primary',
          '--limit',
          '1',
          '--json',
        ],
        { limit: 1 },
      ],
      [
        [
          'device',
          'invite',
          'list',
          '--vault',
          'vault.primary',
          '--limit',
          '200',
          '--json',
        ],
        { limit: 200 },
      ],
      [
        [
          'device',
          'invite',
          'list',
          '--vault',
          'vault.primary',
          '--cursor',
          nextCursor,
          '--json',
        ],
        { limit: 50, cursor: nextCursor },
      ],
    ] as const;

    for (const [arguments_, expectedOptions] of argumentSets) {
      const listed = await execute(arguments_, { listInvitePage });
      expect(listed.exitCode).toBe(CLI_EXIT_CODES.success);
      expect(JSON.parse(listed.stdout)).toEqual(page);
      expect(listed.stdout).not.toMatch(/token|hash/iu);
      expect(listInvitePage).toHaveBeenLastCalledWith('vault.primary', expectedOptions);
    }

    expect(listInvitePage).toHaveBeenCalledTimes(4);
  });

  it('rejects noncanonical invite page options before invoking the use case', async () => {
    const listInvitePage = vi.fn(() =>
      Promise.resolve({ invites: [], nextCursor: null }),
    );
    const invalidArguments = [
      ['--limit', '0'],
      ['--limit', '201'],
      ['--limit', '01'],
      ['--limit', '1.5'],
      ['--limit', '1e2'],
      ['--cursor', 'AA'],
      ['--unknown', 'value'],
    ];

    for (const invalid of invalidArguments) {
      const listed = await execute(
        ['device', 'invite', 'list', '--vault', 'vault.primary', ...invalid],
        { listInvitePage },
      );
      expect(listed.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(listed.stderr).not.toContain(invalid.at(-1) ?? '');
    }
    expect(listInvitePage).not.toHaveBeenCalled();
  });

  it('rejects malformed invite pages without exposing returned data', async () => {
    const invite = publicInviteRecordSchema.parse({
      id: 'invite.protocol',
      vaultId: 'vault.primary',
      issuedByDeviceId: 'device.owner',
      scopes: ['sync:read'],
      state: 'active',
      createdAt: '2026-08-10T00:00:00.000Z',
      expiresAt: '2026-08-10T01:00:00.000Z',
    });
    const malformedPages = [
      { invites: [] },
      { invites: [invite], nextCursor: 'AA' },
      { invites: Array.from({ length: 201 }, () => invite), nextCursor: null },
      {
        invites: [{ ...invite, tokenHash: SECRET_CANARY }],
        nextCursor: null,
      },
    ];

    for (const malformedPage of malformedPages) {
      const listed = await execute(
        ['device', 'invite', 'list', '--vault', 'vault.primary'],
        {
          listInvitePage: () => Promise.resolve(malformedPage as never),
        },
      );
      expect(listed.exitCode).toBe(CLI_EXIT_CODES.failure);
      expect(listed.stderr).toBe(
        'Error [UNEXPECTED_FAILURE]: The command failed without exposing internal details.\n',
      );
      expect(listed.stderr).not.toContain(SECRET_CANARY);
    }
  });

  it('revokes only canonical public invite metadata', async () => {
    const inviteId = inviteIdSchema.parse('invite.primary');

    const revokeInvite = vi.fn(() => Promise.resolve());
    const revoked = await execute(
      [
        'device',
        'invite',
        'revoke',
        inviteId,
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
    const inviteListHelp = await execute(['device', 'invite', 'list', '--help'], {
      show,
    });
    const joinHelp = await execute(['device', 'invite', 'join', '--help'], { show });
    expect(help.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(help.stdout).toContain('show [options] <group> <credential>');
    expect(help.stdout).toContain('copy [options] <group> <credential> <field>');
    expect(joinHelp.stdout).toContain('--invite-stdin');
    expect(joinHelp.stdout).not.toContain('--invite <');
    expect(joinHelp.stdout).not.toContain('--passphrase <');
    expect(joinHelp.stdout).not.toContain('--portable-key <');
    expect(inviteListHelp.stdout).toContain('--limit <1..200>');
    expect(inviteListHelp.stdout).toContain('--cursor <opaque>');
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
    const publishedCommands =
      'version generate totp key init unlock lock status group credential completion';
    const unavailableCommands = /\b(?:show|copy|device)\b/u;
    expect(PUBLIC_CLI_COMMAND_CATALOG.map(({ name }) => name)).toEqual(
      publishedCommands.split(' '),
    );
    const help = await executePublic(['--help']);
    expect(help.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(
      [...help.stdout.matchAll(/^ {2}([a-z][a-z-]*)(?:\s|$)/gmu)].map(
        (match) => match[1],
      ),
    ).toEqual(publishedCommands.split(' '));
    for (const command of publishedCommands.split(' ')) {
      expect(help.stdout).toContain(command);
    }
    expect(help.stdout).not.toMatch(unavailableCommands);

    const expectedCompletions = {
      bash: `_creds_complete() { COMPREPLY=( $(compgen -W '${publishedCommands}' -- "\${COMP_WORDS[COMP_CWORD]}") ); }\ncomplete -F _creds_complete creds\n`,
      zsh: `#compdef creds\n_arguments '1:command:(${publishedCommands})'\n`,
      fish: `complete -c creds -f -n '__fish_use_subcommand' -a '${publishedCommands}'\n`,
      powershell: `Register-ArgumentCompleter -Native -CommandName creds -ScriptBlock { param($wordToComplete) '${publishedCommands}'.Split(' ') | Where-Object { $_ -like "$wordToComplete*" } }\n`,
    } as const;
    for (const [shell, expected] of Object.entries(expectedCompletions)) {
      const completion = await executePublic(['completion', shell]);
      expect(completion.exitCode).toBe(CLI_EXIT_CODES.success);
      expect(completion.stdout).toBe(expected);
    }

    for (const unavailableOperation of [['show'], ['copy'], ['device']]) {
      const result = await executePublic(unavailableOperation);
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stderr).toBe(
        "Error [CLI_USAGE]: Invalid command usage. Run 'creds --help'.\n",
      );
    }
  });

  it('runs public status once with the exact default or explicit backend policy', async () => {
    const result = {
      vaultState: 'locked' as const,
      vaultId: vaultIdSchema.parse('vault.primary'),
      deviceId: deviceIdSchema.parse('device.primary'),
      syncState: 'offline' as const,
      pendingChanges: 2,
      lastSyncAt: '2026-08-10T01:02:03.000Z',
    };
    const native = vi.fn<PublicStatusCallback>(() => Promise.resolve(result));
    const nativeResult = await executePublic(['status'], native);
    expect(nativeResult).toEqual({
      exitCode: CLI_EXIT_CODES.success,
      stdout:
        'Vault: locked\nVault ID: vault.primary\nDevice ID: device.primary\nSync: offline\nPending changes: 2\nLast sync: 2026-08-10T01:02:03.000Z\n',
      stderr: '',
    });
    expect(native).toHaveBeenCalledOnce();
    const nativeRequest = native.mock.calls[0]?.[0];
    if (nativeRequest === undefined) throw new Error('Missing status request');
    expect(nativeRequest.backendPolicy).toEqual({ kind: 'native' });
    expect(nativeRequest.environment).toBe(process.env);
    expect(typeof nativeRequest.secrets.read).toBe('function');

    const sealedMasked = vi.fn<PublicStatusCallback>(() => Promise.resolve(result));
    await executePublic(['status', '--secret-backend', 'sealed-file'], sealedMasked);
    expect(sealedMasked.mock.calls[0]?.[0].backendPolicy).toEqual({
      kind: 'sealed-file',
      passphraseFromStdin: false,
    });

    const sealedStdin = vi.fn<PublicStatusCallback>(() => Promise.resolve(result));
    const json = await executePublic(
      [
        'status',
        '--json',
        '--secret-backend',
        'sealed-file',
        '--backend-passphrase-stdin',
      ],
      sealedStdin,
    );
    expect(JSON.parse(json.stdout)).toEqual(result);
    expect(sealedStdin).toHaveBeenCalledOnce();
    expect(sealedStdin.mock.calls[0]?.[0].backendPolicy).toEqual({
      kind: 'sealed-file',
      passphraseFromStdin: true,
    });
  });

  it('rejects invalid public status backend options before callback or stdin access', async () => {
    const callback = vi.fn<PublicStatusCallback>();
    const read = vi.fn(() => {
      throw new Error('stdin-must-not-be-read');
    });
    const stdin = new Readable({ read });

    for (const arguments_ of [
      ['status', '--secret-backend', 'automatic'],
      ['status', '--backend-passphrase-stdin'],
    ]) {
      const result = await executePublic(arguments_, callback, stdin);
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stdout).toBe('');
      expect(result.stderr).not.toContain('automatic');
    }
    expect(callback).not.toHaveBeenCalled();
    expect(read).not.toHaveBeenCalled();
  });

  it('keeps public static, help, and invalid paths outside production status', async () => {
    const callback = vi.fn<PublicStatusCallback>();
    for (const arguments_ of [
      ['--help'],
      ['--version'],
      ['version'],
      ['completion', 'bash'],
      ['generate', '--help'],
      ['status', '--help'],
      ['unknown-command'],
    ]) {
      await executePublic(arguments_, callback);
    }
    expect(callback).not.toHaveBeenCalled();
  });

  it('keeps injected status on its supplied receiver without production input', async () => {
    const secretRead = vi.fn(() => Promise.reject(new Error('unexpected secret read')));
    const secrets: SecretInputPort = {
      read: secretRead,
      readBatch: vi.fn(() => Promise.reject(new Error('unexpected batch read'))),
    };
    const status = vi.fn(() =>
      Promise.resolve({
        vaultState: 'locked' as const,
        syncState: 'offline' as const,
        pendingChanges: 0,
      }),
    );

    const result = await execute(
      ['status', '--secret-backend', 'sealed-file', '--backend-passphrase-stdin'],
      { status },
      secrets,
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(status).toHaveBeenCalledOnce();
    expect(secretRead).not.toHaveBeenCalled();
  });

  it('forwards the invite server only when explicitly supplied', async () => {
    const receivers: CliUseCasePorts[] = [];
    const joinInvite = vi.fn(function (this: CliUseCasePorts) {
      receivers.push(this);
      return Promise.resolve({
        vaultId: vaultIdSchema.parse('vault.primary'),
        deviceId: deviceIdSchema.parse('device.new'),
      });
    });
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
    expect(receivers).toHaveLength(2);
    expect(receivers.every((receiver) => receiver.status instanceof Function)).toBe(
      true,
    );
  });

  it('rejects an explicitly empty invite server before the use case', async () => {
    const joinInvite = vi.fn();
    const readBatch = vi.fn(() =>
      Promise.resolve([ACQUIRED_TOKEN, ACQUIRED_PORTABLE_KEY]),
    );
    const secrets: SecretInputPort = {
      read: () => Promise.reject(new Error('Unexpected single secret read')),
      readBatch,
    };

    const result = await execute(
      ['device', 'invite', 'join', '--vault', 'vault.primary', '--server', ''],
      { joinInvite },
      secrets,
    );

    expect(result).toEqual({
      exitCode: CLI_EXIT_CODES.usage,
      stdout: '',
      stderr: 'Error [CLI_USAGE]: The server URL is invalid.\n',
    });
    expect(readBatch).not.toHaveBeenCalled();
    expect(joinInvite).not.toHaveBeenCalled();
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
  productionStatus?: PublicStatusCallback,
  stdin: Readable = Readable.from([]),
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const output = memoryOutput();
  const exitCode = await runPublicCli(
    arguments_,
    {
      stdin,
      stdout: output.stdout.stream,
      stderr: output.stderr.stream,
    },
    productionStatus,
  );
  return { exitCode, stdout: output.stdout.value(), stderr: output.stderr.value() };
}

function useCases(overrides: Partial<CliUseCasePorts>): CliUseCasePorts {
  const unexpected = (): Promise<never> => Promise.reject(new Error('Unexpected call'));
  return {
    status: unexpected,
    lock: unexpected,
    show: unexpected,
    copy: unexpected,
    listInvitePage: unexpected,
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
