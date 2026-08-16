import { Readable, Writable } from 'node:stream';

import { PermissionError, ValidationError } from '@kavrix/core';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliStoredTotpRequest,
  type CliStoredTotpResult,
  type CliUseCasePorts,
} from '../src/index.js';

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;

function writable(isTty = false): MemoryWritable {
  let content = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      content += Buffer.from(chunk).toString('utf8');
      callback();
    },
  }) as Writable & { isTTY?: boolean };
  if (isTty) stream.isTTY = true;
  return { stream, value: () => content };
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

async function execute(
  arguments_: readonly string[],
  portsOverrides: Partial<CliUseCasePorts> = {},
  stdoutIsTty = false,
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const stdout = writable(stdoutIsTty);
  const stderr = writable();
  const dependencies: CliDependencies = {
    ports: useCases(portsOverrides),
    secrets: {
      read: () => Promise.reject(new Error('secrets unneeded')),
      readBatch: () => Promise.reject(new Error('secrets unneeded')),
    },
    runtime: {
      stdin: Readable.from([]),
      stdout: stdout.stream,
      stderr: stderr.stream,
    },
  };
  const exitCode = await runCli(arguments_, dependencies);
  return { exitCode, stdout: stdout.value(), stderr: stderr.value() };
}

/**
 * A seed the command must never emit.
 *
 * It is never handed to the port either: the port returns only a code. Asserting
 * its absence proves the rendered surface has no path that could carry it even if
 * a future result type gained one.
 */
const SEED_CANARY = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const SAMPLE_CODE = '94287082';

/** Built from code points so no raw control byte is stored in this file. */
const ESCAPE = String.fromCharCode(0x1b);
const BELL = String.fromCharCode(0x07);
const REPLACEMENT = String.fromCharCode(0xff_fd);

function codeResult(overrides: Partial<CliStoredTotpResult> = {}): CliStoredTotpResult {
  return {
    groupName: 'Engineering',
    credentialTitle: 'Identity Provider',
    fieldLabel: 'Authenticator seed',
    fieldKey: 'totp-secret',
    code: SAMPLE_CODE,
    remainingSeconds: 1,
    algorithm: 'sha1',
    digits: 8,
    periodSeconds: 30,
    ...overrides,
  };
}

const BASE_ARGUMENTS = [
  'totp',
  'code',
  'Engineering',
  'Identity Provider',
  'totp-secret',
] as const;

describe('CLI stored TOTP command', () => {
  it('keeps the code alone on stdout and the receipt on stderr', async () => {
    const storedTotp = vi.fn(() => Promise.resolve(codeResult()));

    const result = await execute(
      [...BASE_ARGUMENTS, '--digits', '8', '--time', '59', '--stdout'],
      { storedTotp },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(storedTotp).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Identity Provider',
      fieldQuery: 'totp-secret',
      configuration: { algorithm: 'sha1', digits: 8, periodSeconds: 30 },
      unixTimeSeconds: 59,
    } satisfies CliStoredTotpRequest);
    // Command substitution must capture exactly the code and nothing else.
    expect(result.stdout).toBe(`${SAMPLE_CODE}\n`);
    expect(result.stderr).toContain(
      'TOTP code for "Identity Provider" in group "Engineering":',
    );
    expect(result.stderr).toContain('Field: Authenticator seed (totp-secret)');
    expect(result.stderr).toContain('Policy: sha1, 8 digits, 30s period');
    expect(result.stderr).toContain('Valid For: 1s');
    expect(result.stderr).not.toContain(SAMPLE_CODE);
    expect(result.stderr).not.toContain(SEED_CANARY);
  });

  it('selects the only seed field a credential holds when none is named', async () => {
    const storedTotp = vi.fn(() => Promise.resolve(codeResult()));

    const result = await execute(
      ['totp', 'code', 'Engineering', 'Identity Provider', '--time', '59', '--stdout'],
      { storedTotp },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(storedTotp).toHaveBeenCalledWith(
      expect.objectContaining({ fieldQuery: undefined }),
    );
  });

  it('applies the requested algorithm, width, and period verbatim', async () => {
    const storedTotp = vi.fn(() =>
      Promise.resolve(
        codeResult({ algorithm: 'sha512', digits: 6, periodSeconds: 60 }),
      ),
    );

    const result = await execute(
      [
        ...BASE_ARGUMENTS,
        '--algorithm',
        'sha512',
        '--digits',
        '6',
        '--period',
        '60',
        '--time',
        '1111111109',
        '--stdout',
      ],
      { storedTotp },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(storedTotp).toHaveBeenCalledWith(
      expect.objectContaining({
        configuration: { algorithm: 'sha512', digits: 6, periodSeconds: 60 },
        unixTimeSeconds: 1_111_111_109,
      }),
    );
    expect(result.stderr).toContain('Policy: sha512, 6 digits, 60s period');
  });

  it('refuses to stream a code into a redirect that was not asked for', async () => {
    const storedTotp = vi.fn(() => Promise.resolve(codeResult()));

    const result = await execute([...BASE_ARGUMENTS, '--time', '59'], { storedTotp });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('Redirection is denied by default');
    expect(result.stdout).toBe('');
    expect(storedTotp).not.toHaveBeenCalled();
  });

  it('writes to an interactive terminal without requiring --stdout', async () => {
    const storedTotp = vi.fn(() => Promise.resolve(codeResult()));

    const result = await execute(
      [...BASE_ARGUMENTS, '--time', '59'],
      { storedTotp },
      true,
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toBe(`${SAMPLE_CODE}\n`);
  });

  it.each([
    ['unsupported digest', ['--algorithm', 'md5']],
    ['narrow code width', ['--digits', '5']],
    ['wide code width', ['--digits', '9']],
    ['period below the floor', ['--period', '4']],
    ['period above the ceiling', ['--period', '3601']],
    ['fractional period', ['--period', '30.5']],
    ['negative time', ['--time', '-1']],
    ['time beyond the ceiling', ['--time', '253402300800']],
  ])(
    'rejects an out-of-bounds policy before any vault is read: %s',
    async (_label, policyArguments) => {
      const storedTotp = vi.fn(() => Promise.resolve(codeResult()));

      const result = await execute(
        [...BASE_ARGUMENTS, ...policyArguments, '--stdout'],
        {
          storedTotp,
        },
      );

      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain('The TOTP request is invalid.');
      // Bounds are checked before the vault is opened, so no seed is decrypted
      // for a request that could never have produced a usable code.
      expect(storedTotp).not.toHaveBeenCalled();
    },
  );

  it('surfaces a reveal-policy refusal as a failure and prints nothing', async () => {
    const storedTotp = vi.fn(() => Promise.reject(new PermissionError()));

    const result = await execute([...BASE_ARGUMENTS, '--time', '59', '--stdout'], {
      storedTotp,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(result.stdout).toBe('');
    expect(result.stderr).not.toContain(SEED_CANARY);
  });

  it('reports a malformed stored seed generically and prints no code', async () => {
    const storedTotp = vi.fn(() =>
      Promise.reject(
        new ValidationError(
          'The TOTP seed must use canonical unpadded uppercase base32.',
        ),
      ),
    );

    const result = await execute([...BASE_ARGUMENTS, '--time', '59', '--stdout'], {
      storedTotp,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('canonical unpadded uppercase base32');
    expect(result.stderr).not.toContain(SEED_CANARY);
  });

  it('sanitizes hostile terminal sequences in the receipt', async () => {
    const storedTotp = vi.fn(() =>
      Promise.resolve(
        codeResult({
          credentialTitle: `Identity${ESCAPE}[31mProvider${ESCAPE}[0m`,
          fieldLabel: `Authenticator${ESCAPE}]0;pwn${BELL}seed`,
        }),
      ),
    );

    const result = await execute([...BASE_ARGUMENTS, '--time', '59', '--stdout'], {
      storedTotp,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stderr).not.toContain(ESCAPE);
    expect(result.stderr).not.toContain(BELL);
    expect(result.stderr).toContain(`Identity${REPLACEMENT}Provider${REPLACEMENT}`);
    expect(result.stderr).toContain(`Authenticator${REPLACEMENT}seed`);
  });

  it('fails closed when the credential is not named', async () => {
    for (const argv of [
      ['totp', 'code'],
      ['totp', 'code', 'Engineering'],
    ]) {
      const result = await execute([...argv, '--stdout']);
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stderr).toContain('Invalid command usage');
    }
  });

  it('reports an unconfigured stored-TOTP adapter as unavailable rather than crashing', async () => {
    const result = await execute([...BASE_ARGUMENTS, '--time', '59', '--stdout']);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('totp code is unavailable');
    expect(result.stdout).toBe('');
  });

  it('leaves the local-seed command reachable as its own leaf', async () => {
    // Adding a child must not turn `totp` into a group-only command, or every
    // released `creds totp --secret-stdin` invocation would start failing. The
    // seed read is what fails here, which is proof the leaf handler ran.
    const result = await execute(['totp', '--stdout']);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(result.stderr).not.toContain('Invalid command usage');
  });
});
