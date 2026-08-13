import { PassThrough, Readable, Writable } from 'node:stream';

import { describe, expect, it, vi } from 'vitest';

import { CLI_EXIT_CODES, runPublicCli, type CliRuntime } from '../src/index.js';

const RFC_SEEDS = {
  sha1: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  sha256: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  sha512:
    'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA',
} as const;

const RFC_VECTORS = [
  [59, '94287082', '46119246', '90693936'],
  [1_111_111_109, '07081804', '68084774', '25091201'],
  [1_111_111_111, '14050471', '67062674', '99943326'],
  [1_234_567_890, '89005924', '91819424', '93441116'],
  [2_000_000_000, '69279037', '90698825', '38618901'],
  [20_000_000_000, '65353130', '77737706', '47863826'],
] as const;

const RFC_CASES = RFC_VECTORS.flatMap(([time, sha1, sha256, sha512]) => [
  [time, 'sha1', sha1] as const,
  [time, 'sha256', sha256] as const,
  [time, 'sha512', sha512] as const,
]);

describe('public password and passphrase commands', () => {
  it('generates a default password only on an interactive stdout', async () => {
    const result = await executePublic(['generate', 'password'], {
      stdoutIsTty: true,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stderr).toBe('');
    expect(result.stdout).toMatch(/^[!-~]{24}\n$/u);
    expect(result.stdout).toMatch(/[a-z]/u);
    expect(result.stdout).toMatch(/[A-Z]/u);
    expect(result.stdout).toMatch(/[0-9]/u);
    expect(
      Array.from(result.stdout).some((character) =>
        '!@#$%^&*()-_=+[]{}:,.?'.includes(character),
      ),
    ).toBe(true);
  });

  it('applies bounded password minima and exclusions through the real generator', async () => {
    const arguments_ = [
      'generate',
      'password',
      '--length',
      '40',
      '--lowercase-min',
      '6',
      '--uppercase-min',
      '5',
      '--digits-min',
      '4',
      '--symbols-min',
      '3',
      '--exclude',
      'aA0!',
      '--stdout',
    ] as const;
    const result = await executePublic(arguments_);
    const generated = result.stdout.trimEnd();

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(generated).toHaveLength(40);
    expect(generated).not.toMatch(/[aA0!]/u);
    expect(generated.match(/[b-z]/gu)?.length ?? 0).toBeGreaterThanOrEqual(6);
    expect(generated.match(/[B-Z]/gu)?.length ?? 0).toBeGreaterThanOrEqual(5);
    expect(generated.match(/[1-9]/gu)?.length ?? 0).toBeGreaterThanOrEqual(4);
    expect(
      Array.from(generated).filter((character) =>
        '@#$%^&*()-_=+[]{}:,.?'.includes(character),
      ).length,
    ).toBeGreaterThanOrEqual(3);
    expect(arguments_.join(' ')).not.toContain(generated);
  });

  it.each([
    [
      'sum exceeds length',
      ['--length', '8', '--lowercase-min', '8', '--digits-min', '1'],
    ],
    [
      'no enabled classes',
      [
        '--lowercase-min',
        '0',
        '--uppercase-min',
        '0',
        '--digits-min',
        '0',
        '--symbols-min',
        '0',
      ],
    ],
    ['invalid length', ['--length', '7']],
    ['duplicate exclusions', ['--exclude', 'aa']],
  ])('rejects impossible password policy: %s', async (_label, policyArguments) => {
    const result = await executePublic([
      'generate',
      'password',
      ...policyArguments,
      '--stdout',
    ]);
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('password generation policy is invalid');
  });

  it('generates a decorated, excluded-word passphrase with exact output only', async () => {
    const result = await executePublic([
      'generate',
      'passphrase',
      '--words',
      '6',
      '--separator',
      '_',
      '--capitalize',
      '--digit',
      '--stdout',
      '--exclude-word',
      'acid',
    ]);
    const value = result.stdout.trimEnd();
    const tokens = value.split('_');

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toBe(`${value}\n`);
    expect(tokens).toHaveLength(7);
    expect(tokens.at(-1)).toMatch(/^\d$/u);
    expect(tokens.slice(0, -1).filter((word) => /^[A-Z]/u.test(word))).toHaveLength(1);
    expect(tokens.map((word) => word.toLowerCase())).not.toContain('acid');
  });

  it('uses the strong passphrase defaults on an interactive stdout', async () => {
    const result = await executePublic(['generate', 'passphrase'], {
      stdoutIsTty: true,
    });
    const value = result.stdout.trimEnd();

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toBe(`${value}\n`);
    expect(value).toMatch(/^[a-z-]+$/u);
    expect(value.length).toBeGreaterThan(23);
  });

  it.each([
    ['--words', '5'],
    ['--words', '25'],
    ['--separator', ' '],
    ['--exclude-word', 'not-a-canonical-word'],
  ])('rejects invalid passphrase option %s %s', async (flag, value) => {
    const result = await executePublic([
      'generate',
      'passphrase',
      flag,
      value,
      '--stdout',
    ]);
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('passphrase generation policy is invalid');
  });
});

describe('public TOTP command', () => {
  it.each(RFC_CASES)(
    'matches the RFC vector at %i with %s',
    async (time, algorithm, expected) => {
      const result = await executePublic(
        [
          'totp',
          '--secret-stdin',
          '--algorithm',
          algorithm,
          '--digits',
          '8',
          '--period',
          '30',
          '--time',
          String(time),
          '--stdout',
        ],
        { stdin: Readable.from([RFC_SEEDS[algorithm]]) },
      );

      expect(result).toEqual({
        exitCode: CLI_EXIT_CODES.success,
        stdout: `${expected}\n`,
        stderr: '',
      });
    },
  );

  it('reads a seed from a masked terminal without echoing it', async () => {
    const input = new FakeTty();
    const pending = executePublic(
      ['totp', '--algorithm', 'sha1', '--digits', '8', '--time', '59'],
      { stdin: input, stdoutIsTty: true },
    );
    input.write(`${RFC_SEEDS.sha1}\r`);
    const result = await pending;

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toBe('94287082\n');
    expect(result.stderr).toBe('Enter TOTP seed (input hidden): \n');
    expect(result.stderr).not.toContain(RFC_SEEDS.sha1);
    expect(input.rawTransitions).toEqual([true, false]);
  });

  it('uses the current Unix time only when no explicit time is supplied', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(59_000));
    try {
      const result = await executePublic(
        ['totp', '--secret-stdin', '--algorithm', 'sha1', '--digits', '8', '--stdout'],
        { stdin: Readable.from([RFC_SEEDS.sha1]) },
      );
      expect(result.stdout).toBe('94287082\n');
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ['--algorithm', 'md5'],
    ['--digits', '5'],
    ['--digits', '9'],
    ['--period', '4'],
    ['--period', '3601'],
    ['--time', '253402300800'],
    ['--time', '01'],
  ])(
    'rejects invalid TOTP option %s %s before seed acquisition',
    async (flag, value) => {
      const input = new PassThrough();
      input.end(RFC_SEEDS.sha1);
      const result = await executePublic(
        ['totp', '--secret-stdin', flag, value, '--stdout'],
        { stdin: input },
      );

      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain('The TOTP request is invalid.');
      expect(input.readableLength).toBeGreaterThan(0);
    },
  );

  it.each([
    ['lowercase', RFC_SEEDS.sha1.toLowerCase()],
    ['NUL', `${RFC_SEEDS.sha1}\0`],
    ['control', `${RFC_SEEDS.sha1}\u0001`],
    ['short', 'AAAAAAAA'],
  ])('fails generically for malformed %s seed input', async (_label, seed) => {
    const result = await executePublic(
      ['totp', '--secret-stdin', '--time', '59', '--stdout'],
      { stdin: Readable.from([seed]) },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stdout).toBe('');
    expect(`${result.stdout}${result.stderr}`).not.toContain(seed);
  });

  it('rejects oversized stdin without reflecting content', async () => {
    const result = await executePublic(['totp', '--secret-stdin', '--stdout'], {
      stdin: Readable.from([Buffer.alloc(1_048_579, 0x41)]),
    });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('exceeds the supported size');
    expect(result.stderr).not.toContain('AAAA');
  });
});

describe('public secret-output boundary', () => {
  it.each([
    ['generate', 'password'],
    ['generate', 'passphrase'],
  ])('requires --stdout for redirected %s %s output', async (...arguments_) => {
    const result = await executePublic(arguments_);
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('explicit --stdout acknowledgement');
  });

  it('rejects redirected TOTP before consuming its seed', async () => {
    const input = new PassThrough();
    input.end(RFC_SEEDS.sha1);
    const result = await executePublic(['totp', '--secret-stdin'], { stdin: input });
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stdout).toBe('');
    expect(input.readableLength).toBeGreaterThan(0);
  });

  it('keeps unexpected output-boundary failures generic', async () => {
    const canary = 'SECRET-OUTPUT-WRITER-FAILURE-CANARY';
    const stderr = capture(false);
    const stdout = {
      isTTY: true,
      write: (): never => {
        throw new Error(canary);
      },
    } as unknown as Writable;

    const exitCode = await runPublicCli(['generate', 'password'], {
      stdin: Readable.from([]),
      stdout,
      stderr: stderr.stream,
    });

    expect(exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(stderr.value()).toBe(
      'Error [UNEXPECTED_FAILURE]: The command failed without exposing internal details.\n',
    );
    expect(stderr.value()).not.toContain(canary);
  });

  it('never reads a seed from argv/environment or reveals canaries in errors/completion', async () => {
    const canary = 'TOTP-SEED-HISTORY-ENV-CANARY';
    vi.stubEnv('KAVRIX_TOTP_SECRET', canary);
    const argv = await executePublic(['totp', '--secret', canary, '--stdout']);
    expect(argv.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(`${argv.stdout}${argv.stderr}`).not.toContain(canary);

    const ignoredEnvironment = await executePublic(['totp'], {
      stdoutIsTty: true,
    });
    expect(ignoredEnvironment.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(`${ignoredEnvironment.stdout}${ignoredEnvironment.stderr}`).not.toContain(
      canary,
    );

    const completion = await executePublic(['completion', 'bash']);
    expect(completion.stdout).toContain(
      'version generate totp key init unlock lock status group credential field note show copy reveal get sync completion',
    );
    expect(completion.stdout).not.toContain('--secret');
    expect(completion.stdout).not.toContain(canary);
  });
});

type ExecuteOptions = Readonly<{
  stdin?: Readable;
  stdoutIsTty?: boolean;
}>;

async function executePublic(
  arguments_: readonly string[],
  options: ExecuteOptions = {},
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const stdout = capture(options.stdoutIsTty === true);
  const stderr = capture(false);
  const runtime: CliRuntime = {
    stdin: options.stdin ?? Readable.from([]),
    stdout: stdout.stream,
    stderr: stderr.stream,
  };
  const exitCode = await runPublicCli(arguments_, runtime);
  return { exitCode, stdout: stdout.value(), stderr: stderr.value() };
}

class FakeTty extends PassThrough {
  public readonly isTTY = true;
  public isRaw = false;
  public readonly rawTransitions: boolean[] = [];

  public setRawMode(enabled: boolean): void {
    this.isRaw = enabled;
    this.rawTransitions.push(enabled);
  }
}

type CapturedWritable = Readonly<{ stream: Writable; value: () => string }>;

function capture(isTTY: boolean): CapturedWritable {
  let content = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      content += Buffer.from(chunk).toString('utf8');
      callback();
    },
  }) as Writable & { isTTY?: boolean };
  if (isTTY) stream.isTTY = true;
  return { stream, value: () => content };
}
