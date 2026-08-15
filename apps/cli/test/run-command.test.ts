import { resolve } from 'node:path';
import { Readable, Writable } from 'node:stream';

import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliRunResult,
  type CliUseCasePorts,
} from '../src/index.js';
import { cliRunQuerySchema } from '../src/mutation-contracts.js';

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
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const stdout = writable();
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

function result(overrides: Partial<CliRunResult> = {}): CliRunResult {
  return {
    executable: 'deploy',
    exitCode: 0,
    signal: null,
    termination: 'exit',
    outputTruncated: false,
    environmentNames: [],
    secretNames: [],
    stdout: '',
    stderr: '',
    ...overrides,
  };
}

/** The injected port is optional, so each mock names the request it receives. */
type RunPort = NonNullable<CliUseCasePorts['run']>;

describe('CLI run command', () => {
  /** Built from a code point so this source file stays free of control bytes. */
  const ESCAPE = String.fromCodePoint(0x1b);
  const REPLACEMENT = String.fromCodePoint(0xfffd);

  it('forwards every repeated mapping, the inherit allow-list, and the bounds', async () => {
    const run = vi.fn<RunPort>(() => Promise.resolve(result({ executable: 'deploy' })));
    const outcome = await execute(
      [
        'run',
        '--env',
        'DATABASE_URL=Infra/Postgres/url',
        '--env',
        'API_TOKEN=Infra/Vendor/token#2',
        '--inherit',
        'PATH,HOME',
        '--cwd',
        '/srv/app',
        '--timeout',
        '5000',
        '--max-output',
        '4096',
        'deploy',
        'release',
        '--wait',
      ],
      { run },
    );

    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(run).toHaveBeenCalledWith({
      executable: 'deploy',
      arguments: ['release', '--wait'],
      environment: [
        {
          name: 'DATABASE_URL',
          groupQuery: 'Infra',
          credentialQuery: 'Postgres',
          fieldQuery: 'url',
        },
        {
          name: 'API_TOKEN',
          groupQuery: 'Infra',
          credentialQuery: 'Vendor',
          fieldQuery: 'token',
          index: 2,
        },
      ],
      inherit: ['PATH', 'HOME'],
      cwd: resolve('/srv/app'),
      timeoutMs: 5000,
      maxOutputBytes: 4096,
      dryRun: false,
    });
  });

  it('runs with no mapping and defaults the capture limit and working directory', async () => {
    const run = vi.fn<RunPort>(() => Promise.resolve(result({ executable: 'true' })));
    const outcome = await execute(['run', 'true'], { run });

    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    const request = run.mock.calls[0]?.[0];
    expect(request?.environment).toEqual([]);
    expect(request?.inherit).toEqual([]);
    expect(request?.arguments).toEqual([]);
    expect(request?.cwd).toBe(resolve(process.cwd()));
    expect(request?.maxOutputBytes).toBe(64 * 1024);
    expect(request?.timeoutMs).toBeUndefined();
  });

  it('accepts a leading separator before the relayed arguments', async () => {
    const run = vi.fn<RunPort>(() => Promise.resolve(result({ executable: 'node' })));
    const outcome = await execute(['run', 'node', '--', '--version', '--json'], {
      run,
    });

    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(run.mock.calls[0]?.[0].arguments).toEqual(['--version', '--json']);
  });

  it('plans a run without unlocking the vault or reading any field', async () => {
    const run = vi.fn<RunPort>(() =>
      Promise.reject(new Error('A dry run must not execute.')),
    );
    const outcome = await execute(
      [
        'run',
        '--dry-run',
        '--env',
        'API_TOKEN=Infra/Vendor/token',
        '--inherit',
        'PATH',
        '--cwd',
        '/srv/app',
        '--timeout',
        '2500',
        'deploy',
        'release',
      ],
      { run },
    );

    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(run).not.toHaveBeenCalled();
    expect(outcome.stdout).toContain(
      'Planned guarded execution (no command was started)',
    );
    expect(outcome.stdout).toContain('Executable: deploy');
    expect(outcome.stdout).toContain('Arguments: 1');
    expect(outcome.stdout).toContain(`Working Directory: ${resolve('/srv/app')}`);
    expect(outcome.stdout).toContain('Environment Destinations: API_TOKEN');
    expect(outcome.stdout).toContain('Inherited Variables: PATH');
    expect(outcome.stdout).toContain('Timeout: 2500 ms');
    expect(outcome.stdout).toContain('Output Limit: 65536 bytes per stream');
    expect(outcome.stdout).toContain(
      'No field was read, so no value was decrypted for this plan.',
    );
  });

  it('plans a run even when no production adapter is configured', async () => {
    // Nothing in the dry-run path may reach the unlock composition, which would
    // fail closed as unavailable without an environment.
    const outcome = await execute([
      'run',
      '--dry-run',
      '--env',
      'API_TOKEN=Infra/Vendor/token',
      'deploy',
    ]);
    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(outcome.stderr).toBe('');
  });

  it('emits a plan as redacted JSON carrying destination names only', async () => {
    const outcome = await execute([
      'run',
      '--dry-run',
      '--json',
      '--env',
      'API_TOKEN=Infra/Vendor/token',
      '--max-output',
      '1024',
      'deploy',
    ]);
    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(JSON.parse(outcome.stdout)).toEqual({
      executable: 'deploy',
      argumentCount: 0,
      environmentNames: ['API_TOKEN'],
      inherited: [],
      cwd: resolve(process.cwd()),
      timeoutMs: null,
      maxOutputBytes: 1024,
    });
  });

  it('reports destinations, truncation, and secret classification without values', async () => {
    const run = vi.fn<RunPort>(() =>
      Promise.resolve(
        result({
          environmentNames: ['API_TOKEN', 'REGION'],
          secretNames: ['API_TOKEN'],
          outputTruncated: true,
          stdout: 'deployed [REDACTED]\nsecond line\n',
        }),
      ),
    );
    const outcome = await execute(
      [
        'run',
        '--env',
        'API_TOKEN=Infra/Vendor/token',
        '--env',
        'REGION=Infra/Meta/region',
        'deploy',
      ],
      { run },
    );

    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(outcome.stdout).toContain(
      'Environment Destinations: API_TOKEN (secret), REGION',
    );
    expect(outcome.stdout).toContain('Output Truncated: yes');
    expect(outcome.stdout).toContain('deployed [REDACTED]');
    expect(outcome.stdout).toContain('second line');
    expect(outcome.stdout).toContain('stderr: (empty)');
  });

  it('sanitizes escape sequences in captured child output', async () => {
    const run = vi.fn<RunPort>(() =>
      Promise.resolve(result({ stdout: `${ESCAPE}]0;stolen${ESCAPE}\\ok\n` })),
    );
    const outcome = await execute(['run', 'deploy'], { run });

    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(outcome.stdout).not.toContain(ESCAPE);
    expect(outcome.stdout).toContain(REPLACEMENT);
  });

  it('fails when the child exits non-zero while still reporting its status', async () => {
    const run = vi.fn<RunPort>(() => Promise.resolve(result({ exitCode: 12 })));
    const outcome = await execute(['run', 'deploy'], { run });

    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(outcome.stdout).toContain('Exit Code: 12');
    expect(outcome.stderr).toContain('Error [RUN_CHILD_FAILED]');
    expect(outcome.stderr).toContain('The command exited with code 12.');
  });

  it('fails and names the termination reason when a run is bounded or interrupted', async () => {
    for (const termination of ['timeout', 'aborted', 'output-limit'] as const) {
      const run = vi.fn<RunPort>(() =>
        Promise.resolve(result({ exitCode: null, termination, signal: 'SIGKILL' })),
      );
      const outcome = await execute(['run', 'deploy'], { run });

      expect(outcome.exitCode).toBe(CLI_EXIT_CODES.failure);
      expect(outcome.stdout).toContain(`Termination: ${termination}`);
      expect(outcome.stdout).toContain('Signal: SIGKILL');
      expect(outcome.stderr).toContain(
        `The command did not complete normally (${termination}).`,
      );
    }
  });

  it('refuses a destination name the runner reserves for itself', async () => {
    const run = vi.fn<RunPort>(() => Promise.resolve(result()));
    for (const mapping of [
      'PATH=Infra/Vendor/token',
      'path=Infra/Vendor/token',
      'LD_PRELOAD=Infra/Vendor/token',
      'NODE_OPTIONS=Infra/Vendor/token',
    ]) {
      const outcome = await execute(['run', '--env', mapping, 'deploy'], { run });
      expect(outcome.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(outcome.stderr).toContain('The run request is invalid.');
    }
    expect(run).not.toHaveBeenCalled();
  });

  it('refuses a destination name mapped more than once, ignoring case', async () => {
    const run = vi.fn<RunPort>(() => Promise.resolve(result()));
    const outcome = await execute(
      [
        'run',
        '--env',
        'API_TOKEN=Infra/Vendor/token',
        '--env',
        'api_token=Infra/Vendor/other',
        'deploy',
      ],
      { run },
    );
    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(run).not.toHaveBeenCalled();
  });

  it('refuses malformed mappings, unsupported names, and out-of-range bounds', async () => {
    const run = vi.fn<RunPort>(() => Promise.resolve(result()));
    const rejected: readonly (readonly string[])[] = [
      ['run', '--env', 'API_TOKEN', 'deploy'],
      ['run', '--env', 'API_TOKEN=Infra/Vendor', 'deploy'],
      ['run', '--env', 'API_TOKEN=Infra/Vendor/token/extra', 'deploy'],
      ['run', '--env', '1TOKEN=Infra/Vendor/token', 'deploy'],
      ['run', '--env', 'API TOKEN=Infra/Vendor/token', 'deploy'],
      ['run', '--env', 'API_TOKEN=Infra/Vendor/token#0', 'deploy'],
      ['run', '--inherit', 'SECRET_TOKEN', 'deploy'],
      ['run', '--inherit', 'PATH,SECRET_TOKEN', 'deploy'],
      ['run', '--timeout', '0', 'deploy'],
      ['run', '--timeout', 'soon', 'deploy'],
      ['run', '--timeout', '86400001', 'deploy'],
      ['run', '--max-output', '0', 'deploy'],
      ['run', '--max-output', '16777217', 'deploy'],
      ['run', '--cwd', '', 'deploy'],
    ];
    for (const arguments_ of rejected) {
      const outcome = await execute(arguments_, { run });
      expect(outcome.exitCode).toBe(CLI_EXIT_CODES.usage);
    }
    expect(run).not.toHaveBeenCalled();
  });

  it('relays a child flag verbatim instead of letting this CLI claim it', async () => {
    const run = vi.fn<RunPort>(() => Promise.resolve(result({ executable: 'node' })));
    // --version belongs to the root program and --json to this command, so
    // without passthrough both would be answered here and never reach the child.
    const outcome = await execute(['run', 'node', '--version', '--json'], { run });

    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(run.mock.calls[0]?.[0].arguments).toEqual(['--version', '--json']);
    expect(outcome.stdout).not.toContain('0.1.0');
  });

  it('keeps a separator that the child owns while consuming the leading one', async () => {
    const run = vi.fn<RunPort>(() => Promise.resolve(result({ executable: 'node' })));
    const outcome = await execute(['run', 'node', '-e', 'code', '--', 'tail'], { run });

    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(run.mock.calls[0]?.[0].arguments).toEqual(['-e', 'code', '--', 'tail']);
  });

  it('fails closed as unavailable when no production adapter is configured', async () => {
    const outcome = await execute(['run', 'deploy']);
    expect(outcome.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(outcome.stderr).toContain('Error [CLI_UNAVAILABLE]');
    expect(outcome.stdout).toBe('');
  });

  it('refuses a NUL byte in the executable or an argument', () => {
    const nul = String.fromCodePoint(0);
    expect(
      cliRunQuerySchema.safeParse({
        env: [],
        executable: `deploy${nul}`,
        arguments: [],
      }).success,
    ).toBe(false);
    expect(
      cliRunQuerySchema.safeParse({
        env: [],
        executable: 'deploy',
        arguments: [`release${nul}`],
      }).success,
    ).toBe(false);
  });

  it('bounds the mapping count and the argument count', () => {
    const mapping = (index: number): string =>
      `TOKEN_${String(index)}=Infra/Vendor/token`;
    expect(
      cliRunQuerySchema.safeParse({
        env: Array.from({ length: 257 }, (_value, index) => mapping(index)),
        executable: 'deploy',
        arguments: [],
      }).success,
    ).toBe(false);
    expect(
      cliRunQuerySchema.safeParse({
        env: [],
        executable: 'deploy',
        arguments: Array.from({ length: 1025 }, () => 'x'),
      }).success,
    ).toBe(false);
  });
});
