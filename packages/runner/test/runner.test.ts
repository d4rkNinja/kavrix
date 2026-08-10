import { createHash } from 'node:crypto';

import {
  fieldScalarValueSchema,
  itemIdSchema,
  secretValueSchema,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  RunnerError,
  runSecureCommand,
  type EnvironmentMapping,
  type InheritableEnvironmentName,
  type RunnerOutputPolicy,
  type SecureRunRequest,
} from '../src/index.js';

const workingDirectory = process.cwd();

function secret(name: string, value: string): EnvironmentMapping {
  return [name, { kind: 'secret', value: secretValueSchema.parse(value) }];
}

function nodeRequest(
  source: string,
  overrides: Partial<SecureRunRequest> = {},
  extraArguments: readonly string[] = [],
): SecureRunRequest {
  return {
    executable: process.execPath,
    arguments: ['-e', source, ...extraArguments],
    cwd: workingDirectory,
    ...overrides,
  };
}

function capturedText(value: Buffer | undefined): string {
  expect(value).toBeDefined();
  return value?.toString('utf8') ?? '';
}

async function expectRunnerError(
  request: SecureRunRequest,
  code: RunnerError['code'],
  forbiddenValue?: string,
): Promise<void> {
  let caught: unknown;
  try {
    await runSecureCommand(request);
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(RunnerError);
  expect((caught as RunnerError).code).toBe(code);
  if (forbiddenValue !== undefined) {
    expect(String(caught)).not.toContain(forbiddenValue);
  }
}

describe('runSecureCommand', () => {
  it('places a secret only in the child environment and leaves the parent unchanged', async () => {
    const canary = 'kavrix-run-secret-6fdbcfb6edc54a949dc1';
    const variable = 'KAVRIX_RUNNER_SECRET_CANARY';
    const parentBefore = process.env[variable];
    const expectedDigest = createHash('sha256').update(canary).digest('hex');
    const script = `
      const { createHash } = require('node:crypto');
      const value = process.env.${variable} ?? '';
      process.stdout.write(JSON.stringify({
        digest: createHash('sha256').update(value).digest('hex'),
        argv: process.argv.slice(1),
        parentMarker: process.env.KAVRIX_PARENT_ONLY ?? null
      }));
    `;

    const result = await runSecureCommand(
      nodeRequest(script, { environment: [secret(variable, canary)] }, [
        '$HOME;$(echo no)&|<>^%PATH%',
      ]),
    );

    expect(result.termination).toBe('exit');
    expect(result.exitCode).toBe(0);
    const output = capturedText(result.stdout);
    expect(JSON.parse(output)).toEqual({
      digest: expectedDigest,
      argv: ['$HOME;$(echo no)&|<>^%PATH%'],
      parentMarker: null,
    });
    expect(output).not.toContain(canary);
    expect(capturedText(result.stderr)).not.toContain(canary);
    expect(process.env[variable]).toBe(parentBefore);
  });

  it('passes shell metacharacters as one literal argument with shell disabled', async () => {
    const literal = 'a b;$HOME|$(whoami)&<>^%PATH%`quoted`';
    const result = await runSecureCommand(
      nodeRequest('process.stdout.write(JSON.stringify(process.argv.slice(1)))', {}, [
        literal,
      ]),
    );

    expect(JSON.parse(capturedText(result.stdout))).toEqual([literal]);
  });

  it('does not inherit parent stdin and presents immediate EOF', async () => {
    const result = await runSecureCommand(
      nodeRequest(`
        let bytes = 0;
        process.stdin.on('data', (chunk) => { bytes += chunk.length; });
        process.stdin.on('end', () => {
          process.stdout.write(JSON.stringify({ bytes, ended: true }));
        });
        process.stdin.resume();
      `),
    );

    expect(JSON.parse(capturedText(result.stdout))).toEqual({ bytes: 0, ended: true });
  });

  it('rejects a mapped secret anywhere in the executable arguments without echoing it', async () => {
    const canary = 'argument-secret-canary-4b3c0dbd';
    await expectRunnerError(
      nodeRequest('process.exit(0)', {
        arguments: ['-e', 'process.exit(0)', `--token=${canary}`],
        environment: [secret('KAVRIX_ARGUMENT_SECRET', canary)],
      }),
      'RUNNER_SECRET_IN_ARGUMENTS',
      canary,
    );
  });

  it('converts supported canonical scalar kinds without inheriting unrelated variables', async () => {
    const environmentEntry = fieldScalarValueSchema.parse({
      kind: 'environment-entry',
      key: 'IGNORED_SOURCE_NAME',
      value: { classification: 'text', value: 'entry-value' },
    });
    const result = await runSecureCommand(
      nodeRequest('process.stdout.write(JSON.stringify(process.env))', {
        environment: [
          ['KAVRIX_TEXT', { kind: 'text', value: 'hello' }],
          ['KAVRIX_NUMBER', { kind: 'number', value: 42.5 }],
          ['KAVRIX_BOOLEAN', { kind: 'boolean', value: false }],
          ['KAVRIX_ENTRY', environmentEntry],
        ],
      }),
    );

    expect(JSON.parse(capturedText(result.stdout))).toMatchObject({
      KAVRIX_TEXT: 'hello',
      KAVRIX_NUMBER: '42.5',
      KAVRIX_BOOLEAN: 'false',
      KAVRIX_ENTRY: 'entry-value',
    });
  });

  it('redacts captured secret bytes emitted by a child across stream chunks', async () => {
    const canary = 'captured-output-secret-canary';
    const result = await runSecureCommand(
      nodeRequest(
        `
          const value = process.env.KAVRIX_CAPTURED;
          process.stdout.write(value.slice(0, 9));
          setTimeout(() => {
            process.stdout.write(value.slice(9));
            process.stderr.write(value.slice(0, 7));
            setTimeout(() => process.stderr.write(value.slice(7)), 5);
          }, 5);
        `,
        { environment: [secret('KAVRIX_CAPTURED', canary)] },
      ),
    );

    expect(capturedText(result.stdout)).toBe('*'.repeat(canary.length));
    expect(capturedText(result.stderr)).toBe('*'.repeat(canary.length));
    expect(JSON.stringify(result)).not.toContain(canary);
  });

  it.each([
    ['stdout', 1],
    ['stdout', 6],
    ['stdout', 21],
    ['stderr', 1],
    ['stderr', 6],
    ['stderr', 21],
  ] as const)(
    'redacts a %s secret prefix when the output limit cuts after %i bytes',
    async (stream, capturedSecretBytes) => {
      const canary = 'runner-truncation-canary';
      const visiblePrefix = 'safe:';
      const splitAt = Math.min(2, capturedSecretBytes);
      const result = await runSecureCommand(
        nodeRequest(
          `
            const value = process.env.KAVRIX_TRUNCATED;
            const output = process.${stream};
            output.write(${JSON.stringify(visiblePrefix)});
            output.write(value.slice(0, ${String(splitAt)}));
            setTimeout(() => output.write(value.slice(${String(splitAt)})), 5);
          `,
          {
            environment: [secret('KAVRIX_TRUNCATED', canary)],
            output: {
              mode: 'capture',
              maxBytes: visiblePrefix.length + capturedSecretBytes,
            },
            terminationGraceMs: 20,
          },
        ),
      );

      const captured = stream === 'stdout' ? result.stdout : result.stderr;
      expect(result.termination).toBe('output-limit');
      expect(result.outputTruncated).toBe(true);
      expect(capturedText(captured)).toBe(
        `${visiblePrefix}${'*'.repeat(capturedSecretBytes)}`,
      );
      expect(capturedText(captured)).not.toContain(
        canary.slice(0, capturedSecretBytes),
      );
    },
  );

  it('redacts overlapping classified values from the original captured bytes', async () => {
    const first = 'overlap-canary-prefix';
    const second = 'prefix-suffix';
    const result = await runSecureCommand(
      nodeRequest('process.stdout.write(`${process.env.KAVRIX_FIRST}-suffix`)', {
        environment: [secret('KAVRIX_FIRST', first), secret('KAVRIX_SECOND', second)],
      }),
    );

    expect(capturedText(result.stdout)).toBe('*'.repeat(`${first}-suffix`.length));
    expect(JSON.stringify(result)).not.toContain(first);
    expect(JSON.stringify(result)).not.toContain(second);
  });

  it.each([
    ['stdout', 'stderr'],
    ['stderr', 'stdout'],
  ] as const)(
    'redacts a partial %s secret when the %s limit terminates the child',
    async (partialStream, overflowingStream) => {
      const canary = 'cross-stream-truncation-canary';
      const result = await runSecureCommand(
        nodeRequest(
          `
            const value = process.env.KAVRIX_CROSS_STREAM;
            process.${partialStream}.write(value.slice(0, 6));
            setTimeout(() => process.${overflowingStream}.write('x'.repeat(1024)), 5);
          `,
          {
            environment: [secret('KAVRIX_CROSS_STREAM', canary)],
            output: { mode: 'capture', maxBytes: 6 },
            terminationGraceMs: 20,
          },
        ),
      );

      const partial = partialStream === 'stdout' ? result.stdout : result.stderr;
      const overflow = overflowingStream === 'stdout' ? result.stdout : result.stderr;
      expect(result.termination).toBe('output-limit');
      expect(result.outputTruncated).toBe(true);
      expect(capturedText(partial)).toBe('*'.repeat(6));
      expect(capturedText(overflow)).toBe('x'.repeat(6));
    },
  );

  it('reports ordinary exit codes without turning child output into an error', async () => {
    const result = await runSecureCommand(
      nodeRequest("process.stderr.write('expected failure'); process.exit(7)"),
    );

    expect(result).toMatchObject({
      exitCode: 7,
      signal: null,
      termination: 'exit',
      outputTruncated: false,
    });
    expect(capturedText(result.stderr)).toBe('expected failure');
  });

  it('reports a child signal separately from an exit code', async () => {
    const result = await runSecureCommand(
      nodeRequest("setTimeout(() => process.kill(process.pid, 'SIGTERM'), 10)"),
    );

    if (process.platform === 'win32') {
      expect(result.exitCode).toBe(1);
      expect(result.signal).toBeNull();
      expect(result.termination).toBe('exit');
    } else {
      expect(result.exitCode).toBeNull();
      expect(result.signal).toBe('SIGTERM');
      expect(result.termination).toBe('signal');
    }
  });

  it('terminates a long-running child after its timeout', async () => {
    const result = await runSecureCommand(
      nodeRequest('setInterval(() => {}, 1_000)', {
        timeoutMs: 40,
        terminationGraceMs: 20,
      }),
    );

    expect(result.termination).toBe('timeout');
    expect(result.exitCode === null || result.exitCode !== 0).toBe(true);
  });

  it('terminates a child when its abort signal fires', async () => {
    const controller = new AbortController();
    const pending = runSecureCommand(
      nodeRequest('setInterval(() => {}, 1_000)', {
        signal: controller.signal,
        terminationGraceMs: 20,
      }),
    );
    setTimeout(() => {
      controller.abort();
    }, 40);

    const result = await pending;
    expect(result.termination).toBe('aborted');
  });

  it('rejects an already-aborted request before spawning', async () => {
    const controller = new AbortController();
    controller.abort();
    await expectRunnerError(
      nodeRequest('process.exit(99)', { signal: controller.signal }),
      'RUNNER_ABORTED',
    );
  });

  it('kills output that exceeds either bounded capture', async () => {
    const result = await runSecureCommand(
      nodeRequest(
        'process.stdout.write(Buffer.alloc(4096, 65)); process.stderr.write(Buffer.alloc(4096, 66)); setInterval(() => {}, 1_000)',
        { output: { mode: 'capture', maxBytes: 512 }, terminationGraceMs: 20 },
      ),
    );

    expect(result.termination).toBe('output-limit');
    expect(result.outputTruncated).toBe(true);
    expect(result.stdout?.byteLength).toBeLessThanOrEqual(512);
    expect(result.stderr?.byteLength).toBeLessThanOrEqual(512);
  });

  it('inherits only reviewed parent variables when explicitly requested', async () => {
    const result = await runSecureCommand(
      nodeRequest(
        "process.stdout.write(String(typeof process.env.PATH === 'string'))",
        {
          inheritEnvironment: ['PATH'],
        },
      ),
    );

    expect(capturedText(result.stdout)).toBe('true');
  });

  it('sanitizes asynchronous spawn failures', async () => {
    const canary = 'missing-executable-secret-canary';
    await expectRunnerError(
      {
        executable: `${workingDirectory}/does-not-exist-kavrix-runner`,
        cwd: workingDirectory,
        environment: [secret('KAVRIX_SPAWN_CANARY', canary)],
      },
      'RUNNER_SPAWN_FAILED',
      canary,
    );
  });
});

describe('request and environment validation', () => {
  it.each([
    ['invalid name', 'BAD-NAME'],
    ['reserved loader name', 'NODE_OPTIONS'],
    ['reserved path name', 'Path'],
    ['NUL value', 'KAVRIX_VALUE_WITH_NUL'],
  ])('rejects %s generically', async (_label, name) => {
    const value = name === 'KAVRIX_VALUE_WITH_NUL' ? 'bad\0value' : 'safe-value';
    const mapping = [
      name,
      name === 'KAVRIX_VALUE_WITH_NUL'
        ? ({ kind: 'text', value } as const)
        : ({ kind: 'text', value } as const),
    ] as EnvironmentMapping;
    await expectRunnerError(
      nodeRequest('process.exit(0)', { environment: [mapping] }),
      'RUNNER_ENVIRONMENT_REJECTED',
      value,
    );
  });

  it('rejects case-insensitive destination collisions for Windows portability', async () => {
    await expectRunnerError(
      nodeRequest('process.exit(0)', {
        environment: [
          ['KAVRIX_CASE', { kind: 'text', value: 'one' }],
          ['kavrix_case', { kind: 'text', value: 'two' }],
        ],
      }),
      'RUNNER_ENVIRONMENT_REJECTED',
    );
  });

  it('rejects collisions between inherited and mapped variables', async () => {
    await expectRunnerError(
      nodeRequest('process.exit(0)', {
        inheritEnvironment: ['TEMP'],
        environment: [['temp', { kind: 'text', value: 'not-parent-temp' }]],
      }),
      'RUNNER_ENVIRONMENT_REJECTED',
    );
  });

  it('rejects unreviewed inheritance names at runtime', async () => {
    await expectRunnerError(
      nodeRequest('process.exit(0)', {
        inheritEnvironment: ['NODE_OPTIONS' as InheritableEnvironmentName],
      }),
      'RUNNER_ENVIRONMENT_REJECTED',
    );
  });

  it('rejects unsupported canonical reference scalars', async () => {
    const reference = fieldScalarValueSchema.parse({
      kind: 'item-reference',
      itemId: itemIdSchema.parse('item_runner_reference'),
    });
    await expectRunnerError(
      nodeRequest('process.exit(0)', {
        environment: [['KAVRIX_REFERENCE', reference]],
      }),
      'RUNNER_ENVIRONMENT_REJECTED',
    );
  });

  it.each([
    ['relative cwd', { cwd: '.' }, undefined],
    ['file cwd', { cwd: import.meta.filename }, import.meta.filename],
    [
      'missing cwd',
      { cwd: `${workingDirectory}/missing-runner-cwd` },
      `${workingDirectory}/missing-runner-cwd`,
    ],
  ])(
    'rejects an invalid %s without disclosing the path',
    async (_label, override, forbiddenPath) => {
      await expectRunnerError(
        nodeRequest('process.exit(0)', override),
        'RUNNER_INVALID_CWD',
        forbiddenPath,
      );
    },
  );

  it.each([
    { timeoutMs: 0 },
    { timeoutMs: Number.NaN },
    { terminationGraceMs: -1 },
    { output: { mode: 'capture', maxBytes: 0 } as const },
    {
      output: { mode: 'inherit' } as unknown as RunnerOutputPolicy,
    },
    { arguments: ['bad\0argument'] },
  ])('rejects malformed execution bounds', async (override) => {
    await expectRunnerError(
      nodeRequest('process.exit(0)', override),
      'RUNNER_INVALID_REQUEST',
    );
  });

  it('rejects oversized environment values and aggregates', async () => {
    await expectRunnerError(
      nodeRequest('process.exit(0)', {
        environment: [
          ['KAVRIX_TOO_LARGE', { kind: 'text', value: 'x'.repeat(16 * 1_024 + 1) }],
        ],
      }),
      'RUNNER_ENVIRONMENT_REJECTED',
    );

    const mappings = Array.from(
      { length: 3 },
      (_, index) =>
        [
          `KAVRIX_AGGREGATE_${String(index)}`,
          { kind: 'text', value: 'x'.repeat(12 * 1_024) },
        ] as const satisfies EnvironmentMapping,
    );
    await expectRunnerError(
      nodeRequest('process.exit(0)', { environment: mappings }),
      'RUNNER_ENVIRONMENT_REJECTED',
    );
  });
});
