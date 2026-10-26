import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ChildProcess } from 'node:child_process';

import {
  exitCodeForCliError,
  fieldScalarValueSchema,
  itemIdSchema,
  secretValueSchema,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  cliErrorCodeForRunnerError,
  INHERITABLE_ENVIRONMENT_NAMES,
  isReservedEnvironmentName,
  RESERVED_ENVIRONMENT_NAMES,
  RunnerError,
  RUNNER_LIMITS,
  RUNNER_SPAWN_FAILED_CLI_ERROR_CODE,
  runSecureCommand,
  type EnvironmentMapping,
  type InheritableEnvironmentName,
  type RunnerOutputPolicy,
  type SecureRunRequest,
} from '../src/index.js';
import { prepareEnvironment } from '../src/environment.js';

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

/** Synchronous counterpart of expectRunnerError for prepareEnvironment. */
function expectEnvironmentRejected(run: () => unknown): void {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(RunnerError);
  expect((caught as RunnerError).code).toBe('RUNNER_ENVIRONMENT_REJECTED');
}

/** Mutates one parent variable for the duration of run, then restores it. */
async function withParentVariable(
  name: string,
  value: string,
  run: () => Promise<void>,
): Promise<void> {
  const previous = process.env[name];
  process.env[name] = value;
  try {
    await run();
  } finally {
    if (previous === undefined) {
      Reflect.deleteProperty(process.env, name);
    } else {
      process.env[name] = previous;
    }
  }
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function waitForPredicate(
  predicate: () => boolean,
  timeoutMs: number,
  intervalMs = 25,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return true;
    if (Date.now() >= deadline) return false;
    await delay(intervalMs);
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

  it('reports a requested termination with the requested signal', async () => {
    // Default grace so the Windows tree sweep (an external taskkill whose raw
    // TerminateProcess artifact would surface as exit code 1 with no signal)
    // lands before the direct-child escalation; POSIX reports the group
    // SIGTERM directly. Either way the observable shape must be one requested
    // SIGTERM-shaped termination.
    const result = await runSecureCommand(
      nodeRequest('setInterval(() => {}, 1_000)', { timeoutMs: 40 }),
    );

    expect(result.termination).toBe('timeout');
    expect(result.exitCode).toBeNull();
    expect(result.signal).toBe('SIGTERM');
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

  it('terminates descendants of the spawned child, not only the child itself', async () => {
    const treeDirectory = mkdtempSync(join(tmpdir(), 'kavrix-runner-tree-'));
    const pidFile = join(treeDirectory, 'grandchild-pid');
    // The spawner publishes the grandchild pid through a file so the test
    // cancels only after the descendant exists. The grandchild is spawned
    // without `detached` so it stays inside the runner child's POSIX process
    // group while also remaining in the Windows parent chain taskkill walks.
    const spawnerSource = `
      const { spawn } = require('node:child_process');
      const { writeFileSync } = require('node:fs');
      const grandchild = spawn(
        process.execPath,
        ['-e', 'setInterval(() => {}, 1_000)'],
        { stdio: 'ignore' },
      );
      grandchild.unref();
      writeFileSync(process.env.KAVRIX_TREE_PID_FILE, String(grandchild.pid));
      setInterval(() => {}, 1_000);
    `;
    const controller = new AbortController();
    const pending = runSecureCommand(
      nodeRequest(spawnerSource, {
        signal: controller.signal,
        // Generous grace so the Windows taskkill sweep (which must observe
        // the live tree) is never preempted by the direct-child escalation.
        terminationGraceMs: 5_000,
        environment: [['KAVRIX_TREE_PID_FILE', { kind: 'text', value: pidFile }]],
      }),
    );
    let grandchildPid = 0;
    try {
      const published = await waitForPredicate(() => {
        try {
          const parsed = Number(readFileSync(pidFile, 'utf8'));
          return Number.isSafeInteger(parsed) && parsed > 0;
        } catch {
          return false;
        }
      }, 30_000);
      expect(published).toBe(true);
      grandchildPid = Number(readFileSync(pidFile, 'utf8'));

      controller.abort();
      const result = await pending;
      expect(result.termination).toBe('aborted');
      expect(await waitForPredicate(() => !isPidAlive(grandchildPid), 10_000)).toBe(
        true,
      );
    } finally {
      controller.abort();
      // The primary assertions above already failed the test if the run went
      // wrong; settle the promise here so a failure path cannot leave it
      // dangling or surface an unhandled rejection during cleanup.
      await pending.catch(() => {
        // Cleanup only; the run's failure was already reported.
      });
      if (grandchildPid > 0) {
        try {
          process.kill(grandchildPid, 'SIGKILL');
        } catch {
          // Already terminated; nothing to clean up.
        }
      }
      rmSync(treeDirectory, { recursive: true, force: true });
    }
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

  it('inherits parent USER without treating it as a writable dest', async () => {
    const previous = process.env['USER'];
    process.env['USER'] = 'kavrix-inherited-identity';
    try {
      const result = await runSecureCommand(
        nodeRequest('process.stdout.write(process.env.USER ?? "")', {
          inheritEnvironment: ['USER'],
        }),
      );
      expect(capturedText(result.stdout)).toBe('kavrix-inherited-identity');
    } finally {
      if (previous === undefined) {
        Reflect.deleteProperty(process.env, 'USER');
      } else {
        process.env['USER'] = previous;
      }
    }
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

  it('classifies a missing executable as EXECUTION_FAILED, not authorization denied', async () => {
    const request: SecureRunRequest = {
      executable: `${workingDirectory}/does-not-exist-kavrix-runner`,
      cwd: workingDirectory,
    };
    await expectRunnerError(request, 'RUNNER_SPAWN_FAILED');
    await expectRunnerError(
      { ...request, output: { mode: 'inherit' } },
      'RUNNER_SPAWN_FAILED',
    );

    expect(RUNNER_SPAWN_FAILED_CLI_ERROR_CODE).toBe('EXECUTION_FAILED');
    expect(cliErrorCodeForRunnerError('RUNNER_SPAWN_FAILED')).toBe(
      RUNNER_SPAWN_FAILED_CLI_ERROR_CODE,
    );
    expect(cliErrorCodeForRunnerError('RUNNER_SPAWN_FAILED')).not.toBe(
      'AUTHORIZATION_DENIED',
    );
    expect(exitCodeForCliError(cliErrorCodeForRunnerError('RUNNER_SPAWN_FAILED'))).toBe(
      18,
    );
    expect(exitCodeForCliError('AUTHORIZATION_DENIED')).toBe(12);
  });

  it('inherits parent streams in inherit mode and preserves child exit codes', async () => {
    const canary = 'inherit-mode-secret-canary-2c9f';
    const result = await runSecureCommand(
      nodeRequest('process.stdout.write("ran"); process.exit(5)', {
        output: { mode: 'inherit' },
        arguments: [
          '-e',
          'process.stdout.write("ran"); process.exit(5)',
          'positional-arg',
        ],
        environment: [secret('KAVRIX_INHERIT_CANARY', canary)],
      }),
    );

    expect(result).toMatchObject({ exitCode: 5, termination: 'exit' });
    expect(result.stdout).toBeUndefined();
    expect(result.stderr).toBeUndefined();
    expect(result.outputTruncated).toBe(false);
  });

  it('still refuses secrets in arguments in inherit mode', async () => {
    const canary = 'inherit-argv-canary';
    await expectRunnerError(
      nodeRequest('process.exit(0)', {
        output: { mode: 'inherit' },
        arguments: ['-e', 'process.exit(0)', `--token=${canary}`],
        environment: [secret('KAVRIX_INHERIT_ARGV', canary)],
      }),
      'RUNNER_SECRET_IN_ARGUMENTS',
      canary,
    );
  });

  it('reports timeout and signal terminations without captured buffers in inherit mode', async () => {
    const result = await runSecureCommand(
      nodeRequest('setInterval(() => {}, 1_000)', {
        output: { mode: 'inherit' },
        timeoutMs: 40,
        terminationGraceMs: 20,
      }),
    );

    expect(result.termination).toBe('timeout');
    expect(result.stdout).toBeUndefined();
    expect(result.stderr).toBeUndefined();
  });
});

describe('runner setup lifecycle', () => {
  it.each(['capture', 'pipe', 'inherit'] as const)(
    'does not spawn after cancellation during %s setup',
    async (mode) => {
      const controller = new AbortController();
      let spawned = false;
      const pending = runSecureCommand(
        nodeRequest('process.exit(0)', {
          signal: controller.signal,
          output: { mode },
          onSpawn() {
            spawned = true;
          },
        }),
      );
      controller.abort();

      await expect(pending).rejects.toMatchObject({ code: 'RUNNER_ABORTED' });
      expect(spawned).toBe(false);
    },
  );

  it.each(['capture', 'pipe', 'inherit'] as const)(
    'reaps the child and sanitizes a throwing observer in %s mode',
    async (mode) => {
      const canary = 'observer-error-private-canary';
      let child: ChildProcess | undefined;
      let closed = false;
      let close: Promise<void> | undefined;
      try {
        await expectRunnerError(
          nodeRequest('setTimeout(() => {}, 2000)', {
            output: { mode },
            onSpawn(spawnedChild) {
              child = spawnedChild;
              close = new Promise<void>((resolve) => {
                spawnedChild.once('close', () => {
                  closed = true;
                  resolve();
                });
              });
              throw new Error(canary);
            },
          }),
          'RUNNER_SPAWN_FAILED',
          canary,
        );
        expect(closed).toBe(true);
      } finally {
        child?.kill('SIGKILL');
        await close;
      }
    },
  );
});

describe('request and environment validation', () => {
  it('publishes identity names as inheritable reserved destinations', () => {
    expect(INHERITABLE_ENVIRONMENT_NAMES).toEqual(
      expect.arrayContaining(['PATH', 'HOME', 'USER', 'USERNAME', 'LOGNAME']),
    );
    for (const name of ['USER', 'USERNAME', 'LOGNAME', 'PATH', 'HOME'] as const) {
      expect(RESERVED_ENVIRONMENT_NAMES).toContain(name);
      expect(isReservedEnvironmentName(name)).toBe(true);
      expect(isReservedEnvironmentName(name.toLowerCase())).toBe(true);
    }
  });

  it.each([
    ['invalid name', 'BAD-NAME'],
    ['reserved loader name', 'NODE_OPTIONS'],
    ['reserved identity USER', 'USER'],
    ['reserved identity USERNAME', 'USERNAME'],
    ['reserved identity LOGNAME', 'LOGNAME'],
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
    { output: { mode: 'unknown' } as unknown as RunnerOutputPolicy },
    { input: 'stdout' as unknown as 'ignore' },
    { cwd: 42 as unknown as string },
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

    // Sized from the live aggregate budget so this case stays above the cap
    // if the constant moves; fixed-width names keep every entry the same
    // size, matching how environmentBytes counts name=value\0.
    const entryValue = 'x'.repeat(12 * 1_024);
    const entryBytes = 'KAVRIX_AGGREGATE_000'.length + 1 + entryValue.length + 1;
    const entryCount = Math.ceil(
      (RUNNER_LIMITS.maxEnvironmentTotalBytes + 1) / entryBytes,
    );
    expect(entryCount).toBeLessThanOrEqual(RUNNER_LIMITS.maxEnvironmentEntries);
    const mappings = Array.from(
      { length: entryCount },
      (_, index) =>
        [
          `KAVRIX_AGGREGATE_${String(index).padStart(3, '0')}`,
          { kind: 'text', value: entryValue },
        ] as const satisfies EnvironmentMapping,
    );
    await expectRunnerError(
      nodeRequest('process.exit(0)', { environment: mappings }),
      'RUNNER_ENVIRONMENT_REJECTED',
    );
  });

  it('accepts an inherited PATH between the secret cap and the inherited cap', async () => {
    const inheritedPath = 'x'.repeat(20 * 1_024);
    await withParentVariable('PATH', inheritedPath, async () => {
      const result = await runSecureCommand(
        nodeRequest('process.stdout.write(String(process.env.PATH.length))', {
          inheritEnvironment: ['PATH'],
        }),
      );

      expect(capturedText(result.stdout)).toBe(String(inheritedPath.length));
    });
  });

  it('never classifies an inherited value as a secret while accepting the platform-sized cap', () => {
    const inheritedPath = 'x'.repeat(20 * 1_024);
    const accepted = prepareEnvironment([], ['PATH'], { PATH: inheritedPath });
    try {
      expect(accepted.childEnvironment['PATH']).toBe(inheritedPath);
      expect(accepted.secretValues).toEqual([]);
      expect(accepted.secretBuffers).toEqual([]);
    } finally {
      accepted.clear();
    }

    // Above the inherited (platform-sized) cap inheritance still fails even
    // though the same value would fit the raised aggregate budget. The value
    // is injected through the parentEnvironment port because the OS itself
    // cannot hold a 32 KiB+ variable on Windows for an end-to-end run.
    expectEnvironmentRejected(() =>
      prepareEnvironment([], ['PATH'], { PATH: 'x'.repeat(32 * 1_024 + 1) }),
    );
  });

  it('still rejects a mapped secret above the tighter secret cap', async () => {
    await expectRunnerError(
      nodeRequest('process.exit(0)', {
        inheritEnvironment: ['PATH'],
        environment: [secret('KAVRIX_SECRET_OVER_CAP', 'x'.repeat(16 * 1_024 + 1))],
      }),
      'RUNNER_ENVIRONMENT_REJECTED',
    );
    expectEnvironmentRejected(() =>
      prepareEnvironment(
        [secret('KAVRIX_SECRET_OVER_CAP', 'x'.repeat(16 * 1_024 + 1))],
        ['PATH'],
        { PATH: 'x'.repeat(20 * 1_024) },
      ),
    );
  });
});
