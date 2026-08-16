import { describe, expect, it, vi } from 'vitest';
import { Readable, Writable } from 'node:stream';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliRecoveryCodeListResult,
  type CliRecoveryCodeRevealResult,
  type CliRecoveryCodeUseResult,
  type CliUseCasePorts,
} from '../src/index.js';
import { groupIdSchema, itemIdSchema } from '@kavrix/schemas';
import { AmbiguousNameError, PermissionError, ValidationError } from '@kavrix/core';

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

const SAMPLE_CODE = 'aaaa-1111-bbbb';

function listResult(
  overrides: Partial<CliRecoveryCodeListResult> = {},
): CliRecoveryCodeListResult {
  return {
    groupName: 'Engineering',
    credentialTitle: 'Identity Provider',
    fieldLabel: 'Recovery codes',
    inventory: { total: 3, available: 2, used: 1 },
    codes: [
      { id: 'element.one', status: 'available', usedAt: null },
      { id: 'element.two', status: 'available', usedAt: null },
      {
        id: 'element.three',
        status: 'used',
        usedAt: '2026-08-01T00:00:00.000Z',
      },
    ],
    ...overrides,
  };
}

function useResult(
  overrides: Partial<CliRecoveryCodeUseResult> = {},
): CliRecoveryCodeUseResult {
  return {
    groupId: groupIdSchema.parse('group.engineering'),
    credentialId: itemIdSchema.parse('item.identity-provider'),
    fieldLabel: 'Recovery codes',
    codeId: 'element.one',
    usedAt: '2026-08-16T00:00:00.000Z',
    previousRevision: 4,
    revision: 5,
    inventory: { total: 3, available: 1, used: 2 },
    ...overrides,
  };
}

describe('CLI recovery commands', () => {
  it('lists codes by identifier and lifecycle without printing any code value', async () => {
    const listRecoveryCodes = vi.fn(() => Promise.resolve(listResult()));

    const text = await execute(
      ['recovery', 'list', 'Engineering', 'Identity Provider', 'Recovery codes'],
      { listRecoveryCodes },
    );
    expect(text.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(listRecoveryCodes).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Identity Provider',
      fieldQuery: 'Recovery codes',
    });
    expect(text.stdout).toContain('Available: 2 of 3 (used: 1)');
    expect(text.stdout).toContain('- element.one: available');
    expect(text.stdout).toContain('- element.three: used at 2026-08-01T00:00:00.000Z');
    expect(text.stdout).toContain('Values stay masked.');
    expect(text.stdout).not.toContain(SAMPLE_CODE);

    const json = await execute(
      [
        'recovery',
        'list',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--json',
      ],
      { listRecoveryCodes },
    );
    expect(json.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(json.stdout) as CliRecoveryCodeListResult;
    expect(parsed.inventory.available).toBe(2);
    expect(parsed.codes.map((code) => code.id)).toStrictEqual([
      'element.one',
      'element.two',
      'element.three',
    ]);
    // The projection carries no code material in either output mode.
    expect(JSON.stringify(parsed)).not.toContain(SAMPLE_CODE);
  });

  it('marks one code used by identifier and never by position', async () => {
    const useRecoveryCode = vi.fn(() => Promise.resolve(useResult()));

    const result = await execute(
      [
        'recovery',
        'use',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element.one',
      ],
      { useRecoveryCode },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(useRecoveryCode).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Identity Provider',
      fieldQuery: 'Recovery codes',
      code: 'element.one',
    });
    expect(result.stdout).toContain('Recovery code "element.one" marked used.');
    expect(result.stdout).toContain('Remaining: 1 of 3');
    expect(result.stdout).toContain('Revision: 4 -> 5');
    expect(result.stdout).not.toContain(SAMPLE_CODE);
  });

  it('forwards an optimistic revision expectation to the consuming write', async () => {
    const useRecoveryCode = vi.fn(() => Promise.resolve(useResult()));

    const result = await execute(
      [
        'recovery',
        'use',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element.one',
        '--if-revision',
        '4',
        '--json',
      ],
      { useRecoveryCode },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(useRecoveryCode).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Identity Provider',
      fieldQuery: 'Recovery codes',
      code: 'element.one',
      ifRevision: 4,
    });
    const parsed = JSON.parse(result.stdout) as CliRecoveryCodeUseResult;
    expect(parsed.previousRevision).toBe(4);
    expect(parsed.revision).toBe(5);
  });

  it('requires a --code selector rather than defaulting to the first entry', async () => {
    const useRecoveryCode = vi.fn(() => Promise.resolve(useResult()));

    const result = await execute(
      ['recovery', 'use', 'Engineering', 'Identity Provider', 'Recovery codes'],
      { useRecoveryCode },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('A recovery code is required.');
    expect(useRecoveryCode).not.toHaveBeenCalled();
  });

  it('rejects a malformed selector as usage before any vault work happens', async () => {
    const useRecoveryCode = vi.fn(() => Promise.resolve(useResult()));

    for (const malformed of [
      '-leading-dash',
      'has space',
      'semi;colon',
      'a'.repeat(129),
    ]) {
      const result = await execute(
        [
          'recovery',
          'use',
          'Engineering',
          'Identity Provider',
          'Recovery codes',
          '--code',
          malformed,
        ],
        { useRecoveryCode },
      );
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(useRecoveryCode).not.toHaveBeenCalled();
    }
  });

  it('reports an ambiguous identifier prefix as ambiguous rather than guessing', async () => {
    const useRecoveryCode = vi.fn(() =>
      Promise.reject(new AmbiguousNameError(['element.one', 'element.two'])),
    );

    const result = await execute(
      [
        'recovery',
        'use',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element',
      ],
      { useRecoveryCode },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.ambiguous);
    expect(useRecoveryCode).toHaveBeenCalledTimes(1);
  });

  it('refuses a code that is already used instead of restamping it', async () => {
    const useRecoveryCode = vi.fn(() =>
      Promise.reject(new ValidationError('That recovery code has already been used.')),
    );

    const result = await execute(
      [
        'recovery',
        'use',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element.three',
      ],
      { useRecoveryCode },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain('already been used');
  });

  it('denies a revealed code on a redirected stream unless --stdout is explicit', async () => {
    const revealRecoveryCode = vi.fn(() =>
      Promise.resolve<CliRecoveryCodeRevealResult>({
        codeId: 'element.one',
        value: SAMPLE_CODE,
        receipt: null,
      }),
    );

    const denied = await execute(
      [
        'recovery',
        'reveal',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element.one',
      ],
      { revealRecoveryCode },
    );
    expect(denied.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(denied.stderr).toContain('Redirection is denied by default');
    expect(denied.stdout).not.toContain(SAMPLE_CODE);
    expect(revealRecoveryCode).not.toHaveBeenCalled();

    const allowed = await execute(
      [
        'recovery',
        'reveal',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element.one',
        '--stdout',
      ],
      { revealRecoveryCode },
    );
    expect(allowed.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(allowed.stdout).toBe(`${SAMPLE_CODE}\n`);
    expect(revealRecoveryCode).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Identity Provider',
      fieldQuery: 'Recovery codes',
      code: 'element.one',
    });
  });

  it('keeps the consumed-code receipt off the stream that carries the value', async () => {
    const revealRecoveryCode = vi.fn(() =>
      Promise.resolve<CliRecoveryCodeRevealResult>({
        codeId: 'element.one',
        value: SAMPLE_CODE,
        receipt: useResult(),
      }),
    );

    const result = await execute(
      [
        'recovery',
        'reveal',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element.one',
        '--use',
        '--stdout',
      ],
      { revealRecoveryCode },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(revealRecoveryCode).toHaveBeenCalledWith({
      groupQuery: 'Engineering',
      credentialQuery: 'Identity Provider',
      fieldQuery: 'Recovery codes',
      code: 'element.one',
      use: true,
    });
    // Only the code reaches stdout, so command substitution captures it alone.
    expect(result.stdout).toBe(`${SAMPLE_CODE}\n`);
    expect(result.stderr).toContain('Recovery code "element.one" marked used.');
    expect(result.stderr).not.toContain(SAMPLE_CODE);
  });

  it('reveals to an interactive terminal without requiring --stdout', async () => {
    const revealRecoveryCode = vi.fn(() =>
      Promise.resolve<CliRecoveryCodeRevealResult>({
        codeId: 'element.one',
        value: SAMPLE_CODE,
        receipt: null,
      }),
    );

    const result = await execute(
      [
        'recovery',
        'reveal',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element.one',
      ],
      { revealRecoveryCode },
      true,
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toBe(`${SAMPLE_CODE}\n`);
  });

  it('surfaces a reveal-policy refusal as a failure and prints nothing', async () => {
    const revealRecoveryCode = vi.fn(() => Promise.reject(new PermissionError()));

    const result = await execute(
      [
        'recovery',
        'reveal',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element.one',
        '--stdout',
      ],
      { revealRecoveryCode },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(result.stdout).toBe('');
  });

  it('copies one code by identifier and reports only masked receipt metadata', async () => {
    const copy = vi.fn(() =>
      Promise.resolve({ label: 'Recovery codes', clearAfterSeconds: 30 }),
    );

    const result = await execute(
      [
        'recovery',
        'copy',
        'Engineering',
        'Identity Provider',
        'Recovery codes',
        '--code',
        'element.two',
      ],
      { copy },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(copy).toHaveBeenCalledWith(
      'Engineering',
      'Identity Provider',
      'Recovery codes',
      { elementId: 'element.two' },
    );
    expect(result.stdout).not.toContain(SAMPLE_CODE);
  });

  it('sanitizes hostile terminal sequences in recovery output', async () => {
    const listRecoveryCodes = vi.fn(() =>
      Promise.resolve(
        listResult({
          credentialTitle: 'Identity\u001b[31mProvider\u001b[0m',
          codes: [
            { id: 'element.\u001b[31mone\u001b[0m', status: 'available', usedAt: null },
          ],
        }),
      ),
    );

    const result = await execute(
      ['recovery', 'list', 'Engineering', 'Identity Provider', 'Recovery codes'],
      { listRecoveryCodes },
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).not.toContain('\u001b[');
    expect(result.stdout).toContain('Identity\uFFFDProvider\uFFFD');
    expect(result.stdout).toContain('element.\uFFFDone\uFFFD');
  });

  it('fails closed when required arguments are missing', async () => {
    for (const command of ['list', 'use', 'reveal', 'copy']) {
      const result = await execute(['recovery', command, 'Engineering']);
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stderr).toContain('Invalid command usage');
    }
  });

  it('reports an unconfigured recovery adapter as unavailable rather than crashing', async () => {
    const result = await execute([
      'recovery',
      'list',
      'Engineering',
      'Identity Provider',
      'Recovery codes',
    ]);
    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('recovery list is unavailable');
  });
});
