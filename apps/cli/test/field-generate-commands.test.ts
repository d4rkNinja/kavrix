import { Readable, Writable } from 'node:stream';

import { PermissionError, SyncConflictError } from '@kavrix/core';
import { groupIdSchema, itemIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;
type SetFieldPort = NonNullable<CliUseCasePorts['setField']>;
type SetFieldRequest = Parameters<SetFieldPort>[0];
type FieldMutationReceipt = Awaited<ReturnType<SetFieldPort>>;

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

function mutationReceipt(
  overrides: Partial<FieldMutationReceipt> = {},
): FieldMutationReceipt {
  return {
    vaultId: vaultIdSchema.parse('vault.1'),
    groupId: groupIdSchema.parse('group.1'),
    credentialId: itemIdSchema.parse('item.101'),
    title: 'Primary DB',
    fieldKey: 'api-token',
    fieldLabel: 'Api token',
    fieldType: 'secret',
    sensitive: true,
    created: true,
    previousRevision: 4,
    revision: 5,
    ...overrides,
  };
}

/**
 * Captures the exact bytes the write path received.
 *
 * The generated value exists only inside the command, so the port is the single
 * observation point that can prove both what was stored and that the same value
 * never reached a rendered stream.
 */
function capturingSetField(overrides: Partial<FieldMutationReceipt> = {}): Readonly<{
  port: SetFieldPort;
  calls: () => readonly SetFieldRequest[];
  stored: () => string;
}> {
  const calls: SetFieldRequest[] = [];
  const stored: string[] = [];
  const port = vi.fn((request: SetFieldRequest) => {
    // The write path zeroizes the request bytes, so decode before returning.
    stored.push(new TextDecoder().decode(request.value));
    calls.push(request);
    return Promise.resolve(mutationReceipt(overrides));
  });
  return {
    port,
    calls: () => calls,
    stored: () => {
      const value = stored[0];
      if (value === undefined) throw new Error('No value was stored');
      return value;
    },
  };
}

const BASE_ARGUMENTS = ['field', 'generate', 'Engineering', 'Primary DB', 'api-token'];

/** Built from code points so no raw control byte is stored in this file. */
const ESCAPE = String.fromCharCode(0x1b);
const BELL = String.fromCharCode(0x07);
const REPLACEMENT = String.fromCharCode(0xff_fd);

/** The symbol class the password generator draws from. */
const SYMBOL = /[!@#$%^&*()\-_=+[\]{}:,.?]/u;

describe('CLI field generate command', () => {
  it('generates a policy-compliant password and stores it without printing it', async () => {
    const setField = capturingSetField();

    const result = await execute([...BASE_ARGUMENTS, '--create'], {
      setField: setField.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    const calls = setField.calls();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.groupQuery).toBe('Engineering');
    expect(calls[0]?.credentialQuery).toBe('Primary DB');
    expect(calls[0]?.fieldKey).toBe('api-token');
    expect(calls[0]?.create).toBe(true);
    expect(calls[0]?.ifRevision).toBeUndefined();

    const stored = setField.stored();
    expect(stored).toHaveLength(24);
    expect(stored).toMatch(/[a-z]/u);
    expect(stored).toMatch(/[A-Z]/u);
    expect(stored).toMatch(/[0-9]/u);
    expect(stored).toMatch(SYMBOL);

    expect(result.stdout).toContain('Field "api-token" generated');
    expect(result.stdout).toContain('Generated: password (24 characters)');
    expect(result.stdout).toContain('Revision: 4 -> 5');
    expect(result.stdout).not.toContain(stored);
    expect(result.stderr).not.toContain(stored);
  });

  it('honours an explicit character-class policy', async () => {
    const setField = capturingSetField();

    const result = await execute(
      [
        ...BASE_ARGUMENTS,
        '--length',
        '64',
        '--symbols-min',
        '0',
        '--uppercase-min',
        '0',
        '--exclude',
        'abc',
      ],
      { setField: setField.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    const stored = setField.stored();
    expect(stored).toHaveLength(64);
    expect(stored).toMatch(/^[0-9d-z]+$/u);
    expect(result.stdout).not.toContain(stored);
  });

  it('generates a passphrase with the requested shape', async () => {
    const setField = capturingSetField();

    const result = await execute(
      [
        ...BASE_ARGUMENTS,
        '--passphrase',
        '--words',
        '6',
        '--separator',
        '_',
        '--capitalize',
        '--digit',
      ],
      { setField: setField.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    const stored = setField.stored();
    const tokens = stored.split('_');
    // Six words plus the appended digit token.
    expect(tokens).toHaveLength(7);
    expect(tokens.at(-1)).toMatch(/^[0-9]$/u);
    expect(tokens.slice(0, 6).filter((word) => /^[A-Z]/u.test(word))).toHaveLength(1);
    expect(result.stdout).toContain('Generated: passphrase (6 words)');
    expect(result.stdout).not.toContain(stored);
  });

  it('renders a structured receipt that carries no generated value', async () => {
    const setField = capturingSetField();

    const result = await execute([...BASE_ARGUMENTS, '--json'], {
      setField: setField.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    const stored = setField.stored();
    const payload = JSON.parse(result.stdout) as Readonly<{
      action: string;
      fieldKey: string;
      generation: Readonly<{ kind: string; length: number }>;
    }>;
    expect(payload.action).toBe('generate');
    expect(payload.fieldKey).toBe('api-token');
    expect(payload.generation).toEqual({ kind: 'password', length: 24 });
    expect(result.stdout).not.toContain(stored);
  });

  it('forwards an expected revision so a moved credential is refused', async () => {
    const setField = capturingSetField();

    const result = await execute([...BASE_ARGUMENTS, '--if-revision', '4'], {
      setField: setField.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(setField.calls()[0]?.ifRevision).toBe(4);
  });

  it.each([
    ['a length below the supported minimum', ['--length', '7']],
    ['a length above the supported maximum', ['--length', '1025']],
    ['a non-numeric length', ['--length', '24x']],
    ['a word count below the supported minimum', ['--passphrase', '--words', '5']],
    ['a word count above the supported maximum', ['--passphrase', '--words', '25']],
    ['an unsupported separator', ['--passphrase', '--separator', '#']],
    ['repeated exclusion characters', ['--exclude', 'aa']],
    ['a non-ASCII exclusion set', ['--exclude', 'é']],
    ['class minimums that exceed the length', ['--length', '8', '--digits-min', '9']],
    ['an exclusion that empties a required class', ['--exclude', '0123456789']],
  ])('rejects %s before the vault is touched', async (_description, flags) => {
    const setField = capturingSetField();

    const result = await execute([...BASE_ARGUMENTS, ...flags], {
      setField: setField.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(setField.calls()).toHaveLength(0);
  });

  it.each([
    ['a password length', ['--passphrase', '--length', '30']],
    ['a class minimum', ['--passphrase', '--digits-min', '2']],
    ['a character exclusion', ['--passphrase', '--exclude', 'abc']],
  ])('refuses passphrase generation combined with %s', async (_description, flags) => {
    const setField = capturingSetField();

    const result = await execute([...BASE_ARGUMENTS, ...flags], {
      setField: setField.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(setField.calls()).toHaveLength(0);
  });

  it.each([
    ['a word count', ['--words', '10']],
    ['a separator', ['--separator', '_']],
    ['a capitalization request', ['--capitalize']],
    ['an appended digit', ['--digit']],
    ['a word exclusion', ['--exclude-word', 'abacus']],
  ])('refuses password generation combined with %s', async (_description, flags) => {
    const setField = capturingSetField();

    const result = await execute([...BASE_ARGUMENTS, ...flags], {
      setField: setField.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(setField.calls()).toHaveLength(0);
  });

  it('refuses a word exclusion that is not a canonical list entry', async () => {
    const setField = capturingSetField();

    const result = await execute(
      [...BASE_ARGUMENTS, '--passphrase', '--exclude-word', 'not-a-list-word'],
      { setField: setField.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(setField.calls()).toHaveLength(0);
  });

  it('reports a conflicting revision without emitting the generated value', async () => {
    const attempted: string[] = [];
    const setField = vi.fn((request: SetFieldRequest) => {
      attempted.push(new TextDecoder().decode(request.value));
      return Promise.reject(new SyncConflictError());
    });

    const result = await execute([...BASE_ARGUMENTS, '--if-revision', '3'], {
      setField,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(result.stdout).toBe('');
    const generated = attempted[0];
    expect(generated).toBeDefined();
    if (generated !== undefined) expect(result.stderr).not.toContain(generated);
  });

  it('reports a denied write without emitting the generated value', async () => {
    const attempted: string[] = [];
    const setField = vi.fn((request: SetFieldRequest) => {
      attempted.push(new TextDecoder().decode(request.value));
      return Promise.reject(new PermissionError());
    });

    const result = await execute([...BASE_ARGUMENTS], { setField });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.failure);
    expect(result.stdout).toBe('');
    const generated = attempted[0];
    expect(generated).toBeDefined();
    if (generated !== undefined) expect(result.stderr).not.toContain(generated);
  });

  it('refuses a redirected reveal before generating or storing anything', async () => {
    const setField = capturingSetField();
    const reveal = vi.fn(() => Promise.resolve({ value: 'never' }));

    const result = await execute([...BASE_ARGUMENTS, '--reveal'], {
      setField: setField.port,
      reveal,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(setField.calls()).toHaveLength(0);
    expect(reveal).not.toHaveBeenCalled();
  });

  it('reveals through the guarded read path and keeps the receipt off stdout', async () => {
    const setField = capturingSetField();
    let revealed: string | undefined;
    const reveal = vi.fn(() => {
      revealed = setField.stored();
      return Promise.resolve({ value: revealed });
    });

    const result = await execute([...BASE_ARGUMENTS, '--reveal', '--stdout'], {
      setField: setField.port,
      reveal,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(reveal).toHaveBeenCalledWith('Engineering', 'Primary DB', 'api-token', {});
    expect(revealed).toBeDefined();
    expect(result.stdout).toBe(`${setField.stored()}\n`);
    expect(result.stderr).toContain('Field "api-token" generated');
    expect(result.stderr).not.toContain(setField.stored());
  });

  it('allows an interactive reveal without an explicit acknowledgement', async () => {
    const setField = capturingSetField();
    const reveal = vi.fn(() => Promise.resolve({ value: setField.stored() }));

    const result = await execute(
      [...BASE_ARGUMENTS, '--reveal'],
      { setField: setField.port, reveal },
      true,
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toBe(`${setField.stored()}\n`);
  });

  it('copies through the guarded clipboard path without printing the value', async () => {
    const setField = capturingSetField();
    const copy = vi.fn(() =>
      Promise.resolve({ label: 'Api token', clearAfterSeconds: 30 }),
    );

    const result = await execute([...BASE_ARGUMENTS, '--copy'], {
      setField: setField.port,
      copy,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(copy).toHaveBeenCalledWith('Engineering', 'Primary DB', 'api-token', {});
    expect(result.stdout).toContain('Field "api-token" generated');
    expect(result.stdout).toContain('Copied Api token');
    expect(result.stdout).not.toContain(setField.stored());
  });

  it('sanitizes terminal control sequences in the rendered receipt', async () => {
    const setField = capturingSetField({
      fieldLabel: `Api${ESCAPE}[31m token${BELL}`,
    });

    const result = await execute([...BASE_ARGUMENTS], { setField: setField.port });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).not.toContain(ESCAPE);
    expect(result.stdout).not.toContain(BELL);
    expect(result.stdout).toContain(REPLACEMENT);
  });

  it('reports the command as unavailable when no vault adapter is configured', async () => {
    // No `setField` port is configured, so the command falls through to the
    // production path, which has no vault to open in this harness.
    const result = await execute([...BASE_ARGUMENTS]);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('field generate is unavailable');
    expect(result.stdout).toBe('');
  });

  it('keeps the sibling field definition command reachable', async () => {
    const updateField = vi.fn(() =>
      Promise.resolve(mutationReceipt({ created: false, fieldLabel: 'API token' })),
    );

    const result = await execute(
      [
        'field',
        'update',
        'Engineering',
        'Primary DB',
        'api-token',
        '--label',
        'API token',
      ],
      { updateField },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('Field "api-token" updated');
  });
});
