import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough, Readable, Writable } from 'node:stream';

import { AuthenticationError, formatPortableKey, zeroize } from '@kavrix/crypto';
import { readPortableKeyFile } from '@kavrix/key-files';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  MIN_PROTECTED_KEY_FILE_PASSPHRASE_BYTES,
  runPublicCli,
  type CliRuntime,
} from '../src/index.js';
import {
  setWindowsUserOnlyAcl,
  verifyWindowsUserOnlyAcl,
} from '../../../packages/key-files/src/windows-acl.js';

const PASSPHRASE = 'correct horse battery staple 2026';
const OTHER_PASSPHRASE = 'different horse battery staple 2026';
const UNBOUND = { kind: 'unbound' } as const;
const UNPROTECTED = { kind: 'unprotected' } as const;

let testDirectory = '';

beforeEach(async () => {
  testDirectory = await mkdtemp(join(tmpdir(), 'kavrix-cli-key-create-'));
  if (process.platform === 'win32') await setWindowsUserOnlyAcl(testDirectory);
});

afterEach(async () => {
  await rm(testDirectory, { recursive: true, force: true });
});

describe('public portable key-file creation', () => {
  it('creates an unbound version-one file without displaying its key', async () => {
    const path = target('unprotected.cvk');
    const result = await executePublic(['key', 'create', '--file', path]);
    const parsed = await readPortableKeyFile(path, UNPROTECTED, UNBOUND);
    try {
      const formattedKey = formatPortableKey(parsed.key);
      const file = await readFile(path, 'ascii');

      expect(result).toEqual({
        exitCode: CLI_EXIT_CODES.success,
        stdout: 'Portable key file created.\n',
        stderr: '',
      });
      expect(parsed).toMatchObject({ kind: 'unbound', protected: false });
      expect(file).toContain('Version: 1');
      expect(file).toContain('Binding: unbound');
      expect(file).toContain(formattedKey);
      expect(`${result.stdout}${result.stderr}`).not.toContain(formattedKey);
      if (process.platform === 'win32') await verifyWindowsUserOnlyAcl(path);
    } finally {
      zeroize(parsed.key);
    }
  });

  it('refuses overwrite and leaves the winning file unchanged', async () => {
    const path = target('existing.cvk');
    const first = await executePublic(['key', 'create', '--file', path]);
    const before = await readFile(path);
    const second = await executePublic(['key', 'create', '--file', path]);
    const after = await readFile(path);

    expect(first.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(second).toEqual({
      exitCode: CLI_EXIT_CODES.failure,
      stdout: '',
      stderr:
        'Error [KEY_FILE_CREATE_FAILED]: The portable key file could not be created.\n',
    });
    expect(after).toEqual(before);
  });

  it('redacts confirmed passphrases when protected creation fails', async () => {
    const path = target('existing-protected.cvk');
    const created = await executePublic(['key', 'create', '--file', path]);
    const before = await readFile(path);
    const failed = await executePublic(
      [
        'key',
        'create',
        '--file',
        path,
        '--protect-with-passphrase',
        '--passphrase-stdin',
      ],
      { stdin: Readable.from([`${PASSPHRASE}\n${PASSPHRASE}\n`]) },
    );

    expect(created.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(failed).toEqual({
      exitCode: CLI_EXIT_CODES.failure,
      stdout: '',
      stderr:
        'Error [KEY_FILE_CREATE_FAILED]: The portable key file could not be created.\n',
    });
    expect(`${failed.stdout}${failed.stderr}`).not.toContain(PASSPHRASE);
    expect(await readFile(path)).toEqual(before);
  });

  it('creates a passphrase-protected file through two masked confirmations', async () => {
    const path = target('masked-protected.cvk');
    const input = new FakeTty();
    const pending = executePublic(
      ['key', 'create', '--file', path, '--protect-with-passphrase'],
      { stdin: input },
    );

    await waitForPrompt(input, 1);
    input.write(`${PASSPHRASE}\r`);
    await waitForPrompt(input, 2);
    input.write(`${PASSPHRASE}\r`);
    const result = await pending;

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toBe('Portable key file created.\n');
    expect(result.stderr).not.toContain(PASSPHRASE);
    expect(input.rawTransitions).toEqual([true, false, true, false]);
    await assertProtectedRoundTrip(path, result);
  });

  it('creates a protected file from exact confirmed stdin frames', async () => {
    const path = target('stdin-protected.cvk');
    const result = await executePublic(
      [
        'key',
        'create',
        '--file',
        path,
        '--protect-with-passphrase',
        '--passphrase-stdin',
      ],
      { stdin: Readable.from([`${PASSPHRASE}\n${PASSPHRASE}\n`]) },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    await assertProtectedRoundTrip(path, result);
  });

  it.each([
    ['missing confirmation', `${PASSPHRASE}\n`],
    ['mismatch', `${PASSPHRASE}\n${OTHER_PASSPHRASE}\n`],
    ['trailing frame', `${PASSPHRASE}\n${PASSPHRASE}\nextra-frame\n`],
    ['weak passphrase', 'too-short\ntoo-short\n'],
  ])('rejects invalid stdin framing: %s', async (_label, framed) => {
    const path = target('invalid-stdin.cvk');
    const result = await executePublic(
      [
        'key',
        'create',
        '--file',
        path,
        '--protect-with-passphrase',
        '--passphrase-stdin',
      ],
      { stdin: Readable.from([framed]) },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stdout).toBe('');
    await expect(readFile(path)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(`${result.stdout}${result.stderr}`).not.toContain(PASSPHRASE);
    expect(`${result.stdout}${result.stderr}`).not.toContain(OTHER_PASSPHRASE);
  });

  it('rejects passphrase stdin without protection before consuming input', async () => {
    const input = new PassThrough();
    input.end(`${PASSPHRASE}\n${PASSPHRASE}\n`);
    const result = await executePublic(
      ['key', 'create', '--file', target(), '--passphrase-stdin'],
      { stdin: input },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(input.readableLength).toBeGreaterThan(0);
  });

  it('validates hostile and oversized paths before creating a file', async () => {
    const canary = 'KEY-PATH-CONTROL-CANARY';
    for (const path of [`${canary}\n.cvk`, 'x'.repeat(32_769)]) {
      const result = await executePublic(['key', 'create', '--file', path]);
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stdout).toBe('');
      expect(result.stderr).not.toContain(canary);
    }
  });

  it('ignores secret environment variables and rejects secret argv', async () => {
    const canary = 'KEY-CREATE-PASSPHRASE-ARGV-ENV-CANARY';
    vi.stubEnv('KAVRIX_KEY_FILE_PASSPHRASE', canary);
    const argv = await executePublic([
      'key',
      'create',
      '--file',
      target('argv.cvk'),
      '--passphrase',
      canary,
    ]);
    expect(argv.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(`${argv.stdout}${argv.stderr}`).not.toContain(canary);

    const path = target('environment.cvk');
    const environment = await executePublic(['key', 'create', '--file', path]);
    const parsed = await readPortableKeyFile(path, UNPROTECTED, UNBOUND);
    try {
      expect(environment.stdout).toBe('Portable key file created.\n');
      expect(`${environment.stdout}${environment.stderr}`).not.toContain(canary);
      expect(parsed.protected).toBe(false);
    } finally {
      zeroize(parsed.key);
    }
  });

  it('enforces the documented minimum passphrase byte length', () => {
    expect(MIN_PROTECTED_KEY_FILE_PASSPHRASE_BYTES).toBe(12);
  });
});

async function assertProtectedRoundTrip(
  path: string,
  result: Readonly<{ stdout: string; stderr: string }>,
): Promise<void> {
  const passphrase = new TextEncoder().encode(PASSPHRASE);
  const wrong = new TextEncoder().encode(OTHER_PASSPHRASE);
  const parsed = await readPortableKeyFile(
    path,
    { kind: 'passphrase', passphrase },
    UNBOUND,
  );
  try {
    const file = await readFile(path, 'ascii');
    const formattedKey = formatPortableKey(parsed.key);
    expect(parsed).toMatchObject({ kind: 'unbound', protected: true });
    expect(file).toContain('Protection: argon2id+xchacha20-poly1305-ietf');
    expect(file).not.toContain(PASSPHRASE);
    expect(file).not.toContain(formattedKey);
    expect(`${result.stdout}${result.stderr}`).not.toContain(PASSPHRASE);
    expect(`${result.stdout}${result.stderr}`).not.toContain(formattedKey);
    await expect(
      readPortableKeyFile(path, { kind: 'passphrase', passphrase: wrong }, UNBOUND),
    ).rejects.toBeInstanceOf(AuthenticationError);
    if (process.platform === 'win32') await verifyWindowsUserOnlyAcl(path);
  } finally {
    zeroize(parsed.key);
    zeroize(passphrase);
    zeroize(wrong);
  }
}

type ExecuteOptions = Readonly<{ stdin?: Readable }>;

async function executePublic(
  arguments_: readonly string[],
  options: ExecuteOptions = {},
): Promise<Readonly<{ exitCode: number; stdout: string; stderr: string }>> {
  const stdout = capture();
  const stderr = capture();
  const runtime: CliRuntime = {
    stdin: options.stdin ?? Readable.from([]),
    stdout: stdout.stream,
    stderr: stderr.stream,
  };
  const exitCode = await runPublicCli(arguments_, runtime);
  return { exitCode, stdout: stdout.value(), stderr: stderr.value() };
}

async function waitForPrompt(input: FakeTty, count: number): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (input.promptCount() >= count) return;
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
  }
  throw new Error('Masked prompt did not become ready.');
}

class FakeTty extends PassThrough {
  public readonly isTTY = true;
  public isRaw = false;
  public readonly rawTransitions: boolean[] = [];
  #promptCounter = 0;

  public setRawMode(enabled: boolean): void {
    this.isRaw = enabled;
    this.rawTransitions.push(enabled);
    if (enabled) this.#promptCounter += 1;
  }

  public promptCount(): number {
    return this.#promptCounter;
  }
}

type CapturedWritable = Readonly<{ stream: Writable; value: () => string }>;

function capture(): CapturedWritable {
  let content = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      content += Buffer.from(chunk).toString('utf8');
      callback();
    },
  });
  return { stream, value: () => content };
}

function target(name = 'portable-key.cvk'): string {
  return join(testDirectory, name);
}
