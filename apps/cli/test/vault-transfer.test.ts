import { readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { sealVaultExportArchive, zeroize } from '@kavrix/crypto';
import { writeSecureStreamFile } from '@kavrix/key-files';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { generationRequestFromOptions } from '../src/generate-command-impl.js';

const ARCHIVE_PASSPHRASE = 'archive passphrase for tests';
const EXPORT_CANARY = 'export-roundtrip-canary-4b7d';

let container: ExecutionFixture;
let directory: string;

beforeAll(async () => {
  container = await createExecutionFixture({
    'prod/DATABASE_URL': EXPORT_CANARY,
    'prod/API_KEY': 'prod-api-key-value',
    'dev/API_KEY': 'dev-api-key-value',
  });
  directory = await mkdtemp(join(tmpdir(), 'kavrix-transfer-'));
});

afterAll(async () => {
  await destroyFixture(container);
  await rm(directory, { force: true, recursive: true });
});

function routing(): readonly string[] {
  return [...container.routingArgs, '--passphrase-stdin'];
}

/** Publishes test bytes through the owner-only writer the CLI requires on read. */
async function writeProtected(path: string, text: string): Promise<void> {
  const source = async function* (): AsyncIterable<Uint8Array> {
    await Promise.resolve();
    yield new TextEncoder().encode(text);
  };
  await writeSecureStreamFile(path, source(), 1024 * 1024);
}

function frames(...values: readonly string[]): string {
  return values.map((value) => `${value}\n`).join('');
}

async function reveal(name: string): Promise<string> {
  const get = await runCli(
    ['get', name, '--reveal', '--json', ...routing()],
    frames(EXEC_PASSPHRASE),
  );
  expect(get.exitCode).toBe(0);
  return (JSON.parse(get.stdout) as { value: string }).value;
}

describe('kavrix export and import archive', () => {
  it('exports a prefix, keeps values out of the archive, and imports under a new prefix', async () => {
    const file = join(directory, 'prod.kavrix-export');
    const exported = await runCli(
      ['export', '--file', file, '--prefix', 'prod/', '--json', ...routing()],
      frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE, ARCHIVE_PASSPHRASE),
    );
    expect(exported.exitCode).toBe(0);
    const envelope = JSON.parse(exported.stdout) as {
      exported: number;
      names: string[];
    };
    expect(envelope.exported).toBe(2);
    expect(envelope.names).toEqual(['prod/API_KEY', 'prod/DATABASE_URL']);
    expect(exported.stdout + exported.stderr).not.toContain(EXPORT_CANARY);

    const archiveText = await readFile(file, 'utf8');
    expect(archiveText).not.toContain(EXPORT_CANARY);
    expect(archiveText).not.toContain('DATABASE_URL');
    expect(JSON.parse(archiveText)).toMatchObject({
      format: 'kavrix-vault-export',
      entryCount: 2,
    });

    const imported = await runCli(
      [
        'import',
        'archive',
        '--file',
        file,
        '--prefix',
        'copy/',
        '--json',
        ...routing(),
      ],
      frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE),
    );
    expect(imported.exitCode).toBe(0);
    expect(JSON.parse(imported.stdout)).toMatchObject({
      imported: 2,
      names: ['copy/prod/API_KEY', 'copy/prod/DATABASE_URL'],
    });
    expect(imported.stdout + imported.stderr).not.toContain(EXPORT_CANARY);
    expect(await reveal('copy/prod/DATABASE_URL')).toBe(EXPORT_CANARY);
    expect(await reveal('dev/API_KEY')).toBe('dev-api-key-value');

    const conflict = await runCli(
      [
        'import',
        'archive',
        '--file',
        file,
        '--prefix',
        'copy/',
        '--json',
        ...routing(),
      ],
      frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE),
    );
    expect(conflict.exitCode).toBe(1);
    expect(conflict.stderr).toContain('--overwrite');

    const overwrite = await runCli(
      [
        'import',
        'archive',
        '--file',
        file,
        '--prefix',
        'copy/',
        '--overwrite',
        '--json',
        ...routing(),
      ],
      frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE),
    );
    expect(overwrite.exitCode).toBe(0);
  });

  it('refuses to replace an archive without --overwrite', async () => {
    const file = join(directory, 'twice.kavrix-export');
    const args = ['export', '--file', file, '--json', ...routing()];
    const input = frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE, ARCHIVE_PASSPHRASE);
    expect((await runCli(args, input)).exitCode).toBe(0);
    const again = await runCli(args, input);
    expect(again.exitCode).toBe(1);
    expect(again.stderr).toContain('--overwrite');
    expect((await runCli([...args, '--overwrite'], input)).exitCode).toBe(0);
  });

  it('rejects mismatched export passphrases and short ones', async () => {
    const file = join(directory, 'mismatch.kavrix-export');
    const mismatch = await runCli(
      ['export', '--file', file, '--json', ...routing()],
      frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE, `${ARCHIVE_PASSPHRASE}x`),
    );
    expect(mismatch.exitCode).toBe(1);
    expect(mismatch.stderr).toContain('do not match');
    const short = await runCli(
      ['export', '--file', file, '--json', ...routing()],
      frames(EXEC_PASSPHRASE, 'short', 'short'),
    );
    expect(short.exitCode).not.toBe(0);
  });

  it('reports a missing credential set with exit 11', async () => {
    const result = await runCli(
      [
        'export',
        '--file',
        join(directory, 'none.kavrix-export'),
        '--prefix',
        'absent/',
        '--json',
        ...routing(),
      ],
      frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE, ARCHIVE_PASSPHRASE),
    );
    expect(result.exitCode).toBe(11);
  });

  it('fails closed on a wrong passphrase, tampering, and non-archives', async () => {
    const file = join(directory, 'tamper.kavrix-export');
    expect(
      (
        await runCli(
          ['export', '--file', file, '--json', ...routing()],
          frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE, ARCHIVE_PASSPHRASE),
        )
      ).exitCode,
    ).toBe(0);
    const wrong = await runCli(
      ['import', 'archive', '--file', file, '--prefix', 'wrong/', ...routing()],
      frames(EXEC_PASSPHRASE, 'not the archive passphrase'),
    );
    expect(wrong.exitCode).toBe(10);

    const archive = JSON.parse(await readFile(file, 'utf8')) as { createdAt: string };
    const tamperedFile = join(directory, 'tampered.kavrix-export');
    await writeProtected(
      tamperedFile,
      JSON.stringify({ ...archive, createdAt: '2020-01-01T00:00:00.000Z' }),
    );
    const tampered = await runCli(
      [
        'import',
        'archive',
        '--file',
        tamperedFile,
        '--prefix',
        'tamper/',
        ...routing(),
      ],
      frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE),
    );
    expect(tampered.exitCode).toBe(10);

    const garbage = join(directory, 'garbage.kavrix-export');
    await writeProtected(garbage, '{"format":"something-else"}');
    const invalid = await runCli(
      ['import', 'archive', '--file', garbage, ...routing()],
      '',
    );
    expect(invalid.exitCode).toBe(16);
  });

  it('never injects a hostile imported name into the terminal error', async () => {
    // Names from a hostile archive are only schema-bounded (1-256 chars), so
    // control characters and OSC sequences are possible; the validator's
    // message must render them through the control-character sanitizer.
    const hostileName = '\u001b]52;c;oscroll\u0007?';
    const passphrase = new TextEncoder().encode(ARCHIVE_PASSPHRASE);
    let sealed: unknown;
    try {
      sealed = await sealVaultExportArchive(
        [
          {
            name: hostileName,
            value: 'hostile-name-value-canary',
            updatedAt: '2026-01-01T00:00:00.000Z',
          },
        ],
        passphrase,
      );
    } finally {
      zeroize(passphrase);
    }
    const file = join(directory, 'hostile-name.kavrix-export');
    await writeProtected(file, JSON.stringify(sealed));
    const result = await runCli(
      ['import', 'archive', '--file', file, '--json', ...routing()],
      frames(EXEC_PASSPHRASE, ARCHIVE_PASSPHRASE),
    );
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('is invalid');
    expect(result.stderr).toContain('[CONTROL]');
    expect(result.stderr).not.toContain('\u001b');
    expect(result.stderr).not.toContain('\u0007');
    expect(result.stderr + result.stdout).not.toContain('hostile-name-value-canary');
  });
});

describe('kavrix generate', () => {
  it('prints a secret only with --reveal and honours the requested shape', async () => {
    const hex = await runCli([
      'generate',
      '--reveal',
      '--format',
      'hex',
      '--length',
      '48',
    ]);
    expect(hex.exitCode).toBe(0);
    expect(hex.stdout).toMatch(/^[0-9a-f]{48}\n$/u);

    const json = await runCli(['generate', '--reveal', '--json', '--no-symbols']);
    expect(json.exitCode).toBe(0);
    const parsed = JSON.parse(json.stdout) as { value: string; entropyBits: number };
    expect(parsed.value).toMatch(/^[A-Za-z0-9]{32}$/u);
    expect(parsed.entropyBits).toBeGreaterThan(150);
  });

  it('stores a generated value under a name without displaying it', async () => {
    const stored = await runCli(
      ['generate', 'generated/TOKEN', '--length', '40', '--json', ...routing()],
      frames(EXEC_PASSPHRASE),
    );
    expect(stored.exitCode).toBe(0);
    const envelope = JSON.parse(stored.stdout) as Record<string, unknown>;
    expect(envelope).toMatchObject({
      stored: true,
      name: 'generated/TOKEN',
      length: 40,
    });
    expect(envelope).not.toHaveProperty('value');
    const value = await reveal('generated/TOKEN');
    expect(Array.from(value)).toHaveLength(40);
    expect(stored.stdout + stored.stderr).not.toContain(value);

    const conflict = await runCli(
      ['generate', 'generated/TOKEN', '--json', ...routing()],
      frames(EXEC_PASSPHRASE),
    );
    expect(conflict.exitCode).toBe(1);
    expect(await reveal('generated/TOKEN')).toBe(value);

    const replaced = await runCli(
      ['generate', 'generated/TOKEN', '--overwrite', '--json', ...routing()],
      frames(EXEC_PASSPHRASE),
    );
    expect(replaced.exitCode).toBe(0);
    expect(JSON.parse(replaced.stdout)).toMatchObject({ overwritten: true });
    expect(await reveal('generated/TOKEN')).not.toBe(value);
  });

  it('treats ambiguous or invalid requests as usage errors', async () => {
    for (const args of [
      ['generate'],
      ['generate', 'some/name', '--reveal'],
      ['generate', '--reveal', '--length', '7'],
      ['generate', '--reveal', '--length', 'abc'],
      ['generate', '--reveal', '--format', 'emoji'],
      [
        'generate',
        '--reveal',
        '--no-lowercase',
        '--no-uppercase',
        '--no-digits',
        '--no-symbols',
      ],
    ]) {
      const result = await runCli(args);
      expect(result.exitCode, args.join(' ')).toBe(2);
      expect(result.stdout).toBe('');
    }
  });

  it('builds requests from flag defaults', () => {
    expect(generationRequestFromOptions({})).toEqual({
      format: 'password',
      length: 32,
      lowercase: true,
      uppercase: true,
      digits: true,
      symbols: true,
      excludeAmbiguous: false,
    });
  });
});
