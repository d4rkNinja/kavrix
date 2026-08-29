import { createHash } from 'node:crypto';
import { readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  passphraseFrame,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';

let fixture: ExecutionFixture;

beforeAll(async () => {
  fixture = await createExecutionFixture({
    'github/token': 'e2e-canary-secret-value',
    'production/database': 'db-canary-passphrase',
  });
}, 120_000);

afterAll(async () => {
  await destroyFixture(fixture);
});

interface Envelope {
  ran?: boolean;
  decision?: { outcome: string; reason: string };
  executable?: { request: string; displayName?: string };
  exitCode?: number | null;
  signal?: string | null;
  termination?: string;
  stdout?: string;
  stderr?: string;
  error?: { code: string; exitCode: number; message: string };
}

function lastJsonLine(output: string): Envelope {
  const line = output.trim().split('\n').at(-1) ?? '';
  return JSON.parse(line) as Envelope;
}

function digestOf(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function envProbeScript(varName: string): string {
  return [
    'const crypto = require("node:crypto");',
    `const value = process.env[${JSON.stringify(varName)}] ?? '';`,
    'const okArgv = process.argv.every((argument) => value.length === 0 || !argument.includes(value));',
    'process.stdout.write(JSON.stringify({',
    '  digest: crypto.createHash("sha256").update(value).digest("hex"),',
    '  okArgv,',
    '  length: value.length,',
    '}));',
  ].join('\n');
}

describe('kavrix run', () => {
  it('injects an explicitly mapped secret into the child environment only', async () => {
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'KAVRIX_E2E_CANARY=github/token',
        '--json',
        '--',
        process.execPath,
        '-e',
        envProbeScript('KAVRIX_E2E_CANARY'),
      ],
      passphraseFrame(),
    );

    expect(result.exitCode).toBe(0);
    const envelope = lastJsonLine(result.stdout);
    expect(envelope.ran).toBe(true);
    expect(envelope.decision).toMatchObject({ outcome: 'allow' });
    expect(envelope.exitCode).toBe(0);
    expect(envelope.stdout).toContain(
      `"digest":"${digestOf('e2e-canary-secret-value')}"`,
    );
    expect(envelope.stdout).toContain('"okArgv":true');
    // The plaintext never appears anywhere in the supervisor's own output.
    expect(result.stdout).not.toContain('e2e-canary-secret-value');
  });

  it('propagates nonzero child exit codes as the CLI exit code', async () => {
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
        '--',
        process.execPath,
        '-e',
        'process.exit(7)',
      ],
      passphraseFrame(),
    );
    expect(lastJsonLine(result.stdout).exitCode).toBe(7);
    expect(result.stderr).not.toContain('Kavrix command failed');
  });

  it('leaves the parent environment untouched', async () => {
    const before = process.env['KAVRIX_E2E_CANARY'];
    await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'KAVRIX_E2E_CANARY=github/token',
        '--json',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(process.env['KAVRIX_E2E_CANARY']).toBe(before);
    expect(process.env['KAVRIX_E2E_CANARY']).toBeUndefined();
  });

  it('fails closed when a requested credential does not exist', async () => {
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'MISSING=nope/absent',
        '--json',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(11);
    expect(result.stderr).toContain('nope/absent');
    expect(result.stderr).not.toContain('e2e-canary-secret-value');
  });

  it('rejects malformed secret mappings as usage errors', async () => {
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'NO_EQUALS_SIGN',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(14);
    expect(result.stderr).toContain('--secret expects');
  });

  it('redacts captured child output that echoes injected secrets', async () => {
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'KAVRIX_E2E_CANARY=github/token',
        '--json',
        '--',
        process.execPath,
        '-e',
        'console.log(process.env.KAVRIX_E2E_CANARY)',
      ],
      passphraseFrame(),
    );
    const envelope = lastJsonLine(result.stdout);
    expect(envelope.stdout).toBe(`${'*'.repeat('e2e-canary-secret-value'.length)}\n`);
    expect(result.stdout).not.toContain('e2e-canary-secret-value');
  });

  it('maps signal death of the child onto conventional shell exit codes', async () => {
    if (process.platform === 'win32') return;
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
        '--',
        process.execPath,
        '-e',
        "process.kill(process.pid, 'SIGTERM')",
      ],
      passphraseFrame(),
    );
    const envelope = lastJsonLine(result.stdout);
    expect(envelope.exitCode).toBe(143);
    expect(envelope.termination).toBe('signal');
    expect(result.exitCode).toBe(143);
  });

  it('applies project-file environment mappings and rejects conflicts', async () => {
    const configFile = join(fixture.directory, 'kavrix.json');
    await writeFile(
      configFile,
      JSON.stringify({
        version: 1,
        project: 'exec-tests',
        environments: {
          dev: {
            secrets: {
              KAVRIX_PROJECT_VAR: 'github/token',
              SECOND_VAR: 'production/database',
            },
          },
        },
      }),
    );
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--config',
        configFile,
        '--environment',
        'dev',
        '--json',
        '--',
        process.execPath,
        '-e',
        [
          'const crypto=require("node:crypto");',
          'const a=process.env.KAVRIX_PROJECT_VAR??"";',
          'const b=process.env.SECOND_VAR??"";',
          'process.stdout.write(JSON.stringify({a:a.length,b:b.length}));',
        ].join('\n'),
      ],
      passphraseFrame(),
    );
    const envelope = lastJsonLine(result.stdout);
    expect(envelope.stdout).toContain('"a":23,"b":20');

    const conflict = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--config',
        configFile,
        '--environment',
        'dev',
        '--secret',
        'SECOND_VAR=github/token',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(conflict.exitCode).toBe(14);
    expect(conflict.stderr).toContain('conflicting credentials');
  });

  it('rejects protected runtime variable destinations', async () => {
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'NODE_OPTIONS=github/token',
        '--json',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(14);
    expect(result.stderr).toContain('protected runtime variable');
  });

  it('reports multiple matching grants as a grant error', async () => {
    for (let index = 0; index < 2; index += 1) {
      const created = await runCli(
        [
          'grant',
          'create',
          'github/token',
          '--command',
          'node',
          '--ttl',
          '1h',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--json',
        ],
        passphraseFrame(),
      );
      expect(created.exitCode).toBe(0);
    }
    const ambiguous = await runCli(
      [
        'run',
        '--grant',
        'github/token',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(ambiguous.exitCode).toBe(13);
    expect(ambiguous.stderr).toContain('Multiple active grants');
  });

  it('redacts secrets echoed on stderr and flags truncated captures', async () => {
    const echoed = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'KAVRIX_E2E_CANARY=github/token',
        '--json',
        '--',
        process.execPath,
        '-e',
        'console.error(process.env.KAVRIX_E2E_CANARY ?? "")',
      ],
      passphraseFrame(),
    );
    expect(lastJsonLine(echoed.stdout).stderr).toBe(
      `${'*'.repeat('e2e-canary-secret-value'.length)}\n`,
    );

    // Exceeding the per-stream capture bound terminates the child
    // (output-limit → SIGTERM → conventional shell code 143).
    const big = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
        '--',
        process.execPath,
        '-e',
        'process.stdout.write("y".repeat(128 * 1024)); setInterval(() => {}, 1_000)',
      ],
      passphraseFrame(),
    );
    const bigEnvelope = lastJsonLine(big.stdout);
    expect(bigEnvelope.exitCode).toBe(143);
    expect(bigEnvelope.termination).toBe('output-limit');
    expect(bigEnvelope.outputTruncated).toBe(true);
    expect(big.exitCode).toBe(143);
  });

  it('rejects missing commands and unresolvable executables before unlocking', async () => {
    const noCommand = await runCli(
      ['run', ...fixture.routingArgs, '--passphrase-stdin'],
      passphraseFrame(),
    );
    expect(noCommand.exitCode).toBe(14);
    expect(noCommand.stderr).toContain('A command is required');

    const unresolved = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--',
        'definitely-missing-kavrix-tool',
      ],
      passphraseFrame(),
    );
    expect(unresolved.exitCode).toBe(12);
    expect(unresolved.stderr).toContain('could not be resolved');
  });

  it('fails closed when a referenced policy does not exist', async () => {
    const result = await runCli(
      [
        'run',
        '--policy',
        'no-such-policy',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(14);
    expect(result.stderr).toContain("'no-such-policy' is not defined");
  });

  it('never leaves plaintext temporary files behind', async () => {
    const before = new Set(await readdir(fixture.directory));
    await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    const after = new Set(await readdir(fixture.directory));
    const added = [...after].filter((entry) => !before.has(entry));
    expect(added.every((entry) => entry === 'owner.key.authorization')).toBe(true);
    for (const entry of after) {
      expect(entry.endsWith('.tmp')).toBe(false);
      expect(entry.startsWith('.kavrix')).toBe(false);
    }
  });
});
