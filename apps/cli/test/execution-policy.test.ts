import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  createExecutionFixture,
  destroyFixture,
  passphraseFrame,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';

let fixture: ExecutionFixture;

beforeEach(async () => {
  fixture = await createExecutionFixture({
    'github/token': 'reveal-canary-token',
    'production/database': 'reveal-canary-db',
  });
});

afterEach(async () => {
  await destroyFixture(fixture);
});

function routing(): string[] {
  return [...fixture.routingArgs];
}

interface JsonLine {
  error?: { code: string; exitCode: number; message: string };
  events?: Array<Record<string, unknown>>;
  total?: number;
}

function parseLast(output: string): JsonLine {
  const line = output.trim().split('\n').at(-1) ?? '';
  return JSON.parse(line) as JsonLine;
}

describe('use versus reveal separation', () => {
  it('permits use through run while a stored policy forbids plaintext reveal', async () => {
    const created = await runCli(
      [
        'policy',
        'create',
        'gh-locked',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
      ],
      passphraseFrame(),
    );
    expect(created.exitCode).toBe(0);

    const used = await runCli(
      [
        'run',
        '--policy',
        'gh-locked',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(used.exitCode).toBe(0);

    const revealed = await runCli(
      ['get', 'github/token', '--reveal', ...routing(), '--passphrase-stdin'],
      passphraseFrame(),
    );
    expect(
      revealed.exitCode,
      `reveal failed | out=${revealed.stdout.slice(0, 200)} | err=${revealed.stderr.slice(0, 300)}`,
    ).toBe(12);
    expect(revealed.stderr).toContain('denied by policy');
    expect(revealed.stdout).not.toContain('reveal-canary-token');
  });
  it('keeps explicit reveal working when no policy covers the credential', async () => {
    const revealed = await runCli(
      ['get', 'production/database', '--reveal', ...routing(), '--passphrase-stdin'],
      passphraseFrame(),
    );
    expect(revealed.exitCode).toBe(0);
    expect(revealed.stdout.trim()).toBe('reveal-canary-db');
  });

  it('blocks plain unmapped runs of a credential covered by a deny entry', async () => {
    const created = await runCli(
      [
        'policy',
        'create',
        'prod-deny',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--deny',
        '--secret',
        'production/database',
      ],
      passphraseFrame(),
    );
    expect(created.exitCode).toBe(0);

    const denied = await runCli(
      [
        'run',
        ...routing(),
        '--passphrase-stdin',
        '--secret',
        'DBPASS=production/database',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(denied.exitCode).toBe(12);
    expect(denied.stderr).toContain("'prod-deny'");
  });

  it('requires an interactive terminal for confirmation-gated policies', async () => {
    const created = await runCli(
      [
        'policy',
        'create',
        'confirm-me',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
        '--require-confirmation',
      ],
      passphraseFrame(),
    );
    expect(created.exitCode).toBe(0);

    const result = await runCli(
      [
        'run',
        '--policy',
        'confirm-me',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(17);
    expect(result.stderr).toContain('confirmation');
  });

  it('enforces executable hash pins end to end', async () => {
    const { createHash } = await import('node:crypto');
    const realDigest = createHash('sha256')
      .update(await readFile(process.execPath))
      .digest('hex');

    const pinnedWrong = await runCli(
      [
        'policy',
        'create',
        'pinned-wrong',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
        '--hash',
        `node=${'f'.repeat(64)}`,
      ],
      passphraseFrame(),
    );
    expect(pinnedWrong.exitCode).toBe(0);

    const mismatch = await runCli(
      [
        'run',
        '--policy',
        'pinned-wrong',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(mismatch.exitCode).toBe(12);
    expect(mismatch.stderr).toContain('hash does not match');
    void realDigest;

    // A correct pin authorizes the exact binary.
    const pinnedRight = await runCli(
      [
        'policy',
        'create',
        'pinned-right',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
        '--hash',
        `node=${realDigest}`,
      ],
      passphraseFrame(),
    );
    expect(pinnedRight.exitCode).toBe(0);

    const allowed = await runCli(
      [
        'run',
        '--policy',
        'pinned-right',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(allowed.exitCode).toBe(0);
  });

  it('caps the execution window from the policy ttl', async () => {
    const created = await runCli(
      [
        'policy',
        'create',
        'short-window',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
        '--ttl',
        '1s',
      ],
      passphraseFrame(),
    );
    expect(created.exitCode).toBe(0);

    const timedOut = await runCli(
      [
        'run',
        '--policy',
        'short-window',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--',
        process.execPath,
        '-e',
        'setInterval(() => {}, 60_000)',
      ],
      passphraseFrame(),
    );
    expect(timedOut.exitCode).not.toBe(0);
    expect(timedOut.exitCode === null ? true : timedOut.exitCode > 128).toBe(true);
  }, 90_000);
});

describe('project-defined policies', () => {
  it('authorizes runs through policies that exist only in the project file', async () => {
    const configFile = join(fixture.directory, 'project.json');
    await writeFile(
      configFile,
      JSON.stringify({
        version: 1,
        policies: {
          'proj-only': {
            secret: 'github/token',
            commands: ['node'],
          },
        },
      }),
    );
    const result = await runCli(
      [
        'run',
        '--policy',
        'proj-only',
        '--config',
        configFile,
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(0);
  });

  it('asks only when the first argument matches a confirmation token list', async () => {
    await runCli(
      [
        'policy',
        'create',
        'scoped-confirm',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
        '--require-confirmation',
        'publish,push',
      ],
      passphraseFrame(),
    );

    // First argument not on the list: runs without any prompt.
    const cleanRun = await runCli(
      [
        'run',
        '--policy',
        'scoped-confirm',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
        '--',
        'ignored',
      ],
      passphraseFrame(),
    );
    expect(cleanRun.exitCode).toBe(0);

    // First argument on the list: unattended confirmation fails closed.
    const asked = await runCli(
      [
        'run',
        '--policy',
        'scoped-confirm',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        'publish',
        '--registry',
        'https://example.invalid',
      ],
      passphraseFrame(),
    );
    expect(asked.exitCode, `asked-run | err=${asked.stderr.slice(0, 250)}`).toBe(17);
  });
});
describe('working-directory restrictions', () => {
  it('binds use to the policy directory subtree when the invocation matches', async () => {
    const created = await runCli(
      [
        'policy',
        'create',
        'workdir-locked',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
        '--workdir',
        process.cwd(),
      ],
      passphraseFrame(),
    );
    expect(created.exitCode).toBe(0);

    const allowed = await runCli(
      [
        'run',
        '--policy',
        'workdir-locked',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(allowed.exitCode).toBe(0);
  });

  it('denies when the invocation happens outside the restricted subtree', async () => {
    const elsewhere = await mkdtemp(join(tmpdir(), 'kavrix-workdir-out-'));
    try {
      const created = await runCli(
        [
          'policy',
          'create',
          'elsewhere-locked',
          ...routing(),
          '--passphrase-stdin',
          '--json',
          '--secret',
          'github/token',
          '--command',
          'node',
          '--workdir',
          elsewhere,
        ],
        passphraseFrame(),
      );
      expect(created.exitCode).toBe(0);

      const denied = await runCli(
        [
          'run',
          '--policy',
          'elsewhere-locked',
          ...routing(),
          '--passphrase-stdin',
          '--',
          process.execPath,
          '-e',
          'process.exit(0)',
        ],
        passphraseFrame(),
      );
      expect(denied.exitCode, `denied-run | err=${denied.stderr.slice(0, 250)}`).toBe(
        12,
      );
      expect(denied.stderr).toContain('working-directory-mismatch');
    } finally {
      await rm(elsewhere, { force: true, recursive: true });
    }
  });
});

describe('audit trail', () => {
  it('records policy, grant, authorization, and execution events without plaintext', async () => {
    await runCli(
      [
        'policy',
        'create',
        'audited',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
      ],
      passphraseFrame(),
    );
    await runCli(
      [
        'grant',
        'create',
        'github/token',
        '--command',
        'node',
        '--ttl',
        '1h',
        ...routing(),
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    const denied = await runCli(
      [
        'run',
        '--policy',
        'audited',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(
      denied.exitCode,
      `audited-run | out=${denied.stdout.slice(0, 250)} | err=${denied.stderr.slice(0, 250)}`,
    ).toBe(0);

    const auditJson = await runCli(
      ['audit', '--limit', '50', ...routing(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(auditJson.exitCode).toBe(0);
    const parsed = parseLast(auditJson.stdout);
    const actions = (parsed.events ?? []).map((event) => event['action']);
    expect(actions).toContain('policy-created');
    expect(actions).toContain('grant-created');
    expect(actions).toContain('authorization-allowed');
    expect(auditJson.stdout).not.toContain('reveal-canary-token');
    expect(auditJson.stdout).not.toContain('reveal-canary-db');

    const human = await runCli(
      ['audit', '--limit', '5', ...routing(), '--passphrase-stdin'],
      passphraseFrame(),
    );
    expect(human.stdout).toContain('policy-created');
    expect(human.exitCode).toBe(0);
  });
});

describe('sealed state integrity', () => {
  it('fails closed when the sidecar is tampered with', async () => {
    await runCli(
      [
        'policy',
        'create',
        'tamper-target',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
      ],
      passphraseFrame(),
    );

    const sidecar = join(fixture.directory, 'owner.key.authorization');
    const original = await readFile(sidecar, 'utf8');
    const parsedUnknown: unknown = JSON.parse(original);
    const document = parsedUnknown as Record<string, unknown>;
    const ciphertext = Buffer.from(document['ciphertext'] as string, 'base64url');
    ciphertext[0] = ciphertext[0] ^ 0xff;
    document['ciphertext'] = ciphertext.toString('base64url');
    await writeFile(sidecar, JSON.stringify(document), 'utf8');

    const afterTamper = await runCli(
      ['policy', 'list', ...routing(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(afterTamper.exitCode).toBe(16);
    expect(afterTamper.stderr).toContain('failed authentication');
  });

  it('fails closed on a reformatted sidecar so canonical parsing stays strict', async () => {
    await runCli(
      [
        'policy',
        'create',
        'format-target',
        ...routing(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
      ],
      passphraseFrame(),
    );

    const sidecar = join(fixture.directory, 'owner.key.authorization');
    const parsed: unknown = JSON.parse(await readFile(sidecar, 'utf8'));
    await writeFile(sidecar, JSON.stringify(parsed, null, 2), 'utf8');

    const after = await runCli(
      ['policy', 'list', ...routing(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(after.exitCode).toBe(16);
  });
});
