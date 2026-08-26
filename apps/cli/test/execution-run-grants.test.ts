import { createHash } from 'node:crypto';

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

const LONG_NAME = `${'a'.repeat(130)}/token`;

beforeAll(async () => {
  fixture = await createExecutionFixture({
    'github/token': 'e2e-canary-secret-value',
    'production/database': 'db-canary-passphrase',
    [LONG_NAME]: 'long-name-canary',
  });
}, 120_000);

afterAll(async () => {
  await destroyFixture(fixture);
});

interface Envelope {
  ran?: boolean;
  exitCode?: number | null;
  stdout?: string;
  error?: { code: string; exitCode: number; message: string };
}

function lastJsonLine(output: string): Envelope {
  const line = output.trim().split('\n').at(-1) ?? '';
  return JSON.parse(line) as Envelope;
}

function digestOf(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

async function clearGrants(): Promise<void> {
  const listed = await runCli(
    ['grant', 'list', ...fixture.routingArgs, '--passphrase-stdin', '--json'],
    passphraseFrame(),
  );
  expect(listed.exitCode).toBe(0);
  const parsed = JSON.parse(listed.stdout.trim()) as {
    grants: { grantId: string; status: string }[];
  };
  for (const grant of parsed.grants) {
    if (grant.status !== 'active') continue;
    const revoked = await runCli(
      [
        'grant',
        'revoke',
        grant.grantId,
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    expect(revoked.exitCode).toBe(0);
  }
}

async function issueGrant(
  secret: string,
  extra: readonly string[] = [],
): Promise<string> {
  const created = await runCli(
    [
      'grant',
      'create',
      secret,
      '--command',
      'node',
      '--ttl',
      '1h',
      ...fixture.routingArgs,
      '--passphrase-stdin',
      '--json',
      ...extra,
    ],
    passphraseFrame(),
  );
  expect(created.exitCode).toBe(0);
  const parsed = lastJsonLine(created.stdout) as { grantId?: string };
  expect(parsed.grantId).toBeTruthy();
  return parsed.grantId as string;
}

/** Runs one child that prints the SHA-256 of an env variable as JSON. */
async function runDigestProbe(
  cliArgs: readonly string[],
  variableName: string,
): Promise<{ exitCode: number; envelope: Envelope; digest: string | null }> {
  const result = await runCli(
    [
      'run',
      ...cliArgs,
      ...fixture.routingArgs,
      '--passphrase-stdin',
      '--json',
      '--',
      process.execPath,
      '-e',
      `const crypto=require("node:crypto");const value=process.env[${JSON.stringify(variableName)}]??"";process.stdout.write(JSON.stringify({okArgv:process.argv.every((a)=>!value||!a.includes(value)),digest:crypto.createHash("sha256").update(value).digest("hex")}));`,
    ],
    passphraseFrame(),
  );
  const raw = lastJsonLine(result.stdout).stdout ?? '{}';
  let digest: string | null = null;
  try {
    digest = (JSON.parse(raw) as { digest?: string }).digest ?? null;
  } catch {
    digest = null;
  }
  return { exitCode: result.exitCode, envelope: lastJsonLine(result.stdout), digest };
}

describe('kavrix run --grant', () => {
  it('injects a grant referenced by id under its declared env variable', async () => {
    await clearGrants();
    const grantId = await issueGrant('github/token', ['--env', 'KAVRIX_TOKEN']);
    const probe = await runDigestProbe(['--grant', grantId], 'KAVRIX_TOKEN');
    expect(probe.exitCode).toBe(0);
    expect(probe.envelope.ran).toBe(true);
    // The id-resolved credential must be found and injected; the historical
    // bug reported CREDENTIAL_MISSING even though `has` confirmed existence.
    expect(probe.digest).toBe(digestOf('e2e-canary-secret-value'));
    expect(probe.envelope.stdout).toContain('"okArgv":true');
  });

  it('injects a bare grant under a derived destination name', async () => {
    await clearGrants();
    await issueGrant('production/database');
    const probe = await runDigestProbe(
      ['--grant', 'production/database'],
      'PRODUCTION_DATABASE',
    );
    expect(probe.exitCode).toBe(0);
    expect(probe.digest).toBe(digestOf('db-canary-passphrase'));
  });

  it('fails with exit 11 and does not consume the use when the credential vanished', async () => {
    await clearGrants();
    const grantId = await issueGrant('production/database');
    const removed = await runCli(
      [
        'remove',
        'production/database',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    expect(removed.exitCode).toBe(0);
    const failed = await runCli(
      [
        'run',
        '--grant',
        grantId,
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
    expect(failed.exitCode).toBe(11);
    expect(lastJsonLine(failed.stdout).error?.code).toBe('CREDENTIAL_MISSING');

    // Restore the credential and prove the earlier failure burned nothing.
    const restored = await runCli(
      [
        'put',
        'production/database',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--value-stdin',
        '--overwrite',
        '--json',
      ],
      `${EXEC_PASSPHRASE}\ndb-canary-passphrase\n`,
    );
    expect(restored.exitCode).toBe(0);
    const retried = await runDigestProbe(['--grant', grantId], 'PRODUCTION_DATABASE');
    expect(retried.exitCode).toBe(0);
    expect(retried.digest).toBe(digestOf('db-canary-passphrase'));
  });

  it('refuses unmappable bare-grant credentials with exit 14 before consuming', async () => {
    await clearGrants();
    await issueGrant(LONG_NAME);
    const result = await runCli(
      [
        'run',
        '--grant',
        LONG_NAME,
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
    expect(result.exitCode).toBe(14);
    const list = await runCli(
      ['grant', 'list', ...fixture.routingArgs, '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    const listed = JSON.parse(list.stdout.trim()) as {
      grants: { secret: string; usedCount: number }[];
    };
    const target = listed.grants.find((grant) => grant.secret === LONG_NAME);
    expect(target?.usedCount).toBe(0);
  });

  it('reports unknown grant references without consuming anything', async () => {
    await clearGrants();
    const result = await runCli(
      [
        'run',
        '--grant',
        'no/such-grant',
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
    expect(result.exitCode).toBe(13);
  });
});
