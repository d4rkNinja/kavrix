import { Readable, Writable } from 'node:stream';

import { groupIdSchema, itemIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;
type RekeyPort = NonNullable<CliUseCasePorts['rekeyItems']>;
type RekeyRequest = Parameters<RekeyPort>[0];
type RekeyResult = Awaited<ReturnType<RekeyPort>>;

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

/** A rotation port that records every request the command produced. */
function capturingRekey(result: RekeyResult): Readonly<{
  port: RekeyPort;
  calls: () => readonly RekeyRequest[];
}> {
  const calls: RekeyRequest[] = [];
  const port = vi.fn((request: RekeyRequest) => {
    calls.push(request);
    return Promise.resolve(result);
  });
  return { port, calls: () => calls };
}

const VAULT_ID = vaultIdSchema.parse('vault.1');
const GROUP_ID = groupIdSchema.parse('group.1');
const FIRST_ID = itemIdSchema.parse('item.101');
const SECOND_ID = itemIdSchema.parse('item.102');

function rekeyResult(overrides: Partial<RekeyResult> = {}): RekeyResult {
  return {
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    groupName: 'Engineering',
    rotated: [{ credentialId: FIRST_ID, title: 'Primary DB' }],
    skipped: [],
    ...overrides,
  };
}

/** Built from code points so no raw control byte is stored in this file. */
const ESCAPE = String.fromCharCode(0x1b);
const BELL = String.fromCharCode(0x07);
const REPLACEMENT = String.fromCharCode(0xff_fd);

describe('CLI key rekey command', () => {
  it('rotates every active credential in a group when no selection is given', async () => {
    const rekey = capturingRekey(
      rekeyResult({
        rotated: [
          { credentialId: FIRST_ID, title: 'Primary DB' },
          { credentialId: SECOND_ID, title: 'Replica DB' },
        ],
      }),
    );

    const result = await execute(['key', 'rekey', '--group', 'Engineering'], {
      rekeyItems: rekey.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    // An omitted selection has to mean "every active credential", not an empty
    // batch the client would refuse as a malformed selection.
    expect(rekey.calls()).toEqual([{ groupQuery: 'Engineering' }]);
    expect(result.stdout).toContain('Rotated 2 item key(s) in Engineering (group.1).');
    expect(result.stdout).toContain('Primary DB (item.101)');
    expect(result.stdout).toContain('Replica DB (item.102)');
    expect(result.stdout).toContain(
      'Group and vault keys, key versions, and associated data are unchanged',
    );
    expect(result.stdout).not.toContain('Skipped');
  });

  it('forwards a repeatable credential selection in the given order', async () => {
    const rekey = capturingRekey(rekeyResult());

    const result = await execute(
      [
        'key',
        'rekey',
        '--group',
        'Engineering',
        '--credential',
        'Primary DB',
        '--credential',
        'item.102',
      ],
      { rekeyItems: rekey.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(rekey.calls()).toEqual([
      {
        groupQuery: 'Engineering',
        credentialQueries: ['Primary DB', 'item.102'],
      },
    ]);
  });

  it('reports skipped credentials with the reason instead of a bare count', async () => {
    const rekey = capturingRekey(
      rekeyResult({
        rotated: [],
        skipped: [
          {
            credentialId: FIRST_ID,
            title: 'Signed Contract',
            reason: 'attachments-present',
          },
          { credentialId: SECOND_ID, title: 'Old Router', reason: 'deleted' },
        ],
      }),
    );

    const result = await execute(['key', 'rekey', '--group', 'Engineering'], {
      rekeyItems: rekey.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('Rotated 0 item key(s)');
    expect(result.stdout).toContain('Skipped 2 credential(s):');
    // A partial rotation reported as a complete one would leave the operator
    // believing an attachment-bearing credential holds a fresh item key.
    expect(result.stdout).toContain(
      'Signed Contract (item.101): attachment keys are wrapped under this item key, so rotating it would strand them',
    );
    expect(result.stdout).toContain(
      'Old Router (item.102): the record is deleted and holds no live item key',
    );
  });

  it('refuses a missing, blank, or oversized selection before opening the vault', async () => {
    const rekey = capturingRekey(rekeyResult());
    const oversized = Array.from({ length: 100 }, (_value, index) => [
      '--credential',
      `item.${String(index)}`,
    ]).flat();

    for (const argv of [
      ['key', 'rekey'],
      ['key', 'rekey', '--group', '   '],
      ['key', 'rekey', '--group', `Engineering${ESCAPE}[31m`],
      ['key', 'rekey', '--group', 'Engineering', '--credential', '  '],
      ['key', 'rekey', '--group', 'Engineering', ...oversized],
    ]) {
      const result = await execute(argv, { rekeyItems: rekey.port });
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stdout).toBe('');
    }
    expect(rekey.calls()).toHaveLength(0);
  });

  it('neutralizes hostile credential titles in both output modes', async () => {
    const hostile = rekeyResult({
      groupName: `Engineering${ESCAPE}[31m`,
      rotated: [{ credentialId: FIRST_ID, title: `Primary${ESCAPE}]0;pwned${BELL}` }],
      skipped: [
        {
          credentialId: SECOND_ID,
          title: `Router${ESCAPE}[2K`,
          reason: 'attachments-present',
        },
      ],
    });

    const text = await execute(['key', 'rekey', '--group', 'Engineering'], {
      rekeyItems: capturingRekey(hostile).port,
    });
    const json = await execute(['key', 'rekey', '--group', 'Engineering', '--json'], {
      rekeyItems: capturingRekey(hostile).port,
    });

    expect(text.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(text.stdout).not.toContain(ESCAPE);
    expect(text.stdout).not.toContain(BELL);
    expect(text.stdout).toContain(REPLACEMENT);

    expect(json.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(json.stdout).not.toContain(ESCAPE);
    expect(json.stdout).not.toContain(BELL);
    const parsed = JSON.parse(json.stdout) as RekeyResult;
    expect(parsed.groupName).toContain(REPLACEMENT);
    expect(parsed.rotated[0]?.title).toContain(REPLACEMENT);
    expect(parsed.skipped[0]?.reason).toBe('attachments-present');
  });

  it('reports an unconfigured rotation adapter as unavailable rather than crashing', async () => {
    const result = await execute(['key', 'rekey', '--group', 'Engineering']);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('key rekey is unavailable');
    expect(result.stdout).toBe('');
  });
});
