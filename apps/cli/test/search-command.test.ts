import { Readable, Writable } from 'node:stream';

import { groupIdSchema, itemIdSchema } from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;
type SearchPort = NonNullable<CliUseCasePorts['search']>;
type SearchRequest = Parameters<SearchPort>[0];
type SearchResult = Awaited<ReturnType<SearchPort>>;

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

/** A search port that records every request the command produced. */
function capturingSearch(result: SearchResult): Readonly<{
  port: SearchPort;
  calls: () => readonly SearchRequest[];
}> {
  const calls: SearchRequest[] = [];
  const port = vi.fn((request: SearchRequest) => {
    calls.push(request);
    return Promise.resolve(result);
  });
  return { port, calls: () => calls };
}

function searchResult(overrides: Partial<SearchResult> = {}): SearchResult {
  return {
    hits: [],
    matchedCount: 0,
    truncated: false,
    scannedGroups: 1,
    scannedCredentials: 3,
    ...overrides,
  };
}

const GROUP_ID = groupIdSchema.parse('group.1');
const CREDENTIAL_ID = itemIdSchema.parse('item.101');

/** Built from code points so no raw control byte is stored in this file. */
const ESCAPE = String.fromCharCode(0x1b);
const BELL = String.fromCharCode(0x07);
const REPLACEMENT = String.fromCharCode(0xff_fd);

describe('CLI search command', () => {
  it('renders group and credential hits by matched property', async () => {
    const search = capturingSearch(
      searchResult({
        hits: [
          {
            kind: 'group',
            groupId: GROUP_ID,
            groupName: 'Engineering',
            matches: [{ source: 'group-tag', locator: 'primary' }],
            matchesTruncated: false,
          },
          {
            kind: 'credential',
            groupId: GROUP_ID,
            groupName: 'Engineering',
            credentialId: CREDENTIAL_ID,
            title: 'Primary DB',
            matches: [
              { source: 'title' },
              { source: 'field-value', locator: 'Api token' },
            ],
            matchesTruncated: false,
          },
        ],
        matchedCount: 2,
      }),
    );

    const result = await execute(['search', 'primary'], { search: search.port });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('Matches (2):');
    expect(result.stdout).toContain('- Group Engineering [group.1]');
    expect(result.stdout).toContain('Matched: group-tag (primary)');
    expect(result.stdout).toContain('- Engineering / Primary DB [item.101]');
    expect(result.stdout).toContain('Matched: title, field-value (Api token)');
    expect(result.stdout).toContain('Scanned 1 group(s) and 3 credential(s).');
    expect(result.stdout).not.toContain('Refine the term');
  });

  it('scans metadata only unless secret values are opted into per invocation', async () => {
    const search = capturingSearch(searchResult());

    const result = await execute(['search', 'primary'], { search: search.port });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    // A stored setting could leave secret search enabled for a later command, so
    // the request carries the decision explicitly and defaults to refusing it.
    expect(search.calls()).toEqual([
      { term: 'primary', includeArchived: false, includeSecretValues: false },
    ]);
    expect(result.stdout).toContain('No matches found.');
    expect(result.stdout).toContain('Scanned 1 group(s) and 3 credential(s).');
  });

  it('forwards the group, limit, and both opt-in scopes', async () => {
    const search = capturingSearch(searchResult());

    const result = await execute(
      [
        'search',
        'token',
        '--group',
        'Engineering',
        '--limit',
        '25',
        '--include-archived',
        '--include-secret-values',
      ],
      { search: search.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(search.calls()).toEqual([
      {
        term: 'token',
        groupQuery: 'Engineering',
        limit: 25,
        includeArchived: true,
        includeSecretValues: true,
      },
    ]);
  });

  it('reports truncation instead of implying the result set is complete', async () => {
    const search = capturingSearch(
      searchResult({
        hits: [
          {
            kind: 'credential',
            groupId: GROUP_ID,
            groupName: 'Engineering',
            credentialId: CREDENTIAL_ID,
            title: 'Primary DB',
            matches: [{ source: 'tag', locator: 'shared' }],
            matchesTruncated: true,
          },
        ],
        matchedCount: 9,
        truncated: true,
      }),
    );

    const result = await execute(['search', 'shared', '--limit', '1'], {
      search: search.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('Matches (1 of 9):');
    expect(result.stdout).toContain('Matched: tag (shared), …');
    expect(result.stdout).toContain('Refine the term or raise --limit');
  });

  it('rejects a term or limit outside the supported bounds before reading the vault', async () => {
    const search = capturingSearch(searchResult());

    for (const argv of [
      ['search'],
      ['search', '   '],
      ['search', `token${ESCAPE}[31m`],
      ['search', 'a'.repeat(257)],
      ['search', 'token', '--limit', '0'],
      ['search', 'token', '--limit', '201'],
      ['search', 'token', '--limit', 'many'],
      ['search', 'token', '--limit', '1.5'],
      ['search', 'token', '--group', '  '],
    ]) {
      const result = await execute(argv, { search: search.port });
      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(result.stdout).toBe('');
    }
    expect(search.calls()).toHaveLength(0);
  });

  it('neutralizes hostile record names and locators in both output modes', async () => {
    const hostile = searchResult({
      hits: [
        {
          kind: 'credential',
          groupId: GROUP_ID,
          groupName: `Engineering${ESCAPE}[31m`,
          credentialId: CREDENTIAL_ID,
          title: `Primary${ESCAPE}]0;pwned${BELL}`,
          matches: [{ source: 'field-label', locator: `Api${ESCAPE}[2Ktoken` }],
          matchesTruncated: false,
        },
      ],
      matchedCount: 1,
    });

    const text = await execute(['search', 'primary'], {
      search: capturingSearch(hostile).port,
    });
    const json = await execute(['search', 'primary', '--json'], {
      search: capturingSearch(hostile).port,
    });

    expect(text.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(text.stdout).not.toContain(ESCAPE);
    expect(text.stdout).not.toContain(BELL);
    expect(text.stdout).toContain(REPLACEMENT);

    expect(json.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(json.stdout).not.toContain(ESCAPE);
    expect(json.stdout).not.toContain(BELL);
    const parsed = JSON.parse(json.stdout) as SearchResult;
    expect(parsed.matchedCount).toBe(1);
    expect(parsed.hits[0]?.matches[0]?.source).toBe('field-label');
    expect(parsed.hits[0]?.groupName).toContain(REPLACEMENT);
  });

  it('reports an unconfigured search adapter as unavailable rather than crashing', async () => {
    const result = await execute(['search', 'primary']);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('search is unavailable');
    expect(result.stdout).toBe('');
  });
});
