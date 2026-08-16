import { Readable, Writable } from 'node:stream';

import {
  groupIdSchema,
  itemIdSchema,
  noteIdSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import {
  CLI_EXIT_CODES,
  runCli,
  type CliDependencies,
  type CliUseCasePorts,
} from '../src/index.js';

type MemoryWritable = Readonly<{ stream: Writable; value: () => string }>;

type PreviewPort = NonNullable<CliUseCasePorts['previewPurge']>;
type PreviewRequest = Parameters<PreviewPort>[0];
type PreviewResult = Awaited<ReturnType<PreviewPort>>;
type FieldsPort = NonNullable<CliUseCasePorts['purgeFields']>;
type FieldsRequest = Parameters<FieldsPort>[0];
type FieldsResult = Awaited<ReturnType<FieldsPort>>;
type NotesPort = NonNullable<CliUseCasePorts['purgeNotes']>;
type NotesRequest = Parameters<NotesPort>[0];
type NotesResult = Awaited<ReturnType<NotesPort>>;

type PurgeUnit = PreviewResult['plan']['units'][number];
type CategoryTotal = PreviewResult['plan']['totals'][number];

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

/** A port that answers with one result and records every request it received. */
function capturing<TRequest, TResult>(
  result: TResult,
): Readonly<{
  port: (request: TRequest) => Promise<TResult>;
  calls: () => readonly TRequest[];
}> {
  const calls: TRequest[] = [];
  const port = vi.fn((request: TRequest) => {
    calls.push(request);
    return Promise.resolve(result);
  });
  return { port, calls: () => calls };
}

const VAULT_ID = vaultIdSchema.parse('vault.1');
const GROUP_ID = groupIdSchema.parse('group.1');
const ITEM_ID = itemIdSchema.parse('item.101');
const TARGET_ID = itemIdSchema.parse('item.102');
const NOTE_ID = noteIdSchema.parse('note.1');

/** Built from code points so no raw control byte is stored in this file. */
const ESCAPE = String.fromCharCode(0x1b);
const BELL = String.fromCharCode(0x07);
const REPLACEMENT = String.fromCharCode(0xff_fd);

/**
 * A secret that must never reach a rendered purge result.
 *
 * Both purging commands destroy the last copy of something an operator once
 * stored, so a renderer that echoed it back would leave in terminal scrollback
 * exactly what the command was run to remove.
 */
const CANARY = 'canary-archived-secret';

function total(
  overrides: Partial<CategoryTotal> & Pick<CategoryTotal, 'category'>,
): CategoryTotal {
  return {
    purgeable: 0,
    retained: 0,
    serverRetained: 0,
    unsupported: 0,
    ...overrides,
  };
}

function previewResult(
  units: readonly PurgeUnit[],
  overrides: Partial<PreviewResult['plan']> = {},
  undiscoverable: PreviewResult['undiscoverableCategories'] = [],
): PreviewResult {
  return {
    vaultId: VAULT_ID,
    plan: {
      evaluatedAt: '2026-08-16T00:00:00.000Z',
      categories: ['archived-field', 'orphan-value', 'note'],
      units,
      totals: [total({ category: 'archived-field', purgeable: units.length })],
      purgeableCount: units.filter((unit) => unit.disposition === 'purgeable').length,
      retiredRelations: [],
      unreferencedAttachments: [],
      truncated: false,
      ...overrides,
    },
    undiscoverableCategories: undiscoverable,
  };
}

function fieldsResult(overrides: Partial<FieldsResult> = {}): FieldsResult {
  return {
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    groupName: 'Engineering',
    credentialId: ITEM_ID,
    title: 'Primary DB',
    purged: [
      {
        fieldKey: 'legacy_token',
        fieldLabel: 'Legacy token',
        reason: 'type-conversion',
        archivedAt: '2026-01-01T00:00:00.000Z',
        ageDays: 227,
      },
    ],
    retiredRelations: [],
    unreferencedAttachments: [],
    previousRevision: 4,
    revision: 5,
    ...overrides,
  };
}

function notesResult(overrides: Partial<NotesResult> = {}): NotesResult {
  return {
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    groupName: 'Engineering',
    purged: [
      {
        noteId: NOTE_ID,
        title: 'Old rotation runbook',
        archivedAt: '2026-01-01T00:00:00.000Z',
        ageDays: 227,
      },
    ],
    previousRevision: 7,
    revision: 8,
    ...overrides,
  };
}

describe('CLI purge preview command', () => {
  it('forwards no filter at all when none is given, because the vault is the default scope', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(
      previewResult([
        {
          category: 'archived-field',
          disposition: 'purgeable',
          groupId: GROUP_ID,
          groupName: 'Engineering',
          credentialId: ITEM_ID,
          credentialTitle: 'Primary DB',
          unitId: 'legacy_token',
          label: 'Legacy token',
          retiredAt: '2026-01-01T00:00:00.000Z',
          ageDays: 227,
        },
      ]),
    );

    const result = await execute(['purge', 'preview'], { previewPurge: preview.port });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(preview.calls()).toEqual([{}]);
    expect(result.stdout).toContain(
      'Purge preview at 2026-08-16T00:00:00.000Z (no retention window):',
    );
    expect(result.stdout).toContain('- [archived-field] Legacy token (purgeable)');
    expect(result.stdout).toContain('In: group Engineering, credential Primary DB');
    expect(result.stdout).toContain(
      'Retired: 2026-01-01T00:00:00.000Z (227 day(s) ago)',
    );
    expect(result.stdout).toContain('1 unit(s) would be destroyed permanently');
  });

  it('forwards each filter and names the retention window it was given', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(
      previewResult([], { olderThanDays: 90 }),
    );

    const result = await execute(
      [
        'purge',
        'preview',
        '--group',
        'Engineering',
        '--credential',
        'Primary DB',
        '--older-than',
        '90',
        '--category',
        'archived-field',
        '--category',
        'note',
      ],
      { previewPurge: preview.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(preview.calls()).toEqual([
      {
        groupQuery: 'Engineering',
        credentialQuery: 'Primary DB',
        olderThanDays: 90,
        categories: ['archived-field', 'note'],
      },
    ]);
    expect(result.stdout).toContain('retired more than 90 day(s) ago');
    expect(result.stdout).toContain('(nothing in scope)');
  });

  it('refuses a credential filter with no group, so the filter cannot silently widen', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(previewResult([]));

    const result = await execute(['purge', 'preview', '--credential', 'Primary DB'], {
      previewPurge: preview.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(preview.calls()).toEqual([]);
  });

  it('refuses an unknown category rather than silently examining every category', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(previewResult([]));

    const result = await execute(['purge', 'preview', '--category', 'everything'], {
      previewPurge: preview.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(preview.calls()).toEqual([]);
  });

  it.each([['0'], ['-1'], ['1.5'], ['36501'], ['ninety']])(
    'refuses the retention window %s before any vault is opened',
    async (window) => {
      const preview = capturing<PreviewRequest, PreviewResult>(previewResult([]));

      const result = await execute(['purge', 'preview', '--older-than', window], {
        previewPurge: preview.port,
      });

      expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
      expect(preview.calls()).toEqual([]);
    },
  );

  it('reports a retained unit and its reason instead of hiding it', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(
      previewResult(
        [
          {
            category: 'note',
            disposition: 'retained',
            reason: 'Retired 3 days ago, inside the requested 90-day retention window.',
            groupId: GROUP_ID,
            groupName: 'Engineering',
            unitId: NOTE_ID,
            label: 'Old rotation runbook',
            retiredAt: '2026-08-13T00:00:00.000Z',
            ageDays: 3,
          },
        ],
        {
          olderThanDays: 90,
          totals: [total({ category: 'note', retained: 1 })],
          purgeableCount: 0,
        },
      ),
    );

    const result = await execute(['purge', 'preview', '--older-than', '90'], {
      previewPurge: preview.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain(
      '- [note] Old rotation runbook (retained by the window)',
    );
    expect(result.stdout).toContain(
      'Why: Retired 3 days ago, inside the requested 90-day retention window.',
    );
    expect(result.stdout).toContain('note: 0 purgeable, 1 retained by the window');
    expect(result.stdout).toContain('0 unit(s) would be destroyed permanently');
  });

  it('states the server retention clock for a deleted record it may not destroy', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(
      previewResult(
        [
          {
            category: 'credential',
            disposition: 'server-retained',
            reason:
              "A deleted record is destroyed by the vault's own retention schedule.",
            groupId: GROUP_ID,
            groupName: 'Engineering',
            credentialId: TARGET_ID,
            unitId: TARGET_ID,
            label: TARGET_ID,
            retiredAt: '2026-06-01T00:00:00.000Z',
            ageDays: 76,
            tombstone: {
              deletedAt: '2026-06-01T00:00:00.000Z',
              purgeAfter: '2026-09-01T00:00:00.000Z',
            },
          },
        ],
        {
          totals: [total({ category: 'credential', serverRetained: 1 })],
          purgeableCount: 0,
        },
      ),
    );

    const result = await execute(['purge', 'preview'], { previewPurge: preview.port });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain(
      '- [credential] item.102 (retained by the server schedule)',
    );
    expect(result.stdout).toContain(
      'Server may destroy after: 2026-09-01T00:00:00.000Z',
    );
    expect(result.stdout).toContain(
      'credential: 0 purgeable, 0 retained by the window, 1 retained by the server',
    );
  });

  it('separates a category it cannot enumerate from one it enumerated and found empty', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(
      previewResult([], { totals: [total({ category: 'group' })] }, [
        {
          category: 'group',
          reason: 'A deleted group is absent from every vault listing.',
        },
      ]),
    );

    const result = await execute(['purge', 'preview'], { previewPurge: preview.port });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain(
      'group: A deleted group is absent from every vault listing.',
    );
  });

  it('says the plan was truncated instead of presenting it as the whole vault', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(
      previewResult([], { truncated: true }),
    );

    const result = await execute(['purge', 'preview'], { previewPurge: preview.port });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('stopped at its unit ceiling');
  });

  it('neutralizes terminal control bytes in every rendered identity', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(
      previewResult([
        {
          category: 'archived-field',
          disposition: 'purgeable',
          groupId: GROUP_ID,
          groupName: `Eng${ESCAPE}[31m`,
          credentialId: ITEM_ID,
          credentialTitle: `DB${BELL}`,
          unitId: 'legacy_token',
          label: `Legacy${ESCAPE}]0;pwned${BELL}`,
          retiredAt: '2026-01-01T00:00:00.000Z',
          ageDays: 227,
        },
      ]),
    );

    const result = await execute(['purge', 'preview'], { previewPurge: preview.port });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).not.toContain(ESCAPE);
    expect(result.stdout).not.toContain(BELL);
    expect(result.stdout).toContain(REPLACEMENT);
  });

  it('emits stable JSON that carries the plan and no field value', async () => {
    const preview = capturing<PreviewRequest, PreviewResult>(
      previewResult([
        {
          category: 'orphan-value',
          disposition: 'purgeable',
          groupId: GROUP_ID,
          groupName: 'Engineering',
          credentialId: ITEM_ID,
          credentialTitle: 'Primary DB',
          unitId: 'removed_field',
          label: 'Removed field',
          retiredAt: '2026-01-01T00:00:00.000Z',
          ageDays: 227,
        },
      ]),
    );

    const result = await execute(['purge', 'preview', '--json'], {
      previewPurge: preview.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    const parsed = JSON.parse(result.stdout) as {
      readonly plan: { readonly units: readonly { readonly unitId: string }[] };
    };
    expect(parsed.plan.units.map((unit) => unit.unitId)).toEqual(['removed_field']);
    expect(result.stdout).not.toContain(CANARY);
  });
});

describe('CLI purge fields command', () => {
  it('refuses to destroy anything without --force', async () => {
    const purge = capturing<FieldsRequest, FieldsResult>(fieldsResult());

    const result = await execute(['purge', 'fields', 'Engineering', 'Primary DB'], {
      purgeFields: purge.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain(
      'The --force flag is required for permanent field value purging.',
    );
    // The refusal must happen before the port is reached: an irreversible write
    // that already landed cannot be undone by reporting a usage error afterwards.
    expect(purge.calls()).toEqual([]);
  });

  it('forwards every filter and reports what it destroyed by identity only', async () => {
    const purge = capturing<FieldsRequest, FieldsResult>(fieldsResult());

    const result = await execute(
      [
        'purge',
        'fields',
        'Engineering',
        'Primary DB',
        '--field',
        'Legacy token',
        '--reason',
        'type-conversion',
        '--reason',
        'user-archived',
        '--older-than',
        '30',
        '--if-revision',
        '4',
        '--force',
      ],
      { purgeFields: purge.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(purge.calls()).toEqual([
      {
        groupQuery: 'Engineering',
        credentialQuery: 'Primary DB',
        fieldKey: 'Legacy token',
        reasons: ['type-conversion', 'user-archived'],
        olderThanDays: 30,
        ifRevision: 4,
      },
    ]);
    expect(result.stdout).toContain(
      'Permanently destroyed 1 archived value(s) of Primary DB (item.101) in Engineering:',
    );
    expect(result.stdout).toContain(
      '- Legacy token (legacy_token, type-conversion), archived 2026-01-01T00:00:00.000Z (227 day(s) ago)',
    );
    expect(result.stdout).toContain('Revision 4 -> 5.');
  });

  it('refuses an unknown archive reason rather than widening the sweep', async () => {
    const purge = capturing<FieldsRequest, FieldsResult>(fieldsResult());

    const result = await execute(
      [
        'purge',
        'fields',
        'Engineering',
        'Primary DB',
        '--reason',
        'because',
        '--force',
      ],
      { purgeFields: purge.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(purge.calls()).toEqual([]);
  });

  it('reports a sweep that matched nothing as an unchanged revision, not a success', async () => {
    const purge = capturing<FieldsRequest, FieldsResult>(
      fieldsResult({ purged: [], previousRevision: 4, revision: 4 }),
    );

    const result = await execute(
      ['purge', 'fields', 'Engineering', 'Primary DB', '--force'],
      { purgeFields: purge.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('nothing was destroyed');
    expect(result.stdout).toContain('Revision 4 is unchanged.');
  });

  it('names a retired relation and an attachment left unreferenced', async () => {
    const purge = capturing<FieldsRequest, FieldsResult>(
      fieldsResult({
        retiredRelations: [TARGET_ID],
        unreferencedAttachments: ['attachment.9'],
      }),
    );

    const result = await execute(
      ['purge', 'fields', 'Engineering', 'Primary DB', '--force'],
      { purgeFields: purge.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain(
      'Relation retired because no value binds it any more: item.102.',
    );
    expect(result.stdout).toContain(
      'Attachment left unreferenced: attachment.9; use `attachment delete --force` to unlink it.',
    );
  });

  it('never renders the destroyed value, in text or in JSON', async () => {
    const purge = capturing<FieldsRequest, FieldsResult>(
      fieldsResult({
        purged: [
          {
            fieldKey: 'legacy_token',
            fieldLabel: `Legacy token${ESCAPE}[0m`,
            reason: 'user-archived',
            archivedAt: '2026-01-01T00:00:00.000Z',
            ageDays: 227,
          },
        ],
      }),
    );

    const text = await execute(
      ['purge', 'fields', 'Engineering', 'Primary DB', '--force'],
      {
        purgeFields: purge.port,
      },
    );
    const json = await execute(
      ['purge', 'fields', 'Engineering', 'Primary DB', '--force', '--json'],
      { purgeFields: purge.port },
    );

    expect(text.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(json.exitCode).toBe(CLI_EXIT_CODES.success);
    for (const output of [text.stdout, json.stdout]) {
      expect(output).not.toContain(CANARY);
      expect(output).not.toContain(ESCAPE);
    }
    expect(text.stdout).toContain(REPLACEMENT);
  });
});

describe('CLI purge notes command', () => {
  it('refuses to destroy anything without --force', async () => {
    const purge = capturing<NotesRequest, NotesResult>(notesResult());

    const result = await execute(['purge', 'notes', 'Engineering'], {
      purgeNotes: purge.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(result.stderr).toContain(
      'The --force flag is required for permanent note purging.',
    );
    expect(purge.calls()).toEqual([]);
  });

  it("purges a group's own notes when no credential is named", async () => {
    const purge = capturing<NotesRequest, NotesResult>(notesResult());

    const result = await execute(
      [
        'purge',
        'notes',
        'Engineering',
        '--older-than',
        '30',
        '--if-revision',
        '7',
        '--force',
      ],
      { purgeNotes: purge.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(purge.calls()).toEqual([
      { groupQuery: 'Engineering', olderThanDays: 30, ifRevision: 7 },
    ]);
    expect(result.stdout).toContain(
      'Permanently destroyed 1 archived note(s) of Engineering (group.1):',
    );
    expect(result.stdout).toContain(
      '- Old rotation runbook (note.1), archived 2026-01-01T00:00:00.000Z (227 day(s) ago)',
    );
    expect(result.stdout).toContain('Revision 7 -> 8.');
  });

  it("purges one credential's notes when it is named", async () => {
    const purge = capturing<NotesRequest, NotesResult>(
      notesResult({ credentialId: ITEM_ID, credentialTitle: 'Primary DB' }),
    );

    const result = await execute(
      ['purge', 'notes', 'Engineering', '--credential', 'Primary DB', '--force'],
      { purgeNotes: purge.port },
    );

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(purge.calls()).toEqual([
      { groupQuery: 'Engineering', credentialQuery: 'Primary DB' },
    ]);
    expect(result.stdout).toContain(
      'Permanently destroyed 1 archived note(s) of Primary DB (item.101) in Engineering:',
    );
  });

  it('forwards a note ID unchanged and refuses a value that is not one', async () => {
    const accepted = capturing<NotesRequest, NotesResult>(notesResult());
    const rejected = capturing<NotesRequest, NotesResult>(notesResult());

    const byId = await execute(
      ['purge', 'notes', 'Engineering', '--note', 'note.1', '--force'],
      { purgeNotes: accepted.port },
    );
    // A title prefix is refused rather than resolved: this is the one command that
    // destroys a note, so resolving "Old" to whichever note happens to match is
    // exactly the guess that must not be available here.
    const byTitle = await execute(
      ['purge', 'notes', 'Engineering', '--note', 'Old rotation runbook', '--force'],
      { purgeNotes: rejected.port },
    );

    expect(byId.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(accepted.calls()).toEqual([{ groupQuery: 'Engineering', noteId: NOTE_ID }]);
    expect(byTitle.exitCode).toBe(CLI_EXIT_CODES.usage);
    expect(rejected.calls()).toEqual([]);
  });

  it('reports a sweep that matched nothing as an unchanged revision', async () => {
    const purge = capturing<NotesRequest, NotesResult>(
      notesResult({ purged: [], previousRevision: 7, revision: 7 }),
    );

    const result = await execute(['purge', 'notes', 'Engineering', '--force'], {
      purgeNotes: purge.port,
    });

    expect(result.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(result.stdout).toContain('nothing was destroyed');
    expect(result.stdout).toContain('Revision 7 is unchanged.');
  });

  it('never renders the destroyed note body, in text or in JSON', async () => {
    const purge = capturing<NotesRequest, NotesResult>(
      notesResult({
        purged: [
          {
            noteId: NOTE_ID,
            title: `Runbook${ESCAPE}[31m`,
            archivedAt: '2026-01-01T00:00:00.000Z',
            ageDays: 227,
          },
        ],
      }),
    );

    const text = await execute(['purge', 'notes', 'Engineering', '--force'], {
      purgeNotes: purge.port,
    });
    const json = await execute(['purge', 'notes', 'Engineering', '--force', '--json'], {
      purgeNotes: purge.port,
    });

    expect(text.exitCode).toBe(CLI_EXIT_CODES.success);
    expect(json.exitCode).toBe(CLI_EXIT_CODES.success);
    for (const output of [text.stdout, json.stdout]) {
      expect(output).not.toContain(CANARY);
      expect(output).not.toContain(ESCAPE);
    }
    expect(text.stdout).toContain(REPLACEMENT);
  });
});

describe('CLI purge command availability', () => {
  // An irreversible command with no adapter behind it must fail closed rather
  // than reach a partially-configured write path.
  it('reports an unconfigured preview adapter as unavailable rather than crashing', async () => {
    const result = await execute(['purge', 'preview']);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('purge preview is unavailable');
    expect(result.stdout).toBe('');
  });

  it('reports an unconfigured field-purge adapter as unavailable rather than crashing', async () => {
    const result = await execute([
      'purge',
      'fields',
      'Engineering',
      'Primary DB',
      '--force',
    ]);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('purge fields is unavailable');
    expect(result.stdout).toBe('');
  });

  it('reports an unconfigured note-purge adapter as unavailable rather than crashing', async () => {
    const result = await execute(['purge', 'notes', 'Engineering', '--force']);

    expect(result.exitCode).toBe(CLI_EXIT_CODES.unavailable);
    expect(result.stderr).toContain('purge notes is unavailable');
    expect(result.stdout).toBe('');
  });
});
