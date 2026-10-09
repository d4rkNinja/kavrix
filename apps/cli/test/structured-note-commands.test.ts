import { readFile } from 'node:fs/promises';

import {
  CLI_EXIT_CODES,
  noteIdSchema,
  timestampSchema,
  vaultIdSchema,
  type StructuredVaultPayload,
} from '@kavrix/schemas';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  addStructuredNote,
  createStructuredItem,
  displayStructuredNoteContent,
  projectStructuredNotes,
  removeStructuredNote,
  resolveItem,
  resolveProjectContext,
  resolveService,
  structuredNoteReference,
} from '../src/structured-vault-impl.js';
import {
  DEFAULT_PROJECT_CONTEXT_NAME,
  DEFAULT_SERVICE_NAME,
  createEmptyStructuredVaultPayload,
} from '../src/structured-vault-projection.js';
import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';

const at = timestampSchema.parse('2026-08-29T00:00:00.000Z');
const CANARY = 'structured-note-plaintext-canary-3f9a1c';

let fixture: ExecutionFixture;

beforeAll(async () => {
  fixture = await createExecutionFixture({});
  const created = await runCli(
    [
      'item',
      'create',
      'runbook',
      '--context',
      DEFAULT_PROJECT_CONTEXT_NAME,
      '--service',
      DEFAULT_SERVICE_NAME,
      ...fixture.routingArgs,
      '--passphrase-stdin',
      '--json',
    ],
    frames(EXEC_PASSPHRASE),
  );
  expect(created.exitCode).toBe(CLI_EXIT_CODES.ok);
  expect(JSON.parse(created.stdout)).toMatchObject({
    created: true,
    type: 'item',
    title: 'runbook',
  });
});

afterAll(async () => {
  await destroyFixture(fixture);
});

function itemPayload(): StructuredVaultPayload {
  return createStructuredItem(
    createEmptyStructuredVaultPayload(vaultIdSchema.parse('vault_notes'), at),
    DEFAULT_PROJECT_CONTEXT_NAME,
    DEFAULT_SERVICE_NAME,
    'database/prod',
    at,
  );
}

function notePayload(): StructuredVaultPayload {
  let payload = addStructuredNote(
    itemPayload(),
    DEFAULT_PROJECT_CONTEXT_NAME,
    DEFAULT_SERVICE_NAME,
    'database/prod',
    { title: 'Recovery hint', content: 'call the on-call engineer', now: at },
  ).payload;
  payload = addStructuredNote(
    payload,
    DEFAULT_PROJECT_CONTEXT_NAME,
    DEFAULT_SERVICE_NAME,
    'database/prod',
    { title: 'Break-glass', content: CANARY, sensitive: true, pinned: true, now: at },
  ).payload;
  return payload;
}

function itemOf(payload: StructuredVaultPayload) {
  const context = resolveProjectContext(payload, DEFAULT_PROJECT_CONTEXT_NAME);
  const service = resolveService(payload, context.id, DEFAULT_SERVICE_NAME);
  return resolveItem(payload, service.id, 'database/prod');
}

function noteRoutes(args: readonly string[]): readonly string[] {
  return [...args, ...fixture.routingArgs];
}

function frames(...values: readonly string[]): string {
  return values.map((value) => `${value}\n`).join('');
}

function parseJson(stdout: string): Record<string, unknown> {
  return JSON.parse(stdout) as Record<string, unknown>;
}

describe('structured note command model', () => {
  it('attaches notes to an item and projects metadata without the body', () => {
    const item = itemOf(notePayload());
    const notes = projectStructuredNotes(item);

    expect(notes.map((note) => note.title)).toEqual(['Recovery hint', 'Break-glass']);
    expect(notes.map((note) => note.sensitive)).toEqual([false, true]);
    expect(notes.map((note) => note.pinned)).toEqual([false, true]);
    expect(notes.every((note) => noteIdSchema.safeParse(note.id).success)).toBe(true);
    const serialized = JSON.stringify(notes);
    expect(serialized).not.toContain(CANARY);
    expect(serialized).not.toContain('call the on-call engineer');
    expect(item.revision).toBe(2);
    expect(item.notes).toHaveLength(2);
  });

  it('masks a sensitive body by default and reveals it only when authorized', () => {
    const notes = itemOf(notePayload()).notes;

    expect(displayStructuredNoteContent(notes[0]!, false)).toBe(
      'call the on-call engineer',
    );
    expect(displayStructuredNoteContent(notes[1]!, false)).toBe('[REDACTED]');
    expect(displayStructuredNoteContent(notes[1]!, true)).toBe(CANARY);
  });

  it('fails closed on invalid titles, empty bodies, duplicates, and unknown notes', () => {
    expect(() =>
      addStructuredNote(
        createEmptyStructuredVaultPayload(vaultIdSchema.parse('vault_notes'), at),
        DEFAULT_PROJECT_CONTEXT_NAME,
        DEFAULT_SERVICE_NAME,
        'database/prod',
        { title: 'Any', content: 'body', now: at },
      ),
    ).toThrow('Credential item was not found.');
    const payload = itemPayload();
    const add = (title: string, content: string) =>
      addStructuredNote(
        payload,
        DEFAULT_PROJECT_CONTEXT_NAME,
        DEFAULT_SERVICE_NAME,
        'database/prod',
        { title, content, now: at },
      );
    expect(() => add('   ', 'body')).toThrow('Note title is invalid.');
    expect(() => add('Any', '')).toThrow('Note content is empty.');

    const withNotes = notePayload();
    expect(() =>
      addStructuredNote(
        withNotes,
        DEFAULT_PROJECT_CONTEXT_NAME,
        DEFAULT_SERVICE_NAME,
        'database/prod',
        { title: 'Recovery hint', content: 'another body', now: at },
      ),
    ).toThrow('already exists');
    expect(() =>
      removeStructuredNote(
        withNotes,
        DEFAULT_PROJECT_CONTEXT_NAME,
        DEFAULT_SERVICE_NAME,
        'database/prod',
        'note_missing',
        at,
      ),
    ).toThrow('Note was not found.');
    expect(() =>
      removeStructuredNote(
        withNotes,
        DEFAULT_PROJECT_CONTEXT_NAME,
        DEFAULT_SERVICE_NAME,
        'database/prod',
        'not an opaque id',
        at,
      ),
    ).toThrow('Note ID is invalid.');
  });

  it('archives a removed note instead of discarding its encrypted record', () => {
    const payload = notePayload();
    const target = itemOf(payload).notes[0]!;
    const removed = removeStructuredNote(
      payload,
      DEFAULT_PROJECT_CONTEXT_NAME,
      DEFAULT_SERVICE_NAME,
      'database/prod',
      target.id,
      '2026-08-29T00:00:05.000Z',
    ).payload;

    const item = itemOf(removed);
    expect(projectStructuredNotes(item).map((note) => note.title)).toEqual([
      'Break-glass',
    ]);
    expect(item.notes).toHaveLength(2);
    expect(item.notes.find((note) => note.id === target.id)).toMatchObject({
      archivedAt: '2026-08-29T00:00:05.000Z',
    });
    expect(() =>
      removeStructuredNote(
        removed,
        DEFAULT_PROJECT_CONTEXT_NAME,
        DEFAULT_SERVICE_NAME,
        'database/prod',
        target.id,
        at,
      ),
    ).toThrow('Note was not found.');
  });

  it('bounds the authorization-policy reference for one note', () => {
    expect(structuredNoteReference('context', 'service', 'item', 'note_01J')).toBe(
      'context/service/item/note_01J',
    );
    expect(() =>
      structuredNoteReference('c'.repeat(300), 'service', 'item', 'note_01J'),
    ).toThrow('too long for authorization policy');
  });
});

describe('kavrix note (file datastore, database container)', () => {
  it('add → list → show → remove round-trips through the encrypted vault', async () => {
    const created = parseJson(
      (
        await runCli(
          noteRoutes([
            'note',
            'add',
            'runbook',
            'Rotation notes',
            '--context',
            DEFAULT_PROJECT_CONTEXT_NAME,
            '--service',
            DEFAULT_SERVICE_NAME,
            '--passphrase-stdin',
            '--content-stdin',
            '--json',
          ]),
          frames(EXEC_PASSPHRASE, 'rotate weekly and verify the caller'),
        )
      ).stdout,
    );
    expect(created).toMatchObject({ added: true, type: 'note', sensitive: false });
    const noteId = String(created['id']);
    expect(noteIdSchema.safeParse(noteId).success).toBe(true);

    const listed = parseJson(
      (
        await runCli(
          noteRoutes([
            'note',
            'list',
            'runbook',
            '--context',
            DEFAULT_PROJECT_CONTEXT_NAME,
            '--service',
            DEFAULT_SERVICE_NAME,
            '--passphrase-stdin',
            '--json',
          ]),
          frames(EXEC_PASSPHRASE),
        )
      ).stdout,
    );
    expect(listed['notes']).toEqual([
      expect.objectContaining({ id: noteId, title: 'Rotation notes' }),
    ]);
    expect(JSON.stringify(listed)).not.toContain('rotate weekly');

    const shown = parseJson(
      (
        await runCli(
          noteRoutes([
            'note',
            'show',
            'runbook',
            noteId,
            '--context',
            DEFAULT_PROJECT_CONTEXT_NAME,
            '--service',
            DEFAULT_SERVICE_NAME,
            '--passphrase-stdin',
            '--json',
          ]),
          frames(EXEC_PASSPHRASE),
        )
      ).stdout,
    );
    expect(shown).toMatchObject({
      id: noteId,
      title: 'Rotation notes',
      sensitive: false,
      content: 'rotate weekly and verify the caller',
    });

    const removed = parseJson(
      (
        await runCli(
          noteRoutes([
            'note',
            'remove',
            'runbook',
            noteId,
            '--context',
            DEFAULT_PROJECT_CONTEXT_NAME,
            '--service',
            DEFAULT_SERVICE_NAME,
            '--passphrase-stdin',
            '--json',
          ]),
          frames(EXEC_PASSPHRASE),
        )
      ).stdout,
    );
    expect(removed).toMatchObject({ removed: true, type: 'note', id: noteId });
    const afterRemoval = parseJson(
      (
        await runCli(
          noteRoutes([
            'note',
            'list',
            'runbook',
            '--context',
            DEFAULT_PROJECT_CONTEXT_NAME,
            '--service',
            DEFAULT_SERVICE_NAME,
            '--passphrase-stdin',
            '--json',
          ]),
          frames(EXEC_PASSPHRASE),
        )
      ).stdout,
    );
    expect(afterRemoval['notes']).toEqual([]);
  });

  it('masks a sensitive note body until an explicit reveal is authorized', async () => {
    const created = parseJson(
      (
        await runCli(
          noteRoutes([
            'note',
            'add',
            'runbook',
            'Break-glass',
            '--sensitive',
            '--pin',
            '--context',
            DEFAULT_PROJECT_CONTEXT_NAME,
            '--service',
            DEFAULT_SERVICE_NAME,
            '--passphrase-stdin',
            '--content-stdin-base64',
            '--json',
          ]),
          frames(EXEC_PASSPHRASE, Buffer.from(CANARY, 'utf8').toString('base64')),
        )
      ).stdout,
    );
    expect(created).toMatchObject({
      added: true,
      type: 'note',
      sensitive: true,
      pinned: true,
    });
    const noteId = String(created['id']);

    const masked = await runCli(
      noteRoutes([
        'note',
        'show',
        'runbook',
        noteId,
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--passphrase-stdin',
        '--json',
      ]),
      frames(EXEC_PASSPHRASE),
    );
    expect(masked.exitCode).toBe(CLI_EXIT_CODES.ok);
    expect(parseJson(masked.stdout)['content']).toBe('[REDACTED]');
    expect(masked.stdout).not.toContain(CANARY);

    const revealed = await runCli(
      noteRoutes([
        'note',
        'show',
        'runbook',
        noteId,
        '--reveal',
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--passphrase-stdin',
        '--json',
      ]),
      frames(EXEC_PASSPHRASE),
    );
    expect(revealed.exitCode).toBe(CLI_EXIT_CODES.ok);
    expect(parseJson(revealed.stdout)['content']).toBe(CANARY);
  });

  it('fails closed on unknown items, contexts, and notes', async () => {
    const missingItem = await runCli(
      noteRoutes([
        'note',
        'list',
        'not/an/item',
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--passphrase-stdin',
        '--json',
      ]),
      frames(EXEC_PASSPHRASE),
    );
    expect(missingItem.exitCode).toBe(CLI_EXIT_CODES.unclassifiedFailure);
    expect(missingItem.stderr).toContain('Credential item was not found.');

    const missingContext = await runCli(
      noteRoutes([
        'note',
        'list',
        'runbook',
        '--context',
        'not/a/context',
        '--service',
        DEFAULT_SERVICE_NAME,
        '--passphrase-stdin',
        '--json',
      ]),
      frames(EXEC_PASSPHRASE),
    );
    expect(missingContext.exitCode).toBe(CLI_EXIT_CODES.unclassifiedFailure);

    const missingNote = await runCli(
      noteRoutes([
        'note',
        'show',
        'runbook',
        'note_01JDOESNOTEXIST',
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--passphrase-stdin',
        '--json',
      ]),
      frames(EXEC_PASSPHRASE),
    );
    expect(missingNote.exitCode).toBe(CLI_EXIT_CODES.unclassifiedFailure);
    expect(missingNote.stderr).toContain('Note was not found.');

    const invalidNote = await runCli(
      noteRoutes([
        'note',
        'remove',
        'runbook',
        'note with spaces',
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--passphrase-stdin',
        '--json',
      ]),
      frames(EXEC_PASSPHRASE),
    );
    expect(invalidNote.exitCode).toBe(CLI_EXIT_CODES.unclassifiedFailure);
    expect(invalidNote.stderr).toContain('Note ID is invalid.');
  });

  it('never places a note body in argv and never stores it as plaintext', async () => {
    const canaryNote = 'note-body-canary-7ac19783';
    const argv: string[] = [
      'note',
      'add',
      'runbook',
      'Canary',
      '--context',
      DEFAULT_PROJECT_CONTEXT_NAME,
      '--service',
      DEFAULT_SERVICE_NAME,
      ...fixture.routingArgs,
      '--passphrase-stdin',
      '--content-stdin',
      '--json',
    ];
    expect(argv.some((argument) => argument.includes(canaryNote))).toBe(false);

    const added = await runCli(argv, frames(EXEC_PASSPHRASE, canaryNote));
    expect(added.exitCode).toBe(CLI_EXIT_CODES.ok);
    expect(added.stdout).not.toContain(canaryNote);
    expect(added.stderr).not.toContain(canaryNote);

    const listed = await runCli(
      noteRoutes([
        'note',
        'list',
        'runbook',
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--passphrase-stdin',
        '--json',
      ]),
      frames(EXEC_PASSPHRASE),
    );
    expect(listed.exitCode).toBe(CLI_EXIT_CODES.ok);
    expect(listed.stdout).not.toContain(canaryNote);
    expect(listed.stderr).not.toContain(canaryNote);

    const stored = await readFile(fixture.dataFile);
    expect(stored.includes(Buffer.from(canaryNote, 'utf8'))).toBe(false);
    expect(stored.includes(Buffer.from(EXEC_PASSPHRASE, 'utf8'))).toBe(false);
  });

  it('refuses conflicting note-body stdin flags and half-framed secret input', async () => {
    const conflict = await runCli(
      noteRoutes([
        'note',
        'add',
        'runbook',
        'Conflicting',
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--content-stdin',
        '--content-stdin-base64',
      ]),
      frames(EXEC_PASSPHRASE, 'body'),
    );
    expect(conflict.exitCode).toBe(CLI_EXIT_CODES.unclassifiedFailure);
    expect(conflict.stderr).toContain(
      'Use either --content-stdin or --content-stdin-base64, not both.',
    );

    const partial = await runCli(
      noteRoutes([
        'note',
        'add',
        'runbook',
        'Partial',
        '--context',
        DEFAULT_PROJECT_CONTEXT_NAME,
        '--service',
        DEFAULT_SERVICE_NAME,
        '--content-stdin',
      ]),
      frames(EXEC_PASSPHRASE, 'body'),
    );
    expect(partial.exitCode).toBe(CLI_EXIT_CODES.invalidConfiguration);
    expect(partial.stderr).toContain('Missing --passphrase-stdin');
  });
});
