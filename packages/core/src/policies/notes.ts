import {
  noteCollectionSchema,
  noteSchema,
  type Note,
  type NoteId,
  type SecretValue,
} from '@kavrix/schemas';

import { NotFoundError, ValidationError } from '../errors.js';

export type NoteUpdate = Readonly<{
  title?: string;
  content?: SecretValue;
  isSensitive?: boolean;
  isPinned?: boolean;
  tags?: readonly string[];
}>;

export function addNote(notes: readonly Note[], note: Note): readonly Note[] {
  if (notes.some((candidate) => candidate.id === note.id)) {
    throw new ValidationError('A note with this ID already exists.');
  }
  return noteCollectionSchema.parse([...notes, note]);
}

export function updateNote(
  notes: readonly Note[],
  noteId: NoteId,
  update: NoteUpdate,
  updatedAt: string,
): readonly Note[] {
  return replaceNote(notes, noteId, (note) =>
    noteSchema.parse({
      ...note,
      ...update,
      tags: update.tags === undefined ? note.tags : [...update.tags],
      updatedAt,
    }),
  );
}

export function archiveNote(
  notes: readonly Note[],
  noteId: NoteId,
  timestamp: string,
): readonly Note[] {
  return replaceNote(notes, noteId, (note) =>
    noteSchema.parse({ ...note, archivedAt: timestamp, updatedAt: timestamp }),
  );
}

export function restoreNote(
  notes: readonly Note[],
  noteId: NoteId,
  timestamp: string,
): readonly Note[] {
  return replaceNote(notes, noteId, (note) => {
    const active = { ...note };
    delete active.archivedAt;
    return noteSchema.parse({ ...active, updatedAt: timestamp });
  });
}

export function deleteNote(notes: readonly Note[], noteId: NoteId): readonly Note[] {
  if (!notes.some((note) => note.id === noteId)) throw new NotFoundError();
  return noteCollectionSchema.parse(notes.filter((note) => note.id !== noteId));
}

export function duplicateNote(
  notes: readonly Note[],
  sourceId: NoteId,
  duplicateId: NoteId,
  timestamp: string,
): readonly Note[] {
  const source = notes.find((note) => note.id === sourceId);
  if (!source) throw new NotFoundError();
  const active = { ...source };
  delete active.archivedAt;
  return addNote(
    notes,
    noteSchema.parse({
      ...active,
      id: duplicateId,
      title: `${source.title} (copy)`,
      isPinned: false,
      sortOrder: notes.length,
      createdAt: timestamp,
      updatedAt: timestamp,
    }),
  );
}

export function reorderNotes(
  notes: readonly Note[],
  orderedIds: readonly NoteId[],
  timestamp: string,
): readonly Note[] {
  if (orderedIds.length !== notes.length || new Set(orderedIds).size !== notes.length) {
    throw new ValidationError('The note order must contain every note exactly once.');
  }
  const byId = new Map(notes.map((note) => [note.id, note]));
  return noteCollectionSchema.parse(
    orderedIds.map((id, sortOrder) => {
      const note = byId.get(id);
      if (!note) throw new ValidationError('The note order contains an unknown note.');
      return { ...note, sortOrder, updatedAt: timestamp };
    }),
  );
}

function replaceNote(
  notes: readonly Note[],
  noteId: NoteId,
  replacement: (note: Note) => Note,
): readonly Note[] {
  if (!notes.some((note) => note.id === noteId)) throw new NotFoundError();
  const updated = notes.map((note) => {
    if (note.id !== noteId) return note;
    return replacement(note);
  });
  return noteCollectionSchema.parse(updated);
}
