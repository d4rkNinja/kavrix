import { z } from 'zod';

import { noteIdSchema } from './identifiers.js';
import {
  nonEmptyTextSchema,
  secretValueSchema,
  sortOrderSchema,
  timestampSchema,
} from './primitives.js';

export const noteSchema = z
  .object({
    id: noteIdSchema,
    title: nonEmptyTextSchema,
    content: secretValueSchema,
    isSensitive: z.boolean(),
    isPinned: z.boolean(),
    tags: z.array(z.string().trim().min(1).max(128)).max(256),
    sortOrder: sortOrderSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    archivedAt: timestampSchema.optional(),
  })
  .strict();

export const noteCollectionSchema = z
  .array(noteSchema)
  .max(10_000)
  .superRefine((notes, context) => {
    const ids = new Set<string>();
    for (const [index, note] of notes.entries()) {
      if (ids.has(note.id)) {
        context.addIssue({
          code: 'custom',
          message: 'Note IDs must be unique',
          path: [index, 'id'],
        });
      }
      ids.add(note.id);
    }
  });

export type Note = z.infer<typeof noteSchema>;
export type NoteCollection = z.infer<typeof noteCollectionSchema>;
