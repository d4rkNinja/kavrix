import { z } from 'zod';

const setupPath = z
  .string()
  .min(1)
  .max(4096)
  .refine((value) => !value.includes('\0'));
export const setupToolActionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('browse-setup-folders'), path: setupPath }).strict(),
  z
    .object({
      type: z.literal('repair-setup-directory'),
      path: setupPath,
      mode: z.enum(['preview', 'apply']),
    })
    .strict(),
  z
    .object({
      type: z.literal('test-setup-mongodb'),
      databaseUrl: z.string().min(1).max(4096),
      database: z.string().min(1).max(128),
    })
    .strict(),
]);
export type SetupToolAction = Readonly<z.infer<typeof setupToolActionSchema>>;

export const setupToolResultSchema = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('folders'),
      directory: setupPath,
      parent: setupPath,
      entries: z
        .array(z.object({ name: z.string().min(1).max(255), path: setupPath }).strict())
        .max(100),
      truncated: z.boolean(),
    })
    .strict(),
  z
    .object({
      kind: z.literal('repair'),
      directory: setupPath,
      mode: z.enum(['preview', 'apply']),
    })
    .strict(),
  z
    .object({
      kind: z.literal('connection'),
      status: z.enum(['ok', 'invalid', 'transport', 'authentication', 'unreachable']),
    })
    .strict(),
]);
export type SetupToolResult = Readonly<z.infer<typeof setupToolResultSchema>>;
export const setupProgressSchema = z
  .object({
    stage: z.enum([
      'checking-permissions',
      'connecting',
      'creating-storage',
      'creating-vault',
      'creating-recovery',
      'verifying-recovery',
    ]),
  })
  .strict();
export type SetupProgress = Readonly<z.infer<typeof setupProgressSchema>>;
