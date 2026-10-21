import { z } from 'zod';

/**
 * Request contract for locally generated secrets. The generator lives in
 * `@kavrix/core`; the CLI builds one request from flags and never accepts a
 * generated value from argv.
 */
export const SECRET_GENERATION_FORMATS = ['password', 'hex', 'base64url'] as const;
export const MIN_GENERATED_SECRET_LENGTH = 8;
export const MAX_GENERATED_SECRET_LENGTH = 1024;
export const DEFAULT_GENERATED_SECRET_LENGTH = 32;

export const secretGenerationFormatSchema = z.enum(SECRET_GENERATION_FORMATS);

export const secretGenerationRequestSchema = z
  .object({
    format: secretGenerationFormatSchema,
    length: z
      .number()
      .int()
      .min(MIN_GENERATED_SECRET_LENGTH)
      .max(MAX_GENERATED_SECRET_LENGTH),
    lowercase: z.boolean(),
    uppercase: z.boolean(),
    digits: z.boolean(),
    symbols: z.boolean(),
    excludeAmbiguous: z.boolean(),
  })
  .strict()
  .superRefine((request, context) => {
    if (request.format !== 'password') return;
    const classes = [
      request.lowercase,
      request.uppercase,
      request.digits,
      request.symbols,
    ].filter(Boolean).length;
    if (classes === 0) {
      context.addIssue({
        code: 'custom',
        message: 'A password needs at least one character class',
        path: ['format'],
      });
    }
  });

export type SecretGenerationFormat = z.infer<typeof secretGenerationFormatSchema>;
export type SecretGenerationRequest = z.infer<typeof secretGenerationRequestSchema>;
