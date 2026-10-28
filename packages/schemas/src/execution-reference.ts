import { z } from 'zod';

const referencePartSchema = z
  .string()
  .min(1)
  .max(256)
  .refine(
    (value) => value.trim() === value,
    'Reference parts must use exact canonical names',
  )
  .refine(
    // eslint-disable-next-line no-control-regex
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    'Reference parts must not contain controls',
  );

export const structuredExecutionReferenceSchema = z
  .object({
    context: referencePartSchema,
    service: referencePartSchema,
    item: referencePartSchema,
    field: referencePartSchema,
  })
  .strict();

export type StructuredExecutionReference = z.infer<
  typeof structuredExecutionReferenceSchema
>;

/** Canonical, unambiguous reference shared by policies, grants, projects and runs. */
export function executionReference(input: StructuredExecutionReference): string {
  const parsed = structuredExecutionReferenceSchema.parse(input);
  const reference = `field:${[parsed.context, parsed.service, parsed.item, parsed.field].map(encodeURIComponent).join('/')}`;
  if (reference.length > 256)
    throw new Error('Execution reference exceeds the supported length.');
  return reference;
}

export function parseExecutionReference(
  reference: string,
): ({ kind: 'field' } & StructuredExecutionReference) | { kind: 'flat'; name: string } {
  if (!reference.startsWith('field:')) return { kind: 'flat', name: reference };
  const parts = reference.slice(6).split('/');
  if (parts.length !== 4) throw new Error('Structured execution reference is invalid.');
  let decoded: string[];
  try {
    decoded = parts.map(decodeURIComponent);
  } catch {
    throw new Error('Structured execution reference is invalid.');
  }
  const parsed = structuredExecutionReferenceSchema.safeParse({
    context: decoded[0],
    service: decoded[1],
    item: decoded[2],
    field: decoded[3],
  });
  if (!parsed.success || executionReference(parsed.data) !== reference)
    throw new Error('Structured execution reference is invalid.');
  return { kind: 'field', ...parsed.data };
}

/** Legacy structured reveal policies remain restrictive during migration. */
export function executionReferenceAliases(reference: string): readonly string[] {
  const parsed = parseExecutionReference(reference);
  return parsed.kind === 'flat'
    ? [reference]
    : [reference, `${parsed.context}/${parsed.service}/${parsed.item}/${parsed.field}`];
}
