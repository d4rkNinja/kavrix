import {
  executionReference,
  executionReferenceAliases,
  parseExecutionReference,
  structuredExecutionReferenceSchema,
  type StructuredVaultPayload,
} from '@kavrix/schemas';
import {
  DEFAULT_PROJECT_CONTEXT_ID,
  DEFAULT_SERVICE_ID,
  DEFAULT_VALUE_FIELD_KEY,
} from '../structured-vault-projection.js';

/** Deny and reveal rules follow the authenticated compatibility projection. */
export function executionReferenceIdentities(
  payload: StructuredVaultPayload,
  reference: string,
): readonly string[] {
  const aliases = new Set(executionReferenceAliases(reference));
  const context = payload.projectContexts.find(
    (entry) => entry.id === DEFAULT_PROJECT_CONTEXT_ID,
  );
  const group = payload.groups.find(
    (entry) =>
      entry.id === DEFAULT_SERVICE_ID && entry.projectContextId === context?.id,
  );
  if (context === undefined || group === undefined) return [...aliases];
  const parsed = parseExecutionReference(reference);
  if (parsed.kind === 'field') {
    if (
      parsed.context === context.name &&
      parsed.service === group.name &&
      parsed.field === DEFAULT_VALUE_FIELD_KEY
    )
      aliases.add(parsed.item);
  } else {
    const candidate = structuredExecutionReferenceSchema.safeParse({
      context: context.name,
      service: group.name,
      item: reference,
      field: DEFAULT_VALUE_FIELD_KEY,
    });
    if (candidate.success) {
      const parts = Object.values(candidate.data);
      // Legacy names may contain lone surrogates and may exceed URI limits.
      if (parts.every((part) => Buffer.from(part, 'utf8').toString('utf8') === part)) {
        const encoded =
          'field:' +
          [
            candidate.data.context,
            candidate.data.service,
            candidate.data.item,
            candidate.data.field,
          ]
            .map(encodeURIComponent)
            .join('/');
        if (encoded.length <= 256)
          for (const alias of executionReferenceAliases(
            executionReference(candidate.data),
          ))
            aliases.add(alias);
      }
    }
  }
  return [...aliases];
}
