import { AmbiguousNameError, NotFoundError, ValidationError } from '../errors.js';

export type ResolvableEntity<TId extends string> = Readonly<{
  id: TId;
  name: string;
  slug?: string | undefined;
  aliases: readonly string[];
}>;

export function resolveNamedEntity<T extends ResolvableEntity<string>>(
  query: string,
  candidates: readonly T[],
): T {
  const exactQuery = normalizeExactValue(query);
  const normalizedQuery = normalizeLookupValue(query);
  if (normalizedQuery.length === 0) {
    throw new ValidationError('A non-empty name, alias, slug, or ID is required.');
  }

  const exactId = resolveMatchSet(
    candidates.filter((candidate) => candidate.id === query.trim()),
  );
  if (exactId !== undefined) return exactId;

  const caseSensitivePhases = [
    (candidate: T) =>
      (candidate.slug !== undefined &&
        normalizeExactValue(candidate.slug) === exactQuery) ||
      candidate.aliases.some((alias) => normalizeExactValue(alias) === exactQuery),
    (candidate: T) => normalizeExactValue(candidate.name) === exactQuery,
  ];
  for (const matchesPhase of caseSensitivePhases) {
    const exact = resolveMatchSet(candidates.filter(matchesPhase));
    if (exact !== undefined) return exact;
  }

  const caseInsensitive = resolveMatchSet(
    candidates.filter((candidate) =>
      [candidate.name, candidate.slug, ...candidate.aliases].some(
        (value) =>
          value !== undefined && normalizeLookupValue(value) === normalizedQuery,
      ),
    ),
  );
  if (caseInsensitive !== undefined) return caseInsensitive;

  const prefix = resolveMatchSet(
    candidates.filter((candidate) =>
      [candidate.id, candidate.name, candidate.slug, ...candidate.aliases].some(
        (value) =>
          value !== undefined &&
          normalizeLookupValue(value).startsWith(normalizedQuery),
      ),
    ),
  );
  if (prefix === undefined) throw new NotFoundError();
  return prefix;
}

function normalizeExactValue(value: string): string {
  return value.trim().normalize('NFKC');
}

function resolveMatchSet<T extends ResolvableEntity<string>>(
  matches: readonly T[],
): T | undefined {
  if (matches.length > 1) throw new AmbiguousNameError(matches.map(({ id }) => id));
  return matches[0];
}

export function normalizeLookupValue(value: string): string {
  return value.trim().normalize('NFKC').toLocaleLowerCase('und');
}
