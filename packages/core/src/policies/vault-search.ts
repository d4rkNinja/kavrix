import type {
  ActiveFieldValue,
  FieldDefinition,
  GroupPayload,
  ItemPayload,
  Note,
} from '@kavrix/schemas';

import { ValidationError } from '../errors.js';
import { normalizeLookupValue } from './name-resolution.js';

/** Longest term the local matcher accepts, so a hostile query cannot force unbounded scanning. */
export const MAX_VAULT_SEARCH_TERM_LENGTH = 256;
/** Hard ceiling on returned hits, independent of what a caller requests. */
export const MAX_VAULT_SEARCH_RESULTS = 200;
/** Hits returned when a caller states no preference. */
export const DEFAULT_VAULT_SEARCH_RESULT_LIMIT = 50;
/** Matches reported for one hit before the remainder is summarised as truncated. */
export const MAX_VAULT_SEARCH_MATCHES_PER_HIT = 16;

/**
 * Where a match was found.
 *
 * The vocabulary is deliberately coarse: it names the property that matched and
 * never carries the matched text, so a result can be rendered or serialised
 * without becoming a decryption oracle for the value that produced it.
 */
export type VaultSearchMatchSource =
  | 'group-name'
  | 'group-slug'
  | 'group-alias'
  | 'group-tag'
  | 'group-description'
  | 'group-note-title'
  | 'group-note-content'
  | 'title'
  | 'slug'
  | 'alias'
  | 'subtitle'
  | 'tag'
  | 'environment'
  | 'owner'
  | 'purpose'
  | 'note-title'
  | 'note-content'
  | 'field-label'
  | 'field-value';

/**
 * One reported match.
 *
 * `locator` names the note or field that matched — never the matched text and
 * never a surrounding snippet.
 */
export type VaultSearchMatch = Readonly<{
  source: VaultSearchMatchSource;
  locator?: string;
}>;

export type VaultSearchHit =
  | Readonly<{
      kind: 'group';
      groupId: GroupPayload['id'];
      groupName: string;
      matches: readonly VaultSearchMatch[];
      matchesTruncated: boolean;
    }>
  | Readonly<{
      kind: 'credential';
      groupId: GroupPayload['id'];
      groupName: string;
      credentialId: ItemPayload['id'];
      title: string;
      matches: readonly VaultSearchMatch[];
      matchesTruncated: boolean;
    }>;

export type VaultSearchOptions = Readonly<{
  /**
   * Opt in to matching secret field values for this invocation only.
   *
   * Even when enabled, a field is searched only if its own definition permits
   * local search and permits reveal.
   */
  includeSecretValues: boolean;
  /** Include archived groups, credentials, and notes. Deleted records are never included. */
  includeArchived: boolean;
  limit?: number;
}>;

/** One group and the credentials read from it, already decrypted in memory. */
export type VaultSearchScope = Readonly<{
  group: GroupPayload;
  credentials: readonly ItemPayload[];
}>;

export type VaultSearchResult = Readonly<{
  hits: readonly VaultSearchHit[];
  /** Entities that matched, including those beyond the limit. */
  matchedCount: number;
  truncated: boolean;
  scannedGroups: number;
  scannedCredentials: number;
}>;

/**
 * Folds a raw query into the single comparable form used on both sides of every
 * comparison, and refuses a query that cannot narrow anything.
 */
export function normalizeVaultSearchTerm(term: string): string {
  if (term.length > MAX_VAULT_SEARCH_TERM_LENGTH) {
    throw new ValidationError(
      `A search term cannot exceed ${String(MAX_VAULT_SEARCH_TERM_LENGTH)} characters.`,
    );
  }
  const normalized = normalizeLookupValue(term);
  if (normalized.length === 0) {
    throw new ValidationError('A non-empty search term is required.');
  }
  return normalized;
}

/**
 * Decides whether a field's stored value may be matched at all.
 *
 * A field opted out of local search is never scanned. A sensitive field is
 * scanned only when the caller enabled secret-value search for this invocation
 * *and* the field's own reveal policy permits reading it — a `never`-reveal
 * field must not become a search oracle for a value it refuses to show.
 */
export function isFieldValueSearchable(
  definition: FieldDefinition,
  options: Pick<VaultSearchOptions, 'includeSecretValues'>,
): boolean {
  if (!definition.searchableLocally) return false;
  if (!definition.sensitive) return true;
  return options.includeSecretValues && definition.revealPolicy !== 'never';
}

/**
 * Matches a term against already-decrypted vault records.
 *
 * The scan is pure and in-memory: it builds no index, persists nothing, and
 * sends nothing anywhere. Results name the properties that matched and never
 * echo the matched text.
 */
export function searchVault(
  scopes: readonly VaultSearchScope[],
  term: string,
  options: VaultSearchOptions,
): VaultSearchResult {
  const needle = normalizeVaultSearchTerm(term);
  const limit = resolveLimit(options.limit);

  const hits: VaultSearchHit[] = [];
  let matchedCount = 0;
  let scannedGroups = 0;
  let scannedCredentials = 0;

  for (const { group, credentials } of scopes) {
    if (!isSearchable(group, options)) continue;
    scannedGroups += 1;

    const groupMatches = collectGroupMatches(group, needle, options);
    if (groupMatches.matches.length > 0) {
      matchedCount += 1;
      if (hits.length < limit) {
        hits.push(
          Object.freeze({
            kind: 'group' as const,
            groupId: group.id,
            groupName: group.name,
            matches: Object.freeze([...groupMatches.matches]),
            matchesTruncated: groupMatches.truncated,
          }),
        );
      }
    }

    const templateDefinitions = new Map(
      group.template.fields.map((definition) => [definition.id, definition] as const),
    );
    for (const credential of credentials) {
      if (!isSearchable(credential, options)) continue;
      scannedCredentials += 1;

      const found = collectCredentialMatches(
        credential,
        templateDefinitions,
        needle,
        options,
      );
      if (found.matches.length === 0) continue;
      matchedCount += 1;
      if (hits.length < limit) {
        hits.push(
          Object.freeze({
            kind: 'credential' as const,
            groupId: group.id,
            groupName: group.name,
            credentialId: credential.id,
            title: credential.title,
            matches: Object.freeze([...found.matches]),
            matchesTruncated: found.truncated,
          }),
        );
      }
    }
  }

  return Object.freeze({
    hits: Object.freeze(hits),
    matchedCount,
    truncated: matchedCount > hits.length,
    scannedGroups,
    scannedCredentials,
  });
}

/** Accumulates matches for one hit, deduplicated by source and locator. */
interface MatchAccumulator {
  readonly matches: VaultSearchMatch[];
  readonly seen: Set<string>;
  truncated: boolean;
}

function accumulator(): MatchAccumulator {
  return { matches: [], seen: new Set<string>(), truncated: false };
}

function record(
  into: MatchAccumulator,
  source: VaultSearchMatchSource,
  haystack: string | undefined,
  needle: string,
  locator?: string,
): void {
  if (haystack === undefined) return;
  if (!normalizeLookupValue(haystack).includes(needle)) return;

  const key = `${source}\u0000${locator ?? ''}`;
  if (into.seen.has(key)) return;
  into.seen.add(key);

  if (into.matches.length >= MAX_VAULT_SEARCH_MATCHES_PER_HIT) {
    into.truncated = true;
    return;
  }
  into.matches.push(
    locator === undefined
      ? Object.freeze({ source })
      : Object.freeze({ source, locator }),
  );
}

/** Deleted records are never searchable; archived records only on request. */
function isSearchable(
  record_: Readonly<{
    archivedAt?: string | undefined;
    deletedAt?: string | undefined;
  }>,
  options: VaultSearchOptions,
): boolean {
  if (record_.deletedAt !== undefined) return false;
  return record_.archivedAt === undefined || options.includeArchived;
}

function collectGroupMatches(
  group: GroupPayload,
  needle: string,
  options: VaultSearchOptions,
): MatchAccumulator {
  const into = accumulator();
  record(into, 'group-name', group.name, needle);
  record(into, 'group-slug', group.slug, needle);
  for (const alias of group.aliases) record(into, 'group-alias', alias, needle);
  for (const tag of group.tags) record(into, 'group-tag', tag, needle);
  record(into, 'group-description', group.description, needle);
  recordNotes(
    into,
    group.notes,
    needle,
    options,
    'group-note-title',
    'group-note-content',
  );
  return into;
}

function collectCredentialMatches(
  credential: ItemPayload,
  templateDefinitions: ReadonlyMap<string, FieldDefinition>,
  needle: string,
  options: VaultSearchOptions,
): MatchAccumulator {
  const into = accumulator();
  record(into, 'title', credential.title, needle);
  record(into, 'slug', credential.slug, needle);
  for (const alias of credential.aliases) record(into, 'alias', alias, needle);
  record(into, 'subtitle', credential.subtitle, needle);
  for (const tag of credential.tags) record(into, 'tag', tag, needle);
  record(into, 'environment', credential.environment, needle);
  record(into, 'owner', credential.owner, needle);
  record(into, 'purpose', credential.purpose, needle);
  recordNotes(into, credential.notes, needle, options, 'note-title', 'note-content');

  // Item-only definitions cannot shadow template fields, so a flat merge is exact.
  const definitions = new Map(templateDefinitions);
  for (const definition of credential.itemFields)
    definitions.set(definition.id, definition);
  for (const definition of definitions.values()) {
    record(into, 'field-label', definition.label, needle, definition.label);
  }

  for (const stored of [...credential.templateValues, ...credential.itemValues]) {
    const definition = definitions.get(stored.fieldId);
    // An unknown definition means unknown sensitivity, so the value is skipped
    // rather than assumed safe. Archived field values are excluded entirely.
    if (definition === undefined) continue;
    if (!isFieldValueSearchable(definition, options)) continue;
    for (const text of searchableText(stored.value, options)) {
      record(into, 'field-value', text, needle, definition.label);
    }
  }
  return into;
}

function recordNotes(
  into: MatchAccumulator,
  notes: readonly Note[],
  needle: string,
  options: VaultSearchOptions,
  titleSource: VaultSearchMatchSource,
  contentSource: VaultSearchMatchSource,
): void {
  for (const note of notes) {
    if (!isSearchable(note, options)) continue;
    record(into, titleSource, note.title, needle, note.title);
    // A sensitive note's body is never a search target; its title still is.
    if (note.isSensitive) continue;
    record(into, contentSource, note.content, needle, note.title);
  }
}

/**
 * The text a stored value contributes to matching.
 *
 * Only textual scalars participate. Numbers, booleans, and opaque references
 * carry no local search meaning, and an environment entry's secret-classified
 * value is withheld unless the caller enabled secret-value search — the
 * containing field can be non-sensitive while individual entries are not.
 */
function searchableText(
  value: ActiveFieldValue,
  options: VaultSearchOptions,
): readonly string[] {
  if (value.state !== 'present') return [];
  const scalars =
    value.content.cardinality === 'single'
      ? [value.content.value]
      : value.content.elements.map(({ value: scalar }) => scalar);

  const texts: string[] = [];
  for (const scalar of scalars) {
    if (scalar.kind === 'text' || scalar.kind === 'secret') {
      texts.push(scalar.value);
      continue;
    }
    if (scalar.kind !== 'environment-entry') continue;
    texts.push(scalar.key);
    if (scalar.value.classification === 'text' || options.includeSecretValues) {
      texts.push(scalar.value.value);
    }
  }
  return texts;
}

function resolveLimit(limit: number | undefined): number {
  if (limit === undefined) return DEFAULT_VAULT_SEARCH_RESULT_LIMIT;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_VAULT_SEARCH_RESULTS) {
    throw new ValidationError(
      `A search limit must be a whole number between 1 and ${String(MAX_VAULT_SEARCH_RESULTS)}.`,
    );
  }
  return limit;
}
