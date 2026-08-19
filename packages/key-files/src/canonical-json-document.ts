import { canonicalJson } from '@kavrix/schemas';

import { PortableKeyFileError } from './errors.js';
import {
  readSecureFile,
  readSecureFileWhileExclusive,
  replaceSecureFileWhileExclusive,
  withExclusiveSecureFile,
  writeSecureFile,
} from './filesystem.js';

/** A caller-provided strict runtime parser for a non-secret JSON document. */
export type CanonicalJsonDocumentSchema<T> = Readonly<{
  parse(value: unknown): T;
}>;

export type ProtectedJsonDocumentOptions<T> = Readonly<{
  schema: CanonicalJsonDocumentSchema<T>;
  maximumBytes: number;
}>;

export type ProtectedJsonDocumentTransition<T, Result> = Readonly<{
  document: T;
  result: Result;
}>;

const protectedJsonDocumentPublicationBrand = Symbol(
  'protectedJsonDocumentPublication',
);

/**
 * Runtime-opaque evidence that a canonical document replacement started. It
 * intentionally exposes no path, lock, identity, prior bytes, or intended
 * bytes and has no deletion authority.
 */
export type ProtectedJsonDocumentPublication = Readonly<{
  readonly [protectedJsonDocumentPublicationBrand]: true;
}>;

export type ProtectedJsonDocumentTransitionPublicationResult<Result> =
  | Readonly<{
      status: 'not-published';
      error: Error;
    }>
  | Readonly<{
      status: 'published';
      result: Result;
      publication: ProtectedJsonDocumentPublication;
    }>
  | Readonly<{
      status: 'publication-uncertain';
      publication: ProtectedJsonDocumentPublication;
      error: Error;
    }>;

type ProtectedJsonDocumentTransitionCallback<T, Result> =
  | ((current: T) => ProtectedJsonDocumentTransition<T, Result>)
  | ((current: T) => Promise<ProtectedJsonDocumentTransition<T, Result>>);

const protectedJsonDocumentPublications = new WeakSet<object>();

export class ProtectedJsonDocumentError extends Error {
  public constructor() {
    super('The protected JSON document is invalid.');
    this.name = 'ProtectedJsonDocumentError';
  }
}

/** Reads a bounded, strict, canonically serialized JSON document as a clone. */
export async function readProtectedJsonDocument<T>(
  path: string,
  options: ProtectedJsonDocumentOptions<T>,
): Promise<T> {
  let bytes: Uint8Array | undefined;
  try {
    bytes = await readSecureFile(path, options.maximumBytes);
    return parseCanonicalDocument(bytes, options.schema);
  } finally {
    bytes?.fill(0);
  }
}

/** Creates or replaces a strict canonical JSON document through protected publication. */
export async function writeProtectedJsonDocument<T>(
  path: string,
  document: T,
  mode: 'create' | 'replace',
  options: ProtectedJsonDocumentOptions<T>,
): Promise<void> {
  let bytes: Uint8Array | undefined;
  try {
    bytes = serializeCanonicalDocument(document, options.schema, options.maximumBytes);
    await writeSecureFile(path, bytes, mode, options.maximumBytes);
  } finally {
    bytes?.fill(0);
  }
}

/**
 * Runs one canonical JSON state transition under the protected-file lock. The
 * callback receives a cloned parsed document only; filesystem handles, paths,
 * identities, raw bytes, and replacement operations remain internal.
 */
export async function transitionProtectedJsonDocument<T, Result>(
  path: string,
  options: ProtectedJsonDocumentOptions<T>,
  callback: ProtectedJsonDocumentTransitionCallback<T, Result>,
): Promise<Result> {
  const publication = await transitionProtectedJsonDocumentWithPublicationStatus(
    path,
    options,
    callback,
  );
  if (publication.status === 'published') return publication.result;
  throw publication.error;
}

/**
 * Runs one protected canonical transition and returns a closed publication
 * result. A replacement error is read back under the same cooperative lock:
 * exact prior bytes prove non-publication, while intended or foreign bytes are
 * retained as uncertainty. The opaque capability is evidence only and cannot
 * be used to restore or delete a document.
 */
export async function transitionProtectedJsonDocumentWithPublicationStatus<T, Result>(
  path: string,
  options: ProtectedJsonDocumentOptions<T>,
  callback: ProtectedJsonDocumentTransitionCallback<T, Result>,
): Promise<ProtectedJsonDocumentTransitionPublicationResult<Result>> {
  let callbackOutcome:
    ProtectedJsonDocumentTransitionPublicationResult<Result> | undefined;
  try {
    return await withExclusiveSecureFile(path, options.maximumBytes, async (lock) => {
      let prior: Uint8Array | undefined;
      let replacement: Uint8Array | undefined;
      try {
        prior = await readSecureFileWhileExclusive(lock);
        const current = parseCanonicalDocument(prior, options.schema);
        let transition: ProtectedJsonDocumentTransition<T, Result>;
        try {
          transition = await callback(current);
          replacement = serializeCanonicalDocument(
            transition.document,
            options.schema,
            options.maximumBytes,
          );
        } catch (error) {
          callbackOutcome = {
            status: 'not-published',
            error: asTransitionError(error),
          };
          return callbackOutcome;
        }

        const publication = newProtectedJsonDocumentPublication();
        try {
          await replaceSecureFileWhileExclusive(lock, replacement);
          callbackOutcome = {
            status: 'published',
            result: transition.result,
            publication,
          };
          return callbackOutcome;
        } catch (error) {
          const publicationError = asPublicationError(error);
          const readback = await readbackPublication(
            lock,
            options.schema,
            prior,
            replacement,
          );
          if (readback === 'prior') {
            callbackOutcome = {
              status: 'not-published',
              error: publicationError,
            };
            return callbackOutcome;
          }
          callbackOutcome = {
            status: 'publication-uncertain',
            publication,
            error: publicationError,
          };
          return callbackOutcome;
        }
      } catch (error) {
        callbackOutcome = {
          status: 'not-published',
          error: asTransitionError(error),
        };
        return callbackOutcome;
      } finally {
        prior?.fill(0);
        replacement?.fill(0);
      }
    });
  } catch (error) {
    if (
      callbackOutcome?.status === 'published' ||
      callbackOutcome?.status === 'publication-uncertain'
    ) {
      return {
        status: 'publication-uncertain',
        publication: callbackOutcome.publication,
        error: asPublicationError(error),
      };
    }
    return {
      status: 'not-published',
      error: asPublicationError(error),
    };
  }
}

function newProtectedJsonDocumentPublication(): ProtectedJsonDocumentPublication {
  const publication = Object.freeze({});
  protectedJsonDocumentPublications.add(publication);
  return publication as ProtectedJsonDocumentPublication;
}

async function readbackPublication<T>(
  lock: Parameters<typeof readSecureFileWhileExclusive>[0],
  schema: CanonicalJsonDocumentSchema<T>,
  prior: Uint8Array,
  replacement: Uint8Array,
): Promise<'prior' | 'intended' | 'foreign-or-unreadable'> {
  let observed: Uint8Array | undefined;
  try {
    observed = await readSecureFileWhileExclusive(lock);
    parseCanonicalDocument(observed, schema);
    if (sameBytes(observed, prior) && !sameBytes(prior, replacement)) return 'prior';
    if (sameBytes(observed, replacement)) return 'intended';
    return 'foreign-or-unreadable';
  } catch {
    return 'foreign-or-unreadable';
  } finally {
    observed?.fill(0);
  }
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  return left.every((value, index) => value === right[index]);
}

function asTransitionError(error: unknown): Error {
  return error instanceof Error
    ? error
    : new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
}

function asPublicationError(error: unknown): Error {
  return error instanceof PortableKeyFileError ||
    error instanceof ProtectedJsonDocumentError
    ? error
    : new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
}

function parseCanonicalDocument<T>(
  bytes: Uint8Array,
  schema: CanonicalJsonDocumentSchema<T>,
): T {
  try {
    const text = Buffer.from(bytes).toString('utf8');
    if (Buffer.byteLength(text, 'utf8') !== bytes.byteLength) throw invalid();
    const parsed = schema.parse(JSON.parse(text) as unknown);
    if (canonicalJson(parsed) !== text) throw invalid();
    return cloneDocument(parsed, schema);
  } catch (error) {
    if (
      error instanceof PortableKeyFileError ||
      error instanceof ProtectedJsonDocumentError
    ) {
      throw error;
    }
    throw invalid();
  }
}

function serializeCanonicalDocument<T>(
  document: T,
  schema: CanonicalJsonDocumentSchema<T>,
  maximumBytes: number,
): Uint8Array {
  try {
    const parsed = schema.parse(document);
    const canonical = canonicalJson(parsed);
    const bytes = Buffer.from(canonical, 'utf8');
    if (bytes.byteLength === 0 || bytes.byteLength > maximumBytes) {
      bytes.fill(0);
      throw invalid();
    }
    cloneDocument(parsed, schema);
    return bytes;
  } catch (error) {
    if (
      error instanceof PortableKeyFileError ||
      error instanceof ProtectedJsonDocumentError
    ) {
      throw error;
    }
    throw invalid();
  }
}

function cloneDocument<T>(document: T, schema: CanonicalJsonDocumentSchema<T>): T {
  return schema.parse(JSON.parse(canonicalJson(document)) as unknown);
}

function invalid(): ProtectedJsonDocumentError {
  return new ProtectedJsonDocumentError();
}
