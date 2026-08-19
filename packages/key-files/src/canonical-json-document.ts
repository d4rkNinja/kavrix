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
  callback:
    | ((current: T) => ProtectedJsonDocumentTransition<T, Result>)
    | ((current: T) => Promise<ProtectedJsonDocumentTransition<T, Result>>),
): Promise<Result> {
  return withExclusiveSecureFile(path, options.maximumBytes, async (lock) => {
    let bytes: Uint8Array | undefined;
    let replacement: Uint8Array | undefined;
    try {
      bytes = await readSecureFileWhileExclusive(lock);
      const current = parseCanonicalDocument(bytes, options.schema);
      const transition = await callback(current);
      replacement = serializeCanonicalDocument(
        transition.document,
        options.schema,
        options.maximumBytes,
      );
      await replaceSecureFileWhileExclusive(lock, replacement);
      return transition.result;
    } finally {
      bytes?.fill(0);
      replacement?.fill(0);
    }
  });
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
