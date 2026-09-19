import type { Command } from 'commander';

import { LocalCliError } from './cli-error.js';

/**
 * Product default for root CLI commands when neither a datastore profile nor
 * an explicit `--datastore` is selected.
 *
 * Aligned with `kavrix init`'s local-file quick-start so `put` / `get` /
 * `list` / `doctor` (and other root CRUD) never silently flip to MongoDB —
 * that mismatch was a launch footgun for first-run scripts.
 */
export const DEFAULT_ROOT_DATASTORE = 'file' as const;

export type RootDatastore = 'file' | 'mongodb';

export const ROOT_DATASTORE_OPTION_DESCRIPTION =
  'Encrypted datastore: file or mongodb.';

export const INVALID_ROOT_DATASTORE_MESSAGE = '--datastore must be mongodb or file.';

/**
 * Parse an explicit `--datastore` value. Invalid values throw
 * {@link LocalCliError} so the top-level runner exits non-zero.
 */
export function parseRootDatastore(value: string): RootDatastore {
  if (value === 'mongodb' || value === 'file') return value;
  throw new LocalCliError(INVALID_ROOT_DATASTORE_MESSAGE);
}

/**
 * Resolve the effective root datastore when no profile routing applies.
 * Omitted / `undefined` selects {@link DEFAULT_ROOT_DATASTORE}.
 */
export function resolveRootDatastore(value: string | undefined): RootDatastore {
  if (value === undefined) return DEFAULT_ROOT_DATASTORE;
  return parseRootDatastore(value);
}

/** Attach the shared `--datastore` option with the unified product default. */
export function addRootDatastoreOption(command: Command): Command {
  return command.option(
    '--datastore <type>',
    ROOT_DATASTORE_OPTION_DESCRIPTION,
    DEFAULT_ROOT_DATASTORE,
  );
}
