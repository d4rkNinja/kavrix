import { readFile } from 'node:fs/promises';

import { parse as parseYaml } from 'yaml';

import {
  normalizeProjectConfigAliases,
  projectConfigDocumentSchema,
  type PermissionEntry,
  type ProjectConfigDocument,
} from '@kavrix/schemas';

import { invalidConfiguration } from './exit-codes.js';

const MAX_PROJECT_CONFIG_BYTES = 128 * 1024;

/**
 * Loads a non-secret project file (`kavrix.yaml` or `.json`). The file may
 * carry credential references and permission definitions only; strict schema
 * validation fails closed on unknown keys, and every load re-validates so a
 * tampered or hand-edited file can never bypass the contract.
 */
export async function loadProjectConfig(
  path: string,
): Promise<Readonly<{ document: ProjectConfigDocument }>> {
  let raw: Buffer;
  try {
    raw = await readFile(path);
  } catch {
    throw invalidConfiguration(`Project configuration could not be read: ${path}`);
  }
  if (raw.byteLength === 0 || raw.byteLength > MAX_PROJECT_CONFIG_BYTES) {
    throw invalidConfiguration('Project configuration is empty or exceeds 128 KiB.');
  }
  const text = raw.toString('utf8');
  const parsed: unknown = path.endsWith('.json')
    ? parseJson(text)
    : parseYamlDocument(text);
  const normalized = normalizeProjectConfigAliases(parsed);
  const result = projectConfigDocumentSchema.safeParse(normalized);
  if (!result.success) {
    throw invalidConfiguration(
      'Project configuration is invalid. Only version 1 documents with credential references are accepted.',
    );
  }
  return { document: result.data };
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw invalidConfiguration('Project configuration is not valid JSON.');
  }
}

function parseYamlDocument(text: string): unknown {
  try {
    return parseYaml(text) as unknown;
  } catch {
    throw invalidConfiguration('Project configuration is not valid YAML.');
  }
}

/** Resolves one environment's secret mappings in declaration order. */
export function environmentMappings(
  document: ProjectConfigDocument,
  environmentName: string,
): readonly (readonly [destination: string, secret: string])[] {
  const environment = document.environments?.[environmentName];
  if (environment === undefined) {
    throw invalidConfiguration(
      `Project environment '${environmentName}' is not defined.`,
    );
  }
  return Object.entries(environment.secrets ?? {}).map(
    ([destination, secret]) => [destination, secret] as const,
  );
}

/** Collects every policy definition from a project document by identifier. */
export function projectPolicies(
  document: ProjectConfigDocument,
): ReadonlyMap<string, PermissionEntry> {
  const policies = new Map<string, PermissionEntry>();
  for (const [id, entry] of Object.entries(document.policies ?? {})) {
    policies.set(id, entry);
  }
  for (const environment of Object.values(document.environments ?? {})) {
    for (const [id, entry] of Object.entries(environment.policies ?? {})) {
      if (!policies.has(id)) policies.set(id, entry);
    }
  }
  return policies;
}
