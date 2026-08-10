import { fieldScalarValueSchema, type FieldScalarValue } from '@kavrix/schemas';

import { RunnerError } from './errors.js';
import {
  INHERITABLE_ENVIRONMENT_NAMES,
  type EnvironmentMapping,
  type InheritableEnvironmentName,
} from './types.js';

const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;
const MAX_ENVIRONMENT_ENTRIES = 256;
const MAX_ENVIRONMENT_VALUE_BYTES = 16 * 1_024;
const MAX_ENVIRONMENT_TOTAL_BYTES = 32 * 1_024;

/** Variables with runtime loader, language-runtime, or shell startup effects. */
const RESERVED_MAPPING_NAMES = new Set([
  'BASH_ENV',
  'BUNDLE_GEMFILE',
  'CDPATH',
  'CLASSPATH',
  'COMSPEC',
  'DYLD_FRAMEWORK_PATH',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_LIBRARY_PATH',
  'ENV',
  'GLOBIGNORE',
  'GIT_ASKPASS',
  'GIT_CONFIG_COUNT',
  'GIT_CONFIG_GLOBAL',
  'GIT_CONFIG_SYSTEM',
  'HOME',
  'IFS',
  'JAVA_TOOL_OPTIONS',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'LD_AUDIT',
  'LD_LIBRARY_PATH',
  'LD_PRELOAD',
  'NODE_OPTIONS',
  'NODE_PATH',
  'NPM_CONFIG_USERCONFIG',
  'PATH',
  'PATHEXT',
  'PERL5OPT',
  'PROMPT_COMMAND',
  'PS4',
  'PYTHONHOME',
  'PYTHONINSPECT',
  'PYTHONPATH',
  'PYTHONSTARTUP',
  'RUBYLIB',
  'RUBYOPT',
  'SHELLOPTS',
  'SYSTEMROOT',
  'TEMP',
  'TMP',
  'TZ',
  'USERPROFILE',
  'WINDIR',
  '_JAVA_OPTIONS',
]);

const inheritableNames = new Set<string>(
  INHERITABLE_ENVIRONMENT_NAMES.map((name) => canonicalEnvironmentName(name)),
);

export type PreparedEnvironment = Readonly<{
  childEnvironment: NodeJS.ProcessEnv;
  secretBuffers: readonly Buffer[];
  secretValues: string[];
  clear(): void;
}>;

function canonicalEnvironmentName(name: string): string {
  // A portable mapping must also be unambiguous on Windows, where names are
  // case-insensitive. Applying that rule everywhere prevents a safe config on
  // one platform from becoming ambiguous on another.
  return name.toUpperCase();
}

function environmentValue(
  scalarInput: FieldScalarValue,
): Readonly<{ value: string; secret: boolean }> {
  const parsed = fieldScalarValueSchema.safeParse(scalarInput);
  if (!parsed.success) {
    throw new RunnerError('RUNNER_ENVIRONMENT_REJECTED');
  }

  const scalar = parsed.data;
  switch (scalar.kind) {
    case 'text':
      return { value: scalar.value, secret: false };
    case 'secret':
      return { value: scalar.value, secret: true };
    case 'number':
      return { value: String(scalar.value), secret: false };
    case 'boolean':
      return { value: scalar.value ? 'true' : 'false', secret: false };
    case 'environment-entry':
      return {
        value: scalar.value.value,
        secret: scalar.value.classification === 'secret',
      };
    case 'attachment-reference':
    case 'item-reference':
      throw new RunnerError('RUNNER_ENVIRONMENT_REJECTED');
  }
}

function assertEnvironmentValue(value: string): void {
  if (
    value.includes('\0') ||
    Buffer.byteLength(value, 'utf8') > MAX_ENVIRONMENT_VALUE_BYTES
  ) {
    throw new RunnerError('RUNNER_ENVIRONMENT_REJECTED');
  }
}

function parentValue(
  requestedName: InheritableEnvironmentName,
  parentEnvironment: NodeJS.ProcessEnv,
): Readonly<{ name: string; value: string }> | null {
  const canonicalRequestedName = canonicalEnvironmentName(requestedName);
  for (const [name, value] of Object.entries(parentEnvironment)) {
    if (
      value !== undefined &&
      canonicalEnvironmentName(name) === canonicalRequestedName
    ) {
      return { name, value };
    }
  }
  return null;
}

function addEnvironmentEntry(
  childEnvironment: NodeJS.ProcessEnv,
  occupiedNames: Set<string>,
  name: string,
  value: string,
): void {
  const canonicalName = canonicalEnvironmentName(name);
  if (occupiedNames.has(canonicalName)) {
    throw new RunnerError('RUNNER_ENVIRONMENT_REJECTED');
  }
  occupiedNames.add(canonicalName);
  childEnvironment[name] = value;
}

function environmentBytes(environment: NodeJS.ProcessEnv): number {
  let total = 1;
  for (const [name, value] of Object.entries(environment)) {
    if (value !== undefined) {
      total += Buffer.byteLength(`${name}=${value}\0`, 'utf8');
    }
  }
  return total;
}

export function prepareEnvironment(
  mappings: readonly EnvironmentMapping[],
  inheritedNames: readonly InheritableEnvironmentName[],
  parentEnvironment: NodeJS.ProcessEnv = process.env,
): PreparedEnvironment {
  if (
    mappings.length > MAX_ENVIRONMENT_ENTRIES ||
    inheritedNames.length > INHERITABLE_ENVIRONMENT_NAMES.length
  ) {
    throw new RunnerError('RUNNER_ENVIRONMENT_REJECTED');
  }

  const childEnvironment: NodeJS.ProcessEnv = Object.create(null) as NodeJS.ProcessEnv;
  const occupiedNames = new Set<string>();
  const secretBuffers: Buffer[] = [];
  const secretValues: string[] = [];

  try {
    for (const inheritedName of inheritedNames) {
      const canonicalName = canonicalEnvironmentName(inheritedName);
      if (!inheritableNames.has(canonicalName)) {
        throw new RunnerError('RUNNER_ENVIRONMENT_REJECTED');
      }
      const inherited = parentValue(inheritedName, parentEnvironment);
      if (inherited !== null) {
        assertEnvironmentValue(inherited.value);
        addEnvironmentEntry(
          childEnvironment,
          occupiedNames,
          inherited.name,
          inherited.value,
        );
      }
    }

    for (const mapping of mappings) {
      if (!Array.isArray(mapping)) {
        throw new RunnerError('RUNNER_ENVIRONMENT_REJECTED');
      }
      const [name, scalar] = mapping;
      if (
        typeof name !== 'string' ||
        !ENVIRONMENT_NAME.test(name) ||
        RESERVED_MAPPING_NAMES.has(canonicalEnvironmentName(name))
      ) {
        throw new RunnerError('RUNNER_ENVIRONMENT_REJECTED');
      }
      const converted = environmentValue(scalar);
      assertEnvironmentValue(converted.value);
      addEnvironmentEntry(childEnvironment, occupiedNames, name, converted.value);
      if (converted.secret) {
        secretValues.push(converted.value);
        secretBuffers.push(Buffer.from(converted.value, 'utf8'));
      }
    }

    if (environmentBytes(childEnvironment) > MAX_ENVIRONMENT_TOTAL_BYTES) {
      throw new RunnerError('RUNNER_ENVIRONMENT_REJECTED');
    }
  } catch (error) {
    for (const secret of secretBuffers) secret.fill(0);
    secretValues.fill('');
    for (const name of Object.keys(childEnvironment)) {
      Reflect.deleteProperty(childEnvironment, name);
    }
    throw error;
  }

  return {
    childEnvironment,
    secretBuffers,
    secretValues,
    clear(): void {
      for (const secret of secretBuffers) secret.fill(0);
      secretValues.fill('');
      for (const name of Object.keys(childEnvironment)) {
        Reflect.deleteProperty(childEnvironment, name);
      }
    },
  };
}
