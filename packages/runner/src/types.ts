import type { FieldScalarValue } from '@kavrix/schemas';

/** A destination variable and one canonical, already-decrypted field scalar. */
export type EnvironmentMapping = readonly [
  destinationName: string,
  value: FieldScalarValue,
];

/**
 * The only parent variables a caller may deliberately forward. The default is
 * an empty list; secrets are never inherited implicitly.
 */
export const INHERITABLE_ENVIRONMENT_NAMES = [
  'PATH',
  'PATHEXT',
  'SystemRoot',
  'WINDIR',
  'COMSPEC',
  'TEMP',
  'TMP',
  'HOME',
  'USERPROFILE',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
] as const;

export type InheritableEnvironmentName = (typeof INHERITABLE_ENVIRONMENT_NAMES)[number];

/** Destination names a mapping may target, before the reserved-name check. */
export const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;

/** Variables with runtime loader, language-runtime, or shell startup effects. */
const RESERVED_ENVIRONMENT_NAMES = new Set([
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

/**
 * Reports whether a destination name is refused as a mapping target. Names are
 * compared case-insensitively because Windows treats them that way, so a safe
 * mapping on one platform cannot become an override on another.
 */
export function isReservedEnvironmentName(name: string): boolean {
  return RESERVED_ENVIRONMENT_NAMES.has(name.toUpperCase());
}

/**
 * Request bounds a composer must respect before spawning. They are published so
 * callers can reject an out-of-range request as a usage error instead of
 * duplicating the numbers and drifting from what the executor enforces.
 */
export const RUNNER_LIMITS = Object.freeze({
  maxArguments: 1_024,
  maxArgumentBytes: 128 * 1_024,
  defaultCaptureBytes: 64 * 1_024,
  maxCaptureBytes: 16 * 1_024 * 1_024,
  maxTimeoutMs: 24 * 60 * 60 * 1_000,
  defaultTerminationGraceMs: 1_000,
  maxTerminationGraceMs: 60_000,
  maxEnvironmentEntries: 256,
  maxEnvironmentValueBytes: 16 * 1_024,
  maxEnvironmentTotalBytes: 32 * 1_024,
});

export type RunnerOutputPolicy = Readonly<{
  mode: 'capture';
  maxBytes?: number;
}>;

export type SecureRunRequest = Readonly<{
  executable: string;
  arguments?: readonly string[];
  cwd: string;
  environment?: readonly EnvironmentMapping[];
  inheritEnvironment?: readonly InheritableEnvironmentName[];
  output?: RunnerOutputPolicy;
  timeoutMs?: number;
  terminationGraceMs?: number;
  signal?: AbortSignal;
}>;

export type RunTermination = 'exit' | 'signal' | 'timeout' | 'aborted' | 'output-limit';

export type SecureRunResult = Readonly<{
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  termination: RunTermination;
  outputTruncated: boolean;
  stdout?: Buffer;
  stderr?: Buffer;
}>;
