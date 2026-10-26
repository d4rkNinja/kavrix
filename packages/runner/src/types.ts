import type { ChildProcess } from 'node:child_process';

import {
  SPAWN_FAILURE_CLI_ERROR_CODE,
  type CliErrorCode,
  type FieldScalarValue,
} from '@kavrix/schemas';

/**
 * CLI class for `RUNNER_SPAWN_FAILED`. Missing executables and other child
 * start failures are execution failures, not authorization denies.
 */
export const RUNNER_SPAWN_FAILED_CLI_ERROR_CODE: CliErrorCode =
  SPAWN_FAILURE_CLI_ERROR_CODE;

/** A destination variable and one canonical, already-decrypted field scalar. */
export type EnvironmentMapping = readonly [
  destinationName: string,
  value: FieldScalarValue,
];

/**
 * The only parent variables a caller may deliberately forward. The default is
 * an empty list; secrets are never inherited implicitly.
 *
 * PATH/HOME (and the rest of this list) may be copied from the parent.
 * USER/USERNAME/LOGNAME may also be inherited, but they are reserved
 * destinations and cannot be secret overwrite targets.
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
  'USER',
  'USERNAME',
  'LOGNAME',
] as const;

export type InheritableEnvironmentName = (typeof INHERITABLE_ENVIRONMENT_NAMES)[number];

/** Destination names a mapping may target, before the reserved-name check. */
export const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;

/**
 * Names refused as mapping destinations. Identity names (USER/USERNAME/LOGNAME)
 * are inheritable from the parent but never writable secret dests.
 */
export const RESERVED_ENVIRONMENT_NAMES = [
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
  'USER',
  'USERNAME',
  'LOGNAME',
  'USERPROFILE',
  'WINDIR',
  '_JAVA_OPTIONS',
] as const;

export type ReservedEnvironmentName = (typeof RESERVED_ENVIRONMENT_NAMES)[number];

const reservedEnvironmentNames = new Set<string>(
  RESERVED_ENVIRONMENT_NAMES.map((name) => name.toUpperCase()),
);

/**
 * Reports whether a destination name is refused as a mapping target. Names are
 * compared case-insensitively because Windows treats them that way, so a safe
 * mapping on one platform cannot become an override on another.
 */
export function isReservedEnvironmentName(name: string): boolean {
  return reservedEnvironmentNames.has(name.toUpperCase());
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
  // Mapped values (text or secret) stay under the tight secret-sized cap:
  // every mapped value is redaction-tracked or user-provided content, and no
  // legitimate credential-sized value belongs in an environment variable.
  maxEnvironmentValueBytes: 16 * 1_024,
  // Inherited values are allowlisted names copied verbatim from the parent
  // and are never treated as secrets. Windows caps a single variable at
  // 32,767 characters, and a real developer PATH there commonly exceeds the
  // 16 KiB secret cap, so inheritance gets this platform-sized cap instead.
  maxInheritedEnvironmentValueBytes: 32 * 1_024,
  // Whole child-environment budget (name=value\0 per entry). Sized for a
  // full-size Windows PATH plus the rest of the inherit allowlist and mapped
  // values on a real developer machine, with headroom for several of them.
  maxEnvironmentTotalBytes: 128 * 1_024,
});

export type RunnerOutputCapturePolicy = Readonly<{
  mode: 'capture';
  maxBytes?: number;
}>;

/**
 * Inherit mode streams child output straight to this process's streams. No
 * capture buffer exists, so secret redaction cannot be applied; callers that
 * need redacted output must use capture mode instead.
 */
export type RunnerOutputInheritPolicy = Readonly<{
  mode: 'inherit';
}>;

/**
 * Pipe mode hands the raw child streams to the caller through `onSpawn` and
 * buffers nothing. The caller owns consumption, framing, and lifecycle of the
 * streams; timeouts and aborts still terminate the child.
 */
export type RunnerOutputPipePolicy = Readonly<{
  mode: 'pipe';
}>;

export type RunnerOutputPolicy =
  RunnerOutputCapturePolicy | RunnerOutputInheritPolicy | RunnerOutputPipePolicy;

/**
 * How the child's stdin is provided. With `pipe`, stdin is opened as a pipe
 * that is reachable only through the `onSpawn` handle: the consumer must
 * write to and then end (or destroy) `child.stdin` itself. Nothing writes or
 * closes it automatically, so a consumer that never wires stdin owns the
 * resulting child lifetime — a child reading stdin waits on the open pipe.
 */
export type RunnerInputPolicy = 'ignore' | 'inherit' | 'pipe';

export type SecureRunRequest = Readonly<{
  executable: string;
  arguments?: readonly string[];
  cwd: string;
  environment?: readonly EnvironmentMapping[];
  inheritEnvironment?: readonly InheritableEnvironmentName[];
  output?: RunnerOutputPolicy;
  input?: RunnerInputPolicy;
  timeoutMs?: number;
  terminationGraceMs?: number;
  signal?: AbortSignal;
  /**
   * Delivers the child handle to the consumer immediately after spawn: for
   * observation and supervisor concerns such as signal forwarding, and — with
   * `input: 'pipe'` — as the only access to the child's stdin. In that case
   * the consumer must write to and end (or destroy) `child.stdin` itself;
   * nothing in the runner writes, closes, or drains it, so a consumer that
   * never wires stdin keeps the child's stdin pipe open for the child's
   * whole lifetime.
   */
  onSpawn?: (child: ChildProcess) => void;
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
