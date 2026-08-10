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
