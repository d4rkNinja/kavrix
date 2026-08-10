export type RunnerErrorCode =
  | 'RUNNER_ABORTED'
  | 'RUNNER_ENVIRONMENT_REJECTED'
  | 'RUNNER_INVALID_CWD'
  | 'RUNNER_INVALID_REQUEST'
  | 'RUNNER_SECRET_IN_ARGUMENTS'
  | 'RUNNER_SPAWN_FAILED';

const messages = {
  RUNNER_ABORTED: 'The child process was cancelled before it started.',
  RUNNER_ENVIRONMENT_REJECTED: 'The child environment is not safe to construct.',
  RUNNER_INVALID_CWD: 'The child working directory is not a valid directory.',
  RUNNER_INVALID_REQUEST: 'The child process request is invalid.',
  RUNNER_SECRET_IN_ARGUMENTS:
    'A mapped secret cannot be included in the executable or argument list.',
  RUNNER_SPAWN_FAILED: 'The child process could not be started.',
} as const satisfies Readonly<Record<RunnerErrorCode, string>>;

export class RunnerError extends Error {
  public override readonly name = 'RunnerError';

  public constructor(public readonly code: RunnerErrorCode) {
    super(messages[code]);
  }
}
