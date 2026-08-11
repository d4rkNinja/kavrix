export interface WorkflowRunQuery {
  readonly repository: string;
  readonly sha: string;
  readonly workflowPath: string;
}

export interface WorkflowRun {
  readonly id: number;
  readonly event: string;
  readonly status: string;
  readonly conclusion: string;
  readonly head_sha: string;
  readonly head_branch: string;
  readonly path: string;
  readonly repository: { readonly full_name: string };
  readonly head_repository: { readonly full_name: string };
  readonly [key: string]: unknown;
}

export interface WorkflowStep {
  readonly name: string;
  readonly status: string;
  readonly conclusion: string;
  readonly [key: string]: unknown;
}

export interface WorkflowJob {
  readonly name: string;
  readonly status: string;
  readonly conclusion: string;
  readonly steps: readonly WorkflowStep[];
  readonly [key: string]: unknown;
}

export interface WorkflowRunOptions {
  readonly apiUrl: string;
  readonly fetchImplementation?: typeof fetch;
  readonly repository: string;
  readonly sha: string;
  readonly token: string;
  readonly workflowPaths: readonly string[];
}

export type NpmReleaseChannel = 'beta' | 'latest';

export function resolveReleaseChannel(
  version: string,
  prerelease: boolean,
): NpmReleaseChannel;

export function validateReleaseChannel(
  version: string,
  prerelease: boolean,
  npmDistTag: unknown,
): void;

export function findExactSuccessfulPushRun(
  payload: unknown,
  query: WorkflowRunQuery,
): WorkflowRun;

export function findSuccessfulCodeQlAnalysisJob(payload: unknown): WorkflowJob;

export function requireExactSuccessfulWorkflowRuns(
  options: WorkflowRunOptions,
): Promise<void>;
