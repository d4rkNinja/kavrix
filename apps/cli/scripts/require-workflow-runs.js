import { pathToFileURL } from 'node:url';
import process from 'node:process';

const repositoryPattern = /^[a-zA-Z0-9][a-zA-Z0-9._-]*\/[a-zA-Z0-9][a-zA-Z0-9._-]*$/u;
const workflowPathPattern = /^\.github\/workflows\/[a-zA-Z0-9._-]+\.ya?ml$/u;
const shaPattern = /^[0-9a-f]{40}$/u;
const semverNumber = '(?:0|[1-9][0-9]*)';
const stableVersionPattern = new RegExp(
  `^${semverNumber}\\.${semverNumber}\\.${semverNumber}$`,
  'u',
);
const betaVersionPattern = new RegExp(
  `^${semverNumber}\\.${semverNumber}\\.${semverNumber}-beta\\.${semverNumber}$`,
  'u',
);

export function resolveReleaseChannel(version, prerelease) {
  const normalizedVersion = requiredString(version, 'package version');
  if (typeof prerelease !== 'boolean') {
    throw new Error('GitHub release prerelease state must be boolean.');
  }
  if (stableVersionPattern.test(normalizedVersion)) {
    if (prerelease) {
      throw new Error(
        'A stable package version requires a non-prerelease GitHub release.',
      );
    }
    return 'latest';
  }
  if (betaVersionPattern.test(normalizedVersion)) {
    if (!prerelease) {
      throw new Error('A beta package version requires a prerelease GitHub release.');
    }
    return 'beta';
  }
  throw new Error(
    'Only stable X.Y.Z or beta X.Y.Z-beta.N package versions may be released.',
  );
}

export function validateReleaseChannel(version, prerelease, npmDistTag) {
  const expected = resolveReleaseChannel(version, prerelease);
  if (npmDistTag !== expected) {
    throw new Error(
      `The ${version} release requires the npm ${expected} dist-tag, not ${String(npmDistTag)}.`,
    );
  }
}

export function findExactSuccessfulPushRun(payload, query) {
  assertQuery(query);
  if (!isRecord(payload) || !Array.isArray(payload.workflow_runs)) {
    throw new Error('GitHub Actions API returned an invalid workflow-runs response.');
  }

  const runs = payload.workflow_runs.map((candidate) => parseWorkflowRun(candidate));
  const run = runs.find(
    (candidate) =>
      candidate.event === 'push' &&
      candidate.status === 'completed' &&
      candidate.conclusion === 'success' &&
      candidate.head_sha === query.sha &&
      candidate.head_branch === 'main' &&
      candidate.path === query.workflowPath &&
      candidate.repository.full_name === query.repository &&
      candidate.head_repository.full_name === query.repository,
  );
  if (run === undefined) {
    throw new Error(
      `No successful completed main push run of ${query.workflowPath} exactly matches the tagged commit.`,
    );
  }
  return run;
}

export function findSuccessfulCodeQlAnalysisJob(payload) {
  if (!isRecord(payload) || !Array.isArray(payload.jobs)) {
    throw new Error('GitHub Actions API returned an invalid workflow-jobs response.');
  }
  const jobs = payload.jobs.map((candidate) => parseWorkflowJob(candidate));
  const analysisJob = jobs.find(
    (candidate) =>
      candidate.name === 'Analyze JavaScript and TypeScript' &&
      candidate.status === 'completed' &&
      candidate.conclusion === 'success',
  );
  if (analysisJob === undefined) {
    throw new Error(
      'The exact CodeQL run did not complete its analysis job successfully.',
    );
  }
  const analysisStep = analysisJob.steps.find(
    (candidate) =>
      (candidate.name === 'Perform CodeQL Analysis' ||
        candidate.name.includes('codeql-action/analyze')) &&
      candidate.status === 'completed' &&
      candidate.conclusion === 'success',
  );
  if (analysisStep === undefined) {
    throw new Error(
      'The exact CodeQL run did not complete its analyze step successfully.',
    );
  }
  return analysisJob;
}

export async function requireExactSuccessfulWorkflowRuns(options) {
  if (!isRecord(options)) {
    throw new Error('Workflow-run options must be an object.');
  }
  const apiUrl = requiredString(options.apiUrl, 'apiUrl');
  const repository = requiredString(options.repository, 'repository');
  const sha = requiredString(options.sha, 'sha');
  const token = requiredString(options.token, 'token');
  if (!Array.isArray(options.workflowPaths) || options.workflowPaths.length === 0) {
    throw new Error('At least one required workflow path must be supplied.');
  }
  if (new Set(options.workflowPaths).size !== options.workflowPaths.length) {
    throw new Error('Required workflow paths must be unique.');
  }
  const fetchImplementation = options.fetchImplementation ?? globalThis.fetch;
  if (typeof fetchImplementation !== 'function') {
    throw new Error('Workflow-run fetch implementation must be a function.');
  }

  for (const workflowPath of options.workflowPaths) {
    const query = { repository, sha, workflowPath };
    assertQuery(query);
    const workflowFile = workflowPath.slice('.github/workflows/'.length);
    const url = new globalThis.URL(
      `/repos/${repository}/actions/workflows/${encodeURIComponent(workflowFile)}/runs`,
      apiUrl,
    );
    url.searchParams.set('event', 'push');
    url.searchParams.set('head_sha', sha);
    url.searchParams.set('status', 'success');
    url.searchParams.set('per_page', '100');

    const response = await fetchImplementation(url, {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'X-GitHub-Api-Version': '2022-11-28',
      },
      redirect: 'error',
      signal: globalThis.AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      throw new Error(
        `GitHub Actions API returned HTTP ${response.status} for ${workflowPath}.`,
      );
    }
    const payload = await response.json();
    const run = findExactSuccessfulPushRun(payload, query);
    if (workflowPath === '.github/workflows/codeql.yml') {
      const jobsUrl = new globalThis.URL(
        `/repos/${repository}/actions/runs/${run.id}/jobs`,
        apiUrl,
      );
      jobsUrl.searchParams.set('per_page', '100');
      const jobsResponse = await fetchImplementation(jobsUrl, {
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${token}`,
          'X-GitHub-Api-Version': '2022-11-28',
        },
        redirect: 'error',
        signal: globalThis.AbortSignal.timeout(30_000),
      });
      if (!jobsResponse.ok) {
        throw new Error(
          `GitHub Actions jobs API returned HTTP ${jobsResponse.status} for ${workflowPath}.`,
        );
      }
      findSuccessfulCodeQlAnalysisJob(await jobsResponse.json());
    }
  }
}

function assertQuery(query) {
  if (!isRecord(query)) {
    throw new Error('Workflow-run query must be an object.');
  }
  const repository = requiredString(query.repository, 'repository');
  const sha = requiredString(query.sha, 'sha');
  const workflowPath = requiredString(query.workflowPath, 'workflowPath');
  if (!repositoryPattern.test(repository)) {
    throw new Error('Workflow-run repository is invalid.');
  }
  if (!shaPattern.test(sha)) {
    throw new Error('Workflow-run SHA must be a lowercase full commit SHA.');
  }
  if (!workflowPathPattern.test(workflowPath)) {
    throw new Error('Workflow-run path is invalid.');
  }
}

function parseWorkflowRun(candidate) {
  if (!isRecord(candidate)) {
    throw new Error('GitHub Actions API returned a malformed workflow run.');
  }
  return {
    ...candidate,
    id: requiredPositiveInteger(candidate.id, 'workflow run ID'),
    event: requiredString(candidate.event, 'workflow run event'),
    status: requiredString(candidate.status, 'workflow run status'),
    conclusion: requiredString(candidate.conclusion, 'workflow run conclusion'),
    head_sha: requiredString(candidate.head_sha, 'workflow run head SHA'),
    head_branch: requiredString(candidate.head_branch, 'workflow run head branch'),
    path: requiredString(candidate.path, 'workflow run path'),
    repository: parseRepository(candidate.repository),
    head_repository: parseRepository(candidate.head_repository),
  };
}

function parseWorkflowJob(candidate) {
  if (!isRecord(candidate) || !Array.isArray(candidate.steps)) {
    throw new Error('GitHub Actions API returned a malformed workflow job.');
  }
  return {
    ...candidate,
    name: requiredString(candidate.name, 'workflow job name'),
    status: requiredString(candidate.status, 'workflow job status'),
    conclusion: requiredString(candidate.conclusion, 'workflow job conclusion'),
    steps: candidate.steps.map((step) => parseWorkflowStep(step)),
  };
}

function parseWorkflowStep(candidate) {
  if (!isRecord(candidate)) {
    throw new Error('GitHub Actions API returned a malformed workflow step.');
  }
  return {
    ...candidate,
    name: requiredString(candidate.name, 'workflow step name'),
    status: requiredString(candidate.status, 'workflow step status'),
    conclusion: requiredString(candidate.conclusion, 'workflow step conclusion'),
  };
}

function parseRepository(value) {
  if (!isRecord(value)) {
    throw new Error('GitHub Actions API returned a malformed workflow repository.');
  }
  return { ...value, full_name: requiredString(value.full_name, 'repository name') };
}

function requiredString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Missing or invalid ${label}.`);
  }
  return value;
}

function requiredPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`Missing or invalid ${label}.`);
  }
  return value;
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requiredEnvironment(name) {
  return requiredString(process.env[name], `release context ${name}`);
}

async function main() {
  const workflowPaths = process.argv.slice(2);
  await requireExactSuccessfulWorkflowRuns({
    apiUrl: requiredEnvironment('GITHUB_API_URL'),
    repository: requiredEnvironment('GITHUB_REPOSITORY'),
    sha: requiredEnvironment('TAGGED_COMMIT'),
    token: requiredEnvironment('GITHUB_TOKEN'),
    workflowPaths,
  });
}

const entrypoint = process.argv[1];
if (entrypoint !== undefined && import.meta.url === pathToFileURL(entrypoint).href) {
  await main();
}
