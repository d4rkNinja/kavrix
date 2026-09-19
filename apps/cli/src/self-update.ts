/**
 * `kavrix update` — check the npm registry for a newer `kavrix` release and,
 * for global npm installs only, replace the installed package.
 *
 * Fail-closed for Homebrew, pnpm, yarn, npx, and workspace/dev checkouts.
 * `--check` never installs and always exits 0 (pair with `--json` for CI).
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Command } from 'commander';

import { LocalCliError } from './cli-error.js';
import { invalidConfiguration } from './execution/exit-codes.js';
import { renderTerminalStatus, terminalColorEnabled } from './terminal-presentation.js';
import { CLI_VERSION } from './version.js';

export const NPM_PACKAGE_NAME = 'kavrix';
export const DEFAULT_NPM_REGISTRY = 'https://registry.npmjs.org';
export const DEFAULT_DIST_TAG = 'latest';
export const NODE_ENGINES = '>=24.12.0 <25 || >=25.1.0';

const STABLE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const BETA_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-beta\.(0|[1-9]\d*)$/u;

export type InstallMethod =
  'npm-global' | 'npx' | 'pnpm' | 'yarn' | 'homebrew' | 'dev-checkout' | 'unknown';

export type InstallKind =
  | Readonly<{ kind: 'npm-global'; method: 'npm-global'; packageRoot: string }>
  | Readonly<{
      kind: 'unsupported';
      method: Exclude<InstallMethod, 'npm-global'>;
      detail: string;
    }>;

export type NpmInstallResult = Readonly<{
  status: number;
  stdout: string;
  stderr: string;
}>;

export type SelfUpdateOptions = Readonly<{
  check?: boolean;
  json?: boolean;
  tag?: string;
  registry?: string;
}>;

/** Machine-readable `--json` contract (stable for automation). */
export type SelfUpdateJson = Readonly<{
  installed: string;
  latest: string;
  updateAvailable: boolean;
  channel: string;
  action: 'check' | 'noop' | 'updated' | 'refused' | 'failed';
  error?: string;
}>;

export type SelfUpdateReport = SelfUpdateJson &
  Readonly<{
    package: string;
    registry: string;
    installMethod: InstallMethod;
    npmCommand: string;
    message: string;
  }>;

export type SelfUpdateDeps = Readonly<{
  currentVersion: string;
  argv1: string | undefined;
  env: NodeJS.ProcessEnv;
  fetchRegistry: (input: {
    packageName: string;
    distTag: string;
    registry: string;
  }) => Promise<string>;
  detectInstall: (argv1: string | undefined) => InstallKind;
  resolveNpm: () => Readonly<{ command: string; argsPrefix: readonly string[] }>;
  runNpmInstall: (input: {
    version: string;
    registry: string;
    command: string;
    argsPrefix: readonly string[];
  }) => Promise<NpmInstallResult>;
  stdoutIsTTY: boolean;
  writeStdout: (text: string) => void;
  writeStderr: (text: string) => void;
}>;

const HELP_DESCRIPTION =
  'Upgrade a global npm install of kavrix from the npm registry. Supports only `npm install -g kavrix` layouts. Homebrew, pnpm, yarn, npx, and workspace/dev checkouts are not supported — upgrade through that package manager or reinstall with npm. Requires Node.js ' +
  NODE_ENGINES +
  '.';

/** Compare published Kavrix versions (stable X.Y.Z or beta X.Y.Z-beta.N). */
export function comparePublishedVersions(left: string, right: string): number {
  const a = parsePublishedVersion(left);
  const b = parsePublishedVersion(right);
  for (let index = 0; index < 3; index += 1) {
    const leftPart = a.core[index] ?? 0;
    const rightPart = b.core[index] ?? 0;
    const delta = leftPart - rightPart;
    if (delta !== 0) return delta < 0 ? -1 : 1;
  }
  if (a.beta === null && b.beta === null) return 0;
  if (a.beta === null) return 1; // stable > beta of same core
  if (b.beta === null) return -1;
  if (a.beta === b.beta) return 0;
  return a.beta < b.beta ? -1 : 1;
}

export function parsePublishedVersion(version: string): Readonly<{
  core: readonly [number, number, number];
  beta: number | null;
}> {
  const stable = STABLE_VERSION.exec(version);
  if (stable) {
    return {
      core: [Number(stable[1]), Number(stable[2]), Number(stable[3])],
      beta: null,
    };
  }
  const beta = BETA_VERSION.exec(version);
  if (beta) {
    return {
      core: [Number(beta[1]), Number(beta[2]), Number(beta[3])],
      beta: Number(beta[4]),
    };
  }
  throw new LocalCliError(
    `Unsupported package version ${JSON.stringify(version)}; expected X.Y.Z or X.Y.Z-beta.N.`,
  );
}

export function formatNpmInstallCommand(version: string, registry: string): string {
  const normalized = registry.replace(/\/+$/u, '');
  const registryArg =
    normalized === DEFAULT_NPM_REGISTRY ? '' : ` --registry ${normalized}`;
  return `npm install --global ${NPM_PACKAGE_NAME}@${version}${registryArg}`;
}

/** Fetch the version currently pointed at by an npm dist-tag. */
export async function fetchNpmDistTagVersion(input: {
  packageName: string;
  distTag: string;
  registry: string;
  fetchImpl?: typeof fetch;
}): Promise<string> {
  const registry = input.registry.replace(/\/+$/u, '');
  const url = `${registry}/${encodeURIComponent(input.packageName)}`;
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new LocalCliError(
      'This Node runtime cannot query the npm registry (fetch missing).',
    );
  }
  let response: Response;
  try {
    response = await fetchImpl(url, {
      headers: {
        Accept: 'application/vnd.npm.install-v1+json, application/json',
      },
    });
  } catch {
    throw new LocalCliError(
      `Could not reach the npm registry at ${registry} (offline or blocked). Check network access and retry, or run \`${formatNpmInstallCommand('latest', registry)}\` manually when online.`,
    );
  }
  if (!response.ok) {
    throw new LocalCliError(
      `npm registry returned HTTP ${String(response.status)} for ${input.packageName}.`,
    );
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new LocalCliError('npm registry returned an invalid JSON document.');
  }
  if (typeof body !== 'object' || body === null || !('dist-tags' in body)) {
    throw new LocalCliError('npm registry response is missing dist-tags.');
  }
  const distTags = body['dist-tags'];
  if (typeof distTags !== 'object' || distTags === null || Array.isArray(distTags)) {
    throw new LocalCliError('npm registry response is missing dist-tags.');
  }
  const tags = distTags as Record<string, unknown>;
  const version = tags[input.distTag];
  if (typeof version !== 'string' || version.length === 0) {
    throw new LocalCliError(
      `npm dist-tag ${JSON.stringify(input.distTag)} is not published for ${input.packageName}.`,
    );
  }
  parsePublishedVersion(version);
  return version;
}

function unsupported(
  method: Exclude<InstallMethod, 'npm-global'>,
  detail: string,
): InstallKind {
  return { kind: 'unsupported', method, detail };
}

/**
 * Classify how this process was launched. Only global npm installs under
 * `.../node_modules/kavrix/...` are eligible for automatic replacement.
 */
export function detectInstallKind(argv1: string | undefined): InstallKind {
  if (argv1 === undefined || argv1.length === 0) {
    return unsupported(
      'unknown',
      'Could not determine the installed package path. Reinstall with `npm install --global kavrix`.',
    );
  }

  let resolved = argv1;
  try {
    if (argv1.startsWith('file:')) {
      resolved = fileURLToPath(argv1);
    }
  } catch {
    resolved = argv1;
  }

  const normalized = resolved.replaceAll('\\', '/');
  const lower = normalized.toLowerCase();

  if (
    lower.includes('/_npx/') ||
    lower.includes('/npm/_npx/') ||
    lower.includes('/.npm/_npx/')
  ) {
    return unsupported(
      'npx',
      'This kavrix process was launched via npx. `kavrix update` cannot replace npx caches. Install globally with `npm install --global kavrix`, or re-run `npx kavrix@latest`.',
    );
  }

  if (
    lower.includes('/cellar/') ||
    lower.includes('/homebrew/') ||
    lower.includes('/linuxbrew/')
  ) {
    return unsupported(
      'homebrew',
      'This kavrix binary looks like a Homebrew install. `kavrix update` only manages global npm installs. If you installed via Homebrew, upgrade with brew (or reinstall with `npm install --global kavrix`).',
    );
  }

  if (
    lower.includes('/.pnpm/') ||
    lower.includes('/pnpm/global/') ||
    lower.includes('/pnpm-global/')
  ) {
    return unsupported(
      'pnpm',
      'This kavrix binary looks like a pnpm global install. `kavrix update` only manages npm globals. Upgrade with `pnpm add -g kavrix@latest` (or reinstall with `npm install --global kavrix`).',
    );
  }

  if (
    lower.includes('/.yarn/') ||
    lower.includes('/yarn/global/') ||
    lower.includes('/berry/global/')
  ) {
    return unsupported(
      'yarn',
      'This kavrix binary looks like a Yarn global install. `kavrix update` only manages npm globals. Upgrade with `yarn global add kavrix` (or reinstall with `npm install --global kavrix`).',
    );
  }

  if (
    /\/apps\/cli\/(dist|src)\//u.test(normalized) ||
    (normalized.includes('/kavrix-') && !normalized.includes('/node_modules/kavrix/'))
  ) {
    return unsupported(
      'dev-checkout',
      'This kavrix binary looks like a workspace/dev checkout. `kavrix update` only manages global npm installs. Pull/build from git, or install a release with `npm install --global kavrix`.',
    );
  }

  const marker = '/node_modules/kavrix/';
  const index = normalized.lastIndexOf(marker);
  if (index === -1) {
    return unsupported(
      'unknown',
      'This kavrix binary is not a global npm package install. Homebrew, pnpm, yarn, npx, and workspace installs are unsupported. Reinstall with `npm install --global kavrix`.',
    );
  }

  const packageRoot = normalized
    .slice(0, index + marker.length - 1)
    .replaceAll('/', sep);
  const manifestPath = join(packageRoot, 'package.json');
  if (!existsSync(manifestPath)) {
    return unsupported(
      'unknown',
      'The installed package directory is missing package.json. Reinstall with `npm install --global kavrix`.',
    );
  }

  return { kind: 'npm-global', packageRoot, method: 'npm-global' };
}

/** Resolve the npm CLI the same way packed-smoke does on Windows. */
export function resolveNpmInvoker(
  platform: NodeJS.Platform = process.platform,
  execPath: string = process.execPath,
): Readonly<{ command: string; argsPrefix: readonly string[] }> {
  if (platform === 'win32') {
    const npmCli = join(dirname(execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
    if (existsSync(npmCli)) {
      return { command: execPath, argsPrefix: [npmCli] };
    }
  }
  return { command: 'npm', argsPrefix: [] };
}

export async function runGlobalNpmInstall(input: {
  version: string;
  registry: string;
  command: string;
  argsPrefix: readonly string[];
  spawnImpl?: typeof spawn;
  env?: NodeJS.ProcessEnv;
}): Promise<NpmInstallResult> {
  const spawnImpl = input.spawnImpl ?? spawn;
  const args = [
    ...input.argsPrefix,
    'install',
    '--global',
    `${NPM_PACKAGE_NAME}@${input.version}`,
    '--registry',
    input.registry.replace(/\/+$/u, ''),
  ];
  return await new Promise((resolvePromise, rejectPromise) => {
    const child = spawnImpl(input.command, args, {
      env: input.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => {
      stdoutChunks.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderrChunks.push(chunk);
    });
    child.on('error', (error: Error) => {
      rejectPromise(
        new LocalCliError(
          `Failed to launch npm (${error.message}). Install npm or reinstall Node (${NODE_ENGINES}), then retry \`${formatNpmInstallCommand(input.version, input.registry)}\`.`,
        ),
      );
    });
    child.on('close', (code) => {
      resolvePromise({
        status: code ?? 1,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
      });
    });
  });
}

export function createDefaultSelfUpdateDeps(
  overrides: Partial<SelfUpdateDeps> = {},
): SelfUpdateDeps {
  return {
    currentVersion: CLI_VERSION,
    argv1: process.argv[1],
    env: process.env,
    fetchRegistry: ({ packageName, distTag, registry }) =>
      fetchNpmDistTagVersion({ packageName, distTag, registry }),
    detectInstall: detectInstallKind,
    resolveNpm: () => resolveNpmInvoker(),
    runNpmInstall: ({ version, registry, command, argsPrefix }) =>
      runGlobalNpmInstall({ version, registry, command, argsPrefix }),
    stdoutIsTTY: process.stdout.isTTY,
    writeStdout: (text) => {
      process.stdout.write(text);
    },
    writeStderr: (text) => {
      process.stderr.write(text);
    },
    ...overrides,
  };
}

function toJson(report: SelfUpdateReport): SelfUpdateJson {
  return {
    installed: report.installed,
    latest: report.latest,
    updateAvailable: report.updateAvailable,
    channel: report.channel,
    action: report.action,
    ...(report.error === undefined ? {} : { error: report.error }),
  };
}

function emitReport(
  report: SelfUpdateReport,
  options: SelfUpdateOptions,
  deps: SelfUpdateDeps,
): void {
  if (options.json === true || !deps.stdoutIsTTY) {
    deps.writeStdout(`${JSON.stringify(toJson(report))}\n`);
    return;
  }
  const color = terminalColorEnabled(process.stdout);
  const kind =
    report.action === 'updated'
      ? 'success'
      : report.action === 'refused' || report.action === 'failed'
        ? 'error'
        : report.updateAvailable
          ? 'warning'
          : 'success';
  deps.writeStdout(renderTerminalStatus(kind, report.message, color));
  if (report.action === 'updated') {
    deps.writeStdout(
      renderTerminalStatus(
        'info',
        `Verify with \`kavrix --version\` (expected ${report.latest}).`,
        color,
      ),
    );
  }
}

function summarizeNpmFailure(text: string): string {
  const lines = text
    .split(/\r?\n/u)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  const eacces = lines.find((line) => /EACCES|permission denied/iu.test(line));
  if (eacces !== undefined) {
    return (
      'EACCES: npm cannot write to its global prefix. Fix with:\n' +
      '  npm config set prefix ~/.local\n' +
      '  export PATH="$HOME/.local/bin:$PATH"\n' +
      'then retry the command below. If npm reports EBADENGINE, use Node.js ' +
      NODE_ENGINES +
      '.'
    );
  }
  const engine = lines.find((line) => /EBADENGINE|unsupported engine/iu.test(line));
  if (engine !== undefined) {
    return `Node.js engines mismatch: kavrix requires ${NODE_ENGINES}. Upgrade or switch Node, then retry.`;
  }
  const line = lines.find((entry) => !entry.startsWith('npm '));
  if (line === undefined) return '';
  return line.length > 200 ? `${line.slice(0, 197)}...` : line;
}

/**
 * Execute update/check. Throws LocalCliError / CodedCliError on hard failures.
 * `--check` never installs and always leaves exit code 0 for the caller.
 */
export async function executeSelfUpdate(
  options: SelfUpdateOptions,
  deps: SelfUpdateDeps = createDefaultSelfUpdateDeps(),
): Promise<SelfUpdateReport> {
  const trimmedTag = options.tag?.trim();
  const channel =
    trimmedTag === undefined || trimmedTag.length === 0 ? DEFAULT_DIST_TAG : trimmedTag;
  const trimmedRegistry = options.registry?.trim();
  const envRegistry = deps.env['npm_config_registry']?.trim();
  const registry =
    trimmedRegistry !== undefined && trimmedRegistry.length > 0
      ? trimmedRegistry
      : envRegistry !== undefined && envRegistry.length > 0
        ? envRegistry
        : DEFAULT_NPM_REGISTRY;
  if (!/^[a-z0-9][a-z0-9._-]*$/iu.test(channel)) {
    throw new LocalCliError(
      'Invalid --tag; use an npm dist-tag such as latest or beta.',
    );
  }
  if (!/^https?:\/\//iu.test(registry)) {
    throw new LocalCliError(
      'Invalid --registry; expected an http(s) npm registry URL.',
    );
  }

  const latest = await deps.fetchRegistry({
    packageName: NPM_PACKAGE_NAME,
    distTag: channel,
    registry,
  });
  const updateAvailable = comparePublishedVersions(deps.currentVersion, latest) < 0;
  const install = deps.detectInstall(deps.argv1);
  const checkOnly = options.check === true;
  const npmCommand = formatNpmInstallCommand(latest, registry);
  const installMethod: InstallMethod =
    install.kind === 'npm-global' ? 'npm-global' : install.method;

  // Unsupported layouts must be refused (or clearly noted under --check) before
  // the "already newest" early return — otherwise current Homebrew/pnpm/dev
  // installs silently look successful.
  if (install.kind === 'unsupported') {
    const message = `${install.detail} Newest ${channel} is ${latest}. Manual command: \`${npmCommand}\`.`;
    if (checkOnly) {
      const report: SelfUpdateReport = {
        package: NPM_PACKAGE_NAME,
        installed: deps.currentVersion,
        latest,
        updateAvailable,
        channel,
        action: 'check',
        registry,
        installMethod,
        npmCommand,
        message,
        error: message,
      };
      emitReport(report, options, deps);
      return report;
    }
    const report: SelfUpdateReport = {
      package: NPM_PACKAGE_NAME,
      installed: deps.currentVersion,
      latest,
      updateAvailable,
      channel,
      action: 'refused',
      registry,
      installMethod,
      npmCommand,
      message,
      error: message,
    };
    emitReport(report, options, deps);
    throw invalidConfiguration(message);
  }

  if (!updateAvailable) {
    const report: SelfUpdateReport = {
      package: NPM_PACKAGE_NAME,
      installed: deps.currentVersion,
      latest,
      updateAvailable: false,
      channel,
      action: checkOnly ? 'check' : 'noop',
      registry,
      installMethod,
      npmCommand,
      message: `kavrix ${deps.currentVersion} is already the newest ${channel} release (${latest}).`,
    };
    emitReport(report, options, deps);
    return report;
  }

  if (checkOnly) {
    const report: SelfUpdateReport = {
      package: NPM_PACKAGE_NAME,
      installed: deps.currentVersion,
      latest,
      updateAvailable: true,
      channel,
      action: 'check',
      registry,
      installMethod,
      npmCommand,
      message: `Update available: ${deps.currentVersion} → ${latest} (npm ${channel}). Run \`kavrix update\` to install (global npm only).`,
    };
    emitReport(report, options, deps);
    return report;
  }

  const npm = deps.resolveNpm();
  const result = await deps.runNpmInstall({
    version: latest,
    registry,
    command: npm.command,
    argsPrefix: npm.argsPrefix,
  });
  if (result.status !== 0) {
    const detail = summarizeNpmFailure(result.stderr || result.stdout);
    const message =
      `${npmCommand} failed` +
      (detail.length > 0 ? `:\n${detail}` : '.') +
      ` Retry the exact command above. Kavrix requires Node.js ${NODE_ENGINES}.`;
    const report: SelfUpdateReport = {
      package: NPM_PACKAGE_NAME,
      installed: deps.currentVersion,
      latest,
      updateAvailable: true,
      channel,
      action: 'failed',
      registry,
      installMethod,
      npmCommand,
      message,
      error: message,
    };
    emitReport(report, options, deps);
    throw new LocalCliError(message);
  }

  const report: SelfUpdateReport = {
    package: NPM_PACKAGE_NAME,
    installed: deps.currentVersion,
    latest,
    updateAvailable: true,
    channel,
    action: 'updated',
    registry,
    installMethod: 'npm-global',
    npmCommand,
    message: `Updated kavrix ${deps.currentVersion} → ${latest}.`,
  };
  emitReport(report, options, deps);
  return report;
}

/** Register `kavrix update` on the root program. */
export function registerSelfUpdateCommand(program: Command): void {
  program
    .command('update')
    .description(HELP_DESCRIPTION)
    .option(
      '--check',
      'Report whether a newer release is available without installing (always exits 0; use --json for automation).',
    )
    .option(
      '--json',
      'Emit machine-readable JSON ({ installed, latest, updateAvailable, channel, action, error? }).',
    )
    .option(
      '--tag <dist-tag>',
      'npm dist-tag to follow (default: latest).',
      DEFAULT_DIST_TAG,
    )
    .option(
      '--registry <url>',
      'npm registry URL (default: https://registry.npmjs.org or npm_config_registry).',
    )
    .addHelpText(
      'after',
      `
Notes:
  Package name on npm is \`kavrix\`. Only global npm installs are upgraded in place.
  Unsupported: Homebrew, pnpm, yarn, npx, and workspace/dev checkouts.
  On EACCES, set a user prefix: \`npm config set prefix ~/.local\` and put \`~/.local/bin\` on PATH.
  Node.js engines: ${NODE_ENGINES}.
`,
    )
    .action(async (...args: unknown[]) => {
      const command = args.at(-1) as Command;
      const options: SelfUpdateOptions = command.opts();
      // --check never mutates and always exits 0 (JSON already written).
      await executeSelfUpdate(options);
    });
}
