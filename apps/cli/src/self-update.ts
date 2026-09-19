/**
 * `kavrix update` — check the npm registry for a newer `kavrix` release and,
 * for global npm installs only, replace the installed package.
 *
 * Fail-closed for Homebrew, pnpm, yarn, npx, and workspace/dev checkouts.
 * `--check` never installs. Successful checks and check-mode query failures exit 0;
 * pair with `--json` for automation (JSON is always emitted when `--json` is set).
 */
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
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
  /** Optional override for post-install version verification (tests). */
  readInstalledVersion?: (packageRoot: string) => string | undefined;
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

/** POSIX-safe single-quote for pasteable shell commands (never unquoted). */
export function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/**
 * Validate and normalize an npm registry URL for fetch + display.
 * Requires https (http only for loopback). Rejects embedded credentials so
 * pasteable commands cannot echo tokens; use npm config for auth instead.
 */
export function assertSafeNpmRegistry(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || /[\r\n\0]/.test(trimmed)) {
    throw new LocalCliError(
      'Invalid --registry; expected an http(s) npm registry URL.',
    );
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new LocalCliError(
      'Invalid --registry; expected an http(s) npm registry URL.',
    );
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new LocalCliError(
      'Invalid --registry; expected an http(s) npm registry URL.',
    );
  }
  const host = parsed.hostname.toLowerCase();
  const loopback =
    host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
  if (parsed.protocol === 'http:' && !loopback) {
    throw new LocalCliError(
      'Invalid --registry; use an https:// registry URL (http is only allowed for localhost).',
    );
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new LocalCliError(
      'Invalid --registry; credentials in the URL are not allowed. Configure registry auth via npm config instead.',
    );
  }
  if (parsed.hash.length > 0) {
    throw new LocalCliError('Invalid --registry; URL fragments are not allowed.');
  }
  const path = parsed.pathname.replace(/\/+$/u, '');
  const normalized = `${parsed.protocol}//${parsed.host}${path === '/' ? '' : path}`;
  return normalized;
}

/** Registry string safe for human/error text (credentials never included). */
export function displayNpmRegistry(registry: string): string {
  try {
    return assertSafeNpmRegistry(registry);
  } catch {
    return 'https://registry.npmjs.org';
  }
}

export function formatNpmInstallCommand(version: string, registry: string): string {
  const normalized = displayNpmRegistry(registry);
  const pkg = `${NPM_PACKAGE_NAME}@${version}`;
  if (normalized === DEFAULT_NPM_REGISTRY) {
    return `npm install --global ${shellSingleQuote(pkg)}`;
  }
  return `npm install --global ${shellSingleQuote(pkg)} --registry ${shellSingleQuote(normalized)}`;
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
 * Classify how this process was launched. Only recognized global npm installs
 * (`…/lib/node_modules/kavrix` or Windows `…/npm/node_modules/kavrix`) whose
 * package.json name is exactly `kavrix` are eligible for automatic replacement.
 *
 * Resolves symlinks first so a typical `$PREFIX/bin/kavrix` npm-global bin is
 * classified correctly. Homebrew-*Node* npm globals under `/opt/homebrew/lib/…`
 * are accepted as npm-global; Homebrew *formula* Cellar paths are refused.
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

  try {
    resolved = realpathSync(resolved);
  } catch {
    // Keep the unresolved path; bin→node_modules fallback may still apply.
  }

  const normalized = resolved.replaceAll('\\', '/');
  const lower = normalized.toLowerCase();

  // npm-global first (before Homebrew substring checks) so Homebrew-Node
  // prefixes like /opt/homebrew/lib/node_modules/kavrix classify correctly.
  const npmGlobal = classifyNpmGlobalInstall(normalized);
  if (npmGlobal !== undefined) {
    return npmGlobal;
  }

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

  if (lower.includes('/.bun/') || lower.includes('/bun/install/global/')) {
    return unsupported(
      'unknown',
      'This kavrix binary looks like a Bun install. `kavrix update` only manages global npm installs. Reinstall with `npm install --global kavrix`.',
    );
  }

  // Narrow: only the monorepo apps/cli tree — not arbitrary directories named kavrix-*.
  if (/\/apps\/cli\/(dist|src)\//u.test(normalized)) {
    return unsupported(
      'dev-checkout',
      'This kavrix binary looks like a workspace/dev checkout. `kavrix update` only manages global npm installs. Pull/build from git, or install a release with `npm install --global kavrix`.',
    );
  }

  return unsupported(
    'unknown',
    'This kavrix binary is not a global npm package install. Homebrew, pnpm, yarn, npx, and workspace installs are unsupported. Reinstall with `npm install --global kavrix`.',
  );
}

function readPackageName(manifestPath: string): string | undefined {
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
      name?: unknown;
    };
    return typeof manifest.name === 'string' ? manifest.name : undefined;
  } catch {
    return undefined;
  }
}

export function readPackageVersion(packageRoot: string): string | undefined {
  const manifestPath = join(packageRoot, 'package.json');
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
      version?: unknown;
    };
    return typeof manifest.version === 'string' ? manifest.version : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Accept only recognized global npm layouts with package name `kavrix`.
 * Also maps `$PREFIX/bin/kavrix` (pre-realpath or unbroken symlink target miss)
 * to `$PREFIX/lib/node_modules/kavrix` / Windows `$PREFIX/node_modules/kavrix`.
 */
function classifyNpmGlobalInstall(normalized: string): InstallKind | undefined {
  const marker = '/node_modules/kavrix';
  let packageRootPosix: string | undefined;
  const embedded = normalized.lastIndexOf(`${marker}/`);
  const exactRoot = normalized.endsWith(marker) ? normalized : undefined;
  if (embedded !== -1) {
    packageRootPosix = normalized.slice(0, embedded + marker.length);
  } else if (exactRoot !== undefined) {
    packageRootPosix = exactRoot;
  } else {
    const binMatch = /\/bin\/kavrix(\.cmd|\.ps1)?$/iu.exec(normalized);
    if (binMatch === null) {
      return undefined;
    }
    const prefix = normalized.slice(0, binMatch.index);
    const candidates = [
      `${prefix}/lib/node_modules/kavrix`,
      `${prefix}/node_modules/kavrix`,
    ];
    for (const candidate of candidates) {
      if (existsSync(join(candidate.replaceAll('/', sep), 'package.json'))) {
        packageRootPosix = candidate;
        break;
      }
    }
    if (packageRootPosix === undefined) {
      return undefined;
    }
  }

  const prefixBeforeNodeModules = packageRootPosix.slice(
    0,
    packageRootPosix.lastIndexOf('/node_modules/kavrix'),
  );
  if (prefixBeforeNodeModules.includes('/node_modules/')) {
    return undefined;
  }

  const isUnixGlobal = prefixBeforeNodeModules.endsWith('/lib');
  const isWindowsGlobal =
    /\/npm$/iu.test(prefixBeforeNodeModules) ||
    /\/AppData\/Roaming\/npm$/iu.test(prefixBeforeNodeModules);
  if (!isUnixGlobal && !isWindowsGlobal) {
    return undefined;
  }

  const packageRoot = packageRootPosix.replaceAll('/', sep);
  const manifestPath = join(packageRoot, 'package.json');
  if (!existsSync(manifestPath)) {
    return undefined;
  }
  if (readPackageName(manifestPath) !== NPM_PACKAGE_NAME) {
    return undefined;
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
  // Never paint [OK] when an error/refuse is present (including --check notes).
  const kind =
    report.error !== undefined ||
    report.action === 'refused' ||
    report.action === 'failed'
      ? 'error'
      : report.action === 'updated'
        ? 'success'
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
  const line =
    lines.find((entry) => !entry.startsWith('npm ')) ??
    lines.find((entry) => /^npm ERR!/iu.test(entry)) ??
    lines[0];
  if (line === undefined) return '';
  return line.length > 200 ? `${line.slice(0, 197)}...` : line;
}

/**
 * Execute update/check. Throws LocalCliError / CodedCliError on hard failures.
 * `--check` never installs; successful checks and check-mode query failures exit 0.
 * When `--json` is set, failures emit `{ action:"failed", error }` before throwing
 * (or returning under `--check`).
 */
export async function executeSelfUpdate(
  options: SelfUpdateOptions,
  deps: SelfUpdateDeps = createDefaultSelfUpdateDeps(),
): Promise<SelfUpdateReport> {
  const checkOnly = options.check === true;
  const wantJson = options.json === true || !deps.stdoutIsTTY;
  const trimmedTag = options.tag?.trim();
  const channel =
    trimmedTag === undefined || trimmedTag.length === 0 ? DEFAULT_DIST_TAG : trimmedTag;
  const trimmedRegistry = options.registry?.trim();
  const envRegistry = deps.env['npm_config_registry']?.trim();
  const rawRegistry =
    trimmedRegistry !== undefined && trimmedRegistry.length > 0
      ? trimmedRegistry
      : envRegistry !== undefined && envRegistry.length > 0
        ? envRegistry
        : DEFAULT_NPM_REGISTRY;

  const emitFailed = (
    message: string,
    channelName: string,
    registryName: string,
  ): SelfUpdateReport => {
    const install = deps.detectInstall(deps.argv1);
    const installMethod: InstallMethod =
      install.kind === 'npm-global' ? 'npm-global' : install.method;
    const report: SelfUpdateReport = {
      package: NPM_PACKAGE_NAME,
      installed: deps.currentVersion,
      latest: '',
      updateAvailable: false,
      channel: channelName,
      action: 'failed',
      registry: registryName,
      installMethod,
      npmCommand: formatNpmInstallCommand('latest', registryName),
      message,
      error: message,
    };
    emitReport(report, options, deps);
    return report;
  };

  if (!/^[a-z0-9][a-z0-9._-]*$/iu.test(channel)) {
    const message = 'Invalid --tag; use an npm dist-tag such as latest or beta.';
    if (wantJson || checkOnly) {
      const report = emitFailed(message, channel, DEFAULT_NPM_REGISTRY);
      if (checkOnly) return report;
      throw new LocalCliError('');
    }
    throw new LocalCliError(message);
  }

  let registry: string;
  try {
    registry = assertSafeNpmRegistry(rawRegistry);
  } catch (error) {
    const message =
      error instanceof LocalCliError
        ? error.message
        : 'Invalid --registry; expected an http(s) npm registry URL.';
    if (wantJson || checkOnly) {
      const report = emitFailed(message, channel, DEFAULT_NPM_REGISTRY);
      if (checkOnly) return report;
      throw new LocalCliError('');
    }
    throw error instanceof LocalCliError ? error : new LocalCliError(message);
  }

  let latest: string;
  try {
    latest = await deps.fetchRegistry({
      packageName: NPM_PACKAGE_NAME,
      distTag: channel,
      registry,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'npm registry query failed.';
    if (wantJson || checkOnly) {
      const report = emitFailed(message, channel, registry);
      if (checkOnly) return report;
      throw new LocalCliError('');
    }
    throw error instanceof LocalCliError ? error : new LocalCliError(message);
  }

  const updateAvailable = comparePublishedVersions(deps.currentVersion, latest) < 0;
  const install = deps.detectInstall(deps.argv1);
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
    // Message already presented (TTY [X] or JSON); suppress stderr duplicate.
    throw invalidConfiguration('');
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
    // Message already presented; suppress stderr duplicate.
    throw new LocalCliError('');
  }

  const postInstall = deps.detectInstall(deps.argv1);
  const packageRootForVerify =
    postInstall.kind === 'npm-global' ? postInstall.packageRoot : install.packageRoot;
  const installedAfter =
    deps.readInstalledVersion?.(packageRootForVerify) ??
    readPackageVersion(packageRootForVerify);
  if (installedAfter !== latest) {
    const message =
      `npm reported success but kavrix is ${installedAfter ?? 'unknown'} (expected ${latest}). ` +
      `Retry \`${npmCommand}\` and verify with \`kavrix --version\`.`;
    const failed: SelfUpdateReport = {
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
    emitReport(failed, options, deps);
    throw new LocalCliError('');
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
      'Report whether a newer release is available without installing (exits 0 on success and on check-mode query failures; use --json for automation).',
    )
    .option(
      '--json',
      'Emit machine-readable JSON ({ installed, latest, updateAvailable, channel, action, error? }); always emitted when set, including failures.',
    )
    .option('--tag <dist-tag>', 'npm dist-tag to follow.', DEFAULT_DIST_TAG)
    .option(
      '--registry <url>',
      'https npm registry URL (http only for localhost; no credentials in URL).',
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
      // --check never mutates; query failures under --check exit 0 after JSON/status.
      await executeSelfUpdate(options);
    });
}
