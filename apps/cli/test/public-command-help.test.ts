import type { Command } from 'commander';
import { describe, expect, it, vi } from 'vitest';

import { buildLocalCli, runLocalCli } from '../src/local-vault-cli.js';
import { LocalSecretInput } from '../src/local-secrets.js';
import { CLI_VERSION } from '../src/version.js';

type CommandNode = Readonly<{
  command: Command;
  segments: readonly Command[];
}>;

type HelpRoute = Readonly<{
  command: Command;
  path: readonly string[];
}>;

type CapturedRun = Readonly<{
  exitCode: string | number | undefined;
  secretReadCount: number;
  stderr: string;
  stdout: string;
}>;

const ANSI_MARKER = /[\u001b\u009b]/u;
const STACK_LINE = /(?:^|\n)\s+at\s+\S+/u;

function visibleChildCommands(command: Command): readonly Command[] {
  const registered = new Set(command.commands);
  return command
    .createHelp()
    .visibleCommands(command)
    .filter((child) => registered.has(child));
}

function collectPublicCommands(
  command: Command,
  segments: readonly Command[] = [],
): readonly CommandNode[] {
  return [
    { command, segments },
    ...visibleChildCommands(command).flatMap((child) =>
      collectPublicCommands(child, [...segments, child]),
    ),
  ];
}

function expandRoutes(segments: readonly Command[]): readonly (readonly string[])[] {
  return segments.reduce<readonly (readonly string[])[]>(
    (routes, segment) =>
      routes.flatMap((route) =>
        [segment.name(), ...segment.aliases()].map((name) => [...route, name]),
      ),
    [[]],
  );
}

function publicHelpRoutes(program: Command): Readonly<{
  aliases: readonly HelpRoute[];
  canonical: readonly HelpRoute[];
}> {
  const canonical: HelpRoute[] = [];
  const aliases: HelpRoute[] = [];
  const seen = new Set<string>();

  for (const node of collectPublicCommands(program)) {
    const canonicalPath = node.segments.map((segment) => segment.name());
    const canonicalKey = canonicalPath.join('\0');
    for (const path of expandRoutes(node.segments)) {
      const key = path.join('\0');
      if (seen.has(key))
        throw new Error(`Duplicate public command route: ${path.join(' ')}`);
      seen.add(key);
      const route = { command: node.command, path };
      if (key === canonicalKey) canonical.push(route);
      else aliases.push(route);
    }
  }

  return { aliases, canonical };
}

function restoreProperty(
  target: NodeJS.WriteStream,
  key: 'isTTY',
  descriptor: PropertyDescriptor | undefined,
): void {
  if (descriptor === undefined) delete (target as { isTTY?: boolean }).isTTY;
  else Object.defineProperty(target, key, descriptor);
}

async function captureNonTtyRun(args: readonly string[]): Promise<CapturedRun> {
  const originalExitCode = process.exitCode;
  const stdoutTty = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  const stderrTty = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
  const stdout: string[] = [];
  const stderr: string[] = [];
  const writeOut = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    stdout.push(String(chunk));
    return true;
  });
  const writeErr = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    stderr.push(String(chunk));
    return true;
  });
  const readSecret = vi
    .spyOn(LocalSecretInput.prototype, 'read')
    .mockRejectedValue(new Error('CLI metadata must never read secret input.'));

  try {
    Object.defineProperty(process.stdout, 'isTTY', {
      configurable: true,
      value: false,
    });
    Object.defineProperty(process.stderr, 'isTTY', {
      configurable: true,
      value: false,
    });
    process.exitCode = undefined;
    await runLocalCli(['node', 'kavrix', ...args]);
    return {
      exitCode: process.exitCode,
      secretReadCount: readSecret.mock.calls.length,
      stderr: stderr.join(''),
      stdout: stdout.join(''),
    };
  } finally {
    readSecret.mockRestore();
    writeOut.mockRestore();
    writeErr.mockRestore();
    restoreProperty(process.stdout, 'isTTY', stdoutTty);
    restoreProperty(process.stderr, 'isTTY', stderrTty);
    process.exitCode = originalExitCode;
  }
}

function normalizedWhitespace(value: string): string {
  return value.replace(/\s+/gu, ' ').trim();
}

function expectNoInternalFailure(output: string): void {
  expect(output).not.toContain('(outputHelp)');
  expect(output).not.toContain('CommanderError');
  expect(output).not.toContain('Kavrix command failed.');
  expect(output).not.toMatch(STACK_LINE);
}

describe('public command help contract', () => {
  it('renders every canonical and alias help route without actions or unsafe output', async () => {
    const routes = publicHelpRoutes(buildLocalCli());

    // These counts make intentional public-surface changes explicit while the
    // tree-derived loop below automatically exercises the resulting routes.
    expect(routes.canonical).toHaveLength(101);
    expect(routes.aliases).toHaveLength(16);

    for (const route of [...routes.canonical, ...routes.aliases]) {
      const label =
        route.path.length === 0 ? 'kavrix' : `kavrix ${route.path.join(' ')}`;
      const result = await captureNonTtyRun([...route.path, '--help']);
      const output = result.stdout + result.stderr;

      expect(result.exitCode, label).toBe(0);
      expect(result.stderr, label).toBe('');
      expect(result.secretReadCount, label).toBe(0);
      expect(output, label).toContain('Usage:');
      expect(normalizedWhitespace(output), label).toContain(
        normalizedWhitespace(route.command.description()),
      );
      expect(output, label).not.toMatch(ANSI_MARKER);
      expect(output, label).not.toMatch(/\binput hidden\b/iu);
      expect(output, label).not.toMatch(/(?:^|\n)\s*error:/iu);
      expectNoInternalFailure(output);
    }
  });

  it('keeps the destructive command registered but hidden and without public help', () => {
    const program = buildLocalCli();
    const destroy = program.commands.find((command) => command.name() === 'destroy');

    expect(destroy).toBeDefined();
    expect(program.createHelp().visibleCommands(program)).not.toContain(destroy);
    expect(program.helpInformation()).not.toMatch(/(?:^|\n)\s+destroy\b/u);
    expect(destroy?.createHelp().visibleOptions(destroy)).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ long: '--help' })]),
    );
  });

  it('renders version as a safe successful non-TTY response', async () => {
    const result = await captureNonTtyRun(['--version']);
    const output = result.stdout + result.stderr;

    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe(CLI_VERSION);
    expect(result.stderr).toBe('');
    expect(result.secretReadCount).toBe(0);
    expect(output).not.toMatch(ANSI_MARKER);
    expectNoInternalFailure(output);
  });

  it('reports an unknown root command with usage exit 2 and no internal detail', async () => {
    const result = await captureNonTtyRun(['definitely-not-a-kavrix-command']);
    const output = result.stdout + result.stderr;

    expect(result.exitCode).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain(
      "error: unknown command 'definitely-not-a-kavrix-command'",
    );
    expect(
      result.stderr.match(/unknown command 'definitely-not-a-kavrix-command'/gu),
    ).toHaveLength(1);
    expect(result.stderr).toContain('Usage: kavrix');
    expect(result.secretReadCount).toBe(0);
    expect(output).not.toMatch(ANSI_MARKER);
    expectNoInternalFailure(output);
  });
});
