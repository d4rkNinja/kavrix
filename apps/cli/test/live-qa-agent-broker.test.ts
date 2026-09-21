import { spawn } from 'node:child_process';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { ensureSecureDirectory } from '@kavrix/key-files';
import { runCli } from './execution-helpers.js';

const directories: string[] = [];

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) =>
      rm(directory, { force: true, recursive: true }).catch(() => undefined),
    ),
  );
});

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-agent-qa-${label}-`),
  );
  directories.push(directory);
  return directory;
}

const CANARY = 'live-qa-agent-canary-TOPSECRET-2231';
const PASSPHRASE = 'AgentQaPassphrase22!';

/**
 * The agent process under test. It proves the credential-firewall contract
 * from inside the session and writes its findings to a result file:
 * the agent environment and argv never contain the secret, only the broker
 * endpoint and one-session token, authorized `agent exec` runs deliver the
 * secret to the allowed grandchild only, policy denials never start a child,
 * and a missing broker-side executable maps to the execution-failure exit
 * (not an authorization denial).
 */
const AGENT_SCRIPT = `
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const [resultPath, binPath] = process.argv.slice(2);
const CANARY = ${JSON.stringify(CANARY)};
const result = {
  canaryHiddenInEnv: true,
  canaryHiddenInArgv: true,
  brokerEnvPresent: false,
  allowedValue: null,
  allowExit: null,
  denialExit: null,
  denialStderr: '',
  denialStdout: '',
  unknownExit: null,
  unknownStderr: '',
  missingJsonExit: null,
  missingJsonCode: '',
  missingHumanExit: null,
  missingHumanStderr: '',
};
for (const [name, value] of Object.entries(process.env)) {
  if (typeof value === 'string' && value.includes(CANARY)) {
    result.canaryHiddenInEnv = false;
    result.leakyVariable = name;
  }
}
if (JSON.stringify(process.argv).includes(CANARY)) result.canaryHiddenInArgv = false;
result.brokerEnvPresent =
  typeof process.env.KAVRIX_AGENT_BROKER === 'string' &&
  process.env.KAVRIX_AGENT_BROKER.length > 0 &&
  typeof process.env.KAVRIX_AGENT_TOKEN === 'string' &&
  process.env.KAVRIX_AGENT_TOKEN.length > 0;

const exec = (permission, args, extraOptions) =>
  spawnSync(
    process.execPath,
    [binPath, 'agent', 'exec', permission, ...extraOptions, '--', ...args],
    { encoding: 'utf8' },
  );

const printToken = "process.stdout.write(process.env.TARGET_TOKEN === undefined ? 'MISSING' : process.env.TARGET_TOKEN)";
const allowed = exec('token-read', [process.execPath, '-e', printToken], []);
result.allowedValue = allowed.stdout;
result.allowExit = allowed.status;

const leakAttempt = "process.stdout.write('RAN:' + (process.env.TARGET_TOKEN === undefined ? 'MISSING' : process.env.TARGET_TOKEN))";
const denial = exec('token-blocked', [process.execPath, '-e', leakAttempt], []);
result.denialExit = denial.status;
result.denialStderr = (denial.stderr || '').trim();
result.denialStdout = (denial.stdout || '');

const unknown = exec('no-such-permission', [process.execPath, '-e', '1'], []);
result.unknownExit = unknown.status;
result.unknownStderr = (unknown.stderr || '').trim();

const missingJson = exec(
  'token-read',
  ['definitely-not-a-real-executable-xyz'],
  ['--json'],
);
result.missingJsonExit = missingJson.status;
const lastJsonLine = (missingJson.stdout || '')
  .trim()
  .split('\\n')
  .filter(Boolean)
  .pop();
result.missingJsonCode =
  lastJsonLine === undefined ? '' : String(JSON.parse(lastJsonLine).error.code);

const missingHuman = exec(
  'token-read',
  ['definitely-not-a-real-executable-xyz'],
  [],
);
result.missingHumanExit = missingHuman.status;
result.missingHumanStderr = (missingHuman.stderr || '').trim();

fs.writeFileSync(resultPath, JSON.stringify(result));
`;

describe('0.2.23 live agent broker isolation (real CLI, isolated home)', () => {
  it(
    'hides credentials from the agent, delivers them only to authorized children, denies policy violations, audits both, and maps child-start misses to execution failure',
    async () => {
      const home = await scratch('journey');
      const configDir = join(home, 'config');
      const env: NodeJS.ProcessEnv = { HOME: home, USERPROFILE: home };
      const bin = resolve('apps/cli/dist/bin.js');

      const live = (args: readonly string[], frames: readonly string[]) =>
        new Promise<{ stdout: string; stderr: string; code: number | null }>(
          (resolvePromise, rejectPromise) => {
            const child = spawn(process.execPath, [bin, ...args], {
              env: { ...process.env, ...env },
              stdio: ['pipe', 'pipe', 'pipe'],
              windowsHide: true,
            });
            const stdout: Buffer[] = [];
            const stderr: Buffer[] = [];
            child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
            child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
            child.stdin.end(frames.map((frame) => `${frame}\n`).join(''), 'utf8');
            child.on('error', rejectPromise);
            child.on('close', (exitCode) => {
              resolvePromise({
                stdout: Buffer.concat(stdout).toString('utf8'),
                stderr: Buffer.concat(stderr).toString('utf8'),
                code: exitCode,
              });
            });
          },
        );

      // ---- Real datastore setup through the CLI ----
      // Portable-key writes require an existing owner-only parent; create and
      // harden the kavrix home exactly like classic init does.
      await ensureSecureDirectory(join(home, '.kavrix'));
      const add = await live(
        [
          'db',
          'profile',
          'add',
          'default',
          '--datastore',
          'file',
          '--data-file',
          join(home, '.kavrix', 'kavrix.vault'),
          '--key-file',
          join(home, '.kavrix', 'kavrix.key'),
          '--profile-config-dir',
          configDir,
          '--json',
        ],
        [],
      );
      expect(add.code).toBe(0);
      expect(
        (
          await live(
            ['db', 'profile', 'use', 'default', '--profile-config-dir', configDir],
            [],
          )
        ).code,
      ).toBe(0);
      const init = await live(
        [
          'db',
          'init',
          '--profile',
          'default',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
          '--json',
        ],
        ['lab', PASSPHRASE, PASSPHRASE],
      );
      expect(init.code).toBe(0);
      const vaultCreate = await live(
        [
          'db',
          'vault',
          'create',
          '--profile',
          'default',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
          '--json',
        ],
        [PASSPHRASE, 'agent-qa-vault'],
      );
      expect(vaultCreate.code).toBe(0);
      const created = JSON.parse(vaultCreate.stdout) as { vaultId?: string };
      const vaultId = created.vaultId;
      expect(typeof vaultId).toBe('string');
      expect(
        (
          await live(
            [
              'db',
              'vault',
              'use',
              String(vaultId),
              '--profile',
              'default',
              '--profile-config-dir',
              configDir,
              '--passphrase-stdin',
            ],
            [PASSPHRASE],
          )
        ).code,
      ).toBe(0);
      const put = await live(
        [
          'put',
          'github/token',
          '--profile',
          'default',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
          '--value-stdin',
        ],
        [PASSPHRASE, CANARY],
      );
      expect(put.code).toBe(0);

      // ---- Project agent firewall config ----
      const projectDir = join(home, 'project');
      await mkdir(projectDir, { recursive: true });
      await writeFile(
        join(projectDir, 'kavrix.yaml'),
        [
          'version: 1',
          'agents:',
          '  bot:',
          '    permissions:',
          '      token-read:',
          '        secret: github/token',
          '        env: TARGET_TOKEN',
          '        commands:',
          '          - node',
          '      token-blocked:',
          '        secret: github/token',
          '        env: TARGET_TOKEN',
          '        commands:',
          '          - definitely-not-a-real-executable-xyz',
          '',
        ].join('\n'),
        'utf8',
      );

      // ---- Run the agent: it holds no secret material ----
      const resultPath = join(home, 'agent-result.json');
      const agentScriptPath = join(home, 'agent-child.cjs');
      await writeFile(agentScriptPath, AGENT_SCRIPT, 'utf8');
      const run = await live(
        [
          'agent',
          'run',
          '--agent',
          'bot',
          '--config',
          join(projectDir, 'kavrix.yaml'),
          '--profile',
          'default',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
          '--json',
          '--',
          'node',
          agentScriptPath,
          resultPath,
          bin,
        ],
        [PASSPHRASE],
      );

      const envelopeLine = run.stdout.trim().split('\n').filter(Boolean).pop() ?? '';
      const envelope = JSON.parse(envelopeLine) as {
        ran?: boolean;
        allowedRequests?: number;
        deniedRequests?: number;
        exitCode?: number;
      };
      expect(
        envelope.ran,
        `run stderr: ${run.stderr}
run stdout: ${run.stdout}`,
      ).toBe(true);
      expect(envelope.allowedRequests).toBe(1);
      expect(envelope.deniedRequests).toBe(2);
      expect(envelope.exitCode).toBe(0);

      const result = JSON.parse(await readFile(resultPath, 'utf8')) as {
        canaryHiddenInEnv: boolean;
        canaryHiddenInArgv: boolean;
        brokerEnvPresent: boolean;
        allowedValue: string;
        allowExit: number | null;
        denialExit: number | null;
        denialStderr: string;
        denialStdout: string;
        unknownExit: number | null;
        unknownStderr: string;
        missingJsonExit: number | null;
        missingJsonCode: string;
        missingHumanExit: number | null;
        missingHumanStderr: string;
      };

      // THE core isolation guarantee: the agent never holds the credential.
      expect(result.canaryHiddenInEnv).toBe(true);
      expect(result.canaryHiddenInArgv).toBe(true);
      // It only gets the broker endpoint and a one-session token.
      expect(result.brokerEnvPresent).toBe(true);
      // Authorized request: the broker injects the secret into that child only.
      // (The exec client appends its own decision summary line to the output.)
      expect(result.allowExit).toBe(0);
      expect(result.allowedValue).toContain(CANARY);
      expect(result.allowedValue).toContain('outcome=allow');
      expect(result.allowedValue).not.toContain('MISSING');
      // Policy violation: denied before any child starts; no secret, no run.
      expect(result.denialExit).toBe(1);
      expect(result.denialStderr).toContain('denied (command-not-allowed)');
      expect(result.denialStdout).not.toContain('RAN:');
      expect(result.denialStdout).not.toContain(CANARY);
      // Unknown permission: fail closed as well.
      expect(result.unknownExit).toBe(1);
      expect(result.unknownStderr).toContain('denied (policy-denied)');
      // Missing broker-side executable: the execution-failure path (exit 18),
      // never an authorization deny — parity with `kavrix run`.
      expect(result.missingJsonExit).toBe(18);
      expect(result.missingJsonCode).toBe('EXECUTION_FAILED');
      expect(result.missingHumanExit).toBe(18);
      expect(result.missingHumanStderr.length).toBeGreaterThan(0);

      // ---- Audit recorded allowed and denied decisions, never the secret ----
      const audit = await live(
        [
          'audit',
          '--profile',
          'default',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
          '--json',
        ],
        [PASSPHRASE],
      );
      expect(audit.code).toBe(0);
      expect(audit.stdout).not.toContain(CANARY);
      const auditBody = JSON.parse(audit.stdout) as {
        events?: Array<{ action?: string }>;
      };
      const actions = (auditBody.events ?? []).map((event) => event.action ?? '');
      expect(actions).toContain('authorization-allowed');
      expect(actions, JSON.stringify(auditBody)).toContain('authorization-denied');

      // ---- In-process guard: runCli classification stays coherent ----
      const dryRun = await runCli(
        [
          'agent',
          'run',
          '--agent',
          'bot',
          '--config',
          join(projectDir, 'kavrix.yaml'),
          '--profile',
          'default',
          '--profile-config-dir',
          configDir,
          '--dry-run',
          '--json',
        ],
        '',
      );
      expect(dryRun.exitCode).toBe(0);
      const dryRunBody = JSON.parse(dryRun.stdout) as { permissionCount?: number };
      expect(dryRunBody.permissionCount).toBe(2);
    },
    process.platform === 'win32' ? 900_000 : 300_000,
  );
});
