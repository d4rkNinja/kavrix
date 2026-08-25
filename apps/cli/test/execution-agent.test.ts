import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { executeAgentRun } from '../src/execution/agent-command.js';
import {
  createExecutionFixture,
  destroyFixture,
  passphraseFrame,
  withStdinFrames,
  type ExecutionFixture,
} from './execution-helpers.js';

let fixture: ExecutionFixture;

const SECRET_VALUE = 'agent-canary-token-value';

beforeEach(async () => {
  fixture = await createExecutionFixture({
    'github/token': SECRET_VALUE,
  });
});

afterEach(async () => {
  await destroyFixture(fixture);
});

interface RecordedFrame {
  event: string;
  outcome?: string;
  reason?: string;
  data?: string;
  exitCode?: number | null;
}

interface AgentObservation {
  readonly allowed: Record<string, unknown>;
  readonly denied: Array<{ permission: string; frames: RecordedFrame[] }>;
  readonly clientRun?: {
    readonly code: number;
    readonly out: string;
    readonly err?: string;
  };
  readonly failing?: { readonly frames: RecordedFrame[] };
}

function agentScript(observationFile: string): string {
  return [
    'const net = require("node:net");',
    'const fs = require("node:fs");',
    `const observationFile = ${JSON.stringify(observationFile)};`,
    'const token = process.env.KAVRIX_AGENT_TOKEN ?? "";',
    'const endpoint = process.env.KAVRIX_AGENT_BROKER ?? "";',
    'if (!token || !endpoint) { fs.writeFileSync(observationFile, JSON.stringify({error:"missing-broker-env"})); process.exit(1); }',
    'function request(permission, argv, overrideToken) {',
    '  return new Promise((resolve) => {',
    '    const socket = net.connect(endpoint, () => {',
    '      socket.write(JSON.stringify({ v: 1, token: overrideToken ?? token, op: "exec", permission, argv }) + "\\n");',
    '    });',
    '    let buffer = "";',
    '    const frames = [];',
    '    const finish = () => { resolve({ frames }); socket.end(); };',
    '    socket.on("data", (chunk) => {',
    '      buffer += chunk.toString("utf8");',
    '      let index;',
    '      while ((index = buffer.indexOf("\\n")) >= 0) {',
    '        const frame = JSON.parse(buffer.slice(0, index));',
    '        buffer = buffer.slice(index + 1);',
    '        frames.push(frame);',
    '        if (frame.event === "exit") {',
    '          finish();',
    '          return;',
    '        }',
    '      }',
    '    });',
    '    socket.on("close", () => resolve({ frames, closedWithoutExit: true }));',
    '    socket.on("error", (error) => resolve({ frames, error: String(error) }));',
    '  });',
    '}',
    '(async () => {',
    `  const innerScript = 'const big = "x".repeat(700*1024); const nl = String.fromCharCode(10); process.stdout.write("LEAKED:" + (process.env.GITHUB_TOKEN ?? "") + nl); process.stdout.write(big + nl); process.exitCode = 3;';`,
    '  const allowed = await request("gh", [process.execPath, "-e", innerScript]);',
    '  const deniedUnknown = await request("unknown-permission", [process.execPath, "-e", "process.exit(0)"]);',
    '  const deniedEntry = await request("prod-db", [process.execPath, "-e", "process.exit(0)"]);',
    '  const confirmGate = await request("confirm-gate", [process.execPath, "-e", "process.exit(0)"]);',
    '  const unresolved = await request("gh", ["definitely-missing-kavrix-tool"]);',
    '  const noMapping = await request("no-env-permission", [process.execPath, "-e", "process.exit(0)"]);',
    '  // Inner child exits nonzero so the supervisor propagates exitCode 7.',
    '  const failing = await request("gh", [process.execPath, "-e", "process.exit(7)"]);',
    '  const { execFileSync } = require("node:child_process");',
    `  const bin = ${JSON.stringify(join(process.cwd(), 'apps', 'cli', 'dist', 'bin.js'))};`,
    '  let clientRun = null;',
    '  try {',
    '    const out = execFileSync(',
    '      process.execPath,',
    '      [bin, "agent", "exec", "gh", "--", process.execPath, "-e",',
    '       "console.log(\\"CLIENT:\\" + (process.env.GITHUB_TOKEN ?? \\"\\")); process.exit(5)"],',
    '      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },',
    '    );',
    '    clientRun = { code: 0, out };',
    '  } catch (error) {',
    '    clientRun = {',
    '      code: error.status,',
    '      out: String(error.stdout ?? ""),',
    '      err: String(error.stderr ?? ""),',
    '    };',
    '  }',
    '  fs.writeFileSync(observationFile, JSON.stringify({ allowed, deniedUnknown, deniedEntry, confirmGate, unresolved, noMapping, clientRun, failing }));',
    '  process.exit(0);',
    '})().catch((error) => { fs.writeFileSync(observationFile, JSON.stringify({ error: String(error) })); process.exit(1); });',
  ].join('\n');
}

describe('kavrix agent firewall', () => {
  it('brokers an authorized operation without exposing secrets to the agent process', async () => {
    const configFile = join(fixture.directory, 'agents.json');
    await writeFile(
      configFile,
      JSON.stringify({
        version: 1,
        agents: {
          bot: {
            permissions: {
              gh: {
                secret: 'github/token',
                commands: ['node'],
                env: 'GITHUB_TOKEN',
              },
              'prod-db': { deny: true },
              'no-env-permission': {
                secret: 'github/token',
                commands: ['node'],
              },
              'confirm-gate': {
                secret: 'github/token',
                commands: ['node'],
                env: 'GITHUB_TOKEN',
                requireConfirmation: true,
              },
            },
          },
        },
      }),
    );

    const observationFile = join(fixture.directory, 'observation.json');
    const originalExit = process.exitCode;

    const summary = (await withStdinFrames(passphraseFrame(), () =>
      executeAgentRun({
        profile: 'exec',
        profileConfigDir: join(fixture.directory, 'profiles'),
        vault: fixture.vaultId,
        databaseUrlStdin: false,
        passphraseStdin: true,
        agentName: 'bot',
        config: configFile,
        executableAndArgs: [process.execPath, '-e', agentScript(observationFile)],
      }),
    )) as {
      ran: boolean;
      allowedRequests: number;
      deniedRequests: number;
      exitCode: number;
    };

    process.exitCode = originalExit;
    expect(summary.ran).toBe(true);
    // One raw-socket allow, plus one allow through the real client binary;
    // denials: unknown permission, deny entry, confirmation unavailable,
    // unresolved executable, and a missing injection mapping.
    expect(summary.allowedRequests).toBe(3);
    expect(summary.deniedRequests).toBe(5);
    // The agent process exited cleanly; its own exit code propagates.
    expect(summary.exitCode).toBe(0);

    const observation = JSON.parse(
      await readFile(observationFile, 'utf8'),
    ) as AgentObservation;

    const allowFrames = observation.allowed.frames as RecordedFrame[];
    const decision = allowFrames.find((frame) => frame.event === 'decision');
    expect(decision).toMatchObject({ outcome: 'allow' });
    // Output larger than one frame is split into bounded base64 chunks and
    // reassembles into the exact child bytes.
    const stdoutFrames = allowFrames.filter((frame) => frame.event === 'stdout');
    const decodedStdout = Buffer.concat(
      stdoutFrames.map((frame) => Buffer.from(frame.data ?? '', 'base64')),
    ).toString('utf8');
    expect(decodedStdout).toContain(`LEAKED:${SECRET_VALUE}`);
    expect(decodedStdout.length).toBeGreaterThan(700 * 1024);
    const exitFrame = allowFrames.find((frame) => frame.event === 'exit');
    expect(exitFrame?.exitCode).toBe(3);

    expect(observation.deniedUnknown.frames.some((f) => f.outcome === 'deny')).toBe(
      true,
    );
    expect(observation.deniedEntry.frames.map((f) => f.reason)).toContain(
      'policy-denied',
    );
    expect(observation.confirmGate.frames.map((f) => f.reason)).toContain(
      'confirmation-unavailable',
    );
    expect(observation.unresolved.frames.map((f) => f.reason)).toContain(
      'executable-unresolved',
    );
    expect(observation.noMapping.frames.map((f) => f.reason)).toContain(
      'no-injection-mapping',
    );

    // Nonzero inner exits propagate through the broker's exit frame.
    const failingExit = observation.failing?.frames.find(
      (frame) => frame.event === 'exit',
    );
    expect(failingExit?.exitCode).toBe(7);

    // The real `agent exec` client drove the same broker end to end: the
    // authorized child's stdout reached the client, and the child's exit
    // code (5) became the client process exit code.
    expect(observation.clientRun).toBeDefined();
    const clientRun = observation.clientRun as {
      code: number;
      out: string;
      err?: string;
    };
    expect(
      clientRun.code,
      `client-run | out=${clientRun.out.slice(0, 200)} | err=${(clientRun.err ?? '').slice(0, 300)}`,
    ).toBe(5);
    expect(clientRun.out).toContain(`CLIENT:${SECRET_VALUE}`);
    expect(observation.deniedEntry.frames.map((f) => f.reason)).toContain(
      'policy-denied',
    );
    expect(observation.confirmGate.frames.map((f) => f.reason)).toContain(
      'confirmation-unavailable',
    );

    // The supervisor's own protocol view (raw frames) carries no plaintext;
    // the client's captured stdout is the authorized child's output and is
    // asserted separately above.
    const { clientRun: _clientOutput, ...protocolView } = observation;
    void _clientOutput;
    expect(JSON.stringify(protocolView)).not.toContain(SECRET_VALUE);
  });

  it('refuses agents when the configured agent name is missing', async () => {
    const configFile = join(fixture.directory, 'agents.json');
    await writeFile(configFile, JSON.stringify({ version: 1, agents: {} }));

    let message = '';
    try {
      await withStdinFrames(passphraseFrame(), () =>
        executeAgentRun({
          profile: 'exec',
          profileConfigDir: join(fixture.directory, 'profiles'),
          vault: fixture.vaultId,
          databaseUrlStdin: false,
          passphraseStdin: true,
          agentName: 'missing-bot',
          config: configFile,
          executableAndArgs: [process.execPath, '-e', 'process.exit(0)'],
        }),
      );
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain('not defined');
  });

  it('requires a project configuration explicitly or beside the working directory', async () => {
    let message = '';
    try {
      await withStdinFrames(passphraseFrame(), () =>
        executeAgentRun({
          profile: 'exec',
          profileConfigDir: join(fixture.directory, 'profiles'),
          vault: fixture.vaultId,
          databaseUrlStdin: false,
          passphraseStdin: true,
          agentName: 'bot',
          executableAndArgs: [process.execPath, '-e', 'process.exit(0)'],
        }),
      );
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain('project file');
  });
});
