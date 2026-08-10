import { describe, expect, it } from 'vitest';

import {
  NodeClipboardCommands,
  NodeClipboardScheduler,
  NodeExecutableResolver,
} from '../src/node-runtime.js';
import type { ClipboardCommand } from '../src/types.js';
import { bytes } from './helpers.js';

const echoScript = [
  "const chunks=[];process.stdin.on('data',(c)=>chunks.push(c));",
  "process.stdin.on('end',()=>process.stdout.write(Buffer.concat(chunks)));",
].join('');

describe('NodeClipboardCommands', () => {
  it('spawns with shell disabled semantics, isolated env, and an owned stdin copy', async () => {
    const runner = new NodeClipboardCommands();
    const secret = bytes('runtime-stdin-canary');
    const command = nodeCommand(echoScript, secret, {
      KAVRIX_CLIPBOARD_TEST: 'isolated',
    });
    const pending = runner.run(command);
    secret.fill(0);

    const result = await pending;
    expect(new TextDecoder().decode(result.stdout)).toBe('runtime-stdin-canary');
    expect(JSON.stringify(command.args)).not.toContain('runtime-stdin-canary');
    expect(JSON.stringify(command.environment)).not.toContain('runtime-stdin-canary');
    result.stdout.fill(0);
  });

  it('does not surface child stderr or secret input through generic failures', async () => {
    const runner = new NodeClipboardCommands();
    const canary = 'runtime-error-secret-canary';
    const script = [
      "const chunks=[];process.stdin.on('data',(c)=>chunks.push(c));",
      "process.stdin.on('end',()=>{process.stderr.write(Buffer.concat(chunks));process.exit(7)});",
    ].join('');
    const operation = runner.run(nodeCommand(script, bytes(canary)));

    await expect(operation).rejects.toMatchObject({
      code: 'CLIPBOARD_OPERATION_FAILED',
      message: 'Clipboard operation failed.',
    });
    await expect(operation).rejects.not.toThrow(canary);
  });

  it('terminates timed-out and aborted children with stable errors', async () => {
    const runner = new NodeClipboardCommands();
    const waiting = 'process.stdin.resume();setInterval(()=>{},1000)';
    const timed = runner.run({
      ...nodeCommand(waiting, bytes('timeout-value')),
      timeoutMs: 25,
    });
    await expect(timed).rejects.toMatchObject({ code: 'CLIPBOARD_TIMEOUT' });

    const controller = new AbortController();
    const aborted = runner.run({
      ...nodeCommand(waiting, bytes('abort-value')),
      signal: controller.signal,
    });
    controller.abort();
    await expect(aborted).rejects.toMatchObject({ code: 'CLIPBOARD_ABORTED' });
  });

  it('bounds stdout without including captured content in the error', async () => {
    const runner = new NodeClipboardCommands();
    const operation = runner.run({
      ...nodeCommand("process.stdout.write('x'.repeat(2048))", new Uint8Array()),
      maxStdoutBytes: 32,
    });
    await expect(operation).rejects.toMatchObject({
      code: 'CLIPBOARD_OPERATION_FAILED',
    });
  });

  it('bounds stderr and rejects unavailable executables generically', async () => {
    const runner = new NodeClipboardCommands();
    const stderr = runner.run({
      ...nodeCommand("process.stderr.write('x'.repeat(2048))", new Uint8Array()),
      maxStderrBytes: 32,
    });
    await expect(stderr).rejects.toMatchObject({
      code: 'CLIPBOARD_OPERATION_FAILED',
    });

    const missing = runner.run({
      ...nodeCommand('', new Uint8Array()),
      executable: `${process.execPath}.does-not-exist`,
    });
    await expect(missing).rejects.toMatchObject({
      code: 'CLIPBOARD_OPERATION_FAILED',
    });
  });

  it('rejects pre-aborted and invalid command configurations', async () => {
    const runner = new NodeClipboardCommands();
    const controller = new AbortController();
    controller.abort();
    await expect(
      runner.run({ ...nodeCommand('', new Uint8Array()), signal: controller.signal }),
    ).rejects.toMatchObject({ code: 'CLIPBOARD_ABORTED' });

    for (const command of [
      { ...nodeCommand('', new Uint8Array()), executable: 'relative-command' },
      { ...nodeCommand('', new Uint8Array()), timeoutMs: 0 },
      { ...nodeCommand('', new Uint8Array()), timeoutMs: 30_001 },
      { ...nodeCommand('', new Uint8Array()), maxStdoutBytes: -1 },
      { ...nodeCommand('', new Uint8Array()), maxStderrBytes: -1 },
    ]) {
      expect(() => runner.run(command)).toThrow(
        expect.objectContaining({ code: 'CLIPBOARD_VALIDATION_FAILED' }),
      );
    }
  });

  it('resolves only accessible absolute executables and supports cancellable timers', async () => {
    const resolver = new NodeExecutableResolver();
    await expect(
      resolver.resolve('node', [
        'relative',
        `${process.execPath}.missing`,
        process.execPath,
      ]),
    ).resolves.toBe(process.execPath);
    await expect(resolver.resolve('missing', ['relative'])).resolves.toBeNull();

    const scheduler = new NodeClipboardScheduler();
    let called = false;
    const timer = scheduler.set(10_000, () => {
      called = true;
    });
    scheduler.clear(timer);
    await new Promise((resolve) => setImmediate(resolve));
    expect(called).toBe(false);
  });
});

function nodeCommand(
  script: string,
  stdin: Uint8Array,
  environment: Readonly<Record<string, string>> = {},
): ClipboardCommand {
  return {
    executable: process.execPath,
    args: ['-e', script],
    environment,
    stdin,
    timeoutMs: 5_000,
    maxStdoutBytes: 1024 * 1024,
    maxStderrBytes: 16 * 1024,
  };
}
