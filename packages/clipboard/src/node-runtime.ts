import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { isAbsolute } from 'node:path';

import { ClipboardError } from './errors.js';
import type {
  ClipboardCommand,
  ClipboardCommandPort,
  ClipboardCommandResult,
  ClipboardRuntime,
  ClipboardSchedulerPort,
  ExecutableResolverPort,
} from './types.js';

export class NodeClipboardCommands implements ClipboardCommandPort {
  public run(command: ClipboardCommand): Promise<ClipboardCommandResult> {
    if (command.signal?.aborted === true) {
      return Promise.reject(abortedError());
    }
    assertCommand(command);
    return new Promise((resolve, reject) => {
      const ownedInput = Uint8Array.from(command.stdin ?? new Uint8Array());
      const stdoutChunks: Uint8Array[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let failure: ClipboardError | null = null;
      let settled = false;

      let child: ChildProcessWithoutNullStreams;
      try {
        child = spawn(command.executable, [...command.args], {
          shell: false,
          windowsHide: true,
          stdio: ['pipe', 'pipe', 'pipe'],
          env: { ...command.environment },
        });
      } catch {
        ownedInput.fill(0);
        reject(
          new ClipboardError(
            'CLIPBOARD_OPERATION_FAILED',
            'Clipboard operation failed.',
          ),
        );
        return;
      }

      const fail = (error: ClipboardError): void => {
        failure ??= error;
        child.kill('SIGKILL');
      };
      const timeout = setTimeout(() => {
        fail(new ClipboardError('CLIPBOARD_TIMEOUT', 'Clipboard operation timed out.'));
      }, command.timeoutMs);
      timeout.unref();
      const onAbort = (): void => {
        fail(abortedError());
      };
      command.signal?.addEventListener('abort', onAbort, { once: true });

      child.stdout.on('data', (value: Buffer) => {
        stdoutBytes += value.byteLength;
        if (stdoutBytes > command.maxStdoutBytes) {
          value.fill(0);
          fail(
            new ClipboardError(
              'CLIPBOARD_OPERATION_FAILED',
              'Clipboard operation failed.',
            ),
          );
          return;
        }
        stdoutChunks.push(Uint8Array.from(value));
        value.fill(0);
      });
      child.stderr.on('data', (value: Buffer) => {
        stderrBytes += value.byteLength;
        value.fill(0);
        if (stderrBytes > command.maxStderrBytes) {
          fail(
            new ClipboardError(
              'CLIPBOARD_OPERATION_FAILED',
              'Clipboard operation failed.',
            ),
          );
        }
      });
      child.on('error', () => {
        failure ??= new ClipboardError(
          'CLIPBOARD_OPERATION_FAILED',
          'Clipboard operation failed.',
        );
      });
      child.on('close', (code, signal) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        command.signal?.removeEventListener('abort', onAbort);
        ownedInput.fill(0);
        if (failure !== null || code !== 0 || signal !== null) {
          wipeChunks(stdoutChunks);
          reject(
            failure ??
              new ClipboardError(
                'CLIPBOARD_OPERATION_FAILED',
                'Clipboard operation failed.',
              ),
          );
          return;
        }
        const combined = Buffer.concat(
          stdoutChunks.map((chunk) =>
            Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength),
          ),
          stdoutBytes,
        );
        const stdout = Uint8Array.from(combined);
        combined.fill(0);
        wipeChunks(stdoutChunks);
        resolve({ stdout });
      });

      child.stdin.on('error', () => {
        // Close/exit decides the generic outcome; never surface native text.
      });
      child.stdin.end(
        Buffer.from(ownedInput.buffer, ownedInput.byteOffset, ownedInput.byteLength),
      );
    });
  }
}

export class NodeExecutableResolver implements ExecutableResolverPort {
  public async resolve(
    _name: string,
    candidates: readonly string[],
  ): Promise<string | null> {
    for (const candidate of candidates) {
      if (!isAbsolute(candidate)) continue;
      try {
        await access(candidate, constants.X_OK);
        return candidate;
      } catch (error) {
        if (!isMissingOrDenied(error)) {
          throw new ClipboardError(
            'CLIPBOARD_OPERATION_FAILED',
            'Clipboard command detection failed.',
          );
        }
      }
    }
    return null;
  }
}

export class NodeClipboardScheduler implements ClipboardSchedulerPort {
  public set(delayMs: number, task: () => void): NodeJS.Timeout {
    const handle = setTimeout(task, delayMs);
    handle.unref();
    return handle;
  }

  public clear(handle: object | number): void {
    clearTimeout(handle as NodeJS.Timeout);
  }
}

export function createNodeClipboardRuntime(): ClipboardRuntime {
  return {
    platform: process.platform,
    environment: process.env,
    commands: new NodeClipboardCommands(),
    executables: new NodeExecutableResolver(),
    scheduler: new NodeClipboardScheduler(),
  };
}

function assertCommand(command: ClipboardCommand): void {
  if (
    !isAbsolute(command.executable) ||
    !Number.isSafeInteger(command.timeoutMs) ||
    command.timeoutMs < 1 ||
    command.timeoutMs > 30_000 ||
    !Number.isSafeInteger(command.maxStdoutBytes) ||
    command.maxStdoutBytes < 0 ||
    !Number.isSafeInteger(command.maxStderrBytes) ||
    command.maxStderrBytes < 0
  ) {
    throw new ClipboardError(
      'CLIPBOARD_VALIDATION_FAILED',
      'Clipboard command configuration is invalid.',
    );
  }
}

function abortedError(): ClipboardError {
  return new ClipboardError('CLIPBOARD_ABORTED', 'Clipboard operation was cancelled.');
}

function wipeChunks(chunks: readonly Uint8Array[]): void {
  for (const chunk of chunks) chunk.fill(0);
}

function isMissingOrDenied(error: unknown): boolean {
  if (typeof error !== 'object' || error === null || !('code' in error)) return false;
  const code = String(error.code);
  return code === 'ENOENT' || code === 'EACCES' || code === 'EPERM';
}
