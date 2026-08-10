import { ClipboardError } from '../src/errors.js';
import type {
  ClipboardCommand,
  ClipboardCommandPort,
  ClipboardCommandResult,
  ClipboardRuntime,
  ClipboardSchedulerPort,
  ExecutableResolverPort,
} from '../src/types.js';

export class MemoryClipboardCommands implements ClipboardCommandPort {
  public clipboard: Uint8Array = new Uint8Array();
  public readonly calls: ClipboardCommand[] = [];
  public afterWrite: (() => void) | undefined;
  public failAfterWrite = false;
  public failNext = false;
  public failuresRemaining = 0;
  public rawReadOutput: Uint8Array | undefined;
  public rawWriteInput: Uint8Array | undefined;

  public run(command: ClipboardCommand): Promise<ClipboardCommandResult> {
    this.calls.push(cloneCommand(command));
    if (command.signal?.aborted === true) {
      return Promise.reject(
        new ClipboardError('CLIPBOARD_ABORTED', 'Clipboard operation was cancelled.'),
      );
    }
    if (this.failNext) {
      this.failNext = false;
      return Promise.reject(
        new ClipboardError('CLIPBOARD_OPERATION_FAILED', 'Clipboard operation failed.'),
      );
    }
    if (this.failuresRemaining > 0) {
      this.failuresRemaining -= 1;
      return Promise.reject(
        new ClipboardError('CLIPBOARD_OPERATION_FAILED', 'Clipboard operation failed.'),
      );
    }
    const kind = commandKind(command);
    if (kind === 'read') {
      const stdout = Uint8Array.from(this.clipboard);
      this.rawReadOutput = stdout;
      return Promise.resolve({ stdout });
    }
    if (kind === 'clear') {
      this.clipboard.fill(0);
      this.clipboard = new Uint8Array();
      return Promise.resolve({ stdout: new Uint8Array() });
    }
    this.clipboard.fill(0);
    this.rawWriteInput = command.stdin;
    this.clipboard = Uint8Array.from(command.stdin ?? new Uint8Array());
    this.afterWrite?.();
    if (this.failAfterWrite) {
      this.failAfterWrite = false;
      return Promise.reject(
        new ClipboardError('CLIPBOARD_OPERATION_FAILED', 'Clipboard operation failed.'),
      );
    }
    return Promise.resolve({ stdout: new Uint8Array() });
  }
}

export class MemoryExecutableResolver implements ExecutableResolverPort {
  public readonly requests: Readonly<{
    name: string;
    candidates: readonly string[];
  }>[] = [];

  public constructor(private readonly available: ReadonlySet<string>) {}

  public resolve(name: string, candidates: readonly string[]): Promise<string | null> {
    (this.requests as { name: string; candidates: readonly string[] }[]).push({
      name,
      candidates: [...candidates],
    });
    return Promise.resolve(
      candidates.find((candidate) => this.available.has(candidate)) ?? null,
    );
  }
}

interface ScheduledTask {
  readonly task: () => void;
  readonly delayMs: number;
  cancelled: boolean;
}

export class MemoryScheduler implements ClipboardSchedulerPort {
  public readonly tasks: ScheduledTask[] = [];

  public set(delayMs: number, task: () => void): ScheduledTask {
    const scheduled = { task, delayMs, cancelled: false };
    this.tasks.push(scheduled);
    return scheduled;
  }

  public clear(handle: object | number): void {
    (handle as ScheduledTask).cancelled = true;
  }

  public async run(index: number, includeCancelled = false): Promise<void> {
    const scheduled = this.tasks[index];
    if (scheduled === undefined) throw new Error('Missing scheduled task');
    if (!scheduled.cancelled || includeCancelled) scheduled.task();
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
  }
}

export function testRuntime(
  platform: NodeJS.Platform,
  available: readonly string[],
  environment: Readonly<Record<string, string | undefined>> = {},
): Readonly<{
  runtime: ClipboardRuntime;
  commands: MemoryClipboardCommands;
  executables: MemoryExecutableResolver;
  scheduler: MemoryScheduler;
}> {
  const commands = new MemoryClipboardCommands();
  const executables = new MemoryExecutableResolver(new Set(available));
  const scheduler = new MemoryScheduler();
  return {
    runtime: { platform, environment, commands, executables, scheduler },
    commands,
    executables,
    scheduler,
  };
}

export function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function cloneCommand(command: ClipboardCommand): ClipboardCommand {
  return {
    ...command,
    args: [...command.args],
    environment: { ...command.environment },
    ...(command.stdin === undefined ? {} : { stdin: Uint8Array.from(command.stdin) }),
  };
}

function commandKind(command: ClipboardCommand): 'clear' | 'read' | 'write' {
  const args = command.args.join(' ');
  if (args.includes('Clipboard]::GetText') || args.includes('--no-newline')) {
    return 'read';
  }
  if (args.includes('Clipboard]::Clear') || args.includes('--clear')) return 'clear';
  if (args.includes('-out') || args.includes('--output')) return 'read';
  if (command.executable.endsWith('pbpaste')) return 'read';
  return command.stdin?.byteLength === 0 ? 'clear' : 'write';
}
