export const MIN_CLEAR_TIMEOUT_MS = 250;
export const MAX_CLEAR_TIMEOUT_MS = 5 * 60 * 1_000;
export const MAX_CLIPBOARD_BYTES = 1024 * 1024;

export interface ClipboardCopyOptions {
  /** Clear delay is bounded to 250 ms through five minutes. */
  readonly clearAfterMs: number;
  readonly signal?: AbortSignal;
}

export interface ClipboardCopyReceipt {
  /** Opaque in-process ownership generation; it is not a secret or identifier. */
  readonly generation: number;
  readonly clearAfterMs: number;
}

export interface SecureClipboardPort {
  /** Copies already-authorized UTF-8 secret bytes without taking ownership. */
  copy(
    secret: Uint8Array,
    options: ClipboardCopyOptions,
  ): Promise<ClipboardCopyReceipt>;
  /** Immediately clears only the still-matching Kavrix clipboard generation. */
  lock(signal?: AbortSignal): Promise<boolean>;
  /** Cancels timers and performs the same guarded best-effort clear as lock. */
  dispose(signal?: AbortSignal): Promise<boolean>;
  /** Returns and clears a generic failure raised by a background expiry. */
  takeBackgroundError(): Error | null;
}

export interface ClipboardCommand {
  readonly executable: string;
  readonly args: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
  readonly stdin?: Uint8Array;
  readonly timeoutMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
  readonly signal?: AbortSignal;
}

export interface ClipboardCommandResult {
  /** Adapter-owned bytes; the consumer must clear them after use. */
  readonly stdout: Uint8Array;
}

export interface ClipboardCommandPort {
  run(command: ClipboardCommand): Promise<ClipboardCommandResult>;
}

export interface ExecutableResolverPort {
  resolve(name: string, candidates: readonly string[]): Promise<string | null>;
}

export interface ClipboardSchedulerPort {
  set(delayMs: number, task: () => void): object | number;
  clear(handle: object | number): void;
}

export interface ClipboardRuntime {
  readonly platform: NodeJS.Platform;
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly commands: ClipboardCommandPort;
  readonly executables: ExecutableResolverPort;
  readonly scheduler: ClipboardSchedulerPort;
}
