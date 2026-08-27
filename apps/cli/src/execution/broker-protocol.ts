import { timingSafeEqual } from 'node:crypto';

/**
 * Pure protocol helpers for the agent broker. Kept separate from the socket
 * orchestration so the framing, token, and sanitization rules can be tested
 * directly against adversarial inputs.
 */

export const MAX_FRAME_BYTES = 2 * 1024 * 1024;

export class BrokerFrameTooLargeError extends Error {
  public constructor() {
    super('The agent broker frame exceeds the maximum size.');
    this.name = 'BrokerFrameTooLargeError';
  }
}

export class NdjsonDecoder {
  private buffer = Buffer.alloc(0);

  public push(chunk: Buffer): readonly string[] {
    let pending =
      this.buffer.byteLength === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const lines: string[] = [];
    let newline = pending.indexOf(0x0a);
    while (newline >= 0) {
      if (newline > MAX_FRAME_BYTES) {
        this.buffer = Buffer.alloc(0);
        throw new BrokerFrameTooLargeError();
      }
      lines.push(pending.subarray(0, newline).toString('utf8'));
      pending = pending.subarray(newline + 1);
      newline = pending.indexOf(0x0a);
    }
    if (pending.byteLength > MAX_FRAME_BYTES) {
      this.buffer = Buffer.alloc(0);
      throw new BrokerFrameTooLargeError();
    }
    this.buffer = Buffer.from(pending);
    return lines;
  }
}

/** Constant-time comparison once lengths agree; length itself is not secret. */
export function tokensMatch(supplied: string, expected: string): boolean {
  const left = Buffer.from(supplied, 'utf8');
  const right = Buffer.from(expected, 'utf8');
  if (left.byteLength !== right.byteLength) return false;
  return timingSafeEqual(left, right);
}

/** Strips terminal control sequences and bounds untrusted argv text. */
export function safeCommandName(value: string): string {
  // eslint-disable-next-line no-control-regex
  const stripped = value.replace(/[\u0000-\u001f\u007f]/gu, '?');
  return stripped.length > 64 ? `${stripped.slice(0, 61)}...` : stripped;
}

export function boundedPreview(argv: readonly string[]): string[] {
  return argv.slice(0, 8).map(safeCommandName);
}

import type { Socket } from 'node:net';
import type { AgentBrokerServerFrame } from '@kavrix/schemas';

/** Emits one child-output chunk as one or more bounded base64 frames. */
export function streamOutputFrames(
  socket: Socket,
  event: 'stdout' | 'stderr',
  chunk: Buffer,
  sendFrame: (socket: Socket, frame: AgentBrokerServerFrame) => void,
): void {
  const CHUNK = 512 * 1024;
  for (let offset = 0; offset < chunk.byteLength; offset += CHUNK) {
    const slice = chunk.subarray(offset, Math.min(offset + CHUNK, chunk.byteLength));
    sendFrame(socket, { v: 1, event, data: slice.toString('base64') });
  }
}
