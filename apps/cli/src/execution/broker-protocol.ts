import { timingSafeEqual } from 'node:crypto';

/**
 * Pure protocol helpers for the agent broker. Kept separate from the socket
 * orchestration so the framing, token, and sanitization rules can be tested
 * directly against adversarial inputs.
 */

export const MAX_FRAME_BYTES = 2 * 1024 * 1024;

export class NdjsonDecoder {
  private buffer = '';

  public push(chunk: Buffer): readonly string[] {
    this.buffer += chunk.toString('utf8');
    if (this.buffer.length > MAX_FRAME_BYTES * 2) {
      // A peer flooding us with unterminated bytes loses everything
      // buffered so far; the connection is torn down by the caller.
      this.buffer = '';
      return [];
    }
    const lines: string[] = [];
    let newline = this.buffer.indexOf('\n');
    while (newline >= 0) {
      lines.push(this.buffer.slice(0, newline));
      this.buffer = this.buffer.slice(newline + 1);
      newline = this.buffer.indexOf('\n');
    }
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
