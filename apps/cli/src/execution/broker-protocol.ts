import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

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

export class BrokerFrameAuthError extends Error {
  public constructor() {
    super('The agent broker frame failed authentication.');
    this.name = 'BrokerFrameAuthError';
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

/**
 * Audit-safe bare command name for `argv[0]`, which may arrive as a full
 * path. Reduces to the basename and returns `undefined` when the result
 * still cannot satisfy the audit schema's command-name pattern so callers
 * can omit the field instead of dropping the whole denial event.
 */
export function auditCommandName(value: string): string | undefined {
  const cut = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'));
  const base = cut >= 0 && cut + 1 < value.length ? value.slice(cut + 1) : value;
  const stripped = safeCommandName(base);
  return /^[A-Za-z0-9][A-Za-z0-9._+-]*$/u.test(stripped) ? stripped : undefined;
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

// ---- frame confidentiality --------------------------------------------------
//
// The broker endpoint is a named pipe on Windows or a 0600 POSIX socket, but
// Node does not expose named-pipe security descriptors, so a same-user
// process may be able to passively observe server-to-client traffic (policy
// decisions and child output). Both endpoints already hold the 256-bit
// session token, so every frame in both directions is sealed with
// chacha20-poly1305 under a key derived from that token and the endpoint.

export const BROKER_SESSION_KEY_BYTES = 32;
const BROKER_NONCE_BYTES = 12;
const BROKER_TAG_BYTES = 16;
const BROKER_KEY_INFO = 'kavrix/agent-broker/v1/session-key';
const BROKER_AAD_PREFIX = 'kavrix/agent-broker/v1/';
const BROKER_BASE64URL = /^[A-Za-z0-9_-]+$/;

export type BrokerFrameDirection = 'client-to-server' | 'server-to-client';

interface EncryptedFrameLine {
  readonly v: 1;
  readonly event: 'enc';
  readonly n: string;
  readonly c: string;
  readonly t: string;
}

/**
 * Derives the per-session frame key from the shared broker token. The
 * endpoint is the HKDF salt, so a token reused across broker sessions never
 * derives the same key twice; the info label separates the protocol domain.
 */
export function deriveBrokerSessionKey(token: string, endpoint: string): Buffer {
  return Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from(token, 'utf8'),
      Buffer.from(endpoint, 'utf8'),
      BROKER_KEY_INFO,
      BROKER_SESSION_KEY_BYTES,
    ),
  );
}

function frameAad(direction: BrokerFrameDirection): Buffer {
  return Buffer.from(`${BROKER_AAD_PREFIX}${direction}`, 'utf8');
}

/** Seals one broker frame into a single encrypted NDJSON line. */
export function encodeBrokerFrameLine(
  key: Buffer,
  direction: BrokerFrameDirection,
  frame: unknown,
): string {
  if (key.byteLength !== BROKER_SESSION_KEY_BYTES) {
    throw new BrokerFrameAuthError();
  }
  const plaintext = Buffer.from(JSON.stringify(frame), 'utf8');
  if (plaintext.byteLength > MAX_FRAME_BYTES) {
    throw new BrokerFrameTooLargeError();
  }
  const nonce = randomBytes(BROKER_NONCE_BYTES);
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: BROKER_TAG_BYTES,
  });
  cipher.setAAD(frameAad(direction), { plaintextLength: plaintext.byteLength });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 1,
    event: 'enc',
    n: nonce.toString('base64url'),
    c: ciphertext.toString('base64url'),
    t: tag.toString('base64url'),
  } satisfies EncryptedFrameLine);
}

function decodeBase64UrlField(
  value: unknown,
  expectedBytes: number,
): Buffer | undefined {
  if (typeof value !== 'string' || !BROKER_BASE64URL.test(value)) return undefined;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.byteLength === expectedBytes ? decoded : undefined;
}

/**
 * Opens one encrypted NDJSON line and returns the parsed frame. Any shape,
 * size, or authentication failure raises {@link BrokerFrameAuthError}; the
 * connection must be treated as hostile and destroyed.
 */
export function decodeBrokerFrameLine(
  key: Buffer,
  direction: BrokerFrameDirection,
  line: string,
): unknown {
  if (key.byteLength !== BROKER_SESSION_KEY_BYTES) {
    throw new BrokerFrameAuthError();
  }
  let envelope: unknown;
  try {
    envelope = JSON.parse(line) as unknown;
  } catch {
    throw new BrokerFrameAuthError();
  }
  if (
    typeof envelope !== 'object' ||
    envelope === null ||
    (envelope as { v?: unknown }).v !== 1 ||
    (envelope as { event?: unknown }).event !== 'enc'
  ) {
    throw new BrokerFrameAuthError();
  }
  const record = envelope as Record<string, unknown>;
  const nonce = decodeBase64UrlField(record['n'], BROKER_NONCE_BYTES);
  const tag = decodeBase64UrlField(record['t'], BROKER_TAG_BYTES);
  if (
    nonce === undefined ||
    tag === undefined ||
    typeof record['c'] !== 'string' ||
    !BROKER_BASE64URL.test(record['c'])
  ) {
    throw new BrokerFrameAuthError();
  }
  const ciphertext = Buffer.from(record['c'], 'base64url');
  if (ciphertext.byteLength === 0 || ciphertext.byteLength > MAX_FRAME_BYTES) {
    throw new BrokerFrameAuthError();
  }
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: BROKER_TAG_BYTES,
  });
  decipher.setAAD(frameAad(direction), { plaintextLength: ciphertext.byteLength });
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new BrokerFrameAuthError();
  }
  if (plaintext.byteLength > MAX_FRAME_BYTES) {
    throw new BrokerFrameTooLargeError();
  }
  try {
    return JSON.parse(plaintext.toString('utf8')) as unknown;
  } catch {
    throw new BrokerFrameAuthError();
  }
}
