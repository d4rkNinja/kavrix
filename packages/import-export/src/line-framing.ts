import { BackupError } from './errors.js';

export const MAX_BACKUP_LINE_BYTES = 32 * 1024 * 1024;
export const DEFAULT_MAX_BACKUP_BYTES = 16 * 1024 * 1024 * 1024;
const INITIAL_BUFFER_BYTES = 4096;

export async function* splitBackupLines(
  source: AsyncIterable<Uint8Array>,
  maximumBytes = DEFAULT_MAX_BACKUP_BYTES,
): AsyncGenerator<Uint8Array> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
    throw new RangeError('The backup byte limit must be a positive safe integer.');
  }
  let buffer = Buffer.allocUnsafe(INITIAL_BUFFER_BYTES);
  let length = 0;
  let totalBytes = 0;

  try {
    for await (const chunk of source) {
      totalBytes += chunk.byteLength;
      if (!Number.isSafeInteger(totalBytes) || totalBytes > maximumBytes) {
        throw new BackupError(
          'BACKUP_TOO_LARGE',
          'The encrypted backup exceeds the aggregate byte limit.',
        );
      }
      let offset = 0;
      while (offset < chunk.byteLength) {
        const remaining = chunk.subarray(offset);
        const newlineOffset = remaining.indexOf(0x0a);
        const pieceLength = newlineOffset === -1 ? remaining.byteLength : newlineOffset;
        buffer = ensureCapacity(buffer, length + pieceLength);
        Buffer.from(remaining.buffer, remaining.byteOffset, pieceLength).copy(
          buffer,
          length,
        );
        length += pieceLength;
        offset += pieceLength;

        if (newlineOffset === -1) {
          break;
        }

        if (length === 0 || buffer[length - 1] === 0x0d) {
          throw new BackupError(
            'BACKUP_INVALID',
            'Backup lines must use canonical non-empty LF framing.',
          );
        }
        yield Uint8Array.from(buffer.subarray(0, length));
        buffer.fill(0, 0, length);
        length = 0;
        offset += 1;
      }
    }

    if (length !== 0) {
      throw new BackupError(
        'BACKUP_INCOMPLETE',
        'The encrypted backup is missing its final line delimiter.',
      );
    }
  } finally {
    buffer.fill(0);
  }
}

function ensureCapacity(
  buffer: Buffer<ArrayBuffer>,
  required: number,
): Buffer<ArrayBuffer> {
  if (required > MAX_BACKUP_LINE_BYTES) {
    throw new BackupError(
      'BACKUP_TOO_LARGE',
      'A backup record exceeds the size limit.',
    );
  }
  if (required <= buffer.byteLength) {
    return buffer;
  }

  let capacity = buffer.byteLength;
  while (capacity < required) {
    capacity = Math.min(capacity * 2, MAX_BACKUP_LINE_BYTES);
  }
  const replacement = Buffer.allocUnsafe(capacity);
  buffer.copy(replacement);
  buffer.fill(0);
  return replacement;
}
