import { describe, expect, it } from 'vitest';

import { MAX_BACKUP_LINE_BYTES, splitBackupLines } from '../src/index.js';

describe('backup line framing', () => {
  it('streams multiple canonical lines and grows its bounded buffer', async () => {
    const large = Buffer.alloc(5_000, 0x61);
    const source = chunks(
      Buffer.concat([large, Buffer.from('\nnext\n', 'ascii')]),
      997,
    );
    const lines = await collectLines(source);

    expect(lines).toHaveLength(2);
    expect(Buffer.from(lines[0] ?? [])).toEqual(large);
    expect(Buffer.from(lines[1] ?? []).toString('ascii')).toBe('next');
  });

  it('rejects empty, CRLF, unterminated, over-budget, and oversized lines', async () => {
    for (const value of [Buffer.from('\n'), Buffer.from('value\r\n')]) {
      await expect(collectLines(chunks(value))).rejects.toMatchObject({
        code: 'BACKUP_INVALID',
      });
    }
    await expect(
      collectLines(chunks(Buffer.from('unterminated'))),
    ).rejects.toMatchObject({ code: 'BACKUP_INCOMPLETE' });
    await expect(collectLines(chunks(Buffer.from('value\n')), 5)).rejects.toMatchObject(
      { code: 'BACKUP_TOO_LARGE' },
    );
    await expect(
      collectLines(chunks(Buffer.alloc(MAX_BACKUP_LINE_BYTES + 1, 0x61))),
    ).rejects.toMatchObject({ code: 'BACKUP_TOO_LARGE' });
  });

  it('rejects invalid configured aggregate limits before consuming input', async () => {
    await expect(
      collectLines(chunks(Buffer.from('value\n')), 0),
    ).rejects.toBeInstanceOf(RangeError);
  });
});

async function collectLines(
  source: AsyncIterable<Uint8Array>,
  maximumBytes?: number,
): Promise<Uint8Array[]> {
  const lines: Uint8Array[] = [];
  for await (const line of splitBackupLines(source, maximumBytes)) lines.push(line);
  return lines;
}

function chunks(
  value: Uint8Array,
  chunkSize = value.byteLength,
): AsyncIterable<Uint8Array> {
  const values: Uint8Array[] = [];
  for (let offset = 0; offset < value.byteLength; offset += chunkSize) {
    values.push(value.subarray(offset, Math.min(offset + chunkSize, value.byteLength)));
  }
  return {
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      let index = 0;
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          const next = values[index];
          index += 1;
          return Promise.resolve(
            next === undefined
              ? { done: true, value: undefined }
              : { done: false, value: next },
          );
        },
      };
    },
  };
}
