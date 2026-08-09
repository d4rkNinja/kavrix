import { describe, expect, it } from 'vitest';

import {
  attachmentSecretStreamManifestSchema,
  attachmentSecretStreamRecordSchema,
  type AttachmentSecretStreamManifest,
  type AttachmentSecretStreamRecord,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import {
  AuthenticationError,
  CryptoInputError,
  decryptAttachmentStream,
  decryptAttachmentStreamToStager,
  encryptAttachmentStream,
  encryptAttachmentStreamToStager,
  generateAttachmentKey,
  parseAttachmentStreamRecord,
} from '../src/index.js';
import {
  attachmentChunkAad,
  mutateBase64Url,
  otherGroupId,
  otherItemId,
} from './helpers.js';

describe('incremental attachment secretstream', () => {
  it('authenticates ordered canonical persisted records and the final tag', async () => {
    const key = generateAttachmentKey();
    const plaintext = [
      new TextEncoder().encode('first chunk'),
      new TextEncoder().encode('second chunk'),
      new Uint8Array(),
    ];
    const records = await collect(
      encryptAttachmentStream(plaintext, key, attachmentChunkAad()),
    );
    await expect(
      collect(decryptAttachmentStream(records, key, attachmentChunkAad())),
    ).resolves.toEqual(plaintext);
    expect(records[0]).toMatchObject({
      recordType: 'header',
      streamVersion: 1,
      keyVersion: 1,
      attachmentId: 'attachment-1',
    });
    for (const record of records) {
      expect(parseAttachmentStreamRecord(record)).toEqual(record);
    }
    expect(JSON.stringify(records)).not.toContain('first chunk');
  });

  it('copies a reused producer buffer before requesting the next chunk', async () => {
    const key = generateAttachmentKey();
    function* reusedBuffer(): Generator<Uint8Array> {
      const buffer = Uint8Array.of(1);
      yield buffer;
      buffer[0] = 2;
      yield buffer;
      buffer[0] = 3;
    }
    const records = await collect(
      encryptAttachmentStream(reusedBuffer(), key, attachmentChunkAad()),
    );
    await expect(
      collect(decryptAttachmentStream(records, key, attachmentChunkAad())),
    ).resolves.toEqual([Uint8Array.of(1), Uint8Array.of(2)]);
  });

  it('stages encryption with the exact internally computed manifest', async () => {
    const key = generateAttachmentKey();
    function* reusedBuffer(): Generator<Uint8Array> {
      const buffer = Uint8Array.of(1);
      yield buffer;
      buffer[0] = 2;
      yield buffer;
      buffer[0] = 99;
    }
    const records: AttachmentSecretStreamRecord[] = [];
    let committedManifest: AttachmentSecretStreamManifest | undefined;
    let aborted = false;
    const manifest = await encryptAttachmentStreamToStager(
      reusedBuffer(),
      key,
      attachmentChunkAad(),
      {
        write(record) {
          records.push(structuredClone(record));
        },
        commit(value) {
          committedManifest = structuredClone(value);
        },
        abort() {
          aborted = true;
        },
      },
    );

    expect(committedManifest).toEqual(manifest);
    expect(aborted).toBe(false);
    expect(manifest).toMatchObject({
      chunkCount: 2,
      totalPlaintextBytes: 2,
      plaintextSha256: 'oShx_uIQ-4YZKR6uoZRYHL0lMeSyN1nSJfaAaSP2MiI',
    });
    expect(manifest.header).toBe(
      records[0]?.recordType === 'header' ? records[0].header : undefined,
    );
    await expect(
      collect(decryptAttachmentStream(records, key, attachmentChunkAad())),
    ).resolves.toEqual([Uint8Array.of(1), Uint8Array.of(2)]);

    const jsonRecords = JSON.parse(JSON.stringify(records)) as unknown[];
    const jsonManifest = JSON.parse(JSON.stringify(manifest)) as unknown;
    expect(
      jsonRecords.map((record) => attachmentSecretStreamRecordSchema.parse(record)),
    ).toEqual(records);
    expect(attachmentSecretStreamManifestSchema.parse(jsonManifest)).toEqual(manifest);
  });

  it('aborts staged encryption when the record sink fails', async () => {
    const key = generateAttachmentKey();
    let writes = 0;
    let committed = false;
    let aborted = false;
    await expect(
      encryptAttachmentStreamToStager(
        [Uint8Array.of(1), Uint8Array.of(2)],
        key,
        attachmentChunkAad(),
        {
          write() {
            writes += 1;
            if (writes === 2) {
              throw new Error('staging sink failed');
            }
          },
          commit() {
            committed = true;
          },
          abort() {
            aborted = true;
          },
        },
      ),
    ).rejects.toThrow('staging sink failed');
    expect(committed).toBe(false);
    expect(aborted).toBe(true);
  });

  it('represents an empty attachment with one authenticated final chunk', async () => {
    const key = generateAttachmentKey();
    const records = await collect(
      encryptAttachmentStream([], key, attachmentChunkAad()),
    );
    expect(records).toHaveLength(2);
    await expect(
      collect(decryptAttachmentStream(records, key, attachmentChunkAad())),
    ).resolves.toEqual([new Uint8Array()]);
  });

  it.each(['header', 'chunk', 'tag', 'order', 'missing-final', 'appended'] as const)(
    'rejects %s tampering',
    async (kind) => {
      const key = generateAttachmentKey();
      const records = cloneRecords(
        await collect(
          encryptAttachmentStream(
            [new TextEncoder().encode('one'), new TextEncoder().encode('two')],
            key,
            attachmentChunkAad(),
          ),
        ),
      );
      const header = records[0];
      const firstChunk = records[1];
      const finalChunk = records[2];
      if (
        header?.recordType !== 'header' ||
        firstChunk?.recordType !== 'chunk' ||
        finalChunk?.recordType !== 'chunk'
      ) {
        throw new Error('Expected a header and two encrypted chunks');
      }
      if (kind === 'header') {
        records[0] = { ...header, header: mutateBase64Url(header.header) };
      } else if (kind === 'chunk') {
        records[1] = {
          ...firstChunk,
          ciphertext: mutateBase64Url(firstChunk.ciphertext) as never,
        };
      } else if (kind === 'tag') {
        records[1] = { ...firstChunk, tag: 'final' };
      } else if (kind === 'order') {
        records.splice(1, 2, finalChunk, firstChunk);
      } else if (kind === 'missing-final') {
        records.pop();
      } else {
        records.push({ ...finalChunk, index: 2 });
      }
      await expect(
        collect(decryptAttachmentStream(records, key, attachmentChunkAad())),
      ).rejects.toBeInstanceOf(AuthenticationError);
    },
  );

  it('rejects wrong keys and item/group/key-version swapping', async () => {
    const key = generateAttachmentKey();
    const records = await collect(
      encryptAttachmentStream(
        [new TextEncoder().encode('attachment data')],
        key,
        attachmentChunkAad(),
      ),
    );
    await expect(
      collect(
        decryptAttachmentStream(records, generateAttachmentKey(), attachmentChunkAad()),
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      collect(
        decryptAttachmentStream(
          records,
          key,
          attachmentChunkAad({ groupId: otherGroupId }),
        ),
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      collect(
        decryptAttachmentStream(
          records,
          key,
          attachmentChunkAad({ parentId: otherItemId }),
        ),
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);

    const wrongVersion = cloneRecords(records);
    const header = wrongVersion[0];
    if (header?.recordType !== 'header') {
      throw new Error('Expected a stream header');
    }
    wrongVersion[0] = { ...header, keyVersion: 2 as never };
    await expect(
      collect(decryptAttachmentStream(wrongVersion, key, attachmentChunkAad())),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('enforces total-size bounds incrementally on both paths', async () => {
    const key = generateAttachmentKey();
    const plaintext = [Uint8Array.of(1, 2, 3), Uint8Array.of(4, 5, 6)];
    await expect(
      collect(
        encryptAttachmentStream(plaintext, key, attachmentChunkAad(), {
          maximumTotalBytes: 5,
        }),
      ),
    ).rejects.toBeInstanceOf(CryptoInputError);
    const records = await collect(
      encryptAttachmentStream(plaintext, key, attachmentChunkAad()),
    );
    await expect(
      collect(
        decryptAttachmentStream(records, key, attachmentChunkAad(), {
          maximumTotalBytes: 5,
        }),
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('stages provisional plaintext and commits only after manifest verification', async () => {
    const key = generateAttachmentKey();
    const plaintext = [Uint8Array.of(1, 2), Uint8Array.of(3, 4, 5)];
    const encrypted = await encryptToMemory(plaintext, key);
    const { records, manifest } = encrypted;
    const staged: Uint8Array[] = [];
    let committed = false;
    let aborted = false;
    await decryptAttachmentStreamToStager(
      records,
      key,
      attachmentChunkAad(),
      manifest,
      {
        write(chunk) {
          staged.push(Uint8Array.from(chunk));
        },
        commit() {
          committed = true;
        },
        abort() {
          aborted = true;
        },
      },
    );
    expect(staged).toEqual(plaintext);
    expect(committed).toBe(true);
    expect(aborted).toBe(false);

    committed = false;
    aborted = false;
    await expect(
      decryptAttachmentStreamToStager(
        records.slice(0, -1),
        key,
        attachmentChunkAad(),
        manifest,
        {
          write() {
            return undefined;
          },
          commit() {
            committed = true;
          },
          abort() {
            aborted = true;
          },
        },
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    expect(committed).toBe(false);
    expect(aborted).toBe(true);
  });

  it('clears and frees push and pull WASM states', async () => {
    await sodium.ready;
    const runtime = (
      sodium as unknown as {
        readonly libsodium: {
          _free: (address: number) => void;
          _crypto_secretstream_xchacha20poly1305_init_push: (
            ...arguments_: number[]
          ) => number;
          _crypto_secretstream_xchacha20poly1305_init_pull: (
            ...arguments_: number[]
          ) => number;
        };
      }
    ).libsodium;
    const originalFree = runtime._free;
    const originalInitPush = runtime._crypto_secretstream_xchacha20poly1305_init_push;
    const originalInitPull = runtime._crypto_secretstream_xchacha20poly1305_init_pull;
    const stateAddresses: number[] = [];
    const freedAddresses = new Set<number>();
    runtime._free = (address: number): void => {
      freedAddresses.add(address);
      originalFree(address);
    };
    runtime._crypto_secretstream_xchacha20poly1305_init_push = (
      ...arguments_: number[]
    ): number => {
      stateAddresses.push(arguments_[0] ?? -1);
      return originalInitPush(...arguments_);
    };
    runtime._crypto_secretstream_xchacha20poly1305_init_pull = (
      ...arguments_: number[]
    ): number => {
      stateAddresses.push(arguments_[0] ?? -1);
      return originalInitPull(...arguments_);
    };
    try {
      const key = generateAttachmentKey();
      const records = await collect(
        encryptAttachmentStream([Uint8Array.of(1, 2, 3)], key, attachmentChunkAad()),
      );
      await collect(decryptAttachmentStream(records, key, attachmentChunkAad()));
      expect(stateAddresses).toHaveLength(2);
      expect(stateAddresses.every((address) => freedAddresses.has(address))).toBe(true);
    } finally {
      runtime._free = originalFree;
      runtime._crypto_secretstream_xchacha20poly1305_init_push = originalInitPush;
      runtime._crypto_secretstream_xchacha20poly1305_init_pull = originalInitPull;
    }
  });
});

async function collect<Value>(source: AsyncIterable<Value>): Promise<Value[]> {
  const values: Value[] = [];
  for await (const value of source) {
    values.push(value);
  }
  return values;
}

function cloneRecords(
  records: readonly AttachmentSecretStreamRecord[],
): AttachmentSecretStreamRecord[] {
  return records.map((record) => ({ ...record }));
}

async function encryptToMemory(
  plaintext: readonly Uint8Array[],
  key: Uint8Array,
): Promise<{
  readonly records: AttachmentSecretStreamRecord[];
  readonly manifest: AttachmentSecretStreamManifest;
}> {
  const records: AttachmentSecretStreamRecord[] = [];
  let committed: AttachmentSecretStreamManifest | undefined;
  const manifest = await encryptAttachmentStreamToStager(
    plaintext,
    key,
    attachmentChunkAad(),
    {
      write(record) {
        records.push(record);
      },
      commit(value) {
        committed = value;
      },
      abort() {
        throw new Error('Unexpected encryption abort');
      },
    },
  );
  expect(committed).toEqual(manifest);
  return { records, manifest };
}
