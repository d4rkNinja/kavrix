import { argon2, type Argon2Parameters } from 'node:crypto';

export interface Argon2idParameters {
  readonly message: Argon2Parameters['message'];
  readonly nonce: Argon2Parameters['nonce'];
  readonly parallelism: number;
  readonly tagLength: number;
  readonly memoryKiB: number;
  readonly passes: number;
  readonly secret?: Argon2Parameters['secret'];
  readonly associatedData?: Argon2Parameters['associatedData'];
}

// Internal primitive adapter, intentionally omitted from the package index.
// Persisted profiles must pass the validation owned by keys.ts before calling it.
export function deriveArgon2id(parameters: Argon2idParameters): Promise<Buffer> {
  const nodeParameters: Argon2Parameters = {
    message: parameters.message,
    nonce: parameters.nonce,
    parallelism: parameters.parallelism,
    tagLength: parameters.tagLength,
    memory: parameters.memoryKiB,
    passes: parameters.passes,
    ...(parameters.secret === undefined ? {} : { secret: parameters.secret }),
    ...(parameters.associatedData === undefined
      ? {}
      : { associatedData: parameters.associatedData }),
  };

  return new Promise((resolve, reject) => {
    argon2('argon2id', nodeParameters, (error, derivedKey) => {
      if (error !== null) {
        reject(error);
        return;
      }
      resolve(derivedKey);
    });
  });
}
