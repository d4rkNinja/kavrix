import { createHash, randomBytes } from 'node:crypto';

import {
  apiBearerTokenSchema,
  sha256DigestSchema,
  type ApiBearerToken,
  type Sha256Digest,
} from '@kavrix/schemas';

import type { IssuedToken, TokenPort } from './ports.js';

export class NodeTokenPort implements TokenPort {
  public async issue(): Promise<IssuedToken> {
    const bytes = randomBytes(32);
    try {
      const token = apiBearerTokenSchema.parse(bytes.toString('base64url'));
      return { token, hash: await this.hash(token) };
    } finally {
      bytes.fill(0);
    }
  }

  public hash(token: ApiBearerToken): Promise<Sha256Digest> {
    const parsed = apiBearerTokenSchema.parse(token);
    const bytes = Buffer.from(parsed, 'base64url');
    const digest = createHash('sha256').update(bytes).digest();
    try {
      return Promise.resolve(sha256DigestSchema.parse(digest.toString('base64url')));
    } finally {
      bytes.fill(0);
      digest.fill(0);
    }
  }
}
