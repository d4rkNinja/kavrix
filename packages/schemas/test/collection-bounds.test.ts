import { describe, expect, it } from 'vitest';

import {
  databaseCatalogPayloadSchema,
  MAX_DATABASE_VAULTS,
} from '../src/database-container.js';

describe('untrusted collection validation bounds', () => {
  it('rejects oversized vault lists before accumulating element errors', () => {
    const result = databaseCatalogPayloadSchema.shape.vaults.safeParse(
      Array.from({ length: MAX_DATABASE_VAULTS + 1 }, () => null),
    );
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.error.issues).toHaveLength(1);
    expect(result.error.issues[0]).toMatchObject({ code: 'too_big', path: [] });
  });
});
