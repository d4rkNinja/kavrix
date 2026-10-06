import { z } from 'zod';

import { recordRevisionSchema } from './primitives.js';

export const VAULT_BROWSE_CONTEXT_LIMIT = 20;
export const VAULT_BROWSE_SERVICE_LIMIT = 20;
export const VAULT_BROWSE_ITEM_LIMIT = 30;

/** Metadata only: field values, notes, and credential payloads are excluded. */
export const vaultBrowseNodeSchema = z
  .object({
    id: z.string().min(1).max(256),
    kind: z.enum(['context', 'service', 'item']),
    label: z.string().max(256),
    detail: z.string().max(264),
  })
  .strict();

export const vaultBrowseSnapshotSchema = z
  .object({
    nodes: z
      .array(vaultBrowseNodeSchema)
      .max(
        VAULT_BROWSE_CONTEXT_LIMIT *
          (1 + VAULT_BROWSE_SERVICE_LIMIT * (1 + VAULT_BROWSE_ITEM_LIMIT)),
      ),
    truncated: z.boolean(),
    revision: recordRevisionSchema,
  })
  .strict();

export type VaultBrowseNode = z.infer<typeof vaultBrowseNodeSchema>;
export type VaultBrowseSnapshot = z.infer<typeof vaultBrowseSnapshotSchema>;
