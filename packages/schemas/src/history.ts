import type { z } from 'zod';

import { itemPayloadV1Schema } from './payloads.js';

/**
 * Version 1 history payloads are canonical snapshots of the referenced item.
 * The history record carries the opaque event identity and item revision; the
 * encrypted plaintext intentionally reuses the item snapshot contract so no
 * second secret-bearing field model can drift from the active item schema.
 */
export const historyPayloadV1Schema = itemPayloadV1Schema;
export const historyPayloadSchema = historyPayloadV1Schema;

export type HistoryPayloadV1 = z.infer<typeof historyPayloadV1Schema>;
export type HistoryPayload = HistoryPayloadV1;
