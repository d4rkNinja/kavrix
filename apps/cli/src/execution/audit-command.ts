import type { DatabaseFlatCommandOptions } from '../database-flat-commands.js';
import { withAuthorizationState } from './authorization-session.js';

export interface AuditOptions extends DatabaseFlatCommandOptions {
  readonly limit?: number | undefined;
}

/**
 * Renders recent security-relevant audit events. Events carry bounded
 * metadata only; no schema in the audit family can hold plaintext values.
 */
export async function executeAudit(options: AuditOptions): Promise<unknown> {
  const limit = options.limit ?? 100;
  return await withAuthorizationState(options, async (state) => {
    const snapshot = await state.read();
    const total = snapshot.audit.length;
    const events = snapshot.audit.slice(Math.max(0, total - limit));
    return { total, shown: events.length, events };
  });
}
