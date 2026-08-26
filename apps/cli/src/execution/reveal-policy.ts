import { AuthorizationState } from './authorization-state.js';
import { authorizationDenied } from './exit-codes.js';
import { evaluateReveal } from './engine.js';
import type { DatabaseSession } from '../database-session.js';
import type { DatastoreProfile } from '../datastore-profiles.js';

/**
 * Enforces the stored reveal policy for one credential: permission to use a
 * credential never implies permission to print it. Any stored policy covering
 * the credential that does not explicitly grant `reveal` blocks every reveal
 * path, and deny entries block unconditionally. The attempt and its outcome
 * are audited; the derived key is wiped on every exit path.
 */
export async function enforceRevealPolicy(
  session: DatabaseSession,
  profile: DatastoreProfile,
  secret: string,
): Promise<void> {
  const authzKey = session.authorizationStateKey();
  let state: AuthorizationState | undefined;
  try {
    state = await AuthorizationState.open(profile.keyFile, authzKey, {
      scopeKind: 'database',
      scopeId: session.databaseId,
    });
    const snapshot = await state.read();
    const covering = Object.values(snapshot.policies)
      .map((record) => record.definition)
      .filter((entry) => entry.secret === secret);
    const decision = evaluateReveal(covering);
    await state.recordEvent({ actor: 'user', action: 'reveal-attempted', secret });
    if (decision.outcome !== 'allow') {
      await state.recordEvent({
        actor: 'user',
        action: 'reveal-denied',
        secret,
        ...(decision.policyId === undefined ? {} : { policyId: decision.policyId }),
      });
      // Deny entries block use as well as reveal; only reveal-scoped policies
      // leave `run` available.
      const denied = covering.some((entry) => entry.deny === true);
      throw authorizationDenied(
        denied
          ? `Revealing '${secret}' is denied by policy; a deny entry blocks every use of the credential.`
          : `Revealing '${secret}' is denied by policy; use is still permitted through \`kavrix run\`.`,
      );
    }
  } catch (error) {
    state?.close();
    authzKey.fill(0);
    throw error;
  }
  state.close();
  authzKey.fill(0);
}
