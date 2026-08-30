import {
  canonicalJson,
  type CollaborativeMembershipManifest,
  type DatabaseAuthorityRecoveryEnvelope,
} from '@kavrix/schemas';

const SAFE_MESSAGE = 'Collaborative recovery-envelope verification failed.';

/** Cross-binds the database-visible recovery envelope to its authenticated copy. */
export function requireExactDatabaseAuthorityRecoveryEnvelope(
  carrier: Readonly<{
    databaseAuthorityRecoveryEnvelope: DatabaseAuthorityRecoveryEnvelope;
  }>,
  manifest: CollaborativeMembershipManifest,
): DatabaseAuthorityRecoveryEnvelope {
  const recoveryEnvelope = requireDatabaseAuthorityRecoveryEnvelope(manifest);
  if (
    canonicalJson(carrier.databaseAuthorityRecoveryEnvelope) !==
    canonicalJson(recoveryEnvelope)
  ) {
    throw new Error(SAFE_MESSAGE);
  }
  return recoveryEnvelope;
}

export function requireDatabaseAuthorityRecoveryEnvelope(
  manifest: CollaborativeMembershipManifest,
): DatabaseAuthorityRecoveryEnvelope {
  const recoveryEnvelopes = manifest.keyEnvelopes.filter(
    (envelope): envelope is DatabaseAuthorityRecoveryEnvelope =>
      !('membershipId' in envelope),
  );
  const recoveryEnvelope = recoveryEnvelopes[0];
  if (recoveryEnvelopes.length !== 1 || recoveryEnvelope === undefined) {
    throw new Error(SAFE_MESSAGE);
  }
  return recoveryEnvelope;
}
