# Security testing

Kavrix release validation always covers the packed local-file path and covers
direct MongoDB behavior when a disposable MongoDB prerequisite is available.

## Required local checks

\`\`\`sh
pnpm install --frozen-lockfile
pnpm build
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm --filter kavrix package:smoke
pnpm acceptance:pre-ci
pnpm audit --audit-level high
\`\`\`

The schema and crypto suites cover malformed envelopes, tampering, associated
data swaps, key-slot wrapping, recovery-slot binding, and plaintext canaries.
Protected-file suites cover passphrase failures, tampering, path safety, and
permission enforcement. The storage suite covers fail-closed Mongo URI policy
and local-file schema, bounds, permissions, links, locking, conflicts, atomic
publication, and deletion. The packed acceptance test invokes the complete
applicable command lifecycle against test-owned local files and removes its
temporary root in `finally` after success or failure.

## MongoDB integration

MongoDB integration is optional in the local pre-CI runner and must use a
disposable URI supplied through its protected stdin flow. Do not claim a real
MongoDB result when that prerequisite is absent.

The current repository does not ship a standalone live-Mongo integration script;
the unit suite proves URI policy and adapter contracts, not a live topology.

## Environment caveats

No MongoDB daemon is bundled with the repository. Windows ACL checks depend on
the account and filesystem policy and must be run on a supported Windows
runner. A passing local unit suite is not evidence that a remote MongoDB
deployment is correctly configured for TLS or backup protection.
