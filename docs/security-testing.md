# Security testing

Kavrix release validation focuses on the supported direct-MongoDB path.

## Required local checks

\`\`\`sh
pnpm install --frozen-lockfile
pnpm build
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm --filter kavrix package:smoke
pnpm audit --audit-level high
\`\`\`

The schema and crypto suites cover malformed envelopes, tampering, associated
data swaps, key-slot wrapping, recovery-slot binding, and plaintext canaries.
Protected-file suites cover passphrase failures, tampering, path safety, and
permission enforcement. The storage suite covers fail-closed Mongo URI policy.

## MongoDB integration

Set \`KAVRIX_MONGODB_URI\` to a disposable replica-set connection and run:

\`\`\`sh
pnpm --filter @kavrix/storage test:integration
\`\`\`

The integration test creates a unique vault document, checks ping/create/get,
and verifies optimistic revision updates. It does not print credential values
or retain a fixed test secret.

## Environment caveats

No MongoDB daemon is bundled with the repository. Windows ACL checks depend on
the account and filesystem policy and must be run on a supported Windows
runner. A passing local unit suite is not evidence that a remote MongoDB
deployment is correctly configured for TLS or backup protection.
