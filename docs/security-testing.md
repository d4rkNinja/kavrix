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
pnpm acceptance:pre-ci
pnpm acceptance:database-container
pnpm --filter kavrix package:smoke
pnpm --filter kavrix pack:check
pnpm audit --audit-level high
\`\`\`

The schema and crypto suites cover malformed envelopes, tampering, associated
data swaps, key-slot wrapping, recovery-slot binding, and plaintext canaries.
Protected-file suites cover passphrase failures, database/vault binding,
tampering, path safety, and POSIX/Windows permission enforcement. The storage
suite covers fail-closed Mongo URI policy, two-collection transaction behavior,
and local schema, bounds, links, locks, compare-and-swap conflicts, atomic
publication, and deletion.

`acceptance:database-container` packs the actual public package, installs it into
an isolated temporary prefix with a dedicated npm cache, and invokes only that
installed executable. Runtime-random passphrases, private labels, and plaintext
canaries travel through exact stdin frames, never argv or environment variables.
The test covers profile selection, two vaults, isolated writes/reads, a second
database and wrong-key rejection, switch-back integrity, legacy migration,
concurrent conflict, rollback-anchor rejection, catalog tampering, default label
redaction, package allowlisting, and scans of outputs and protected artifacts.

The runner handles `SIGINT` and `SIGTERM`, stops active children, attempts every
cleanup target even after an earlier cleanup failure, restores the caller's npm
cache setting, aggregates redacted operation/cleanup errors, and prints success
only after cleanup. Expected negative tests run inside the same cleanup envelope.

## MongoDB integration

The storage integration test runs only when `KAVRIX_MONGODB_URI` identifies a
disposable replica set or sharded topology with transaction support. It creates a
random test database, verifies transactional database/vault operations and
indexes in the live service, and drops only that generated database.

The repository does not bootstrap MongoDB in CI: the workflow has no reviewed,
immutable, transaction-capable service image or safe replica-set startup path.
Unit doubles and a standalone server are not reported as live MongoDB proof.
Provide `KAVRIX_MONGODB_URI` in an authorized integration environment to obtain
that evidence.

## Environment caveats

No MongoDB daemon is bundled with the repository. Windows ACL checks and the
masked-terminal raw-mode restoration regression run on native Windows in the CI
matrix; macOS/Linux results are not substituted for Windows evidence. A passing
local suite is not evidence that a remote deployment is correctly configured for
TLS, transactions, authorization, or backup protection.
