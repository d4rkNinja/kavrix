# Architecture

## Supported path

\`\`\`
masked input / protected key file
|
v
kavrix CLI
(unlock + AEAD)
|
v
MongoLocalVaultStore
|
v
MongoDB
\`\`\`

The CLI is the only process in the supported product. It composes command
handlers, schemas, crypto, protected file I/O, and the MongoDB adapter. The
database is a zero-knowledge storage layer: it can store and compare opaque
documents but cannot derive the root key.

## Boundaries

- \`packages/schemas\` owns canonical persisted document and envelope schemas.
- \`packages/crypto\` owns key derivation, authenticated encryption, wrapping, and secure byte handling.
- \`packages/key-files\` owns protected portable-key and recovery-kit file formats, path safety, and permissions.
- \`packages/storage\` owns MongoDB connection policy and optimistic document I/O.
- \`apps/cli\` owns interactive input, command routing, and sanitized rendering.

No API server, sync daemon, SQLite store, or TUI is required for the local path.
The public package bundles the CLI and reviewed third-party libraries while
leaving MongoDB as its single external runtime dependency.

## Trust and residual risk

Unlock material never crosses the storage boundary. MongoDB still sees
identifiers, revision/timestamp metadata, envelope sizes, and writes. The local
payload AAD authenticates the complete document metadata, including revision and
key-slot/recovery-slot state. A restrictive sidecar next to the active key file
stores a root-key-authenticated highest-seen revision and metadata digest; lower
revisions and same-revision metadata forks are rejected before plaintext is
returned. Recovery-only unlocks require the same anchor. Deleting the anchor is
fail-closed unless an operator explicitly accepts the current state through
\`doctor health --accept-current\`. Recovery use rotates the root key, which
prevents the old slot from unlocking the current document, but it cannot erase
old ciphertext snapshots.

The supported security claim is therefore confidentiality and authenticated
integrity against storage inspection and accidental corruption, not immunity to
a fully privileged local process or rollback-capable database administrator.
