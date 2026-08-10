# Package-layer engineering guide

Packages contain Kavrix's reusable contracts, policies, cryptography, adapters,
and terminal components. Dependency direction points toward schemas and core;
consumer packages must not duplicate canonical interfaces.

## Boundaries

- `schemas` owns runtime validation, branded identifiers, wire records, encrypted
  persistence shapes, and types inferred from those schemas.
- `core` owns framework-free policies, errors, ports, generators, and use cases.
  It does not import HTTP, MongoDB, CLI, TUI, or platform implementations.
- `crypto` exposes small, context-bound, misuse-resistant operations. Every
  ciphertext and wrapped key has a version and exact authenticated context.
- `storage` stores opaque records only and implements core ports with transactional
  concurrency, idempotency, ordered change feeds, and tombstone semantics.
- `sync` moves only canonical opaque records and stores rollback anchors through a
  protected local-state port.
- `client` owns HTTPS and unlocked-vault orchestration. Secret keys never enter a
  transport object or server request.
- `keychain`, `key-files`, `clipboard`, and `runner` are hostile platform
  boundaries. Use fixed executables/argument arrays, bounded I/O and timeouts,
  minimal environments, generic errors, and best-effort zeroization.
- `tui` renders schema-driven state and emits authorization intents. It does not
  own persistence, cryptography, the clipboard, or authentication policy.
- `import-export` accepts only authenticated, versioned, bounded formats and
  publishes a restore only after full verification.

## Implementation rules

- Prefer a Zod schema and `z.infer` over a parallel TypeScript interface for data
  crossing a trust boundary.
- Use branded IDs and secret-byte types; do not cast generic strings across vault,
  group, item, attachment, key-slot, device, or invite domains.
- Build dynamic field behavior from `FieldDefinition` and template data. Avoid
  type-specific duplicated components or command handlers.
- Keep owned buffers explicit and wipe them in `finally`. Document unavoidable
  JavaScript string/runtime copies instead of claiming guaranteed erasure.
- Production source contains no mocks, placeholder encryption, silent fallback,
  TODO security behavior, or catch-and-ignore cleanup.
- Tests target observable invariants: tampering, context swaps, malformed bounds,
  retries, interruption, concurrency, rollback, and plaintext canaries.

Do not weaken a schema, resource bound, assertion, or coverage threshold to make a
test pass. Diagnose the violated contract and fix the owning layer.
