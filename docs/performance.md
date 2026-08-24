# Performance notes

Kavrix is a local CLI whose dominant costs are Argon2id passphrase derivation,
authenticated encryption, and either local atomic file I/O or MongoDB round
trips. Commands avoid starting a server or loading a sync graph.

The MongoDB adapter uses bounded server-selection, connect, socket, and operation
timeouts. The local-file adapter uses bounded reads, an exclusive writer lock,
atomic publication, and directory synchronization. Both use optimistic revision
checks so concurrent or stale writers fail closed.

No benchmark numbers are treated as release evidence in this repository. Add a
repeatable benchmark with a disposable MongoDB replica set before making
latency, throughput, or startup claims.

## Execution layer characteristics

The credential execution features add the following costs and behaviors:

- **Unlock dominates.** Every vault-touching command pays one Argon2id
  derivation; its parameters are part of the key-slot format and are
  deliberately expensive.
- **Policy evaluation is in-memory** — command allowlists, executable pins,
  TTL checks, confirmation matching, and working-directory subtree tests run
  against parsed sealed-state documents with no I/O beyond the single
  sidecar read.
- **Sealed-state mutations rewrite one small document** under an exclusive
  lock: size stays bounded (audit ring capped at 512 events; policy and grant
  counts capped by schema), so writes remain compact.
- **Executable resolution hashes the target binary** (bounded at 512 MB) when
  a policy pins SHA-256 digests; unpinned policies skip hashing entirely.
- **`kavrix run` pays one unlock per invocation.** For scripted loops, wrap
  many operations in a single invocation; the agent broker amortizes unlock
  across a whole session — secrets decrypt once per session and each request
  costs only a local socket round trip plus policy evaluation.
- **Remote MongoDB deployments** add one network round trip per CAS operation
  plus transaction overhead (a replica set is required); the transport opt-in
  (`--allow-insecure-transport`) does not change message volume.

## Guidance

- Unlock cost is deliberate. Do not reduce Argon2id parameters to speed up
  commands.
- Prefer batching work into fewer invocations over invoking per operation.
