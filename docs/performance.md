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
# Performance

Measured on a development workstation (Windows 11, Node 24, local SSD) against
the execution layer added in this release. Numbers are indicative for this
class of machine, not contractual guarantees; CI runs the same functional
suites on Linux/macOS but does not gate on timing.

## Component micro-benchmarks (in-process)

| Operation | Measured | Notes |
| --- | --- | --- |
| Policy evaluation (`evaluatePermission`) | < 1 Âµs per call (10,000 calls â‰ˆ 9 ms) | Pure in-memory allowlist/pin/cwd/TTL checks |
| Sealed-state envelope encrypt+decrypt round trip | â‰ˆ 136 Âµs per round trip (100 iterations) | XChaCha20-Poly1305 via libsodium on a small document |
| Executable resolution incl. SHA-256 of `node.exe` (â‰ˆ87 MB) | â‰ˆ 64 ms | Hash dominates; resolution itself is sub-millisecond |
| Argon2id passphrase KDF (vault unlock) | â‰ˆ 600â€“1,000 ms | Intentional cost; dominates every unlock-touching command |

## End-to-end observations

- `kavrix run` end-to-end against a local file datastore: â‰ˆ 1 s wall clock,
  dominated by Argon2id unlock; policy evaluation, sealed-state read/write,
  and spawn overhead are noise by comparison.
- Remote MongoDB deployments add one network round trip per CAS operation
  plus transaction overhead (replica-set required); observed command wall
  times of roughly 2â€“4 s depending on latency.
- The agent broker adds one socket round trip per requested operation
  (sub-millisecond locally) plus the same spawn cost as direct `run`.
- The sealed authorization sidecar rewrites its whole document per mutation;
  size stays bounded (audit ring capped at 512 events, â‰¤128 policies,
  â‰¤128 grants), so writes remain small.

## Guidance

- Unlock cost is deliberate (Argon2id parameters are part of the key-slot
  format). Do not reduce them to speed up commands.
- For scripted loops, prefer one `kavrix run` invocation wrapping many
  operations over repeated invocations; each invocation pays one unlock.
- The agent broker amortizes unlock across an entire agent session: secrets
  are decrypted once per session and every request costs only a local
  socket round trip plus policy evaluation.

