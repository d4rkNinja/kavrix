# Performance notes

Kavrix is a local CLI whose dominant costs are Argon2id passphrase derivation,
authenticated encryption, and either local atomic file I/O or MongoDB round
trips. Commands avoid starting a server or loading a sync graph.

The MongoDB adapter uses bounded server-selection, connect, socket, and operation
timeouts. The local-file adapter uses bounded reads, an exclusive writer lock,
atomic publication, and directory synchronization. Both use optimistic revision
checks so concurrent or stale writers fail closed.

The local-file adapters additionally reuse verified work within one open store:

- **Read snapshot.** The first read of a session takes the full path (identity
  checks, permission checks, bounded read, parse, canonicalization, and
  byte-exact canonicality comparison). While the store holds the exclusive
  writer lock, later reads are served from that verified container after a
  single `lstat` whose metadata snapshot (inode, size, mode, link count,
  nanosecond mtime/ctime) matches the verified read. Any change to any of
  those fields — including an in-place edit or a permission change — falls
  back to the full verification path, so no trusted content is served without
  evidence it is unchanged.
- **Permission-verification reuse.** Full ACL/ownership verification results
  are reused per path under the same snapshot rule. Every check still
  re-`lstat`s; only the platform permission check is skipped when the snapshot
  is unchanged, and any snapshot change or stat error reruns the full check.
- **Publication.** Writes keep atomic publication with staging, file sync, and
  directory syncs. After a successful publish the store records the exact
  published container, so the next read is served from verified memory after
  one confirming `lstat`; the published-file readback still parses and
  canonicalizes the on-disk bytes and compares them byte-for-byte with the
  staged bytes.

The executable entry point enables Node's V8 module compile cache before
loading the CLI graph, which removes most of the parse cost of the bundled
module graph from warm runs. The cache validates entries against the exact
source bytes and degrades to normal compilation when it cannot be written.

## CLI command latency

Every command's registration (parser, options, help text, and dispatch) is
loaded eagerly from a light module graph, while each command's implementation
loads through a dynamic import only after the arguments parse. Help, `--version`,
usage errors, and unknown commands therefore never load command
implementations, and no command pays for another command's code. Stable exit
codes live in a schema-free leaf of `@kavrix/schemas` so failure
classification does not pull the schema runtime into that path.

On Windows, the first protected-file operation pays a one-time helper
interpreter boot (several hundred milliseconds cold). The CLI starts that
helper unreferenced while arguments and unlock input are still being read, so
the boot overlaps work the command would wait for anyway. The warm-up is pure:
it never verifies anything and cannot turn a later failure into success; if it
cannot start, the first real request starts the helper again and fails closed.
Test runners can suppress it with `KAVRIX_SKIP_ACL_PREWARM=1` without changing
any verification outcome.

Measured on Windows (medians of cold real-command runs against a disposable
vault fixture, before versus after the registration split):

| Scenario                     |     Before |      After |     Ratio |
| ---------------------------- | ---------: | ---------: | --------: |
| `--version` process overhead |   166.4 ms |    76.1 ms |      0.46 |
| `vault get` (unlocked)       |   695.4 ms |   594.5 ms |      0.85 |
| JSON credential views        | 695–709 ms | 583–610 ms | 0.84–0.90 |
| `vault list` (unlocked)      |   606.1 ms |   604.8 ms |      1.00 |
| put + remove round trip      |  1516.6 ms |  1302.0 ms |      0.86 |
| rename round trip            |  1462.5 ms |  1450.8 ms |      0.99 |

The remaining cost of a real command is dominated by the deliberate Argon2id
unlock derivation plus the cold helper interpreter boot; both are unchanged in
strength by these optimizations.

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
