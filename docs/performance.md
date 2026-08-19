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
