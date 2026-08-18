# Performance notes

Kavrix is a local CLI whose dominant costs are MongoDB round trips, Argon2id
passphrase derivation, and authenticated encryption. Commands avoid starting a
server or loading a sync graph.

The connection adapter uses bounded server-selection, connect, socket, and
operation timeouts. Vault writes use an optimistic revision check so concurrent
writers fail closed rather than silently overwriting one another.

No benchmark numbers are treated as release evidence in this repository. Add a
repeatable benchmark with a disposable MongoDB replica set before making
latency, throughput, or startup claims.
