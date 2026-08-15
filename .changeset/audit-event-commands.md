---
'kavrix': minor
---

Expose `creds audit list` and `creds audit show` in the public executable.

Both commands render a local projection derived only from state the authorized
device already holds: unlock-slot lifecycle timestamps and queued opaque
mutations. `audit list` returns events newest first with bounded keyset
pagination (`--limit 1..200`, default 50) and an optional `--class` filter;
`audit show` inspects one event by its opaque identifier. Output carries opaque
metadata only, is terminal-sanitized, and never includes ciphertext, derivation
salts, or idempotency keys.

Two limitations are covered by tests rather than hidden: the `backup` class has
no locally persisted source, so it is accepted as a filter and yields no events;
and the creation event of a slot that was later superseded or revoked reports no
`state`, because the state at creation time is not retained locally.
