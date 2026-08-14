# Semantic backup restore design

Date: 2026-08-14

## Scope

Issue #44 extends the known-version backup restore verifier with the two
documented semantic families that can be validated by the current vault model:

- v1 history records contain an item snapshot.
- v1 audit records contain a key-slot audit event.

The verifier remains zero-knowledge. It opens these payloads only in memory for
validation and never includes decrypted content in a receipt, log, sync event,
or MongoDB document.

## Canonical contracts and key ownership

History v1 reuses the v1 item payload schema. The record is bound to its
archived vault, group, item, schema, item revision, and ciphertext digest. Its
encrypted payload is opened with the referenced item's active key and the
history-record AAD. The payload identity and revision must agree with the
outer record, and the history envelope must use the item's current payload key
version.

Audit v1 reuses the documented key-slot audit payload schema. Its encrypted
payload is opened with the archived vault root key and the audit-record AAD. The
record must reference a key version present in the archived key-slot set, and
the payload's slot identity, slot type, key version, action, and resulting
state must agree with that archived state. Audit payloads use the canonical JSON
encoding emitted by the slot lifecycle writer.

## Verification sequence

The verifier parses and bounds the outer archive before it processes records.
For each history or audit entry it then:

1. rejects duplicate opaque record identities and invalid parent relationships;
2. checks the documented schema and key-version bindings;
3. decrypts with the owning in-memory key and the record's authenticated AAD;
4. rejects malformed, non-canonical, or semantically mismatched plaintext;
5. classifies authenticated future payload versions explicitly as unsupported;
6. wipes temporary plaintext before returning the aggregate count receipt.

Authenticated corruption, malformed payloads, and relationship mismatches use
the generic invalid-archive result. A recognized family with a future payload
version uses the explicit unsupported result. Neither result discloses
plaintext or which secret was close to valid.

## Publication and receipt

The verified restore count algebra now includes bounded history and audit
subcounts. The isolated restore store publishes those records only after the
complete archive has been verified, in the same transaction boundary as the
other opaque records. The publication receipt reports counts and identifiers,
not decrypted payloads.

## Regression coverage

Client verifier tests cover valid v1 history and audit records, authenticated
semantic/ciphertext corruption, duplicate and binding failures, and
authenticated future versions. Schema tests cover non-zero bounded semantic
subcounts. Storage fixture and integration tests exercise the canonical v1
archive, receipt counts, publication, and explicit future-version failure.
