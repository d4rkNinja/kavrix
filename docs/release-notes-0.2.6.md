# Kavrix 0.2.6 — Structured project credentials

Kavrix 0.2.6 moves database vaults beyond a flat name/value map while retaining
the established root command behavior. New database vaults use a versioned,
vault-bound hierarchy:

```text
database → vault → project context/environment → service/group
         → credential item → typed fields, notes, attachments, and history
```

## Structured command surface

The new `context`, `service`, `item`, and `field` command families operate on
database-container profiles. `environment`, `group`, and `credential` are
equivalent aliases. Parent names resolve exactly; duplicate, missing, ambiguous,
or non-empty removal requests fail closed.

Typed fields include username, password, API key, URL, certificate, TOTP seed,
recovery-code list, JSON, and environment-map values. Each field carries its
copy, reveal, reauthentication, and export policies in the authenticated
schema. Values are accepted only through a masked prompt or protected stdin.
List and show output never contains field values. Ordinary `field get` returns
non-sensitive values as escaped JSON and redacts present sensitive values;
explicit reveal must pass the field policy and the existing stored reveal
authorization. `--reveal-base64` provides an authorized multiline-safe
transport without terminal control-sequence interpretation.

Items retain the canonical note, expiry, rotation, attachment-reference, and
history relationships. This release models and preserves encrypted attachment
and history records but does not add attachment transfer or history-restore
commands.

## Flat-command compatibility

`put`, `get`, `list`, `view`, `search`, `stats`, `has`, `rename`, and `remove`
continue to operate on a compatibility view: the default project context,
default service, and one sensitive `value` password field per item. A flat name
such as `production/database/main` remains one literal title rather than being
interpreted as a hierarchy path. Structured entities outside the default
context/service are not exposed through flat commands.

Legacy database payloads are not rewritten merely because a root command reads
or updates them. The first structured mutation, or an explicit copy-first
database migration, performs the versioned upgrade. Flat changes applied to an
already structured vault preserve item identities and unrelated typed fields;
ambiguous transitions are rejected rather than guessed.

## Zero-knowledge and validation boundary

The hierarchy is not a new server-visible data model. Project names, service
names, item metadata, typed values, notes, policies, attachment relationships,
and history records remain inside the existing client-encrypted vault payload.
MongoDB and the local database adapter continue to store opaque authenticated
documents only.

The aggregate is bound to the enclosing vault ID and validates its own version,
entity bounds, scoped name uniqueness, parent references, attachment ownership,
history ownership, and canonical field/value combinations before use. Unknown
versions or policies, malformed links, cross-vault records, and oversized
plaintext fail closed.

## Release verification

Publication is gated by the complete local release suite, package smoke and
content inspection, dependency audit, exact-commit CI and CodeQL, npm trusted
publishing with provenance, registry SHA-512 integrity reconciliation, and
GitHub release creation only after npm confirms `kavrix@0.2.6`.
