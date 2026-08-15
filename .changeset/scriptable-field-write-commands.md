---
'kavrix': minor
'@kavrix/core': minor
'@kavrix/schemas': minor
---

Complete the scriptable `creds get`, `set`, and `update` command family.

A field value is no longer accepted as a process argument. `field set` lost its
positional value and `field add` lost `--value <text>`; both now read a value
only from `--value-stdin` or the masked prompt, which itself fails closed with a
usage error when no terminal is attached. Local processes can read another
process's arguments, so this removes the only path that placed decrypted
credential data there.

`set` and `update` now resolve their target field exactly the way `get` does —
by ID, stable key, exact label, case-insensitive label, or unique prefix — so a
mistyped name reports not found (exit 3) or ambiguous (exit 4) instead of
silently defining a new field. Defining a field through `set` requires an
explicit `--create`. `update` refuses to redefine a field that comes from the
group template, because that definition is shared by every credential in the
group.

Both writes accept `--if-revision <n>` and refuse the write when the record has
already moved past that revision, reporting the existing sync-conflict error.
`get --json` now reports the `revision` the value was read at, so a script can
feed it straight back into `--if-revision`, plus a `redacted` flag that
distinguishes a withheld secret from a stored value that happens to spell
`[REDACTED]`. Every write returns a receipt naming the field, its label, type,
sensitivity, whether it was created, and the revision transition, in text or
`--json`.

A new `assertSingleValueWriteTarget` policy refuses a whole-value write to a
repeatable field or a collection field type instead of discarding the elements
already stored there, built on a new `fieldExpectsMultipleValues` predicate so
the set of element-holding types is defined once.

`set` and `update` are also published as top-level commands, replacing the entry
that documented them as unavailable. Each shares one handler with its `field`
counterpart so the two spellings cannot drift apart.

Two limitations remain and are covered by tests rather than hidden: writing an
individual element of a repeatable field is still unsupported, so such a field
must be rebuilt through the template path; and note content still accepts
`--content` as an argument, which issue #57's remaining work tracks separately.
