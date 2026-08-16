---
'kavrix': minor
---

Expose `creds search <term>` in the public executable.

The command scans the unlocked vault on this device. Group and credential names,
slugs, aliases, tags, subtitle, environment, owner, and purpose are matched, along
with note titles, non-sensitive note content, field labels, and field values whose
definition is locally searchable. Nothing is indexed, cached, or written, and no
term or result leaves the process, so the API and its database learn neither what
was searched nor what matched.

Sensitive field values are excluded unless `--include-secret-values` is passed on
that invocation, and even then a value whose reveal policy is `never` stays
excluded. An `environment-map` entry is gated on the entry's own `secret`
classification, because that field type is not itself sensitive and the
definition-level gate alone would turn a metadata-only search into a secret
oracle. Archived records are skipped unless `--include-archived` is passed and
deleted records are never scanned. A value whose field definition is missing is
refused rather than matched, so an unknown field identifier fails closed.

Results are bounded: the term is capped at 256 characters, a hit list at 200
records, and the matches reported per hit at 16, with truncation reported rather
than implied. A hit names the group or credential and the property that matched,
with a label locator such as a field label, note title, or tag. It never carries
the matched value or an excerpt of it, so reading a matched secret still requires
`creds reveal` or `creds get --reveal`.

`@kavrix/client` gains `VaultReadSession.listScopes`, which reads every group with
its items in one pass. Resolving a group query re-opens every group, so the
`listGroups` plus per-group `listItems` form would cost a quadratic number of
decryptions on a large vault. Each group key stays live only while its items are
opened and every key is zeroized on the success and the failure path.
