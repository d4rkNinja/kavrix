---
'kavrix': minor
---

Expose credential reference management as `creds reference add`/`remove`/`list`.

A reference is one credential pointing at another through an `item-reference`
field, and the item payload requires every such field value to resolve through
the credential's relation list. The field value and the relation are therefore
written in the same revision-bound mutation: writing either one alone would
produce a payload the schema refuses, so they are never separable steps. Only an
`item-reference` field is accepted. A text field can hold an item identifier as
characters, but that is a string and not a relation — no traversal would follow
it and deleting the target would leave it silently stale — so writing a
reference into any other field type is refused rather than accommodated.

Removal is the same invariant read backwards. The relation is retired only once
no remaining field value names the target, because a second field pointing at
the same credential still has to resolve through it. A field holding several
references refuses to guess and asks for `--target`, since dropping one
reference and dropping every one are different intents. A target that no longer
resolves anywhere is still removable: a relation can outlive the credential it
named, and refusing to clean that up would leave an unresolvable edge
permanently stuck.

An add that changes nothing writes nothing. Publishing a byte-identical payload
would consume a revision and record a history entry describing a change that
never happened, so a repeated add reports the reference as already present and
leaves the record untouched.

Cycles are disclosed rather than forbidden. Mutual references are a legitimate
shape, but closing a loop unannounced is how a reference set stops being
navigable, so the write refuses and names the path it would close until
`--allow-cycle` records that the loop is intended. The walk itself marks a cycle
and a revisit instead of following either, so a looped graph still terminates.

The new core reference-graph policy resolves each relation to an active,
archived, or missing target together with the field bindings that hold it, and
walks one level by default. Depth is bounded at 16 levels and 500 nodes, and a
walk that hits either bound reports the truncation rather than implying it saw
everything. Listing opens the whole vault in one pass because a reference may
cross groups: a walk confined to the credential's own group would report a
legitimate cross-group target as missing, which is the one answer this command
must never give wrongly. It asks for no mutation queue, so the read-only path
cannot reach the write path at all.

Repair remains explicit. A relation whose target was purged is reported as
missing on every walk and nothing prunes it automatically, because deciding that
an edge is obsolete is the operator's call; `reference remove` is the only thing
that drops it.
