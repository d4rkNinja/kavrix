---
'kavrix': minor
---

Expose retention purge as `creds purge preview`/`fields`/`notes`.

Archiving a field value or a note keeps it in the record. That is the point —
an archived value is recoverable — but it also means a vault accumulates every
secret it ever held, and nothing could look at that accumulation or act on it.
A rotated database password stayed readable to anyone who could unlock the
group, indefinitely, with no way to answer even the first question an operator
would ask: what is still in here, and how old is it?

`packages/core/src/policies/retention-purge.ts` answers that question before
anything is destroyed. It inventories the vault into seven categories —
archived field values, orphaned values, notes, credential tombstones, group
tombstones, attachments, and history — and assigns each unit one of four fates:
purgeable, retained, server-retained, or unsupported. Every category reports a
total on every plan, including the empty ones, because a category silently
absent from a report reads as "nothing here" when it may mean "never looked".
Zero and unexamined are different answers and the plan distinguishes them.

`purge preview` is the whole of the read path and it asks for no mutation
queue, so previewing cannot reach the write path even by mistake. It states a
fate and a reason per unit and writes nothing. A retention window is honoured
only when one is given: no default window is assumed, because guessing an age
threshold on a destructive operation is how a value nobody meant to lose gets
lost. A plan is capped at 2,000 units and a truncated plan says so rather than
implying it saw the whole vault. A window is bounded at 36,500 days.

Destruction is deliberately narrow. `purge fields` and `purge notes` each
require `--force`, take `--if-revision` so a plan built against a stale read
cannot execute against a record that moved underneath it, and write one
revision-bound mutation per record. A retry is not a second destruction: the
values are already gone, so the repeat selects nothing and consumes no further
revision. `--field` resolves against the archived definitions, which is the
only place a purgeable value's field can still be named — it is by then absent
from both the item's live fields and its template's. An active note is refused
by ID rather than quietly skipped, since asking to purge a note that is in use
is a mistake worth reporting.

What the client cannot destroy, it declines to pretend about. Credential
tombstones carry a server-owned `purgeAfter` clock and are reported as
server-retained, because the deletion horizon is not the client's to move.
Group tombstones are not enumerable from a client at all, so the plan names
that as an undiscoverable category instead of reporting an empty result that
would read as "no deleted groups". History is server-owned and reported as
unsupported.

Two consequences of purging are reported rather than acted on. A relation is
retired only when the purge removes the last field value binding it, since a
second value still pointing at the same credential has to keep resolving.
An attachment stranded by a purged reference is reported and left linked:
unlinking blob content as a side effect of destroying a field value is not
something an operator asked for, and an attachment reachable from a
report is recoverable where a silently unlinked one is not.
