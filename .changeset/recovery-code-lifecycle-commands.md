---
'kavrix': minor
---

Expose `creds recovery list`, `use`, `reveal`, and `copy` in the public
executable.

Every command selects a recovery code by its stable element identifier — an
exact match or an unambiguous prefix — and never by position, so a list whose
order changed between two invocations cannot cause the wrong code to be spent.
An ambiguous prefix is reported as ambiguous rather than resolved.

`recovery list` reports element identifiers, lifecycle state, and available/used
inventory counts with every code value masked in both text and JSON output.
`recovery use` marks exactly one element used, accepts `--if-revision <n>` for
optimistic concurrency, refuses an already-used code instead of restamping it,
and prints only a masked receipt. `recovery reveal` releases one unused value
under the same redirection guard as `creds reveal`, refuses a field whose
`revealPolicy` is `never`, and with `--use` marks the code used before printing
it so a crash can never leave a displayed code available; its receipt goes to
stderr so command substitution captures the code alone. `recovery copy` places
one unused code on the guarded clipboard and deliberately does not consume it,
because a clipboard write can fail after the value has left the vault.

The used state and its timestamp live inside the encrypted item record and reach
storage only through the existing revision-bound, crash-resumable mutation
queue, so the transition is durable and retry-safe without the API or MongoDB
being able to observe it.

Two limitations are documented rather than hidden. No CLI command mints a
recovery-code list; multi-element values arrive through `creds transfer import`,
sync, or a restore path the packed executable does not yet expose. And there is
no per-element archive, because the canonical element lifecycle is closed at
`available` and `used`; field-level `creds field archive` and
`creds field restore` retire a whole list.
