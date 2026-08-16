# Direct access CLI

The product requirement is a fast direct path to one credential. The packed
`creds` executable now composes that path: `show`, `copy`, `reveal`, `get`, and
the `recovery` lifecycle commands are all registered in
`PUBLIC_CLI_COMMAND_CATALOG`. The sections below state what each released
contract does and does not guarantee.

## Capability status

| Requested surface                           | Live implementation                                                                               | Executable status                   |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------- |
| `creds show <group> <credential>`           | Parser, use-case contract, local read session, schema validation, and redacted text/JSON renderer | Registered in the packed executable |
| `creds copy <group> <credential> <field>`   | Native secure-clipboard adapter, composed copy use case, and TUI item-ID/field-ID intent boundary | Registered in the packed executable |
| `creds reveal <group> <credential> <field>` | Composed reveal use case with a non-interactive redirection guard                                 | Registered in the packed executable |
| `creds recovery list / use / reveal / copy` | Core recovery-code selection policy plus composed lifecycle executors                             | Registered in the packed executable |

See [CLI Reference](./cli-reference.md) for the full public command list.

## Show contract

The repository catalog defines:

```text
creds show <group-query> <credential-query> [--json]
```

Each query is trimmed and must contain 1 through 512 characters. The CLI makes
one call to the injected show use case with both queries. The
[`VaultReadSession`](../packages/client/src/vault-read-session.ts) then resolves
the group, loads only that group's items, resolves the credential within it, and
locally unwraps/decrypts authenticated records. It rejects tombstoned records,
wrong vault/group identity, unsupported key/schema binding, duplicate opaque
IDs, noncanonical payload JSON, and item/template mismatch.

The API is not involved in name resolution and cannot see decrypted names. The
production CLI must consume an authenticated opaque snapshot or storage port; it
must not connect directly to MongoDB.

### Group and credential resolution order

[`resolveNamedEntity`](../packages/core/src/policies/name-resolution.ts) applies
the same deterministic phases to the group and then to the credential:

1. exact opaque ID, case-sensitive after trimming;
2. exact normalized slug or alias, case-sensitive;
3. exact normalized display name, case-sensitive;
4. one case-insensitive exact match across name, slug, and aliases;
5. one unique case-insensitive prefix across ID, name, slug, and aliases.

Name, slug, alias, and prefix comparisons trim, apply Unicode NFKC
normalization. The last two phases also perform locale-independent lowercase
comparison. An exact higher-priority phase wins before a lower phase is
considered; for example, an exact alias wins over another record's display name.
More than one match within the selected phase is an error. No match returns
`NOT_FOUND`/exit `3`; ambiguity
returns `AMBIGUOUS_NAME`/exit `4` and instructs the caller to use an opaque ID or
unique alias without listing candidate IDs.

Group resolution completes before credential resolution. A credential query is
never allowed to select an item from a different group silently.

### Redacted projection

`show` does not return raw decrypted domain data directly to stdout. The current
renderer validates that the item matches its exact template version and builds a
safe projection:

- text includes title, opaque item/group IDs, template name, revision, optional
  subtitle/tags, all active fields, archived fields, and note titles;
- JSON additionally includes favorite and production-sensitive flags plus each
  field's stable key, label, value state, archived state, and sort order;
- template fields, item-only fields, and archived values are ordered
  deterministically;
- a field marked sensitive is always `[REDACTED]`;
- `secret` scalar values and secret-classified environment entries are redacted
  even if a malformed caller labels their definition nonsensitive;
- every note body is redacted; only sanitized note metadata is rendered;
- missing, empty, inapplicable, and unreadable values use explicit state markers;
- terminal escape/control and bidi sequences are neutralized in both text and
  JSON.

`--json` is a stable redacted machine-readable view, not an export or secret
access mechanism. Piping either form must remain ANSI-free and must never make
secret fields visible.

## Copy target

The canonical form is:

```text
creds copy <group-query> <credential-query> <field>
```

It exists in the built package. The `copy` port takes the group, credential, and
field queries plus optional copy options, and the field query accepts a field ID,
stable key, exact label, or unique prefix. The data model establishes a stable
field key for automation and copy sequences; display labels are mutable and must
not be silently treated as stable automation identifiers. Group and credential
resolve with the order above, one exact field identity is resolved without
guessing, and missing, archived, or otherwise ambiguous selection fails rather
than picking a candidate.

The existing lower-level behavior provides these constraints:

- the TUI issues only item ID and field ID to `copyField`; it never receives the
  copied value back;
- noncopyable fields and `copyPolicy: never` are refused, while
  `copyPolicy: confirm` requires confirmation;
- the secure clipboard adapter accepts already-authorized UTF-8 bytes only,
  writes them to fixed native commands through child stdin, and never puts them
  in argv, environment variables, URLs, persistence, logs, or error messages;
- expiry is bounded from 250 ms through five minutes; generation checks prevent
  an older Kavrix timer from clearing a newer Kavrix copy;
- timed clear, lock, and dispose compare the current clipboard fingerprint and
  preserve newer external content when it no longer matches.

Clipboard clearing is best effort. Clipboard managers, accessibility tools,
remote-desktop software, other processes, and malware can retain plaintext. The
native command APIs cannot provide a portable atomic compare-and-clear. See the
[TUI Guide](./tui-guide.md) for the implemented interactive intent boundary.

A repeatable value is selectable two ways. `creds copy` and `creds get` keep
their one-based `--index <n>`, and `creds recovery copy`, `creds recovery use`,
and `creds recovery reveal` select an element with `--code <id>`, which accepts an
exact identifier or an unambiguous prefix and never an ordinal. Identifier
selection is the safer form, because the same index names a different element once
a list gains or loses one. `creds recovery reveal --use` is the only consume
action, and it marks the code used before printing it. There is still no
`--sequence` and no JSON secret-copy mode.

## Reveal target

The canonical form is:

```text
creds reveal <group-query> <credential-query> <field>
```

It exists in the built package and denies non-interactive redirection unless
`--stdout` is passed explicitly. `creds recovery reveal` prints one recovery code
under the same guard, and adds `--use` to mark that code used before it is
printed.

Only the recovery path consults the field's `revealPolicy`: it refuses a field
declared `never`. `creds reveal` and `creds get --reveal` do not, so the timed and
`confirm` reveal ceremony remains TUI-only. The TUI state machine permits reveal
only for a sensitive field whose `revealPolicy` is not `never`, requests
confirmation when the policy is `confirm`, delegates
authorization/reauthentication to a use case, and grants a 15-second reveal state
after authorization. Lock, group/item changes, and expiry clear reveal state.

That TUI contract is not the CLI contract, and neither one may be inferred from
the other. The CLI has no reauthentication prompt on reveal and no timed
expiry of a printed value, because a value written to a terminal or a pipe cannot
be recalled.

## Quoting direct targets

These examples show how the positional syntax must be quoted in each shell.

```text
# Bash, Zsh, or Fish
creds show 'Email Accounts' 'Gmail Work'
creds copy 'Email Accounts' 'Gmail Work' 'password'

# PowerShell
creds show 'Email Accounts' 'Gmail Work'
creds copy 'Email Accounts' 'Gmail Work' 'password'
```

Single quotes prevent whitespace splitting and most shell expansion. PowerShell
represents an apostrophe inside a single-quoted name by doubling it. Bash and Zsh
can close the literal, insert `\'`, and reopen it. For difficult punctuation or
names beginning with `-`, prefer an opaque ID and the option terminator `--`.
Names and stable keys are not secret;
portable keys, passphrases, recovery keys, tokens, and field values must never be
passed this way.

## Remaining acceptance gaps

The direct workflow is not complete until the packed executable composes a real
profile, native session credential, encrypted sync snapshot, protected rollback
state, unlock slot, vault read session, clipboard, and lock lifecycle. Required
but currently absent executable evidence includes exact names/aliases/IDs across
shells, Unicode and ambiguous targets, direct copy without printing, clipboard
expiry on each supported OS, guarded reveal, redirected redaction, offline/error
behavior, and full lock/zeroization cleanup.
