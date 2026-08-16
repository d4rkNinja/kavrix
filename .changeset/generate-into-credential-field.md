---
'kavrix': minor
---

Expose `creds field generate <group> <credential> <field>` in the public executable.

The command generates one password or passphrase and stores it in a credential
field in a single invocation, so a generated secret no longer has to travel
through a shell pipeline, a scrollback buffer, or a clipboard to reach the vault.
The value is produced by the same `@kavrix/core` generators `creds generate`
uses and is written through the same single-update path `creds field set` uses,
so the write either lands whole or not at all.

Password options (`--length`, `--lowercase-min`, `--uppercase-min`,
`--digits-min`, `--symbols-min`, `--exclude`) and passphrase options
(`--passphrase`, `--words`, `--separator`, `--capitalize`, `--digit`,
`--exclude-word`) match `creds generate password` and `creds generate
passphrase` and are bounds-checked before the vault is opened, so an
out-of-range policy exits 2 without unlocking anything. Mixing the two policies
is refused rather than silently resolved. `--create` defines a missing field and
`--if-revision <n>` refuses a write against a credential that moved.

The generated value is never printed by the write itself; the receipt reports the
resolved field, the revision transition, and the requested shape only. `--copy`
places the value on the guarded clipboard and `--reveal` prints it, each by
re-reading the stored field through the same reveal and copy policies `creds
copy` and `creds reveal` enforce, so a field that denies reveal denies it here
too. With `--reveal` the value is alone on stdout under the existing redirection
guard and the receipts move to stderr, so a command substitution captures the
secret alone.

One limitation is documented rather than hidden: a generated value reaches
JavaScript as an immutable string that cannot be zeroed, so only the encoded
bytes handed to the write path are wiped.
