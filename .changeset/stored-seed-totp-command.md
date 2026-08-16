---
'kavrix': minor
---

Expose `creds totp code <group> <credential> [field]` in the public executable.

The command generates one RFC 6238 code from a seed that is already stored in
the local encrypted vault. It takes no seed input: the seed is decrypted locally
through the unlocked read session, decoded inside `@kavrix/core`, and its decoded
bytes are wiped on every exit path including the failure path. Nothing is sent to
the API, which holds neither the seed nor a key able to decrypt it.

Policy options (`--algorithm`, `--digits`, `--period`, `--time`) match `creds
totp` and are validated before the vault is opened, so an out-of-range request
never decrypts anything. Omitting `[field]` selects the credential's only TOTP
field and refuses to guess between two. A field whose reveal policy is `never`
is refused, a field of any other type is refused as a wrong type rather than
reported as a missing seed, and a tampered or non-canonical stored seed fails
closed with a message that never echoes the stored bytes. The code goes to stdout
under the existing `--stdout` redirection guard while the field and policy receipt
goes to stderr, so a command substitution captures the code alone.

Two limitations are documented rather than hidden: a decrypted seed reaches
JavaScript as an immutable string that cannot be zeroed, so only the decoded
bytes are wiped; and `otpauth://` seed URIs are deliberately out of scope, so a
stored URI fails closed on the canonical base32 check.
