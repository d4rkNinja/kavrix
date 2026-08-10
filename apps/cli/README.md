# `kavrix` CLI shell

The injectable CLI catalog exposes schema-driven `show` and guarded `copy` commands for a
production composition layer. `show` accepts only the strict redacted projection exported by
`@kavrix/client`. `copy` accepts only a safe label/deadline receipt and prints:

```text
Copied <label> — clipboard clears in N seconds.
```

Plaintext field values never enter CLI contracts, renderers, stdout, stderr, or command
arguments. Repeatable values use a one-based `--index` selected by the client use case.

## Public local security tools

The packed executable includes `creds generate password`, `creds generate passphrase`, and
`creds totp`. Generation uses the production cryptographic RNG and reviewed policy functions from
`@kavrix/core`; TOTP uses its canonical Base32 decoder and RFC 6238 implementation. These commands
write exactly one generated value or code plus a newline.

Secret output requires an interactive stdout. Redirected or piped output fails before generation
or seed acquisition unless the caller explicitly supplies `--stdout`. TOTP seeds are accepted only
through a masked terminal prompt or `--secret-stdin`; there is no seed argument or environment
fallback. JavaScript strings can retain unavoidable immutable copies, so callers should keep the
process short-lived and must not log captured output.

Password options expose bounded length, class minima, and visible-ASCII exclusions. Passphrase
options expose bounded word count, the core-supported separators, one random capitalization, one
random digit, and canonical word exclusions. TOTP exposes SHA-1/SHA-256/SHA-512, 6-8 digits,
bounded period, and an optional bounded Unix timestamp. Verification windows are not exposed
because this command generates a code; it does not verify one.

### Embedded word-list attribution

Passphrase generation embeds the **EFF Short Wordlist for Passphrases #1**, created and
published by the Electronic Frontier Foundation. The reviewed
[source list](https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt) and EFF's
[generation methodology](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases)
are provided under [EFF's copyright policy](https://www.eff.org/copyright) and the
[Creative Commons Attribution 4.0 International license](https://creativecommons.org/licenses/by/4.0/).
The embedded copy removes the dice-code column and retains the 1,296 words in source order.

## Public portable key-file creation

`creds key create --file <path>` generates a new portable key locally and delegates canonical
version-one serialization, atomic create-only publication, filesystem ownership, and Windows ACL
enforcement to `@kavrix/key-files`. Files are unbound and unprotected by default. Existing targets
are never replaced, the key is never displayed, and successful output is only
`Portable key file created.`

`--protect-with-passphrase` encrypts the file with the reviewed Argon2id and
XChaCha20-Poly1305 implementation. Masked input requires the passphrase twice.
`--passphrase-stdin` instead requires exactly two bounded UTF-8 frames followed by EOF. Both
entries must match in constant time and contain at least 12 UTF-8 bytes. Passphrases are never
accepted through argv or environment variables. Owned key and encoded passphrase buffers are
wiped best effort; immutable JavaScript input strings remain an unavoidable runtime limitation.

## Injectable vault initialization

The internal catalog also exposes `creds init` when a composition root injects the client
lifecycle coordinator, durable journal, protected session/device storage, and a dedicated
sensitive-display implementation. Generated initialization displays portable and recovery
material once; existing-portable initialization displays only the newly generated recovery
material. The display port must attest an interactive TTY and explicit acknowledgement before
the CLI accepts confirmation.

Existing portable material can come from a masked prompt, an injected protected key-file
reader, or explicit `--key-stdin`. Secret values are never accepted in arguments or environment
variables. `--confirmation-stdin` uses exactly two bounded UTF-8 line frames (portable then
recovery) followed by EOF. `--key-stdin` is staged: the first bounded frame supplies the imported
portable key, the recovery material is then generated and acknowledged, and only then are the
portable and recovery confirmation frames consumed, followed by EOF. Missing, empty, oversized,
or trailing frames fail closed.

`creds init resume <operation-id>` and `creds init cancel <operation-id>` delegate to the durable
lifecycle journal; unsafe cancellation is reported generically. JavaScript can retain unavoidable
immutable string copies, so production ports must minimize lifetime and never log, serialize, or
redisplay them.

The public packed executable advertises only version, static completion, local generation, TOTP,
and portable key-file creation. Vault initialization, unlock, storage, clipboard, and authorization
remain injectable until their native composition is available. Native profile/journal and
sensitive-display composition remains outside this package slice.
