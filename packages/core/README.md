# `@kavrix/core`

Framework-free Kavrix entities, policies, ports, and use cases.

## Passphrase generation

`generatePassphrase()` uses Node's cryptographic random source and unbiased
rejection sampling. The default selects eight independent words from EFF's
1,296-word short list, producing `8 × log2(1296)`, approximately **82.7 bits**
of search space before optional decorations. Generation is entirely offline.

Policies can select 6–24 words, one of the fixed visible-ASCII separators,
one uniformly positioned capitalized word, one random trailing decimal digit,
and exact word exclusions. Policies below 64 bits of effective search space,
including a plain six-word policy with the short list, are rejected. Selection
uses replacement; repeated words are valid and do not weaken the stated search
space.

Generated values are branded as the canonical `SecretValue`. JavaScript strings
cannot be reliably zeroized, so callers must not log, persist, or pass them in
process arguments and should keep their lifetime short.

### Word-list provenance and license

The embedded list is **EFF Short Wordlist for Passphrases #1**, created and
published by the Electronic Frontier Foundation:

- Source: <https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt>
- Methodology: <https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases>
- License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/), under [EFF's copyright policy](https://www.eff.org/copyright)

The embedded copy removes the dice-code column while retaining all 1,296 words
in source order. Its normalized source checksum is documented beside the list.
