# Release notes — 0.3.2

0.3.2 is a documentation-only release. The CLI code, exit codes, output
shapes, stdin frame orders, and package artifacts are unchanged from 0.3.1.

## Documentation reads as a first release

- The command guide and every user-facing page now describe the current
  command surface directly. There are no rename tables and no comparisons
  between releases; each page reads as the first description of the product.
- `kavrix --help` and `kavrix <command> --help` remain the authoritative
  summary for the installed version.
- The everyday commands are `add`, `get`, `ls`, `rm`, and `mv`; advanced
  database, owner-key, recovery, and migration operations live under
  `kavrix db ...`.
