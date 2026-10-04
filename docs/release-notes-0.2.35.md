# Release notes — 0.2.35 setup destination recovery

## Fixes

- Windows parent-directory verification now handles inherit-only ACL entries
  correctly. These entries do not grant access to the parent itself. In
  particular, standard CREATOR OWNER child-inheritance rules no longer cause a
  false portable-key safety failure. Actual untrusted write/delete/control
  grants on the parent are still rejected.
- Interactive setup checks file, key, and recovery destinations when submitted.
  A rejected destination stays editable, with permission repair instructions
  and Enter to recheck. File and key destinations are checked before asking for
  owner passphrases or MongoDB connection credentials.
- Setup preflights all artifact destinations, including revision anchors, before
  adding a profile or initializing a database. Existing destinations and
  collisions are rejected before profile changes.
- Permission guidance explains Windows folder Security settings and local NTFS
  requirements, or POSIX ownership and modes. Missing folders and existing
  filenames have separate corrective instructions.

## Security and limitations

MongoDB and file profiles both require protected local key and recovery files.
Unsafe directories, symbolic links/reparse points, and unverifiable permissions
remain blocked. Setup can harden Kavrix's own existing artifact directory; it
does not rewrite permissions on arbitrary user-selected folders or home folders.
Users must repair those permissions or choose another protected destination.
Preflight does not replace checks performed again during protected-file writes.

## Verification

Regression tests cover actual Windows inherit-only versus direct write grants,
destination rejection/edit/recheck for both storage choices, existing filename
correction without spawning commands, and retained protected-input boundaries.
Publication requires the release gates and exact-commit CI/CodeQL checks described
in [the release guide](release.md).
