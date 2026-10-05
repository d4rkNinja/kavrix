# Release notes — 0.2.37 guided setup and faster TUI

This release addresses all six setup and interaction improvements following
0.2.35's cross-platform destination fix and 0.2.36's fullscreen UI update. It also
removes redundant profile reads that delayed TUI actions and screen updates.

## Six improvements

1. **Truthful clipboard status.** Copy reports the backend actually used.
   Terminal clipboard copies schedule a best-effort clear after approximately
   30 seconds while Kavrix remains open. System clipboard copies explicitly
   say automatic clearing is unavailable and ask the user to clear manually.
2. **Guided permission repair.** Path fields provide secure defaults, a folder
   browser, a permission-repair preview, and Enter to recheck. Repair requires
   confirmation and restricts the Kavrix artifact directory to its owner.
   Home directories, filesystem roots, unrelated folders, and symlinked managed
   directories are refused. File contents are never edited. On Windows,
   directory repair can tighten inherited child permissions.
3. **Review before creating.** Setup displays storage, profile, database or
   data-file location, key-file location, recovery location, and vault label.
   Edit controls retain unrelated answers; protected values remain hidden.
   Destination validation alone never creates a vault. Enter on the review
   screen explicitly starts creation.
4. **MongoDB connection test.** Test Connection (`Ctrl+T`) uses masked input,
   checks connectivity and authentication, and sends only a read-only `ping`.
   Enter tests an unverified address before requesting passphrases. Editing
   the address or database invalidates its verification. An isolated worker
   has a 15-second lifetime limit, including DNS resolution. Driver diagnostics
   are suppressed; errors use finite, generic categories. Remote connections
   require TLS, including the driver's TLS default for SRV addresses.
5. **Actual operation stages and elapsed time.** Creation reports permission
   checking, encrypted storage creation, MongoDB connection where applicable,
   vault creation, recovery-kit creation, and recovery verification as those
   operations run. Elapsed time reflects the running operation. Duplicate
   creation and tool actions are blocked; no estimated completion percentage
   is presented for these operations.
6. **Cursor editing and folder selection.** Inputs support arrows, Home/End,
   Delete, and `Ctrl+A/E/U`. `Ctrl+B` opens a bounded folder-only browser;
   `Ctrl+S` chooses the folder while preserving the filename. The browser
   returns metadata only, never protected file contents. Selected paths still
   pass the existing secure destination checks before use.
   Default paths start browsing at home so the browser also works before
   `.kavrix` has been created on a fresh installation.

## UI and security

Review edit controls remain in the footer on compact terminals. The review
summary scrolls with arrows, and `Ctrl+G` shows full public settings and guidance.
Mouse controls emit the same guarded keyboard actions. Protected input stays
masked when moving the cursor, reviewing settings, or opening Help.

File and MongoDB storage both need a protected local portable-key file. An unsafe
key-file error describes a local permission or path problem, independently of
the datastore. Setup now offers correction before creating artifacts; it still
fails closed on unsafe permissions, authentication, or corruption. MongoDB
continues to receive encrypted vault records only.

## Faster TUI updates

Screen updates use one freshly validated profile document instead of five
repeated reads. The profile list, selected profile, and session target share
that consistent view. Permission checks remain active on every update; no
authorization result is cached. This removes redundant work on every supported
operating system. Local Windows measurements improved from about 1.1 seconds
to 0.36 seconds across three samples each. Encryption, protected storage, and
database latency still depend on the operation.

## Verification and limits

Regression coverage includes preview versus confirmed repair, refusal to change
unrelated or symlinked directories, bounded metadata listing, cursor edits,
review confirmation, preserved answers, connection invalidation, worker expiry,
generic error handling, masked-input canaries, compact controls, mounted stage
updates, elapsed time, and duplicate action guards. A real-driver test covers a
refused connection; the replica-set integration test checks that a successful
probe creates neither collections nor a database.

A successful connection test does not prove later write permissions, service
availability, or an entire vault operation. Clipboard clearing is not guaranteed
by the terminal, and clipboard managers may retain history. Folder metadata can
change after browsing; protected I/O rechecks destinations. JavaScript string
copies cannot be guaranteed erased from memory. Touch depends on the terminal
translating taps into supported mouse reports.

Publication requires the [release gates](release.md), native platform CI, and
CodeQL on the exact release commit. Versions 0.2.35 and 0.2.36 remain immutable.
