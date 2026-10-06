# Release notes — 0.2.39 reliable unlock and existing-vault compatibility

The TUI opens existing single-vault profiles through their protected standalone
routes instead of misclassifying them as uninitialized database containers.
MongoDB connections remain in memory after successful unlock for subsequent
credential actions, and are cleared on lock or unsuccessful authentication.
Failed authentication also clears prior unlocked state and credential names.

Expired convenience sessions now open masked passphrase input. Shift+U always
uses passphrase input, allowing users to recover from an unavailable OS keychain.
MongoDB unlock collects its masked connection string before authentication.

Common credential actions share one fresh verified profile read for their
routing and stdin frames. Database profile selection uses one fresh protected
snapshot instead of reading the registry twice. These are per-operation reads,
not an authorization cache; concurrent profile switches remain observable.
Permission verification and authentication stay mandatory.

Credential reads, edits, and refreshes honor the selected vault. Selecting a
vault clears prior derived screen rows and refreshes its credential list. Home
descriptions use plain language, and the footer shows the current operation and
elapsed time rather than an unexplained busy state. The existing 60-second child
deadline remains bounded; a timeout does not establish a wrong passphrase.

No encrypted vault, portable-key, profile, or cryptographic envelope format is
changed. Native Windows regression tests created populated legacy file and
MongoDB vaults with the installed 0.2.34 executable, then opened them with this
checkout. Credential names were preserved, a subsequent MongoDB refresh worked,
and encrypted records and key-file bytes remained unchanged after unlock/lock.
Observed unlock times were approximately 6.6 seconds for the file fixture and
2.3 seconds for local MongoDB; these are local measurements, not latency promises.
The local MongoDB test covered legacy storage on a standalone server, not
database-container transactions on a replica set.

The development toolchain pins source-map-js 1.2.2 to address
[GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q).
Its minimum-release-age exception is limited to that reviewed patch. Runtime
dependencies are unchanged. The high-severity audit gate passes locally; two
moderate advisories remain.

Cross-platform CI, CodeQL, full local release gates, trusted npm publication,
archive-integrity reconciliation, and GitHub release verification must finish
before publication is claimed. See the [canonical release procedure](release.md).
JavaScript cannot guarantee erasure of string copies, and these changes do not
protect an unlocked host from same-user malware or administrator access.
