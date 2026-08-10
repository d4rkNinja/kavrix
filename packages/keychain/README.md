# `@kavrix/keychain`

Native-only storage for remembered device-unlock material, API session
credentials, and the protected synchronization rollback anchor. There is no
plaintext-file fallback.

The protected-state adapter implements the canonical `ProtectedSyncStatePort`.
It stores a compact versioned binary value containing its canonical vault and
device binding, highest-seen vault revision, and timestamp. It does not store
plaintext JSON or a placeholder hash. Its account namespace is
`v1:protected-sync-state:...`, distinct from device-unlock and API-session
accounts.

Join lifecycle bearer material uses the separate versioned namespace
`v1:vault-join-operation:...`. `NativeJoinJournalSecrets` encodes only a
schema-validated active join record in a canonical versioned binary frame. The
three bearer values remain raw fixed 32-byte fields inside native protected
storage; the whole frame is limited to 1,536 bytes (and therefore below the
2,560-byte Windows Credential Manager hard bound). Input is copied before the
native await, native load values are copied and wiped, adapter-owned write and
decode buffers are wiped on success and failure, and loaded bearer arrays are
fresh caller-owned values.

Revision saves are monotonic. A lower revision is rejected; for an equal
revision, an older timestamp is rejected. A higher revision remains valid when
the wall clock moves backward. Native input/output buffers and adapter-owned
copies are wiped on success and failure on a best-effort basis.

## Limitations

- Serialization is instance-local. Native credential stores do not expose a
  portable compare-and-swap operation, so concurrent CLI processes can race.
  Composition must enforce one sync writer per vault/device across processes;
  this package does not claim cross-process monotonicity.
- OS keychain protection depends on the signed-in platform account and its
  credential-store policy; it is not necessarily hardware-backed.
- JavaScript strings, OS keychain internals, and native-library copies cannot be
  guaranteed zeroized.
- Real native round-trip tests require `KAVRIX_KEYCHAIN_INTEGRATION=1`. They are
  skipped by default and clean up the generated entries when explicitly run.
- Native credential stores do not expose portable compare-and-swap or
  enumeration. Join lifecycle atomicity therefore comes from the local SQLite
  reservation/reconciliation protocol and its cross-process writer lease, not
  from this adapter alone.
