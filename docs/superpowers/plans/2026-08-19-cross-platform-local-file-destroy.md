# Cross-platform local-file vault and destruction implementation plan

> Implement the approved design in
> `docs/superpowers/specs/2026-08-19-cross-platform-local-file-destroy-design.md`.

## Invariants

- Preserve MongoDB as the default and preserve current command contracts.
- Never expose secret values in argv, environment, logs, prompts, or test output.
- Store only the canonical authenticated encrypted vault document in a local file.
- Keep `destroy` out of normal help/discovery and require unlock plus two exact confirmations.
- Every acceptance artifact must be test-owned and removed in `finally` on pass or failure.

## Workstreams

1. Fix receiver-safe terminal raw-mode handling and add exhaustive masked-input tests.
2. Add the backend-neutral encrypted-store contract, hardened file adapter, Mongo delete,
   and storage tests.
3. Refactor CLI datastore composition, implement hidden destroy and guarded cleanup,
   then add CLI tests.
4. Add packed all-command pre-CI acceptance with local-file lifecycle and unconditional cleanup.
5. Reconcile documentation, package/SBOM rules, CI gates, and release claims.
6. Run focused tests, full verification, package smoke/dry-run/audit, local acceptance,
   and remote acceptance if the operator-supplied Ubuntu host becomes reachable.

## Completion evidence

- Terminal regression tests reproduce the old detached-receiver failure and pass with the fix.
- File-store tests cover schema/tampering, permissions, links, locking, CAS, and deletion.
- Packed acceptance exercises every applicable command and proves all created files are gone.
- Root verification, packed smoke, package inspection, and dependency audit pass.
- Windows/macOS/Linux CI configuration runs the local-file acceptance gate.
- Documentation states exact verified results and honest remote/Mongo limitations.
