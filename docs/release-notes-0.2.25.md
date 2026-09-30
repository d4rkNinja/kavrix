# Release notes — 0.2.25 CI acceptance split

No product-behavior changes; the published CLI bits are identical to 0.2.24.
This release ships the CI change that keeps Windows verify shards test-only:

- The packed-database/all-commands/packed-CLI acceptance steps moved from
  Windows verify shard 1 into a parallel `windows-acceptance` CI job, so they
  no longer extend the slowest shard.
- Windows test files remain serialized per shard. Bounded-parallel file
  execution (`maxWorkers: 4`) was validated on a 32-core dev machine (the
  ten starvation-sensitive files passed 134/134) but reverted after two CI
  shards on 4-vCPU hosted runners starved real-CLI children: fixture
  `beforeAll` hooks blew past their 120s cliffs, and the agent broker
  correctly fail-closed starved live requests as `invalid-request` before a
  decision was sent, breaking journey assertions. Revisit with a split pool
  that keeps the child-spawning journeys serial while the unit-heavy files
  run concurrently.
