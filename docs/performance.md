# Performance evaluation

Kavrix has a manual, correctness-first benchmark harness at
[`benchmarks/performance.ts`](../benchmarks/performance.ts), reached through the
runtime-checking
[`benchmarks/run-performance.js`](../benchmarks/run-performance.js) launcher.
It is an evaluation tool, not a CI gate and not a cross-platform performance
claim. Every result is specific to the reported runtime, OS, architecture, CPU,
memory, build, and background load.

## What the harness measures

The harness exercises compiled production APIs and a package produced from the
public CLI manifest. It does not replace cryptography, storage, sync, or backup
code with benchmark mocks.

| Area               | Measured operation                                                               | Fixture                                                                                                                               |
| ------------------ | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Public CLI         | Fresh Node process running packed `creds --version`                              | Package created with lifecycle scripts disabled from the existing reviewed build output, installed into a private temporary directory |
| Public CLI         | Fresh Node process rendering static Fish completion                              | Packed `creds completion fish`; output and exit status are checked                                                                    |
| Passphrase unlock  | Argon2id derivation plus authenticated root-key unwrap                           | Production minimum policy: 65,536 KiB, 3 passes, parallelism 4                                                                        |
| Portable unlock    | Portable-key parsing, HKDF, and authenticated root-key unwrap                    | Generated benchmark-only portable slot                                                                                                |
| Direct resolution  | Unique group and item resolution, plus ambiguity rejection                       | 500 group names and 5,000 item names                                                                                                  |
| Exact-ID item read | Unlock, direct group/item lookup, authenticated decrypt, and schema validation   | One group and one item read from a snapshot containing the full fixture                                                               |
| Named item read    | Unlock, group/item authenticated decrypt, schema validation, and name resolution | 128 encrypted groups; 32 encrypted items in the selected group                                                                        |
| Opaque sync        | Runtime-schema validation, content-hash checks, copy, and snapshot application   | One 161-record pull page: vault, 128 groups, and 32 items                                                                             |
| Encrypted backup   | Authenticated streaming create and streaming verify                              | Vault plus the same 160 encrypted records; actual size is reported                                                                    |

Fixtures use generated keys and production XChaCha20-Poly1305, HKDF, Argon2id,
wrapping, sync, and backup APIs. Their decrypted payloads are explicitly
benchmark-only data. Keys, formatted portable keys, plaintext payloads, local
paths, hostnames, usernames, and environment values are not written to the
report.

### Exact-ID fast path and named-read limitation

When both queries are canonical opaque IDs, the exported read session uses
direct `getGroup` and `getItem` calls. The exact-ID metric asserts one group
lookup, one item lookup, and zero list calls on every sample while the backing
snapshot still contains the full fixture.

Name, slug, alias, case-insensitive, and prefix lookup retains broader fan-out.
The named metric decrypts all 128 group metadata records before resolving the
group, then all 32 item metadata records in the selected group before resolving
the item. It does not decrypt every credential payload in the vault. The report
records both exact-ID and named fan-out counts, and the two results must not be
conflated.

## Methodology and safety

Timing uses `node:perf_hooks` `performance.now()`. CLI processes use
`node:child_process` `spawn` with argument arrays, `shell: false`, ignored stdin,
bounded output, and a timeout. Each metric has at least one warmup and multiple
samples. Batch measurements are normalized to one operation. The report uses
the median and nearest-rank p95.

Correctness is checked during fixture setup and again after every warmup and
sample before that duration is retained. Examples include exact CLI output and
exit status, constant byte equality after unwrap, expected ambiguity errors,
selected item identity, sync cursor/count progression, and full backup
authentication. A correctness failure aborts the run instead of publishing
partial timings.

Read-call counts come from transparent instrumentation that delegates every
operation to the production opaque snapshot. It does not return synthetic
records or replace the storage implementation.

The harness accepts only Node `>=24.12.0 <25 || >=25.1.0`, mirroring
`engines.node`. `--output` uses exclusive file creation and refuses to overwrite
an existing file. Report metadata omits
working-directory paths, temporary paths, usernames, hostnames, and environment
contents. Child processes receive a narrow environment. Temporary package data
is removed after the run.

## Evaluation budgets

These budgets are review objectives, not portable guarantees. They make slow
evaluation results visible without failing the benchmark or weakening a
security policy. Median and p95 must both be within the listed values for the
report's informational status to be `true`.

| Metric                                       | Median objective | p95 objective | Rationale                                                                   |
| -------------------------------------------- | ---------------: | ------------: | --------------------------------------------------------------------------- |
| Packed cold `--version`                      |           350 ms |        750 ms | Static metadata should not initialize vault services                        |
| Packed cold Fish completion                  |           350 ms |        750 ms | Completion is static and must not read vault state                          |
| Minimum-policy Argon2id unlock               |         1,500 ms |      2,500 ms | Tolerates deliberate KDF cost; parameters are never lowered to meet timing  |
| Portable authenticated unwrap                |            10 ms |         25 ms | Local parsing, HKDF, and one authenticated unwrap                           |
| 500-group resolution                         |             2 ms |          5 ms | Bounded direct metadata scan                                                |
| 5,000-item resolution                        |            20 ms |         40 ms | Bounded direct metadata scan                                                |
| 5,000-item ambiguity rejection               |            20 ms |         40 ms | Includes collecting and rejecting the ambiguous match set                   |
| Exact-ID one-group/one-item show             |            25 ms |         50 ms | Authenticated decrypt and validation over direct production adapter lookups |
| 128-group/32-item named show                 |           250 ms |        500 ms | Explicitly budgets current metadata fan-out, not a single-record read       |
| Apply 161 opaque sync records                |            80 ms |        160 ms | Includes schema and content-hash validation plus adapter-owned copies       |
| Create authenticated encrypted backup stream |           100 ms |        200 ms | Approximately one MiB, with exact bytes reported                            |
| Verify authenticated encrypted backup stream |           100 ms |        200 ms | Approximately one MiB, with exact bytes reported                            |

Argon2id always uses the production minimum of 64 MiB, 3 passes, and
parallelism 4. A missed Argon2 budget is a measurement to investigate, never a
reason to reduce those values.

## Run it

Build all production packages and the public CLI first. The harness intentionally
imports compiled output and packages the existing CLI output with lifecycle
scripts disabled, so it cannot silently rebuild or mutate release artifacts.

```powershell
corepack pnpm install --frozen-lockfile
corepack pnpm build
node benchmarks/run-performance.js
```

Write a report only to a new path:

```powershell
node benchmarks/run-performance.js --output benchmarks/results/local.json
```

Remove or rename an existing report deliberately before reusing a filename; the
harness has no overwrite flag. Do not attach environment dumps or terminal logs
to a performance report.

Check the benchmark itself with the repository-pinned tools:

```powershell
node node_modules/typescript/bin/tsc -p benchmarks/tsconfig.json --pretty false
node node_modules/eslint/bin/eslint.js benchmarks/performance.ts benchmarks/run-performance.js --max-warnings 0
node node_modules/prettier/bin/prettier.cjs --check benchmarks/performance.ts benchmarks/run-performance.js benchmarks/tsconfig.json docs/performance.md
```

The local `tsconfig` is
[`benchmarks/tsconfig.json`](../benchmarks/tsconfig.json). No performance budget
is enforced in CI today. Add a gate only after multiple controlled hosts have
established variance, ownership, and a regression-triage policy.

## Node 24.19 Windows x64 reference run

The checked-in
[`2026-08-10 Windows x64 report`](../benchmarks/results/windows-x64-node-v24.19.0-2026-08-10.json)
is a local working-tree measurement, not a release or cross-platform claim. It
was recorded on 2026-08-10 after rebuilding the production packages and public
CLI.

| Environment    | Measured value                                         |
| -------------- | ------------------------------------------------------ |
| Node           | v24.19.0; V8 13.6.233.17-node.51                       |
| OS             | Windows `win32`, release 10.0.26200, x64               |
| CPU            | 13th Gen Intel(R) Core(TM) i9-13900K; 32 logical CPUs  |
| Memory         | 63.8 GiB total                                         |
| Backup fixture | 1,666,158 bytes (1.589 MiB), 161 authenticated records |

| Metric                           | Warmups | Samples | Operations per sample |      Median |         p95 | Within informational budget |
| -------------------------------- | ------: | ------: | --------------------: | ----------: | ----------: | :-------------------------: |
| Packed cold `--version`          |       3 |      15 |                     1 |  122.369 ms |  127.084 ms |             Yes             |
| Packed cold Fish completion      |       3 |      15 |                     1 |  124.768 ms |  145.467 ms |             Yes             |
| Minimum-policy Argon2id unlock   |       1 |       7 |                     1 |   52.614 ms |   66.952 ms |             Yes             |
| Portable authenticated unwrap    |       3 |      21 |                     1 |    0.074 ms |    0.134 ms |             Yes             |
| 500-group resolution             |       5 |      31 |                    25 | 0.083 ms/op | 0.129 ms/op |             Yes             |
| 5,000-item resolution            |       5 |      31 |                    10 | 0.848 ms/op | 0.993 ms/op |             Yes             |
| 5,000-item ambiguity rejection   |       5 |      31 |                    10 | 0.800 ms/op | 1.045 ms/op |             Yes             |
| Exact-ID one-group/one-item show |       3 |      21 |                     1 |    0.503 ms |    0.889 ms |             Yes             |
| 128-group/32-item named show     |       2 |      11 |                     1 |   24.188 ms |   29.100 ms |             Yes             |
| Apply 161 opaque sync records    |       3 |      15 |                     1 |   12.206 ms |   15.066 ms |             Yes             |
| Create encrypted backup stream   |       2 |      11 |                     1 |    9.160 ms |   13.808 ms |             Yes             |
| Verify encrypted backup stream   |       3 |      15 |                     1 |    8.982 ms |   12.467 ms |             Yes             |

At the measured median, backup creation processed 173.469 MiB/s and
verification processed 176.906 MiB/s for this bounded in-memory fixture. Those
figures do not include filesystem or network I/O and must not be presented as
disk-backup throughput.
