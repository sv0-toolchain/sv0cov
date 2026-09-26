<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->
# Benchmarks (SPEC 24)

- `protocol.json`: the frozen measurement protocol (pairing, ABBA ordering,
  3 warmup + 30 measured slots, timeout, retries, invalidation, statistics,
  aggregation). Its SHA-256 is pinned in `harness.py`; the harness refuses
  any other bytes. Changing it means a new protocol version and a complete
  rebaseline, never an edit after seeing results.
- `harness.py`: runs a plan's fixtures under the protocol and writes one
  canonical `sv0cov.benchmark-results` 1.0 bundle with the host descriptor,
  every raw sample (including invalid runs and their reasons), per-arm
  statistics, and the trend-series key. `harness.py host --stage <stage>`
  prints the descriptor alone.
- Stages: `managed-ci-provisional` (F0-R0.1 trend evidence only),
  `reference-dedicated` (R1 conformance), `local-development`. Only
  `reference-dedicated` bundles may claim conformance.

Until coverage instrumentation exists, fixtures have only a coverage-off arm;
those runs are baselines, never overhead evidence.

## Corpus (`corpus/`, `corpus.py`)

- `corpus/manifest.json`: 38 fixtures in the ten SPEC 24.3 categories, each
  with source or generator identity, seed and parameters, tree digest,
  expected result, scale, backends, coverage modes, timed boundary, budgets,
  and status (`runnable-baseline`, or `pending: <reason>` naming the slice
  that must land first). `corpus.py check` regenerates it and verifies the
  real-project snapshots; `write --heavy` also rebuilds the 250,000-point
  merge/report artifacts (about 3.5 minutes, 1.2 GB) and records their
  digests.
- `corpus/real/`: byte-for-byte copies of sv0c behavior cases and
  sv0-mathlib v0.2.0 at pinned commits (`REDISTRIBUTION.md`).
- `corpus.py plan --toolchain ROOT --work DIR --dimension compile|execute|ingest`
  materializes fixtures (checking replay digests), builds what the
  dimension needs, and prints a harness plan.
- Expected results were checked on 2026-09-25 with sv0c `d1a5100`: every
  runnable fixture gives its expected exit code and empty stdout on native
  and VM-v1 (`vm_exit` for the VM).
- Known toolchain limit: `region-large` (1,000 functions of 20 statements)
  exhausts the native compiler's 262,144-handle Vec table, so it is pending.
- `.github/workflows/perf-provisional.yml` runs the ingest campaign for the
  1,000,000 point/profile-pair fixture on the four managed-CI hosts weekly
  and on demand, as labelled provisional trend evidence.
