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
