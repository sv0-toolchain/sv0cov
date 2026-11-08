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
  prints the descriptor alone (both take `--toolchain-revision`; the
  CI workflow passes the checked-out commit). `cpu_model` is read from
  `/proc/cpuinfo` (x86 model name, or Arm implementer/part mapped to a name),
  and `filesystem` is the type of the work/temp directory (mountinfo on
  Linux, `stat -f %T` on macOS); only truly unobservable fields stay `unknown`.
- Stages: `managed-ci-provisional` (F0-R0.1 trend evidence only),
  `managed-ci-recorded` (R1 evidence under the DEC-087 managed-CI exception,
  CV-410), `reference-dedicated` (R1 conformance), `local-development`.
  Only `reference-dedicated` bundles claim conformance themselves; each
  stage has its own fixed label.
- Arms: `corpus.py plan` pairs the native build without and with
  `--coverage=instrument` (compile dimension) and the two executables
  (execute dimension; the instrumented one writes its profiles to a
  per-fixture directory, through the arm's `env`). Both builds run once at
  plan time to record each fixture's `facts`: the artifact sizes and the
  map's planned counters. Ingest stays one arm. Verified-contract fixtures
  build with `--contract-mode=verified`; VM-only fixtures (vm-dispatch)
  build with `vm-native-compile` and run under `vm-run` (v2 joins after
  CV-463); the native-contention fixtures build `contention.c` with `cc`,
  plain and linked against the native runtime.
- Semantic validation before timing (CV-427, COV-PERF-015): `plan` runs
  every arm once and refuses the fixture unless it gives its expected exit
  code and stdout, and a coverage-on arm publishes exactly one profile that
  decodes against its map (the contention fixtures: the exact per-counter
  totals). Each timed run then rechecks the exit code and stdout digest.

## Budgets and the evaluator (CV-410)

- `budgets.json`: the SPEC 24 table frozen as gates: compile and execution
  p95 overhead (1.20), artifact size (geometric mean 1.30, every fixture
  1.75), counter memory (16 B per planned point + 8 MiB), merge and report
  absolutes, determinism; and the campaigns each stage needs (three
  `managed-ci-recorded`, one `reference-dedicated`).
- `evaluate.py --campaign a.json,b.json [--campaign ...] [--exception rec.json] [--template out.json]`:
  one host class at a time; refuses to pool another series (observed
  hardware), stage, toolchain revision, corpus or class. Per campaign:
  per-fixture values, equal-weight category geometric means (exact integer
  roots), the corpus value, ceiling failures. A gate passes only in every
  campaign (no compensation) and is `incomplete` while any applicable
  fixture of the frozen corpus is pending, missing, invalid or one-arm.
  Eligibility: `reference-dedicated` stands alone; `managed-ci-recorded`
  needs three campaigns and a DEC-087 exception record naming the gate,
  else `refused`; other stages are `ineligible`.
- The exception record (`sv0cov.perf-exception` 1.0) binds the exact
  bundle digests and repeats the campaigns' facts (host class, provider,
  runner label and image, observed hardware, every `unknown` descriptor
  field, the measured variance per gate); `--template` writes it with those
  filled in, and a person adds the accepted risk, the owner and the date.
  A record that disagrees with the campaigns, or is not accepted by a
  person, covers nothing.
- The root workflow `.github/workflows/perf-recorded.yml` runs one campaign
  per dispatch. Only Linux x86-64 can build the toolchain in CI today; the
  other classes wait for CV-409.

## Corpus (`corpus/`, `corpus.py`)

- `corpus/manifest.json` (corpus 1.1): 38 fixtures in the ten SPEC 24.3
  categories, each with source or generator identity, seed and parameters,
  tree digest, expected result, scale, backends, coverage modes, timed
  boundary, budgets, and status. Every fixture is `runnable-baseline` since
  CV-427 (vm-v2 is a backend that joins after CV-463, not a status).
  `revisions` records why each corpus version changed (1.1: the scale
  profiles' counts were inconsistent with their map, so merge rejected
  them). `corpus.py check` regenerates it and verifies the
  real-project snapshots; `write --heavy` also rebuilds the 250,000-point
  merge/report artifacts (about 3.5 minutes, 1.2 GB) and records their
  digests.
- `corpus/real/`: byte-for-byte copies of sv0c behavior cases and
  sv0-mathlib v0.2.0 at pinned commits (`REDISTRIBUTION.md`).
- `corpus.py plan --toolchain ROOT --work DIR --dimension compile|execute|ingest|merge|native-terminal-report|html-report`
  materializes fixtures (checking replay digests), builds what the
  dimension needs, validates it, and prints a harness plan. The scale
  dimensions time `sv0cov merge` and `sv0cov report --format term|html`
  (through `sv0cov_cmd.py`, stdout only); `plan` merges once and checks the
  evidence against the raw profiles decoded directly (complete, every
  profile accepted, the same total count), and each timed run must
  reproduce the plan-time stdout digest.
- `contention.c`: one to eight threads of a fixed LCG workload with a hit
  per step on counter 0 (shared) or counter t (disjoint); prints a sum
  `corpus.py` computes in closed form. On Linux it pins each thread and the
  plan's `facts.affinity` says `pinned`, elsewhere `advisory` (SPEC 24.3).
- Expected results were checked on 2026-09-25 with sv0c `d1a5100`: every
  runnable fixture gives its expected exit code and empty stdout on native
  and VM-v1 (`vm_exit` for the VM).
- `region-large` (1,000 functions of 20 statements) builds and runs since
  the native compiler's Vec-handle limit was lifted (checked 2026-11-08).
- `.github/workflows/perf-provisional.yml` runs the ingest campaign for the
  1,000,000 point/profile-pair fixture on the four managed-CI hosts weekly
  and on demand, as labelled provisional trend evidence.
