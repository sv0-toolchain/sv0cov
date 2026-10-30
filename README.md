<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# sv0cov

Source-based code coverage for the [sv0](https://github.com/sv0-toolchain)
language.

sv0cov measures execution against original `.sv0` source constructs, not
against generated C, host debug information, or VM instruction offsets. The
goal is one coverage truth across both sv0 execution paths: generated
C/native executables and `.sv0b` bytecode on `sv0vm`.

## Status

**F0, R0 and R0.1 complete; R1 in progress.** F0 (2026-10-08) froze the
protocols (canonical JSON, point identities, schemas, raw-profile and VM
codecs); R0 (2026-10-17) delivered the developer preview (the lifecycle
CLI, merge, terminal and native JSON reports, fixed thresholds, submodule and
compatibility policy); R0.1 (2026-10-24) added exclusions, contexts, HTML, contract and
entity coverage, scopes, changed-region checks, ratchets and exclusion caps.
R1 work so far (2026-10-29): LCOV and Cobertura export with commit manifests
and consumer conformance, native-report `check`, saturation policy, privacy,
HTML accessibility, native concurrency, process-lifecycle fork guards, the
recorded performance campaign, the orderly-flush-only proof and the
reliability closure. The slice-by-slice status is in the checklist
named below. Nothing is released.

The governing contract is the sv0cov specification
(`project-specs/sv0cov/SPEC.md`, version `0.1.73-draft`). Planning and the
slice backlog live in the `sv0-toolchain` meta-repository:
`task/sv0cov-coverage.Rmd` (hub) and `task/sv0cov-checklist.Rmd` (`CV-###`
slices).

The latest source audit against the SPEC's observed facts is
[`docs/audit/2026-09-24.md`](docs/audit/2026-09-24.md).

## Ownership

| Concern | Owner |
|---|---|
| Source syntax, semantics, bytecode contract | `sv0doc` |
| Coverage planning, source regions, C and VM instrumentation | `sv0c` |
| `.sv0b` execution and VM-side counters | `sv0vm` |
| Merge, indexed evidence, reports, policy, CLI | `sv0cov` (this repo) |
| Submodule pin and `./scripts/sv0 coverage` integration | `sv0-toolchain` |

## Layout

```text
src/sv0cov/   Python implementation (standard library only at runtime)
tests/        test suites
docs/         documentation
LICENSES/     complete license texts not held at the repository root
```

Further directories (`schemas/`, `registries/`, `runtime/`, `resources/`,
`scripts/`) are added by the slices that populate them.

## Licensing

Software is licensed under `MIT OR Apache-2.0`, and documentation under
`CC-BY-4.0`. See [`LICENSE`](LICENSE) for the content-class map.

Check licensing annotations with:

```bash
python3 -m unittest discover -s tests
```
