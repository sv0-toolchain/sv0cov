<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Changelog

sv0cov has not been released. Product versions follow `MAJOR.MINOR.PATCH`
(SPEC 25.4.1, 25.4.2): major zero until every R1 gate passes, and the first
stable release is exactly `1.0.0`. Every release lists its public-contract
changes here with their impact (PATCH, MINOR or MAJOR). Distribution is only
through GitHub Release assets and the `sv0-toolchain` submodule pin; see
`docs/release-policy.md`.

## Unreleased (`0.0.0`)

The development tree. `sv0cov version --json` advertises only the `version`
command until the R0 gate review (CV-244); the other commands work but are
not yet part of the advertised contract.

### Formats and protocols (F0)

- Canonical JSON, point identity 1.0, the diagnostic registry (revision 2,
  adding `COV2130` "Test command failed"), and closed Draft 2020-12 schemas
  with generated structural validators for every artifact.
- Coverage map 1.0, raw profile 1.0 with CRC32C, VM binding 1.0 and COVR
  1.0, run IDs and run-set manifest 1.0, indexed evidence 1.0 and its
  semantic projection, native report 1.0, resolved configuration 1.0.
- Root compatibility policy 1.0, version manifest 1.0, doctor result 1.0,
  release manifest 1.0 and `SHA256SUMS`.

### Collection (R0)

- The generated-C coverage runtime: transport, arena, flush and publication,
  raw-profile tiers, concurrency and saturation, lifecycle at every exit
  path.
- Region, line, branch and contract derivation; counter expressions;
  fragment and program-map assembly; ownership of dependency sources.

### Commands (R0)

- `merge`, `report` (terminal and native JSON), `check`, `clean`, `run`
  (build, execute, collect, merge, report, check), and `doctor` in
  standalone mode (D001 to D008) and toolchain mode (D009 to D018, with the
  bundled smoke fixture).
- CLI framework: argument grammar, exit statuses, human and JSON Lines
  diagnostics, quiet and color; no-replace publication.

### Hardening (R0)

- Parser fuzzing with a regression corpus and resource limits; a security
  suite (no network, containment, injection, environment poisoning).
- Releases: a dry-run pipeline (`tools/release.py`) builds the sdist and
  wheel once from the commit, twice for byte identity, writes the release
  build-info resource, and produces `SHA256SUMS`, the release manifest, an
  SPDX 2.3 SBOM, evidence, and the other attachments without publishing.
