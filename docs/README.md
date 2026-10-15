<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# sv0cov documentation

Documentation is licensed under `CC-BY-4.0`. Pages are added as the
implementation slices land. The normative contract remains the sv0cov
specification (`project-specs/sv0cov/SPEC.md`).

- [Command line](cli.md): argument grammar, order of checks, exit codes, diagnostics, `--quiet` and `--color`.
- [Configuration](configuration.md): the `[tool.sv0cov]` table, precedence, what fails, and the resolved record.
- [Generated-C coverage protocol 1](generated-c-protocol.md): what instrumented C contains and what the native runtime must validate.
- [Indexed evidence 1.0](indexed-evidence.md): the merge result's two closed schemas, what is validated so far, and the structure fixtures.
- [Merge](merge.md): how inputs are classified, copies and collisions, run selection, and what the engine returns.
- [Native report 1.0](native-report.md): the report and resolved-configuration schemas, how a report is produced and counted, and what the reader re-derives.
- [Terminal report](terminal-report.md): the plain-text view of a native report, its sections, its escaping and color rules, and its goldens.
- [Run](run.md): what `sv0cov run` builds, how the test command is started, its environment and run directory.
- [Report](report.md): formats, the destination matrix, and the exit statuses of `sv0cov report`.
- [Check](check.md): what `sv0cov check` evaluates, its exit statuses, and its output.
- [Clean](clean.md): what `sv0cov clean` recognizes as its own and how it refuses everything else.
- [Doctor](doctor.md): the standalone probes D001 to D008, their facts, and the exit statuses.
- [Planning conventions](planning-conventions.md): how the planner assigns entities, regions, and counters.
- [Publication](publication.md): how outputs are written without ever replacing anything, and the primitive used per host.
- [Release policy](release-policy.md): release identity, versioning, attestations, checksums, SBOM, approval, publication, retention.
