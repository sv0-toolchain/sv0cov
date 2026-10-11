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
- [Planning conventions](planning-conventions.md): how the planner assigns entities, regions, and counters.
- [Publication](publication.md): how outputs are written without ever replacing anything, and the primitive used per host.
- [Release policy](release-policy.md): release identity, versioning, attestations, checksums, SBOM, approval, publication, retention.
