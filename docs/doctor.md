<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# The doctor command

```text
sv0cov doctor [--json] [--quiet]
```

`doctor` checks the installed sv0cov product and reports the result as one
`sv0cov.doctor` 1.0 aggregate (SPEC 20.7). This build has the standalone
mode: probes D001 to D008. Toolchain mode (`--toolchain-root`, probes D009 to
D018) comes with CV-242 and is refused for now with `COV5001`, exit 7.

It reads no project configuration, no `sv0.toml`, no Git state and no
environment variable, and writes nothing that outlives it.

## Probes

| Probe | Checks | Fails with |
|---|---|---|
| D001 | The version manifest of the running build is constructed and validates. | (exit 8) |
| D002 | The diagnostic registry is canonical and self-consistent, and is the one the manifest names. | (exit 8) |
| D003 | Each of the 13 schemas is present, is a draft 2020-12 JSON object without duplicate keys, and has the exact bytes its generated validator was made from. | `COV5004` |
| D004 | Every module of the import package and every resource (registry, schemas, C runtime sources) is a regular file. | `COV5004` |
| D005 | The effective host is the manifest's and a supported one. | `COV5001` |
| D006 | The interpreter is CPython of a supported line, is the manifest's, and `sv0cov` is imported from the package whose files were checked. | `COV0016` for an unsupported interpreter, else `COV5004` |
| D007 | A private directory can be made with mode `0700`, written, read and emptied. | `COV6002` when not private, else `COV5004` |
| D008 | The C runtime sources have their exact bytes. | `COV5004` |

D003, D004, D005 and D006 need D001; D008 needs D004. A probe whose
prerequisite failed is `skipped`. D009 to D018 are `not_applicable`.

The counts in the facts are of fixed logical members, the same for a source
checkout and an installed wheel: 13 schemas, 75 layout members (59 modules,
the registry, 13 schemas, 2 runtime sources), 2 runtime sources. Adding a
module or a schema means adding it to `sv0cov.probes`; a test fails until
then.

## Output

- `--json`: the canonical aggregate on stdout and nothing else, validated
  before the first byte. `--quiet` does not remove it.
- Otherwise: one line per probe and a summary line, which `--quiet` removes.
- Every failed probe's diagnostic goes to stderr in the chosen format, with
  the fact `probe_id`, exactly as the aggregate lists it.

## Exit status

| Exit | Meaning |
|---:|---|
| 0 | Every applicable probe passed. |
| 2 | Invalid usage. |
| 7 | A probe failed or was skipped, or toolchain mode was asked for. |
| 8 | D001 or D002 cannot pass, the private directory cannot be removed, or no valid aggregate can be built. No JSON is written. |

A passing doctor proves only what it records. It is not toolchain
conformance, and it does not authenticate the installed bytes.
