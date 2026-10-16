<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# The doctor command

```text
sv0cov doctor [--toolchain-root <path>] [--json] [--quiet]
```

`doctor` checks the installed sv0cov product and reports the result as one
`sv0cov.doctor` 1.0 aggregate (SPEC 20.7). Without `--toolchain-root` it runs
the standalone probes D001 to D008. With it, it also checks the sv0-toolchain
checkout at `<path>` (probes D009 to D018); `./scripts/sv0 coverage doctor`
passes the checkout's own root and refuses a caller's. `<path>` is resolved
from the working directory, must be an existing directory that is not a
symlink (otherwise `COV0001`, exit 2), and is never written into the result.

It reads no project configuration, no `sv0.toml` and no environment variable,
and writes nothing that outlives it. Toolchain mode reads Git state of the
checkout (with no `GIT_*` variable) and runs the checkout's own driver.

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
prerequisite failed or was skipped is `skipped`. In standalone mode D009 to
D018 are `not_applicable`.

The counts in the facts are of fixed logical members, the same for a source
checkout and an installed wheel: 13 schemas, 78 layout members (60 modules,
the registry, 13 schemas, 2 runtime sources, the smoke fixture and its
oracle), 2 runtime sources. Adding a
module or a schema means adding it to `sv0cov.probes`; a test fails until
then.

## Toolchain probes

| Probe | Checks | Needs | Fails with |
|---|---|---|---|
| D009 | `compatibility/sv0cov.json` is a regular file reached without a symlink, at most 64 KiB, and a valid policy. | | `COV6002` for a symlink, else `COV5002` |
| D010 | `.gitmodules` has exactly the `sv0cov` entry (path, SSH URL, nothing else, no alias); the staged gitlink is the policy's `expected_revision`; the submodule is checked out at exactly that commit with no tracked or untracked change. | D009 | `COV5002` |
| D011 | The running build's registry, the policy's one allowed registry, and the checked-out submodule's registry are the same revision and digest. | D002, D009, D010 | `COV5002`; `COV8002` for an unreadable registry |
| D012 | The policy and this build's capability manifest agree (SPEC 20.6.2; the same comparison as the root preflight). | D001, D005, D006, D009, D010, D011 | `COV5002` |
| D013 | The smoke fixture has the oracle's digest, and the checkout's `scripts/sv0 native-compile --coverage=map` makes a valid map of it. | D003, D004, D007, D010, D012 | `COV1004`, `COV1020`, or the map's own code |
| D014 | An instrumented generated-C build has the same map, runs to exit 0, publishes one raw profile, and merges into complete evidence whose counts and line states are the oracle's. | D007, D008, D013 | `COV1020`, `COV1013`, `COV2130`, `COV2010`, a merge code, or `COV5004` for the oracle |
| D015 | The same through `vm-native-compile` and `vm-run` (VM-v1). | D007, D013 | as D014 |
| D016 | VM-v2 collection: `not_applicable` while `vm-v2` is unadvertised (SPEC 15.6). | D007, D013 | |
| D017 | Every backend gave the same semantic projection. | D014, D015, D016 | `COV5004` |
| D018 | Both profiles merge into one native report that reads back and passes a fixed policy (100 % function, region, line and branch). | D014, D015, D016, D017 | the failed assertion's code |

The fixture is `resources/doctor/doctor-r1-smoke.sv0`; its oracle
`doctor-r1-smoke.oracle.json` lists the source digest and each point's count
and each line's state for one run, checked by hand. The fixture is copied
into the private directory and built and run there, with the caller's
environment less every `SV0COV_*` name. Each child has 60 s and 1 MiB of
output, the whole doctor 300 s and 64 MiB of temporary storage (`COV6001`
past a bound). Children are only `<root>/scripts/sv0` and the programs it
built; nothing is looked up on `PATH`.

Facts that are digests come from this run: `map_id` and the semantic
projection name the compiler revision, so they change with sv0c, not from
run to run. D018's `native_report_sha256` is the digest of the report's
transport-free projection: the report with each input's artifact digest,
name, profile ID and run ID, and the provenance's indexed-input digest and
run IDs, left out (planning-hub decision D-12). A fresh raw profile has a
random profile ID, so the report itself differs on every run, while the
doctor result must not.

The `toolchain` record gives the root's and the submodule's `HEAD` and
whether each worktree is clean, nothing else.

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
| 2 | Invalid usage, including a `--toolchain-root` that is not an existing, non-symlink directory. |
| 7 | A probe failed or was skipped. |
| 8 | D001 or D002 cannot pass, the private directory cannot be removed, or no valid aggregate can be built. No JSON is written. |

A passing doctor proves only what it records. It is not toolchain
conformance, and it does not authenticate the installed bytes.
