<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Fuzzing and resource limits

`tools/fuzz.py` fuzzes every artifact reader of sv0cov, the merge engine
and the counter-expression evaluator (SPEC 28.4). It is deterministic for a
given seed and uses only the standard library, so it needs no fuzzing
dependency and runs anywhere the tests run.

```sh
python3 tools/fuzz.py list                                   # the harnesses
python3 tools/fuzz.py run --seconds 60 --seed 1 --crash-dir findings
python3 tools/fuzz.py run --harness map --iterations 20000
python3 tools/fuzz.py replay                                 # tests/fixtures/fuzz
```

## Harnesses

| Harness | Reads | Seeds |
|---|---|---|
| `rawprofile` | raw profiles, unbound and bound to maps of several sizes | the raw-profile goldens |
| `json` | canonical JSON; an accepted document must re-encode to the same bytes | reports, an indexed profile, the registry |
| `map` | coverage maps | the expected map of every semantic fixture |
| `indexed` | indexed profiles, through the cross-validating reader | valid evidence of every semantic fixture and of a multi-run input, and the structure fixtures |
| `report` | native reports, through the cross-validating reader | valid reports of that evidence, with and without thresholds, and the structure fixtures |
| `merge` | the merge engine over a map and mutated profiles; a publishable result must read back | the semantic fixtures' maps and profiles |
| `expr` | counter expressions; a result lies in `[0, UINT64_MAX]` and equals the plain sum when nothing saturates | the expression fixtures and random cases |
| `runset`, `manifest`, `doctor`, `registry`, `compatibility`, `release` | the run-set manifest, version manifest, doctor result, diagnostic registry, compatibility policy and release manifest | one valid artifact each |

Inputs are made by byte mutations (bit flips, extreme 32- and 64-bit words,
insertions, deletions, truncation, splices) and, for JSON artifacts, by
mutating the decoded tree (dropped, duplicated, retyped and extreme
values). After a mutation the fuzzer usually recomputes the raw profile's
CRC32C or the artifact's self-digest (`map_id`, `manifest_sha256`,
`doctor_sha256`, the projection digest, ...), so the input gets past that
check and reaches the rest of the validation.

## Rules

An input breaks a rule when:

1. the reader raises anything but its own documented error, or a coded
   error whose code is not in the diagnostic registry;
2. one input takes more than 5 seconds;
3. on a sampled input, the peak Python allocation exceeds 64 times the input
   size plus 8 MiB, which means a declared size was trusted before it was
   checked (COV-FMT-022).

On Linux the fuzzer also caps its address space at 2 GiB, so an unbounded
allocation becomes a finding instead of the process being killed.

A finding is minimized and written to
`<crash-dir>/<harness>/<sha256-prefix>.bin`. Copied into
`tests/fixtures/fuzz/<harness>/` it becomes a regression fixture:
`tests/test_fuzz.py` replays every one on every run.

## Where it runs

- **Every test run:** the regression corpus, each harness's seeds, and a
  short fixed-seed run of every harness (`tests/test_fuzz.py`).
- **Every push (CI job `fuzz`):** the regression corpus, then every harness
  for 60 seconds with a seed taken from the CI run. A finding fails the job
  and its minimized input is uploaded as the `fuzz-findings` artifact.

## Findings so far

| Harness | Finding | Fix |
|---|---|---|
| `map` | A 5 KB map declaring `program_counter_count = 2147483646` made the validator build a list of that size; the process was killed. | The counter check compares sizes and bounds instead of building the sequence. |
| `expr` | A point ID holding a lone surrogate escaped the expression checker as `UnicodeEncodeError`. | Refused with `COV1010`. |
| (sweep) | The same pattern in the report reader: an exclusion's branch or clause span with an `end_line` near four billion was enumerated line by line. | Spans are compared with the line records instead. |
