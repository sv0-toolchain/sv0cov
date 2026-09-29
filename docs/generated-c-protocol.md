<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Generated-C coverage protocol 1

This page describes the interface between the C that `sv0c` emits under
`--coverage=instrument` and the native coverage runtime. `sv0c` emits it as
of CV-113. The runtime `runtime/c/sv0cov_rt.c` (CV-114, CV-115) implements it. The
normative rules are SPEC §14.1-14.3, §16.4, and §23.4.

## What the generated C contains

After `#include "sv0_runtime.h"`, an instrumented translation unit carries:

```c
struct __sv0cov_fragment {
  const char *fragment_id;      /* the map fragment's 64-hex fragment_id */
  uint32_t slice_base;          /* its first program counter */
  uint32_t slice_length;        /* its counter count (may be 0) */
};
struct __sv0cov_module {
  uint32_t protocol_major;      /* 1 */
  const char *map_id;           /* the map's 64-hex map_id */
  uint32_t program_counter_count;
  const char *target;           /* the map's target name */
  const char *compiler_identity;/* the map's compiler identity */
  uint32_t slice_base;          /* the module's first program counter */
  uint32_t slice_length;        /* the module's counter count */
  uint32_t fragment_count;
  const struct __sv0cov_fragment *fragments;
};
void __sv0cov_start(const struct __sv0cov_module *const *modules, uint32_t module_count);
void __sv0cov_hit(const struct __sv0cov_module *module, uint32_t local_index);
```

It also carries the static descriptors, taken from the map:

- `__sv0cov_fragments[]`: one entry per map fragment, in map order;
- `__sv0cov_module`: the module record;
- `__sv0cov_modules[]`: the modules the program registers.

Two kinds of call use them:

- **Hits.** Every placed hit is `__sv0cov_hit(&__sv0cov_module, <i>u);`. Here
  `<i>` is local to the module, so the program counter is
  `slice_base + <i>`.
- **Registration.** The hosted `main` calls
  `__sv0cov_start(__sv0cov_modules, <n>u);` right after
  `sv0_runtime_init(argc, argv);` and before any user code. Registration
  therefore never depends on C constructor order.

## Runtime obligations

`__sv0cov_start` validates the registration before user code runs:

- every expected module registers exactly once, with protocol major 1;
- all modules name the same map ID and program counter count;
- within a module, the fragments are contiguous from its `slice_base` and
  cover exactly `slice_length` counters;
- the modules' slices are in bounds, do not overlap, and cover
  `0..program_counter_count` with no gaps.

A zero-counter program still registers its zero-length fragments. Its arena
then has zero elements, and no hit is ever called.

`__sv0cov_hit` translates `slice_base + local_index` with checked
arithmetic. It then increments the shared arena with the saturating relaxed
compare-and-exchange that SPEC §14.2 specifies.

## What `runtime/c/sv0cov_rt.c` does

`__sv0cov_start` runs four checks in order. On the first failure it prints
one diagnostic to stderr, `sv0cov: error[<code>]: <title>: <detail>`. The
detail names the variable or field at fault but never shows a transport
value.

| Step | Rule | Code |
|---|---|---|
| Transport | Only `SV0COV_PROFILE_DIR`, `SV0COV_RUN_ID`, `SV0COV_CONTEXT` and `SV0COV_REQUIRED` are allowed. No other `SV0COV_*` name, no duplicates. | COV2001 |
| | `SV0COV_PROFILE_DIR` must be set, absolute, and an existing directory. | COV2001 |
| | `SV0COV_RUN_ID` must be set, exactly 32 lowercase hex digits, and nonzero. | COV2001 |
| | `SV0COV_REQUIRED` is `0` or `1`, or absent (not required). Any other value is an error, and required mode applies (fail closed). | COV2001 |
| | `SV0COV_CONTEXT` is at most 256 bytes of strict UTF-8. Set but empty is distinct from absent. | COV2001 |
| Registration | The rules in "Runtime obligations" above. The target is nonempty, and the compiler identity is 1-255 printable non-space ASCII bytes. A second `__sv0cov_start` is also refused. | COV1015 |
| Arena | One `_Atomic uint64_t` per program counter, plus an atomic overflow bitmap of `ceil(count / 64)` words. | COV2011 on allocation failure |
| Profile ID | 16 bytes from `getentropy`, with no fallback. An all-zero result is refused. | COV2002 |

In required mode (`SV0COV_REQUIRED=1`), any failure exits the process with
status 1 before user code runs. Status 1 is the sv0 runtime's failure
status, the same one panics and contract failures use. Otherwise
collection stays off: hits are no-ops, and no complete profile can be
published. The same applies after a hit that names an unregistered module
or an index outside its slice, which generated code never produces.

`__sv0cov_hit` is the SPEC 14.2 saturating compare-and-exchange with
relaxed ordering. A counter that is already at `UINT64_MAX` stays there, and
its overflow bit is set.

### Flush and publication

`__sv0cov_start` registers an `atexit` handler once it succeeds. The
handler runs when `main` returns, on `exit()`, and on the sv0 runtime's
panic and contract-failure paths, which call `exit(1)`. Nothing is
published after `_exit`, a signal, or a crash. A killed run leaves no
profile and no temporary file.

The handler writes one raw profile 1.0 (SPEC §16.4) into
`SV0COV_PROFILE_DIR` as `<run_id>-<profile_id>.sv0profraw`, both IDs in
lowercase hex:

1. It streams the bytes into a mode-0600 `mkstemp` file named
   `.<name>.tmp-XXXXXX`, with a running CRC32C.
2. It fsyncs and closes that file.
3. It commits it under the final name with an atomic no-replace
   operation: `renamex_np(RENAME_EXCL)` on macOS, `renameat2(RENAME_NOREPLACE)`
   on Linux, and otherwise `link` followed by `unlink`.
4. It fsyncs the directory.

The profile's contents:

- **Backend:** the backend flag is `BACKEND_NATIVE`.
- **Context:** the context is written when `SV0COV_CONTEXT` was set, even
  if it was empty.
- **Counts:** only nonzero counts are written, as (index, count) pairs.
- **Overflow bitmap:** it marks exactly the written counts equal to
  `UINT64_MAX`, as the format requires.

The counters are read twice, once to size the profile and once to write
it. Each read takes one relaxed load per counter, in index order. If the
set of nonzero counters changes between the two passes, hits ran during
the flush, so nothing is published. The program should join its worker
threads before exiting.

| Failure at exit | Code |
|---|---|
| The temporary file cannot be created or written (for example, the directory is gone) | COV2010 |
| Hits ran during the flush, or a hit named an unregistered counter | COV2011 |
| A profile with the final name already exists (the existing file is left alone) | COV2112 |
| A forked child exits; it never publishes its parent's counters | COV2120 |

In required mode, each of these ends the process with `_exit(1)`. Outside
required mode, the diagnostic is printed and the exit status is left
unchanged.

A map with more than 4,194,304 counters (the standard raw-profile tier) is
refused at start with COV6001. The runtime has no configuration, and the
transport may not raise the tier.

`sv0 native-compile --coverage=instrument` compiles this file with
`-std=c11 -O2` and links it into the executable. The program C itself stays
`-std=gnu99`.

Two builds exist:

- **Production:** C11, no test hooks.
- **Test:** `-DSV0COV_RT_TESTING`. It adds inspection functions and three
  environment overrides:
  - `SV0COVRT_TEST_ENTROPY=fail|zero` forces an entropy failure or an
    all-zero profile ID;
  - `SV0COVRT_TEST_PROFILE_ID=<32 hex>` supplies a fixture profile ID;
  - `SV0COVRT_TEST_BACKEND=vm-v1|vm-v2` writes another backend flag.

  The last two exist only for the byte-parity tests.

`tests/test_native_runtime.py` drives the test build through
`runtime/c/tests/rt_driver.c`. It covers:

- counting, saturation, and contended increments across 8 threads;
- zero-counter programs and two-module programs;
- the transport and registration rejection matrices;
- entropy failure and all-zero profile IDs;
- profiles published on normal exit and on `exit(1)`, decoded by
  `sv0cov.formats.rawprofile`: counts, context, overflow bitmap, and the
  zero-counter case;
- nothing published after SIGKILL or `_exit`;
- name collisions, a vanished directory, and forked children;
- byte parity (CV-116, F0-G8). With fixture IDs, the C writer's output
  equals all five CV-024 golden profiles byte for byte. It also equals
  `sv0cov.formats.rawprofile.encode` for 40 seeded random native profiles,
  which vary the size, sparse and saturated counts, and absent, empty and
  multibyte contexts.

## The current `sv0c` shape

`sv0c` compiles a whole program, including every source of a project, into
one translation unit. That unit is therefore one module, holding every map
fragment. Its slice is the whole program (`slice_base` 0, `slice_length` =
`program_counter_count`), so a hit's local index equals its program counter.
Several separately compiled modules (COV-C-004, R1) would reuse the same
records, with one entry per module in `__sv0cov_modules`.

`sv0c/test/coverage/plan/run_emit_c.py` checks the emitted C against each
fixture's map. It links every program twice:

- **Against this runtime.** Under a valid transport, the program must behave
  exactly like the uninstrumented build and publish one profile with the
  stub's counts. With a malformed run ID in required mode, it must exit 1
  before any output.
- **Against a counting stub** (`stub_rt.c`). The counts must equal the
  fixtures' `expected-counts.json`.
