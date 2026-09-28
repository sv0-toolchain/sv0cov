<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Generated-C coverage protocol 1

This page describes the interface between the C that `sv0c` emits under
`--coverage=instrument` and the native coverage runtime. `sv0c` emits it as
of CV-113. The runtime (`runtime/c`, CV-114) implements it. The normative
rules are SPEC §14.1 and §14.2.

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

## The current `sv0c` shape

`sv0c` compiles a whole program, including every source of a project, into
one translation unit. That unit is therefore one module, holding every map
fragment. Its slice is the whole program (`slice_base` 0, `slice_length` =
`program_counter_count`), so a hit's local index equals its program counter.
Several separately compiled modules (COV-C-004, R1) would reuse the same
records, with one entry per module in `__sv0cov_modules`.

`sv0c/test/coverage/plan/run_emit_c.py` checks the emitted C against each
fixture's map. It also links the C against a test-only stub of this
interface (`stub_rt.c`) and checks the counts against the fixtures'
`expected-counts.json`.
