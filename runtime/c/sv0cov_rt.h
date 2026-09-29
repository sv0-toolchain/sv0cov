/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla */
/*
 * sv0cov native coverage runtime: generated-C protocol 1 (SPEC 14.1-14.3).
 *
 * sv0c's instrumented C declares these two records and two functions itself
 * (docs/generated-c-protocol.md); this header is the runtime's copy of the
 * same interface, and its layout must stay identical to what sv0c emits.
 *
 * The runtime is C11 (stdatomic) and needs no sv0 runtime support.
 */
#ifndef SV0COV_RT_H
#define SV0COV_RT_H

#include <stdint.h>

#define SV0COV_PROTOCOL_MAJOR 1u

struct __sv0cov_fragment {
  const char *fragment_id;     /* the map fragment's 64-hex fragment_id */
  uint32_t slice_base;         /* its first program counter */
  uint32_t slice_length;       /* its counter count (may be 0) */
};

struct __sv0cov_module {
  uint32_t protocol_major;     /* SV0COV_PROTOCOL_MAJOR */
  const char *map_id;          /* the map's 64-hex map_id */
  uint32_t program_counter_count;
  const char *target;          /* the map's target name */
  const char *compiler_identity;
  uint32_t slice_base;         /* the module's first program counter */
  uint32_t slice_length;       /* the module's counter count */
  uint32_t fragment_count;
  const struct __sv0cov_fragment *fragments;
};

/* Called by the generated hosted main after sv0_runtime_init and before user
   code. Reads the SV0COV_* transport, validates the registration, allocates
   the counter arena, and draws the profile ID. On any failure it prints one
   diagnostic; in required mode (SV0COV_REQUIRED=1) it then exits with status
   1, otherwise collection is disabled for this process and no complete
   profile can be published. */
void __sv0cov_start(const struct __sv0cov_module *const *modules, uint32_t module_count);

/* One execution of a planned point: saturating relaxed increment of program
   counter module->slice_base + local_index. A no-op when collection is not
   active. */
void __sv0cov_hit(const struct __sv0cov_module *module, uint32_t local_index);

/* Collection state. */
#define SV0COV_RT_STATE_OFF 0        /* __sv0cov_start not called */
#define SV0COV_RT_STATE_ACTIVE 1     /* counting; a complete profile is possible */
#define SV0COV_RT_STATE_INCOMPLETE 2 /* failed; no complete profile */

#ifdef SV0COV_RT_TESTING
/* Test-only inspection, compiled only with -DSV0COV_RT_TESTING. The testing
   build also reads SV0COVRT_TEST_ENTROPY=fail|zero to force an entropy
   failure or an all-zero profile ID, SV0COVRT_TEST_PROFILE_ID=<32 hex> to
   use a fixture profile ID, and SV0COVRT_TEST_BACKEND=vm-v1|vm-v2 to write
   another backend flag (CV-116 byte parity); never in a production build. */
int sv0cov_rt_test_state(void);
uint32_t sv0cov_rt_test_counter_count(void);
uint64_t sv0cov_rt_test_counter(uint32_t index);
void sv0cov_rt_test_set_counter(uint32_t index, uint64_t value);
int sv0cov_rt_test_overflow(uint32_t index);
int sv0cov_rt_test_required(void);
const uint8_t *sv0cov_rt_test_run_id(void);     /* 16 bytes */
const uint8_t *sv0cov_rt_test_profile_id(void); /* 16 bytes */
const char *sv0cov_rt_test_profile_dir(void);
/* -1 when absent, else the context length (its bytes via the pointer). */
int sv0cov_rt_test_context(const char **bytes);
#endif

#endif /* SV0COV_RT_H */
