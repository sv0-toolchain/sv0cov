/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla */
/*
 * sv0cov native coverage runtime: arena and transport (CV-114).
 *
 * __sv0cov_start runs once, from the generated hosted main before user code:
 *
 *   1. transport (SPEC 14.3): exactly the four SV0COV_* names are
 *      recognized; any other name with that prefix, a duplicate, a
 *      malformed value, or a missing SV0COV_PROFILE_DIR / SV0COV_RUN_ID is
 *      COV2001. SV0COV_RUN_ID is exact lowercase 32-hex and nonzero;
 *      SV0COV_REQUIRED is 0 or 1 (a malformed value counts as required, so
 *      it fails closed); SV0COV_CONTEXT is at most 256 bytes of valid
 *      UTF-8, and set-but-empty is distinct from absent; SV0COV_PROFILE_DIR
 *      is an absolute path to an existing directory.
 *   2. registration (SPEC 14.1): every module speaks protocol 1 and names
 *      the same 64-hex map ID, counter count, and compiler identity; its
 *      fragments are distinct, 64-hex, and contiguous across its slice;
 *      the module slices tile 0..count with no gap or overlap. Else COV1015.
 *   3. the arena: one _Atomic uint64_t per program counter plus an atomic
 *      overflow bitmap of ceil(count / 64) words.
 *   4. the profile ID (SPEC 16.4): 16 bytes from getentropy, never all zero
 *      and never a predictable fallback. Else COV2002.
 *
 * A failure prints one diagnostic that names the variable or field, never
 * a transport value. In required mode the process then exits with status 1
 * (the sv0 runtime's failure status) before user code; otherwise collection
 * stays off and no complete profile can be published (CV-115 flushes).
 *
 * __sv0cov_hit is the SPEC 14.2 saturating relaxed compare-and-exchange: a
 * counter at UINT64_MAX stays there and sets its overflow bit.
 */
#if !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1 /* getentropy, environ (glibc) */
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "sv0cov_rt.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

#define SV0COV_CONTEXT_MAX 256u

static struct {
  atomic_int state;
  int required;
  uint32_t count;
  _Atomic uint64_t *counters;
  _Atomic uint64_t *overflow;
  const struct __sv0cov_module *const *modules;
  uint32_t module_count;
  uint8_t run_id[16];
  uint8_t profile_id[16];
  char *profile_dir;
  char *context;
  int context_len; /* -1 = absent */
} rt = {.context_len = -1};

/* ── diagnostics ───────────────────────────────────────────────────────── */

static void rt_diag(const char *code, const char *title, const char *detail) {
  fprintf(stderr, "sv0cov: error[%s]: %s: %s\n", code, title, detail);
}

/* Record a failure: required mode exits now, before user code; otherwise
   collection stays off for the rest of the process. */
static void rt_fail(const char *code, const char *title, const char *detail) {
  rt_diag(code, title, detail);
  atomic_store_explicit(&rt.state, SV0COV_RT_STATE_INCOMPLETE, memory_order_relaxed);
  if (rt.required) {
    fprintf(stderr, "sv0cov: coverage is required (SV0COV_REQUIRED=1); stopping before the program runs\n");
    exit(1);
  }
}

/* ── transport ─────────────────────────────────────────────────────────── */

static int rt_hexval(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

/* Exact lowercase 64-hex (map, fragment IDs). */
static int rt_is_hex64(const char *s) {
  if (s == NULL)
    return 0;
  size_t i = 0;
  for (; s[i] != '\0'; i++)
    if (i >= 64 || rt_hexval(s[i]) < 0)
      return 0;
  return i == 64;
}

/* Exact lowercase 32-hex, nonzero, into 16 bytes. */
static int rt_decode_run_id(const char *s, uint8_t out[16]) {
  if (strlen(s) != 32)
    return 0;
  int nonzero = 0;
  for (int i = 0; i < 16; i++) {
    int hi = rt_hexval(s[2 * i]);
    int lo = rt_hexval(s[2 * i + 1]);
    if (hi < 0 || lo < 0)
      return 0;
    out[i] = (uint8_t)(hi * 16 + lo);
    nonzero |= out[i];
  }
  return nonzero != 0;
}

/* Strict UTF-8: no overlong forms, no surrogates, nothing above U+10FFFF. */
static int rt_valid_utf8(const unsigned char *s, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned c = s[i];
    size_t len;
    unsigned min;
    unsigned cp;
    if (c < 0x80) {
      i++;
      continue;
    } else if (c >= 0xc2 && c <= 0xdf) {
      len = 2, min = 0x80, cp = c & 0x1f;
    } else if (c >= 0xe0 && c <= 0xef) {
      len = 3, min = 0x800, cp = c & 0x0f;
    } else if (c >= 0xf0 && c <= 0xf4) {
      len = 4, min = 0x10000, cp = c & 0x07;
    } else {
      return 0;
    }
    if (n - i < len)
      return 0;
    for (size_t k = 1; k < len; k++) {
      if ((s[i + k] & 0xc0) != 0x80)
        return 0;
      cp = (cp << 6) | (s[i + k] & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
      return 0;
    i += len;
  }
  return 1;
}

enum { T_DIR, T_RUN, T_CONTEXT, T_REQUIRED, T_NAMES };
static const char *const rt_names[T_NAMES] = {
    "SV0COV_PROFILE_DIR", "SV0COV_RUN_ID", "SV0COV_CONTEXT", "SV0COV_REQUIRED"};

/* Read the transport from environ. Returns 0 on success, else fills `why`. */
static int rt_read_transport(char *why, size_t why_len) {
  const char *value[T_NAMES] = {NULL, NULL, NULL, NULL};
  const char *bad = NULL;
  const char *bad_reason = NULL;
  for (char **e = environ; e != NULL && *e != NULL; e++) {
    if (strncmp(*e, "SV0COV_", 7) != 0)
      continue;
    const char *eq = strchr(*e, '=');
    size_t nlen = eq ? (size_t)(eq - *e) : strlen(*e);
    int known = -1;
    for (int k = 0; k < T_NAMES; k++)
      if (strlen(rt_names[k]) == nlen && strncmp(*e, rt_names[k], nlen) == 0)
        known = k;
    if (known < 0 || eq == NULL) {
      if (bad == NULL)
        bad = "", bad_reason = "an unknown SV0COV_* variable is set (only SV0COV_PROFILE_DIR, "
                               "SV0COV_RUN_ID, SV0COV_CONTEXT and SV0COV_REQUIRED are recognized)";
      continue;
    }
    if (value[known] != NULL) {
      if (bad == NULL)
        bad = rt_names[known], bad_reason = "is set more than once";
      continue;
    }
    value[known] = eq + 1;
  }

  /* Required mode first, so every later failure knows whether to stop. */
  if (value[T_REQUIRED] != NULL) {
    if (strcmp(value[T_REQUIRED], "1") == 0) {
      rt.required = 1;
    } else if (strcmp(value[T_REQUIRED], "0") != 0) {
      rt.required = 1; /* fail closed */
      if (bad == NULL)
        bad = "SV0COV_REQUIRED", bad_reason = "is not 0 or 1";
    }
  }
  if (bad != NULL) {
    snprintf(why, why_len, "%s%s%s", bad, *bad ? " " : "", bad_reason);
    return -1;
  }

  const char *dir = value[T_DIR];
  if (dir == NULL) {
    snprintf(why, why_len, "SV0COV_PROFILE_DIR is not set");
    return -1;
  }
  struct stat st;
  if (dir[0] != '/' || stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
    snprintf(why, why_len, "SV0COV_PROFILE_DIR is not an absolute path to an existing directory");
    return -1;
  }
  if (value[T_RUN] == NULL) {
    snprintf(why, why_len, "SV0COV_RUN_ID is not set");
    return -1;
  }
  if (!rt_decode_run_id(value[T_RUN], rt.run_id)) {
    snprintf(why, why_len, "SV0COV_RUN_ID is not 32 lowercase hex digits naming a nonzero run");
    return -1;
  }
  const char *ctx = value[T_CONTEXT];
  if (ctx != NULL) {
    size_t n = strlen(ctx);
    if (n > SV0COV_CONTEXT_MAX || !rt_valid_utf8((const unsigned char *)ctx, n)) {
      snprintf(why, why_len, "SV0COV_CONTEXT is longer than 256 bytes or not valid UTF-8");
      return -1;
    }
  }

  rt.profile_dir = strdup(dir);
  if (ctx != NULL)
    rt.context = strdup(ctx);
  if (rt.profile_dir == NULL || (ctx != NULL && rt.context == NULL)) {
    snprintf(why, why_len, "out of memory copying the transport");
    return -1;
  }
  rt.context_len = ctx != NULL ? (int)strlen(ctx) : -1;
  return 0;
}

/* ── registration ──────────────────────────────────────────────────────── */

/* 1..255 printable ASCII, no whitespace (SPEC 16.3 compiler identity). */
static int rt_is_identity(const char *s) {
  if (s == NULL)
    return 0;
  size_t n = strlen(s);
  if (n == 0 || n > 255)
    return 0;
  for (size_t i = 0; i < n; i++)
    if ((unsigned char)s[i] < 0x21 || (unsigned char)s[i] > 0x7e)
      return 0;
  return 1;
}

/* Returns 0 when the registration is valid, else fills `why`. */
static int rt_check_registration(const struct __sv0cov_module *const *modules, uint32_t module_count,
                                 char *why, size_t why_len) {
  if (modules == NULL || module_count == 0) {
    snprintf(why, why_len, "no module registered");
    return -1;
  }
  const struct __sv0cov_module *first = modules[0];
  if (first == NULL) {
    snprintf(why, why_len, "module 0 is missing");
    return -1;
  }
  uint64_t total = first->program_counter_count;
  for (uint32_t k = 0; k < module_count; k++) {
    const struct __sv0cov_module *m = modules[k];
    if (m == NULL) {
      snprintf(why, why_len, "module %u is missing", k);
      return -1;
    }
    if (m->protocol_major != SV0COV_PROTOCOL_MAJOR) {
      snprintf(why, why_len, "module %u speaks generated-C protocol %u, not %u", k, m->protocol_major,
               SV0COV_PROTOCOL_MAJOR);
      return -1;
    }
    if (!rt_is_hex64(m->map_id) || strcmp(m->map_id, first->map_id) != 0 ||
        m->program_counter_count != first->program_counter_count) {
      snprintf(why, why_len, "module %u names a different or malformed map", k);
      return -1;
    }
    if (m->target == NULL || m->target[0] == '\0' || strcmp(m->target, first->target) != 0 ||
        !rt_is_identity(m->compiler_identity) ||
        strcmp(m->compiler_identity, first->compiler_identity) != 0) {
      snprintf(why, why_len, "module %u has a missing or conflicting target or compiler identity", k);
      return -1;
    }
    if (m->fragment_count == 0 || m->fragments == NULL) {
      snprintf(why, why_len, "module %u registers no fragment", k);
      return -1;
    }
    uint64_t next = m->slice_base;
    for (uint32_t f = 0; f < m->fragment_count; f++) {
      const struct __sv0cov_fragment *fr = &m->fragments[f];
      if (!rt_is_hex64(fr->fragment_id)) {
        snprintf(why, why_len, "module %u fragment %u has a malformed fragment ID", k, f);
        return -1;
      }
      if (fr->slice_base != next) {
        snprintf(why, why_len, "module %u fragment %u overlaps or leaves a gap", k, f);
        return -1;
      }
      next += fr->slice_length;
    }
    if (next != (uint64_t)m->slice_base + m->slice_length) {
      snprintf(why, why_len, "module %u fragments do not cover its slice", k);
      return -1;
    }
    if ((uint64_t)m->slice_base + m->slice_length > total) {
      snprintf(why, why_len, "module %u slice lies outside the program's counters", k);
      return -1;
    }
  }
  /* Every fragment exactly once, program-wide. */
  for (uint32_t a = 0; a < module_count; a++)
    for (uint32_t f = 0; f < modules[a]->fragment_count; f++)
      for (uint32_t b = a; b < module_count; b++)
        for (uint32_t g = (b == a ? f + 1 : 0); g < modules[b]->fragment_count; g++)
          if (strcmp(modules[a]->fragments[f].fragment_id, modules[b]->fragments[g].fragment_id) == 0) {
            snprintf(why, why_len, "a fragment is registered more than once");
            return -1;
          }
  /* The module slices tile 0..total: each lies inside it (checked above),
     no two nonempty slices overlap, and their lengths add up to it. */
  uint64_t sum = 0;
  for (uint32_t a = 0; a < module_count; a++) {
    const struct __sv0cov_module *x = modules[a];
    sum += x->slice_length;
    for (uint32_t b = a + 1; b < module_count; b++) {
      const struct __sv0cov_module *y = modules[b];
      if (x == y) {
        snprintf(why, why_len, "a module is registered more than once");
        return -1;
      }
      if (x->slice_length > 0 && y->slice_length > 0 &&
          (uint64_t)x->slice_base < (uint64_t)y->slice_base + y->slice_length &&
          (uint64_t)y->slice_base < (uint64_t)x->slice_base + x->slice_length) {
        snprintf(why, why_len, "modules %u and %u have overlapping slices", a, b);
        return -1;
      }
    }
  }
  if (sum != total) {
    snprintf(why, why_len, "the module slices do not cover the program's counters exactly once");
    return -1;
  }
  return 0;
}

/* ── entropy ───────────────────────────────────────────────────────────── */

static int rt_entropy(uint8_t out[16]) {
#ifdef SV0COV_RT_TESTING
  const char *force = getenv("SV0COVRT_TEST_ENTROPY");
  if (force != NULL && strcmp(force, "fail") == 0)
    return -1;
  if (force != NULL && strcmp(force, "zero") == 0) {
    memset(out, 0, 16);
    return 0;
  }
#endif
  return getentropy(out, 16);
}

/* ── entry points ──────────────────────────────────────────────────────── */

void __sv0cov_start(const struct __sv0cov_module *const *modules, uint32_t module_count) {
  char why[256];
  if (atomic_load_explicit(&rt.state, memory_order_relaxed) != SV0COV_RT_STATE_OFF) {
    rt_fail("COV1015", "invalid counter or fragment binding", "coverage registration ran more than once");
    return;
  }
  if (rt_read_transport(why, sizeof why) != 0) {
    rt_fail("COV2001", "invalid runtime transport", why);
    return;
  }
  if (rt_check_registration(modules, module_count, why, sizeof why) != 0) {
    rt_fail("COV1015", "invalid counter or fragment binding", why);
    return;
  }
  uint32_t n = modules[0]->program_counter_count;
  size_t words = ((size_t)n + 63) / 64;
  rt.counters = calloc(n ? n : 1, sizeof(_Atomic uint64_t));
  rt.overflow = calloc(words ? words : 1, sizeof(_Atomic uint64_t));
  if (rt.counters == NULL || rt.overflow == NULL) {
    rt_fail("COV2011", "raw profile incomplete", "out of memory allocating the counter arena");
    return;
  }
  if (rt_entropy(rt.profile_id) != 0) {
    rt_fail("COV2002", "runtime entropy unavailable", "the operating system's secure random source failed");
    return;
  }
  int nonzero = 0;
  for (int i = 0; i < 16; i++)
    nonzero |= rt.profile_id[i];
  if (!nonzero) {
    rt_fail("COV2002", "runtime entropy unavailable", "the secure random source returned an all-zero profile ID");
    return;
  }
  rt.count = n;
  rt.modules = modules;
  rt.module_count = module_count;
  atomic_store_explicit(&rt.state, SV0COV_RT_STATE_ACTIVE, memory_order_release);
}

void __sv0cov_hit(const struct __sv0cov_module *module, uint32_t local_index) {
  if (atomic_load_explicit(&rt.state, memory_order_relaxed) != SV0COV_RT_STATE_ACTIVE)
    return;
  int registered = 0;
  for (uint32_t k = 0; k < rt.module_count; k++)
    if (rt.modules[k] == module)
      registered = 1;
  if (!registered || local_index >= module->slice_length) {
    /* Generated code never does this; if it happens the counts are suspect. */
    atomic_store_explicit(&rt.state, SV0COV_RT_STATE_INCOMPLETE, memory_order_relaxed);
    return;
  }
  uint64_t i = (uint64_t)module->slice_base + local_index;
  _Atomic uint64_t *c = &rt.counters[i];
  uint64_t old = atomic_load_explicit(c, memory_order_relaxed);
  for (;;) {
    if (old == UINT64_MAX) {
      atomic_fetch_or_explicit(&rt.overflow[i / 64], (uint64_t)1 << (i % 64), memory_order_relaxed);
      return;
    }
    if (atomic_compare_exchange_weak_explicit(c, &old, old + 1, memory_order_relaxed,
                                              memory_order_relaxed))
      return;
  }
}

#ifdef SV0COV_RT_TESTING
int sv0cov_rt_test_state(void) { return atomic_load(&rt.state); }
uint32_t sv0cov_rt_test_counter_count(void) { return rt.count; }
uint64_t sv0cov_rt_test_counter(uint32_t index) { return atomic_load(&rt.counters[index]); }
void sv0cov_rt_test_set_counter(uint32_t index, uint64_t value) { atomic_store(&rt.counters[index], value); }
int sv0cov_rt_test_overflow(uint32_t index) {
  return (int)((atomic_load(&rt.overflow[index / 64]) >> (index % 64)) & 1u);
}
int sv0cov_rt_test_required(void) { return rt.required; }
const uint8_t *sv0cov_rt_test_run_id(void) { return rt.run_id; }
const uint8_t *sv0cov_rt_test_profile_id(void) { return rt.profile_id; }
const char *sv0cov_rt_test_profile_dir(void) { return rt.profile_dir; }
int sv0cov_rt_test_context(const char **bytes) {
  *bytes = rt.context;
  return rt.context_len;
}
#endif
