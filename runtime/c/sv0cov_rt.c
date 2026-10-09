/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla */
/*
 * sv0cov native coverage runtime: arena, transport, flush and publication
 * (CV-114, CV-115).
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
 *      the module slices tile 0..count with no gap or overlap, and an
 *      empty fragment sits at a positive slice's base or at count. Every
 *      module is checked whatever its position in the aggregator. Else
 *      COV1015.
 *   3. the arena: one _Atomic uint64_t per program counter plus an atomic
 *      overflow bitmap of ceil(count / 64) words.
 *   4. the profile ID (SPEC 16.4): 16 bytes from getentropy, never all zero
 *      and never a predictable fallback. Else COV2002.
 *
 * The map must fit the standard raw-profile tier (4,194,304 counters), else
 * COV6001: a runtime has no configuration, and the transport may not set a
 * tier.
 *
 * A failure prints one diagnostic that names the variable or field, never
 * a transport value. In required mode the process then exits with status 1
 * (the sv0 runtime's failure status) before user code; otherwise collection
 * stays off and no complete profile can be published.
 *
 * Flush (SPEC 16.4, 23.4): an atexit handler, so it runs on return from
 * main, exit(), and the sv0 runtime's panic and contract-failure paths
 * (both exit(1)); _exit, signals and crashes publish nothing. It writes
 * <run_id>-<profile_id>.sv0profraw into SV0COV_PROFILE_DIR: a mode-0600
 * mkstemp temporary (.<name>.tmp-XXXXXX) is streamed with a running CRC32C,
 * fsynced, closed, and committed with an atomic no-replace rename
 * (renamex_np RENAME_EXCL / renameat2 RENAME_NOREPLACE, else link+unlink);
 * the directory is then fsynced. Counters are read with one index-ordered
 * relaxed load each, in two passes (size, then write); a nonzero set that
 * changes between them means hits ran during the flush, and the profile is
 * withheld as incomplete. The overflow bitmap marks exactly the written
 * counts equal to UINT64_MAX. A process image forked from the registering
 * one never publishes the inherited counters. When the profile cannot be
 * published (COV2010, COV2011, COV2112, COV2120) required mode ends the
 * process with status 1.
 *
 * __sv0cov_hit is the SPEC 14.2 saturating relaxed compare-and-exchange: a
 * counter at UINT64_MAX stays there and sets its overflow bit.
 */
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1 /* getentropy, environ, renameat2 (glibc) */
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "sv0cov_rt.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

#define SV0COV_CONTEXT_MAX 256u
#define SV0COV_TIER_MAX_COUNTERS 4194304u /* standard tier (SPEC 16.4) */

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
  uint8_t map_id[32];
  pid_t pid;       /* the process image that registered */
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
  /* A zero-length fragment owns no counter and sits at the base of a
     positive slice or at the total count (SPEC 16.3.3; CV-206). */
  for (uint32_t a = 0; a < module_count; a++)
    for (uint32_t f = 0; f < modules[a]->fragment_count; f++) {
      const struct __sv0cov_fragment *z = &modules[a]->fragments[f];
      if (z->slice_length != 0 || z->slice_base == total)
        continue;
      int placed = 0;
      for (uint32_t b = 0; b < module_count && !placed; b++)
        for (uint32_t g = 0; g < modules[b]->fragment_count; g++)
          if (modules[b]->fragments[g].slice_length > 0 && modules[b]->fragments[g].slice_base == z->slice_base) {
            placed = 1;
            break;
          }
      if (!placed) {
        snprintf(why, why_len, "module %u fragment %u is empty but not at a slice boundary", a, f);
        return -1;
      }
    }
  return 0;
}

/* ── entropy ───────────────────────────────────────────────────────────── */

static int rt_decode_run_id(const char *s, uint8_t out[16]);

static int rt_entropy(uint8_t out[16]) {
#ifdef SV0COV_RT_TESTING
  /* CV-116 byte parity: a fixture-supplied profile ID. */
  const char *fixed = getenv("SV0COVRT_TEST_PROFILE_ID");
  if (fixed != NULL)
    return rt_decode_run_id(fixed, out) ? 0 : -1;
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

/* ── flush and publication ─────────────────────────────────────────────── */

static uint32_t rt_crc_table[256];

static void rt_crc_init(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++)
      c = (c & 1u) ? (c >> 1) ^ 0x82f63b78u : c >> 1;
    rt_crc_table[i] = c;
  }
}

/* Buffered writer with a running CRC32C (reflected Castagnoli; the state
   starts at 0xffffffff and is inverted once at the end). */
struct rt_out {
  int fd;
  int failed;
  uint32_t crc;
  size_t used;
  unsigned char buf[65536];
};

static void rt_out_flush(struct rt_out *o) {
  size_t off = 0;
  while (off < o->used && !o->failed) {
    ssize_t w = write(o->fd, o->buf + off, o->used - off);
    if (w < 0 && errno == EINTR)
      continue;
    if (w <= 0)
      o->failed = 1;
    else
      off += (size_t)w;
  }
  o->used = 0;
}

static void rt_out_bytes(struct rt_out *o, const void *data, size_t n, int in_crc) {
  const unsigned char *p = data;
  for (size_t i = 0; i < n; i++) {
    if (in_crc)
      o->crc = (o->crc >> 8) ^ rt_crc_table[(o->crc ^ p[i]) & 0xffu];
    if (o->used == sizeof o->buf)
      rt_out_flush(o);
    o->buf[o->used++] = p[i];
  }
}

static void rt_out_u32(struct rt_out *o, uint32_t v) {
  unsigned char b[4] = {(unsigned char)v, (unsigned char)(v >> 8), (unsigned char)(v >> 16),
                        (unsigned char)(v >> 24)};
  rt_out_bytes(o, b, 4, 1);
}

static void rt_out_u64(struct rt_out *o, uint64_t v) {
  unsigned char b[8];
  for (int i = 0; i < 8; i++)
    b[i] = (unsigned char)(v >> (8 * i));
  rt_out_bytes(o, b, 8, 1);
}

static void rt_hex(char *out, const uint8_t *b, size_t n) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = digits[b[i] >> 4];
    out[2 * i + 1] = digits[b[i] & 15];
  }
  out[2 * n] = '\0';
}

/* Commit tmp as dst only if dst does not exist. 0, or -1 with errno. */
static int rt_publish_noreplace(const char *tmp, const char *dst) {
#if defined(__APPLE__)
  if (renamex_np(tmp, dst, RENAME_EXCL) == 0)
    return 0;
  if (errno != ENOTSUP && errno != EINVAL)
    return -1;
#elif defined(__linux__) && defined(RENAME_NOREPLACE)
  if (renameat2(AT_FDCWD, tmp, AT_FDCWD, dst, RENAME_NOREPLACE) == 0)
    return 0;
  if (errno != ENOSYS && errno != EINVAL && errno != ENOTSUP)
    return -1;
#endif
  /* link() never replaces an existing name. */
  if (link(tmp, dst) != 0)
    return -1;
  unlink(tmp);
  return 0;
}

/* Publication failed: say why; required mode turns it into status 1. */
static void rt_unpublished(const char *code, const char *title, const char *detail) {
  rt_diag(code, title, detail);
  if (rt.required) {
    fprintf(stderr, "sv0cov: coverage is required (SV0COV_REQUIRED=1); failing the process\n");
    fflush(stderr);
    _exit(1);
  }
}

static void rt_flush(void) {
  if (getpid() != rt.pid) {
    /* A forked child must not publish the counters it inherited. */
    rt_unpublished("COV2120", "unsupported process lifecycle",
                   "a forked process image does not publish its parent's counters");
    return;
  }
  if (atomic_load_explicit(&rt.state, memory_order_acquire) != SV0COV_RT_STATE_ACTIVE) {
    rt_unpublished("COV2011", "raw profile incomplete",
                   "a coverage hit named an unregistered counter; the counts are not trustworthy");
    return;
  }
  /* Pass 1: size. */
  uint32_t n = rt.count;
  uint32_t pairs = 0;
  int saturated = 0;
  for (uint32_t i = 0; i < n; i++) {
    uint64_t c = atomic_load_explicit(&rt.counters[i], memory_order_relaxed);
    pairs += c != 0;
    saturated |= c == UINT64_MAX;
  }
  uint32_t words = saturated ? (uint32_t)(((uint64_t)n + 63) / 64) : 0;
  uint64_t *bitmap = NULL;
  if (words > 0 && (bitmap = calloc(words, sizeof(uint64_t))) == NULL) {
    rt_unpublished("COV2011", "raw profile incomplete", "out of memory for the overflow bitmap");
    return;
  }

  char name[32 * 2 + 1 + 32 + 16];
  char run_hex[33], profile_hex[33];
  rt_hex(run_hex, rt.run_id, 16);
  rt_hex(profile_hex, rt.profile_id, 16);
  snprintf(name, sizeof name, "%s-%s.sv0profraw", run_hex, profile_hex);
  size_t dlen = strlen(rt.profile_dir);
  char *dst = malloc(dlen + 1 + strlen(name) + 1);
  char *tmp = malloc(dlen + 2 + strlen(name) + 16);
  struct rt_out *o = malloc(sizeof *o);
  if (dst == NULL || tmp == NULL || o == NULL) {
    free(bitmap), free(dst), free(tmp), free(o);
    rt_unpublished("COV2011", "raw profile incomplete", "out of memory preparing the profile");
    return;
  }
  sprintf(dst, "%s/%s", rt.profile_dir, name);
  sprintf(tmp, "%s/.%s.tmp-XXXXXX", rt.profile_dir, name);
  int fd = mkstemp(tmp); /* mode 0600, unpredictable name */
  if (fd < 0) {
    free(bitmap), free(dst), free(tmp), free(o);
    rt_unpublished("COV2010", "raw profile unavailable", "cannot create a temporary file in SV0COV_PROFILE_DIR");
    return;
  }
  fchmod(fd, 0600);

  /* Pass 2: write. */
  rt_crc_init();
  o->fd = fd, o->failed = 0, o->crc = 0xffffffffu, o->used = 0;
  uint32_t flags = 0x04u; /* BACKEND_NATIVE */
#ifdef SV0COV_RT_TESTING
  /* CV-116 byte parity against the VM goldens' flag variants. */
  const char *backend = getenv("SV0COVRT_TEST_BACKEND");
  if (backend != NULL && strcmp(backend, "vm-v1") == 0)
    flags = 0x08u;
  if (backend != NULL && strcmp(backend, "vm-v2") == 0)
    flags = 0x10u;
#endif
  if (rt.context_len >= 0)
    flags |= 0x01u; /* CONTEXT_PRESENT */
  if (saturated)
    flags |= 0x02u; /* OVERFLOW_PRESENT */
  rt_out_bytes(o, "SV0PRF\0\0", 8, 1);
  rt_out_bytes(o, "\x01\x00\x00\x00", 4, 1); /* major 1, minor 0 */
  rt_out_u32(o, flags);
  rt_out_bytes(o, rt.map_id, 32, 1);
  rt_out_bytes(o, rt.run_id, 16, 1);
  rt_out_bytes(o, rt.profile_id, 16, 1);
  rt_out_u32(o, rt.context_len >= 0 ? (uint32_t)rt.context_len : 0u);
  if (rt.context_len > 0)
    rt_out_bytes(o, rt.context, (size_t)rt.context_len, 1);
  rt_out_u32(o, pairs);
  uint32_t written = 0;
  int saw_saturated = 0;
  for (uint32_t i = 0; i < n; i++) {
    uint64_t c = atomic_load_explicit(&rt.counters[i], memory_order_relaxed);
    if (c == 0)
      continue;
    written++;
    if (written <= pairs) {
      rt_out_u32(o, i);
      rt_out_u64(o, c);
    }
    if (c == UINT64_MAX) {
      saw_saturated = 1;
      if (bitmap != NULL)
        bitmap[i / 64] |= (uint64_t)1 << (i % 64);
    }
  }
  int racing = written != pairs || saw_saturated != saturated;
  rt_out_u32(o, words);
  for (uint32_t w = 0; w < words; w++)
    rt_out_u64(o, bitmap[w]);
  rt_out_bytes(o, "SV0DONE!", 8, 1);
  uint32_t crc = o->crc ^ 0xffffffffu;
  unsigned char cb[4] = {(unsigned char)crc, (unsigned char)(crc >> 8), (unsigned char)(crc >> 16),
                         (unsigned char)(crc >> 24)};
  rt_out_bytes(o, cb, 4, 0);
  rt_out_flush(o);
  int io_failed = o->failed || fsync(fd) != 0;
  io_failed |= close(fd) != 0;
  free(bitmap);
  free(o);

  if (racing || io_failed) {
    unlink(tmp);
    free(dst), free(tmp);
    if (racing)
      rt_unpublished("COV2011", "raw profile incomplete",
                     "coverage hits ran while the profile was being written; join worker threads before exit");
    else
      rt_unpublished("COV2010", "raw profile unavailable", "writing the profile failed");
    return;
  }
  if (rt_publish_noreplace(tmp, dst) != 0) {
    int collided = errno == EEXIST;
    unlink(tmp);
    free(dst), free(tmp);
    if (collided)
      rt_unpublished("COV2112", "raw-profile identity collision", "a profile with this run and profile ID already exists");
    else
      rt_unpublished("COV2010", "raw profile unavailable", "committing the profile failed");
    return;
  }
  int dfd = open(rt.profile_dir, O_RDONLY);
  if (dfd >= 0) {
    fsync(dfd); /* where the filesystem supports it */
    close(dfd);
  }
  free(dst), free(tmp);
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
  if (n > SV0COV_TIER_MAX_COUNTERS) {
    rt_fail("COV6001", "resource limit exceeded",
            "the map has more counters than the standard raw-profile tier allows (4194304)");
    return;
  }
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
  for (int i = 0; i < 32; i++)
    rt.map_id[i] = (uint8_t)(rt_hexval(modules[0]->map_id[2 * i]) * 16 + rt_hexval(modules[0]->map_id[2 * i + 1]));
  rt.count = n;
  rt.modules = modules;
  rt.module_count = module_count;
  rt.pid = getpid();
  if (atexit(rt_flush) != 0) {
    rt_fail("COV2011", "raw profile incomplete", "cannot register the exit-time flush");
    return;
  }
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
