/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla */
/*
 * Scenario driver for the native runtime tests (tests/test_native_runtime.py).
 * Built with -DSV0COV_RT_TESTING against runtime/c/sv0cov_rt.c. Each run is
 * one process: it registers a fixture program, prints "user-code" (the point
 * a generated main reaches after __sv0cov_start), runs the scenario, and
 * prints the runtime state:
 *
 *   state=<0|1|2> required=<0|1> run_id=<hex> profile_id=<hex>
 *   context=<absent|len:<n>:<hex>> counts=<c0,c1,...> overflow=<o0,o1,...>
 *
 * The exit scenarios (CV-115) end the process in a specific way after the
 * "ok" hit pattern: kill (SIGKILL), underscore-exit (_exit(0)), exit1
 * (exit(1), as the sv0 runtime's panic and contract-failure paths do),
 * collide (the final profile name already exists), rmdir (the profile
 * directory is gone), fork (a child exits normally after forking).
 * "per-fragment <order>" (CV-206) registers one module per fragment, as
 * sv0c emits, in the given order; "bad-modules <kind>" breaks one rule in
 * a later module of that set.
 * "stress <threads> <hits>", "race-saturate <trials>" and "probe" (CV-210)
 * are the contention, saturation-race, and lock-free/alignment checks.
 * "write" (CV-116) registers a map of a given size and counts, for byte
 * parity with the Python writer.
 *
 * The fixture program has 70 counters (so the overflow bitmap has two
 * words) in two fragments.
 */
#define _POSIX_C_SOURCE 200809L /* fork, rmdir, open under -std=c11 */

#include "../sv0cov_rt.h"

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define MAP_ID "4f5da9345b6f601cba7b19e442e4b26352c18a1fb2044e8141685a2915b81b6c"
#define FRAG_A "6d599e56e518833b373e55b1e8c222e77b7cdcc241f74d02a5a1a3a6f6b72971"
#define FRAG_B "0000000000000000000000000000000000000000000000000000000000000001"
#define FRAG_C "0000000000000000000000000000000000000000000000000000000000000002"
#define N 70u

static struct __sv0cov_fragment frags[2] = {{FRAG_A, 0, 40}, {FRAG_B, 40, 30}};
static struct __sv0cov_module mod = {1u, MAP_ID, N, "fixture", "sv0c+test", 0u, N, 2u, frags};
static const struct __sv0cov_module *mods[1] = {&mod};

/* A second, valid split of the same program into two modules. */
static struct __sv0cov_fragment frags_lo[1] = {{FRAG_A, 0, 40}};
static struct __sv0cov_fragment frags_hi[2] = {{FRAG_B, 40, 30}, {FRAG_C, 70, 0}};
static struct __sv0cov_module mod_lo = {1u, MAP_ID, N, "fixture", "sv0c+test", 0u, 40u, 1u, frags_lo};
static struct __sv0cov_module mod_hi = {1u, MAP_ID, N, "fixture", "sv0c+test", 40u, 30u, 2u, frags_hi};
static const struct __sv0cov_module *mods2[2] = {&mod_hi, &mod_lo};

/* One module per fragment, as sv0c emits since CV-206: two positive slices
   and two empty fragments (one at an inner boundary, one at the total). */
#define FRAG_D "0000000000000000000000000000000000000000000000000000000000000003"
static struct __sv0cov_fragment f4a[1] = {{FRAG_A, 0, 40}};
static struct __sv0cov_fragment f4d[1] = {{FRAG_D, 40, 0}};
static struct __sv0cov_fragment f4b[1] = {{FRAG_B, 40, 30}};
static struct __sv0cov_fragment f4c[1] = {{FRAG_C, 70, 0}};
static struct __sv0cov_module m4[4] = {
    {1u, MAP_ID, N, "fixture", "sv0c+test", 0u, 40u, 1u, f4a},
    {1u, MAP_ID, N, "fixture", "sv0c+test", 40u, 0u, 1u, f4d},
    {1u, MAP_ID, N, "fixture", "sv0c+test", 40u, 30u, 1u, f4b},
    {1u, MAP_ID, N, "fixture", "sv0c+test", 70u, 0u, 1u, f4c},
};

/* Register the four per-fragment modules in the order given as digits
   ("0123", "3120", ...), then hit each positive module's first and last
   counter once. */
static int per_fragment(const char *order) {
  static const struct __sv0cov_module *ms[4];
  if (strlen(order) != 4)
    return 2;
  for (int i = 0; i < 4; i++) {
    if (order[i] < '0' || order[i] > '3')
      return 2;
    ms[i] = &m4[order[i] - '0'];
  }
  __sv0cov_start(ms, 4u);
  __sv0cov_hit(&m4[0], 0);
  __sv0cov_hit(&m4[0], 39);
  __sv0cov_hit(&m4[2], 0);
  __sv0cov_hit(&m4[2], 29);
  return 0;
}

/* Malformed per-fragment registrations: each breaks one rule in a module
   other than the first registered one. */
static int bad_modules(const char *kind) {
  static struct __sv0cov_fragment f[4][1];
  static struct __sv0cov_module m[4];
  static const struct __sv0cov_module *ms[5];
  for (int i = 0; i < 4; i++) {
    m[i] = m4[i];
    f[i][0] = m4[i].fragments[0];
    m[i].fragments = f[i];
    ms[i] = &m[i];
  }
  uint32_t count = 4;
  if (strcmp(kind, "map-id") == 0)
    m[2].map_id = "1111111111111111111111111111111111111111111111111111111111111111";
  else if (strcmp(kind, "total") == 0)
    m[2].program_counter_count = 71;
  else if (strcmp(kind, "target") == 0)
    m[2].target = "other";
  else if (strcmp(kind, "identity") == 0)
    m[2].compiler_identity = "sv0c+other";
  else if (strcmp(kind, "protocol") == 0)
    m[3].protocol_major = 2;
  else if (strcmp(kind, "overlap") == 0) {
    m[2].slice_base = 39;
    f[2][0].slice_base = 39;
  } else if (strcmp(kind, "gap") == 0) {
    m[2].slice_base = 41;
    m[2].slice_length = 29;
    f[2][0].slice_base = 41;
    f[2][0].slice_length = 29;
  } else if (strcmp(kind, "missing") == 0) {
    ms[2] = &m[3]; /* m[2] (counters 40..69) is never registered */
    count = 3;
  } else if (strcmp(kind, "out-of-range") == 0) {
    m[3].slice_base = 71;
    f[3][0].slice_base = 71;
  } else if (strcmp(kind, "dup-fragment") == 0)
    f[2][0].fragment_id = FRAG_A;
  else if (strcmp(kind, "dup-empty-fragment") == 0)
    f[3][0].fragment_id = FRAG_D;
  else if (strcmp(kind, "empty-misplaced") == 0) {
    m[1].slice_base = 10;
    f[1][0].slice_base = 10;
  } else if (strcmp(kind, "dup-module") == 0) {
    ms[4] = &m[2];
    count = 5;
  } else if (strcmp(kind, "null-module") == 0)
    ms[2] = NULL;
  else
    return 2;
  __sv0cov_start(ms, count);
  return 0;
}

static void hex(const uint8_t *b, size_t n) {
  for (size_t i = 0; i < n; i++)
    printf("%02x", b[i]);
}

static void report(void) {
  printf("state=%d required=%d run_id=", sv0cov_rt_test_state(), sv0cov_rt_test_required());
  hex(sv0cov_rt_test_run_id(), 16);
  printf(" profile_id=");
  hex(sv0cov_rt_test_profile_id(), 16);
  const char *ctx;
  int clen = sv0cov_rt_test_context(&ctx);
  if (clen < 0)
    printf(" context=absent");
  else {
    printf(" context=len:%d:", clen);
    hex((const uint8_t *)ctx, (size_t)clen);
  }
  uint32_t n = sv0cov_rt_test_counter_count();
  printf(" counts=");
  for (uint32_t i = 0; i < n; i++)
    printf("%s%llu", i ? "," : "", (unsigned long long)sv0cov_rt_test_counter(i));
  printf(" overflow=");
  for (uint32_t i = 0; i < n; i++)
    printf("%s%d", i ? "," : "", sv0cov_rt_test_overflow(i));
  printf("\n");
}

struct job {
  uint32_t local;
  const struct __sv0cov_module *m;
  int hits;
};

static void *hammer(void *arg) {
  struct job *j = arg;
  for (int k = 0; k < j->hits; k++)
    __sv0cov_hit(j->m, j->local);
  return NULL;
}

static void threads(const struct __sv0cov_module *m, uint32_t local, int nthreads, int hits) {
  pthread_t t[16];
  struct job j = {local, m, hits};
  for (int i = 0; i < nthreads; i++)
    pthread_create(&t[i], NULL, hammer, &j);
  for (int i = 0; i < nthreads; i++)
    pthread_join(t[i], NULL);
}

/* CV-210 stress. One thread per counter in [first, first + nthreads), each
   hitting its own counter `hits` times (no sharing: exact per-counter totals). */
static void spread(const struct __sv0cov_module *m, uint32_t first, int nthreads, int hits) {
  pthread_t t[16];
  struct job j[16];
  for (int i = 0; i < nthreads; i++) {
    j[i] = (struct job){first + (uint32_t)i, m, hits};
    pthread_create(&t[i], NULL, hammer, &j[i]);
  }
  for (int i = 0; i < nthreads; i++)
    pthread_join(t[i], NULL);
}

/* CV-210 / AC-036: threads that wait at a gate, then hit one counter `hits`
   times each, so the hits collide as closely as the host allows. */
struct racer {
  atomic_int *gate;
  const struct __sv0cov_module *m;
  uint32_t local;
  int hits;
};

static void *race(void *arg) {
  struct racer *r = arg;
  while (atomic_load_explicit(r->gate, memory_order_acquire) == 0)
    ;
  for (int k = 0; k < r->hits; k++)
    __sv0cov_hit(r->m, r->local);
  return NULL;
}

/* `trials` rounds: the counter starts `below` under UINT64_MAX, `nthreads`
   racers hit it `hits` times each (nthreads * hits > below, so it must
   saturate). Returns the number of rounds in which it did not end at exactly
   UINT64_MAX with its overflow bit set (it wrapped, lost the bit, or stopped
   short). */
static int race_saturate(const struct __sv0cov_module *m, uint32_t local, int trials, uint64_t below,
                         int nthreads, int hits) {
  int failures = 0;
  for (int n = 0; n < trials; n++) {
    atomic_int gate = 0;
    pthread_t t[16];
    struct racer r = {&gate, m, local, hits};
    sv0cov_rt_test_set_counter(local, UINT64_MAX - below);
    sv0cov_rt_test_clear_overflow(local);
    for (int i = 0; i < nthreads; i++)
      pthread_create(&t[i], NULL, race, &r);
    atomic_store_explicit(&gate, 1, memory_order_release);
    for (int i = 0; i < nthreads; i++)
      pthread_join(t[i], NULL);
    if (sv0cov_rt_test_counter(local) != UINT64_MAX || !sv0cov_rt_test_overflow(local))
      failures++;
  }
  return failures;
}

/* CV-210 / COV-INS-012: a worker that is never joined keeps hitting every
   counter while main returns and the exit-time flush runs. */
static void *restless(void *arg) {
  const struct __sv0cov_module *m = arg;
  for (;;)
    for (uint32_t i = 0; i < N; i++)
      __sv0cov_hit(m, i);
  return NULL;
}

/* CV-210: deliberate faults that prove a sanitizer build is really
   instrumented (the sanitizer must stop each one). Never run otherwise. */
static int plain_shared;

static void *unsynchronized(void *arg) {
  (void)arg;
  for (int k = 0; k < 100000; k++)
    plain_shared++;
  return NULL;
}

static int selfcheck(const char *kind) {
  if (strcmp(kind, "race") == 0) {
    pthread_t a, b;
    pthread_create(&a, NULL, unsynchronized, NULL);
    pthread_create(&b, NULL, unsynchronized, NULL);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    return 0;
  }
  if (strcmp(kind, "heap") == 0) {
    volatile size_t n = 8;
    char *p = malloc(n);
    p[n] = 1; /* one past the end */
    free(p);
    return 0;
  }
  if (strcmp(kind, "overflow") == 0) {
    volatile int big = 2147483647;
    volatile int more = big + 1; /* signed overflow */
    return more == 0;
  }
  return 2;
}

/* Malformed registrations: each breaks one rule. */
static int bad_registration(const char *kind) {
  static struct __sv0cov_fragment f[2];
  static struct __sv0cov_module m;
  static const struct __sv0cov_module *ms[2];
  memcpy(f, frags, sizeof f);
  m = mod;
  m.fragments = f;
  ms[0] = &m;
  uint32_t count = 1;
  if (strcmp(kind, "protocol") == 0)
    m.protocol_major = 2;
  else if (strcmp(kind, "map-id") == 0)
    m.map_id = "4F5DA9345B6F601CBA7B19E442E4B26352C18A1FB2044E8141685A2915B81B6C";
  else if (strcmp(kind, "gap") == 0)
    f[1].slice_base = 41;
  else if (strcmp(kind, "overlap") == 0)
    f[1].slice_base = 39;
  else if (strcmp(kind, "short") == 0)
    m.slice_length = 69;
  else if (strcmp(kind, "total") == 0)
    m.program_counter_count = 71;
  else if (strcmp(kind, "dup-fragment") == 0)
    f[1].fragment_id = FRAG_A;
  else if (strcmp(kind, "fragment-id") == 0)
    f[0].fragment_id = "xyz";
  else if (strcmp(kind, "identity") == 0)
    m.compiler_identity = "sv0c test";
  else if (strcmp(kind, "no-fragments") == 0)
    m.fragment_count = 0;
  else if (strcmp(kind, "dup-module") == 0) {
    ms[1] = &m;
    count = 2;
  } else if (strcmp(kind, "none") == 0)
    count = 0;
  else
    return 2;
  __sv0cov_start(ms, count);
  return 0;
}

int main(int argc, char **argv) {
  const char *scenario = argc > 1 ? argv[1] : "ok";
  if (strcmp(scenario, "per-fragment") == 0) {
    if (argc < 3 || per_fragment(argv[2]) != 0)
      return 2;
    puts("user-code");
    report();
    return 0;
  }
  if (strcmp(scenario, "bad-modules") == 0) {
    if (argc < 3 || bad_modules(argv[2]) != 0)
      return 2;
    puts("user-code");
    report();
    return 0;
  }
  if (strcmp(scenario, "selfcheck") == 0)
    return argc < 3 ? 2 : selfcheck(argv[2]);
  if (strcmp(scenario, "bad-registration") == 0) {
    if (argc < 3 || bad_registration(argv[2]) != 0)
      return 2;
    puts("user-code");
    report();
    return 0;
  }
  if (strcmp(scenario, "dup-env") == 0) {
    /* environ with SV0COV_RUN_ID twice (a mapping cannot express it). */
    static char *env[8];
    int k = 0;
    for (char **e = environ; *e != NULL && k < 6; e++)
      if (strncmp(*e, "SV0COV_", 7) == 0)
        env[k++] = *e;
    env[k++] = "SV0COV_RUN_ID=0123456789abcdef0123456789abcdef";
    env[k] = NULL;
    environ = env;
  }
  if (strcmp(scenario, "write") == 0) {
    /* write <map_id> <counters> [<index>=<count> ...]: register a
       one-fragment program of that size, give the listed counters those
       counts (through hits below 1000, else set directly), and exit. */
    if (argc < 4)
      return 2;
    static struct __sv0cov_fragment wf[1] = {{FRAG_A, 0, 0}};
    static struct __sv0cov_module wm = {1u, NULL, 0u, "fixture", "sv0c+test", 0u, 0u, 1u, wf};
    static const struct __sv0cov_module *wms[1] = {&wm};
    uint32_t n = (uint32_t)strtoul(argv[3], NULL, 10);
    wm.map_id = argv[2];
    wm.program_counter_count = n, wm.slice_length = n, wf[0].slice_length = n;
    __sv0cov_start(wms, 1u);
    for (int a = 4; a < argc; a++) {
      char *eq = strchr(argv[a], '=');
      if (eq == NULL)
        return 2;
      uint32_t i = (uint32_t)strtoul(argv[a], NULL, 10);
      unsigned long long c = strtoull(eq + 1, NULL, 10);
      if (c < 1000)
        for (unsigned long long k = 0; k < c; k++)
          __sv0cov_hit(&wm, i);
      else
        sv0cov_rt_test_set_counter(i, c);
    }
    return 0;
  }
  if (strcmp(scenario, "zero") == 0) {
    /* A zero-counter program: a zero-length fragment, no hit ever. */
    static struct __sv0cov_fragment zf[1] = {{FRAG_A, 0, 0}};
    static struct __sv0cov_module zm = {1u, MAP_ID, 0u, "fixture", "sv0c+test", 0u, 0u, 1u, zf};
    static const struct __sv0cov_module *zms[1] = {&zm};
    __sv0cov_start(zms, 1u);
    puts("user-code");
    report();
    return 0;
  }
  if (strcmp(scenario, "hit-before-start") == 0) {
    __sv0cov_hit(&mod, 0);
    report();
    return 0;
  }
  __sv0cov_start(strcmp(scenario, "two-modules") == 0 ? mods2 : mods,
                 strcmp(scenario, "two-modules") == 0 ? 2u : 1u);
  puts("user-code");
  if (strcmp(scenario, "ok") == 0 || strcmp(scenario, "dup-env") == 0) {
    for (uint32_t i = 0; i < N; i++)
      for (uint32_t k = 0; k <= i % 5; k++)
        __sv0cov_hit(&mod, i);
  } else if (strcmp(scenario, "two-modules") == 0) {
    __sv0cov_hit(&mod_lo, 0);
    __sv0cov_hit(&mod_lo, 39);
    __sv0cov_hit(&mod_hi, 0);
    __sv0cov_hit(&mod_hi, 29);
    __sv0cov_hit(&mod_hi, 29);
  } else if (strcmp(scenario, "saturate") == 0) {
    sv0cov_rt_test_set_counter(3, UINT64_MAX - 5);
    for (int k = 0; k < 10; k++)
      __sv0cov_hit(&mod, 3);
    sv0cov_rt_test_set_counter(65, UINT64_MAX);
    __sv0cov_hit(&mod, 65);
    sv0cov_rt_test_set_counter(66, UINT64_MAX - 1);
    __sv0cov_hit(&mod, 66);
  } else if (strcmp(scenario, "threads") == 0) {
    threads(&mod, 0, 8, 100000);
    sv0cov_rt_test_set_counter(1, UINT64_MAX - 1000);
    threads(&mod, 1, 8, 10000);
  } else if (strcmp(scenario, "stress") == 0) {
    /* stress <threads> <hits>: one shared counter, then one counter each. */
    int nt = argc > 2 ? atoi(argv[2]) : 8, hits = argc > 3 ? atoi(argv[3]) : 100000;
    if (nt < 1 || nt > 16 || hits < 1)
      return 2;
    threads(&mod, 0, nt, hits);
    spread(&mod, 10, nt, hits);
  } else if (strcmp(scenario, "race-saturate") == 0) {
    /* race-saturate <trials>: AC-036 (two threads, one hit each, from
       UINT64_MAX - 1), then eight threads crossing the limit together. */
    int trials = argc > 2 ? atoi(argv[2]) : 1000;
    int two = race_saturate(&mod, 5, trials, 1, 2, 1);
    int eight = race_saturate(&mod, 64, trials / 10 + 1, 1000, 8, 500);
    printf("race two_thread_failures=%d eight_thread_failures=%d trials=%d\n", two, eight, trials);
  } else if (strcmp(scenario, "unjoined") == 0) {
    pthread_t t;
    pthread_create(&t, NULL, restless, &mod);
    pthread_detach(t);
    /* Return while the worker runs: the profile is either complete as
       written or refused (COV2011), never torn. */
    return 0;
  } else if (strcmp(scenario, "probe") == 0) {
    int build = -1;
    int run = __sv0cov_atomic_u64_lock_free(&build);
    printf("probe lock_free_build=%d lock_free_runtime=%d counter_size=%u storage_aligned=%d\n", build, run,
           sv0cov_rt_test_counter_size(), sv0cov_rt_test_storage_aligned());
  } else if (strcmp(scenario, "twice") == 0) {
    __sv0cov_start(mods, 1u);
    puts("after-second-start");
  } else if (strcmp(scenario, "bad-hit") == 0) {
    __sv0cov_hit(&mod, N);
  } else if (strcmp(scenario, "foreign-hit") == 0) {
    __sv0cov_hit(&mod_lo, 0);
  } else if (strcmp(scenario, "kill") == 0 || strcmp(scenario, "underscore-exit") == 0 ||
             strcmp(scenario, "exit1") == 0 || strcmp(scenario, "collide") == 0 ||
             strcmp(scenario, "rmdir") == 0 || strcmp(scenario, "fork") == 0) {
    for (uint32_t i = 0; i < N; i++)
      for (uint32_t k = 0; k <= i % 5; k++)
        __sv0cov_hit(&mod, i);
    report();
    fflush(stdout);
    if (strcmp(scenario, "kill") == 0)
      raise(SIGKILL);
    if (strcmp(scenario, "underscore-exit") == 0)
      _exit(0);
    if (strcmp(scenario, "exit1") == 0)
      exit(1);
    if (strcmp(scenario, "collide") == 0) {
      char path[4096], hex[65];
      const uint8_t *r = sv0cov_rt_test_run_id(), *q = sv0cov_rt_test_profile_id();
      for (int i = 0; i < 16; i++)
        sprintf(hex + 2 * i, "%02x", r[i]);
      int n = snprintf(path, sizeof path, "%s/%s-", sv0cov_rt_test_profile_dir(), hex);
      for (int i = 0; i < 16; i++)
        sprintf(hex + 2 * i, "%02x", q[i]);
      snprintf(path + n, sizeof path - (size_t)n, "%s.sv0profraw", hex);
      int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
      if (fd < 0 || write(fd, "occupied", 8) != 8)
        return 3;
      close(fd);
    }
    if (strcmp(scenario, "rmdir") == 0 && rmdir(sv0cov_rt_test_profile_dir()) != 0)
      return 3;
    if (strcmp(scenario, "fork") == 0) {
      pid_t child = fork();
      if (child == 0)
        exit(0); /* must not publish the inherited counters */
      int status;
      if (child < 0 || waitpid(child, &status, 0) != child)
        return 3;
      printf("child-status=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
    return 0;
  } else {
    return 2;
  }
  report();
  return 0;
}
