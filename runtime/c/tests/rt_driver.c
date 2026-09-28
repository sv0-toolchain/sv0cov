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
 * The fixture program has 70 counters (so the overflow bitmap has two
 * words) in two fragments.
 */
#include "../sv0cov_rt.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  } else if (strcmp(scenario, "twice") == 0) {
    __sv0cov_start(mods, 1u);
    puts("after-second-start");
  } else if (strcmp(scenario, "bad-hit") == 0) {
    __sv0cov_hit(&mod, N);
  } else if (strcmp(scenario, "foreign-hit") == 0) {
    __sv0cov_hit(&mod_lo, 0);
  } else {
    return 2;
  }
  report();
  return 0;
}
