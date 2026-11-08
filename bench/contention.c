/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla */
/*
 * Native contention fixture (CV-427; SPEC 24.3 native-contention,
 * COV-PERF-016, AC-068). bench/corpus.py builds it twice: plain (the
 * coverage-off arm) and with -DSV0COV_ON linked against
 * runtime/c/sv0cov_rt.c (the coverage-on arm), which adds one
 * __sv0cov_hit per step.
 *
 *   contention <threads> shared|disjoint <hits-per-thread> <seed>
 *
 * Thread t runs <hits-per-thread> steps of x = (x * a_t + b_t) mod 1000003
 * from x = t + 1, hitting counter 0 (shared) or counter t (disjoint). It
 * prints the sum of the final x values, which bench/corpus.py computes in
 * closed form, so a run that skips work cannot pass. On Linux each thread
 * is pinned to CPU t mod the online count; stderr says "affinity: pinned"
 * or "affinity: advisory" (SPEC 24.3: report when pinning is advisory).
 */
#if defined(__linux__)
#define _GNU_SOURCE 1 /* pthread_setaffinity_np */
#endif

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MOD 1000003u
#define MAX_THREADS 8

#ifdef SV0COV_ON
#include "sv0cov_rt.h"
#define MAP_ID "ce0000000000000000000000000000000000000000000000000000000000c427"
#define FRAG_ID "ce0000000000000000000000000000000000000000000000000000000000f427"
static const struct __sv0cov_fragment frag = {FRAG_ID, 0u, MAX_THREADS};
static const struct __sv0cov_module mod = {SV0COV_PROTOCOL_MAJOR, MAP_ID, MAX_THREADS, "bench-contention", "sv0cov-bench", 0u, MAX_THREADS, 1u, &frag};
static const struct __sv0cov_module *const mods[1] = {&mod};
#endif

struct job {
  uint32_t counter;
  uint64_t a, b, x;
  long hits;
};

static void *work(void *arg) {
  struct job *j = arg;
  uint64_t x = j->x;
  for (long k = 0; k < j->hits; k++) {
    x = (x * j->a + j->b) % MOD;
#ifdef SV0COV_ON
    __sv0cov_hit(&mod, j->counter);
#endif
  }
  j->x = x;
  return NULL;
}

int main(int argc, char **argv) {
  if (argc != 5)
    return 2;
  int n = atoi(argv[1]);
  int shared = strcmp(argv[2], "shared") == 0;
  long hits = atol(argv[3]);
  uint64_t seed = strtoull(argv[4], NULL, 10);
  if (n < 1 || n > MAX_THREADS || (!shared && strcmp(argv[2], "disjoint") != 0) || hits < 0)
    return 2;
#ifdef SV0COV_ON
  __sv0cov_start(mods, 1u);
#endif
  pthread_t t[MAX_THREADS];
  struct job j[MAX_THREADS];
  int pinned = 0;
#if defined(__linux__)
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  pinned = cpus > 0;
#endif
  for (int i = 0; i < n; i++) {
    j[i] = (struct job){shared ? 0u : (uint32_t)i, 2 + (seed * 31 + (uint64_t)i) % 900, (seed * 17 + (uint64_t)i * 7) % MOD, (uint64_t)i + 1, hits};
    if (pthread_create(&t[i], NULL, work, &j[i]) != 0)
      return 3;
#if defined(__linux__)
    if (pinned) {
      cpu_set_t set;
      CPU_ZERO(&set);
      CPU_SET((int)(i % cpus), &set);
      pinned = pthread_setaffinity_np(t[i], sizeof set, &set) == 0;
    }
#endif
  }
  uint64_t sum = 0;
  for (int i = 0; i < n; i++) {
    if (pthread_join(t[i], NULL) != 0)
      return 3;
    sum += j[i].x;
  }
  fprintf(stderr, "affinity: %s\n", pinned ? "pinned" : "advisory");
  printf("%llu\n", (unsigned long long)sum);
  return 0;
}
