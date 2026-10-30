/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla */
/*
 * I/O trace shim for the CV-406 orderly-flush-only proof (SPEC 23.4,
 * COV-FMT-011/012, AC-032). Linked only into the trace build of
 * rt_driver.c, never into the runtime itself.
 *
 * It defines the file-creating, file-writing, file-naming and memory-mapping
 * calls the runtime could make. A definition in the executable binds the
 * runtime object's references at link time (ELF and Mach-O alike), so every
 * such call the runtime makes lands here; each one is recorded and then
 * forwarded to the C library through dlsym(RTLD_NEXT). The C library's own
 * internal calls (stdio, malloc) are not seen, which is the point: only the
 * runtime's and the driver's calls are traced.
 *
 * One line per call goes to the file named by RT_IOTRACE (not an SV0COV_*
 * name: the runtime refuses unknown names of its own prefix), written at
 * once so a killed process keeps its trace:
 *
 *   <phase> <op> <target>
 *
 * <phase> is rt_iotrace_phase, which the driver sets: "pre" before
 * __sv0cov_start, "user" while user code runs, "exit" once it leaves main.
 * <target> classifies the path or descriptor: "tmp" (a runtime temporary,
 * .<name>.tmp-*), "profile" (*.sv0profraw), "dir" (SV0COV_PROFILE_DIR
 * itself), "stdio" (descriptors 0-2), "anon" (an anonymous mapping), else
 * "other". A rename names both sides: "tmp>profile".
 */
#define _GNU_SOURCE 1 /* RTLD_NEXT, renameat2 (glibc) */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

const char *volatile rt_iotrace_phase = "pre";

static int trace_fd = -2; /* -2 = not opened yet, -1 = no trace */
static char fd_class[4096][8];

/* dlsym returns an object pointer; copy it into a function pointer without
   the cast ISO C leaves undefined (and -pedantic rejects). */
#define REAL(type, name)                                                                                     \
  static type real_##name;                                                                                   \
  if (real_##name == NULL) {                                                                                 \
    void *sym = dlsym(RTLD_NEXT, #name);                                                                     \
    if (sym == NULL)                                                                                         \
      abort();                                                                                               \
    memcpy(&real_##name, &sym, sizeof sym);                                                                  \
  }

typedef int (*open_fn)(const char *, int, ...);
typedef ssize_t (*write_fn)(int, const void *, size_t);

static void record(const char *op, const char *target) {
  REAL(write_fn, write)
  if (trace_fd == -2) {
    REAL(open_fn, open)
    const char *path = getenv("RT_IOTRACE");
    trace_fd = path == NULL ? -1 : real_open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
  }
  if (trace_fd < 0)
    return;
  char line[128];
  int n = snprintf(line, sizeof line, "%s %s %s\n", rt_iotrace_phase, op, target);
  if (n > 0 && (size_t)n < sizeof line && real_write(trace_fd, line, (size_t)n) != n)
    abort();
}

static const char *path_class(const char *path) {
  const char *dir = getenv("SV0COV_PROFILE_DIR");
  if (dir != NULL && strcmp(path, dir) == 0)
    return "dir";
  const char *base = strrchr(path, '/');
  base = base == NULL ? path : base + 1;
  if (base[0] == '.' && strstr(base, ".tmp-") != NULL)
    return "tmp";
  size_t n = strlen(base), s = strlen(".sv0profraw");
  if (n >= s && strcmp(base + n - s, ".sv0profraw") == 0)
    return "profile";
  return "other";
}

static const char *fd_target(int fd) {
  if (fd >= 0 && fd <= 2)
    return "stdio";
  if (fd >= 0 && fd < 4096 && fd_class[fd][0] != '\0')
    return fd_class[fd];
  return "other";
}

static void remember(int fd, const char *cls) {
  if (fd >= 0 && fd < 4096)
    snprintf(fd_class[fd], sizeof fd_class[fd], "%s", cls);
}

static void record2(const char *op, const char *from, const char *to) {
  char both[24];
  snprintf(both, sizeof both, "%s>%s", path_class(from), path_class(to));
  record(op, both);
}

/* ── traced calls ──────────────────────────────────────────────────────── */

int open(const char *path, int flags, ...) {
  REAL(open_fn, open)
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  record("open", path_class(path));
  int fd = real_open(path, flags, mode);
  remember(fd, path_class(path));
  return fd;
}

int mkstemp(char *template_) {
  typedef int (*fn)(char *);
  REAL(fn, mkstemp)
  int fd = real_mkstemp(template_);
  record("mkstemp", path_class(template_));
  remember(fd, path_class(template_));
  return fd;
}

ssize_t write(int fd, const void *buf, size_t n) {
  REAL(write_fn, write)
  record("write", fd_target(fd));
  return real_write(fd, buf, n);
}

ssize_t pwrite(int fd, const void *buf, size_t n, off_t off) {
  typedef ssize_t (*fn)(int, const void *, size_t, off_t);
  REAL(fn, pwrite)
  record("pwrite", fd_target(fd));
  return real_pwrite(fd, buf, n, off);
}

int fsync(int fd) {
  typedef int (*fn)(int);
  REAL(fn, fsync)
  record("fsync", fd_target(fd));
  return real_fsync(fd);
}

int ftruncate(int fd, off_t len) {
  typedef int (*fn)(int, off_t);
  REAL(fn, ftruncate)
  record("ftruncate", fd_target(fd));
  return real_ftruncate(fd, len);
}

int fchmod(int fd, mode_t mode) {
  typedef int (*fn)(int, mode_t);
  REAL(fn, fchmod)
  record("fchmod", fd_target(fd));
  return real_fchmod(fd, mode);
}

int close(int fd) {
  typedef int (*fn)(int);
  REAL(fn, close)
  record("close", fd_target(fd));
  if (fd >= 0 && fd < 4096)
    fd_class[fd][0] = '\0';
  return real_close(fd);
}

int link(const char *from, const char *to) {
  typedef int (*fn)(const char *, const char *);
  REAL(fn, link)
  record2("link", from, to);
  return real_link(from, to);
}

int unlink(const char *path) {
  typedef int (*fn)(const char *);
  REAL(fn, unlink)
  record("unlink", path_class(path));
  return real_unlink(path);
}

int rename(const char *from, const char *to) {
  typedef int (*fn)(const char *, const char *);
  REAL(fn, rename)
  record2("rename", from, to);
  return real_rename(from, to);
}

#if defined(__APPLE__)
int renamex_np(const char *from, const char *to, unsigned int flags) {
  typedef int (*fn)(const char *, const char *, unsigned int);
  REAL(fn, renamex_np)
  record2("rename", from, to);
  return real_renamex_np(from, to, flags);
}
#elif defined(__linux__) && defined(RENAME_NOREPLACE)
int renameat2(int fromfd, const char *from, int tofd, const char *to, unsigned int flags) {
  typedef int (*fn)(int, const char *, int, const char *, unsigned int);
  REAL(fn, renameat2)
  record2("rename", from, to);
  return real_renameat2(fromfd, from, tofd, to, flags);
}
#endif

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
  typedef void *(*fn)(void *, size_t, int, int, int, off_t);
  REAL(fn, mmap)
  record("mmap", fd < 0 ? "anon" : fd_target(fd));
  return real_mmap(addr, len, prot, flags, fd, off);
}

int msync(void *addr, size_t len, int flags) {
  typedef int (*fn)(void *, size_t, int);
  REAL(fn, msync)
  record("msync", "other");
  return real_msync(addr, len, flags);
}

int munmap(void *addr, size_t len) {
  typedef int (*fn)(void *, size_t);
  REAL(fn, munmap)
  record("munmap", "other");
  return real_munmap(addr, len);
}
