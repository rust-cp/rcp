/* Diagnostic only. Compile with profile-flush.c using -shared -fPIC -O2 -ldl.
 * Observe libc metadata/enumeration calls without changing arguments or results.
 * Static programs and raw syscalls bypass these probes. Counts are per process;
 * forked children can inherit earlier counters, so do not sum process totals.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct metric { _Atomic uint64_t calls; _Atomic uint64_t nanoseconds; };
static struct metric stat_metric, lstat_metric, fstat_metric, statx_metric, readdir_metric;
static int (*original_stat)(const char *, struct stat64 *);
static int (*original_lstat)(const char *, struct stat64 *);
static int (*original_fstat)(int, struct stat64 *);
static int (*original_statx)(int, const char *, int, unsigned int, struct statx *);
static struct dirent64 *(*original_readdir)(DIR *);

__attribute__((constructor)) static void initialize(void) {
    original_stat = dlsym(RTLD_NEXT, "stat64");
    original_lstat = dlsym(RTLD_NEXT, "lstat64");
    original_fstat = dlsym(RTLD_NEXT, "fstat64");
    original_statx = dlsym(RTLD_NEXT, "statx");
    original_readdir = dlsym(RTLD_NEXT, "readdir64");
}

static void record(struct metric *metric, struct timespec start) {
    int saved_errno = errno;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t ns = (uint64_t)((end.tv_sec-start.tv_sec)*1000000000LL + end.tv_nsec-start.tv_nsec);
    atomic_fetch_add(&metric->calls, 1);
    atomic_fetch_add(&metric->nanoseconds, ns);
    errno = saved_errno;
}

#define OBSERVE(metric, original, call, failure) \
    if (!(original)) { errno = ENOSYS; return failure; } \
    struct timespec start; clock_gettime(CLOCK_MONOTONIC, &start); \
    __typeof__(call) result = (call); record(&(metric), start); return result

int stat64(const char *path, struct stat64 *buffer) {
    OBSERVE(stat_metric, original_stat, original_stat(path, buffer), -1);
}
int lstat64(const char *path, struct stat64 *buffer) {
    OBSERVE(lstat_metric, original_lstat, original_lstat(path, buffer), -1);
}
int fstat64(int fd, struct stat64 *buffer) {
    OBSERVE(fstat_metric, original_fstat, original_fstat(fd, buffer), -1);
}
int statx(int fd, const char *path, int flags, unsigned int mask, struct statx *buffer) {
    OBSERVE(statx_metric, original_statx, original_statx(fd, path, flags, mask, buffer), -1);
}
struct dirent64 *readdir64(DIR *dir) {
    OBSERVE(readdir_metric, original_readdir, original_readdir(dir), NULL);
}

__attribute__((destructor)) static void report(void) {
    struct metric *metrics[] = { &stat_metric, &lstat_metric, &fstat_metric, &statx_metric, &readdir_metric };
    const char *names[] = { "stat64", "lstat64", "fstat64", "statx", "readdir64" };
    for (unsigned int i = 0; i < sizeof(metrics)/sizeof(metrics[0]); ++i) {
        fprintf(stderr, "PROFILE metadata pid=%ld operation=%s calls=%llu nanoseconds=%llu\n",
                (long)getpid(), names[i], (unsigned long long)atomic_load(&metrics[i]->calls),
                (unsigned long long)atomic_load(&metrics[i]->nanoseconds));
    }
}
