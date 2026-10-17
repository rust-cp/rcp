/* Local diagnostic shim: observe, never suppress, syncfs durability barriers.
 * Compile: cc -Wall -Wextra -Werror -O2 -shared -fPIC profile-flush.c -ldl -o profile-flush.so
 * Static executables bypass LD_PRELOAD; their external `sync -f` is still observed.
 * Profiled trials are diagnostic evidence, not uninstrumented performance rankings.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int syncfs(int fd) {
    typedef int (*sync_function)(int);
    sync_function original = (sync_function)dlsym(RTLD_NEXT, "syncfs");
    if (!original) {
        errno = ENOSYS;
        return -1;
    }
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int result = original(fd);
    int saved_errno = errno;
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    fprintf(stderr, "PROFILE syncfs pid=%ld seconds=%.9f result=%d\n",
            (long)getpid(), elapsed, result);
    errno = saved_errno;
    return result;
}
