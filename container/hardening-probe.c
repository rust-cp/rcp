/* Test fixture only; never copied into the distributable image. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char line[256], effective[32] = "unknown", bounding[32] = "unknown";
    int no_new_privileges = -1, seccomp = -1;
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return 1;
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "CapEff: %31s", effective) == 1) continue;
        if (sscanf(line, "CapBnd: %31s", bounding) == 1) continue;
        if (sscanf(line, "NoNewPrivs: %d", &no_new_privileges) == 1) continue;
        (void)sscanf(line, "Seccomp: %d", &seccomp);
    }
    fclose(status);
    printf("{\"uid\":%ld,\"gid\":%ld,\"effective\":\"%s\",\"bounding\":\"%s\",\"no_new_privileges\":%d,\"seccomp\":%d}\n",
           (long)geteuid(), (long)getegid(), effective, bounding, no_new_privileges, seccomp);
    return 0;
}
