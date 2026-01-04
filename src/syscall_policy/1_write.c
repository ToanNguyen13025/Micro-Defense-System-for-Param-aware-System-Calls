#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"

#define MAX_WRITE_SIZE 4096

int write_1_policy(pid_t pid, char *arg0, char *arg1, char *arg2) {
    char target[256];

    if (!arg0 || !arg1 || !arg2) {
        fprintf(stderr, "[write] Invalid arguments\n");
        return 0;
    }

    int fd = atoi(arg0);
    unsigned long count = strtoul(arg2, NULL, 10);

    if (get_fd_target(pid, fd, target, sizeof(target)) < 0) {
        fprintf(stderr, "[write] Cannot resolve fd %d\n", fd);
        return 0;
    }

    fd_type_t type = classify_fd(target);


    /* Dangerous output destinations */
    if (type == FD_SOCKET ||
        type == FD_PIPE   ||
        type == FD_PROC   ||
        type == FD_DEV) {
        fprintf(stderr,
            "[write] Dangerous write destination fd=%d target=%s\n",
            fd, target);
        return 0;
    }

    /* Limit write size (anti-exfiltration / DoS) */
    if (count == 0 || count > MAX_WRITE_SIZE) {
        fprintf(stderr,
            "[write] Unsafe write size: %lu\n", count);
        return 0;
    }

    return 1; /* ALLOW */
}
