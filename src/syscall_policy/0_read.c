#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"

#define MAX_READ_SIZE 4096
#define USER_SPACE_MAX 0x00007fffffffffffUL

static int is_safe_buf(unsigned long buf) {
    return buf > 0 && buf < USER_SPACE_MAX;
}

static int is_safe_count(unsigned long count) {
    return count > 0 && count <= MAX_READ_SIZE;
}

int read_0_policy(pid_t pid, char *arg0, char *arg1, char *arg2) {
    char target[256];

    if (!arg0 || !arg1 || !arg2) {
        fprintf(stderr, "[read] Invalid arguments\n");
        return 0;
    }

    int fd = atoi(arg0);
    unsigned long buf   = strtoul(arg1, NULL, 10);
    unsigned long count = strtoul(arg2, NULL, 10);

    /* resolve fd target */
    if (get_fd_target(pid, fd, target, sizeof(target)) < 0) {
        fprintf(stderr, "[read] Cannot resolve fd %d\n", fd);
        return 0;
    }

    fd_type_t type = classify_fd(target);

    /* policy: fd type */
    if (type == FD_PROC || type == FD_DEV) {
        fprintf(stderr, "[read] Dangerous fd target: %s\n", target);
        return 0;
    }

    /* policy: buffer address */
    if (!is_safe_buf(buf)) {
        fprintf(stderr, "[read] Unsafe buffer address: 0x%lx\n", buf);
        return 0;
    }

    /* policy: read size */
    if (!is_safe_count(count)) {
        fprintf(stderr, "[read] Unsafe read size: %lu\n", count);
        return 0;
    }

    return 1; /* ALLOW */
}
