#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <string.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"

#define USER_SPACE_MAX 0x00007fffffffffffUL


static int is_safe_ptr(unsigned long ptr) {
    if (ptr == 0) return 1; 
    return ptr > 0 && ptr < USER_SPACE_MAX;
}


static int is_dangerous_ioctl(unsigned long cmd) {
    switch (cmd) {
        /* TTY hijack / input injection */
        case TIOCSTI:   
        case TIOCSCTTY: 


        /* network / interface control */
        case SIOCSIFFLAGS:
        case SIOCSIFADDR:
        case SIOCSIFNETMASK:

            return 1;

        default:
            return 0;
    }
}


int ioctl_16_policy(pid_t pid, char *arg0, char *arg1, char *arg2){
    char target[256];

    if (!arg0 || !arg1 || !arg2) {
        fprintf(stderr, "[ioctl] Invalid arguments\n");
        return 0;
    }

    int fd = atoi(arg0);
    unsigned long cmd = strtoul(arg1, NULL, 10);
    unsigned long argp = strtoul(arg2, NULL, 10);

    /* resolve fd target */
    if (get_fd_target(pid, fd, target, sizeof(target)) < 0) {
        fprintf(stderr, "[ioctl] Cannot resolve fd %d\n", fd);
        return 0;
    }

    fd_type_t type = classify_fd(target);

    /* policy: device / proc fd */
    if (type == FD_DEV || type == FD_PROC) {
        fprintf(stderr,
                "[ioctl] Dangerous ioctl on %s (fd=%d)\n",
                target, fd);
        return 0;
    }

    /* policy: ioctl command */
    if (is_dangerous_ioctl(cmd)) {
        fprintf(stderr,
                "[ioctl] Dangerous ioctl cmd: 0x%lx\n",
                cmd);
        return 0;
    }

    /* policy: pointer safety */
    if (!is_safe_ptr(argp)) {
        fprintf(stderr,
                "[ioctl] Unsafe arg pointer: 0x%lx\n",
                argp);
        return 0;
    }

    return 1; /* ALLOW */
}
