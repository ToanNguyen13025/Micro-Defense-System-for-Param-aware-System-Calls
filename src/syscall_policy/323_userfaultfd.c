#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"


int userfaultfd_323_policy(pid_t pid, char *arg0){
    if (!arg0) {
        fprintf(stderr, "[userfaultfd] Invalid arguments\n");
        return 0;
    }

    int flags = atoi(arg0);

    (void)pid;

    /* deny all usages */
    fprintf(stderr,
            "[userfaultfd] Deny userfaultfd usage (flags=0x%x)\n",
            flags);

    return 0;
}
