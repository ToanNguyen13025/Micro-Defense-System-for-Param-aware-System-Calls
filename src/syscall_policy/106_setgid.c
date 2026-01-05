#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"


static int is_privileged_gid(gid_t gid) {
    if (gid == 0) return 1;
    if (gid < 1000) return 1; 
    return 0;
}


int setgid_106_policy(pid_t pid, char *arg0){
    if (!arg0) {
        fprintf(stderr, "[setgid] Invalid arguments\n");
        return 0;
    }

    gid_t new_gid = (gid_t)atoi(arg0);
    gid_t cur_gid = getgid();
    gid_t eff_gid = getegid();

    /* deny privilege escalation */
    if (new_gid < cur_gid || new_gid < eff_gid) {
        fprintf(stderr,
                "[setgid] Privilege escalation denied: %d -> %d\n",
                cur_gid, new_gid);
        return 0;
    }

    /* deny switching to privileged/system group */
    if (is_privileged_gid(new_gid)) {
        fprintf(stderr,
                "[setgid] Dangerous target GID denied: %d\n",
                new_gid);
        return 0;
    }

    /* allow no-op or drop-privilege only */
    return 1; /* ALLOW */
}
