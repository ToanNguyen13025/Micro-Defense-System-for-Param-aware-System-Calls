#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"

static int is_privileged_uid(uid_t uid) {
    /* root or system users */
    if (uid == 0) return 1;
    if (uid < 1000) return 1;  /* typical system UID range */
    return 0;
}

int setuid_105_policy(pid_t pid, char *arg0){
    if (!arg0) {
        fprintf(stderr, "[setuid] Invalid arguments\n");
        return 0;
    }

    uid_t new_uid = (uid_t)atoi(arg0);
    uid_t cur_uid = getuid();
    uid_t eff_uid = geteuid();

    /* deny privilege escalation */
    if (new_uid < cur_uid || new_uid < eff_uid) {
        fprintf(stderr,
                "[setuid] Privilege escalation denied: %d -> %d\n",
                cur_uid, new_uid);
        return 0;
    }

    /* deny switching to privileged/system UID */
    if (is_privileged_uid(new_uid)) {
        fprintf(stderr,
                "[setuid] Dangerous target UID denied: %d\n",
                new_uid);
        return 0;
    }

    /* allow no-op or drop-privilege only */
    return 1; /* ALLOW */
}
