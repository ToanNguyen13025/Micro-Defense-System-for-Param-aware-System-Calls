#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"

static int is_dangerous_signal(int sig) {
    switch (sig) {
        case SIGKILL:   /* cannot be caught */
        case SIGSTOP:   /* cannot be caught */
            return 1;
        default:
            return 0;
    }
}

static int is_control_signal(int sig) {
    switch (sig) {
        case SIGTERM:
        case SIGINT:
        case SIGQUIT:
        case SIGHUP:
            return 1;
        default:
            return 0;
    }
}


int kill_62_policy(pid_t tracer_pid, char *arg0, char *arg1){
    if (!arg0 || !arg1) {
        fprintf(stderr, "[kill] Invalid arguments\n");
        return 0;
    }

    pid_t target_pid = (pid_t)atoi(arg0);
    int sig = atoi(arg1);

    /* kill(0, sig) -> process group */
    if (target_pid == 0) {
        fprintf(stderr,
                "[kill] Deny process-group signal: sig=%d\n",
                sig);
        return 0;
    }

    /* kill(-1, sig) -> all processes */
    if (target_pid == -1) {
        fprintf(stderr,
                "[kill] Deny broadcast signal: sig=%d\n",
                sig);
        return 0;
    }

    /* policy: dangerous signals */
    if (is_dangerous_signal(sig)) {
        fprintf(stderr,
                "[kill] Dangerous signal denied: sig=%d\n",
                sig);
        return 0;
    }

    /* policy: self-signal allowed */
    if (target_pid == tracer_pid) {
        return 1;
    }

    /* policy: control signals only to children */
    if (is_control_signal(sig)) {
        if (!is_child_process(tracer_pid, target_pid)) {
            fprintf(stderr,
                    "[kill] Deny signal %d to non-child pid=%d\n",
                    sig, target_pid);
            return 0;
        }
        return 1;
    }

    /* default: deny everything else */
    fprintf(stderr,
            "[kill] Deny signal sig=%d to pid=%d\n",
            sig, target_pid);
    return 0;
}
