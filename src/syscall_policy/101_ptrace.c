#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"


static int is_dangerous_request(long request) {
    switch (request) {

        /* attach / seize another process */
        case PTRACE_ATTACH:
        case PTRACE_SEIZE:

        /* control execution */
        case PTRACE_CONT:
        case PTRACE_SYSCALL:
        case PTRACE_SINGLESTEP:

        /* modify registers / memory */
        case PTRACE_POKEDATA:
        case PTRACE_POKETEXT:
        case PTRACE_SETREGS:
        case PTRACE_SETOPTIONS:

        /* detach can hide tracing */
        case PTRACE_DETACH:
            return 1;

        default:
            return 0;
    }
}


int ptrace_101_policy(pid_t tracer_pid, char *arg0, char *arg1, char *arg2, char *arg3) {
    if (!arg0 || !arg1 || !arg2 || !arg3) {
        fprintf(stderr, "[ptrace] Invalid arguments\n");
        return 0;
    }

    long request = strtol(arg0, NULL, 10);
    pid_t target = (pid_t)atoi(arg1);
    unsigned long addr = strtoul(arg2, NULL, 10);
    unsigned long data = strtoul(arg3, NULL, 10);

    (void)addr;
    (void)data;

    /* allow self tracing declaration */
    if (request == PTRACE_TRACEME) {
        return 1;
    }

    /* deny attaching to any other process */
    if (is_dangerous_request(request)) {
        fprintf(stderr,
                "[ptrace] Dangerous request %ld on pid %d\n",
                request, target);
        return 0;
    }

    /* default: deny everything else */
    fprintf(stderr,
            "[ptrace] Deny ptrace request %ld\n",
            request);
    return 0;
}
