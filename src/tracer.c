#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "syscall.h"
void trace_process(pid_t pid) {
    int status;
    struct user_regs_struct regs;
    int in_syscall = 0;

    /* initial stop */
    waitpid(pid, &status, 0);

    /* enable syscall-stop flag */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

    while (1) {
        /* run until next syscall entry/exit */
        printf("[trace] stop sig=%d in_syscall=%d\n",
            WSTOPSIG(status), in_syscall);
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            break;

        if (waitpid(pid, &status, 0) == -1)
            break;

        if (WIFEXITED(status)) {
            printf("[tracer] child exited\n");
            break;
        }

        /* only handle syscall-stops */
        if (!WIFSTOPPED(status) || !(WSTOPSIG(status) & 0x80))
            continue;

        ptrace(PTRACE_GETREGS, pid, 0, &regs);

        if (!in_syscall) {
            /* ===== syscall ENTRY ===== */
            in_syscall = 1;

            int allowed = syscall_decode(pid, &regs);
            if (!allowed) {
                fprintf(stderr, "[tracer] syscall denied\n");
                ptrace(PTRACE_KILL, pid, 0, 0);
                break;
            }

        } else {
            /* ===== syscall EXIT ===== */
            in_syscall = 0;
            /* do nothing */
        }
    }
}

