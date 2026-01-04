#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "policy.h"


#define MAX_ARG_STR 32

int handle_syscall(pid_t pid, long syscall_num, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {

    char arg_str[6][MAX_ARG_STR];
    char *arg[6];

    long raw_arg[6] = {arg1, arg2, arg3, arg4, arg5, arg6};
    printf("[decode] syscall=%ld\n", syscall_num);

    /* convert long → char* */
    for (int i = 0; i < 6; i++) {
        snprintf(arg_str[i], MAX_ARG_STR, "%ld", raw_arg[i]);
        arg[i] = arg_str[i];
    }

    printf("Syscall %ld args: %s %s %s %s %s %s\n",
        syscall_num,
        arg[0] ? arg[0] : "-",
        arg[1] ? arg[1] : "-",
        arg[2] ? arg[2] : "-",
        arg[3] ? arg[3] : "-",
        arg[4] ? arg[4] : "-",
        arg[5] ? arg[5] : "-");
 
    return check_policy(pid, syscall_num, arg);
}




#ifdef __x86_64__
int syscall_decode(pid_t pid, struct user_regs_struct *regs) {
    if (regs == NULL) {
        fprintf(stderr, "Error: NULL pointer to user_regs_struct\n");
        return 0;
    }

    long syscall_num = regs->orig_rax;
    long arg1 = regs->rdi;
    long arg2 = regs->rsi;
    long arg3 = regs->rdx;
    long arg4 = regs->r10;
    long arg5 = regs->r9;
    long arg6 = regs->r8;

    return handle_syscall(pid, syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
}
#endif

#ifdef __arm__
int syscall_decode(pid_t pid, struct user_regs_struct *regs) {
    if (regs == NULL) {
        fprintf(stderr, "Error: NULL pointer to user_regs_struct\n");
        return 0;
    }

    long syscall_num = regs->uregs[7]; 
    long arg1 = regs->uregs[0];
    long arg2 = regs->uregs[1];
    long arg3 = regs->uregs[2];
    long arg4 = regs->uregs[3];
    long arg5 = regs->uregs[4];
    long arg6 = regs->uregs[5];

    return handle_syscall(pid, syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
}
#endif

#ifdef __riscv
int syscall_decode(pid_t pid, struct user_regs_struct *regs) {
    if (regs == NULL) {
        fprintf(stderr, "Error: NULL pointer to user_regs_struct\n");
        return 0;
    }

    long syscall_num = regs->a7;
    long arg1 = regs->a0;
    long arg2 = regs->a1;
    long arg3 = regs->a2;
    long arg4 = regs->a3;
    long arg5 = regs->a4;
    long arg6 = regs->a5;

    return handle_syscall(pid, syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
}
#endif