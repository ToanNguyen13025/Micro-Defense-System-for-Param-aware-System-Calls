#ifndef SYSCALL_H
#define SYSCALL_H
#include <unistd.h>

int syscall_decode(pid_t pid, struct user_regs_struct *regs);

#endif