#ifndef SYSCALL_POLICY_H
#define SYSCALL_POLICY_H

#include <sys/types.h>
#include <stddef.h>

typedef enum {
    FD_REGULAR = 0,
    FD_SOCKET,
    FD_PIPE,
    FD_PROC,
    FD_DEV,
    FD_UNKNOWN
} fd_type_t;

typedef enum {
    PROC_TRUSTED = 0,
    PROC_SEMI_TRUSTED,
    PROC_UNTRUSTED
} proc_trust_t;

fd_type_t classify_fd(const char *fd_target);

int read_0_policy(pid_t pid, char *arg1, char *arg2, char *arg3);
int write_1_policy(pid_t pid, char *arg1, char *arg2, char *arg3);
int open_2_policy(pid_t pid, char *arg0, char *arg1, char *arg2);
int mmap_9_policy(pid_t pid, char *arg0, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5);
int ioctl_16_policy(pid_t pid, char *arg0, char *arg1, char *arg2);
int socket_41_policy(pid_t pid, char *arg0, char *arg1, char *arg2);
int connect_42_policy(pid_t pid, char *arg0, char *arg1, char *arg2);
int kill_62_policy(pid_t tracer_pid, char *arg0, char *arg1);
int chmod_90_policy(pid_t tracer_pid, char *arg0, char *arg1);
int ptrace_101_policy(pid_t tracer_pid, char *arg0, char *arg1, char *arg2, char *arg3);
int setuid_105_policy(pid_t pid, char *arg0);
int setgid_106_policy(pid_t pid, char *arg0);
int openat_257_policy(pid_t pid, char *arg0, char *arg1, char *arg2, char *arg3);
int bpf_321_policy(pid_t pid, char *arg0, char *arg1, char *arg2);
int userfaultfd_323_policy(pid_t pid, char *arg0);


#endif
