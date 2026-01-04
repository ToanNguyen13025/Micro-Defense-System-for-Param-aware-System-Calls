#ifndef POLICY_H
#define POLICY_H
#include <unistd.h>


int check_policy(pid_t pid, long syscall, char *argv[]);

#endif