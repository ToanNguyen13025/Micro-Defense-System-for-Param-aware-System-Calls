#ifndef UTIL_H
#define UTIL_H
#include <unistd.h>

int get_fd_target(pid_t pid, int fd, char *out, size_t size);
int read_child_string(pid_t pid, unsigned long addr, char *buf, size_t max_len);
#endif