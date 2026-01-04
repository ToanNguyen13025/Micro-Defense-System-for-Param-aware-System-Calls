#include "syscall_policy.h"
#include <string.h>

fd_type_t classify_fd(const char *t) {
    if (!t) return FD_UNKNOWN;

    if (strncmp(t, "socket:", 7) == 0)
        return FD_SOCKET;
    if (strncmp(t, "pipe:", 5) == 0)
        return FD_PIPE;
    if (strncmp(t, "/proc", 5) == 0)
        return FD_PROC;
    if (strncmp(t, "/dev", 4) == 0)
        return FD_DEV;
    if (t[0] == '/')
        return FD_REGULAR;

    return FD_UNKNOWN;
}
