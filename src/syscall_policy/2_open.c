#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"
#include <sys/stat.h>

#define MAX_PATH_LEN 256
#define USER_SPACE_MAX 0x00007fffffffffffUL


static int is_safe_ptr(unsigned long ptr) {
    return ptr > 0 && ptr < USER_SPACE_MAX;
}

static int is_safe_path(const char *path) {
    if (!path) return 0;

    /* path traversal */
    if (strstr(path, "..")) return 0;

    /* sensitive directories */
    if (!strncmp(path, "/proc", 5)) return 0;
    if (!strncmp(path, "/dev", 4))  return 0;
    if (!strncmp(path, "/sys", 4))  return 0;
    if (!strncmp(path, "/etc", 4))  return 0;

    return 1;
}

static int is_dangerous_flags(int flags) {
    if (flags & O_WRONLY) return 1;
    if (flags & O_RDWR)   return 1;
    if (flags & O_TRUNC)  return 1;
    if (flags & O_CREAT)  return 1;
    return 0;
}

static int is_dangerous_mode(int mode) {
    if ((mode & 0777) == 0777) return 1;
    if (mode & S_ISUID) return 1;
    if (mode & S_ISGID) return 1;
    return 0;
}


int open_2_policy(pid_t pid, char *arg0, char *arg1, char *arg2) {
    char path[MAX_PATH_LEN];

    if (!arg0 || !arg1 || !arg2) {
        fprintf(stderr, "[open] Invalid arguments\n");
        return 0;
    }

    unsigned long pathname_ptr = strtoul(arg0, NULL, 10);
    int flags = atoi(arg1);
    int mode  = atoi(arg2);

    /* policy: pathname pointer */
    if (!is_safe_ptr(pathname_ptr)) {
        fprintf(stderr, "[open] Unsafe pathname pointer: 0x%lx\n", pathname_ptr);
        return 0;
    }

    /* read pathname from child memory */
    if (read_child_string(pid, pathname_ptr, path, sizeof(path)) < 0) {
        fprintf(stderr, "[open] Cannot read pathname\n");
        return 0;
    }

    /* policy: path */
    if (!is_safe_path(path)) {
        fprintf(stderr, "[open] Dangerous path: %s\n", path);
        return 0;
    }

    /* policy: flags */
    if (is_dangerous_flags(flags)) {
        fprintf(stderr, "[open] Dangerous flags: 0x%x\n", flags);
        return 0;
    }

    /* policy: mode */
    if (flags & O_CREAT) {
        if (is_dangerous_mode(mode)) {
            fprintf(stderr, "[open] Dangerous file mode: %o\n", mode);
            return 0;
        }
    }

    return 1; /* ALLOW */
}
