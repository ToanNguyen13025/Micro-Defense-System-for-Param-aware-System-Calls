#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"

#define USER_SPACE_MAX 0x00007fffffffffffUL
#define MAX_PATH_LEN 256


static int is_safe_ptr(unsigned long ptr) {
    return ptr > 0 && ptr < USER_SPACE_MAX;
}

static int is_dangerous_mode(mode_t mode) {
    /* SUID / SGID */
    if (mode & S_ISUID) return 1;
    if (mode & S_ISGID) return 1;

    /* world writable or world executable */
    if (mode & S_IWOTH) return 1;
    if (mode & S_IXOTH) return 1;

    return 0;
}

static int is_dangerous_path(const char *path) {
    if (!path) return 1;

    /* sensitive directories */
    if (!strncmp(path, "/proc", 5)) return 1;
    if (!strncmp(path, "/sys", 4))  return 1;
    if (!strncmp(path, "/dev", 4))  return 1;
    if (!strncmp(path, "/etc", 4))  return 1;

    /* path traversal */
    if (strstr(path, "..")) return 1;

    return 0;
}


int chmod_90_policy(pid_t pid, char *arg0, char *arg1)
{
    char path[MAX_PATH_LEN];

    if (!arg0 || !arg1) {
        fprintf(stderr, "[chmod] Invalid arguments\n");
        return 0;
    }

    unsigned long path_ptr = strtoul(arg0, NULL, 10);
    mode_t mode = (mode_t)strtoul(arg1, NULL, 8);

    /* policy: pointer safety */
    if (!is_safe_ptr(path_ptr)) {
        fprintf(stderr,
                "[chmod] Unsafe pathname pointer: 0x%lx\n",
                path_ptr);
        return 0;
    }

    /* read pathname from child */
    if (read_child_string(pid, path, path, sizeof(path)) < 0) {
        fprintf(stderr,
                "[chmod] Cannot read pathname\n");
        return 0;
    }

    /* policy: path */
    if (is_dangerous_path(path)) {
        fprintf(stderr,
                "[chmod] Dangerous path: %s\n",
                path);
        return 0;
    }

    /* policy: mode */
    if (is_dangerous_mode(mode)) {
        fprintf(stderr,
                "[chmod] Dangerous mode: %o\n",
                mode);
        return 0;
    }

    return 1; /* ALLOW */
}
