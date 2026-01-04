#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"

#define USER_SPACE_MAX 0x00007fffffffffffUL
#define MAX_MMAP_SIZE  (16 * 1024 * 1024) /* 16MB */


static int is_safe_addr(unsigned long addr) {
    if (addr == 0) return 1;
    return addr < USER_SPACE_MAX;
}

static int is_safe_length(unsigned long len) {
    return len > 0 && len <= MAX_MMAP_SIZE;
}

static int is_dangerous_prot(int prot) {
    if ((prot & PROT_READ) &&
        (prot & PROT_WRITE) &&
        (prot & PROT_EXEC))
        return 1;

    if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
        return 1;

    return 0;
}

static int is_dangerous_flags(int flags) {
    if ((flags & MAP_ANONYMOUS) && (flags & MAP_PRIVATE))
        return 0; 

    return 0;
}


int mmap_9_policy(pid_t pid, char *arg0, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5){
    if (!arg0 || !arg1 || !arg2 || !arg3 || !arg4 || !arg5) {
        fprintf(stderr, "[mmap] Invalid arguments\n");
        return 0;
    }

    unsigned long addr   = strtoul(arg0, NULL, 10);
    unsigned long length = strtoul(arg1, NULL, 10);
    int prot  = atoi(arg2);
    int flags = atoi(arg3);
    int fd    = atoi(arg4);
    unsigned long offset = strtoul(arg5, NULL, 10);

    (void)pid;
    (void)fd;
    (void)offset;

    /* policy: address */
    if (!is_safe_addr(addr)) {
        fprintf(stderr, "[mmap] Unsafe address: 0x%lx\n", addr);
        return 0;
    }

    /* policy: length */
    if (!is_safe_length(length)) {
        fprintf(stderr, "[mmap] Unsafe length: %lu\n", length);
        return 0;
    }

    /* policy: protection */
    if (is_dangerous_prot(prot)) {
        fprintf(stderr, "[mmap] Dangerous protection flags: 0x%x\n", prot);
        return 0;
    }

    /* policy: executable anonymous memory */
    if (is_dangerous_flags(flags)) {
        fprintf(stderr, "[mmap] Anonymous executable mapping denied\n");
        return 0;
    }

    return 1; /* ALLOW */
}
