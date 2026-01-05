#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <sys/types.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"

#define USER_SPACE_MAX 0x00007fffffffffffUL


static int is_safe_ptr(unsigned long ptr) {
    return ptr > 0 && ptr < USER_SPACE_MAX;
}


static int is_dangerous_bpf_cmd(int cmd) {
    switch (cmd) {

        /* load BPF program into kernel */
        case BPF_PROG_LOAD:

        /* inspect kernel maps */
        case BPF_MAP_GET_FD_BY_ID:
        case BPF_MAP_GET_NEXT_ID:
        case BPF_MAP_LOOKUP_ELEM:
        case BPF_MAP_UPDATE_ELEM:
        case BPF_MAP_DELETE_ELEM:

        /* inspect kernel programs */
        case BPF_PROG_GET_FD_BY_ID:
        case BPF_PROG_GET_NEXT_ID:

        /* attach / detach kernel hooks */
        case BPF_PROG_ATTACH:
        case BPF_PROG_DETACH:

            return 1;

        default:
            return 0;
    }
}

int bpf_321_policy(pid_t pid, char *arg0, char *arg1, char *arg2){
    if (!arg0 || !arg1 || !arg2) {
        fprintf(stderr, "[bpf] Invalid arguments\n");
        return 0;
    }

    int cmd = atoi(arg0);
    unsigned long attr_ptr = strtoul(arg1, NULL, 10);
    unsigned int size = (unsigned int)strtoul(arg2, NULL, 10);

    (void)pid;

    /* policy: pointer safety */
    if (!is_safe_ptr(attr_ptr)) {
        fprintf(stderr,
                "[bpf] Unsafe attr pointer: 0x%lx\n",
                attr_ptr);
        return 0;
    }

    /* policy: command */
    if (is_dangerous_bpf_cmd(cmd)) {
        fprintf(stderr,
                "[bpf] Dangerous bpf command denied: %d\n",
                cmd);
        return 0;
    }

    /* policy: attribute size sanity */
    if (size == 0 || size > 4096) {
        fprintf(stderr,
                "[bpf] Suspicious attr size: %u\n",
                size);
        return 0;
    }

    return 1; /* ALLOW */
}
