#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"
#include <netinet/in.h>


static int is_dangerous_domain(int domain) {
    switch (domain) {
        case AF_INET:   /* IPv4 */
        case AF_INET6:  /* IPv6 */
            return 1;   /* network socket */
        default:
            return 0;
    }
}

static int is_dangerous_type(int type) {
    /* mask flags like SOCK_NONBLOCK */
    int base = type & 0xf;

    switch (base) {
        case SOCK_STREAM: /* TCP */
        case SOCK_DGRAM:  /* UDP */
            return 1;
        default:
            return 0;
    }
}

static int is_dangerous_protocol(int proto) {
    /* proto == 0 lets kernel choose */
    if (proto == IPPROTO_TCP) return 1;
    if (proto == IPPROTO_UDP) return 1;
    return 0;
}


int socket_41_policy(pid_t pid, char *arg0, char *arg1, char *arg2) {
    (void)pid;

    if (!arg0 || !arg1 || !arg2) {
        fprintf(stderr, "[socket] Invalid arguments\n");
        return 0;
    }

    int domain   = atoi(arg0);
    int type     = atoi(arg1);
    int protocol = atoi(arg2);

    /* policy: domain */
    if (is_dangerous_domain(domain)) {
        fprintf(stderr,
                "[socket] Dangerous domain: %d\n",
                domain);
        return 0;
    }

    /* policy: type */
    if (is_dangerous_type(type)) {
        fprintf(stderr,
                "[socket] Dangerous socket type: %d\n",
                type);
        return 0;
    }

    /* policy: protocol */
    if (is_dangerous_protocol(protocol)) {
        fprintf(stderr,
                "[socket] Dangerous protocol: %d\n",
                protocol);
        return 0;
    }

    return 1; /* ALLOW */
}
