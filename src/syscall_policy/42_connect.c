#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "syscall_policy/syscall_policy.h"
#include "util.h"

#define USER_SPACE_MAX 0x00007fffffffffffUL

static int is_safe_ptr(unsigned long ptr) {
    return ptr > 0 && ptr < USER_SPACE_MAX;
}

static int is_allowed_ipv4(uint32_t ip_be) {
    uint32_t ip = ntohl(ip_be);

    /* 127.0.0.0/8 loopback */
    if ((ip & 0xff000000U) == 0x7f000000U) return 1;

    /* 10.0.0.0/8 */
    if ((ip & 0xff000000U) == 0x0a000000U) return 1;

    /* 172.16.0.0/12 */
    if ((ip & 0xfff00000U) == 0xac100000U) return 1;

    /* 192.168.0.0/16 */
    if ((ip & 0xffff0000U) == 0xc0a80000U) return 1;

    return 0; /* public IPv4 -> deny */
}

static int is_allowed_port(uint16_t port_be) {
    uint16_t port = ntohs(port_be);

    if (port == 53)  return 1;
    if (port == 80)  return 1;
    if (port == 443) return 1;

    return 0;
}

int connect_42_policy(pid_t pid, char *arg0, char *arg1, char *arg2){
    if (!arg0 || !arg1 || !arg2) {
        fprintf(stderr, "[connect] Invalid arguments\n");
        return 0;
    }

    unsigned long addr_ptr = strtoul(arg1, NULL, 10);
    socklen_t addrlen = (socklen_t)strtoul(arg2, NULL, 10);

    (void)pid;

    if (!is_safe_ptr(addr_ptr)) {
        fprintf(stderr, "[connect] Unsafe sockaddr pointer: 0x%lx\n", addr_ptr);
        return 0;
    }

    /* Read minimal sockaddr from child */
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));

    if (read_child_mem(pid, addr_ptr, &ss, addrlen < sizeof(ss) ? addrlen : sizeof(ss)) < 0) {
        fprintf(stderr, "[connect] Cannot read sockaddr\n");
        return 0;
    }

    /* Dispatch by family */
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)&ss;

        if (!is_allowed_ipv4(in->sin_addr.s_addr)) {
            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in->sin_addr, ipstr, sizeof(ipstr));
            fprintf(stderr,
                    "[connect] DENY IPv4 %s:%u\n",
                    ipstr, ntohs(in->sin_port));
            return 0;
        }

        if (!is_allowed_port(in->sin_port)) {
            fprintf(stderr,
                    "[connect] DENY port %u\n",
                    ntohs(in->sin_port));
            return 0;
        }

        return 1; /* ALLOW IPv4 private/loopback + allowed port */
    }

    if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;

        /* Allow IPv6 loopback ::1 only */
        static const struct in6_addr loop6 = IN6ADDR_LOOPBACK_INIT;
        if (memcmp(&in6->sin6_addr, &loop6, sizeof(loop6)) != 0) {
            char ip6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &in6->sin6_addr, ip6, sizeof(ip6));
            fprintf(stderr,
                    "[connect] DENY IPv6 %s:%u\n",
                    ip6, ntohs(in6->sin6_port));
            return 0;
        }

        if (!is_allowed_port(in6->sin6_port)) {
            fprintf(stderr,
                    "[connect] DENY port %u\n",
                    ntohs(in6->sin6_port));
            return 0;
        }

        return 1; /* ALLOW ::1 */
    }

    /* Other families: conservative allow */
    return 1;
}
