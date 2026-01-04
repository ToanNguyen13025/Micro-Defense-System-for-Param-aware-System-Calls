#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>


int get_fd_target(pid_t pid, int fd, char *out, size_t size){
    char path[64];

    // /proc/<pid>/fd/<fd>
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
    ssize_t len = readlink(path, out, size - 1);
    if (len < 0) {
        return -1; // fd không tồn tại hoặc lỗi
    }

    out[len] = '\0'; // readlink không tự thêm null byte
    return 0;
}

int read_child_string(pid_t pid, unsigned long addr, char *buf, size_t max_len) {
    size_t copied = 0;

    if (!buf || max_len == 0) return -1;

    while (copied < max_len) {
        int errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, pid, addr + copied, NULL);
        if (data == -1 && errno) {
            return -1;
        }

        /* copy word byte-by-byte */
        for (size_t i = 0; i < sizeof(long); i++) {
            if (copied >= max_len) break;

            char c = (data >> (i * 8)) & 0xff;
            buf[copied++] = c;

            if (c == '\0') {
                return 0;
            }
        }
    }

    /* force terminate */
    buf[max_len - 1] = '\0';
    return 0;
}