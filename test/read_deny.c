#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    int fd;
    char buf[16];  // buffer hợp lệ, user-space

    fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* count = 8192 > MAX_READ_SIZE (4096) */
    read(fd, buf, 8192);

    close(fd);
    return 0;
}
