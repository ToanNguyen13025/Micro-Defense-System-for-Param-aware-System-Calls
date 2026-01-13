#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define BIG_SIZE 8192

int main() {
    int fd;
    static char buf[BIG_SIZE];

    memset(buf, 'A', sizeof(buf));

    fd = open("/tmp/mds_write_deny.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* count = 8192 > MAX_WRITE_SIZE (4096) */
    write(fd, buf, sizeof(buf));

    close(fd);
    return 0;
}
