#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    int fd;

    /* Read-only, regular file */
    fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    close(fd);
    return 0;
}
