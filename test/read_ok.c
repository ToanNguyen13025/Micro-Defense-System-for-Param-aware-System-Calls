#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    char buf[16];
    int fd = open("/etc/hostname", O_RDONLY);
    read(fd, buf, sizeof(buf));
    close(fd);
    return 0;
}
