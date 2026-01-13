#include <sys/stat.h>
#include <stdio.h>

int main() {
    /* user-space file, safe permission */
    if (chmod("/tmp/mds_chmod_ok.txt", 0644) < 0) {
        perror("chmod");
        return 1;
    }
    return 0;
}
