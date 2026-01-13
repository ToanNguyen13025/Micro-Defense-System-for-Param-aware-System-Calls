#include <sys/stat.h>

int main() {
    /* world-writable permission */
    chmod("/tmp/mds_chmod_ok.txt", 0777);
    return 0;
}
