#include <fcntl.h>

int main() {
    /* Sensitive system file */
    open("/etc/shadow", O_RDONLY);
    return 0;
}
