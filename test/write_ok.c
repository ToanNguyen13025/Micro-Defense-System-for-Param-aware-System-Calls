#include <unistd.h>
#include <string.h>

int main() {
    const char *msg = "write OK via inherited fd\n";

    /* fd=1 is inherited, not opened by process */
    write(1, msg, strlen(msg));

    return 0;
}

//echo "test" > /tmp/mds_write_ok.txt
//sudo ./tracer ./test/write_ok > /tmp/mds_write_ok.txt
//cat /tmp/mds_write_ok.txt
