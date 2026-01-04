#include <sys/mman.h>
#include <stdio.h>
#include <string.h>

int main() {
    /* ALLOW: RW anonymous */
    void *p1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("p1=%p\n", p1);

    // /* DENY: RWX shellcode style */
    // void *p2 = mmap(NULL, 4096,
    //                 PROT_READ | PROT_WRITE | PROT_EXEC,
    //                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // printf("p2=%p\n", p2);

    return 0;
}
