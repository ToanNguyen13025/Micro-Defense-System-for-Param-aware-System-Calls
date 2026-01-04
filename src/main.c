#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#include "tracer.h"

int main(int argc, char **argv) {
    if (argc < 2){
        printf("Usage: %s <program>\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();

    if (pid < 0){
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } 
    else if (pid == 0){   
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
            perror("ptrace_traceme failed");
            exit(EXIT_FAILURE);
        }

        execvp(argv[1], argv+1);
        perror("execvp failed");
        exit(EXIT_FAILURE);
    } 
    else {
        printf("Parent PID: %d, Child PID: %d\n", getpid(), pid);
        fflush(stdout);

        trace_process(pid); 
    }

    return 0;
}
