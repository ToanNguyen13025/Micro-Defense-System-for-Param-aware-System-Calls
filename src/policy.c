#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "syscall_policy/syscall_policy.h"

int check_policy(pid_t pid, long syscall, char *argv[]){
    switch (syscall){
        case 0:
            if (!read_0_policy(pid, argv[0], argv[1], argv[2])){
                return 0;
            };
            break;
        case 1:
            if (!write_1_policy(pid, argv[0], argv[1], argv[2])){
                return 0;
            };
            break;
        case 2:
            if (!open_2_policy(pid, argv[0], argv[1], argv[2])){
                return 0;
            }
            break;
        case 9:
            if (!mmap_9_policy(pid, argv[0], argv[1], argv[2], argv[3], argv[4], argv[5])){
                return 0;
            }
            break;
        case 16:
            if (!ioctl_16_policy(pid, argv[0], argv[1], argv[2])){
                return 0;
            }
            break;
        case 41:
            if (!socket_41_policy(pid, argv[0], argv[1], argv[2])){
                return 0;
            }
            break;
        case 42:
            if (!connect_42_policy(pid, argv[0], argv[1], argv[2])){
                return 0;
            }
            break;
        case 62:
            if (!kill_62_policy(pid, argv[0], argv[1])){
                return 0;
            }
            break;
        case 90:
            if (!chmod_90_policy(pid, argv[0], argv[1])){
                return 0;
            }
            break;  
        case 101:
            if (!ptrace_101_policy(pid, argv[0], argv[1], argv[2], argv[3])){
                return 0;
            }
            break;
        case 105:
            if (!setuid_105_policy(pid, argv[0])){
                return 0;
            }
            break;
        case 106:
            if (!setgid_106_policy(pid, argv[0])){
                return 0;
            }
            break;   
        case 257:
            if (!openat_257_policy(pid, argv[0], argv[1], argv[2], argv[3])){
                return 0;
            }
            break;
        case 321:
            if (!bpf_321_policy(pid, argv[0], argv[1], argv[2])){
                    return 0;
            }
            break;
        case 323:
            if (!userfaultfd_323_policy(pid, argv[0])){
                return 0;
            }
            break;
        default:
            return 1;
    }
    return 1;
}