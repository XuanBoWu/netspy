#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <nids.h>
#include "uthash.h"

#define MAX_PROCESS_NAME 256

typedef struct {
    pid_t pid;
    char* process_name;
} process_info;

long port_inode(u_short port);
void *  find_process_by_inode(ino_t target_inode);