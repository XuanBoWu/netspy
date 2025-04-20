#pragma once
#include <arpa/inet.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <sys/types.h>
#include "hash.h"
#include "inode.h"

#define REFRESH_RATE_HZ 200 // 刷新频率50Hz

typedef struct {
    in_addr_t local_ip;
    u_short local_port;
    in_addr_t rem_ip;
    u_short rem_port;
    ino_t inode;
    pid_t pid;
    char* process_name;
} socket_info;

void* refresh_socket(void * data);
socket_info* find_by_local_port(Queue* queue, u_short port);