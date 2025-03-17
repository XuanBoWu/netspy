/**
net.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <ldns/ldns.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "net.h"


struct local_ip *local_ips = NULL;

// 释放链表内存
void free_ips() {
    struct local_ip *current = local_ips;
    while (current) {
        struct local_ip *next = current->next;
        free(current);
        current = next;
    }
}

int is_local_ip(struct in_addr addr) {
    refresh_local_ips();
    
    // 遍历链表（使用指针而非结构体复制）
    struct local_ip *current = local_ips;
    while (current) {
        
        if (current->addr.s_addr == addr.s_addr) {
            return 1; 
        }
        
        current = current->next;
    }
    return 0;
}

void refresh_local_ips() {
    struct ifaddrs *addrs, *tmp;
    getifaddrs(&addrs);
    tmp = addrs;
    
    while (tmp) {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *paddr = (struct sockaddr_in*)tmp->ifa_addr;
            struct local_ip *ip_node = malloc(sizeof(struct local_ip));
            
            // 直接存储二进制地址（无需转换字符串）
            ip_node->addr = paddr->sin_addr;
            ip_node->next = local_ips;
            local_ips = ip_node;
        }
        tmp = tmp->ifa_next;
    }
    freeifaddrs(addrs);
}