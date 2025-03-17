#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

// 存储本地IP的结构体（使用struct in_addr存储二进制格式）
struct local_ip {
    struct in_addr addr;  
    struct local_ip *next;
};

struct local_ip *local_ips = NULL;

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

// 释放链表内存
void free_ips() {
    struct local_ip *current = local_ips;
    while (current) {
        struct local_ip *next = current->next;
        free(current);
        current = next;
    }
}

int main() {
    refresh_local_ips();
    
    // 正确遍历链表（使用指针而非结构体复制）
    struct local_ip *current = local_ips;
    while (current) {
        // 按需转换为字符串输出
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(current->addr), ip_str, INET_ADDRSTRLEN);
        printf("IP: %s\n", ip_str);
        
        current = current->next;
    }
    
    free_ips();  // 释放内存
    return 0;
}
