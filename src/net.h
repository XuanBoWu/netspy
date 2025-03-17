/**
net.h
 */
#include <stdio.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/udp.h>

// 存储本地IP的结构体（使用struct in_addr存储二进制格式）
struct local_ip {
    struct in_addr addr;  
    struct local_ip *next;
};

extern struct local_ip *local_ips;

void refresh_local_ips();

int is_local_ip(struct in_addr addr);