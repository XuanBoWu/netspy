#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "net.h"


int print_interface(){
    char buf_err[PCAP_BUF_SIZE];
    pcap_if_t *intf;

    if (pcap_findalldevs(&intf, buf_err) != 0){

        perror("getifaddrs");
        exit(1);
    } else {
        printf("Interface info:\n");
    }

    int intf_num = 0;
    for (pcap_if_t *d = intf; d != NULL; d = d->next ) {
        intf_num++;
        printf("%d[%s]:", intf_num, d->name);

        // macOS 上无效
        if (d->description != NULL) {
            printf("%s\n", d->description);
        } else {
            printf("\n");
        }

        for (pcap_addr_t *addr = d->addresses; addr != NULL; addr = addr->next) {
        char buf[INET6_ADDRSTRLEN]; // 足够存储 IPv4 或 IPv6 地址

        if (addr->addr == NULL) {
            continue; // 跳过无效地址
        }

        if (addr->addr->sa_family == AF_INET) {
            // 处理 IPv4 地址
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr->addr;
            inet_ntop(AF_INET, &(addr_in->sin_addr), buf, sizeof(buf));
            printf("  IPv4 Address: %s\n", buf);
        } else if (addr->addr->sa_family == AF_INET6) {
            // 处理 IPv6 地址
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr->addr;
            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), buf, sizeof(buf));
            printf("  IPv6 Address: %s\n", buf);
        }
    }

    }

    return 0;
}