#include <pcap.h>           // libpcap 核心功能（必需）
#include <stdio.h>          // 标准输入输出（printf、fprintf等）
#include <stdlib.h>         // 标准库（exit、malloc等）
#include <string.h>         // 字符串操作（strerror等）
#include <arpa/inet.h>      // 网络地址转换（inet_ntoa等）
#include <netinet/ip.h>     // IP 包头结构（struct iphdr）
#include <netinet/tcp.h>    // TCP 包头结构（struct tcphdr）
#include <netinet/udp.h>    // UDP 包头结构（struct udphdr）
#include <netinet/if_ether.h> // 以太网帧结构（struct ethhdr）
#include <sys/time.h>       // 时间结构（struct timeval）

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
    pcap_freealldevs(intf);
    intf = NULL;
    return 0;
}

int cap_netinfo(char *dev){

    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;                    // 网络地址和掩码

    // 获取网络地址和掩码
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    // 将二进制地址转换为可读字符串
    struct in_addr addr;
    addr.s_addr = net;
    printf("Network: %s\n", inet_ntoa(addr));

    addr.s_addr = mask;
    printf("Netmask: %s\n", inet_ntoa(addr));

    return 0;
}

int cap_dns_info(char *target_dev) {
    char errbuf[PCAP_BUF_SIZE];

    bpf_u_int32 net, mask;                    // 网络地址和掩码

    // 获取网络地址和掩码
    if (pcap_lookupnet(target_dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    pcap_t *handle = pcap_open_live(
        target_dev,      // 接口名称
        65535,           // 捕获完整数据包（snaplen = 65535）
        1,               // 混杂模式（1=启用）
        1000,             // 超时时间（毫秒）
        errbuf           // 错误缓冲区
    );

    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    struct bpf_program filter;
    char filter_exp[] = "udp port 53";  // 过滤 HTTP 流量

    // 编译过滤器规则
    if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Filter compile error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // 应用过滤器
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Filter set error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // 释放过滤器资源
    pcap_freecode(&filter);

    // 定义回调函数（见第6步）
    void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes);

    // 持续抓包（count=-1 表示无限循环）
    pcap_loop(handle, -1, packet_handler, NULL);


    return 0;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    // 跳过以太网头（14字节）
    const u_char *ip_packet = bytes + 14;

    // 解析 IPv4 头前 20 字节
    uint8_t ip_hl = (ip_packet[0] & 0x0F) * 4;  // 计算 IP 头长度
    uint32_t src_ip = *(uint32_t*)(ip_packet + 12); // 源 IP（偏移 12）
    uint32_t dst_ip = *(uint32_t*)(ip_packet + 16); // 目标 IP（偏移 16）

    struct in_addr addr;
    addr.s_addr = src_ip;
    printf("Source IP: %s\n", inet_ntoa(addr));
    addr.s_addr = dst_ip;
    printf("Dest IP: %s\n", inet_ntoa(addr));
}
