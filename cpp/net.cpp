#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <ldns/ldns.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "net.h"

// #define BUFSIZ 512
#define MAX_BUFFER_SIZE 1024


/* 以太网头结构 */
struct ethheader {
    u_char  ether_dhost[6]; /* 目标MAC地址 */
    u_char  ether_shost[6]; /* 源MAC地址 */
    u_short ether_type;     /* 网络层协议类型 */
};

typedef struct {
    char **ips;      // 存储 IP 字符串的指针数组
    size_t count;    // 当前存储的 IP 数量
    size_t capacity; // 当前数组容量
} IPList;

IPList* iplist_create() {
    IPList *list = malloc(sizeof(IPList));
    if (!list) return NULL;

    list->capacity = 16; // 初始容量
    list->count = 0;
    list->ips = malloc(list->capacity * sizeof(char*));
    if (!list->ips) {
        free(list);
        return NULL;
    }
    return list;
}

int iplist_append(IPList *list, const char *ip_str) {
    // 扩容检查
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity * 2;
        char **new_ips = realloc(list->ips, new_cap * sizeof(char*));
        if (!new_ips) return -1; // 扩容失败
        list->ips = new_ips;
        list->capacity = new_cap;
    }

    // 深拷贝字符串
    char *copy = strdup(ip_str);
    if (!copy) return -1;

    list->ips[list->count++] = copy;
    return 0;
}

void process_and_free_iplist(IPList *list) {
    if (!list) return;

    // for (size_t i = 0; i < list->count; i++) {
    //     printf("Stored IP: %s\n", list->ips[i]);
    // }

    // 释放每个字符串和数组
    for (size_t i = 0; i < list->count; i++) {
        free(list->ips[i]);
    }
    free(list->ips);
    free(list);
}

// 添加回调函数定义
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    /* 只处理IPv4数据包（0x0800是以太网类型代码） */
    if (ntohs(eth->ether_type) != 0x0800) return;

    /* 解析IP头 */
    struct ip *ip = (struct ip *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->ip_hl * 4;  /* IP头长度（32位字转字节） */

    /* 确保是UDP协议 */
    if (ip->ip_p != IPPROTO_UDP) return;

    /* 解析UDP头 */
    struct udphdr *udp = (struct udphdr *)((char *)ip + ip_header_len);

    /* 检查DNS端口（源或目的端口为53） */
    if (ntohs(udp->uh_sport) != 53 && ntohs(udp->uh_dport) != 53) return;

    /* 解析DNS头 */
    const u_char *dns_data = (u_char*)udp + sizeof(struct udphdr);
    size_t dns_data_len = ntohs(udp->uh_ulen) - sizeof(struct udphdr);

    // 使用ldns解析DNS数据
    ldns_pkt *dns_packet;
    ldns_status status = ldns_wire2pkt(&dns_packet, dns_data, dns_data_len);

    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "ldns_wire2pkt failed: %s\n", ldns_get_errorstr_by_id(status));
        return;
    }

    // 如果是请求包
    if (ldns_pkt_qr(dns_packet) != 1) {
        // uint16_t port = ntohs(udp->uh_sport);
        
        // char *process = get_process_by_port(port);
        // printf("请求的应用端口为：%d\n应用进程为：%s\n", port, process);
        // free(process); // 释放内存
        
        ldns_pkt_free(dns_packet);
        return;
    }

    // 获取查询部分 (Question Section)
    ldns_rr_list *questions = ldns_pkt_question(dns_packet);
    char *domain_str;
    if (questions) {
        for (size_t i = 0; i < ldns_rr_list_rr_count(questions); i++) { // 使用 ldns_rr_list_rr_count
            ldns_rr *question = ldns_rr_list_rr(questions, i);
            ldns_rdf *domain = ldns_rr_owner(question); // 获取域名
            if (domain) {
                domain_str = ldns_rdf2str(domain);
                // printf("Query Domain: %s\n", domain_str);
                // free(domain_str);
            }
        }
    }

    IPList *ip_list = iplist_create();
    if (!ip_list) {
        fprintf(stderr, "Failed to create IP list\n");
        return;
    }

    // 获取应答部分 (Answer Section)  只处理A记录
    ldns_rr_list *answers = ldns_pkt_answer(dns_packet);
    if (answers) {
        for (size_t i = 0; i < ldns_rr_list_rr_count(answers); i++) {  // 使用 ldns_rr_list_rr_count
            ldns_rr *answer = ldns_rr_list_rr(answers, i);

            // 只处理A记录 (IPv4地址)
            if (ldns_rr_get_type(answer) == LDNS_RR_TYPE_A) {
                ldns_rdf *ip_rdf = ldns_rr_rdf(answer, 0); // 获取IP地址
                if (ip_rdf) {
                    struct in_addr addr;
                    addr.s_addr = *(uint32_t*)ldns_rdf_data(ip_rdf); //直接从数据中取出
                    char *convertedIP = inet_ntoa(addr);
                    if (iplist_append(ip_list, convertedIP) != 0) {
                        fprintf(stderr, "Failed to add IPv4 to list\n");
                    }
                }
            } else if (ldns_rr_get_type(answer) == LDNS_RR_TYPE_AAAA){ //处理AAAA记录
                ldns_rdf *ip_rdf = ldns_rr_rdf(answer, 0);
                if(ip_rdf){
                        // 直接从 ldns_rdf 数据中提取 IPv6 地址
                    unsigned char *ipv6_data = ldns_rdf_data(ip_rdf);
                    char ipv6_str[INET6_ADDRSTRLEN];

                    if (inet_ntop(AF_INET6, ipv6_data, ipv6_str, INET6_ADDRSTRLEN) != NULL) {
                        if (iplist_append(ip_list, ipv6_str) != 0) {
                            fprintf(stderr, "Failed to add IPv6 to list\n");
                        }
                    }
                }
            }
        }
    }
    // 释放ldns_pkt
    ldns_pkt_free(dns_packet);

    /* 打印关键信息 */
    printf("\n=== 捕获到DNS数据包（长度：%d 字节） ===\n", header->len);
    printf("源IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
    printf("目的IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
    printf("UDP总长度: %d 字节\n", ntohs(udp->uh_ulen));
    printf("DNS数据长度: %lu 字节\n", ntohs(udp->uh_ulen) - sizeof(struct udphdr));
    printf("查询域名: %s\n", domain_str);
    for (size_t i = 0; i < ip_list->count; i++) {
        // printf("i = %zu\n", i);
        printf("    IP %lu: %s\n", i+1, ip_list->ips[i]);
    }

    process_and_free_iplist(ip_list);

}

int cap_netinfo(char *dev){
    pcap_t *handle; //pcap 会话句柄
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息缓冲
    struct bpf_program fp; // 编译后的过滤器
    char filter_exp[] = "udp port 53"; // 过滤表达式
    bpf_u_int32 mask; // 捕获设备的网络掩码
    bpf_u_int32 net; // 捕获设备的IP

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    
    handle = pcap_open_live(dev, BUFSIZ, 0, 500, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	    return(2);
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	    return(2);
    }

    
    // init_port_cache();

    printf("Starting packet capture...\n");
    int num_packets = -1; // -1 表示持续捕获，直到出错或中断
    if (pcap_loop(handle, num_packets, packet_handler, NULL) == -1) {
        fprintf(stderr, "Error in pcap_loop: %s\n", pcap_geterr(handle));
        return(2);
    }

    pcap_close(handle);
    return 0;
}

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