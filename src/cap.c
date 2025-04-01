#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <nids.h>
#include <sys/types.h>
#include "inode.h"
#include "net.h"

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

void print_udp_info(struct tuple4 *addr, char *buf, int len, struct ip *ip){
    // ==================== 打印四元组信息 ====================
    printf("\n============ UDP 数据包信息 ============\n");
    
    // 1. 转换网络字节序到主机字节序
    struct in_addr src_ip, dst_ip;
    src_ip.s_addr = addr->saddr;
    dst_ip.s_addr = addr->daddr;
    u_short src_port = addr->source;
    u_short dst_port = addr->dest;
    
    // 2. 打印连接四元组
    printf("[四元组信息]\n");
    printf("源IP: %-15s 源端口: %-5d\n", inet_ntoa(src_ip), src_port);
    printf("目的IP: %-15s 目的端口: %-5d\n", inet_ntoa(dst_ip), dst_port);
    
    // ==================== 打印IP头信息 ====================
    printf("\n[IP头信息]\n");
    printf("版本: IPV%d\n", ip->ip_v);  // 4或6
    printf("头长度: %d 字节\n", ip->ip_hl * 4);  // 头长度以4字节为单位
    printf("服务类型: 0x%02x\n", ip->ip_tos);
    printf("总长度: %d 字节\n", ntohs(ip->ip_len));
    printf("ID: 0x%04x\n", ntohs(ip->ip_id));
    printf("分片偏移: 0x%04x\n", ntohs(ip->ip_off) & 0x1FFF);
    printf("TTL: %d\n", ip->ip_ttl);
    printf("协议: %d (1=ICMP, 6=TCP, 17=UDP)\n", ip->ip_p);
    printf("校验和: 0x%04x\n", ntohs(ip->ip_sum));
    
    // 打印实际IP地址（可能与tuple4重复，但用于验证）
    struct in_addr ip_src, ip_dst;
    ip_src.s_addr = ip->ip_src.s_addr;
    ip_dst.s_addr = ip->ip_dst.s_addr;
    printf("IP头-源地址: %s\n", inet_ntoa(ip_src));
    printf("IP头-目的地址: %s\n", inet_ntoa(ip_dst));
    
    // ==================== 数据信息 ====================
    printf("\n[数据信息]\n");
    printf("Payload长度: %d 字节\n", len);
    printf("首16字节内容: ");
    for(int i=0; i<(len>16?16:len); i++) {
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("\n=========================================\n");
}

void udp_callback(struct tuple4 *addr, char *buf, int len, struct ip *ip) {
    // debug 打印数据包完整信息
    print_udp_info(addr, buf, len, ip);
    // IP协议 解析

    // 获取数据包 IP信息，nids已转换主机序，不需要转换
    // 获取源IP和目的IP的二进制形式
    struct in_addr src_ip, dst_ip;
    src_ip.s_addr = addr->saddr;
    dst_ip.s_addr = addr->daddr;

    //获取源IP和目的IP的字符串形式
    // 分别获取并保存IP字符串
    char src_ip_str[16]; // 足够存储IPv4地址的字符串
    char dst_ip_str[16];
    strcpy(src_ip_str, inet_ntoa(src_ip));
    strcpy(dst_ip_str, inet_ntoa(dst_ip));

    // udp 协议解析
    // 获取 端口信息，nids已转换主机序，不需要转换，
    u_short src_port = addr->source;
    u_short dst_port = addr->dest;

    // 获取了IP和端口既可以获取 inode 号和进程信息

    //首先判断数据包传输方向,传入源IP判断是发出数据包还是接受数据包
    u_short process_port = 0; // 初始化进程端口
    int pack_d = packet_direction(src_ip, dst_ip); // 获取数据包传输方向
    printf("数据包传输方向：%d\n", pack_d);

    // 根据传输方向判断进程端口，并存储
    if (pack_d == 0){
        // 既不是传入也不是发出 不解析
        return;
    } else if (pack_d == 1) {
        // 向外发出数据包，源端口为进程端口
        process_port = src_port;
    } else if (pack_d == 2) {
        // 向内接受数据包， 目标端口为进程端口
        process_port = dst_port;
    } else if (pack_d == 3) {
        // 内部传输数据包, 进程端口定义为源端口
        process_port = src_port;
    }

    // 初始化进程名字符串
    char *process_name = malloc(256);
    strcpy(process_name, "unknown");
    
    long inode = 0; // 初始化 inode 号
    inode = port_inode(process_port); // 依据端口获取inode号
    process_name = find_process_by_inode(inode); // 依据inode号获取进程名

    printf("##################################\n");
    printf("%s:%u --> %s:%u\n", src_ip_str, src_port, dst_ip_str, dst_port);
    printf("Process Port: %u\n", process_port);
    printf("Process Inode: %li\n", inode);
    printf("Process Name: %s\n", process_name);
    printf("##################################\n");

    // dns 协议解析

    return;

    struct in_addr target_addr_s;
    struct in_addr target_addr_d;
    target_addr_s.s_addr = addr->saddr;
    target_addr_d.s_addr = addr->daddr;
    

    // char *process_name = malloc(256);
    // strcpy(process_name, "unknown");
    // long inode = 0;

    printf("源地址为：%s", inet_ntoa(ip->ip_src));
    if (is_local_ip(target_addr_s)){
        printf("发出UDP数据包\n");
        inode = port_inode(addr->source);

    } else if(is_local_ip(target_addr_d)){
        printf("接收UDP数据包\n");
        inode = port_inode(addr->dest);
    } else {
        printf("不是本地发出或接收的数据包\n");
    }

    process_name = find_process_by_inode(inode);


    
    // 判断是否为DNS
    if (addr->source != 53 && addr->dest != 53) {
        /* 打印关键信息 */
        printf("\n=== 捕获到UDP数据包（长度：%d 字节） ===\n", len);
        printf("源IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_src), addr->source);
        printf("目的IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_dst), addr->dest);
        printf("inode: %li\n", inode);
        printf("process_name: %s\n", process_name);
        
        return;
    }

    /* 解析DNS头 */
    const u_char *dns_data = (u_char *)buf;
    size_t dns_data_len = len;

    // 使用ldns解析DNS数据
    ldns_pkt *dns_packet;
    ldns_status status = ldns_wire2pkt(&dns_packet, dns_data, dns_data_len);

    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "ldns_wire2pkt failed: %s\n", ldns_get_errorstr_by_id(status));
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

        // 如果是请求包
    if (ldns_pkt_qr(dns_packet) != 1) {
        // uint16_t port = ntohs(udp->uh_sport);
        
        // char *process = get_process_by_port(port);
        // printf("请求的应用端口为：%d\n应用进程为：%s\n", port, process);
        // free(process); // 释放内存
        /* 打印关键信息 */
        printf("\n=== 捕获到DNS请求包（长度：%d 字节） ===\n", len);
        printf("源IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_src), addr->source);
        printf("目的IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_dst), addr->dest);
        printf("查询域名: %s\n", domain_str);
        printf("inode: %li\n", inode);
        printf("process_name: %s\n", process_name);
        ldns_pkt_free(dns_packet);
        return;
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
    printf("\n=== 捕获到DNS响应包（长度：%d 字节） ===\n", len);
    printf("源IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_src), addr->source);
    printf("目的IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_dst), addr->dest);
    printf("inode: %li\n", inode);
    printf("process_name: %s\n", process_name);
    // printf("UDP总长度: %d 字节\n", ntohs(udp->uh_ulen));
    // printf("DNS数据长度: %lu 字节\n", ntohs(udp->uh_ulen) - sizeof(struct udphdr));
    printf("查询域名: %s\n", domain_str);
    for (size_t i = 0; i < ip_list->count; i++) {
        // printf("i = %zu\n", i);
        printf("    IP %lu: %s\n", i+1, ip_list->ips[i]);
    }

    process_and_free_iplist(ip_list);

}

void tcp_callback(struct tcp_stream *ts, void **param) {
    printf("TCP\n");
    if (ts->nids_state == NIDS_DATA) {
        printf("TCP Data: %.*s\n", ts->server.count_new, ts->server.data);
    }
}

int net_cap(){
    printf("HELLO\n");

    nids_params.device = "any";

    if (!nids_init()) {
        fprintf(stderr, "Failed to initialize libnids\n");
        return 1;
    }

    nids_register_tcp(tcp_callback);
    nids_register_udp(udp_callback);

    nids_run();

    return 0;
}

int main(){
    net_cap();
    return 0;
}