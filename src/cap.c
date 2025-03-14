#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <nids.h>

void tcp_callback(struct tcp_stream *ts, void **param) {
    printf("TCP\n");
    if (ts->nids_state == NIDS_DATA) {
        printf("TCP Data: %.*s\n", ts->server.count_new, ts->server.data);
    }
}

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

void udp_callback(struct tuple4 *addr, char *buf, int len, struct ip *ip) {
 

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
    printf("\n=== 捕获到DNS数据包（长度：%d 字节） ===\n", len);
    printf("源IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_src), ntohs(addr->saddr));
    printf("目的IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_dst), ntohs(addr->daddr));
    // printf("UDP总长度: %d 字节\n", ntohs(udp->uh_ulen));
    // printf("DNS数据长度: %lu 字节\n", ntohs(udp->uh_ulen) - sizeof(struct udphdr));
    printf("查询域名: %s\n", domain_str);
    for (size_t i = 0; i < ip_list->count; i++) {
        // printf("i = %zu\n", i);
        printf("    IP %lu: %s\n", i+1, ip_list->ips[i]);
    }

    process_and_free_iplist(ip_list);

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