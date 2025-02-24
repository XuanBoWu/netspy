#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ldns/ldns.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

#define ETHER_HEADER_LEN 14
#define IP_HEADER_LEN(ip_header) (((ip_header)->ip_hl) * 4)
#define UDP_HEADER_LEN 8

/* 新增：回调函数声明 */
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

int cap_netinfo(char *dev) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask: %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 0, 500, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Filter error: %s\n", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Filter install error: %s\n", pcap_geterr(handle));
        return 2;
    }

    /* 关键修改：使用pcap_loop代替while循环 */
    pcap_loop(handle, 0, packet_handler, NULL); // 0表示无限捕获

    pcap_close(handle);
    return 0;
}

/* 新增：数据包处理回调函数 */
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    // 解析以太网头部
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;

    // 解析IP头部
    struct ip *ip_header = (struct ip *)(packet + ETHER_HEADER_LEN);
    if (ip_header->ip_p != IPPROTO_UDP) return;

    // 解析UDP头部
    struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_HEADER_LEN + IP_HEADER_LEN(ip_header));
    if (ntohs(udp_header->uh_sport) != 53) return;

    // 定位DNS数据
    const u_char *dns_data = packet + ETHER_HEADER_LEN + IP_HEADER_LEN(ip_header) + UDP_HEADER_LEN;
    size_t dns_data_len = h->len - (ETHER_HEADER_LEN + IP_HEADER_LEN(ip_header) + UDP_HEADER_LEN);

    // 解析DNS数据
    ldns_pkt *dns_packet;
    if (ldns_wire2pkt(&dns_packet, dns_data, dns_data_len) != LDNS_STATUS_OK) return;
    if (ldns_pkt_qr(dns_packet) != 1) { // 确保是响应包
        ldns_pkt_free(dns_packet);
        return;
    }

    // 处理查询部分
    ldns_rr_list *questions = ldns_pkt_question(dns_packet);
    if (questions) {
        for (size_t i = 0; i < ldns_rr_list_rr_count(questions); i++) {
            ldns_rr *question = ldns_rr_list_rr(questions, i);
            char *domain_str = ldns_rdf2str(ldns_rr_owner(question));
            printf("Query Domain: %s\n", domain_str);
            free(domain_str);
        }
    }

    // 处理应答部分
    ldns_rr_list *answers = ldns_pkt_answer(dns_packet);
    if (answers) {
        for (size_t i = 0; i < ldns_rr_list_rr_count(answers); i++) {
            ldns_rr *answer = ldns_rr_list_rr(answers, i);
            ldns_rr_type type = ldns_rr_get_type(answer);

            if (type == LDNS_RR_TYPE_A) {
                struct in_addr addr;
                addr.s_addr = *(uint32_t*)ldns_rdf_data(ldns_rr_rdf(answer, 0));
                printf("  IPv4 Address: %s\n", inet_ntoa(addr));
            } 
            else if (type == LDNS_RR_TYPE_AAAA) {
                char ipv6_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, ldns_rdf_data(ldns_rr_rdf(answer, 0)),
                         ipv6_str, INET6_ADDRSTRLEN);
                printf("  IPv6 Address: %s\n", ipv6_str);
            }
        }
    }

    ldns_pkt_free(dns_packet);
    printf("-----------------------\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    return cap_netinfo(argv[1]);
}
