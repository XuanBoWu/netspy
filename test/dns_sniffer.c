#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ldns/ldns.h>
#include <arpa/inet.h> // For inet_ntoa()
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

#define ETHER_HEADER_LEN 14 // 以太网头部长度
#define IP_HEADER_LEN(ip_header) (((ip_header)->ip_hl) * 4)
#define UDP_HEADER_LEN 8


int cap_netinfo(char *dev) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "udp port 53"; // 只抓取DNS响应 (UDP源端口53)
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;

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

     while ((packet = pcap_next(handle, &header)) != NULL) {

        // 解析以太网头部
        struct ether_header *eth_header = (struct ether_header *)packet;

        // 确保是IP协议
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            continue;
        }


        // 解析IP头部
        struct ip *ip_header = (struct ip *)(packet + ETHER_HEADER_LEN);
        //int ip_header_len = ip_header->ip_hl * 4; // IP头部长度 (以4字节为单位)

        // 确保是UDP协议
        if (ip_header->ip_p != IPPROTO_UDP) {
          continue;
        }

        // 解析UDP头部
        struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_HEADER_LEN + IP_HEADER_LEN(ip_header));

        // 确保是DNS端口 (53)
        if (ntohs(udp_header->uh_sport) != 53) { //只检查sport
          continue;
        }


        // DNS数据包起始位置
        const u_char *dns_data = packet + ETHER_HEADER_LEN + IP_HEADER_LEN(ip_header) + UDP_HEADER_LEN;
        size_t dns_data_len = header.len - (ETHER_HEADER_LEN + IP_HEADER_LEN(ip_header) + UDP_HEADER_LEN);

        // 使用ldns解析DNS数据
        ldns_pkt *dns_packet;
        ldns_status status = ldns_wire2pkt(&dns_packet, dns_data, dns_data_len);

        if (status != LDNS_STATUS_OK) {
            fprintf(stderr, "ldns_wire2pkt failed: %s\n", ldns_get_errorstr_by_id(status));
            continue;
        }
        // 进一步确认是响应报文(可选,但更严谨)
        if (ldns_pkt_qr(dns_packet) != 1) {
             ldns_pkt_free(dns_packet); // 释放不是响应的包
             continue;
        }

        // 获取查询部分 (Question Section)
        ldns_rr_list *questions = ldns_pkt_question(dns_packet);
        if (questions) {
            for (size_t i = 0; i < ldns_rr_list_rr_count(questions); i++) { // 使用 ldns_rr_list_rr_count
                ldns_rr *question = ldns_rr_list_rr(questions, i);
                ldns_rdf *domain = ldns_rr_owner(question); // 获取域名
                if (domain) {
                    char *domain_str = ldns_rdf2str(domain);
                    printf("Query Domain: %s\n", domain_str);
                    free(domain_str);
                }
            }
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
                        //char *ip_str = ldns_rdf2str(ip_rdf); //不需要转换为字符串
						struct in_addr addr;
                        // ldns_rdf2native_in_addr(&addr,ip_rdf); // 不使用此函数
                        addr.s_addr = *(uint32_t*)ldns_rdf_data(ip_rdf); //直接从数据中取出

						char *convertedIP = inet_ntoa(addr);
                        printf("  IP Address: %s\n", convertedIP); // 打印IP
                        //free(ip_str);
                    }
                } else if (ldns_rr_get_type(answer) == LDNS_RR_TYPE_AAAA){ //处理AAAA记录
                    ldns_rdf *ip_rdf = ldns_rr_rdf(answer, 0);
                    if(ip_rdf){
                         // 直接从 ldns_rdf 数据中提取 IPv6 地址
                        unsigned char *ipv6_data = ldns_rdf_data(ip_rdf);
                        char ipv6_str[INET6_ADDRSTRLEN];

                        if (inet_ntop(AF_INET6, ipv6_data, ipv6_str, INET6_ADDRSTRLEN) != NULL) {
                            printf("  IPv6 Address: %s\n", ipv6_str);
                        } else {
                            perror("inet_ntop failed for IPv6");
                        }
                    }
                }
            }
        }
        // 释放ldns_pkt
        ldns_pkt_free(dns_packet);
        printf("-----------------------\n");

     }

    pcap_close(handle);
    return 0;
}

int main(int argc, char *argv[]) {
     if(argc != 2){
        fprintf(stderr, "Usage: %s <network_interface>\n", argv[0]);
        return 1;
     }
     char *dev = argv[1];
     cap_netinfo(dev);
     return 0;

}
