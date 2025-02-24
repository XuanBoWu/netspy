#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>        // struct iphdr
#include <netinet/udp.h>       // struct udphdr
#include <netinet/ether.h>     // struct ethhdr
#include <arpa/inet.h>         // inet_ntoa

// UDP数据包处理函数
void udp_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    
    // 正确计算IP头长度（考虑选项字段）
    int ip_header_len = ip_header->ihl * 4;
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header_len);

    // 转换IP地址格式
    struct in_addr src_addr, dest_addr;
    src_addr.s_addr = ip_header->saddr;
    dest_addr.s_addr = ip_header->daddr;

    printf("UDP Packet captured\n");
    printf("Source IP: %s\n", inet_ntoa(src_addr));
    printf("Destination IP: %s\n", inet_ntoa(dest_addr));
    printf("Source Port: %d\n", ntohs(udp_header->source));
    printf("Destination Port: %d\n", ntohs(udp_header->dest));
}

int main() {
    pcap_t *handle;
    char *device = "eth0"; // 网络接口名称
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "udp port 53"; // 过滤表达式

    // 打开网络接口
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        return 1;
    }

    // 编译过滤器
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // 设置过滤器
    if (pcap_setfilter(handle, &fp) != 0) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // 捕获数据包
    pcap_loop(handle, -1, udp_packet_handler, NULL);

    // 关闭句柄
    pcap_close(handle);
    return 0;
}
