#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>

/* 以太网头结构 */
struct ethheader {
    u_char  ether_dhost[6]; /* 目标MAC地址 */
    u_char  ether_shost[6]; /* 源MAC地址 */
    u_short ether_type;     /* 网络层协议类型 */
};

/* 数据包处理回调函数 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
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

    /* 打印关键信息 */
    printf("\n=== 捕获到DNS数据包（长度：%d 字节） ===\n", header->len);
    printf("源IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
    printf("目的IP: %-15s 端口: %d\n", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
    printf("UDP总长度: %d 字节\n", ntohs(udp->uh_ulen));
    printf("DNS数据长度: %d 字节\n", ntohs(udp->uh_ulen) - sizeof(struct udphdr));
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* 1. 获取网络设备 */
    char *dev = pcap_lookupdev(errbuf);
    if (!dev) {
        fprintf(stderr, "找不到默认设备: %s\n", errbuf);
        return 2;
    }
    printf("监听网卡: %s\n", dev);

    /* 2. 打开网卡混杂模式 */
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "无法打开设备 %s: %s\n", dev, errbuf);
        return 2;
    }

    /* 3. 验证数据链路类型为以太网 */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "错误：%s 不是以太网设备\n", dev);
        pcap_close(handle);
        return 2;
    }

    /* 4. 设置BPF过滤器 */
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "警告：无法获取网络掩码: %s\n", errbuf);
        net = mask = 0;
    }

    char filter_exp[] = "udp port 53";  // DNS过滤器
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "过滤器语法错误: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "设置过滤器失败: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }

    /* 5. 开始抓包循环 */
    printf("开始捕获DNS流量（Ctrl+C退出）...\n");
    pcap_loop(handle, -1, got_packet, NULL);

    /* 清理资源 */
    pcap_close(handle);
    return 0;
}
