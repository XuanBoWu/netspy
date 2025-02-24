#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>

/* 以太网头结构 */
struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

/* DNS头部结构 */
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* 解析DNS名称（处理压缩指针） */
void parse_dns_name(const u_char *ptr, const u_char *base, char *out, int maxlen) {
    int pos = 0;
    int len;
    int jumps = 0;
    
    while ((len = *ptr++) != 0) {
        if (jumps++ > 10) break; // 防止无限循环
        
        /* 处理压缩指针 */
        if ((len & 0xC0) == 0xC0) {
            int offset = ((len & 0x3F) << 8) | (*ptr++);
            parse_dns_name(base + offset, base, out + pos, maxlen - pos);
            return;
        }

        if (pos + len + 1 >= maxlen) break;
        
        memcpy(out + pos, ptr, len);
        ptr += len;
        pos += len;
        out[pos++] = '.';
    }
    out[pos > 0 ? pos-1 : 0] = '\0'; // 去除末尾点号
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) return;

    struct ip *ip = (struct ip *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->ip_hl * 4;

    if (ip->ip_p != IPPROTO_UDP) return;

    struct udphdr *udp = (struct udphdr *)((char *)ip + ip_header_len);

    if (ntohs(udp->uh_sport) != 53 && ntohs(udp->uh_dport) != 53) return;

    /* 获取DNS数据 */
    const u_char *dns_data = (u_char *)udp + sizeof(struct udphdr);
    int dns_len = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
    
    if (dns_len < (int)sizeof(struct dns_header)) return;

    /* 解析DNS头部 */
    struct dns_header *dns_hdr = (struct dns_header *)dns_data;
    uint16_t qdcount = ntohs(dns_hdr->qdcount);
    uint16_t ancount = ntohs(dns_hdr->ancount);

    /* 只处理响应包 */
    if (!(ntohs(dns_hdr->flags) & 0x8000)) return;

    printf("\n=== DNS响应包（长度：%d 字节）===", header->len);

    /* 解析查询问题 */
    const u_char *ptr = dns_data + sizeof(struct dns_header);
    char query[256] = {0};
    char ips[16][INET_ADDRSTRLEN];  // 存储最多16个IP地址
    int ip_count = 0;
    
    if (qdcount > 0) {
        parse_dns_name(ptr, dns_data, query, sizeof(query));
        /* 跳过查询部分 */
        ptr += (strlen(query) + 1 + 4); // QTYPE(2) + QCLASS(2)
    }

    /* 解析回答记录 */
    for (int i = 0; i < ancount; i++) {
        if (ptr + 12 > dns_data + dns_len) break; // 检查长度

        /* 修复后的名称解析逻辑 */
        const u_char *current = ptr;
        while (*current != 0) {
            if ((*current & 0xC0) == 0xC0) { // 处理压缩指针
                current += 2; // 跳过2字节指针
                break;
            }
            uint8_t label_len = *current;
            current += 1 + label_len; // 跳过长度字节和标签内容
        }
        ptr = current + 1; // 跳过最后的0字节

        uint16_t type = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        ptr += 2; // 跳过CLASS
        ptr += 4; // 跳过TTL
        uint16_t rdlength = ntohs(*(uint16_t*)ptr);
        ptr += 2;

        /* 只处理A记录 */
        printf("[2]type:%d, rdlength:%d", type, rdlength);
        if (type == 1 && rdlength == 4) {
            struct in_addr addr;
            memcpy(&addr.s_addr, ptr, 4);
            inet_ntop(AF_INET, &addr, ips[ip_count], INET_ADDRSTRLEN);
            ip_count++;
            printf("[1]ip_count:%d", ip_count);
        }
        ptr += rdlength;
    }
    /* 统一输出结果 */
    printf("\n=== DNS响应包（长度：%d 字节）===", header->len);
    printf("\n[查询域名] %s", query);
    if (ip_count > 0) {
        printf("\n[IP地址] ");
        for (int i = 0; i < ip_count; i++) {
            printf("%s ", ips[i]);
        }
    }
    printf("\n");
}

/* main函数保持不变，与之前版本相同 */
int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
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
