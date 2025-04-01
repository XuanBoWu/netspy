#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <nids.h>
#include <sys/types.h>


void tcp_callback(struct tcp_stream *ts, void **param) {
    printf("TCP\n");
    if (ts->nids_state == NIDS_DATA) {
        printf("TCP Data: %.*s\n", ts->server.count_new, ts->server.data);
    }
}


void udp_callback(struct tuple4 *addr, char *buf, int len, struct ip *ip) {
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