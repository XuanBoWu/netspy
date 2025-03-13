#include <stdio.h>
#include <nids.h>

void tcp_callback(struct tcp_stream *ts, void **param) {
    printf("TCP\n");
    if (ts->nids_state == NIDS_DATA) {
        printf("TCP Data: %.*s\n", ts->server.count_new, ts->server.data);
    }
}

void udp_callback(struct tuple4 *addr, char *buf, int len, struct ip *ip) {
    printf("UDP\n");
    printf("UDP Len: %d\nSRC_IP:%u DST_IP:%u \n", len, ip->ip_src.s_addr,ip->ip_dst.s_addr);
    printf("UDP Data: %.*s\n", len, buf);
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