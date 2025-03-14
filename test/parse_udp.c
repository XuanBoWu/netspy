#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <ctype.h>

int main() {
    FILE *fp = fopen("/proc/net/udp", "r");
    if (!fp) {
        perror("Failed to open /proc/net/udp");
        return 1;
    }

    char line[512];
    //跳过标题行
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        // 将行拆分为标记（字段）
        char *fields[32];
        int field_count = 0;
        char *saveptr;
        char *token = strtok_r(line, " \t\n", &saveptr);
        while (token && field_count < 32) {
            fields[field_count++] = token;
            token = strtok_r(NULL, " \t\n", &saveptr);
        }
        if (field_count < 10) {
            continue; // 跳过无效行
        }

        // 解析本地地址（字段[1]为“IP:端口”）
        char *local_addr = fields[1];
        char *ip_part = strtok_r(local_addr, ":", &saveptr);
        char *port_part = strtok_r(NULL, ":", &saveptr);
        if (!ip_part || !port_part || strlen(ip_part) != 8 || strlen(port_part) != 4) {
            fprintf(stderr, "Invalid local address format: %s\n", local_addr);
            continue;
        }

        // 将IP从十六进制字符串转换为点分十进制格式
        struct in_addr ip;
        uint8_t ip_bytes[4];
        for (int i = 0; i < 4; i++) {
            if (sscanf(ip_part + 2*i, "%2hhx", &ip_bytes[3-i]) != 1) {
                fprintf(stderr, "Failed to parse IP: %s\n", ip_part);
                break;
            }
        }
        ip.s_addr = *(uint32_t*)ip_bytes;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

        // 将端口从十六进制字符串转换为主机字节顺序
        uint16_t port;
        uint8_t port_bytes[2];
        for (int i = 0; i < 2; i++) {
            if (sscanf(port_part + 2*i, "%2hhx", &port_bytes[i]) != 1) {
                fprintf(stderr, "Failed to parse port: %s\n", port_part);
                break;
            }
        }
        port = ntohs(*(uint16_t*)port_bytes);

        // 解析inode编号（第10个字段，索引9）
        unsigned long inode = strtoul(fields[9], NULL, 10);

        // 打印结果
        printf("IP: %-15s Port: %-5d Inode: %lu\n", ip_str, port, inode);
    }

    fclose(fp);
    return 0;
}
