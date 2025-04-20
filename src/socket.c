#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <nids.h>
#include "hash.h"
#include "inode.h"
#include "socket.h"


void free_socket_info(socket_info* info) {
    if (!info) return;
    
    // 释放进程名字符串
    if (info->process_name) {
        free(info->process_name);
    }
    
    // 释放结构体本身
    free(info);
}

void print_socket_info(int key, void* value) {
    socket_info* info = (socket_info*)value;
    
    // 将IP地址从网络字节序转换为人可读的格式
    char local_ip_str[INET_ADDRSTRLEN];
    char rem_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(info->local_ip), local_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(info->rem_ip), rem_ip_str, INET_ADDRSTRLEN);
    
    // 打印所有信息
    printf("Socket Info:\n");
    printf("  Key: %d\n", key);
    printf("  Local: %s:%d\n", local_ip_str, ntohs(info->local_port));
    printf("  Remote: %s:%d\n", rem_ip_str, ntohs(info->rem_port));
    printf("  Inode: %lu\n", (unsigned long)info->inode);
    printf("  PID: %d\n", info->pid);
    printf("  Process: %s\n", info->process_name ? info->process_name : "(null)");
    printf("-----------------------\n");
}

// 用于queue_put和queue_free的回调函数
void free_socket_info_callback(void* data) {
    free_socket_info((socket_info*)data);
}

socket_info* create_socket_info(
    in_addr_t local_ip, u_short local_port,
    in_addr_t rem_ip, u_short rem_port,
    ino_t inode, pid_t pid,
    const char* process_name) {
    
    socket_info* info = malloc(sizeof(socket_info));
    if (!info) return NULL;
    
    info->local_ip = local_ip;
    info->local_port = local_port;
    info->rem_ip = rem_ip;
    info->rem_port = rem_port;
    info->inode = inode;
    info->pid = pid;
    
    // 复制进程名
    if (process_name) {
        info->process_name = strdup(process_name);
        if (!info->process_name) {
            free(info);
            return NULL;
        }
    } else {
        info->process_name = NULL;
    }
    
    return info;
}

socket_info* find_by_local_port(Queue* queue, u_short port) {
    Node* current = queue->head;
    while (current) {
        socket_info* info = (socket_info*)current->value;
        // printf("查询端口：%d\n", port);  // 调试打印
        // print_socket_info(0, info); // 调试打印
        if (info && (ntohs(info->local_port) == port || ntohs(info->rem_port) == port)) {
            return info;
        }
        current = current->next;
    }
    printf("未查询到端口：%d 对应的进程\n", port);
    return NULL;
}

int get_socket(char * socket_fp, Queue* queue){
    // 根据传入的地址读取socket状态文件
    FILE *fp = fopen(socket_fp, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open %s: %s\n", socket_fp, strerror(errno));
        return 1;
    }

    // 初始化
    char line[512];
    //跳过标题行
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        // printf("原始数据：%s", line); // 调试打印
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
        char *rem_address = fields[2];
        char *l_ip_part = strtok_r(local_addr, ":", &saveptr);
        char *l_port_part = strtok_r(NULL, ":", &saveptr);
        char *r_ip_part = strtok_r(rem_address, ":", &saveptr);
        char *r_port_part = strtok_r(NULL, ":", &saveptr);
        if (!l_ip_part || !l_port_part || strlen(l_ip_part) != 8 || strlen(l_port_part) != 4 ||
            !r_ip_part || !r_port_part || strlen(r_ip_part) != 8 || strlen(r_port_part) != 4 ) {
            fprintf(stderr, "Invalid local address format: %s\n", local_addr);
            continue;
        }

        struct tuple4 *addr = malloc(sizeof(struct tuple4));
        uint8_t ip_bytes[4];
        for (int i = 0; i < 4; i++) {
            // 转换进制的同时反转端序
            if (sscanf(l_ip_part + 2*i, "%2hhx", &ip_bytes[3-i]) != 1) {
                fprintf(stderr, "Failed to parse IP: %s\n", l_ip_part);
                break;
            }
        }
        
        addr->saddr = *(u_int32_t*)ip_bytes;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->saddr, ip_str, sizeof(ip_str));

        // 将端口从十六进制字符串转换为主机字节顺序
        uint8_t port_bytes[2];
        for (int i = 0; i < 2; i++) {
            if (sscanf(l_port_part + 2*i, "%2hhx", &port_bytes[i]) != 1) {
                fprintf(stderr, "Failed to parse port: %s\n", l_port_part);
                break;
            }
        }
        addr->source = *(uint16_t*)port_bytes;

        // 解析inode编号（第10个字段，索引9）
        ino_t inode = strtoul(fields[9], NULL, 10);

        // 根据 inode 查询 PID 和进程名
        process_info* pi = find_process_by_inode(inode);

        // 初始化 socket 节点
        socket_info *info = create_socket_info(
            addr->saddr, addr->source, 
            addr->daddr, addr->dest, 
            inode, 
            pi->pid, pi->process_name);
        
        // print_socket_info(0, info); // 调试打印

        if (info) {
            queue_put(queue, inode, info, free_socket_info_callback);
        }

    }
    fclose(fp);
    return 0;

}

void* refresh_socket(void * queue){
    int i = 0;
    while(1){
        get_socket("/proc/net/udp", queue);
        get_socket("/proc/net/tcp", queue);
        i++;
        // printf("刷新次数：%d\n", i);

        // if (i%200 == 0) {
        //     queue_print(queue, print_socket_info);
        // }
        usleep(1000000 / REFRESH_RATE_HZ);
    }
}