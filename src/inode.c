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
#include "uthash.h"
#include "inode.h"

#define MAX_PROCESS_NAME 256

struct inode_info {
    struct tuple4 *addr;
    unsigned long inode;
    UT_hash_handle hh; 
};

struct hash_table {
    int port;
    struct inode_info *value;
    UT_hash_handle hh;
};

// 获取进程名称
static int get_process_name(pid_t pid, char *name_buf, size_t buf_size) {
    char path[PATH_MAX];
    FILE *fp;
    
    // 尝试从 comm 文件获取
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    if ((fp = fopen(path, "r"))) {
        if (fgets(name_buf, buf_size, fp)) {
            fclose(fp);
            // 去除换行符
            size_t len = strlen(name_buf);
            if (len > 0 && name_buf[len-1] == '\n')
                name_buf[len-1] = '\0';
            return 0;
        }
        fclose(fp);
    }

    // 如果失败，尝试从 status 文件获取
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    if ((fp = fopen(path, "r"))) {
        while (fgets(path, sizeof(path), fp)) {
            if (strncmp(path, "Name:", 5) == 0) {
                char *p = path + 5;
                while (*p == ' ' || *p == '\t') p++;
                size_t len = strlen(p);
                if (len > 0 && p[len-1] == '\n')
                    p[len-1] = '\0';
                strncpy(name_buf, p, buf_size-1);
                name_buf[buf_size-1] = '\0';
                fclose(fp);
                return 0;
            }
        }
        fclose(fp);
    }

    // 最后尝试从 exe 的符号链接获取
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, name_buf, buf_size-1);
    if (len != -1) {
        name_buf[len] = '\0';
        // 提取文件名部分
        char *p = strrchr(name_buf, '/');
        if (p) {
            strncpy(name_buf, p+1, buf_size);
            return 0;
        }
        return 0;
    }

    return -1;
}

// 处理单个进程的 /proc/<PID>/fd 目录
static char* process_pid(pid_t pid, ino_t target_inode) {
    char fd_path[PATH_MAX];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);

    DIR *fd_dir = opendir(fd_path);
    if (!fd_dir) return NULL;

    struct dirent *fd_entry;
    int found = 0;
    while ((fd_entry = readdir(fd_dir)) != NULL) {
        if (strcmp(fd_entry->d_name, ".") == 0 || 
            strcmp(fd_entry->d_name, "..") == 0)
            continue;

        char fd_full_path[PATH_MAX];
        snprintf(fd_full_path, sizeof(fd_full_path), 
                "%s/%s", fd_path, fd_entry->d_name);

        struct stat fd_stat;
        if (stat(fd_full_path, &fd_stat) == -1)
            continue;

        if (fd_stat.st_ino == target_inode) {
            found = 1;
            break;
        }
    }
    closedir(fd_dir);

    if (found) {
        char *process_name = malloc(MAX_PROCESS_NAME);
        if (process_name == NULL) {
            perror("malloc failed");
            return NULL;
        }
    

        if (get_process_name(pid, process_name, MAX_PROCESS_NAME) != 0) {
            free(process_name);
            return NULL;
        }
        printf("Process: %-16s PID: %-6d FD: %-4s Inode: %lu\n",
              process_name, pid, fd_entry->d_name, (unsigned long)target_inode);
        return process_name;
    }
    return NULL;
}

// 处理网络 Socket 文件
static void process_net_file(const char *path, ino_t target_inode) {
    FILE *file = fopen(path, "r");
    if (!file) return;

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        unsigned long inode;
        if (sscanf(line, "%*d: %*x %*x %*x %*x %*x %*x %*x %*x %*x %lu", 
                  &inode) == 1) {
            if (inode == target_inode) {
                printf("Network: %-47s Inode: %lu\n", path, inode);
            }
        }
    }
    fclose(file);
}

// 主查询函数
char* find_process_by_inode(ino_t target_inode) {

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc failed");
        return NULL;
    }

    char *process_name = malloc(MAX_PROCESS_NAME);
    if (process_name == NULL) {
        printf("内存分配失败\n");
    }
    strcpy(process_name, "unknown");

    struct dirent *proc_entry;
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        if (proc_entry->d_type != DT_DIR)
            continue;

        char *endptr;
        pid_t pid = (pid_t)strtol(proc_entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0)
            continue;

        if ((process_name = process_pid(pid, target_inode)) != NULL){
            break;
        }
        // printf("TAG:process_name: %s\n", process_name);
    }
    closedir(proc_dir);

    process_net_file("/proc/net/tcp", target_inode);
    process_net_file("/proc/net/udp", target_inode);
    process_net_file("/proc/net/raw", target_inode);
    process_net_file("/proc/net/unix", target_inode);

    return process_name;
}

void print_help(const char *prog_name) {
    printf("Inode Process Finder v1.2\n");
    printf("Usage: %s <inode>\n\n", prog_name);
    printf("Options:\n");
    printf("  <inode>\tTarget inode number to search (required)\n");
    printf("\nExample:\n");
    printf("  sudo %s 48840\n", prog_name);
    printf("  sudo %s $(ls -i /path/to/file | awk '{print $1}')\n", prog_name);
}

long port_inode(u_short port_num){
    FILE *fp = fopen("/proc/net/udp", "r");
    if (!fp) {
        perror("Failed to open /proc/net/udp");
        return 1;
    }
    
    struct hash_table *set = NULL;

    char line[512];
    //跳过标题行
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        struct inode_info *info = malloc(sizeof *info);
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
        // printf("%d.%d.%d.%d\n", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
        addr->saddr = *(u_int32_t*)ip_bytes;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->saddr, ip_str, sizeof(ip_str));

        // 将端口从十六进制字符串转换为主机字节顺序
        uint8_t port_bytes[2];
        for (int i = 0; i < 2; i++) {
            if (sscanf(l_port_part + 2*i, "%2hhx", &port_bytes[1-i]) != 1) {
                fprintf(stderr, "Failed to parse port: %s\n", l_port_part);
                break;
            }
        }
        addr->source = *(uint16_t*)port_bytes;
        printf("port_bytes: %d \nl_port_part: %s\n", (int)*port_bytes, l_port_part);
        printf("addr->source: %d\n", addr->source);

        // 解析inode编号（第10个字段，索引9）
        unsigned long inode = strtoul(fields[9], NULL, 10);

        // 打印结果
        printf("IP: %-15s Port: %d Inode: %lu\n", ip_str, addr->source, inode);
        struct hash_table *h = (struct hash_table*)malloc(sizeof(struct hash_table));
        h->port = (int)addr->source;
        info->inode = inode;
        info->addr = addr;
        h->value = info;
        HASH_ADD_INT(set, port, h);

    }

    struct hash_table *s;
    // 遍历哈希表内容
    printf("HASH表内容：\n");
    printf("查询Port：%d\n", port_num);
    for(s=set; s != NULL; s=s->hh.next) {
        char ip_str[INET_ADDRSTRLEN];
        printf("Key_Port: %d IP: %s:%d inode: %lu\n", s->port, inet_ntop(AF_INET,&s->value->addr->saddr, ip_str, sizeof(ip_str)), s->value->addr->source, s->value->inode);
    }

    // char str_port[8];
    // sprintf(str_port, "%d", port_num);
    struct hash_table *result;
    int port_key = (int)port_num;
    HASH_FIND_INT(set, &port_key, result);
    if (result) {
        printf("inode已匹配！\n");
        return result->value->inode;
    }

    return -1;
}

// int main(int argc, char *argv[]) {

//     if(1) {
//         port_inode(53);
//         return 0;
//     }

//     if (argc != 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
//         print_help(argv[0]);
//         return EXIT_FAILURE;
//     }

//     // inode 号校验转换逻辑
//     char *endptr;
//     errno = 0;
//     unsigned long inode = strtoul(argv[1], &endptr, 10);
    
//     if (errno != 0 || *endptr != '\0' || inode == 0) {
//         fprintf(stderr, "Invalid inode: %s\n", argv[1]);
//         fprintf(stderr, "Please provide a valid positive integer\n");
//         return EXIT_FAILURE;
//     }
//     // ino_t 为 inode 类型
//     find_process_by_inode((ino_t)inode);
    
//     return EXIT_SUCCESS;
// }
