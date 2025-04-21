#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <nids.h>
#include "inode.h"


static int get_process_name(pid_t pid, char *name_buf, size_t buf_size) {
    char path[PATH_MAX];
    FILE *fp;

    // 尝试从 cmdline 文件获取
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
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