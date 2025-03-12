#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#define MAX_PROCESS_NAME 256

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
static void process_pid(pid_t pid, ino_t target_inode) {
    char fd_path[PATH_MAX];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);

    DIR *fd_dir = opendir(fd_path);
    if (!fd_dir) return;

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
        char process_name[MAX_PROCESS_NAME] = "unknown";
        get_process_name(pid, process_name, sizeof(process_name));
        
        printf("Process: %-16s PID: %-6d FD: %-4s Inode: %lu\n",
              process_name, pid, fd_entry->d_name, (unsigned long)target_inode);
    }
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
void find_process_by_inode(ino_t target_inode) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc failed");
        return;
    }

    struct dirent *proc_entry;
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        if (proc_entry->d_type != DT_DIR)
            continue;

        char *endptr;
        pid_t pid = (pid_t)strtol(proc_entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0)
            continue;

        process_pid(pid, target_inode);
    }
    closedir(proc_dir);

    process_net_file("/proc/net/tcp", target_inode);
    process_net_file("/proc/net/udp", target_inode);
    process_net_file("/proc/net/raw", target_inode);
    process_net_file("/proc/net/unix", target_inode);
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

int main(int argc, char *argv[]) {
    if (argc != 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_help(argv[0]);
        return EXIT_FAILURE;
    }

    char *endptr;
    errno = 0;
    unsigned long inode = strtoul(argv[1], &endptr, 10);
    
    if (errno != 0 || *endptr != '\0' || inode == 0) {
        fprintf(stderr, "Invalid inode: %s\n", argv[1]);
        fprintf(stderr, "Please provide a valid positive integer\n");
        return EXIT_FAILURE;
    }
    
    find_process_by_inode((ino_t)inode);
    
    return EXIT_SUCCESS;
}
