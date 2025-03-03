#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

#define BUFFER_SIZE (1024 * 512)  // 512KB缓存
#define LINE_MAX     1024         // 单行最大长度

// 环形缓冲区结构
typedef struct {
    char data[BUFFER_SIZE];
    size_t write_pos;
    size_t read_pos;
    size_t used;
} CircularBuffer;

CircularBuffer buffer = {0};
pthread_mutex_t buffer_mutex = PTHREAD_MUTEX_INITIALIZER;

// 初始化缓冲区
void buffer_init() {
    memset(buffer.data, 0, BUFFER_SIZE);
    buffer.write_pos = 0;
    buffer.read_pos = 0;
    buffer.used = 0;
}

// 追加数据到缓冲区
void buffer_append(const char* str, size_t len) {
    if (len == 0) return;

    // 丢弃超出缓冲区容量的数据
    if (len > BUFFER_SIZE) {
        str += (len - BUFFER_SIZE);
        len = BUFFER_SIZE;
    }

    pthread_mutex_lock(&buffer_mutex);
    
    // 需要分两段写入的情况
    if (buffer.write_pos + len > BUFFER_SIZE) {
        size_t first_part = BUFFER_SIZE - buffer.write_pos;
        memcpy(buffer.data + buffer.write_pos, str, first_part);
        memcpy(buffer.data, str + first_part, len - first_part);
        buffer.write_pos = len - first_part;
    } else {
        memcpy(buffer.data + buffer.write_pos, str, len);
        buffer.write_pos += len;
        if (buffer.write_pos == BUFFER_SIZE) buffer.write_pos = 0;
    }

    // 更新已用空间
    buffer.used += len;
    if (buffer.used > BUFFER_SIZE) {
        buffer.used = BUFFER_SIZE;
        buffer.read_pos = (buffer.write_pos + 1) % BUFFER_SIZE;
    }

    pthread_mutex_unlock(&buffer_mutex);
}

// 线程函数：读取UDP状态
void* udp_reader_thread(void* arg) {
    (void)arg;
    
    while (1) {
        FILE* fp = fopen("/proc/net/udp", "r");
        if (!fp) {
            perror("Open udp failed");
            usleep(100000);
            continue;
        }

        char line[LINE_MAX];
        size_t total_len = 0;
        char temp_buffer[BUFFER_SIZE];
        time_t now = time(NULL);
        
        // 添加时间戳
        int header_len = snprintf(temp_buffer, LINE_MAX, "\n=== [%ld] ===\n", now);
        total_len += header_len;

        // 读取文件内容
        while (fgets(line, LINE_MAX, fp)) {
            size_t line_len = strlen(line);
            if (total_len + line_len >= BUFFER_SIZE) break;
            memcpy(temp_buffer + total_len, line, line_len);
            total_len += line_len;
        }
        fclose(fp);

        // 追加到环形缓冲区
        buffer_append(temp_buffer, total_len);
        usleep(100000); // 100ms间隔
    }
    return NULL;
}

int main() {
    buffer_init();
    pthread_t tid;
    
    if (pthread_create(&tid, NULL, udp_reader_thread, NULL)) {
        perror("Create thread failed");
        return 1;
    }

    // 主线程示例：打印缓冲区状态
    while (1) {
        pthread_mutex_lock(&buffer_mutex);
        printf("Buffer usage: %zu/%d\n", buffer.used, BUFFER_SIZE);
        
        // 示例：打印前100字节
        size_t print_len = buffer.used;
        char temp[BUFFER_SIZE] = {0};
        if (buffer.read_pos + print_len <= BUFFER_SIZE) {
            memcpy(temp, buffer.data + buffer.read_pos, print_len);
        } else {
            size_t first = BUFFER_SIZE - buffer.read_pos;
            memcpy(temp, buffer.data + buffer.read_pos, first);
            memcpy(temp + first, buffer.data, print_len - first);
        }
        printf("Preview: %s\n", temp);
        pthread_mutex_unlock(&buffer_mutex);
        
        sleep(2); // 主线程每2秒查看一次
    }
    
    return 0;
}
