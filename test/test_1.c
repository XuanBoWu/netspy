#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

#define BUFFER_SIZE 4096    // 环形缓冲区大小
#define READ_INTERVAL 1     // 读取间隔（秒）
#define PRINT_INTERVAL 5    // 打印间隔（秒）

// 共享数据结构
typedef struct {
    char buffer[BUFFER_SIZE];  // 环形缓冲区
    size_t write_pos;          // 当前写入位置
    size_t bytes_available;    // 当前有效数据量
    pthread_mutex_t mutex;     // 互斥锁
} SharedBuffer;

// 读取/proc/net/udp的线程函数
void* reader_thread(void* arg) {
    SharedBuffer* sbuf = (SharedBuffer*)arg;
    char temp_buf[BUFFER_SIZE]; // 临时读取缓冲区

    while (1) {
        // 读取/proc/net/udp文件内容
        FILE* fp = fopen("/proc/net/udp", "r");
        if (fp) {
            size_t bytes_read = fread(temp_buf, 1, BUFFER_SIZE, fp);
            fclose(fp);

            pthread_mutex_lock(&sbuf->mutex);
            
            // 处理缓冲区写入
            if (bytes_read > 0) {
                // 计算可用空间
                size_t free_space = BUFFER_SIZE - sbuf->bytes_available;
                
                if (bytes_read > BUFFER_SIZE) {
                    // 如果读取的数据超过缓冲区大小，只保留最后的部分
                    memcpy(sbuf->buffer, 
                          temp_buf + (bytes_read - BUFFER_SIZE), 
                          BUFFER_SIZE);
                    sbuf->write_pos = 0;
                    sbuf->bytes_available = BUFFER_SIZE;
                } else {
                    // 计算需要覆盖的旧数据量
                    size_t overflow = (sbuf->bytes_available + bytes_read > BUFFER_SIZE) ?
                                     (sbuf->bytes_available + bytes_read - BUFFER_SIZE) : 0;

                    // 写入新数据到环形缓冲区
                    size_t first_chunk = BUFFER_SIZE - sbuf->write_pos;
                    if (first_chunk > bytes_read) {
                        first_chunk = bytes_read;
                    }

                    // 分两部分写入
                    memcpy(sbuf->buffer + sbuf->write_pos, temp_buf, first_chunk);
                    memcpy(sbuf->buffer, 
                          temp_buf + first_chunk, 
                          bytes_read - first_chunk);

                    // 更新写入位置和有效字节数
                    sbuf->write_pos = (sbuf->write_pos + bytes_read) % BUFFER_SIZE;
                    sbuf->bytes_available = (sbuf->bytes_available + bytes_read > BUFFER_SIZE) ?
                                           BUFFER_SIZE : sbuf->bytes_available + bytes_read;
                }
            }
            
            pthread_mutex_unlock(&sbuf->mutex);
        } else {
            perror("Error opening /proc/net/udp");
        }
        
        sleep(READ_INTERVAL);
    }
    return NULL;
}

int main() {
    SharedBuffer sbuf = {
        .write_pos = 0,
        .bytes_available = 0,
        .mutex = PTHREAD_MUTEX_INITIALIZER
    };

    // 创建读取线程
    pthread_t tid;
    if (pthread_create(&tid, NULL, reader_thread, &sbuf) != 0) {
        perror("Failed to create thread");
        return 1;
    }

    // 主线程打印循环
    while (1) {
        sleep(PRINT_INTERVAL);
        
        pthread_mutex_lock(&sbuf.mutex);
        
        // 创建临时缓冲区用于安全读取
        char print_buf[BUFFER_SIZE + 1] = {0};
        
        if (sbuf.bytes_available > 0) {
            size_t first_chunk = BUFFER_SIZE - sbuf.write_pos;
            if (first_chunk > sbuf.bytes_available) {
                first_chunk = sbuf.bytes_available;
            }
            
            // 复制环形缓冲区内容
            memcpy(print_buf, sbuf.buffer + sbuf.write_pos, first_chunk);
            memcpy(print_buf + first_chunk, 
                  sbuf.buffer, 
                  sbuf.bytes_available - first_chunk);
        }
        
        pthread_mutex_unlock(&sbuf.mutex);
        
        // 打印结果
        printf("=== UDP Socket Information (%zu bytes) ===\n", sbuf.bytes_available);
        fwrite(print_buf, 1, sbuf.bytes_available, stdout);
        printf("\n==========================================\n\n");
    }

    // 理论上应该添加线程清理代码，但这里保持示例简单
    return 0;
}
