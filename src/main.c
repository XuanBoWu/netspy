#include <stdio.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>
#include "net.h"
#include "cap.h"
#include "socket.h"

int main(int argc, char *argv[]){
    int opt;
    char *file_name = NULL;
    char *interface = NULL;

    // while((opt = getopt(argc, argv, "i:")) != -1) {
    //      switch (opt) {
    //         case 'i':
    //             interface = optarg; // optarg 存储选项的参数值
    //             break;
    //         case '?':
    //             fprintf(stderr, "未知选项: -%c\n", optopt);
    //             return 1;
    //         default:
    //             fprintf(stderr, "用法: %s [-i 接口名]\n", argv[0]);
    //             return 1;
    //     }
    // }

    // print_interface();
    printf("main:\n");
    
    // 初始化 队列
    const Queue* queue = queue_init(200);
    refresh_socket(queue);
    return 0;
    // 子线程定时刷新 socket 信息并缓存
    pthread_t refresh_tid;
    pthread_create(&refresh_tid, NULL, refresh_socket, (void*)&queue);

    net_cap();
    // cap_dns_info(interface);

    return 0;
}