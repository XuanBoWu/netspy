#include <stdio.h>
#include <unistd.h>
#include "net.h"

int main(int argc, char *argv[]){
    int opt;
    char *file_name = NULL;
    char *interface = NULL;

    while((opt = getopt(argc, argv, "i:")) != -1) {
         switch (opt) {
            case 'i':
                interface = optarg; // optarg 存储选项的参数值
                break;
            case '?':
                fprintf(stderr, "未知选项: -%c\n", optopt);
                return 1;
            default:
                fprintf(stderr, "用法: %s [-i 接口名]\n", argv[0]);
                return 1;
        }
    }

    // print_interface();
    // cap_netinfo(interface);
    cap_dns_info(interface);

    return 0;
}