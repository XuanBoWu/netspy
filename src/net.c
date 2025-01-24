#include <stdio.h>
#include <pcap.h>
#include "net.h"

int check_interface(){
    char buf_err[PCAP_BUF_SIZE];
    pcap_if_t *intf;

    if (pcap_findalldevs(&intf, buf_err) != 0){
        printf("NET INTERFACE FAILED\n");
    } else {
        printf("Interface info:\n");
    }
    return 0;
}