#include <stdio.h>
int main() {
    int num = 1;
    char *ptr = (char *)&num;
    if (*ptr == 1) {
        printf("Little-Endian\n");
    } else {
        printf("Big-Endian\n");
    }
    return 0;
}