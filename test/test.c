#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

typedef struct{
    
} thread_arg;

void test_thread(int id) {
    while(1){
        printf("Thread %d\n", id);
        usleep(500);
    }   
}

int main() {

    printf("Start Main:\n");
    
    pthread_t thread1;

    pthread_create(&thread1, NULL, (void *)&test_thread, (void *)1);
    while(1){
        printf("Main Thread\n");
        usleep(500);
    }

    return 0;
}