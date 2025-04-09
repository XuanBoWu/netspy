#include <stdio.h>
#include <time.h>
#include "../src/hash.h"


// 定义复杂数据结构
typedef struct {
    int id;
    char* name;
    double price;
    time_t timestamp;
    int* related_ids;
    int related_count;
} Product;

// 释放Product的函数
void free_product(void* p) {
    Product* product = (Product*)p;
    if (product) {
        if (product->name) free(product->name);
        if (product->related_ids) free(product->related_ids);
        free(product);
    }
}

// 打印Product的函数
void print_product(int key, void* p) {
    Product* product = (Product*)p;
    if (!product) {
        printf("NULL");
        return;
    }
    
    printf("Product{id=%d, name='%s', price=%.2f, timestamp=%ld, related=[", 
           product->id, product->name, product->price, product->timestamp);
    
    for (int i = 0; i < product->related_count; i++) {
        if (i > 0) printf(", ");
        printf("%d", product->related_ids[i]);
    }
    printf("]}");
}

// 创建测试用的Product
Product* create_product(int id, const char* name, double price, int related_count) {
    Product* p = (Product*)malloc(sizeof(Product));
    if (!p) return NULL;
    
    p->id = id;
    p->name = strdup(name);
    p->price = price;
    p->timestamp = time(NULL);
    p->related_count = related_count;
    
    if (related_count > 0) {
        p->related_ids = (int*)malloc(related_count * sizeof(int));
        for (int i = 0; i < related_count; i++) {
            p->related_ids[i] = rand() % 100; // 随机生成相关ID
        }
    } else {
        p->related_ids = NULL;
    }
    
    return p;
}

int main() {
    // 初始化随机数种子
    srand(time(NULL));
    
    // 创建容量为20的队列
    Queue* queue = queue_init(20);
    if (!queue) {
        printf("Failed to initialize queue\n");
        return 1;
    }
    
    printf("=== 测试开始 ===\n");
    
    // 添加10个产品到队列中
    for (int i = 1; i <= 10; i++) {
        char name[20];
        snprintf(name, sizeof(name), "Product-%d", i);
        
        Product* p = create_product(i, name, 9.99 + i, i % 3 + 1);
        if (!p) {
            printf("Failed to create product %d\n", i);
            continue;
        }
        
        queue_put(queue, i, p, free_product);
        printf("添加产品: ");
        print_product(i, p);
        printf("\n");
    }
    
    // 打印当前队列状态
    printf("\n当前队列内容:\n");
    queue_print(queue, print_product);
    
    // 测试更新操作
    printf("\n更新产品5:\n");
    Product* updated_p5 = create_product(5, "Updated-Product-5", 19.99, 2);
    queue_put(queue, 5, updated_p5, free_product);
    queue_print(queue, print_product);
    
    // 测试获取操作
    printf("\n获取产品3:\n");
    Product* p3 = (Product*)queue_get(queue, 3);
    if (p3) {
        printf("找到产品3: ");
        print_product(3, p3);
        printf("\n");
    } else {
        printf("未找到产品3\n");
    }
    
    // 测试获取不存在的产品
    printf("\n获取不存在的产品99:\n");
    Product* p99 = (Product*)queue_get(queue, 99);
    if (p99) {
        printf("找到产品99: ");
        print_product(99, p99);
        printf("\n");
    } else {
        printf("未找到产品99\n");
    }
    
    // 填满队列
    printf("\n填满队列到容量上限:\n");
    for (int i = 11; i <= 25; i++) {
        char name[20];
        snprintf(name, sizeof(name), "Extra-Product-%d", i);
        
        Product* p = create_product(i, name, 5.99 + i, i % 4);
        if (!p) {
            printf("Failed to create product %d\n", i);
            continue;
        }
        
        queue_put(queue, i, p, free_product);
    }
    printf("队列大小: %d (容量: %d)\n", queue->size, queue->capacity);
    queue_print(queue, print_product);
    
    // 释放队列
    queue_free(queue, free_product);
    
    printf("\n=== 测试结束 ===\n");
    return 0;
}
