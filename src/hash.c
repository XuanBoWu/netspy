#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"



// 初始化队列
Queue* queue_init(int capacity) {
    Queue* queue = (Queue*)malloc(sizeof(Queue));
    if (!queue) return NULL;
    
    queue->head = NULL;
    queue->tail = NULL;
    queue->hash_table = NULL;
    queue->size = 0;
    queue->capacity = capacity > 0 ? capacity : 100;
    
    return queue;
}

// 在哈希表中查找节点
Node* find_node(Queue* queue, int key) {
    Node* node;
    HASH_FIND_INT(queue->hash_table, &key, node);
    return node;
}

// 添加节点到队列尾部
void append_to_queue(Queue* queue, Node* node) {
    if (!queue->tail) {  // 队列为空
        queue->head = node;
        queue->tail = node;
        node->next = NULL;
        node->prev = NULL;
    } else {  // 队列不为空
        node->prev = queue->tail;
        node->next = NULL;
        queue->tail->next = node;
        queue->tail = node;
    }
}

// 从队列中移除节点（但不从哈希表中移除）
void remove_from_queue(Queue* queue, Node* node) {
    if (node->prev) {
        node->prev->next = node->next;
    } else {
        queue->head = node->next;  // 移除的是头节点
    }
    
    if (node->next) {
        node->next->prev = node->prev;
    } else {
        queue->tail = node->prev;  // 移除的是尾节点
    }
}

// 添加或更新节点
void queue_put(Queue* queue, int key, void* value, void (*free_value)(void*)) {
    Node* node = find_node(queue, key);
    
    if (node) {  // 节点已存在，更新值
        if (free_value && node->value) {
            free_value(node->value);  // 释放旧值的资源
        }
        node->value = value;
    } else {  // 节点不存在，创建新节点
        node = (Node*)malloc(sizeof(Node));
        if (!node) return;  // 内存分配失败
        
        node->key = key;
        node->value = value;
        
        HASH_ADD_INT(queue->hash_table, key, node);  // 添加到哈希表
        
        if (queue->size >= queue->capacity) {  // 队列已满，移除最老的节点
            Node* oldest = queue->head;
            remove_from_queue(queue, oldest);
            HASH_DEL(queue->hash_table, oldest);  // 从哈希表中移除
            if (free_value && oldest->value) {
                free_value(oldest->value);  // 释放值的资源
            }
            free(oldest);
        } else {
            queue->size++;
        }
        
        append_to_queue(queue, node);  // 添加到队列尾部
    }
}

// 查询节点
void* queue_get(Queue* queue, int key) {
    Node* node = find_node(queue, key);
    return node ? node->value : NULL;
}

// 打印队列内容（需要用户提供打印函数）
void queue_print(Queue* queue, void (*print_value)(int key, void* value)) {
    printf("Queue (size: %d):\n", queue->size);
    Node* current = queue->head;
    while (current) {
        printf("Key: %d, Value: ", current->key);
        if (print_value) {
            print_value(current->key, current->value);
        } else {
            printf("%p", current->value);
        }
        printf("\n");
        current = current->next;
    }
    printf("-----------------------\n");
}

// 释放队列资源
void queue_free(Queue* queue, void (*free_value)(void*)) {
    Node *current, *tmp;
    
    HASH_ITER(hh, queue->hash_table, current, tmp) {
        HASH_DEL(queue->hash_table, current);
        if (free_value && current->value) {
            free_value(current->value);  // 释放值的资源
        }
        free(current);
    }
    
    free(queue);
}
