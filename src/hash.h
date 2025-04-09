#pragma once
#include "uthash.h"


// 节点结构定义
typedef struct Node {
    int key;                // 唯一标识
    void* value;            // 指向任意数据的指针
    struct Node* next;      // 队列中的下一个节点
    struct Node* prev;      // 队列中的前一个节点
    UT_hash_handle hh;      // uthash处理句柄
} Node;

// 队列管理结构
typedef struct {
    Node* head;              // 队列头（最老的元素）
    Node* tail;              // 队列尾（最新的元素）
    Node* hash_table;        // uthash哈希表
    int size;                // 当前队列大小
    int capacity;            // 队列最大容量
} Queue;

Queue* queue_init(int capacity);
Node* find_node(Queue* queue, int key);
void append_to_queue(Queue* queue, Node* node);
void remove_from_queue(Queue* queue, Node* node);
void queue_put(Queue* queue, int key, void* value, void (*free_value)(void*));
void* queue_get(Queue* queue, int key);
void queue_print(Queue* queue, void (*print_value)(int key, void* value));
void queue_free(Queue* queue, void (*free_value)(void*));