/**
 * IDA-MCP 复杂测试程序
 * 
 * 用途：测试高级 IDA 分析功能
 * - 结构体和类型系统
 * - 函数指针
 * - 复杂的调用图
 * - 栈变量
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// 结构体定义
// ============================================================================

typedef struct {
    int x;
    int y;
} Point;

typedef struct {
    Point top_left;
    Point bottom_right;
    unsigned int color;
    char name[32];
} Rectangle;

typedef struct Node {
    int value;
    struct Node* next;
    struct Node* prev;
} Node;

typedef struct {
    Node* head;
    Node* tail;
    int count;
} LinkedList;

// 函数指针类型
typedef int (*BinaryOp)(int, int);
typedef void (*Callback)(void* data, int result);

// ============================================================================
// 全局变量
// ============================================================================

static Rectangle g_rects[10];
static int g_rect_count = 0;
static LinkedList g_list = {NULL, NULL, 0};

const char* ERROR_MESSAGES[] = {
    "Success",
    "Out of memory",
    "Invalid argument",
    "Not found",
    "Already exists"
};

// ============================================================================
// Point 操作
// ============================================================================

Point point_create(int x, int y) {
    Point p = {x, y};
    return p;
}

int point_distance_squared(Point* a, Point* b) {
    int dx = a->x - b->x;
    int dy = a->y - b->y;
    return dx * dx + dy * dy;
}

void point_translate(Point* p, int dx, int dy) {
    p->x += dx;
    p->y += dy;
}

// ============================================================================
// Rectangle 操作
// ============================================================================

int rect_init(Rectangle* r, int x1, int y1, int x2, int y2, 
              unsigned int color, const char* name) {
    if (!r || !name) return 2;  // Invalid argument
    
    r->top_left = point_create(x1, y1);
    r->bottom_right = point_create(x2, y2);
    r->color = color;
    strncpy(r->name, name, sizeof(r->name) - 1);
    r->name[sizeof(r->name) - 1] = '\0';
    return 0;
}

int rect_width(Rectangle* r) {
    return r->bottom_right.x - r->top_left.x;
}

int rect_height(Rectangle* r) {
    return r->bottom_right.y - r->top_left.y;
}

int rect_area(Rectangle* r) {
    return rect_width(r) * rect_height(r);
}

int rect_contains_point(Rectangle* r, Point* p) {
    return (p->x >= r->top_left.x && p->x <= r->bottom_right.x &&
            p->y >= r->top_left.y && p->y <= r->bottom_right.y);
}

// ============================================================================
// LinkedList 操作
// ============================================================================

Node* node_create(int value) {
    Node* n = (Node*)malloc(sizeof(Node));
    if (!n) return NULL;
    n->value = value;
    n->next = NULL;
    n->prev = NULL;
    return n;
}

int list_push_back(LinkedList* list, int value) {
    Node* n = node_create(value);
    if (!n) return 1;  // Out of memory
    
    if (list->tail) {
        list->tail->next = n;
        n->prev = list->tail;
        list->tail = n;
    } else {
        list->head = list->tail = n;
    }
    list->count++;
    return 0;
}

int list_push_front(LinkedList* list, int value) {
    Node* n = node_create(value);
    if (!n) return 1;
    
    if (list->head) {
        list->head->prev = n;
        n->next = list->head;
        list->head = n;
    } else {
        list->head = list->tail = n;
    }
    list->count++;
    return 0;
}

int list_pop_front(LinkedList* list) {
    if (!list->head) return -1;
    
    Node* old = list->head;
    int value = old->value;
    
    list->head = old->next;
    if (list->head) {
        list->head->prev = NULL;
    } else {
        list->tail = NULL;
    }
    
    free(old);
    list->count--;
    return value;
}

Node* list_find(LinkedList* list, int value) {
    Node* curr = list->head;
    while (curr) {
        if (curr->value == value)
            return curr;
        curr = curr->next;
    }
    return NULL;
}

void list_clear(LinkedList* list) {
    while (list->head) {
        list_pop_front(list);
    }
}

void list_foreach(LinkedList* list, Callback cb, void* user_data) {
    Node* curr = list->head;
    while (curr) {
        cb(user_data, curr->value);
        curr = curr->next;
    }
}

// ============================================================================
// 函数指针示例
// ============================================================================

int op_add(int a, int b) { return a + b; }
int op_sub(int a, int b) { return a - b; }
int op_mul(int a, int b) { return a * b; }
int op_div(int a, int b) { return b ? a / b : 0; }

static BinaryOp operations[] = {op_add, op_sub, op_mul, op_div};

int apply_operation(int op_index, int a, int b) {
    if (op_index < 0 || op_index >= 4)
        return 0;
    return operations[op_index](a, b);
}

// ============================================================================
// 复杂栈使用示例
// ============================================================================

typedef struct {
    char name[64];
    int values[16];
    double factor;
} StackHeavyStruct;

int process_data(int* data, int count) {
    StackHeavyStruct local_struct;
    int sum = 0;
    int min_val = data[0];
    int max_val = data[0];
    
    memset(&local_struct, 0, sizeof(local_struct));
    strcpy(local_struct.name, "ProcessedData");
    local_struct.factor = 1.5;
    
    for (int i = 0; i < count && i < 16; i++) {
        local_struct.values[i] = data[i];
        sum += data[i];
        
        if (data[i] < min_val) min_val = data[i];
        if (data[i] > max_val) max_val = data[i];
    }
    
    printf("Processed: name=%s, sum=%d, min=%d, max=%d\n",
           local_struct.name, sum, min_val, max_val);
    
    return sum;
}

// ============================================================================
// 回调示例
// ============================================================================

void print_callback(void* data, int result) {
    int* counter = (int*)data;
    printf("  Item %d: %d\n", (*counter)++, result);
}

void sum_callback(void* data, int result) {
    int* sum = (int*)data;
    *sum += result;
}

// ============================================================================
// 主函数
// ============================================================================

int main(int argc, char* argv[]) {
    printf("=== IDA-MCP Complex Test Program ===\n\n");
    
    // 测试 Rectangle
    printf("-- Rectangle Test --\n");
    Rectangle rect;
    rect_init(&rect, 10, 20, 110, 70, 0xFF0000, "TestRect");
    printf("Rect '%s': area=%d, width=%d, height=%d\n",
           rect.name, rect_area(&rect), rect_width(&rect), rect_height(&rect));
    
    Point p = point_create(50, 40);
    printf("Point (50,40) in rect: %s\n", 
           rect_contains_point(&rect, &p) ? "yes" : "no");
    
    // 测试 LinkedList
    printf("\n-- LinkedList Test --\n");
    for (int i = 1; i <= 5; i++) {
        list_push_back(&g_list, i * 10);
    }
    
    int counter = 0;
    printf("List items:\n");
    list_foreach(&g_list, print_callback, &counter);
    
    int sum = 0;
    list_foreach(&g_list, sum_callback, &sum);
    printf("Sum of all items: %d\n", sum);
    
    // 测试函数指针
    printf("\n-- Function Pointer Test --\n");
    printf("add(10, 5) = %d\n", apply_operation(0, 10, 5));
    printf("sub(10, 5) = %d\n", apply_operation(1, 10, 5));
    printf("mul(10, 5) = %d\n", apply_operation(2, 10, 5));
    printf("div(10, 5) = %d\n", apply_operation(3, 10, 5));
    
    // 测试复杂栈
    printf("\n-- Stack Heavy Test --\n");
    int test_data[] = {5, 12, 3, 8, 15, 7, 9, 1};
    process_data(test_data, 8);
    
    // 清理
    list_clear(&g_list);
    
    printf("\n=== Test Completed ===\n");
    return 0;
}

