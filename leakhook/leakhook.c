// leakhook.c  (gcc -shared -fPIC -ldl -pthread -o libleakhook.so leakhook.c)
// 可选：-lunwind 或 -lexecinfo 以开启回溯
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <execinfo.h>   // 若musl无此头，可改用 libunwind
#include <unistd.h>

typedef struct Node {
    void* ptr;
    size_t size;
    uint64_t tid;
    uint32_t hash;
    int bt_n;
    void* bt[16];   // 调用栈（可调小以省内存）
    struct Node* next;
} Node;

static void* (*real_malloc)(size_t)=NULL;
static void  (*real_free)(void*)=NULL;
static void* (*real_calloc)(size_t,size_t)=NULL;
static void* (*real_realloc)(void*,size_t)=NULL;

#define HSIZE  65536   // 哈希桶
static Node* g_tab[HSIZE];
static pthread_mutex_t g_mu[HSIZE];
static atomic_size_t g_inuse = 0;

static inline uint32_t h32(uint64_t x){ x^=x>>33; x*=0xff51afd7ed558ccdULL; x^=x>>33; x*=0xc4ceb9fe1a85ec53ULL; x^=x>>33; return (uint32_t)x; }
static inline uint64_t get_tid(){ return (uint64_t)pthread_self(); }

static __attribute__((constructor)) void init_hook(){
    real_malloc  = dlsym(RTLD_NEXT,"malloc");
    real_free    = dlsym(RTLD_NEXT,"free");
    real_calloc  = dlsym(RTLD_NEXT,"calloc");
    real_realloc = dlsym(RTLD_NEXT,"realloc");
    for(int i=0;i<HSIZE;++i) pthread_mutex_init(&g_mu[i], NULL);
}

static void record_alloc(void* p, size_t sz){
    if(!p) return;
    Node* n = real_malloc(sizeof(Node));
    if(!n) return;
    n->ptr=p; n->size=sz; n->tid=get_tid();
    n->bt_n = backtrace(n->bt, 16); // 若不可用，可置0
    uint32_t k = h32((uint64_t)p);
    n->hash=k; int b = k & (HSIZE-1);
    pthread_mutex_lock(&g_mu[b]);
    n->next = g_tab[b]; g_tab[b]=n;
    pthread_mutex_unlock(&g_mu[b]);
    atomic_fetch_add(&g_inuse, sz);
}

static void record_free(void* p){
    if(!p) return;
    uint32_t k = h32((uint64_t)p);
    int b = k & (HSIZE-1);
    pthread_mutex_lock(&g_mu[b]);
    Node** pp = &g_tab[b];
    while(*pp){
        if((*pp)->ptr==p){
            Node* del=*pp; *pp=del->next;
            atomic_fetch_sub(&g_inuse, del->size);
            pthread_mutex_unlock(&g_mu[b]);
            real_free(del);
            return;
        }
        pp=&(*pp)->next;
    }
    pthread_mutex_unlock(&g_mu[b]);
    // double free / 外部释放，不处理
}

void* malloc(size_t sz){ void* p = real_malloc(sz); record_alloc(p, sz); return p; }
void  free(void* p){ record_free(p); real_free(p); }
void* calloc(size_t n,size_t s){ void* p=real_calloc(n,s); record_alloc(p, n*s); return p; }
void* realloc(void* p,size_t s){
    if(p) record_free(p);
    void* np = real_realloc(p,s);
    record_alloc(np, s);
    return np;
}

// 信号触发报告： kill -USR1 <pid>
#include <signal.h>
static void dump_report(){
    fprintf(stderr,"[leakhook] inuse=%zu bytes, report top (by size) ...\n", (size_t)atomic_load(&g_inuse));
    // 简单按桶扫描，打印若干条目；生产上可做聚合(按回溯签名哈希)
    int printed=0;
    for(int i=0;i<HSIZE && printed<100;i++){
        pthread_mutex_lock(&g_mu[i]);
        for(Node* n=g_tab[i]; n && printed<100; n=n->next){
            fprintf(stderr," ptr=%p size=%zu tid=%llu bt=%d\n",
                n->ptr, n->size, (unsigned long long)n->tid, n->bt_n);
            if(n->bt_n>0){
                char** syms = backtrace_symbols(n->bt, n->bt_n);
                if(syms){
                    for(int j=0;j<n->bt_n;j++) fprintf(stderr,"    %s\n", syms[j]);
                    real_free(syms);
                }
            }
            printed++;
        }
        pthread_mutex_unlock(&g_mu[i]);
    }
}

static void on_sigusr1(int){ dump_report(); }
static __attribute__((constructor)) void hook_sig(){
    struct sigaction sa={0}; sa.sa_handler=on_sigusr1; sigaction(SIGUSR1,&sa,NULL);
}
