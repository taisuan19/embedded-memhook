#include <stdio.h>
#include <errno.h>
// memhook_wrap.c - wrap 版：编进可执行 + 链接用 --wrap
#ifdef __cplusplus
extern "C" {
#endif
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#ifndef MEMHOOK_LOG_PATH_FMT
#define MEMHOOK_LOG_PATH_FMT "/mnt/mmc/memhook_%u.bin"  /* 新默认：按 PID + CLOCK_MONOTONIC单调时钟 命名*/
#endif

#ifndef MEMHOOK_FILENAME_MS
// 1=用毫秒；0=用秒
#define MEMHOOK_FILENAME_MS 1
#endif

#define SYS_WRITE(fd, buf, sz) syscall(SYS_write, (fd), (buf), (sz))
#define SYS_GETTID()           ((pid_t)syscall(SYS_gettid))

static __thread int g_in_hook = 0;
static int g_log_fd = -1;

typedef struct __attribute__((packed)) {
    uint64_t ts_ns;     // monotonic ns
    uint64_t wall_ns;   // real system time ns since epoch
    uint32_t tid;
    uint16_t op;
    uint16_t pad;
    uint64_t ptr;
    uint64_t arg;
    uint64_t retaddr;
} rec_t;

static inline void open_log(void){
    if (g_log_fd >= 0) return;

    struct timespec ts = {0,0};
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);

#if MEMHOOK_FILENAME_MS
    unsigned long long up = (unsigned long long)ts.tv_sec * 1000ull
                          + (unsigned long long)(ts.tv_nsec / 1000000ull);
    char path[192], path2[200];
    snprintf(path, sizeof(path), "/mnt/mmc/memhook_%u_up%llums.bin",
             (unsigned)getpid(), up);
#else
    unsigned long long up = (unsigned long long)ts.tv_sec;
    char path[192], path2[200];
    snprintf(path, sizeof(path), "/mnt/mmc/memhook_%u_up%llus.bin",
             (unsigned)getpid(), up);
#endif

    int fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0644);
    if (fd < 0 && errno == EEXIST) {
        snprintf(path2, sizeof(path2), "%s.1", path);
        fd = open(path2, O_CREAT | O_WRONLY | O_EXCL, 0644);
        if (fd < 0 && errno == EEXIST) {
            fd = open(path2, O_WRONLY | O_APPEND);
            if (fd < 0) fd = open(path2, O_CREAT | O_WRONLY | O_APPEND, 0644);
        }
    }
    if (fd >= 0) g_log_fd = fd;
}

static inline void logrec(uint16_t op, void* p, uint64_t arg, void* ra){
    if (g_log_fd < 0) return;
    rec_t r;
    struct timespec ts, ts_wall;

    if (clock_gettime(CLOCK_MONOTONIC, &ts)==0)
        r.ts_ns = (uint64_t)ts.tv_sec*1000000000ull + ts.tv_nsec;
    else
        r.ts_ns = 0;

    if (clock_gettime(CLOCK_REALTIME, &ts_wall)==0)
        r.wall_ns = (uint64_t)ts_wall.tv_sec*1000000000ull + ts_wall.tv_nsec;
    else
        r.wall_ns = 0;

    r.tid = (uint32_t)SYS_GETTID();
    r.op  = op; r.pad = 0;
    r.ptr = (uint64_t)(uintptr_t)p;
    r.arg = arg;
    r.retaddr = (uint64_t)(uintptr_t)ra;
    (void)SYS_WRITE(g_log_fd, &r, sizeof(r));
}

__attribute__((constructor))
static void memhook_init(void){ open_log(); }

__attribute__((destructor))
static void memhook_fini(void){
    if (g_log_fd >= 0) { (void)syscall(SYS_fsync, g_log_fd); close(g_log_fd); g_log_fd = -1; }
}

/* 声明真实符号（由链接器提供） */
void* __real_malloc(size_t);
void  __real_free(void*);
void* __real_realloc(void*, size_t);
void* __real_calloc(size_t, size_t);

/* 拦截实现 */
void* __wrap_malloc(size_t sz){
    open_log();
    if (g_in_hook) return __real_malloc(sz);
    g_in_hook = 1;
    void* p = __real_malloc(sz);
    logrec(0, p, sz, __builtin_return_address(0));
    g_in_hook = 0; return p;
}

void  __wrap_free(void* p){
    open_log();
    if (g_in_hook){ __real_free(p); return; }
    g_in_hook = 1;
    logrec(1, p, 0, __builtin_return_address(0));
    __real_free(p);
    g_in_hook = 0;
}

void* __wrap_realloc(void* p, size_t sz){
    open_log();
    if (g_in_hook) return __real_realloc(p, sz);
    g_in_hook = 1;
    void* ra = __builtin_return_address(0);
    logrec(2, p, sz, ra);                 /* old */
    void* np = __real_realloc(p, sz);
    logrec(2, np, sz, ra);                /* new */
    g_in_hook = 0; return np;
}

void* __wrap_calloc(size_t n, size_t sz){
    open_log();
    if (g_in_hook) return __real_calloc(n, sz);
    g_in_hook = 1;
    void* p = __real_calloc(n, sz);
    logrec(3, p, (uint64_t)n*sz, __builtin_return_address(0));
    g_in_hook = 0; return p;
}
#ifdef __cplusplus
}
#endif
