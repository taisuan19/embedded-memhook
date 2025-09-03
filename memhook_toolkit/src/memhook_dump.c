// memhook_dump.c - decode memhook.bin (40 or 48 bytes/record) to CSV + summary + leak list
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

/* ---- record formats ---- */
#pragma pack(push,1)
typedef struct {                    /* v1: 40B, no wall_ns */
    uint64_t ts_ns;
    uint32_t tid;
    uint16_t op;
    uint16_t pad;
    uint64_t ptr;
    uint64_t arg;
    uint64_t retaddr;
} rec_v1;

typedef struct {                    /* v2: 48B, with wall_ns */
    uint64_t ts_ns;
    uint64_t wall_ns;               /* NEW in v2 */
    uint32_t tid;
    uint16_t op;
    uint16_t pad;
    uint64_t ptr;
    uint64_t arg;
    uint64_t retaddr;
} rec_v2;
#pragma pack(pop)

/* ---- utils ---- */
static const char* op_name(uint16_t op){
    switch(op){
        case 0: return "malloc";
        case 1: return "free";
        case 2: return "realloc";
        case 3: return "calloc";
        default: return "?";
    }
}
static const char* human(uint64_t n, char buf[32]){
    static const char* u[]={"B","KB","MB","GB","TB"};
    double d=(double)n; int i=0;
    while(d>=1024 && i<4){ d/=1024.0; i++; }
    snprintf(buf,32,"%.2f%s",d,u[i]);
    return buf;
}
/* 相对时间（毫秒精度）："t+SSS.mmm" */
static void tsns_to_short_ms(uint64_t ts_ns, uint64_t base_ns, char out[24]){
    uint64_t rel = (base_ns && ts_ns >= base_ns) ? (ts_ns - base_ns) : ts_ns;
    uint64_t sec = rel / 1000000000ull;
    uint64_t ms  = (rel % 1000000000ull) / 1000000ull;
    snprintf(out, 24, "t+%llu.%03llu",
             (unsigned long long)sec, (unsigned long long)ms);
}
/* 系统时间（毫秒精度）："YYYY-MM-DD HH:MM:SS.mmm"；无则 "-" */
static void wallns_to_full_ms(uint64_t wall_ns, char out[32]){
    if(!wall_ns){ strcpy(out, "-"); return; }
    time_t sec = (time_t)(wall_ns / 1000000000ull);
    unsigned long ms = (unsigned long)((wall_ns % 1000000000ull) / 1000000ull);
    struct tm tmv; localtime_r(&sec, &tmv);                 /* 如需 UTC 用 gmtime_r */
    strftime(out, 32, "%Y-%m-%d %H:%M:%S", &tmv);
    size_t len = strlen(out);
    if (len < 31) snprintf(out + len, 32 - len, ".%03lu", ms);
}
/* 持续时间 ns -> "HH:MM:SS.mmm" */
static void span_ns_to_hhmmss_ms(uint64_t ns, char out[32]){
    unsigned long long total_ms = ns / 1000000ull;
    unsigned long long ms = total_ms % 1000ull;
    unsigned long long total_s = total_ms / 1000ull;
    unsigned long long s = total_s % 60ull;
    unsigned long long m = (total_s / 60ull) % 60ull;
    unsigned long long h = total_s / 3600ull;
    snprintf(out, 32, "%02llu:%02llu:%02llu.%03llu", h, m, s, ms);
}

/* ---- live set ---- */
typedef struct Live {
    uint64_t ptr, size, ts_ns, wall_ns, ra;
    uint32_t tid;
    struct Live* next;
} Live;
static Live* live_head=NULL;

static void add_live(uint64_t ptr,uint64_t size,uint32_t tid,uint64_t ts,uint64_t wall,uint64_t ra){
    Live* n=(Live*)malloc(sizeof(Live));
    if(!n) return;
    n->ptr=ptr; n->size=size; n->tid=tid; n->ts_ns=ts; n->wall_ns=wall; n->ra=ra;
    n->next=live_head; live_head=n;
}
static int del_live(uint64_t ptr, uint64_t* out_size){
    Live **pp=&live_head, *p=live_head;
    while(p){
        if(p->ptr==ptr){
            if(out_size) *out_size = p->size;
            *pp=p->next; free(p); return 1;
        }
        pp=&p->next; p=p->next;
    }
    return 0;
}

/* ---- leak rows ---- */
typedef struct {
    uint64_t ptr, size, ts_ns, wall_ns, ra;
    uint32_t tid;
} LeakRow;

/* 默认：size 降序；时间较晚者在后（ts 升序） */
static int cmp_leak_desc(const void* a,const void* b){
    const LeakRow* x=(const LeakRow*)a; const LeakRow* y=(const LeakRow*)b;
    if (y->size > x->size) return 1;
    if (y->size < x->size) return -1;
    if (x->ts_ns < y->ts_ns) return -1;   /* 更早的在前 */
    if (x->ts_ns > y->ts_ns) return 1;
    return 0;
}
/* 新增：按时间升序 */
static int cmp_leak_time_asc(const void* a,const void* b){
    const LeakRow* x=(const LeakRow*)a; const LeakRow* y=(const LeakRow*)b;
    if (x->ts_ns < y->ts_ns) return -1;
    if (x->ts_ns > y->ts_ns) return 1;
    /* 次关键字：size 降序（方便看大块） */
    if (y->size > x->size) return 1;
    if (y->size < x->size) return -1;
    return 0;
}

/* ---- options ---- */
typedef struct {
    const char* bin_path;
    const char* csv_path;  /* NULL => no CSV */
    int live_all;          /* print all leaks */
    long live_top;         /* print top-N leaks (default 20) */
    uint64_t min_size;     /* only list/aggregate leaks >= min_size */
    int sort_time;         /* --time-asc: sort leaks by time ascending */
} Opts;

static void usage(const char* prog){
    fprintf(stderr,
        "Usage: %s memhook.bin [--csv out.csv] [--live-all] [--live-top N] [--min-size N] [--time-asc]\n"
        "  --csv out.csv   Write per-record CSV: idx,ts_ns,wall_ns,wall_time,tid,op,ptr,arg,retaddr\n"
        "                  (v1 files have wall_ns=0 & wall_time=\"-\")\n"
        "  --live-all      Print ALL unfreed (leak) blocks in summary\n"
        "  --live-top N    Print top N leaks by size (default 20)\n"
        "  --min-size N    Only count/list leaks with size >= N bytes (default 0)\n"
        "  --time-asc      Sort leaks by allocation time ascending\n",
        prog);
}
static int parse_long(const char* s, long* out){
    char* end=NULL; long v = strtol(s, &end, 10);
    if(!s || !*s || (end && *end!='\0')) return 0;
    *out=v; return 1;
}
static int parse_u64(const char* s, uint64_t* out){
    char* end=NULL; unsigned long long v = strtoull(s, &end, 10);
    if(!s || !*s || (end && *end!='\0')) return 0;
    *out=(uint64_t)v; return 1;
}

int main(int argc,char**argv){
    Opts opt; memset(&opt,0,sizeof(opt));
    opt.live_top = 20; /* default */

    if(argc<2){ usage(argv[0]); return 1; }
    opt.bin_path = argv[1];

    for(int i=2;i<argc;i++){
        if(strcmp(argv[i],"--csv")==0 && i+1<argc){ opt.csv_path=argv[++i]; continue; }
        if(strcmp(argv[i],"--live-all")==0){ opt.live_all=1; continue; }
        if(strcmp(argv[i],"--live-top")==0 && i+1<argc){ long v; if(parse_long(argv[++i],&v)) opt.live_top=v; continue; }
        if(strcmp(argv[i],"--min-size")==0 && i+1<argc){ uint64_t v; if(parse_u64(argv[++i],&v)) opt.min_size=v; continue; }
        if(strcmp(argv[i],"--time-asc")==0){ opt.sort_time=1; continue; }
        usage(argv[0]); return 1;
    }

    FILE* f=fopen(opt.bin_path,"rb"); if(!f){ perror("fopen"); return 2; }
    fseek(f,0,SEEK_END); long sz=ftell(f); rewind(f);

    /* 判断版本：48B(v2) 优先，否则 40B(v1)，否则尝试 v2 读失败再退 v1 */
    int is_v2=0;
    if (sz % (long)sizeof(rec_v2) == 0 && sz/(long)sizeof(rec_v2) > 0) is_v2=1;
    else if (sz % (long)sizeof(rec_v1) == 0 && sz/(long)sizeof(rec_v1) > 0) is_v2=0;
    else is_v2=1;

    long nrec = is_v2 ? (sz/(long)sizeof(rec_v2)) : (sz/(long)sizeof(rec_v1));

    FILE* fcsv=NULL;
    if(opt.csv_path){
        fcsv = fopen(opt.csv_path,"w");
        if(!fcsv){ perror("fopen csv"); fclose(f); return 3; }
        fprintf(fcsv,"idx,ts_ns,wall_ns,wall_time,tid,op,ptr,arg,retaddr\n");
    }

    uint64_t total_malloc=0,total_calloc=0,total_realloc_new=0,total_freed=0;
    uint64_t cnt[4]={0};
    uint64_t first_ts=0,last_ts=0;

    long idx=0;
    while(1){
        uint64_t wall_ns=0;
        rec_v1 r1;
        rec_v2 r2;

        if(is_v2){
            size_t n=fread(&r2,sizeof(r2),1,f);
            if(n!=1){
                if (!n && idx==0){ /* 可能不是 v2，退回 v1 */
                    is_v2=0; rewind(f); nrec = sz/(long)sizeof(rec_v1); continue;
                }
                break;
            }
            r1.ts_ns=r2.ts_ns; r1.tid=r2.tid; r1.op=r2.op; r1.pad=r2.pad;
            r1.ptr=r2.ptr; r1.arg=r2.arg; r1.retaddr=r2.retaddr;
            wall_ns=r2.wall_ns;
        }else{
            if(fread(&r1,sizeof(r1),1,f)!=1) break;
            wall_ns=0;
        }

        if(first_ts==0) first_ts=r1.ts_ns;
        last_ts=r1.ts_ns;

        if(fcsv){
            char wfull[32];
            wallns_to_full_ms(wall_ns, wfull);     /* v2 有值；v1 为 "-" */
            fprintf(fcsv,
                    "%ld,%" PRIu64 ",%" PRIu64 ",%s,%u,%s,0x%016" PRIx64 ",%" PRIu64 ",0x%016" PRIx64 "\n",
                    idx, r1.ts_ns, wall_ns, wfull, r1.tid, op_name(r1.op), r1.ptr, r1.arg, r1.retaddr);
        }

        if(r1.op<4) cnt[r1.op]++;
        if(r1.op==0){ add_live(r1.ptr,r1.arg,r1.tid,r1.ts_ns,wall_ns,r1.retaddr); total_malloc+=r1.arg; }
        else if(r1.op==3){ add_live(r1.ptr,r1.arg,r1.tid,r1.ts_ns,wall_ns,r1.retaddr); total_calloc+=r1.arg; }
        else if(r1.op==2){ /* realloc: old then new */
            uint64_t oldsz=0;
            if(del_live(r1.ptr,&oldsz)){ total_freed+=oldsz; }
            else { add_live(r1.ptr,r1.arg,r1.tid,r1.ts_ns,wall_ns,r1.retaddr); total_realloc_new+=r1.arg; }
        }
        else if(r1.op==1){ uint64_t oldsz=0; if(del_live(r1.ptr,&oldsz)){ total_freed+=oldsz; } }
        idx++;
    }
    fclose(f);
    if(fcsv) fclose(fcsv);

    /* collect leaks (apply min_size filter) */
    uint64_t live_bytes=0; uint64_t live_blocks=0;
    size_t cap=1024, nrows=0;
    LeakRow* rows = (LeakRow*)malloc(cap*sizeof(LeakRow));
    if(!rows) cap=nrows=0;
    for(Live* p=live_head;p;p=p->next){
        if(p->size < ((uint64_t)opt.min_size)) continue;
        live_bytes += p->size; live_blocks++;
        if(rows){
            if(nrows==cap){
                cap*=2;
                LeakRow* nr=(LeakRow*)realloc(rows,cap*sizeof(LeakRow));
                if(!nr){ free(rows); rows=NULL; cap=0; nrows=0; break; }
                rows=nr;
            }
            rows[nrows].ptr=p->ptr; rows[nrows].size=p->size; rows[nrows].tid=p->tid;
            rows[nrows].ts_ns=p->ts_ns; rows[nrows].wall_ns=p->wall_ns; rows[nrows].ra=p->ra; nrows++;
        }
    }
    if(rows && nrows>1){
        if(opt.sort_time)
            qsort(rows,nrows,sizeof(LeakRow),cmp_leak_time_asc);
        else
            qsort(rows,nrows,sizeof(LeakRow),cmp_leak_desc);
    }

    /* summary */
    char hm[32],hc[32],hr[32],hf[32],hl[32];
    uint64_t span_ns = (first_ts && last_ts && last_ts>=first_ts)? (last_ts-first_ts) : 0;
    char span_str[32]; span_ns_to_hhmmss_ms(span_ns, span_str);

    fprintf(stderr,
        "== summary ==\n"
        "records=%ld size=%ldB\n"
        "counts: malloc=%" PRIu64 " free=%" PRIu64 " realloc=%" PRIu64 " calloc=%" PRIu64 "\n"
        "total malloc=%s calloc=%s realloc(new)=%s freed=%s\n"
        "live=%s in %" PRIu64 " blocks  (min-size filter: >= %" PRIu64 "B)\n"
        "span=%s\n"
        "order=%s\n",
        nrec, (long)sz,
        cnt[0],cnt[1],cnt[2],cnt[3],
        human(total_malloc,hm),human(total_calloc,hc),human(total_realloc_new,hr),human(total_freed,hf),
        human(live_bytes,hl), live_blocks, (uint64_t)opt.min_size,
        span_str,
        opt.sort_time ? "time-asc" : "size-desc"
    );

    /* print leak details（保持长指针，去掉 ts_ns，追加 t 与 wall） */
    if(nrows>0){
        size_t limit = opt.live_all ? nrows : (opt.live_top>0 ? (size_t)opt.live_top : 0);
        if(limit>nrows) limit=nrows;
        fprintf(stderr, "\n== leaks (unfreed blocks) %s, order=%s ==\n",
                opt.live_all? "[ALL]":"[TOP]",
                opt.sort_time ? "time-asc" : "size-desc");
        for(size_t i=0;i<limit;i++){
            char hs[32], tshort[24], wfull[32];
            tsns_to_short_ms(rows[i].ts_ns, first_ts, tshort);
            wallns_to_full_ms(rows[i].wall_ns, wfull);
            fprintf(stderr, "%4zu) size=%s  ptr=0x%016" PRIx64 "  tid=%u  ra=0x%016" PRIx64
                            "  t=%s  wall=%s\n",
                    i+1, human(rows[i].size,hs), rows[i].ptr, rows[i].tid, rows[i].ra,
                    tshort, wfull);
        }
        if(!opt.live_all && nrows>limit){
            fprintf(stderr, "... (%zu more, use --live-all to show all)\n", nrows-limit);
        }
        fprintf(stderr, "\nHint: addr2line -e <elf> 0xRETADDR   # map ra to source:line\n");
    }else{
        fprintf(stderr, "\n== leaks (unfreed blocks) ==\n<none matched the current min-size filter>\n");
    }

    /* free list */
    while(live_head){ Live* n=live_head; live_head=live_head->next; free(n); }
    if(rows) free(rows);
    return 0;
}
