// memhook_dump.c - decode memhook.bin (40 bytes/record) to CSV + summary + leak list
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#pragma pack(push,1)
typedef struct {
    uint64_t ts_ns;   // monotonic time (ns)
    uint32_t tid;     // thread id
    uint16_t op;      // 0=malloc 1=free 2=realloc 3=calloc
    uint16_t pad;     // alignment
    uint64_t ptr;     // pointer
    uint64_t arg;     // size or 0
    uint64_t retaddr; // return address
} rec_t;              // total 40 bytes
#pragma pack(pop)

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

/* ---- live set: singly linked list (简单稳定) ---- */
typedef struct Live {
    uint64_t ptr, size, ts_ns, ra;
    uint32_t tid;
    struct Live* next;
} Live;

static Live* live_head=NULL;

static void add_live(uint64_t ptr,uint64_t size,uint32_t tid,uint64_t ts,uint64_t ra){
    Live* n=(Live*)malloc(sizeof(Live));
    if(!n) return;
    n->ptr=ptr; n->size=size; n->tid=tid; n->ts_ns=ts; n->ra=ra;
    n->next=live_head; live_head=n;
}
static Live* find_live(uint64_t ptr){
    for(Live* p=live_head;p;p=p->next) if(p->ptr==ptr) return p;
    return NULL;
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

/* ---- dynamic array to sort leaks ---- */
typedef struct {
    uint64_t ptr, size, ts_ns, ra;
    uint32_t tid;
} LeakRow;

static int cmp_leak_desc(const void* a,const void* b){
    const LeakRow* x=(const LeakRow*)a; const LeakRow* y=(const LeakRow*)b;
    if (y->size > x->size) return 1;
    if (y->size < x->size) return -1;
    /* tie-breaker: older first */
    if (x->ts_ns > y->ts_ns) return 1;
    if (x->ts_ns < y->ts_ns) return -1;
    return 0;
}

/* ---- options ---- */
typedef struct {
    const char* bin_path;
    const char* csv_path;  /* NULL => no CSV */
    int live_all;          /* print all leaks */
    long live_top;         /* print top-N leaks (default 20) */
    uint64_t min_size;     /* only list/aggregate leaks >= min_size */
} Opts;

static void usage(const char* prog){
    fprintf(stderr,
        "Usage: %s memhook.bin [--csv out.csv] [--live-all] [--live-top N] [--min-size N]\n"
        "  --csv out.csv   Write per-record CSV like: idx,ts_ns,tid,op,ptr,arg,retaddr\n"
        "  --live-all      Print ALL unfreed (leak) blocks in summary\n"
        "  --live-top N    Print top N leaks by size (default 20)\n"
        "  --min-size N    Only count/list leaks with size >= N bytes (default 0)\n",
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

    /* parse optional args */
    for(int i=2;i<argc;i++){
        if(strcmp(argv[i],"--csv")==0 && i+1<argc){ opt.csv_path=argv[++i]; continue; }
        if(strcmp(argv[i],"--live-all")==0){ opt.live_all=1; continue; }
        if(strcmp(argv[i],"--live-top")==0 && i+1<argc){ long v; if(parse_long(argv[++i],&v)) opt.live_top=v; continue; }
        if(strcmp(argv[i],"--min-size")==0 && i+1<argc){ uint64_t v; if(parse_u64(argv[++i],&v)) opt.min_size=v; continue; }
        usage(argv[0]); return 1;
    }

    FILE* f=fopen(opt.bin_path,"rb"); if(!f){ perror("fopen"); return 2; }
    fseek(f,0,SEEK_END); long sz=ftell(f); rewind(f);
    long nrec= (sz>= (long)sizeof(rec_t)) ? (sz/ (long)sizeof(rec_t)) : 0;

    FILE* fcsv=NULL;
    if(opt.csv_path){
        fcsv = fopen(opt.csv_path,"w");
        if(!fcsv){ perror("fopen csv"); fclose(f); return 3; }
        fprintf(fcsv,"idx,ts_ns,tid,op,ptr,arg,retaddr\n");
    }

    uint64_t total_malloc=0,total_calloc=0,total_realloc_new=0,total_freed=0;
    uint64_t cnt[4]={0};
    uint64_t first_ts=0,last_ts=0;

    rec_t r; long idx=0;
    while(fread(&r,sizeof(r),1,f)==1){
        if(first_ts==0) first_ts=r.ts_ns;
        last_ts=r.ts_ns;

        if(fcsv){
            fprintf(fcsv,"%ld,%" PRIu64 ",%u,%s,0x%016" PRIx64 ",%" PRIu64 ",0x%016" PRIx64 "\n",
                    idx,r.ts_ns,r.tid,op_name(r.op),r.ptr,r.arg,r.retaddr);
        }

        if(r.op<4) cnt[r.op]++;
        if(r.op==0){ add_live(r.ptr,r.arg,r.tid,r.ts_ns,r.retaddr); total_malloc+=r.arg; }
        else if(r.op==3){ add_live(r.ptr,r.arg,r.tid,r.ts_ns,r.retaddr); total_calloc+=r.arg; }
        else if(r.op==2){ /* realloc: old then new */
            uint64_t oldsz=0;
            if(del_live(r.ptr,&oldsz)){ total_freed+=oldsz; }
            else { add_live(r.ptr,r.arg,r.tid,r.ts_ns,r.retaddr); total_realloc_new+=r.arg; }
        }
        else if(r.op==1){ uint64_t oldsz=0; if(del_live(r.ptr,&oldsz)){ total_freed+=oldsz; } }
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
        if(p->size < opt.min_size) continue;
        live_bytes += p->size; live_blocks++;
        if(rows){
            if(nrows==cap){ cap*=2; rows=(LeakRow*)realloc(rows,cap*sizeof(LeakRow)); if(!rows){cap=0;nrows=0;} }
            if(rows){ rows[nrows].ptr=p->ptr; rows[nrows].size=p->size; rows[nrows].tid=p->tid; rows[nrows].ts_ns=p->ts_ns; rows[nrows].ra=p->ra; nrows++; }
        }
    }

    /* sort leaks by size desc */
    if(rows && nrows>1) qsort(rows,nrows,sizeof(LeakRow),cmp_leak_desc);

    /* summary */
    char hm[32],hc[32],hr[32],hf[32],hl[32];
    fprintf(stderr,
        "== summary ==\n"
        "records=%ld size=%ldB\n"
        "counts: malloc=%" PRIu64 " free=%" PRIu64 " realloc=%" PRIu64 " calloc=%" PRIu64 "\n"
        "total malloc=%s calloc=%s realloc(new)=%s freed=%s\n"
        "live=%s in %" PRIu64 " blocks  (min-size filter: >= %" PRIu64 "B)\n"
        "span=%.3fs\n",
        nrec, sz,
        cnt[0],cnt[1],cnt[2],cnt[3],
        human(total_malloc,hm),human(total_calloc,hc),human(total_realloc_new,hr),human(total_freed,hf),
        human(live_bytes,hl), live_blocks, opt.min_size,
        (first_ts && last_ts && last_ts>=first_ts)? ((last_ts-first_ts)/1e9):0.0
    );

    /* print leak details */
    if(nrows>0){
        size_t limit = opt.live_all ? nrows : (opt.live_top>0 ? (size_t)opt.live_top : 0);
        if(limit>nrows) limit=nrows;
        fprintf(stderr, "\n== leaks (unfreed blocks) %s ==\n",
                opt.live_all? "[ALL]":"[TOP]");
        size_t i;
        for(i=0;i<limit;i++){
            char hs[32];
            fprintf(stderr, "%4zu) size=%s  ptr=0x%016" PRIx64 "  tid=%u  ra=0x%016" PRIx64 "  ts_ns=%" PRIu64 "\n",
                    i+1, human(rows[i].size,hs), rows[i].ptr, rows[i].tid, rows[i].ra, rows[i].ts_ns);
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
