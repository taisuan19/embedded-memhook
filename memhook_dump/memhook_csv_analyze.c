// tools/memhook_csv_analyze.c
// 重放 memhook CSV，输出峰值/排行/泄漏/时间序列（抽样）

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    long idx;
    uint64_t ts_ns, wall_ns;
    char wall_time[64];
    int tid;
    char op[16];
    uint64_t ptr;
    uint64_t arg;
    uint64_t ra;
} Row;

static uint64_t parse_hex_or_dec(const char* s){
    while(isspace((unsigned char)*s)) s++;
    if(!*s) return 0;
    if (!strncasecmp(s,"0x",2)) return strtoull(s, NULL, 16);
    return strtoull(s, NULL, 10);
}

static char** split_csv_line(char* line, int* outn){
    // 朴素 CSV split（假设无引号/逗号在字段内）
    int cap=16,n=0; char** a=malloc(sizeof(char*)*cap);
    char* p=line;
    while(*p){
        if(n==cap){ cap*=2; a=realloc(a,sizeof(char*)*cap); }
        a[n++]=p;
        char* q=strchr(p, ',');
        if(!q) break;
        *q='\0'; p=q+1;
    }
    *outn=n;
    return a;
}

typedef struct { int idx,ts_ns,wall_ns,wall_time,tid,op,ptr,arg,retaddr; } ColIx;

static int find_cols(char** hdr,int n, ColIx* ix){
    #define FIND(name, field) \
        do{ ix->field=-1; for(int i=0;i<n;i++){ if(!strcmp(hdr[i], name)){ ix->field=i; break; } } \
            if(ix->field<0){ fprintf(stderr,"[err] missing column: %s\n", name); return 0; } }while(0)
    FIND("idx",idx);
    FIND("ts_ns",ts_ns);
    FIND("wall_ns",wall_ns);
    FIND("wall_time",wall_time);
    FIND("tid",tid);
    FIND("op",op);
    FIND("ptr",ptr);
    FIND("arg",arg);
    FIND("retaddr",retaddr);
    #undef FIND
    return 1;
}

/* --- 简易哈希表（开地址）存 ptr -> {size, tid, ra, ts_ns, wall_time} --- */
typedef struct {
    uint64_t key_ptr;
    uint64_t size;
    int tid;
    uint64_t ra;
    uint64_t ts_ns;
    char wall_time[64];
    int used;
} LiveEnt;

typedef struct {
    LiveEnt* a;
    size_t cap;
    size_t cnt;
} LiveMap;

static uint64_t hmix(uint64_t x){ x ^= x>>33; x*=0xff51afd7ed558ccdULL; x^=x>>33; x*=0xc4ceb9fe1a85ec53ULL; x^=x>>33; return x; }

static void live_init(LiveMap* m){ m->cap=1<<20; m->cnt=0; m->a=calloc(m->cap,sizeof(LiveEnt)); } // ~1M 槽，可装几十万块
static void live_free(LiveMap* m){ free(m->a); m->a=NULL; m->cap=m->cnt=0; }

static LiveEnt* live_find(LiveMap* m, uint64_t key){
    size_t mask=m->cap-1;
    size_t i = (size_t)hmix(key) & mask;
    for(size_t step=0; step<m->cap; step++){
        LiveEnt* e=&m->a[i];
        if(!e->used) return NULL;
        if(e->key_ptr==key) return e;
        i=(i+1)&mask;
    }
    return NULL;
}
static LiveEnt* live_upsert(LiveMap* m, uint64_t key){
    size_t mask=m->cap-1;
    size_t i = (size_t)hmix(key) & mask;
    for(size_t step=0; step<m->cap; step++){
        LiveEnt* e=&m->a[i];
        if(!e->used){ e->used=1; e->key_ptr=key; m->cnt++; return e; }
        if(e->key_ptr==key) return e;
        i=(i+1)&mask;
    }
    return NULL;
}
static int live_erase(LiveMap* m, uint64_t key, LiveEnt* out){ // Robin-Hood 简化删除：标记空，并向后回填
    size_t mask=m->cap-1;
    size_t i=(size_t)hmix(key)&mask;
    for(size_t step=0; step<m->cap; step++){
        LiveEnt* e=&m->a[i];
        if(!e->used) return 0;
        if(e->key_ptr==key){
            if(out) *out=*e;
            e->used=0;
            // 迁移后续簇
            size_t j=(i+1)&mask;
            while(m->a[j].used){
                LiveEnt tmp=m->a[j]; m->a[j].used=0;
                live_upsert(m,tmp.key_ptr)[0]=tmp;
                j=(j+1)&mask;
            }
            m->cnt--; return 1;
        }
        i=(i+1)&mask;
    }
    return 0;
}

/* --- 排行动态数组 --- */
typedef struct { int tid; uint64_t peak; long idx; uint64_t ts_ns; char wall_time[64]; } TidPeak;
typedef struct { uint64_t ra; uint64_t peak; long idx; uint64_t ts_ns; char wall_time[64]; } RaPeak;

typedef struct { TidPeak* a; size_t n,cap; } TidVec;
typedef struct { RaPeak*  a; size_t n,cap; } RaVec;

static void tv_push(TidVec* v, TidPeak x){ if(v->n==v->cap){ v->cap=v->cap? v->cap*2:128; v->a=realloc(v->a,v->cap*sizeof(*v->a)); } v->a[v->n++]=x; }
static void rv_push(RaVec* v, RaPeak  x){ if(v->n==v->cap){ v->cap=v->cap? v->cap*2:128; v->a=realloc(v->a,v->cap*sizeof(*v->a)); } v->a[v->n++]=x; }
static int cmp_tid_peak_desc(const void* A,const void* B){ const TidPeak* a=A,*b=B; return (a->peak<b->peak)-(a->peak>b->peak); }
static int cmp_ra_peak_desc (const void* A,const void* B){ const RaPeak*  a=A,*b=B; return (a->peak<b->peak)-(a->peak>b->peak); }

/* --- 简单 map：tid->cur, peak；ra->cur, peak --- */
typedef struct { int tid; uint64_t cur, peak; long pidx; uint64_t pts; char pwt[64]; } TidStat;
typedef struct { uint64_t ra; uint64_t cur, peak; long pidx; uint64_t pts; char pwt[64]; } RaStat;
typedef struct { TidStat* a; size_t n,cap; } TidStatVec;
typedef struct { RaStat*  a; size_t n,cap; } RaStatVec;
static TidStat* get_tid(TidStatVec* v,int tid){ for(size_t i=0;i<v->n;i++) if(v->a[i].tid==tid) return &v->a[i]; if(v->n==v->cap){ v->cap=v->cap? v->cap*2:128; v->a=realloc(v->a,v->cap*sizeof(*v->a)); } v->a[v->n]=(TidStat){.tid=tid}; return &v->a[v->n++]; }
static RaStat*  get_ra (RaStatVec* v,uint64_t ra){ for(size_t i=0;i<v->n;i++) if(v->a[i].ra==ra) return &v->a[i]; if(v->n==v->cap){ v->cap=v->cap? v->cap*2:128; v->a=realloc(v->a,v->cap*sizeof(*v->a)); } v->a[v->n]=(RaStat){.ra=ra};   return &v->a[v->n++]; }

/* --- IO 辅助 --- */
static void write_overview(const char* outdir, long recs, uint64_t peak, long pidx, uint64_t pts, uint64_t pwall_ns, const char* pwt,
                           size_t end_blocks, uint64_t end_bytes, int has_cross, long cidx, uint64_t cts, const char* cwt, uint64_t cbytes){
    char path[512]; snprintf(path,sizeof(path), "%s/overview.csv", outdir);
    FILE* f=fopen(path,"w"); if(!f){ perror("overview.csv"); return; }
    fprintf(f,"records,peak_live_bytes,peak_idx,peak_ts_ns,peak_wall_ns,peak_wall_time,end_live_blocks,end_live_bytes,approx_cross\n");
    fprintf(f,"%ld,%" PRIu64 ",%ld,%" PRIu64 ",%" PRIu64 ",%s,%zu,%" PRIu64 ",", recs, peak, pidx, pts, pwall_ns, pwt, end_blocks, end_bytes);
    if(has_cross) fprintf(f,"{idx:%ld,ts_ns:%" PRIu64 ",wall_time:%s,bytes:%" PRIu64 "}\n", cidx, cts, cwt, cbytes);
    else fprintf(f,"\n");
    fclose(f);
}
static void write_top_tids(const char* outdir, TidStatVec* st, int top){
    char path[512]; snprintf(path,sizeof(path), "%s/top_tids_by_peak.csv", outdir);
    FILE* f=fopen(path,"w"); if(!f){ perror("top_tids_by_peak.csv"); return; }
    fprintf(f,"tid,peak_live_bytes,peak_idx,peak_ts_ns,peak_wall_time\n");
    TidVec v={0};
    for(size_t i=0;i<st->n;i++){ TidPeak x={st->a[i].tid, st->a[i].peak, st->a[i].pidx, st->a[i].pts, {0}}; strncpy(x.wall_time, st->a[i].pwt, sizeof(x.wall_time)-1); tv_push(&v,x); }
    qsort(v.a, v.n, sizeof(*v.a), cmp_tid_peak_desc);
    if(top>0 && v.n> (size_t)top) v.n=top;
    for(size_t i=0;i<v.n;i++) fprintf(f,"%d,%" PRIu64 ",%ld,%" PRIu64 ",%s\n", v.a[i].tid, v.a[i].peak, v.a[i].idx, v.a[i].ts_ns, v.a[i].wall_time);
    fclose(f); free(v.a);
}
static void write_top_sites(const char* outdir, RaStatVec* st, int top){
    char path[512]; snprintf(path,sizeof(path), "%s/top_sites_by_peak.csv", outdir);
    FILE* f=fopen(path,"w"); if(!f){ perror("top_sites_by_peak.csv"); return; }
    fprintf(f,"retaddr,peak_live_bytes,peak_idx,peak_ts_ns,peak_wall_time\n");
    RaVec v={0};
    for(size_t i=0;i<st->n;i++){ RaPeak x={st->a[i].ra, st->a[i].peak, st->a[i].pidx, st->a[i].pts, {0}}; strncpy(x.wall_time, st->a[i].pwt, sizeof(x.wall_time)-1); rv_push(&v,x); }
    qsort(v.a, v.n, sizeof(*v.a), cmp_ra_peak_desc);
    if(top>0 && v.n> (size_t)top) v.n=top;
    for(size_t i=0;i<v.n;i++) fprintf(f,"0x%016" PRIx64 ",%" PRIu64 ",%ld,%" PRIu64 ",%s\n", v.a[i].ra, v.a[i].peak, v.a[i].idx, v.a[i].ts_ns, v.a[i].wall_time);
    fclose(f); free(v.a);
}
static void write_live_blocks(const char* outdir, LiveMap* live){
    // 拉出所有仍在存块，按 size 降序
    typedef struct { uint64_t ptr,size,ra,ts_ns; int tid; char wt[64]; } LB;
    LB* a=NULL; size_t n=0,cap=0;
    for(size_t i=0;i<live->cap;i++){
        LiveEnt* e=&live->a[i]; if(!e->used) continue;
        if(n==cap){ cap=cap?cap*2:1024; a=realloc(a,cap*sizeof(*a)); }
        a[n++] = (LB){e->key_ptr, e->size, e->ra, e->ts_ns, e->tid,{0}};
        strncpy(a[n-1].wt, e->wall_time, sizeof(a[n-1].wt)-1);
    }
    int cmp(const void* A,const void* B){ const LB* a=A,*b=B; return (a->size<b->size)-(a->size>b->size); }
    qsort(a,n,sizeof(*a),cmp);
    char path[512]; snprintf(path,sizeof(path), "%s/live_blocks_at_end.csv", outdir);
    FILE* f=fopen(path,"w"); if(!f){ perror("live_blocks_at_end.csv"); free(a); return; }
    fprintf(f,"ptr,size,tid,ra,alloc_ts_ns,alloc_wall_time\n");
    for(size_t i=0;i<n;i++) fprintf(f,"0x%016" PRIx64 ",%" PRIu64 ",%d,0x%016" PRIx64 ",%" PRIu64 ",%s\n",
        a[i].ptr,a[i].size,a[i].tid,a[i].ra,a[i].ts_ns,a[i].wt);
    fclose(f); free(a);
}
static void write_timeseries(const char* outdir, uint64_t* idxs, uint64_t* ts, char (*wt)[64], uint64_t* values, size_t n, int maxpts){
    char path[512]; snprintf(path,sizeof(path), "%s/timeseries_downsampled.csv", outdir);
    FILE* f=fopen(path,"w"); if(!f){ perror("timeseries_downsampled.csv"); return; }
    fprintf(f,"idx,ts_ns,wall_time,cur_live_bytes\n");
    if(maxpts<=0 || (int)n<=maxpts){
        for(size_t i=0;i<n;i++) fprintf(f,"%" PRIu64 ",%" PRIu64 ",%s,%" PRIu64 "\n", idxs[i], ts[i], wt[i], values[i]);
    }else{
        double step=(double)n/(double)maxpts; double k=0.0;
        for(int i=0;i<maxpts;i++){ size_t j=(size_t)k; if(j>=n) j=n-1; fprintf(f,"%" PRIu64 ",%" PRIu64 ",%s,%" PRIu64 "\n", idxs[j], ts[j], wt[j], values[j]); k+=step; }
        if(idxs[n-1]!=idxs[(size_t)(k-step)] ) fprintf(f,"%" PRIu64 ",%" PRIu64 ",%s,%" PRIu64 "\n", idxs[n-1], ts[n-1], wt[n-1], values[n-1]);
    }
    fclose(f);
}

int main(int argc, char** argv){
    if(argc<2){
        fprintf(stderr,
            "Usage: %s <records.csv> [--out DIR] [--top N] [--downsample N] [--approx-mem BYTES]\n",
            argv[0]);
        return 1;
    }
    const char* csvpath=argv[1];
    const char* outdir="out_report";
    int top=50, down=400;
    uint64_t approx_mem=0;

    for(int i=2;i<argc;i++){
        if(!strcmp(argv[i],"--out") && i+1<argc){ outdir=argv[++i]; continue; }
        if(!strcmp(argv[i],"--top") && i+1<argc){ top=atoi(argv[++i]); continue; }
        if(!strcmp(argv[i],"--downsample") && i+1<argc){ down=atoi(argv[++i]); continue; }
        if(!strcmp(argv[i],"--approx-mem") && i+1<argc){ approx_mem = (uint64_t)strtoull(argv[++i],NULL,10); continue; }
        fprintf(stderr,"Unknown arg: %s\n", argv[i]); return 1;
    }
    char cmd[512]; snprintf(cmd,sizeof(cmd),"mkdir -p \"%s\"", outdir); system(cmd);

    FILE* f=fopen(csvpath,"r"); if(!f){ perror("open csv"); return 2; }

    // 读表头
    char* line=NULL; size_t len=0; ssize_t nread=getline(&line,&len,f);
    if(nread<=0){ fprintf(stderr,"empty csv\n"); return 2; }
    // 去掉换行
    if(nread>0 && (line[nread-1]=='\n'||line[nread-1]=='\r')) line[nread-1]='\0';
    int ncol=0; char** hdr = split_csv_line(line,&ncol);
    ColIx ix;
    if(!find_cols(hdr,ncol,&ix)) return 2;

    LiveMap live; live_init(&live);
    TidStatVec tstats={0}; RaStatVec rstats={0};

    // 时间序列缓存
    size_t cap_ts=1024,n_ts=0;
    uint64_t* ts_idx  = malloc(cap_ts*sizeof(uint64_t));
    uint64_t* ts_tsns = malloc(cap_ts*sizeof(uint64_t));
    char     (*ts_wt)[64] = malloc(cap_ts*sizeof(*ts_wt));
    uint64_t* ts_val  = malloc(cap_ts*sizeof(uint64_t));

    uint64_t cur_live=0, peak_live=0, peak_tsns=0, peak_wall_ns=0;
    char peak_wt[64]={0}; long peak_idx=-1;
    int have_cross=0; long cross_idx=-1; uint64_t cross_tsns=0, cross_bytes=0; char cross_wt[64]={0};

    // 逐行读取
    char* l2=NULL; size_t l2len=0;
    long recs=0;
    while( (nread=getline(&l2,&l2len,f))>0 ){
        if(nread>0 && (l2[nread-1]=='\n'||l2[nread-1]=='\r')) l2[nread-1]='\0';
        int nc=0; char** col = split_csv_line(l2,&nc);
        if(nc < ncol){ free(col); continue; }
        Row r={0};
        r.idx = atol(col[ix.idx]);
        r.ts_ns = strtoull(col[ix.ts_ns],NULL,10);
        r.wall_ns = *col[ix.wall_ns]? strtoull(col[ix.wall_ns],NULL,10):0;
        strncpy(r.wall_time, col[ix.wall_time], sizeof(r.wall_time)-1);
        r.tid = atoi(col[ix.tid]);
        strncpy(r.op, col[ix.op], sizeof(r.op)-1);
        r.ptr = parse_hex_or_dec(col[ix.ptr]);
        r.arg = *col[ix.arg]? strtoull(col[ix.arg],NULL,10):0;
        r.ra  = parse_hex_or_dec(col[ix.retaddr]);

        // 时间序列 push（行前状态）
        if(n_ts==cap_ts){ cap_ts*=2;
            ts_idx = realloc(ts_idx,cap_ts*sizeof(*ts_idx));
            ts_tsns= realloc(ts_tsns,cap_ts*sizeof(*ts_tsns));
            ts_wt  = realloc(ts_wt,cap_ts*sizeof(*ts_wt));
            ts_val = realloc(ts_val,cap_ts*sizeof(*ts_val));
        }
        ts_idx[n_ts]= (uint64_t)r.idx; ts_tsns[n_ts]=r.ts_ns; strncpy(ts_wt[n_ts], r.wall_time, 63); ts_val[n_ts]=cur_live; n_ts++;

        // 维护 live/峰值
        if(!strcmp(r.op,"malloc") || !strcmp(r.op,"calloc")){
            uint64_t sz=r.arg;
            LiveEnt* e = live_upsert(&live, r.ptr);
            e->size=sz; e->tid=r.tid; e->ra=r.ra; e->ts_ns=r.ts_ns; strncpy(e->wall_time,r.wall_time,63);
            cur_live += sz;

            TidStat* ts = get_tid(&tstats,r.tid); ts->cur += sz;
            if(ts->cur > ts->peak){ ts->peak=ts->cur; ts->pidx=r.idx; ts->pts=r.ts_ns; strncpy(ts->pwt,r.wall_time,63); }

            RaStat* rs = get_ra(&rstats,r.ra); rs->cur += sz;
            if(rs->cur > rs->peak){ rs->peak=rs->cur; rs->pidx=r.idx; rs->pts=r.ts_ns; strncpy(rs->pwt,r.wall_time,63); }
        }
        else if(!strcmp(r.op,"realloc")){
            LiveEnt old;
            if(live_erase(&live,r.ptr,&old)){ // 先减旧
                if(cur_live>=old.size) cur_live-=old.size; else cur_live=0;
                TidStat* ts=get_tid(&tstats,old.tid); ts->cur = (ts->cur>=old.size? ts->cur-old.size:0);
                RaStat*  rs=get_ra(&rstats,old.ra);    rs->cur = (rs->cur>=old.size? rs->cur-old.size:0);
            }
            // 再加新
            uint64_t sz=r.arg;
            LiveEnt* e = live_upsert(&live, r.ptr);
            e->size=sz; e->tid=r.tid; e->ra=r.ra; e->ts_ns=r.ts_ns; strncpy(e->wall_time,r.wall_time,63);
            cur_live += sz;

            TidStat* ts = get_tid(&tstats,r.tid); ts->cur += sz;
            if(ts->cur > ts->peak){ ts->peak=ts->cur; ts->pidx=r.idx; ts->pts=r.ts_ns; strncpy(ts->pwt,r.wall_time,63); }

            RaStat* rs = get_ra(&rstats,r.ra); rs->cur += sz;
            if(rs->cur > rs->peak){ rs->peak=rs->cur; rs->pidx=r.idx; rs->pts=r.ts_ns; strncpy(rs->pwt,r.wall_time,63); }
        }
        else if(!strcmp(r.op,"free")){
            LiveEnt old;
            if(live_erase(&live,r.ptr,&old)){
                if(cur_live>=old.size) cur_live-=old.size; else cur_live=0;
                TidStat* ts=get_tid(&tstats,old.tid); ts->cur = (ts->cur>=old.size? ts->cur-old.size:0);
                RaStat*  rs=get_ra(&rstats,old.ra);    rs->cur = (rs->cur>=old.size? rs->cur-old.size:0);
            }
        }

        if(cur_live > peak_live){ peak_live=cur_live; peak_idx=r.idx; peak_tsns=r.ts_ns; peak_wall_ns=r.wall_ns; strncpy(peak_wt,r.wall_time,63); }
        if(approx_mem && !have_cross && cur_live>=approx_mem){ have_cross=1; cross_idx=r.idx; cross_tsns=r.ts_ns; cross_bytes=cur_live; strncpy(cross_wt,r.wall_time,63); }

        recs++;
        free(col);
    }
    free(line); free(hdr); free(l2);
    fclose(f);

    // 汇总末尾 live
    size_t end_cnt=0; uint64_t end_bytes=0;
    for(size_t i=0;i<live.cap;i++) if(live.a[i].used){ end_cnt++; end_bytes += live.a[i].size; }

    // 输出
    write_overview(outdir, recs, peak_live, peak_idx, peak_tsns, peak_wall_ns, peak_wt,
                   end_cnt, end_bytes,
                   have_cross, cross_idx, cross_tsns, cross_wt, cross_bytes);
    write_top_tids(outdir, &tstats, top);
    write_top_sites(outdir, &rstats, top);
    write_live_blocks(outdir, &live);
    write_timeseries(outdir, ts_idx, ts_tsns, ts_wt, ts_val, n_ts, down);

    printf("[ok] peak=%" PRIu64 " bytes at %s (idx=%ld)\n", peak_live, peak_wt, peak_idx);
    if(have_cross) printf("[ok] crossed approx-mem at %s (bytes=%" PRIu64 ", idx=%ld)\n", cross_wt, cross_bytes, cross_idx);
    printf("[ok] outputs at: %s\n", outdir);

    live_free(&live);
    free(tstats.a); free(rstats.a);
    free(ts_idx); free(ts_tsns); free(ts_wt); free(ts_val);
    return 0;
}
