#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#include "file_handling_enc_mt.h"

// شما این‌ها را در پروژه دارید
// #define BLOCK_SIZE 16
// #define KEY_COUNT ...
// #define KEY_HALF_SIZE ...
// و encrypt_block هم در همین پروژه هست (static یا non-static فرقی ندارد، فقط باید در همین translation unit قابل دسترسی باشد
// یا اگر در فایل دیگری است، prototypeاش را اینجا declare کنید).

// اگر encrypt_block در فایل دیگری non-static است:
void encrypt_block(uint8_t block[BLOCK_SIZE],
                   const uint8_t key[KEY_COUNT][KEY_HALF_SIZE]);

// ---------------- Cross-platform threading ----------------
#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>

  typedef HANDLE thread_t;

  typedef struct { CRITICAL_SECTION cs; } mutex_t;
  typedef struct { CONDITION_VARIABLE cv; } cond_t;

  static void mutex_init(mutex_t *m){ InitializeCriticalSection(&m->cs); }
  static void mutex_lock(mutex_t *m){ EnterCriticalSection(&m->cs); }
  static void mutex_unlock(mutex_t *m){ LeaveCriticalSection(&m->cs); }
  static void mutex_destroy(mutex_t *m){ DeleteCriticalSection(&m->cs); }

  static void cond_init(cond_t *c){ InitializeConditionVariable(&c->cv); }
  static void cond_wait(cond_t *c, mutex_t *m){ SleepConditionVariableCS(&c->cv, &m->cs, INFINITE); }
  static void cond_signal(cond_t *c){ WakeConditionVariable(&c->cv); }
  static void cond_broadcast(cond_t *c){ WakeAllConditionVariable(&c->cv); }
  static void cond_destroy(cond_t *c){ (void)c; }

  static int default_threads(void){
      SYSTEM_INFO si;
      GetSystemInfo(&si);
      return (int)(si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 4);
  }

#else
  #include <pthread.h>
  #include <unistd.h>

  typedef pthread_t thread_t;

  typedef struct { pthread_mutex_t m; } mutex_t;
  typedef struct { pthread_cond_t  c; } cond_t;

  static void mutex_init(mutex_t *m){ pthread_mutex_init(&m->m, NULL); }
  static void mutex_lock(mutex_t *m){ pthread_mutex_lock(&m->m); }
  static void mutex_unlock(mutex_t *m){ pthread_mutex_unlock(&m->m); }
  static void mutex_destroy(mutex_t *m){ pthread_mutex_destroy(&m->m); }

  static void cond_init(cond_t *c){ pthread_cond_init(&c->c, NULL); }
  static void cond_wait(cond_t *c, mutex_t *m){ pthread_cond_wait(&c->c, &m->m); }
  static void cond_signal(cond_t *c){ pthread_cond_signal(&c->c); }
  static void cond_broadcast(cond_t *c){ pthread_cond_broadcast(&c->c); }
  static void cond_destroy(cond_t *c){ pthread_cond_destroy(&c->c); }

  static int default_threads(void){
      long n = sysconf(_SC_NPROCESSORS_ONLN);
      return (n > 0) ? (int)n : 4;
  }
#endif

// ---------------- Design ----------------
//
// برای جلوگیری از overhead شدید، فایل را به صورت "چانک" های بزرگ می‌خوانیم.
// هر چانک شامل چندین بلاک 16 بایتی است.
// Workerها روی چانک حلقه می‌زنند و encrypt_block را برای هر 16 بایت صدا می‌زنند.
//
// نکته: padding روی بلاک 16 بایتی است (PKCS#7).
//

#ifndef IO_CHUNK_SIZE
#define IO_CHUNK_SIZE (64u * 1024u)  // 64KB، باید مضرب BLOCK_SIZE باشد
#endif

#ifndef MAX_INFLIGHT
#define MAX_INFLIGHT 128
#endif

#if (IO_CHUNK_SIZE % BLOCK_SIZE) != 0
#error "IO_CHUNK_SIZE must be a multiple of BLOCK_SIZE"
#endif

typedef struct {
    uint64_t index;
    size_t   nread;     // bytes read from file for this chunk (<= IO_CHUNK_SIZE)
    int      is_last;
    uint8_t *buf;       // IO_CHUNK_SIZE
} job_t;

typedef struct {
    int      ready;
    size_t   out_len;   // bytes to write for this chunk (padded for last)
    uint8_t *buf;       // IO_CHUNK_SIZE
} result_t;

typedef struct {
    job_t   buf[MAX_INFLIGHT];
    size_t  head, tail, count;
    int     closed;
    mutex_t mu;
    cond_t  not_empty;
    cond_t  not_full;
} job_queue_t;

static void jq_init(job_queue_t *q){
    memset(q, 0, sizeof(*q));
    mutex_init(&q->mu);
    cond_init(&q->not_empty);
    cond_init(&q->not_full);
}

static void jq_close(job_queue_t *q){
    mutex_lock(&q->mu);
    q->closed = 1;
    cond_broadcast(&q->not_empty);
    cond_broadcast(&q->not_full);
    mutex_unlock(&q->mu);
}

static void jq_destroy(job_queue_t *q){
    mutex_destroy(&q->mu);
    cond_destroy(&q->not_empty);
    cond_destroy(&q->not_full);
}

static int jq_push(job_queue_t *q, const job_t *j){
    mutex_lock(&q->mu);
    while (q->count == MAX_INFLIGHT && !q->closed){
        cond_wait(&q->not_full, &q->mu);
    }
    if (q->closed){
        mutex_unlock(&q->mu);
        return 1;
    }
    q->buf[q->tail] = *j;
    q->tail = (q->tail + 1) % MAX_INFLIGHT;
    q->count++;
    cond_signal(&q->not_empty);
    mutex_unlock(&q->mu);
    return 0;
}

static int jq_pop(job_queue_t *q, job_t *out){
    mutex_lock(&q->mu);
    while (q->count == 0 && !q->closed){
        cond_wait(&q->not_empty, &q->mu);
    }
    if (q->count == 0 && q->closed){
        mutex_unlock(&q->mu);
        return 1;
    }
    *out = q->buf[q->head];
    q->head = (q->head + 1) % MAX_INFLIGHT;
    q->count--;
    cond_signal(&q->not_full);
    mutex_unlock(&q->mu);
    return 0;
}

typedef struct {
    const uint8_t (*key_out)[KEY_HALF_SIZE];

    result_t *results;
    uint64_t total_chunks;

    job_queue_t *q;

    mutex_t res_mu;
    cond_t  res_cv;
} worker_ctx_t;

static void encrypt_chunk_inplace(uint8_t *buf, size_t len,
                                  const uint8_t key_out[KEY_COUNT][KEY_HALF_SIZE])
{
    // len باید مضرب BLOCK_SIZE باشد
    for (size_t off = 0; off < len; off += BLOCK_SIZE){
        encrypt_block(buf + off, key_out);
    }
}

static void set_result(worker_ctx_t *ctx, uint64_t idx, uint8_t *buf, size_t out_len){
    mutex_lock(&ctx->res_mu);
    memcpy(ctx->results[idx].buf, buf, out_len);
    ctx->results[idx].out_len = out_len;
    ctx->results[idx].ready = 1;
    cond_broadcast(&ctx->res_cv);
    mutex_unlock(&ctx->res_mu);
}

#ifdef _WIN32
static DWORD WINAPI worker_main(LPVOID arg)
#else
static void* worker_main(void *arg)
#endif
{
    worker_ctx_t *ctx = (worker_ctx_t*)arg;
    job_t j;

    while (jq_pop(ctx->q, &j) == 0){
        size_t out_len = 0;

        if (!j.is_last){
            out_len = j.nread; // باید IO_CHUNK_SIZE باشد به جز آخرین
        } else {
            // PKCS#7 padding روی BLOCK_SIZE (16)
            // اگر nread مضرب BLOCK_SIZE باشد => یک بلاک کامل padding اضافه می‌شود
            size_t rem = j.nread % BLOCK_SIZE;
            size_t pad = (rem == 0) ? BLOCK_SIZE : (BLOCK_SIZE - rem);
            out_len = j.nread + pad;

            // توجه: اگر j.nread == IO_CHUNK_SIZE، out_len می‌شود IO_CHUNK_SIZE + 16
            // برای این حالت، producer یک chunk اضافی padding-only می‌فرستد (پایین‌تر).
            if (out_len > IO_CHUNK_SIZE){
                // اینجا نباید رخ دهد
                out_len = IO_CHUNK_SIZE;
            }

            memset(j.buf + j.nread, (uint8_t)pad, pad);
        }

        encrypt_chunk_inplace(j.buf, out_len, ctx->key_out);

        set_result(ctx, j.index, j.buf, out_len);

        free(j.buf);
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int file_handling_enc_mt(const char *in_path,
                         const char *out_path,
                         const uint8_t key_out[KEY_COUNT][KEY_HALF_SIZE],
                         int num_threads)
{
    if (num_threads <= 0) num_threads = default_threads();

    FILE *in = fopen(in_path, "rb");
    if (!in){ perror("fopen input"); return 1; }

    FILE *out = fopen(out_path, "wb");
    if (!out){ perror("fopen output"); fclose(in); return 1; }

    // اندازه فایل
    if (fseek(in, 0, SEEK_END) != 0){ perror("fseek"); fclose(in); fclose(out); return 1; }
    long fsz_l = ftell(in);
    if (fsz_l < 0){ perror("ftell"); fclose(in); fclose(out); return 1; }
    size_t fsz = (size_t)fsz_l;
    rewind(in);

    // محاسبه تعداد چانک‌ها:
    // اگر فایل دقیقاً مضرب IO_CHUNK_SIZE باشد یا فایل خالی باشد، باز هم یک چانک padding-only لازم است.
    uint64_t full = (uint64_t)(fsz / IO_CHUNK_SIZE);
    size_t rem = fsz % IO_CHUNK_SIZE;

    uint64_t total_chunks = full + 1; // حداقل یک chunk آخر داریم
    if (rem == 0){
        // فایل یا خالی است یا دقیقاً روی مرز چانک تمام شده => chunk آخر padding-only خواهد بود
        // total_chunks همین full+1 درست است
    }

    // نتایج
    result_t *results = (result_t*)calloc((size_t)total_chunks, sizeof(result_t));
    if (!results){ perror("calloc results"); fclose(in); fclose(out); return 1; }
    for (uint64_t i = 0; i < total_chunks; i++){
        results[i].buf = (uint8_t*)malloc(IO_CHUNK_SIZE);
        if (!results[i].buf){ perror("malloc results buf"); fclose(in); fclose(out); return 1; }
        results[i].ready = 0;
        results[i].out_len = 0;
    }

    job_queue_t q;
    jq_init(&q);

    worker_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.key_out = key_out;
    ctx.results = results;
    ctx.total_chunks = total_chunks;
    ctx.q = &q;
    mutex_init(&ctx.res_mu);
    cond_init(&ctx.res_cv);

    thread_t *threads = (thread_t*)calloc((size_t)num_threads, sizeof(thread_t));
    if (!threads){ perror("calloc threads"); fclose(in); fclose(out); return 1; }

    int started = 0;
    for (int i = 0; i < num_threads; i++){
#ifdef _WIN32
        threads[i] = CreateThread(NULL, 0, worker_main, &ctx, 0, NULL);
        if (!threads[i]){ perror("CreateThread"); break; }
#else
        if (pthread_create(&threads[i], NULL, worker_main, &ctx) != 0){
            perror("pthread_create");
            break;
        }
#endif
        started++;
    }
    if (started == 0){
        free(threads);
        jq_destroy(&q);
        fclose(in); fclose(out);
        return 1;
    }

    // Producer
    for (uint64_t ci = 0; ci < total_chunks; ci++){
        job_t j;
        memset(&j, 0, sizeof(j));
        j.index = ci;
        j.buf = (uint8_t*)malloc(IO_CHUNK_SIZE);
        if (!j.buf){ perror("malloc job buf"); break; }

        if (ci < full){
            size_t n = fread(j.buf, 1, IO_CHUNK_SIZE, in);
            if (n != IO_CHUNK_SIZE){ perror("fread chunk"); free(j.buf); break; }
            j.nread = n;
            j.is_last = 0;
        } else {
            // آخرین chunk یا padding-only
            j.is_last = 1;

            if (rem == 0){
                // padding-only
                j.nread = 0;
            } else {
                size_t n = fread(j.buf, 1, rem, in);
                if (n != rem){ perror("fread last"); free(j.buf); break; }
                j.nread = n;
            }
        }

        if (jq_push(&q, &j) != 0){
            free(j.buf);
            break;
        }
    }

    jq_close(&q);

    // Writer ordered
    for (uint64_t expect = 0; expect < total_chunks; expect++){
        mutex_lock(&ctx.res_mu);
        while (!results[expect].ready){
            cond_wait(&ctx.res_cv, &ctx.res_mu);
        }
        size_t out_len = results[expect].out_len;
        mutex_unlock(&ctx.res_mu);

        if (out_len > 0){
            if (fwrite(results[expect].buf, 1, out_len, out) != out_len){
                perror("fwrite");
                break;
            }
        }
    }

    // Join
    jq_close(&q);
    for (int i = 0; i < started; i++){
#ifdef _WIN32
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif
    }

    free(threads);

    cond_destroy(&ctx.res_cv);
    mutex_destroy(&ctx.res_mu);
    jq_destroy(&q);

    for (uint64_t i = 0; i < total_chunks; i++){
        free(results[i].buf);
    }
    free(results);

    fclose(in);
    fclose(out);
    return 0;
}
