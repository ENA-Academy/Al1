// feistel_file_encrypt_portable.c

//  قابل بیلد/ران روی Linux و Windows (MSVC/MinGW)
//
// Build (Linux):
//   gcc -O2 -Wall -Wextra -std=c11 feistel.c -o feistel_enc
//   (روی بعضی لینوکس‌های قدیمی ممکنه نیاز بشه: ... -lrt)
//
// Build (Windows - MSVC, Developer Command Prompt):
//   cl /O2 /W4 feistel.c
//
// Build (Windows - MinGW-w64):
//   gcc -O2 -Wall -Wextra -std=c11 feistel_file_encrypt_portable.c -o feistel_enc.exe
//
// Run:
//   ./feistel_enc input.bin output.enc
//   (ویندوز: feistel.exe input.bin output.enc)




#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


#ifdef _WIN32
#include <windows.h>   // QueryPerformanceCounter
#else
#include <time.h>      // clock_gettime / timespec_get
#endif

// ============================
//   CONFIG
// ============================

#define BLOCK_SIZE 16             // 64-bit block
#define HALF_SIZE  (BLOCK_SIZE/2)  // 32 bytes
#define HALF_HALF_SIZE  (HALF_SIZE/2)  // 16 bytes
#define ROUNDS     35
#define KEYLEN     64
// exactly 64 characters

// ============================
//   TIME (Portable)
// ============================

static double now_seconds(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq;
    LARGE_INTEGER counter;

    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&counter);

    return (double)counter.QuadPart / (double)freq.QuadPart;
#else
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
    }
#endif

#if defined(TIME_UTC)
    struct timespec ts2;
    if (timespec_get(&ts2, TIME_UTC) != 0) {
        return (double)ts2.tv_sec + (double)ts2.tv_nsec / 1e9;
    }
#endif

    return 0.0;
#endif
}

// ============================
//   /2 - *2
// ============================
static int split_generic(const uint8_t *in, size_t n,
                         uint8_t *L, uint8_t *R)
{
    if (!in || !L || !R) return 1;
    if ((n % 2) != 0) return 1;

    size_t half = n / 2;

    memcpy(L, in, half);
    memcpy(R, in + half, half);
    return 0;
}

static int join_generic(uint8_t *out, size_t n,
                        const uint8_t *L, const uint8_t *R)
{
    if (!out || !L || !R) return 1;
    if ((n % 2) != 0) return 1;

    size_t half = n / 2;

    memcpy(out, L, half);
    memcpy(out + half, R, half);

    return 0;
}



// ============================
//   XOR
// ============================


static void xor_generic(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}



// ============================
//   F
// ============================

static inline uint8_t keymerg_onebit(uint8_t r, uint8_t k) {
    return (uint8_t)(r ^ k);
}

static void feistel_round(const uint8_t R[HALF_SIZE],
                          const uint8_t master_key[KEYLEN],
                          int round,
                          uint8_t f_out[HALF_SIZE])
{
    uint8_t newL[HALF_HALF_SIZE], newR[HALF_HALF_SIZE],keyL[HALF_HALF_SIZE];

    if (split_generic(R, HALF_SIZE, newL, newR) != 0) {
        memset(f_out, 0, HALF_SIZE);
        return;
    }


    for (int i = 0; i < HALF_HALF_SIZE; i++) {
        uint8_t kL = (uint8_t)(
            master_key[(round * HALF_SIZE + i) % KEYLEN] ^
            (uint8_t)(round * 17 + i * 31)
            );
        keyL[i] = keymerg_onebit(newL[i], kL);
    }

xor_generic(keyL, newR , newR, HALF_HALF_SIZE);

    for (int i = 0; i < HALF_HALF_SIZE; i++) {
        uint8_t oldR = newR[i];
        newR[i] =newL[i];
        newL[i] = oldR;

    }

    (void)join_generic(f_out, HALF_SIZE, newL, newR);
}



static void feistel_round_inv(const uint8_t f_out[HALF_SIZE],
                              const uint8_t master_key[KEYLEN],
                              int round,
                              uint8_t R[HALF_SIZE])
{
    uint8_t newL[HALF_HALF_SIZE], newR[HALF_HALF_SIZE];
    uint8_t oldL[HALF_HALF_SIZE], oldR[HALF_HALF_SIZE];

    // f_out = join(newL, newR)
    if (split_generic(f_out, HALF_SIZE, newL, newR) != 0) {
        memset(R, 0, HALF_SIZE);
        return;
    }

    // در encrypt داخل feistel_round آخرش swap شد:
    // newR == oldL
    // پس:
    memcpy(oldL, newR, HALF_HALF_SIZE);

    // newL = oldR ^ (oldL ^ k)  => oldR = newL ^ oldL ^ k
    for (int i = 0; i < HALF_HALF_SIZE; i++) {
        uint8_t kL = (uint8_t)(
            master_key[(round * HALF_SIZE + i) % KEYLEN] ^
            (uint8_t)(round * 17 + i * 31)
            );
        oldR[i] = (uint8_t)(newL[i] ^ oldL[i] ^ kL);
    }

    (void)join_generic(R, HALF_SIZE, oldL, oldR);
}

// ============================
//  encrypt_block
// ============================



static void encrypt_block(uint8_t block[BLOCK_SIZE], const uint8_t master_key[KEYLEN]) {
    uint8_t L[HALF_SIZE], R[HALF_SIZE];
    if (split_generic(block, BLOCK_SIZE, L, R) != 0) {
        return;
    }


    for (int round = 0; round < ROUNDS; round++) {

        uint8_t feistelout_R[HALF_SIZE];
        uint8_t feistelout_L[HALF_SIZE];
         uint8_t feistelout_M[HALF_SIZE];
        uint8_t xorout_one[HALF_SIZE];
        uint8_t xorout_two[HALF_SIZE];


        feistel_round(R, master_key, round, feistelout_R);
        feistel_round(L, master_key, round, feistelout_L);


       xor_generic(feistelout_L,feistelout_R, xorout_one, HALF_SIZE);

      feistel_round(xorout_one, master_key, round, feistelout_M);

       xor_generic(feistelout_L,feistelout_M, xorout_two, HALF_SIZE);

        for (int i = 0; i < HALF_SIZE; i++) {
            uint8_t oldR = xorout_one[i];
              R[i] = xorout_two[i];
            L[i] = oldR;

        }
    }

   (void)join_generic(block, BLOCK_SIZE, L, R);
}











// ============================
//   MAIN (menu: 1=enc, 2=dec)
// ============================

int main(int argc, char *argv[]) {

    // read key-64
    char key_in[KEYLEN + 4];
    uint8_t master_key[KEYLEN];

    printf("Enter a 64-character key (exactly 64 chars):\n");
    if (!fgets(key_in, sizeof(key_in), stdin)) {
        fprintf(stderr, "Failed to read key.\n");
        return 1;
    }

    // length of key and delete enter
    size_t klen = strcspn(key_in, "\r\n");
    key_in[klen] = '\0';

    if (klen != KEYLEN) {
        fprintf(stderr, "Error: key length is %zu, but must be exactly %d characters.\n", klen, KEYLEN);
        return 1;
    }

    // key = master key
    memcpy(master_key, key_in, KEYLEN);

    // encrypt/decrypt and timing







    return 0;
}

