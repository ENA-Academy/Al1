// feistel_file_encrypt_portable.c

//  قابل بیلد/ران روی Linux و Windows (MSVC/MinGW)
//
// Build (Linux):
//
//   gcc -O2 -Wall -Wextra -std=c11 key.c SDS.c tools.c feistel.c -o feistel_en
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
#include "SDS.h"
#include "key.h"
#include "SDS.h"
#include "tools.h"

#ifdef _WIN32
#include <windows.h>   // QueryPerformanceCounter
#else
#include <time.h>      // clock_gettime / timespec_get
#endif

// ============================
//   CONFIG
// ============================

#define BLOCK_SIZE 16            // 128-bit block
#define HALF_SIZE  (BLOCK_SIZE/2)  // 64 bit
#define HALF_HALF_SIZE  (HALF_SIZE/2)  // 32 bit
#define ROUNDS     12
#define KEYLEN 32   // 256-bit = 32 bytes
#define KEY_HALF_SIZE 8
#define KEY_COUNT 26


uint8_t key[KEY_COUNT][KEY_HALF_SIZE];


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
//   F
// ============================


static void feistel_round(const uint8_t in[HALF_SIZE],
                          uint8_t f_out[HALF_SIZE])
{
    uint8_t buffer1[HALF_HALF_SIZE];
    uint8_t buffer2[HALF_HALF_SIZE];
    uint8_t *newL = buffer1;
    uint8_t *newR = buffer2;


    if (split_generic(in, HALF_SIZE, newL, newR) != 0) {
        memset(f_out, 0, HALF_SIZE);
        return;
    }




//enter SDS





    sds32_round(newL);




    xor_generic(newL, newR , newR, HALF_HALF_SIZE);

  sds32_round(newR);

 xor_generic(newR, newL , newR, HALF_HALF_SIZE);


    // for (int i = 0; i < HALF_HALF_SIZE; i++) {
    //     uint8_t oldR = newR[i];
    //     newR[i] =newL[i];
    //     newL[i] = oldR;

    // }


// swap
 uint8_t *tmp = newL;
 newL = newR;
 newR = tmp;



    (void)join_generic(f_out, HALF_SIZE, newL, newR);
}



// ============================
//  encrypt _ decrypt
// ============================



static void encrypt_block(uint8_t block[BLOCK_SIZE], const uint8_t key[KEY_COUNT][KEY_HALF_SIZE]) {
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
         uint8_t feistelout_LSH[HALF_SIZE];


         xor_generic(key[round*2],L, L, HALF_SIZE);
         xor_generic(key[(round*2)+1],R, R, HALF_SIZE);




        feistel_round(R, feistelout_R);
        feistel_round(L,feistelout_L);

        rotl_bytes_generic(feistelout_L, feistelout_LSH, 8, 43);
       xor_generic(feistelout_LSH,feistelout_R, xorout_one, HALF_SIZE);

      feistel_round(xorout_one, feistelout_M);

       xor_generic(feistelout_L,feistelout_M, xorout_two, HALF_SIZE);

        for (int i = 0; i < HALF_SIZE; i++) {
            uint8_t oldR = xorout_one[i];
              R[i] = xorout_two[i];
            L[i] = oldR;

        }


        if(round ==11){
        xor_generic(key[25],L, L, HALF_SIZE);
        xor_generic(key[24],R, R, HALF_SIZE);
        }
    }


   (void)join_generic(block, BLOCK_SIZE, L, R);
}


static void decrypt_block(uint8_t block[BLOCK_SIZE],
                          const uint8_t key[KEY_COUNT][KEY_HALF_SIZE])
{
   uint8_t L[HALF_SIZE], R[HALF_SIZE];
   if (split_generic(block, BLOCK_SIZE, L, R) != 0) {
        return;
   }

   for (int round = ROUNDS - 1; round >= 0; round--) {

        // --------- (A) Undo post-whitening of round 11 ----------
        // در encrypt اگر round==11 این XORها در انتهای راند انجام می‌شوند
        if (round == 11) {
        xor_generic(key[25], L, L, HALF_SIZE);
        xor_generic(key[24], R, R, HALF_SIZE);
        }

        // الان L و R برابر خروجی مرحله swap هستند:
        // L = xorout_one
        // R = xorout_two
        uint8_t xorout_one[HALF_SIZE];
        uint8_t xorout_two[HALF_SIZE];
        memcpy(xorout_one, L, HALF_SIZE);
        memcpy(xorout_two, R, HALF_SIZE);

        // --------- (B) بازسازی feistelout_L و feistelout_R ----------
        // از encrypt داریم:
        // feistelout_R = F(R_k)
        // feistelout_L = F(L_k)
        //
        // feistelout_LSH = rotl(feistelout_L)
        // xorout_one = feistelout_LSH XOR feistelout_R
        // feistelout_M = F(xorout_one)
        // xorout_two = feistelout_L XOR feistelout_M
        //
        // پس:
        // feistelout_M = feistel_round(xorout_one)  (همان F)
        // feistelout_L = xorout_two XOR feistelout_M
        // feistelout_LSH = rotl(feistelout_L)
        // feistelout_R = xorout_one XOR feistelout_LSH

        uint8_t feistelout_M[HALF_SIZE];
        feistel_round(xorout_one, feistelout_M);

        uint8_t feistelout_L[HALF_SIZE];
        xor_generic(xorout_two, feistelout_M, feistelout_L, HALF_SIZE);

        uint8_t feistelout_LSH[HALF_SIZE];
        rotl_bytes_generic(feistelout_L, feistelout_LSH, 8, 43);

        uint8_t feistelout_R[HALF_SIZE];
        xor_generic(xorout_one, feistelout_LSH, feistelout_R, HALF_SIZE);

        // --------- (C) برگشت از feistel_round های اول راند ----------
        // feistelout_R = F(R_k) => R_k = F^{-1}(feistelout_R)
        // feistelout_L = F(L_k) => L_k = F^{-1}(feistelout_L)

        uint8_t Rk[HALF_SIZE];
        uint8_t Lk[HALF_SIZE];
        // feistel_round_inv(feistelout_R, Rk);
        // feistel_round_inv(feistelout_L, Lk);

        // --------- (D) Undo key XOR در ابتدای راند ----------
        // در encrypt:
        // L_k = L ^ key[round*2]
        // R_k = R ^ key[round*2+1]
        // پس برای برگشت همان XOR را دوباره می‌زنیم

        xor_generic(key[round * 2],     Lk, Lk, HALF_SIZE);
        xor_generic(key[round * 2 + 1], Rk, Rk, HALF_SIZE);

        // آماده‌ی راند قبلی
        memcpy(L, Lk, HALF_SIZE);
        memcpy(R, Rk, HALF_SIZE);
   }

   (void)join_generic(block, BLOCK_SIZE, L, R);
}





// ============================
//  file_handling
// ============================




//  file with padding and encrypt
static int file_handling_enc(const char *in_path, const char *out_path,  const uint8_t key_out[KEY_COUNT][KEY_HALF_SIZE]) {
    FILE *in = fopen(in_path, "rb");
    if (!in) {
        perror("fopen input");
        return 1;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("fopen output");
        fclose(in);
        return 1;
    }

    uint8_t block[BLOCK_SIZE];
    size_t n;

    //encrypt for evry block
    while ((n = fread(block, 1, BLOCK_SIZE, in)) == BLOCK_SIZE) {
        encrypt_block(block, key);
        if (fwrite(block, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
            perror("fwrite");
            fclose(in);
            fclose(out);
            return 1;
        }
    }

    if (ferror(in)) {
        perror("fread");
        fclose(in);
        fclose(out);
        return 1;
    }

    //padding
    uint8_t pad = (uint8_t)(BLOCK_SIZE - n);
    memset(block + n, pad, pad);

    encrypt_block(block, key);
    if (fwrite(block, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
        perror("fwrite last");
        fclose(in);
        fclose(out);
        return 1;
    }

    fclose(in);
    fclose(out);
    return 0;
}


static int file_handling_dec(const char *in_path, const char *out_path, const uint8_t key[KEY_COUNT][KEY_HALF_SIZE])
{
    FILE *in = fopen(in_path, "rb");
    if (!in) {
        perror("fopen input");
        return 1;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("fopen output");
        fclose(in);
        return 1;
    }

    uint8_t block[BLOCK_SIZE];
    uint8_t next_block[BLOCK_SIZE];

    size_t n = fread(block, 1, BLOCK_SIZE, in);
    if (n == 0) {
        fprintf(stderr, "Error: empty ciphertext.\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    if (n != BLOCK_SIZE) {
        fprintf(stderr, "Error: ciphertext size is not multiple of BLOCK_SIZE.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    // همه بلوک‌ها به جز آخری
    while ((n = fread(next_block, 1, BLOCK_SIZE, in)) == BLOCK_SIZE) {
        decrypt_block(block, key);

        if (fwrite(block, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
            perror("fwrite");
            fclose(in);
            fclose(out);
            return 1;
        }

        memcpy(block, next_block, BLOCK_SIZE);
    }

    if (ferror(in)) {
        perror("fread");
        fclose(in);
        fclose(out);
        return 1;
    }

    if (n != 0) {
        fprintf(stderr, "Error: ciphertext size is not multiple of BLOCK_SIZE.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    // آخرین بلوک: decrypt و unpad
    decrypt_block(block, key);

    uint8_t pad = block[BLOCK_SIZE - 1];
    if (pad == 0 || pad > BLOCK_SIZE) {
        fprintf(stderr, "Error: invalid padding value.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    for (size_t i = 0; i < pad; i++) {
        if (block[BLOCK_SIZE - 1 - i] != pad) {
            fprintf(stderr, "Error: invalid padding bytes.\n");
            fclose(in);
            fclose(out);
            return 1;
        }
    }

    size_t plain_len = (size_t)(BLOCK_SIZE - pad);
    if (plain_len > 0) {
        if (fwrite(block, 1, plain_len, out) != plain_len) {
            perror("fwrite last");
            fclose(in);
            fclose(out);
            return 1;
        }
    }

    fclose(in);
    fclose(out);
    return 0;
}




// ============================
//   MAIN (menu: 1=enc, 2=dec)
// ============================
int main(int argc, char *argv[])
{
    // ✅ قبول کردن هر دو حالت: بدون کلید (3) و با کلید (4)
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s [base64_key] <input_file_path> <output_file_path>\n", argv[0]);
        return 1;
    }

    // ✅ اگر کلید داده شده باشد، in/out جابجا می‌شوند
    const char *in_path  = (argc == 3) ? argv[1] : argv[2];
    const char *out_path = (argc == 3) ? argv[2] : argv[3];

    // 2) menu
    int choice = 0;
    printf("Select mode:\n");
    printf("  1) Encrypt\n");
    printf("  2) Decrypt\n");
    printf("Enter choice (1/2): ");

    if (scanf("%d", &choice) != 1) {
        fprintf(stderr, "Failed to read choice.\n");
        return 1;
    }

    // 3) flush leftover newline from scanf (so fgets works)
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {}

    if (choice != 1 && choice != 2) {
        fprintf(stderr, "Invalid choice. Must be 1 or 2.\n");
        return 1;
    }


    if (key_main(argc, argv, key) != 0) {
        fprintf(stderr, "main_key failed\n");
        return 1;
    }

    printf("Derived subkeys (key_out):\n");
    print_key_out_hex(key);


    // 5) run + timing
    double t0 = now_seconds();

    int rc = 0;
    if (choice == 1) {
        rc = file_handling_enc(in_path, out_path, key);
    } else {
        rc = file_handling_dec(in_path, out_path, key);
    }

    double t1 = now_seconds();

    // 6) report
    if (rc != 0) {
        fprintf(stderr, "%s failed.\n", (choice == 1) ? "Encryption" : "Decryption");
        return 1;
    }

    printf("Output file: %s\n", out_path);
    printf("Elapsed time: %.6f seconds\n", (t1 - t0));

    return 0;
}
