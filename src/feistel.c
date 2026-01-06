// feistel_file_encrypt_portable.c

//  قابل بیلد/ران روی Linux و Windows (MSVC/MinGW)
//
// Build (Linux):
//
//   gcc -O2 -Wall -Wextra -std=c11 key.c SDS.c  feistel.c -o feistel_en
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
//   Tools
// ============================


static void xor_generic(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static void rotl_bytes_generic(const uint8_t *in, uint8_t *out, size_t n, unsigned shift_bits)
{
    if (n == 0) return;

    unsigned total_bits = (unsigned)(n * 8);
    shift_bits %= total_bits;
    if (shift_bits == 0) {
        for (size_t i = 0; i < n; i++) out[i] = in[i];
        return;
    }

    unsigned byte_shift = shift_bits / 8;
    unsigned bit_shift  = shift_bits % 8;

    for (size_t i = 0; i < n; i++) {
        size_t src1 = (i + byte_shift) % n;
        size_t src2 = (i + byte_shift + 1) % n;

        uint8_t a = in[src1];
        uint8_t b = in[src2];

        if (bit_shift == 0) {
            out[i] = a;
        } else {
            out[i] = (uint8_t)((a << bit_shift) | (b >> (8 - bit_shift)));
        }
    }
}

static void rotr_bytes_generic(const uint8_t *in, uint8_t *out, size_t n, unsigned shift_bits)
{
    if (n == 0) return;

    unsigned total_bits = (unsigned)(n * 8);
    shift_bits %= total_bits;
    if (shift_bits == 0) {
        for (size_t i = 0; i < n; i++) out[i] = in[i];
        return;
    }

    // right rotate by k == left rotate by (total_bits - k)
    rotl_bytes_generic(in, out, n, (unsigned)(total_bits - shift_bits));
}



//base64 ----> hex
static int b64_index(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2;     // padding
    if (c == ' ' || c == '\n' || c == '\r' || c == '\t') return -3; // whitespace
    return -1; // invalid
}

// returns 0 on success, nonzero on error
// out_len is set to number of decoded bytes
static int base64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len) {
    int vals[4];
    int vcount = 0;
    size_t olen = 0;

    for (size_t i = 0; in[i] != '\0'; i++) {
        int v = b64_index((unsigned char)in[i]);
        if (v == -3) continue;           // skip whitespace
        if (v == -1) return 1;           // invalid char

        vals[vcount++] = v;

        if (vcount == 4) {
            // Handle padding cases
            if (vals[0] < 0 || vals[1] < 0) return 1;

            uint32_t triple = 0;
            triple |= (uint32_t)(vals[0] & 0x3F) << 18;
            triple |= (uint32_t)(vals[1] & 0x3F) << 12;

            if (vals[2] >= 0) triple |= (uint32_t)(vals[2] & 0x3F) << 6;
            if (vals[3] >= 0) triple |= (uint32_t)(vals[3] & 0x3F);

            // output bytes based on padding
            if (vals[2] == -2 && vals[3] != -2) return 1; // invalid padding form

            if (vals[2] == -2 && vals[3] == -2) {
                // xx== -> 1 byte
                if (olen + 1 > out_cap) return 2;
                out[olen++] = (uint8_t)((triple >> 16) & 0xFF);
            } else if (vals[3] == -2) {
                // xxx= -> 2 bytes
                if (olen + 2 > out_cap) return 2;
                out[olen++] = (uint8_t)((triple >> 16) & 0xFF);
                out[olen++] = (uint8_t)((triple >> 8) & 0xFF);
            } else {
                // xxxx -> 3 bytes
                if (olen + 3 > out_cap) return 2;
                out[olen++] = (uint8_t)((triple >> 16) & 0xFF);
                out[olen++] = (uint8_t)((triple >> 8) & 0xFF);
                out[olen++] = (uint8_t)(triple & 0xFF);
            }

            vcount = 0;
        }
    }

    if (vcount != 0) return 1; // incomplete quartet
    *out_len = olen;
    return 0;
}

// Reads a base64 key from stdin, decodes, and requires exactly 32 bytes (256-bit)
static int read_key_256bit_base64(uint8_t key[KEYLEN]) {
    char key_in[4096];

    printf("Enter a 256-bit key in Base64 (should decode to exactly 32 bytes):\n");
    if (!fgets(key_in, sizeof(key_in), stdin)) {
        fprintf(stderr, "Failed to read key.\n");
        return 1;
    }

    size_t klen = strcspn(key_in, "\r\n");
    key_in[klen] = '\0';

    size_t out_len = 0;
    int rc = base64_decode(key_in, key, KEYLEN, &out_len);
    if (rc != 0) {
        fprintf(stderr, "Error: invalid Base64 key.\n");
        return 1;
    }
    if (out_len != KEYLEN) {
        fprintf(stderr, "Error: Base64 decoded length is %zu bytes, must be exactly %d bytes (256-bit).\n",
                out_len, KEYLEN);
        return 1;
    }

    return 0;
}




static void print_key_out_hex(const uint8_t key[KEY_COUNT][KEY_HALF_SIZE]) {
    for (int i = 0; i < KEY_COUNT; i++) {
        printf("K[%02d] = ", i);
        for (int j = 0; j < KEY_HALF_SIZE; j++) {
            printf("%02X", key[i][j]);
        }
        putchar('\n');
    }
}






// ============================
//   F
// ============================


static void feistel_round(const uint8_t in[HALF_SIZE],
                          uint8_t f_out[HALF_SIZE])
{
    uint8_t newL[HALF_HALF_SIZE], newR[HALF_HALF_SIZE];

    if (split_generic(in, HALF_SIZE, newL, newR) != 0) {
        memset(f_out, 0, HALF_SIZE);
        return;
    }




//enter SDS

uint8_t newLSDS1[HALF_HALF_SIZE];
uint8_t newRSDS2[HALF_HALF_SIZE];



//convert newL to 32bit
    uint32_t x = (uint32_t)newL[0]
                 | ((uint32_t)newL[1] << 8)
                 | ((uint32_t)newL[2] << 16)
                 | ((uint32_t)newL[3] << 24);

    uint32_t y = sds32_round(x);

    newLSDS1[0] = (uint8_t)(y);
    newLSDS1[1] = (uint8_t)(y >> 8);
    newLSDS1[2] = (uint8_t)(y >> 16);
    newLSDS1[3] = (uint8_t)(y >> 24);


    xor_generic(newLSDS1, newR , newR, HALF_HALF_SIZE);

    uint32_t z = (uint32_t)newR[0]
                 | ((uint32_t)newR[1] << 8)
                 | ((uint32_t)newR[2] << 16)
                 | ((uint32_t)newR[3] << 24);

    uint32_t g = sds32_round(z);

    newRSDS2[0] = (uint8_t)(g);
    newRSDS2[1] = (uint8_t)(g >> 8);
    newRSDS2[2] = (uint8_t)(g >> 16);
    newRSDS2[3] = (uint8_t)(g >> 24);


 xor_generic(newRSDS2, newL , newR, HALF_HALF_SIZE);


    for (int i = 0; i < HALF_HALF_SIZE; i++) {
        uint8_t oldR = newR[i];
        newR[i] =newL[i];
        newL[i] = oldR;

    }

    (void)join_generic(f_out, HALF_SIZE, newL, newR);
}



static void feistel_round_inv(const uint8_t in[HALF_SIZE],
                              uint8_t f_out[HALF_SIZE])
{
    uint8_t newL[HALF_HALF_SIZE], newR[HALF_HALF_SIZE];

    if (split_generic(in, HALF_SIZE, newL, newR) != 0) {
        memset(f_out, 0, HALF_SIZE);
        return;
    }

    // undo swap (forward آخرش swap کرده بود)
    for (int i = 0; i < HALF_HALF_SIZE; i++) {
        uint8_t t = newL[i];
        newL[i] = newR[i];
        newR[i] = t;
    }
    // الان: newL = L0  و newR = R2

    uint8_t sdsR1_out[HALF_HALF_SIZE];   // SDS(R1)
    uint8_t R1_bytes[HALF_HALF_SIZE];    // R1
    uint8_t sdsL0_bytes[HALF_HALF_SIZE]; // SDS(L0)

    // SDS(R1) = R2 XOR L0
    xor_generic(newR, newL, sdsR1_out, HALF_HALF_SIZE);

    // R1 = SDS_INV(SDS(R1))
    uint32_t a = (uint32_t)sdsR1_out[0]
                 | ((uint32_t)sdsR1_out[1] << 8)
                 | ((uint32_t)sdsR1_out[2] << 16)
                 | ((uint32_t)sdsR1_out[3] << 24);

    uint32_t b = sds32_round_inv(a);

    R1_bytes[0] = (uint8_t)(b);
    R1_bytes[1] = (uint8_t)(b >> 8);
    R1_bytes[2] = (uint8_t)(b >> 16);
    R1_bytes[3] = (uint8_t)(b >> 24);

    // SDS(L0)
    uint32_t x = (uint32_t)newL[0]
                 | ((uint32_t)newL[1] << 8)
                 | ((uint32_t)newL[2] << 16)
                 | ((uint32_t)newL[3] << 24);

    uint32_t y = sds32_round(x);

    sdsL0_bytes[0] = (uint8_t)(y);
    sdsL0_bytes[1] = (uint8_t)(y >> 8);
    sdsL0_bytes[2] = (uint8_t)(y >> 16);
    sdsL0_bytes[3] = (uint8_t)(y >> 24);

    // R0 = R1 XOR SDS(L0)  -> نتیجه را داخل newR می‌ریزیم
    xor_generic(R1_bytes, sdsL0_bytes, newR, HALF_HALF_SIZE);

    // خروجی: (L0, R0)
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
        feistel_round_inv(feistelout_R, Rk);
        feistel_round_inv(feistelout_L, Lk);

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
