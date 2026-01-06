// make header file

//  sudo apt-get install cproto
//  cproto -I. key.c > key.h



//build - linux

//       gcc -O2 -Wall -Wextra -std=c11 key.c SDS.c -o feistel_enc







#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


// ============================
//   CONFIG
// ============================

#define BLOCK_SIZE 32            // 256-bit block
#define HALF_SIZE  (BLOCK_SIZE/2)  // 128 bit
#define HALF_HALF_SIZE  (HALF_SIZE/2)  // 64 bit
//#define ROUNDS     40
#define KEYLEN 32   // 256-bit = 32 bytes
#define KEY_COUNT      26

uint8_t KEY_OUT[KEY_COUNT][HALF_HALF_SIZE];

uint8_t master_key[KEY_COUNT][HALF_HALF_SIZE];


static const uint8_t C1[HALF_SIZE] = {
    0x13,0x37,0xA9,0x5C,0x01,0x02,0x03,0x04,
    0x55,0xAA,0x10,0x20,0x30,0x40,0xDE,0xAD
};
static const uint8_t C2[HALF_SIZE] = {
    0xC0,0xFF,0xEE,0x12,0x9B,0x7A,0x66,0xD4,
    0x0F,0x1E,0x2D,0x3C,0x4B,0x5A,0x69,0x78
};




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



void print_key_out(uint8_t KEY_OUT[KEY_COUNT][HALF_HALF_SIZE]) {
    for (int i = 0; i < KEY_COUNT; i++) {
        printf("KEY_OUT[%d]: ", i);
        for (int j = 0; j < HALF_HALF_SIZE; j++) {
            printf("%02X ", KEY_OUT[i][j]);
        }
        printf("\n");
    }
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
static int read_key_256bit_base64(uint8_t master_key[KEY_COUNT][HALF_HALF_SIZE]) {
    char key_in[4096];

    printf("Enter a 256-bit key in Base64 (should decode to exactly 32 bytes):\n");
    if (!fgets(key_in, sizeof(key_in), stdin)) {
        fprintf(stderr, "Failed to read key.\n");
        return 1;
    }

    size_t klen = strcspn(key_in, "\r\n");
    key_in[klen] = '\0';

    size_t out_len = 0;
    int rc = base64_decode(key_in, &master_key[0][0], sizeof master_key, &out_len);

  //  int rc = base64_decode(key_in, master_key, KEYLEN, &out_len);
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



// decode base64 string to 32-byte key
static int read_key_256bit_base64_from_str(const char *b64str, uint8_t *out_key) {
    size_t out_len = 0;
    int rc = base64_decode(b64str, out_key, KEYLEN, &out_len); // base64_decode از قبل داری
    if (rc != 0) return 1;
    if (out_len != KEYLEN) return 1;
    return 0;
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
//encrypt_block
// ============================



static void encrypt_block(const uint8_t master_key[KEYLEN]) {
    uint8_t L[HALF_SIZE], R[HALF_SIZE];

    if (split_generic(master_key, BLOCK_SIZE, L, R) != 0) {
        return;
    }

    uint8_t LC[HALF_SIZE], RC[HALF_SIZE];


    xor_generic(L,C1, LC, HALF_SIZE);
    xor_generic(R,C2,RC, HALF_SIZE);

    for (int round = 0; round <40; round++) {

        uint8_t feistelout_R[HALF_SIZE];
        uint8_t feistelout_L[HALF_SIZE];
        uint8_t feistelout_M[HALF_SIZE];
        uint8_t xorout_one[HALF_SIZE];
        uint8_t xorout_two[HALF_SIZE];
        uint8_t feistelout_LSH[HALF_SIZE];

        feistel_round(RC,master_key,round ,feistelout_R);
        feistel_round(LC,master_key,round ,feistelout_L);

        rotl_bytes_generic(feistelout_L, feistelout_LSH, HALF_SIZE, 43);
        xor_generic(feistelout_LSH,feistelout_R, xorout_one, HALF_SIZE);

        feistel_round(xorout_one, master_key, round, feistelout_M);

        xor_generic(feistelout_L,feistelout_M, xorout_two, HALF_SIZE);

        for (int i = 0; i < HALF_SIZE; i++) {
            uint8_t oldR = xorout_one[i];
            R[i] = xorout_two[i];
            L[i] = oldR;

        }



        uint8_t R1[HALF_HALF_SIZE], R2[HALF_HALF_SIZE];
        if (round == 16) {
            split_generic(R, HALF_SIZE, R1, R2);
            memcpy(KEY_OUT[round - 16], R1, HALF_HALF_SIZE);
            memcpy(KEY_OUT[round- 15], R2, HALF_HALF_SIZE);
        }else if (round == 17) {
                split_generic(R, HALF_SIZE, R1, R2);
                memcpy(KEY_OUT[round - 15], R1, HALF_HALF_SIZE);
                memcpy(KEY_OUT[round- 14], R2, HALF_HALF_SIZE);

        } else if (round > 16 && (round % 2) == 0) {
            split_generic(R, HALF_SIZE, R1, R2);
            memcpy(KEY_OUT[round - 15], R1, HALF_HALF_SIZE);
            memcpy(KEY_OUT[round - 14], R2, HALF_HALF_SIZE);
        }   else if( round == 39 ) {
            split_generic(R, HALF_SIZE, R1, R2);
            memcpy(KEY_OUT[round - 15], R1, HALF_HALF_SIZE);
            memcpy(KEY_OUT[round - 14], R2, HALF_HALF_SIZE);
        }


}
}


// ============================
//   MAIN
// ============================


int key_main(int argc, char *argv[],
             uint8_t out_key_out[KEY_COUNT][HALF_HALF_SIZE])
{
uint8_t master_key[KEYLEN];
char base64_buf[256];

if (!out_key_out) return 2;

const char *base64_str = NULL;

// ✅ فقط اگر 3 آرگومان بعد از نام برنامه داریم (key + in + out) از argv کلید بگیر
if (argc == 4) {
        base64_str = argv[1];
} else {
        printf("Enter Base64 key: ");
        fflush(stdout);

        if (!fgets(base64_buf, sizeof base64_buf, stdin)) {
            fprintf(stderr, "Failed to read key\n");
            return 1;
        }

        base64_buf[strcspn(base64_buf, "\r\n")] = 0;

        if (base64_buf[0] == '\0') {
            fprintf(stderr, "Empty key entered\n");
            return 1;
        }

        base64_str = base64_buf;
}

if (read_key_256bit_base64_from_str(base64_str, master_key) != 0) {
        printf("Failed to parse Base64 key\n");
        return 1;
}

encrypt_block(master_key);  // KEY_OUT پر می‌شود
memcpy(out_key_out, KEY_OUT, sizeof(KEY_OUT));
return 0;
}
//---------------

//int main(int argc, char *argv[])
//{
//uint8_t out[KEY_COUNT][HALF_HALF_SIZE];

//int rc = key_main(argc, argv, out);
//if (rc != 0) return rc;

//// حالا به جای KEY_OUT از out استفاده کن
//print_key_out(out);

//return 0;
//}
