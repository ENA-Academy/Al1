// make header file

//  sudo apt-get install cproto
//  cproto -I. key.c > key.h



//build - linux

//       gcc -O2 -Wall -Wextra -std=c11 key.c SDS.c -o feistel_enc







#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "SDS.h"
#include "tools.h"

// ============================
//   CONFIG
// ============================

#define KEY_BLOCK_SIZE 32            // 256-bit block
#define KEY_HALF_SIZE  (KEY_BLOCK_SIZE/2)  // 128 bit
#define KEY_HH_SIZE  (KEY_HALF_SIZE/2)  // 64 bit
//#define ROUNDS     40
#define KEYLEN 32   // 256-bit = 32 bytes
#define KEY_COUNT      26

uint8_t KEY_OUT[KEY_COUNT][KEY_HH_SIZE];

uint8_t master_key[KEY_COUNT][KEY_HH_SIZE];


static const uint8_t C1[KEY_HALF_SIZE] = {
    0x13,0x37,0xA9,0x5C,0x01,0x02,0x03,0x04,
    0x55,0xAA,0x10,0x20,0x30,0x40,0xDE,0xAD
};
static const uint8_t C2[KEY_HALF_SIZE] = {
    0xC0,0xFF,0xEE,0x12,0x9B,0x7A,0x66,0xD4,
    0x0F,0x1E,0x2D,0x3C,0x4B,0x5A,0x69,0x78
};



// ============================
//   F
// ============================

static inline uint8_t keymerg_onebit(uint8_t r, uint8_t k) {
    return (uint8_t)(r ^ k);
}

static void feistel_round(const uint8_t R[KEY_HALF_SIZE],
                          const uint8_t master_key[KEYLEN],
                          int round,
                          uint8_t f_out[KEY_HALF_SIZE])
{
    uint8_t newL[KEY_HH_SIZE], newR[KEY_HH_SIZE],keyL[KEY_HH_SIZE];

    if (split_generic(R, KEY_HALF_SIZE, newL, newR) != 0) {
        memset(f_out, 0, KEY_HALF_SIZE);
        return;
    }


    for (int i = 0; i < KEY_HH_SIZE; i++) {
        uint8_t kL = (uint8_t)(
            master_key[(round * KEY_HALF_SIZE + i) % KEYLEN] ^
            (uint8_t)(round * 17 + i * 31)
            );
        keyL[i] = keymerg_onebit(newL[i], kL);
    }

    xor_generic(keyL, newR , newR, KEY_HH_SIZE);

    for (int i = 0; i < KEY_HH_SIZE; i++) {
        uint8_t oldR = newR[i];
        newR[i] =newL[i];
        newL[i] = oldR;

    }

    (void)join_generic(f_out, KEY_HALF_SIZE, newL, newR);
}



static void feistel_round_inv(const uint8_t f_out[KEY_HALF_SIZE],
                              const uint8_t master_key[KEYLEN],
                              int round,
                              uint8_t R[KEY_HALF_SIZE])
{
    uint8_t newL[KEY_HH_SIZE], newR[KEY_HH_SIZE];
    uint8_t oldL[KEY_HH_SIZE], oldR[KEY_HH_SIZE];

    // f_out = join(newL, newR)
    if (split_generic(f_out, KEY_HALF_SIZE, newL, newR) != 0) {
        memset(R, 0, KEY_HALF_SIZE);
        return;
    }

    // در encrypt داخل feistel_round آخرش swap شد:
    // newR == oldL
    // پس:
    memcpy(oldL, newR, KEY_HH_SIZE);

    // newL = oldR ^ (oldL ^ k)  => oldR = newL ^ oldL ^ k
    for (int i = 0; i < KEY_HH_SIZE; i++) {
        uint8_t kL = (uint8_t)(
            master_key[(round * KEY_HALF_SIZE + i) % KEYLEN] ^
            (uint8_t)(round * 17 + i * 31)
            );
        oldR[i] = (uint8_t)(newL[i] ^ oldL[i] ^ kL);
    }

    (void)join_generic(R, KEY_HALF_SIZE, oldL, oldR);
}




// ============================
//encrypt_block
// ============================



static void encrypt_block(const uint8_t master_key[KEYLEN]) {
    uint8_t L[KEY_HALF_SIZE], R[KEY_HALF_SIZE];

    if (split_generic(master_key, KEY_BLOCK_SIZE, L, R) != 0) {
        return;
    }

    uint8_t LC[KEY_HALF_SIZE], RC[KEY_HALF_SIZE];


    xor_generic(L,C1, LC, KEY_HALF_SIZE);
    xor_generic(R,C2,RC, KEY_HALF_SIZE);

    for (int round = 0; round <40; round++) {

        uint8_t feistelout_R[KEY_HALF_SIZE];
        uint8_t feistelout_L[KEY_HALF_SIZE];
        uint8_t feistelout_M[KEY_HALF_SIZE];
        uint8_t xorout_one[KEY_HALF_SIZE];
        uint8_t xorout_two[KEY_HALF_SIZE];
        uint8_t feistelout_LSH[KEY_HALF_SIZE];

        feistel_round(RC,master_key,round ,feistelout_R);
        feistel_round(LC,master_key,round ,feistelout_L);

        rotl_bytes_generic(feistelout_L, feistelout_LSH, KEY_HALF_SIZE, 43);
        xor_generic(feistelout_LSH,feistelout_R, xorout_one, KEY_HALF_SIZE);

        feistel_round(xorout_one, master_key, round, feistelout_M);

        xor_generic(feistelout_L,feistelout_M, xorout_two, KEY_HALF_SIZE);

        for (int i = 0; i < KEY_HALF_SIZE; i++) {
            uint8_t oldR = xorout_one[i];
            R[i] = xorout_two[i];
            L[i] = oldR;

        }



        uint8_t R1[KEY_HH_SIZE], R2[KEY_HH_SIZE];
        if (round == 16) {
            split_generic(R, KEY_HALF_SIZE, R1, R2);
            memcpy(KEY_OUT[round - 16], R1, KEY_HH_SIZE);
            memcpy(KEY_OUT[round- 15], R2, KEY_HH_SIZE);
        }else if (round == 17) {
                split_generic(R, KEY_HALF_SIZE, R1, R2);
                memcpy(KEY_OUT[round - 15], R1, KEY_HH_SIZE);
                memcpy(KEY_OUT[round- 14], R2, KEY_HH_SIZE);

        } else if (round > 16 && (round % 2) == 0) {
            split_generic(R, KEY_HALF_SIZE, R1, R2);
            memcpy(KEY_OUT[round - 15], R1, KEY_HH_SIZE);
            memcpy(KEY_OUT[round - 14], R2, KEY_HH_SIZE);
        }   else if( round == 39 ) {
            split_generic(R, KEY_HALF_SIZE, R1, R2);
            memcpy(KEY_OUT[round - 15], R1, KEY_HH_SIZE);
            memcpy(KEY_OUT[round - 14], R2, KEY_HH_SIZE);
        }


}
}


// ============================
//   MAIN
// ============================


int key_main(int argc, char *argv[],
             uint8_t out_key_out[KEY_COUNT][KEY_HH_SIZE])
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
//uint8_t out[KEY_COUNT][KEY_HH_SIZE];

//int rc = key_main(argc, argv, out);
//if (rc != 0) return rc;

//// حالا به جای KEY_OUT از out استفاده کن
//print_key_out(out);

//return 0;
//}
