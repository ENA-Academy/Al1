// make header file

//  sudo apt-get install cproto
//  cproto -I. key.c > key.h



//build - linux

//       gcc -O2 -Wall -Wextra -std=c11 key.c SDS.c tools.c -o feistel_enc







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



static void G(const uint8_t B[KEY_HALF_SIZE],
                          const uint8_t master_key[KEYLEN],
                          uint8_t G_out[KEY_HALF_SIZE])
{
    uint8_t buffer1[KEY_HH_SIZE];
    uint8_t buffer2[KEY_HH_SIZE];
    uint8_t *L = buffer1;
    uint8_t *R = buffer2;

    uint8_t keyL[KEY_HH_SIZE];
     uint8_t L1[KEY_HH_SIZE/2], R1[KEY_HH_SIZE/2];
      uint8_t L2[KEY_HH_SIZE/2], R2[KEY_HH_SIZE/2];


  split_generic(B, KEY_HH_SIZE, L, R);


  split_generic(L, (KEY_HH_SIZE/2), L1, R1);
    sds32_round(L1);
    sds32_round(R1);
    join_generic(L, KEY_HALF_SIZE/2, L1, R1);



    xor_generic(L, R , R, KEY_HH_SIZE);



    split_generic(R, (KEY_HH_SIZE/2), L2, R2);
    sds32_round(L2);
    sds32_round(R2);
    join_generic(R, KEY_HALF_SIZE/2, L2, R2);
    xor_generic(L, R , L, KEY_HH_SIZE);

         uint8_t *tmp = L;
            L = R;
            R = tmp;


    (void)join_generic(G_out, KEY_HALF_SIZE, L, R);
}





// ============================
//encrypt_block
// ============================



static void encrypt_block(const uint8_t master_key[KEYLEN]) {
    

    uint8_t buffer1[KEY_HALF_SIZE];
    uint8_t buffer2[KEY_HALF_SIZE];
    uint8_t *L = buffer1;
    uint8_t *R = buffer2;

    if (split_generic(master_key, KEY_BLOCK_SIZE, L, R) != 0) {
        return;
    }



    xor_generic(L,C1, L, KEY_HALF_SIZE);
    xor_generic(R,C2,R, KEY_HALF_SIZE);

    for (int round = 0; round <40; round++) {

      
        uint8_t LSHOUT[KEY_HALF_SIZE];

        G(R,master_key,R);
        G(L,master_key,L);

        rotl_bytes_generic(L, LSHOUT, KEY_HALF_SIZE, 43);
        xor_generic(LSHOUT,R, R, KEY_HALF_SIZE);

        G(R, master_key, R);

        xor_generic(L,R, L, KEY_HALF_SIZE);


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

            
   
         uint8_t *tmp = L;
            L = R;
            R = tmp;





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

// int main(int argc, char *argv[])
// {
// uint8_t out[KEY_COUNT][KEY_HH_SIZE];

// int rc = key_main(argc, argv, out);
// if (rc != 0) return rc;

// // حالا به جای KEY_OUT از out استفاده کن
// print_key_out_hex(out);

// return 0;
// }
