

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


// ============================
//   CONFIG
// ============================

#define KEY_BLOCK_SIZE 32            // 256-bit block
#define KEY_HALF_SIZE  (KEY_BLOCK_SIZE/2)  // 128 bit
#define KEY_HH_SIZE  (KEY_HALF_SIZE/2)  // 64 bit
//#define ROUNDS     40
#define KEYLEN 32   // 256-bit = 32 bytes
#define KEY_COUNT      26

extern KEY_OUT[KEY_COUNT][KEY_HH_SIZE];

extern master_key[KEY_COUNT][KEY_HH_SIZE];


// ============================
//   /2 - *2
// ============================
 int split_generic(const uint8_t *in, size_t n,
                         uint8_t *L, uint8_t *R)
{
    if (!in || !L || !R) return 1;
    if ((n % 2) != 0) return 1;

    size_t half = n / 2;

    memcpy(L, in, half);
    memcpy(R, in + half, half);
    return 0;
}

 int join_generic(uint8_t *out, size_t n,
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


 void xor_generic(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

 void rotl_bytes_generic(const uint8_t *in, uint8_t *out, size_t n, unsigned shift_bits)
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

 void rotr_bytes_generic(const uint8_t *in, uint8_t *out, size_t n, unsigned shift_bits)
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
 int b64_index(unsigned char c) {
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
 int base64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len) {
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
 int read_key_256bit_base64(uint8_t key[KEYLEN]) {
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




 void print_key_out_hex(const uint8_t key[KEY_COUNT][KEY_HALF_SIZE]) {
    for (int i = 0; i < KEY_COUNT; i++) {
        printf("K[%02d] = ", i);
        for (int j = 0; j < KEY_HALF_SIZE; j++) {
            printf("%02X", key[i][j]);
        }
        putchar('\n');
    }
}


// decode base64 string to 32-byte key
 int read_key_256bit_base64_from_str(const char *b64str, uint8_t *out_key) {
    size_t out_len = 0;
    int rc = base64_decode(b64str, out_key, KEYLEN, &out_len); // base64_decode از قبل داری
    if (rc != 0) return 1;
    if (out_len != KEYLEN) return 1;
    return 0;
}



