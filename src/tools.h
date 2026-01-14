/* tools.c */
int split_generic(const uint8_t *in, size_t n, uint8_t *L, uint8_t *R);
int join_generic(uint8_t *out, size_t n, const uint8_t *L, const uint8_t *R);
void xor_generic(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t n);
void rotl_bytes_generic(const uint8_t *in, uint8_t *out, size_t n, unsigned shift_bits);
void rotr_bytes_generic(const uint8_t *in, uint8_t *out, size_t n, unsigned shift_bits);
int b64_index(unsigned char c);
int base64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len);
int read_key_256bit_base64(uint8_t key[32]);
void print_key_out_hex(const uint8_t key[26][(32/2)]);
int read_key_256bit_base64_from_str(const char *b64str, uint8_t *out_key);
