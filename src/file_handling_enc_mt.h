#ifndef FILE_HANDLING_ENC_MT_H
#define FILE_HANDLING_ENC_MT_H

#include <stdint.h>


int file_handling_enc_mt(const char *in_path,
                         const char *out_path,
                         const uint8_t key_out[KEY_COUNT][KEY_HALF_SIZE],
                         int num_threads);

#endif
