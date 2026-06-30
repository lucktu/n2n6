/* Pure C AES implementation for n2n6.
 * Ported from n2n project (ntop.org), plain C path only.
 */

#ifndef N2N_AES_H
#define N2N_AES_H

#include <stdint.h>
#include <stdlib.h>
#include "portable_endian.h"

#define N2N_AES_BLOCK_SIZE    16
#define N2N_AES_IV_SIZE       16
#define N2N_AES256_KEY_BYTES  32
#define N2N_AES192_KEY_BYTES  24
#define N2N_AES128_KEY_BYTES  16

typedef struct n2n_aes_context_t {
    uint32_t enc_rk[60];
    uint32_t dec_rk[60];
    int      Nr;
} n2n_aes_context_t;

int n2n_aes_cbc_encrypt(unsigned char *out, const unsigned char *in, size_t in_len,
                        const unsigned char *iv, n2n_aes_context_t *ctx);
int n2n_aes_cbc_decrypt(unsigned char *out, const unsigned char *in, size_t in_len,
                        const unsigned char *iv, n2n_aes_context_t *ctx);
int n2n_aes_ecb_encrypt(unsigned char *out, const unsigned char *in, n2n_aes_context_t *ctx);
int n2n_aes_init(const unsigned char *key, size_t key_size, n2n_aes_context_t **ctx);
int n2n_aes_deinit(n2n_aes_context_t *ctx);

#endif /* N2N_AES_H */
