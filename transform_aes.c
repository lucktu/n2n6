/* AES-CBC transform for n2n6.
 * Packet format and key derivation identical to cnn2n for full interoperability.
 * Uses pure C AES (aes.c) and pure C SHA (sha.c) - no OpenSSL dependency.
 */

#include "n2n.h"
#include "n2n_transforms.h"
#include "aes.h"
#include "sha.h"
#include "random.h"

#define N2N_AES_TRANSFORM_VERSION    1
#define N2N_AES_IVEC_SIZE            N2N_AES_BLOCK_SIZE   /* 16 */

#define AES256_KEY_BYTES N2N_AES256_KEY_BYTES
#define AES192_KEY_BYTES N2N_AES192_KEY_BYTES
#define AES128_KEY_BYTES N2N_AES128_KEY_BYTES

#define TRANSOP_AES_VER_SIZE         1
#define TRANSOP_AES_IV_SEED_SIZE     8
#define TRANSOP_AES_IV_PADDING_SIZE  (N2N_AES_IVEC_SIZE - TRANSOP_AES_IV_SEED_SIZE)
#define TRANSOP_AES_IV_KEY_BYTES     AES128_KEY_BYTES
#define TRANSOP_AES_PREAMBLE_SIZE    (TRANSOP_AES_VER_SIZE + TRANSOP_AES_IV_SEED_SIZE)

typedef unsigned char n2n_aes_ivec_t[N2N_AES_IVEC_SIZE];

typedef struct transop_aes {
    n2n_aes_context_t *enc_ctx;
    n2n_aes_context_t *dec_ctx;
    n2n_aes_context_t *iv_enc_ctx;   /* AES128 context for IV encryption */
    uint8_t            iv_pad_val[TRANSOP_AES_IV_PADDING_SIZE];
    uint8_t            assembly[N2N_TRANSFORM_BUF_SIZE]; /* heap-allocated to avoid large stack */
} transop_aes_t;

static int transop_deinit_aes(n2n_trans_op_t *arg) {
    transop_aes_t *priv = (transop_aes_t *)arg->priv;
    if (priv) {
        n2n_aes_deinit(priv->enc_ctx);
        n2n_aes_deinit(priv->dec_ctx);
        n2n_aes_deinit(priv->iv_enc_ctx);
        free(priv);
    }
    arg->priv = NULL;
    return 0;
}

static void set_aes_cbc_iv(transop_aes_t *priv, n2n_aes_ivec_t ivec, uint8_t *iv_seed) {
    uint8_t iv_full[N2N_AES_IVEC_SIZE];
    memcpy(iv_full, priv->iv_pad_val, TRANSOP_AES_IV_PADDING_SIZE);
    memcpy(iv_full + TRANSOP_AES_IV_PADDING_SIZE, iv_seed, TRANSOP_AES_IV_SEED_SIZE);
    n2n_aes_ecb_encrypt(ivec, iv_full, priv->iv_enc_ctx);
}

static ssize_t transop_encode_aes(n2n_trans_op_t *arg,
                                   uint8_t *outbuf, size_t out_len,
                                   const uint8_t *inbuf, size_t in_len,
                                   const uint8_t *peer_mac) {
    transop_aes_t *priv = (transop_aes_t *)arg->priv;

    if (in_len > N2N_TRANSFORM_BUF_SIZE || (in_len + TRANSOP_AES_PREAMBLE_SIZE) > out_len) return -1;

    size_t idx = 0;
    uint8_t iv_seed[TRANSOP_AES_IV_SEED_SIZE];
    n2n_aes_ivec_t enc_ivec = {0};

    encode_uint8(outbuf, &idx, N2N_AES_TRANSFORM_VERSION);
    random_bytes_buf(iv_seed, TRANSOP_AES_IV_SEED_SIZE);
    encode_buf(outbuf, &idx, iv_seed, TRANSOP_AES_IV_SEED_SIZE);

    memset(priv->assembly, 0, N2N_TRANSFORM_BUF_SIZE);
    memcpy(priv->assembly, inbuf, in_len);
    int len2 = ((in_len / N2N_AES_BLOCK_SIZE) + 1) * N2N_AES_BLOCK_SIZE;
    priv->assembly[len2 - 1] = len2 - in_len;

    set_aes_cbc_iv(priv, enc_ivec, iv_seed);
    n2n_aes_cbc_encrypt(outbuf + TRANSOP_AES_PREAMBLE_SIZE, priv->assembly, len2, enc_ivec, priv->enc_ctx);

    return len2 + TRANSOP_AES_PREAMBLE_SIZE;
}

static ssize_t transop_decode_aes(n2n_trans_op_t *arg,
                                   uint8_t *outbuf, size_t out_len,
                                   const uint8_t *inbuf, size_t in_len,
                                   const uint8_t *peer_mac) {
    transop_aes_t *priv = (transop_aes_t *)arg->priv;

    if (in_len < TRANSOP_AES_PREAMBLE_SIZE || (in_len - TRANSOP_AES_PREAMBLE_SIZE) > N2N_TRANSFORM_BUF_SIZE) return 0;

    size_t rem = in_len, idx = 0;
    uint8_t aes_enc_ver = 0, iv_seed[TRANSOP_AES_IV_SEED_SIZE];

    decode_uint8(&aes_enc_ver, inbuf, &rem, &idx);
    if (aes_enc_ver != N2N_AES_TRANSFORM_VERSION) return 0;

    decode_buf(iv_seed, TRANSOP_AES_IV_SEED_SIZE, inbuf, &rem, &idx);
    int len = in_len - TRANSOP_AES_PREAMBLE_SIZE;
    if (len % N2N_AES_BLOCK_SIZE != 0) return 0;

    n2n_aes_ivec_t dec_ivec = {0};
    set_aes_cbc_iv(priv, dec_ivec, iv_seed);
    n2n_aes_cbc_decrypt(priv->assembly, inbuf + TRANSOP_AES_PREAMBLE_SIZE, len, dec_ivec, priv->dec_ctx);

    uint8_t padding = priv->assembly[len - 1] & 0xff;
    if (len < (int)padding) return 0;
    len -= padding;
    memcpy(outbuf, priv->assembly, len);
    return len;
}

static int setup_aes_key(transop_aes_t *priv, const uint8_t *key, ssize_t key_size) {
    size_t aes_key_size_bytes;
    uint8_t key_mat_buf[N2N_SHA512_DIGEST_LENGTH + N2N_SHA256_DIGEST_LENGTH];
    size_t key_mat_buf_length;

    /* Key derivation identical to cnn2n */
    if (key_size >= 65) {
        aes_key_size_bytes = AES256_KEY_BYTES;
        n2n_sha512(key, key_size, key_mat_buf);
        key_mat_buf_length = N2N_SHA512_DIGEST_LENGTH;
    } else if (key_size >= 44) {
        aes_key_size_bytes = AES192_KEY_BYTES;
        n2n_sha384(key, key_size, key_mat_buf);
        n2n_sha256(key_mat_buf, N2N_SHA384_DIGEST_LENGTH, key_mat_buf + N2N_SHA384_DIGEST_LENGTH);
        key_mat_buf_length = N2N_SHA384_DIGEST_LENGTH + N2N_SHA256_DIGEST_LENGTH;
    } else {
        aes_key_size_bytes = AES128_KEY_BYTES;
        n2n_sha256(key, key_size, key_mat_buf);
        n2n_sha256(key_mat_buf, N2N_SHA256_DIGEST_LENGTH, key_mat_buf + N2N_SHA256_DIGEST_LENGTH);
        key_mat_buf_length = 2 * N2N_SHA256_DIGEST_LENGTH;
    }

    n2n_aes_init(key_mat_buf, aes_key_size_bytes, &priv->enc_ctx);
    n2n_aes_init(key_mat_buf, aes_key_size_bytes, &priv->dec_ctx);
    n2n_aes_init(key_mat_buf + aes_key_size_bytes, TRANSOP_AES_IV_KEY_BYTES, &priv->iv_enc_ctx);
    memcpy(priv->iv_pad_val, key_mat_buf + aes_key_size_bytes + TRANSOP_AES_IV_KEY_BYTES, TRANSOP_AES_IV_PADDING_SIZE);

    traceEvent(TRACE_DEBUG, "AES %zu bits setup completed", aes_key_size_bytes * 8);
    return 0;
}

static int transop_addspec_aes(n2n_trans_op_t *arg, const n2n_cipherspec_t *cspec) { return 0; }
static n2n_tostat_t transop_tick_aes(n2n_trans_op_t *arg, time_t now) {
    transop_aes_t *priv = (transop_aes_t *)arg->priv;
    n2n_tostat_t r; memset(&r, 0, sizeof(r));
    r.can_tx = (priv && priv->enc_ctx) ? 1 : 0;
    return r;
}

int transop_aes_init(n2n_trans_op_t *ttt) {
    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_AESCBC;
    ttt->tick    = transop_tick_aes;
    ttt->deinit  = transop_deinit_aes;
    ttt->fwd     = transop_encode_aes;
    ttt->rev     = transop_decode_aes;
    ttt->addspec = transop_addspec_aes;

    transop_aes_t *priv = (transop_aes_t *)calloc(1, sizeof(transop_aes_t));
    if (!priv) return -1;
    ttt->priv = priv;
    return 0;
}

int edge_init_aes_from_key(n2n_trans_op_t *ttt, const uint8_t *key, size_t key_len) {
    return setup_aes_key((transop_aes_t *)ttt->priv, key, (ssize_t)key_len);
}
