/* ChaCha20 transform for n2n.
 * Uses cc20.c (pure C or OpenSSL) - no OpenSSL version dependency.
 * Compatible with cnn2n: transform_id=4, packet format [V(1)|IV(16)|encrypted]
 */

#include "n2n.h"
#include "n2n_transforms.h"
#include "cc20.h"
#include "random.h"
#include "pearson.h"
#ifdef USE_OPENSSL
#include <openssl/sha.h>
#endif

#define N2N_CC20_TRANSFORM_VERSION   1
#define N2N_CC20_IVEC_SIZE           CC20_IV_SIZE   /* 16 */
#define TRANSOP_CC20_VER_SIZE        1
#define TRANSOP_CC20_PREAMBLE_SIZE   (TRANSOP_CC20_VER_SIZE + N2N_CC20_IVEC_SIZE)

typedef struct transop_cc20 {
    cc20_context_t *ctx;
} transop_cc20_t;

static int transop_deinit_cc20(n2n_trans_op_t *arg) {
    transop_cc20_t *priv = (transop_cc20_t *)arg->priv;
    if (priv) {
        cc20_deinit(priv->ctx);
        free(priv);
    }
    arg->priv = NULL;
    return 0;
}

static ssize_t transop_encode_cc20(n2n_trans_op_t *arg,
                                uint8_t *outbuf, size_t out_len,
                                const uint8_t *inbuf, size_t in_len,
                                const uint8_t *peer_mac) {
    transop_cc20_t *priv = (transop_cc20_t *)arg->priv;

    if (in_len > N2N_TRANSFORM_BUF_SIZE) { traceEvent(TRACE_ERROR, "encode_cc20 inbuf too big"); return -1; }
    if ((in_len + TRANSOP_CC20_PREAMBLE_SIZE) > out_len) { traceEvent(TRACE_ERROR, "encode_cc20 outbuf too small"); return -1; }

    size_t idx = 0;
    uint8_t enc_ivec[N2N_CC20_IVEC_SIZE];

    encode_uint8(outbuf, &idx, N2N_CC20_TRANSFORM_VERSION);

    /* IV from cryptographically secure random source */
    random_bytes_buf(enc_ivec, N2N_CC20_IVEC_SIZE);
    encode_buf(outbuf, &idx, enc_ivec, N2N_CC20_IVEC_SIZE);

    cc20_crypt(outbuf + TRANSOP_CC20_PREAMBLE_SIZE, inbuf, in_len, enc_ivec, priv->ctx);

    return in_len + TRANSOP_CC20_PREAMBLE_SIZE;
}

static ssize_t transop_decode_cc20(n2n_trans_op_t *arg,
                                uint8_t *outbuf, size_t out_len,
                                const uint8_t *inbuf, size_t in_len,
                                const uint8_t *peer_mac) {
    transop_cc20_t *priv = (transop_cc20_t *)arg->priv;

    if (in_len < TRANSOP_CC20_PREAMBLE_SIZE || (in_len - TRANSOP_CC20_PREAMBLE_SIZE) > N2N_TRANSFORM_BUF_SIZE) {
        traceEvent(TRACE_ERROR, "decode_cc20 wrong size %zu", in_len); return 0;
    }

    size_t rem = in_len, idx = 0;
    uint8_t cc20_enc_ver = 0;
    uint8_t dec_ivec[N2N_CC20_IVEC_SIZE];

    decode_uint8(&cc20_enc_ver, inbuf, &rem, &idx);
    if (cc20_enc_ver != N2N_CC20_TRANSFORM_VERSION) {
        traceEvent(TRACE_ERROR, "decode_cc20 unsupported version %u", cc20_enc_ver); return 0;
    }

    decode_buf(dec_ivec, N2N_CC20_IVEC_SIZE, inbuf, &rem, &idx);

    int len = in_len - TRANSOP_CC20_PREAMBLE_SIZE;
    cc20_crypt(outbuf, inbuf + TRANSOP_CC20_PREAMBLE_SIZE, len, dec_ivec, priv->ctx);

    return len;
}

static int transop_addspec_cc20(n2n_trans_op_t *arg, const n2n_cipherspec_t *cspec) { return 0; }
static n2n_tostat_t transop_tick_cc20(n2n_trans_op_t *arg, time_t now) {
    n2n_tostat_t r; memset(&r, 0, sizeof(r)); r.can_tx = 1; return r;
}

int transop_cc20_init(n2n_trans_op_t *ttt) {
    transop_cc20_t *priv;

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_CHACHA20;
    ttt->tick    = transop_tick_cc20;
    ttt->deinit  = transop_deinit_cc20;
    ttt->fwd     = transop_encode_cc20;
    ttt->rev     = transop_decode_cc20;
    ttt->addspec = transop_addspec_cc20;

    priv = (transop_cc20_t *)calloc(1, sizeof(transop_cc20_t));
    if (!priv) { traceEvent(TRACE_ERROR, "cannot allocate transop_cc20_t"); return -1; }
    ttt->priv = priv;
    /* ctx initialized later in edge_init_cc20_from_key */
    return 0;
}

int edge_init_cc20_from_key(n2n_trans_op_t *ttt, const uint8_t *key, size_t key_len) {
    transop_cc20_t *priv = (transop_cc20_t *)ttt->priv;

    /* SHA256 key derivation - same as cnn2n */
    uint8_t key_mat[32];
#ifdef USE_OPENSSL
    SHA256(key, key_len, key_mat);
#else
    pearson_hash_256(key_mat, key, key_len);
#endif

    if (priv->ctx) cc20_deinit(priv->ctx);
    cc20_init(key_mat, &priv->ctx);

    traceEvent(TRACE_DEBUG, "ChaCha20 key setup completed");
    return 0;
}
