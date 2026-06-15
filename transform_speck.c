#include "n2n.h"
#include "n2n_transforms.h"
#include "speck.h"
#include "pearson.h"
#include "random.h"
#include <time.h>

#define N2N_SPECK_TRANSFORM_VERSION   1
#define N2N_SPECK_NONCE_SIZE          16

typedef struct transop_speck {
    speck_context_t ctx;
    int             key_set;  /* 1 if key has been configured */
} transop_speck_t;

/* Modified setup_speck_key function using pearson_hash_256 */
int setup_speck_key(void *priv, const uint8_t *encrypt_key, size_t encrypt_key_len) {
    transop_speck_t *speck_priv = (transop_speck_t *)priv;
    uint8_t key_mat_buf[32] = {0};

    /* Clear out any old possibly longer key matter. */
    memset(&(speck_priv->ctx), 0, sizeof(speck_context_t));

    /* The input key always gets hashed to make a more unpredictable and more complete use of the key space */
    pearson_hash_256(key_mat_buf, encrypt_key, encrypt_key_len);

    /* Expand the key material to the context (= round keys) */
    speck_expand_key(key_mat_buf, &speck_priv->ctx);
    speck_priv->key_set = 1;

    traceEvent(TRACE_DEBUG, "Speck key setup completed\n");
    return 0;
}

int transop_deinit_speck(n2n_trans_op_t *arg) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    if (priv) {
#if defined (SPECK_ALIGNED_CTX)
        _mm_free(priv);
#else
        free(priv);
#endif
    }
    return 0;
}

/* Generate IV using fast PRNG (no syscall overhead). */
static void set_speck_iv(transop_speck_t *priv _unused_, uint8_t *ivec) {
    fast_rand_bytes(ivec, N2N_SPECK_NONCE_SIZE);
}

ssize_t transop_encode_speck(n2n_trans_op_t *arg,
                            uint8_t *outbuf,
                            size_t out_len,
                            const uint8_t *inbuf,
                            size_t in_len,
                            const uint8_t *peer_mac _unused_) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    uint8_t nonce[N2N_SPECK_NONCE_SIZE];
    size_t idx = 0;

    if (out_len < in_len + N2N_SPECK_NONCE_SIZE + 1) {
        return -1;
    }
    if (!priv || !arg->priv) {
        traceEvent(TRACE_ERROR, "Speck transform not initialized");
        return -1;
    }

    /* Version byte */
    outbuf[idx++] = N2N_SPECK_TRANSFORM_VERSION;

    /* Generate and encode the IV using cryptographically secure random source */
    set_speck_iv(priv, nonce);
    memcpy(outbuf + idx, nonce, N2N_SPECK_NONCE_SIZE);
    idx += N2N_SPECK_NONCE_SIZE;

    /* Encrypt data */
#ifdef SPECK_CTX_BYVAL
    speck_ctr(outbuf + idx, inbuf, in_len, nonce, priv->ctx);
#else
    speck_ctr(outbuf + idx, inbuf, in_len, nonce, &priv->ctx);
#endif
    idx += in_len;

    traceEvent(TRACE_DEBUG, "encode_speck: encrypted %u bytes.\n", in_len);
    return idx;
}

ssize_t transop_decode_speck(n2n_trans_op_t *arg,
                             uint8_t *outbuf,
                             size_t out_len,
                             const uint8_t *inbuf,
                             size_t in_len,
                             const uint8_t *peer_mac _unused_) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    uint8_t nonce[N2N_SPECK_NONCE_SIZE];
    size_t idx = 0;

    if (in_len < N2N_SPECK_NONCE_SIZE + 1) {
        return -1;
    }

    /* Check version */
    if (inbuf[idx++] != N2N_SPECK_TRANSFORM_VERSION) {
        if (traceLevel >= TRACE_INFO) {
            traceEvent(TRACE_INFO, "decode_speck unsupported Speck version %u.", inbuf[idx-1]);
        }
        return -1;
    }

    /* Extract nonce */
    memcpy(nonce, inbuf + idx, N2N_SPECK_NONCE_SIZE);
    idx += N2N_SPECK_NONCE_SIZE;

    /* Decrypt data */
#ifdef SPECK_CTX_BYVAL
    speck_ctr(outbuf, inbuf + idx, in_len - idx, nonce, priv->ctx);
#else
    speck_ctr(outbuf, inbuf + idx, in_len - idx, nonce, &priv->ctx);
#endif

    traceEvent(TRACE_DEBUG, "decode_speck: decrypted %u bytes.\n", in_len - idx);
    return in_len - idx;
}

n2n_tostat_t transop_tick_speck(n2n_trans_op_t *arg, time_t now) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    n2n_tostat_t status;
    memset(&status, 0, sizeof(status));
    status.can_tx = (priv && priv->key_set) ? 1 : 0;
    status.tx_spec.t = N2N_TRANSFORM_ID_SPECK;
    status.tx_spec.valid_from = 0;
    status.tx_spec.valid_until = 0xFFFFFFFF;
    return status;
}

int transop_addspec_speck(n2n_trans_op_t *arg, const n2n_cipherspec_t *cspec) {
    const char *key_data = (const char *)cspec->opaque;
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    size_t key_len;

    /* Skip "0_" prefix if present */
    if (strlen(key_data) > 2 && key_data[0] == '0' && key_data[1] == '_') {
        key_data += 2;
    }

    key_len = strlen(key_data);

    /* Use setup_speck_key with pearson_hash_256 */
    return setup_speck_key(priv, (const uint8_t *)key_data, key_len);
}

int transop_speck_init(n2n_trans_op_t *ttt) {
    transop_speck_t *priv;

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_SPECK;

    ttt->tick = transop_tick_speck;
    ttt->deinit = transop_deinit_speck;
    ttt->fwd = transop_encode_speck;
    ttt->rev = transop_decode_speck;
    ttt->addspec = transop_addspec_speck;

#if defined (SPECK_ALIGNED_CTX)
    priv = (transop_speck_t*) _mm_malloc(sizeof(transop_speck_t), SPECK_ALIGNED_CTX);
#else
    priv = (transop_speck_t*) calloc(1, sizeof(transop_speck_t));
#endif
    if (!priv) {
        traceEvent(TRACE_ERROR, "cannot allocate transop_speck_t memory");
        return -1;
    }
    ttt->priv = priv;

    return 0;
}
