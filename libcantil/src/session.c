/* clock_gettime, CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

/*
 * Transport security model — read before modifying this file.
 *
 * The wire protocol is Noise_XX_25519_ChaChaPoly_SHA256. Mutual
 * authentication, forward secrecy, and confidentiality come from the Noise
 * handshake, not from TLS or any PKI library. The session slot's X.509
 * certificate is metadata about the device's Noise static key, not a TLS
 * credential. Certificate validation is performed by libcantil against an
 * application-supplied trust policy (TOFU pin, fingerprint pin, or allowlisted
 * root). It is not delegated to a standard X.509 path-validation library, does
 * not involve a system trust store, and does not consult OCSP or
 * network-distributed CRLs. The certificate binds an identity to the static
 * key for client-side policy decisions; handshake security does not depend on
 * the certificate at all.
 *
 * Full design: docs/transport-and-pairing.md
 */

/*
 * Noise_XX_25519_ChaChaPoly_SHA256 initiator (client side).
 *
 * Mirrors the firmware's session.c responder exactly. Uses libsodium for
 * Curve25519 DH, ChaCha20-Poly1305 AEAD, SHA-256 hashing, and HMAC-SHA-256.
 *
 * Wire framing: big-endian 16-bit length prefix before every message,
 * matching the firmware's send_frame / recv_frame helpers.
 *
 * Handshake message sizes (no payload tokens):
 *   Message 1  →  e                  32 bytes
 *   Message 2  ←  e, ee, s, es       96 bytes  (32 + 48 + 16)
 *   Message 3  →  s, se              64 bytes  (48 + 16)
 *
 * Session keys after Split():
 *   k1 (initiator→responder) = client tx_key
 *   k2 (responder→initiator) = client rx_key
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sodium.h>
#include "internal.h"
#include "trust.h"
#include "cantil_cbor.h"

#define NOISE_TAG_LEN      16
#define MAX_FRAME_PAYLOAD  4096
#define DEFAULT_TIMEOUT_MS 5000
#define SESSION_CBOR_KEY_CHAIN 1

/* ── Nonce encoding ─────────────────────────────────────────────────────── */

static void nonce_encode(uint8_t out[12], uint64_t n)
{
    memset(out, 0, 4);
    for (int i = 0; i < 8; i++)
        out[4 + i] = (uint8_t)(n >> (8 * i));
}

/* ── Symmetric state ────────────────────────────────────────────────────── */

struct sym_state {
    uint8_t  h[32];
    uint8_t  ck[32];
    uint8_t  k[32];
    uint64_t n;
    int      has_key;
};

/* Exactly 32 bytes — no NUL terminator, intentional. */
static const uint8_t PROTOCOL_NAME[32] = {
    'N','o','i','s','e','_','X','X','_','2','5','5','1','9','_',
    'C','h','a','C','h','a','P','o','l','y','_','S','H','A','2','5','6'
};

static void sym_init(struct sym_state *s)
{
    memcpy(s->h,  PROTOCOL_NAME, 32);
    memcpy(s->ck, PROTOCOL_NAME, 32);
    sodium_memzero(s->k, 32);
    s->n = 0;
    s->has_key = 0;
}

/* h = SHA-256(h || data) */
static void mix_hash(struct sym_state *s, const uint8_t *data, size_t len)
{
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, s->h, 32);
    if (len > 0)
        crypto_hash_sha256_update(&st, data, len);
    crypto_hash_sha256_final(&st, s->h);
}

/* HMAC-SHA-256(key, data). data may be NULL when data_len == 0. */
static void hmac256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t out[32])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    if (data_len > 0 && data)
        crypto_auth_hmacsha256_update(&st, data, data_len);
    crypto_auth_hmacsha256_final(&st, out);
}

/*
 * HKDF-2 matching the Noise spec and firmware implementation:
 *   temp_key = HMAC(ck, ikm)
 *   out1     = HMAC(temp_key, 0x01)
 *   out2     = HMAC(temp_key, out1 || 0x02)
 */
static void hkdf2(uint8_t out1[32], uint8_t out2[32],
                  const uint8_t ck[32],
                  const uint8_t *ikm, size_t ikm_len)
{
    uint8_t temp[32];
    uint8_t buf[33];
    uint8_t b;

    hmac256(ck, 32, ikm, ikm_len, temp);

    b = 0x01;
    hmac256(temp, 32, &b, 1, out1);

    memcpy(buf, out1, 32);
    buf[32] = 0x02;
    hmac256(temp, 32, buf, 33, out2);

    sodium_memzero(temp, 32);
}

static void mix_key(struct sym_state *s, const uint8_t *ikm, size_t ikm_len)
{
    uint8_t new_ck[32], new_k[32];

    hkdf2(new_ck, new_k, s->ck, ikm, ikm_len);
    memcpy(s->ck, new_ck, 32);
    memcpy(s->k,  new_k,  32);
    s->n = 0;
    s->has_key = 1;

    sodium_memzero(new_ck, 32);
    sodium_memzero(new_k,  32);
}

static void sym_split(struct sym_state *s, uint8_t k1[32], uint8_t k2[32])
{
    hkdf2(k1, k2, s->ck, NULL, 0);
}

/* EncryptAndHash: when unkeyed, pass-through; when keyed, AEAD + MixHash. */
static int encrypt_and_hash(struct sym_state *s,
                             const uint8_t *pt, size_t pt_len,
                             uint8_t *ct, size_t ct_buf, size_t *ct_len)
{
    if (!s->has_key) {
        if (ct_buf < pt_len) return -ENOBUFS;
        if (pt_len > 0) memcpy(ct, pt, pt_len);
        *ct_len = pt_len;
        mix_hash(s, ct, pt_len);
        return 0;
    }

    uint8_t nonce_buf[12];
    nonce_encode(nonce_buf, s->n);
    unsigned long long clen;
    int ret = crypto_aead_chacha20poly1305_ietf_encrypt(
        ct, &clen,
        pt, pt_len,
        s->h, 32,
        NULL, nonce_buf, s->k);
    if (ret) return -EIO;

    *ct_len = (size_t)clen;
    s->n++;
    mix_hash(s, ct, *ct_len);
    return 0;
}

/* DecryptAndHash: when unkeyed, pass-through; when keyed, AEAD + MixHash. */
static int decrypt_and_hash(struct sym_state *s,
                             const uint8_t *ct, size_t ct_len,
                             uint8_t *pt, size_t pt_buf, size_t *pt_len)
{
    if (!s->has_key) {
        if (pt_buf < ct_len) return -ENOBUFS;
        if (ct_len > 0) memcpy(pt, ct, ct_len);
        *pt_len = ct_len;
        mix_hash(s, ct, ct_len);
        return 0;
    }

    uint8_t nonce_buf[12];
    nonce_encode(nonce_buf, s->n);
    unsigned long long mlen;
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
        pt, &mlen,
        NULL,
        ct, ct_len,
        s->h, 32,
        nonce_buf, s->k);
    if (ret) return -EBADMSG;

    *pt_len = (size_t)mlen;
    s->n++;
    mix_hash(s, ct, ct_len);
    return 0;
}

/* ── Transport framing ──────────────────────────────────────────────────── */

static int send_frame(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
    uint8_t hdr[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
    int ret = t->send(t, hdr, 2);
    if (ret) return ret;
    return t->send(t, buf, len);
}

/*
 * Read exactly len bytes, polling with short timeouts until a deadline.
 * Returns 0 on success, -ETIMEDOUT if the deadline passes, -errno on error.
 */
static int recv_exact(cantil_transport_t *t, uint8_t *buf, size_t len,
                      int timeout_ms)
{
    struct timespec start, cur;
    clock_gettime(CLOCK_MONOTONIC, &start);
    size_t got = 0;

    while (got < len) {
        clock_gettime(CLOCK_MONOTONIC, &cur);
        long elapsed = (cur.tv_sec  - start.tv_sec)  * 1000
                     + (cur.tv_nsec - start.tv_nsec) / 1000000L;
        if (elapsed >= timeout_ms)
            return -ETIMEDOUT;

        size_t n = 0;
        int ret = t->recv(t, buf + got, len - got, &n, 50);
        if (ret == -ETIMEDOUT) continue;
        if (ret) return ret;
        got += n;
    }
    return 0;
}

static int recv_frame(cantil_transport_t *t, uint8_t *buf, size_t max_len,
                      size_t *recv_len, int timeout_ms)
{
    uint8_t hdr[2];
    int ret = recv_exact(t, hdr, 2, timeout_ms);
    if (ret) return ret;

    size_t frame_len = ((size_t)hdr[0] << 8) | hdr[1];
    if (frame_len > max_len) return -ENOBUFS;

    ret = recv_exact(t, buf, frame_len, timeout_ms);
    if (!ret) *recv_len = frame_len;
    return ret;
}

/* ── Key generation API ─────────────────────────────────────────────────── */

cantil_err_t cantil_keygen(cantil_key_t *out_priv, cantil_key_t *out_pub)
{
    if (!out_priv || !out_pub)
        return CANTIL_ERR_INVALID_ARG;
    randombytes_buf(out_priv->bytes, 32);
    crypto_scalarmult_curve25519_base(out_pub->bytes, out_priv->bytes);
    return CANTIL_OK;
}

cantil_err_t cantil_pubkey_from_privkey(const cantil_key_t *priv,
                                       cantil_key_t       *out_pub)
{
    if (!priv || !out_pub)
        return CANTIL_ERR_INVALID_ARG;
    crypto_scalarmult_curve25519_base(out_pub->bytes, priv->bytes);
    return CANTIL_OK;
}

/* ── Device identity chain (msg2 payload, T-04) ─────────────────────────── */

/*
 * Parse the CBOR { 1: [ <leaf_der>, ... ] } the device sent as its encrypted
 * msg2 payload and copy the leaf-first chain into the session. Best-effort: an
 * empty or unrecognized payload simply leaves the chain empty — the handshake
 * itself is already authenticated by the Noise AEAD, so a malformed identity
 * payload is a policy concern (Phase C), not a handshake failure here.
 */
static void parse_device_chain(cantil_session_t *s,
                               const uint8_t *pt, size_t pt_len)
{
    s->device_chain_total = 0;
    s->device_cert_count  = 0;
    if (pt_len == 0)
        return;

    size_t  off = 0;
    uint8_t major;
    uint64_t val;

    if (cantil_cbor_read_head(pt, pt_len, &off, &major, &val) != 0)
        return;
    if (major != CANTIL_CBOR_MT_MAP)
        return;

    size_t pairs = (size_t)val;
    for (size_t p = 0; p < pairs; p++) {
        uint32_t key;
        if (cantil_cbor_read_uint32(pt, pt_len, &off, &key) != 0)
            return;
        if (key != SESSION_CBOR_KEY_CHAIN)
            return;   /* device only emits the chain key */

        uint8_t  amaj;
        uint64_t acount;
        if (cantil_cbor_read_head(pt, pt_len, &off, &amaj, &acount) != 0)
            return;
        if (amaj != CANTIL_CBOR_MT_ARRAY)
            return;

        for (size_t i = 0; i < (size_t)acount; i++) {
            const uint8_t *cert;
            size_t cl;
            if (cantil_cbor_read_bstr(pt, pt_len, &off, &cert, &cl) != 0)
                return;
            if (s->device_cert_count >= CANTIL_DEVICE_CHAIN_CERTS)
                return;
            if (s->device_chain_total + cl > CANTIL_DEVICE_CHAIN_MAX)
                return;
            memcpy(s->device_chain + s->device_chain_total, cert, cl);
            s->device_cert_off[s->device_cert_count] = s->device_chain_total;
            s->device_cert_len[s->device_cert_count] = cl;
            s->device_cert_count++;
            s->device_chain_total += cl;
        }
        return;   /* chain consumed */
    }
}

int cantil_session_device_cert(const cantil_session_t *s, size_t idx,
                               const uint8_t **der, size_t *len)
{
    if (!s || !der || !len)
        return -EINVAL;
    if (idx >= s->device_cert_count)
        return -ENOENT;
    *der = s->device_chain + s->device_cert_off[idx];
    *len = s->device_cert_len[idx];
    return 0;
}

size_t cantil_session_device_cert_count(const cantil_session_t *s)
{
    return s ? s->device_cert_count : 0;
}

/* ── Noise_XX initiator handshake ───────────────────────────────────────── */

cantil_session_t *cantil_session_open(cantil_transport_t           *t,
                                      const cantil_key_t           *client_priv,
                                      const cantil_trust_policy_t  *policy,
                                      const cantil_client_cert_t   *client_cert,
                                      uint32_t                      timeout_ms)
{
    if (!t || !client_priv)
        return NULL;

    int tms = timeout_ms ? (int)timeout_ms : DEFAULT_TIMEOUT_MS;

    cantil_session_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->transport = t;

    uint8_t eI_priv[32], eI_pub[32];
    struct sym_state sym;
    static const uint8_t empty[1];
    int ret;

    /* Derive our static public key from the provided private key. */
    crypto_scalarmult_curve25519_base(s->client_s_pub, client_priv->bytes);

    /* Generate an ephemeral keypair. */
    randombytes_buf(eI_priv, 32);
    crypto_scalarmult_curve25519_base(eI_pub, eI_priv);

    sym_init(&sym);

    /* MixHash(prologue = "") */
    mix_hash(&sym, empty, 0);

    /* ── Message 1: → e ── */

    mix_hash(&sym, eI_pub, 32);         /* MixHash(eI_pub) */
    mix_hash(&sym, empty, 0);           /* MixHash("") — empty payload */

    ret = send_frame(t, eI_pub, 32);
    if (ret) goto fail;

    /* ── Message 2: ← e, ee, s, es ── */

    /*
     * Layout: eR_pub(32) | EncryptAndHash(sR_pub)(48) |
     *         EncryptAndHash(chain_cbor)(chain_cbor + 16)
     * Minimum 96 bytes (empty chain); larger when the device sends its
     * identity cert chain (T-04).
     */
    uint8_t msg2[MAX_FRAME_PAYLOAD];
    size_t  msg2_len;

    ret = recv_frame(t, msg2, sizeof(msg2), &msg2_len, tms);
    if (ret || msg2_len < 96) {
        ret = ret ? ret : -EPROTO;
        goto fail;
    }

    uint8_t eR_pub[32];
    memcpy(eR_pub, msg2, 32);
    mix_hash(&sym, eR_pub, 32);         /* MixHash(eR_pub) */

    /* ee token: DH(eI_priv, eR_pub), MixKey(ee). */
    {
        uint8_t ee[32];
        if (crypto_scalarmult_curve25519(ee, eI_priv, eR_pub) != 0) {
            ret = -EIO;
            goto fail;
        }
        mix_key(&sym, ee, 32);
        sodium_memzero(ee, 32);
    }

    /* s token: DecryptAndHash(enc_sR_pub) → sR_pub. Key active now. */
    {
        size_t dec_len;
        ret = decrypt_and_hash(&sym, msg2 + 32, 48,
                               s->device_s_pub, 32, &dec_len);
        if (ret) goto fail;
    }

    /* es token: DH(eI_priv, sR_pub), MixKey(es). */
    {
        uint8_t es[32];
        if (crypto_scalarmult_curve25519(es, eI_priv, s->device_s_pub) != 0) {
            ret = -EIO;
            goto fail;
        }
        mix_key(&sym, es, 32);
        sodium_memzero(es, 32);
    }

    /* Identity-chain payload: decrypt the trailing CBOR (msg2_len - 80
     * ciphertext bytes, >= 16) and parse the device cert chain. */
    {
        uint8_t chain_pt[MAX_FRAME_PAYLOAD];
        size_t  chain_len;
        ret = decrypt_and_hash(&sym, msg2 + 80, msg2_len - 80,
                               chain_pt, sizeof(chain_pt), &chain_len);
        if (ret) goto fail;
        parse_device_chain(s, chain_pt, chain_len);
    }

    /* Trust policy: validate the device identity chain per caller's policy. */
    {
        cantil_err_t terr = cantil_trust_check_policy(policy, s);
        if (terr != CANTIL_OK) {
            ret = (int)terr;
            goto fail;
        }
    }

    /* ── Message 3: → s, se ── */

    /*
     * Layout: EncryptAndHash(sI_pub)(48) | EncryptAndHash(client_cbor)(M+16)
     * When client_cert is NULL: client_cbor is empty CBOR map {} (1 byte),
     * giving msg3 = 65 bytes. When client_cert is provided (Method 4),
     * client_cbor is { 1: [<leaf_der>, <intermediate_der>, ...] }.
     */

    /* Build the client CBOR payload. */
    uint8_t client_cbor[3000];   /* generous for cert chain */
    size_t  client_cbor_len = 0;

    if (client_cert && client_cert->cert_der && client_cert->cert_len > 0) {
        /* Encode { 1: [leaf, <intermediates>...] } */
        size_t off = 0;

        /* Count total certs to include: leaf + any from chain_der. */
        size_t ncerts = 1;
        if (client_cert->chain_der && client_cert->chain_len > 0) {
            /* Walk the chain blob to count certs (each is an ASN.1 SEQUENCE). */
            size_t co = 0;
            while (co + 2 < client_cert->chain_len) {
                /* Minimal ASN.1 length parse — just skip to count. */
                const uint8_t *p = client_cert->chain_der + co;
                if (p[0] != 0x30) break;   /* not SEQUENCE */
                size_t hlen, inner;
                if (p[1] & 0x80) {
                    size_t nb = p[1] & 0x7F;
                    if (nb > 3 || co + 2 + nb > client_cert->chain_len) break;
                    inner = 0;
                    for (size_t b = 0; b < nb; b++)
                        inner = (inner << 8) | p[2 + b];
                    hlen = 2 + nb;
                } else {
                    inner = p[1];
                    hlen = 2;
                }
                if (co + hlen + inner > client_cert->chain_len) break;
                ncerts++;
                co += hlen + inner;
            }
        }

        /* Encode map { 1: array[ncerts] } */
        if (cantil_cbor_emit_map(client_cbor, sizeof(client_cbor), &off, 1) ||
            cantil_cbor_emit_uint(client_cbor, sizeof(client_cbor), &off,
                                  SESSION_CBOR_KEY_CHAIN) ||
            cantil_cbor_emit_array(client_cbor, sizeof(client_cbor), &off,
                                   (uint32_t)ncerts)) {
            ret = -EMSGSIZE;
            goto fail;
        }

        /* Leaf cert. */
        if (cantil_cbor_emit_bstr(client_cbor, sizeof(client_cbor), &off,
                                  client_cert->cert_der, client_cert->cert_len)) {
            ret = -EMSGSIZE;
            goto fail;
        }

        /* Intermediate certs from chain_der (split on ASN.1 SEQUENCE). */
        if (client_cert->chain_der && client_cert->chain_len > 0) {
            size_t co = 0;
            while (co + 2 < client_cert->chain_len) {
                const uint8_t *p = client_cert->chain_der + co;
                if (p[0] != 0x30) break;
                size_t hlen, inner;
                if (p[1] & 0x80) {
                    size_t nb = p[1] & 0x7F;
                    if (nb > 3 || co + 2 + nb > client_cert->chain_len) break;
                    inner = 0;
                    for (size_t b = 0; b < nb; b++)
                        inner = (inner << 8) | p[2 + b];
                    hlen = 2 + nb;
                } else {
                    inner = p[1];
                    hlen = 2;
                }
                if (co + hlen + inner > client_cert->chain_len) break;
                if (cantil_cbor_emit_bstr(client_cbor, sizeof(client_cbor),
                                          &off, p, hlen + inner)) {
                    ret = -EMSGSIZE;
                    goto fail;
                }
                co += hlen + inner;
            }
        }

        client_cbor_len = off;
    } else {
        /* No client cert: send empty CBOR map {}. */
        client_cbor[0] = 0xA0;
        client_cbor_len = 1;
    }

    /* msg3 buffer: 48 bytes (enc_sI_pub) + client_cbor_len + 16 (tag). */
    uint8_t *msg3 = malloc(48 + client_cbor_len + 16 + 4 /* margin */);
    if (!msg3) { ret = -ENOMEM; goto fail; }
    size_t  msg3_pos = 0, enc_len;

    /* s token: EncryptAndHash(sI_pub). */
    ret = encrypt_and_hash(&sym, s->client_s_pub, 32,
                           msg3, 48, &enc_len);
    if (ret) { free(msg3); goto fail; }
    msg3_pos += enc_len;  /* enc_len == 48 */

    /* se token: DH(sI_priv, eR_pub), MixKey(se). */
    {
        uint8_t se[32];
        if (crypto_scalarmult_curve25519(se, client_priv->bytes, eR_pub) != 0) {
            ret = -EIO;
            free(msg3);
            goto fail;
        }
        mix_key(&sym, se, 32);
        sodium_memzero(se, 32);
    }

    /* Client identity payload: EncryptAndHash(client_cbor). */
    ret = encrypt_and_hash(&sym, client_cbor, client_cbor_len,
                           msg3 + msg3_pos,
                           client_cbor_len + NOISE_TAG_LEN, &enc_len);
    if (ret) { free(msg3); goto fail; }
    msg3_pos += enc_len;

    ret = send_frame(t, msg3, msg3_pos);
    free(msg3);
    if (ret) goto fail;

    /* ── Handshake complete: Split() ── */

    {
        uint8_t k1[32], k2[32];
        sym_split(&sym, k1, k2);
        memcpy(s->tx_key, k1, 32);   /* k1: initiator→responder */
        memcpy(s->rx_key, k2, 32);   /* k2: responder→initiator */
        sodium_memzero(k1, 32);
        sodium_memzero(k2, 32);
    }

    s->tx_nonce   = 0;
    s->rx_nonce   = 0;
    s->established = 1;

    sodium_memzero(eI_priv, 32);
    sodium_memzero(&sym, sizeof(sym));
    return s;

fail:
    sodium_memzero(eI_priv, 32);
    sodium_memzero(&sym, sizeof(sym));
    sodium_memzero(s, sizeof(*s));
    free(s);
    return NULL;
}

cantil_err_t cantil_session_get_device_pubkey(const cantil_session_t *s,
                                             cantil_key_t           *out_pub)
{
    if (!s || !s->established || !out_pub)
        return CANTIL_ERR_INVALID_ARG;
    memcpy(out_pub->bytes, s->device_s_pub, 32);
    return CANTIL_OK;
}

cantil_err_t cantil_session_verify_policy(const cantil_session_t *s,
                                          const cantil_trust_policy_t *policy)
{
    if (!s || !s->established || !policy)
        return CANTIL_ERR_INVALID_ARG;
    return cantil_trust_check_policy(policy, s);
}

void cantil_session_close(cantil_session_t *s)
{
    if (!s) return;
    sodium_memzero(s, sizeof(*s));
    free(s);
}

/* ── Post-handshake encrypted I/O ───────────────────────────────────────── */

int cantil_session_send(cantil_session_t *s, const uint8_t *buf, size_t len)
{
    if (!s || !s->established) return -EINVAL;
    if (len > MAX_FRAME_PAYLOAD) return -EMSGSIZE;

    static uint8_t ct_buf[MAX_FRAME_PAYLOAD + NOISE_TAG_LEN];
    uint8_t nonce_buf[12];
    unsigned long long ct_len;

    nonce_encode(nonce_buf, s->tx_nonce);
    int ret = crypto_aead_chacha20poly1305_ietf_encrypt(
        ct_buf, &ct_len,
        buf, len,
        NULL, 0,                 /* AD = empty, matching firmware session.c */
        NULL, nonce_buf, s->tx_key);
    if (ret) return -EIO;

    s->tx_nonce++;
    return send_frame(s->transport, ct_buf, (size_t)ct_len);
}

int cantil_session_recv_to(cantil_session_t *s, uint8_t *buf, size_t max_len,
                          size_t *received, int timeout_ms)
{
    if (!s || !s->established || !buf || !received) return -EINVAL;
    if (max_len < NOISE_TAG_LEN) return -ENOBUFS;

    static uint8_t ct_buf[MAX_FRAME_PAYLOAD + NOISE_TAG_LEN];
    size_t ct_len;

    int ret = recv_frame(s->transport, ct_buf, sizeof(ct_buf),
                         &ct_len, timeout_ms > 0 ? timeout_ms : DEFAULT_TIMEOUT_MS);
    if (ret) return ret;
    if (ct_len < NOISE_TAG_LEN) return -EPROTO;

    uint8_t nonce_buf[12];
    nonce_encode(nonce_buf, s->rx_nonce);
    unsigned long long pt_len;
    ret = crypto_aead_chacha20poly1305_ietf_decrypt(
        buf, &pt_len,
        NULL,
        ct_buf, ct_len,
        NULL, 0,
        nonce_buf, s->rx_key);
    if (ret) return -EBADMSG;

    s->rx_nonce++;
    *received = (size_t)pt_len;
    return 0;
}

int cantil_session_recv(cantil_session_t *s, uint8_t *buf, size_t max_len,
                       size_t *received)
{
    return cantil_session_recv_to(s, buf, max_len, received, DEFAULT_TIMEOUT_MS);
}

const char *cantil_strerror(cantil_err_t err)
{
    switch (err) {
    case CANTIL_OK:                return "OK";
    case CANTIL_ERR_IO:            return "I/O error";
    case CANTIL_ERR_NOISE:         return "Noise handshake or decryption failure";
    case CANTIL_ERR_PROTOCOL:      return "Unexpected response from device";
    case CANTIL_ERR_DEVICE_LOCKED: return "Device is locked";
    case CANTIL_ERR_TIMEOUT:       return "Timeout";
    case CANTIL_ERR_NO_MEMORY:     return "Out of memory";
    case CANTIL_ERR_INVALID_ARG:   return "Invalid argument";
    case CANTIL_ERR_NOT_SUPPORTED: return "Not supported by this firmware";
    case CANTIL_ERR_CERT_INVALID:  return "Device rejected certificate";
    case CANTIL_ERR_KEY_FULL:      return "No free key slots on device";
    case CANTIL_ERR_KEY_NOT_FOUND: return "Key slot not found";
    case CANTIL_ERR_CERT_NOT_FOUND:return "Certificate not found";
    case CANTIL_ERR_BOND_FULL:     return "BLE bond store full";
    case CANTIL_ERR_ALREADY_REVOKED:  return "Certificate already revoked";
    case CANTIL_ERR_TRUST:            return "Trust policy check failed";
    case CANTIL_ERR_AUTH:             return "Passkey wrong or tap-confirm denied";
    case CANTIL_ERR_PASSKEY_REQUIRED: return "Device requires passkey entry (Method 3)";
    case CANTIL_ERR_FW_UPDATE_BUSY:   return "Firmware update already in progress on device";
    case CANTIL_ERR_FW_UPDATE_FLASH:  return "Device flash erase/write error during firmware update";
    default:                          return "Unknown error";
    }
}
