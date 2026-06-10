/*
 * CA-side commands: SIGN_CSR, GET_CA_CERT/CHAIN/SERIAL/CSR, PUSH_CA_CERT.
 *
 * All commands go through cantil_do_request (CBOR `{cmd,seq,data?}` request,
 * `{err,seq,data?}` response). Slot-0-targeted convenience aliases; the
 * generic per-slot variants live in [key_ops.c] (added later in the CA push).
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../include/cantil.h"
#include "internal.h"
#include "cantil_cbor.h"

/* Per-call scratch buffer for response decoding. Sized for cert DER + frame
 * overhead. mbedtls writes typical P-256 end-entity certs in ~350 B; CA certs
 * with longer DN run ~450 B; budget 4 KB to leave headroom. */
#define CA_SCRATCH_SZ  (4096 + 64)

/* Helper: duplicate response bytes into caller-owned heap buffer. */
static cantil_err_t dup_resp(const uint8_t *src, size_t src_len,
                             uint8_t **out, size_t *out_len)
{
    if (!src || src_len == 0) return CANTIL_ERR_PROTOCOL;
    uint8_t *buf = malloc(src_len);
    if (!buf) return CANTIL_ERR_NO_MEMORY;
    memcpy(buf, src, src_len);
    *out = buf;
    *out_len = src_len;
    return CANTIL_OK;
}

cantil_err_t cantil_sign_csr(cantil_session_t *s,
                             const uint8_t *csr, size_t csr_len,
                             uint8_t **out_cert, size_t *out_len)
{
    if (!s || !csr || csr_len == 0 || !out_cert || !out_len)
        return CANTIL_ERR_INVALID_ARG;

    *out_cert = NULL;
    *out_len = 0;

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL;
    size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_SIGN_CSR, 0x01,
                                        csr, csr_len,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    return dup_resp(d, dlen, out_cert, out_len);
}

cantil_err_t cantil_get_ca_serial(cantil_session_t *s,
                                  uint8_t *out, size_t out_size,
                                  size_t *out_len)
{
    if (!s || !out || out_size == 0 || !out_len) return CANTIL_ERR_INVALID_ARG;
    *out_len = 0;

    uint8_t scratch[128];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_CA_SERIAL, 0x01,
                                        NULL, 0,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen == 0) return CANTIL_ERR_PROTOCOL;
    if (dlen > out_size) return CANTIL_ERR_NO_MEMORY;
    memcpy(out, d, dlen);
    *out_len = dlen;
    return CANTIL_OK;
}

cantil_err_t cantil_get_cert_count(cantil_session_t *s, uint32_t *out_count)
{
    if (!s || !out_count) return CANTIL_ERR_INVALID_ARG;

    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_CERT_COUNT, 0x01,
                                        NULL, 0,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen != 4) return CANTIL_ERR_PROTOCOL;
    *out_count = ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) |
                 ((uint32_t)d[2] << 8) | (uint32_t)d[3];
    return CANTIL_OK;
}

cantil_err_t cantil_list_certs(cantil_session_t *s,
                               int (*cb)(const cantil_cert_info_t *, void *),
                               void *userdata)
{
    if (!s || !cb) return CANTIL_ERR_INVALID_ARG;

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_LIST_CERTS, 0x01,
                                        NULL, 0,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen == 0) return CANTIL_ERR_PROTOCOL;

    /* Decode payload: array of map(4) with keys "f","i","n","s". */
    size_t off = 0;
    uint8_t mt; uint64_t v;
    if (cantil_cbor_read_head(d, dlen, &off, &mt, &v) != 0)
        return CANTIL_ERR_PROTOCOL;
    if (mt != CANTIL_CBOR_MT_ARRAY) return CANTIL_ERR_PROTOCOL;
    uint32_t count = (uint32_t)v;

    for (uint32_t i = 0; i < count; i++) {
        if (cantil_cbor_read_head(d, dlen, &off, &mt, &v) != 0 ||
            mt != CANTIL_CBOR_MT_MAP || v != 4)
            return CANTIL_ERR_PROTOCOL;

        cantil_cert_info_t info = {0};
        info.key_slot = UINT32_MAX;

        for (int k = 0; k < 4; k++) {
            const uint8_t *key; size_t klen;
            if (cantil_cbor_read_tstr(d, dlen, &off, &key, &klen) != 0 ||
                klen != 1)
                return CANTIL_ERR_PROTOCOL;
            char kc = (char)key[0];

            if (kc == 's') {
                const uint8_t *p; size_t pl;
                if (cantil_cbor_read_bstr(d, dlen, &off, &p, &pl) != 0)
                    return CANTIL_ERR_PROTOCOL;
                if (pl > sizeof(info.serial)) return CANTIL_ERR_PROTOCOL;
                memcpy(info.serial, p, pl);
                info.serial_len = pl;
            } else if (kc == 'n') {
                const uint8_t *p; size_t pl;
                if (cantil_cbor_read_tstr(d, dlen, &off, &p, &pl) != 0)
                    return CANTIL_ERR_PROTOCOL;
                size_t copy = pl < sizeof(info.subject) - 1 ?
                              pl : sizeof(info.subject) - 1;
                memcpy(info.subject, p, copy);
                info.subject[copy] = '\0';
            } else if (kc == 'i') {
                uint32_t u;
                if (cantil_cbor_read_uint32(d, dlen, &off, &u) != 0)
                    return CANTIL_ERR_PROTOCOL;
                info.key_slot = u;
            } else if (kc == 'f') {
                uint32_t u;
                if (cantil_cbor_read_uint32(d, dlen, &off, &u) != 0)
                    return CANTIL_ERR_PROTOCOL;
                info.revoked = (u & 0x01) ? 1 : 0;
            } else {
                return CANTIL_ERR_PROTOCOL;
            }
        }

        int stop = cb(&info, userdata);
        if (stop) return (cantil_err_t)stop;
    }
    return CANTIL_OK;
}

cantil_err_t cantil_gen_key(cantil_session_t  *s,
                            cantil_key_type_t  type,
                            uint32_t          *out_slot_id)
{
    if (!s || !out_slot_id) return CANTIL_ERR_INVALID_ARG;
    *out_slot_id = 0;

    uint8_t req[1] = { (uint8_t)type };
    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GEN_KEY, 0x01,
                                        req, sizeof(req),
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen != 4) return CANTIL_ERR_PROTOCOL;
    *out_slot_id = ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) |
                   ((uint32_t)d[2] << 8) | (uint32_t)d[3];
    return CANTIL_OK;
}

cantil_err_t cantil_protect_slot(cantil_session_t *s, uint32_t slot_id,
                                 uint8_t protect_issued_certs)
{
    if (!s) return CANTIL_ERR_INVALID_ARG;

    uint8_t req[5] = {
        (uint8_t)(slot_id >> 24), (uint8_t)(slot_id >> 16),
        (uint8_t)(slot_id >>  8), (uint8_t)(slot_id),
        protect_issued_certs ? 1 : 0
    };
    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request_to(s, CMD_PROTECT_SLOT, 0x01,
                                req, sizeof(req),
                                scratch, sizeof(scratch),
                                &d, &dlen, CANTIL_TAP_CONFIRM_TIMEOUT_MS);
}

cantil_err_t cantil_unprotect_slot(cantil_session_t *s, uint32_t slot_id)
{
    if (!s) return CANTIL_ERR_INVALID_ARG;

    uint8_t req[4] = {
        (uint8_t)(slot_id >> 24), (uint8_t)(slot_id >> 16),
        (uint8_t)(slot_id >>  8), (uint8_t)(slot_id)
    };
    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request_to(s, CMD_UNPROTECT_SLOT, 0x01,
                                req, sizeof(req),
                                scratch, sizeof(scratch),
                                &d, &dlen, CANTIL_TAP_CONFIRM_TIMEOUT_MS);
}

cantil_err_t cantil_gen_key_csr(cantil_session_t *s, uint32_t slot_id,
                                const char *subject_dn)
{
    if (!s || !subject_dn || subject_dn[0] == '\0')
        return CANTIL_ERR_INVALID_ARG;

    size_t dn_len = strlen(subject_dn);
    if (dn_len > 240) return CANTIL_ERR_INVALID_ARG;

    uint8_t req[4 + 256];
    req[0] = (uint8_t)(slot_id >> 24);
    req[1] = (uint8_t)(slot_id >> 16);
    req[2] = (uint8_t)(slot_id >>  8);
    req[3] = (uint8_t)(slot_id);
    memcpy(&req[4], subject_dn, dn_len);

    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request(s, CMD_GEN_KEY_CSR, 0x01,
                             req, 4 + dn_len,
                             scratch, sizeof(scratch),
                             &d, &dlen);
}

cantil_err_t cantil_get_key_csr(cantil_session_t *s, uint32_t slot_id,
                                uint8_t **out, size_t *out_len)
{
    if (!s || !out || !out_len) return CANTIL_ERR_INVALID_ARG;
    *out = NULL; *out_len = 0;

    uint8_t req[4] = {
        (uint8_t)(slot_id >> 24), (uint8_t)(slot_id >> 16),
        (uint8_t)(slot_id >>  8), (uint8_t)(slot_id)
    };
    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_KEY_CSR, 0x01,
                                        req, sizeof(req),
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    return dup_resp(d, dlen, out, out_len);
}

cantil_err_t cantil_push_key_cert(cantil_session_t *s,
                                  uint32_t slot_id,
                                  const uint8_t *cert, size_t cert_len,
                                  const uint8_t *chain, size_t chain_len)
{
    if (!s || !cert || cert_len == 0 || cert_len > 0xFFFFu)
        return CANTIL_ERR_INVALID_ARG;
    if (chain_len > 0 && !chain) return CANTIL_ERR_INVALID_ARG;
    if (6 + cert_len + chain_len > 2000) return CANTIL_ERR_INVALID_ARG;

    static uint8_t req[8 + 2048];
    req[0] = (uint8_t)(slot_id >> 24);
    req[1] = (uint8_t)(slot_id >> 16);
    req[2] = (uint8_t)(slot_id >>  8);
    req[3] = (uint8_t)(slot_id);
    req[4] = (uint8_t)(cert_len >> 8);
    req[5] = (uint8_t)(cert_len & 0xFF);
    memcpy(&req[6], cert, cert_len);
    if (chain_len) memcpy(&req[6 + cert_len], chain, chain_len);

    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request(s, CMD_PUSH_KEY_CERT, 0x01,
                             req, 6 + cert_len + chain_len,
                             scratch, sizeof(scratch),
                             &d, &dlen);
}

/* Wire format for PUSH_KEY_X509 payload (after the 4-byte BE slot id):
 *
 *   [validity_days BE u16]
 *   [is_ca u8]                      0/1
 *   [path_len u8]                   0xFF == unconstrained
 *   [key_usage BE u16]              CANTIL_KU_* bitmask (RFC 5280 numbering)
 *   [len u8][CN bytes]              required, len > 0
 *   [len u8][O  bytes]              len may be 0
 *   [len u8][OU bytes]
 *   [len u8][C  bytes]              len must be 0 or 2
 *   [len u8][ST bytes]
 *   [len u8][L  bytes]
 *
 * Matches `x509_parse` in firmware/src/ca/ca.c. The struct's six C-string
 * fields (cn..l) cap at 64 bytes; CN/validity_days are mandatory. We accept
 * NULL or "" interchangeably for the optional fields.
 */
static size_t x509_str_len(const char *s)
{
    return s ? strlen(s) : 0;
}

static int x509_emit_str(uint8_t *buf, size_t cap, size_t *off, const char *s)
{
    size_t n = x509_str_len(s);

    if (n > 64) return -1;
    if (*off + 1 + n > cap) return -1;
    buf[(*off)++] = (uint8_t)n;
    if (n) memcpy(buf + *off, s, n);
    *off += n;
    return 0;
}

cantil_err_t cantil_push_key_x509(cantil_session_t *s,
                                  uint32_t slot_id,
                                  const cantil_x509_data_t *x509)
{
    if (!s || !x509) return CANTIL_ERR_INVALID_ARG;
    if (x509->validity_days == 0) return CANTIL_ERR_INVALID_ARG;

    size_t cn_len = x509_str_len(x509->cn);
    size_t c_len  = x509_str_len(x509->c);

    if (cn_len == 0 || cn_len > 64) return CANTIL_ERR_INVALID_ARG;
    if (c_len != 0 && c_len != 2)   return CANTIL_ERR_INVALID_ARG;

    /* Header (6) + six length-prefixed strings, each at most 1 + 64. The
     * firmware caps the whole blob at X509_DATA_MAX (512); this matches. */
    uint8_t req[4 + 6 + 6 * (1 + 64)];
    size_t  off = 0;

    req[off++] = (uint8_t)(slot_id >> 24);
    req[off++] = (uint8_t)(slot_id >> 16);
    req[off++] = (uint8_t)(slot_id >>  8);
    req[off++] = (uint8_t)(slot_id);

    req[off++] = (uint8_t)(x509->validity_days >> 8);
    req[off++] = (uint8_t)(x509->validity_days & 0xFF);
    req[off++] = x509->is_ca ? 1 : 0;
    req[off++] = (x509->path_len < 0) ? 0xFF : (uint8_t)x509->path_len;
    req[off++] = (uint8_t)(x509->key_usage >> 8);
    req[off++] = (uint8_t)(x509->key_usage & 0xFF);

    if (x509_emit_str(req, sizeof(req), &off, x509->cn) ||
        x509_emit_str(req, sizeof(req), &off, x509->o)  ||
        x509_emit_str(req, sizeof(req), &off, x509->ou) ||
        x509_emit_str(req, sizeof(req), &off, x509->c)  ||
        x509_emit_str(req, sizeof(req), &off, x509->st) ||
        x509_emit_str(req, sizeof(req), &off, x509->l)) {
        return CANTIL_ERR_INVALID_ARG;
    }

    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request(s, CMD_PUSH_KEY_X509, 0x01,
                             req, off,
                             scratch, sizeof(scratch),
                             &d, &dlen);
}

cantil_err_t cantil_sign_csr_slot(cantil_session_t *s,
                                  uint32_t issuer_slot,
                                  const uint8_t *csr, size_t csr_len,
                                  uint8_t **out_cert, size_t *out_len)
{
    if (!s || !csr || csr_len == 0 || !out_cert || !out_len)
        return CANTIL_ERR_INVALID_ARG;
    *out_cert = NULL; *out_len = 0;

    static uint8_t req[4 + 1024];
    if (4 + csr_len > sizeof(req)) return CANTIL_ERR_INVALID_ARG;
    req[0] = (uint8_t)(issuer_slot >> 24);
    req[1] = (uint8_t)(issuer_slot >> 16);
    req[2] = (uint8_t)(issuer_slot >>  8);
    req[3] = (uint8_t)(issuer_slot);
    memcpy(&req[4], csr, csr_len);

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_SIGN_CSR_SLOT, 0x01,
                                        req, 4 + csr_len,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    return dup_resp(d, dlen, out_cert, out_len);
}

cantil_err_t cantil_sign_key_slot(cantil_session_t *s,
                                  uint32_t issuer_slot,
                                  uint32_t subject_slot)
{
    if (!s) return CANTIL_ERR_INVALID_ARG;

    uint8_t req[8] = {
        (uint8_t)(issuer_slot >> 24), (uint8_t)(issuer_slot >> 16),
        (uint8_t)(issuer_slot >>  8), (uint8_t)(issuer_slot),
        (uint8_t)(subject_slot >> 24), (uint8_t)(subject_slot >> 16),
        (uint8_t)(subject_slot >>  8), (uint8_t)(subject_slot),
    };
    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request(s, CMD_SIGN_KEY_SLOT, 0x01,
                             req, sizeof(req),
                             scratch, sizeof(scratch),
                             &d, &dlen);
}

cantil_err_t cantil_delete_key(cantil_session_t *s, uint32_t slot_id)
{
    if (!s) return CANTIL_ERR_INVALID_ARG;

    uint8_t req[4] = {
        (uint8_t)(slot_id >> 24), (uint8_t)(slot_id >> 16),
        (uint8_t)(slot_id >>  8), (uint8_t)(slot_id)
    };
    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request(s, CMD_DELETE_KEY, 0x01,
                             req, sizeof(req),
                             scratch, sizeof(scratch),
                             &d, &dlen);
}

cantil_err_t cantil_list_keys(cantil_session_t *s,
                              int (*cb)(const cantil_key_slot_info_t *, void *),
                              void *userdata)
{
    if (!s || !cb) return CANTIL_ERR_INVALID_ARG;

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_LIST_KEYS, 0x01,
                                        NULL, 0,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen == 0) return CANTIL_ERR_PROTOCOL;

    size_t off = 0;
    uint8_t mt; uint64_t v;
    if (cantil_cbor_read_head(d, dlen, &off, &mt, &v) != 0)
        return CANTIL_ERR_PROTOCOL;
    if (mt != CANTIL_CBOR_MT_ARRAY) return CANTIL_ERR_PROTOCOL;
    uint32_t count = (uint32_t)v;

    for (uint32_t i = 0; i < count; i++) {
        if (cantil_cbor_read_head(d, dlen, &off, &mt, &v) != 0 ||
            mt != CANTIL_CBOR_MT_MAP || v != 5)
            return CANTIL_ERR_PROTOCOL;

        cantil_key_slot_info_t info = {0};

        for (int k = 0; k < 5; k++) {
            const uint8_t *key; size_t klen;
            if (cantil_cbor_read_tstr(d, dlen, &off, &key, &klen) != 0 ||
                klen != 1)
                return CANTIL_ERR_PROTOCOL;
            char kc = (char)key[0];
            uint32_t u;
            if (cantil_cbor_read_uint32(d, dlen, &off, &u) != 0)
                return CANTIL_ERR_PROTOCOL;
            if (kc == 's') info.slot_id = u;
            else if (kc == 't') info.key_type = (cantil_key_type_t)u;
            else if (kc == 'c') info.has_cert = (uint8_t)u;
            else if (kc == 'r') info.has_csr  = (uint8_t)u;
            /* 'p' (protect bits) not currently surfaced on the struct */
        }

        int stop = cb(&info, userdata);
        if (stop) return (cantil_err_t)stop;
    }
    return CANTIL_OK;
}

cantil_err_t cantil_auto_expire(cantil_session_t *s,
                                int64_t now_unix,
                                uint32_t *out_expired_count)
{
    if (!s || !out_expired_count || now_unix <= 0) return CANTIL_ERR_INVALID_ARG;

    uint8_t req[8];
    uint64_t u = (uint64_t)now_unix;
    for (int i = 0; i < 8; i++)
        req[i] = (uint8_t)(u >> (56 - 8 * i));

    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_AUTO_EXPIRE, 0x01,
                                        req, sizeof(req),
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen != 4) return CANTIL_ERR_PROTOCOL;
    *out_expired_count = ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) |
                         ((uint32_t)d[2] << 8) | (uint32_t)d[3];
    return CANTIL_OK;
}

cantil_err_t cantil_revoke_cert_at(cantil_session_t *s,
                                   const uint8_t *serial, size_t serial_len,
                                   uint64_t now_unix)
{
    if (!s || !serial || serial_len == 0 || serial_len > 20)
        return CANTIL_ERR_INVALID_ARG;

    /* Wire (task 2): serial_len(1) + serial + [now_unix BE u64]?. We
     * always include the timestamp when now_unix > 0 so the device records
     * a real revocationDate; clients that don't have a wall clock may pass
     * 0 to omit it (the device's DER encoder substitutes thisUpdate). */
    uint8_t req[1 + 20 + 8];
    size_t  req_len = 0;
    req[req_len++] = (uint8_t)serial_len;
    memcpy(&req[req_len], serial, serial_len);
    req_len += serial_len;
    if (now_unix != 0) {
        req[req_len++] = (uint8_t)(now_unix >> 56);
        req[req_len++] = (uint8_t)(now_unix >> 48);
        req[req_len++] = (uint8_t)(now_unix >> 40);
        req[req_len++] = (uint8_t)(now_unix >> 32);
        req[req_len++] = (uint8_t)(now_unix >> 24);
        req[req_len++] = (uint8_t)(now_unix >> 16);
        req[req_len++] = (uint8_t)(now_unix >>  8);
        req[req_len++] = (uint8_t)(now_unix);
    }

    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request(s, CMD_REVOKE_CERT, 0x01,
                             req, req_len,
                             scratch, sizeof(scratch),
                             &d, &dlen);
}

cantil_err_t cantil_revoke_cert(cantil_session_t *s,
                                const uint8_t *serial, size_t serial_len)
{
    return cantil_revoke_cert_at(s, serial, serial_len, 0);
}

cantil_err_t cantil_get_crl(cantil_session_t *s,
                            uint32_t issuer_slot,
                            uint64_t now_unix,
                            uint8_t **out, size_t *out_len)
{
    if (!s || !out || !out_len) return CANTIL_ERR_INVALID_ARG;
    if (now_unix == 0) return CANTIL_ERR_INVALID_ARG;
    *out = NULL; *out_len = 0;

    /* Wire (task 2): BE u32 slot + BE u64 now_unix → DER CRL bytes. */
    uint8_t req[12] = {
        (uint8_t)(issuer_slot >> 24), (uint8_t)(issuer_slot >> 16),
        (uint8_t)(issuer_slot >>  8), (uint8_t)(issuer_slot),
        (uint8_t)(now_unix    >> 56), (uint8_t)(now_unix    >> 48),
        (uint8_t)(now_unix    >> 40), (uint8_t)(now_unix    >> 32),
        (uint8_t)(now_unix    >> 24), (uint8_t)(now_unix    >> 16),
        (uint8_t)(now_unix    >>  8), (uint8_t)(now_unix),
    };

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_CRL, 0x01,
                                        req, sizeof(req),
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    return dup_resp(d, dlen, out, out_len);
}

cantil_err_t cantil_get_ca_cert(cantil_session_t *s,
                                uint8_t **out, size_t *out_len)
{
    if (!s || !out || !out_len) return CANTIL_ERR_INVALID_ARG;
    *out = NULL; *out_len = 0;

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_CA_CERT, 0x01,
                                        NULL, 0,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    return dup_resp(d, dlen, out, out_len);
}

cantil_err_t cantil_get_session_cert(cantil_session_t *s,
                                     uint8_t **out, size_t *out_len)
{
    if (!s || !out || !out_len) return CANTIL_ERR_INVALID_ARG;
    *out = NULL; *out_len = 0;

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_SESSION_CERT, 0x01,
                                        NULL, 0,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    return dup_resp(d, dlen, out, out_len);
}

cantil_err_t cantil_get_session_csr(cantil_session_t *s,
                                    uint8_t **out, size_t *out_len)
{
    if (!s || !out || !out_len) return CANTIL_ERR_INVALID_ARG;
    *out = NULL; *out_len = 0;

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_SESSION_CSR, 0x01,
                                        NULL, 0,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    return dup_resp(d, dlen, out, out_len);
}

cantil_err_t cantil_sign_session_from_slot(cantil_session_t *s,
                                           uint32_t issuer_slot, uint8_t force)
{
    if (!s) return CANTIL_ERR_INVALID_ARG;

    /* Wire: BE u32 issuer_slot + 1-byte force flag. Tap-confirm on device. */
    uint8_t req[5] = {
        (uint8_t)(issuer_slot >> 24), (uint8_t)(issuer_slot >> 16),
        (uint8_t)(issuer_slot >>  8), (uint8_t)(issuer_slot),
        force ? 1 : 0
    };
    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request_to(s, CMD_SIGN_SESSION_FROM_SLOT, 0x01,
                                req, sizeof(req),
                                scratch, sizeof(scratch),
                                &d, &dlen, CANTIL_TAP_CONFIRM_TIMEOUT_MS);
}

cantil_err_t cantil_push_session_cert(cantil_session_t *s,
                                      const uint8_t *cert, size_t cert_len,
                                      const uint8_t *chain, size_t chain_len,
                                      uint8_t force)
{
    if (!s || !cert || cert_len == 0 || cert_len > 0xFFFFu)
        return CANTIL_ERR_INVALID_ARG;
    if (chain_len > 0 && !chain) return CANTIL_ERR_INVALID_ARG;
    if (3 + cert_len + chain_len > 3000) return CANTIL_ERR_INVALID_ARG;

    /* Wire: 1-byte force || BE u16 cert_len || cert DER || chain DER.
     * Tap-confirm on device — installs the device's identity to the world. */
    static uint8_t req[3 + 3072];
    req[0] = force ? 1 : 0;
    req[1] = (uint8_t)(cert_len >> 8);
    req[2] = (uint8_t)(cert_len & 0xFF);
    memcpy(&req[3], cert, cert_len);
    if (chain_len) memcpy(&req[3 + cert_len], chain, chain_len);

    uint8_t scratch[64];
    const uint8_t *d = NULL; size_t dlen = 0;

    return cantil_do_request_to(s, CMD_PUSH_SESSION_CERT, 0x01,
                                req, 3 + cert_len + chain_len,
                                scratch, sizeof(scratch),
                                &d, &dlen, CANTIL_TAP_CONFIRM_TIMEOUT_MS);
}

cantil_err_t cantil_get_key_chain(cantil_session_t *s, uint32_t slot,
                                  uint8_t **out, size_t *out_len)
{
    if (!s || !out || !out_len) return CANTIL_ERR_INVALID_ARG;
    *out = NULL; *out_len = 0;

    /* Wire: GET_CA_CHAIN (0x03) with optional BE u32 slot arg. Empty body
     * keeps the slot-0 default; a 4-byte body selects an arbitrary slot. */
    uint8_t req[4] = {
        (uint8_t)(slot >> 24), (uint8_t)(slot >> 16),
        (uint8_t)(slot >>  8), (uint8_t)(slot)
    };

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_CA_CHAIN, 0x01,
                                        req, sizeof(req),
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    return dup_resp(d, dlen, out, out_len);
}

cantil_err_t cantil_get_ca_chain(cantil_session_t *s,
                                 uint8_t **out, size_t *out_len)
{
    /* Slot 0 is the master CA — empty body selects it on the wire. */
    if (!s || !out || !out_len) return CANTIL_ERR_INVALID_ARG;
    *out = NULL; *out_len = 0;

    static uint8_t scratch[CA_SCRATCH_SZ];
    const uint8_t *d = NULL; size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_CA_CHAIN, 0x01,
                                        NULL, 0,
                                        scratch, sizeof(scratch),
                                        &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    return dup_resp(d, dlen, out, out_len);
}
