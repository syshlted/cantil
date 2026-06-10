/*
 * Cantil wire-protocol CBOR codec. See cantil_cbor.h.
 *
 * Implements just enough of RFC 8949 to encode/decode our two map shapes.
 * No floats, no tags, no indefinite-length items, no negative integers.
 * Canonical (shortest) integer encoding on the wire.
 */

#include "cantil_cbor.h"

#include <errno.h>
#include <string.h>

/* Major types (top 3 bits of initial byte). */
#define MT_UINT  0x00
#define MT_BSTR  0x40
#define MT_TSTR  0x60
#define MT_ARRAY 0x80
#define MT_MAP   0xA0

/* ── Encoders ─────────────────────────────────────────────────────────── */

static int emit_head(uint8_t *buf, size_t max, size_t *off,
                     uint8_t major, uint64_t val)
{
    size_t need;
    if (val < 24)            need = 1;
    else if (val < 0x100)    need = 2;
    else if (val < 0x10000)  need = 3;
    else if (val < 0x100000000ULL) need = 5;
    else                     need = 9;

    if (*off + need > max) return -ENOMEM;
    uint8_t *p = buf + *off;

    if (val < 24) {
        p[0] = major | (uint8_t)val;
    } else if (val < 0x100) {
        p[0] = major | 24;
        p[1] = (uint8_t)val;
    } else if (val < 0x10000) {
        p[0] = major | 25;
        p[1] = (uint8_t)(val >> 8);
        p[2] = (uint8_t)val;
    } else if (val < 0x100000000ULL) {
        p[0] = major | 26;
        p[1] = (uint8_t)(val >> 24);
        p[2] = (uint8_t)(val >> 16);
        p[3] = (uint8_t)(val >>  8);
        p[4] = (uint8_t)val;
    } else {
        p[0] = major | 27;
        for (int i = 0; i < 8; i++)
            p[1 + i] = (uint8_t)(val >> (56 - 8 * i));
    }
    *off += need;
    return 0;
}

static int emit_tstr(uint8_t *buf, size_t max, size_t *off,
                     const char *s, size_t slen)
{
    int rc = emit_head(buf, max, off, MT_TSTR, (uint64_t)slen);
    if (rc) return rc;
    if (*off + slen > max) return -ENOMEM;
    memcpy(buf + *off, s, slen);
    *off += slen;
    return 0;
}

static int emit_bstr(uint8_t *buf, size_t max, size_t *off,
                     const uint8_t *bs, size_t bslen)
{
    int rc = emit_head(buf, max, off, MT_BSTR, (uint64_t)bslen);
    if (rc) return rc;
    if (*off + bslen > max) return -ENOMEM;
    if (bslen) memcpy(buf + *off, bs, bslen);
    *off += bslen;
    return 0;
}

static int encode_map(uint8_t *buf, size_t max,
                      const char *k1, size_t k1l, uint32_t v1,
                      const char *k2, size_t k2l, uint32_t v2,
                      const char *k3, size_t k3l,
                      const uint8_t *data, size_t data_len)
{
    size_t off = 0;
    int n = (data_len > 0) ? 3 : 2;

    int rc = emit_head(buf, max, &off, MT_MAP, (uint64_t)n);
    if (rc) return rc;

    rc = emit_tstr(buf, max, &off, k1, k1l); if (rc) return rc;
    rc = emit_head(buf, max, &off, MT_UINT, v1); if (rc) return rc;

    rc = emit_tstr(buf, max, &off, k2, k2l); if (rc) return rc;
    rc = emit_head(buf, max, &off, MT_UINT, v2); if (rc) return rc;

    if (data_len > 0) {
        rc = emit_tstr(buf, max, &off, k3, k3l); if (rc) return rc;
        rc = emit_bstr(buf, max, &off, data, data_len); if (rc) return rc;
    }
    return (int)off;
}

int cantil_cbor_encode_request(uint8_t *buf, size_t max,
                               uint32_t cmd, uint32_t seq,
                               const uint8_t *data, size_t data_len)
{
    /* Canonical key order: "cmd" (63 63 6D 64) < "seq" (63 73 65 71)
     * < "data" (64 64 61 74 61). */
    return encode_map(buf, max,
                      "cmd",  3, cmd,
                      "seq",  3, seq,
                      "data", 4, data, data_len);
}

int cantil_cbor_encode_response(uint8_t *buf, size_t max,
                                uint32_t seq, uint32_t err,
                                const uint8_t *data, size_t data_len)
{
    /* Canonical key order: "err" (63 65 72 72) < "seq" (63 73 65 71)
     * < "data" (64 64 61 74 61). */
    return encode_map(buf, max,
                      "err",  3, err,
                      "seq",  3, seq,
                      "data", 4, data, data_len);
}

/* ── Decoders ─────────────────────────────────────────────────────────── */

static int read_head(const uint8_t *buf, size_t len, size_t *off,
                     uint8_t *major, uint64_t *val)
{
    if (*off >= len) return -EINVAL;
    uint8_t ib = buf[*off];
    *major = ib & 0xE0;
    uint8_t ai = ib & 0x1F;
    *off += 1;

    if (ai < 24) {
        *val = ai;
    } else if (ai == 24) {
        if (*off + 1 > len) return -EINVAL;
        *val = buf[*off];
        *off += 1;
    } else if (ai == 25) {
        if (*off + 2 > len) return -EINVAL;
        *val = ((uint64_t)buf[*off] << 8) | buf[*off + 1];
        *off += 2;
    } else if (ai == 26) {
        if (*off + 4 > len) return -EINVAL;
        *val = ((uint64_t)buf[*off] << 24) |
               ((uint64_t)buf[*off + 1] << 16) |
               ((uint64_t)buf[*off + 2] <<  8) |
                (uint64_t)buf[*off + 3];
        *off += 4;
    } else if (ai == 27) {
        if (*off + 8 > len) return -EINVAL;
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | buf[*off + i];
        *val = v;
        *off += 8;
    } else {
        /* Indefinite-length and reserved — not supported. */
        return -EINVAL;
    }
    return 0;
}

/* Match the next item against an expected text string. Returns 0 on match,
 * -EINVAL on type mismatch or short input, -ENOENT on string mismatch. */
static int match_tstr(const uint8_t *buf, size_t len, size_t *off,
                      const char *s, size_t slen)
{
    size_t saved = *off;
    uint8_t mt;
    uint64_t v;
    int rc = read_head(buf, len, off, &mt, &v);
    if (rc) { *off = saved; return rc; }
    if (mt != MT_TSTR) { *off = saved; return -EINVAL; }
    if (v != slen || *off + slen > len) { *off = saved; return -ENOENT; }
    if (memcmp(buf + *off, s, slen) != 0) { *off = saved; return -ENOENT; }
    *off += slen;
    return 0;
}

static int read_uint32(const uint8_t *buf, size_t len, size_t *off,
                       uint32_t *out)
{
    uint8_t mt; uint64_t v;
    int rc = read_head(buf, len, off, &mt, &v);
    if (rc) return rc;
    if (mt != MT_UINT) return -EINVAL;
    if (v > 0xFFFFFFFFULL) return -ERANGE;
    *out = (uint32_t)v;
    return 0;
}

static int read_bstr(const uint8_t *buf, size_t len, size_t *off,
                     const uint8_t **out, size_t *out_len)
{
    uint8_t mt; uint64_t v;
    int rc = read_head(buf, len, off, &mt, &v);
    if (rc) return rc;
    if (mt != MT_BSTR) return -EINVAL;
    if (*off + v > len) return -EINVAL;
    *out = buf + *off;
    *out_len = (size_t)v;
    *off += (size_t)v;
    return 0;
}

/* Skip any single CBOR item. Used to tolerate unknown map entries. */
static int skip_item(const uint8_t *buf, size_t len, size_t *off)
{
    uint8_t mt; uint64_t v;
    int rc = read_head(buf, len, off, &mt, &v);
    if (rc) return rc;
    switch (mt) {
    case MT_UINT:
        return 0;
    case MT_BSTR:
    case MT_TSTR:
        if (*off + v > len) return -EINVAL;
        *off += (size_t)v;
        return 0;
    case MT_MAP: {
        for (uint64_t i = 0; i < v; i++) {
            rc = skip_item(buf, len, off); if (rc) return rc;
            rc = skip_item(buf, len, off); if (rc) return rc;
        }
        return 0;
    }
    case MT_ARRAY: {
        for (uint64_t i = 0; i < v; i++) {
            rc = skip_item(buf, len, off); if (rc) return rc;
        }
        return 0;
    }
    default:
        return -EINVAL;
    }
}

/* ── Public low-level primitives ───────────────────────────────────────── */

int cantil_cbor_emit_head(uint8_t *buf, size_t max, size_t *off,
                          uint8_t major, uint64_t val)
{
    return emit_head(buf, max, off, major, val);
}

int cantil_cbor_emit_uint(uint8_t *buf, size_t max, size_t *off, uint64_t v)
{
    return emit_head(buf, max, off, MT_UINT, v);
}

int cantil_cbor_emit_bstr(uint8_t *buf, size_t max, size_t *off,
                          const uint8_t *s, size_t len)
{
    return emit_bstr(buf, max, off, s, len);
}

int cantil_cbor_emit_tstr(uint8_t *buf, size_t max, size_t *off,
                          const char *s, size_t len)
{
    return emit_tstr(buf, max, off, s, len);
}

int cantil_cbor_emit_array(uint8_t *buf, size_t max, size_t *off, uint32_t n)
{
    return emit_head(buf, max, off, MT_ARRAY, (uint64_t)n);
}

int cantil_cbor_emit_map(uint8_t *buf, size_t max, size_t *off, uint32_t n)
{
    return emit_head(buf, max, off, MT_MAP, (uint64_t)n);
}

int cantil_cbor_read_head(const uint8_t *buf, size_t len, size_t *off,
                          uint8_t *major, uint64_t *val)
{
    return read_head(buf, len, off, major, val);
}

int cantil_cbor_read_uint32(const uint8_t *buf, size_t len, size_t *off,
                            uint32_t *out)
{
    return read_uint32(buf, len, off, out);
}

int cantil_cbor_read_bstr(const uint8_t *buf, size_t len, size_t *off,
                          const uint8_t **out, size_t *out_len)
{
    return read_bstr(buf, len, off, out, out_len);
}

int cantil_cbor_read_tstr(const uint8_t *buf, size_t len, size_t *off,
                          const uint8_t **out, size_t *out_len)
{
    uint8_t mt; uint64_t v;
    int rc = read_head(buf, len, off, &mt, &v);
    if (rc) return rc;
    if (mt != MT_TSTR) return -EINVAL;
    if (*off + v > len) return -EINVAL;
    *out = buf + *off;
    *out_len = (size_t)v;
    *off += (size_t)v;
    return 0;
}

struct decoded_fields {
    int      have_int1, have_int2, have_data;
    uint32_t int1, int2;
    const uint8_t *data;
    size_t   data_len;
};

/* Decode a 2-or-3 entry map. Recognises three keys: name1 → int1, name2 → int2,
 * "data" → bstr. Any other key is rejected (-EINVAL) so the schema stays tight. */
static int decode_map(const uint8_t *buf, size_t len,
                      const char *name1, size_t n1len,
                      const char *name2, size_t n2len,
                      struct decoded_fields *out)
{
    if (!buf || len == 0) return -EINVAL;
    size_t off = 0;
    uint8_t mt; uint64_t v;
    int rc = read_head(buf, len, &off, &mt, &v);
    if (rc) return rc;
    if (mt != MT_MAP) return -EINVAL;
    if (v < 2 || v > 3) return -EINVAL;
    uint64_t entries = v;

    memset(out, 0, sizeof(*out));

    for (uint64_t i = 0; i < entries; i++) {
        size_t saved = off;
        rc = match_tstr(buf, len, &off, name1, n1len);
        if (rc == 0) {
            rc = read_uint32(buf, len, &off, &out->int1);
            if (rc) return rc;
            out->have_int1 = 1;
            continue;
        }
        off = saved;
        rc = match_tstr(buf, len, &off, name2, n2len);
        if (rc == 0) {
            rc = read_uint32(buf, len, &off, &out->int2);
            if (rc) return rc;
            out->have_int2 = 1;
            continue;
        }
        off = saved;
        rc = match_tstr(buf, len, &off, "data", 4);
        if (rc == 0) {
            rc = read_bstr(buf, len, &off, &out->data, &out->data_len);
            if (rc) return rc;
            out->have_data = 1;
            continue;
        }
        /* Unknown key — skip its key and value to stay forward-compatible. */
        off = saved;
        rc = skip_item(buf, len, &off); if (rc) return rc;
        rc = skip_item(buf, len, &off); if (rc) return rc;
    }

    if (!out->have_int1 || !out->have_int2) return -ENOENT;
    return 0;
}

int cantil_cbor_decode_request(const uint8_t *buf, size_t len,
                               uint32_t *cmd, uint32_t *seq,
                               const uint8_t **data, size_t *data_len)
{
    struct decoded_fields f;
    int rc = decode_map(buf, len, "cmd", 3, "seq", 3, &f);
    if (rc) return rc;
    if (cmd)      *cmd = f.int1;
    if (seq)      *seq = f.int2;
    if (data)     *data = f.have_data ? f.data : NULL;
    if (data_len) *data_len = f.have_data ? f.data_len : 0;
    return 0;
}

int cantil_cbor_decode_response(const uint8_t *buf, size_t len,
                                uint32_t *seq, uint32_t *err,
                                const uint8_t **data, size_t *data_len)
{
    struct decoded_fields f;
    int rc = decode_map(buf, len, "err", 3, "seq", 3, &f);
    if (rc) return rc;
    if (err)      *err = f.int1;
    if (seq)      *seq = f.int2;
    if (data)     *data = f.have_data ? f.data : NULL;
    if (data_len) *data_len = f.have_data ? f.data_len : 0;
    return 0;
}
