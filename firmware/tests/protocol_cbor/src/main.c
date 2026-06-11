/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Wire-protocol CBOR codec conformance on native_sim.
 *
 * Drives common/cbor/cantil_cbor.c against fixed RFC 8949 byte vectors:
 *   - canonical request/response encoding (golden bytes)
 *   - round-trip identity (encode -> decode == original)
 *   - liberal decode (out-of-canonical-order maps accepted)
 *   - rejection of malformed / unknown / oversized inputs
 *   - large bstr (~3 KiB) round-trip
 *
 * Tests are intentionally hermetic — no Zephyr subsystems beyond ztest.
 */

#include <zephyr/ztest.h>
#include <string.h>
#include "cantil_cbor.h"

/* ── 1. Golden vectors ──────────────────────────────────────────────────── */

/* Request: cmd=0x30 (DEVICE_STATUS), seq=1, no data
 *   A2                              # map(2)
 *      63 63 6D 64                  #   tstr(3) "cmd"
 *      18 30                        #   uint(0x30)
 *      63 73 65 71                  #   tstr(3) "seq"
 *      01                           #   uint(1)
 */
static const uint8_t REQ_STATUS_GOLDEN[] = {
    0xA2,
    0x63, 'c','m','d',  0x18, 0x30,
    0x63, 's','e','q',  0x01,
};

/* Response: err=0, seq=1, data = 4 bytes 0xDEADBEEF
 *   A3                              # map(3)
 *      63 65 72 72  00              #   "err"  -> 0
 *      63 73 65 71  01              #   "seq"  -> 1
 *      64 64 61 74 61  44 DE AD BE EF  # "data" -> bstr(4) DEADBEEF
 */
static const uint8_t RESP_DATA_GOLDEN[] = {
    0xA3,
    0x63, 'e','r','r',  0x00,
    0x63, 's','e','q',  0x01,
    0x64, 'd','a','t','a',  0x44, 0xDE, 0xAD, 0xBE, 0xEF,
};

ZTEST(protocol_cbor, test_encode_request_canonical_status)
{
    uint8_t out[64];
    int n = cantil_cbor_encode_request(out, sizeof(out), 0x30, 1, NULL, 0);
    zassert_equal(n, (int)sizeof(REQ_STATUS_GOLDEN), "len=%d", n);
    zassert_mem_equal(out, REQ_STATUS_GOLDEN, sizeof(REQ_STATUS_GOLDEN));
}

ZTEST(protocol_cbor, test_encode_response_canonical_with_data)
{
    uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t out[64];
    int n = cantil_cbor_encode_response(out, sizeof(out), 1, 0,
                                        payload, sizeof(payload));
    zassert_equal(n, (int)sizeof(RESP_DATA_GOLDEN), "len=%d", n);
    zassert_mem_equal(out, RESP_DATA_GOLDEN, sizeof(RESP_DATA_GOLDEN));
}

/* ── 2. Round-trip identity ─────────────────────────────────────────────── */

ZTEST(protocol_cbor, test_roundtrip_request_no_data)
{
    uint8_t buf[64];
    int n = cantil_cbor_encode_request(buf, sizeof(buf), 0x01, 42, NULL, 0);
    zassert_true(n > 0, "encode rc=%d", n);

    uint32_t cmd = 0, seq = 0;
    const uint8_t *data = (void *)0x1;
    size_t data_len = 99;
    int rc = cantil_cbor_decode_request(buf, (size_t)n, &cmd, &seq,
                                        &data, &data_len);
    zassert_equal(rc, 0);
    zassert_equal(cmd, 0x01u);
    zassert_equal(seq, 42u);
    zassert_is_null(data);
    zassert_equal(data_len, 0u);
}

ZTEST(protocol_cbor, test_roundtrip_request_with_data)
{
    uint8_t payload[37];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i * 7);

    uint8_t buf[128];
    int n = cantil_cbor_encode_request(buf, sizeof(buf), 0x2A, 0x12345678,
                                       payload, sizeof(payload));
    zassert_true(n > 0);

    uint32_t cmd = 0, seq = 0;
    const uint8_t *out = NULL;
    size_t out_len = 0;
    int rc = cantil_cbor_decode_request(buf, (size_t)n, &cmd, &seq,
                                        &out, &out_len);
    zassert_equal(rc, 0);
    zassert_equal(cmd, 0x2Au);
    zassert_equal(seq, 0x12345678u);
    zassert_equal(out_len, sizeof(payload));
    zassert_mem_equal(out, payload, sizeof(payload));
}

ZTEST(protocol_cbor, test_roundtrip_response)
{
    uint8_t payload[26]; /* DEVICE_STATUS-shaped */
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(0xAA ^ i);

    uint8_t buf[128];
    int n = cantil_cbor_encode_response(buf, sizeof(buf), 7, 0,
                                        payload, sizeof(payload));
    zassert_true(n > 0);

    uint32_t seq = 0, err = 99;
    const uint8_t *out = NULL;
    size_t out_len = 0;
    int rc = cantil_cbor_decode_response(buf, (size_t)n, &seq, &err,
                                         &out, &out_len);
    zassert_equal(rc, 0);
    zassert_equal(seq, 7u);
    zassert_equal(err, 0u);
    zassert_equal(out_len, sizeof(payload));
    zassert_mem_equal(out, payload, sizeof(payload));
}

/* ── 3. Liberal decode: keys in non-canonical order ─────────────────────── */

ZTEST(protocol_cbor, test_decode_request_reorders_seq_first)
{
    /* { "seq": 5, "cmd": 0x02 } — non-canonical key order, must still parse. */
    const uint8_t buf[] = {
        0xA2,
        0x63, 's','e','q',  0x05,
        0x63, 'c','m','d',  0x02,
    };
    uint32_t cmd = 0, seq = 0;
    const uint8_t *d = NULL; size_t dl = 0;
    int rc = cantil_cbor_decode_request(buf, sizeof(buf), &cmd, &seq, &d, &dl);
    zassert_equal(rc, 0);
    zassert_equal(cmd, 0x02u);
    zassert_equal(seq, 5u);
}

/* ── 4. Malformed input rejection ───────────────────────────────────────── */

ZTEST(protocol_cbor, test_decode_rejects_short_buffer)
{
    const uint8_t buf[] = { 0xA2, 0x63, 'c' };
    uint32_t cmd, seq;
    const uint8_t *d; size_t dl;
    int rc = cantil_cbor_decode_request(buf, sizeof(buf), &cmd, &seq, &d, &dl);
    zassert_true(rc < 0, "rc=%d", rc);
}

ZTEST(protocol_cbor, test_decode_rejects_wrong_top_type)
{
    /* Top is an array, not a map. */
    const uint8_t buf[] = { 0x82, 0x01, 0x02 };
    uint32_t cmd, seq;
    const uint8_t *d; size_t dl;
    int rc = cantil_cbor_decode_request(buf, sizeof(buf), &cmd, &seq, &d, &dl);
    zassert_true(rc < 0);
}

ZTEST(protocol_cbor, test_decode_rejects_missing_required_key)
{
    /* Map(2) with only "cmd" and a bogus key — missing "seq". */
    const uint8_t buf[] = {
        0xA2,
        0x63, 'c','m','d',  0x01,
        0x61, 'x',           0x02,
    };
    uint32_t cmd, seq;
    const uint8_t *d; size_t dl;
    int rc = cantil_cbor_decode_request(buf, sizeof(buf), &cmd, &seq, &d, &dl);
    zassert_true(rc < 0, "expected error, got %d", rc);
}

ZTEST(protocol_cbor, test_decode_rejects_truncated_bstr)
{
    /* "data" claims bstr(10) but only 3 bytes follow. */
    const uint8_t buf[] = {
        0xA3,
        0x63, 'c','m','d',  0x01,
        0x63, 's','e','q',  0x01,
        0x64, 'd','a','t','a', 0x4A, 0xAA, 0xBB, 0xCC,
    };
    uint32_t cmd, seq;
    const uint8_t *d; size_t dl;
    int rc = cantil_cbor_decode_request(buf, sizeof(buf), &cmd, &seq, &d, &dl);
    zassert_true(rc < 0);
}

/* ── 5. Buffer-too-small on encode ──────────────────────────────────────── */

ZTEST(protocol_cbor, test_encode_returns_enomem_on_small_buffer)
{
    uint8_t out[3]; /* far too small */
    int n = cantil_cbor_encode_request(out, sizeof(out), 0x01, 1, NULL, 0);
    zassert_true(n < 0);
}

/* ── 6. Large bstr round-trip ───────────────────────────────────────────── */

ZTEST(protocol_cbor, test_roundtrip_large_bstr)
{
    static uint8_t payload[3000];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i * 131);

    static uint8_t buf[3072];
    int n = cantil_cbor_encode_response(buf, sizeof(buf), 9, 0,
                                        payload, sizeof(payload));
    zassert_true(n > 0, "encode rc=%d", n);

    uint32_t seq, err;
    const uint8_t *d = NULL; size_t dl = 0;
    int rc = cantil_cbor_decode_response(buf, (size_t)n, &seq, &err, &d, &dl);
    zassert_equal(rc, 0);
    zassert_equal(seq, 9u);
    zassert_equal(err, 0u);
    zassert_equal(dl, sizeof(payload));
    zassert_mem_equal(d, payload, sizeof(payload));
}

/* ── 7. Forward-compatibility: unknown keys in decoded map ──────────────── */

ZTEST(protocol_cbor, test_decode_skips_unknown_key)
{
    /* Map(3) with bogus 1-char key "x". Decoder must ignore it. */
    const uint8_t buf[] = {
        0xA3,
        0x63, 'c','m','d',  0x01,
        0x61, 'x',           0x05,
        0x63, 's','e','q',  0x07,
    };
    uint32_t cmd = 0, seq = 0;
    const uint8_t *d = NULL; size_t dl = 0;
    int rc = cantil_cbor_decode_request(buf, sizeof(buf), &cmd, &seq, &d, &dl);
    /* Schema requires map(2) or map(3); with unknown key still seen we
     * accept a 3-entry map if the two required fields are present. */
    zassert_equal(rc, 0, "rc=%d", rc);
    zassert_equal(cmd, 0x01u);
    zassert_equal(seq, 0x07u);
}

ZTEST_SUITE(protocol_cbor, NULL, NULL, NULL, NULL, NULL);
