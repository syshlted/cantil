/*
 * Device-level commands: DEVICE_STATUS, GET_RANDOM.
 *
 * Wire encoding: CBOR map `{cmd,seq,data?}` request / `{err,seq,data?}`
 * response. See common/cbor/cantil_cbor.h and docs/ca/01-cbor-foundation.md.
 *
 * DEVICE_STATUS response inner data: 26-byte packed struct (see firmware
 * protocol.c STATUS_WIRE_LEN). GET_RANDOM request inner data: uint16 length
 * (big-endian); response inner data: that many random bytes.
 */

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include "../include/cantil.h"
#include "internal.h"
#include "cantil_cbor.h"

#define STATUS_WIRE_LEN 26

static inline uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
           ((uint32_t)p[3]);
}

static cantil_err_t map_proto_err(uint32_t err)
{
    switch (err) {
    case PROTO_ERR_OK:               return CANTIL_OK;
    case PROTO_ERR_DEVICE_LOCKED:    return CANTIL_ERR_DEVICE_LOCKED;
    case PROTO_ERR_AUTH:             return CANTIL_ERR_AUTH;
    case PROTO_ERR_PASSKEY_REQUIRED: return CANTIL_ERR_PASSKEY_REQUIRED;
    case PROTO_ERR_FW_UPDATE_BUSY:   return CANTIL_ERR_FW_UPDATE_BUSY;
    case PROTO_ERR_FW_UPDATE_FLASH:  return CANTIL_ERR_FW_UPDATE_FLASH;
    case PROTO_ERR_FW_UPDATE_ARGS:   return CANTIL_ERR_INVALID_ARG;
    default:                         return CANTIL_ERR_PROTOCOL;
    }
}

/* Send a request and receive a response. On success, fills *resp_data /
 * *resp_data_len with a pointer into the caller's scratch buffer. */
cantil_err_t cantil_do_request_to(cantil_session_t *s,
                                  uint32_t cmd, uint32_t seq,
                                  const uint8_t *req_data, size_t req_data_len,
                                  uint8_t *scratch, size_t scratch_sz,
                                  const uint8_t **resp_data, size_t *resp_data_len,
                                  int timeout_ms)
{
    uint8_t req[64 + 16];   /* enough for cmd+seq+small bstr header */
    /* For larger request payloads (e.g., cert DER) the caller passes them
     * in via req_data — we still need a temporary big enough to hold the
     * encoded frame. Allocate based on req_data_len. */
    uint8_t large_req_stack[2048];
    uint8_t *req_buf = req;
    size_t   req_buf_sz = sizeof(req);
    if (req_data_len + 32 > req_buf_sz) {
        if (req_data_len + 32 > sizeof(large_req_stack))
            return CANTIL_ERR_INVALID_ARG;
        req_buf = large_req_stack;
        req_buf_sz = sizeof(large_req_stack);
    }

    int n = cantil_cbor_encode_request(req_buf, req_buf_sz, cmd, seq,
                                       req_data, req_data_len);
    if (n < 0) return CANTIL_ERR_INVALID_ARG;

    if (cantil_session_send(s, req_buf, (size_t)n) != 0)
        return CANTIL_ERR_IO;

    size_t got;
    if (cantil_session_recv_to(s, scratch, scratch_sz, &got, timeout_ms) != 0)
        return CANTIL_ERR_IO;

    uint32_t rseq = 0, rerr = 0;
    int rc = cantil_cbor_decode_response(scratch, got, &rseq, &rerr,
                                         resp_data, resp_data_len);
    if (rc != 0) return CANTIL_ERR_PROTOCOL;
    if (rseq != seq) return CANTIL_ERR_PROTOCOL;
    return map_proto_err(rerr);
}

cantil_err_t cantil_do_request(cantil_session_t *s,
                               uint32_t cmd, uint32_t seq,
                               const uint8_t *req_data, size_t req_data_len,
                               uint8_t *scratch, size_t scratch_sz,
                               const uint8_t **resp_data, size_t *resp_data_len)
{
    return cantil_do_request_to(s, cmd, seq, req_data, req_data_len,
                                scratch, scratch_sz, resp_data, resp_data_len,
                                0 /* default timeout */);
}

cantil_err_t cantil_get_status(cantil_session_t *s, cantil_status_t *out)
{
    if (!s || !out)
        return CANTIL_ERR_INVALID_ARG;

    uint8_t scratch[128];
    const uint8_t *d = NULL;
    size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_DEVICE_STATUS, 0x01,
                                 NULL, 0,
                                 scratch, sizeof(scratch), &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen < STATUS_WIRE_LEN) return CANTIL_ERR_PROTOCOL;

    memset(out, 0, sizeof(*out));
    out->fw_major          = d[0];
    out->fw_minor          = d[1];
    out->fw_patch          = d[2];
    out->locked            = d[3];
    out->certs_issued      = get_be32(&d[4]);
    out->certs_stored      = get_be32(&d[8]);
    out->key_slots_used    = get_be32(&d[12]);
    out->key_slots_total   = get_be32(&d[16]);
    out->flash_free_kb     = get_be32(&d[20]);
    out->ble_bonds         = d[24];
    out->has_external_flash = d[25];

    return CANTIL_OK;
}

/* cantil_get_status with an explicit response timeout. Use from the pair
 * command where the device may be waiting for tap confirmation before it
 * can process commands (PAIRING_TAP_CONFIRM). */
cantil_err_t cantil_get_status_wait(cantil_session_t *s, cantil_status_t *out,
                                     int timeout_ms)
{
    if (!s || !out)
        return CANTIL_ERR_INVALID_ARG;

    uint8_t scratch[128];
    const uint8_t *d = NULL;
    size_t dlen = 0;

    cantil_err_t rc = cantil_do_request_to(s, CMD_DEVICE_STATUS, 0x01,
                                            NULL, 0,
                                            scratch, sizeof(scratch), &d, &dlen,
                                            timeout_ms);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen < STATUS_WIRE_LEN) return CANTIL_ERR_PROTOCOL;

    memset(out, 0, sizeof(*out));
    out->fw_major           = d[0];
    out->fw_minor           = d[1];
    out->fw_patch           = d[2];
    out->locked             = d[3];
    out->certs_issued       = get_be32(&d[4]);
    out->certs_stored       = get_be32(&d[8]);
    out->key_slots_used     = get_be32(&d[12]);
    out->key_slots_total    = get_be32(&d[16]);
    out->flash_free_kb      = get_be32(&d[20]);
    out->ble_bonds          = d[24];
    out->has_external_flash = d[25];

    return CANTIL_OK;
}

cantil_err_t cantil_trigger_uf2_reboot(cantil_session_t *s)
{
    if (!s)
        return CANTIL_ERR_INVALID_ARG;

    uint8_t scratch[64];
    const uint8_t *d = NULL;
    size_t dlen = 0;

    /* Short timeout: device sends ACK then immediately reboots, so the
     * window for the ACK to arrive is small but the command is fast. */
    cantil_err_t rc = cantil_do_request_to(s, CMD_UPDATE_FIRMWARE, 0x01,
                                            NULL, 0,
                                            scratch, sizeof(scratch), &d, &dlen,
                                            3000 /* ms */);
    if (rc == CANTIL_ERR_PROTOCOL)
        return CANTIL_ERR_NOT_SUPPORTED; /* MCUBOOT: ERR_INVALID_CMD */
    return rc;
}

cantil_err_t cantil_random_bytes(cantil_session_t *s,
                                uint8_t *out, size_t out_len)
{
    if (!s || (!out && out_len) || out_len == 0 || out_len > UINT16_MAX)
        return CANTIL_ERR_INVALID_ARG;

    uint8_t req_data[2] = {
        (uint8_t)(out_len >> 8),
        (uint8_t)(out_len & 0xFF),
    };

    /* Response frame size = ~16 bytes overhead + payload. */
    static uint8_t scratch[16 + 4096];
    if (out_len > sizeof(scratch) - 32)
        return CANTIL_ERR_INVALID_ARG;

    const uint8_t *d = NULL;
    size_t dlen = 0;

    cantil_err_t rc = cantil_do_request(s, CMD_GET_RANDOM, 0x01,
                                 req_data, sizeof(req_data),
                                 scratch, sizeof(scratch), &d, &dlen);
    if (rc != CANTIL_OK) return rc;
    if (!d || dlen != out_len) return CANTIL_ERR_PROTOCOL;

    memcpy(out, d, out_len);
    return CANTIL_OK;
}

/* ── cantil_fw_update ────────────────────────────────────────────────────── */

/*
 * Encode an UPDATE_FIRMWARE sub-operation into buf[0..max].
 * Returns number of bytes written or negative on error.
 */
static int encode_fw_begin(uint8_t *buf, size_t max, uint32_t total_size)
{
    size_t off = 0;
    if (cantil_cbor_emit_map(buf, max, &off, 2) != 0) return -1;
    if (cantil_cbor_emit_uint(buf, max, &off, 0) != 0) return -1;  /* key: sub_op */
    if (cantil_cbor_emit_uint(buf, max, &off, 0) != 0) return -1;  /* val: BEGIN=0 */
    if (cantil_cbor_emit_uint(buf, max, &off, 1) != 0) return -1;  /* key: total_size */
    if (cantil_cbor_emit_uint(buf, max, &off, total_size) != 0) return -1;
    return (int)off;
}

static int encode_fw_chunk(uint8_t *buf, size_t max,
                           uint32_t offset,
                           const uint8_t *data, size_t data_len)
{
    size_t off = 0;
    if (cantil_cbor_emit_map(buf, max, &off, 3) != 0) return -1;
    if (cantil_cbor_emit_uint(buf, max, &off, 0) != 0) return -1;  /* key: sub_op */
    if (cantil_cbor_emit_uint(buf, max, &off, 1) != 0) return -1;  /* val: CHUNK=1 */
    if (cantil_cbor_emit_uint(buf, max, &off, 1) != 0) return -1;  /* key: offset */
    if (cantil_cbor_emit_uint(buf, max, &off, offset) != 0) return -1;
    if (cantil_cbor_emit_uint(buf, max, &off, 2) != 0) return -1;  /* key: data */
    if (cantil_cbor_emit_bstr(buf, max, &off, data, data_len) != 0) return -1;
    return (int)off;
}

static int encode_fw_commit(uint8_t *buf, size_t max)
{
    size_t off = 0;
    if (cantil_cbor_emit_map(buf, max, &off, 1) != 0) return -1;
    if (cantil_cbor_emit_uint(buf, max, &off, 0) != 0) return -1;  /* key: sub_op */
    if (cantil_cbor_emit_uint(buf, max, &off, 2) != 0) return -1;  /* val: COMMIT=2 */
    return (int)off;
}

/* Scratch buffer for a single request/response exchange.
 * Large enough for CBOR framing + CANTIL_FW_CHUNK_MAX payload. */
#define FW_SCRATCH_SZ (CANTIL_FW_CHUNK_MAX + 256)

cantil_err_t cantil_fw_update(cantil_session_t *s,
                              const char *image_path,
                              void (*progress_cb)(size_t done, size_t total,
                                                  void *user),
                              void *user)
{
    if (!s || !image_path) return CANTIL_ERR_INVALID_ARG;

    FILE *f = fopen(image_path, "rb");
    if (!f) return CANTIL_ERR_IO;

    cantil_err_t rc = CANTIL_ERR_IO;

    if (fseek(f, 0, SEEK_END) != 0) goto done;
    long fsize = ftell(f);
    if (fsize <= 0 || (size_t)fsize > (size_t)UINT32_MAX) {
        rc = CANTIL_ERR_INVALID_ARG;
        goto done;
    }
    rewind(f);

    size_t total = (size_t)fsize;
    static uint8_t req_buf[FW_SCRATCH_SZ];
    static uint8_t scratch[256];
    const uint8_t *d = NULL;
    size_t dlen = 0;

    /* BEGIN */
    int n = encode_fw_begin(req_buf, sizeof(req_buf), (uint32_t)total);
    if (n < 0) { rc = CANTIL_ERR_PROTOCOL; goto done; }
    rc = cantil_do_request(s, CMD_UPDATE_FIRMWARE, 0x01,
                           req_buf, (size_t)n,
                           scratch, sizeof(scratch), &d, &dlen);
    if (rc == CANTIL_ERR_PROTOCOL) { rc = CANTIL_ERR_NOT_SUPPORTED; goto done; }
    if (rc != CANTIL_OK) goto done;

    /* CHUNK loop */
    static uint8_t chunk_buf[CANTIL_FW_CHUNK_MAX];
    size_t offset = 0;

    while (offset < total) {
        size_t to_read = total - offset;
        if (to_read > CANTIL_FW_CHUNK_MAX) to_read = CANTIL_FW_CHUNK_MAX;

        size_t nr = fread(chunk_buf, 1, to_read, f);
        if (nr != to_read) { rc = CANTIL_ERR_IO; goto done; }

        n = encode_fw_chunk(req_buf, sizeof(req_buf),
                            (uint32_t)offset, chunk_buf, nr);
        if (n < 0) { rc = CANTIL_ERR_PROTOCOL; goto done; }

        rc = cantil_do_request(s, CMD_UPDATE_FIRMWARE, 0x01,
                               req_buf, (size_t)n,
                               scratch, sizeof(scratch), &d, &dlen);
        if (rc != CANTIL_OK) goto done;

        offset += nr;
        if (progress_cb) progress_cb(offset, total, user);
    }

    /* COMMIT — device will prompt for tap-confirm then reboot.
     * Use a long timeout to accommodate the tap. */
    n = encode_fw_commit(req_buf, sizeof(req_buf));
    if (n < 0) { rc = CANTIL_ERR_PROTOCOL; goto done; }
    rc = cantil_do_request_to(s, CMD_UPDATE_FIRMWARE, 0x01,
                              req_buf, (size_t)n,
                              scratch, sizeof(scratch), &d, &dlen,
                              CANTIL_TAP_CONFIRM_TIMEOUT_MS);
    /* ERR_BUSY = user denied tap — map to a sensible error */
    if (rc == CANTIL_ERR_PROTOCOL) rc = CANTIL_ERR_IO;

done:
    fclose(f);
    return rc;
}
