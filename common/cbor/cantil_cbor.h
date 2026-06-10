/*
 * Cantil wire-protocol CBOR codec — shared between firmware and libcantil.
 *
 * Schema (RFC 8949 canonical CBOR):
 *
 *   Request:  { "cmd": uint, "seq": uint, "data"?: bstr }
 *   Response: { "err": uint, "seq": uint, "data"?: bstr }
 *
 * "data" is omitted entirely when zero-length. Map keys are emitted in
 * canonical (bytewise) order; the decoder accepts any order.
 *
 * No allocations. Decoders return a pointer that aliases the input buffer.
 *
 * See [docs/ca/01-cbor-foundation.md](../../docs/ca/01-cbor-foundation.md).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns number of bytes written on success, or negative errno:
 *   -ENOMEM if the buffer is too small. */
int cantil_cbor_encode_request(uint8_t *buf, size_t max,
                               uint32_t cmd, uint32_t seq,
                               const uint8_t *data, size_t data_len);

int cantil_cbor_encode_response(uint8_t *buf, size_t max,
                                uint32_t seq, uint32_t err,
                                const uint8_t *data, size_t data_len);

/* Returns 0 on success or negative errno:
 *   -EINVAL  malformed CBOR or unexpected types
 *   -ENOENT  required key missing
 *   -ERANGE  integer field exceeds uint32_t
 * On success, *data points into the input buffer (or NULL if absent),
 * and *data_len is set. */
int cantil_cbor_decode_request(const uint8_t *buf, size_t len,
                               uint32_t *cmd, uint32_t *seq,
                               const uint8_t **data, size_t *data_len);

int cantil_cbor_decode_response(const uint8_t *buf, size_t len,
                                uint32_t *seq, uint32_t *err,
                                const uint8_t **data, size_t *data_len);

/* ── Low-level primitives ────────────────────────────────────────────────
 *
 * For handlers that need to build/parse CBOR shapes the high-level
 * request/response codec doesn't cover (e.g. LIST_CERTS' "array of small
 * maps" payload).
 *
 * All emit functions return 0 on success or negative errno (-ENOMEM on
 * buffer overflow). They advance *off by the number of bytes written.
 *
 * All read functions return 0 on success or negative errno (-EINVAL on
 * malformed input, -ERANGE if a uint exceeds uint32_t).
 */

#define CANTIL_CBOR_MT_UINT  0x00
#define CANTIL_CBOR_MT_BSTR  0x40
#define CANTIL_CBOR_MT_TSTR  0x60
#define CANTIL_CBOR_MT_ARRAY 0x80
#define CANTIL_CBOR_MT_MAP   0xA0

int cantil_cbor_emit_head(uint8_t *buf, size_t max, size_t *off,
                          uint8_t major, uint64_t val);
int cantil_cbor_emit_uint(uint8_t *buf, size_t max, size_t *off, uint64_t v);
int cantil_cbor_emit_bstr(uint8_t *buf, size_t max, size_t *off,
                          const uint8_t *s, size_t len);
int cantil_cbor_emit_tstr(uint8_t *buf, size_t max, size_t *off,
                          const char *s, size_t len);
int cantil_cbor_emit_array(uint8_t *buf, size_t max, size_t *off, uint32_t n);
int cantil_cbor_emit_map(uint8_t *buf, size_t max, size_t *off, uint32_t n);

int cantil_cbor_read_head(const uint8_t *buf, size_t len, size_t *off,
                          uint8_t *major, uint64_t *val);
int cantil_cbor_read_uint32(const uint8_t *buf, size_t len, size_t *off,
                            uint32_t *out);
int cantil_cbor_read_bstr(const uint8_t *buf, size_t len, size_t *off,
                          const uint8_t **out, size_t *out_len);
int cantil_cbor_read_tstr(const uint8_t *buf, size_t len, size_t *off,
                          const uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif
