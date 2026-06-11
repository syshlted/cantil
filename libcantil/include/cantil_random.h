/**
 * cantil_random.h — Hardware TRNG utilities for libcantil
 *
 * This header is independently importable. The format-conversion functions
 * have no dependency on the rest of libcantil — they operate on raw byte
 * buffers. Only cantil_rand_source_device() requires a live cantil_session_t.
 *
 * All generators take an cantil_rand_source_t as their first argument so
 * the entropy source is pluggable: use the device TRNG, /dev/urandom, a
 * test PRNG, or any other source that can fill a byte buffer.
 *
 * Each generator group is guarded by a feature macro so it can be excluded
 * from builds that do not need it (e.g. no floating-point support on some
 * embedded host toolchains):
 *
 *   CANTIL_RAND_ENABLE_INT     (default 1) integers and raw bytes
 *   CANTIL_RAND_ENABLE_FLOAT   (default 1) double / float
 *   CANTIL_RAND_ENABLE_UUID    (default 1) RFC 4122 v4 UUID
 *   CANTIL_RAND_ENABLE_HEX     (default 1) hex strings with/without colons
 *   CANTIL_RAND_ENABLE_STRING  (default 1) strings from character sets
 *
 * To disable a group, define the macro to 0 before including this header
 * or pass -DCANTIL_RAND_ENABLE_FLOAT=0 to the compiler.
 *
 * Minimal import example (TRNG bytes + UUID only, no float, no strings):
 *
 *   #define CANTIL_RAND_ENABLE_FLOAT  0
 *   #define CANTIL_RAND_ENABLE_STRING 0
 *   #include "cantil_random.h"
 */

#ifndef CANTIL_RANDOM_H
#define CANTIL_RANDOM_H

#include <stddef.h>
#include <stdint.h>

/* Forward declaration — only needed if cantil_rand_source_device() is used. */
typedef struct cantil_session cantil_session_t;

/* Pull in cantil_err_t without requiring all of cantil.h. */
#ifndef CANTIL_H
typedef enum {
    CANTIL_RAND_OK           =  0,
    CANTIL_RAND_ERR_IO       = -1,
    CANTIL_RAND_ERR_ARGS     = -7,
    CANTIL_RAND_ERR_MEMORY   = -6,
    CANTIL_RAND_ERR_RANGE    = -20, /* range/length constraints violated      */
} cantil_rand_err_t;
#define cantil_err_t cantil_rand_err_t
#endif

#ifndef CANTIL_RAND_ENABLE_INT
#  define CANTIL_RAND_ENABLE_INT 1
#endif
#ifndef CANTIL_RAND_ENABLE_FLOAT
#  define CANTIL_RAND_ENABLE_FLOAT 1
#endif
#ifndef CANTIL_RAND_ENABLE_UUID
#  define CANTIL_RAND_ENABLE_UUID 1
#endif
#ifndef CANTIL_RAND_ENABLE_HEX
#  define CANTIL_RAND_ENABLE_HEX 1
#endif
#ifndef CANTIL_RAND_ENABLE_STRING
#  define CANTIL_RAND_ENABLE_STRING 1
#endif
#ifndef CANTIL_RAND_ENABLE_NAMES
#  define CANTIL_RAND_ENABLE_NAMES 1
#endif

#ifdef __cplusplus
extern "C" {
#endif


/* ─── Pluggable entropy source ───────────────────────────────────────────── */

/*
 * A random source is a function that fills buf[0..len-1] with entropy,
 * plus an opaque context pointer passed through unchanged.
 * Return 0 on success, nonzero on failure.
 */
typedef int (*cantil_rand_fn)(uint8_t *buf, size_t len, void *ctx);

typedef struct {
    cantil_rand_fn fn;
    void         *ctx;
} cantil_rand_source_t;

/*
 * Build a source backed by the device's CryptoCell-310 TRNG.
 * The session must remain open for the lifetime of the source.
 */
cantil_rand_source_t cantil_rand_source_device(cantil_session_t *s);

/*
 * Convenience: build a source from a plain function with no context.
 * Useful for wrapping /dev/urandom, arc4random_buf, etc.
 *
 *   static int my_urandom(uint8_t *b, size_t n, void *_) {
 *       return getentropy(b, n) == 0 ? 0 : -1;
 *   }
 *   cantil_rand_source_t src = cantil_rand_source_fn(my_urandom);
 */
cantil_rand_source_t cantil_rand_source_fn(cantil_rand_fn fn);


/* ─── Raw bytes ──────────────────────────────────────────────────────────── */

#if CANTIL_RAND_ENABLE_INT

cantil_err_t cantil_rand_bytes(cantil_rand_source_t src,
                              uint8_t *buf, size_t len);

#endif /* CANTIL_RAND_ENABLE_INT */


/* ─── Integers ───────────────────────────────────────────────────────────── */

#if CANTIL_RAND_ENABLE_INT

cantil_err_t cantil_rand_uint8(cantil_rand_source_t src, uint8_t  *out);
cantil_err_t cantil_rand_uint16(cantil_rand_source_t src, uint16_t *out);
cantil_err_t cantil_rand_uint32(cantil_rand_source_t src, uint32_t *out);
cantil_err_t cantil_rand_uint64(cantil_rand_source_t src, uint64_t *out);

/*
 * Uniform random integer in [min, max] (inclusive).
 * Uses rejection sampling to avoid modulo bias.
 */
cantil_err_t cantil_rand_uint64_range(cantil_rand_source_t src,
                                     uint64_t min, uint64_t max,
                                     uint64_t *out);

#endif /* CANTIL_RAND_ENABLE_INT */


/* ─── Floating point ─────────────────────────────────────────────────────── */

#if CANTIL_RAND_ENABLE_FLOAT

/* Uniform double in [0.0, 1.0) using all 53 mantissa bits. */
cantil_err_t cantil_rand_double(cantil_rand_source_t src, double *out);

/* Uniform float in [0.0f, 1.0f) using all 24 mantissa bits. */
cantil_err_t cantil_rand_float(cantil_rand_source_t src, float *out);

/* Uniform double in [lo, hi). */
cantil_err_t cantil_rand_double_range(cantil_rand_source_t src,
                                     double lo, double hi,
                                     double *out);

#endif /* CANTIL_RAND_ENABLE_FLOAT */


/* ─── UUID v4 ────────────────────────────────────────────────────────────── */

#if CANTIL_RAND_ENABLE_UUID

/*
 * Generate an RFC 4122 version 4 UUID.
 * out must be at least 37 bytes: "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx\0"
 * Bits 6–7 of byte 8 are set to 10b (variant 1); bits 12–15 of byte 6
 * are set to 0100b (version 4).
 */
cantil_err_t cantil_rand_uuid(cantil_rand_source_t src, char out[37]);

#define CANTIL_UUID_STR_LEN 37  /* including NUL terminator */

#endif /* CANTIL_RAND_ENABLE_UUID */


/* ─── Hex strings ────────────────────────────────────────────────────────── */

#if CANTIL_RAND_ENABLE_HEX

/*
 * Generate nbytes of random data formatted as a lowercase hex string.
 *
 * cantil_rand_hex        "aabbccdd..."   out_size >= nbytes*2 + 1
 * cantil_rand_hex_colons "aa:bb:cc:dd"   out_size >= nbytes*3     (no trailing colon)
 * cantil_rand_hex_upper  "AABBCCDD..."   out_size >= nbytes*2 + 1
 */
cantil_err_t cantil_rand_hex(cantil_rand_source_t src,
                            size_t nbytes, char *out, size_t out_size);

cantil_err_t cantil_rand_hex_colons(cantil_rand_source_t src,
                                   size_t nbytes, char *out, size_t out_size);

cantil_err_t cantil_rand_hex_upper(cantil_rand_source_t src,
                                  size_t nbytes, char *out, size_t out_size);

/* Required output buffer size macros. */
#define CANTIL_HEX_SIZE(nbytes)        ((nbytes) * 2 + 1)
#define CANTIL_HEX_COLONS_SIZE(nbytes) ((nbytes) * 3)

#endif /* CANTIL_RAND_ENABLE_HEX */


/* ─── Strings from character sets ───────────────────────────────────────────*/

#if CANTIL_RAND_ENABLE_STRING

/*
 * Character set descriptor.
 *
 * Specify either an explicit set of characters (chars != NULL) or a
 * contiguous ASCII range [lo, hi] (chars == NULL). Multiple descriptors
 * can be combined in a single cantil_rand_string() call — the union of all
 * provided sets is used.
 *
 * Convenience initialiser macros:
 *   CANTIL_CS_LITERAL("abc!@#")     explicit character list
 *   CANTIL_CS_RANGE('a', 'z')       range a–z inclusive
 */
typedef struct {
    const char *chars;  /* explicit set (NUL-terminated); NULL → use lo/hi  */
    char        lo;     /* range low bound  (inclusive), when chars == NULL  */
    char        hi;     /* range high bound (inclusive), when chars == NULL  */
} cantil_charset_t;

#define CANTIL_CS_LITERAL(s)  { (s),  0,   0   }
#define CANTIL_CS_RANGE(l, h) { NULL, (l), (h) }

/* Pre-built standard sets. */
extern const cantil_charset_t cantil_cs_lower;     /* a–z                     */
extern const cantil_charset_t cantil_cs_upper;     /* A–Z                     */
extern const cantil_charset_t cantil_cs_digits;    /* 0–9                     */
extern const cantil_charset_t cantil_cs_hex_lower; /* 0–9 a–f                 */
extern const cantil_charset_t cantil_cs_hex_upper; /* 0–9 A–F                 */
extern const cantil_charset_t cantil_cs_alpha;     /* a–z A–Z                 */
extern const cantil_charset_t cantil_cs_alnum;     /* a–z A–Z 0–9             */
extern const cantil_charset_t cantil_cs_printable; /* 0x20–0x7E               */

/*
 * Generate a random string of exactly `length` characters drawn uniformly
 * from the union of the provided character sets.
 *
 * Uses rejection sampling to eliminate modulo bias when the charset size
 * is not a power of two.
 *
 * out_size must be >= length + 1 (NUL terminator).
 *
 * Example — random 16-char password from lower + upper + digits + symbols:
 *
 *   const cantil_charset_t sets[] = {
 *       cantil_cs_lower,
 *       cantil_cs_upper,
 *       cantil_cs_digits,
 *       CANTIL_CS_LITERAL("!@#$%^&*"),
 *   };
 *   char pw[17];
 *   cantil_rand_string(src, sets, 4, 16, pw, sizeof(pw));
 */
cantil_err_t cantil_rand_string(cantil_rand_source_t    src,
                               const cantil_charset_t *sets,
                               size_t                 num_sets,
                               size_t                 length,
                               char                  *out,
                               size_t                 out_size);

#endif /* CANTIL_RAND_ENABLE_STRING */


/* ─── Baby names (device-TRNG selected, UTF-8 byte stream) ──────────────── */

#if CANTIL_RAND_ENABLE_NAMES

/*
 * Wire encoding
 * -------------
 * The device returns raw UTF-8 name bytes with 0xFF as the delimiter between
 * names.  0xFF is an invalid UTF-8 byte and therefore an unambiguous separator
 * regardless of language or script.  The last name is also followed by 0xFF.
 *
 * Format: <name-utf8> 0xFF <name-utf8> 0xFF ...
 *
 * API
 * ---
 * cantil_rand_names() sends CMD_GET_RANDOM_NAMES (0x50) to the device and
 * invokes `cb` once per decoded name.  The name string passed to `cb` is
 * NUL-terminated UTF-8 and valid only for the duration of the call.
 *
 * `count` is clamped to CANTIL_NAMES_BATCH_MAX by the device.
 *
 * Returns CANTIL_OK on success; a negative error code on I/O or decode
 * failure.
 *
 * Standalone decode
 * -----------------
 * cantil_names_decode() splits a raw response buffer on 0xFF separators and
 * invokes `cb` for each name, without touching the session.  Useful for
 * testing or piping raw device responses through other tools.
 */

#define CANTIL_NAMES_BATCH_MAX  64U
#define CANTIL_NAME_MAX_LEN     32U   /* longest SSA name fits comfortably */

typedef void (*cantil_name_cb_t)(const char *name, void *ctx);

cantil_err_t cantil_rand_names(cantil_session_t   *s,
                              uint16_t           count,
                              cantil_name_cb_t    cb,
                              void              *ctx);

/*
 * Decode a packed 6-bit bitstream into individual names.
 *
 * `bits`     — byte buffer containing the bitstream (MSB-first)
 * `bits_len` — byte length of the bitstream buffer
 * `cb`       — called once per decoded name (NUL-terminated, lowercase)
 * `ctx`      — opaque pointer forwarded to `cb`
 *
 * Returns the number of names decoded, or a negative error code.
 */
int cantil_names_decode(const uint8_t  *bits,
                       size_t          bits_len,
                       cantil_name_cb_t cb,
                       void           *ctx);

#endif /* CANTIL_RAND_ENABLE_NAMES */


#ifdef __cplusplus
}
#endif

#endif /* CANTIL_RANDOM_H */
