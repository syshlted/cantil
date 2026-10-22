/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#ifndef CANTIL_CA_CERTGEN_H
#define CANTIL_CA_CERTGEN_H

/*
 * certgen — backend-independent X.509 certificate + CSR *writer* seam.
 *
 * This is the boundary introduced by step 4 of docs/roadmap/wolfssl-migration.md.
 * ca.c owns everything else (slot loading, storage, parsing, serial/date policy)
 * and hands this layer plain C data — raw key bytes, a structured DN, and cert
 * parameters — receiving a finished DER blob back. The one implementation is:
 *
 *   certgen_wolfssl.c  — wc_MakeCert / wc_SignCert / wc_MakeCertReq.
 *
 * The seam speaks only bytes, so it carries no library type. That is what let
 * the mbedTLS writer that once lived here be dropped by deleting one file, and
 * what will let a future backend slot in the same way.
 *
 * All keys are P-256. Private keys are the raw 32-byte scalar; public keys are
 * the 65-byte SEC1 uncompressed point (0x04 || X || Y). DER output is written to
 * the FRONT of the caller's buffer, with *out_len updated to the byte count.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Structured distinguished name. Each field is a NUL-terminated string; an
 * empty string omits that RDN. Sizes mirror ca.c's x509_params_t. `cn` is
 * required by callers; the writer does not enforce it.
 */
typedef struct {
	char cn[65];
	char o[65];
	char ou[65];
	char c[3];
	char st[65];
	char l[65];
} certgen_dn_t;

/*
 * A P-256 key as raw bytes. For a subject key, either `priv` (the writer derives
 * the public point) or `pub` may be supplied. For an issuer (signing) key,
 * `priv` is required.
 */
typedef struct {
	const uint8_t *priv; /* 32-byte scalar, or NULL */
	const uint8_t *pub;  /* 65-byte SEC1 uncompressed (0x04||X||Y), or NULL */
} certgen_key_t;

/*
 * RFC 5280 KeyUsage bits, in the byte-level encoding certgen writes and
 * certparse reads back. mbedTLS's MBEDTLS_X509_KU_* and wolfCrypt's KEYUSE_*
 * are both this same encoding, so naming them here lets ca.c, both backends and
 * the tests share one set of names without any of them pulling in a library
 * header for the constant. (bit 0 is the high-order bit of the first octet;
 * see RFC 5280 §4.2.1.3.)
 */
#define CERTGEN_KU_DIGITAL_SIGNATURE 0x0080
#define CERTGEN_KU_NON_REPUDIATION   0x0040
#define CERTGEN_KU_KEY_ENCIPHERMENT  0x0020
#define CERTGEN_KU_DATA_ENCIPHERMENT 0x0010
#define CERTGEN_KU_KEY_AGREEMENT     0x0008
#define CERTGEN_KU_KEY_CERT_SIGN     0x0004
#define CERTGEN_KU_CRL_SIGN          0x0002

/*
 * Certificate parameters. Serial and validity are computed by ca.c so the
 * writer stays a pure encoder. `key_usage` is the RFC 5280 KeyUsage BIT STRING
 * value (the CERTGEN_KU_* encoding above); 0 omits the extension. An optional
 * non-critical custom extension
 * is described by `ext_oid` (the raw DER OID value octets, no tag/len) and
 * `ext_val` (the raw extnValue content the writer wraps in an OCTET STRING);
 * `ext_val == NULL` omits it.
 */
typedef struct {
	const uint8_t *serial;
	size_t serial_len;
	const char *not_before; /* "YYYYMMDDHHMMSS" (14 chars) */
	const char *not_after;  /* "YYYYMMDDHHMMSS" (14 chars) */
	bool emit_bc;           /* emit the basicConstraints extension at all */
	bool is_ca;             /* CA:TRUE when set (only meaningful if emit_bc) */
	int path_len;           /* -1 = unconstrained; used only when is_ca */
	uint16_t key_usage;     /* RFC 5280 KU bits; 0 = omit */
	const uint8_t *ext_oid;
	size_t ext_oid_len;
	const uint8_t *ext_val; /* NULL = no custom extension */
	size_t ext_val_len;
} certgen_cert_params_t;

/*
 * Build and sign an X.509 v3 certificate.
 *
 * `subject` provides the subjectPublicKeyInfo — its `pub` if set, otherwise the
 * point derived from its `priv`. `issuer` signs with its `priv` (for a
 * self-signed cert, pass the same key as both). SHA-256/ECDSA throughout.
 *
 * On success writes the DER to the front of `out` and sets *out_len. Returns 0,
 * or a negative errno (-EINVAL, -ENOMEM, -EIO).
 */
int certgen_build_cert(const certgen_key_t *subject, const certgen_key_t *issuer,
		       const certgen_dn_t *subject_dn, const certgen_dn_t *issuer_dn,
		       const certgen_cert_params_t *params, uint8_t *out, size_t *out_len);

/*
 * Build and self-sign a PKCS#10 CSR. `subject->priv` is required (it signs and
 * supplies the public key). `key_usage` (RFC 5280 bits, 0 = omit) becomes an
 * extensionRequest attribute, as does the optional custom extension
 * (`ext_val == NULL` omits it).
 *
 * On success writes the DER to the front of `out` and sets *out_len.
 */
int certgen_build_csr(const certgen_key_t *subject, const certgen_dn_t *subject_dn,
		      uint16_t key_usage, const uint8_t *ext_oid, size_t ext_oid_len,
		      const uint8_t *ext_val, size_t ext_val_len, uint8_t *out, size_t *out_len);

#endif /* CANTIL_CA_CERTGEN_H */
