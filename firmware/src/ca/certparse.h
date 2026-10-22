/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#ifndef CANTIL_CA_CERTPARSE_H
#define CANTIL_CA_CERTPARSE_H

/*
 * certparse — backend-independent X.509 *reader* seam.
 *
 * Step 6a of docs/roadmap/wolfssl-migration.md, and the mirror of certgen.h:
 * that one writes certificates, this one reads them. Together they are the
 * whole of ca.c's dependency on an X.509 library — which is what let mbedTLS be
 * removed from the firmware once both had a wolfCrypt implementation.
 *
 *   certparse_wolfssl.c  — the only backend: wolfCrypt's DecodedCert, plus a
 *                          chain walker written here (see the warning below).
 *                          The mbedTLS reader was removed at the end of the
 *                          migration.
 *
 * As with certgen.h, nothing in this header names a library type, and nothing
 * returns a pointer into a parsed structure — every field a caller needs is
 * copied into certparse_cert_t. That costs a few hundred bytes of struct per
 * call and removes the lifetime rules different libraries would express
 * differently.
 *
 * ── A warning about certparse_verify_chain ──────────────────────────────────
 *
 * It cannot call wolfSSL's own chain verifier: the firmware is WOLFCRYPT_ONLY,
 * and wolfSSL's chain
 * walker (wolfSSL_CertManager*) lives in the TLS layer that flag excludes —
 * src/ssl_certman.c is #include'd into ssl.c and needs a TLS method. Bringing
 * it in would add the TLS state machine to a device with no network interface.
 * So the wolfSSL backend builds the path itself on top of
 * wc_CheckCertSigPubKey.
 *
 * That is hand-written security-critical code, and the host seam
 * (libcantil/src/x509_wolfssl.c) shipped a trust-anchor bug in its first draft:
 * treating supplied intermediates as trusted rather than verifying them first.
 * Read that file's comment before touching this one.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "ca/certgen.h" /* certgen_dn_t — the same six RDNs Cantil issues */

/* Longest serial ca.c will accept out of a certificate. RFC 5280 caps serials
 * at 20 octets; 32 is slack. */
#define CERTPARSE_SERIAL_MAX 32

/* Most certificates ca.c will split out of one concatenated chain blob, anchor
 * included. Cantil chains are a leaf plus at most a couple of sub-CAs; the
 * bound exists so a malformed blob cannot drive an unbounded loop. */
#define CERTPARSE_MAX_CHAIN 8

/* Longest subject DN TLV kept. Cantil's six RDNs cap at 64 chars each, so a
 * real DN is ~200 B. */
#define CERTPARSE_SUBJECT_MAX 320

/*
 * Everything ca.c reads out of a certificate, copied.
 *
 * `dn_overflow` is not cosmetic: ca_session_cert_matches_constant treats an RDN
 * longer than the build constant could hold as a mismatch. Without this flag a
 * truncating parser would silently compare a prefix, so a subject with a padded
 * O= could match the constant it is not equal to.
 */
typedef struct {
	uint8_t serial[CERTPARSE_SERIAL_MAX];
	size_t serial_len;

	certgen_dn_t subject; /* decoded; unknown RDNs dropped */
	bool dn_overflow;     /* some RDN did not fit — treat as mismatch */

	/*
	 * The subject DN as a complete DER element — SEQUENCE tag and length
	 * included, not just the contents. The CRL encoder copies these bytes
	 * straight into the CertificateList issuer field, so the definition is
	 * load-bearing: mbedTLS's subject_raw spans the full TLV, wolfSSL's
	 * subjectRaw starts after the header, and a backend returning the
	 * contents alone would emit a malformed CRL that still looked plausible.
	 * Zero length if the DN did not fit.
	 */
	uint8_t subject_der[CERTPARSE_SUBJECT_MAX];
	size_t subject_der_len;

	uint8_t pubkey[65]; /* SEC1 uncompressed, 0x04 || X || Y */
	bool has_pubkey;    /* false if the key is not a P-256 point */

	bool self_signed; /* issuer DN equals subject DN, byte for byte */
	bool is_ca;       /* basicConstraints CA:TRUE */

	/* RFC 5280 KeyUsage bits, in the same encoding certgen_cert_params_t
	 * emits (mbedTLS MBEDTLS_X509_KU_* == wolfCrypt KEYUSE_*). 0 if the
	 * extension is absent. */
	uint16_t key_usage;

	/* notAfter, split out because that is all ca.c compares. Zeroed if the
	 * date could not be read; a caller checking a validity window must treat
	 * year == 0 as "unknown" rather than as a match. */
	uint16_t na_year;
	uint8_t na_mon;
	uint8_t na_day;

	uint8_t x25519[32]; /* the Noise static-key binding extension */
	bool has_x25519;
} certparse_cert_t;

/*
 * Parse one DER certificate. Returns 0, or -EINVAL if it is not a certificate
 * this build can read. Fields that are absent leave their `has_*` flag false
 * rather than failing the parse — a certificate with no X25519 extension is
 * perfectly valid, just not a session certificate.
 */
int certparse_cert(const uint8_t *der, size_t len, certparse_cert_t *out);

/*
 * Parse a PKCS#10 CSR, yielding its subject DN and its public key. Returns 0,
 * -EINVAL if unreadable or if the subject carries no CN.
 */
int certparse_csr(const uint8_t *der, size_t len, certgen_dn_t *subject, uint8_t pubkey[65]);

/*
 * Verify that `leaf` chains to `anchor`, optionally through intermediates
 * supplied in any order. Returns 0 on success, -EINVAL otherwise.
 *
 * Policy, identical in both backends and deliberately fixed here rather than
 * left to callers:
 *
 *   - Validity dates are NOT checked. The device has no RTC, so every
 *     certificate it issues carries a synthetic window.
 *   - Only the anchor is trusted a priori. An intermediate is used only once
 *     it has itself verified against something already trusted.
 *   - A non-leaf certificate must carry basicConstraints CA:TRUE.
 */
int certparse_verify_chain(const uint8_t *leaf_der, size_t leaf_len,
			   const uint8_t *const inter_ders[], const size_t inter_lens[],
			   size_t inter_count, const uint8_t *anchor_der, size_t anchor_len);

#endif /* CANTIL_CA_CERTPARSE_H */
