/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#ifndef CANTIL_TEST_PKI_H
#define CANTIL_TEST_PKI_H

/*
 * Test-side PKI generation, built on the firmware's own seams.
 *
 * The ztest suites used to mint their CSRs and synthetic anchors with
 * mbedTLS's x509write API — a second implementation, which is what made
 * "wolfCrypt ca.c parsed an mbedTLS-written CSR" a real cross-check. That
 * cross-check moved to the OpenSSL gate (scripts/openssl_gate.sh) when the
 * mbedTLS backend was removed, and the suites need a certificate/CSR *writer*
 * that does not pull mbedTLS back in.
 *
 * These helpers use certgen.h (the wolfCrypt writer the firmware itself ships)
 * plus crypto_keygen(), so a suite links no library the firmware does not. The
 * independent oracle is no longer "the other library parsed it" — it is
 * openssl parsing the generated artifact, so a suite that generates
 * certificates should also hand them to the gate via test_artifacts.h.
 *
 * DN inputs are certgen_dn_t (structured), not RFC 4514 strings: certgen and
 * certparse both speak the same six RDNs, and a string parser would be one
 * more thing to keep in step with them.
 */

#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "crypto/crypto.h"
#include "ca/certgen.h"

/* Fresh P-256 keypair: priv[32] scalar, pub[65] SEC1 uncompressed. */
static inline int test_pki_keypair(uint8_t priv[32], uint8_t pub[65])
{
	size_t pl = 32;
	int rc = crypto_keygen(priv, &pl);

	if (rc || pl != 32) {
		return rc ? rc : -EIO;
	}

	size_t ql = 65;

	rc = crypto_pubkey_from_privkey(priv, 32, pub, &ql);
	if (rc || ql != 65) {
		return rc ? rc : -EIO;
	}
	return 0;
}

/* Populate a certgen_dn_t with just a CN — the common case in these suites. */
static inline certgen_dn_t test_pki_dn_cn(const char *cn)
{
	certgen_dn_t dn = {0};

	strncpy(dn.cn, cn, sizeof(dn.cn) - 1);
	return dn;
}

/*
 * Build a PKCS#10 CSR over a fresh key for `dn`. Writes DER to out/out_len; if
 * priv_out is non-NULL, the 32-byte private scalar is copied there so the
 * caller can later act as this subject (e.g. build a chain under it).
 */
static inline int test_pki_csr(const certgen_dn_t *dn, uint8_t *out, size_t *out_len,
			       uint8_t priv_out[32])
{
	uint8_t priv[32], pub[65];
	int rc = test_pki_keypair(priv, pub);

	if (rc) {
		return rc;
	}

	/*
	 * priv only, pub NULL: certgen imports the scalar and derives the point,
	 * keeping the scalar to self-sign the CSR. Supplying pub would make it
	 * import the public key alone, and the CSR would have no signing key.
	 */
	certgen_key_t key = {.priv = priv, .pub = NULL};

	rc = certgen_build_csr(&key, dn, 0, NULL, 0, NULL, 0, out, out_len);
	if (rc == 0 && priv_out) {
		memcpy(priv_out, priv, 32);
	}
	return rc;
}

/* CN-only convenience over test_pki_csr(). */
static inline int test_pki_csr_cn(const char *cn, uint8_t *out, size_t *out_len,
				  uint8_t priv_out[32])
{
	certgen_dn_t dn = test_pki_dn_cn(cn);

	return test_pki_csr(&dn, out, out_len, priv_out);
}

/*
 * Build a self-signed certificate over a fresh key. With is_ca set it is a CA
 * (basicConstraints CA:TRUE, keyCertSign|cRLSign) — a synthetic external
 * anchor; without it, a plain end-entity leaf, e.g. the "some unknown CA"
 * cert the pairing trust-tier tests expect to be rejected. Serial is fixed
 * (0x01); validity is a wide fixed window, since the device checks neither.
 * priv_out receives the private scalar if non-NULL.
 */
static inline int test_pki_self_signed(const certgen_dn_t *dn, bool is_ca, uint8_t *out,
				       size_t *out_len, uint8_t priv_out[32])
{
	uint8_t priv[32], pub[65];
	int rc = test_pki_keypair(priv, pub);

	if (rc) {
		return rc;
	}

	certgen_key_t key = {.priv = priv, .pub = pub};
	static const uint8_t serial[] = {0x01};
	certgen_cert_params_t p = {
		.serial = serial,
		.serial_len = sizeof(serial),
		.not_before = "20200101000000",
		.not_after = "20400101000000",
		.emit_bc = is_ca,
		.is_ca = is_ca,
		.path_len = -1,
		.key_usage = is_ca ? (CERTGEN_KU_KEY_CERT_SIGN | CERTGEN_KU_CRL_SIGN)
				   : CERTGEN_KU_DIGITAL_SIGNATURE,
	};

	rc = certgen_build_cert(&key, &key, dn, dn, &p, out, out_len);
	if (rc == 0 && priv_out) {
		memcpy(priv_out, priv, 32);
	}
	return rc;
}

#endif /* CANTIL_TEST_PKI_H */
