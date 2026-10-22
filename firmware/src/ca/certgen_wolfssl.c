/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * certgen.h — wolfCrypt implementation (WOLFSSL backend).
 *
 * Step 4 of docs/roadmap/wolfssl-migration.md. Where certgen_mbedtls.c builds a
 * certificate incrementally through x509write mutators, wolfCrypt fills a `Cert`
 * struct and calls wc_MakeCert / wc_SignCert (wc_MakeCertReq for a CSR). The
 * seam hides that difference: ca.c passes the same plain-C inputs to either.
 *
 * Notes on the mapping:
 *   - KeyUsage: wolfCrypt's KEYUSE_* bit values equal the RFC 5280 / mbedTLS
 *     BIT STRING encoding, so params->key_usage passes straight into
 *     cert.keyUsage.
 *   - basicConstraints: cert.basicConstSet emits the extension; cert.isCA sets
 *     CA:TRUE, and pathLen is emitted only for a CA whose keyUsage allows
 *     keyCertSign (wolfCrypt's own rule, always satisfied here). A non-CA leaf
 *     with basicConstSet emits CA:FALSE.
 *   - Validity: no RTC, so the dates are supplied pre-formatted and encoded
 *     here as a full ASN.1 time element (UTCTime < 2050, else GeneralizedTime),
 *     which is why cert generation does not need a time() backend.
 *   - Custom extension: wc_SetCustomExtension wraps the raw value in the OCTET
 *     STRING extnValue, exactly as mbedTLS did, so the X25519 binding is
 *     byte-for-byte the same shape a client already parses.
 *   - Signing: the issuer key is set deterministic (RFC 6979), matching the
 *     mbedTLS backend and crypto_sign().
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "ca/certgen.h"

/* ASN.1 UNIVERSAL time tags (wolfCrypt's internal asn.h names, inlined so this
 * file needs only the public headers). */
#define TAG_UTC_TIME         0x17
#define TAG_GENERALIZED_TIME 0x18

/* Map a wolfCrypt return (negative on error) to an errno the dispatcher uses. */
static int wc_err(int rc)
{
	if (rc >= 0) {
		return 0;
	}
	return (rc == BUFFER_E) ? -ENOMEM : -EIO;
}

/* Copy the six known RDNs into a wolfCrypt CertName. wc_InitCert already set
 * the per-field string-encoding types and zeroed the struct, so empty fields
 * are simply skipped by the encoder. */
static void fill_certname(CertName *cn, const certgen_dn_t *dn)
{
#define COPY(field, src)                                                                           \
	do {                                                                                       \
		size_t _n = strlen(src);                                                           \
		if (_n >= CTC_NAME_SIZE) {                                                         \
			_n = CTC_NAME_SIZE - 1;                                                    \
		}                                                                                  \
		memcpy((field), (src), _n);                                                        \
		(field)[_n] = '\0';                                                                \
	} while (0)
	COPY(cn->commonName, dn->cn);
	COPY(cn->org, dn->o);
	COPY(cn->unit, dn->ou);
	COPY(cn->country, dn->c);
	COPY(cn->state, dn->st);
	COPY(cn->locality, dn->l);
#undef COPY
}

/*
 * Encode a "YYYYMMDDHHMMSS" string into a full ASN.1 time element (tag, length,
 * value) as wolfCrypt's cert encoder expects in Cert.beforeDate/afterDate. RFC
 * 5280: UTCTime for years < 2050, GeneralizedTime otherwise. Returns the byte
 * count written (fits in CTC_DATE_SIZE = 32).
 */
static int encode_time(const char *t, unsigned char *out)
{
	int year = (t[0] - '0') * 1000 + (t[1] - '0') * 100 + (t[2] - '0') * 10 + (t[3] - '0');

	if (year < 2050) {
		out[0] = TAG_UTC_TIME;
		out[1] = 13;                /* "YYMMDDHHMMSSZ" */
		memcpy(out + 2, t + 2, 12); /* drop the century */
		out[14] = 'Z';
		return 15;
	}
	out[0] = TAG_GENERALIZED_TIME;
	out[1] = 15; /* "YYYYMMDDHHMMSSZ" */
	memcpy(out + 2, t, 14);
	out[16] = 'Z';
	return 17;
}

/*
 * Convert raw DER OID value octets to the dotted-decimal string
 * wc_SetCustomExtension wants (there is one such OID in Cantil, but converting
 * keeps this file honest if it changes). Returns 0 on success.
 */
static int oid_to_dotted(const uint8_t *oid, size_t len, char *out, size_t cap)
{
	if (len < 1 || cap == 0) {
		return -1;
	}

	unsigned first = oid[0];
	unsigned a = first / 40, b = first % 40;

	if (first >= 80) { /* first arc can only be 0,1,2 */
		a = 2;
		b = first - 80;
	}

	int n = snprintf(out, cap, "%u.%u", a, b);

	if (n < 0 || (size_t)n >= cap) {
		return -1;
	}
	size_t pos = (size_t)n;
	unsigned long v = 0;

	for (size_t i = 1; i < len; i++) {
		v = (v << 7) | (oid[i] & 0x7F);
		if (!(oid[i] & 0x80)) {
			n = snprintf(out + pos, cap - pos, ".%lu", v);
			if (n < 0 || (size_t)n >= cap - pos) {
				return -1;
			}
			pos += (size_t)n;
			v = 0;
		}
	}
	return 0;
}

/*
 * Import a subject key: its public point if given, else the private scalar
 * with the public point derived. wc_ecc_import_private_key_ex() with a NULL
 * public argument imports only the scalar, leaving the key public-less —
 * wc_MakeCert needs the public point for the subjectPublicKeyInfo, so compute
 * it with wc_ecc_make_pub().
 */
static int import_subject_key(const certgen_key_t *k, ecc_key *key)
{
	if (k->pub) {
		return wc_ecc_import_x963_ex(k->pub, 65, key, ECC_SECP256R1);
	}
	if (k->priv) {
		int rc = wc_ecc_import_private_key_ex(k->priv, 32, NULL, 0, key, ECC_SECP256R1);
		if (rc != 0) {
			return rc;
		}
		return wc_ecc_make_pub(key, NULL);
	}
	return BAD_FUNC_ARG;
}

/* Populate the shared Cert fields both cert and CSR paths need. */
static int prepare_cert(Cert *cert, const certgen_dn_t *subject_dn)
{
	wc_InitCert(cert);
	cert->sigType = CTC_SHA256wECDSA;
	cert->selfSigned = 0; /* the issuer is always set explicitly */
	fill_certname(&cert->subject, subject_dn);
	return 0;
}

int certgen_build_cert(const certgen_key_t *subject, const certgen_key_t *issuer,
		       const certgen_dn_t *subject_dn, const certgen_dn_t *issuer_dn,
		       const certgen_cert_params_t *params, uint8_t *out, size_t *out_len)
{
	if (!subject || !issuer || !issuer->priv || !subject_dn || !issuer_dn || !params || !out ||
	    !out_len || *out_len == 0 || params->serial_len > CTC_SERIAL_SIZE) {
		return -EINVAL;
	}

	Cert cert;
	ecc_key subj_key, iss_key;
	WC_RNG rng;
	char oidbuf[64];
	int rc, ret = -EIO;
	bool have_subj = false, have_iss = false, have_rng = false;

	if (wc_InitRng(&rng) != 0) {
		return -EIO;
	}
	have_rng = true;

	if (wc_ecc_init(&subj_key) != 0) {
		goto out;
	}
	have_subj = true;
	if (wc_ecc_init(&iss_key) != 0) {
		goto out;
	}
	have_iss = true;

	prepare_cert(&cert, subject_dn);
	fill_certname(&cert.issuer, issuer_dn);

	memcpy(cert.serial, params->serial, params->serial_len);
	cert.serialSz = (int)params->serial_len;

	cert.beforeDateSz = encode_time(params->not_before, cert.beforeDate);
	cert.afterDateSz = encode_time(params->not_after, cert.afterDate);

	if (params->emit_bc) {
		cert.basicConstSet = 1;
		if (params->is_ca) {
			cert.isCA = 1;
			if (params->path_len >= 0) {
				cert.pathLen = (byte)params->path_len;
				cert.pathLenSet = 1;
			}
		}
	}

	cert.keyUsage = params->key_usage;

	if (params->ext_val) {
		if (oid_to_dotted(params->ext_oid, params->ext_oid_len, oidbuf, sizeof(oidbuf)) !=
		    0) {
			ret = -EINVAL;
			goto out;
		}
		rc = wc_SetCustomExtension(&cert, 0 /* non-critical */, oidbuf, params->ext_val,
					   (word32)params->ext_val_len);
		if (rc != 0) {
			ret = wc_err(rc);
			goto out;
		}
	}

	rc = import_subject_key(subject, &subj_key);
	if (rc != 0) {
		ret = wc_err(rc);
		goto out;
	}
	rc = wc_ecc_import_private_key_ex(issuer->priv, 32, NULL, 0, &iss_key, ECC_SECP256R1);
	if (rc != 0) {
		ret = wc_err(rc);
		goto out;
	}

	/* Deterministic ECDSA (RFC 6979), matching crypto_sign() and the mbedTLS
	 * backend. wc_SignCert still needs an RNG for blinding. */
	(void)wc_ecc_set_deterministic_ex(&iss_key, 1, WC_HASH_TYPE_SHA256);
	(void)wc_ecc_set_rng(&iss_key, &rng);

	rc = wc_MakeCert(&cert, out, (word32)*out_len, NULL, &subj_key, &rng);
	if (rc < 0) {
		ret = wc_err(rc);
		goto out;
	}
	rc = wc_SignCert(cert.bodySz, cert.sigType, out, (word32)*out_len, NULL, &iss_key, &rng);
	if (rc < 0) {
		ret = wc_err(rc);
		goto out;
	}

	*out_len = (size_t)rc;
	ret = 0;

out:
	if (have_iss) {
		wc_ecc_free(&iss_key);
	}
	if (have_subj) {
		wc_ecc_free(&subj_key);
	}
	if (have_rng) {
		wc_FreeRng(&rng);
	}
	return ret;
}

int certgen_build_csr(const certgen_key_t *subject, const certgen_dn_t *subject_dn,
		      uint16_t key_usage, const uint8_t *ext_oid, size_t ext_oid_len,
		      const uint8_t *ext_val, size_t ext_val_len, uint8_t *out, size_t *out_len)
{
	if (!subject || !subject->priv || !subject_dn || !out || !out_len || *out_len == 0) {
		return -EINVAL;
	}

	Cert cert;
	ecc_key key;
	WC_RNG rng;
	char oidbuf[64];
	int rc, ret = -EIO;
	bool have_key = false, have_rng = false;

	if (wc_InitRng(&rng) != 0) {
		return -EIO;
	}
	have_rng = true;
	if (wc_ecc_init(&key) != 0) {
		goto out;
	}
	have_key = true;

	prepare_cert(&cert, subject_dn);
	cert.version = 0; /* PKCS#10 CertificationRequestInfo version is v1 (0) */

	if (key_usage) {
		cert.keyUsage = key_usage;
	}

	if (ext_val) {
		if (oid_to_dotted(ext_oid, ext_oid_len, oidbuf, sizeof(oidbuf)) != 0) {
			ret = -EINVAL;
			goto out;
		}
		rc = wc_SetCustomExtension(&cert, 0 /* non-critical */, oidbuf, ext_val,
					   (word32)ext_val_len);
		if (rc != 0) {
			ret = wc_err(rc);
			goto out;
		}
	}

	/* import_subject_key imports the scalar and derives the public point,
	 * which wc_MakeCertReq needs for the CSR's subjectPublicKeyInfo; the
	 * scalar remains for signing. */
	rc = import_subject_key(subject, &key);
	if (rc != 0) {
		ret = wc_err(rc);
		goto out;
	}
	(void)wc_ecc_set_deterministic_ex(&key, 1, WC_HASH_TYPE_SHA256);
	(void)wc_ecc_set_rng(&key, &rng);

	rc = wc_MakeCertReq(&cert, out, (word32)*out_len, NULL, &key);
	if (rc < 0) {
		ret = wc_err(rc);
		goto out;
	}
	rc = wc_SignCert(cert.bodySz, cert.sigType, out, (word32)*out_len, NULL, &key, &rng);
	if (rc < 0) {
		ret = wc_err(rc);
		goto out;
	}

	*out_len = (size_t)rc;
	ret = 0;

out:
	if (have_key) {
		wc_ecc_free(&key);
	}
	if (have_rng) {
		wc_FreeRng(&rng);
	}
	return ret;
}
