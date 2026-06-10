/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/oid.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/platform_util.h>

#if defined(CONFIG_CANTIL_CRYPTO_BACKEND_ACCELERATED)
#include <psa/crypto.h>
#endif

#include "ca.h"
#include "crypto/crypto.h"
#include "storage/storage.h"
#include "cantil_cbor.h"

LOG_MODULE_REGISTER(ca, LOG_LEVEL_INF);

#define CA_SLOT          0
#define KEY_BLOB_MAX     128   /* 12 nonce + 32 ct + 16 tag = 60; round up */
#define CERT_DER_MAX     2048
#define X509_DATA_MAX    512
#define DN_MAX           256

/* Default validity for SIGN_CSR-issued certs (no client-side override yet). */
#define SIGN_CSR_VALIDITY_DAYS 365

/* Synthetic not-before epoch matching NOT_BEFORE_BASE = "20260101000000".
 * Unix timestamp for 2026-01-01 00:00:00 UTC. Used to populate meta
 * timestamps at sign time so AUTO_EXPIRE has something to compare against. */
#define SIGN_CSR_NOT_BEFORE_UNIX  ((uint64_t)1767225600)

/*
 * Per-issued-cert metadata. Wire layout has been v2 since task 2 of the CRL
 * work; v1 readers are tolerated (revoked_at_unix + revocation_reason both
 * implicitly zero). Packed, v2 = 116 bytes (v1 was 108).
 *
 * v1 → v2 differences:
 *   - reserved0 (byte at offset 3) repurposed as revocation_reason
 *     (RFC 5280 §5.3.1 CRLReason enum, default 0 = unspecified)
 *   - trailing uint64 revoked_at_unix appended
 */
#define ISSUED_META_VERSION   2
#define ISSUED_META_V1_SIZE   108
typedef struct __attribute__((packed)) {
	uint8_t  version;          /* 2 (new writes); 1 still accepted on read */
	uint8_t  flags;            /* bit0=revoked, bit1=protected, bit2=expired */
	uint8_t  serial_len;       /* 1..20 */
	uint8_t  revocation_reason;/* RFC 5280 CRLReason; 0=unspecified, only
				    * meaningful when flags & ISSUED_FLAG_REVOKED */
	uint32_t issuer_slot;      /* host byte order; native_sim & ARM both LE */
	uint64_t not_before_unix;  /* 0 if unknown (no RTC) */
	uint64_t not_after_unix;
	uint8_t  serial[20];       /* RFC 5280 max 20 octets */
	char     cn[64];           /* null-terminated, truncated if longer */
	uint64_t revoked_at_unix;  /* v2; 0 = unknown (caller didn't supply) */
} issued_cert_meta_t;
BUILD_ASSERT(sizeof(issued_cert_meta_t) == 116, "issued_cert_meta_t v2 layout");

#define ISSUED_FLAG_REVOKED   0x01
#define ISSUED_FLAG_PROTECTED 0x02
#define ISSUED_FLAG_EXPIRED   0x04

/*
 * Read the issued-cert meta into `out`, tolerating v1 on-disk blobs by
 * zero-filling the v2-only tail. Returns the storage layer's errno on read
 * failure, -EINVAL on version mismatch or truncated blob.
 */
static int read_issued_meta(const uint8_t *serial, size_t serial_len,
			    issued_cert_meta_t *out)
{
	uint8_t buf[sizeof(issued_cert_meta_t) + 8];
	size_t  buf_len = sizeof(buf);
	int rc = storage_issued_meta_read(serial, serial_len, buf, &buf_len);

	if (rc) return rc;
	if (buf_len < 1) return -EINVAL;

	if (buf[0] == ISSUED_META_VERSION) {
		if (buf_len < sizeof(issued_cert_meta_t)) return -EINVAL;
		memcpy(out, buf, sizeof(*out));
		return 0;
	}
	if (buf[0] == 1) {
		if (buf_len < ISSUED_META_V1_SIZE) return -EINVAL;
		memset(out, 0, sizeof(*out));
		memcpy(out, buf, ISSUED_META_V1_SIZE);
		/* v1 had no revocation_reason; the byte at offset 3 was
		 * `reserved0` and may be nonzero garbage. Zero it. */
		out->revocation_reason = 0;
		out->version = ISSUED_META_VERSION;  /* in-memory upgrade */
		return 0;
	}
	return -EINVAL;
}

/*
 * Per-slot meta blob (24 bytes, packed).  Version 1.  Fields beyond `version`
 * are tied to that version; bump on layout change.
 */
typedef struct __attribute__((packed)) {
	uint8_t  version;          /* 1 */
	uint8_t  key_type;         /* 1 = P-256 */
	uint8_t  is_protected;     /* 0 / 1 */
	uint8_t  protect_issued;   /* 0 / 1 */
	uint32_t flags;            /* reserved, 0 */
	uint64_t created_unix;     /* 0 if no RTC */
	uint8_t  reserved[8];
} slot_meta_t;
BUILD_ASSERT(sizeof(slot_meta_t) == 24, "slot_meta_t layout");

#define KEY_TYPE_P256 1

/* mbedtls f_rng callback signature.  See crypto.c — same TRNG wrapped here. */
extern int crypto_trng(uint8_t *buf, size_t len);

static int rng_cb(void *ctx, unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);
	return crypto_trng(buf, len) ? -1 : 0;
}

static bool provisioned;

/* ── meta helpers ──────────────────────────────────────────────────────── */

static int meta_read(uint32_t slot, slot_meta_t *m)
{
	uint8_t buf[sizeof(slot_meta_t)];
	size_t len = sizeof(buf);
	int ret = storage_slot_meta_read(slot, buf, &len);

	if (ret) {
		return ret;
	}
	if (len != sizeof(slot_meta_t) || buf[0] != 1) {
		return -EINVAL;
	}
	memcpy(m, buf, sizeof(slot_meta_t));
	return 0;
}

static int meta_write(uint32_t slot, const slot_meta_t *m)
{
	return storage_slot_meta_write(slot, (const uint8_t *)m, sizeof(*m));
}

/* ── key load ──────────────────────────────────────────────────────────── */

static int load_slot_privkey(uint32_t slot, uint8_t *privkey, size_t *privkey_len)
{
	uint8_t storage_key[32];
	int ret = crypto_storage_key_derive(storage_key);

	if (ret) {
		return ret;
	}

	uint8_t blob[KEY_BLOB_MAX];
	size_t blob_len = sizeof(blob);

	ret = storage_key_read(slot, blob, &blob_len);
	if (ret) {
		mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
		return ret;
	}

	ret = crypto_decrypt_blob(storage_key, blob, blob_len, privkey, privkey_len);
	mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
	mbedtls_platform_zeroize(blob, sizeof(blob));
	return ret;
}

/* ── slot PK context ───────────────────────────────────────────────────────
 *
 * Wraps the load-32B-priv-scalar-into-a-PK-context dance several call sites
 * share. FREE backend = mbedtls_pk_setup(MBEDTLS_PK_ECKEY) + mpi_read +
 * ecp_mul. ACCELERATED backend = psa_import_key (volatile P-256 keypair) +
 * mbedtls_pk_setup_opaque, so downstream x509 writers and mbedtls_pk_sign
 * dispatch through PSA (and CC3XX where supported). slot_pk_free destroys
 * the underlying PSA key on the opaque path (mbedtls 3.x behaviour).
 */
struct slot_pk {
	mbedtls_pk_context pk;
};

static void slot_pk_init(struct slot_pk *sp)
{
	mbedtls_pk_init(&sp->pk);
}

static void slot_pk_free(struct slot_pk *sp)
{
	mbedtls_pk_free(&sp->pk);
}

static int slot_pk_load_priv(const uint8_t *priv, size_t priv_len,
					    struct slot_pk *sp)
{
	if (priv_len != 32) {
		return -EINVAL;
	}
#if defined(CONFIG_CANTIL_CRYPTO_BACKEND_ACCELERATED)
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr,
			      PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	psa_status_t st = psa_import_key(&attr, priv, priv_len, &kid);

	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	int rc = mbedtls_pk_setup_opaque(&sp->pk, kid);

	if (rc) {
		(void)psa_destroy_key(kid);
		return rc;
	}
	return 0;
#else
	int rc = mbedtls_pk_setup(&sp->pk,
				  mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

	if (rc) {
		return rc;
	}

	mbedtls_ecp_keypair *kp = mbedtls_pk_ec(sp->pk);

	rc = mbedtls_ecp_group_load(&kp->MBEDTLS_PRIVATE(grp),
				    MBEDTLS_ECP_DP_SECP256R1);
	if (rc) {
		return rc;
	}
	rc = mbedtls_mpi_read_binary(&kp->MBEDTLS_PRIVATE(d), priv, priv_len);
	if (rc) {
		return rc;
	}
	return mbedtls_ecp_mul(&kp->MBEDTLS_PRIVATE(grp),
			       &kp->MBEDTLS_PRIVATE(Q),
			       &kp->MBEDTLS_PRIVATE(d),
			       &kp->MBEDTLS_PRIVATE(grp).G,
			       rng_cb, NULL);
#endif
}

/* Load a 65-byte SEC1 uncompressed pubkey (0x04 || X || Y) into a PK
 * context so x509 writers can embed it as subjectPublicKeyInfo. Used by
 * ca_sign_key_slot for the subject side. */
static int slot_pk_load_pub(const uint8_t pub[65],
					   struct slot_pk *sp)
{
	if (pub[0] != 0x04) {
		return -EINVAL;
	}
#if defined(CONFIG_CANTIL_CRYPTO_BACKEND_ACCELERATED)
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attr,
			      PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	psa_status_t st = psa_import_key(&attr, pub, 65, &kid);

	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	int rc = mbedtls_pk_setup_opaque(&sp->pk, kid);

	if (rc) {
		(void)psa_destroy_key(kid);
		return rc;
	}
	return 0;
#else
	int rc = mbedtls_pk_setup(&sp->pk,
				  mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

	if (rc) {
		return rc;
	}

	mbedtls_ecp_keypair *kp = mbedtls_pk_ec(sp->pk);

	rc = mbedtls_ecp_group_load(&kp->MBEDTLS_PRIVATE(grp),
				    MBEDTLS_ECP_DP_SECP256R1);
	if (rc) {
		return rc;
	}
	return mbedtls_ecp_point_read_binary(&kp->MBEDTLS_PRIVATE(grp),
					     &kp->MBEDTLS_PRIVATE(Q),
					     pub, 65);
#endif
}

/* ── x509 data parsing ─────────────────────────────────────────────────── */

/*
 * X.509 key-usage bit values follow the ASN.1 BIT STRING encoding (RFC 5280
 * §4.2.1.3): bit 0 is the high-order bit of the first octet.  mbedtls uses
 * the same numbering (see MBEDTLS_X509_KU_* in mbedtls/x509.h), so passing
 * a naive 1u<<N here would silently emit the wrong extension bits.
 */
#define KU_DIGITAL_SIGNATURE 0x0080  /* bit 0 */
#define KU_KEY_CERT_SIGN     0x0004  /* bit 5 */
#define KU_CRL_SIGN          0x0002  /* bit 6 */

typedef struct {
	uint16_t validity_days;
	uint8_t  is_ca;
	uint8_t  path_len;        /* 0xFF = unconstrained */
	uint16_t key_usage;
	char     cn[65];
	char     o[65];
	char     ou[65];
	char     c[3];
	char     st[65];
	char     l[65];
} x509_params_t;

/* Consume a single [len(1)][bytes(len)] string field. */
static int parse_str_field(const uint8_t **pp, const uint8_t *end,
			   char *out, size_t cap)
{
	if (*pp >= end) {
		return -EINVAL;
	}
	uint8_t n = **pp;
	(*pp)++;

	if (n >= cap || (*pp) + n > end) {
		return -EINVAL;
	}
	memcpy(out, *pp, n);
	out[n] = '\0';
	*pp += n;
	return 0;
}

static int x509_parse(const uint8_t *data, size_t len, x509_params_t *p)
{
	if (len < 6) {
		return -EINVAL;
	}
	const uint8_t *cur = data;
	const uint8_t *end = data + len;

	memset(p, 0, sizeof(*p));
	p->validity_days = ((uint16_t)cur[0] << 8) | cur[1];
	p->is_ca         = cur[2];
	p->path_len      = cur[3];
	p->key_usage     = ((uint16_t)cur[4] << 8) | cur[5];
	cur += 6;

	if (parse_str_field(&cur, end, p->cn,  sizeof(p->cn))  ||
	    parse_str_field(&cur, end, p->o,   sizeof(p->o))   ||
	    parse_str_field(&cur, end, p->ou,  sizeof(p->ou))  ||
	    parse_str_field(&cur, end, p->c,   sizeof(p->c))   ||
	    parse_str_field(&cur, end, p->st,  sizeof(p->st))  ||
	    parse_str_field(&cur, end, p->l,   sizeof(p->l))) {
		return -EINVAL;
	}

	if (p->cn[0] == '\0' || p->validity_days == 0) {
		return -EINVAL;
	}
	if (p->c[0] != '\0' && strlen(p->c) != 2) {
		return -EINVAL;
	}
	return 0;
}

/* Build an RFC 4514 DN string from the parsed params: "CN=…, O=…, …". */
static int build_dn(const x509_params_t *p, char *out, size_t cap)
{
	int n;
	size_t off = 0;

	n = snprintf(out + off, cap - off, "CN=%s", p->cn);
	if (n < 0 || (size_t)n >= cap - off) {
		return -EINVAL;
	}
	off += n;

#define APPEND(tag, val) do {                                          \
	if ((val)[0] != '\0') {                                        \
		n = snprintf(out + off, cap - off, ",%s=%s", tag, val);\
		if (n < 0 || (size_t)n >= cap - off) {                 \
			return -EINVAL;                                \
		}                                                      \
		off += n;                                              \
	}                                                              \
} while (0)
	APPEND("O",  p->o);
	APPEND("OU", p->ou);
	APPEND("C",  p->c);
	APPEND("ST", p->st);
	APPEND("L",  p->l);
#undef APPEND
	return 0;
}

/*
 * No RTC: use a fixed not-before baseline (matches the firmware build epoch
 * conceptually) and compute not-after = not-before + validity_days.  When a
 * host-provided wall clock arrives in a later command, this becomes a TODO
 * to back-fill real timestamps.
 */
#define NOT_BEFORE_BASE  "20260101000000"
#define SECS_PER_DAY     86400

static void compute_not_after(uint16_t validity_days, char out[15])
{
	/* mbedtls accepts any monotonically-correct YYYYMMDDHHMMSS string.
	 * Since we have no RTC and not_before is fixed, we just bump the day
	 * field within a fixed year for tiny windows, otherwise step the year.
	 * Good enough for bootstrap; revisit once AUTO_EXPIRE wall-clock lands.
	 */
	uint32_t total_days = validity_days;
	uint32_t years = total_days / 365;
	uint32_t rem_days = total_days % 365;

	uint32_t year = 2026 + years;
	uint32_t month = 1 + (rem_days / 30);
	uint32_t day = 1 + (rem_days % 30);

	if (month > 12) {
		month = 12;
	}
	if (day > 28) {
		day = 28;  /* safe for any month */
	}
	snprintf(out, 15, "%04u%02u%02u000000", year, month, day);
}

/* ── self-signed cert builder ──────────────────────────────────────────── */

/*
 * Build a self-signed X.509 certificate for `slot` using the stored privkey
 * and the supplied params.  Writes cert.der into the slot on success.
 */
static int build_self_signed_cert(uint32_t slot, const x509_params_t *p)
{
	uint8_t privkey[32];
	size_t  privkey_len = sizeof(privkey);
	int rc;

	if (slot >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
		return -EINVAL;
	}
	rc = load_slot_privkey(slot, privkey, &privkey_len);
	if (rc || privkey_len != 32) {
		LOG_ERR("load_slot_privkey=%d", rc);
		return rc ? rc : -EIO;
	}

	struct slot_pk sp;
	mbedtls_x509write_cert crt;
	uint8_t serial[8];
	char dn[DN_MAX];
	char not_after[15];

	slot_pk_init(&sp);
	mbedtls_x509write_crt_init(&crt);

	rc = slot_pk_load_priv(privkey, privkey_len, &sp);
	if (rc) {
		goto out;
	}

	rc = build_dn(p, dn, sizeof(dn));
	if (rc) {
		goto out;
	}

	rc = mbedtls_x509write_crt_set_subject_name(&crt, dn);
	if (rc) {
		goto out;
	}
	rc = mbedtls_x509write_crt_set_issuer_name(&crt, dn);
	if (rc) {
		goto out;
	}

	mbedtls_x509write_crt_set_subject_key(&crt, &sp.pk);
	mbedtls_x509write_crt_set_issuer_key(&crt, &sp.pk);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

	rc = crypto_trng(serial, sizeof(serial));
	if (rc) {
		goto out;
	}
	serial[0] = (serial[0] & 0x7F) | 0x01;  /* positive ASN.1 INTEGER, non-zero */
#if defined(MBEDTLS_X509_CRT_VERSION_3)
	rc = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
#else
	rc = -ENOTSUP;
#endif
	if (rc) {
		goto out;
	}

	compute_not_after(p->validity_days, not_after);
	rc = mbedtls_x509write_crt_set_validity(&crt, NOT_BEFORE_BASE, not_after);
	if (rc) {
		goto out;
	}

	if (p->is_ca) {
		int path = (p->path_len == 0xFF) ? -1 : p->path_len;
		rc = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, path);
		if (rc) {
			goto out;
		}
	}

	uint16_t ku = p->key_usage;

	if (p->is_ca) {
		/* Always sensible for a CA. */
		ku |= KU_KEY_CERT_SIGN | KU_CRL_SIGN;
	}
	if (ku) {
		rc = mbedtls_x509write_crt_set_key_usage(&crt, ku);
		if (rc) {
			goto out;
		}
	}

	/* Subject/authority key identifiers require SHA-1 in mbedtls; skipped. */

	uint8_t der[CERT_DER_MAX];
	int n = mbedtls_x509write_crt_der(&crt, der, sizeof(der), rng_cb, NULL);

	if (n < 0) {
		LOG_ERR("x509write_crt_der=%d", n);
		rc = -EIO;
		goto out;
	}

	/* mbedtls writes DER at the END of the buffer; cert bytes start at der+(sizeof(der)-n). */
	rc = storage_slot_cert_write(slot, der + sizeof(der) - n, n);
	if (rc) {
		LOG_ERR("storage_slot_cert_write=%d", rc);
		goto out;
	}
	LOG_INF("slot %u: self-signed cert written (%d bytes)", slot, n);

out:
	mbedtls_platform_zeroize(privkey, sizeof(privkey));
	mbedtls_x509write_crt_free(&crt);
	slot_pk_free(&sp);
	return rc;
}

/* ── session-slot identity cert builder ────────────────────────────────────
 *
 * Transport + pairing T-02. The session slot (/session/) is NOT a /keys/<n>/
 * slot, so it can't go through build_self_signed_cert (which loads the privkey
 * from a numbered slot and writes the DER straight back into that slot). This
 * variant takes the P-256 identity privkey and the params blob directly and
 * emits the DER into a caller buffer. It also binds the 32-byte X25519 Noise
 * static pubkey into a private-OID extension so a client validating the cert
 * can confirm it attests to the same static key the Noise handshake used.
 */

/*
 * 1.3.6.1.4.1.58270.1.1 — Cantil enterprise arc (placeholder PEN 58270),
 * .1.1 = session Noise X25519-key binding.  Non-critical; extnValue is an
 * OCTET STRING wrapping the raw 32-byte little-endian X25519 public key
 * (mbedtls_x509write_crt_set_extension wraps the value in the OCTET STRING).
 * Replace the arc with a real IANA-assigned PEN before distribution.
 */
static const uint8_t OID_SESSION_X25519[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xc7, 0x1e, 0x01, 0x01
};

int ca_build_session_cert(const uint8_t *x509_blob, size_t blob_len,
			  const char *cn_override,
			  const uint8_t id_priv[32],
			  const uint8_t x25519_pub[32],
			  uint8_t *out, size_t *out_len)
{
	x509_params_t p;
	int rc = x509_parse(x509_blob, blob_len, &p);

	if (rc) {
		return rc;
	}
	if (p.is_ca) {
		/* The transport identity must never be a CA. */
		return -EINVAL;
	}
	if (cn_override != NULL && cn_override[0] != '\0') {
		size_t n = strlen(cn_override);

		if (n >= sizeof(p.cn)) {
			return -EINVAL;
		}
		memcpy(p.cn, cn_override, n + 1);
	}

	struct slot_pk sp;
	mbedtls_x509write_cert crt;
	uint8_t serial[8];
	char dn[DN_MAX];
	char not_after[15];

	slot_pk_init(&sp);
	mbedtls_x509write_crt_init(&crt);

	rc = slot_pk_load_priv(id_priv, 32, &sp);
	if (rc) {
		goto out;
	}

	rc = build_dn(&p, dn, sizeof(dn));
	if (rc) {
		goto out;
	}
	rc = mbedtls_x509write_crt_set_subject_name(&crt, dn);
	if (rc) {
		goto out;
	}
	rc = mbedtls_x509write_crt_set_issuer_name(&crt, dn);
	if (rc) {
		goto out;
	}

	mbedtls_x509write_crt_set_subject_key(&crt, &sp.pk);
	mbedtls_x509write_crt_set_issuer_key(&crt, &sp.pk);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

	rc = crypto_trng(serial, sizeof(serial));
	if (rc) {
		goto out;
	}
	serial[0] = (serial[0] & 0x7F) | 0x01;  /* positive, non-zero INTEGER */
	rc = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
	if (rc) {
		goto out;
	}

	compute_not_after(p.validity_days, not_after);
	rc = mbedtls_x509write_crt_set_validity(&crt, NOT_BEFORE_BASE, not_after);
	if (rc) {
		goto out;
	}

	/* KU comes straight from the build constant (digitalSignature +
	 * keyAgreement); is_ca is already rejected above, so no cert-sign bits. */
	if (p.key_usage) {
		rc = mbedtls_x509write_crt_set_key_usage(&crt, p.key_usage);
		if (rc) {
			goto out;
		}
	}

	rc = mbedtls_x509write_crt_set_extension(&crt,
				(const char *)OID_SESSION_X25519,
				sizeof(OID_SESSION_X25519),
				0 /* non-critical */,
				x25519_pub, 32);
	if (rc) {
		goto out;
	}

	uint8_t der[CERT_DER_MAX];
	int n = mbedtls_x509write_crt_der(&crt, der, sizeof(der), rng_cb, NULL);

	if (n < 0) {
		LOG_ERR("session x509write_crt_der=%d", n);
		rc = -EIO;
		goto out;
	}
	if ((size_t)n > *out_len) {
		rc = -ENOMEM;
		goto out;
	}
	/* mbedtls writes DER at the END of the buffer. */
	memcpy(out, der + sizeof(der) - n, n);
	*out_len = (size_t)n;
	rc = 0;

out:
	mbedtls_x509write_crt_free(&crt);
	slot_pk_free(&sp);
	return rc;
}

int ca_build_session_csr(const uint8_t *x509_blob, size_t blob_len,
			 const char *cn_override,
			 const uint8_t id_priv[32],
			 const uint8_t x25519_pub[32],
			 uint8_t *out, size_t *out_len)
{
	x509_params_t p;
	int rc = x509_parse(x509_blob, blob_len, &p);

	if (rc) {
		return rc;
	}
	if (p.is_ca) {
		/* The transport identity must never be a CA. */
		return -EINVAL;
	}
	if (cn_override != NULL && cn_override[0] != '\0') {
		size_t n = strlen(cn_override);

		if (n >= sizeof(p.cn)) {
			return -EINVAL;
		}
		memcpy(p.cn, cn_override, n + 1);
	}

	struct slot_pk sp;
	mbedtls_x509write_csr req;
	char dn[DN_MAX];

	slot_pk_init(&sp);
	mbedtls_x509write_csr_init(&req);

	rc = slot_pk_load_priv(id_priv, 32, &sp);
	if (rc) {
		goto out;
	}

	rc = build_dn(&p, dn, sizeof(dn));
	if (rc) {
		goto out;
	}
	rc = mbedtls_x509write_csr_set_subject_name(&req, dn);
	if (rc) {
		rc = -EINVAL;
		goto out;
	}

	mbedtls_x509write_csr_set_key(&req, &sp.pk);
	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);

	if (p.key_usage) {
		rc = mbedtls_x509write_csr_set_key_usage(&req,
				(unsigned char)(p.key_usage & 0xFF));
		if (rc) {
			rc = -EINVAL;
			goto out;
		}
	}

	/* Carry the Noise X25519 static key as an extensionRequest so an
	 * upstream CA can copy it into the issued cert's extension, matching
	 * the self-signed cert built by ca_build_session_cert(). */
	rc = mbedtls_x509write_csr_set_extension(&req,
				(const char *)OID_SESSION_X25519,
				sizeof(OID_SESSION_X25519),
				0 /* non-critical */,
				x25519_pub, 32);
	if (rc) {
		rc = -EIO;
		goto out;
	}

	/*
	 * Write straight into the caller's buffer — it is the dispatcher's 4 KB
	 * response scratch, far larger than any P-256 CSR. A local
	 * der[CERT_DER_MAX] here would stack a second 2 KB buffer on top of that
	 * scratch and overflow the main thread's stack while signing (the CSR is
	 * built live in the dispatcher call chain, unlike the cert which is built
	 * once at first boot). mbedtls writes the DER at the END of the buffer,
	 * so shift it to the front afterwards.
	 */
	int n = mbedtls_x509write_csr_der(&req, out, *out_len, rng_cb, NULL);

	if (n < 0) {
		LOG_ERR("session x509write_csr_der=%d", n);
		rc = -EIO;
		goto out;
	}
	memmove(out, out + *out_len - n, (size_t)n);
	*out_len = (size_t)n;
	rc = 0;

out:
	mbedtls_x509write_csr_free(&req);
	slot_pk_free(&sp);
	return rc;
}

int ca_session_cert_matches_constant(const uint8_t *cert_der, size_t cert_len,
				     const uint8_t *x509_blob, size_t blob_len)
{
	x509_params_t want;
	int rc = x509_parse(x509_blob, blob_len, &want);

	if (rc) {
		return rc;
	}

	mbedtls_x509_crt crt;

	mbedtls_x509_crt_init(&crt);
	rc = mbedtls_x509_crt_parse_der(&crt, cert_der, cert_len);
	if (rc) {
		mbedtls_x509_crt_free(&crt);
		return -EINVAL;
	}

	int match = 1;

	/* A CA-signed cert (issuer != subject) carries the CA's validity window,
	 * not the device's synthetic constant.  Skip not_after for those; the
	 * chain-signature gate in T-07 already verified trust. */
	bool ca_signed = (crt.issuer_raw.len != crt.subject_raw.len) ||
			 (memcmp(crt.issuer_raw.p, crt.subject_raw.p,
				 crt.subject_raw.len) != 0);

	/*
	 * Subject DN fields. CN is FICR-derived per device, so it is collected
	 * but never compared; everything else must match the build constant.
	 */
	char o[65] = "", ou[65] = "", c[3] = "", st[65] = "", l[65] = "";

	for (const mbedtls_x509_name *n = &crt.subject; n != NULL; n = n->next) {
		char  *dst = NULL;
		size_t cap = 0;

		if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_ORGANIZATION, &n->oid) == 0) {
			dst = o;  cap = sizeof(o);
		} else if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_ORG_UNIT, &n->oid) == 0) {
			dst = ou; cap = sizeof(ou);
		} else if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_COUNTRY, &n->oid) == 0) {
			dst = c;  cap = sizeof(c);
		} else if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_STATE, &n->oid) == 0) {
			dst = st; cap = sizeof(st);
		} else if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_LOCALITY, &n->oid) == 0) {
			dst = l;  cap = sizeof(l);
		} else {
			continue;  /* CN and any unexpected RDN: ignored */
		}

		if (n->val.len >= cap) {
			match = 0;  /* longer than the constant could ever hold */
			break;
		}
		memcpy(dst, n->val.p, n->val.len);
		dst[n->val.len] = '\0';
	}

	if (match &&
	    (strcmp(o,  want.o)  != 0 || strcmp(ou, want.ou) != 0 ||
	     strcmp(c,  want.c)  != 0 || strcmp(st, want.st) != 0 ||
	     strcmp(l,  want.l)  != 0)) {
		match = 0;
	}

	/* key_usage: mbedtls parses KU into the same MBEDTLS_X509_KU_* bit values
	 * the packed constant uses, so a direct compare on the low 16 bits holds. */
	if (match && (crt.MBEDTLS_PRIVATE(key_usage) & 0xFFFFu) != want.key_usage) {
		match = 0;
	}

	/* Validity window: for self-signed certs not_after must match the
	 * constant exactly (captures validity_days drift in the build TOML).
	 * CA-signed certs use the issuing CA's window — skip the comparison. */
	if (match && !ca_signed) {
		char na[15];

		compute_not_after(want.validity_days, na);  /* "YYYYMMDD000000" */

		int yy = (na[0] - '0') * 1000 + (na[1] - '0') * 100 +
			 (na[2] - '0') * 10   + (na[3] - '0');
		int mo = (na[4] - '0') * 10 + (na[5] - '0');
		int dd = (na[6] - '0') * 10 + (na[7] - '0');

		if (crt.valid_to.year != yy || crt.valid_to.mon != mo ||
		    crt.valid_to.day  != dd) {
			match = 0;
		}
	}

	mbedtls_x509_crt_free(&crt);
	return match;
}

/* ── public API ────────────────────────────────────────────────────────── */

int ca_init(void)
{
	uint8_t blob[KEY_BLOB_MAX];
	size_t blob_len = sizeof(blob);
	int ret = storage_key_read(CA_SLOT, blob, &blob_len);

	if (ret == 0 && blob_len > 0) {
		provisioned = true;
		LOG_INF("CA key slot present");
		mbedtls_platform_zeroize(blob, sizeof(blob));

		/* Crash-window recovery: key + x509 present but no cert →
		 * regenerate from stored params. */
		if (storage_slot_cert_exists(CA_SLOT) == 0) {
			uint8_t x509_buf[X509_DATA_MAX];
			size_t x509_len = sizeof(x509_buf);

			if (storage_slot_x509_read(CA_SLOT, x509_buf, &x509_len) == 0) {
				x509_params_t p;
				if (x509_parse(x509_buf, x509_len, &p) == 0) {
					LOG_INF("regenerating slot 0 cert from stored x509 data");
					(void)build_self_signed_cert(CA_SLOT, &p);
				}
			}
		}
		return 0;
	}

	mbedtls_platform_zeroize(blob, sizeof(blob));
	LOG_INF("no CA key found — first boot provisioning required");
	ret = ca_provision();
	if (ret) {
		LOG_ERR("ca_provision failed: %d", ret);
		return ret;
	}
	return 0;
}

int ca_provision(void)
{
	LOG_INF("generating CA keypair on CC310 TRNG");

	uint8_t storage_key[32];
	int ret = crypto_storage_key_derive(storage_key);

	if (ret) {
		return ret;
	}

	uint8_t privkey[64];
	size_t privkey_len = sizeof(privkey);

	ret = crypto_keygen(privkey, &privkey_len);
	if (ret) {
		mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
		return ret;
	}

	uint8_t blob[KEY_BLOB_MAX];
	size_t blob_len = sizeof(blob);

	ret = crypto_encrypt_blob(storage_key, privkey, privkey_len,
				  blob, &blob_len);
	mbedtls_platform_zeroize(privkey, sizeof(privkey));
	mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
	if (ret) {
		return ret;
	}

	ret = storage_key_write(CA_SLOT, blob, blob_len);
	mbedtls_platform_zeroize(blob, sizeof(blob));
	if (ret) {
		return ret;
	}

	slot_meta_t m = {
		.version        = 1,
		.key_type       = KEY_TYPE_P256,
		.is_protected   = 1,
		.protect_issued = 1,
	};
	ret = meta_write(CA_SLOT, &m);
	if (ret) {
		LOG_ERR("meta_write slot 0: %d", ret);
		return ret;
	}

	provisioned = true;
	LOG_INF("CA provisioned — slot 0 key+meta written, awaiting PUSH_KEY_X509");
	return 0;
}

bool ca_ready(void)
{
	return provisioned && (storage_slot_cert_exists(CA_SLOT) == 1);
}

int ca_push_key_x509(uint32_t slot_id, const uint8_t *data, size_t len)
{
	if (data == NULL || len == 0 || len > X509_DATA_MAX) {
		return -EINVAL;
	}

	/* Bootstrap exemption: protected slots block writes UNLESS no cert yet. */
	slot_meta_t m;
	int ret = meta_read(slot_id, &m);

	if (ret == 0 && m.is_protected) {
		int has_cert = storage_slot_cert_exists(slot_id);

		if (has_cert < 0) {
			return has_cert;
		}
		if (has_cert == 1) {
			LOG_WRN("slot %u protected and cert present — push refused", slot_id);
			return -EACCES;
		}
	}

	x509_params_t p;

	ret = x509_parse(data, len, &p);
	if (ret) {
		return ret;
	}

	ret = storage_slot_x509_write(slot_id, data, len);
	if (ret) {
		return ret;
	}

	ret = build_self_signed_cert(slot_id, &p);
	if (ret) {
		LOG_ERR("build_self_signed_cert slot %u: %d", slot_id, ret);
		return ret;
	}
	/* Self-signed cert just replaced whatever was at cert.der; any stale
	 * chain.der belonged to a previous externally-signed cert and is no
	 * longer valid for this slot. */
	(void)storage_slot_chain_delete(slot_id);
	return 0;
}

/*
 * Load any slot's stored x509 params so we can rebuild the issuer DN
 * byte-for-byte identical to that slot's self-signed cert subject.
 */
static int load_issuer_x509_params(uint32_t slot, x509_params_t *p)
{
	uint8_t buf[X509_DATA_MAX];
	size_t  len = sizeof(buf);
	int rc = storage_slot_x509_read(slot, buf, &len);

	if (rc) {
		return rc;
	}
	return x509_parse(buf, len, p);
}

int ca_sign_csr(const uint8_t *csr_der, size_t csr_len,
		uint8_t *cert_der, size_t *cert_len)
{
	return ca_sign_csr_slot(CA_SLOT, csr_der, csr_len, cert_der, cert_len);
}

int ca_sign_csr_slot(uint32_t issuer_slot,
		     const uint8_t *csr_der, size_t csr_len,
		     uint8_t *cert_der, size_t *cert_len)
{
	if (!csr_der || csr_len == 0 || !cert_der || !cert_len || *cert_len == 0) {
		return -EINVAL;
	}
	if (issuer_slot >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
		return -EINVAL;
	}
	if (storage_slot_key_exists(issuer_slot) != 1) {
		LOG_WRN("ca_sign_csr_slot: issuer slot %u has no key", issuer_slot);
		return -ENOENT;
	}
	if (issuer_slot == CA_SLOT && !ca_ready()) {
		LOG_WRN("ca_sign_csr: slot 0 not ready (no cert)");
		return -ENOENT;
	}

	mbedtls_x509_csr csr;
	struct slot_pk ca_sp;
	mbedtls_x509write_cert crt;
	uint8_t privkey[32];
	size_t  privkey_len = sizeof(privkey);
	uint8_t serial[8];
	char issuer_dn[DN_MAX];
	char subject_dn[DN_MAX];
	char not_after[15];
	x509_params_t ca_params;
	int rc;

	mbedtls_x509_csr_init(&csr);
	slot_pk_init(&ca_sp);
	mbedtls_x509write_crt_init(&crt);

	rc = mbedtls_x509_csr_parse_der(&csr, csr_der, csr_len);
	if (rc) {
		LOG_WRN("csr_parse_der=-0x%04x", -rc);
		rc = -EINVAL;
		goto out;
	}

	/* Subject DN string from the CSR (RFC 4514). */
	rc = mbedtls_x509_dn_gets(subject_dn, sizeof(subject_dn), &csr.subject);
	if (rc <= 0 || (size_t)rc >= sizeof(subject_dn)) {
		LOG_WRN("dn_gets=%d", rc);
		rc = -EINVAL;
		goto out;
	}

	rc = load_issuer_x509_params(issuer_slot, &ca_params);
	if (rc) {
		LOG_ERR("load_issuer_x509_params slot %u=%d", issuer_slot, rc);
		goto out;
	}
	rc = build_dn(&ca_params, issuer_dn, sizeof(issuer_dn));
	if (rc) {
		goto out;
	}

	/* Load issuer slot privkey into a PK context for the writer. */
	rc = load_slot_privkey(issuer_slot, privkey, &privkey_len);
	if (rc || privkey_len != 32) {
		LOG_ERR("load_slot_privkey slot %u=%d", issuer_slot, rc);
		rc = rc ? rc : -EIO;
		goto out;
	}

	rc = slot_pk_load_priv(privkey, privkey_len, &ca_sp);
	if (rc) goto out;

	/* Build the new cert. */
	rc = mbedtls_x509write_crt_set_subject_name(&crt, subject_dn);
	if (rc) goto out;
	rc = mbedtls_x509write_crt_set_issuer_name(&crt, issuer_dn);
	if (rc) goto out;

	mbedtls_x509write_crt_set_subject_key(&crt, &csr.pk);
	mbedtls_x509write_crt_set_issuer_key(&crt, &ca_sp.pk);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

	rc = crypto_trng(serial, sizeof(serial));
	if (rc) goto out;
	serial[0] = (serial[0] & 0x7F) | 0x01;  /* positive ASN.1 INTEGER, non-zero */
	rc = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
	if (rc) goto out;

	compute_not_after(SIGN_CSR_VALIDITY_DAYS, not_after);
	rc = mbedtls_x509write_crt_set_validity(&crt, NOT_BEFORE_BASE, not_after);
	if (rc) goto out;

	/* End-entity cert: not a CA, digital_signature only. */
	rc = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
	if (rc) goto out;
	rc = mbedtls_x509write_crt_set_key_usage(&crt, KU_DIGITAL_SIGNATURE);
	if (rc) goto out;

	uint8_t der[CERT_DER_MAX];
	int n = mbedtls_x509write_crt_der(&crt, der, sizeof(der), rng_cb, NULL);

	if (n < 0) {
		LOG_ERR("x509write_crt_der=-0x%04x", -n);
		rc = -EIO;
		goto out;
	}
	if ((size_t)n > *cert_len) {
		LOG_WRN("output buffer too small: need %d, have %zu", n, *cert_len);
		rc = -ENOMEM;
		goto out;
	}

	/* mbedtls writes DER at the END of the buffer. */
	const uint8_t *cert_start = der + sizeof(der) - n;

	memcpy(cert_der, cert_start, n);
	*cert_len = (size_t)n;

	/* Persist into the issued-cert store. */
	rc = storage_issued_cert_write(serial, sizeof(serial), cert_start, n);
	if (rc) {
		LOG_ERR("issued_cert_write=%d", rc);
		goto out;
	}

	issued_cert_meta_t meta = {
		.version         = 1,
		.flags           = 0,
		.serial_len      = sizeof(serial),
		.issuer_slot     = issuer_slot,
		.not_before_unix = SIGN_CSR_NOT_BEFORE_UNIX,
		.not_after_unix  = SIGN_CSR_NOT_BEFORE_UNIX +
				   (uint64_t)SIGN_CSR_VALIDITY_DAYS * 86400ULL,
	};
	memcpy(meta.serial, serial, sizeof(serial));

	/* Best-effort capture of the subject CN. */
	const mbedtls_x509_name *name = &csr.subject;
	while (name) {
		if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0) {
			size_t cap = sizeof(meta.cn) - 1;
			size_t copy = (name->val.len < cap) ? name->val.len : cap;
			memcpy(meta.cn, name->val.p, copy);
			meta.cn[copy] = '\0';
			break;
		}
		name = name->next;
	}

	rc = storage_issued_meta_write(serial, sizeof(serial),
				       (const uint8_t *)&meta, sizeof(meta));
	if (rc) {
		LOG_ERR("issued_meta_write=%d", rc);
		goto out;
	}

	LOG_INF("signed cert: serial=%02x%02x%02x%02x%02x%02x%02x%02x (%d bytes)",
		serial[0], serial[1], serial[2], serial[3],
		serial[4], serial[5], serial[6], serial[7], n);
	rc = 0;

out:
	mbedtls_platform_zeroize(privkey, sizeof(privkey));
	mbedtls_x509write_crt_free(&crt);
	slot_pk_free(&ca_sp);
	mbedtls_x509_csr_free(&csr);
	return rc;
}

int ca_sign_session_cert(uint32_t issuer_slot,
			 const uint8_t *x509_blob, size_t blob_len,
			 const char *cn_override,
			 const uint8_t id_priv[32],
			 const uint8_t x25519_pub[32],
			 uint8_t *out, size_t *out_len)
{
	if (!x509_blob || !id_priv || !x25519_pub || !out || !out_len ||
	    *out_len == 0) {
		return -EINVAL;
	}
	if (issuer_slot >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
		return -EINVAL;
	}
	if (storage_slot_key_exists(issuer_slot) != 1) {
		LOG_WRN("ca_sign_session_cert: issuer slot %u has no key",
			issuer_slot);
		return -ENOENT;
	}
	if (issuer_slot == CA_SLOT && !ca_ready()) {
		LOG_WRN("ca_sign_session_cert: slot 0 not ready (no cert)");
		return -ENOENT;
	}

	x509_params_t p;
	int rc = x509_parse(x509_blob, blob_len, &p);

	if (rc) {
		return rc;
	}
	if (p.is_ca) {
		/* The transport identity must never be a CA. */
		return -EINVAL;
	}
	if (cn_override != NULL && cn_override[0] != '\0') {
		size_t n = strlen(cn_override);

		if (n >= sizeof(p.cn)) {
			return -EINVAL;
		}
		memcpy(p.cn, cn_override, n + 1);
	}

	struct slot_pk subj_sp;   /* P-256 session identity key (subject) */
	struct slot_pk ca_sp;     /* issuer CA slot key */
	mbedtls_x509write_cert crt;
	uint8_t ca_priv[32];
	size_t  ca_priv_len = sizeof(ca_priv);
	x509_params_t ca_params;
	uint8_t serial[8];
	char subject_dn[DN_MAX];
	char issuer_dn[DN_MAX];
	char not_after[15];

	slot_pk_init(&subj_sp);
	slot_pk_init(&ca_sp);
	mbedtls_x509write_crt_init(&crt);

	/* Subject side: the session identity (mirrors ca_build_session_cert). */
	rc = slot_pk_load_priv(id_priv, 32, &subj_sp);
	if (rc) {
		goto out;
	}
	rc = build_dn(&p, subject_dn, sizeof(subject_dn));
	if (rc) {
		goto out;
	}

	/* Issuer side: the CA slot's DN + private key. */
	rc = load_issuer_x509_params(issuer_slot, &ca_params);
	if (rc) {
		LOG_ERR("ca_sign_session_cert: load issuer params slot %u=%d",
			issuer_slot, rc);
		goto out;
	}
	rc = build_dn(&ca_params, issuer_dn, sizeof(issuer_dn));
	if (rc) {
		goto out;
	}
	rc = load_slot_privkey(issuer_slot, ca_priv, &ca_priv_len);
	if (rc || ca_priv_len != 32) {
		LOG_ERR("ca_sign_session_cert: load issuer privkey slot %u=%d",
			issuer_slot, rc);
		rc = rc ? rc : -EIO;
		goto out;
	}
	rc = slot_pk_load_priv(ca_priv, ca_priv_len, &ca_sp);
	if (rc) {
		goto out;
	}

	rc = mbedtls_x509write_crt_set_subject_name(&crt, subject_dn);
	if (rc) {
		goto out;
	}
	rc = mbedtls_x509write_crt_set_issuer_name(&crt, issuer_dn);
	if (rc) {
		goto out;
	}

	mbedtls_x509write_crt_set_subject_key(&crt, &subj_sp.pk);
	mbedtls_x509write_crt_set_issuer_key(&crt, &ca_sp.pk);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

	rc = crypto_trng(serial, sizeof(serial));
	if (rc) {
		goto out;
	}
	serial[0] = (serial[0] & 0x7F) | 0x01;  /* positive, non-zero INTEGER */
	rc = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
	if (rc) {
		goto out;
	}

	compute_not_after(p.validity_days, not_after);
	rc = mbedtls_x509write_crt_set_validity(&crt, NOT_BEFORE_BASE, not_after);
	if (rc) {
		goto out;
	}

	/* End-entity: not a CA. KU straight from the build constant
	 * (digitalSignature + keyAgreement). */
	rc = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
	if (rc) {
		goto out;
	}
	if (p.key_usage) {
		rc = mbedtls_x509write_crt_set_key_usage(&crt, p.key_usage);
		if (rc) {
			goto out;
		}
	}

	/* Preserve the Noise X25519 binding extension. */
	rc = mbedtls_x509write_crt_set_extension(&crt,
				(const char *)OID_SESSION_X25519,
				sizeof(OID_SESSION_X25519),
				0 /* non-critical */,
				x25519_pub, 32);
	if (rc) {
		goto out;
	}

	uint8_t der[CERT_DER_MAX];
	int n = mbedtls_x509write_crt_der(&crt, der, sizeof(der), rng_cb, NULL);

	if (n < 0) {
		LOG_ERR("ca_sign_session_cert: x509write_crt_der=%d", n);
		rc = -EIO;
		goto out;
	}
	if ((size_t)n > *out_len) {
		rc = -ENOMEM;
		goto out;
	}
	/* mbedtls writes DER at the END of the buffer. */
	memcpy(out, der + sizeof(der) - n, n);
	*out_len = (size_t)n;
	rc = 0;

	LOG_INF("session cert CA-signed by slot %u (%d bytes)", issuer_slot, n);

out:
	mbedtls_platform_zeroize(ca_priv, sizeof(ca_priv));
	mbedtls_x509write_crt_free(&crt);
	slot_pk_free(&ca_sp);
	slot_pk_free(&subj_sp);
	return rc;
}

/* Find `needle` within `hay`; first match or NULL. */
static const uint8_t *find_bytes(const uint8_t *hay, size_t hay_len,
				 const uint8_t *needle, size_t needle_len)
{
	if (needle_len == 0 || hay_len < needle_len) {
		return NULL;
	}
	for (size_t i = 0; i + needle_len <= hay_len; i++) {
		if (memcmp(hay + i, needle, needle_len) == 0) {
			return hay + i;
		}
	}
	return NULL;
}

/*
 * Extract the 32-byte X25519 binding pubkey from a parsed cert's raw v3
 * extensions. Mirrors the writer (ca_build_session_cert): the extension value
 * is an OCTET STRING (0x04 0x20) wrapping the raw key, under OID_SESSION_X25519.
 * Returns 0 on success, -ENOENT if the binding is absent or malformed.
 */
static int cert_extract_x25519(const mbedtls_x509_crt *crt, uint8_t out[32])
{
	const uint8_t *ext = crt->v3_ext.p;
	size_t ext_len = crt->v3_ext.len;
	const uint8_t *oid = find_bytes(ext, ext_len, OID_SESSION_X25519,
					sizeof(OID_SESSION_X25519));

	if (oid == NULL) {
		return -ENOENT;
	}

	const uint8_t *after = oid + sizeof(OID_SESSION_X25519);
	const uint8_t *end = ext + ext_len;
	const uint8_t os_hdr[] = {0x04, 0x20};
	const uint8_t *os = find_bytes(after, (size_t)(end - after),
				       os_hdr, sizeof(os_hdr));

	if (os == NULL || os + 2 + 32 > end) {
		return -ENOENT;
	}
	memcpy(out, os + 2, 32);
	return 0;
}

/*
 * Chain-verify callback. The device has no RTC, so a real validity-window check
 * is impossible — clear the time-based verdicts (EXPIRED / FUTURE) and let the
 * cryptographic verdicts (bad signature, not-trusted, bad key usage) stand. The
 * leaf's own validity is fixed at build time; client-side Tier-3 validation
 * (T-12) is where wall-clock policy belongs.
 */
static int chain_vrfy_cb(void *ctx, mbedtls_x509_crt *crt, int depth,
			 uint32_t *flags)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(crt);
	ARG_UNUSED(depth);
	*flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED |
			      MBEDTLS_X509_BADCERT_FUTURE);
	return 0;
}

int ca_validate_pushed_session_cert(const uint8_t *cert_der, size_t cert_len,
				    const uint8_t *chain_der, size_t chain_len,
				    const uint8_t id_pub[65],
				    const uint8_t x25519_pub[32],
				    const uint8_t *x509_blob, size_t blob_len,
				    bool *out_ca_signed)
{
	if (!cert_der || cert_len == 0 || !id_pub || !x25519_pub || !x509_blob) {
		return -EINVAL;
	}

	mbedtls_x509_crt leaf;

	mbedtls_x509_crt_init(&leaf);

	int rc = mbedtls_x509_crt_parse_der(&leaf, cert_der, cert_len);

	if (rc) {
		LOG_WRN("push_session_cert: leaf parse=-0x%04x", -rc);
		mbedtls_x509_crt_free(&leaf);
		return -EINVAL;
	}

	/* 1. SPKI gate — the cert must bind THIS device's P-256 identity key.
	 * mbedtls writes the SEC1 pubkey at the END of the buffer. */
	uint8_t cert_pub_buf[80];
	uint8_t *cert_pub_p = cert_pub_buf + sizeof(cert_pub_buf);
	int wlen = mbedtls_pk_write_pubkey(&cert_pub_p, cert_pub_buf, &leaf.pk);

	if (wlen != 65 || cert_pub_p[0] != 0x04 ||
	    memcmp(cert_pub_p, id_pub, 65) != 0) {
		LOG_WRN("push_session_cert: SPKI != device identity key");
		rc = -EINVAL;
		goto out_leaf;
	}

	/* 2. X25519 binding gate — must attest the same Noise static key. */
	uint8_t cert_x[32];

	if (cert_extract_x25519(&leaf, cert_x) != 0 ||
	    memcmp(cert_x, x25519_pub, 32) != 0) {
		LOG_WRN("push_session_cert: X25519 binding missing/mismatch");
		rc = -EINVAL;
		goto out_leaf;
	}

	/* 3. Subject-constant consistency — a pushed cert that drifts the
	 * identity fields would trip boot-time recovery (T-03) on next reset. */
	rc = ca_session_cert_matches_constant(cert_der, cert_len,
					      x509_blob, blob_len);
	if (rc != 1) {
		LOG_WRN("push_session_cert: subject != build constant (%d)", rc);
		rc = -EINVAL;
		goto out_leaf;
	}
	rc = 0;   /* matches_constant returns 1 on match — normalize to success */

	/* Self-signed? (issuer DN == subject DN). A self-signed push needs no
	 * chain and does not latch the CA-signed marker. */
	bool self_signed = (leaf.issuer_raw.len == leaf.subject_raw.len) &&
			   (memcmp(leaf.issuer_raw.p, leaf.subject_raw.p,
				   leaf.subject_raw.len) == 0);

	if (out_ca_signed) {
		*out_ca_signed = !self_signed;
	}

	/* 4. Chain-link verification (T-07). A CA-signed leaf MUST arrive with
	 * the issuer chain so the device can verify the link cryptographically;
	 * the topmost supplied cert is the trust anchor and every link from the
	 * leaf up to it is signature-checked (time ignored — no RTC). */
	if (self_signed) {
		rc = 0;            /* nothing above the leaf to verify */
		goto out_leaf;
	}
	if (chain_len == 0 || chain_der == NULL) {
		LOG_WRN("push_session_cert: CA-signed cert pushed without chain");
		rc = -EINVAL;
		goto out_leaf;
	}

	mbedtls_x509_crt chain;

	mbedtls_x509_crt_init(&chain);

	/* The chain blob is concatenated DER. mbedtls parses one cert at a
	 * time, so split on the outer SEQUENCE length and append each. */
	size_t off = 0;

	while (off + 1 < chain_len) {
		const unsigned char *p = chain_der + off;
		unsigned char *q = (unsigned char *)p;
		size_t inner;

		if (mbedtls_asn1_get_tag(&q, p + (chain_len - off), &inner,
					 MBEDTLS_ASN1_CONSTRUCTED |
					 MBEDTLS_ASN1_SEQUENCE) != 0) {
			rc = -EINVAL;
			break;
		}

		size_t this_len = (size_t)(q - p) + inner;

		if (off + this_len > chain_len ||
		    mbedtls_x509_crt_parse_der(&chain, p, this_len) != 0) {
			rc = -EINVAL;
			break;
		}
		off += this_len;
	}

	if (rc == 0) {
		/* Trust anchor = topmost supplied cert. */
		mbedtls_x509_crt *anchor = &chain;

		while (anchor->next != NULL) {
			anchor = anchor->next;
		}

		leaf.next = &chain;   /* present intermediates to the verifier */

		uint32_t flags = 0;
		int vrc = mbedtls_x509_crt_verify_with_profile(
				&leaf, anchor, NULL,
				&mbedtls_x509_crt_profile_default,
				NULL, &flags, chain_vrfy_cb, NULL);

		leaf.next = NULL;     /* sever before freeing either list */

		if (vrc != 0) {
			LOG_WRN("push_session_cert: chain verify failed flags=0x%08x",
				flags);
			rc = -EINVAL;
		}
	}

	mbedtls_x509_crt_free(&chain);

out_leaf:
	mbedtls_x509_crt_free(&leaf);
	return rc;
}

/*
 * Validate a client certificate chain against an on-device CA slot's cert
 * (transport + pairing T-19, Method 4 CA-anchored pairing).
 *
 * cert_ders[0..cert_count-1]: leaf-first chain presented by the client.
 *   cert_ders[0] is the client leaf cert.
 *   cert_ders[1..] are intermediates, if any, up to (but NOT including)
 *   the anchor CA cert — that one is loaded from anchor_slot's storage.
 *
 * Verification: leaf → [intermediates] → anchor (slot cert).
 * Validity windows are ignored — the device has no RTC; only signature links
 * matter (same policy as push-session-cert and Tier-3 client validation).
 *
 * Returns 0 on success, -ENOENT if anchor slot has no stored cert,
 * -EINVAL if any cert fails to parse or the chain doesn't verify,
 * -EIO on an mbedtls internal failure.
 */
int ca_validate_client_cert_chain(const uint8_t *const cert_ders[],
				   const size_t cert_lens[], size_t cert_count,
				   uint32_t anchor_slot)
{
	if (!cert_ders || !cert_lens || cert_count == 0) {
		return -EINVAL;
	}

	/* Load the trust anchor cert from storage. */
	static uint8_t anchor_buf[1024];
	size_t anchor_len = sizeof(anchor_buf);
	int rc = storage_slot_cert_read(anchor_slot, anchor_buf, &anchor_len);

	if (rc == -ENOENT) {
		LOG_WRN("ca_anchor: slot %u has no cert", anchor_slot);
		return -ENOENT;
	}
	if (rc) {
		LOG_ERR("ca_anchor: slot %u cert read=%d", anchor_slot, rc);
		return -EIO;
	}

	mbedtls_x509_crt anchor;
	mbedtls_x509_crt leaf;
	mbedtls_x509_crt intermediates;

	mbedtls_x509_crt_init(&anchor);
	mbedtls_x509_crt_init(&leaf);
	mbedtls_x509_crt_init(&intermediates);

	rc = mbedtls_x509_crt_parse_der(&anchor, anchor_buf, anchor_len);
	if (rc) {
		LOG_WRN("ca_anchor: anchor cert parse=-0x%04x", -rc);
		rc = -EINVAL;
		goto out;
	}

	rc = mbedtls_x509_crt_parse_der(&leaf, cert_ders[0], cert_lens[0]);
	if (rc) {
		LOG_WRN("ca_anchor: client leaf parse=-0x%04x", -rc);
		rc = -EINVAL;
		goto out;
	}

	/* Parse intermediate certs (indices 1..cert_count-1). Each call to
	 * mbedtls_x509_crt_parse_der appends to the linked list rooted at
	 * intermediates; leaf.next is severed after verification. */
	for (size_t i = 1; i < cert_count; i++) {
		int mrc = mbedtls_x509_crt_parse_der(&intermediates,
						      cert_ders[i], cert_lens[i]);

		if (mrc) {
			LOG_WRN("ca_anchor: intermediate[%zu] parse=-0x%04x",
				i, -mrc);
			rc = -EINVAL;
			goto out;
		}
	}

	if (cert_count > 1) {
		leaf.next = &intermediates;
	}

	{
		uint32_t flags = 0;
		int vrc = mbedtls_x509_crt_verify_with_profile(
				&leaf, &anchor, NULL,
				&mbedtls_x509_crt_profile_default,
				NULL, &flags, chain_vrfy_cb, NULL);

		leaf.next = NULL;   /* sever before freeing */

		if (vrc != 0) {
			LOG_WRN("ca_anchor: chain verify failed flags=0x%08x",
				flags);
			rc = -EINVAL;
		} else {
			LOG_INF("ca_anchor: client chain valid (slot %u as anchor)",
				anchor_slot);
			rc = 0;
		}
	}

out:
	leaf.next = NULL;   /* defensive — already cleared in the success path */
	mbedtls_x509_crt_free(&intermediates);
	mbedtls_x509_crt_free(&leaf);
	mbedtls_x509_crt_free(&anchor);
	return rc;
}

int ca_get_cert(uint8_t *cert_der, size_t *cert_len)
{
	return storage_slot_cert_read(CA_SLOT, cert_der, cert_len);
}

/*
 * Recursive chain walker. On entry, `*chain_len` is the buffer capacity; on
 * exit, the number of bytes written. `depth` is bounded by the slot count to
 * detect cycles (a malformed issuer_slot chain that loops back).
 *
 * Output: slot's own cert.der, followed by either the chain.der the host
 * pushed for it, or — if this slot's cert was signed on-device by another
 * slot — that issuer slot's full chain (recursively).
 */
static int chain_walk(uint32_t slot, uint8_t *out, size_t cap, size_t *out_off,
		      unsigned depth)
{
	if (depth >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
		LOG_ERR("ca_get_chain: cycle/depth >= max slots");
		return -ELOOP;
	}
	if (slot >= CONFIG_CANTIL_MAX_KEY_SLOTS) return -EINVAL;
	if (storage_slot_cert_exists(slot) != 1) return -ENOENT;

	/* Append this slot's own cert. */
	size_t avail = cap - *out_off;
	size_t cert_len = avail;
	int rc = storage_slot_cert_read(slot, out + *out_off, &cert_len);

	if (rc) return rc;
	*out_off += cert_len;

	/* Externally-signed sub-CA: chain.der holds everything above us. */
	if (storage_slot_chain_exists(slot) == 1) {
		size_t cl = cap - *out_off;
		rc = storage_slot_chain_read(slot, out + *out_off, &cl);
		if (rc) return rc;
		*out_off += cl;
		return 0;
	}

	/* On-device signed: look up issued-cert meta by this cert's serial
	 * to find the issuer slot. Self-signed slot certs are NOT written to
	 * /certs/, so a missing meta means we've reached a root. */
	mbedtls_x509_crt parsed;
	mbedtls_x509_crt_init(&parsed);
	rc = mbedtls_x509_crt_parse_der(&parsed, out + *out_off - cert_len, cert_len);
	if (rc) {
		mbedtls_x509_crt_free(&parsed);
		LOG_WRN("chain_walk: parse slot %u =-0x%04x", slot, -rc);
		return -EIO;
	}

	issued_cert_meta_t m;
	int mrc = read_issued_meta(parsed.serial.p, parsed.serial.len, &m);
	uint32_t issuer = (mrc == 0) ? m.issuer_slot : slot;

	mbedtls_x509_crt_free(&parsed);

	if (issuer == slot) {
		/* Self-signed root — done. */
		return 0;
	}
	return chain_walk(issuer, out, cap, out_off, depth + 1);
}

int ca_get_chain_slot(uint32_t slot, uint8_t *chain_der, size_t *chain_len)
{
	if (!chain_der || !chain_len || *chain_len == 0) return -EINVAL;

	size_t cap = *chain_len;
	size_t off = 0;
	int rc = chain_walk(slot, chain_der, cap, &off, 0);

	if (rc) {
		*chain_len = 0;
		return rc;
	}
	*chain_len = off;
	return 0;
}

int ca_get_chain(uint8_t *chain_der, size_t *chain_len)
{
	return ca_get_chain_slot(CA_SLOT, chain_der, chain_len);
}

int ca_get_serial(uint8_t *serial, size_t *serial_len)
{
	if (!serial || !serial_len || *serial_len == 0) {
		return -EINVAL;
	}

	uint8_t cert[CERT_DER_MAX];
	size_t cert_len = sizeof(cert);
	int rc = storage_slot_cert_read(CA_SLOT, cert, &cert_len);

	if (rc) {
		*serial_len = 0;
		return rc;
	}

	mbedtls_x509_crt parsed;
	mbedtls_x509_crt_init(&parsed);

	rc = mbedtls_x509_crt_parse_der(&parsed, cert, cert_len);
	if (rc) {
		LOG_ERR("ca_get_serial parse=-0x%04x", -rc);
		mbedtls_x509_crt_free(&parsed);
		*serial_len = 0;
		return -EIO;
	}

	if (parsed.serial.len > *serial_len) {
		mbedtls_x509_crt_free(&parsed);
		*serial_len = 0;
		return -ENOMEM;
	}

	memcpy(serial, parsed.serial.p, parsed.serial.len);
	*serial_len = parsed.serial.len;
	mbedtls_x509_crt_free(&parsed);
	return 0;
}

int ca_get_csr(uint8_t *csr_der, size_t *csr_len)
{
	return storage_slot_csr_read(CA_SLOT, csr_der, csr_len);
}

int ca_push_cert(const uint8_t *cert_der, size_t cert_len,
		 const uint8_t *chain_der, size_t chain_len)
{
	int rc = storage_slot_cert_write(CA_SLOT, cert_der, cert_len);

	if (rc) return rc;

	if (chain_len > 0 && chain_der != NULL) {
		rc = storage_slot_chain_write(CA_SLOT, chain_der, chain_len);
		if (rc) {
			LOG_ERR("ca_push_cert: chain_write=%d", rc);
			return rc;
		}
	} else {
		/* Caller pushed a cert with no chain — drop any stale chain
		 * left over from a previous push so the walker doesn't return
		 * a chain that no longer matches the installed cert. */
		(void)storage_slot_chain_delete(CA_SLOT);
	}
	return 0;
}

/*
 * LIST_CERTS payload — CBOR array of small maps, canonical key order
 * (bytewise: "f" < "i" < "n" < "s"):
 *
 *   [
 *     { "f": <flags-uint>, "i": <issuer-slot-uint>,
 *       "n": <cn-tstr>,    "s": <serial-bstr> },
 *     ...
 *   ]
 *
 * Compact 1-char keys keep the payload small enough that the full list of
 * issued certs fits inside the existing MSG_BUF_SIZE response budget even
 * with a few hundred entries.
 */
struct list_certs_ctx {
	uint8_t *buf;
	size_t   cap;
	size_t   off;
	uint32_t count;
	int      first_err;       /* first encode error, sticky */
	int      stop;            /* nonzero when we ran out of space */
};

static int list_certs_cb(const uint8_t *serial, size_t serial_len, void *user)
{
	struct list_certs_ctx *ctx = (struct list_certs_ctx *)user;

	if (ctx->stop) return 1;

	issued_cert_meta_t meta;
	int rc = read_issued_meta(serial, serial_len, &meta);

	uint32_t issuer_slot = CA_SLOT;
	uint8_t  flags = 0;
	const char *cn = "";
	size_t cn_len = 0;

	if (rc == 0) {
		issuer_slot = meta.issuer_slot;
		flags = meta.flags;
		cn = meta.cn;
		while (cn_len < sizeof(meta.cn) && meta.cn[cn_len] != '\0') {
			cn_len++;
		}
	}

	/* Emit one map(4) entry. */
	size_t saved = ctx->off;
	int e = cantil_cbor_emit_map(ctx->buf, ctx->cap, &ctx->off, 4);

	if (!e) e = cantil_cbor_emit_tstr(ctx->buf, ctx->cap, &ctx->off, "f", 1);
	if (!e) e = cantil_cbor_emit_uint(ctx->buf, ctx->cap, &ctx->off, flags);

	if (!e) e = cantil_cbor_emit_tstr(ctx->buf, ctx->cap, &ctx->off, "i", 1);
	if (!e) e = cantil_cbor_emit_uint(ctx->buf, ctx->cap, &ctx->off, issuer_slot);

	if (!e) e = cantil_cbor_emit_tstr(ctx->buf, ctx->cap, &ctx->off, "n", 1);
	if (!e) e = cantil_cbor_emit_tstr(ctx->buf, ctx->cap, &ctx->off, cn, cn_len);

	if (!e) e = cantil_cbor_emit_tstr(ctx->buf, ctx->cap, &ctx->off, "s", 1);
	if (!e) e = cantil_cbor_emit_bstr(ctx->buf, ctx->cap, &ctx->off,
					  serial, serial_len);

	if (e) {
		/* Buffer full — rewind and stop. Keep what we encoded so far. */
		ctx->off = saved;
		ctx->stop = 1;
		ctx->first_err = e;
		return 1;
	}
	ctx->count++;
	return 0;
}

int ca_list_certs(uint8_t *cbor_out, size_t *len)
{
	if (!cbor_out || !len || *len < 16) {
		return -EINVAL;
	}

	/* Two-pass: first count, then re-emit with the right array header.
	 * Both passes walk LittleFS — cheap on native_sim and for the modest
	 * issuance volumes a CA on this device will see (10s..100s of certs). */
	uint32_t total = 0;
	int rc = storage_count_issued_certs(&total);

	if (rc) {
		*len = 0;
		return rc;
	}

	struct list_certs_ctx ctx = {
		.buf = cbor_out,
		.cap = *len,
		.off = 0,
	};

	rc = cantil_cbor_emit_array(cbor_out, *len, &ctx.off, total);
	if (rc) {
		*len = 0;
		return -ENOMEM;
	}

	rc = storage_issued_certs_iter(list_certs_cb, &ctx);
	if (rc < 0) {
		*len = 0;
		return rc;
	}
	/* If we ran out of space, the array header was sized for `total` but
	 * we wrote fewer entries — the blob is malformed CBOR. Bail and let
	 * the caller retry with a bigger buffer (current MSG_BUF_SIZE - frame
	 * overhead = ~4080 bytes, room for ~40 entries with 8-byte serials). */
	if (ctx.count != total) {
		*len = 0;
		return -ENOMEM;
	}

	*len = ctx.off;
	return 0;
}

int ca_get_cert_count(uint32_t *count)
{
	if (!count) return -EINVAL;
	return storage_count_issued_certs(count);
}

int ca_get_issued_cert(const uint8_t *serial, size_t serial_len,
		       uint8_t *cert_der, size_t *cert_len)
{
	return storage_issued_cert_read(serial, serial_len, cert_der, cert_len);
}

int ca_revoke_cert(const uint8_t *serial, size_t serial_len,
		   uint64_t now_unix)
{
	if (!serial || serial_len == 0 || serial_len > 20) {
		return -EINVAL;
	}

	issued_cert_meta_t m;
	int rc = read_issued_meta(serial, serial_len, &m);

	if (rc) {
		return rc; /* -ENOENT if no such cert */
	}

	if (m.flags & ISSUED_FLAG_PROTECTED) {
		LOG_WRN("revoke refused: cert is protected");
		return -EACCES;
	}
	if (m.flags & ISSUED_FLAG_REVOKED) {
		return -EALREADY;
	}

	m.flags             |= ISSUED_FLAG_REVOKED;
	m.revoked_at_unix    = now_unix;
	m.revocation_reason  = 0;  /* unspecified; future opcode can override */
	rc = storage_issued_meta_write(serial, serial_len,
				       (const uint8_t *)&m, sizeof(m));
	if (rc) {
		return rc;
	}

	/* Per-slot CRL number monotonic: bump on every successful revoke so
	 * verifiers can detect rollback. Failure to persist is non-fatal —
	 * we'd just emit the previous crlNumber on the next GET_CRL. */
	uint32_t n = 0;
	(void)storage_slot_crl_number_read(m.issuer_slot, &n);
	n++;
	int wrc = storage_slot_crl_number_write(m.issuer_slot, n);
	if (wrc) {
		LOG_WRN("crl_number bump slot %u failed: %d", m.issuer_slot, wrc);
	}

	LOG_INF("revoked cert (issuer slot %u, %zu byte serial, now=%llu)",
		m.issuer_slot, serial_len, (unsigned long long)now_unix);
	return 0;
}

struct expire_ctx {
	uint64_t now_unix;
	uint32_t count;
	int      err;
};

static int expire_cb(const uint8_t *serial, size_t serial_len, void *user)
{
	struct expire_ctx *ctx = (struct expire_ctx *)user;
	issued_cert_meta_t m;

	if (read_issued_meta(serial, serial_len, &m)) {
		return 0;   /* corrupt entries are skipped, not fatal */
	}
	if (m.not_after_unix == 0) {
		return 0;                           /* no validity recorded */
	}
	if (m.flags & ISSUED_FLAG_EXPIRED) {
		return 0;                           /* already marked */
	}
	if (ctx->now_unix < m.not_after_unix) {
		return 0;                           /* still valid */
	}

	m.flags |= ISSUED_FLAG_EXPIRED;
	int rc = storage_issued_meta_write(serial, serial_len,
					   (const uint8_t *)&m, sizeof(m));
	if (rc) {
		ctx->err = rc;
		return 1;                           /* abort iteration */
	}
	ctx->count++;
	return 0;
}

int ca_auto_expire(uint64_t now_unix, uint32_t *expired_count)
{
	if (!expired_count) return -EINVAL;
	*expired_count = 0;
	if (now_unix == 0) return -EINVAL;

	struct expire_ctx ctx = { .now_unix = now_unix };
	int rc = storage_issued_certs_iter(expire_cb, &ctx);

	if (rc < 0) return rc;
	if (ctx.err) return ctx.err;
	*expired_count = ctx.count;
	return 0;
}

/* ── RFC 5280 DER CRL encoder ───────────────────────────────────────────── */
/* (defined later in this file; forward decl so ca_get_crl can call it) */
static int build_crl_der(uint32_t issuer_slot, uint64_t now_unix,
			 uint8_t *out, size_t out_cap, size_t *out_len);

int ca_get_crl(uint32_t issuer_slot, uint64_t now_unix,
	       uint8_t *crl_out, size_t *crl_len)
{
	if (!crl_out || !crl_len || *crl_len == 0) {
		return -EINVAL;
	}
	if (issuer_slot >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
		return -EINVAL;
	}
	if (now_unix == 0) {
		return -EINVAL;
	}
	if (storage_slot_key_exists(issuer_slot) != 1) {
		return -ENOENT;
	}
	if (storage_slot_cert_exists(issuer_slot) != 1) {
		/* Need the issuer cert's subject DN bytes to populate the
		 * CRL's issuer field. Treat as "slot not provisioned enough". */
		return -ENOENT;
	}
	return build_crl_der(issuer_slot, now_unix, crl_out, *crl_len, crl_len);
}

/*
 * LIST_KEYS payload — CBOR array of small maps, canonical key order
 * (bytewise: "c" < "p" < "r" < "s" < "t"):
 *
 *   [
 *     { "c": <has_cert>, "p": <protect_bits>, "r": <has_csr>,
 *       "s": <slot_id>, "t": <key_type> },
 *     ...
 *   ]
 *
 * "p" packs protect bits: bit0 = is_protected, bit1 = protect_issued_certs.
 */
int ca_list_keys(uint8_t *cbor_out, size_t *len)
{
	if (!cbor_out || !len || *len < 16) return -EINVAL;

	/* Pass 1: count used slots. */
	uint32_t count = 0;
	int rc = storage_count_slots_used(&count);

	if (rc) { *len = 0; return rc; }

	size_t off = 0;

	rc = cantil_cbor_emit_array(cbor_out, *len, &off, count);
	if (rc) { *len = 0; return -ENOMEM; }

	uint32_t emitted = 0;

	for (uint32_t slot = 0; slot < CONFIG_CANTIL_MAX_KEY_SLOTS; slot++) {
		if (storage_slot_key_exists(slot) != 1) continue;

		uint8_t  key_type   = 0;
		uint32_t protect_bits = 0;

		uint8_t meta_buf[64];
		size_t  meta_len = sizeof(meta_buf);

		if (storage_slot_meta_read(slot, meta_buf, &meta_len) == 0 &&
		    meta_len >= 24 && meta_buf[0] == 1) {
			key_type = meta_buf[1];
			protect_bits = (meta_buf[2] ? 0x01 : 0) |
				       (meta_buf[3] ? 0x02 : 0);
		}

		uint32_t has_cert = storage_slot_cert_exists(slot) == 1 ? 1 : 0;
		uint32_t has_csr  = storage_slot_csr_exists(slot)  == 1 ? 1 : 0;

		int e = cantil_cbor_emit_map(cbor_out, *len, &off, 5);
		if (!e) e = cantil_cbor_emit_tstr(cbor_out, *len, &off, "c", 1);
		if (!e) e = cantil_cbor_emit_uint(cbor_out, *len, &off, has_cert);
		if (!e) e = cantil_cbor_emit_tstr(cbor_out, *len, &off, "p", 1);
		if (!e) e = cantil_cbor_emit_uint(cbor_out, *len, &off, protect_bits);
		if (!e) e = cantil_cbor_emit_tstr(cbor_out, *len, &off, "r", 1);
		if (!e) e = cantil_cbor_emit_uint(cbor_out, *len, &off, has_csr);
		if (!e) e = cantil_cbor_emit_tstr(cbor_out, *len, &off, "s", 1);
		if (!e) e = cantil_cbor_emit_uint(cbor_out, *len, &off, slot);
		if (!e) e = cantil_cbor_emit_tstr(cbor_out, *len, &off, "t", 1);
		if (!e) e = cantil_cbor_emit_uint(cbor_out, *len, &off, key_type);
		if (e) { *len = 0; return -ENOMEM; }
		emitted++;
	}

	if (emitted != count) {
		*len = 0;
		return -EIO;   /* race between count and walk; bail */
	}
	*len = off;
	return 0;
}

int ca_gen_key(uint8_t key_type, uint32_t *slot_id_out)
{
	if (!slot_id_out) return -EINVAL;
	*slot_id_out = 0;

	/* Only P-256 supported in this iteration. Treat key_type==0 as the
	 * implicit P-256 default so older clients that don't pass a type byte
	 * still work. */
	if (key_type == 0) key_type = KEY_TYPE_P256;
	if (key_type != KEY_TYPE_P256) {
		LOG_WRN("ca_gen_key: unsupported key_type %u", key_type);
		return -ENOTSUP;
	}

	/* Find first free slot starting from 1 — slot 0 is reserved for the
	 * master CA. */
	uint32_t slot = UINT32_MAX;
	for (uint32_t i = 1; i < CONFIG_CANTIL_MAX_KEY_SLOTS; i++) {
		int ex = storage_slot_key_exists(i);
		if (ex < 0) return ex;
		if (ex == 0) { slot = i; break; }
	}
	if (slot == UINT32_MAX) {
		LOG_WRN("ca_gen_key: no free slots");
		return -ENOSPC;
	}

	/* Generate + encrypt. Mirrors ca_provision's slot 0 flow. */
	uint8_t storage_key[32];
	int rc = crypto_storage_key_derive(storage_key);
	if (rc) return rc;

	uint8_t privkey[64];
	size_t  privkey_len = sizeof(privkey);
	rc = crypto_keygen(privkey, &privkey_len);
	if (rc) {
		mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
		return rc;
	}

	uint8_t blob[KEY_BLOB_MAX];
	size_t  blob_len = sizeof(blob);
	rc = crypto_encrypt_blob(storage_key, privkey, privkey_len, blob, &blob_len);
	mbedtls_platform_zeroize(privkey, sizeof(privkey));
	mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
	if (rc) return rc;

	rc = storage_key_write(slot, blob, blob_len);
	mbedtls_platform_zeroize(blob, sizeof(blob));
	if (rc) return rc;

	slot_meta_t m = {
		.version        = 1,
		.key_type       = KEY_TYPE_P256,
		.is_protected   = 0,
		.protect_issued = 0,
	};
	rc = meta_write(slot, &m);
	if (rc) {
		LOG_ERR("ca_gen_key meta_write slot %u: %d", slot, rc);
		return rc;
	}

	*slot_id_out = slot;
	LOG_INF("ca_gen_key: allocated slot %u (P-256)", slot);
	return 0;
}

int ca_delete_key(uint32_t slot_id)
{
	if (slot_id == CA_SLOT) {
		LOG_WRN("ca_delete_key: refusing to delete CA slot 0");
		return -EPERM;
	}
	if (slot_id >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
		return -EINVAL;
	}
	if (storage_slot_key_exists(slot_id) != 1) {
		return -ENOENT;
	}

	slot_meta_t m;
	int rc = meta_read(slot_id, &m);

	if (rc == 0 && m.is_protected) {
		LOG_WRN("ca_delete_key: slot %u protected, refused", slot_id);
		return -EACCES;
	}

	rc = storage_slot_delete(slot_id);
	if (rc) {
		LOG_ERR("ca_delete_key storage err %d", rc);
		return rc;
	}
	LOG_INF("ca_delete_key: slot %u wiped", slot_id);
	return 0;
}

struct propagate_ctx { uint32_t slot; uint32_t count; };

static int propagate_protected_cb(const uint8_t *serial, size_t serial_len,
				  void *user)
{
	struct propagate_ctx *ctx = user;
	issued_cert_meta_t m;

	if (read_issued_meta(serial, serial_len, &m)) return 0;
	if (m.issuer_slot != ctx->slot) return 0;
	if (m.flags & ISSUED_FLAG_PROTECTED) return 0;
	m.flags |= ISSUED_FLAG_PROTECTED;
	if (storage_issued_meta_write(serial, serial_len,
				      (const uint8_t *)&m, sizeof(m)) == 0) {
		ctx->count++;
	}
	return 0;
}

int ca_protect_slot(uint32_t slot_id, bool protect_issued)
{
	if (slot_id >= CONFIG_CANTIL_MAX_KEY_SLOTS) return -EINVAL;
	if (storage_slot_key_exists(slot_id) != 1) return -ENOENT;

	slot_meta_t m;
	int rc = meta_read(slot_id, &m);

	if (rc) return rc;
	m.is_protected   = 1;
	m.protect_issued = protect_issued ? 1 : 0;
	rc = meta_write(slot_id, &m);
	if (rc) return rc;

	if (protect_issued) {
		struct propagate_ctx ctx = { .slot = slot_id };

		rc = storage_issued_certs_iter(propagate_protected_cb, &ctx);
		if (rc < 0) return rc;
		LOG_INF("ca_protect_slot %u: protected %u issued certs",
			slot_id, ctx.count);
	} else {
		LOG_INF("ca_protect_slot %u (issued certs untouched)", slot_id);
	}
	return 0;
}

int ca_unprotect_slot(uint32_t slot_id)
{
	if (slot_id >= CONFIG_CANTIL_MAX_KEY_SLOTS) return -EINVAL;
	if (storage_slot_key_exists(slot_id) != 1) return -ENOENT;

	slot_meta_t m;
	int rc = meta_read(slot_id, &m);

	if (rc) return rc;
	m.is_protected   = 0;
	m.protect_issued = 0;
	rc = meta_write(slot_id, &m);
	if (rc) return rc;
	LOG_INF("ca_unprotect_slot %u", slot_id);
	return 0;
}

int ca_gen_key_csr(uint32_t slot_id, const char *subject_dn)
{
	if (!subject_dn || subject_dn[0] == '\0') return -EINVAL;
	if (slot_id >= CONFIG_CANTIL_MAX_KEY_SLOTS) return -EINVAL;
	if (storage_slot_key_exists(slot_id) != 1) return -ENOENT;

	uint8_t privkey[32];
	size_t  privkey_len = sizeof(privkey);
	int rc = load_slot_privkey(slot_id, privkey, &privkey_len);

	if (rc || privkey_len != 32) {
		mbedtls_platform_zeroize(privkey, sizeof(privkey));
		return rc ? rc : -EIO;
	}

	struct slot_pk sp;
	mbedtls_x509write_csr req;

	slot_pk_init(&sp);
	mbedtls_x509write_csr_init(&req);

	rc = slot_pk_load_priv(privkey, privkey_len, &sp);
	if (rc) goto out;

	mbedtls_x509write_csr_set_key(&req, &sp.pk);
	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
	rc = mbedtls_x509write_csr_set_subject_name(&req, subject_dn);
	if (rc) {
		LOG_WRN("set_subject_name=-0x%04x", -rc);
		rc = -EINVAL;
		goto out;
	}

	uint8_t scratch[CERT_DER_MAX];
	int n = mbedtls_x509write_csr_der(&req, scratch, sizeof(scratch),
					  rng_cb, NULL);
	if (n < 0) {
		LOG_ERR("x509write_csr_der=-0x%04x", -n);
		rc = -EIO;
		goto out;
	}

	rc = storage_slot_csr_write(slot_id, scratch + sizeof(scratch) - n, n);
	if (rc) {
		LOG_ERR("csr_write=%d", rc);
	} else {
		LOG_INF("ca_gen_key_csr slot %u: wrote %d-byte CSR", slot_id, n);
	}

out:
	mbedtls_platform_zeroize(privkey, sizeof(privkey));
	mbedtls_x509write_csr_free(&req);
	slot_pk_free(&sp);
	return rc;
}

int ca_get_key_csr(uint32_t slot_id, uint8_t *csr_der, size_t *csr_len)
{
	return storage_slot_csr_read(slot_id, csr_der, csr_len);
}

/* Derive the uncompressed EC public point (65 B: 0x04 || X || Y) from a
 * slot's private scalar. Backend-agnostic — crypto_pubkey_from_privkey
 * dispatches to PSA (CC3XX/Oberon) or mbedtls software as configured. */
static int derive_slot_pubkey(uint32_t slot_id, uint8_t pub[65])
{
	uint8_t privkey[32];
	size_t  privkey_len = sizeof(privkey);
	int rc = load_slot_privkey(slot_id, privkey, &privkey_len);

	if (rc || privkey_len != 32) {
		mbedtls_platform_zeroize(privkey, sizeof(privkey));
		return rc ? rc : -EIO;
	}

	size_t pub_len = 65;

	rc = crypto_pubkey_from_privkey(privkey, privkey_len, pub, &pub_len);
	mbedtls_platform_zeroize(privkey, sizeof(privkey));
	if (rc) {
		return rc;
	}
	return (pub_len == 65) ? 0 : -EIO;
}

int ca_push_key_cert(uint32_t slot_id,
		     const uint8_t *cert_der, size_t cert_len,
		     const uint8_t *chain_der, size_t chain_len)
{
	if (!cert_der || cert_len == 0) return -EINVAL;
	if (slot_id >= CONFIG_CANTIL_MAX_KEY_SLOTS) return -EINVAL;
	if (storage_slot_key_exists(slot_id) != 1) return -ENOENT;

	/* Protected slot: refuse only if it already has a cert (otherwise
	 * the bootstrap exemption applies — same rule as PUSH_KEY_X509). */
	slot_meta_t m;
	int rc = meta_read(slot_id, &m);

	if (rc == 0 && m.is_protected &&
	    storage_slot_cert_exists(slot_id) == 1) {
		LOG_WRN("push_key_cert: slot %u protected, has cert — refused",
			slot_id);
		return -EACCES;
	}

	/* Validate the pushed cert parses cleanly and its pubkey matches
	 * the slot's. This blocks an externally-signed cert for the WRONG
	 * key being installed in the slot. */
	mbedtls_x509_crt parsed;

	mbedtls_x509_crt_init(&parsed);
	rc = mbedtls_x509_crt_parse_der(&parsed, cert_der, cert_len);
	if (rc) {
		LOG_WRN("push_key_cert parse=-0x%04x", -rc);
		mbedtls_x509_crt_free(&parsed);
		return -EINVAL;
	}

	/* Extract the cert's pubkey as raw SEC1 (0x04 || X || Y) via
	 * mbedtls_pk_write_pubkey — backend-agnostic, works for both the
	 * mbedtls-software PK type and the PSA-opaque PK type. mbedtls
	 * writes to the END of the supplied buffer and returns the length. */
	uint8_t cert_pub_buf[80];
	uint8_t *cert_pub_p = cert_pub_buf + sizeof(cert_pub_buf);
	int wlen = mbedtls_pk_write_pubkey(&cert_pub_p, cert_pub_buf, &parsed.pk);

	mbedtls_x509_crt_free(&parsed);

	if (wlen != 65 || cert_pub_p[0] != 0x04) {
		LOG_WRN("push_key_cert: cannot extract cert pubkey wlen=%d", wlen);
		return -EINVAL;
	}

	uint8_t slot_pub[65];

	rc = derive_slot_pubkey(slot_id, slot_pub);
	if (rc) {
		LOG_ERR("push_key_cert: derive_slot_pubkey=%d", rc);
		return rc;
	}
	if (memcmp(cert_pub_p, slot_pub, 65) != 0) {
		LOG_WRN("push_key_cert: cert pubkey != slot pubkey");
		return -EINVAL;
	}

	rc = storage_slot_cert_write(slot_id, cert_der, cert_len);
	if (rc) {
		LOG_ERR("push_key_cert storage=%d", rc);
		return rc;
	}

	if (chain_len > 0 && chain_der != NULL) {
		rc = storage_slot_chain_write(slot_id, chain_der, chain_len);
		if (rc) {
			LOG_ERR("push_key_cert: chain_write=%d", rc);
			return rc;
		}
	} else {
		(void)storage_slot_chain_delete(slot_id);
	}

	LOG_INF("push_key_cert: slot %u installed (%zu bytes, %zu chain)",
		slot_id, cert_len, chain_len);
	return 0;
}

int ca_sign_key_slot(uint32_t issuer_slot, uint32_t subject_slot)
{
	if (issuer_slot >= CONFIG_CANTIL_MAX_KEY_SLOTS ||
	    subject_slot >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
		return -EINVAL;
	}
	if (storage_slot_key_exists(issuer_slot) != 1) return -ENOENT;
	if (storage_slot_key_exists(subject_slot) != 1) return -ENOENT;

	x509_params_t issuer_params, subject_params;
	int rc = load_issuer_x509_params(issuer_slot, &issuer_params);

	if (rc) { LOG_WRN("issuer slot %u x509 missing", issuer_slot); return -ENOENT; }
	rc = load_issuer_x509_params(subject_slot, &subject_params);
	if (rc) { LOG_WRN("subject slot %u x509 missing", subject_slot); return -ENOENT; }

	uint8_t subject_pub[65];
	rc = derive_slot_pubkey(subject_slot, subject_pub);
	if (rc) return rc;

	uint8_t issuer_priv[32];
	size_t  issuer_priv_len = sizeof(issuer_priv);
	rc = load_slot_privkey(issuer_slot, issuer_priv, &issuer_priv_len);
	if (rc || issuer_priv_len != 32) {
		mbedtls_platform_zeroize(issuer_priv, sizeof(issuer_priv));
		return rc ? rc : -EIO;
	}

	struct slot_pk subject_sp, issuer_sp;
	mbedtls_x509write_cert crt;
	char issuer_dn[DN_MAX], subject_dn[DN_MAX], not_after[15];
	uint8_t serial[8];

	slot_pk_init(&subject_sp);
	slot_pk_init(&issuer_sp);
	mbedtls_x509write_crt_init(&crt);

	rc = slot_pk_load_pub(subject_pub, &subject_sp);
	if (rc) goto out;

	rc = slot_pk_load_priv(issuer_priv, issuer_priv_len, &issuer_sp);
	if (rc) goto out;

	rc = build_dn(&issuer_params, issuer_dn, sizeof(issuer_dn));
	if (rc) goto out;
	rc = build_dn(&subject_params, subject_dn, sizeof(subject_dn));
	if (rc) goto out;

	rc = mbedtls_x509write_crt_set_issuer_name(&crt, issuer_dn);
	if (rc) goto out;
	rc = mbedtls_x509write_crt_set_subject_name(&crt, subject_dn);
	if (rc) goto out;
	mbedtls_x509write_crt_set_subject_key(&crt, &subject_sp.pk);
	mbedtls_x509write_crt_set_issuer_key(&crt, &issuer_sp.pk);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

	rc = crypto_trng(serial, sizeof(serial));
	if (rc) goto out;
	serial[0] = (serial[0] & 0x7F) | 0x01;
	rc = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
	if (rc) goto out;

	compute_not_after(SIGN_CSR_VALIDITY_DAYS, not_after);
	rc = mbedtls_x509write_crt_set_validity(&crt, NOT_BEFORE_BASE, not_after);
	if (rc) goto out;

	/* Honour the subject's stored is_ca flag — sub-CA chains can stack. */
	int is_ca = subject_params.is_ca ? 1 : 0;
	int path  = (subject_params.path_len == 0xFF) ? -1
						      : subject_params.path_len;
	rc = mbedtls_x509write_crt_set_basic_constraints(&crt, is_ca, path);
	if (rc) goto out;

	uint16_t ku = subject_params.key_usage;
	if (is_ca) ku |= KU_KEY_CERT_SIGN | KU_CRL_SIGN;
	if (!ku) ku = KU_DIGITAL_SIGNATURE;
	rc = mbedtls_x509write_crt_set_key_usage(&crt, ku);
	if (rc) goto out;

	uint8_t der[CERT_DER_MAX];
	int n = mbedtls_x509write_crt_der(&crt, der, sizeof(der), rng_cb, NULL);

	if (n < 0) {
		LOG_ERR("x509write_crt_der=-0x%04x", -n);
		rc = -EIO;
		goto out;
	}
	const uint8_t *cert_start = der + sizeof(der) - n;

	rc = storage_slot_cert_write(subject_slot, cert_start, n);
	if (rc) goto out;

	/* New cert was signed by another on-device slot — discard any stale
	 * externally-pushed chain. The walker will recurse to issuer_slot. */
	(void)storage_slot_chain_delete(subject_slot);

	rc = storage_issued_cert_write(serial, sizeof(serial), cert_start, n);
	if (rc) goto out;

	issued_cert_meta_t meta = {
		.version         = 1,
		.flags           = 0,
		.serial_len      = sizeof(serial),
		.issuer_slot     = issuer_slot,
		.not_before_unix = SIGN_CSR_NOT_BEFORE_UNIX,
		.not_after_unix  = SIGN_CSR_NOT_BEFORE_UNIX +
				   (uint64_t)SIGN_CSR_VALIDITY_DAYS * 86400ULL,
	};
	memcpy(meta.serial, serial, sizeof(serial));
	size_t cn_len = 0;
	while (cn_len < sizeof(meta.cn) - 1 &&
	       subject_params.cn[cn_len] != '\0') {
		meta.cn[cn_len] = subject_params.cn[cn_len];
		cn_len++;
	}
	meta.cn[cn_len] = '\0';
	rc = storage_issued_meta_write(serial, sizeof(serial),
				       (const uint8_t *)&meta, sizeof(meta));
	if (rc) goto out;

	LOG_INF("ca_sign_key_slot: issuer=%u subject=%u, cert installed",
		issuer_slot, subject_slot);
	rc = 0;

out:
	mbedtls_platform_zeroize(issuer_priv, sizeof(issuer_priv));
	mbedtls_x509write_crt_free(&crt);
	slot_pk_free(&issuer_sp);
	slot_pk_free(&subject_sp);
	return rc;
}

/* ── RFC 5280 v2 CertificateList DER encoder ───────────────────────────── */
/*
 * Builds and signs a CRL on demand. The packed-blob source-of-truth is
 * intentionally gone; the encoder iterates /certs/ each call and produces
 * a fresh, signed DER blob. Costs ~one ECDSA sign per fetch (~10 ms on
 * CC310). See task 2 design notes in conversation_042.md.
 *
 * Capacity budget (rough): 64 entries × ~30 bytes each + ~250 bytes header
 * ~= 2.2 KB. Caller passes a 2.5 KB buffer; we conservatively cap entries
 * at 64 to keep stack usage bounded.
 */

#define CRL_MAX_REVOKED   64
#define CRL_TIME_BUF      32

struct crl_entry {
	uint8_t  serial[20];
	uint8_t  serial_len;
	uint64_t revoked_at_unix;   /* 0 → encoder substitutes thisUpdate */
};

struct crl_collect_ctx {
	uint32_t            target_slot;
	uint64_t            this_update;
	struct crl_entry    entries[CRL_MAX_REVOKED];
	size_t              count;
	int                 overflow;
};

static int crl_collect_cb(const uint8_t *serial, size_t serial_len, void *user)
{
	struct crl_collect_ctx *ctx = user;
	issued_cert_meta_t m;

	if (read_issued_meta(serial, serial_len, &m)) return 0;
	if (m.issuer_slot != ctx->target_slot)       return 0;
	if (!(m.flags & ISSUED_FLAG_REVOKED))        return 0;

	if (ctx->count >= CRL_MAX_REVOKED) {
		ctx->overflow = 1;
		return 0;
	}
	struct crl_entry *e = &ctx->entries[ctx->count++];
	memcpy(e->serial, serial, serial_len);
	e->serial_len = (uint8_t)serial_len;
	e->revoked_at_unix = m.revoked_at_unix
		? m.revoked_at_unix : ctx->this_update;
	return 0;
}

/* Convert Unix epoch seconds → broken-down UTC components. Year is the
 * full Gregorian year (e.g. 2026), month is 1..12, day is 1..31. */
static void unix_to_ymdhms(uint64_t secs, int *Y, int *M, int *D,
			   int *h, int *m, int *sec)
{
	uint64_t days = secs / 86400;
	uint32_t sod  = (uint32_t)(secs % 86400);

	*h   = (int)(sod / 3600);
	*m   = (int)((sod % 3600) / 60);
	*sec = (int)(sod % 60);

	int year = 1970;
	for (;;) {
		int leap = (((year & 3) == 0) && (year % 100 != 0))
			|| (year % 400 == 0);
		uint32_t yd = leap ? 366 : 365;
		if (days < yd) break;
		days -= yd;
		year++;
	}
	*Y = year;

	static const uint8_t mdn[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
	int leap = (((year & 3) == 0) && (year % 100 != 0))
		|| (year % 400 == 0);
	int mo = 0;
	for (;;) {
		uint8_t md = mdn[mo] + ((mo == 1 && leap) ? 1 : 0);
		if (days < md) break;
		days -= md;
		mo++;
	}
	*M = mo + 1;
	*D = (int)days + 1;
}

/* Write a Time element backwards into *p. UTCTime for years in [1950,2050),
 * GeneralizedTime otherwise, per RFC 5280 §5.1.2.4. Both end in 'Z'. */
static int write_time(uint8_t **p, uint8_t *start, uint64_t unix_secs)
{
	int Y, M, D, h, m, s;
	unix_to_ymdhms(unix_secs, &Y, &M, &D, &h, &m, &s);

	uint8_t buf[CRL_TIME_BUF];
	size_t  buf_len;
	int     tag;

	if (Y >= 1950 && Y < 2050) {
		snprintf((char *)buf, sizeof(buf),
			 "%02d%02d%02d%02d%02d%02dZ",
			 Y % 100, M, D, h, m, s);
		buf_len = 13;
		tag = MBEDTLS_ASN1_UTC_TIME;
	} else {
		snprintf((char *)buf, sizeof(buf),
			 "%04d%02d%02d%02d%02d%02dZ",
			 Y, M, D, h, m, s);
		buf_len = 15;
		tag = MBEDTLS_ASN1_GENERALIZED_TIME;
	}

	int ret, len = 0;
	MBEDTLS_ASN1_CHK_ADD(len,
		mbedtls_asn1_write_raw_buffer(p, start, buf, buf_len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, buf_len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, tag));
	return len;
}

/* Write an INTEGER for a variable-length cert serial. Caller guarantees
 * len ≥ 1. Prepends a 0x00 pad if the high bit is set (to keep it
 * positive). */
static int write_serial_int(uint8_t **p, uint8_t *start,
			    const uint8_t *serial, size_t serial_len)
{
	if (serial_len == 0 || serial_len > 20) {
		return MBEDTLS_ERR_ASN1_INVALID_DATA;
	}
	int ret, len = 0;
	int pad = (serial[0] & 0x80) ? 1 : 0;

	MBEDTLS_ASN1_CHK_ADD(len,
		mbedtls_asn1_write_raw_buffer(p, start, serial, serial_len));
	if (pad) {
		if (*p <= start) return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
		(*p)--;
		**p = 0x00;
		len++;
	}
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
				 MBEDTLS_ASN1_INTEGER));
	return len;
}

/* One revokedCertificates SEQUENCE { userCertificate INTEGER,
 * revocationDate Time }. */
static int write_revoked_entry(uint8_t **p, uint8_t *start,
			       const struct crl_entry *e)
{
	int ret, len = 0;

	MBEDTLS_ASN1_CHK_ADD(len, write_time(p, start, e->revoked_at_unix));
	MBEDTLS_ASN1_CHK_ADD(len, write_serial_int(p, start,
				 e->serial, e->serial_len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
				 MBEDTLS_ASN1_CONSTRUCTED |
				 MBEDTLS_ASN1_SEQUENCE));
	return len;
}

/* crlExtensions [0] EXPLICIT SEQUENCE OF Extension { cRLNumber }. */
static int write_crl_extensions(uint8_t **p, uint8_t *start,
				uint32_t crl_number)
{
	int ret, len = 0;
	int ext_len = 0;
	int extn_inner_len = 0;

	/* OCTET STRING containing INTEGER crl_number */
	MBEDTLS_ASN1_CHK_ADD(extn_inner_len,
		mbedtls_asn1_write_int(p, start, (int)crl_number));
	MBEDTLS_ASN1_CHK_ADD(extn_inner_len,
		mbedtls_asn1_write_len(p, start, extn_inner_len));
	MBEDTLS_ASN1_CHK_ADD(extn_inner_len,
		mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));

	/* OID id-ce-cRLNumber (2.5.29.20) */
	MBEDTLS_ASN1_CHK_ADD(extn_inner_len,
		mbedtls_asn1_write_oid(p, start, MBEDTLS_OID_CRL_NUMBER,
				       MBEDTLS_OID_SIZE(MBEDTLS_OID_CRL_NUMBER)));

	/* Wrap as Extension SEQUENCE */
	MBEDTLS_ASN1_CHK_ADD(extn_inner_len,
		mbedtls_asn1_write_len(p, start, extn_inner_len));
	MBEDTLS_ASN1_CHK_ADD(extn_inner_len,
		mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
				       MBEDTLS_ASN1_SEQUENCE));
	ext_len += extn_inner_len;

	/* Wrap as SEQUENCE OF Extension */
	MBEDTLS_ASN1_CHK_ADD(ext_len, mbedtls_asn1_write_len(p, start, ext_len));
	MBEDTLS_ASN1_CHK_ADD(ext_len, mbedtls_asn1_write_tag(p, start,
				 MBEDTLS_ASN1_CONSTRUCTED |
				 MBEDTLS_ASN1_SEQUENCE));
	len += ext_len;

	/* Wrap in [0] EXPLICIT */
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
				 MBEDTLS_ASN1_CONTEXT_SPECIFIC |
				 MBEDTLS_ASN1_CONSTRUCTED | 0));
	return len;
}

/* AlgorithmIdentifier ::= SEQUENCE { OID ecdsa-with-SHA256 } (no params). */
static int write_alg_ecdsa_sha256(uint8_t **p, uint8_t *start)
{
	int ret, len = 0;
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start,
		MBEDTLS_OID_ECDSA_SHA256,
		MBEDTLS_OID_SIZE(MBEDTLS_OID_ECDSA_SHA256)));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
				 MBEDTLS_ASN1_CONSTRUCTED |
				 MBEDTLS_ASN1_SEQUENCE));
	return len;
}

/*
 * Build the TBSCertList into [out, out+cap), writing backwards. On success
 * returns bytes written; tbs DER lives at [end-len, end). Updates *out_off
 * to the offset of the first TBS byte (so the caller can hash + sign).
 */
static int write_tbs_cert_list(uint8_t *out, size_t cap, size_t *out_off,
			       const uint8_t *issuer_raw, size_t issuer_raw_len,
			       uint64_t this_update, uint64_t next_update,
			       const struct crl_entry *entries, size_t n_entries,
			       uint32_t crl_number)
{
	uint8_t *p = out + cap;
	uint8_t *start = out;
	int ret, len = 0;

	/* crlExtensions (always present — we always emit cRLNumber) */
	MBEDTLS_ASN1_CHK_ADD(len, write_crl_extensions(&p, start, crl_number));

	/* revokedCertificates SEQUENCE OF (optional — omitted when empty) */
	if (n_entries > 0) {
		int rc_len = 0;
		/* Entries are written in reverse iteration order so they appear
		 * in `entries[]` order in the encoded DER. */
		for (int i = (int)n_entries - 1; i >= 0; i--) {
			MBEDTLS_ASN1_CHK_ADD(rc_len,
				write_revoked_entry(&p, start, &entries[i]));
		}
		MBEDTLS_ASN1_CHK_ADD(rc_len,
			mbedtls_asn1_write_len(&p, start, rc_len));
		MBEDTLS_ASN1_CHK_ADD(rc_len,
			mbedtls_asn1_write_tag(&p, start,
				 MBEDTLS_ASN1_CONSTRUCTED |
				 MBEDTLS_ASN1_SEQUENCE));
		len += rc_len;
	}

	/* nextUpdate */
	MBEDTLS_ASN1_CHK_ADD(len, write_time(&p, start, next_update));
	/* thisUpdate */
	MBEDTLS_ASN1_CHK_ADD(len, write_time(&p, start, this_update));

	/* Issuer Name — raw bytes lifted from the slot's cert subject_raw */
	MBEDTLS_ASN1_CHK_ADD(len,
		mbedtls_asn1_write_raw_buffer(&p, start, issuer_raw,
					      issuer_raw_len));
	len += 0;  /* raw_buffer already counted in CHK_ADD above */

	/* signature AlgorithmIdentifier (matches the outer signatureAlgorithm) */
	MBEDTLS_ASN1_CHK_ADD(len, write_alg_ecdsa_sha256(&p, start));

	/* version INTEGER (1 == v2 per RFC 5280) */
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, start, 1));

	/* Wrap as TBSCertList SEQUENCE */
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, start,
				 MBEDTLS_ASN1_CONSTRUCTED |
				 MBEDTLS_ASN1_SEQUENCE));

	*out_off = (size_t)(p - out);
	return len;
}

static int build_crl_der(uint32_t issuer_slot, uint64_t now_unix,
			 uint8_t *out, size_t out_cap, size_t *out_len)
{
	int rc;
	int ret;   /* used by MBEDTLS_ASN1_CHK_ADD during the final wrap */

	/* Collect entries first. */
	struct crl_collect_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.target_slot = issuer_slot;
	ctx.this_update = now_unix;

	rc = storage_issued_certs_iter(crl_collect_cb, &ctx);
	if (rc < 0) return rc;
	if (ctx.overflow) {
		LOG_WRN("CRL slot %u overflow — truncated to %u entries",
			issuer_slot, (unsigned)ctx.count);
	}

	/* CRL number — bumped on revoke, so a fresh GET_CRL just reads it. */
	uint32_t crl_number = 0;
	(void)storage_slot_crl_number_read(issuer_slot, &crl_number);
	if (crl_number == 0) {
		crl_number = 1;  /* RFC 5280 cRLNumber MUST be ≥ 0; 1 for the
				  * empty-CRL case so verifiers don't have to
				  * special-case 0. */
	}

	/* Lift issuer Name bytes from the slot's self-signed cert. */
	uint8_t issuer_cert[CERT_DER_MAX];
	size_t  issuer_cert_len = sizeof(issuer_cert);
	rc = storage_slot_cert_read(issuer_slot, issuer_cert, &issuer_cert_len);
	if (rc) return rc;

	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
	rc = mbedtls_x509_crt_parse_der(&crt, issuer_cert, issuer_cert_len);
	if (rc) {
		LOG_ERR("CRL issuer cert parse=%d", rc);
		mbedtls_x509_crt_free(&crt);
		return -EIO;
	}
	const uint8_t *issuer_raw = crt.subject_raw.p;
	size_t issuer_raw_len = crt.subject_raw.len;

	/* nextUpdate: thisUpdate + Kconfig validity window. */
	uint64_t next_update = now_unix + CONFIG_CANTIL_CRL_VALIDITY_SEC;

	/* Build TBS into a static scratch buffer (backwards). We can't reuse
	 * the caller's output buffer directly: in DER order the layout is
	 * SEQUENCE { TBS, sigAlg, sigValue }, but the mbedtls writers go
	 * right-to-left. Putting TBS first into `out` and then prepending
	 * sigAlg/sigValue would land them to the LEFT of TBS, inverting the
	 * required order. So we encode TBS once in scratch, then assemble the
	 * outer SEQUENCE into `out` in DER-correct order.
	 *
	 * Static (BSS) instead of stack: CRL fetch is single-command-in-flight,
	 * scratch is ~2 KB which would dominate this thread's stack budget. */
	static uint8_t tbs_scratch[CERT_DER_MAX];
	size_t tbs_off = 0;
	int tbs_len = write_tbs_cert_list(tbs_scratch, sizeof(tbs_scratch),
					  &tbs_off,
					  issuer_raw, issuer_raw_len,
					  now_unix, next_update,
					  ctx.entries, ctx.count, crl_number);
	mbedtls_x509_crt_free(&crt);
	if (tbs_len < 0) {
		LOG_ERR("TBSCertList encode=%d", tbs_len);
		return (tbs_len == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
			? -ENOMEM : -EIO;
	}
	const uint8_t *tbs_bytes = tbs_scratch + tbs_off;

	/* Hash the encoded TBS. */
	uint8_t hash[32];
	rc = mbedtls_sha256(tbs_bytes, (size_t)tbs_len, hash, 0);
	if (rc) return -EIO;

	/* Sign with the issuer slot's privkey. */
	uint8_t privkey[32];
	size_t  privkey_len = sizeof(privkey);
	rc = load_slot_privkey(issuer_slot, privkey, &privkey_len);
	if (rc || privkey_len != 32) {
		mbedtls_platform_zeroize(privkey, sizeof(privkey));
		return rc ? rc : -EIO;
	}

	struct slot_pk sp;

	slot_pk_init(&sp);
	rc = slot_pk_load_priv(privkey, privkey_len, &sp);
	if (rc) goto sign_out;

	uint8_t sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
	size_t  sig_len = 0;
	rc = mbedtls_pk_sign(&sp.pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
			     sig, sizeof(sig), &sig_len,
			     rng_cb, NULL);
	if (rc) {
		LOG_ERR("CRL sign=%d", rc);
		rc = -EIO;
		goto sign_out;
	}

	rc = 0;

sign_out:
	mbedtls_platform_zeroize(privkey, sizeof(privkey));
	slot_pk_free(&sp);
	if (rc) return rc;

	/*
	 * Assemble CertificateList in `out`, writing backwards from the right
	 * end. DER order is { TBS, sigAlg, sigValue }, so we write rightmost
	 * first:
	 *   1. signatureValue BIT STRING
	 *   2. signatureAlgorithm
	 *   3. TBS bytes (copied from scratch)
	 *   4. outer SEQUENCE tag+len
	 */
	uint8_t *p     = out + out_cap;
	uint8_t *start = out;
	int outer_len  = 0;

	/* signatureValue BIT STRING */
	{
		int sv_len = 0;
		MBEDTLS_ASN1_CHK_ADD(sv_len,
			mbedtls_asn1_write_raw_buffer(&p, start, sig, sig_len));
		if (p <= start) return -ENOMEM;
		(*--p) = 0x00;          /* unused-bits prefix */
		sv_len++;
		MBEDTLS_ASN1_CHK_ADD(sv_len,
			mbedtls_asn1_write_len(&p, start, sv_len));
		MBEDTLS_ASN1_CHK_ADD(sv_len,
			mbedtls_asn1_write_tag(&p, start,
				 MBEDTLS_ASN1_BIT_STRING));
		outer_len += sv_len;
	}

	/* signatureAlgorithm */
	{
		int alg_len = 0;
		MBEDTLS_ASN1_CHK_ADD(alg_len,
			write_alg_ecdsa_sha256(&p, start));
		outer_len += alg_len;
	}

	/* TBS — memcpy from scratch backwards (bytes preserve order). */
	if ((size_t)(p - start) < (size_t)tbs_len) return -ENOMEM;
	p -= tbs_len;
	memcpy(p, tbs_bytes, (size_t)tbs_len);
	outer_len += tbs_len;

	/* Outer CertificateList SEQUENCE wrapper */
	MBEDTLS_ASN1_CHK_ADD(outer_len,
		mbedtls_asn1_write_len(&p, start, outer_len));
	MBEDTLS_ASN1_CHK_ADD(outer_len,
		mbedtls_asn1_write_tag(&p, start,
			 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	/* Move the encoded CRL to the front of the buffer. */
	memmove(out, p, (size_t)outer_len);
	*out_len = (size_t)outer_len;
	return 0;
}
