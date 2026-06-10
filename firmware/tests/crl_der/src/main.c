/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * RFC 5280 v2 CertificateList (DER CRL) conformance on native_sim — task 2
 * of the CRL roadmap.
 *
 * Drives ca_get_crl() / ca_revoke_cert() / ca_revoke_cert_at end-to-end.
 * Every returned CRL is parsed with mbedtls_x509_crl_parse_der and, where
 * appropriate, its signature is verified against the issuer slot's pubkey
 * using mbedtls_pk_verify on the TBS hash. We exercise:
 *
 *   1. empty CRL (parses, zero entries)
 *   2. single revoke (parses, one entry, serial match)
 *   3. multi revoke (parses, three entries)
 *   4. signature verifies under slot 0
 *   5. sub-CA chain — slot 1 signs end-entities + its own CRL
 *   6. crlNumber monotonic across two fetches
 *   7. now=0 rejected
 *   8. out-of-range + unpopulated slot rejected
 *   9. nextUpdate - thisUpdate == CONFIG_CANTIL_CRL_VALIDITY_SEC
 *  10. per-slot isolation: slot 0 and slot 1 CRLs hold only their own serials
 *  11. revocationDate substitution: revoke with now=0, fetch with now=T,
 *      entry's revocationDate == T (thisUpdate)
 *  12. revocationDate preserved: revoke with now=T0, entry holds T0 verbatim
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/fs/fs.h>
#include <string.h>
#include <errno.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/oid.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>

#include "ca/ca.h"
#include "crypto/crypto.h"
#include "storage/storage.h"
#include "cantil_cbor.h"

#define LFS_MOUNT  "/lfs"
#define CERTS_DIR  LFS_MOUNT "/certs"

/* Plausible 2026-ish "now" so UTCTime encoding is used. */
#define NOW_DEFAULT  ((uint64_t)1767225600)   /* 2026-01-01 00:00:00 UTC */

static int trng_rng_cb(void *ctx, unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);
	return crypto_trng(buf, len) ? -1 : 0;
}

/* Build the same x509-data blob as the sign_csr suite — keeps tests
 * comparable. */
static size_t build_x509_blob(uint8_t *out, size_t cap)
{
	size_t off = 0;
	const char *cn = "Cantil CA";
	const char *o  = "Cantil";

	zassert_true(cap >= 32, "blob too small");
	out[off++] = 0x01; out[off++] = 0x68;   /* validity_days = 360 */
	out[off++] = 1;                         /* is_ca */
	out[off++] = 0;                         /* path_len */
	out[off++] = 0x00; out[off++] = 0x86;   /* digital_sig | keyCertSign | cRLSign */
	out[off++] = (uint8_t)strlen(cn); memcpy(&out[off], cn, strlen(cn)); off += strlen(cn);
	out[off++] = (uint8_t)strlen(o);  memcpy(&out[off], o,  strlen(o));  off += strlen(o);
	out[off++] = 0; out[off++] = 0; out[off++] = 0; out[off++] = 0;
	return off;
}

static void wipe_dir(const char *dir)
{
	struct fs_dir_t d;
	struct fs_dirent ent;
	char path[128];

	fs_dir_t_init(&d);
	if (fs_opendir(&d, dir) != 0) return;
	while (fs_readdir(&d, &ent) == 0 && ent.name[0] != '\0') {
		snprintf(path, sizeof(path), "%s/%s", dir, ent.name);
		if (ent.type == FS_DIR_ENTRY_DIR) {
			wipe_dir(path);
		} else {
			fs_unlink(path);
		}
	}
	fs_closedir(&d);
	fs_unlink(dir);
}

static int gen_csr(uint8_t *csr_der_out, size_t csr_cap,
		   mbedtls_pk_context *pk_out, const char *subject)
{
	mbedtls_x509write_csr req;
	mbedtls_x509write_csr_init(&req);
	mbedtls_pk_init(pk_out);

	zassert_equal(mbedtls_pk_setup(pk_out,
		      mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)), 0, "pk_setup");
	zassert_equal(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
		      mbedtls_pk_ec(*pk_out), trng_rng_cb, NULL), 0, "gen_key");

	mbedtls_x509write_csr_set_key(&req, pk_out);
	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
	zassert_equal(mbedtls_x509write_csr_set_subject_name(&req, subject), 0,
		      "set_subject");

	uint8_t scratch[1024];
	int n = mbedtls_x509write_csr_der(&req, scratch, sizeof(scratch),
					  trng_rng_cb, NULL);
	zassert_true(n > 0 && (size_t)n <= csr_cap, "csr_der");
	memcpy(csr_der_out, scratch + sizeof(scratch) - n, n);
	mbedtls_x509write_csr_free(&req);
	return n;
}

/*
 * Sign one CSR under the given issuer slot. Stores the parsed cert into
 * `out`. Caller frees the cert via mbedtls_x509_crt_free.
 */
static void sign_one_under(uint32_t issuer_slot, const char *cn,
			   mbedtls_x509_crt *parsed_out)
{
	uint8_t csr[512];
	mbedtls_pk_context pk;
	size_t cl = gen_csr(csr, sizeof(csr), &pk, cn);

	uint8_t cert[1500];
	size_t certl = sizeof(cert);

	int rc = (issuer_slot == 0)
		? ca_sign_csr(csr, cl, cert, &certl)
		: ca_sign_csr_slot(issuer_slot, csr, cl, cert, &certl);
	zassert_equal(rc, 0, "sign_csr(slot=%u)=%d", issuer_slot, rc);

	mbedtls_x509_crt_init(parsed_out);
	zassert_equal(mbedtls_x509_crt_parse_der(parsed_out, cert, certl), 0,
		      "parse issued");

	mbedtls_pk_free(&pk);
}

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init");
	return NULL;
}

static void test_before(void *fixture)
{
	ARG_UNUSED(fixture);
	char p[64];
	for (uint32_t i = 0; i < 8; i++) {
		snprintf(p, sizeof(p), LFS_MOUNT "/keys/%u", i);
		wipe_dir(p);
	}
	wipe_dir(CERTS_DIR);
}

static void bootstrap_slot0(void)
{
	zassert_ok(ca_init(), "ca_init");
	uint8_t blob[256];
	size_t len = build_x509_blob(blob, sizeof(blob));
	zassert_ok(ca_push_key_x509(0, blob, len), "push_key_x509");
	zassert_true(ca_ready(), "ca_ready");
}

/* Stand up a sub-CA at the next free slot, return its id. */
static uint32_t stand_up_subca(void)
{
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen sub-CA");
	uint8_t blob[256];
	size_t blob_len = build_x509_blob(blob, sizeof(blob));
	zassert_ok(ca_push_key_x509(slot, blob, blob_len), "push x509 sub-CA");
	return slot;
}

/* Load slot's cert and extract its public key for CRL signature verify. */
static void load_slot_pubkey(uint32_t slot, mbedtls_pk_context *pk_out)
{
	uint8_t cert[1500];
	size_t  cl = sizeof(cert);
	zassert_ok(storage_slot_cert_read(slot, cert, &cl), "cert read");

	mbedtls_x509_crt parsed;
	mbedtls_x509_crt_init(&parsed);
	zassert_equal(mbedtls_x509_crt_parse_der(&parsed, cert, cl), 0, "parse");

	/* Copy the pk into a freestanding context (pk is owned by parsed). */
	mbedtls_pk_init(pk_out);
	zassert_equal(mbedtls_pk_setup(pk_out,
		      mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)), 0, "pk_setup");

	const mbedtls_ecp_keypair *src = mbedtls_pk_ec(parsed.pk);
	mbedtls_ecp_keypair *dst = mbedtls_pk_ec(*pk_out);
	zassert_equal(mbedtls_ecp_group_copy(&dst->MBEDTLS_PRIVATE(grp),
					     &src->MBEDTLS_PRIVATE(grp)), 0, "grp");
	zassert_equal(mbedtls_ecp_copy(&dst->MBEDTLS_PRIVATE(Q),
				       &src->MBEDTLS_PRIVATE(Q)), 0, "Q");

	mbedtls_x509_crt_free(&parsed);
}

/* Hash crl->tbs and verify crl->sig against pubkey using mbedtls_pk_verify. */
static void verify_crl_signature(const mbedtls_x509_crl *crl,
				 mbedtls_pk_context *issuer_pk)
{
	uint8_t hash[32];
	int rc = mbedtls_sha256(crl->tbs.p, crl->tbs.len, hash, 0);
	zassert_equal(rc, 0, "sha256=%d", rc);

	rc = mbedtls_pk_verify(issuer_pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
			       crl->MBEDTLS_PRIVATE(sig).p, crl->MBEDTLS_PRIVATE(sig).len);
	zassert_equal(rc, 0, "pk_verify=%d", rc);
}

/* Convert mbedtls_x509_time → Unix seconds (UTC, ignoring leap seconds). */
static uint64_t x509_time_to_unix(const mbedtls_x509_time *t)
{
	int y = t->year, mo = t->mon, d = t->day;
	int h = t->hour, mi = t->min, s = t->sec;

	static const int mdn[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
	uint64_t days = 0;
	for (int yy = 1970; yy < y; yy++) {
		int leap = ((yy & 3) == 0 && yy % 100 != 0) || (yy % 400 == 0);
		days += leap ? 366 : 365;
	}
	int leap_y = ((y & 3) == 0 && y % 100 != 0) || (y % 400 == 0);
	for (int mm = 1; mm < mo; mm++) {
		days += mdn[mm - 1] + ((mm == 2 && leap_y) ? 1 : 0);
	}
	days += (d - 1);
	return days * 86400 + (uint64_t)h * 3600 + (uint64_t)mi * 60 + s;
}

/* Count entries in a parsed CRL (mbedtls stores them as a linked list). */
static size_t count_entries(const mbedtls_x509_crl *crl)
{
	size_t n = 0;
	for (const mbedtls_x509_crl_entry *e = &crl->entry;
	     e != NULL && e->raw.len != 0;
	     e = e->next) {
		n++;
	}
	return n;
}

/* Find an entry by serial bytes; returns NULL if not present. */
static const mbedtls_x509_crl_entry *
find_entry(const mbedtls_x509_crl *crl, const uint8_t *serial, size_t sl)
{
	for (const mbedtls_x509_crl_entry *e = &crl->entry;
	     e != NULL && e->raw.len != 0;
	     e = e->next) {
		if (e->serial.len == sl &&
		    memcmp(e->serial.p, serial, sl) == 0) {
			return e;
		}
	}
	return NULL;
}

ZTEST_SUITE(crl_der, NULL, suite_setup, test_before, NULL, NULL);

/* ── tests ──────────────────────────────────────────────────────────────── */

ZTEST(crl_der, test_01_empty_crl_parses)
{
	bootstrap_slot0();

	uint8_t crl_der[2048]; size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");
	zassert_true(crl_len > 0, "crl_len=%zu", crl_len);

	mbedtls_x509_crl crl;
	mbedtls_x509_crl_init(&crl);
	int rc = mbedtls_x509_crl_parse_der(&crl, crl_der, crl_len);
	zassert_equal(rc, 0, "crl_parse_der=%d", rc);
	zassert_equal(count_entries(&crl), 0u, "empty crl has zero entries");
	mbedtls_x509_crl_free(&crl);
}

ZTEST(crl_der, test_02_single_revoke_one_entry)
{
	bootstrap_slot0();

	mbedtls_x509_crt issued;
	sign_one_under(0, "CN=victim-01", &issued);
	zassert_ok(ca_revoke_cert(issued.serial.p, issued.serial.len,
				  NOW_DEFAULT), "revoke");

	uint8_t crl_der[2048]; size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	mbedtls_x509_crl crl;
	mbedtls_x509_crl_init(&crl);
	zassert_equal(mbedtls_x509_crl_parse_der(&crl, crl_der, crl_len), 0,
		      "parse_der");
	zassert_equal(count_entries(&crl), 1u, "one entry");
	zassert_not_null(find_entry(&crl, issued.serial.p, issued.serial.len),
			 "serial present");

	mbedtls_x509_crl_free(&crl);
	mbedtls_x509_crt_free(&issued);
}

ZTEST(crl_der, test_03_multi_revoke_three_entries)
{
	bootstrap_slot0();

	mbedtls_x509_crt c1, c2, c3;
	sign_one_under(0, "CN=mult-01", &c1);
	sign_one_under(0, "CN=mult-02", &c2);
	sign_one_under(0, "CN=mult-03", &c3);
	zassert_ok(ca_revoke_cert(c1.serial.p, c1.serial.len, NOW_DEFAULT), "r1");
	zassert_ok(ca_revoke_cert(c2.serial.p, c2.serial.len, NOW_DEFAULT), "r2");
	zassert_ok(ca_revoke_cert(c3.serial.p, c3.serial.len, NOW_DEFAULT), "r3");

	uint8_t crl_der[2048]; size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	mbedtls_x509_crl crl;
	mbedtls_x509_crl_init(&crl);
	zassert_equal(mbedtls_x509_crl_parse_der(&crl, crl_der, crl_len), 0,
		      "parse_der");
	zassert_equal(count_entries(&crl), 3u, "three entries");
	zassert_not_null(find_entry(&crl, c1.serial.p, c1.serial.len), "c1");
	zassert_not_null(find_entry(&crl, c2.serial.p, c2.serial.len), "c2");
	zassert_not_null(find_entry(&crl, c3.serial.p, c3.serial.len), "c3");

	mbedtls_x509_crl_free(&crl);
	mbedtls_x509_crt_free(&c1);
	mbedtls_x509_crt_free(&c2);
	mbedtls_x509_crt_free(&c3);
}

ZTEST(crl_der, test_04_signature_verifies_under_slot0)
{
	bootstrap_slot0();
	mbedtls_x509_crt issued;
	sign_one_under(0, "CN=sig-test", &issued);
	zassert_ok(ca_revoke_cert(issued.serial.p, issued.serial.len,
				  NOW_DEFAULT), "revoke");

	uint8_t crl_der[2048]; size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	mbedtls_x509_crl crl;
	mbedtls_x509_crl_init(&crl);
	zassert_equal(mbedtls_x509_crl_parse_der(&crl, crl_der, crl_len), 0,
		      "parse_der");

	mbedtls_pk_context pk;
	load_slot_pubkey(0, &pk);
	verify_crl_signature(&crl, &pk);

	mbedtls_pk_free(&pk);
	mbedtls_x509_crl_free(&crl);
	mbedtls_x509_crt_free(&issued);
}

ZTEST(crl_der, test_05_sub_ca_crl_verifies_under_sub_ca)
{
	bootstrap_slot0();
	uint32_t sub = stand_up_subca();

	mbedtls_x509_crt issued;
	sign_one_under(sub, "CN=sub-victim", &issued);
	zassert_ok(ca_revoke_cert(issued.serial.p, issued.serial.len,
				  NOW_DEFAULT), "revoke");

	/* Fetch sub-CA's CRL — its issuer Name and signature must come from
	 * slot `sub`, not slot 0. */
	uint8_t crl_der[2048]; size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(sub, NOW_DEFAULT, crl_der, &crl_len), "get_crl sub");

	mbedtls_x509_crl crl;
	mbedtls_x509_crl_init(&crl);
	zassert_equal(mbedtls_x509_crl_parse_der(&crl, crl_der, crl_len), 0,
		      "parse_der");
	zassert_equal(count_entries(&crl), 1u, "one entry");

	mbedtls_pk_context pk_sub;
	load_slot_pubkey(sub, &pk_sub);
	verify_crl_signature(&crl, &pk_sub);

	/* And it must NOT verify under slot 0's pubkey. */
	mbedtls_pk_context pk_root;
	load_slot_pubkey(0, &pk_root);
	uint8_t hash[32];
	mbedtls_sha256(crl.tbs.p, crl.tbs.len, hash, 0);
	int rc = mbedtls_pk_verify(&pk_root, MBEDTLS_MD_SHA256, hash,
				   sizeof(hash), crl.MBEDTLS_PRIVATE(sig).p, crl.MBEDTLS_PRIVATE(sig).len);
	zassert_not_equal(rc, 0, "must fail under wrong issuer pubkey");

	mbedtls_pk_free(&pk_sub);
	mbedtls_pk_free(&pk_root);
	mbedtls_x509_crl_free(&crl);
	mbedtls_x509_crt_free(&issued);
}

/*
 * Find the cRLNumber INTEGER inside crl->crl_ext.
 * Returns 0 + sets *out on success, -1 if not found.
 * crl_ext layout: SEQUENCE OF Extension {
 *   SEQUENCE { OID 2.5.29.20, OCTET STRING { INTEGER crlNumber } }
 * }
 */
static int extract_crl_number(const mbedtls_x509_crl *crl, uint32_t *out)
{
	const uint8_t *p   = crl->crl_ext.p;
	const uint8_t *end = p + crl->crl_ext.len;
	size_t len;

	/* Outer SEQUENCE OF */
	if (mbedtls_asn1_get_tag((uint8_t **)&p, end, &len,
	    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) return -1;
	const uint8_t *outer_end = p + len;

	while (p < outer_end) {
		/* Extension SEQUENCE */
		if (mbedtls_asn1_get_tag((uint8_t **)&p, outer_end, &len,
		    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
			return -1;
		const uint8_t *ext_end = p + len;

		/* OID */
		size_t oid_len;
		if (mbedtls_asn1_get_tag((uint8_t **)&p, ext_end, &oid_len,
		    MBEDTLS_ASN1_OID) != 0) return -1;
		int is_crl_number =
			oid_len == MBEDTLS_OID_SIZE(MBEDTLS_OID_CRL_NUMBER) &&
			memcmp(p, MBEDTLS_OID_CRL_NUMBER, oid_len) == 0;
		p += oid_len;

		/* Optional critical BOOLEAN — skip if present */
		if (p < ext_end && *p == MBEDTLS_ASN1_BOOLEAN) {
			size_t b_len;
			if (mbedtls_asn1_get_tag((uint8_t **)&p, ext_end,
			    &b_len, MBEDTLS_ASN1_BOOLEAN) != 0) return -1;
			p += b_len;
		}

		/* OCTET STRING extnValue */
		size_t ov_len;
		if (mbedtls_asn1_get_tag((uint8_t **)&p, ext_end, &ov_len,
		    MBEDTLS_ASN1_OCTET_STRING) != 0) return -1;
		const uint8_t *ov = p;
		p += ov_len;

		if (is_crl_number) {
			/* INTEGER inside the OCTET STRING */
			size_t i_len;
			const uint8_t *ip = ov;
			if (mbedtls_asn1_get_tag((uint8_t **)&ip,
			    ov + ov_len, &i_len, MBEDTLS_ASN1_INTEGER) != 0)
				return -1;
			uint32_t val = 0;
			for (size_t i = 0; i < i_len; i++) {
				val = (val << 8) | ip[i];
			}
			*out = val;
			return 0;
		}
	}
	return -1;
}

ZTEST(crl_der, test_06_crl_number_monotonic)
{
	bootstrap_slot0();

	mbedtls_x509_crt c1, c2;
	sign_one_under(0, "CN=mono-01", &c1);
	sign_one_under(0, "CN=mono-02", &c2);

	zassert_ok(ca_revoke_cert(c1.serial.p, c1.serial.len, NOW_DEFAULT), "r1");
	uint8_t crl1_der[2048]; size_t crl1_len = sizeof(crl1_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl1_der, &crl1_len), "get_crl 1");

	zassert_ok(ca_revoke_cert(c2.serial.p, c2.serial.len, NOW_DEFAULT), "r2");
	uint8_t crl2_der[2048]; size_t crl2_len = sizeof(crl2_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl2_der, &crl2_len), "get_crl 2");

	mbedtls_x509_crl a, b;
	mbedtls_x509_crl_init(&a); mbedtls_x509_crl_init(&b);
	zassert_equal(mbedtls_x509_crl_parse_der(&a, crl1_der, crl1_len), 0, "p1");
	zassert_equal(mbedtls_x509_crl_parse_der(&b, crl2_der, crl2_len), 0, "p2");

	uint32_t n1 = 0, n2 = 0;
	zassert_equal(extract_crl_number(&a, &n1), 0, "extract n1");
	zassert_equal(extract_crl_number(&b, &n2), 0, "extract n2");
	zassert_true(n2 > n1, "n2(%u) > n1(%u)", n2, n1);

	mbedtls_x509_crl_free(&a); mbedtls_x509_crl_free(&b);
	mbedtls_x509_crt_free(&c1); mbedtls_x509_crt_free(&c2);
}

ZTEST(crl_der, test_07_now_zero_rejected)
{
	bootstrap_slot0();
	uint8_t crl[64]; size_t crl_len = sizeof(crl);
	int rc = ca_get_crl(0, 0, crl, &crl_len);
	zassert_equal(rc, -EINVAL, "expected -EINVAL, got %d", rc);
}

ZTEST(crl_der, test_08_slot_validation)
{
	bootstrap_slot0();
	uint8_t crl[64]; size_t crl_len = sizeof(crl);

	int rc = ca_get_crl(CONFIG_CANTIL_MAX_KEY_SLOTS, NOW_DEFAULT,
			    crl, &crl_len);
	zassert_equal(rc, -EINVAL, "oob: expected -EINVAL, got %d", rc);

	crl_len = sizeof(crl);
	rc = ca_get_crl(1, NOW_DEFAULT, crl, &crl_len);
	zassert_equal(rc, -ENOENT, "unpopulated: expected -ENOENT, got %d", rc);
}

ZTEST(crl_der, test_09_next_update_window)
{
	bootstrap_slot0();

	uint8_t crl_der[2048]; size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	mbedtls_x509_crl crl;
	mbedtls_x509_crl_init(&crl);
	zassert_equal(mbedtls_x509_crl_parse_der(&crl, crl_der, crl_len), 0,
		      "parse_der");

	uint64_t tu = x509_time_to_unix(&crl.this_update);
	uint64_t nu = x509_time_to_unix(&crl.next_update);
	zassert_equal(tu, NOW_DEFAULT, "thisUpdate==NOW_DEFAULT (%llu vs %llu)",
		      (unsigned long long)tu, (unsigned long long)NOW_DEFAULT);
	zassert_equal(nu - tu, (uint64_t)CONFIG_CANTIL_CRL_VALIDITY_SEC,
		      "nextUpdate - thisUpdate == VALIDITY_SEC (%llu vs %u)",
		      (unsigned long long)(nu - tu),
		      CONFIG_CANTIL_CRL_VALIDITY_SEC);

	mbedtls_x509_crl_free(&crl);
}

ZTEST(crl_der, test_10_per_slot_isolation)
{
	bootstrap_slot0();
	uint32_t sub = stand_up_subca();

	mbedtls_x509_crt c0, c1;
	sign_one_under(0,   "CN=iso-root", &c0);
	sign_one_under(sub, "CN=iso-sub",  &c1);
	zassert_ok(ca_revoke_cert(c0.serial.p, c0.serial.len, NOW_DEFAULT), "r0");
	zassert_ok(ca_revoke_cert(c1.serial.p, c1.serial.len, NOW_DEFAULT), "r1");

	uint8_t buf0[2048]; size_t l0 = sizeof(buf0);
	uint8_t buf1[2048]; size_t l1 = sizeof(buf1);
	zassert_ok(ca_get_crl(0,   NOW_DEFAULT, buf0, &l0), "g0");
	zassert_ok(ca_get_crl(sub, NOW_DEFAULT, buf1, &l1), "g1");

	mbedtls_x509_crl x0, x1;
	mbedtls_x509_crl_init(&x0); mbedtls_x509_crl_init(&x1);
	zassert_equal(mbedtls_x509_crl_parse_der(&x0, buf0, l0), 0, "p0");
	zassert_equal(mbedtls_x509_crl_parse_der(&x1, buf1, l1), 0, "p1");

	zassert_equal(count_entries(&x0), 1u, "x0 count");
	zassert_equal(count_entries(&x1), 1u, "x1 count");
	zassert_not_null(find_entry(&x0, c0.serial.p, c0.serial.len), "x0 has c0");
	zassert_is_null(find_entry(&x0, c1.serial.p, c1.serial.len),  "x0 lacks c1");
	zassert_not_null(find_entry(&x1, c1.serial.p, c1.serial.len), "x1 has c1");
	zassert_is_null(find_entry(&x1, c0.serial.p, c0.serial.len),  "x1 lacks c0");

	mbedtls_x509_crl_free(&x0); mbedtls_x509_crl_free(&x1);
	mbedtls_x509_crt_free(&c0); mbedtls_x509_crt_free(&c1);
}

ZTEST(crl_der, test_11_revocation_date_substituted_when_zero)
{
	bootstrap_slot0();

	mbedtls_x509_crt issued;
	sign_one_under(0, "CN=no-ts", &issued);
	/* now_unix=0 → meta records 0; encoder must substitute thisUpdate. */
	zassert_ok(ca_revoke_cert(issued.serial.p, issued.serial.len, 0),
		   "revoke now=0");

	const uint64_t fetch_now = NOW_DEFAULT + 1000;
	uint8_t crl_der[2048]; size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, fetch_now, crl_der, &crl_len), "get_crl");

	mbedtls_x509_crl crl;
	mbedtls_x509_crl_init(&crl);
	zassert_equal(mbedtls_x509_crl_parse_der(&crl, crl_der, crl_len), 0,
		      "parse_der");

	const mbedtls_x509_crl_entry *e =
		find_entry(&crl, issued.serial.p, issued.serial.len);
	zassert_not_null(e, "entry present");
	uint64_t rev_at = x509_time_to_unix(&e->revocation_date);
	zassert_equal(rev_at, fetch_now,
		      "revocationDate substituted with fetch_now (%llu vs %llu)",
		      (unsigned long long)rev_at,
		      (unsigned long long)fetch_now);

	mbedtls_x509_crl_free(&crl);
	mbedtls_x509_crt_free(&issued);
}

/*
 * Dump the generated CRL DER + the issuer cert PEM to /tmp so a host-side
 * shell wrapper (scripts/crl_smoke_openssl.sh) can verify them against the
 * OpenSSL command-line. Always runs as part of the suite; the openssl
 * checks are an optional CI gate, not a ztest assertion.
 */
ZTEST(crl_der, test_13_smoke_dump_for_openssl)
{
	bootstrap_slot0();

	mbedtls_x509_crt issued;
	sign_one_under(0, "CN=smoke-victim", &issued);
	zassert_ok(ca_revoke_cert(issued.serial.p, issued.serial.len,
				  NOW_DEFAULT), "revoke");

	uint8_t crl_der[2048]; size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	/* Issuer cert in PEM (for openssl -verify -CAfile). */
	uint8_t cert_der[1500]; size_t cert_len = sizeof(cert_der);
	zassert_ok(storage_slot_cert_read(0, cert_der, &cert_len), "cert read");

	/* native_sim has real POSIX FS via the host. Skip silently if writes
	 * fail (e.g. read-only /tmp in some CI environments) — this case is
	 * an export-for-tooling, not a correctness check. */
	FILE *f = fopen("/tmp/cantil_crl_smoke.der", "wb");
	if (f) {
		fwrite(crl_der, 1, crl_len, f);
		fclose(f);
	}
	f = fopen("/tmp/cantil_crl_smoke_cert.der", "wb");
	if (f) {
		fwrite(cert_der, 1, cert_len, f);
		fclose(f);
	}

	mbedtls_x509_crt_free(&issued);
}

ZTEST(crl_der, test_12_revocation_date_preserved_when_provided)
{
	bootstrap_slot0();

	const uint64_t revoke_at = NOW_DEFAULT + 500;
	mbedtls_x509_crt issued;
	sign_one_under(0, "CN=with-ts", &issued);
	zassert_ok(ca_revoke_cert(issued.serial.p, issued.serial.len, revoke_at),
		   "revoke with ts");

	/* Fetch later — entry must still carry revoke_at, not the fetch time. */
	uint8_t crl_der[2048]; size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT + 9999, crl_der, &crl_len),
		   "get_crl later");

	mbedtls_x509_crl crl;
	mbedtls_x509_crl_init(&crl);
	zassert_equal(mbedtls_x509_crl_parse_der(&crl, crl_der, crl_len), 0,
		      "parse_der");

	const mbedtls_x509_crl_entry *e =
		find_entry(&crl, issued.serial.p, issued.serial.len);
	zassert_not_null(e, "entry present");
	uint64_t rev_at = x509_time_to_unix(&e->revocation_date);
	zassert_equal(rev_at, revoke_at,
		      "revocationDate preserved (%llu vs %llu)",
		      (unsigned long long)rev_at,
		      (unsigned long long)revoke_at);

	mbedtls_x509_crl_free(&crl);
	mbedtls_x509_crt_free(&issued);
}
