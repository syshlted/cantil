/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * RFC 5280 v2 CertificateList (DER CRL) conformance on native_sim — task 2
 * of the CRL roadmap.
 *
 * Drives ca_get_crl() / ca_revoke_cert() / ca_revoke_cert_at end-to-end.
 * Every returned CRL is read with a small self-contained forward-DER walker
 * (see below) — a different code path from der_write.c's backwards encoder —
 * and its structure and signature are checked independently by the OpenSSL
 * gate (test_13 exports the artifacts; scripts/openssl_gate.sh runs
 * `openssl crl -verify`). We exercise:
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

#include "ca/ca.h"
#include "ca/certparse.h"
#include "crypto/crypto.h"
#include "storage/storage.h"
#include "cantil_cbor.h"
#include "test_artifacts.h"
#include "test_pki.h"

#define LFS_MOUNT "/lfs"
#define CERTS_DIR LFS_MOUNT "/certs"

/* Plausible 2026-ish "now" so UTCTime encoding is used. */
#define NOW_DEFAULT ((uint64_t)1767225600) /* 2026-01-01 00:00:00 UTC */

/* Build the same x509-data blob as the sign_csr suite — keeps tests
 * comparable. */
static size_t build_x509_blob(uint8_t *out, size_t cap)
{
	size_t off = 0;
	const char *cn = "Cantil CA";
	const char *o = "Cantil";

	zassert_true(cap >= 32, "blob too small");
	out[off++] = 0x01;
	out[off++] = 0x68; /* validity_days = 360 */
	out[off++] = 1;    /* is_ca */
	out[off++] = 0;    /* path_len */
	out[off++] = 0x00;
	out[off++] = 0x86; /* digital_sig | keyCertSign | cRLSign */
	out[off++] = (uint8_t)strlen(cn);
	memcpy(&out[off], cn, strlen(cn));
	off += strlen(cn);
	out[off++] = (uint8_t)strlen(o);
	memcpy(&out[off], o, strlen(o));
	off += strlen(o);
	out[off++] = 0;
	out[off++] = 0;
	out[off++] = 0;
	out[off++] = 0;
	return off;
}

static void wipe_dir(const char *dir)
{
	struct fs_dir_t d;
	struct fs_dirent ent;
	char path[128];

	fs_dir_t_init(&d);
	if (fs_opendir(&d, dir) != 0) {
		return;
	}
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

/* Just enough of an issued certificate for the revoke calls: its serial. */
typedef struct {
	uint8_t serial[CERTPARSE_SERIAL_MAX];
	size_t serial_len;
} issued_t;

/*
 * Sign one fresh CSR under the given issuer slot and record the issued
 * certificate's serial. The CSR is minted with the wolfCrypt writer (via
 * test_pki), the issued cert is read back with the firmware's certparse seam,
 * and the DER structure + signature are the OpenSSL gate's job — no library
 * here is asked to grade its own output.
 */
static void sign_one_under(uint32_t issuer_slot, const char *cn, issued_t *out)
{
	uint8_t csr[512];
	size_t cl = sizeof(csr);

	zassert_ok(test_pki_csr_cn(cn, csr, &cl, NULL), "gen csr");

	uint8_t cert[1500];
	size_t certl = sizeof(cert);

	int rc = (issuer_slot == 0) ? ca_sign_csr(csr, cl, cert, &certl)
				    : ca_sign_csr_slot(issuer_slot, csr, cl, cert, &certl);
	zassert_equal(rc, 0, "sign_csr(slot=%u)=%d", issuer_slot, rc);

	certparse_cert_t parsed;

	zassert_ok(certparse_cert(cert, certl, &parsed), "parse issued");
	memcpy(out->serial, parsed.serial, parsed.serial_len);
	out->serial_len = parsed.serial_len;
}

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init");

	/*
	 * A fresh native_sim volume has no identity marker, and minting is now
	 * refused on an unmarked, empty volume — that combination is what a
	 * misdeclared partition looks like. Mark it, which is exactly what the
	 * factory image does to real hardware before anything is provisioned.
	 */
	(void)storage_volume_marker_write();
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
	zassert_ok(ca_provision(0), "ca_provision");
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

/* ── a self-contained CRL reader ─────────────────────────────────────────────
 *
 * The suite used to parse the returned CRLs with mbedtls_x509_crl, a genuine
 * second implementation. mbedTLS is gone, and certparse.h reads certificates
 * and CSRs but not CRLs (a WOLFCRYPT_ONLY build has no CRL enumerator — the one
 * wolfSSL ships lives in the TLS layer). So the fields these tests check —
 * entry serials, revocationDate, crlNumber, the thisUpdate/nextUpdate window —
 * are read here by a small forward-DER walker.
 *
 * This is a different code path from src/ca/der_write.c, which writes the CRL
 * *backwards*, so a shared encoding bug would have to be made twice to hide.
 * And it is not the only check on these bytes: scripts/openssl_gate.sh parses
 * the same CRLs with the openssl CLI and verifies their signatures
 * (test_13_export_for_openssl_gate), so a malformed CRL that fooled this walker
 * still fails the gate.
 */

struct der_rd {
	const uint8_t *p;
	const uint8_t *end;
};

/* Read one TLV header+body; *tag/*body/*blen set, cursor advanced past body. */
static int der_hdr(struct der_rd *r, uint8_t *tag, const uint8_t **body, size_t *blen)
{
	if (r->p + 2 > r->end) {
		return -1;
	}
	*tag = *r->p++;

	size_t len = *r->p++;

	if (len & 0x80) {
		int nb = (int)(len & 0x7f);

		if (nb < 1 || nb > 3 || r->p + nb > r->end) {
			return -1;
		}
		len = 0;
		while (nb--) {
			len = (len << 8) | *r->p++;
		}
	}
	if ((size_t)(r->end - r->p) < len) {
		return -1;
	}
	*body = r->p;
	*blen = len;
	r->p += len;
	return 0;
}

/* Next tag without consuming, or -1 at end. */
static int der_peek(const struct der_rd *r, uint8_t *tag)
{
	if (r->p >= r->end) {
		return -1;
	}
	*tag = *r->p;
	return 0;
}

/* Enter a SEQUENCE (tag 0x30): sub spans its contents. */
static int der_seq(struct der_rd *r, struct der_rd *sub)
{
	uint8_t t;
	const uint8_t *b;
	size_t l;

	if (der_hdr(r, &t, &b, &l) || t != 0x30) {
		return -1;
	}
	sub->p = b;
	sub->end = b + l;
	return 0;
}

static uint64_t ymd_to_unix(int y, int mo, int d, int h, int mi, int s)
{
	static const int mdn[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
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

#define D2(c, i) (((c)[i] - '0') * 10 + ((c)[(i) + 1] - '0'))

/* UTCTime (0x17, YYMMDDHHMMSSZ) or GeneralizedTime (0x18, YYYYMMDDHHMMSSZ). */
static int der_time(uint8_t tag, const uint8_t *b, size_t l, uint64_t *out)
{
	const char *c = (const char *)b;

	if (tag == 0x17 && l >= 13) {
		int yy = D2(c, 0);

		*out = ymd_to_unix(yy < 50 ? 2000 + yy : 1900 + yy, D2(c, 2), D2(c, 4), D2(c, 6),
				   D2(c, 8), D2(c, 10));
		return 0;
	}
	if (tag == 0x18 && l >= 15) {
		int y = D2(c, 0) * 100 + D2(c, 2);

		*out = ymd_to_unix(y, D2(c, 4), D2(c, 6), D2(c, 8), D2(c, 10), D2(c, 12));
		return 0;
	}
	return -1;
}

typedef struct {
	uint8_t serial[CERTPARSE_SERIAL_MAX];
	size_t serial_len;
	uint64_t rev_date;
} crl_entry_t;

typedef struct {
	size_t n;
	crl_entry_t e[16];
	bool has_number;
	uint32_t number;
	uint64_t this_update;
	uint64_t next_update;
} crl_view_t;

/* 2.5.29.20 cRLNumber, OID value octets. */
static const uint8_t OID_CRL_NUMBER[] = {0x55, 0x1d, 0x14};

/* Drop one leading 0x00 sign/pad byte so serials compare by value: the CRL
 * encoder (ca.c write_serial_int) pads when the high bit is set. */
static void serial_norm(const uint8_t **p, size_t *l)
{
	if (*l > 1 && (*p)[0] == 0x00) {
		(*p)++;
		(*l)--;
	}
}

static int crl_parse(const uint8_t *der, size_t len, crl_view_t *v)
{
	memset(v, 0, sizeof(*v));

	struct der_rd top = {der, der + len}, cl, tbs;
	uint8_t tag;
	const uint8_t *b;
	size_t l;

	if (der_seq(&top, &cl) || der_seq(&cl, &tbs)) { /* CertificateList / tbs */
		return -1;
	}

	/* optional version INTEGER */
	if (!der_peek(&tbs, &tag) && tag == 0x02 && der_hdr(&tbs, &tag, &b, &l)) {
		return -1;
	}
	/* signature AlgorithmIdentifier, then issuer Name — both SEQUENCE, skip */
	if (der_hdr(&tbs, &tag, &b, &l) || tag != 0x30) {
		return -1;
	}
	if (der_hdr(&tbs, &tag, &b, &l) || tag != 0x30) {
		return -1;
	}
	/* thisUpdate */
	if (der_hdr(&tbs, &tag, &b, &l) || der_time(tag, b, l, &v->this_update)) {
		return -1;
	}
	/* optional nextUpdate */
	if (!der_peek(&tbs, &tag) && (tag == 0x17 || tag == 0x18)) {
		if (der_hdr(&tbs, &tag, &b, &l) || der_time(tag, b, l, &v->next_update)) {
			return -1;
		}
	}
	/* optional revokedCertificates */
	if (!der_peek(&tbs, &tag) && tag == 0x30) {
		struct der_rd rev;

		if (der_seq(&tbs, &rev)) {
			return -1;
		}
		while (rev.p < rev.end) {
			struct der_rd ent;

			if (der_seq(&rev, &ent)) {
				return -1;
			}
			if (der_hdr(&ent, &tag, &b, &l) || tag != 0x02) { /* serial */
				return -1;
			}
			if (v->n >= 16 || l > CERTPARSE_SERIAL_MAX) {
				return -1;
			}
			crl_entry_t *e = &v->e[v->n++];

			memcpy(e->serial, b, l);
			e->serial_len = l;

			if (der_hdr(&ent, &tag, &b, &l) || /* revocationDate */
			    der_time(tag, b, l, &e->rev_date)) {
				return -1;
			}
			/* entry extensions, if any, ignored */
		}
	}
	/* optional crlExtensions [0] */
	if (!der_peek(&tbs, &tag) && tag == 0xa0) {
		if (der_hdr(&tbs, &tag, &b, &l)) {
			return -1;
		}
		struct der_rd exts = {b, b + l}, seq;

		if (der_seq(&exts, &seq)) {
			return -1;
		}
		while (seq.p < seq.end) {
			struct der_rd ext;

			if (der_seq(&seq, &ext)) {
				return -1;
			}
			if (der_hdr(&ext, &tag, &b, &l) || tag != 0x06) { /* OID */
				return -1;
			}
			bool is_num =
				(l == sizeof(OID_CRL_NUMBER) && memcmp(b, OID_CRL_NUMBER, l) == 0);

			/* optional critical BOOLEAN */
			if (!der_peek(&ext, &tag) && tag == 0x01 && der_hdr(&ext, &tag, &b, &l)) {
				return -1;
			}
			if (der_hdr(&ext, &tag, &b, &l) || tag != 0x04) { /* extnValue */
				return -1;
			}
			if (is_num) {
				struct der_rd iv = {b, b + l};

				if (der_hdr(&iv, &tag, &b, &l) || tag != 0x02) {
					return -1;
				}
				uint32_t val = 0;

				for (size_t i = 0; i < l; i++) {
					val = (val << 8) | b[i];
				}
				v->number = val;
				v->has_number = true;
			}
		}
	}
	return 0;
}

/* Parse a CRL DER or fail the test; returns the view by value. */
static crl_view_t crl_view(const uint8_t *der, size_t len)
{
	crl_view_t v;

	zassert_ok(crl_parse(der, len, &v), "crl_parse");
	return v;
}

/* True if the CRL holds an entry whose serial equals `serial` (by value). */
static bool crl_has_serial(const crl_view_t *v, const uint8_t *serial, size_t sl)
{
	serial_norm(&serial, &sl);
	for (size_t i = 0; i < v->n; i++) {
		const uint8_t *es = v->e[i].serial;
		size_t esl = v->e[i].serial_len;

		serial_norm(&es, &esl);
		if (esl == sl && memcmp(es, serial, sl) == 0) {
			return true;
		}
	}
	return false;
}

/* The revocationDate of the entry matching `serial`, or 0 if absent. */
static uint64_t crl_rev_date(const crl_view_t *v, const uint8_t *serial, size_t sl)
{
	serial_norm(&serial, &sl);
	for (size_t i = 0; i < v->n; i++) {
		const uint8_t *es = v->e[i].serial;
		size_t esl = v->e[i].serial_len;

		serial_norm(&es, &esl);
		if (esl == sl && memcmp(es, serial, sl) == 0) {
			return v->e[i].rev_date;
		}
	}
	return 0;
}

ZTEST_SUITE(crl_der, NULL, suite_setup, test_before, NULL, NULL);

/* ── tests ──────────────────────────────────────────────────────────────── */

ZTEST(crl_der, test_01_empty_crl_parses)
{
	bootstrap_slot0();

	uint8_t crl_der[2048];
	size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");
	zassert_true(crl_len > 0, "crl_len=%zu", crl_len);

	crl_view_t v = crl_view(crl_der, crl_len);
	zassert_equal(v.n, 0u, "empty crl has zero entries");
}

ZTEST(crl_der, test_02_single_revoke_one_entry)
{
	bootstrap_slot0();

	issued_t issued;
	sign_one_under(0, "victim-01", &issued);
	zassert_ok(ca_revoke_cert(issued.serial, issued.serial_len, NOW_DEFAULT), "revoke");

	uint8_t crl_der[2048];
	size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	crl_view_t v = crl_view(crl_der, crl_len);
	zassert_equal(v.n, 1u, "one entry");
	zassert_true(crl_has_serial(&v, issued.serial, issued.serial_len), "serial present");
}

ZTEST(crl_der, test_03_multi_revoke_three_entries)
{
	bootstrap_slot0();

	issued_t c1, c2, c3;
	sign_one_under(0, "mult-01", &c1);
	sign_one_under(0, "mult-02", &c2);
	sign_one_under(0, "mult-03", &c3);
	zassert_ok(ca_revoke_cert(c1.serial, c1.serial_len, NOW_DEFAULT), "r1");
	zassert_ok(ca_revoke_cert(c2.serial, c2.serial_len, NOW_DEFAULT), "r2");
	zassert_ok(ca_revoke_cert(c3.serial, c3.serial_len, NOW_DEFAULT), "r3");

	uint8_t crl_der[2048];
	size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	crl_view_t v = crl_view(crl_der, crl_len);
	zassert_equal(v.n, 3u, "three entries");
	zassert_true(crl_has_serial(&v, c1.serial, c1.serial_len), "c1");
	zassert_true(crl_has_serial(&v, c2.serial, c2.serial_len), "c2");
	zassert_true(crl_has_serial(&v, c3.serial, c3.serial_len), "c3");
}

/*
 * The CRL signature verifies under the issuing slot.
 *
 * There is no signature-verify primitive in the WOLFCRYPT_ONLY build to call
 * here (crypto.h signs but does not verify), so the signature check is the
 * OpenSSL gate's: test_13 exports a populated slot-0 CRL alongside slot 0's
 * cert, and scripts/openssl_gate.sh runs `openssl crl -verify` on it. This
 * test confirms the content the gate then vouches for.
 */
ZTEST(crl_der, test_04_signature_verifies_under_slot0)
{
	bootstrap_slot0();
	issued_t issued;
	sign_one_under(0, "sig-test", &issued);
	zassert_ok(ca_revoke_cert(issued.serial, issued.serial_len, NOW_DEFAULT), "revoke");

	uint8_t crl_der[2048];
	size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	crl_view_t v = crl_view(crl_der, crl_len);
	zassert_true(crl_has_serial(&v, issued.serial, issued.serial_len),
		     "revoked serial present in the CRL the gate verifies");
}

/*
 * A sub-CA's CRL is issued and signed by the sub-CA, not the root.
 *
 * The per-issuer *signature* binding is checked by the OpenSSL gate: test_13
 * exports the sub-CA's CRL with the sub-CA's cert as the companion anchor, so
 * if ca.c had signed it with the root key `openssl crl -verify` would fail.
 * Here we confirm the sub-CA CRL carries exactly its own revoked serial.
 */
ZTEST(crl_der, test_05_sub_ca_crl_verifies_under_sub_ca)
{
	bootstrap_slot0();
	uint32_t sub = stand_up_subca();

	issued_t issued;
	sign_one_under(sub, "sub-victim", &issued);
	zassert_ok(ca_revoke_cert(issued.serial, issued.serial_len, NOW_DEFAULT), "revoke");

	uint8_t crl_der[2048];
	size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(sub, NOW_DEFAULT, crl_der, &crl_len), "get_crl sub");

	crl_view_t v = crl_view(crl_der, crl_len);
	zassert_equal(v.n, 1u, "one entry");
	zassert_true(crl_has_serial(&v, issued.serial, issued.serial_len), "sub-CA serial present");
}

ZTEST(crl_der, test_06_crl_number_monotonic)
{
	bootstrap_slot0();

	issued_t c1, c2;
	sign_one_under(0, "mono-01", &c1);
	sign_one_under(0, "mono-02", &c2);

	zassert_ok(ca_revoke_cert(c1.serial, c1.serial_len, NOW_DEFAULT), "r1");
	uint8_t crl1_der[2048];
	size_t crl1_len = sizeof(crl1_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl1_der, &crl1_len), "get_crl 1");

	zassert_ok(ca_revoke_cert(c2.serial, c2.serial_len, NOW_DEFAULT), "r2");
	uint8_t crl2_der[2048];
	size_t crl2_len = sizeof(crl2_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl2_der, &crl2_len), "get_crl 2");

	crl_view_t a = crl_view(crl1_der, crl1_len);
	crl_view_t b = crl_view(crl2_der, crl2_len);
	zassert_true(a.has_number, "crl 1 has a cRLNumber");
	zassert_true(b.has_number, "crl 2 has a cRLNumber");
	zassert_true(b.number > a.number, "n2(%u) > n1(%u)", b.number, a.number);
}

ZTEST(crl_der, test_07_now_zero_rejected)
{
	bootstrap_slot0();
	uint8_t crl[64];
	size_t crl_len = sizeof(crl);
	int rc = ca_get_crl(0, 0, crl, &crl_len);
	zassert_equal(rc, -EINVAL, "expected -EINVAL, got %d", rc);
}

ZTEST(crl_der, test_08_slot_validation)
{
	bootstrap_slot0();
	uint8_t crl[64];
	size_t crl_len = sizeof(crl);

	int rc = ca_get_crl(CONFIG_CANTIL_MAX_KEY_SLOTS, NOW_DEFAULT, crl, &crl_len);
	zassert_equal(rc, -EINVAL, "oob: expected -EINVAL, got %d", rc);

	crl_len = sizeof(crl);
	rc = ca_get_crl(1, NOW_DEFAULT, crl, &crl_len);
	zassert_equal(rc, -ENOENT, "unpopulated: expected -ENOENT, got %d", rc);
}

ZTEST(crl_der, test_09_next_update_window)
{
	bootstrap_slot0();

	uint8_t crl_der[2048];
	size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	crl_view_t v = crl_view(crl_der, crl_len);
	zassert_equal(v.this_update, NOW_DEFAULT, "thisUpdate==NOW_DEFAULT (%llu vs %llu)",
		      (unsigned long long)v.this_update, (unsigned long long)NOW_DEFAULT);
	zassert_equal(v.next_update - v.this_update, (uint64_t)CONFIG_CANTIL_CRL_VALIDITY_SEC,
		      "nextUpdate - thisUpdate == VALIDITY_SEC (%llu vs %u)",
		      (unsigned long long)(v.next_update - v.this_update),
		      CONFIG_CANTIL_CRL_VALIDITY_SEC);
}

ZTEST(crl_der, test_10_per_slot_isolation)
{
	bootstrap_slot0();
	uint32_t sub = stand_up_subca();

	issued_t c0, c1;
	sign_one_under(0, "iso-root", &c0);
	sign_one_under(sub, "iso-sub", &c1);
	zassert_ok(ca_revoke_cert(c0.serial, c0.serial_len, NOW_DEFAULT), "r0");
	zassert_ok(ca_revoke_cert(c1.serial, c1.serial_len, NOW_DEFAULT), "r1");

	uint8_t buf0[2048];
	size_t l0 = sizeof(buf0);
	uint8_t buf1[2048];
	size_t l1 = sizeof(buf1);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, buf0, &l0), "g0");
	zassert_ok(ca_get_crl(sub, NOW_DEFAULT, buf1, &l1), "g1");

	crl_view_t x0 = crl_view(buf0, l0);
	crl_view_t x1 = crl_view(buf1, l1);

	zassert_equal(x0.n, 1u, "x0 count");
	zassert_equal(x1.n, 1u, "x1 count");
	zassert_true(crl_has_serial(&x0, c0.serial, c0.serial_len), "x0 has c0");
	zassert_false(crl_has_serial(&x0, c1.serial, c1.serial_len), "x0 lacks c1");
	zassert_true(crl_has_serial(&x1, c1.serial, c1.serial_len), "x1 has c1");
	zassert_false(crl_has_serial(&x1, c0.serial, c0.serial_len), "x1 lacks c0");
}

ZTEST(crl_der, test_11_revocation_date_substituted_when_zero)
{
	bootstrap_slot0();

	issued_t issued;
	sign_one_under(0, "no-ts", &issued);
	/* now_unix=0 -> meta records 0; encoder must substitute thisUpdate. */
	zassert_ok(ca_revoke_cert(issued.serial, issued.serial_len, 0), "revoke now=0");

	const uint64_t fetch_now = NOW_DEFAULT + 1000;
	uint8_t crl_der[2048];
	size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, fetch_now, crl_der, &crl_len), "get_crl");

	crl_view_t v = crl_view(crl_der, crl_len);
	zassert_true(crl_has_serial(&v, issued.serial, issued.serial_len), "entry present");
	uint64_t rev_at = crl_rev_date(&v, issued.serial, issued.serial_len);
	zassert_equal(rev_at, fetch_now, "revocationDate substituted with fetch_now (%llu vs %llu)",
		      (unsigned long long)rev_at, (unsigned long long)fetch_now);
}

/*
 * Hand a populated CRL and its issuer to the OpenSSL gate.
 *
 * This is the suite's independent oracle. Every other test reads the CRL with
 * the forward-DER walker above, which is a different code path from the
 * backwards writer in src/ca/der_write.c but is still Cantil's own code. The
 * gate is not: scripts/openssl_gate.sh parses these artifacts with the openssl
 * CLI and, because each .crl.der is paired with its issuer's .ca.der, verifies
 * the ECDSA-Sig-Value that nothing else in the tree ever reads.
 *
 * This replaced a dump to /tmp that named a host-side wrapper
 * (scripts/crl_smoke_openssl.sh) which was never written.
 */
ZTEST(crl_der, test_13_export_for_openssl_gate)
{
	bootstrap_slot0();

	issued_t issued;
	sign_one_under(0, "smoke-victim", &issued);
	zassert_ok(ca_revoke_cert(issued.serial, issued.serial_len, NOW_DEFAULT), "revoke");

	uint8_t crl_der[2048];
	size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT, crl_der, &crl_len), "get_crl");

	uint8_t cert_der[1500];
	size_t cert_len = sizeof(cert_der);
	zassert_ok(storage_slot_cert_read(0, cert_der, &cert_len), "cert read");

	test_artifact_crl("slot0_revoked", crl_der, crl_len);
	test_artifact_ca("slot0_revoked", cert_der, cert_len);

	/* An empty CRL takes a different path through der_write.c -
	 * revokedCertificates is omitted entirely rather than emitted as an
	 * empty SEQUENCE - so it is worth gating separately. A fresh sub-CA has
	 * revoked nothing, and signs its own CRL, so one slot covers both the
	 * empty body and the sub-CA issuer (which is also test_05's signature
	 * check). */
	uint32_t sub = stand_up_subca();

	uint8_t empty_der[2048];
	size_t empty_len = sizeof(empty_der);
	zassert_ok(ca_get_crl(sub, NOW_DEFAULT, empty_der, &empty_len), "get_crl sub-CA");

	uint8_t sub_cert[1500];
	size_t sub_len = sizeof(sub_cert);
	zassert_ok(storage_slot_cert_read(sub, sub_cert, &sub_len), "sub cert read");

	test_artifact_crl("subca_empty", empty_der, empty_len);
	test_artifact_ca("subca_empty", sub_cert, sub_len);
}

ZTEST(crl_der, test_12_revocation_date_preserved_when_provided)
{
	bootstrap_slot0();

	const uint64_t revoke_at = NOW_DEFAULT + 500;
	issued_t issued;
	sign_one_under(0, "with-ts", &issued);
	zassert_ok(ca_revoke_cert(issued.serial, issued.serial_len, revoke_at), "revoke with ts");

	/* Fetch later - entry must still carry revoke_at, not the fetch time. */
	uint8_t crl_der[2048];
	size_t crl_len = sizeof(crl_der);
	zassert_ok(ca_get_crl(0, NOW_DEFAULT + 9999, crl_der, &crl_len), "get_crl later");

	crl_view_t v = crl_view(crl_der, crl_len);
	zassert_true(crl_has_serial(&v, issued.serial, issued.serial_len), "entry present");
	uint64_t rev_at = crl_rev_date(&v, issued.serial, issued.serial_len);
	zassert_equal(rev_at, revoke_at, "revocationDate preserved (%llu vs %llu)",
		      (unsigned long long)rev_at, (unsigned long long)revoke_at);
}
