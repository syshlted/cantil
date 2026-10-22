/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * SIGN_CSR (CMD 0x01) conformance on native_sim.
 *
 * Verifies the full slot-0 CSR signing flow:
 *   1. SIGN_CSR before CA is ready  -> -ENOENT
 *   2. After bootstrap: round-trip a fresh P-256 CSR through ca_sign_csr,
 *      parse the resulting cert, check issuer/subject/serial/version/
 *      signature against the CA pubkey.
 *   3. Issued-cert store: cert.der + meta.bin both present, meta has
 *      version=1, issuer_slot=0, serial match, subject CN match.
 *   4. Malformed inputs: empty CSR, junk CSR -> -EINVAL.
 *   5. Two consecutive signs produce two distinct serial numbers.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/fs/fs.h>
#include <string.h>
#include <errno.h>

#include "ca/ca.h"
#include "ca/certparse.h"
#include "test_artifacts.h"
#include "test_pki.h"
#include "crypto/crypto.h"
#include "storage/storage.h"
#include "cantil_cbor.h"

#define LFS_MOUNT "/lfs"
#define SLOT0_DIR LFS_MOUNT "/keys/0"
#define CERTS_DIR LFS_MOUNT "/certs"

/* Reused from ca_bootstrap test: build the flat x509-data blob. */
static size_t build_x509_blob(uint8_t *out, size_t cap)
{
	size_t off = 0;
	const char *cn = "Cantil CA";
	const char *o = "Cantil";

	zassert_true(cap >= 32, "blob buffer too small");
	out[off++] = 0x01;
	out[off++] = 0x68; /* validity_days = 360 */
	out[off++] = 1;    /* is_ca */
	out[off++] = 0;    /* path_len = 0 */
	out[off++] = 0x00;
	out[off++] = 0x86; /* key_usage = digital_sig|keyCertSign|cRLSign */

	out[off++] = (uint8_t)strlen(cn);
	memcpy(&out[off], cn, strlen(cn));
	off += strlen(cn);
	out[off++] = (uint8_t)strlen(o);
	memcpy(&out[off], o, strlen(o));
	off += strlen(o);
	out[off++] = 0; /* ou */
	out[off++] = 0; /* c  */
	out[off++] = 0; /* st */
	out[off++] = 0; /* l  */
	return off;
}

/* Recursively unlink a directory and its contents. */
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

/* Parse an RFC 4514 "CN=x,O=y" subject into a certgen DN (only CN and O, the
 * fields these tests use). */
static certgen_dn_t subj_dn(const char *subject)
{
	certgen_dn_t dn = {0};
	char tmp[128];

	strncpy(tmp, subject, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';

	for (char *tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
		while (*tok == ' ') {
			tok++;
		}
		if (strncmp(tok, "CN=", 3) == 0) {
			strncpy(dn.cn, tok + 3, sizeof(dn.cn) - 1);
		} else if (strncmp(tok, "O=", 2) == 0) {
			strncpy(dn.o, tok + 2, sizeof(dn.o) - 1);
		}
	}
	return dn;
}

/* Mint a fresh P-256 CSR for `subject` via the wolfCrypt writer (test_pki). */
static size_t gen_csr(uint8_t *out, size_t cap, const char *subject)
{
	certgen_dn_t dn = subj_dn(subject);
	size_t len = cap;

	zassert_ok(test_pki_csr(&dn, out, &len, NULL), "gen csr '%s'", subject);
	return len;
}

/* Just enough of an issued cert for the store lookups: its serial. */
typedef struct {
	uint8_t serial[CERTPARSE_SERIAL_MAX];
	size_t serial_len;
} issued_t;

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

/* Bring slot 0 up to "ready" — key provisioned and self-signed cert installed. */
static void bootstrap_slot0(void)
{
	zassert_ok(ca_provision(0), "ca_provision");

	uint8_t blob[256];
	size_t len = build_x509_blob(blob, sizeof(blob));
	zassert_ok(ca_push_key_x509(0, blob, len), "push_key_x509");
	zassert_true(ca_ready(), "ca_ready expected after push");
}

ZTEST_SUITE(sign_csr, NULL, suite_setup, test_before, NULL, NULL);

/* ── tests ──────────────────────────────────────────────────────────────── */

ZTEST(sign_csr, test_01_sign_before_ready_returns_enoent)
{
	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=Client");

	uint8_t cert[1500];
	size_t cert_len = sizeof(cert);
	int rc = ca_sign_csr(csr, cl, cert, &cert_len);
	zassert_equal(rc, -ENOENT, "expected -ENOENT, got %d", rc);
}

ZTEST(sign_csr, test_02_roundtrip_parse_issuer_subject_serial)
{
	bootstrap_slot0();

	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=alice,O=Cantil");

	uint8_t cert[1500];
	size_t cert_len = sizeof(cert);
	int rc = ca_sign_csr(csr, cl, cert, &cert_len);
	zassert_equal(rc, 0, "sign_csr=%d", rc);
	zassert_true(cert_len > 200 && cert_len < 1500, "cert_len=%zu", cert_len);

	/* Read the fields with certparse; the issuer identity is proven
	 * cryptographically by test_03's chain verification, not by name. */
	certparse_cert_t parsed;
	zassert_ok(certparse_cert(cert, cert_len, &parsed), "certparse");

	zassert_equal(parsed.serial_len, 8u, "serial=%zu", parsed.serial_len);
	zassert_equal(strcmp(parsed.subject.cn, "alice"), 0, "subj CN=alice, got '%s'",
		      parsed.subject.cn);
	zassert_equal(strcmp(parsed.subject.o, "Cantil"), 0, "subj O=Cantil, got '%s'",
		      parsed.subject.o);
}

ZTEST(sign_csr, test_03_signature_verifies_against_ca_pubkey)
{
	bootstrap_slot0();

	/* Read CA cert (the trust anchor). */
	uint8_t ca_cert[1500];
	size_t ca_len = sizeof(ca_cert);
	zassert_ok(ca_get_cert(ca_cert, &ca_len), "ca_get_cert");

	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=bob");

	uint8_t cert[1500];
	size_t cert_len = sizeof(cert);
	zassert_ok(ca_sign_csr(csr, cl, cert, &cert_len), "sign");

	/* The issued leaf must chain to the CA. certparse_verify_chain checks
	 * the signature; the OpenSSL gate (test_54) checks it again with a third
	 * implementation. */
	zassert_ok(certparse_verify_chain(cert, cert_len, NULL, NULL, 0, ca_cert, ca_len),
		   "issued chains to CA");
}

ZTEST(sign_csr, test_04_issued_store_has_cert_and_meta)
{
	bootstrap_slot0();

	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=carol");

	uint8_t cert[1500];
	size_t cert_len = sizeof(cert);
	zassert_ok(ca_sign_csr(csr, cl, cert, &cert_len), "sign");

	certparse_cert_t parsed;
	zassert_ok(certparse_cert(cert, cert_len, &parsed), "certparse");

	const uint8_t *serial = parsed.serial;
	size_t serial_len = parsed.serial_len;

	/* Look up by serial in the issued-cert store. */
	zassert_equal(storage_issued_cert_exists(serial, serial_len), 1, "exists");

	uint8_t stored_cert[1500];
	size_t stored_len = sizeof(stored_cert);
	zassert_ok(storage_issued_cert_read(serial, serial_len, stored_cert, &stored_len),
		   "issued_cert_read");
	zassert_equal(stored_len, cert_len, "stored len match");
	zassert_mem_equal(stored_cert, cert, cert_len, "stored bytes match");

	uint8_t meta_buf[256];
	size_t meta_len = sizeof(meta_buf);
	zassert_ok(storage_issued_meta_read(serial, serial_len, meta_buf, &meta_len), "meta_read");
	zassert_equal(meta_buf[0], 1, "meta version");
	zassert_equal(meta_buf[1], 0, "meta flags clear");
	zassert_equal(meta_buf[2], 8, "meta serial_len");
	/* issuer_slot at offset 4..7 (host-LE). */
	zassert_equal(meta_buf[4], 0, "issuer_slot LSB");
}

ZTEST(sign_csr, test_05_empty_csr_rejected)
{
	bootstrap_slot0();

	uint8_t cert[1500];
	size_t cert_len = sizeof(cert);
	int rc = ca_sign_csr(NULL, 0, cert, &cert_len);
	zassert_equal(rc, -EINVAL, "null/0 -> %d", rc);

	uint8_t junk[16] = {0};
	cert_len = sizeof(cert);
	rc = ca_sign_csr(junk, sizeof(junk), cert, &cert_len);
	zassert_equal(rc, -EINVAL, "junk -> %d", rc);
}

ZTEST(sign_csr, test_07_get_ca_serial_matches_cert)
{
	bootstrap_slot0();

	uint8_t serial[32];
	size_t serial_len = sizeof(serial);
	int rc = ca_get_serial(serial, &serial_len);
	zassert_equal(rc, 0, "get_serial=%d", rc);
	zassert_true(serial_len > 0 && serial_len <= 20, "serial_len=%zu", serial_len);

	/* Should match what parses out of slot 0's own cert. */
	uint8_t cert[1500];
	size_t cert_len = sizeof(cert);
	zassert_ok(ca_get_cert(cert, &cert_len), "get_cert");

	certparse_cert_t parsed;
	zassert_ok(certparse_cert(cert, cert_len, &parsed), "certparse");
	zassert_equal(parsed.serial_len, serial_len, "len match");
	zassert_mem_equal(parsed.serial, serial, serial_len, "bytes match");
}

ZTEST(sign_csr, test_08_get_ca_serial_before_bootstrap_errors)
{
	uint8_t serial[32];
	size_t serial_len = sizeof(serial);
	int rc = ca_get_serial(serial, &serial_len);
	zassert_true(rc < 0, "expected error before bootstrap, got %d", rc);
	zassert_equal(serial_len, 0u, "serial_len cleared on error");
}

ZTEST(sign_csr, test_09_get_ca_serial_buffer_too_small)
{
	bootstrap_slot0();
	uint8_t serial[4]; /* CA serial is 8 bytes, won't fit */
	size_t serial_len = sizeof(serial);
	int rc = ca_get_serial(serial, &serial_len);
	zassert_equal(rc, -ENOMEM, "expected -ENOMEM, got %d", rc);
}

/* Decode the LIST_CERTS CBOR payload: an array of map(4). Counts entries
 * and optionally returns the first serial via out_serial / out_serial_len. */
static int decode_list_certs(const uint8_t *buf, size_t len, uint32_t *count_out,
			     uint8_t *first_serial, size_t *first_serial_len)
{
	size_t off = 0;
	uint8_t mt;
	uint64_t v;
	int rc = cantil_cbor_read_head(buf, len, &off, &mt, &v);
	if (rc) {
		return rc;
	}
	if (mt != CANTIL_CBOR_MT_ARRAY) {
		return -1;
	}
	*count_out = (uint32_t)v;

	int saw_first = 0;
	for (uint32_t i = 0; i < *count_out; i++) {
		rc = cantil_cbor_read_head(buf, len, &off, &mt, &v);
		if (rc || mt != CANTIL_CBOR_MT_MAP || v != 4) {
			return -2;
		}
		for (int k = 0; k < 4; k++) {
			const uint8_t *key;
			size_t klen;
			rc = cantil_cbor_read_tstr(buf, len, &off, &key, &klen);
			if (rc) {
				return -3;
			}
			if (klen != 1) {
				return -4;
			}
			char kc = (char)key[0];
			if (kc == 's') {
				const uint8_t *p;
				size_t pl;
				rc = cantil_cbor_read_bstr(buf, len, &off, &p, &pl);
				if (rc) {
					return -5;
				}
				if (!saw_first && first_serial && first_serial_len) {
					memcpy(first_serial, p, pl);
					*first_serial_len = pl;
					saw_first = 1;
				}
			} else if (kc == 'n') {
				const uint8_t *p;
				size_t pl;
				rc = cantil_cbor_read_tstr(buf, len, &off, &p, &pl);
				if (rc) {
					return -6;
				}
			} else {
				uint32_t u;
				rc = cantil_cbor_read_uint32(buf, len, &off, &u);
				if (rc) {
					return -7;
				}
			}
		}
	}
	return 0;
}

ZTEST(sign_csr, test_10_list_certs_empty)
{
	bootstrap_slot0();

	uint32_t count = 99;
	zassert_ok(ca_get_cert_count(&count), "count");
	zassert_equal(count, 0u, "expected 0 before any signs, got %u", count);

	uint8_t out[256];
	size_t out_len = sizeof(out);
	zassert_ok(ca_list_certs(out, &out_len), "list_certs empty");
	zassert_true(out_len >= 1, "out_len=%zu", out_len);

	/* Should decode to array(0). */
	uint32_t decoded_count = 0;
	zassert_equal(decode_list_certs(out, out_len, &decoded_count, NULL, NULL), 0, "decode");
	zassert_equal(decoded_count, 0u, "decoded count");
}

ZTEST(sign_csr, test_11_list_certs_after_two_signs)
{
	bootstrap_slot0();

	uint8_t csr1[512], csr2[512];
	size_t l1 = gen_csr(csr1, sizeof(csr1), "CN=foo");
	size_t l2 = gen_csr(csr2, sizeof(csr2), "CN=bar,O=Cantil");
	uint8_t cert1[1500], cert2[1500];
	size_t cl1 = sizeof(cert1), cl2 = sizeof(cert2);
	zassert_ok(ca_sign_csr(csr1, l1, cert1, &cl1), "sign1");
	zassert_ok(ca_sign_csr(csr2, l2, cert2, &cl2), "sign2");

	uint32_t count = 0;
	zassert_ok(ca_get_cert_count(&count), "count");
	zassert_equal(count, 2u, "count=%u", count);

	uint8_t out[1024];
	size_t out_len = sizeof(out);
	zassert_ok(ca_list_certs(out, &out_len), "list_certs");

	uint32_t decoded_count = 0;
	uint8_t first_serial[20] = {0};
	size_t first_serial_len = 0;
	int rc = decode_list_certs(out, out_len, &decoded_count, first_serial, &first_serial_len);
	zassert_equal(rc, 0, "decode rc=%d", rc);
	zassert_equal(decoded_count, 2u, "decoded count=%u", decoded_count);
	zassert_equal(first_serial_len, 8u, "first serial len");
}

ZTEST(sign_csr, test_12_list_certs_tiny_buffer_errors)
{
	bootstrap_slot0();

	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=alice");
	uint8_t cert[1500];
	size_t certl = sizeof(cert);
	zassert_ok(ca_sign_csr(csr, cl, cert, &certl), "sign");

	uint8_t tiny[16];
	size_t tiny_len = sizeof(tiny);
	int rc = ca_list_certs(tiny, &tiny_len);
	zassert_equal(rc, -ENOMEM, "expected -ENOMEM, got %d", rc);
	zassert_equal(tiny_len, 0u, "len cleared");
}

/* Helper: sign one CSR under slot 0 and record the issued cert's serial. */
static void sign_one(const char *cn, uint8_t *cert_out, size_t *cert_len, issued_t *out)
{
	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), cn);

	zassert_ok(ca_sign_csr(csr, cl, cert_out, cert_len), "sign %s", cn);

	certparse_cert_t parsed;

	zassert_ok(certparse_cert(cert_out, *cert_len, &parsed), "parse");
	memcpy(out->serial, parsed.serial, parsed.serial_len);
	out->serial_len = parsed.serial_len;
}

ZTEST(sign_csr, test_13_revoke_unknown_serial)
{
	bootstrap_slot0();
	uint8_t serial[8] = {0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78};
	int rc = ca_revoke_cert(serial, sizeof(serial), 0);
	zassert_equal(rc, -ENOENT, "expected -ENOENT, got %d", rc);
}

ZTEST(sign_csr, test_14_revoke_flips_meta_flag)
{
	bootstrap_slot0();

	uint8_t cert[1500];
	size_t cl = sizeof(cert);
	issued_t issued;
	sign_one("CN=victim", cert, &cl, &issued);

	int rc = ca_revoke_cert(issued.serial, issued.serial_len, 0);
	zassert_equal(rc, 0, "revoke=%d", rc);

	/* Meta should now have bit0 set. */
	uint8_t meta[256];
	size_t ml = sizeof(meta);
	zassert_ok(storage_issued_meta_read(issued.serial, issued.serial_len, meta, &ml),
		   "meta_read");
	zassert_equal(meta[1] & 0x01, 0x01, "revoked bit set");

	/* Double-revoke -> -EALREADY. */
	rc = ca_revoke_cert(issued.serial, issued.serial_len, 0);
	zassert_equal(rc, -EALREADY, "expected -EALREADY, got %d", rc);
}

ZTEST(sign_csr, test_15_revoke_protected_cert_blocked)
{
	bootstrap_slot0();

	uint8_t cert[1500];
	size_t cl = sizeof(cert);
	issued_t issued;
	sign_one("CN=untouchable", cert, &cl, &issued);

	/* Manually set ISSUED_FLAG_PROTECTED on the cert's meta. */
	uint8_t meta[256];
	size_t ml = sizeof(meta);
	zassert_ok(storage_issued_meta_read(issued.serial, issued.serial_len, meta, &ml),
		   "meta_read");
	meta[1] |= 0x02; /* ISSUED_FLAG_PROTECTED */
	zassert_ok(storage_issued_meta_write(issued.serial, issued.serial_len, meta, ml),
		   "meta_write");

	int rc = ca_revoke_cert(issued.serial, issued.serial_len, 0);
	zassert_equal(rc, -EACCES, "expected -EACCES, got %d", rc);
}

/* CRL coverage moved to firmware/tests/crl_der/ — that suite asserts
 * RFC 5280 DER properties end-to-end (parse, signature verify, crlNumber,
 * per-slot isolation, etc.) which the old blob-format tests can't. */

ZTEST(sign_csr, test_17_auto_expire_no_certs)
{
	bootstrap_slot0();

	uint32_t count = 99;
	int rc = ca_auto_expire(2000000000ULL, &count);
	zassert_equal(rc, 0, "rc=%d", rc);
	zassert_equal(count, 0u, "no certs to expire");
}

ZTEST(sign_csr, test_18_auto_expire_invalid_now_zero)
{
	bootstrap_slot0();
	uint32_t count = 7;
	int rc = ca_auto_expire(0ULL, &count);
	zassert_equal(rc, -EINVAL, "now=0 -> %d", rc);
}

ZTEST(sign_csr, test_19_auto_expire_flips_expired_bit)
{
	bootstrap_slot0();

	/* Sign two certs: one default, plus one we'll manually backdate. */
	uint8_t cert1[1500], cert2[1500];
	size_t cl1 = sizeof(cert1), cl2 = sizeof(cert2);
	issued_t p1, p2;
	sign_one("CN=keeper", cert1, &cl1, &p1);
	sign_one("CN=dying", cert2, &cl2, &p2);

	/* Now well past 2026-01-01 + 365d (which is 1798761600); pick 2030. */
	uint64_t now_2030 = 1893456000ULL;

	uint32_t count = 0;
	zassert_ok(ca_auto_expire(now_2030, &count), "expire");
	zassert_equal(count, 2u, "both should expire, got %u", count);

	/* Re-run: nothing left to flip. */
	count = 99;
	zassert_ok(ca_auto_expire(now_2030, &count), "expire2");
	zassert_equal(count, 0u, "already expired");

	/* Verify the EXPIRED flag is set on meta of cert1. */
	uint8_t meta[256];
	size_t ml = sizeof(meta);
	zassert_ok(storage_issued_meta_read(p1.serial, p1.serial_len, meta, &ml), "meta");
	zassert_equal(meta[1] & 0x04, 0x04, "EXPIRED bit set");
}

ZTEST(sign_csr, test_20_auto_expire_before_validity_no_op)
{
	bootstrap_slot0();
	uint8_t cert[1500];
	size_t cl = sizeof(cert);
	issued_t p;
	sign_one("CN=fresh", cert, &cl, &p);

	/* now == not_before (no expiry yet, since now < not_after). */
	uint32_t count = 99;
	zassert_ok(ca_auto_expire(1767225600ULL, &count), "expire");
	zassert_equal(count, 0u, "should not expire yet");
}

/* Decode LIST_KEYS payload: array of map(5) with keys c/p/r/s/t.
 * Returns count, fills first entry into *first_slot/type/has_cert. */
static int decode_list_keys(const uint8_t *buf, size_t len, uint32_t *count_out,
			    uint32_t *first_slot, uint32_t *first_type, uint32_t *first_has_cert,
			    uint32_t *first_protect)
{
	size_t off = 0;
	uint8_t mt;
	uint64_t v;
	int rc = cantil_cbor_read_head(buf, len, &off, &mt, &v);

	if (rc) {
		return rc;
	}
	if (mt != CANTIL_CBOR_MT_ARRAY) {
		return -1;
	}
	*count_out = (uint32_t)v;

	int saw_first = 0;
	for (uint32_t i = 0; i < *count_out; i++) {
		rc = cantil_cbor_read_head(buf, len, &off, &mt, &v);
		if (rc || mt != CANTIL_CBOR_MT_MAP || v != 5) {
			return -2;
		}
		uint32_t slot = 0, type = 0, has_cert = 0, protect = 0;
		for (int k = 0; k < 5; k++) {
			const uint8_t *key;
			size_t klen;
			rc = cantil_cbor_read_tstr(buf, len, &off, &key, &klen);
			if (rc || klen != 1) {
				return -3;
			}
			char kc = (char)key[0];
			uint32_t u;
			rc = cantil_cbor_read_uint32(buf, len, &off, &u);
			if (rc) {
				return -4;
			}
			if (kc == 's') {
				slot = u;
			} else if (kc == 't') {
				type = u;
			} else if (kc == 'c') {
				has_cert = u;
			} else if (kc == 'p') {
				protect = u;
			}
		}
		if (!saw_first) {
			if (first_slot) {
				*first_slot = slot;
			}
			if (first_type) {
				*first_type = type;
			}
			if (first_has_cert) {
				*first_has_cert = has_cert;
			}
			if (first_protect) {
				*first_protect = protect;
			}
			saw_first = 1;
		}
	}
	return 0;
}

ZTEST(sign_csr, test_21_list_keys_empty)
{
	uint8_t out[64];
	size_t out_len = sizeof(out);
	zassert_ok(ca_list_keys(out, &out_len), "list_keys empty");
	uint32_t count = 99;
	zassert_equal(decode_list_keys(out, out_len, &count, NULL, NULL, NULL, NULL), 0, "decode");
	zassert_equal(count, 0u, "no slots");
}

ZTEST(sign_csr, test_22_list_keys_after_bootstrap_slot_zero)
{
	bootstrap_slot0();
	uint8_t out[256];
	size_t out_len = sizeof(out);
	zassert_ok(ca_list_keys(out, &out_len), "list_keys");

	uint32_t count = 0, slot = 99, type = 99, has_cert = 99, protect = 99;
	zassert_equal(decode_list_keys(out, out_len, &count, &slot, &type, &has_cert, &protect), 0,
		      "decode");
	zassert_equal(count, 1u, "1 slot");
	zassert_equal(slot, 0u, "slot=0");
	zassert_equal(type, 1u, "P-256");
	zassert_equal(has_cert, 1u, "has_cert");
	zassert_equal(protect & 0x01, 0x01, "is_protected (slot 0 always)");
}

ZTEST(sign_csr, test_23_gen_key_allocates_slot_one)
{
	bootstrap_slot0();
	wipe_dir(LFS_MOUNT "/keys/1");

	uint32_t slot = 99;
	int rc = ca_gen_key(1, &slot);
	zassert_equal(rc, 0, "gen_key=%d", rc);
	zassert_equal(slot, 1u, "first free slot should be 1");

	zassert_equal(storage_slot_key_exists(1), 1, "key.bin present");
}

ZTEST(sign_csr, test_24_gen_key_unsupported_type)
{
	bootstrap_slot0();
	uint32_t slot = 99;
	int rc = ca_gen_key(99, &slot);
	zassert_equal(rc, -ENOTSUP, "expected -ENOTSUP, got %d", rc);
	zassert_equal(slot, 0u, "slot zeroed on error");
}

ZTEST(sign_csr, test_25_gen_key_picks_next_free)
{
	bootstrap_slot0();
	wipe_dir(LFS_MOUNT "/keys/1");
	wipe_dir(LFS_MOUNT "/keys/2");
	wipe_dir(LFS_MOUNT "/keys/3");

	uint32_t s1, s2, s3;
	zassert_ok(ca_gen_key(1, &s1), "gen1");
	zassert_ok(ca_gen_key(1, &s2), "gen2");
	zassert_ok(ca_gen_key(1, &s3), "gen3");
	zassert_equal(s1, 1u, "s1");
	zassert_equal(s2, 2u, "s2");
	zassert_equal(s3, 3u, "s3");
}

ZTEST(sign_csr, test_26_delete_slot_zero_refused)
{
	bootstrap_slot0();
	int rc = ca_delete_key(0);
	zassert_equal(rc, -EPERM, "expected -EPERM, got %d", rc);
	zassert_equal(storage_slot_key_exists(0), 1, "slot 0 still present");
}

ZTEST(sign_csr, test_27_delete_unknown_slot)
{
	int rc = ca_delete_key(2);
	zassert_equal(rc, -ENOENT, "expected -ENOENT, got %d", rc);
}

ZTEST(sign_csr, test_28_delete_protected_blocked)
{
	bootstrap_slot0();
	uint32_t slot = 0;
	zassert_ok(ca_gen_key(1, &slot), "gen");

	/* Mark slot protected manually (Task 10 will do this via PROTECT_SLOT). */
	uint8_t mb[64];
	size_t mlen = sizeof(mb);
	zassert_ok(storage_slot_meta_read(slot, mb, &mlen), "meta_read");
	mb[2] = 1; /* is_protected */
	zassert_ok(storage_slot_meta_write(slot, mb, mlen), "meta_write");

	int rc = ca_delete_key(slot);
	zassert_equal(rc, -EACCES, "expected -EACCES, got %d", rc);
	zassert_equal(storage_slot_key_exists(slot), 1, "still present");
}

ZTEST(sign_csr, test_29_delete_unprotected_succeeds)
{
	bootstrap_slot0();
	uint32_t slot = 0;
	zassert_ok(ca_gen_key(1, &slot), "gen");
	zassert_equal(storage_slot_key_exists(slot), 1, "exists pre-delete");

	zassert_ok(ca_delete_key(slot), "delete");
	zassert_equal(storage_slot_key_exists(slot), 0, "key.bin gone");
}

ZTEST(sign_csr, test_30_protect_unknown_slot)
{
	int rc = ca_protect_slot(5, false);
	zassert_equal(rc, -ENOENT, "expected -ENOENT, got %d", rc);
}

ZTEST(sign_csr, test_31_protect_sets_meta_bit)
{
	bootstrap_slot0();
	uint32_t slot = 0;
	zassert_ok(ca_gen_key(1, &slot), "gen");

	zassert_ok(ca_protect_slot(slot, false), "protect");

	uint8_t mb[64];
	size_t mlen = sizeof(mb);
	zassert_ok(storage_slot_meta_read(slot, mb, &mlen), "meta");
	zassert_equal(mb[2], 1, "is_protected");
	zassert_equal(mb[3], 0, "protect_issued not set");

	/* Round-trip: delete attempt now blocked. */
	int rc = ca_delete_key(slot);
	zassert_equal(rc, -EACCES, "delete blocked, got %d", rc);
}

ZTEST(sign_csr, test_32_unprotect_clears_bit)
{
	bootstrap_slot0();
	uint32_t slot = 0;
	zassert_ok(ca_gen_key(1, &slot), "gen");
	zassert_ok(ca_protect_slot(slot, true), "protect");
	zassert_ok(ca_unprotect_slot(slot), "unprotect");

	uint8_t mb[64];
	size_t mlen = sizeof(mb);
	zassert_ok(storage_slot_meta_read(slot, mb, &mlen), "meta");
	zassert_equal(mb[2], 0, "is_protected cleared");
	zassert_equal(mb[3], 0, "protect_issued cleared");

	/* Delete should succeed now. */
	zassert_ok(ca_delete_key(slot), "delete after unprotect");
}

ZTEST(sign_csr, test_33_protect_issued_propagates_to_certs)
{
	bootstrap_slot0();

	/* Sign a cert under slot 0, then protect slot 0 with protect_issued=1.
	 * The issued cert's meta should pick up ISSUED_FLAG_PROTECTED. */
	uint8_t cert[1500];
	size_t cl = sizeof(cert);
	issued_t p;
	sign_one("CN=propagate", cert, &cl, &p);

	zassert_ok(ca_protect_slot(0, true), "protect slot 0 w/ issued");

	uint8_t mb[256];
	size_t mlen = sizeof(mb);
	zassert_ok(storage_issued_meta_read(p.serial, p.serial_len, mb, &mlen), "issued meta");
	zassert_equal(mb[1] & 0x02, 0x02, "ISSUED_FLAG_PROTECTED set");

	/* Revoke now refused. */
	int rc = ca_revoke_cert(p.serial, p.serial_len, 0);
	zassert_equal(rc, -EACCES, "revoke blocked, got %d", rc);
}

ZTEST(sign_csr, test_34_gen_key_csr_unknown_slot)
{
	int rc = ca_gen_key_csr(5, "CN=ghost");
	zassert_equal(rc, -ENOENT, "expected -ENOENT, got %d", rc);
}

ZTEST(sign_csr, test_35_gen_key_csr_invalid_dn)
{
	bootstrap_slot0();
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen");
	int rc = ca_gen_key_csr(slot, "");
	zassert_equal(rc, -EINVAL, "empty DN -> %d", rc);
	rc = ca_gen_key_csr(slot, NULL);
	zassert_equal(rc, -EINVAL, "NULL DN -> %d", rc);
}

ZTEST(sign_csr, test_36_gen_key_csr_writes_and_reads_back)
{
	bootstrap_slot0();
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen");

	zassert_ok(ca_gen_key_csr(slot, "CN=enrolment,O=Cantil"), "gen_csr");

	uint8_t csr[1024];
	size_t csr_len = sizeof(csr);
	zassert_ok(ca_get_key_csr(slot, csr, &csr_len), "get_csr");
	zassert_true(csr_len > 100 && csr_len < 1024, "csr_len=%zu", csr_len);

	/* Parse back and verify subject matches, via the certparse seam. */
	certgen_dn_t subj;
	uint8_t pub[65];
	zassert_ok(certparse_csr(csr, csr_len, &subj, pub), "parse csr");
	zassert_equal(strcmp(subj.cn, "enrolment"), 0, "CN: %s", subj.cn);
	zassert_equal(strcmp(subj.o, "Cantil"), 0, "O: %s", subj.o);
}

ZTEST(sign_csr, test_37_get_key_csr_when_none)
{
	bootstrap_slot0();
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen");

	uint8_t csr[1024];
	size_t csr_len = sizeof(csr);
	int rc = ca_get_key_csr(slot, csr, &csr_len);
	zassert_equal(rc, -ENOENT, "no csr.der -> %d", rc);
}

ZTEST(sign_csr, test_38_push_key_cert_unknown_slot)
{
	uint8_t junk[200] = {0};
	int rc = ca_push_key_cert(5, junk, sizeof(junk), NULL, 0);
	zassert_equal(rc, -ENOENT, "expected -ENOENT, got %d", rc);
}

ZTEST(sign_csr, test_39_push_key_cert_invalid_der)
{
	bootstrap_slot0();
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen");
	uint8_t junk[64] = {0x30, 0x82, 0x00, 0x10, 0xff, 0xff};
	int rc = ca_push_key_cert(slot, junk, sizeof(junk), NULL, 0);
	zassert_equal(rc, -EINVAL, "junk -> %d", rc);
}

ZTEST(sign_csr, test_40_push_key_cert_wrong_key_rejected)
{
	bootstrap_slot0();

	/* Sign a cert for some *external* keypair under the CA, then try to
	 * install that cert into a freshly-genned slot. The slot's pubkey
	 * won't match the cert's, so the push must reject. */
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen");

	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=external");
	uint8_t cert[1500];
	size_t certl = sizeof(cert);
	zassert_ok(ca_sign_csr(csr, cl, cert, &certl), "sign");

	int rc = ca_push_key_cert(slot, cert, certl, NULL, 0);
	zassert_equal(rc, -EINVAL, "pubkey mismatch -> %d", rc);
}

ZTEST(sign_csr, test_41_push_key_cert_matches_and_installs)
{
	bootstrap_slot0();

	/* Generate a slot key, then GEN_KEY_CSR for it, sign that CSR with
	 * the CA, then push the resulting cert back into the slot. */
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen");
	zassert_ok(ca_gen_key_csr(slot, "CN=enrolled"), "gen_csr");

	uint8_t csr[1024];
	size_t cl = sizeof(csr);
	zassert_ok(ca_get_key_csr(slot, csr, &cl), "get_csr");

	uint8_t cert[1500];
	size_t certl = sizeof(cert);
	zassert_ok(ca_sign_csr(csr, cl, cert, &certl), "ca sign");

	int rc = ca_push_key_cert(slot, cert, certl, NULL, 0);
	zassert_equal(rc, 0, "push=%d", rc);

	/* Cert is now installed; read back and check identity. */
	uint8_t stored[1500];
	size_t stored_len = sizeof(stored);
	zassert_ok(storage_slot_cert_read(slot, stored, &stored_len), "cert_read");
	zassert_equal(stored_len, certl, "len match");
	zassert_mem_equal(stored, cert, certl, "bytes match");
}

ZTEST(sign_csr, test_42_push_key_cert_protected_blocked)
{
	bootstrap_slot0();
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen");
	zassert_ok(ca_gen_key_csr(slot, "CN=blocked"), "gen_csr");
	uint8_t csr[1024];
	size_t cl = sizeof(csr);
	zassert_ok(ca_get_key_csr(slot, csr, &cl), "get_csr");
	uint8_t cert[1500];
	size_t certl = sizeof(cert);
	zassert_ok(ca_sign_csr(csr, cl, cert, &certl), "sign");
	zassert_ok(ca_push_key_cert(slot, cert, certl, NULL, 0), "1st push");

	/* Mark protected, push again -> -EACCES (cert already present). */
	uint8_t mb[64];
	size_t ml = sizeof(mb);
	zassert_ok(storage_slot_meta_read(slot, mb, &ml), "meta");
	mb[2] = 1;
	zassert_ok(storage_slot_meta_write(slot, mb, ml), "meta_write");

	int rc = ca_push_key_cert(slot, cert, certl, NULL, 0);
	zassert_equal(rc, -EACCES, "blocked: %d", rc);
}

ZTEST(sign_csr, test_43_sign_csr_slot_zero_matches_legacy)
{
	bootstrap_slot0();

	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=parity");

	uint8_t cert[1500];
	size_t certl = sizeof(cert);
	zassert_ok(ca_sign_csr_slot(0, csr, cl, cert, &certl), "slot 0");
	zassert_true(certl > 200, "got %zu", certl);

	/* Issued by slot 0: the leaf must chain to slot 0's own cert. This is a
	 * stronger check than matching the issuer DN string — it verifies the
	 * signature. */
	uint8_t ca_cert[1500];
	size_t ca_len = sizeof(ca_cert);
	zassert_ok(ca_get_cert(ca_cert, &ca_len), "ca cert");
	zassert_ok(certparse_verify_chain(cert, certl, NULL, NULL, 0, ca_cert, ca_len),
		   "issued chains to slot 0");
}

ZTEST(sign_csr, test_44_sign_csr_slot_unknown_issuer)
{
	bootstrap_slot0();
	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=lost");

	uint8_t cert[1500];
	size_t certl = sizeof(cert);
	int rc = ca_sign_csr_slot(5, csr, cl, cert, &certl);
	zassert_equal(rc, -ENOENT, "issuer slot 5 unpopulated: %d", rc);
}

ZTEST(sign_csr, test_45_sign_csr_slot_subca_chain)
{
	bootstrap_slot0();

	/* Create a sub-CA: gen key + push x509 makes slot 1 into a CA with
	 * its own self-signed cert. Then sign an end-entity CSR via slot 1. */
	uint32_t sub_slot;
	zassert_ok(ca_gen_key(1, &sub_slot), "gen sub-CA");

	uint8_t x509[256];
	size_t x509_len = build_x509_blob(x509, sizeof(x509));
	/* Repurpose helper: this writes "CN=Cantil CA" — fine for the sub-CA test;
	 * the test cares about the chain working, not the names being distinct. */
	zassert_ok(ca_push_key_x509(sub_slot, x509, x509_len), "x509");

	/* Sign an end-entity CSR via the sub-CA. */
	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=end-entity");

	uint8_t cert[1500];
	size_t certl = sizeof(cert);
	zassert_ok(ca_sign_csr_slot(sub_slot, csr, cl, cert, &certl), "subca sign");

	/* The end-entity must chain to the sub-CA cert. */
	uint8_t sub_cert[1500];
	size_t sub_len = sizeof(sub_cert);
	zassert_ok(storage_slot_cert_read(sub_slot, sub_cert, &sub_len), "subca read");

	zassert_ok(certparse_verify_chain(cert, certl, NULL, NULL, 0, sub_cert, sub_len),
		   "issued chains to sub-CA");

	/* And meta records the right issuer_slot. */
	certparse_cert_t issued;
	zassert_ok(certparse_cert(cert, certl, &issued), "parse issued");
	uint8_t mb[256];
	size_t ml = sizeof(mb);
	zassert_ok(storage_issued_meta_read(issued.serial, issued.serial_len, mb, &ml), "meta");
	uint32_t recorded_issuer;
	memcpy(&recorded_issuer, &mb[4], 4);
	zassert_equal(recorded_issuer, sub_slot, "meta issuer_slot");
}

/* Build x509 blob with a specific CN — extends build_x509_blob to vary subject. */
static size_t build_x509_blob_cn(uint8_t *out, size_t cap, const char *cn, bool is_ca)
{
	size_t off = 0;
	const char *o = "Cantil";
	out[off++] = 0x01;
	out[off++] = 0x68;
	out[off++] = is_ca ? 1 : 0;
	out[off++] = 0;
	out[off++] = 0x00;
	out[off++] = is_ca ? 0x86 : 0x80;
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

ZTEST(sign_csr, test_46_sign_key_slot_unknown_subject)
{
	bootstrap_slot0();
	int rc = ca_sign_key_slot(0, 5);
	zassert_equal(rc, -ENOENT, "subject 5 -> %d", rc);
}

ZTEST(sign_csr, test_47_sign_key_slot_unknown_issuer)
{
	int rc = ca_sign_key_slot(5, 0);
	zassert_equal(rc, -ENOENT, "issuer 5 -> %d", rc);
}

ZTEST(sign_csr, test_48_sign_key_slot_subject_no_x509)
{
	bootstrap_slot0();
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen");
	int rc = ca_sign_key_slot(0, slot);
	zassert_equal(rc, -ENOENT, "subject has no x509 -> %d", rc);
}

ZTEST(sign_csr, test_49_sign_key_slot_chain_verifies)
{
	bootstrap_slot0();

	/* Gen subject slot 1 with its own x509 (entity, not CA). */
	uint32_t sub;
	zassert_ok(ca_gen_key(1, &sub), "gen sub");

	uint8_t x509[256];
	size_t x509_len = build_x509_blob_cn(x509, sizeof(x509), "entity-key", false);
	zassert_ok(ca_push_key_x509(sub, x509, x509_len), "subject x509");

	/* Issuer (slot 0) signs subject's pubkey. */
	zassert_ok(ca_sign_key_slot(0, sub), "sign");

	/* The newly-written cert should chain to slot 0. */
	uint8_t sub_cert[1500];
	size_t sub_len = sizeof(sub_cert);
	zassert_ok(storage_slot_cert_read(sub, sub_cert, &sub_len), "read");

	uint8_t ca_cert[1500];
	size_t ca_len = sizeof(ca_cert);
	zassert_ok(ca_get_cert(ca_cert, &ca_len), "ca cert");

	zassert_ok(certparse_verify_chain(sub_cert, sub_len, NULL, NULL, 0, ca_cert, ca_len),
		   "issued chains to slot 0");

	/* Subject identity is read from the leaf; the issuer identity is proven
	 * by the chain verification above. */
	certparse_cert_t issued;
	zassert_ok(certparse_cert(sub_cert, sub_len, &issued), "parse issued");
	zassert_equal(strcmp(issued.subject.cn, "entity-key"), 0, "subject CN: %s",
		      issued.subject.cn);
}

ZTEST(sign_csr, test_06_two_signs_have_distinct_serials)
{
	bootstrap_slot0();

	uint8_t csr1[512], csr2[512];
	size_t l1 = gen_csr(csr1, sizeof(csr1), "CN=one");
	size_t l2 = gen_csr(csr2, sizeof(csr2), "CN=two");

	uint8_t cert1[1500], cert2[1500];
	size_t cl1 = sizeof(cert1), cl2 = sizeof(cert2);
	zassert_ok(ca_sign_csr(csr1, l1, cert1, &cl1), "sign1");
	zassert_ok(ca_sign_csr(csr2, l2, cert2, &cl2), "sign2");

	certparse_cert_t p1, p2;
	zassert_ok(certparse_cert(cert1, cl1, &p1), "parse1");
	zassert_ok(certparse_cert(cert2, cl2, &p2), "parse2");

	zassert_true(p1.serial_len == p2.serial_len, "serial lens differ");
	zassert_true(memcmp(p1.serial, p2.serial, p1.serial_len) != 0, "serials collided");

	uint32_t count = 0;
	zassert_ok(storage_count_issued_certs(&count), "count");
	zassert_equal(count, 2u, "cert count=%u", count);
}

/* ── chain walker (GET_CA_CHAIN / ca_get_chain_slot) ────────────────────── */

ZTEST(sign_csr, test_50_chain_self_signed_root)
{
	bootstrap_slot0();

	uint8_t chain[2048];
	size_t chain_len = sizeof(chain);
	zassert_ok(ca_get_chain_slot(0, chain, &chain_len), "chain slot 0");

	/* Self-signed root: chain is exactly slot 0's cert. */
	uint8_t cert[1500];
	size_t cert_len = sizeof(cert);
	zassert_ok(ca_get_cert(cert, &cert_len), "ca cert");
	zassert_equal(chain_len, cert_len, "chain_len=%zu cert_len=%zu", chain_len, cert_len);
	zassert_mem_equal(chain, cert, cert_len, "chain != cert");
}

/* DER SEQUENCE is tag 0x30 followed by length (short or long form). Return
 * the total byte length of a single DER cert at *p (header + body). */
static size_t der_cert_total_len(const uint8_t *p, size_t cap)
{
	if (cap < 2 || p[0] != 0x30) {
		return 0;
	}
	if ((p[1] & 0x80) == 0) {
		return 2 + p[1];
	}
	int nb = p[1] & 0x7F;
	if (nb == 0 || nb > 4 || (size_t)(2 + nb) > cap) {
		return 0;
	}
	size_t len = 0;
	for (int i = 0; i < nb; i++) {
		len = (len << 8) | p[2 + i];
	}
	return 2 + nb + len;
}

ZTEST(sign_csr, test_51_chain_subca_two_certs_verify)
{
	bootstrap_slot0();

	/* Build a sub-CA at slot 1 signed by slot 0. */
	uint32_t sub;
	zassert_ok(ca_gen_key(1, &sub), "gen sub-CA");
	uint8_t x509[256];
	size_t x509_len = build_x509_blob_cn(x509, sizeof(x509), "Cantil SubCA", true);
	zassert_ok(ca_push_key_x509(sub, x509, x509_len), "subca x509");
	zassert_ok(ca_sign_key_slot(0, sub), "slot 0 signs sub-CA");

	uint8_t chain[4096];
	size_t chain_len = sizeof(chain);
	zassert_ok(ca_get_chain_slot(sub, chain, &chain_len), "chain sub");

	/* Split the chain into individual DER certs. */
	size_t off = 0;
	size_t len1 = der_cert_total_len(&chain[off], chain_len - off);
	zassert_true(len1 > 0 && len1 < chain_len, "len1=%zu", len1);
	off += len1;
	size_t len2 = der_cert_total_len(&chain[off], chain_len - off);
	zassert_true(len2 > 0, "len2=%zu", len2);
	zassert_equal(off + len2, chain_len, "extra bytes after 2 certs");

	/* The two split certs must verify as a chain: leaf (the sub-CA cert)
	 * against root (slot 0). */
	zassert_ok(certparse_verify_chain(chain, len1, NULL, NULL, 0, &chain[len1], len2),
		   "sub-CA chains to root");
}

ZTEST(sign_csr, test_52_chain_external_push_round_trips)
{
	bootstrap_slot0();

	/* Build an "external" chain blob — two fake DER certs concatenated.
	 * We reuse the slot 0 self-signed cert bytes twice; the walker just
	 * appends chain.der after the slot's own cert and stops, so the
	 * test only needs to confirm bytes flow through. */
	uint8_t fake_a[1500];
	size_t la = sizeof(fake_a);
	uint8_t fake_b[1500];
	size_t lb = sizeof(fake_b);
	zassert_ok(ca_get_cert(fake_a, &la), "ca cert a");
	zassert_ok(ca_get_cert(fake_b, &lb), "ca cert b");

	uint8_t pushed_chain[2 * 1500];
	memcpy(&pushed_chain[0], fake_a, la);
	memcpy(&pushed_chain[la], fake_b, lb);
	size_t pushed_len = la + lb;

	/* Push as slot 0's chain via ca_push_cert(cert, chain). The cert we
	 * push is just the existing slot 0 cert (so the leaf doesn't change). */
	uint8_t leaf[1500];
	size_t leaf_len = sizeof(leaf);
	zassert_ok(ca_get_cert(leaf, &leaf_len), "leaf");
	zassert_ok(ca_push_cert(leaf, leaf_len, pushed_chain, pushed_len),
		   "push_ca_cert with chain");

	uint8_t chain[4096];
	size_t chain_len = sizeof(chain);
	zassert_ok(ca_get_chain_slot(0, chain, &chain_len), "chain slot 0");

	/* Expected: leaf || pushed_chain. */
	zassert_equal(chain_len, leaf_len + pushed_len, "chain_len=%zu expected=%zu", chain_len,
		      leaf_len + pushed_len);
	zassert_mem_equal(chain, leaf, leaf_len, "leaf bytes");
	zassert_mem_equal(&chain[leaf_len], pushed_chain, pushed_len, "appended chain bytes");
}

ZTEST(sign_csr, test_53_regen_self_signed_drops_chain)
{
	bootstrap_slot0();

	/* Use a non-protected slot so we can re-push x509 freely. */
	uint32_t slot;
	zassert_ok(ca_gen_key(1, &slot), "gen");
	uint8_t x509[256];
	size_t x509_len = build_x509_blob_cn(x509, sizeof(x509), "RegenSlot", false);
	zassert_ok(ca_push_key_x509(slot, x509, x509_len), "x509");

	/* Install an arbitrary chain — bytes content doesn't matter, just
	 * that the walker would append it if it were still present. */
	uint8_t leaf[1500];
	size_t leaf_len = sizeof(leaf);
	zassert_ok(storage_slot_cert_read(slot, leaf, &leaf_len), "leaf");

	uint8_t fake_chain[1500];
	size_t fc_len = sizeof(fake_chain);
	zassert_ok(ca_get_cert(fake_chain, &fc_len), "fake chain bytes");
	zassert_ok(ca_push_key_cert(slot, leaf, leaf_len, fake_chain, fc_len),
		   "push_key_cert with chain");

	uint8_t chain[4096];
	size_t chain_len = sizeof(chain);
	zassert_ok(ca_get_chain_slot(slot, chain, &chain_len), "chain v1");
	zassert_equal(chain_len, leaf_len + fc_len, "chain v1 size");

	/* Regenerate self-signed via PUSH_KEY_X509 — must drop chain. */
	zassert_ok(ca_push_key_x509(slot, x509, x509_len), "re-push x509");
	chain_len = sizeof(chain);
	zassert_ok(ca_get_chain_slot(slot, chain, &chain_len), "chain v2");

	leaf_len = sizeof(leaf);
	zassert_ok(storage_slot_cert_read(slot, leaf, &leaf_len), "leaf v2");
	zassert_equal(chain_len, leaf_len, "chain not collapsed");
}

/*
 * Export a real CA-signed leaf, its issuer, and a CSR for scripts/openssl_gate.sh.
 *
 * This test asserts almost nothing itself — that is deliberate. Its job is to
 * hand generated DER to a third implementation, because every other assertion
 * in this file uses the same library that produced the bytes and therefore
 * cannot see a misunderstanding the writer and reader share. Two step-4 bugs
 * (a CSR emitted as version 2, a certificate with an empty SPKI) were exactly
 * that shape.
 *
 * If the gate rejects any of these, the suite still reports PASS and
 * scripts/test.sh reports FAIL — which is the intended division of labour.
 */
ZTEST(sign_csr, test_54_export_for_openssl_gate)
{
	bootstrap_slot0();

	uint8_t cert[1500];
	size_t cert_len = sizeof(cert);
	issued_t issued;

	sign_one("CN=openssl-gate-leaf", cert, &cert_len, &issued);

	uint8_t ca_cert[1500];
	size_t ca_len = sizeof(ca_cert);

	zassert_ok(storage_slot_cert_read(0, ca_cert, &ca_len), "read slot 0 cert");

	/* Paired names: the gate verifies <base>.leaf.der against <base>.ca.der. */
	test_artifact_leaf("signed_leaf", cert, cert_len);
	test_artifact_ca("signed_leaf", ca_cert, ca_len);

	/* The issuer on its own, as a plain certificate. */
	test_artifact_cert("slot0_ca", ca_cert, ca_len);

	/* A CSR, so the gate checks its self-signature — the version-2 bug lived
	 * here and a same-library round trip did not notice. */
	uint8_t csr[512];
	size_t cl = gen_csr(csr, sizeof(csr), "CN=openssl-gate-csr");

	test_artifact_csr("generated", csr, cl);
}
