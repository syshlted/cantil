/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * Session-slot identity conformance on native_sim (transport + pairing T-02).
 *
 * Drives session_slot.c + ca_build_session_cert() against the simulated flash
 * partition in boards/native_sim.overlay. Each test starts from a wiped
 * /session/ + /noise/ via test_before(), so order-independence holds.
 *
 * Coverage:
 *   1. First boot writes key.bin / id_key.bin / meta.bin / cert.der.
 *   2. cert.der parses and is a valid self-signed X.509 (TBS signature
 *      verifies under its own SubjectPublicKeyInfo).
 *   3. Subject CN is FICR-derived; KU = digitalSignature + keyAgreement,
 *      never keyCertSign; not a CA.
 *   4. The 1.3.6.1.4.1.58270.1.1 extension carries the cached X25519 pubkey,
 *      which matches both meta.bin and the /noise/ static pubkey.
 *   5. Re-init is a no-op: cert bytes and pubkey are unchanged.
 *   6–9. T-03 strict comparison: ca_session_cert_matches_constant() matches a
 *      fresh cert, detects DN / key_usage / validity tampering, and the
 *      non-strict boot path warns-and-continues on a planted mismatch (the
 *      strict "enter recovery" path lives in the session_recovery test app).
 *   10–12. T-05 GET_SESSION_CSR.
 *   13–16. T-06 SIGN_SESSION_FROM_SLOT: self-signed → CA-signed by slot 0
 *      (issuer != subject, signature verifies under the CA cert, X25519 ext +
 *      subject identity preserved); force-required re-signing rule; the
 *      CA-signed cert still matches the build constant (T-03 ignores issuer);
 *      bad issuer slots are rejected.
 *   17–21. T-07 PUSH_SESSION_CERT.
 *   22. T-08 validity relaxation: CA-signed cert passes matches_constant even
 *      when the constant's validity_days has drifted; self-signed cert with the
 *      same drift is still rejected.
 *   23–24. T-09 refuse-as-issuer sweep: ca_sign_csr_slot and ca_sign_key_slot
 *      both return -EINVAL for any out-of-range issuer_slot (which covers the
 *      session slot — it has no numbered /keys/ ID).
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/fs/fs.h>
#include <string.h>
#include <errno.h>

#include "ca/certparse.h"
#include "session/session_slot.h"
#include "session/session_x509.h"
#include "ca/ca.h"
#include "crypto/crypto.h"
#include "storage/storage.h"
#include "test_artifacts.h"

#define LFS_MOUNT     "/lfs"
#define SESSION_DIR   LFS_MOUNT "/session"
#define SESSION_KEY   SESSION_DIR "/key.bin"
#define SESSION_IDKEY SESSION_DIR "/id_key.bin"
#define SESSION_META  SESSION_DIR "/meta.bin"
#define SESSION_CERT  SESSION_DIR "/cert.der"
#define SESSION_CSR   SESSION_DIR "/csr.der"
#define NOISE_DIR     LFS_MOUNT "/noise"

/* 1.3.6.1.4.1.58270.1.1 — the session X25519-binding extension OID (DER). */
static const uint8_t OID_X25519[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xc7, 0x1e, 0x01, 0x01};

/* ── helpers ──────────────────────────────────────────────────────────── */

static int file_exists(const char *path)
{
	struct fs_dirent ent;
	int ret = fs_stat(path, &ent);

	if (ret == 0) {
		return 1;
	}
	if (ret == -ENOENT) {
		return 0;
	}
	return ret;
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
		fs_unlink(path);
	}
	fs_closedir(&d);
	fs_unlink(dir);
}

/* Find `needle` within `hay`; returns pointer to first match or NULL. */
static const uint8_t *find_bytes(const uint8_t *hay, size_t hay_len, const uint8_t *needle,
				 size_t needle_len)
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
 * Copy the X25519-binding pubkey out of a session cert (the
 * 1.3.6.1.4.1.58270.1.1 extension). certparse reads it; returns 0 on success,
 * -1 if the extension is absent or the cert does not parse.
 */
static int cert_x25519(const uint8_t *der, size_t len, uint8_t out[32])
{
	certparse_cert_t c;

	if (certparse_cert(der, len, &c) != 0 || !c.has_x25519) {
		return -1;
	}
	memcpy(out, c.x25519, 32);
	return 0;
}

/* Verify `leaf` was signed by `issuer` (both raw DER). 0 on success. */
static int verify_under(const uint8_t *leaf, size_t ll, const uint8_t *issuer, size_t il)
{
	return certparse_verify_chain(leaf, ll, NULL, NULL, 0, issuer, il);
}

/* Build a packed x509 blob for a CA slot (is_ca=1, keyCertSign|cRLSign). */
static size_t build_ca_blob(uint8_t *out, size_t cap)
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
	out[off++] = 0x86; /* KU = digitalSig|keyCertSign|cRLSign */
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

/* Provision CA slot 0 with a key + self-signed cert so it can issue. */
static void bootstrap_slot0(void)
{
	uint8_t blob[256];
	size_t len = build_ca_blob(blob, sizeof(blob));

	zassert_ok(ca_provision(0), "ca_provision");
	zassert_ok(ca_push_key_x509(0, blob, len), "push_key_x509 slot 0");
	zassert_true(ca_ready(), "ca_ready after push");
}

/* True if two certs carry the same P-256 subject public key. */
static bool same_pubkey_cert(const uint8_t *a, size_t la, const uint8_t *b, size_t lb)
{
	certparse_cert_t ca, cb;

	if (certparse_cert(a, la, &ca) || certparse_cert(b, lb, &cb)) {
		return false;
	}
	return ca.has_pubkey && cb.has_pubkey && memcmp(ca.pubkey, cb.pubkey, 65) == 0;
}

/* ── suite scaffolding ────────────────────────────────────────────────── */

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init failed");

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
	wipe_dir(SESSION_DIR);
	wipe_dir(NOISE_DIR);
	wipe_dir(LFS_MOUNT "/keys/0"); /* T-06 provisions a CA in slot 0 */

	/*
	 * Tests 25-27 remove the volume marker. Restore it here rather than
	 * trusting each test to clean up: native_sim keeps one flash.bin at the
	 * repo root shared by every suite and every later run, so a test that
	 * fails part-way would otherwise leave the next suite in degraded mode.
	 */
	(void)storage_volume_marker_write();
	(void)storage_volume_verify();
}

ZTEST_SUITE(session_slot, NULL, suite_setup, test_before, NULL, NULL);

/* ── tests ────────────────────────────────────────────────────────────── */

ZTEST(session_slot, test_01_first_boot_creates_identity)
{
	zassert_ok(session_slot_init(), "session_slot_init first boot");

	zassert_equal(file_exists(SESSION_KEY), 1, "key.bin should exist");
	zassert_equal(file_exists(SESSION_IDKEY), 1, "id_key.bin should exist");
	zassert_equal(file_exists(SESSION_META), 1, "meta.bin should exist");
	zassert_equal(file_exists(SESSION_CERT), 1, "cert.der should exist");
	/* T-04: the X25519 key now lives only in /session/key.bin — first-boot
	 * init no longer writes the retired /noise/ store. */
	zassert_equal(file_exists(NOISE_DIR "/pub.bin"), 0,
		      "retired /noise/ store should not be created");
}

ZTEST(session_slot, test_02_cert_is_valid_self_signed)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");
	zassert_true(der_len > 0 && der_len <= sizeof(der), "cert len sane");

	certparse_cert_t crt;

	zassert_ok(certparse_cert(der, der_len, &crt), "cert parses as DER");
	zassert_true(crt.self_signed, "self-signed: issuer == subject");

	/* The self-signature itself is verified by the OpenSSL gate: test_28
	 * exports this same cert as both leaf and anchor, and the gate runs
	 * `openssl verify -check_ss_sig`. certparse_verify_chain cannot stand in
	 * here — it requires a CA anchor, and a session cert is CA:FALSE. */
}

ZTEST(session_slot, test_03_subject_ku_and_not_ca)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	certparse_cert_t crt;

	zassert_ok(certparse_cert(der, der_len, &crt), "parse");
	zassert_equal(strncmp(crt.subject.cn, "Cantil", 6), 0,
		      "subject CN should be FICR-derived (got '%s')", crt.subject.cn);

	/* KU: digitalSignature + keyAgreement set; keyCertSign not. */
	zassert_true(crt.key_usage & CERTGEN_KU_DIGITAL_SIGNATURE, "digitalSignature must be set");
	zassert_true(crt.key_usage & CERTGEN_KU_KEY_AGREEMENT, "keyAgreement must be set");
	zassert_false(crt.key_usage & CERTGEN_KU_KEY_CERT_SIGN, "keyCertSign must NOT be set");

	/* Not a CA. */
	zassert_false(crt.is_ca, "session cert must not be a CA");
}

ZTEST(session_slot, test_04_x25519_extension_matches_pubkey)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	uint8_t ext_pub[32];

	zassert_ok(cert_x25519(der, der_len, ext_pub), "X25519 binding extension present");

	uint8_t meta_pub[32];

	zassert_ok(session_slot_get_pubkey(meta_pub), "get_pubkey from meta");
	zassert_mem_equal(ext_pub, meta_pub, 32, "extension pubkey == cached meta pubkey");

	/* T-04 retired the /noise/ store: the session slot now owns the X25519
	 * key, so the cert's bound pubkey, the cached meta pubkey, and the slot
	 * accessor are the single source of truth. */
}

ZTEST(session_slot, test_05_reinit_is_noop)
{
	zassert_ok(session_slot_init(), "first init");

	uint8_t der1[2048], der2[2048];
	size_t len1 = sizeof(der1), len2 = sizeof(der2);
	uint8_t pub1[32], pub2[32];

	zassert_ok(session_slot_get_cert(der1, &len1), "cert #1");
	zassert_ok(session_slot_get_pubkey(pub1), "pub #1");

	/* Second init must not regenerate keys or cert. */
	zassert_ok(session_slot_init(), "second init (no-op)");

	zassert_ok(session_slot_get_cert(der2, &len2), "cert #2");
	zassert_ok(session_slot_get_pubkey(pub2), "pub #2");

	zassert_equal(len1, len2, "cert length stable across re-init");
	zassert_mem_equal(der1, der2, len1, "cert bytes stable across re-init");
	zassert_mem_equal(pub1, pub2, 32, "pubkey stable across re-init");
}

/* ── T-03: strict boot-time identity comparison ───────────────────────────
 *
 * These run in the non-strict default build (CONFIG_CANTIL_SESSION_X509_STRICT
 * unset), so they cover the pure comparison helper and the "warn + continue"
 * path. The strict "enter recovery" path is exercised by the separate
 * session_recovery test app (built with STRICT=y).
 */

/* Offset of the first byte of the O (organization) value inside a packed blob:
 * 6-byte header, then [cn_len][cn], then [o_len], then O bytes. */
static size_t blob_o_value_off(const uint8_t *blob)
{
	size_t off = 6;
	uint8_t cn_len = blob[off];

	off += 1 + cn_len; /* skip cn_len + cn bytes */
	off += 1;          /* skip o_len byte → first O byte */
	return off;
}

ZTEST(session_slot, test_06_compare_matches_real_constant)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	int m = ca_session_cert_matches_constant(der, der_len, cantil_session_x509_constant,
						 cantil_session_x509_constant_len);

	zassert_equal(m, 1, "fresh cert must match its own build constant (got %d)", m);
}

ZTEST(session_slot, test_07_compare_detects_dn_mismatch)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	/* Copy the constant and flip one byte of the O value. */
	uint8_t blob[256];

	zassert_true(cantil_session_x509_constant_len <= sizeof(blob), "blob fits");
	memcpy(blob, cantil_session_x509_constant, cantil_session_x509_constant_len);
	blob[blob_o_value_off(blob)] ^= 0x20; /* perturb O */

	int m = ca_session_cert_matches_constant(der, der_len, blob,
						 cantil_session_x509_constant_len);

	zassert_equal(m, 0, "altered O must be detected as a mismatch (got %d)", m);
}

ZTEST(session_slot, test_08_compare_detects_ku_and_validity_mismatch)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	uint8_t blob[256];

	/* key_usage lives at bytes 4..5 (BE). Drop the keyAgreement bit (0x08). */
	memcpy(blob, cantil_session_x509_constant, cantil_session_x509_constant_len);
	blob[5] &= (uint8_t)~0x08;
	zassert_equal(ca_session_cert_matches_constant(der, der_len, blob,
						       cantil_session_x509_constant_len),
		      0, "altered key_usage must be a mismatch");

	/* validity_days lives at bytes 0..1 (BE). Bump it by one day. */
	memcpy(blob, cantil_session_x509_constant, cantil_session_x509_constant_len);
	blob[1] ^= 0x01;
	zassert_equal(ca_session_cert_matches_constant(der, der_len, blob,
						       cantil_session_x509_constant_len),
		      0, "altered validity must be a mismatch");
}

ZTEST(session_slot, test_09_nonstrict_mismatch_warns_continues)
{
	/* Plant a cert built from a constant whose O differs from the real one,
	 * so the boot-time verify path sees a mismatch. */
	uint8_t blob[256];

	memcpy(blob, cantil_session_x509_constant, cantil_session_x509_constant_len);
	blob[blob_o_value_off(blob)] ^= 0x20;

	uint8_t id_priv[64];
	size_t id_len = sizeof(id_priv);

	zassert_ok(crypto_keygen(id_priv, &id_len), "P-256 keygen");
	zassert_equal(id_len, 32, "P-256 scalar is 32 bytes");

	uint8_t x25519_pub[32] = {0};
	uint8_t cert[2048];
	size_t cert_len = sizeof(cert);

	zassert_ok(ca_build_session_cert(blob, cantil_session_x509_constant_len, "Cantil", id_priv,
					 x25519_pub, cert, &cert_len),
		   "build mismatching cert");

	zassert_ok(storage_session_cert_write(cert, cert_len), "plant cert.der");

	/* Non-strict build: a mismatch must NOT brick the device. */
	zassert_ok(session_slot_init(), "init returns OK despite mismatch");
	zassert_false(session_slot_in_recovery(),
		      "non-strict mismatch must not enter recovery mode");
}

/* ── T-05: GET_SESSION_CSR ─────────────────────────────────────────────────
 *
 * session_slot_get_csr() builds a PKCS#10 CSR over the P-256 identity key with
 * the session subject DN and the X25519-binding extensionRequest, and persists
 * it to /session/csr.der.
 */

ZTEST(session_slot, test_10_get_csr_before_init_is_enoent)
{
	uint8_t der[2048];
	size_t der_len = sizeof(der);

	/* test_before() wiped /session/, so no identity exists yet. */
	zassert_equal(session_slot_get_csr(der, &der_len), -ENOENT,
		      "CSR before first-boot init must be -ENOENT");
}

ZTEST(session_slot, test_11_csr_parses_and_matches_cert_identity)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t cert_der[2048], csr_der[2048];
	size_t cert_len = sizeof(cert_der), csr_len = sizeof(csr_der);

	zassert_ok(session_slot_get_cert(cert_der, &cert_len), "get_cert");
	zassert_ok(session_slot_get_csr(csr_der, &csr_len), "get_csr");
	zassert_true(csr_len > 0 && csr_len <= sizeof(csr_der), "csr len sane");
	zassert_equal(file_exists(SESSION_CSR), 1, "csr.der persisted");

	certparse_cert_t crt;
	certgen_dn_t csr_dn;
	uint8_t csr_pub[65];

	zassert_ok(certparse_cert(cert_der, cert_len, &crt), "parse cert");
	zassert_ok(certparse_csr(csr_der, csr_len, &csr_dn, csr_pub), "parse csr");

	/* Subject CN must match the session cert. */
	zassert_str_equal(crt.subject.cn, csr_dn.cn,
			  "CSR subject CN matches session cert subject CN");

	/* SubjectPublicKeyInfo (P-256 identity key) must be identical. */
	zassert_true(crt.has_pubkey && memcmp(crt.pubkey, csr_pub, 65) == 0,
		     "CSR public key == session cert public key");
}

ZTEST(session_slot, test_12_csr_carries_x25519_extension)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t csr_der[2048];
	size_t csr_len = sizeof(csr_der);

	zassert_ok(session_slot_get_csr(csr_der, &csr_len), "get_csr");

	/* The X25519 key rides in an extensionRequest attribute. Locate the OID
	 * and its OCTET STRING { 32 bytes } payload in the raw CSR DER. */
	const uint8_t *oid = find_bytes(csr_der, csr_len, OID_X25519, sizeof(OID_X25519));
	zassert_not_null(oid, "X25519 OID present in CSR");

	const uint8_t os_hdr[] = {0x04, 0x20};
	const uint8_t *after = oid + sizeof(OID_X25519);
	const uint8_t *os =
		find_bytes(after, (size_t)(csr_der + csr_len - after), os_hdr, sizeof(os_hdr));
	zassert_not_null(os, "X25519 OCTET STRING payload present");
	zassert_true(os + 2 + 32 <= csr_der + csr_len, "32-byte payload fits");

	uint8_t meta_pub[32];

	zassert_ok(session_slot_get_pubkey(meta_pub), "get_pubkey");
	zassert_mem_equal(os + 2, meta_pub, 32, "CSR extension X25519 key == cached Noise pubkey");
}

/* ── T-06: SIGN_SESSION_FROM_SLOT ──────────────────────────────────────────
 *
 * session_slot_sign_from_slot() re-signs /session/cert.der with an on-device
 * CA slot. The leaf's subject identity (DN, P-256 SPKI, X25519 extension) is
 * preserved; only the issuer DN + signature change.
 */

ZTEST(session_slot, test_13_sign_from_slot0_self_to_casigned)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();

	/* Capture the self-signed subject identity before re-signing. */
	uint8_t pre[2048];
	size_t pre_len = sizeof(pre);

	zassert_ok(session_slot_get_cert(pre, &pre_len), "get_cert pre");

	certparse_cert_t pre_crt;

	zassert_ok(certparse_cert(pre, pre_len, &pre_crt), "parse pre");

	char pre_subj[65];

	strncpy(pre_subj, pre_crt.subject.cn, sizeof(pre_subj) - 1);
	pre_subj[sizeof(pre_subj) - 1] = '\0';

	uint8_t pre_ext[32];

	zassert_ok(cert_x25519(pre, pre_len, pre_ext), "pre X25519 ext");

	/* Self-signed → CA-signed: allowed without force. */
	zassert_ok(session_slot_sign_from_slot(0, false), "sign from slot 0");

	uint8_t post[2048];
	size_t post_len = sizeof(post);

	zassert_ok(session_slot_get_cert(post, &post_len), "get_cert post");

	certparse_cert_t post_crt;

	zassert_ok(certparse_cert(post, post_len, &post_crt), "parse post");

	/* Subject CN preserved; the cert is no longer self-signed (issuer is the
	 * CA). The issuer identity itself is proven by the chain verification
	 * below, not by an issuer DN string. */
	zassert_str_equal(pre_subj, post_crt.subject.cn, "subject CN preserved across CA-sign");
	zassert_false(post_crt.self_signed, "CA-signed cert: issuer must differ from subject");

	/* Subject P-256 SPKI preserved. */
	zassert_true(same_pubkey_cert(pre, pre_len, post, post_len),
		     "subject SPKI preserved across CA-sign");

	/* X25519 binding extension preserved. */
	uint8_t post_ext[32];

	zassert_ok(cert_x25519(post, post_len, post_ext), "post X25519 ext");
	zassert_mem_equal(pre_ext, post_ext, 32, "X25519 binding preserved");

	/* Signature verifies under the CA slot's cert. */
	uint8_t ca_der[2048];
	size_t ca_len = sizeof(ca_der);

	zassert_ok(ca_get_cert(ca_der, &ca_len), "get CA cert");
	zassert_ok(verify_under(post, post_len, ca_der, ca_len),
		   "session cert signature verifies under the CA cert");
}

ZTEST(session_slot, test_14_resign_requires_force)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();

	zassert_ok(session_slot_sign_from_slot(0, false), "first CA-sign");

	/* Already CA-signed: a second sign without force is refused. */
	zassert_equal(session_slot_sign_from_slot(0, false), -EEXIST,
		      "re-sign without force must be -EEXIST");

	/* With force it succeeds (and re-issues a fresh cert). */
	zassert_ok(session_slot_sign_from_slot(0, true), "re-sign with force must succeed");
}

ZTEST(session_slot, test_15_casigned_still_matches_constant)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();
	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	/* T-03 comparison ignores issuer/signature, so a CA-signed cert must
	 * still match the build constant — no false recovery on next boot. */
	int m = ca_session_cert_matches_constant(der, der_len, cantil_session_x509_constant,
						 cantil_session_x509_constant_len);

	zassert_equal(m, 1, "CA-signed cert must still match build constant (got %d)", m);
}

ZTEST(session_slot, test_16_bad_issuer_slot_rejected)
{
	zassert_ok(session_slot_init(), "init");

	/* Empty slot (no key): -ENOENT. Slot 0 was wiped by test_before and not
	 * provisioned in this test. */
	zassert_equal(session_slot_sign_from_slot(0, false), -ENOENT,
		      "unprovisioned issuer slot must be -ENOENT");

	/* Out-of-range slot: -EINVAL. */
	zassert_equal(session_slot_sign_from_slot(CONFIG_CANTIL_MAX_KEY_SLOTS, false), -EINVAL,
		      "out-of-range issuer slot must be -EINVAL");
}

/* ── T-07: PUSH_SESSION_CERT ───────────────────────────────────────────────
 *
 * session_slot_push_cert() installs an externally-signed leaf (+ issuer chain)
 * after validating SPKI == device identity key, the X25519 binding, the
 * subject-vs-constant identity, and — for a CA-signed leaf — the chain links.
 *
 * The tests build a genuinely CA-signed leaf for THIS device's identity key by
 * round-tripping through session_slot_sign_from_slot(0) (which signs the stored
 * cert with CA slot 0), capturing the result as the "external" cert to push.
 */

ZTEST(session_slot, test_17_push_self_signed_roundtrip)
{
	zassert_ok(session_slot_init(), "init");

	/* The device's own self-signed cert is a valid push for its identity. */
	uint8_t leaf[2048];
	size_t leaf_len = sizeof(leaf);

	zassert_ok(session_slot_get_cert(leaf, &leaf_len), "get self-signed cert");

	/* Self-signed leaf needs no chain and must not latch the CA-signed flag. */
	zassert_ok(session_slot_push_cert(leaf, leaf_len, NULL, 0, false),
		   "push self-signed (no chain) must succeed");

	uint8_t post[2048];
	size_t post_len = sizeof(post);

	zassert_ok(session_slot_get_cert(post, &post_len), "get_cert post");
	zassert_equal(post_len, leaf_len, "stored cert length unchanged");
	zassert_mem_equal(post, leaf, leaf_len, "stored cert == pushed cert");

	/* No chain file should exist after a chainless push. */
	zassert_equal(storage_session_chain_exists(), 0, "no chain after push");
}

ZTEST(session_slot, test_18_push_casigned_chain_and_force_matrix)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();

	/* Capture the self-signed leaf, then produce a CA-signed leaf + its
	 * issuer (the CA cert) for the SAME device identity key. */
	uint8_t self_leaf[2048];
	size_t self_len = sizeof(self_leaf);

	zassert_ok(session_slot_get_cert(self_leaf, &self_len), "self leaf");

	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t ca_leaf[2048];
	size_t ca_leaf_len = sizeof(ca_leaf);

	zassert_ok(session_slot_get_cert(ca_leaf, &ca_leaf_len), "ca leaf");

	uint8_t ca_cert[2048];
	size_t ca_cert_len = sizeof(ca_cert);

	zassert_ok(ca_get_cert(ca_cert, &ca_cert_len), "CA cert (chain)");

	/* Stored cert is now CA-signed: overwriting it requires force. A
	 * self-signed push without force is refused. */
	zassert_equal(session_slot_push_cert(self_leaf, self_len, NULL, 0, false), -EEXIST,
		      "overwrite CA-signed without force must be -EEXIST");

	/* With force, revert to self-signed (clears the CA-signed flag). */
	zassert_ok(session_slot_push_cert(self_leaf, self_len, NULL, 0, true),
		   "force revert to self-signed must succeed");

	/* Now self-signed → CA-signed is allowed WITHOUT force; the chain link
	 * (leaf signed by the CA cert) is verified. */
	zassert_ok(session_slot_push_cert(ca_leaf, ca_leaf_len, ca_cert, ca_cert_len, false),
		   "push CA-signed leaf + valid chain must succeed");

	uint8_t post[2048];
	size_t post_len = sizeof(post);

	zassert_ok(session_slot_get_cert(post, &post_len), "get_cert post");
	zassert_equal(post_len, ca_leaf_len, "stored == pushed CA-signed leaf");
	zassert_mem_equal(post, ca_leaf, ca_leaf_len, "stored bytes match");
	zassert_equal(storage_session_chain_exists(), 1, "chain persisted");

	/* The CA-signed cert must still match the build constant (no recovery
	 * drift on next boot — issuer/signature are ignored by T-03). */
	zassert_equal(ca_session_cert_matches_constant(post, post_len, cantil_session_x509_constant,
						       cantil_session_x509_constant_len),
		      1, "pushed CA-signed cert still matches constant");
}

ZTEST(session_slot, test_19_push_foreign_cert_rejected)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();

	/* The CA cert binds the CA key (not the device identity key) and carries
	 * the CA's subject DN — it fails both the SPKI and constant gates. */
	uint8_t ca_cert[2048];
	size_t ca_cert_len = sizeof(ca_cert);

	zassert_ok(ca_get_cert(ca_cert, &ca_cert_len), "CA cert");

	zassert_equal(session_slot_push_cert(ca_cert, ca_cert_len, NULL, 0, false), -EINVAL,
		      "foreign cert (wrong key/subject) must be -EINVAL");
}

ZTEST(session_slot, test_20_push_casigned_without_chain_rejected)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();
	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t ca_leaf[2048];
	size_t ca_leaf_len = sizeof(ca_leaf);

	zassert_ok(session_slot_get_cert(ca_leaf, &ca_leaf_len), "ca leaf");

	/* A CA-signed leaf with no chain cannot have its link verified. force is
	 * set only to clear the re-sign rule; the chain gate is what rejects. */
	zassert_equal(session_slot_push_cert(ca_leaf, ca_leaf_len, NULL, 0, true), -EINVAL,
		      "CA-signed push without chain must be -EINVAL");
}

ZTEST(session_slot, test_21_push_broken_chain_rejected)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();

	uint8_t self_leaf[2048];
	size_t self_len = sizeof(self_leaf);

	zassert_ok(session_slot_get_cert(self_leaf, &self_len), "self leaf");

	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t ca_leaf[2048];
	size_t ca_leaf_len = sizeof(ca_leaf);

	zassert_ok(session_slot_get_cert(ca_leaf, &ca_leaf_len), "ca leaf");

	/* Wrong chain: the self-signed device cert did NOT sign the CA-signed
	 * leaf, so the chain link does not verify. */
	zassert_equal(session_slot_push_cert(ca_leaf, ca_leaf_len, self_leaf, self_len, true),
		      -EINVAL, "leaf with non-issuer chain must be -EINVAL");
}

/*
 * T-08 validity relaxation: ca_session_cert_matches_constant() must accept a
 * CA-signed cert even when the build constant's validity_days differs from the
 * cert's not_after (external CAs set their own validity window).  A self-signed
 * cert with the same validity drift must still be rejected.
 */
ZTEST(session_slot, test_22_casigned_validity_relaxed)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();

	/* Capture the self-signed leaf before CA-signing. */
	uint8_t self_leaf[2048];
	size_t self_len = sizeof(self_leaf);

	zassert_ok(session_slot_get_cert(self_leaf, &self_len), "self leaf");

	/* CA-sign so we have a cert where issuer != subject. */
	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t ca_leaf[2048];
	size_t ca_leaf_len = sizeof(ca_leaf);

	zassert_ok(session_slot_get_cert(ca_leaf, &ca_leaf_len), "ca leaf");

	/* Build a modified build constant with a different validity_days.
	 * The packed blob starts with a BE u16 validity_days; bump it by 1. */
	uint8_t tweaked[256];

	zassert_true(cantil_session_x509_constant_len <= sizeof(tweaked),
		     "constant fits in local buffer");
	memcpy(tweaked, cantil_session_x509_constant, cantil_session_x509_constant_len);
	uint16_t orig_days = ((uint16_t)tweaked[0] << 8) | tweaked[1];
	uint16_t new_days = orig_days + 1;

	tweaked[0] = (uint8_t)(new_days >> 8);
	tweaked[1] = (uint8_t)(new_days & 0xFF);

	/* CA-signed cert with a drifted constant: validity relaxed → match. */
	zassert_equal(ca_session_cert_matches_constant(ca_leaf, ca_leaf_len, tweaked,
						       cantil_session_x509_constant_len),
		      1, "CA-signed cert must match despite validity drift");

	/* Self-signed cert with the same drifted constant: still strict → no match. */
	zassert_equal(ca_session_cert_matches_constant(self_leaf, self_len, tweaked,
						       cantil_session_x509_constant_len),
		      0, "self-signed cert must fail on validity drift");
}

/* ── T-09: refuse-as-issuer sweep ──────────────────────────────────────────
 *
 * The session slot lives at /session/ and has no numbered /keys/N/ ID. Any
 * issuer_slot value >= CONFIG_CANTIL_MAX_KEY_SLOTS must be refused by the ca
 * functions (the dispatcher adds an identical gate before reaching them).
 */

ZTEST(session_slot, test_23_sign_csr_slot_bad_issuer_rejected)
{
	/* A minimal but structurally valid DER blob isn't needed — the range
	 * check fires before any CSR parsing. Pass a non-null stub. */
	uint8_t stub[4] = {0x30, 0x02, 0x00, 0x00};
	uint8_t out[512];
	size_t out_len = sizeof(out);

	zassert_equal(
		ca_sign_csr_slot(CONFIG_CANTIL_MAX_KEY_SLOTS, stub, sizeof(stub), out, &out_len),
		-EINVAL, "issuer == MAX_KEY_SLOTS must be -EINVAL");
	zassert_equal(ca_sign_csr_slot(UINT32_MAX, stub, sizeof(stub), out, &out_len), -EINVAL,
		      "issuer == UINT32_MAX must be -EINVAL");
}

ZTEST(session_slot, test_24_sign_key_slot_bad_issuer_rejected)
{
	/* The range check on issuer fires before checking if slot 0 has a key. */
	zassert_equal(ca_sign_key_slot(CONFIG_CANTIL_MAX_KEY_SLOTS, 0), -EINVAL,
		      "issuer == MAX_KEY_SLOTS must be -EINVAL");
	zassert_equal(ca_sign_key_slot(UINT32_MAX, 0), -EINVAL,
		      "issuer == UINT32_MAX must be -EINVAL");
}

/* ── Ephemeral identity on an unverifiable volume ───────────────────────── */

ZTEST(session_slot, test_25_unverified_volume_mints_into_ram_only)
{
	/*
	 * test_before() leaves /session/ and slot 0 empty; removing the marker
	 * makes this UNMARKED-and-empty, which is the fingerprint of a
	 * misdeclared partition. Writing an identity there is not harmless: the
	 * hardware test recipe misdeclares 0x180000+0x80000 inside a real volume
	 * of 0x0+0x200000, so every block the wrong mount allocates lands inside
	 * the live filesystem.
	 */
	zassert_ok(fs_unlink(LFS_MOUNT "/volume.bin"), "remove the marker");
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_UNMARKED,
		      "volume must read as unmarked");

	zassert_ok(session_slot_init(), "session_slot_init on unverified volume");
	zassert_true(session_slot_is_ephemeral(), "identity must be ephemeral, not persisted");

	zassert_equal(file_exists(SESSION_KEY), 0, "key.bin must not be written");
	zassert_equal(file_exists(SESSION_IDKEY), 0, "id_key.bin must not be written");
	zassert_equal(file_exists(SESSION_META), 0, "meta.bin must not be written");
	zassert_equal(file_exists(SESSION_CERT), 0, "cert.der must not be written");

	/* Restore for whatever runs next. */
	zassert_ok(storage_volume_marker_write(), "re-mark the volume");
}

ZTEST(session_slot, test_26_ephemeral_identity_is_usable)
{
	/*
	 * An identity that exists but cannot be handed to the transport would
	 * leave the device unreachable, which defeats the point: DEVICE_STATUS
	 * and UPDATE_FIRMWARE are exactly what degraded mode keeps open.
	 */
	uint8_t cert[2048];
	size_t cert_len = sizeof(cert);
	uint8_t priv[32], pub[32], pub2[32];

	zassert_ok(fs_unlink(LFS_MOUNT "/volume.bin"), "remove the marker");
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_UNMARKED,
		      "state is cached at mount — re-verify after unlinking");
	zassert_ok(session_slot_init(), "session_slot_init");
	zassert_true(session_slot_is_ephemeral(), "must be ephemeral");

	/* The handshake needs all three: static key, its pubkey, and the cert
	 * that msg2 carries. */
	zassert_ok(session_slot_get_ephemeral_static(priv, pub), "static keypair");
	zassert_ok(session_slot_get_pubkey(pub2), "get_pubkey");
	zassert_mem_equal(pub, pub2, 32, "get_pubkey must match the static key");

	zassert_ok(session_slot_get_cert(cert, &cert_len), "get_cert");
	zassert_true(cert_len > 0 && cert_len < sizeof(cert), "plausible cert len");

	certparse_cert_t crt;

	zassert_ok(certparse_cert(cert, cert_len, &crt), "ephemeral cert parses");
	zassert_true(crt.self_signed, "ephemeral cert is self-signed");

	/* Hand the ephemeral cert to the OpenSSL gate as its own anchor so its
	 * self-signature is verified by a third implementation — the ephemeral
	 * path does not otherwise reach the gate. */
	test_artifact_leaf("session_ephemeral", cert, cert_len);
	test_artifact_ca("session_ephemeral", cert, cert_len);

	zassert_ok(storage_volume_marker_write(), "re-mark the volume");
}

ZTEST(session_slot, test_27_ephemeral_is_dropped_once_the_volume_verifies)
{
	/*
	 * An ephemeral identity outliving its justification would be worse than
	 * not having had one: the device would keep answering with a RAM key
	 * while a real stored identity sat unused.
	 */
	uint8_t eph_pub[32], stored_pub[32], priv[32];

	zassert_ok(fs_unlink(LFS_MOUNT "/volume.bin"), "remove the marker");
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_UNMARKED,
		      "state is cached at mount — re-verify after unlinking");
	zassert_ok(session_slot_init(), "ephemeral init");
	zassert_true(session_slot_is_ephemeral(), "must be ephemeral");
	zassert_ok(session_slot_get_ephemeral_static(priv, eph_pub), "static keypair");

	zassert_ok(storage_volume_marker_write(), "re-mark the volume");
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_VALID, "verified again");
	zassert_ok(session_slot_init(), "re-init on a verified volume");

	zassert_false(session_slot_is_ephemeral(),
		      "ephemeral identity must not survive a verified re-init");
	zassert_equal(file_exists(SESSION_KEY), 1, "key.bin now written");
	zassert_ok(session_slot_get_pubkey(stored_pub), "get_pubkey");
	zassert_true(memcmp(eph_pub, stored_pub, 32) != 0,
		     "the persisted identity must be a new key, not the RAM one");
}

/*
 * Hand the session slot's three generated artefacts to the OpenSSL gate.
 *
 * This suite is the highest-risk one to leave without an independent oracle.
 * The session certificate is the only thing Cantil emits that carries a
 * *custom* extension — the 1.3.6.1.4.1.58270.1.1 X25519 binding — and a
 * private OID is exactly where a writer and a reader from the same library
 * agree on something malformed and nobody notices. Every other check here
 * parses with mbedTLS, which stops being a second implementation the moment
 * mbedTLS leaves the tree.
 *
 * Three claims, each a different code path:
 *
 *   session_self   self-signed leaf, verified against itself — proves the
 *                  self-signature, which no other backend has ever checked
 *   session_csr    PKCS#10; the gate runs `req -verify`, which is what caught
 *                  the wolfCrypt version-2 CSR bug in step 4
 *   session_casigned  leaf signed by CA slot 0 — the extension survives
 *                  ca_build_session_cert()'s re-issue path
 */
ZTEST(session_slot, test_28_export_for_openssl_gate)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t self_leaf[2048];
	size_t self_len = sizeof(self_leaf);

	zassert_ok(session_slot_get_cert(self_leaf, &self_len), "self leaf");
	test_artifact_leaf("session_self", self_leaf, self_len);
	test_artifact_ca("session_self", self_leaf, self_len);

	uint8_t csr_der[2048];
	size_t csr_len = sizeof(csr_der);

	zassert_ok(session_slot_get_csr(csr_der, &csr_len), "get_csr");
	test_artifact_csr("session", csr_der, csr_len);

	bootstrap_slot0();
	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t ca_leaf[2048];
	size_t ca_leaf_len = sizeof(ca_leaf);

	zassert_ok(session_slot_get_cert(ca_leaf, &ca_leaf_len), "ca leaf");

	uint8_t ca_cert[2048];
	size_t ca_cert_len = sizeof(ca_cert);

	zassert_ok(storage_slot_cert_read(0, ca_cert, &ca_cert_len), "slot 0 cert");

	test_artifact_leaf("session_casigned", ca_leaf, ca_leaf_len);
	test_artifact_ca("session_casigned", ca_cert, ca_cert_len);
}
