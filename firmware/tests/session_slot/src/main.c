/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

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

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pk.h>

#include "session/session_slot.h"
#include "session/session_x509.h"
#include "ca/ca.h"
#include "crypto/crypto.h"
#include "storage/storage.h"

#define LFS_MOUNT     "/lfs"
#define SESSION_DIR   LFS_MOUNT "/session"
#define SESSION_KEY   SESSION_DIR "/key.bin"
#define SESSION_IDKEY SESSION_DIR "/id_key.bin"
#define SESSION_META  SESSION_DIR "/meta.bin"
#define SESSION_CERT  SESSION_DIR "/cert.der"
#define SESSION_CSR   SESSION_DIR "/csr.der"
#define NOISE_DIR     LFS_MOUNT "/noise"

/* 1.3.6.1.4.1.58270.1.1 — the session X25519-binding extension OID (DER). */
static const uint8_t OID_X25519[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xc7, 0x1e, 0x01, 0x01
};

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
 * Locate the X25519-binding extension in a parsed cert's raw v3 extensions and
 * copy its 32-byte payload into out. Returns 0 on success, -1 if not found /
 * malformed. The extension value is an OCTET STRING (0x04 0x20) wrapping the
 * raw pubkey, written by mbedtls_x509write_crt_set_extension(val, 32).
 */
static int extract_x25519_ext(const mbedtls_x509_crt *crt, uint8_t out[32])
{
	const uint8_t *ext = crt->v3_ext.p;
	size_t ext_len = crt->v3_ext.len;

	const uint8_t *oid = find_bytes(ext, ext_len, OID_X25519, sizeof(OID_X25519));

	if (oid == NULL) {
		return -1;
	}
	const uint8_t *after = oid + sizeof(OID_X25519);
	const uint8_t *end = ext + ext_len;

	/* The extension SEQUENCE is { OID, OCTET STRING { 32 raw bytes } }, so
	 * an OCTET STRING header (04 20) followed by 32 bytes appears after the
	 * OID. (No critical BOOLEAN — the binding is non-critical.) */
	const uint8_t os_hdr[] = {0x04, 0x20};
	const uint8_t *os = find_bytes(after, (size_t)(end - after),
				       os_hdr, sizeof(os_hdr));

	if (os == NULL || os + 2 + 32 > end) {
		return -1;
	}
	memcpy(out, os + 2, 32);
	return 0;
}

/* Verify a cert's TBS signature under an arbitrary issuer public key. */
static int verify_sig_under(mbedtls_x509_crt *leaf, mbedtls_pk_context *issuer_pk)
{
	uint8_t hash[32];
	const mbedtls_x509_buf *tbs = &leaf->tbs;
	const mbedtls_x509_buf *sig = &leaf->MBEDTLS_PRIVATE(sig);

	int rc = mbedtls_sha256(tbs->p, tbs->len, hash, 0);

	if (rc) {
		return rc;
	}
	return mbedtls_pk_verify(issuer_pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
				 sig->p, sig->len);
}

/* Build a packed x509 blob for a CA slot (is_ca=1, keyCertSign|cRLSign). */
static size_t build_ca_blob(uint8_t *out, size_t cap)
{
	size_t off = 0;
	const char *cn = "Cantil CA";
	const char *o  = "Cantil";

	zassert_true(cap >= 32, "blob buffer too small");
	out[off++] = 0x01; out[off++] = 0x68;   /* validity_days = 360 */
	out[off++] = 1;                         /* is_ca */
	out[off++] = 0;                         /* path_len = 0 */
	out[off++] = 0x00; out[off++] = 0x86;   /* KU = digitalSig|keyCertSign|cRLSign */
	out[off++] = (uint8_t)strlen(cn); memcpy(&out[off], cn, strlen(cn)); off += strlen(cn);
	out[off++] = (uint8_t)strlen(o);  memcpy(&out[off], o,  strlen(o));  off += strlen(o);
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
	size_t  len = build_ca_blob(blob, sizeof(blob));

	zassert_ok(ca_init(), "ca_init");
	zassert_ok(ca_push_key_x509(0, blob, len), "push_key_x509 slot 0");
	zassert_true(ca_ready(), "ca_ready after push");
}

/* Verify a self-signed cert's signature using its own embedded public key. */
static int verify_self_signature(mbedtls_x509_crt *crt)
{
	uint8_t hash[32];
	const mbedtls_x509_buf *tbs = &crt->tbs;
	const mbedtls_x509_buf *sig = &crt->MBEDTLS_PRIVATE(sig);

	int rc = mbedtls_sha256(tbs->p, tbs->len, hash, 0);

	if (rc) {
		return rc;
	}
	return mbedtls_pk_verify(&crt->pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
				 sig->p, sig->len);
}

/* True if two parsed public keys serialize to identical SubjectPublicKeyInfo. */
static int same_pubkey(mbedtls_pk_context *a, mbedtls_pk_context *b)
{
	uint8_t da[256], db[256];
	int la = mbedtls_pk_write_pubkey_der(a, da, sizeof(da));
	int lb = mbedtls_pk_write_pubkey_der(b, db, sizeof(db));

	if (la <= 0 || la != lb) {
		return 0;
	}
	/* write_pubkey_der writes at the END of each buffer. */
	return memcmp(da + sizeof(da) - la, db + sizeof(db) - lb, (size_t)la) == 0;
}

/* ── suite scaffolding ────────────────────────────────────────────────── */

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init failed");
	return NULL;
}

static void test_before(void *fixture)
{
	ARG_UNUSED(fixture);
	wipe_dir(SESSION_DIR);
	wipe_dir(NOISE_DIR);
	wipe_dir(LFS_MOUNT "/keys/0");   /* T-06 provisions a CA in slot 0 */
}

ZTEST_SUITE(session_slot, NULL, suite_setup, test_before, NULL, NULL);

/* ── tests ────────────────────────────────────────────────────────────── */

ZTEST(session_slot, test_01_first_boot_creates_identity)
{
	zassert_ok(session_slot_init(), "session_slot_init first boot");

	zassert_equal(file_exists(SESSION_KEY),   1, "key.bin should exist");
	zassert_equal(file_exists(SESSION_IDKEY), 1, "id_key.bin should exist");
	zassert_equal(file_exists(SESSION_META),  1, "meta.bin should exist");
	zassert_equal(file_exists(SESSION_CERT),  1, "cert.der should exist");
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

	mbedtls_x509_crt crt;

	mbedtls_x509_crt_init(&crt);
	zassert_ok(mbedtls_x509_crt_parse_der(&crt, der, der_len),
		   "cert parses as DER");

	/* Self-signed: issuer DN == subject DN. */
	char subj[256], iss[256];

	zassert_true(mbedtls_x509_dn_gets(subj, sizeof(subj),
			&crt.subject) > 0, "subject DN");
	zassert_true(mbedtls_x509_dn_gets(iss, sizeof(iss),
			&crt.issuer) > 0, "issuer DN");
	zassert_str_equal(subj, iss, "self-signed: issuer == subject");

	zassert_ok(verify_self_signature(&crt),
		   "TBS signature verifies under embedded SPKI");

	mbedtls_x509_crt_free(&crt);
}

ZTEST(session_slot, test_03_subject_ku_and_not_ca)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	mbedtls_x509_crt crt;

	mbedtls_x509_crt_init(&crt);
	zassert_ok(mbedtls_x509_crt_parse_der(&crt, der, der_len), "parse");

	char subj[256];

	mbedtls_x509_dn_gets(subj, sizeof(subj), &crt.subject);
	zassert_not_null(strstr(subj, "CN=Cantil"),
			 "subject CN should be FICR-derived (got '%s')", subj);

	/* KU: digitalSignature + keyAgreement allowed; keyCertSign denied. */
	zassert_ok(mbedtls_x509_crt_check_key_usage(&crt,
			MBEDTLS_X509_KU_DIGITAL_SIGNATURE),
		   "digitalSignature must be set");
	zassert_ok(mbedtls_x509_crt_check_key_usage(&crt,
			MBEDTLS_X509_KU_KEY_AGREEMENT),
		   "keyAgreement must be set");
	zassert_not_equal(mbedtls_x509_crt_check_key_usage(&crt,
			MBEDTLS_X509_KU_KEY_CERT_SIGN), 0,
		   "keyCertSign must NOT be set");

	/* Not a CA. */
	zassert_equal(crt.MBEDTLS_PRIVATE(ca_istrue), 0,
		      "session cert must not be a CA");

	mbedtls_x509_crt_free(&crt);
}

ZTEST(session_slot, test_04_x25519_extension_matches_pubkey)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	mbedtls_x509_crt crt;

	mbedtls_x509_crt_init(&crt);
	zassert_ok(mbedtls_x509_crt_parse_der(&crt, der, der_len), "parse");

	uint8_t ext_pub[32];

	zassert_ok(extract_x25519_ext(&crt, ext_pub),
		   "X25519 binding extension present");

	uint8_t meta_pub[32];

	zassert_ok(session_slot_get_pubkey(meta_pub), "get_pubkey from meta");
	zassert_mem_equal(ext_pub, meta_pub, 32,
			  "extension pubkey == cached meta pubkey");

	/* T-04 retired the /noise/ store: the session slot now owns the X25519
	 * key, so the cert's bound pubkey, the cached meta pubkey, and the slot
	 * accessor are the single source of truth. */

	mbedtls_x509_crt_free(&crt);
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

	off += 1 + cn_len;   /* skip cn_len + cn bytes */
	off += 1;            /* skip o_len byte → first O byte */
	return off;
}

ZTEST(session_slot, test_06_compare_matches_real_constant)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	int m = ca_session_cert_matches_constant(
			der, der_len,
			cantil_session_x509_constant,
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
	blob[blob_o_value_off(blob)] ^= 0x20;  /* perturb O */

	int m = ca_session_cert_matches_constant(
			der, der_len, blob, cantil_session_x509_constant_len);

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
	zassert_equal(ca_session_cert_matches_constant(
			der, der_len, blob, cantil_session_x509_constant_len), 0,
		      "altered key_usage must be a mismatch");

	/* validity_days lives at bytes 0..1 (BE). Bump it by one day. */
	memcpy(blob, cantil_session_x509_constant, cantil_session_x509_constant_len);
	blob[1] ^= 0x01;
	zassert_equal(ca_session_cert_matches_constant(
			der, der_len, blob, cantil_session_x509_constant_len), 0,
		      "altered validity must be a mismatch");
}

ZTEST(session_slot, test_09_nonstrict_mismatch_warns_continues)
{
	/* Plant a cert built from a constant whose O differs from the real one,
	 * so the boot-time verify path sees a mismatch. */
	uint8_t blob[256];

	memcpy(blob, cantil_session_x509_constant, cantil_session_x509_constant_len);
	blob[blob_o_value_off(blob)] ^= 0x20;

	uint8_t id_priv[64];
	size_t  id_len = sizeof(id_priv);

	zassert_ok(crypto_keygen(id_priv, &id_len), "P-256 keygen");
	zassert_equal(id_len, 32, "P-256 scalar is 32 bytes");

	uint8_t x25519_pub[32] = {0};
	uint8_t cert[2048];
	size_t  cert_len = sizeof(cert);

	zassert_ok(ca_build_session_cert(blob, cantil_session_x509_constant_len,
					 "Cantil", id_priv, x25519_pub,
					 cert, &cert_len),
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
	size_t  der_len = sizeof(der);

	/* test_before() wiped /session/, so no identity exists yet. */
	zassert_equal(session_slot_get_csr(der, &der_len), -ENOENT,
		      "CSR before first-boot init must be -ENOENT");
}

ZTEST(session_slot, test_11_csr_parses_and_matches_cert_identity)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t cert_der[2048], csr_der[2048];
	size_t  cert_len = sizeof(cert_der), csr_len = sizeof(csr_der);

	zassert_ok(session_slot_get_cert(cert_der, &cert_len), "get_cert");
	zassert_ok(session_slot_get_csr(csr_der, &csr_len), "get_csr");
	zassert_true(csr_len > 0 && csr_len <= sizeof(csr_der), "csr len sane");
	zassert_equal(file_exists(SESSION_CSR), 1, "csr.der persisted");

	mbedtls_x509_crt crt;
	mbedtls_x509_csr csr;

	mbedtls_x509_crt_init(&crt);
	mbedtls_x509_csr_init(&csr);
	zassert_ok(mbedtls_x509_crt_parse_der(&crt, cert_der, cert_len), "parse cert");
	zassert_ok(mbedtls_x509_csr_parse_der(&csr, csr_der, csr_len), "parse csr");

	/* Subject DN must match the session cert byte-for-byte (textual form). */
	char cert_subj[256], csr_subj[256];

	zassert_true(mbedtls_x509_dn_gets(cert_subj, sizeof(cert_subj),
			&crt.subject) > 0, "cert subject");
	zassert_true(mbedtls_x509_dn_gets(csr_subj, sizeof(csr_subj),
			&csr.subject) > 0, "csr subject");
	zassert_str_equal(cert_subj, csr_subj,
			  "CSR subject DN matches session cert subject DN");

	/* SubjectPublicKeyInfo (P-256 identity key) must be identical. */
	zassert_true(same_pubkey(&csr.pk, &crt.pk),
		     "CSR public key == session cert public key");

	mbedtls_x509_csr_free(&csr);
	mbedtls_x509_crt_free(&crt);
}

ZTEST(session_slot, test_12_csr_carries_x25519_extension)
{
	zassert_ok(session_slot_init(), "init");

	uint8_t csr_der[2048];
	size_t  csr_len = sizeof(csr_der);

	zassert_ok(session_slot_get_csr(csr_der, &csr_len), "get_csr");

	/* The X25519 key rides in an extensionRequest attribute. Locate the OID
	 * and its OCTET STRING { 32 bytes } payload in the raw CSR DER. */
	const uint8_t *oid = find_bytes(csr_der, csr_len,
					OID_X25519, sizeof(OID_X25519));
	zassert_not_null(oid, "X25519 OID present in CSR");

	const uint8_t os_hdr[] = {0x04, 0x20};
	const uint8_t *after = oid + sizeof(OID_X25519);
	const uint8_t *os = find_bytes(after, (size_t)(csr_der + csr_len - after),
				       os_hdr, sizeof(os_hdr));
	zassert_not_null(os, "X25519 OCTET STRING payload present");
	zassert_true(os + 2 + 32 <= csr_der + csr_len, "32-byte payload fits");

	uint8_t meta_pub[32];

	zassert_ok(session_slot_get_pubkey(meta_pub), "get_pubkey");
	zassert_mem_equal(os + 2, meta_pub, 32,
			  "CSR extension X25519 key == cached Noise pubkey");
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
	size_t  pre_len = sizeof(pre);

	zassert_ok(session_slot_get_cert(pre, &pre_len), "get_cert pre");

	mbedtls_x509_crt pre_crt;

	mbedtls_x509_crt_init(&pre_crt);
	zassert_ok(mbedtls_x509_crt_parse_der(&pre_crt, pre, pre_len), "parse pre");

	char pre_subj[256];

	zassert_true(mbedtls_x509_dn_gets(pre_subj, sizeof(pre_subj),
			&pre_crt.subject) > 0, "pre subject");

	uint8_t pre_ext[32];

	zassert_ok(extract_x25519_ext(&pre_crt, pre_ext), "pre X25519 ext");

	/* Self-signed → CA-signed: allowed without force. */
	zassert_ok(session_slot_sign_from_slot(0, false), "sign from slot 0");

	uint8_t post[2048];
	size_t  post_len = sizeof(post);

	zassert_ok(session_slot_get_cert(post, &post_len), "get_cert post");

	mbedtls_x509_crt post_crt;

	mbedtls_x509_crt_init(&post_crt);
	zassert_ok(mbedtls_x509_crt_parse_der(&post_crt, post, post_len), "parse post");

	/* Subject DN preserved; issuer now differs (the CA, "Cantil CA"). */
	char post_subj[256], post_iss[256];

	zassert_true(mbedtls_x509_dn_gets(post_subj, sizeof(post_subj),
			&post_crt.subject) > 0, "post subject");
	zassert_true(mbedtls_x509_dn_gets(post_iss, sizeof(post_iss),
			&post_crt.issuer) > 0, "post issuer");
	zassert_str_equal(pre_subj, post_subj, "subject DN preserved across CA-sign");
	zassert_true(strcmp(post_subj, post_iss) != 0,
		     "CA-signed cert: issuer must differ from subject");
	zassert_not_null(strstr(post_iss, "Cantil CA"),
			 "issuer DN should be the CA slot's DN (got '%s')", post_iss);

	/* Subject P-256 SPKI preserved. */
	zassert_true(same_pubkey(&pre_crt.pk, &post_crt.pk),
		     "subject SPKI preserved across CA-sign");

	/* X25519 binding extension preserved. */
	uint8_t post_ext[32];

	zassert_ok(extract_x25519_ext(&post_crt, post_ext), "post X25519 ext");
	zassert_mem_equal(pre_ext, post_ext, 32, "X25519 binding preserved");

	/* Signature verifies under the CA slot's cert public key. */
	uint8_t ca_der[2048];
	size_t  ca_len = sizeof(ca_der);

	zassert_ok(ca_get_cert(ca_der, &ca_len), "get CA cert");

	mbedtls_x509_crt ca_crt;

	mbedtls_x509_crt_init(&ca_crt);
	zassert_ok(mbedtls_x509_crt_parse_der(&ca_crt, ca_der, ca_len), "parse CA");
	zassert_ok(verify_sig_under(&post_crt, &ca_crt.pk),
		   "session cert signature verifies under CA pubkey");

	mbedtls_x509_crt_free(&ca_crt);
	mbedtls_x509_crt_free(&post_crt);
	mbedtls_x509_crt_free(&pre_crt);
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
	zassert_ok(session_slot_sign_from_slot(0, true),
		   "re-sign with force must succeed");
}

ZTEST(session_slot, test_15_casigned_still_matches_constant)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();
	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t der[2048];
	size_t  der_len = sizeof(der);

	zassert_ok(session_slot_get_cert(der, &der_len), "get_cert");

	/* T-03 comparison ignores issuer/signature, so a CA-signed cert must
	 * still match the build constant — no false recovery on next boot. */
	int m = ca_session_cert_matches_constant(
			der, der_len,
			cantil_session_x509_constant,
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
	zassert_equal(session_slot_sign_from_slot(CONFIG_CANTIL_MAX_KEY_SLOTS,
						  false),
		      -EINVAL, "out-of-range issuer slot must be -EINVAL");
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
	size_t  leaf_len = sizeof(leaf);

	zassert_ok(session_slot_get_cert(leaf, &leaf_len), "get self-signed cert");

	/* Self-signed leaf needs no chain and must not latch the CA-signed flag. */
	zassert_ok(session_slot_push_cert(leaf, leaf_len, NULL, 0, false),
		   "push self-signed (no chain) must succeed");

	uint8_t post[2048];
	size_t  post_len = sizeof(post);

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
	size_t  self_len = sizeof(self_leaf);

	zassert_ok(session_slot_get_cert(self_leaf, &self_len), "self leaf");

	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t ca_leaf[2048];
	size_t  ca_leaf_len = sizeof(ca_leaf);

	zassert_ok(session_slot_get_cert(ca_leaf, &ca_leaf_len), "ca leaf");

	uint8_t ca_cert[2048];
	size_t  ca_cert_len = sizeof(ca_cert);

	zassert_ok(ca_get_cert(ca_cert, &ca_cert_len), "CA cert (chain)");

	/* Stored cert is now CA-signed: overwriting it requires force. A
	 * self-signed push without force is refused. */
	zassert_equal(session_slot_push_cert(self_leaf, self_len, NULL, 0, false),
		      -EEXIST, "overwrite CA-signed without force must be -EEXIST");

	/* With force, revert to self-signed (clears the CA-signed flag). */
	zassert_ok(session_slot_push_cert(self_leaf, self_len, NULL, 0, true),
		   "force revert to self-signed must succeed");

	/* Now self-signed → CA-signed is allowed WITHOUT force; the chain link
	 * (leaf signed by the CA cert) is verified. */
	zassert_ok(session_slot_push_cert(ca_leaf, ca_leaf_len,
					  ca_cert, ca_cert_len, false),
		   "push CA-signed leaf + valid chain must succeed");

	uint8_t post[2048];
	size_t  post_len = sizeof(post);

	zassert_ok(session_slot_get_cert(post, &post_len), "get_cert post");
	zassert_equal(post_len, ca_leaf_len, "stored == pushed CA-signed leaf");
	zassert_mem_equal(post, ca_leaf, ca_leaf_len, "stored bytes match");
	zassert_equal(storage_session_chain_exists(), 1, "chain persisted");

	/* The CA-signed cert must still match the build constant (no recovery
	 * drift on next boot — issuer/signature are ignored by T-03). */
	zassert_equal(ca_session_cert_matches_constant(
			      post, post_len, cantil_session_x509_constant,
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
	size_t  ca_cert_len = sizeof(ca_cert);

	zassert_ok(ca_get_cert(ca_cert, &ca_cert_len), "CA cert");

	zassert_equal(session_slot_push_cert(ca_cert, ca_cert_len, NULL, 0, false),
		      -EINVAL, "foreign cert (wrong key/subject) must be -EINVAL");
}

ZTEST(session_slot, test_20_push_casigned_without_chain_rejected)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();
	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t ca_leaf[2048];
	size_t  ca_leaf_len = sizeof(ca_leaf);

	zassert_ok(session_slot_get_cert(ca_leaf, &ca_leaf_len), "ca leaf");

	/* A CA-signed leaf with no chain cannot have its link verified. force is
	 * set only to clear the re-sign rule; the chain gate is what rejects. */
	zassert_equal(session_slot_push_cert(ca_leaf, ca_leaf_len, NULL, 0, true),
		      -EINVAL, "CA-signed push without chain must be -EINVAL");
}

ZTEST(session_slot, test_21_push_broken_chain_rejected)
{
	zassert_ok(session_slot_init(), "init");
	bootstrap_slot0();

	uint8_t self_leaf[2048];
	size_t  self_len = sizeof(self_leaf);

	zassert_ok(session_slot_get_cert(self_leaf, &self_len), "self leaf");

	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t ca_leaf[2048];
	size_t  ca_leaf_len = sizeof(ca_leaf);

	zassert_ok(session_slot_get_cert(ca_leaf, &ca_leaf_len), "ca leaf");

	/* Wrong chain: the self-signed device cert did NOT sign the CA-signed
	 * leaf, so the chain link does not verify. */
	zassert_equal(session_slot_push_cert(ca_leaf, ca_leaf_len,
					     self_leaf, self_len, true),
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
	size_t  self_len = sizeof(self_leaf);

	zassert_ok(session_slot_get_cert(self_leaf, &self_len), "self leaf");

	/* CA-sign so we have a cert where issuer != subject. */
	zassert_ok(session_slot_sign_from_slot(0, false), "CA-sign");

	uint8_t ca_leaf[2048];
	size_t  ca_leaf_len = sizeof(ca_leaf);

	zassert_ok(session_slot_get_cert(ca_leaf, &ca_leaf_len), "ca leaf");

	/* Build a modified build constant with a different validity_days.
	 * The packed blob starts with a BE u16 validity_days; bump it by 1. */
	uint8_t tweaked[256];

	zassert_true(cantil_session_x509_constant_len <= sizeof(tweaked),
		     "constant fits in local buffer");
	memcpy(tweaked, cantil_session_x509_constant, cantil_session_x509_constant_len);
	uint16_t orig_days = ((uint16_t)tweaked[0] << 8) | tweaked[1];
	uint16_t new_days  = orig_days + 1;

	tweaked[0] = (uint8_t)(new_days >> 8);
	tweaked[1] = (uint8_t)(new_days & 0xFF);

	/* CA-signed cert with a drifted constant: validity relaxed → match. */
	zassert_equal(ca_session_cert_matches_constant(
			      ca_leaf, ca_leaf_len,
			      tweaked, cantil_session_x509_constant_len),
		      1, "CA-signed cert must match despite validity drift");

	/* Self-signed cert with the same drifted constant: still strict → no match. */
	zassert_equal(ca_session_cert_matches_constant(
			      self_leaf, self_len,
			      tweaked, cantil_session_x509_constant_len),
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
	uint8_t stub[4] = { 0x30, 0x02, 0x00, 0x00 };
	uint8_t out[512];
	size_t  out_len = sizeof(out);

	zassert_equal(ca_sign_csr_slot(CONFIG_CANTIL_MAX_KEY_SLOTS,
				       stub, sizeof(stub), out, &out_len),
		      -EINVAL,
		      "issuer == MAX_KEY_SLOTS must be -EINVAL");
	zassert_equal(ca_sign_csr_slot(UINT32_MAX,
				       stub, sizeof(stub), out, &out_len),
		      -EINVAL,
		      "issuer == UINT32_MAX must be -EINVAL");
}

ZTEST(session_slot, test_24_sign_key_slot_bad_issuer_rejected)
{
	/* The range check on issuer fires before checking if slot 0 has a key. */
	zassert_equal(ca_sign_key_slot(CONFIG_CANTIL_MAX_KEY_SLOTS, 0),
		      -EINVAL,
		      "issuer == MAX_KEY_SLOTS must be -EINVAL");
	zassert_equal(ca_sign_key_slot(UINT32_MAX, 0),
		      -EINVAL,
		      "issuer == UINT32_MAX must be -EINVAL");
}
