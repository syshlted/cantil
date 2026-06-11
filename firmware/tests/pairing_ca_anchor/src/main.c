/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Method 4 (PAIRING_CA_ANCHOR) pairing gate conformance on native_sim (T-19).
 *
 * Drives pairing.c + ca.c + storage.c against a simulated flash partition.
 * Suite setup provisions slot 0 as a CA (the trust anchor) and generates a
 * test client cert signed by it.  Per-test setup resets the session stub.
 *
 * Coverage:
 *   1. Valid client cert (signed by slot 0) → 0 (session allowed, no bond).
 *   2. No client cert in msg3 (cert_count == 0) → -EACCES.
 *   3. Client cert self-signed (not by slot 0) → -EACCES.
 *   4. Slot 0 anchor not provisioned (cert.der deleted) → -EACCES.
 *   5. Corrupted cert DER (random bytes) → -EACCES.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/fs/fs.h>
#include <string.h>
#include <errno.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>

#include "ca/ca.h"
#include "crypto/crypto.h"
#include "storage/storage.h"
#include "clients/pairing.h"
#include "session/session.h"

/* Declared in session_stub.c */
cantil_session_t *ca_anchor_test_session(void);
void ca_anchor_test_set_client_certs(const uint8_t *const ders[],
				     const size_t lens[], size_t count);
void ca_anchor_test_clear_client_certs(void);

/* ── TRNG callback for mbedtls ──────────────────────────────────────────── */

static int trng_rng_cb(void *ctx, unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);
	return crypto_trng(buf, len) ? -1 : 0;
}

/* ── Test-owned cert DER buffers (populated once in suite_setup) ─────────── */

static uint8_t g_anchor_cert_der[1024];  /* slot 0 CA cert — trust anchor */
static size_t  g_anchor_cert_len;

static uint8_t g_valid_cert_der[1024];   /* client cert signed by slot 0 */
static size_t  g_valid_cert_len;

static uint8_t g_self_signed_cert_der[1024];  /* cert with unknown CA */
static size_t  g_self_signed_cert_len;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void wipe_dir(const char *path)
{
	struct fs_dir_t dir;
	struct fs_dirent ent;
	char child[128];

	fs_dir_t_init(&dir);
	if (fs_opendir(&dir, path) != 0) return;
	while (fs_readdir(&dir, &ent) == 0 && ent.name[0] != '\0') {
		snprintf(child, sizeof(child), "%s/%s", path, ent.name);
		if (ent.type == FS_DIR_ENTRY_DIR) wipe_dir(child);
		fs_unlink(child);
	}
	fs_closedir(&dir);
	fs_unlink(path);
}

static size_t build_ca_x509_blob(uint8_t *out, size_t cap)
{
	size_t off = 0;
	const char *cn = "Cantil Test CA";
	const char *o  = "Cantil";

	zassert_true(cap >= 64, "blob buffer too small");
	out[off++] = 0x01; out[off++] = 0x68;  /* validity_days = 360 */
	out[off++] = 1;                         /* is_ca */
	out[off++] = 0;                         /* path_len = 0 */
	out[off++] = 0x00; out[off++] = 0x86;  /* KU: digSig|keyCertSign|cRLSign */

	out[off++] = (uint8_t)strlen(cn);
	memcpy(&out[off], cn, strlen(cn)); off += strlen(cn);
	out[off++] = (uint8_t)strlen(o);
	memcpy(&out[off], o,  strlen(o));  off += strlen(o);
	out[off++] = 0; /* ou */
	out[off++] = 0; /* c  */
	out[off++] = 0; /* st */
	out[off++] = 0; /* l  */
	return off;
}

static int build_client_csr(uint8_t *csr_der, size_t *csr_len)
{
	mbedtls_pk_context pk;
	mbedtls_x509write_csr csr;

	mbedtls_pk_init(&pk);
	mbedtls_x509write_csr_init(&csr);

	int rc = mbedtls_pk_setup(&pk,
				  mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (rc) goto out;

	rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk),
				  trng_rng_cb, NULL);
	if (rc) goto out;

	mbedtls_x509write_csr_set_key(&csr, &pk);
	rc = mbedtls_x509write_csr_set_subject_name(&csr, "CN=TestClient");
	if (rc) goto out;
	mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);

	int n = mbedtls_x509write_csr_der(&csr, csr_der, *csr_len,
					  trng_rng_cb, NULL);
	if (n <= 0) { rc = (n ? n : -1); goto out; }
	memmove(csr_der, csr_der + (*csr_len - (size_t)n), (size_t)n);
	*csr_len = (size_t)n;

out:
	mbedtls_x509write_csr_free(&csr);
	mbedtls_pk_free(&pk);
	return rc;
}

static int build_self_signed_cert(uint8_t *cert_der, size_t *cert_len)
{
	mbedtls_pk_context      pk;
	mbedtls_x509write_cert  wc;
	mbedtls_mpi             serial;

	mbedtls_pk_init(&pk);
	mbedtls_x509write_crt_init(&wc);
	mbedtls_mpi_init(&serial);

	int rc = mbedtls_pk_setup(&pk,
				  mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (rc) goto out;

	rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk),
				  trng_rng_cb, NULL);
	if (rc) goto out;

	mbedtls_x509write_crt_set_subject_key(&wc, &pk);
	mbedtls_x509write_crt_set_issuer_key(&wc,  &pk);
	rc = mbedtls_x509write_crt_set_subject_name(&wc, "CN=Unknown");
	if (rc) goto out;
	rc = mbedtls_x509write_crt_set_issuer_name(&wc,  "CN=Unknown");
	if (rc) goto out;

	mbedtls_mpi_lset(&serial, 1);
	rc = mbedtls_x509write_crt_set_serial(&wc, &serial);
	if (rc) goto out;

	rc = mbedtls_x509write_crt_set_validity(&wc,
						 "20260101000000",
						 "20360101000000");
	if (rc) goto out;

	mbedtls_x509write_crt_set_md_alg(&wc, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_version(&wc, MBEDTLS_X509_CRT_VERSION_3);

	int n = mbedtls_x509write_crt_der(&wc, cert_der, *cert_len,
					   trng_rng_cb, NULL);
	if (n <= 0) { rc = (n ? n : -1); goto out; }
	memmove(cert_der, cert_der + (*cert_len - (size_t)n), (size_t)n);
	*cert_len = (size_t)n;

out:
	mbedtls_mpi_free(&serial);
	mbedtls_x509write_crt_free(&wc);
	mbedtls_pk_free(&pk);
	return rc;
}

/* ── Suite setup ─────────────────────────────────────────────────────────── */

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init failed");

	/* Provision slot 0 as trust anchor CA. */
	wipe_dir("/lfs/keys/0");
	zassert_ok(ca_provision(), "ca_provision failed");

	uint8_t blob[64];
	size_t  blob_len = build_ca_x509_blob(blob, sizeof(blob));

	zassert_ok(ca_push_key_x509(0, blob, blob_len),
		   "ca_push_key_x509 failed");
	zassert_true(ca_ready(), "slot 0 not ready after push");

	/* Save the anchor cert for test 4's restore path. */
	g_anchor_cert_len = sizeof(g_anchor_cert_der);
	zassert_ok(storage_slot_cert_read(0, g_anchor_cert_der, &g_anchor_cert_len),
		   "could not read slot 0 cert after push");

	/* Sign a test client CSR with slot 0 → g_valid_cert_der. */
	uint8_t csr_buf[512];
	size_t  csr_len = sizeof(csr_buf);

	zassert_ok(build_client_csr(csr_buf, &csr_len),
		   "client CSR build failed");

	g_valid_cert_len = sizeof(g_valid_cert_der);
	zassert_ok(ca_sign_csr_slot(0, csr_buf, csr_len,
				    g_valid_cert_der, &g_valid_cert_len),
		   "CA sign CSR failed");

	/* Build a self-signed cert not anchored in slot 0 → g_self_signed_cert_der. */
	g_self_signed_cert_len = sizeof(g_self_signed_cert_der);
	zassert_ok(build_self_signed_cert(g_self_signed_cert_der,
					  &g_self_signed_cert_len),
		   "self-signed cert build failed");

	return NULL;
}

static void before(void *unused)
{
	ARG_UNUSED(unused);
	ca_anchor_test_clear_client_certs();
}

ZTEST_SUITE(pairing_ca_anchor, NULL, suite_setup, before, NULL, NULL);

static const uint8_t PUB_A[32] = { 0xAA, 0x01, 0x02, 0x03 };

/* ── Test 1: valid cert (signed by slot 0) → allowed ────────────────────── */

ZTEST(pairing_ca_anchor, test_valid_cert_allowed)
{
	const uint8_t *ders[1] = { g_valid_cert_der };
	size_t         lens[1] = { g_valid_cert_len };

	ca_anchor_test_set_client_certs(ders, lens, 1);

	cantil_session_t *s = ca_anchor_test_session();

	zassert_ok(pairing_check_and_bond(PUB_A, s),
		   "Method 4: valid cert should be allowed");
}

/* ── Test 2: no cert chain → rejected ───────────────────────────────────── */

ZTEST(pairing_ca_anchor, test_no_cert_rejected)
{
	cantil_session_t *s = ca_anchor_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "Method 4: no cert should be rejected, got %d", rc);
}

/* ── Test 3: self-signed cert (not from slot 0) → rejected ──────────────── */

ZTEST(pairing_ca_anchor, test_wrong_ca_rejected)
{
	const uint8_t *ders[1] = { g_self_signed_cert_der };
	size_t         lens[1] = { g_self_signed_cert_len };

	ca_anchor_test_set_client_certs(ders, lens, 1);

	cantil_session_t *s = ca_anchor_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "Method 4: cert from wrong CA should be rejected, got %d", rc);
}

/* ── Test 4: slot 0 cert.der deleted (anchor missing) → rejected ─────────── */

ZTEST(pairing_ca_anchor, test_anchor_missing_rejected)
{
	/* Temporarily remove the anchor cert. */
	zassert_ok(fs_unlink("/lfs/keys/0/cert.der"),
		   "could not delete anchor cert for test");

	const uint8_t *ders[1] = { g_valid_cert_der };
	size_t         lens[1] = { g_valid_cert_len };

	ca_anchor_test_set_client_certs(ders, lens, 1);

	cantil_session_t *s = ca_anchor_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	/* Restore the anchor cert so test 5 can still use it. */
	zassert_ok(storage_slot_cert_write(0, g_anchor_cert_der, g_anchor_cert_len),
		   "restore of anchor cert failed — test 5 may fail");

	zassert_equal(rc, -EACCES,
		      "Method 4: missing anchor should reject, got %d", rc);
}

/* ── Test 5: corrupted cert DER → rejected ───────────────────────────────── */

ZTEST(pairing_ca_anchor, test_corrupted_cert_rejected)
{
	static const uint8_t junk[32] = {
		0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
		0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
		0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
		0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0,
	};
	const uint8_t *ders[1] = { junk };
	size_t         lens[1] = { sizeof(junk) };

	ca_anchor_test_set_client_certs(ders, lens, 1);

	cantil_session_t *s = ca_anchor_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "Method 4: corrupted cert should be rejected, got %d", rc);
}
