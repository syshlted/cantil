/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Method 5 (PAIRING_CA_ANCHOR_PLUS_PASSKEY) pairing gate conformance on
 * native_sim (T-20).
 *
 * Drives pairing.c + ca.c + storage.c against a simulated flash partition.
 * Suite setup provisions slot 0 as a CA (the trust anchor) and generates a
 * test client cert signed by it.  Per-test setup resets all stub state.
 *
 * Method 5 = cert chain validation (Method 4) + passkey + tap-confirm (Method 3).
 * A known (previously-bonded) client skips both gates.
 *
 * Coverage:
 *   1. Valid cert + correct passkey + gesture OK → bonded + PSK stored.
 *   2. No client cert in msg3 → -EACCES (cert gate rejects before passkey).
 *   3. Cert from wrong CA (self-signed) → -EACCES (cert gate).
 *   4. Valid cert + wrong passkey → -EACCES + ERR_AUTH, not bonded.
 *   5. Valid cert + transport timeout → -EACCES, not bonded.
 *   6. Valid cert + correct passkey + gesture denied → -EACCES, not bonded.
 *   7. Already-bonded client (known) → allowed with no cert or passkey.
 *   8. Valid cert + cap full → -EACCES without passkey prompt.
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
#include "clients/client_bond.h"
#include "gesture/gesture.h"
#include "session/session.h"
#include "protocol/protocol.h"

/* Declared in session_stub.c */
cantil_session_t *m5_test_session(void);
void m5_test_set_client_certs(const uint8_t *const ders[],
			      const size_t lens[], size_t count);
void m5_test_clear_client_certs(void);
void m5_test_set_reply_digits(uint32_t digits);
void m5_test_lock_digits(uint32_t digits);
void m5_test_set_reply_timeout(void);
uint32_t m5_test_last_response_err(void);
void m5_test_reset(void);

/* Declared in gesture_stub.c */
void m5_test_set_gesture_result(cantil_confirm_result_t r);

/* ── TRNG callback for mbedtls ──────────────────────────────────────────── */

static int trng_rng_cb(void *ctx, unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);
	return crypto_trng(buf, len) ? -1 : 0;
}

/* ── Test-owned cert DER buffers (populated once in suite_setup) ─────────── */

static uint8_t g_anchor_cert_der[1024];
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
	mbedtls_pk_context     pk;
	mbedtls_x509write_cert wc;
	mbedtls_mpi            serial;

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

/* ── Passkey hook ────────────────────────────────────────────────────────── */

void pairing_test_passkey_hook(uint32_t passkey)
{
	m5_test_set_reply_digits(passkey);
}

/* ── Suite setup ─────────────────────────────────────────────────────────── */

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init failed");

	wipe_dir("/lfs/keys/0");
	zassert_ok(ca_provision(), "ca_provision failed");

	uint8_t blob[64];
	size_t  blob_len = build_ca_x509_blob(blob, sizeof(blob));

	zassert_ok(ca_push_key_x509(0, blob, blob_len),
		   "ca_push_key_x509 failed");
	zassert_true(ca_ready(), "slot 0 not ready after push");

	g_anchor_cert_len = sizeof(g_anchor_cert_der);
	zassert_ok(storage_slot_cert_read(0, g_anchor_cert_der, &g_anchor_cert_len),
		   "could not read slot 0 cert after push");

	/* Sign a test client CSR with slot 0 → g_valid_cert_der. */
	uint8_t csr_buf[512];
	size_t  csr_len = sizeof(csr_buf);

	zassert_ok(build_client_csr(csr_buf, &csr_len), "client CSR build failed");

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
	wipe_dir("/lfs/clients");
	m5_test_reset();
	m5_test_set_gesture_result(CANTIL_CONFIRM_OK);
}

ZTEST_SUITE(pairing_ca_anchor_passkey, NULL, suite_setup, before, NULL, NULL);

static const uint8_t PUB_A[32] = {
	0xAA, 0x01, 0x02, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const uint8_t PUB_B[32] = {
	0xBB, 0x01, 0x02, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const uint8_t PUB_C[32] = {
	0xCC, 0x01, 0x02, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* ── Test 1: valid cert + correct passkey + gesture OK → bonded + PSK ───── */

ZTEST(pairing_ca_anchor_passkey, test_valid_cert_passkey_bonded)
{
	const uint8_t *ders[1] = { g_valid_cert_der };
	size_t         lens[1] = { g_valid_cert_len };

	m5_test_set_client_certs(ders, lens, 1);

	cantil_session_t *s = m5_test_session();

	zassert_ok(pairing_check_and_bond(PUB_A, s),
		   "Method 5: valid cert + passkey should be allowed");

	zassert_equal(client_bond_exists(PUB_A), 1,
		      "bond not stored after Method 5 success");

	/* PSK file must exist and be non-empty. */
	uint8_t id[4] = {0xAA, 0x01, 0x02, 0x03};
	uint8_t psk_enc[64];
	size_t  psk_enc_len = sizeof(psk_enc);

	zassert_ok(storage_client_bond_psk_read(id, psk_enc, &psk_enc_len),
		   "PSK not stored after Method 5");
	zassert_true(psk_enc_len > 0, "PSK blob is empty");

	zassert_equal(m5_test_last_response_err(), (uint32_t)ERR_OK,
		      "device sent non-OK response on success");
}

/* ── Test 2: no cert in msg3 → rejected before passkey ──────────────────── */

ZTEST(pairing_ca_anchor_passkey, test_no_cert_rejected)
{
	/* No certs injected — stub returns cert_count == 0. */
	m5_test_set_reply_timeout();  /* recv would error if called */

	cantil_session_t *s = m5_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "Method 5: no cert should be rejected, got %d", rc);
	zassert_equal(client_bond_exists(PUB_A), 0,
		      "bonded despite missing cert");
}

/* ── Test 3: self-signed cert (wrong CA) → rejected before passkey ───────── */

ZTEST(pairing_ca_anchor_passkey, test_wrong_ca_rejected)
{
	const uint8_t *ders[1] = { g_self_signed_cert_der };
	size_t         lens[1] = { g_self_signed_cert_len };

	m5_test_set_client_certs(ders, lens, 1);
	m5_test_set_reply_timeout();  /* recv would error if called */

	cantil_session_t *s = m5_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "Method 5: cert from wrong CA should be rejected, got %d", rc);
	zassert_equal(client_bond_exists(PUB_A), 0,
		      "bonded despite invalid cert");
}

/* ── Test 4: valid cert + wrong passkey → -EACCES + ERR_AUTH ────────────── */

ZTEST(pairing_ca_anchor_passkey, test_wrong_passkey_rejected)
{
	const uint8_t *ders[1] = { g_valid_cert_der };
	size_t         lens[1] = { g_valid_cert_len };

	m5_test_set_client_certs(ders, lens, 1);
	/* Lock stub to 0 — generate_passkey() never returns 0, so always a mismatch. */
	m5_test_lock_digits(0U);

	cantil_session_t *s = m5_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "Method 5: wrong passkey should reject, got %d", rc);
	zassert_equal(client_bond_exists(PUB_A), 0, "bonded despite wrong passkey");
	zassert_equal(m5_test_last_response_err(), (uint32_t)ERR_AUTH,
		      "expected ERR_AUTH response, got %u",
		      m5_test_last_response_err());
}

/* ── Test 5: valid cert + passkey recv timeout → -EACCES ─────────────────── */

ZTEST(pairing_ca_anchor_passkey, test_timeout_rejected)
{
	const uint8_t *ders[1] = { g_valid_cert_der };
	size_t         lens[1] = { g_valid_cert_len };

	m5_test_set_client_certs(ders, lens, 1);
	m5_test_set_reply_timeout();

	cantil_session_t *s = m5_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "Method 5: passkey timeout should reject, got %d", rc);
	zassert_equal(client_bond_exists(PUB_A), 0, "bonded despite timeout");
}

/* ── Test 6: valid cert + correct passkey + gesture denied → -EACCES ──────── */

ZTEST(pairing_ca_anchor_passkey, test_gesture_denied_rejected)
{
	const uint8_t *ders[1] = { g_valid_cert_der };
	size_t         lens[1] = { g_valid_cert_len };

	m5_test_set_client_certs(ders, lens, 1);
	m5_test_set_gesture_result(CANTIL_CONFIRM_DENIED);

	cantil_session_t *s = m5_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "Method 5: denied gesture should reject, got %d", rc);
	zassert_equal(client_bond_exists(PUB_A), 0, "bonded despite denied gesture");
}

/* ── Test 7: already-bonded client → allowed with no cert or passkey ─────── */

ZTEST(pairing_ca_anchor_passkey, test_known_client_allowed)
{
	/* Pre-establish a bond for PUB_A. */
	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "setup bond");

	/* No cert injected, recv would timeout if called. */
	m5_test_set_reply_timeout();

	cantil_session_t *s = m5_test_session();

	zassert_ok(pairing_check_and_bond(PUB_A, s),
		   "Method 5: known client should be allowed");

	uint32_t hosts = 0, peers = 0;

	zassert_ok(client_bond_count(&hosts, &peers), "count failed");
	zassert_equal(hosts, 1, "expected 1 bond, got %u", hosts);
}

/* ── Test 8: valid cert + cap full → -EACCES without passkey prompt ─────── */

ZTEST(pairing_ca_anchor_passkey, test_cap_full_rejected)
{
	/* Fill the cap (max 2 per prj.conf). */
	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "bond A");
	zassert_ok(client_bond_add(PUB_B, CLIENT_KIND_HOST, 0), "bond B");

	const uint8_t *ders[1] = { g_valid_cert_der };
	size_t         lens[1] = { g_valid_cert_len };

	m5_test_set_client_certs(ders, lens, 1);
	m5_test_set_reply_timeout();  /* recv must not be called */

	cantil_session_t *s = m5_test_session();
	int rc = pairing_check_and_bond(PUB_C, s);

	zassert_equal(rc, -EACCES,
		      "Method 5: cap full should reject, got %d", rc);
	zassert_equal(client_bond_exists(PUB_C), 0, "bonded despite cap full");
}
